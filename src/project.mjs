// @ts-check
// Read-only project inspection for the bypass-mode checks and for resolving
// `HEAD` in push/reset rules. This is the only part of policy evaluation that
// touches the filesystem, and it only stats and reads: it never runs git,
// never writes, and every failure degrades to "no project / not configured /
// branch unknown", which is the strict direction.

import { lstatSync, statSync, readdirSync, readFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { basename, dirname, isAbsolute, join, resolve } from 'node:path';

import { isAncestorOrSelf, normalizePath } from './path-targets.mjs';

/**
 * @typedef {{
 *   gitRoot: string|null,
 *   projectRoot: string|null,
 *   sandboxConfigured: boolean,
 *   nestedRepos: boolean,
 *   branch?: string|null,
 *   upstream?: {remote: string, merge: string}|null,
 * }} ProjectInfo
 */

/** Scratch locations never count as a project, even if they hold a repo. */
export const DEFAULT_EPHEMERAL_ROOTS = [
  '/tmp',
  '/private/tmp',
  '/var/folders',
  '/private/var/folders',
  normalizePath(tmpdir()),
];

/** @param {unknown} value @returns {value is Record<string, unknown>} */
const isObject = (value) => typeof value === 'object' && value !== null && !Array.isArray(value);

/** @param {string} path */
function exists(path) {
  try { lstatSync(path); return true; } catch { return false; }
}

/** @param {string} path */
function readText(path) {
  try { return readFileSync(path, 'utf8'); } catch { return null; }
}

/**
 * Nearest ancestor (or self) that holds a `.git` entry — a directory for a
 * normal checkout, a file for a linked worktree or submodule.
 * @param {string} directory
 */
export function findGitRoot(directory) {
  let current = normalizePath(directory);
  if (!current.startsWith('/')) return null;
  for (;;) {
    if (exists(join(current, '.git'))) return current;
    if (current === '/') return null;
    current = dirname(current);
  }
}

/**
 * Where a work tree keeps its metadata. A linked worktree's `.git` is a file
 * (`gitdir: <main>/.git/worktrees/<name>`) whose `commondir` points back at
 * the main repository's `.git`.
 * @param {string} gitRoot
 * @returns {{gitDir: string, commonDir: string, linked: boolean}|null}
 */
export function gitDirs(gitRoot) {
  const dotGit = join(gitRoot, '.git');
  let stat;
  try { stat = lstatSync(dotGit); } catch { return null; }
  if (stat.isDirectory()) return { gitDir: dotGit, commonDir: dotGit, linked: false };
  const pointer = /^gitdir:\s*(.+?)\s*$/m.exec(readText(dotGit) ?? '');
  if (!pointer) return null;
  const gitDir = isAbsolute(pointer[1]) ? normalizePath(pointer[1]) : resolve(gitRoot, pointer[1]);
  const common = readText(join(gitDir, 'commondir'))?.trim();
  const commonDir = common ? (isAbsolute(common) ? normalizePath(common) : resolve(gitDir, common)) : gitDir;
  return { gitDir, commonDir, linked: true };
}

/**
 * The main worktree of a linked worktree (`member/.worktrees/x`,
 * `.claude/worktrees/agent-*`), or null for a main checkout, a submodule or a
 * bare repository.
 * @param {string} gitRoot
 */
export function mainWorktree(gitRoot) {
  const dirs = gitDirs(gitRoot);
  if (!dirs?.linked || basename(dirs.commonDir) !== '.git') return null;
  const main = dirname(dirs.commonDir);
  return main === gitRoot ? null : main;
}

const MAX_SYMREF_DEPTH = 5;

/**
 * Strip a git-config comment (`;` or `#` outside double quotes) and the
 * quoting itself from a line.
 * @param {string} line
 */
export function stripConfigComment(line) {
  let result = '';
  let quoted = false;
  for (let index = 0; index < line.length; index++) {
    const char = line[index];
    if (char === '\\' && index + 1 < line.length) { result += char + line[++index]; continue; }
    if (char === '"') { quoted = !quoted; result += char; continue; }
    if (!quoted && (char === ';' || char === '#')) break;
    result += char;
  }
  return result.trim();
}

/**
 * The branch HEAD names, following symbolic refs (`ref: refs/heads/alias`
 * whose loose file is itself `ref: refs/heads/main`). Null when HEAD is
 * detached, unreadable, too deeply nested, or a reftable placeholder
 * (`refs/heads/.invalid`), since the real ref then lives where this lexical
 * reader cannot see it.
 * @param {{gitDir: string, commonDir: string}} dirs
 */
function headBranch(dirs) {
  let ref = /^ref:\s*(\S+)\s*$/.exec(readText(join(dirs.gitDir, 'HEAD')) ?? '')?.[1];
  for (let depth = 0; ref !== undefined && depth < MAX_SYMREF_DEPTH; depth++) {
    if (!ref.startsWith('refs/heads/')) return null;
    const name = ref.slice('refs/heads/'.length);
    if (name === '' || name === '.invalid') return null;
    const loose = readText(join(dirs.commonDir, ref));
    const next = loose === null ? null : /^ref:\s*(\S+)\s*$/.exec(loose);
    if (!next) return name;
    ref = next[1];
  }
  return null;
}

/**
 * Current branch of a work tree and its configured upstream, read from
 * `HEAD` and the repository `config`. `branch` is null when HEAD is detached
 * or unreadable.
 * @param {string} gitRoot
 * @returns {{branch: string|null, upstream: {remote: string, merge: string}|null}}
 */
export function gitHead(gitRoot) {
  const dirs = gitDirs(gitRoot);
  if (!dirs) return { branch: null, upstream: null };
  const branch = headBranch(dirs);
  if (branch === null) return { branch: null, upstream: null };
  const config = readText(join(dirs.commonDir, 'config')) ?? '';
  /** @type {Record<string, string>} */
  const section = {};
  let inSection = false;
  for (const raw of config.split('\n')) {
    const line = stripConfigComment(raw);
    const header = /^\[\s*branch\s+"(.*)"\s*\]$/i.exec(line);
    if (header) { inSection = header[1] === branch; continue; }
    if (line.startsWith('[')) { inSection = false; continue; }
    if (!inSection) continue;
    const entry = /^([A-Za-z]+)\s*=\s*(.*?)\s*$/.exec(line);
    if (entry) section[entry[1].toLowerCase()] = entry[2].replace(/^"(.*)"$/, '$1');
  }
  const upstream = section.merge ? { remote: section.remote ?? '', merge: section.merge } : null;
  return { branch, upstream };
}

/**
 * Outermost enclosing repository: a member repo inside a thin project root
 * belongs to that root, whose `.worktrees/`, `data/` and sibling members are
 * still "inside the project". Repositories at or above the home directory
 * (a dotfiles-style `~/.git`) never widen the project.
 * @param {string} gitRoot
 */
export function findProjectRoot(gitRoot) {
  const home = normalizePath(homedir());
  let outer = gitRoot;
  let current = dirname(gitRoot);
  while (current !== '/' && !isAncestorOrSelf(current, home)) {
    if (exists(join(current, '.git'))) outer = current;
    current = dirname(current);
  }
  return outer;
}

/** @param {string} path @returns {Record<string, unknown>} */
function readJsonObject(path) {
  try {
    const value = JSON.parse(readFileSync(path, 'utf8'));
    return isObject(value) ? value : {};
  } catch {
    return {};
  }
}

/**
 * Merge the way Claude Code layers settings scopes: objects merge, arrays
 * concatenate, scalars from the later (local) file win.
 * @param {Record<string, unknown>} base @param {Record<string, unknown>} override
 * @returns {Record<string, unknown>}
 */
function mergeSettings(base, override) {
  /** @type {Record<string, unknown>} */
  const merged = { ...base };
  for (const [key, value] of Object.entries(override)) {
    const current = merged[key];
    if (isObject(current) && isObject(value)) merged[key] = mergeSettings(current, value);
    else if (Array.isArray(current) && Array.isArray(value)) merged[key] = [...current, ...value];
    else merged[key] = value;
  }
  return merged;
}

/**
 * A directory counts as sandbox-configured when its merged
 * `.claude/settings.json` + `.claude/settings.local.json` grants a non-empty
 * `sandbox.filesystem.allowWrite` and does not set `sandbox.enabled: false`.
 * `enabled: true` alone says nothing project-specific (the user-level
 * settings already enable the sandbox), so it does not count.
 * @param {string} directory
 */
export function projectSandboxConfigured(directory) {
  const settings = mergeSettings(
    readJsonObject(join(directory, '.claude', 'settings.json')),
    readJsonObject(join(directory, '.claude', 'settings.local.json')),
  );
  const sandbox = settings.sandbox;
  if (!isObject(sandbox) || sandbox.enabled === false) return false;
  const filesystem = sandbox.filesystem;
  return isObject(filesystem) && Array.isArray(filesystem.allowWrite) && filesystem.allowWrite.length > 0;
}

/**
 * A thin project root holds member repositories as direct children. Running
 * `git clean -x` there deletes ignored project assets (data links, media).
 * @param {string} directory
 */
export function hasNestedRepos(directory) {
  try {
    const entries = readdirSync(directory, { withFileTypes: true });
    return entries.some((entry) =>
      entry.name !== '.git' && entry.name !== 'node_modules' &&
      (entry.isDirectory() || entry.isSymbolicLink()) &&
      exists(join(directory, entry.name, '.git')));
  } catch {
    return false;
  }
}

/**
 * @param {string} directory @param {string[]} ephemeralRoots
 */
const isEphemeral = (directory, ephemeralRoots) =>
  ephemeralRoots.some((root) => root !== '/' && isAncestorOrSelf(normalizePath(root), directory));

/**
 * Settings locations for a work tree: itself, and for a linked worktree the
 * main worktree (an untracked `settings.local.json` lives only there).
 * @param {string} directory
 */
function settingsDirectories(directory) {
  const main = mainWorktree(directory);
  return main ? [directory, main] : [directory];
}

/**
 * Inspect the directory a command runs in (the hook `cwd`). Project settings
 * are looked up at its git root, and for a linked worktree also at the main
 * worktree.
 * @param {string} directory
 * @param {{ephemeralRoots?: string[]}} [options]
 * @returns {ProjectInfo}
 */
export function inspectDirectory(directory, options = {}) {
  const ephemeralRoots = options.ephemeralRoots ?? DEFAULT_EPHEMERAL_ROOTS;
  const gitRoot = findGitRoot(directory);
  if (gitRoot === null) return { gitRoot: null, projectRoot: null, sandboxConfigured: false, nestedRepos: false, branch: null, upstream: null };
  const configDirectories = settingsDirectories(gitRoot);
  return {
    gitRoot,
    projectRoot: findProjectRoot(gitRoot),
    sandboxConfigured: !isEphemeral(gitRoot, ephemeralRoots) && configDirectories.some(projectSandboxConfigured),
    nestedRepos: hasNestedRepos(gitRoot),
    ...gitHead(gitRoot),
  };
}

/**
 * Inspect the directory a Claude Code session was started in
 * (`CLAUDE_PROJECT_DIR`). Claude Code reads project settings from exactly
 * there, so that directory — plus the main worktree when it is a linked
 * worktree — decides `sandboxConfigured`, even if it is not a git root.
 * @param {string} projectDir
 * @param {{ephemeralRoots?: string[]}} [options]
 * @returns {ProjectInfo}
 */
export function inspectProjectDir(projectDir, options = {}) {
  const ephemeralRoots = options.ephemeralRoots ?? DEFAULT_EPHEMERAL_ROOTS;
  const directory = normalizePath(projectDir);
  const info = inspectDirectory(directory, options);
  return {
    ...info,
    projectRoot: info.projectRoot ?? directory,
    sandboxConfigured: !isEphemeral(directory, ephemeralRoots) && settingsDirectories(directory).some(projectSandboxConfigured),
  };
}

/**
 * Memoize per hook invocation; the core may ask about the same directory for
 * several rules.
 * @param {(directory: string) => ProjectInfo} inspect
 */
export function memoizeInspector(inspect) {
  /** @type {Map<string, ProjectInfo>} */
  const cache = new Map();
  return (/** @type {string} */ directory) => {
    const key = normalizePath(directory);
    let info = cache.get(key);
    if (!info) {
      try { info = inspect(key); } catch { info = { gitRoot: null, projectRoot: null, sandboxConfigured: false, nestedRepos: false, branch: null, upstream: null }; }
      cache.set(key, info);
    }
    return info;
  };
}

/** Nearest .beads directory wins; unreadable paths are deliberately silent.
 * @param {string|null} directory
 */
export function hasBeadsHooks(directory) {
  if (!directory || !isAbsolute(directory)) return false;
  let current = resolve(directory);
  for (;;) {
    try {
      if (statSync(join(current, '.beads')).isDirectory()) {
        return readdirSync(join(current, '.beads', 'hooks')).length > 0;
      }
    } catch (error) {
      if (/** @type {NodeJS.ErrnoException} */ (error).code !== 'ENOENT') return false;
      // A present .beads without hooks must not fall through to its parent.
      if (exists(join(current, '.beads'))) return false;
    }
    const parent = dirname(current);
    if (parent === current) return false;
    current = parent;
  }
}
