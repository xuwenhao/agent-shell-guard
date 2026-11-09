// @ts-check
// Read-only project inspection for the bypass-mode checks. This is the only
// part of policy evaluation that touches the filesystem, and it only stats and
// reads: it never runs git, never writes, and every failure degrades to
// "no project / not configured", which is the strict direction.

import { lstatSync, readdirSync, readFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { dirname, join } from 'node:path';

import { isAncestorOrSelf, normalizePath } from './path-targets.mjs';

/**
 * @typedef {{
 *   gitRoot: string|null,
 *   projectRoot: string|null,
 *   sandboxConfigured: boolean,
 *   nestedRepos: boolean,
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
 * A project counts as sandbox-configured when its merged
 * `.claude/settings.json` + `.claude/settings.local.json` has a `sandbox`
 * object that is either explicitly `enabled: true`, or not disabled and
 * grants a non-empty `filesystem.allowWrite`.
 * `permissions.blockWritesOutsideWorkingDirectories` comes from user-level
 * settings and is not required here.
 * @param {string} gitRoot
 */
export function projectSandboxConfigured(gitRoot) {
  const settings = mergeSettings(
    readJsonObject(join(gitRoot, '.claude', 'settings.json')),
    readJsonObject(join(gitRoot, '.claude', 'settings.local.json')),
  );
  const sandbox = settings.sandbox;
  if (!isObject(sandbox)) return false;
  if (sandbox.enabled === true) return true;
  if (sandbox.enabled === false) return false;
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
    const entries = readdirSync(directory, { withFileTypes: true }).slice(0, 500);
    return entries.some((entry) =>
      entry.name !== '.git' && entry.name !== 'node_modules' &&
      (entry.isDirectory() || entry.isSymbolicLink()) &&
      exists(join(directory, entry.name, '.git')));
  } catch {
    return false;
  }
}

/**
 * @param {string} directory
 * @param {{ephemeralRoots?: string[]}} [options]
 * @returns {ProjectInfo}
 */
export function inspectDirectory(directory, options = {}) {
  const ephemeralRoots = options.ephemeralRoots ?? DEFAULT_EPHEMERAL_ROOTS;
  const gitRoot = findGitRoot(directory);
  if (gitRoot === null) return { gitRoot: null, projectRoot: null, sandboxConfigured: false, nestedRepos: false };
  const ephemeral = ephemeralRoots.some((root) => root !== '/' && isAncestorOrSelf(normalizePath(root), gitRoot));
  return {
    gitRoot,
    projectRoot: findProjectRoot(gitRoot),
    sandboxConfigured: !ephemeral && projectSandboxConfigured(gitRoot),
    nestedRepos: hasNestedRepos(gitRoot),
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
      try { info = inspect(key); } catch { info = { gitRoot: null, projectRoot: null, sandboxConfigured: false, nestedRepos: false }; }
      cache.set(key, info);
    }
    return info;
  };
}
