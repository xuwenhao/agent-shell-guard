// @ts-check
// Host-independent shell guard core.
//
// Shell syntax is parsed by the pinned shfmt AST analyzer. Policy rules only
// inspect normalized command argv or one already-parsed data argument; they do
// not infer quoting, command boundaries, or evaluator semantics with regex.
// Path comparisons are lexical (the hook `cwd` is joined literally); the only
// filesystem access is the read-only project inspection in ./project.mjs,
// used for bypass-mode checks and for spotting a thin project root.

import { analyzeShellInput, selectShellDialect } from './shell-analyzer.mjs';
import { isPolicyEnabled, permissionTier, resolvePolicyProfile } from './policies/profiles.mjs';
import {
  commandName,
  commandTargets,
  displayCommand,
  effectiveDisplayArgv,
  gitConfigIsRead,
  githubApiPath,
  gitPositionals,
  hasFlag,
  hasRecursiveFlag,
  isCommand,
  isLongOption,
  isOrgRulesetEndpoint,
  parseGhApi,
  parseGitCommand,
  shortOptionHas,
} from './command-utils.mjs';
import {
  expandHome,
  globCovers,
  lastSegment,
  normalizePath,
  parseGlobTarget,
  resolveTarget,
  targetCovers,
} from './path-targets.mjs';
import { inspectDirectory, memoizeInspector } from './project.mjs';
import { isExcludedCommandGraph, isReadOnlyGraph } from './write-class.mjs';

/** @param {string} value @param {number} [length] */
const trunc = (value, length = 160) => value.length > length ? `${value.slice(0, length)}…` : value;

/** @typedef {ReturnType<typeof analyzeShellInput>} ShellGraph */
/** @typedef {ShellGraph['commands'][number]} AnalyzedCommand */
/** @typedef {Parameters<typeof analyzeShellInput>[0]} ShellInput */
/** @typedef {(ruleId: string) => boolean} PolicyEnabled */
/** @typedef {{ruleId: string, evaluation: 'matched'|'unknown', detail: string, why: string}} PolicyMatch */
/** @typedef {import('./project.mjs').ProjectInfo} ProjectInfo */
/**
 * @typedef {{
 *   tier: import('./policies/profiles.mjs').PermissionTier,
 *   cwd: string|null,
 *   trustedCwd: string|null,
 *   unsandboxed: boolean,
 *   protectedRoots: string[],
 *   protectedPaths: string[],
 *   inspect: (directory: string) => ProjectInfo,
 * }} RuleContext
 */

const TRUNK_REF = /^(?:refs\/heads\/)?(?:main|master)$/;
const CWD_CHANGING = new Set(['cd', 'pushd', 'popd', 'source', '.']);

/** @param {string} value */
function isProtectedRef(value) {
  const ref = value.replace(/^\+/, '');
  return /^(?:refs\/heads\/)?(?:main|master)$/.test(ref) || /:(?:refs\/heads\/)?(?:main|master)$/.test(ref);
}

/**
 * A branch operand that may name the trunk: main/master themselves, plus
 * reflog-relative spellings (`-`, `@{-1}`, `main@{yesterday}`) that resolve to
 * whatever was checked out before.
 * @param {string|null|undefined} value
 */
function mayNameTrunk(value) {
  if (typeof value !== 'string') return true;
  if (value === '-' || value.startsWith('@{')) return true;
  return TRUNK_REF.test(value.replace(/@\{.*$/, ''));
}

// --- path targets ------------------------------------------------------------

/**
 * @param {{value: string|null, display: string}} target
 * @param {string[]} paths
 * @param {string|null} cwd trusted cwd
 * @param {{ancestors: boolean, dynamicMatches: boolean}} options
 * @returns {'matched'|'unknown'|null}
 */
function targetHitsProtected(target, paths, cwd, options) {
  if (target.value !== null) {
    const resolved = resolveTarget(target.value, cwd);
    if (!paths.some((path) => targetCovers(resolved, path, { ancestors: options.ancestors }))) return null;
    return resolved.kind === 'absolute' ? 'matched' : 'unknown';
  }
  const glob = parseGlobTarget(target.display, cwd);
  if (glob === null) return options.dynamicMatches ? 'unknown' : null;
  return paths.some((path) => globCovers(glob, path)) ? 'unknown' : null;
}

/** @param {{value: string|null, display: string}} target */
function targetIsGitDir(target) {
  if (target.value !== null) return lastSegment(resolveTarget(target.value, null)) === '.git';
  const text = target.display.replace(/["']/g, '').replace(/\/+$/, '');
  const segments = text.split('/');
  return segments[segments.length - 1] === '.git' ||
    (segments.length > 1 && segments[segments.length - 2] === '.git' && /[*?[]/.test(segments[segments.length - 1]));
}

/**
 * Resolve the directory a git command runs in: the trusted cwd, then each
 * `-C`. `--git-dir`/`--work-tree` make the target unknowable.
 * @param {NonNullable<ReturnType<typeof parseGitCommand>>} git @param {string|null} cwd
 */
function gitWorkDir(git, cwd) {
  if (git.gitDirOverride) return null;
  let directory = cwd;
  for (const value of git.workDirs) {
    if (value === null) return null;
    const expanded = expandHome(value);
    if (expanded.startsWith('/')) directory = normalizePath(expanded);
    else if (directory === null) return null;
    else directory = normalizePath(`${directory}/${expanded}`);
  }
  return directory;
}

// --- git classification ------------------------------------------------------

/**
 * Split checkout's argv the way git does. Short options cluster (`-qB`) and may
 * carry their operand attached (`-Bmain`), so scanning for a standalone `-B`
 * token both misses the branch name and mistakes the operand's letters for more
 * flags — `-Bmain` would read as if `-m` were present.
 * @param {{args: Array<string|null>}} git
 */
function parseCheckoutArgs(git) {
  const SHORT_WITH_OPERAND = 'bB';
  // --track[=(direct|inherit)] takes only an attached optional value. Consuming
  // its next token would hide a real --force/-f option from the classifier.
  const LONG_WITH_OPERAND = new Set(['--conflict', '--pathspec-from-file']);
  /** @type {string[]} */ const flags = [];
  /** @type {string[]} */ const letters = [];
  /** @type {Array<string|null>} */ const positionals = [];
  /** @type {string|null|undefined} */ let createTarget;
  let forceCreate = false;
  let endOfOptions = false;

  for (let index = 0; index < git.args.length; index++) {
    const raw = git.args[index];
    if (endOfOptions) { positionals.push(raw); continue; }
    if (raw === null) { positionals.push(null); continue; }
    if (raw === '--') { flags.push('--'); endOfOptions = true; continue; }
    if (raw.startsWith('--')) {
      const eq = raw.indexOf('=');
      const name = eq === -1 ? raw : raw.slice(0, eq);
      flags.push(name);
      const operand = eq === -1 ? undefined : raw.slice(eq + 1);
      if (name === '--orphan') createTarget = operand ?? git.args[++index] ?? null;
      else if (operand === undefined && LONG_WITH_OPERAND.has(name)) index++;
      continue;
    }
    if (raw.startsWith('-') && raw.length > 1) {
      const cluster = raw.slice(1);
      for (let cursor = 0; cursor < cluster.length; cursor++) {
        const letter = cluster[cursor];
        letters.push(letter);
        if (!SHORT_WITH_OPERAND.includes(letter)) continue;
        const attached = cluster.slice(cursor + 1);
        const operand = attached !== '' ? attached : git.args[++index] ?? null;
        if (letter === 'b' || letter === 'B') {
          createTarget = operand;
          if (letter === 'B') forceCreate = true;
        }
        break;
      }
      continue;
    }
    positionals.push(raw);
  }
  return { flags, letters, positionals, createTarget, forceCreate };
}

/**
 * `git checkout` is two commands under one name: switching or creating a branch
 * (cheap, reversible) and restoring paths from a tree-ish (silently discards
 * edits). A lone positional can be either, and nothing in the argv settles it,
 * so it stays a discard unless an explicit branch-intent flag says otherwise.
 * `-B` resets an existing branch tip: trunk (or unresolvable) targets are
 * `git-trunk-ref`, others `git-ref-change`.
 * @param {{args: Array<string|null>}} git
 * @returns {'git-discard'|'git-trunk-ref'|'git-ref-change'|'git-low-risk'|null}
 */
function checkoutRule(git) {
  const parsed = parseCheckoutArgs(git);
  if (parsed.forceCreate && mayNameTrunk(parsed.createTarget)) return 'git-trunk-ref';
  if (git.args.some((arg) => arg === null)) return 'git-discard';
  if (parsed.flags.includes('--')) return 'git-discard';
  // `--pathspec-from-file <file>` restores every path listed in the file, which
  // is a working-tree discard with no positional argument to notice it by.
  if (parsed.flags.some((flag) => isLongOption(flag, '--pathspec-from-file'))) return 'git-discard';
  const forceish = parsed.flags.some((flag) =>
    ['--force', '--ours', '--theirs', '--merge', '--conflict', '--patch', '--overwrite-ignore',
      '--no-detach', '--no-orphan']
      .some((option) => isLongOption(flag, option))) ||
    parsed.letters.some((letter) => 'fmp23'.includes(letter));
  if (forceish) return 'git-discard';
  if (parsed.positionals.some((value) => value === '.' || value === null)) return 'git-discard';
  // Git expands pathspecs itself, so `git checkout '*.txt'` overwrites matching
  // modified files even though no file literally named `*.txt` exists. Refs
  // cannot contain glob metacharacters, and a leading `:` is pathspec magic.
  if (parsed.positionals.some((value) => typeof value === 'string' && (/[*?[\]]/.test(value) || value.startsWith(':')))) {
    return 'git-discard';
  }
  if (parsed.createTarget !== undefined) {
    if (parsed.forceCreate) return 'git-ref-change';
    return 'git-low-risk';
  }
  if (parsed.positionals.length === 0) return 'git-low-risk';
  if (parsed.positionals.length > 1) return 'git-discard';
  // A lone operand is genuinely ambiguous — git resolves it against both refs and
  // paths, and a deleted tracked file is still a valid pathspec. Only flags git
  // itself refuses to pair with a path count as branch intent (verified on git
  // 2.43: `--detach`/`-d` and `--track`/`--no-track`/`-t`).
  const refIntent = ['--detach', '--track', '--no-track'];
  if (parsed.flags.some((flag) => refIntent.includes(flag)) ||
      parsed.letters.some((letter) => letter === 't' || letter === 'd')) {
    return 'git-low-risk';
  }
  return 'git-discard';
}

/** Only explicit, fully static dry-run argv is read-only. Do not infer values
 * from shell assignments or mistake an exclude pattern/path for an option.
 * @param {AnalyzedCommand} command @param {Array<string|null>} args
 */
function cleanIsDryRun(command, args) {
  if (command.argv.some((arg) => arg === null)) return false;
  let dryRun = false;
  for (let index = 0; index < args.length; index++) {
    const arg = args[index];
    if (arg === '--') break;
    if (typeof arg !== 'string') return false;
    if (arg === '--dry-run') { dryRun = true; continue; }
    if (['--force', '--quiet'].includes(arg)) continue;
    if (arg === '--exclude') { if (typeof args[++index] !== 'string') return false; continue; }
    if (arg.startsWith('--exclude=')) continue;
    if (arg.startsWith('--')) return false;
    if (arg.startsWith('-') && arg !== '-') {
      const letters = arg.slice(1);
      for (let cursor = 0; cursor < letters.length; cursor++) {
        const flag = letters[cursor];
        if (flag === 'e') {
          if (cursor + 1 === letters.length && typeof args[++index] !== 'string') return false;
          break;
        }
        if (!'ndfqxX'.includes(flag)) return false;
        if (flag === 'n') dryRun = true;
      }
    }
  }
  return dryRun;
}

/**
 * Operand of a short option that takes one (`-B name`, `-Bname`, `-qBname`).
 * @param {Array<string|null>} args @param {string} letter
 * @returns {string|null|undefined} undefined when the option is absent
 */
function shortOperand(args, letter) {
  for (let index = 0; index < args.length; index++) {
    const arg = args[index];
    if (typeof arg !== 'string' || !/^-[^-]/.test(arg)) continue;
    const position = arg.indexOf(letter, 1);
    if (position < 0) continue;
    const attached = arg.slice(position + 1);
    return attached !== '' ? attached : args[index + 1] ?? null;
  }
  return undefined;
}

/**
 * Fine-grained git classification. Returns the rule id or null.
 * @param {AnalyzedCommand} command
 * @returns {'git-discard'|'git-trunk-ref'|'git-ref-change'|'git-config-global'|'git-lfs'|'git-exec'|'git-push-bulk'|'git-low-risk'|null}
 */
function gitRule(command) {
  const git = parseGitCommand(command);
  if (!git) return null;
  const { subcommand, args } = git;

  if (subcommand === 'clean') return cleanIsDryRun(command, args) ? null : 'git-discard';
  if (['reset', 'restore', 'rm'].includes(subcommand)) return 'git-discard';
  if (subcommand === 'checkout') return checkoutRule(git);
  if (subcommand === 'worktree') {
    if (args[0] === 'remove') {
      return args.slice(1).some((arg) => isLongOption(arg, '--force') || shortOptionHas(arg, /f/)) ? 'git-discard' : 'git-ref-change';
    }
    if (args[0] === 'add') {
      const target = shortOperand(args.slice(1), 'B');
      if (target === undefined) return null;
      return mayNameTrunk(target) ? 'git-trunk-ref' : 'git-ref-change';
    }
    return null;
  }
  if (subcommand === 'stash') return args[0] === 'drop' || args[0] === 'clear' ? 'git-discard' : null;
  if (subcommand === 'config') {
    if (!args.some((arg) => isLongOption(arg, '--global') || isLongOption(arg, '--system'))) return null;
    return gitConfigIsRead(git) ? null : 'git-config-global';
  }
  if (subcommand === 'branch') {
    const forced = args.some((arg) => isLongOption(arg, '--force') || shortOptionHas(arg, /[DfMC]/));
    const deleting = args.some((arg) => isLongOption(arg, '--delete') || shortOptionHas(arg, /d/));
    if (!forced && !deleting) return null;
    const targets = gitPositionals(git, new Set(['--contains', '--no-contains', '--merged', '--no-merged', '-u', '--set-upstream-to']));
    const trunk = targets.some((value) => value === null || TRUNK_REF.test(value));
    if (trunk) return 'git-trunk-ref';
    // `-d` refuses to delete an unmerged branch; -D/-M/-C/-f on a non-trunk ref
    // are recoverable from the reflog.
    return forced ? 'git-ref-change' : 'git-low-risk';
  }
  if (subcommand === 'tag') {
    const force = args.some((arg) => isLongOption(arg, '--force') || shortOptionHas(arg, /f/));
    if (force) return 'git-discard';
    return args.some((arg) => arg === '--delete' || shortOptionHas(arg, /d/)) ? 'git-low-risk' : null;
  }
  if (subcommand === 'switch') {
    const forceCreate = args.some((arg) => isLongOption(arg, '--force-create')) ? (gitPositionals(git)[0] ?? null) : shortOperand(args, 'C');
    if (forceCreate !== undefined && mayNameTrunk(forceCreate)) return 'git-trunk-ref';
    if (args.some((arg) => isLongOption(arg, '--discard-changes') || isLongOption(arg, '--force') || shortOptionHas(arg, /f/))) return 'git-discard';
    if (forceCreate !== undefined) return 'git-ref-change';
    return args.some((arg) => shortOptionHas(arg, /d/)) ? 'git-low-risk' : null;
  }
  if (subcommand === 'submodule') {
    const action = args.find((arg) => typeof arg === 'string' && !arg.startsWith('-'));
    if (action === 'foreach') return 'git-exec';
    return action === 'deinit' ? 'git-low-risk' : null;
  }
  if (subcommand === 'lfs') {
    const action = args.find((arg) => typeof arg === 'string' && !arg.startsWith('-'));
    if (['install', 'migrate', 'uninstall'].includes(String(action))) return 'git-lfs';
    return action === 'prune' ? 'git-ref-change' : null;
  }
  if (subcommand === 'rebase') {
    return args.some((arg) => isLongOption(arg, '--exec') ||
      isLongOption(arg, '--reschedule-failed-exec') || shortOptionHas(arg, /x/)) ? 'git-exec' : null;
  }
  if (subcommand === 'push') {
    if (args.some((arg) => isLongOption(arg, '--mirror') || isLongOption(arg, '--prune'))) return 'git-push-bulk';
    return args.some((arg) =>
      isLongOption(arg, '--delete') || shortOptionHas(arg, /d/) || (typeof arg === 'string' && /^\+?:\S+/.test(arg)))
      ? 'git-ref-change' : null;
  }
  return null;
}

/** @param {AnalyzedCommand} command */
function hardResetRef(command) {
  const git = parseGitCommand(command);
  if (git?.subcommand !== 'reset' || !hasFlag(git.args, '--hard')) return null;
  return git.args.find((arg) => typeof arg === 'string' && !arg.startsWith('-')) ?? null;
}

/** @param {AnalyzedCommand} command */
function forcePush(command) {
  const git = parseGitCommand(command);
  if (git?.subcommand !== 'push') return false;
  const display = effectiveDisplayArgv(command).slice(git.argOffset);
  return git.args.some((arg, index) => {
    const token = arg ?? display[index] ?? '';
    return isLongOption(token, '--force') || isLongOption(token, '--force-with-lease') || shortOptionHas(token, /f/) || /^\+\S+/.test(token);
  });
}

/** @param {AnalyzedCommand} command @returns {Array<{value: string|null, display: string}>} */
function pushPositionals(command) {
  const git = parseGitCommand(command);
  if (git?.subcommand !== 'push') return [];
  const display = effectiveDisplayArgv(command).slice(git.argOffset);
  const valueFlags = new Set(['--repo', '--receive-pack', '--exec', '--push-option', '-o']);
  /** @type {Array<{value: string|null, display: string}>} */
  const positionals = [];
  let options = true;
  for (let index = 0; index < git.args.length; index++) {
    const arg = git.args[index];
    const token = arg ?? display[index] ?? '<?>';
    if (options && token === '--') { options = false; continue; }
    if (options && token.startsWith('-')) {
      if (valueFlags.has(token)) index++;
      continue;
    }
    positionals.push({ value: arg, display: token });
  }
  return positionals;
}

/** @param {AnalyzedCommand} command */
const pushRefs = (command) => pushPositionals(command).slice(1);

/** @param {AnalyzedCommand} command @returns {'matched'|'unknown'|null} */
function pushDeletesTrunk(command) {
  const git = parseGitCommand(command);
  if (git?.subcommand !== 'push') return null;
  if (git.args.some((arg) => isLongOption(arg, '--dry-run') || shortOptionHas(arg, /n/))) return null;
  const emptySource = /^\+?:(?:refs\/heads\/)?(?:main|master)$/;
  if (pushPositionals(command).some((ref) => typeof ref.value === 'string' && emptySource.test(ref.value))) return 'matched';
  const deleting = git.args.some((arg) => isLongOption(arg, '--delete') || shortOptionHas(arg, /d/));
  if (!deleting) return null;
  const refs = pushRefs(command);
  if (refs.some((ref) => typeof ref.value === 'string' && TRUNK_REF.test(ref.value.replace(/^\+/, '')))) return 'matched';
  return refs.some((ref) => ref.value === null) ? 'unknown' : null;
}

/** @param {AnalyzedCommand} command */
function parseSsh(command) {
  const valueFlags = new Set(['-p', '-i', '-o', '-l', '-F', '-J', '-L', '-R', '-D', '-W', '-E', '-b', '-c', '-e', '-m', '-O', '-S']);
  const display = effectiveDisplayArgv(command);
  for (let index = 1; index < command.argv.length; index++) {
    const arg = command.argv[index];
    if (typeof arg === 'string' && arg.startsWith('-')) {
      if (valueFlags.has(arg)) index++;
      continue;
    }
    return {
      host: arg ?? display[index] ?? '(未解析出主机)',
      rest: command.argv.slice(index + 1).map((value, restIndex) => value ?? display[index + 1 + restIndex] ?? '<?>').join(' '),
    };
  }
  return { host: '(未解析出主机)', rest: '' };
}

// --- gh api ------------------------------------------------------------------

/** @param {AnalyzedCommand} command @returns {{kind: 'matched'|'unknown', endpoint: string}|null} */
function orgRulesetWrite(command) {
  const api = parseGhApi(command);
  if (!api) return null;
  const endpoint = typeof api.endpoint?.value === 'string' && isOrgRulesetEndpoint(api.endpoint.value)
    ? api.endpoint.value
    : null;
  const write = api.fieldWrite || /^(?:PUT|POST|PATCH|DELETE)$/.test(api.method);
  const unknownEndpoint = api.endpoint?.value === null;
  if (endpoint && write) return { kind: 'matched', endpoint };
  if ((endpoint && api.methodUnknown) || (unknownEndpoint && (write || api.methodUnknown))) return { kind: 'unknown', endpoint: endpoint ?? '<?>' };
  return null;
}

const REPO_PATH = String.raw`repos/[^/]+/[^/]+`;
const PROTECTED_DELETE_ENDPOINTS = [
  new RegExp(`^${REPO_PATH}$`),
  new RegExp(`^${REPO_PATH}/rulesets(?:/|$)`),
  new RegExp(`^${REPO_PATH}/branches/[^/]+/protection(?:/|$)`),
  new RegExp(`^${REPO_PATH}/git/refs/heads/(?:main|master)$`),
];
const SENSITIVE_DELETE_ENDPOINTS = [
  new RegExp(`^(?:${REPO_PATH}|orgs/[^/]+)/(?:keys|hooks|actions/secrets|environments)(?:/|$)`),
  /^user\/(?:keys|gpg_keys|ssh_signing_keys)(?:\/|$)/,
];

/**
 * @param {AnalyzedCommand} command
 * @returns {{level: 'protected'|'sensitive'|'other', evaluation: 'matched'|'unknown', endpoint: string}|null}
 */
function ghApiDelete(command) {
  const api = parseGhApi(command);
  if (!api) return null;
  const isDelete = api.method === 'DELETE';
  if (!isDelete && !api.methodUnknown) return null;
  const value = api.endpoint?.value;
  if (typeof value !== 'string') return null;
  const path = githubApiPath(value);
  if (path === null) return null;
  if (PROTECTED_DELETE_ENDPOINTS.some((pattern) => pattern.test(path))) {
    return { level: 'protected', evaluation: isDelete ? 'matched' : 'unknown', endpoint: value };
  }
  if (!isDelete) return null;
  const level = SENSITIVE_DELETE_ENDPOINTS.some((pattern) => pattern.test(path)) ? 'sensitive' : 'other';
  return { level, evaluation: 'matched', endpoint: value };
}

// --- git clean at a thin project root ------------------------------------------

/**
 * @param {AnalyzedCommand} command @param {RuleContext} ctx
 * @returns {{evaluation: 'matched'|'unknown', reason: 'double-force'|'dynamic'|'unknown-cwd'|'project-root'}|null}
 */
function gitCleanRoot(command, ctx) {
  const git = parseGitCommand(command);
  if (git?.subcommand !== 'clean' || cleanIsDryRun(command, git.args)) return null;
  let force = 0;
  let ignored = false;
  let dynamic = false;
  let wide = false;
  let options = true;
  for (let index = 0; index < git.args.length; index++) {
    const arg = git.args[index];
    if (arg === null) { if (options) dynamic = true; else wide = true; continue; }
    if (options && arg === '--') { options = false; continue; }
    if (options && arg.startsWith('--')) {
      if (isLongOption(arg, '--force')) force++;
      else if (arg === '--exclude') index++;
      continue;
    }
    if (options && arg.startsWith('-') && arg !== '-') {
      for (let cursor = 1; cursor < arg.length; cursor++) {
        const letter = arg[cursor];
        if (letter === 'e') { if (cursor === arg.length - 1) index++; break; }
        if (letter === 'f') force++;
        if (letter === 'x' || letter === 'X') ignored = true;
      }
      continue;
    }
    if (arg.startsWith(':') || arg.startsWith('/') || arg.split('/').includes('..')) wide = true;
  }
  // -ff also removes nested repositories (members, .worktrees, data shields).
  if (force >= 2) return { evaluation: 'matched', reason: 'double-force' };
  // A dynamic word can carry a second -f.
  if (dynamic) return { evaluation: 'unknown', reason: 'dynamic' };
  if (!ignored) return null;
  const directory = gitWorkDir(git, ctx.trustedCwd);
  if (directory === null) return { evaluation: 'unknown', reason: 'unknown-cwd' };
  const info = ctx.inspect(directory);
  if (info.gitRoot !== null && info.nestedRepos && (info.gitRoot === directory || wide)) {
    return { evaluation: 'matched', reason: 'project-root' };
  }
  return null;
}

// --- policies ------------------------------------------------------------------

/** @param {ShellGraph} graph @param {PolicyEnabled} enabled @param {RuleContext} ctx @returns {PolicyMatch|null} */
function hardPolicy(graph, enabled, ctx) {
  const cwd = ctx.trustedCwd;
  for (const command of graph.commands) {
    const orgWrite = orgRulesetWrite(command);
    if (orgWrite && enabled('org-ruleset-write')) {
      return {
        ruleId: 'org-ruleset-write', evaluation: orgWrite.kind,
        detail: `修改 org-level ruleset（${trunc(orgWrite.endpoint)}）`,
        why: orgWrite.kind === 'unknown'
          ? 'endpoint 或写入方法无法静态还原，可能隐藏组织级 ruleset 写入；按全局约定必须拒绝。改法：endpoint 写成字面量（如 repos/<owner>/<repo>/pulls/1/comments），不要整段放在变量里。'
          : '按全局约定，组织级分支保护规则只能由人在 GitHub UI 修改，AI/CLI 一律不得写入。需要变更时把改动内容写清楚交给用户手动操作。',
      };
    }

    if (enabled('gh-repo-delete') && isCommand(command, 'gh') && command.argv[1] === 'repo' && command.argv[2] === 'delete') {
      return {
        ruleId: 'gh-repo-delete', evaluation: 'matched',
        detail: `删除 GitHub 仓库：${trunc(displayCommand(command))}`,
        why: '仓库删除不可恢复（issue、PR、release 一并消失）。需要删除时把仓库名交给用户在 GitHub UI 操作。',
      };
    }

    const apiDelete = ghApiDelete(command);
    if (apiDelete?.level === 'protected' && enabled('gh-api-delete-protected')) {
      return {
        ruleId: 'gh-api-delete-protected', evaluation: apiDelete.evaluation,
        detail: `GitHub API 删除仓库、ruleset、分支保护或主干 ref（${trunc(apiDelete.endpoint)}）`,
        why: '这些对象删除后无法从 API 恢复，且会解除仓库的保护边界。需要变更时交给用户在 GitHub UI 操作。',
      };
    }

    const rmRecursive = isCommand(command, 'rm') && hasRecursiveFlag(command.argv);
    if (rmRecursive) {
      const targets = commandTargets(command);
      const gitDir = targets.find(targetIsGitDir);
      if (gitDir && enabled('rm-git-dir')) {
        return {
          ruleId: 'rm-git-dir', evaluation: 'matched',
          detail: `递归删除 git 元数据目录 ${gitDir.display}`,
          why: '删除 .git 会丢掉全部本地提交、分支、stash 和 reflog，无法从工作区恢复。确需重建仓库请交给用户。',
        };
      }
      /** @type {{target: {display: string}, evaluation: 'matched'|'unknown'}|null} */
      let hit = null;
      for (const target of targets) {
        const evaluation = targetHitsProtected(target, ctx.protectedRoots, cwd, { ancestors: true, dynamicMatches: true });
        if (evaluation) { hit = { target, evaluation }; if (evaluation === 'matched') break; }
      }
      if (hit && enabled('rm-protected-root')) {
        return {
          ruleId: 'rm-protected-root', evaluation: hit.evaluation,
          detail: `递归删除 ${hit.target.display}（受保护根目录或其上级）`,
          why: hit.evaluation === 'matched'
            ? '一旦执行整个目录树不可恢复、影响面过大。若确需清理，请改用指向具体子目录的精确路径。'
            : '递归删除目标无法静态确定（变量、通配符，或相对路径而 cwd 不可信——例如前面有 cd），可能落在受保护根目录上，必须拒绝。改法：把目标写成字面绝对路径，不要在同一条命令里 cd。',
        };
      }
    }

    if (ctx.protectedPaths.length && enabled('rm-protected-path') &&
        (isCommand(command, 'rm') || isCommand(command, 'unlink') || isCommand(command, 'mv'))) {
      const ancestors = rmRecursive || isCommand(command, 'mv');
      for (const target of commandTargets(command)) {
        const evaluation = targetHitsProtected(target, ctx.protectedPaths, cwd, { ancestors, dynamicMatches: false });
        if (!evaluation) continue;
        return {
          ruleId: 'rm-protected-path', evaluation,
          detail: `${commandName(command)} 受保护路径 ${target.display}`,
          why: '该路径在 protectedPaths 中（通常是兼容链接或共享数据入口），删除或移动会让依赖它的脚本和会话失效。确需调整请交给用户。',
        };
      }
    }

    const clean = gitCleanRoot(command, ctx);
    if (clean && enabled('git-clean-root')) {
      const reasons = {
        'double-force': '`git clean -ff` 会连嵌套仓库（成员仓、.worktrees、data 防清理盾）一起删除。',
        dynamic: 'git clean 参数里有无法静态还原的值，可能带第二个 -f。',
        'unknown-cwd': 'git clean -x/-X 的执行目录无法确定（hook 没给 cwd，或命令里 cd / git -C 动态），可能是项目根。',
        'project-root': '在项目根（含成员仓的薄根仓库）执行 git clean -x/-X 会删掉被忽略的项目资产（data 链接、media 等）。',
      };
      return {
        ruleId: 'git-clean-root', evaluation: clean.evaluation,
        detail: `git clean 可能清掉项目根或嵌套仓库：${trunc(displayCommand(command))}`,
        why: `${reasons[clean.reason]}改法：到具体成员仓里执行单个 -f 的 git clean，或手动删除明确路径。`,
      };
    }

    if (forcePush(command)) {
      const refs = pushRefs(command);
      const protectedRef = refs.find((ref) => ref.value !== null && isProtectedRef(ref.value));
      const unknownRef = refs.find((ref) => ref.value === null);
      const unresolvedTarget = refs.length === 0 || unknownRef !== undefined;
      if ((protectedRef || unresolvedTarget) && enabled('force-push-main')) {
        return {
          ruleId: 'force-push-main', evaluation: protectedRef ? 'matched' : 'unknown',
          detail: `force push 到 main/master（${trunc(displayCommand(command))}，含 --force-with-lease / +refspec 形式）`,
          why: protectedRef
            ? '会重写 main/master 的提交历史，其他人基于旧历史的工作会被破坏；主干改动请走 PR 流程。'
            : 'force push 的目标 ref 无法静态还原，可能是 main/master，必须拒绝。改法：写显式 refspec（如 git push --force-with-lease origin feat/x），即可交给宿主审批。',
        };
      }
    }

    const trunkDelete = pushDeletesTrunk(command);
    if (trunkDelete && enabled('push-delete-trunk')) {
      return {
        ruleId: 'push-delete-trunk', evaluation: trunkDelete,
        detail: `删除远端主干分支：${trunc(displayCommand(command))}`,
        why: trunkDelete === 'matched'
          ? '删除远端 main/master 会让所有协作者和 CI 失去主干；主干只能由人处理。'
          : '远端删除的目标 ref 无法静态还原，可能是 main/master。改法：把分支名写成字面量。',
      };
    }
  }
  return null;
}

/** @param {AnalyzedCommand} command @returns {Array<{value: string|null, display: string}>} */
function relocatingTargets(command) {
  if (isCommand(command, 'rm') && hasRecursiveFlag(command.argv)) return commandTargets(command);
  if (isCommand(command, 'mv')) return commandTargets(command);
  if (isCommand(command, 'rsync') && command.argv.some((arg) => typeof arg === 'string' && arg.startsWith('--delete'))) {
    const targets = commandTargets(command);
    const destination = targets[targets.length - 1];
    return destination && !(typeof destination.value === 'string' && /^[^/]*:/.test(destination.value)) ? [destination] : [];
  }
  const git = parseGitCommand(command);
  if (git?.subcommand === 'worktree' && (git.args[0] === 'remove' || git.args[0] === 'move')) {
    const display = effectiveDisplayArgv(command).slice(git.argOffset);
    /** @type {Array<{value: string|null, display: string}>} */
    const targets = [];
    for (let index = 1; index < git.args.length; index++) {
      const arg = git.args[index];
      if (typeof arg === 'string' && arg.startsWith('-')) continue;
      targets.push({ value: arg, display: arg ?? display[index] ?? '<?>' });
    }
    return targets;
  }
  return [];
}

/**
 * Bypass sessions: a call that runs outside the sandbox (explicit
 * dangerouslyDisableSandbox, or an excludedCommands-style command) is not
 * confined to the project, so recursive deletes and moves that land outside
 * the project root (the outermost repository enclosing cwd, so a thin root's
 * members and `.worktrees/` count as inside) need a human.
 * @param {ShellGraph} graph @param {RuleContext} ctx @returns {PolicyMatch|null}
 */
function unsandboxedOutsideProject(graph, ctx) {
  if (ctx.tier !== 'bypass') return null;
  if (!ctx.unsandboxed && !isExcludedCommandGraph(graph)) return null;
  const root = ctx.cwd ? ctx.inspect(ctx.cwd).projectRoot : null;
  for (const command of graph.commands) {
    for (const target of relocatingTargets(command)) {
      /** @type {'matched'|'unknown'|null} */
      let evaluation = null;
      if (target.value === null) evaluation = 'unknown';
      else {
        const resolved = resolveTarget(target.value, ctx.trustedCwd);
        if (resolved.kind === 'relative') evaluation = 'unknown';
        else if (root === null || !resolved.path.startsWith(`${root}/`)) evaluation = 'matched';
      }
      if (!evaluation) continue;
      return {
        ruleId: 'unsandboxed-outside-project', evaluation,
        detail: `沙盒外执行的删除/移动目标在项目根${root ? `（${root}）` : ''}以外：${trunc(displayCommand(command))}`,
        why: evaluation === 'matched'
          ? '这条命令不受项目沙盒的写权限约束，bypass 下也不会有其他确认；目标在项目外，需要人确认。'
          : '这条命令在沙盒外执行，删除/移动目标无法静态确定（变量、通配符或 cwd 不可信），需要人确认。',
      };
    }
  }
  return null;
}

const GIT_RULE_TEXT = {
  'git-discard': {
    detail: '丢弃工作区或本地状态的 Git 操作',
    why: '可能丢弃未提交改动、未跟踪文件、stash 或已有 tag 指向，请确认目标和参数。',
  },
  'git-trunk-ref': {
    detail: '删除、重置或覆盖主干（或无法确定的）分支引用',
    why: '目标是 main/master 或无法静态确定的分支名；主干引用被删除或重置会影响所有基于它的工作。',
  },
  'git-ref-change': {
    detail: '删除或重置非主干分支 / worktree / 远端分支',
    why: '非主干引用变更通常可从 reflog 或远端恢复；worktree remove 会删除其中被忽略的文件。',
  },
  'git-config-global': {
    detail: '修改用户级或系统级 Git 配置',
    why: '会改变整台机器上所有仓库的 Git 行为（hooksPath、sshCommand、凭据助手等），请确认键和值。',
  },
  'git-lfs': {
    detail: '安装、卸载 Git LFS 或用 LFS 重写历史',
    why: 'lfs install/uninstall 会改 Git 配置和 hooks，lfs migrate 会重写提交历史，请确认作用域。',
  },
  'git-exec': {
    detail: '让 Git 执行任意 shell 命令（rebase -x / submodule foreach）',
    why: '这些子命令会在每一步运行一段 shell，guard 看不到其内容，请确认命令本身。',
  },
  'git-push-bulk': {
    detail: '批量同步或删除远端 refs（push --mirror / --prune）',
    why: '会删除远端上本地不存在的 refs，可能一次性删掉他人的分支和 tag，请确认 remote。',
  },
  'git-low-risk': {
    detail: '执行会改变本地引用或工作区状态的低风险 Git 操作',
    why: '该操作不属于重写历史或强制覆盖，但可能删除本地分支/tag、进入 detached HEAD 或解除 submodule 初始化状态。',
  },
};

/** @param {ShellGraph} graph @param {PolicyEnabled} enabled @returns {PolicyMatch|null} */
function confirmationPolicy(graph, enabled) {
  for (const command of graph.commands) {
    const tool = commandName(command);
    if (enabled('remote-exec') && ['ssh', 'scp', 'rsync'].includes(tool) && (tool === 'rsync' || !hasFlag(command.argv, '-G'))) {
      if (tool === 'ssh') {
        const { host, rest } = parseSsh(command);
        return {
          ruleId: 'remote-exec', evaluation: 'matched',
          detail: `通过 ssh 连接远程机器 ${host}${rest ? `，执行：${trunc(rest)}` : '（交互式会话）'}`,
          why: '远程机器上的操作本机无法回滚，请确认目标主机和命令是否符合预期。',
        };
      }
      return {
        ruleId: 'remote-exec', evaluation: 'matched',
        detail: `用 ${tool} 在本机与远程之间传输/同步文件：${trunc(effectiveDisplayArgv(command).slice(1).join(' '))}`,
        why: '传输会覆盖目标路径的同名文件，请确认方向（谁覆盖谁）和路径。',
      };
    }

    if (enabled('recursive-delete') && isCommand(command, 'rm') && hasRecursiveFlag(command.argv)) {
      const targets = commandTargets(command).map((target) => target.display).join(' ');
      return {
        ruleId: 'recursive-delete', evaluation: 'matched',
        detail: `递归删除：${trunc(targets) || '(未解析出目标)'}`,
        why: '删除不可逆，请确认路径正确、通配符不会扩大到预期之外。',
      };
    }

    if (enabled('force-push') && forcePush(command)) {
      return {
        ruleId: 'force-push', evaluation: 'matched',
        detail: `force push：${trunc(displayCommand(command))}`,
        why: '会覆盖远端分支历史，协作者基于旧历史的提交会被破坏，请确认分支正确且无人依赖旧历史。',
      };
    }

    const sqlCommand = ['psql', 'mysql', 'mysqlsh', 'sqlite3'].includes(commandName(command));
    const sql = sqlCommand && command.argv.find((arg) => typeof arg === 'string' &&
      /(?:DROP\s+(?:TABLE|DATABASE|SCHEMA)|TRUNCATE\s+(?:TABLE\s+)?\w+)/i.test(arg));
    if (typeof sql === 'string' && enabled('destructive-sql')) {
      const match = sql.match(/(?:DROP\s+(?:TABLE|DATABASE|SCHEMA)|TRUNCATE\s+(?:TABLE\s+)?\w+)[^;]*/i);
      return {
        ruleId: 'destructive-sql', evaluation: 'matched',
        detail: `执行破坏性 SQL：${trunc(match?.[0] ?? sql)}`,
        why: '表结构或数据会被删除且通常没有回收站，请确认目标库和表名。',
      };
    }
    const dynamicSql = sqlCommand &&
      command.argv.some((arg, index) => (arg === '-c' || arg === '-e') && command.argv[index + 1] === null);
    const dynamicSqlitePositional = isCommand(command, 'sqlite3') &&
      commandTargets(command).slice(1).some((target) => target.value === null);
    if ((dynamicSql || dynamicSqlitePositional) && enabled('dynamic-sql')) {
      return {
        ruleId: 'dynamic-sql', evaluation: 'unknown',
        detail: '执行内容无法静态还原的 SQL',
        why: 'SQL 执行参数是动态值，无法确认是否包含 DROP/TRUNCATE，需要人工确认。',
      };
    }

    if (enabled('chmod-777') && isCommand(command, 'chmod') && command.argv.some((arg) => arg === '777' || arg === '0777')) {
      return {
        ruleId: 'chmod-777', evaluation: 'matched',
        detail: `把 ${trunc(commandTargets(command).map((target) => target.display).join(' ')) || '目标文件'} 的权限改为 777（所有用户可读写执行）`,
        why: '会移除文件的访问保护，请确认确有必要、范围没有过大。',
      };
    }

    const apiDelete = ghApiDelete(command);
    if (apiDelete?.level === 'sensitive' && enabled('gh-api-delete-sensitive')) {
      return {
        ruleId: 'gh-api-delete-sensitive', evaluation: 'matched',
        detail: `GitHub API 删除部署密钥、webhook、Actions secret 或 environment（${trunc(apiDelete.endpoint)}）`,
        why: '这些配置删除后需要重新生成或找回凭据，CI/部署会立即失效，请确认目标。',
      };
    }
    if (apiDelete?.level === 'other' && enabled('gh-api-delete')) {
      return {
        ruleId: 'gh-api-delete', evaluation: 'matched',
        detail: `GitHub API 删除操作：${trunc(displayCommand(command))}`,
        why: 'GitHub API DELETE 通常不可恢复，请确认 endpoint 与目标资源无误。',
      };
    }

    const resetRef = hardResetRef(command);
    if (typeof resetRef === 'string') {
      const trunk = /^(?:(?:origin|upstream)\/)?(?:main|master)$/.test(resetRef);
      if (trunk || /^origin\//.test(resetRef)) {
        const ruleId = trunk ? 'reset-hard-main' : 'reset-hard-remote';
        if (enabled(ruleId)) {
          return {
            ruleId, evaluation: 'matched',
            detail: `把当前分支硬重置到 ${resetRef}`,
            why: '本地未推送的提交和工作区改动会被丢弃，请先确认没有需要保留的工作。',
          };
        }
        // An explicit remote-ref reset is otherwise left to the host approval
        // layer, as in 0.4; full enables reset-hard-remote above.
        if (!trunk) continue;
      }
    }

    const fine = gitRule(command);
    if (fine && enabled(fine)) {
      const text = GIT_RULE_TEXT[fine];
      return {
        ruleId: fine, evaluation: 'matched',
        detail: `${text.detail}：${trunc(displayCommand(command))}`,
        why: text.why,
      };
    }
  }

  /** @type {Map<number, AnalyzedCommand[]>} */
  const pipelineGroups = new Map();
  for (const command of graph.commands) {
    if (command.pipelineGroup === null) continue;
    const group = pipelineGroups.get(command.pipelineGroup) ?? [];
    group.push(command);
    pipelineGroups.set(command.pipelineGroup, group);
  }
  for (const commands of pipelineGroups.values()) {
    const download = commands.find((command) => isCommand(command, 'curl') || isCommand(command, 'wget'));
    const shell = commands.find((command) => ['sh', 'bash', 'zsh', 'dash'].includes(commandName(command)));
    if (download && shell && enabled('curl-pipe-sh')) {
      const url = download.argv.find((arg) => typeof arg === 'string' && /^https?:\/\//.test(arg));
      return {
        ruleId: 'curl-pipe-sh', evaluation: 'matched',
        detail: `下载远程脚本${typeof url === 'string' ? `（${trunc(url)}）` : ''}并直接交给 shell 执行`,
        why: '脚本内容未经审查就以当前用户权限运行，请确认来源可信。',
      };
    }
  }
  return null;
}

/**
 * @typedef {{
 *   kind: 'deny'|'confirm'|'review',
 *   evaluation: 'matched'|'unknown',
 *   ruleId: string,
 *   command: string,
 *   description: string,
 *   detail: string,
 *   why: string,
 *   analysis: ShellGraph,
 * }} GuardDecision
 */
/**
 * @typedef {{
 *   profile?: string,
 *   envShell?: string,
 *   shfmtPath?: string,
 *   zshPath?: string,
 *   timeoutMs?: number,
 *   maxInputBytes?: number,
 *   maxRecursion?: number,
 *   maxCommands?: number,
 *   protectedRoots?: string[],
 *   protectedPaths?: string[],
 *   inspectDirectory?: (directory: string) => ProjectInfo,
 * }} GuardOptions
 */

/** @param {unknown} input @returns {{shellInput: ShellInput|null, command: string, description: string, explicitShell: string}} */
function extractInput(input) {
  if (typeof input !== 'object' || input === null) return { shellInput: null, command: '', description: '', explicitShell: '' };
  const toolInput = /** @type {Record<string, unknown>} */ (input);
  const rawCommand = toolInput.command;
  const description = typeof toolInput.description === 'string' ? toolInput.description : '';
  const explicit = [toolInput.shell, toolInput.shell_path, toolInput.executable].find((value) => typeof value === 'string');
  const explicitShell = typeof explicit === 'string' ? explicit : '';
  if (typeof rawCommand === 'string') {
    return { shellInput: { kind: 'script', text: rawCommand }, command: rawCommand, description, explicitShell };
  }
  if (Array.isArray(rawCommand)) {
    const argv = rawCommand.map(String);
    return { shellInput: { kind: 'argv', argv }, command: argv.join(' '), description, explicitShell };
  }
  return { shellInput: null, command: '', description, explicitShell };
}

/** @param {Record<string, unknown>} event */
export function eventCwd(event) {
  const value = event.cwd;
  return typeof value === 'string' && value.startsWith('/') ? normalizePath(value) : null;
}

/** @param {Record<string, unknown>} event */
export function eventToolInput(event) {
  const value = event.tool_input ?? event.toolInput;
  return typeof value === 'object' && value !== null ? /** @type {Record<string, unknown>} */ (value) : {};
}

/**
 * Evaluate a host hook event without reading process I/O or environment state.
 * A null result means the event is outside this guard's shell-tool scope.
 * An `allow` result means the shell input was analyzed and no enabled rule
 * requested intervention.
 *
 * Hook fields used besides the tool input: `cwd` (relative-path resolution,
 * project lookup), `permission_mode` (tiering), and
 * `tool_input.dangerouslyDisableSandbox`.
 *
 * @param {Record<string, unknown>} event
 * @param {GuardOptions} [options]
 * @returns {GuardDecision|{kind: 'allow', command: string, description: string, analysis: ShellGraph}|null}
 */
export function evaluateHookEvent(event, options = {}) {
  const toolName = String(event.tool_name ?? event.toolName ?? '');
  if (!/^(Bash|shell|local_shell|exec_command|run_terminal_command)$/i.test(toolName)) return null;
  const toolInput = eventToolInput(event);
  const { shellInput, command, description, explicitShell } = extractInput(toolInput);
  if (!shellInput) return null;
  const dialect = selectShellDialect({ toolName, explicitShell, envShell: options.envShell });
  const analysis = analyzeShellInput(shellInput, {
    dialect,
    shfmtPath: options.shfmtPath,
    zshPath: options.zshPath,
    timeoutMs: options.timeoutMs,
    maxInputBytes: options.maxInputBytes,
    maxRecursion: options.maxRecursion,
    maxCommands: options.maxCommands,
  });
  const profile = resolvePolicyProfile(options.profile);
  const tier = permissionTier(event.permission_mode ?? event.permissionMode);
  const enabled = (/** @type {string} */ ruleId) => isPolicyEnabled(ruleId, profile, tier);
  const cwd = eventCwd(event);
  /** @type {RuleContext} */
  const ctx = {
    tier,
    cwd,
    trustedCwd: analysis.commands.some((item) => CWD_CHANGING.has(commandName(item))) ? null : cwd,
    unsandboxed: toolInput.dangerouslyDisableSandbox === true,
    protectedRoots: options.protectedRoots ?? ['/'],
    protectedPaths: options.protectedPaths ?? [],
    inspect: memoizeInspector(options.inspectDirectory ?? ((directory) => inspectDirectory(directory))),
  };

  const hard = hardPolicy(analysis, enabled, ctx);
  if (hard) return { kind: 'deny', command, description, analysis, ...hard };

  const infrastructureFailure = analysis.unknowns.find((item) =>
    ['parser-missing', 'parser-timeout', 'parser-output-invalid'].includes(item.reason));
  if (infrastructureFailure) {
    return {
      kind: 'deny', evaluation: 'unknown', ruleId: 'guard-unavailable', command, description, analysis,
      detail: `shell parser 不可用（${infrastructureFailure.reason}）`,
      why: 'guard 无法建立可靠的 command graph；基础设施故障不受 policy profile 放宽，必须 fail-closed。',
    };
  }

  if (tier === 'bypass' && enabled('bypass-no-project-sandbox')) {
    const project = cwd ? ctx.inspect(cwd) : null;
    if (!project?.sandboxConfigured && !isReadOnlyGraph(analysis)) {
      const where = project?.gitRoot ?? cwd ?? '(hook 未提供 cwd)';
      return {
        kind: 'deny', evaluation: 'matched', ruleId: 'bypass-no-project-sandbox', command, description, analysis,
        detail: `bypass 会话所在项目（${where}）没有项目沙盒配置，拒绝写类命令：${trunc(command)}`,
        why: 'bypass 只能在配好项目沙盒的项目里用；先配 .claude/settings.json 或切 auto。（判定：会话 cwd 所在 git 根的 .claude/settings.json + settings.local.json 需有 sandbox.enabled: true，或未禁用且 sandbox.filesystem.allowWrite 非空；/tmp、scratchpad 不算项目。只读命令不受影响。）',
      };
    }
  }

  if (analysis.status === 'unknown' && enabled('shell-analysis-unknown')) {
    const reasons = analysis.unknowns.map((item) => item.reason).join(', ') || 'unknown';
    const hardUnknownReasons = new Set(['dynamic-command', 'dynamic-evaluator', 'input-too-large', 'recursion-limit', 'command-limit']);
    const kind = analysis.unknowns.some((item) => hardUnknownReasons.has(item.reason)) ? 'deny' : 'confirm';
    return {
      kind, evaluation: 'unknown', ruleId: 'shell-analysis-unknown', command, description, analysis,
      detail: `shell 结构无法静态确认（${reasons}）：${trunc(command)}`,
      why: kind === 'deny'
        ? '无法证明动态执行内容没有隐藏硬禁区，guard 按 fail-closed 拒绝。'
        : 'parser 无法确认执行结构，需要外部确认后再继续。',
    };
  }

  const outside = enabled('unsandboxed-outside-project') ? unsandboxedOutsideProject(analysis, ctx) : null;
  if (outside) return { kind: 'confirm', command, description, analysis, ...outside };

  const confirmation = confirmationPolicy(analysis, enabled);
  if (confirmation) {
    const kind = confirmation.ruleId === 'git-low-risk' ? 'review' : 'confirm';
    return { kind, command, description, analysis, ...confirmation };
  }
  return { kind: 'allow', command, description, analysis };
}

/** @param {GuardDecision} result */
function decisionReasons(result) {
  return result.ruleId === 'shell-analysis-unknown'
    ? [...new Set(result.analysis.unknowns.map((item) => item.reason))].sort()
    : [];
}

/** @param {GuardDecision} result */
export function explainGuardDecision(result) {
  const reasons = decisionReasons(result);
  const fields = [
    `触发规则: ${result.ruleId}`,
    `匹配状态: ${result.evaluation}`,
    ...(reasons.length ? [`分析原因: ${reasons.join(', ')}`] : []),
    `处置: ${result.kind}`,
    `规则依据: ${result.why}`,
  ];
  const prefix = result.kind === 'deny' ? `已拒绝：${result.detail}。` : `需要确认：${result.detail}。`;
  return `${prefix}（${fields.join('；')}）`;
}
