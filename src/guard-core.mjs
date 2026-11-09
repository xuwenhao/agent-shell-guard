// @ts-check
// Host-independent shell guard core.
//
// Shell syntax is parsed by the pinned shfmt AST analyzer. Policy rules only
// inspect normalized command argv or one already-parsed data argument; they do
// not infer quoting, command boundaries, or evaluator semantics with regex.
// Path comparisons are lexical (the hook `cwd` is joined literally); the only
// filesystem access is the read-only project inspection in ./project.mjs,
// used for bypass-mode checks, for spotting a thin project root and for
// resolving `HEAD` / `@{u}` in push and reset rules.

import { homedir } from 'node:os';
import { basename } from 'node:path';

import { analyzeShellInput, cdArgvOperand, selectShellDialect, shellEvaluator, unwrapCommand } from './shell-analyzer.mjs';
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
  expandTargetWord,
  firstGlobIndex,
  foldCase,
  globCovers,
  isAncestorOrSelf,
  normalizePath,
  resolveTarget,
  segmentMatches,
  setCaseInsensitivePaths,
  targetCovers,
  targetSegments,
} from './path-targets.mjs';
import { inspectDirectory, inspectProjectDir, memoizeInspector } from './project.mjs';
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
 *   cwdsFor: (command: AnalyzedCommand) => Array<string|null>,
 *   projectDir: string|null,
 *   unsandboxed: boolean,
 *   protectedRoots: string[],
 *   protectedPaths: string[],
 *   inspect: (directory: string) => ProjectInfo,
 *   inspectProject: (directory: string) => ProjectInfo,
 * }} RuleContext
 */
/** @typedef {{value: string|null, display: string}} TargetWord */

const TRUNK_REF = /^(?:refs\/heads\/)?(?:main|master)$/;
const CWD_CHANGING = new Set(['cd', 'chdir', 'pushd', 'popd', 'source', '.']);
const CD_LIKE = new Set(['cd', 'chdir', 'pushd']);

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
 * Run a path check in every directory a command may run in. 'matched' when
 * every candidate matches, 'unknown' when only some do (or one is unknown).
 * @param {Array<string|null>} cwds
 * @param {(cwd: string|null) => 'matched'|'unknown'|null} check
 * @returns {'matched'|'unknown'|null}
 */
function acrossCwds(cwds, check) {
  let hits = 0;
  let matched = 0;
  for (const directory of cwds) {
    const result = check(directory);
    if (result) hits++;
    if (result === 'matched') matched++;
  }
  if (hits === 0) return null;
  return matched === cwds.length ? 'matched' : 'unknown';
}

/**
 * zsh glob qualifiers (`*(D)`, `*(.N)`) select among the matches; they never
 * narrow a pattern to fewer names than it already matches without them, so
 * they are dropped before judging the pattern.
 * @param {string} display @param {string|undefined} dialect
 */
const withoutGlobQualifier = (display, dialect) =>
  dialect === 'zsh' ? display.replace(/\([^()/'"]*\)$/, '') : display;

/**
 * @param {TargetWord} target
 * @param {string[]} paths
 * @param {string|null} cwd trusted cwd
 * @param {{ancestors: boolean, dynamicMatches: boolean, dialect?: string}} options
 * @returns {'matched'|'unknown'|null}
 */
function targetHitsProtected(target, paths, cwd, options) {
  if (target.value !== null) {
    const resolved = resolveTarget(target.value, cwd);
    if (!paths.some((path) => targetCovers(resolved, path, { ancestors: options.ancestors }))) return null;
    return resolved.kind === 'absolute' ? 'matched' : 'unknown';
  }
  // Globs and brace expansions: every alternative is checked.
  const word = expandTargetWord(withoutGlobQualifier(target.display, options.dialect), cwd);
  if (word === null) return options.dynamicMatches ? 'unknown' : null;
  if ('overflow' in word) {
    // Too many alternatives to list; a `..` after the brace can climb
    // anywhere, so only the literal prefix bounds nothing.
    if (word.climbs) return 'unknown';
    const prefix = word.overflow;
    return paths.some((path) => targetCovers(prefix, path, { ancestors: true })) ? 'unknown' : null;
  }
  /** @type {'matched'|'unknown'|null} */
  let result = null;
  for (const candidate of word.candidates) {
    if (candidate.kind === 'static') {
      if (!paths.some((path) => targetCovers(candidate.target, path, { ancestors: options.ancestors }))) continue;
      if (candidate.target.kind === 'absolute') return 'matched';
      result = 'unknown';
    } else if (paths.some((path) => globCovers(candidate.glob, path))) {
      result = 'unknown';
    }
  }
  return result;
}

/** @param {string} segment */
const isGitSegment = (segment) => foldCase(segment) === '.git';

/** @param {string} segment */
const isLiteralSegment = (segment) => firstGlobIndex(segment) < 0;

/**
 * Paths inside `.git` that are routinely removed to recover or clean up and
 * hold no history of their own: a submodule's or linked worktree's admin
 * directory (`modules/<name>`, `worktrees/<name>`), an interrupted rebase's
 * state, and stale `*.lock` files. `.git` itself, `objects`, `refs`, `modules`
 * as a whole and everything else stay protected.
 * @param {string[]} rest segments after `.git`
 */
function gitDirTailRecoverable(rest) {
  if (rest.length === 0) return false;
  if (foldCase(rest[rest.length - 1]).endsWith('.lock')) return true;
  if (!isLiteralSegment(rest[0])) return false;
  const first = foldCase(rest[0]);
  if ((first === 'modules' || first === 'worktrees') && rest.length >= 2) return true;
  return first === 'rebase-merge' || first === 'rebase-apply';
}

/**
 * @param {string[]} segments
 * @param {(segment: string) => boolean} isGit
 */
function segmentsDeleteGitDir(segments, isGit) {
  const index = segments.findIndex(isGit);
  return index >= 0 && !gitDirTailRecoverable(segments.slice(index + 1));
}

/**
 * Any segment of the target is `.git`: the directory itself, or anything
 * inside it (`.git/objects`, `.git/refs`), or a glob that matches it —
 * except the recoverable paths of gitDirTailRecoverable.
 * @param {TargetWord} target
 */
function targetIsGitDir(target) {
  if (target.value !== null) return segmentsDeleteGitDir(targetSegments(resolveTarget(target.value, null)), isGitSegment);
  const word = expandTargetWord(target.display, null);
  if (word === null || 'overflow' in word) return false;
  return word.candidates.some((candidate) => candidate.kind === 'static'
    ? segmentsDeleteGitDir(targetSegments(candidate.target), isGitSegment)
    : segmentsDeleteGitDir([...targetSegments(candidate.glob.prefix), ...candidate.glob.pattern],
      (segment) => isGitSegment(segment) || (!isLiteralSegment(segment) && segmentMatches(segment, '.git'))));
}

// --- find ----------------------------------------------------------------------

const FIND_NAME_TESTS = new Set(['-name', '-iname', '-lname', '-ilname']);
const FIND_PATH_TESTS = new Set(['-path', '-ipath', '-wholename', '-iwholename', '-regex', '-iregex']);

/**
 * `find` start paths, name/path tests and whether it deletes what it finds
 * (`-delete`, or `-exec`/`-execdir`/`-ok` running a recursive `rm`).
 * @param {AnalyzedCommand} command
 */
function parseFind(command) {
  if (!['find', 'gfind'].includes(commandName(command))) return null;
  const argv = command.argv;
  const display = effectiveDisplayArgv(command);
  let index = 1;
  while (index < argv.length && typeof argv[index] === 'string' && /^-(?:[HLP]|O\d*)$/.test(/** @type {string} */ (argv[index]))) index++;
  if (argv[index] === '-D') index += 2;
  /** @type {TargetWord[]} */
  const starts = [];
  for (; index < argv.length; index++) {
    const arg = argv[index];
    if (typeof arg === 'string' && (arg.startsWith('-') || arg === '(' || arg === '!')) break;
    starts.push({ value: arg, display: arg ?? display[index] ?? '<?>' });
  }
  if (starts.length === 0) starts.push({ value: '.', display: '.' });
  /** @type {Array<{test: string, value: string|null}>} */
  const tests = [];
  let deletes = false;
  let negated = false;
  for (; index < argv.length; index++) {
    const arg = argv[index];
    if (typeof arg !== 'string') { negated = false; continue; }
    if (arg === '!' || arg === '-not') { negated = true; continue; }
    if (FIND_NAME_TESTS.has(arg) || FIND_PATH_TESTS.has(arg)) {
      const value = argv[++index] ?? null;
      // `-not -path './.git/*'` excludes; only positive tests select. Dropping
      // a negated test can only make the find look broader.
      if (!negated) tests.push({ test: arg, value });
      negated = false;
      continue;
    }
    negated = false;
    if (arg === '-delete') { deletes = true; continue; }
    if (['-exec', '-execdir', '-ok', '-okdir'].includes(arg)) {
      /** @type {Array<string|null>} */
      const sub = [];
      for (index++; index < argv.length && argv[index] !== ';' && argv[index] !== '+'; index++) sub.push(argv[index]);
      // `-exec command rm -rf {}`, `-exec env rm …`, `-exec sudo rm …`
      const { argv: inner } = unwrapCommand(sub);
      if (typeof inner[0] === 'string' && basename(inner[0]) === 'rm' && hasRecursiveFlag(inner)) deletes = true;
      if (inner[0] === null || sub[0] === null) deletes = true;
      // `-exec sh -c 'rm -rf "$1"' _ {} \;`: whatever the script does, it gets
      // each match as an argument.
      if (shellEvaluator(inner)) deletes = true;
    }
  }
  return { starts, tests, deletes };
}

/**
 * Could a deleting find (or `find … | xargs rm -r`) remove a protected root?
 * Only when a start path is the root or one of its ancestors, and the name
 * tests (if any) could select the root or a directory on the way down to it.
 * @param {{starts: TargetWord[], tests: Array<{test: string, value: string|null}>}} find
 * @param {string[]} paths @param {string|null} cwd
 * @returns {{target: TargetWord, evaluation: 'matched'|'unknown'}|null}
 */
function findHitsProtected(find, paths, cwd) {
  for (const start of find.starts) {
    if (start.value === null) return { target: start, evaluation: 'unknown' };
    const resolved = resolveTarget(start.value, cwd);
    for (const path of paths) {
      if (!targetCovers(resolved, path, { ancestors: true })) continue;
      const evaluation = resolved.kind === 'absolute' ? 'matched' : 'unknown';
      if (find.tests.length === 0) return { target: start, evaluation };
      const root = normalizePath(expandHome(path));
      const rootSegments = root === '/' ? [] : root.slice(1).split('/');
      const below = resolved.kind === 'absolute'
        ? (resolved.path === root ? rootSegments.slice(-1) : rootSegments.slice(targetSegments(resolved).length))
        : rootSegments;
      const reaches = find.tests.some((test) => test.value === null || FIND_PATH_TESTS.has(test.test) ||
        below.some((segment) => segmentMatches(test.value ?? '*', segment, { dotRule: false })));
      if (reaches) return { target: start, evaluation: 'unknown' };
    }
  }
  return null;
}

/**
 * A deleting find whose start path or name/path tests select `.git`.
 * @param {ReturnType<typeof parseFind>} find
 */
function findDeletesGitDir(find) {
  if (!find?.deletes) return false;
  if (find.starts.some((start) => start.value !== null && targetSegments(resolveTarget(start.value, null)).some(isGitSegment))) return true;
  return find.tests.some((test) => typeof test.value === 'string' && (FIND_NAME_TESTS.has(test.test)
    ? segmentMatches(test.value, '.git', { dotRule: false })
    : /(?:^|[/*])\\?\.git(?:[/*$]|$)/i.test(test.value)));
}

/**
 * `xargs rm -r…` deletes whatever the pipeline feeds it; when a `find` in the
 * same pipeline produces the list, judge it like a deleting find.
 * @param {AnalyzedCommand} command @param {ShellGraph} graph
 */
function xargsRmSource(command, graph) {
  if (!command.wrappers.includes('xargs') || !isCommand(command, 'rm') || !hasRecursiveFlag(command.argv)) return null;
  if (command.pipelineGroup === null) return null;
  for (const other of graph.commands) {
    if (other === command || other.pipelineGroup !== command.pipelineGroup) continue;
    const find = parseFind(other);
    if (find) return find;
    // `echo <paths> | xargs rm -rf` deletes exactly those paths.
    if (['echo', 'printf'].includes(commandName(other))) {
      const starts = commandTargets(other);
      if (starts.length) return { starts, tests: [], deletes: true };
    }
  }
  return null;
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
  let orphan = false;
  let detach = false;
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
      if (name === '--orphan') { createTarget = operand ?? git.args[++index] ?? null; orphan = true; }
      else if (name === '--detach') detach = true;
      // Negations undo an earlier option instead of adding a mode of their own.
      else if (isLongOption(name, '--no-detach') && name.length >= '--no-d'.length) detach = false;
      else if (isLongOption(name, '--no-orphan') && name.length >= '--no-or'.length) {
        if (orphan) createTarget = undefined;
        orphan = false;
      } else if (operand === undefined && LONG_WITH_OPERAND.has(name)) index++;
      continue;
    }
    if (raw.startsWith('-') && raw.length > 1) {
      const cluster = raw.slice(1);
      for (let cursor = 0; cursor < cluster.length; cursor++) {
        const letter = cluster[cursor];
        letters.push(letter);
        if (letter === 'd') detach = true;
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
  return { flags, letters, positionals, createTarget, forceCreate, orphan, detach };
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
  // `--orphan main` starts a new, parentless `main` when none exists (a fresh
  // clone, or right after deleting the local branch).
  if ((parsed.forceCreate || parsed.orphan) && mayNameTrunk(parsed.createTarget)) return 'git-trunk-ref';
  if (git.args.some((arg) => arg === null)) return 'git-discard';
  if (parsed.flags.includes('--')) return 'git-discard';
  // `--pathspec-from-file <file>` restores every path listed in the file, which
  // is a working-tree discard with no positional argument to notice it by.
  if (parsed.flags.some((flag) => isLongOption(flag, '--pathspec-from-file'))) return 'git-discard';
  const forceish = parsed.flags.some((flag) =>
    ['--force', '--ours', '--theirs', '--merge', '--conflict', '--patch', '--overwrite-ignore']
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
  const refIntent = ['--track', '--no-track'];
  if (parsed.detach || parsed.flags.some((flag) => refIntent.includes(flag)) ||
      parsed.letters.some((letter) => letter === 't')) {
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
    const orphanIndex = args.findIndex((arg) => isLongOption(arg, '--orphan') && /** @type {string} */ (arg).length >= '--or'.length);
    if (orphanIndex >= 0) {
      const flag = /** @type {string} */ (args[orphanIndex]);
      const target = flag.includes('=') ? flag.slice(flag.indexOf('=') + 1) : args[orphanIndex + 1] ?? null;
      if (mayNameTrunk(target)) return 'git-trunk-ref';
    }
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
    const options = pushOptions(args);
    if (options.prune) return 'git-push-bulk';
    return options.delete || args.some((arg) => typeof arg === 'string' && /^\+?:\S+/.test(arg))
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

const TRUNK_SPELLINGS = /^(?:refs\/remotes\/[^/]+\/|remotes\/[^/]+\/|refs\/heads\/|(?:origin|upstream)\/)?(?:main|master)$/;
const UPSTREAM_REF = /^(.*)@\{(?:u|upstream|push)\}$/i;

/**
 * Does a `reset --hard` target name the trunk? Covers `main`,
 * `origin/main`, `refs/remotes/<remote>/main`, `refs/heads/main`, and an
 * `@{u}` / `<branch>@{upstream}` whose configured upstream is the trunk.
 * @param {string} ref @param {AnalyzedCommand} command @param {RuleContext} ctx
 */
function resetRefIsTrunk(ref, command, ctx) {
  if (TRUNK_SPELLINGS.test(ref)) return true;
  const upstream = UPSTREAM_REF.exec(ref);
  if (!upstream) return false;
  const git = parseGitCommand(command);
  const directory = git ? gitWorkDir(git, ctx.trustedCwd) : null;
  if (directory === null) return false;
  const info = ctx.inspect(directory);
  const named = upstream[1] === '' || upstream[1] === 'HEAD' || upstream[1] === '@' ? info.branch : upstream[1];
  if (typeof named !== 'string' || named !== info.branch || !info.upstream) return false;
  return /^(?:refs\/heads\/)?(?:main|master)$/.test(info.upstream.merge);
}

const PUSH_VALUE_OPTIONS = ['--repo', '--receive-pack', '--exec', '--push-option'];

/**
 * `git push` options in order. Short clusters stop at `o`, whose operand is
 * the rest of the word (`-onone` is a push option, not `-n`); `--dry-run` and
 * `--no-dry-run` take the last one given.
 * @param {Array<string|null>} args
 */
function pushOptions(args) {
  const options = { force: false, dryRun: false, delete: false, all: false, mirror: false, prune: false, tags: false };
  for (let index = 0; index < args.length; index++) {
    const arg = args[index];
    if (typeof arg !== 'string') continue;
    if (arg === '--') break;
    if (arg.startsWith('--')) {
      if (!arg.includes('=') && PUSH_VALUE_OPTIONS.some((option) => isLongOption(arg, option) && arg.length >= 4)) { index++; continue; }
      if (isLongOption(arg, '--force') || isLongOption(arg, '--force-with-lease')) options.force = true;
      else if (isLongOption(arg, '--dry-run')) options.dryRun = true;
      else if (isLongOption(arg, '--no-dry-run') && arg.length >= '--no-d'.length) options.dryRun = false;
      else if (isLongOption(arg, '--delete')) options.delete = true;
      else if (isLongOption(arg, '--all') || isLongOption(arg, '--branches')) options.all = true;
      else if (isLongOption(arg, '--mirror')) options.mirror = true;
      else if (isLongOption(arg, '--prune')) options.prune = true;
      else if (isLongOption(arg, '--tags')) options.tags = true;
      continue;
    }
    if (!arg.startsWith('-') || arg === '-') continue;
    const cluster = arg.slice(1);
    for (let cursor = 0; cursor < cluster.length; cursor++) {
      const letter = cluster[cursor];
      if (letter === 'o') { if (cursor === cluster.length - 1) index++; break; }
      if (letter === 'f') options.force = true;
      if (letter === 'n') options.dryRun = true;
      if (letter === 'd') options.delete = true;
    }
  }
  return options;
}

/** @param {AnalyzedCommand} command */
function forcePush(command) {
  const git = parseGitCommand(command);
  if (git?.subcommand !== 'push') return false;
  if (pushOptions(git.args).force) return true;
  return pushPositionals(command).some((ref) => /^\+\S*/.test(ref.display) && ref.display !== '+');
}

/** @param {AnalyzedCommand} command @returns {Array<{value: string|null, display: string}>} */
function pushPositionals(command) {
  const git = parseGitCommand(command);
  if (git?.subcommand !== 'push') return [];
  const display = effectiveDisplayArgv(command).slice(git.argOffset);
  const valueFlags = new Set([...PUSH_VALUE_OPTIONS, '-o']);
  /** @type {Array<{value: string|null, display: string}>} */
  const positionals = [];
  let options = true;
  for (let index = 0; index < git.args.length; index++) {
    const arg = git.args[index];
    const token = arg ?? display[index] ?? '<?>';
    if (options && token === '--') { options = false; continue; }
    if (options && token.startsWith('-')) {
      if (valueFlags.has(token)) index++;
      else if (!token.startsWith('--') && /^-[^o]*o$/.test(token)) index++;
      continue;
    }
    positionals.push({ value: arg, display: token });
  }
  return positionals;
}

/** @param {AnalyzedCommand} command */
const pushRefs = (command) => pushPositionals(command).slice(1);

/** @param {string|null} value */
const isHeadRef = (value) => typeof value === 'string' && /^\+?(?:HEAD|@)$/.test(value);

/**
 * Which ref a force push rewrites, as far as the argv and the repository's
 * HEAD tell. `matched`: main/master (explicitly, via `--all`/`--branches`,
 * or via `HEAD`/`@`/no refspec while main is checked out). `unknown`: a
 * dynamic refspec, a detached or unreadable HEAD, or a branch whose upstream
 * is the trunk (push.default=upstream would push it there).
 * @param {AnalyzedCommand} command @param {RuleContext} ctx
 * @returns {'matched'|'unknown'|null}
 */
function forcePushTarget(command, ctx) {
  const git = parseGitCommand(command);
  if (!git) return null;
  if (pushOptions(git.args).all) return 'matched';
  const refs = pushRefs(command);
  if (refs.some((ref) => ref.value !== null && isProtectedRef(ref.value))) return 'matched';
  // `:` / `+:` push every matching branch; a `*` refspec pushes a whole
  // namespace — both include main/master like `--all`.
  if (refs.some((ref) => ref.value !== null && (/^\+?:$/.test(ref.value) || ref.value.includes('*')))) return 'matched';
  if (refs.some((ref) => ref.value === null)) return 'unknown';
  const usesHead = refs.length === 0 ? !pushOptions(git.args).tags : refs.some((ref) => isHeadRef(ref.value));
  if (!usesHead) return null;
  // Without a refspec, `-c push.default=…` / `-c remote.<name>.push=…` decide
  // what is pushed.
  if (refs.length === 0 && gitGlobalConfigs(command, git).some((entry) => /^(?:push|remote)\./i.test(entry))) return 'unknown';
  const directory = gitWorkDir(git, ctx.trustedCwd);
  if (directory === null) return 'unknown';
  const info = ctx.inspect(directory);
  if (typeof info.branch !== 'string') return 'unknown';
  if (TRUNK_REF.test(info.branch)) return 'matched';
  if (refs.length === 0 && info.upstream && /^(?:refs\/heads\/)?(?:main|master)$/.test(info.upstream.merge)) return 'unknown';
  return null;
}

/** @param {AnalyzedCommand} command */
function pushMirror(command) {
  const git = parseGitCommand(command);
  if (git?.subcommand !== 'push') return false;
  const options = pushOptions(git.args);
  return options.mirror && !options.dryRun;
}

/**
 * Values of git's global `-c key=value` / `-ckey=value` options.
 * @param {AnalyzedCommand} command @param {{argOffset: number}} git
 */
function gitGlobalConfigs(command, git) {
  const globals = command.argv.slice(1, git.argOffset - 1);
  /** @type {string[]} */
  const entries = [];
  for (let index = 0; index < globals.length; index++) {
    const arg = globals[index];
    if (arg === '-c') { const value = globals[++index]; entries.push(typeof value === 'string' ? value : ''); }
    else if (typeof arg === 'string' && /^-c./.test(arg)) entries.push(arg.slice(2));
  }
  return entries;
}

/** @param {AnalyzedCommand} command @param {RuleContext} ctx @returns {'matched'|'unknown'|null} */
function pushDeletesTrunk(command, ctx) {
  const git = parseGitCommand(command);
  if (git?.subcommand !== 'push') return null;
  const options = pushOptions(git.args);
  if (options.dryRun) return null;
  const emptySource = /^\+?:(?:refs\/heads\/)?(?:main|master)$/;
  if (pushPositionals(command).some((ref) => typeof ref.value === 'string' && emptySource.test(ref.value))) return 'matched';
  if (!options.delete) return null;
  const refs = pushRefs(command);
  if (refs.some((ref) => typeof ref.value === 'string' && TRUNK_REF.test(ref.value.replace(/^\+/, '')))) return 'matched';
  if (refs.some((ref) => ref.value === null)) return 'unknown';
  if (!refs.some((ref) => isHeadRef(ref.value))) return null;
  const directory = gitWorkDir(git, ctx.trustedCwd);
  const branch = directory === null ? undefined : ctx.inspect(directory).branch;
  if (typeof branch !== 'string') return 'unknown';
  return TRUNK_REF.test(branch) ? 'matched' : null;
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

/** `gh [-R owner/repo] repo delete …` @param {AnalyzedCommand} command */
function ghRepoDelete(command) {
  if (!isCommand(command, 'gh')) return false;
  let index = 1;
  while (typeof command.argv[index] === 'string' && /** @type {string} */ (command.argv[index]).startsWith('-')) {
    index += ['-R', '--repo', '--hostname'].includes(/** @type {string} */ (command.argv[index])) ? 2 : 1;
  }
  return command.argv[index] === 'repo' && command.argv[index + 1] === 'delete';
}

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
  // A dynamic endpoint with DELETE may be the repository itself.
  if (value === null && isDelete) return { level: 'protected', evaluation: 'unknown', endpoint: api.endpoint?.display ?? '<?>' };
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
  for (const command of graph.commands) {
    const cwds = ctx.cwdsFor(command);
    const dialect = command.dialect;
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

    if (enabled('gh-repo-delete') && ghRepoDelete(command)) {
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
    const find = parseFind(command);
    if (findDeletesGitDir(find) && enabled('rm-git-dir')) {
      return {
        ruleId: 'rm-git-dir', evaluation: 'matched',
        detail: `find 删除 git 元数据目录：${trunc(displayCommand(command))}`,
        why: '删除 .git 会丢掉全部本地提交、分支、stash 和 reflog，无法从工作区恢复。确需重建仓库请交给用户。',
      };
    }
    const findSource = find?.deletes ? find : xargsRmSource(command, graph);
    if (findSource && enabled('rm-protected-root')) {
      /** @type {{target: TargetWord, evaluation: 'matched'|'unknown'}|null} */
      let hit = null;
      const evaluation = acrossCwds(cwds, (directory) => {
        const found = findHitsProtected(findSource, ctx.protectedRoots, directory);
        if (found) hit ??= found;
        return found?.evaluation ?? null;
      });
      if (hit && evaluation) {
        hit = { target: /** @type {{target: TargetWord}} */ (hit).target, evaluation };
        return {
          ruleId: 'rm-protected-root', evaluation: hit.evaluation,
          detail: `${find ? 'find 删除' : 'find | xargs rm 删除'}范围覆盖受保护根目录：${trunc(displayCommand(command))}`,
          why: '起点是受保护根目录或其上级，且名字条件可能选中受保护目录本身，执行后整棵树不可恢复。改法：起点写到具体子目录，或用 -name 精确限定。',
        };
      }
    }
    if (rmRecursive) {
      const targets = commandTargets(command);
      const gitDir = targets.find(targetIsGitDir);
      if (gitDir && enabled('rm-git-dir')) {
        return {
          ruleId: 'rm-git-dir', evaluation: 'matched',
          detail: `递归删除 git 元数据目录 ${gitDir.display}`,
          why: '删除 .git（或其中的 objects/refs 等）会丢掉本地提交、分支、stash 和 reflog，无法从工作区恢复。确需重建仓库请交给用户。',
        };
      }
      /** @type {{target: {display: string}, evaluation: 'matched'|'unknown'}|null} */
      let hit = null;
      for (const target of targets) {
        const evaluation = acrossCwds(cwds, (directory) =>
          targetHitsProtected(target, ctx.protectedRoots, directory, { ancestors: true, dynamicMatches: true, dialect }));
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

    // `git worktree remove` deletes the worktree directory, ignored files
    // included; on a protected root that is a recursive delete.
    const worktreeGit = parseGitCommand(command);
    if (worktreeGit?.subcommand === 'worktree' && worktreeGit.args[0] === 'remove' && enabled('rm-protected-root')) {
      /** @type {TargetWord|null} */
      let removed = null;
      const evaluation = acrossCwds(cwds, (directory) => {
        let result = /** @type {'matched'|'unknown'|null} */ (null);
        for (const target of relocatingTargets(command, directory)) {
          // A dynamic target is not judged: worktree remove refuses the main
          // worktree and only deletes registered linked worktrees.
          const hit = targetHitsProtected(target, ctx.protectedRoots, target.base, { ancestors: true, dynamicMatches: false, dialect });
          if (hit) { removed ??= target; result = result === 'matched' ? result : hit; }
        }
        return result;
      });
      if (evaluation && removed) {
        return {
          ruleId: 'rm-protected-root', evaluation,
          detail: `git worktree remove 删除受保护根目录 ${/** @type {TargetWord} */ (removed).display}`,
          why: 'worktree remove 会连同未跟踪和被忽略的文件删除整个 worktree 目录；目标是受保护根目录（或无法确定）时等同递归删除它。确需移除请交给用户。',
        };
      }
    }

    const rsyncDelete = isCommand(command, 'rsync') && command.argv.some((arg) => typeof arg === 'string' && arg.startsWith('--delete'));
    if (rsyncDelete && enabled('rm-protected-root')) {
      const destination = commandTargets(command).at(-1);
      const remote = typeof destination?.value === 'string' && /^[^/]*:/.test(destination.value);
      const evaluation = destination && !remote
        ? acrossCwds(cwds, (directory) =>
          targetHitsProtected(destination, ctx.protectedRoots, directory, { ancestors: true, dynamicMatches: true, dialect }))
        : null;
      if (destination && evaluation) {
        return {
          ruleId: 'rm-protected-root', evaluation,
          detail: `rsync --delete 的目标覆盖受保护根目录 ${destination.display}`,
          why: 'rsync --delete 会删除目标里源端没有的一切，目标是受保护根目录或其上级时等于清空整棵树。改法：目标写到具体子目录。',
        };
      }
    }

    const lnForce = isCommand(command, 'ln') && command.argv.some((arg) => typeof arg === 'string' &&
      (isLongOption(arg, '--force') || shortOptionHas(arg, /f/)));
    if (ctx.protectedPaths.length && enabled('rm-protected-path') &&
        (isCommand(command, 'rm') || isCommand(command, 'unlink') || isCommand(command, 'mv') || lnForce)) {
      const ancestors = rmRecursive || isCommand(command, 'mv');
      const targets = lnForce ? commandTargets(command).slice(-1) : commandTargets(command);
      for (const target of targets) {
        const evaluation = acrossCwds(cwds, (directory) =>
          targetHitsProtected(target, ctx.protectedPaths, directory, { ancestors, dynamicMatches: false, dialect }));
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

    if (pushMirror(command) && enabled('force-push-main')) {
      return {
        ruleId: 'force-push-main', evaluation: 'matched',
        detail: `push --mirror 强制同步全部 refs（${trunc(displayCommand(command))}）`,
        why: '--mirror 会强制覆盖远端所有分支（含 main/master）并删除远端独有的 refs，等同于对主干 force push；主干改动请走 PR 流程。',
      };
    }

    if (forcePush(command)) {
      const target = forcePushTarget(command, ctx);
      if (target && enabled('force-push-main')) {
        return {
          ruleId: 'force-push-main', evaluation: target,
          detail: `force push 到 main/master（${trunc(displayCommand(command))}，含 --force-with-lease / +refspec / HEAD 形式）`,
          why: target === 'matched'
            ? '会重写 main/master 的提交历史，其他人基于旧历史的工作会被破坏；主干改动请走 PR 流程。'
            : 'force push 的目标 ref 无法静态确定（refspec 是变量、HEAD 处于 detached 或读不到、或当前分支的上游是主干），可能是 main/master，必须拒绝。改法：写显式 refspec（如 git push --force-with-lease origin feat/x），即可交给宿主审批。',
        };
      }
    }

    if (pushDeletesTrunk(command, ctx) === 'matched' && enabled('push-delete-trunk')) {
      return {
        ruleId: 'push-delete-trunk', evaluation: 'matched',
        detail: `删除远端主干分支：${trunc(displayCommand(command))}`,
        why: '删除远端 main/master 会让所有协作者和 CI 失去主干；主干只能由人处理。',
      };
    }
  }
  return null;
}

/**
 * Paths a command deletes or moves, each with the directory a relative path
 * is resolved against (`git -C` changes it; null = unknown).
 * @param {AnalyzedCommand} command @param {string|null} cwd
 * @returns {Array<TargetWord & {base: string|null}>}
 */
function relocatingTargets(command, cwd) {
  /** @param {TargetWord[]} targets @param {string|null} [base] */
  const at = (targets, base = cwd) => targets.map((target) => ({ ...target, base }));
  if (isCommand(command, 'rm') && hasRecursiveFlag(command.argv)) return at(commandTargets(command));
  if (isCommand(command, 'mv')) return at(commandTargets(command));
  if (isCommand(command, 'rsync') && command.argv.some((arg) => typeof arg === 'string' && arg.startsWith('--delete'))) {
    const targets = commandTargets(command);
    const destination = targets[targets.length - 1];
    return destination && !(typeof destination.value === 'string' && /^[^/]*:/.test(destination.value)) ? at([destination]) : [];
  }
  const find = parseFind(command);
  if (find?.deletes) return at(find.starts);
  const git = parseGitCommand(command);
  if (git?.subcommand === 'worktree' && (git.args[0] === 'remove' || git.args[0] === 'move')) {
    const display = effectiveDisplayArgv(command).slice(git.argOffset);
    /** @type {TargetWord[]} */
    const targets = [];
    for (let index = 1; index < git.args.length; index++) {
      const arg = git.args[index];
      if (typeof arg === 'string' && arg.startsWith('-')) continue;
      targets.push({ value: arg, display: arg ?? display[index] ?? '<?>' });
    }
    return at(targets, gitWorkDir(git, cwd));
  }
  // `git worktree add <path>` creates a checkout wherever <path> points.
  if (git?.subcommand === 'worktree' && git.args[0] === 'add') {
    const display = effectiveDisplayArgv(command).slice(git.argOffset);
    for (let index = 1; index < git.args.length; index++) {
      const arg = git.args[index];
      if (arg === '--') { index++; }
      else if (typeof arg === 'string' && arg.startsWith('-')) {
        if (['-b', '-B', '--reason'].includes(arg)) index++;
        continue;
      }
      const value = git.args[index];
      if (value === undefined) break;
      return at([{ value, display: value ?? display[index] ?? '<?>' }], gitWorkDir(git, cwd));
    }
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
  const root = projectInfo(ctx)?.projectRoot ?? null;
  /** @param {string} path */
  const inside = (path) => root !== null && path !== root && isAncestorOrSelf(root, path);
  for (const command of graph.commands) {
    for (const target of relocatingTargets(command, ctx.trustedCwd)) {
      /** @type {'matched'|'unknown'|null} */
      let evaluation = null;
      if (target.value === null) evaluation = 'unknown';
      else {
        const resolved = resolveTarget(target.value, target.base);
        if (resolved.kind === 'relative') evaluation = 'unknown';
        else if (!inside(resolved.path)) evaluation = 'matched';
      }
      if (!evaluation) continue;
      return {
        ruleId: 'unsandboxed-outside-project', evaluation,
        detail: `沙盒外执行的删除/移动目标在项目根${root ? `（${root}）` : ''}以外：${trunc(displayCommand(command))}`,
        why: evaluation === 'matched'
          ? '这条命令不受项目沙盒的写权限约束，bypass 下也不会有其他确认；目标在项目外，需要人确认。'
          : '这条命令在沙盒外执行，删除/移动目标无法静态确定（变量、通配符、git -C 或 cwd 不可信），需要人确认。',
      };
    }
    // Discarding git operations act on the repository they run in; outside
    // the project nothing else stands between them and that repository.
    const git = parseGitCommand(command);
    const rule = git ? gitRule(command) : null;
    if (git && (rule === 'git-discard' || rule === 'git-ref-change')) {
      const directory = gitWorkDir(git, ctx.trustedCwd);
      if (directory !== null && (inside(directory) || directory === root)) continue;
      return {
        ruleId: 'unsandboxed-outside-project', evaluation: directory === null ? 'unknown' : 'matched',
        detail: `沙盒外在项目根${root ? `（${root}）` : ''}以外的仓库执行丢弃/改引用的 Git 操作：${trunc(displayCommand(command))}`,
        why: directory === null
          ? '这条 Git 命令在沙盒外执行，工作目录无法静态确定（git -C 变量或 cwd 不可信），需要人确认。'
          : '这条 Git 命令在沙盒外执行、作用于项目以外的仓库，bypass 下也不会有其他确认，需要人确认。',
      };
    }
  }
  return null;
}

/**
 * The session's project: the Claude Code launch directory when the host
 * reports it, else the hook cwd.
 * @param {RuleContext} ctx
 */
function projectInfo(ctx) {
  if (ctx.projectDir) return ctx.inspectProject(ctx.projectDir);
  return ctx.cwd ? ctx.inspect(ctx.cwd) : null;
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
    detail: '批量删除远端 refs（push --prune）',
    why: '会删除远端上本地不存在的 refs，可能一次性删掉他人的分支和 tag，请确认 remote。',
  },
  'git-low-risk': {
    detail: '执行会改变本地引用或工作区状态的低风险 Git 操作',
    why: '该操作不属于重写历史或强制覆盖，但可能删除本地分支/tag、进入 detached HEAD 或解除 submodule 初始化状态。',
  },
};

/** @param {ShellGraph} graph @param {PolicyEnabled} enabled @param {RuleContext} ctx @returns {PolicyMatch|null} */
function confirmationPolicy(graph, enabled, ctx) {
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

    if (pushDeletesTrunk(command, ctx) === 'unknown' && enabled('push-delete-dynamic')) {
      return {
        ruleId: 'push-delete-dynamic', evaluation: 'unknown',
        detail: `删除远端分支，但目标无法静态确定：${trunc(displayCommand(command))}`,
        why: '远端删除的目标 ref 是变量，可能是 main/master；请确认展开后的分支名。改法：把分支名写成字面量。',
      };
    }

    const resetRef = hardResetRef(command);
    if (typeof resetRef === 'string') {
      const trunk = resetRefIsTrunk(resetRef, command, ctx);
      if (trunk || /^(?:origin\/|refs\/remotes\/|remotes\/)/.test(resetRef) || UPSTREAM_REF.test(resetRef)) {
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
 *   inspectProjectDir?: (directory: string) => ProjectInfo,
 *   host?: 'claude'|'codex'|'grok'|'kimi',
 *   projectDir?: string,
 *   caseInsensitivePaths?: boolean,
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
 * project lookup), `permission_mode` (tiering, Claude only), and
 * `tool_input.dangerouslyDisableSandbox`. The caller passes the host and, for
 * Claude Code, the session's `CLAUDE_PROJECT_DIR` as options.
 *
 * @param {Record<string, unknown>} event
 * @param {GuardOptions} [options]
 * @returns {GuardDecision|{kind: 'allow', command: string, description: string, analysis: ShellGraph}|null}
 */
export function evaluateHookEvent(event, options = {}) {
  if (options.caseInsensitivePaths === undefined) return evaluate(event, options);
  const previous = setCaseInsensitivePaths(options.caseInsensitivePaths);
  try { return evaluate(event, options); } finally { setCaseInsensitivePaths(previous); }
}

/** @param {string} operand @param {string|null} base */
function resolveDirectory(operand, base) {
  const expanded = operand === '' ? homedir() : expandHome(operand);
  if (expanded.startsWith('/')) return normalizePath(expanded);
  return base === null ? null : normalizePath(`${base}/${expanded}`);
}

/**
 * The directory after a run of cds. `-` returns to the previous one, which
 * before the first cd is the shell's unknown OLDPWD.
 * @param {Array<string|null>} operands @param {string|null} cwd
 */
function followOperands(operands, cwd) {
  let current = cwd;
  /** @type {string|null} */
  let previous = null;
  for (const operand of operands) {
    const next = operand === '-' ? previous : operand === null ? null : resolveDirectory(operand, current);
    previous = current;
    current = next;
  }
  return current;
}

const MAX_CWD_CANDIDATES = 32;

/**
 * Where each command may run, given the hook cwd and the command's own
 * directory changes.
 *
 * - No change (or every `cd` goes to the cwd itself): the hook cwd.
 * - Commands that only run once a leading run of `cd`s succeeded (an `&&`
 *   chain, a subshell, `if cd …; then`) and no other change elsewhere: the
 *   directory those `cd`s reach.
 * - Anything else: every directory the script can be in — the hook cwd (a
 *   `cd` that fails leaves it unchanged) and each `cd` target. A `cd` whose
 *   operand is not literal adds null (unknown), which is the only case where a
 *   relative target keeps the common-name exemption.
 *
 * `trusted` is the single directory every command runs in, when there is one.
 * @param {ShellGraph} analysis @param {string|null} cwd
 * @returns {{trusted: string|null, forCommand: (command: AnalyzedCommand) => Array<string|null>}}
 */
function cwdModel(analysis, cwd) {
  const fixed = { trusted: cwd, forCommand: () => [cwd] };
  const changes = analysis.commands.filter((item) => CWD_CHANGING.has(commandName(item)));
  if (changes.length === 0) return fixed;
  if (cwd !== null && changes.every((item) => {
    if (!CD_LIKE.has(commandName(item))) return false;
    const operand = cdArgvOperand(item.argv);
    return typeof operand === 'string' && operand !== '' && expandHome(operand).startsWith('/') &&
      normalizePath(expandHome(operand)) === cwd;
  })) return fixed;

  const prefix = analysis.cdPrefix ?? null;
  const covers = prefix !== null && prefix.operands.length === changes.length &&
    changes.every((item) => CD_LIKE.has(commandName(item)));
  const exactDirectory = covers && prefix ? followOperands(prefix.operands, cwd) : null;

  /** @type {Set<string|null>} */
  const candidates = new Set([cwd]);
  let earlier = false;
  for (const item of changes) {
    const name = commandName(item);
    const operand = CD_LIKE.has(name) ? cdArgvOperand(item.argv) : null;
    if (operand === null || operand === '-') {
      // `cd -` / `popd` go back to a directory already among the candidates.
      const back = earlier && (name === 'popd' || operand === '-');
      if (!back) candidates.add(null);
    } else {
      for (const base of [...candidates]) candidates.add(resolveDirectory(operand, base));
    }
    earlier = true;
    if (candidates.size > MAX_CWD_CANDIDATES) { candidates.add(null); break; }
  }
  const union = [...candidates];
  const exact = covers && prefix ? prefix.exact : [];
  const operands = prefix?.operands ?? [];
  const allAfterEveryCd = exact.every((entry) => entry.depth === operands.length);
  return {
    trusted: covers && prefix?.complete && allAfterEveryCd ? exactDirectory : null,
    forCommand: (command) => {
      const offset = command.rootOffset;
      const entry = typeof offset === 'number'
        ? exact.find(({ range: [start, end] }) => offset >= start && offset < end)
        : undefined;
      return entry ? [followOperands(operands.slice(0, entry.depth), cwd)] : union;
    },
  };
}

/**
 * @param {Record<string, unknown>} event
 * @param {GuardOptions} options
 * @returns {GuardDecision|{kind: 'allow', command: string, description: string, analysis: ShellGraph}|null}
 */
function evaluate(event, options) {
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
  const tier = permissionTier(event.permission_mode ?? event.permissionMode, options.host ?? 'claude');
  const enabled = (/** @type {string} */ ruleId) => isPolicyEnabled(ruleId, profile, tier);
  const cwd = eventCwd(event);
  const cwds = cwdModel(analysis, cwd);
  /** @type {RuleContext} */
  const ctx = {
    tier,
    cwd,
    trustedCwd: cwds.trusted,
    cwdsFor: cwds.forCommand,
    projectDir: typeof options.projectDir === 'string' && options.projectDir.startsWith('/') ? normalizePath(options.projectDir) : null,
    unsandboxed: toolInput.dangerouslyDisableSandbox === true,
    protectedRoots: options.protectedRoots ?? ['/'],
    protectedPaths: options.protectedPaths ?? [],
    inspect: memoizeInspector(options.inspectDirectory ?? ((directory) => inspectDirectory(directory))),
    inspectProject: memoizeInspector(options.inspectProjectDir ?? ((directory) => inspectProjectDir(directory))),
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
    const project = projectInfo(ctx);
    if (!project?.sandboxConfigured && !isReadOnlyGraph(analysis)) {
      const where = ctx.projectDir ?? project?.gitRoot ?? cwd ?? '(hook 未提供 cwd)';
      return {
        kind: 'deny', evaluation: 'matched', ruleId: 'bypass-no-project-sandbox', command, description, analysis,
        detail: `bypass 会话所在项目（${where}）没有项目沙盒配置，拒绝写类命令：${trunc(command)}`,
        why: 'bypass 只能在配好项目沙盒的项目里用；先配 .claude/settings.json 或切 auto。（判定：会话启动目录 CLAUDE_PROJECT_DIR——没有时用 cwd 所在 git 根——的 .claude/settings.json + settings.local.json 需未禁用沙盒且 sandbox.filesystem.allowWrite 非空，linked worktree 还会读主 worktree；只写 sandbox.enabled: true 不算；/tmp、scratchpad 不算项目。只读命令不受影响。）',
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

  const confirmation = confirmationPolicy(analysis, enabled, ctx);
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
