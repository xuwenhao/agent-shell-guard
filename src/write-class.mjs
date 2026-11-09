// @ts-check
// "Write-class" detection for bypass sessions without a project sandbox.
//
// The classification is an allowlist: a shell graph is read-only only when the
// parser fully understood it, every command is a known reader (with the
// arguments that would make it write ruled out), and every redirection either
// reads or targets a harmless sink such as /dev/null. Anything else — unknown
// tools, interpreters, package managers, network clients, git/gh subcommands
// outside the read list — is treated as a write. False positives only cost a
// deny in a session that should not be running in bypass anyway.

import {
  commandName,
  gitConfigIsRead,
  gitPositionals,
  isLongOption,
  parseGhApi,
  parseGitCommand,
  shortOptionHas,
} from './command-utils.mjs';

/** @typedef {import('./shell-analyzer.mjs').AnalyzedCommand} AnalyzedCommand */
/** @typedef {import('./shell-analyzer.mjs').ShellGraph} ShellGraph */

// shfmt v3.13.1 RedirOperator values (pinned parser).
const READ_REDIRECT_OPS = new Set([65 /* < */, 67 /* <& */, 71 /* << */, 72 /* <<- */, 73 /* <<< */]);
const DUP_OUTPUT_OP = 68; /* >& */
const SAFE_SINKS = /^\/dev\/(?:null|stdout|stderr|tty|fd\/\d+)$/;

/** Commands whose only effect is output on stdout/stderr, whatever the args. */
const PURE_READERS = new Set([
  'ls', 'cat', 'bat', 'head', 'tail', 'less', 'more', 'wc', 'grep', 'egrep', 'fgrep', 'rg', 'ag',
  'stat', 'file', 'du', 'df', 'pwd', 'echo', 'printf', 'which', 'whereis', 'type', 'printenv',
  'date', 'whoami', 'id', 'groups', 'uname', 'hostname', 'uptime', 'true', 'false', 'test', '[',
  'basename', 'dirname', 'realpath', 'readlink', 'diff', 'cmp', 'comm', 'cut', 'tr', 'nl', 'column',
  'fold', 'rev', 'tac', 'od', 'strings', 'md5', 'md5sum', 'shasum', 'sha1sum', 'sha256sum', 'cksum',
  'jq', 'cd', 'pushd', 'popd', 'sleep', 'env', 'ps', 'pgrep', 'lsof', 'nproc', 'sw_vers', 'locale',
  'getconf', 'export', 'unset', 'set', 'declare', 'typeset', 'local', 'readonly', 'man', 'help',
  'seq', 'expr', 'paste', 'join', 'look', 'zcat', 'gzcat',
]);

const GIT_READ_SUBCOMMANDS = new Set([
  'status', 'log', 'show', 'diff', 'rev-parse', 'ls-files', 'ls-tree', 'ls-remote', 'cat-file',
  'describe', 'blame', 'annotate', 'shortlog', 'rev-list', 'merge-base', 'name-rev', 'for-each-ref',
  'show-ref', 'show-branch', 'check-ignore', 'check-attr', 'count-objects', 'whatchanged', 'cherry',
  'range-diff', 'grep', 'version', 'help', 'var', 'diff-tree', 'diff-files', 'diff-index',
  'verify-commit', 'verify-tag',
]);

/** @type {Record<string, Set<string>|'any'>} */
const GH_READ_SUBCOMMANDS = {
  pr: new Set(['view', 'list', 'status', 'diff', 'checks']),
  issue: new Set(['view', 'list', 'status']),
  repo: new Set(['view', 'list']),
  run: new Set(['view', 'list', 'watch']),
  workflow: new Set(['view', 'list']),
  release: new Set(['view', 'list']),
  label: new Set(['list']),
  ruleset: new Set(['view', 'list', 'check']),
  gist: new Set(['view', 'list']),
  cache: new Set(['list']),
  secret: new Set(['list']),
  variable: new Set(['list', 'get']),
  auth: new Set(['status']),
  search: 'any',
  status: 'any',
};

/** @param {{op: number, target: string|null}} redirect */
function readOnlyRedirect(redirect) {
  if (READ_REDIRECT_OPS.has(redirect.op)) return true;
  if (redirect.target === null) return false;
  if (redirect.op === DUP_OUTPUT_OP && /^(?:\d+|-)$/.test(redirect.target)) return true;
  return SAFE_SINKS.test(redirect.target);
}

/** @param {Array<string|null>} args @param {(arg: string) => boolean} writes */
const anyArg = (args, writes) => args.some((arg) => arg === null || writes(arg));

/** @param {AnalyzedCommand} command */
function readOnlyGit(command) {
  const git = parseGitCommand(command);
  if (!git || git.gitDirOverride) return false;
  const { subcommand, args } = git;
  if (GIT_READ_SUBCOMMANDS.has(subcommand)) {
    // A dynamic word here is a ref or path operand in practice; only literal
    // output-file options turn these subcommands into writes.
    return !args.some((arg) => typeof arg === 'string' &&
      (isLongOption(arg, '--output') || arg === '-o' || isLongOption(arg, '--open-files-in-pager') || arg.startsWith('-O')));
  }
  if (args.some((arg) => arg === null)) return false;
  const first = args.find((arg) => typeof arg === 'string' && !arg.startsWith('-'));
  if (subcommand === 'branch') {
    const writes = args.some((arg) =>
      ['--delete', '--move', '--copy', '--force', '--set-upstream-to', '--unset-upstream', '--edit-description',
        '--track', '--no-track', '--create-reflog'].some((option) => isLongOption(arg, option)) ||
      shortOptionHas(arg, /[dDmMcCfut]/));
    if (writes) return false;
    const listing = args.some((arg) => isLongOption(arg, '--list') || isLongOption(arg, '--show-current') || shortOptionHas(arg, /l/));
    const positionals = gitPositionals(git, new Set(['--contains', '--no-contains', '--merged', '--no-merged', '--points-at', '--sort', '--format', '--color', '--column']));
    return listing || positionals.length === 0;
  }
  if (subcommand === 'tag') {
    const writes = args.some((arg) =>
      ['--delete', '--force', '--annotate', '--sign', '--message', '--file', '--local-user'].some((option) => isLongOption(arg, option)) ||
      shortOptionHas(arg, /[dfasmFu]/));
    if (writes) return false;
    const listing = args.some((arg) => isLongOption(arg, '--list') || shortOptionHas(arg, /l/));
    const positionals = gitPositionals(git, new Set(['--contains', '--no-contains', '--merged', '--no-merged', '--points-at', '--sort', '--format', '--color', '--column']));
    return listing || positionals.length === 0;
  }
  if (subcommand === 'remote') return first === undefined || first === 'get-url' || first === 'show';
  if (subcommand === 'worktree') return first === 'list';
  if (subcommand === 'stash') return first === 'list' || first === 'show';
  if (subcommand === 'notes') return first === 'list' || first === 'show';
  if (subcommand === 'submodule') return first === undefined || first === 'status' || first === 'summary';
  if (subcommand === 'reflog') return first === undefined || first === 'show';
  if (subcommand === 'symbolic-ref') {
    return !args.some((arg) => isLongOption(arg, '--delete') || shortOptionHas(arg, /d/)) && gitPositionals(git).length <= 1;
  }
  if (subcommand === 'config') return gitConfigIsRead(git);
  return false;
}

/** @param {AnalyzedCommand} command */
function readOnlyGh(command) {
  const group = command.argv[1];
  if (group === 'api') {
    const api = parseGhApi(command);
    if (!api || api.fieldWrite || api.methodUnknown) return false;
    return api.method === '' || api.method === 'GET' || api.method === 'HEAD';
  }
  if (typeof group !== 'string') return false;
  const allowed = GH_READ_SUBCOMMANDS[group];
  if (allowed === undefined) return false;
  if (allowed === 'any') return true;
  const action = command.argv[2];
  return typeof action === 'string' && allowed.has(action);
}

/** @param {AnalyzedCommand} command */
export function isReadOnlyCommand(command) {
  if (command.wrappers.includes('sudo')) return false;
  const name = commandName(command);
  if (!name) return false;
  const args = command.argv.slice(1);
  if (PURE_READERS.has(name)) return true;
  switch (name) {
    case 'command':
      return args.length > 0 && typeof args[0] === 'string' && /^-[^-]*[vV]/.test(args[0]);
    case 'tree':
      return !anyArg(args, (arg) => arg === '-o' || arg.startsWith('-o'));
    case 'sort':
      return !anyArg(args, (arg) => isLongOption(arg, '--output') || /^-[^-]*o/.test(arg));
    case 'uniq':
      return !args.some((arg) => arg === null) && args.filter((arg) => typeof arg === 'string' && !arg.startsWith('-')).length <= 1;
    case 'sed':
    case 'gsed':
      return !anyArg(args, (arg) => isLongOption(arg, '--in-place') || /^-[^-]*[iI]/.test(arg) || /(?:^|[;{}\s/])w\s*\S/.test(arg));
    case 'awk':
    case 'gawk':
    case 'mawk':
      return !anyArg(args, (arg) => /^-i/.test(arg) || isLongOption(arg, '--inplace') || /[>|]|system|getline/.test(arg));
    case 'yq':
      return !anyArg(args, (arg) => isLongOption(arg, '--inplace') || /^-[^-]*i/.test(arg));
    case 'find':
      return !anyArg(args, (arg) => ['-delete', '-exec', '-execdir', '-ok', '-okdir', '-fprint', '-fprint0', '-fprintf', '-fls'].includes(arg));
    case 'fd':
    case 'fdfind':
      return !anyArg(args, (arg) => ['-x', '-X', '--exec', '--exec-batch'].includes(arg) || isLongOption(arg, '--exec'));
    case 'git':
      return readOnlyGit(command);
    case 'gh':
      return readOnlyGh(command);
    default:
      return false;
  }
}

/** @param {ShellGraph} graph */
export function isReadOnlyGraph(graph) {
  if (graph.status !== 'safe') return false;
  if (!graph.redirections.every(readOnlyRedirect)) return false;
  return graph.commands.every(isReadOnlyCommand);
}

// Commands Claude Code is commonly configured to run outside its sandbox
// (`sandbox.excludedCommands`). The guard cannot read the live setting, so this
// mirrors the documented defaults of the managing dotfiles.
const EXCLUDED_GIT = new Set(['push', 'fetch', 'pull', 'clone', 'worktree']);
const EXCLUDED_TOOLS = new Set(['gh', 'ssh', 'scp', 'rsync', 'tailscale', 'op', 'kubectl', 'gcloud', 'docker']);

/** @param {ShellGraph} graph */
export function isExcludedCommandGraph(graph) {
  if (graph.commands.length !== 1 || graph.hasCompound || graph.hasSubstitution) return false;
  const [command] = graph.commands;
  const name = commandName(command);
  if (EXCLUDED_TOOLS.has(name)) return true;
  const git = parseGitCommand(command);
  if (!git) return false;
  if (EXCLUDED_GIT.has(git.subcommand)) return true;
  return git.subcommand === 'branch' && git.args.some((arg) => shortOptionHas(arg, /[dD]/) || isLongOption(arg, '--delete'));
}
