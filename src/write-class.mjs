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
  'ls', 'cat', 'bat', 'head', 'tail', 'more', 'wc', 'grep', 'egrep', 'fgrep', 'ag',
  'stat', 'file', 'du', 'df', 'pwd', 'echo', 'printf', 'which', 'whereis', 'type', 'printenv',
  'date', 'whoami', 'id', 'groups', 'uname', 'hostname', 'uptime', 'true', 'false', 'test', '[',
  'basename', 'dirname', 'realpath', 'readlink', 'diff', 'cmp', 'comm', 'cut', 'tr', 'nl', 'column',
  'fold', 'rev', 'tac', 'od', 'strings', 'md5', 'md5sum', 'shasum', 'sha1sum', 'sha256sum', 'cksum',
  'jq', 'cd', 'pushd', 'popd', 'sleep', 'env', 'ps', 'pgrep', 'lsof', 'nproc', 'sw_vers', 'locale',
  'getconf', 'unset', 'set', 'declare', 'typeset', 'local', 'readonly', 'help',
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

/** Subcommands where `-o` names an output file rather than a mode flag. */
const GIT_OUTPUT_SHORT_O = new Set(['log', 'show', 'diff', 'whatchanged', 'diff-tree', 'diff-files', 'diff-index', 'range-diff', 'format-patch']);

/** @param {AnalyzedCommand} command */
function readOnlyGit(command) {
  const git = parseGitCommand(command);
  if (!git || git.gitDirOverride) return false;
  // Global `-c`/`--config-env` can set core.pager, an alias, diff.external or
  // core.fsmonitor — each runs an arbitrary command from a "read".
  const globals = command.argv.slice(1, git.argOffset - 1);
  if (globals.some((arg) => arg === '-c' || arg === '--config-env' || (typeof arg === 'string' &&
    (arg.startsWith('--config-env=') || /^-c./.test(arg) || arg.startsWith('--exec-path'))))) return false;
  const { subcommand, args } = git;
  if (args.some((arg) => typeof arg === 'string' && (isLongOption(arg, '--ext-diff') || isLongOption(arg, '--textconv')))) return false;
  if (GIT_READ_SUBCOMMANDS.has(subcommand)) {
    // A dynamic word can expand to `--output=<file>` or `-O<pager>` as easily
    // as to a ref, so it makes the command a write.
    if (args.some((arg) => arg === null)) return false;
    return !args.some((arg) => typeof arg === 'string' &&
      (isLongOption(arg, '--output') || (arg === '-o' && GIT_OUTPUT_SHORT_O.has(subcommand)) ||
        isLongOption(arg, '--open-files-in-pager') || arg.startsWith('-O')));
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

/**
 * `gh api graphql -f query='…'` is a POST, but a query without `mutation`
 * only reads. Every field value must be static, and `--input` / `@file`
 * values are unknown content.
 * @param {AnalyzedCommand} command
 */
function graphqlIsQuery(command) {
  const args = command.argv.slice(2);
  /** @type {Array<string|null>} */
  const values = [];
  for (let index = 0; index < args.length; index++) {
    const arg = args[index];
    if (arg === null) return false;
    if (arg === '--input' || arg.startsWith('--input=')) return false;
    if (['-f', '-F', '--field', '--raw-field'].includes(arg)) { values.push(args[++index] ?? null); continue; }
    const attached = /^(?:--field=|--raw-field=|-[fF])(.+)$/.exec(arg);
    if (attached) values.push(attached[1]);
  }
  return values.every((value) => typeof value === 'string' && !/\bmutation\b/i.test(value) &&
    !/^[^=]*=@/.test(value));
}

/** @param {AnalyzedCommand} command */
function readOnlyGh(command) {
  const group = command.argv[1];
  if (group === 'api') {
    const api = parseGhApi(command);
    if (!api || api.methodUnknown) return false;
    if (api.endpoint?.value === 'graphql' && (api.method === '' || api.method === 'POST')) return graphqlIsQuery(command);
    if (api.fieldWrite) return false;
    return api.method === '' || api.method === 'GET' || api.method === 'HEAD';
  }
  if (typeof group !== 'string') return false;
  const allowed = GH_READ_SUBCOMMANDS[group];
  if (allowed === undefined) return false;
  if (allowed === 'any') return true;
  const action = command.argv[2];
  return typeof action === 'string' && allowed.has(action);
}

// sed: `s///e` and the `e` command run shell commands; `-f` reads a script
// the guard cannot see.
const SED_ADDRESS = String.raw`(?:\d+|\$|\/(?:[^/\\]|\\.)*\/)`;
const SED_EXEC_COMMAND = new RegExp(String.raw`(?:^|[;\n{])\s*(?:${SED_ADDRESS}(?:\s*,\s*${SED_ADDRESS})?)?\s*!?\s*e(?:\s|;|}|$)`);
const SED_EXEC_FLAG = new RegExp(String.raw`(?:^|[;\n{}])\s*(?:${SED_ADDRESS}(?:\s*,\s*${SED_ADDRESS})?)?\s*!?\s*s(.)(?:(?!\1)[^\\]|\\.)*\1(?:(?!\1)[^\\]|\\.)*\1[a-zA-Z0-9]*e`);

/** @param {string} arg */
const sedWrites = (arg) => isLongOption(arg, '--in-place') || /^-[^-]*[iI]/.test(arg) || isLongOption(arg, '--file') ||
  /^-[^-]*f/.test(arg) || /(?:^|[;{}\s/])w\s*\S/.test(arg) || SED_EXEC_COMMAND.test(arg) || SED_EXEC_FLAG.test(arg);

const CURL_WRITE_LETTERS = 'oOTdFKcD';
const CURL_VALUE_LETTERS = 'HuAembxwrECYyztUQhPkKcDoTdF';
const CURL_WRITE_LONG = ['--output', '--output-dir', '--remote-name', '--remote-name-all', '--upload-file', '--data',
  '--data-ascii', '--data-binary', '--data-raw', '--data-urlencode', '--form', '--form-string', '--json', '--config',
  '--cookie-jar', '--dump-header', '--trace', '--trace-ascii', '--libcurl', '--stderr', '--etag-save', '--hsts',
  '--alt-svc', '--create-dirs'];

/**
 * curl only reads when it fetches to stdout with GET/HEAD: no output file,
 * upload, request body, cookie/header dump or config file.
 * @param {Array<string|null>} args
 */
function curlIsRead(args) {
  for (let index = 0; index < args.length; index++) {
    const arg = args[index];
    if (arg === null) return false;
    if (arg === '--') break;
    if (arg.startsWith('--')) {
      const name = arg.split('=')[0];
      if (CURL_WRITE_LONG.includes(name)) return false;
      if (name === '--request') {
        const method = arg.includes('=') ? arg.slice(arg.indexOf('=') + 1) : args[++index];
        if (typeof method !== 'string' || !/^(?:GET|HEAD)$/i.test(method)) return false;
      }
      continue;
    }
    if (!arg.startsWith('-') || arg === '-') continue;
    const letters = arg.slice(1);
    for (let cursor = 0; cursor < letters.length; cursor++) {
      const letter = letters[cursor];
      if (CURL_WRITE_LETTERS.includes(letter)) return false;
      if (letter === 'X') {
        const method = cursor + 1 < letters.length ? letters.slice(cursor + 1) : args[++index];
        if (typeof method !== 'string' || !/^(?:GET|HEAD)$/i.test(method)) return false;
        break;
      }
      if (CURL_VALUE_LETTERS.includes(letter)) { if (cursor + 1 === letters.length) index++; break; }
    }
  }
  return true;
}

// awk program text that writes or runs something: output redirection or a
// pipe from print/printf, a pipe into a quoted command, system(), getline.
const AWK_WRITES = [
  /\bprintf?\b[^;{}\n]*[>|]/,
  /\|\s*"/,
  /\bsystem\s*\(/,
  /\bgetline\b/,
];

/**
 * awk only reads when its program is static and has none of the writing
 * constructs above. `-f`/`-i`/`-l`/`-E` load program code the guard cannot
 * see; `--inplace` edits files.
 * @param {Array<string|null>} args
 */
function awkIsRead(args) {
  let program = null;
  for (let index = 0; index < args.length; index++) {
    const arg = args[index];
    if (arg === null) return false;
    if (arg === '--') { program = args[index + 1] ?? null; break; }
    if (arg.startsWith('--')) {
      if (['--file', '--include', '--load', '--exec', '--inplace', '--source'].some((option) => isLongOption(arg, option))) return false;
      if (!arg.includes('=') && ['--field-separator', '--assign'].some((option) => isLongOption(arg, option))) index++;
      continue;
    }
    if (arg.startsWith('-') && arg !== '-') {
      const letter = arg[1];
      if ('fileE'.includes(letter)) return false;
      if ('Fv'.includes(letter) && arg.length === 2) index++;
      continue;
    }
    program = arg;
    break;
  }
  if (program === null) return false;
  return !AWK_WRITES.some((pattern) => pattern.test(program));
}

const NPM_READ = new Set(['ls', 'list', 'll', 'la', 'view', 'info', 'show', 'v', 'outdated', 'explain', 'why', '--version', '-v']);

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
      return !anyArg(args, sedWrites);
    case 'awk':
    case 'gawk':
    case 'mawk':
      return awkIsRead(args);
    case 'less':
      // -o/-O/--log-file/--LOG-FILE copy the input to a file; `+cmd` runs
      // less commands at start-up (including `s file`).
      return !anyArg(args, (arg) => /^-[^-]*[oO]/.test(arg) || isLongOption(arg, '--log-file') ||
        isLongOption(arg, '--LOG-FILE') || arg.startsWith('+'));
    case 'rg':
      return !anyArg(args, (arg) => arg === '--pre' || arg.startsWith('--pre='));
    case 'man':
      return !anyArg(args, (arg) => /^-[^-]*P/.test(arg) || isLongOption(arg, '--pager') || /^-[^-]*H/.test(arg) || isLongOption(arg, '--html'));
    case 'curl':
      return curlIsRead(args);
    case 'npm':
      return args.length > 0 && typeof args[0] === 'string' && NPM_READ.has(args[0]) && !args.some((arg) => arg === null);
    case 'node':
      return args.length === 1 && (args[0] === '--version' || args[0] === '-v');
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

/**
 * Variables that make a reader run something else or write: pagers, diff and
 * ssh helpers, injected git config, less pre/post-processors, loader hooks.
 */
const EXEC_CHANNEL_ENV = /^(?:GIT_PAGER|GIT_EXTERNAL_DIFF|GIT_EDITOR|GIT_SEQUENCE_EDITOR|GIT_SSH|GIT_SSH_COMMAND|GIT_ASKPASS|SSH_ASKPASS|GIT_PROXY_COMMAND|GIT_EXEC_PATH|GIT_TEMPLATE_DIR|GIT_DIR|GIT_WORK_TREE|GIT_INDEX_FILE|GIT_CONFIG(?:_[A-Z0-9_]+)?|PAGER|MANPAGER|MANOPT|LESSOPEN|LESSCLOSE|LESS|LESSKEY|LESSKEYIN|EDITOR|VISUAL|BASH_ENV|ENV|PROMPT_COMMAND|PATH|LD_PRELOAD|LD_LIBRARY_PATH|DYLD_[A-Z_]+|NODE_OPTIONS|PERL5OPT|PYTHONSTARTUP|GIT_TRACE[A-Z0-9_]*)$/;

/** @param {{name: string, value: string|null}} assignment */
function isExecChannel({ name, value }) {
  if (!EXEC_CHANNEL_ENV.test(name)) return false;
  // Common harmless spellings: no pager, `cat`, git trace to stderr, less
  // display options without a log file.
  if (/^(?:GIT_PAGER|PAGER|MANPAGER)$/.test(name) && (value === '' || value === 'cat')) return false;
  if (/^GIT_TRACE/.test(name) && value !== null && /^(?:[0-2]|true|false)?$/i.test(value)) return false;
  if (name === 'LESS' && value !== null && !/[oO+]|log-file/i.test(value)) return false;
  return true;
}

/** @param {ShellGraph} graph */
export function isReadOnlyGraph(graph) {
  if (graph.status !== 'safe') return false;
  if (!graph.redirections.every(readOnlyRedirect)) return false;
  // `export` changes what every later command sees; an exec channel set in
  // any form (prefix, plain assignment, env operand) can run a writer.
  if ((graph.assignments ?? []).some((assignment) => assignment.exported || isExecChannel(assignment))) return false;
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
