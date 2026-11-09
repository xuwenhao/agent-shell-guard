// @ts-check
// Shared argv helpers for policy modules. They only read the analyzer's
// normalized argv (null = a word that cannot be reconstructed statically).

import { basename } from 'node:path';

/** @typedef {import('./shell-analyzer.mjs').AnalyzedCommand} AnalyzedCommand */

/** @param {AnalyzedCommand} command */
export function effectiveDisplayArgv(command) {
  const offset = Math.max(0, command.rawArgv.length - command.argv.length);
  const raw = command.displayArgv.slice(offset);
  return command.argv.map((arg, index) => arg ?? raw[index] ?? '<?>');
}

/** @param {AnalyzedCommand} command */
export const displayCommand = (command) => effectiveDisplayArgv(command).join(' ');

/** @param {AnalyzedCommand} command */
export const commandName = (command) => typeof command.argv[0] === 'string' ? basename(command.argv[0]) : '';

/** @param {AnalyzedCommand} command @param {string} name */
export const isCommand = (command, name) => commandName(command) === name;

/** @param {Array<string|null>} argv @param {string} flag */
export function hasFlag(argv, flag) {
  return argv.some((arg) => arg === flag || (typeof arg === 'string' && arg.startsWith(`${flag}=`)));
}

/** @param {Array<string|null>} argv */
export function hasRecursiveFlag(argv) {
  return argv.slice(1).some((arg) => typeof arg === 'string' && (arg === '--recursive' || /^-[^-]*[rR]/.test(arg)));
}

/**
 * Git accepts any unambiguous prefix of a long option, so `git worktree remove
 * --for` is a forced removal and `git branch --del` is a deletion. Matching by
 * prefix can only put *more* commands in the destructive class, which is the
 * safe direction — an abbreviation that is actually ambiguous makes git itself
 * refuse the command. The flags that *loosen* a classification (checkout's ref
 * intent) deliberately keep their exact spelling.
 * @param {string|null|undefined} arg @param {string} option
 */
export function isLongOption(arg, option) {
  if (typeof arg !== 'string' || !arg.startsWith('--') || arg.length < 3) return false;
  const name = arg.split('=')[0];
  return option.startsWith(name);
}

/** @param {string|null|undefined} arg @param {RegExp} letters */
export function shortOptionHas(arg, letters) {
  return typeof arg === 'string' && /^-[^-]/.test(arg) && letters.test(arg.slice(1));
}

/** @param {AnalyzedCommand} command */
export function commandTargets(command) {
  /** @type {Array<{value: string|null, display: string}>} */
  const targets = [];
  const display = effectiveDisplayArgv(command);
  let options = true;
  for (let index = 1; index < command.argv.length; index++) {
    const arg = command.argv[index];
    if (options && arg === '--') { options = false; continue; }
    if (options && typeof arg === 'string' && arg.startsWith('-')) continue;
    targets.push({ value: arg, display: arg ?? display[index] ?? '<?>' });
  }
  return targets;
}

/** Environment variables that relocate or reconfigure the repository git acts on. */
export const GIT_LOCATION_ENV = /^(?:GIT_DIR|GIT_WORK_TREE|GIT_INDEX_FILE|GIT_COMMON_DIR|GIT_OBJECT_DIRECTORY|GIT_NAMESPACE|GIT_CONFIG(?:_[A-Z0-9_]+)?)$/;

/**
 * @param {AnalyzedCommand} command
 * @returns {{subcommand: string, args: Array<string|null>, argOffset: number, workDirs: Array<string|null>, gitDirOverride: boolean}|null}
 */
export function parseGitCommand(command) {
  if (!isCommand(command, 'git')) return null;
  const valueFlags = new Set(['-C', '-c', '--git-dir', '--work-tree', '--namespace', '--super-prefix', '--config-env']);
  /** @type {Array<string|null>} */
  const workDirs = [];
  // `GIT_DIR=… git …` / `export GIT_WORK_TREE=…; git …` relocate the
  // repository exactly like `--git-dir` / `--work-tree`.
  let gitDirOverride = (command.graphEnv ?? []).some((name) => GIT_LOCATION_ENV.test(name));
  let index = 1;
  for (; index < command.argv.length; index++) {
    const arg = command.argv[index];
    if (arg === '--') { index++; break; }
    if (typeof arg !== 'string') return null;
    if (!arg.startsWith('-')) break;
    if (arg.startsWith('--git-dir=') || arg.startsWith('--work-tree=')) gitDirOverride = true;
    if (valueFlags.has(arg)) {
      if (arg === '-C') workDirs.push(command.argv[index + 1] ?? null);
      if (arg === '--git-dir' || arg === '--work-tree') gitDirOverride = true;
      index++;
    }
  }
  const subcommand = command.argv[index];
  if (typeof subcommand !== 'string') return null;
  return { subcommand, args: command.argv.slice(index + 1), argOffset: index + 1, workDirs, gitDirOverride };
}

/**
 * Positional arguments of a git subcommand.
 * @param {{args: Array<string|null>}} git
 * @param {Set<string>} [valueFlags]
 */
export function gitPositionals(git, valueFlags = new Set()) {
  /** @type {Array<string|null>} */
  const positionals = [];
  let options = true;
  for (let index = 0; index < git.args.length; index++) {
    const arg = git.args[index];
    if (options && arg === '--') { options = false; continue; }
    if (options && typeof arg === 'string' && arg.startsWith('-')) {
      if (valueFlags.has(arg)) index++;
      continue;
    }
    positionals.push(arg);
  }
  return positionals;
}

/**
 * `git config` that only reads: an explicit get/list option or subcommand, or
 * the legacy single-operand form `git config [--global] <key>`. Any write
 * option, a dynamic word, or a key plus value is a write.
 * @param {{args: Array<string|null>}} git
 */
export function gitConfigIsRead(git) {
  if (git.args.some((arg) => arg === null)) return false;
  const args = /** @type {string[]} */ (git.args);
  const writes = args.some((arg) => ['--unset', '--unset-all', '--add', '--replace-all', '--edit', '--rename-section', '--remove-section']
    .some((option) => isLongOption(arg, option)) || arg === '-e');
  if (writes) return false;
  const valueFlags = new Set(['--file', '-f', '--blob', '--type', '--default', '--comment']);
  const positionals = gitPositionals(git, valueFlags);
  const first = positionals[0];
  if (first === 'set' || first === 'unset' || first === 'rename-section' || first === 'remove-section' || first === 'edit') return false;
  if (first === 'get' || first === 'list') return true;
  if (args.some((arg) => ['--get', '--get-all', '--get-regexp', '--get-urlmatch', '--list'].some((option) => isLongOption(arg, option)) || arg === '-l')) return true;
  return positionals.length === 1;
}

const ORG_RULESET_PATH = /^\/?orgs\/[^/\s]+\/rulesets(?:\/|$)/;

/**
 * `gh api` takes either a path (`orgs/x/rulesets`) or a full URL, and a URL has
 * many spellings that reach the same endpoint: `HTTPS://API.GITHUB.COM/…`, an
 * explicit `:443`, a trailing dot on the host. Returns the canonical path
 * (no leading slash, no query) or null for a URL to another host.
 * @param {string} value
 */
export function githubApiPath(value) {
  let path = value;
  if (/^https?:\/\//i.test(value)) {
    let url;
    try { url = new URL(value); } catch { url = null; }
    if (url) {
      const host = url.hostname.toLowerCase().replace(/\.$/, '');
      if (host !== 'api.github.com') return null;
      if (url.port !== '' && url.port !== '443') return null;
      path = url.pathname;
    }
  }
  return path.replace(/[?#].*$/, '').replace(/^\/+/, '').replace(/\/+$/, '');
}

/** @param {string} value */
export const isOrgRulesetEndpoint = (value) => {
  const path = githubApiPath(value);
  return path !== null && ORG_RULESET_PATH.test(path);
};

/**
 * @param {AnalyzedCommand} command
 * @returns {{
 *   endpoint: {value: string|null, display: string}|null,
 *   method: string,
 *   methodUnknown: boolean,
 *   fieldWrite: boolean,
 * }|null}
 */
export function parseGhApi(command) {
  if (!isCommand(command, 'gh') || command.argv[1] !== 'api') return null;
  const args = command.argv.slice(2);
  const display = effectiveDisplayArgv(command).slice(2);
  const tokens = args.map((arg, index) => arg ?? display[index] ?? '<?>');
  const endpointValueFlags = new Set(['-X', '--method', '-f', '-F', '--field', '--raw-field', '--input', '-H', '--header', '--preview', '--cache', '-q', '--jq', '-t', '--template', '--hostname']);
  /** @type {{value: string|null, display: string}|null} */
  let endpoint = null;
  for (let index = 0; index < args.length; index++) {
    const token = tokens[index];
    if (token === '--') {
      index++;
      endpoint = index < args.length ? { value: args[index], display: tokens[index] } : null;
      break;
    }
    if (token.startsWith('-')) {
      if (endpointValueFlags.has(token)) index++;
      continue;
    }
    endpoint = { value: args[index], display: token };
    break;
  }
  const fieldWrite = tokens.some((arg) =>
    arg === '-f' || arg === '-F' || arg === '--field' || arg.startsWith('--field=') ||
    arg === '--raw-field' || arg.startsWith('--raw-field=') || arg === '--input' || arg.startsWith('--input='));
  let method = '';
  let methodUnknown = false;
  for (let index = 0; index < args.length; index++) {
    const arg = args[index];
    const token = tokens[index];
    if (token === '-X' || token === '--method') {
      const value = args[index + 1];
      if (value === null || value === undefined) methodUnknown = true;
      else method = value;
    } else if (token.startsWith('--method=') || (token.startsWith('-X') && token !== '-X')) {
      if (arg === null) methodUnknown = true;
      else method = token.startsWith('--method=') ? token.slice('--method='.length) : token.slice(2).replace(/^=/, '');
    }
  }
  return { endpoint, method: method.toUpperCase(), methodUnknown, fieldWrite };
}
