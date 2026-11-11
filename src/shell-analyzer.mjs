#!/usr/bin/env node
// @ts-check
// Shell structure analyzer for agent-shell-guard. It never executes analyzed input:
// shfmt emits an AST and zsh is invoked with syntax-check-only flags.

import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { basename } from 'node:path';
import { homedir } from 'node:os';
import { resolveShfmtPath } from './config.mjs';
import { DYNAMIC_MARKER, expandBraces } from './path-targets.mjs';

const MAX_INPUT_BYTES = 64 * 1024;
const MAX_RECURSION = 8;
const MAX_COMMANDS = 256;
// shfmt can take longer than 500 ms to cold-start when several Node test
// workers launch it concurrently on macOS. Keep the bound short enough for a
// hook while avoiding a fail-closed denial caused only by process startup.
const DEFAULT_TIMEOUT_MS = 2_000;

/** @typedef {'bash'|'posix'|'zsh'} ShellDialect */
/** @typedef {'top-level'|'shell-c'|'eval'|'command-substitution'|'backtick-substitution'|'process-substitution'} CommandSource */
/** @typedef {{reason: string, detail: string}} AnalysisUnknown */
/** @typedef {{op: number, fd: string|null, target: string|null}} AnalyzedRedirection */
/**
 * @typedef {{
 *   argv: Array<string|null>,
 *   rawArgv: Array<string|null>,
 *   displayArgv: string[],
 *   dialect: ShellDialect,
 *   source: CommandSource,
 *   span: {start: number, end: number},
 *   wrappers: string[],
 *   hasRedirection: boolean,
 *   pipelineGroup: number|null,
 *   rootOffset?: number,
 *   graphEnv?: string[],
 *   assignmentNames?: string[],
 *   commandAssignments?: AnalyzedAssignment[],
 *   wrapperCwds?: Array<string|null>, // outer-to-inner env directory overrides
 *   markedArgv?: Array<string|null>,
 * }} AnalyzedCommand
 */
/**
 * A shell variable assignment seen anywhere in the graph: a prefix
 * assignment (`X=1 cmd`), a plain one (`X=1`), an `env X=1 cmd` operand or a
 * declaration (`export X=1`, `declare -x X`). `value` is null when dynamic or
 * absent (`export X`).
 * @typedef {{name: string, value: string|null, exported: boolean}} AnalyzedAssignment
 */
/**
 * The `cd`s of the script's leading `&&` chain. `operands` holds one entry
 * per `cd` (null = dynamic, '' = home). `exact` lists the byte ranges of the
 * commands that only run after the first `depth` of those `cd`s succeeded;
 * `complete` says that nothing else in the script runs outside those ranges.
 * @typedef {{
 *   operands: Array<string|null>,
 *   exact: Array<{range: [number, number], depth: number}>,
 *   complete: boolean,
 * }} CdPrefix
 */
/**
 * @typedef {{
 *   status: 'safe'|'unknown',
 *   dialect: ShellDialect,
 *   commands: AnalyzedCommand[],
 *   unknowns: AnalysisUnknown[],
 *   hasPipeline: boolean,
 *   hasRedirection: boolean,
 *   hasSubstitution: boolean,
 *   hasCompound: boolean,
 *   nativePromptArgv: string[]|null,
 *   redirections: AnalyzedRedirection[],
 *   cdPrefix?: CdPrefix|null,
 *   assignments?: AnalyzedAssignment[],
 * }} ShellGraph
 */
/** @typedef {{kind: 'script', text: string}|{kind: 'argv', argv: string[]}} ShellInput */
/**
 * @typedef {{
 *   dialect: ShellDialect,
 *   shfmtPath?: string,
 *   zshPath?: string,
 *   timeoutMs?: number,
 *   maxInputBytes?: number,
 *   maxRecursion?: number,
 *   maxCommands?: number,
 * }} AnalyzeOptions
 */

/** @param {string|undefined} value @returns {ShellDialect} */
function dialectFromShell(value) {
  const name = basename(value || '').toLowerCase();
  if (name === 'bash') return 'bash';
  if (name === 'sh' || name === 'dash') return 'posix';
  if (name === 'zsh') return 'zsh';
  return 'posix';
}

/**
 * Claude's Bash tool is always Bash. Generic/Codex shell tools honor an
 * explicit executable and otherwise inherit the current login shell.
 * @param {{toolName: string, explicitShell?: string, envShell?: string}} input
 * @returns {ShellDialect}
 */
export function selectShellDialect(input) {
  if (input.toolName.toLowerCase() === 'bash') return 'bash';
  return dialectFromShell(input.explicitShell || input.envShell);
}

/** @param {unknown} value @returns {value is Record<string, unknown>} */
const isObject = (value) => typeof value === 'object' && value !== null && !Array.isArray(value);

/** @param {Record<string, unknown>} node @param {'Pos'|'End'} field */
function offsetOf(node, field) {
  const point = node[field];
  return isObject(point) && typeof point.Offset === 'number' ? point.Offset : 0;
}

/** @param {string} value @param {boolean} doubleQuoted */
function decodeLiteral(value, doubleQuoted) {
  let result = '';
  for (let index = 0; index < value.length; index++) {
    const char = value[index];
    if (char !== '\\' || index + 1 >= value.length) { result += char; continue; }
    const next = value[++index];
    if (next === '\n') continue;
    if (!doubleQuoted || next === '$' || next === '`' || next === '"' || next === '\\') result += next;
    else result += `\\${next}`;
  }
  return result;
}

const ANSI_C_SIMPLE = /** @type {Record<string, string>} */ ({
  a: '\x07', b: '\b', e: '\x1b', E: '\x1b', f: '\f', n: '\n', r: '\r', t: '\t', v: '\v',
  '\\': '\\', "'": "'", '"': '"', '?': '?',
});

/**
 * Decode the body of a `$'…'` word the way bash does. Escapes that produce a
 * raw byte above 0x7f, a NUL (which truncates the word) or anything the
 * decoder does not know return null, so the word stays dynamic.
 * @param {string} value
 * @returns {string|null}
 */
export function decodeAnsiC(value) {
  let result = '';
  for (let index = 0; index < value.length; index++) {
    const char = value[index];
    if (char !== '\\') { result += char; continue; }
    if (index + 1 >= value.length) return null;
    const next = value[++index];
    if (next in ANSI_C_SIMPLE) { result += ANSI_C_SIMPLE[next]; continue; }
    /** @param {RegExp} digit @param {number} max */
    const take = (digit, max) => {
      let digits = '';
      while (digits.length < max && digit.test(value[index + 1] ?? '')) digits += value[++index];
      return digits;
    };
    let code;
    if (/[0-7]/.test(next)) code = parseInt(next + take(/[0-7]/, 2), 8);
    else if (next === 'x') { const hex = take(/[0-9a-fA-F]/, 2); if (!hex) return null; code = parseInt(hex, 16); }
    else if (next === 'u' || next === 'U') {
      const hex = take(/[0-9a-fA-F]/, next === 'u' ? 4 : 8);
      if (!hex) return null;
      const point = parseInt(hex, 16);
      if (point === 0 || point > 0x10ffff || (point >= 0xd800 && point <= 0xdfff)) return null;
      result += String.fromCodePoint(point);
      continue;
    } else if (next === 'c') {
      if (index + 1 >= value.length) return null;
      code = value[++index].charCodeAt(0) & 0x1f;
    } else return null;
    if (code === 0 || code > 0x7f) return null;
    result += String.fromCharCode(code);
  }
  return result;
}

/**
 * shfmt omits `Value` for an empty `''`.
 * @param {Record<string, unknown>} part
 */
const singleQuotedValue = (part) => {
  if (part.Value !== undefined && typeof part.Value !== 'string') return null;
  const value = typeof part.Value === 'string' ? part.Value : '';
  return part.Dollar === true ? decodeAnsiC(value) : value;
};

/** @param {string} value */
function hasUnescapedExpansion(value) {
  if (value.startsWith('~') && value !== '~' && !value.startsWith('~/')) return true;
  for (let index = 0; index < value.length; index++) {
    if (value[index] === '\\') { index++; continue; }
    if (value[index] === '*' || value[index] === '?') return true;
    if (value[index] !== '[') continue;
    let cursor = index + 1;
    if (value[cursor] === '!' || value[cursor] === '^') cursor++;
    if (value[cursor] === ']') cursor++;
    let hasContent = false;
    for (; cursor < value.length; cursor++) {
      if (value[cursor] === '\\') { cursor++; hasContent = true; continue; }
      if (value[cursor] === ']' && hasContent) return true;
      hasContent = true;
    }
  }
  return false;
}

/** @param {unknown} part @param {boolean} [doubleQuoted] @returns {string|null} */
function staticPart(part, doubleQuoted = false) {
  if (!isObject(part)) return null;
  if (part.Type === 'Lit') {
    if (typeof part.Value !== 'string' || (!doubleQuoted && hasUnescapedExpansion(part.Value))) return null;
    return decodeLiteral(part.Value, doubleQuoted);
  }
  if (part.Type === 'SglQuoted') return singleQuotedValue(part);
  if (part.Type === 'DblQuoted') {
    const parts = Array.isArray(part.Parts) ? part.Parts : [];
    let result = '';
    for (const child of parts) {
      const value = staticPart(child, true);
      if (value === null) return null;
      result += value;
    }
    return result;
  }
  return null;
}

/**
 * Bash and zsh brace-expand unquoted `{a,b}` / `{1..3}` into several words, so
 * a word containing one has no single static value. Quoted text cannot open
 * or close a brace, so it is replaced by a placeholder before checking.
 * @param {unknown[]} parts
 */
function hasBraceExpansion(parts) {
  let skeleton = '';
  for (const part of parts) {
    if (isObject(part) && part.Type === 'Lit' && typeof part.Value === 'string') skeleton += part.Value;
    else skeleton += isObject(part) && (part.Type === 'SglQuoted' || part.Type === 'DblQuoted') ? 'Q' : 'P';
  }
  if (!skeleton.includes('{')) return false;
  const expanded = expandBraces(skeleton);
  return expanded === null || expanded.length !== 1 || expanded[0] !== skeleton;
}

/**
 * Source text of a word with every expansion replaced by DYNAMIC_MARKER, so a
 * double-quoted `bash -c "rm -rf $DIR"` script can still be parsed for its
 * structure. Returns null for words that cannot be rebuilt.
 * @param {unknown} word
 */
function markedWord(word) {
  if (!isObject(word) || !Array.isArray(word.Parts)) return null;
  let result = '';
  for (const part of word.Parts) {
    if (!isObject(part)) return null;
    if (part.Type === 'Lit' && typeof part.Value === 'string') result += decodeLiteral(part.Value, false);
    else if (part.Type === 'SglQuoted') result += singleQuotedValue(part) ?? DYNAMIC_MARKER;
    else if (part.Type === 'DblQuoted') {
      for (const child of Array.isArray(part.Parts) ? part.Parts : []) {
        result += isObject(child) && child.Type === 'Lit' && typeof child.Value === 'string'
          ? decodeLiteral(child.Value, true)
          : DYNAMIC_MARKER;
      }
    } else result += DYNAMIC_MARKER;
  }
  return result;
}

/** @param {unknown} word @returns {string|null} */
function staticWord(word) {
  if (!isObject(word) || !Array.isArray(word.Parts)) return null;
  if (hasBraceExpansion(word.Parts)) return null;
  const first = word.Parts[0];
  const firstLiteral = isObject(first) && first.Type === 'Lit' && typeof first.Value === 'string'
    ? first.Value
    : '';
  const expandHome = firstLiteral.startsWith('~/') || (firstLiteral === '~' && word.Parts.length === 1);
  if (firstLiteral === '~' && word.Parts.length > 1) return null;
  let result = '';
  for (const part of word.Parts) {
    const value = staticPart(part);
    if (value === null) return null;
    result += value;
  }
  if (result.includes(DYNAMIC_MARKER)) return null;
  return expandHome ? `${homedir()}${result.slice(1)}` : result;
}

/**
 * Decode GNU env -S syntax, not shell syntax. Runtime variable references,
 * unknown escapes (including backslash-newline/trailing backslash), unclosed
 * quotes and double-quoted \\c are dynamic (fail closed).
 * @param {string} text @returns {string[]|null}
 */
function splitEnvString(text) {
  /** @type {string[]} */
  const words = [];
  let word = '', quote = '', started = false;
  const flush = () => { if (started) words.push(word); word = ''; started = false; };
  /** @type {Record<string, string>} */
  const escapes = { t: '\t', n: '\n', r: '\r', f: '\f', v: '\v' };
  for (let i = 0; i < text.length; i++) {
    const char = text[i];
    if (char === "'" || char === '"') {
      if (!quote) { quote = char; started = true; continue; }
      if (quote === char) { quote = ''; continue; }
    }
    if (char === '\\') {
      const next = text[++i];
      if (quote === "'" && next !== '\\' && next !== "'") {
        word += '\\'; started = true; i--; continue;
      }
      if (next === undefined) return null;
      if (next === 'c') {
        if (quote) return null;
        flush(); return words;
      }
      if (next === '_') {
        if (!quote) flush();
        else { word += ' '; started = true; }
        continue;
      }
      if ('\\"\'#$'.includes(next)) word += next;
      else if (Object.hasOwn(escapes, next)) word += escapes[next];
      else return null;
      started = true; continue;
    }
    if (quote !== "'" && char === '$' && /[A-Za-z_{]/.test(text[i + 1] ?? '')) return null;
    if (!quote && /[ \t\n\r\f\v]/.test(char)) { flush(); continue; }
    if (!quote && char === '#' && !started) break;
    word += char; started = true;
  }
  if (quote) return null;
  flush();
  return words;
}

/** @typedef {'none'|'required'|'optional'} OptionValue */
/** @typedef {{short: Record<string, string>, long: Record<string, OptionValue>}} OptionTable */
/** @type {OptionTable} */
const ENV_OPTIONS = {
  // `-P` differs between implementations: BSD env (macOS /usr/bin/env) takes
  // `-P altpath`, GNU coreutils 9.x has no short -P value. The guard runs on the
  // machine that executes the command, so pick by platform; mistaking the value
  // for the command would let the real command escape every rule.
  // `-a ARG` (GNU --argv0) takes a value; BSD env rejects it, which is harmless.
  short: { i: 'ignore-environment', 0: 'null', v: 'debug', u: 'unset', C: 'chdir', S: 'split-string',
    a: 'argv0', P: process.platform === 'darwin' ? 'bsd-altpath' : 'default-signal' },
  long: {
    'ignore-environment': 'none', null: 'none', debug: 'none', 'list-signal-handling': 'none',
    help: 'none', version: 'none', unset: 'required', chdir: 'required',
    'split-string': 'required', argv0: 'required', 'default-signal': 'optional',
    'ignore-signal': 'optional', 'block-signal': 'optional',
    // Internal name for BSD `-P altpath`; BSD env has no long options.
    'bsd-altpath': 'required',
  },
};
/** @type {OptionTable} */
const SUDO_OPTIONS = {
  short: {
    a: 'auth-type', u: 'user', g: 'group', h: 'host', p: 'prompt', C: 'close-from', T: 'command-timeout',
    R: 'chroot', D: 'chdir', r: 'role', t: 'type', c: 'login-class', U: 'other-user',
    A: 'askpass', b: 'background', B: 'bell', E: 'preserve-env', e: 'edit', H: 'set-home',
    i: 'login', K: 'remove-timestamp', k: 'reset-timestamp', l: 'list', n: 'non-interactive',
    N: 'no-update', P: 'preserve-groups', S: 'stdin', s: 'shell', V: 'version', v: 'validate',
  },
  long: {
    'auth-type': 'required', user: 'required', group: 'required', host: 'required', prompt: 'required',
    'close-from': 'required', 'command-timeout': 'required', chroot: 'required', chdir: 'required',
    role: 'required', type: 'required', 'login-class': 'required', 'other-user': 'required',
    askpass: 'none', background: 'none', bell: 'none', 'preserve-env': 'optional', edit: 'none',
    'set-home': 'none', login: 'none', 'remove-timestamp': 'none', 'reset-timestamp': 'none',
    list: 'none', 'non-interactive': 'none', 'preserve-groups': 'none', stdin: 'none',
    shell: 'none', version: 'none', validate: 'none', help: 'none',
  },
};

/**
 * Parse one getopt word (possibly a short cluster). Optional values are attached
 * with '=' on long options only. Invalid/ambiguous words consume just themselves:
 * the actual utility exits before executing a command in those cases.
 * @param {Array<string|null>} argv @param {number} index @param {OptionTable} table
 * @returns {{kind: 'operand'|'unknown'|'options', consumed: number,
 *   options: Array<{name: string, value: string|null|undefined, prefix: string}>}}
 */
function parseWrapperOption(argv, index, table) {
  const arg = argv[index];
  const unknown = { kind: /** @type {const} */ ('unknown'), consumed: 1, options: [] };
  if (typeof arg !== 'string' || arg === '-' || !arg.startsWith('-')) {
    return { kind: 'operand', consumed: 0, options: [] };
  }
  if (arg.startsWith('--')) {
    const equal = arg.indexOf('=');
    const key = arg.slice(2, equal < 0 ? undefined : equal);
    const matches = Object.hasOwn(table.long, key) ? [key] : Object.keys(table.long).filter(name => name.startsWith(key));
    if (!key || matches.length !== 1) return unknown;
    const name = matches[0], mode = table.long[name];
    if (equal >= 0 && mode === 'none') return unknown;
    const separate = equal < 0 && mode === 'required';
    return { kind: 'options', consumed: separate ? 2 : 1,
      options: [{ name, value: equal >= 0 ? arg.slice(equal + 1) : separate ? argv[index + 1] : undefined, prefix: '' }] };
  }
  /** @type {Array<{name: string, value: string|null|undefined, prefix: string}>} */
  const options = [];
  for (let i = 1; i < arg.length; i++) {
    const letter = /** @type {string} */ (arg[i]);
    if (!Object.hasOwn(table.short, letter)) return unknown;
    const name = table.short[letter];
    if (table.long[name] === 'required') {
      const attached = arg.slice(i + 1);
      options.push({ name, value: attached || argv[index + 1], prefix: arg.slice(1, i) });
      return { kind: 'options', consumed: attached ? 1 : 2, options };
    }
    options.push({ name, value: undefined, prefix: '' });
  }
  return { kind: 'options', consumed: 1, options };
}

/** Keep dynamic attached cwd/split values using the very same option grammar.
 * @param {string} word */
function markedWrapperOption(word) {
  return [ENV_OPTIONS, SUDO_OPTIONS].some(table => {
    const parsed = parseWrapperOption([word], 0, table);
    return parsed.options.some(option => ['chdir', 'split-string'].includes(option.name) && option.value !== undefined);
  });
}

/** @param {Array<string|null>} rawArgv */
export function unwrapCommand(rawArgv) {
  let argv = rawArgv;
  /** @type {string[]} */
  const wrappers = [];
  /** @type {Array<string|null>} */
  const wrapperCwds = [];
  for (let depth = 0; depth < 8 && typeof argv[0] === 'string'; depth++) {
    const name = basename(/** @type {string} */ (argv[0])).toLowerCase();
    let index = 1;
    if (name === 'command' || name === 'builtin') {
      if (name === 'command' && typeof argv[index] === 'string' &&
        /^-[^-]*[vV]/.test(/** @type {string} */ (argv[index]))) break;
      while (typeof argv[index] === 'string' && argv[index]?.startsWith('-')) index++;
    } else if (name === 'env') {
      let envCwd;
      while (index < argv.length) {
        const arg = argv[index];
        if (arg === '--') { index++; break; }
        if (typeof arg === 'string' && /^[A-Za-z_][A-Za-z0-9_]*=/.test(arg)) { index++; continue; }
        const parsed = parseWrapperOption(argv, index, ENV_OPTIONS);
        if (parsed.kind === 'operand') break;
        for (const { name: option, value, prefix: clusterPrefix } of parsed.options) {
          if (option === 'chdir') {
            envCwd = typeof value === 'string' && !value.includes(DYNAMIC_MARKER) ? value : null;
          } else if (option === 'split-string') {
            const tail = argv.slice(index + parsed.consumed);
            const prefix = [...argv.slice(1, index), ...(clusterPrefix ? ['-' + clusterPrefix] : [])];
            const words = typeof value === 'string' && !value.includes(DYNAMIC_MARKER) ? splitEnvString(value) : null;
            const text = words === null ? null
              : ['env', ...prefix.map(quoteShellWord), ...words.map(quoteShellWord), ...tail.map(quoteShellWord)].join(' ');
            // -C stays in prefix for nested parsing; do not also record this
            // env's directory in the outer command's wrapperCwds.
            return { argv, wrappers: [...wrappers, name], wrapperCwds,
              evaluator: { script: text, scriptIndex: -1 } };
          }
        }
        index += parsed.consumed;
      }
      if (envCwd !== undefined) wrapperCwds.push(envCwd);
    } else if (name === 'exec') {
      while (index < argv.length) {
        const arg = argv[index];
        if (arg === '--') { index++; break; }
        if (arg === '-a') { index += 2; continue; }
        if (typeof arg === 'string' && arg.startsWith('-')) { index++; continue; }
        break;
      }
    } else if (name === 'sudo') {
      let sudoCwd;
      // Options and assignments can alternate until the command or '--'.
      while (index < argv.length) {
        const arg = argv[index];
        if (arg === '--') { index++; break; }
        if (typeof arg === 'string' && /^[A-Za-z_][A-Za-z0-9_]*=/.test(arg)) { index++; continue; }
        const parsed = parseWrapperOption(argv, index, SUDO_OPTIONS);
        if (parsed.kind === 'operand') break;
        for (const option of parsed.options) {
          if (option.name === 'edit') {
            // sudoedit operands are files, not commands. The editor is unknown.
            return { argv: [null], wrappers: [...wrappers, name], wrapperCwds, evaluator: null };
          }
          if (option.name === 'chdir') {
            sudoCwd = typeof option.value === 'string' && !option.value.includes(DYNAMIC_MARKER) ? option.value : null;
          }
        }
        index += parsed.consumed;
      }
      if (sudoCwd !== undefined) wrapperCwds.push(sudoCwd);
    } else if (name === 'nohup' || name === 'setsid') {
      while (typeof argv[index] === 'string' && argv[index]?.startsWith('-')) {
        if (argv[index] === '--') { index++; break; }
        index++;
      }
    } else if (name === 'nice') {
      while (index < argv.length) {
        const arg = argv[index];
        if (arg === '--') { index++; break; }
        if (arg === '-n' || arg === '--adjustment') { index += 2; continue; }
        if (typeof arg === 'string' && arg.startsWith('-')) { index++; continue; }
        break;
      }
    } else if (name === 'time') {
      const valueOptions = new Set(['-o', '--output', '-f', '--format']);
      while (index < argv.length) {
        const arg = argv[index];
        if (arg === '--') { index++; break; }
        if (typeof arg !== 'string' || !arg.startsWith('-')) break;
        index += valueOptions.has(arg) ? 2 : 1;
      }
    } else if (name === 'stdbuf') {
      const valueOptions = new Set(['-i', '--input', '-o', '--output', '-e', '--error']);
      while (index < argv.length) {
        const arg = argv[index];
        if (arg === '--') { index++; break; }
        if (typeof arg !== 'string' || !arg.startsWith('-')) break;
        index += valueOptions.has(arg) ? 2 : 1;
      }
    } else if (name === 'timeout') {
      const valueOptions = new Set(['-k', '--kill-after', '-s', '--signal']);
      while (index < argv.length) {
        const arg = argv[index];
        if (arg === '--') { index++; break; }
        if (typeof arg !== 'string' || !arg.startsWith('-')) break;
        index += valueOptions.has(arg) ? 2 : 1;
      }
      index++; // duration precedes the wrapped command
    } else if (name === 'xargs') {
      // xargs runs its operand as a command with stdin appended as arguments.
      const valueOptions = new Set(['-I', '-L', '-n', '-P', '-s', '-d', '-E', '-a', '-R', '-S',
        '--max-args', '--max-lines', '--max-procs', '--max-chars', '--delimiter', '--eof', '--arg-file',
        '--replace', '--process-slot-var']);
      while (index < argv.length) {
        const arg = argv[index];
        if (arg === '--') { index++; break; }
        if (typeof arg !== 'string' || !arg.startsWith('-')) break;
        index += valueOptions.has(arg) ? 2 : 1;
      }
    } else if (name === 'busybox' || name === 'toybox') {
      if (typeof argv[index] === 'string' && argv[index]?.startsWith('-')) break;
    } else {
      break;
    }
    if (index >= argv.length) break;
    wrappers.push(name);
    argv = argv.slice(index);
  }
  return { argv, wrappers, wrapperCwds, evaluator: null };
}

/** @param {string|null} word */
function quoteShellWord(word) {
  return "'" + (word ?? DYNAMIC_MARKER).replaceAll("'", "'\\''") + "'";
}

/** @param {Array<string|null>} argv */
export function shellEvaluator(argv) {
  if (typeof argv[0] !== 'string') return null;
  const name = basename(argv[0]).toLowerCase();
  if (!['bash', 'sh', 'dash', 'zsh'].includes(name)) return null;
  const valueOptions = new Set(['-o']);
  if (name === 'bash') {
    valueOptions.add('-O');
    valueOptions.add('--init-file');
    valueOptions.add('--rcfile');
  }
  for (let index = 1; index < argv.length; index++) {
    const arg = argv[index];
    if (arg === null) return { dialect: /** @type {ShellDialect} */ (name === 'bash' ? 'bash' : name === 'zsh' ? 'zsh' : 'posix'), script: null, scriptIndex: -1 };
    if (arg === '--') break;
    if (/^-[^-]*c/.test(arg)) {
      let scriptIndex = index + 1;
      if (argv[scriptIndex] === '--') scriptIndex++;
      return {
        dialect: /** @type {ShellDialect} */ (name === 'bash' ? 'bash' : name === 'zsh' ? 'zsh' : 'posix'),
        script: typeof argv[scriptIndex] === 'string' ? argv[scriptIndex] : null,
        scriptIndex,
      };
    }
    if (valueOptions.has(arg)) {
      index++;
      continue;
    }
    if (!arg.startsWith('-')) break;
  }
  return null;
}

/** @param {string} reason @param {string} detail @param {ShellDialect} dialect */
function failedGraph(reason, detail, dialect) {
  return /** @type {ShellGraph} */ ({
    status: 'unknown', dialect, commands: [], unknowns: [{ reason, detail }],
    hasPipeline: false, hasRedirection: false, hasSubstitution: false,
    hasCompound: false, nativePromptArgv: null, redirections: [], assignments: [],
  });
}

/**
 * Parse shell structure into static command events. Dynamic data arguments are
 * represented as null; only a dynamic command/evaluator becomes execution
 * unknown. This keeps ordinary quoted/search data from triggering rules.
 * @param {ShellInput} input
 * @param {AnalyzeOptions} options
 * @returns {ShellGraph}
 */
export function analyzeShellInput(input, options) {
  const dialect = options.dialect;
  const explicitShfmt = options.shfmtPath || process.env.GUARD_BASH_SHFMT;
  const shfmtPath = explicitShfmt || resolveShfmtPath();
  const zshPath = options.zshPath || process.env.GUARD_BASH_ZSH || '/bin/zsh';
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const maxInputBytes = options.maxInputBytes ?? MAX_INPUT_BYTES;
  const maxRecursion = options.maxRecursion ?? MAX_RECURSION;
  const maxCommands = options.maxCommands ?? MAX_COMMANDS;
  if (input.kind === 'argv') {
    const rawArgv = input.argv.map(String);
    const { argv, wrappers, wrapperCwds, evaluator: split } = unwrapCommand(rawArgv);
    /** @type {ShellGraph} */
    const graph = {
      status: 'safe', dialect,
      commands: [{ argv, rawArgv, displayArgv: rawArgv, dialect, source: 'top-level', span: { start: 0, end: 0 }, wrappers, wrapperCwds, hasRedirection: false, pipelineGroup: null, rootOffset: 0 }],
      unknowns: [], hasPipeline: false, hasRedirection: false, hasSubstitution: false,
      hasCompound: false, nativePromptArgv: wrappers.length ? null : rawArgv,
      redirections: [], assignments: envOperandAssignments(rawArgv, argv),
    };
    graph.commands[0].commandAssignments = [...(graph.assignments ?? [])];
    graph.commands[0].assignmentNames = graph.commands[0].commandAssignments.map((item) => item.name);
    const evaluator = split ? { ...split, dialect } : shellEvaluator(argv);
    if (!evaluator) return finishGraph(graph);
    graph.nativePromptArgv = null;
    if (evaluator.script === null) {
      graph.status = 'unknown';
      graph.unknowns.push({ reason: 'dynamic-evaluator', detail: `${String(argv[0])} -c script is dynamic or missing` });
      return finishGraph(graph);
    }
    if (maxRecursion <= 0) {
      graph.status = 'unknown';
      graph.unknowns.push({ reason: 'recursion-limit', detail: 'tokenized shell evaluator exceeds recursion limit' });
      return finishGraph(graph);
    }
    const nested = analyzeShellInput({ kind: 'script', text: evaluator.script }, {
      ...options,
      dialect: evaluator.dialect,
      shfmtPath,
      zshPath,
      timeoutMs,
      maxInputBytes,
      maxRecursion: maxRecursion - 1,
      maxCommands: Math.max(0, maxCommands - 1),
    });
    graph.commands.push(...nested.commands.map((command) => ({
      ...command,
      source: command.source === 'top-level' ? /** @type {CommandSource} */ ('shell-c') : command.source,
      rootOffset: 0,
      wrapperCwds: [...wrapperCwds, ...(command.wrapperCwds ?? [])],
      commandAssignments: [...(graph.commands[0].commandAssignments ?? []), ...(command.commandAssignments ?? [])],
    })));
    graph.assignments?.push(...(nested.assignments ?? []));
    graph.unknowns.push(...nested.unknowns);
    graph.status = nested.status;
    graph.hasPipeline = nested.hasPipeline;
    graph.hasRedirection = nested.hasRedirection;
    graph.hasSubstitution = nested.hasSubstitution;
    graph.hasCompound = nested.hasCompound;
    graph.redirections = nested.redirections;
    return finishGraph(graph);
  }

  if (Buffer.byteLength(input.text) > maxInputBytes) return failedGraph('input-too-large', `shell input exceeds ${maxInputBytes} bytes`, dialect);
  if (!existsSync(shfmtPath)) {
    return failedGraph(
      'parser-missing',
      `shfmt v3.13.1 is required at ${shfmtPath}; run agent-shell-guard setup`,
      dialect,
    );
  }

  /** @type {ShellGraph} */
  const graph = {
    status: 'safe', dialect, commands: [], unknowns: [], hasPipeline: false,
    hasRedirection: false, hasSubstitution: false, hasCompound: false,
    nativePromptArgv: null, redirections: [], assignments: [],
  };
  let commandCount = 0;
  let pipelineCount = 0;

  /** @param {string} reason @param {string} detail */
  const unknown = (reason, detail) => {
    if (!graph.unknowns.some((item) => item.reason === reason && item.detail === detail)) graph.unknowns.push({ reason, detail });
    graph.status = 'unknown';
  };

  /**
   * @param {string} text
   * @param {ShellDialect} currentDialect
   * @param {number} depth
   * @param {CommandSource} source
   * @param {number|null} [rootOffset] span start of the top-level command
   *   that spawned this nested script (null at the top level)
   */
  function parseScript(text, currentDialect, depth, source, rootOffset = null) {
    if (Buffer.byteLength(text) > maxInputBytes) { unknown('input-too-large', `nested shell input exceeds ${maxInputBytes} bytes`); return; }
    if (depth > maxRecursion) { unknown('recursion-limit', `shell evaluator nesting exceeds ${maxRecursion}`); return; }

    const language = currentDialect;
    const parsed = spawnSync(shfmtPath, ['-ln', language, '--to-json'], {
      input: text, encoding: 'utf8', timeout: timeoutMs, maxBuffer: 16 * 1024 * 1024,
    });
    if (parsed.error) {
      const code = /** @type {NodeJS.ErrnoException} */ (parsed.error).code;
      unknown(code === 'ETIMEDOUT' ? 'parser-timeout' : code === 'ENOENT' ? 'parser-missing' : 'parser-failed', parsed.error.message);
      return;
    }

    if (parsed.status !== 0) {
      unknown('parser-failed', String(parsed.stderr || `shfmt exited ${parsed.status}`));
      return;
    }

    let zshValidation = null;
    if (currentDialect === 'zsh') {
      zshValidation = spawnSync(zshPath, ['-f', '-n', '-c', text], {
        encoding: 'utf8', timeout: timeoutMs,
      });
      if (zshValidation.error) {
        const code = /** @type {NodeJS.ErrnoException} */ (zshValidation.error).code;
        unknown(code === 'ETIMEDOUT' ? 'zsh-validation-timeout' : 'zsh-validator-missing', zshValidation.error.message);
        return;
      }
      if (zshValidation.status !== 0 && parsed.status === 0) {
        unknown('zsh-validation-conflict', String(zshValidation.stderr || 'zsh rejected syntax accepted by shfmt'));
        return;
      }
    }
    /** @type {unknown} */
    let ast;
    try { ast = JSON.parse(parsed.stdout); }
    catch (error) { unknown('parser-output-invalid', String(error)); return; }
    if (!isObject(ast) || ast.Type !== 'File' || !Array.isArray(ast.Stmts)) {
      unknown('parser-output-invalid', 'shfmt did not return a File AST');
      return;
    }
    // shfmt reports UTF-8 byte offsets; JS strings index UTF-16 code units.
    const bytes = Buffer.from(text, 'utf8');
    /** @param {number} start @param {number} end */
    const sliceBytes = (start, end) => bytes.subarray(start, end).toString('utf8');

    if (depth === 0) {
      graph.nativePromptArgv = nativeArgvFromRoot(ast);
      graph.cdPrefix = cdPrefixFromRoot(ast, sliceBytes);
    }
    if (ast.Stmts.length !== 1) graph.hasCompound = true;

    /** @param {unknown} list */
    function recordRedirections(list) {
      if (!Array.isArray(list)) return;
      for (const redirect of list) {
        if (!isObject(redirect)) continue;
        graph.hasRedirection = true;
        const fd = isObject(redirect.N) && typeof redirect.N.Value === 'string' ? redirect.N.Value : null;
        graph.redirections.push({
          op: typeof redirect.Op === 'number' ? redirect.Op : -1,
          fd,
          target: redirect.Word ? staticWord(redirect.Word) : null,
        });
      }
    }

    /** @param {unknown} node @param {CommandSource} nodeSource @param {number|null} [pipelineGroup] */
    function walk(node, nodeSource, pipelineGroup = null) {
      if (Array.isArray(node)) { for (const item of node) walk(item, nodeSource, pipelineGroup); return; }
      if (!isObject(node)) return;
      const type = typeof node.Type === 'string' ? node.Type : '';

      if (type === 'CallExpr') {
        const words = Array.isArray(node.Args) ? node.Args : [];
        if (words.length === 0) {
          recordAssignments(node.Assigns, false);
          walk(node.Assigns, nodeSource, pipelineGroup);
          if (Array.isArray(node.Redirs) && node.Redirs.length) {
            recordRedirections(node.Redirs);
            walk(node.Redirs, nodeSource, pipelineGroup);
          }
          return;
        }
        if (++commandCount > maxCommands) { unknown('command-limit', `command graph exceeds ${maxCommands} nodes`); return; }
        const rawArgv = words.map(staticWord);
        const displayArgv = words.map((word) => isObject(word) ? sliceBytes(offsetOf(word, 'Pos'), offsetOf(word, 'End')) : '<?>');
        // Wrapper assignments and attached env/sudo options may use marked values; retain null
        // in the effective argv so dynamic command/data words stay unknown.
        const wrapperArgv = words.map((word, index) => {
          const marked = rawArgv[index] === null ? markedWord(word) : rawArgv[index];
          return rawArgv[index] ?? (marked && (/^[A-Za-z_][A-Za-z0-9_]*=/.test(marked) || markedWrapperOption(marked)) ? marked : null);
        });
        const unwrapped = unwrapCommand(wrapperArgv);
        const wrappers = unwrapped.wrappers;
        const argv = unwrapped.argv.map((arg, index) => arg === null ? null : rawArgv[rawArgv.length - unwrapped.argv.length + index]);
        const span = { start: offsetOf(node, 'Pos'), end: offsetOf(node, 'End') };
        /** @type {AnalyzedCommand} */
        const command = {
          argv, rawArgv, displayArgv, markedArgv: words.map(markedWord).slice(rawArgv.length - argv.length), dialect: currentDialect, source: nodeSource,
          span, wrappers, wrapperCwds: unwrapped.wrapperCwds, hasRedirection: Array.isArray(node.Redirs) && node.Redirs.length > 0,
          pipelineGroup, rootOffset: rootOffset ?? span.start,
        };
        const assignmentStart = graph.assignments?.length ?? 0;
        recordAssignments(node.Assigns, false);
        graph.assignments?.push(...envOperandAssignments(wrapperArgv, argv, rawArgv));
        command.commandAssignments = (graph.assignments ?? []).slice(assignmentStart);
        command.assignmentNames = command.commandAssignments.map((item) => item.name);
        graph.commands.push(command);
        if (argv[0] === null || argv.length === 0) unknown('dynamic-command', 'command name cannot be reconstructed statically');

        const offset = rawArgv.length - argv.length;
        const nestedStart = graph.commands.length;
        const evaluator = unwrapped.evaluator ? { ...unwrapped.evaluator, dialect: currentDialect } : shellEvaluator(argv);
        if (evaluator) {
          if (evaluator.script === null) {
            unknown('dynamic-evaluator', `${String(argv[0])} -c script is dynamic or missing`);
            // Still parse the script with its expansions marked as unknown
            // words, so hard boundaries inside it (rm -rf "$X/…") are seen.
            const marked = evaluator.scriptIndex >= 0 ? markedWord(words[offset + evaluator.scriptIndex]) : null;
            if (marked !== null && marked.replaceAll(DYNAMIC_MARKER, '').trim() !== '') {
              parseScript(marked, evaluator.dialect, depth + 1, 'shell-c', command.rootOffset);
            }
          } else parseScript(evaluator.script, evaluator.dialect, depth + 1, 'shell-c', command.rootOffset);
        } else if (argv[0] === 'eval') {
          const parts = argv.slice(1);
          if (parts.some((part) => part === null)) {
            unknown('dynamic-evaluator', 'eval input cannot be reconstructed statically');
            const marked = words.slice(offset + 1).map(markedWord);
            if (marked.every((part) => part !== null)) {
              parseScript(/** @type {string[]} */ (marked).join(' '), currentDialect, depth + 1, 'eval', command.rootOffset);
            }
          } else parseScript(/** @type {string[]} */ (parts).join(' '), currentDialect, depth + 1, 'eval', command.rootOffset);
        }

        for (const nested of graph.commands.slice(nestedStart)) {
          nested.wrapperCwds = [...(command.wrapperCwds ?? []), ...(nested.wrapperCwds ?? [])];
          nested.commandAssignments = [...(command.commandAssignments ?? []), ...(nested.commandAssignments ?? [])];
          nested.assignmentNames = nested.commandAssignments.map((item) => item.name);
        }
        walk(node.Assigns, nodeSource, pipelineGroup);
        walk(node.Args, nodeSource, pipelineGroup);
        if (Array.isArray(node.Redirs) && node.Redirs.length) {
          recordRedirections(node.Redirs);
          walk(node.Redirs, nodeSource, pipelineGroup);
        }
        return;
      }

      if (type === 'BinaryCmd') {
        graph.hasCompound = true;
        const opPos = isObject(node.OpPos) && typeof node.OpPos.Offset === 'number' ? node.OpPos.Offset : 0;
        const operator = sliceBytes(opPos, opPos + 2);
        const isPipeline = operator.startsWith('|') && !operator.startsWith('||');
        if (isPipeline) graph.hasPipeline = true;
        const group = isPipeline ? (pipelineGroup ?? ++pipelineCount) : pipelineGroup;
        walk(node.X, nodeSource, group);
        walk(node.Y, nodeSource, group);
        return;
      }
      if (type === 'DeclClause') {
        const variant = isObject(node.Variant) && typeof node.Variant.Value === 'string' ? node.Variant.Value : '';
        const args = Array.isArray(node.Args) ? node.Args : [];
        // `declare -x`, `typeset -gx`: a naked option word carrying `x`.
        const exportFlag = args.some((arg) => isObject(arg) && arg.Naked === true && !isObject(arg.Name) &&
          /^-[A-Za-z]*x/.test(String(staticWord(arg.Value) ?? '')));
        recordAssignments(args.filter((arg) => isObject(arg) && isObject(arg.Name)), variant === 'export' || exportFlag);
      }
      if (type === 'CmdSubst') {
        graph.hasSubstitution = true;
        walk(node.Stmts, node.Backquotes === true ? 'backtick-substitution' : 'command-substitution', null);
        return;
      }
      if (type === 'ProcSubst') {
        graph.hasSubstitution = true;
        walk(node.Stmts, 'process-substitution', null);
        return;
      }
      if (type && !['File', 'Lit', 'SglQuoted', 'DblQuoted', 'ParamExp'].includes(type)) graph.hasCompound = true;

      for (const [key, value] of Object.entries(node)) {
        if (['Pos', 'End', 'Position', 'ValuePos', 'ValueEnd', 'Left', 'Right', 'OpPos', 'Rparen'].includes(key)) continue;
        if (key === 'Redirs' && Array.isArray(value) && value.length) recordRedirections(value);
        walk(value, nodeSource, pipelineGroup);
      }
    }

    walk(ast.Stmts, source);
  }

  /** @param {unknown} list @param {boolean} exported */
  function recordAssignments(list, exported) {
    if (!Array.isArray(list)) return;
    for (const assign of list) {
      if (!isObject(assign) || !isObject(assign.Name) || typeof assign.Name.Value !== 'string') continue;
      const value = assign.Naked === true || !assign.Value ? null : staticWord(assign.Value);
      graph.assignments?.push({ name: assign.Name.Value, value, exported });
    }
  }

  parseScript(input.text, dialect, 0, 'top-level');
  return finishGraph(graph);
}

/**
 * `env NAME=value cmd` and `sudo NAME=value cmd` assignments, which unwrapCommand strips with the
 * wrapper.
 * @param {Array<string|null>} rawArgv @param {Array<string|null>} argv
 * @returns {AnalyzedAssignment[]}
 */
/**
 * @param {Array<string|null>} rawArgv words as recorded (marked dynamic words allowed)
 * @param {Array<string|null>} argv the unwrapped command
 * @param {Array<string|null>} [staticArgv] static view of the same words; a null
 *   there means the word is dynamic, so the recorded value must be null (unknown)
 */
function envOperandAssignments(rawArgv, argv, staticArgv = rawArgv) {
  /** @type {AnalyzedAssignment[]} */
  const result = [];
  rawArgv.slice(0, rawArgv.length - argv.length).forEach((word, index) => {
    const match = typeof word === 'string' ? /^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/s.exec(word) : null;
    if (match) result.push({ name: match[1], value: staticArgv[index] === null ? null : match[2], exported: false });
  });
  return result;
}

/**
 * Give every command the names assigned anywhere in its graph, so a rule
 * looking at one command can see `GIT_DIR=… git …` or `export GIT_DIR=…; git …`.
 * @param {ShellGraph} graph
 */
function finishGraph(graph) {
  const names = [...new Set((graph.assignments ?? []).map((item) => item.name))];
  for (const command of graph.commands) {
    command.graphEnv = names;
    if (command.commandAssignments) command.assignmentNames = command.commandAssignments.map((item) => item.name);
  }
  return graph;
}

const CD_COMMANDS = new Set(['cd', 'chdir', 'pushd', 'popd']);
const CWD_COMMANDS = new Set([...CD_COMMANDS, 'source', '.']);

/**
 * A statement that is a single simple command, as its static argv.
 * @param {unknown} stmt
 */
function simpleArgv(stmt) {
  if (!isObject(stmt) || stmt.Negated || stmt.Background || stmt.Coprocess) return null;
  const call = stmt.Cmd;
  if (!isObject(call) || call.Type !== 'CallExpr' || !Array.isArray(call.Args) || call.Args.length === 0) return null;
  return { argv: call.Args.map(staticWord), assigns: Array.isArray(call.Assigns) && call.Assigns.length > 0 };
}

/**
 * The directory operand of a cwd-changing statement: a path, '' for home,
 * '-' for `cd -`, null when it cannot be known (`cd "$X"`, `popd`, `pushd +1`).
 * Undefined when the statement does not change the directory.
 * @param {unknown} stmt
 * @returns {string|null|undefined}
 */
export function cdOperand(stmt) {
  const simple = simpleArgv(stmt);
  if (!simple || typeof simple.argv[0] !== 'string' || !CWD_COMMANDS.has(simple.argv[0])) return undefined;
  const name = simple.argv[0];
  if (!CD_COMMANDS.has(name) || name === 'popd' || simple.assigns) return null;
  return cdArgvOperand(simple.argv);
}

/**
 * @param {Array<string|null>} argv `cd`/`chdir`/`pushd` argv
 * @returns {string|null} the operand, '' for home, '-' for `cd -`
 *   (the previous directory), null when unknowable
 */
export function cdArgvOperand(argv) {
  const rest = argv.slice(1);
  while (typeof rest[0] === 'string' && /^-[LPeq@sn]+$/.test(rest[0])) rest.shift();
  if (rest[0] === '--') rest.shift();
  if (rest.length === 0) return argv[0] === 'pushd' ? null : '';
  if (rest.length > 1 || typeof rest[0] !== 'string' || /^[+-]\d+$/.test(rest[0])) return null;
  if (rest[0] === '-' && argv[0] === 'pushd') return null;
  return rest[0];
}

/**
 * The `cd`s of the script's leading `&&` chain and the commands that only run
 * once the cds before them succeeded. Recognised shapes: an `&&` chain
 * (`cd /x && make && cd y && rm -rf data`),
 * the same inside `( … )` or `{ …; }`, as the condition of an `if` (its
 * `then` branch), followed by `|| tail` or `; more` (the tail is outside the
 * exact range), and with redirections on the `cd`.
 * @param {Record<string, unknown>} ast
 * @param {(start: number, end: number) => string} sliceBytes
 * @returns {CdPrefix|null}
 */
function cdPrefixFromRoot(ast, sliceBytes) {
  if (!Array.isArray(ast.Stmts) || ast.Stmts.length === 0) return null;
  const prefix = chainPrefix(ast.Stmts[0], sliceBytes);
  if (!prefix) return null;
  return { ...prefix, complete: prefix.complete && ast.Stmts.length === 1 };
}

/** @param {unknown} stmt @returns {[number, number]} */
const stmtRange = (stmt) => isObject(stmt) ? [offsetOf(stmt, 'Pos'), offsetOf(stmt, 'End')] : [0, 0];

/**
 * @param {unknown} stmt @param {(start: number, end: number) => string} sliceBytes
 * @returns {CdPrefix|null}
 */
function chainPrefix(stmt, sliceBytes) {
  if (!isObject(stmt) || stmt.Negated || stmt.Background || stmt.Coprocess) return null;
  const cmd = stmt.Cmd;
  if (!isObject(cmd)) return null;
  if ((cmd.Type === 'Subshell' || cmd.Type === 'Block') && Array.isArray(cmd.Stmts) && cmd.Stmts.length) {
    const inner = chainPrefix(cmd.Stmts[0], sliceBytes);
    return inner && { ...inner, complete: inner.complete && cmd.Stmts.length === 1 };
  }
  if (cmd.Type === 'IfClause' && Array.isArray(cmd.Cond) && cmd.Cond.length === 1) {
    const condition = chainPrefix(cmd.Cond[0], sliceBytes);
    if (!condition) return null;
    const then = Array.isArray(cmd.Then) ? cmd.Then : [];
    const thenHasCd = then.some((item) => cdOperand(item) !== undefined);
    const depth = condition.operands.length;
    return {
      operands: condition.operands,
      exact: [...condition.exact, ...(thenHasCd ? [] : then.map((item) => ({ range: stmtRange(item), depth })))],
      complete: condition.complete && !thenHasCd && !isObject(cmd.Else),
    };
  }
  /** @type {unknown[]} */
  const elements = [];
  /** @type {number|null} */
  let cut = null;
  /** @param {unknown} item */
  const flatten = (item) => {
    const inner = isObject(item) ? item.Cmd : null;
    if (isObject(item) && !item.Negated && !item.Background && isObject(inner) && inner.Type === 'BinaryCmd') {
      const opPos = isObject(inner.OpPos) && typeof inner.OpPos.Offset === 'number' ? inner.OpPos.Offset : -1;
      const operator = sliceBytes(opPos, opPos + 2);
      if (operator === '&&') { flatten(inner.X); flatten(inner.Y); return; }
      // `cd x && rm -rf data || true`: the left side is the chain, the
      // right side runs whether or not the cds succeeded.
      if (operator === '||' && elements.length === 0) { flatten(inner.X); cut ??= elements.length; return; }
    }
    elements.push(item);
  };
  flatten(stmt);
  // Every element of an `&&` chain runs only after all the cds before it
  // succeeded, so it runs in the directory those cds reach.
  /** @type {Array<string|null>} */
  const operands = [];
  /** @type {CdPrefix['exact']} */
  const exact = [];
  let complete = cut === null;
  for (let index = 0; index < (cut ?? elements.length); index++) {
    const operand = cdOperand(elements[index]);
    const name = simpleArgv(elements[index])?.argv[0];
    if (operand === undefined) { exact.push({ range: stmtRange(elements[index]), depth: operands.length }); continue; }
    if (name === 'source' || name === '.') { complete = false; break; }
    operands.push(operand);
  }
  if (operands.length === 0) return null;
  return { operands, exact, complete };
}

/** @param {Record<string, unknown>} ast @returns {string[]|null} */
function nativeArgvFromRoot(ast) {
  if (!Array.isArray(ast.Stmts) || ast.Stmts.length !== 1 || !isObject(ast.Stmts[0])) return null;
  const stmt = ast.Stmts[0];
  if (stmt.Semicolon || stmt.Negated || stmt.Background || stmt.Coprocess || (Array.isArray(stmt.Redirs) && stmt.Redirs.length)) return null;
  if (!isObject(stmt.Cmd) || stmt.Cmd.Type !== 'CallExpr') return null;
  const call = stmt.Cmd;
  if ((Array.isArray(call.Assigns) && call.Assigns.length) || (Array.isArray(call.Redirs) && call.Redirs.length) || !Array.isArray(call.Args)) return null;
  const argv = call.Args.map(staticWord);
  if (argv.some((arg) => arg === null)) return null;
  const staticArgv = /** @type {string[]} */ (argv);
  const { argv: effective, wrappers } = unwrapCommand(staticArgv);
  if (wrappers.length || effective.length !== staticArgv.length || shellEvaluator(effective) || effective[0] === 'eval') return null;
  return staticArgv;
}
