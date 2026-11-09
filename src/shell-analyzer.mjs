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
 * }} AnalyzedCommand
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
 *   cdPrefix?: string[]|null,
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
  if (part.Type === 'SglQuoted') {
    return typeof part.Value === 'string' ? part.Value : null;
  }
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
    else if (part.Type === 'SglQuoted' && typeof part.Value === 'string') result += part.Value;
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

/** @param {Array<string|null>} rawArgv */
function unwrapCommand(rawArgv) {
  let argv = rawArgv;
  /** @type {string[]} */
  const wrappers = [];
  for (let depth = 0; depth < 8 && typeof argv[0] === 'string'; depth++) {
    const name = basename(/** @type {string} */ (argv[0])).toLowerCase();
    let index = 1;
    if (name === 'command' || name === 'builtin') {
      if (name === 'command' && typeof argv[index] === 'string' &&
        /^-[^-]*[vV]/.test(/** @type {string} */ (argv[index]))) break;
      while (typeof argv[index] === 'string' && argv[index]?.startsWith('-')) index++;
    } else if (name === 'env') {
      while (index < argv.length) {
        const arg = argv[index];
        if (arg === '--') { index++; break; }
        if (arg === '-u' || arg === '--unset' || arg === '-C' || arg === '--chdir') { index += 2; continue; }
        if (typeof arg === 'string' && (arg.startsWith('-') || /^[A-Za-z_][A-Za-z0-9_]*=/.test(arg))) { index++; continue; }
        break;
      }
    } else if (name === 'exec') {
      while (index < argv.length) {
        const arg = argv[index];
        if (arg === '--') { index++; break; }
        if (arg === '-a') { index += 2; continue; }
        if (typeof arg === 'string' && arg.startsWith('-')) { index++; continue; }
        break;
      }
    } else if (name === 'sudo') {
      const valueOptions = new Set(['-u', '-g', '-h', '-p', '-C', '-T', '-R', '-D']);
      while (index < argv.length) {
        const arg = argv[index];
        if (arg === '--') { index++; break; }
        if (typeof arg !== 'string' || !arg.startsWith('-')) break;
        index += valueOptions.has(arg) ? 2 : 1;
      }
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
  return { argv, wrappers };
}

/** @param {Array<string|null>} argv */
function shellEvaluator(argv) {
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
    hasCompound: false, nativePromptArgv: null, redirections: [],
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
    const { argv, wrappers } = unwrapCommand(rawArgv);
    /** @type {ShellGraph} */
    const graph = {
      status: 'safe', dialect,
      commands: [{ argv, rawArgv, displayArgv: rawArgv, dialect, source: 'top-level', span: { start: 0, end: 0 }, wrappers, hasRedirection: false, pipelineGroup: null }],
      unknowns: [], hasPipeline: false, hasRedirection: false, hasSubstitution: false,
      hasCompound: false, nativePromptArgv: wrappers.length ? null : rawArgv,
      redirections: [],
    };
    const evaluator = shellEvaluator(argv);
    if (!evaluator) return graph;
    graph.nativePromptArgv = null;
    if (evaluator.script === null) {
      graph.status = 'unknown';
      graph.unknowns.push({ reason: 'dynamic-evaluator', detail: `${String(argv[0])} -c script is dynamic or missing` });
      return graph;
    }
    if (maxRecursion <= 0) {
      graph.status = 'unknown';
      graph.unknowns.push({ reason: 'recursion-limit', detail: 'tokenized shell evaluator exceeds recursion limit' });
      return graph;
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
    })));
    graph.unknowns.push(...nested.unknowns);
    graph.status = nested.status;
    graph.hasPipeline = nested.hasPipeline;
    graph.hasRedirection = nested.hasRedirection;
    graph.hasSubstitution = nested.hasSubstitution;
    graph.hasCompound = nested.hasCompound;
    graph.redirections = nested.redirections;
    return graph;
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
    nativePromptArgv: null, redirections: [],
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
   */
  function parseScript(text, currentDialect, depth, source) {
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

    if (depth === 0) {
      graph.nativePromptArgv = nativeArgvFromRoot(ast);
      graph.cdPrefix = cdPrefixFromRoot(ast, text);
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
          walk(node.Assigns, nodeSource, pipelineGroup);
          if (Array.isArray(node.Redirs) && node.Redirs.length) {
            recordRedirections(node.Redirs);
            walk(node.Redirs, nodeSource, pipelineGroup);
          }
          return;
        }
        if (++commandCount > maxCommands) { unknown('command-limit', `command graph exceeds ${maxCommands} nodes`); return; }
        const rawArgv = words.map(staticWord);
        const displayArgv = words.map((word) => isObject(word) ? text.slice(offsetOf(word, 'Pos'), offsetOf(word, 'End')) : '<?>');
        const { argv, wrappers } = unwrapCommand(rawArgv);
        const command = {
          argv, rawArgv, displayArgv, dialect: currentDialect, source: nodeSource,
          span: { start: offsetOf(node, 'Pos'), end: offsetOf(node, 'End') },
          wrappers, hasRedirection: Array.isArray(node.Redirs) && node.Redirs.length > 0,
          pipelineGroup,
        };
        graph.commands.push(command);
        if (argv[0] === null || argv.length === 0) unknown('dynamic-command', 'command name cannot be reconstructed statically');

        const offset = rawArgv.length - argv.length;
        const evaluator = shellEvaluator(argv);
        if (evaluator) {
          if (evaluator.script === null) {
            unknown('dynamic-evaluator', `${String(argv[0])} -c script is dynamic or missing`);
            // Still parse the script with its expansions marked as unknown
            // words, so hard boundaries inside it (rm -rf "$X/…") are seen.
            const marked = evaluator.scriptIndex >= 0 ? markedWord(words[offset + evaluator.scriptIndex]) : null;
            if (marked !== null && marked.replaceAll(DYNAMIC_MARKER, '').trim() !== '') {
              parseScript(marked, evaluator.dialect, depth + 1, 'shell-c');
            }
          } else parseScript(evaluator.script, evaluator.dialect, depth + 1, 'shell-c');
        } else if (argv[0] === 'eval') {
          const parts = argv.slice(1);
          if (parts.some((part) => part === null)) {
            unknown('dynamic-evaluator', 'eval input cannot be reconstructed statically');
            const marked = words.slice(offset + 1).map(markedWord);
            if (marked.every((part) => part !== null)) {
              parseScript(/** @type {string[]} */ (marked).join(' '), currentDialect, depth + 1, 'eval');
            }
          } else parseScript(/** @type {string[]} */ (parts).join(' '), currentDialect, depth + 1, 'eval');
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
        const operator = text.slice(opPos, opPos + 2);
        const isPipeline = operator.startsWith('|') && !operator.startsWith('||');
        if (isPipeline) graph.hasPipeline = true;
        const group = isPipeline ? (pipelineGroup ?? ++pipelineCount) : pipelineGroup;
        walk(node.X, nodeSource, group);
        walk(node.Y, nodeSource, group);
        return;
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

  parseScript(input.text, dialect, 0, 'top-level');
  return graph;
}

/**
 * Literal `cd` operands that lead a script consisting of one `&&` chain
 * (`cd /tmp/x && cd sub && rm -rf data`). Everything after them runs in the
 * directory they reach, because `&&` stops the chain if a `cd` fails. An
 * operand of '' means a bare `cd` (home). Null for any other shape.
 * @param {Record<string, unknown>} ast @param {string} text
 * @returns {string[]|null}
 */
function cdPrefixFromRoot(ast, text) {
  if (!Array.isArray(ast.Stmts) || ast.Stmts.length !== 1) return null;
  /** @type {unknown[]} */
  const elements = [];
  /** @param {unknown} stmt */
  const flatten = (stmt) => {
    if (!isObject(stmt) || stmt.Negated || stmt.Background || stmt.Coprocess) { elements.push(null); return; }
    const cmd = stmt.Cmd;
    if (isObject(cmd) && cmd.Type === 'BinaryCmd') {
      const opPos = isObject(cmd.OpPos) && typeof cmd.OpPos.Offset === 'number' ? cmd.OpPos.Offset : -1;
      if (text.slice(opPos, opPos + 2) === '&&') { flatten(cmd.X); flatten(cmd.Y); return; }
    }
    elements.push(stmt);
  };
  flatten(ast.Stmts[0]);
  /** @type {string[]} */
  const operands = [];
  for (const stmt of elements) {
    if (!isObject(stmt) || (Array.isArray(stmt.Redirs) && stmt.Redirs.length)) break;
    const call = stmt.Cmd;
    if (!isObject(call) || call.Type !== 'CallExpr' || !Array.isArray(call.Args) || (Array.isArray(call.Assigns) && call.Assigns.length)) break;
    const argv = call.Args.map(staticWord);
    if (argv[0] !== 'cd') break;
    const rest = argv.slice(1);
    while (typeof rest[0] === 'string' && /^-[LPe@]+$/.test(rest[0])) rest.shift();
    if (rest[0] === '--') rest.shift();
    if (rest.length > 1 || rest.some((arg) => arg === null || arg === '-')) return null;
    operands.push(rest.length ? /** @type {string} */ (rest[0]) : '');
  }
  return operands.length ? operands : null;
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
