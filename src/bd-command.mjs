// @ts-check
// bd 1.3.4 global options. Unknown options before the verb fail closed.
import { isCommand, hasFlag } from './command-utils.mjs';

const VALUE_FLAGS = new Set(['--actor', '--database', '--db', '-C', '--directory', '--dolt-auto-commit', '--mem-profile']);
const BOOL_FLAGS = new Set(['--cpu-profile', '--global', '-h', '--help', '--ignore-schema-skew', '--json', '--no-color', '-q', '--quiet', '--readonly', '--sandbox', '-v', '--verbose', '-V', '--version']);
export const BD_FORBIDDEN = new Set(['init', 'setup', 'hooks', 'dolt']);
const READ_ONLY = new Set(['list', 'show', 'ready', 'search', 'blocked', 'stats', 'prime', 'where', 'version', 'help', 'info', 'status', 'count', 'graph', 'doctor']);

/** @param {import('./shell-analyzer.mjs').AnalyzedCommand} command */
export function parseBdCommand(command) {
  if (!isCommand(command, 'bd')) return null;
  /** @type {string|null|undefined} undefined = no verb, null = unknown */
  let subcommand;
  /** @type {string|null|undefined} */
  let directory;
  let options = true;
  // A fully dynamic word after the verb may expand to any option (--mem-profile=…,
  // --fix, --directory=…). Words right after a literal `--flag` are taken as that
  // flag's value (`--notes "$N"`), so ordinary dynamic values stay quiet.
  let dynamicOption = false;
  for (let i = 1; i < command.argv.length; i++) {
    const arg = command.argv[i];
    if (options && arg === '--') { options = false; continue; }
    if (arg === null) {
      if (subcommand === undefined) subcommand = null;
      else if (options) {
        const prev = command.argv[i - 1];
        if (!(typeof prev === 'string' && prev.startsWith('-') && !prev.includes('='))) dynamicOption = true;
      }
      continue;
    }
    const flag = arg.split('=')[0];
    if (options && VALUE_FLAGS.has(flag)) {
      const value = arg.includes('=') ? arg.slice(arg.indexOf('=') + 1) : command.argv[++i] ?? null;
      if (flag === '-C' || flag === '--directory') directory = value;
      if (i >= command.argv.length && subcommand === undefined) subcommand = null;
      continue;
    }
    if (options && BOOL_FLAGS.has(flag)) continue;
    if (subcommand === undefined) subcommand = options && arg.startsWith('-') ? null : arg;
  }
  return {
    subcommand, directory, dynamicOption,
    profileWrite: hasFlag(command.markedArgv ?? command.argv, '--mem-profile') || hasFlag(command.markedArgv ?? command.argv, '--cpu-profile') ||
      (command.assignmentNames ?? []).includes('BEADS_MEM_PROFILE'),
    readOnly: subcommand === undefined || (subcommand !== null && READ_ONLY.has(subcommand) &&
      !(subcommand === 'doctor' && hasFlag(command.argv, '--fix'))),
  };
}
