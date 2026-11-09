// @ts-check
// Append-only log of shell calls that asked to leave the sandbox
// (`tool_input.dangerouslyDisableSandbox: true`). The log feeds the weekly
// review that decides when a project can set `allowUnsandboxedCommands:
// false`. Logging is best effort: any failure is swallowed and never changes
// the guard's decision.

import { appendFileSync, mkdirSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

import { redact } from './reviewer.mjs';

export const UNSANDBOXED_LOG_NAME = 'unsandboxed.jsonl';
const COMMAND_LIMIT = 500;

/** @param {NodeJS.ProcessEnv} [env] */
export function stateDirectory(env = process.env) {
  return env.AGENT_SHELL_GUARD_STATE_DIR || join(homedir(), '.local', 'state', 'agent-shell-guard');
}

/**
 * @param {{
 *   command: string,
 *   cwd: string|null,
 *   gitRoot: string|null,
 *   permissionMode: unknown,
 *   sessionId: unknown,
 *   decision: string,
 * }} entry
 * @param {{env?: NodeJS.ProcessEnv, now?: () => Date}} [options]
 * @returns {boolean} whether the line was written
 */
export function logUnsandboxedCall(entry, options = {}) {
  try {
    const directory = stateDirectory(options.env);
    mkdirSync(directory, { recursive: true });
    const line = JSON.stringify({
      ts: (options.now?.() ?? new Date()).toISOString(),
      cwd: entry.cwd,
      gitRoot: entry.gitRoot,
      command: redact(entry.command).slice(0, COMMAND_LIMIT),
      permission_mode: typeof entry.permissionMode === 'string' ? entry.permissionMode : null,
      session_id: typeof entry.sessionId === 'string' ? entry.sessionId : null,
      decision: entry.decision,
    });
    appendFileSync(join(directory, UNSANDBOXED_LOG_NAME), `${line}\n`, { mode: 0o600 });
    return true;
  } catch {
    return false;
  }
}
