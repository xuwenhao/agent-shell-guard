// @ts-check

import { existsSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { delimiter, isAbsolute, join } from 'node:path';

const DEFAULT_CONFIG_PATH = join(homedir(), '.config', 'agent-shell-guard', 'config.json');
const DEFAULT_MANAGED_SHFMT = join(homedir(), '.local', 'share', 'agent-shell-guard', 'bin', 'shfmt');
const DEFAULT_LAUNCHER_PATH = join(homedir(), '.local', 'bin', 'agent-shell-guard');

/** @typedef {'strict'|'reviewed'} GuardMode */
/**
 * @typedef {{
 *   command: string,
 *   args: string[],
 *   model?: string,
 *   timeoutMs: number,
 * }} ReviewerConfig
 */
/**
 * @typedef {{
 *   mode: GuardMode,
 *   profile: 'full'|'dangerous-only'|'off',
 *   shfmtPath: string,
 *   zshPath?: string,
 *   protectedRoots: string[],
 *   nativePrompt: {codex: boolean, grok: boolean, kimi: boolean},
 *   reviewer: ReviewerConfig|null,
 * }} GuardConfig
 */

/** @param {unknown} value @returns {value is Record<string, unknown>} */
const isObject = (value) => typeof value === 'object' && value !== null && !Array.isArray(value);

/** @param {string|undefined} value @param {boolean} fallback */
function booleanOverride(value, fallback) {
  if (value === undefined) return fallback;
  return /^(?:1|true|yes|on)$/i.test(value);
}

/** @param {string} command @param {NodeJS.ProcessEnv} [env] */
function resolveExecutable(command, env = process.env) {
  if (isAbsolute(command) || command.includes('/')) return command;
  for (const directory of String(env.PATH ?? '').split(delimiter)) {
    if (!directory) continue;
    const candidate = join(directory, command);
    if (existsSync(candidate)) return candidate;
  }
  return command;
}

/** @param {string} [explicit] @param {NodeJS.ProcessEnv} [env] */
export function resolveShfmtPath(explicit, env = process.env) {
  const candidates = [
    explicit,
    env.AGENT_SHELL_GUARD_SHFMT,
    DEFAULT_MANAGED_SHFMT,
    join(homedir(), '.local', 'bin', 'shfmt'),
    resolveExecutable('shfmt'),
  ];
  return candidates.find((candidate) => typeof candidate === 'string' && existsSync(candidate))
    ?? DEFAULT_MANAGED_SHFMT;
}

/** @param {string|undefined} path @param {NodeJS.ProcessEnv} env */
function readConfigFile(path, env) {
  const target = path || env.AGENT_SHELL_GUARD_CONFIG || DEFAULT_CONFIG_PATH;
  try {
    const parsed = JSON.parse(readFileSync(target, 'utf8'));
    return isObject(parsed) ? parsed : {};
  } catch {
    return {};
  }
}

/**
 * @param {{configPath?: string, env?: NodeJS.ProcessEnv}} [options]
 * @returns {GuardConfig}
 */
export function loadConfig(options = {}) {
  const env = options.env ?? process.env;
  const file = readConfigFile(options.configPath, env);
  const rawMode = env.AGENT_SHELL_GUARD_MODE ?? file.mode;
  const mode = rawMode === 'reviewed' ? 'reviewed' : 'strict';
  const rawProfile = env.AGENT_SHELL_GUARD_PROFILE ?? env.GUARD_BASH_PROFILE ?? file.profile;
  const profile = rawProfile === 'full' || rawProfile === 'off' ? rawProfile : 'dangerous-only';
  const reviewerValue = isObject(file.reviewer) ? file.reviewer : {};
  const reviewerCommand = env.AGENT_SHELL_GUARD_REVIEWER_COMMAND ??
    (typeof reviewerValue.command === 'string' ? reviewerValue.command : '');
  const reviewerModel = env.AGENT_SHELL_GUARD_REVIEWER_MODEL ??
    (typeof reviewerValue.model === 'string' ? reviewerValue.model : undefined);
  const configuredTimeout = Number(env.AGENT_SHELL_GUARD_REVIEWER_TIMEOUT_MS ??
    reviewerValue.timeoutMs ?? 12_000);
  const reviewer = reviewerCommand
    ? {
        command: resolveExecutable(reviewerCommand, env),
        args: Array.isArray(reviewerValue.args) ? reviewerValue.args.map(String) : [],
        model: reviewerModel,
        timeoutMs: Number.isFinite(configuredTimeout)
          ? Math.max(500, Math.min(20_000, configuredTimeout))
          : 12_000,
      }
    : null;
  const configuredRoots = Array.isArray(file.protectedRoots)
    ? file.protectedRoots.filter((value) => typeof value === 'string')
    : [];
  const environmentRoots = String(env.AGENT_SHELL_GUARD_PROTECTED_ROOTS ?? '')
    .split(',')
    .map((value) => value.trim())
    .filter(Boolean);
  const protectedRoots = ['/', homedir(), ...configuredRoots, ...environmentRoots].map((value) =>
    value === '~' ? homedir() : value.startsWith('~/') ? join(homedir(), value.slice(2)) : value);
  const nativePromptValue = isObject(file.nativePrompt) ? file.nativePrompt : {};

  return {
    mode,
    profile,
    shfmtPath: resolveShfmtPath(
      env.AGENT_SHELL_GUARD_SHFMT ?? (typeof file.shfmtPath === 'string' ? file.shfmtPath : undefined),
      env,
    ),
    zshPath: typeof file.zshPath === 'string' ? file.zshPath : undefined,
    protectedRoots: [...new Set(protectedRoots)],
    nativePrompt: {
      codex: booleanOverride(
        env.AGENT_SHELL_GUARD_NATIVE_PROMPT_CODEX,
        nativePromptValue.codex === true,
      ),
      grok: booleanOverride(
        env.AGENT_SHELL_GUARD_NATIVE_PROMPT_GROK,
        nativePromptValue.grok === true,
      ),
      kimi: booleanOverride(
        env.AGENT_SHELL_GUARD_NATIVE_PROMPT_KIMI,
        nativePromptValue.kimi === true,
      ),
    },
    reviewer,
  };
}

export const CONFIG_PATH = DEFAULT_CONFIG_PATH;
export const MANAGED_SHFMT_PATH = DEFAULT_MANAGED_SHFMT;
export const LAUNCHER_PATH = DEFAULT_LAUNCHER_PATH;
