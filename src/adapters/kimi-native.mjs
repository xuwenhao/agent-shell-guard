// @ts-check

import { CODEX_NATIVE_PROMPT_PREFIXES } from './codex-native.mjs';
import { isNativePromptCovered } from './common.mjs';

/**
 * Kimi (and Grok, which copies this map) keeps a medium list: the Codex
 * ask-level prefixes plus the working-tree discard family and destructive SQL.
 * These hosts have no project sandbox to fall back on, so discarding
 * uncommitted work still gets a native confirmation there.
 * @type {Map<string, string[][]>}
 */
export const KIMI_NATIVE_PROMPT_PREFIXES = new Map([
  ...CODEX_NATIVE_PROMPT_PREFIXES,
  ['git-discard', [
    ['git', 'clean'],
    ['git', 'checkout'],
    ['git', 'reset'],
    ['git', 'restore'],
    ['git', 'rm'],
    ['git', 'stash', 'drop'],
    ['git', 'stash', 'clear'],
    ['git', 'tag', '-f'],
    ['git', 'tag', '--force'],
    ['git', 'switch', '--discard-changes'],
    ['git', 'switch', '-f'],
    ['git', 'switch', '--force'],
    ['git', 'worktree', 'remove', '--force'],
    ['git', 'worktree', 'remove', '-f'],
  ]],
  ['reset-hard-main', [['git', 'reset']]],
  ['destructive-sql', [['psql'], ['mysql'], ['mysqlsh'], ['sqlite3']]],
]);

/** @param {string[]} prefix */
export function kimiPermissionPattern(prefix) {
  return `Bash(${prefix.join(' ')}*)`;
}

export const KIMI_PERMISSION_PATTERNS = [
  ...new Set(
    [...KIMI_NATIVE_PROMPT_PREFIXES.values()]
      .flat()
      .map(kimiPermissionPattern),
  ),
];

/**
 * Kimi permission patterns match the original command string, not normalized
 * argv. Only delegate when both representations have the same literal prefix.
 *
 * @param {string} ruleId
 * @param {{nativePromptArgv: string[]|null}} analysis
 * @param {string} command
 */
export function isKimiNativePromptCovered(ruleId, analysis, command) {
  return isNativePromptCovered(ruleId, analysis, command, KIMI_NATIVE_PROMPT_PREFIXES);
}
