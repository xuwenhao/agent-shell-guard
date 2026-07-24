// @ts-check

import { CODEX_NATIVE_PROMPT_PREFIXES } from './codex-native.mjs';

/** @type {Map<string, string[][]>} */
export const KIMI_NATIVE_PROMPT_PREFIXES = new Map([
  ...CODEX_NATIVE_PROMPT_PREFIXES,
  ['destructive-sql', [['psql'], ['mysql'], ['mysqlsh'], ['sqlite3']]],
  ['chmod-777', [['chmod']]],
  ['gh-api-delete', [['gh', 'api']]],
  ['reset-hard-main', [['git', 'reset']]],
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
  const prefixes = KIMI_NATIVE_PROMPT_PREFIXES.get(ruleId);
  const argv = analysis.nativePromptArgv;
  if (prefixes === undefined || argv === null) return false;
  return prefixes.some((prefix) => {
    const argvMatches = prefix.every((part, index) => argv[index] === part);
    const literal = prefix.join(' ');
    const sourceMatches = command === literal || command.startsWith(`${literal} `);
    return argvMatches && sourceMatches;
  });
}
