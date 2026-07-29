// @ts-check

import { KIMI_NATIVE_PROMPT_PREFIXES } from './kimi-native.mjs';

// Grok Build and Kimi both support Bash prefix rules that remain active in
// their always-approve modes. Keep the policy set aligned while giving each
// host its own matcher and setup surface.
/** @type {Map<string, string[][]>} */
export const GROK_NATIVE_PROMPT_PREFIXES = new Map(KIMI_NATIVE_PROMPT_PREFIXES);

/** @param {string[]} prefix */
function grokPermissionPatterns(prefix) {
  const literal = prefix.join(' ');
  return [literal, `${literal} *`];
}

export const GROK_PERMISSION_PATTERNS = [
  ...new Set(
    [...GROK_NATIVE_PROMPT_PREFIXES.values()]
      .flat()
      .flatMap(grokPermissionPatterns),
  ),
];

/**
 * Grok permission patterns match each shell segment's original text. Delegate
 * only when the hook payload is one static top-level command and its source
 * has the same literal prefix as the installed ask rule.
 *
 * @param {string} ruleId
 * @param {{nativePromptArgv: string[]|null}} analysis
 * @param {string} command
 */
export function isGrokNativePromptCovered(ruleId, analysis, command) {
  const prefixes = GROK_NATIVE_PROMPT_PREFIXES.get(ruleId);
  const argv = analysis.nativePromptArgv;
  if (prefixes === undefined || argv === null) return false;
  return prefixes.some((prefix) => {
    const argvMatches = prefix.every((part, index) => argv[index] === part);
    const literal = prefix.join(' ');
    const sourceMatches = command === literal || command.startsWith(`${literal} `);
    return argvMatches && sourceMatches;
  });
}
