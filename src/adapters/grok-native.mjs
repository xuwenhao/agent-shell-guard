// @ts-check

import { KIMI_NATIVE_PROMPT_PREFIXES } from './kimi-native.mjs';
import { isNativePromptCovered } from './common.mjs';

// Grok Build and Kimi both support Bash prefix rules that remain active in
// their always-approve modes. Both use the medium list (Codex ask-level
// prefixes + git-discard + destructive SQL); keep a separate map so the hosts
// can diverge without touching each other's generated rules.
/** @type {Map<string, string[][]>} */
export const GROK_NATIVE_PROMPT_PREFIXES = new Map(
  [...KIMI_NATIVE_PROMPT_PREFIXES].map(([ruleId, prefixes]) => [ruleId, prefixes.map((prefix) => [...prefix])]),
);

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
  return isNativePromptCovered(ruleId, analysis, command, GROK_NATIVE_PROMPT_PREFIXES);
}
