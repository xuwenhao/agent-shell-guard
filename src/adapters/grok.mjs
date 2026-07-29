// @ts-check

import { isGrokNativePromptCovered } from './grok-native.mjs';
import { evaluateForHost, reviewerToolReason } from './common.mjs';

/** @param {string} reason */
export function grokDenyOutput(reason) {
  return { decision: 'deny', reason };
}

/**
 * @param {Record<string, unknown>} event
 * @param {import('../config.mjs').GuardConfig|any} config
 */
export function adaptGrok(event, config) {
  const nestedReason = reviewerToolReason(event);
  if (nestedReason) return grokDenyOutput(nestedReason);
  const result = evaluateForHost(event, config, {
    supportsHookPrompt: false,
    nativePromptCovered: (decision) =>
      config.nativePrompt.grok &&
      isGrokNativePromptCovered(decision.ruleId, decision.analysis, decision.command),
  });
  if (result === null || result.resolved.action === 'allow' || result.resolved.action === 'delegate') return null;
  return grokDenyOutput(result.resolved.reason ?? '安全规则拒绝了该命令。');
}
