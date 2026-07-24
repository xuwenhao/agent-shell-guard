// @ts-check

import { isCodexNativePromptCovered } from './codex-native.mjs';
import { evaluateForHost, hookOutput, reviewerToolBlock } from './common.mjs';

/**
 * @param {Record<string, unknown>} event
 * @param {import('../config.mjs').GuardConfig|any} config
 */
export function adaptCodex(event, config) {
  const nestedBlock = reviewerToolBlock(event);
  if (nestedBlock) return nestedBlock;
  const result = evaluateForHost(event, config, {
    supportsHookPrompt: false,
    nativePromptCovered: (decision) =>
      config.nativePrompt.codex &&
      isCodexNativePromptCovered(decision.ruleId, decision.analysis),
  });
  if (result === null || result.resolved.action === 'allow' || result.resolved.action === 'delegate') return null;
  return hookOutput('deny', result.resolved.reason ?? '安全规则拒绝了该命令。');
}
