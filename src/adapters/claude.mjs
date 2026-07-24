// @ts-check

import { evaluateForHost, hookOutput, reviewerToolBlock } from './common.mjs';

/**
 * @param {Record<string, unknown>} event
 * @param {import('../config.mjs').GuardConfig|any} config
 */
export function adaptClaude(event, config) {
  const nestedBlock = reviewerToolBlock(event);
  if (nestedBlock) return nestedBlock;
  const result = evaluateForHost(event, config, {
    supportsHookPrompt: true,
    nativePromptCovered: () => false,
  });
  if (result === null || result.resolved.action === 'allow' || result.resolved.action === 'delegate') return null;
  if (result.resolved.action === 'prompt') {
    return hookOutput('ask', result.resolved.reason ?? '需要人工确认。');
  }
  return hookOutput('deny', result.resolved.reason ?? '安全规则拒绝了该命令。');
}
