// @ts-check

import { explainGuardDecision } from './guard-core.mjs';
import { runModelReview } from './reviewer.mjs';

/**
 * @typedef {{
 *   action: 'allow'|'deny'|'prompt'|'delegate',
 *   reason?: string,
 *   reviewer?: {decision: 'allow'|'deny'|'uncertain', reason: string},
 * }} ResolvedDecision
 */

/**
 * @param {Exclude<ReturnType<typeof import('./guard-core.mjs')['evaluateHookEvent']>, null>} decision
 * @param {{
 *   supportsHookPrompt: boolean,
 *   nativePromptCovered: boolean,
 *   mode: 'strict'|'reviewed',
 *   reviewer: import('./config.mjs').ReviewerConfig|null,
 * }} options
 * @returns {ResolvedDecision}
 */
export function resolveDecision(decision, options) {
  if (decision.kind === 'allow') return { action: 'allow' };
  const explanation = explainGuardDecision(decision);
  if (decision.kind === 'deny') return { action: 'deny', reason: explanation };
  if (options.supportsHookPrompt) return { action: 'prompt', reason: explanation };
  if (options.nativePromptCovered) return { action: 'delegate' };

  const mayReview = options.mode === 'reviewed';
  if (!mayReview || options.reviewer === null) {
    const unavailable = decision.kind === 'confirm'
      ? '当前宿主无法保证弹出人工确认，且未启用可用的第二模型 reviewer。'
      : '当前未启用可用的第二模型 reviewer。';
    return { action: 'deny', reason: `${unavailable}${explanation}` };
  }

  const review = runModelReview(decision, options.reviewer);
  if (review.decision === 'allow') {
    return { action: 'allow', reviewer: review };
  }
  return {
    action: 'deny',
    reason: `第二模型安全复核未放行（${review.decision}）：${review.reason}。${explanation}`,
    reviewer: review,
  };
}
