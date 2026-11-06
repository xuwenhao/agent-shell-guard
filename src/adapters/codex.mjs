// @ts-check

import { isCodexNativePromptCovered, codexNativePromptFailure } from './codex-native.mjs';
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
  let reason = result.resolved.reason ?? '安全规则拒绝了该命令。';
  if (result.decision.kind !== 'allow' && result.resolved.reasonCode === 'native-prompt-unavailable') {
    const code = codexNativePromptFailure(result.decision.ruleId, result.decision.analysis, config.nativePrompt.codex);
    // Keep the host's supported hook schema. The JSON marker carries stable,
    // credential-free fields for log consumers without serializing the command.
    reason += `\n[guard-diagnostic] ${JSON.stringify({ reasonCode: code, ruleId: result.decision.ruleId, decisionSource: 'hook' })}`;
    if (code === 'native-prompt-disabled') reason += '\n原生委托未启用：先由配置维护流程安装版本匹配的原生规则并启用 nativePrompt.codex；不要仅切换该标志。';
    if (result.decision.ruleId === 'git-destructive') {
      reason += '\n恢复：require_escalated 不会解除 hook 拒绝。仅对已获授权的操作，用工具 workdir 指定仓库，单独调用一条目标明确的静态 Git 命令；不要附带 &&、换行后的 status/rg/cat、git -C 或变量展开。后续读取另起调用。仍未覆盖的命令需保留人工处理，不得绕过硬拒绝或原生审批结果。';
    }
  }
  return hookOutput('deny', reason);
}
