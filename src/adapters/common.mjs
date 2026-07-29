// @ts-check

import { evaluateHookEvent } from '../guard-core.mjs';
import { resolveDecision } from '../resolver.mjs';
import { isReviewSubprocess } from '../reviewer.mjs';

/**
 * @param {Record<string, unknown>} event
 * @param {import('../config.mjs').GuardConfig|any} config
 * @param {{supportsHookPrompt: boolean, nativePromptCovered: (decision: any) => boolean}} capabilities
 */
export function evaluateForHost(event, config, capabilities) {
  const decision = evaluateHookEvent(event, {
    profile: config.profile,
    envShell: process.env.SHELL,
    shfmtPath: config.shfmtPath,
    zshPath: config.zshPath,
    protectedRoots: config.protectedRoots,
  });
  if (decision === null) return null;
  return {
    decision,
    resolved: resolveDecision(decision, {
      supportsHookPrompt: capabilities.supportsHookPrompt,
      nativePromptCovered: decision.kind === 'allow'
        ? false
        : capabilities.nativePromptCovered(decision),
      mode: config.mode,
      reviewer: config.reviewer,
    }),
  };
}

/** @param {'ask'|'deny'} permissionDecision @param {string} reason */
export function hookOutput(permissionDecision, reason) {
  return {
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision,
      permissionDecisionReason: reason,
    },
  };
}

/**
 * @param {string} ruleId
 * @param {{nativePromptArgv: string[]|null}} analysis
 * @param {string} command
 * @param {Map<string, string[][]>} prefixesByRule
 */
export function isNativePromptCovered(ruleId, analysis, command, prefixesByRule) {
  const prefixes = prefixesByRule.get(ruleId);
  const argv = analysis.nativePromptArgv;
  if (prefixes === undefined || argv === null) return false;
  return prefixes.some((prefix) => {
    const argvMatches = prefix.every((part, index) => argv[index] === part);
    const literal = prefix.join(' ');
    const sourceMatches = command === literal || command.startsWith(`${literal} `);
    return argvMatches && sourceMatches;
  });
}

/** @param {Record<string, unknown>} event */
export function reviewerToolReason(event) {
  const toolName = String(event.tool_name ?? event.toolName ?? '');
  if (!isReviewSubprocess() ||
      !/^(Bash|shell|local_shell|exec_command|run_terminal_command)$/i.test(toolName)) return null;
  return '第二模型 reviewer 不允许调用 shell 工具；本次复核必须只基于 guard 提供的静态 command graph。';
}

/** @param {Record<string, unknown>} event */
export function reviewerToolBlock(event) {
  const reason = reviewerToolReason(event);
  return reason ? hookOutput('deny', reason) : null;
}
