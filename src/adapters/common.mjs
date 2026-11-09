// @ts-check

import { evaluateHookEvent, eventCwd, eventToolInput } from '../guard-core.mjs';
import { inspectDirectory, memoizeInspector } from '../project.mjs';
import { resolveDecision } from '../resolver.mjs';
import { isReviewSubprocess } from '../reviewer.mjs';
import { logUnsandboxedCall } from '../unsandboxed-log.mjs';

/**
 * @param {Record<string, unknown>} event
 * @param {import('../config.mjs').GuardConfig|any} config
 * @param {{supportsHookPrompt: boolean, nativePromptCovered: (decision: any) => boolean}} capabilities
 * @param {{inspectDirectory?: (directory: string) => import('../project.mjs').ProjectInfo, env?: NodeJS.ProcessEnv}} [runtime]
 */
export function evaluateForHost(event, config, capabilities, runtime = {}) {
  const inspect = memoizeInspector(runtime.inspectDirectory ?? ((directory) => inspectDirectory(directory)));
  const decision = evaluateHookEvent(event, {
    profile: config.profile,
    envShell: process.env.SHELL,
    shfmtPath: config.shfmtPath,
    zshPath: config.zshPath,
    protectedRoots: config.protectedRoots,
    protectedPaths: config.protectedPaths ?? [],
    inspectDirectory: inspect,
  });
  if (decision === null) return null;
  if (eventToolInput(event).dangerouslyDisableSandbox === true) {
    let gitRoot = null;
    const cwd = eventCwd(event);
    try { gitRoot = cwd ? inspect(cwd).gitRoot : null; } catch { gitRoot = null; }
    logUnsandboxedCall({
      command: decision.command,
      cwd,
      gitRoot,
      permissionMode: event.permission_mode ?? event.permissionMode,
      sessionId: event.session_id ?? event.sessionId,
      decision: decision.kind,
    }, { env: runtime.env });
  }
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
