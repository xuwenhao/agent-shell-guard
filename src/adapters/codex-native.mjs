// @ts-check
// Codex 原生 prompt 的单一策略源：adapter 读取 rule id，`print-native-rules codex`
// 生成对应前缀，dotfiles 侧与静态的 codex/.codex/rules/default.rules 做双向对账。

/**
 * Prompt prefixes for the 0.5 ask-level rules. Codex has no permission mode
 * in its hook input, so the guard uses the relaxed tier there and never emits
 * these confirmations itself under `dangerous-only`; the generated rules are
 * Codex's own approval layer for them. Rules relaxed in 0.5 (git-discard,
 * non-trunk ref changes, chmod 777, generic gh api DELETE) are intentionally
 * absent, and hard denies (gh repo delete, push --delete main) need no prompt.
 * @type {Map<string, string[][]>}
 */
export const CODEX_NATIVE_PROMPT_PREFIXES = new Map([
  ['git-trunk-ref', [
    ['git', 'branch', '-D', 'main'],
    ['git', 'branch', '-D', 'master'],
    ['git', 'branch', '-d', 'main'],
    ['git', 'branch', '-d', 'master'],
    ['git', 'checkout', '-B', 'main'],
    ['git', 'checkout', '-B', 'master'],
    ['git', 'switch', '-C', 'main'],
    ['git', 'switch', '-C', 'master'],
  ]],
  ['reset-hard-main', [
    ['git', 'reset', '--hard', 'origin/main'],
    ['git', 'reset', '--hard', 'origin/master'],
    ['git', 'reset', '--hard', 'main'],
    ['git', 'reset', '--hard', 'master'],
  ]],
  ['git-config-global', [
    ['git', 'config', '--global'],
    ['git', 'config', '--system'],
  ]],
  ['git-lfs', [
    ['git', 'lfs', 'install'],
    ['git', 'lfs', 'migrate'],
    ['git', 'lfs', 'uninstall'],
  ]],
  ['git-exec', [
    ['git', 'submodule', 'foreach'],
    ['git', 'rebase', '-x'],
    ['git', 'rebase', '--exec'],
    ['git', 'rebase', '--reschedule-failed-exec'],
  ]],
  ['git-push-bulk', [
    ['git', 'push', '--mirror'],
    ['git', 'push', '--prune'],
  ]],
]);

// native prompt 只接管 analyzer 证明为“一个完全静态顶层简单命令”的 argv。
// wrapper、重定向、替换、compound、动态 word 都会令 nativePromptArgv 为 null。
/** @param {string} ruleId @param {{nativePromptArgv: string[]|null}} analysis */
export function isCodexNativePromptCovered(ruleId, analysis) {
  const prefixes = CODEX_NATIVE_PROMPT_PREFIXES.get(ruleId);
  const argv = analysis.nativePromptArgv;
  return prefixes !== undefined && argv !== null && prefixes.some((prefix) =>
    prefix.every((part, index) => argv[index] === part));
}

/** Diagnostic only: never changes the native delegation decision.
 * @param {string} ruleId @param {{nativePromptArgv:string[]|null}} analysis
 * @param {boolean} enabled
 * @returns {'native-prompt-disabled'|'native-prompt-shape-unsupported'|'native-prompt-prefix-uncovered'|null}
 */
export function codexNativePromptFailure(ruleId, analysis, enabled) {
  if (!enabled) return 'native-prompt-disabled';
  if (analysis.nativePromptArgv === null) return 'native-prompt-shape-unsupported';
  return isCodexNativePromptCovered(ruleId, analysis) ? null : 'native-prompt-prefix-uncovered';
}
