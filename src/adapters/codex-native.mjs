// @ts-check
// Codex 原生 prompt 的单一策略源：adapter 读取 rule id，测试读取对应命令前缀，
// 并与静态的 codex/.codex/rules/default.rules 做完整双向对账。

/** @type {Map<string, string[][]>} */
export const CODEX_NATIVE_PROMPT_PREFIXES = new Map([
  ['gh-repo-delete', [['gh', 'repo', 'delete']]],
  // 这里只列能由静态 prefix 精确表达的高风险形式。branch -d --force 等组合
  // 若保留低风险短前缀，会让纯 branch -d 也被 prompt；因此由 adapter fail-closed。
  ['git-destructive', [
    ['git', 'branch', '-D'],
    ['git', 'branch', '-M'],
    ['git', 'branch', '-C'],
    ['git', 'worktree', 'remove'],
    ['git', 'worktree', 'add', '-B'],
    ['git', 'clean'],
    ['git', 'reset'],
    ['git', 'restore'],
    ['git', 'checkout'],
    ['git', 'rm'],
    ['git', 'config', '--global'],
    ['git', 'config', '--system'],
    ['git', 'stash', 'drop'],
    ['git', 'stash', 'clear'],
    ['git', 'tag', '-f'],
    ['git', 'tag', '--force'],
    ['git', 'switch', '--discard-changes'],
    ['git', 'switch', '-f'],
    ['git', 'switch', '--force'],
    ['git', 'switch', '-C'],
    ['git', 'switch', '--force-create'],
    ['git', 'submodule', 'foreach'],
    ['git', 'lfs', 'install'],
    ['git', 'lfs', 'migrate'],
    ['git', 'lfs', 'uninstall'],
    ['git', 'lfs', 'prune'],
    ['git', 'rebase', '-x'],
    ['git', 'rebase', '--exec'],
    ['git', 'rebase', '--reschedule-failed-exec'],
    ['git', 'push', '--delete'],
    ['git', 'push', '-d'],
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
