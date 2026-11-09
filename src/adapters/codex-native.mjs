// @ts-check
// Codex 原生 prompt 的单一策略源：adapter 读取 rule id，`print-native-rules codex`
// 生成对应前缀，dotfiles 侧与静态的 codex/.codex/rules/default.rules 做双向对账。

/**
 * Prompt prefixes per rule. Codex has no permission mode or classifier, so the
 * guard keeps the 0.4 behaviour there (native tier): every `dangerous-only`
 * confirmation is delegated to one of these prefix rules when the command is
 * a single static argv they cover, and denied otherwise. This is the 0.4
 * `git-destructive` list re-keyed by the fine-grained rule ids; chmod 777 and
 * generic `gh api` DELETE had no prefix in 0.4 either and still fail closed.
 * Hard denies (gh repo delete, push to/delete of main, push --mirror) need no
 * prompt.
 * @type {Map<string, string[][]>}
 */
export const CODEX_NATIVE_PROMPT_PREFIXES = new Map([
  ['git-trunk-ref', [
    ['git', 'branch', '-D'],
    ['git', 'branch', '-d', 'main'],
    ['git', 'branch', '-d', 'master'],
    ['git', 'branch', '-M'],
    ['git', 'branch', '-C'],
    ['git', 'checkout', '-B'],
    ['git', 'switch', '-C'],
    ['git', 'switch', '--force-create'],
    ['git', 'worktree', 'add', '-B'],
  ]],
  ['git-ref-change', [
    ['git', 'branch', '-D'],
    ['git', 'branch', '-M'],
    ['git', 'branch', '-C'],
    ['git', 'worktree', 'remove'],
    ['git', 'worktree', 'add', '-B'],
    ['git', 'checkout', '-B'],
    ['git', 'switch', '-C'],
    ['git', 'switch', '--force-create'],
    ['git', 'lfs', 'prune'],
    ['git', 'push', '--delete'],
    ['git', 'push', '-d'],
  ]],
  ['git-discard', [
    ['git', 'clean', '-f'],
    ['git', 'clean', '--force'],
    ['git', 'clean', '-i'],
    ['git', 'clean', '--interactive'],
    ['git', 'reset'],
    ['git', 'restore'],
    ['git', 'checkout', '--'],
    ['git', 'checkout', '-f'],
    ['git', 'checkout', '--force'],
    ['git', 'checkout', '--ours'],
    ['git', 'checkout', '--theirs'],
    ['git', 'checkout', '-m'],
    ['git', 'checkout', '--merge'],
    ['git', 'checkout', '-p'],
    ['git', 'checkout', '--patch'],
    ['git', 'checkout', '--pathspec-from-file'],
    ['git', 'rm'],
    ['git', 'stash', 'drop'],
    ['git', 'stash', 'clear'],
    ['git', 'tag', '-f'],
    ['git', 'tag', '--force'],
    ['git', 'switch', '--discard-changes'],
    ['git', 'switch', '-f'],
    ['git', 'switch', '--force'],
    ['git', 'worktree', 'remove'],
  ]],
  ['reset-hard-main', [['git', 'reset']]],
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
    ['git', 'push', '--prune'],
  ]],
]);

/** Every distinct prefix, in table order (for `print-native-rules`). */
export function uniquePrefixes(/** @type {Map<string, string[][]>} */ table) {
  const seen = new Set();
  return [...table.values()].flat().filter((prefix) => {
    const key = JSON.stringify(prefix);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

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
