// @ts-check
// agent-shell-guard policy profiles. The analyzer always runs; profiles only decide
// whether a matched rule may emit ask/deny or should defer to the host's own
// approval layer.

/** @typedef {'full'|'dangerous-only'|'legacy-dangerous'|'off'} PolicyProfile */
/**
 * `relaxed` / `bypass`: Claude Code sessions, chosen by `permission_mode`.
 * `native`: hosts without permission modes or a classifier (Codex, Grok,
 * Kimi). They keep the 0.4 behaviour: a confirmation is delegated to the
 * host's native prompt rule when one covers it, and denied otherwise.
 * @typedef {'relaxed'|'bypass'|'native'} PermissionTier
 */

/** Hard boundaries: deny in every tier of every profile that enables them. */
export const DENY_RULES = Object.freeze([
  'org-ruleset-write',
  'rm-protected-root',
  'rm-git-dir',
  'rm-protected-path',
  'git-clean-root',
  'force-push-main',
  'push-delete-trunk',
  'gh-repo-delete',
  'gh-api-delete-protected',
]);

/**
 * Confirmation rules that `dangerous-only` emits in Claude bypass sessions
 * and on native-prompt hosts. In Claude auto/default/acceptEdits sessions the
 * guard stays silent and the classifier decides; a hook `ask` would otherwise
 * force a human prompt the classifier cannot answer.
 */
export const ASK_LEVEL_RULES = Object.freeze([
  'destructive-sql',
  'reset-hard-main',
  'git-trunk-ref',
  'git-config-global',
  'git-lfs',
  'git-exec',
  'git-push-bulk',
  'gh-api-delete-sensitive',
  'push-delete-dynamic',
]);

/** Rules that only exist for Claude bypass sessions. */
export const BYPASS_RULES = Object.freeze([
  'bypass-no-project-sandbox',
  'unsandboxed-outside-project',
]);

/**
 * 0.4 `dangerous-only` confirmations that 0.5 relaxes for Claude sessions.
 * Native-prompt hosts keep them.
 */
export const RELAXED_RULES = Object.freeze([
  'git-discard',
  'git-ref-change',
  'chmod-777',
  'gh-api-delete',
]);

/** Everything else: only the `full` profile emits them. */
export const FULL_ONLY_RULES = Object.freeze([
  'shell-analysis-unknown',
  'remote-exec',
  'recursive-delete',
  'force-push',
  'dynamic-sql',
  'reset-hard-remote',
  'git-low-risk',
  'curl-pipe-sh',
]);

/** @type {Record<PolicyProfile, ReadonlySet<string>>} */
export const POLICY_PROFILES = {
  full: new Set([...DENY_RULES, ...ASK_LEVEL_RULES, ...BYPASS_RULES, ...RELAXED_RULES, ...FULL_ONLY_RULES]),
  'dangerous-only': new Set([...DENY_RULES, ...ASK_LEVEL_RULES, ...BYPASS_RULES, ...RELAXED_RULES]),
  // Rollback switch: the 0.4 dangerous-only confirmation set in every
  // permission mode and on every host, without the 0.5 bypass-session rules.
  // The 0.5 hard boundaries stay.
  'legacy-dangerous': new Set([...DENY_RULES, ...ASK_LEVEL_RULES, ...RELAXED_RULES]),
  off: new Set(),
};

const ASK_LEVEL = new Set(ASK_LEVEL_RULES);
const RELAXED = new Set(RELAXED_RULES);
const BYPASS = new Set(BYPASS_RULES);

/** @param {string|undefined} value @returns {PolicyProfile} */
export function resolvePolicyProfile(value) {
  return value === 'dangerous-only' || value === 'off' || value === 'full' || value === 'legacy-dangerous'
    ? value
    : 'dangerous-only';
}

/**
 * @param {string} ruleId @param {PolicyProfile} profile
 * @param {PermissionTier} [tier] defaults to the relaxed tier
 */
export function isPolicyEnabled(ruleId, profile, tier = 'relaxed') {
  if (!POLICY_PROFILES[profile].has(ruleId)) return false;
  if (BYPASS.has(ruleId) && tier !== 'bypass') return false;
  if (profile !== 'dangerous-only') return true;
  if (ASK_LEVEL.has(ruleId)) return tier !== 'relaxed';
  if (RELAXED.has(ruleId)) return tier === 'native';
  return true;
}

/**
 * Claude Code reports `permission_mode` on hook input. Only
 * `bypassPermissions` selects the bypass tier; `auto`, `default`,
 * `acceptEdits`, `plan`, unknown values and a missing field (older Claude
 * Code) use the relaxed tier. Other hosts always use the native tier.
 * @param {unknown} mode
 * @param {'claude'|'codex'|'grok'|'kimi'} [host] defaults to claude
 * @returns {PermissionTier}
 */
export function permissionTier(mode, host = 'claude') {
  if (host !== 'claude') return 'native';
  return mode === 'bypassPermissions' ? 'bypass' : 'relaxed';
}
