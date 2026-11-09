// @ts-check
// agent-shell-guard policy profiles. The analyzer always runs; profiles only decide
// whether a matched rule may emit ask/deny or should defer to the host's own
// approval layer.

/** @typedef {'full'|'dangerous-only'|'legacy-dangerous'|'off'} PolicyProfile */
/** @typedef {'relaxed'|'bypass'} PermissionTier */

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
 * Confirmation rules that `dangerous-only` emits only in bypass sessions. In
 * auto/default/acceptEdits sessions (and hosts without a permission mode) the
 * guard stays silent and the host's classifier or native rules decide; a hook
 * `ask` would otherwise force a human prompt the classifier cannot answer.
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
]);

/** Rules that only exist for Claude bypass sessions. */
export const BYPASS_RULES = Object.freeze([
  'bypass-no-project-sandbox',
  'unsandboxed-outside-project',
]);

/** 0.4 `dangerous-only` confirmations that 0.5 relaxes. */
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
  'dangerous-only': new Set([...DENY_RULES, ...ASK_LEVEL_RULES, ...BYPASS_RULES]),
  // Rollback switch: the 0.4 dangerous-only confirmation set, in every
  // permission mode, on top of the 0.5 hard boundaries.
  'legacy-dangerous': new Set([...DENY_RULES, ...ASK_LEVEL_RULES, ...BYPASS_RULES, ...RELAXED_RULES]),
  off: new Set(),
};

/** Profiles whose ask-level rules defer to the host outside bypass sessions. */
const TIERED_PROFILES = new Set(['dangerous-only']);
const ASK_LEVEL = new Set(ASK_LEVEL_RULES);

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
  if (TIERED_PROFILES.has(profile) && ASK_LEVEL.has(ruleId) && tier !== 'bypass') return false;
  return true;
}

/**
 * Claude Code reports `permission_mode` on hook input. Only
 * `bypassPermissions` selects the bypass tier; `auto`, `default`,
 * `acceptEdits`, `plan`, unknown values and a missing field (Codex, Grok,
 * Kimi, older Claude Code) all use the relaxed tier.
 * @param {unknown} mode @returns {PermissionTier}
 */
export function permissionTier(mode) {
  return mode === 'bypassPermissions' ? 'bypass' : 'relaxed';
}
