// @ts-check
// agent-shell-guard policy profiles. The analyzer always runs; profiles only decide
// whether a matched rule may emit ask/deny or should defer to native approval.

/** @typedef {'full'|'dangerous-only'|'off'} PolicyProfile */
/** @type {Record<PolicyProfile, ReadonlySet<string>>} */
export const POLICY_PROFILES = {
  full: new Set([
    'org-ruleset-write',
    'rm-protected-root',
    'force-push-main',
    'shell-analysis-unknown',
    'remote-exec',
    'recursive-delete',
    'force-push',
    'destructive-sql',
    'dynamic-sql',
    'chmod-777',
    'gh-repo-delete',
    'gh-api-delete',
    'reset-hard-main',
    'reset-hard-remote',
    'git-destructive',
    'git-low-risk',
    'curl-pipe-sh',
  ]),
  'dangerous-only': new Set([
    'org-ruleset-write',
    'rm-protected-root',
    'force-push-main',
    'destructive-sql',
    'chmod-777',
    'gh-repo-delete',
    'gh-api-delete',
    'reset-hard-main',
    'git-destructive',
  ]),
  off: new Set(),
};

/** @param {string|undefined} value @returns {PolicyProfile} */
export function resolvePolicyProfile(value) {
  return value === 'dangerous-only' || value === 'off' || value === 'full' ? value : 'full';
}

/** @param {string} ruleId @param {PolicyProfile} profile */
export function isPolicyEnabled(ruleId, profile) {
  return POLICY_PROFILES[profile].has(ruleId);
}
