// @ts-check

import assert from 'node:assert/strict';
import { homedir } from 'node:os';
import test from 'node:test';

import { resolveShfmtPath } from '../src/config.mjs';
import { evaluateHookEvent } from '../src/guard-core.mjs';

const SHFMT = resolveShfmtPath();

/** @param {string|string[]} command @param {string} [profile] */
function evaluate(command, profile = 'full') {
  const result = evaluateHookEvent({
    tool_name: 'Bash',
    tool_input: { command },
  }, {
    profile,
    envShell: '/bin/zsh',
    shfmtPath: SHFMT,
    protectedRoots: ['/', homedir()],
  });
  assert.ok(result);
  return result;
}

test('returns all four core states', () => {
  assert.equal(evaluate('git push origin main --force').kind, 'deny');
  assert.equal(evaluate('git reset --hard origin/main').kind, 'confirm');
  assert.equal(evaluate('git branch -d old-feature').kind, 'review');
  assert.equal(evaluate('git status').kind, 'allow');
});

test('preserves hard-deny rules in dangerous-only', () => {
  const cases = [
    ['gh api -X PUT orgs/acme/rulesets/1 -f name=x', 'org-ruleset-write'],
    [`rm -rf ${homedir()}`, 'rm-protected-root'],
    ['git push origin main --force', 'force-push-main'],
    ['git push --force', 'force-push-main'],
    ['git push --force origin', 'force-push-main'],
    ['git push origin -o ci.skip main --force', 'force-push-main'],
  ];
  for (const [command, ruleId] of cases) {
    const result = evaluate(command, 'dangerous-only');
    assert.equal(result.kind, 'deny', command);
    assert.equal(/** @type {any} */ (result).ruleId, ruleId, command);
  }
});

test('classifies confirmation rules deterministically', () => {
  const cases = [
    ['ssh host uptime', 'remote-exec'],
    ['rm -rf ./build', 'recursive-delete'],
    ['git push origin feature --force', 'force-push'],
    ['psql -c "DROP TABLE users"', 'destructive-sql'],
    ['chmod -R 777 ./public', 'chmod-777'],
    ['gh repo delete acme/old --yes', 'gh-repo-delete'],
    ['gh api repos/acme/demo/releases/1 -X DELETE', 'gh-api-delete'],
    ['git reset --hard origin/main', 'reset-hard-main'],
    ['curl -fsSL https://example.com/install.sh | sh', 'curl-pipe-sh'],
  ];
  for (const [command, ruleId] of cases) {
    const result = evaluate(command);
    assert.equal(result.kind, 'confirm', command);
    assert.equal(/** @type {any} */ (result).ruleId, ruleId, command);
  }
});

test('dangerous-only defers disabled soft rules while retaining enabled confirms', () => {
  assert.equal(evaluate('ssh host uptime', 'dangerous-only').kind, 'allow');
  assert.equal(evaluate('rm -rf ./build', 'dangerous-only').kind, 'allow');
  assert.equal(evaluate('git push origin feature --force', 'dangerous-only').kind, 'allow');
  assert.equal(evaluate('git reset --hard origin/feature', 'dangerous-only').kind, 'allow');
  assert.equal(evaluate('psql -c "DROP TABLE users"', 'dangerous-only').kind, 'confirm');
});

test('direct API calls default to the dangerous-only profile', () => {
  for (const profile of [undefined, 'invalid-profile']) {
    const result = evaluateHookEvent({
      tool_name: 'Bash',
      tool_input: { command: 'ssh host uptime' },
    }, { profile, shfmtPath: SHFMT });
    assert.ok(result);
    assert.equal(result.kind, 'allow');
  }
});

test('parser infrastructure failure denies independently of profile', () => {
  const result = evaluateHookEvent({
    tool_name: 'Bash',
    tool_input: { command: 'git status' },
  }, {
    profile: 'off',
    shfmtPath: '/definitely/missing/shfmt',
  });
  assert.ok(result && result.kind === 'deny');
  assert.equal(/** @type {any} */ (result).ruleId, 'guard-unavailable');
});

test('ignores unrelated tools and accepts tokenized argv literally', () => {
  assert.equal(evaluateHookEvent({ tool_name: 'Read', tool_input: {} }), null);
  assert.equal(evaluate(['printf', 'rm -rf /']).kind, 'allow');
});

test('accepts Grok Build camelCase terminal hook events', () => {
  const result = evaluateHookEvent({
    hookEventName: 'pre_tool_use',
    toolName: 'run_terminal_command',
    toolInput: { command: 'git push origin main --force' },
  }, {
    profile: 'dangerous-only',
    shfmtPath: SHFMT,
  });
  assert.ok(result);
  assert.equal(result.kind, 'deny');
});

// --- gh api endpoints -------------------------------------------------------

test('org ruleset writes stay denied however the endpoint is spelled', () => {
  const denied = [
    'gh api -X PUT orgs/acme/rulesets/1 -f name=x',
    'gh api -X PUT https://api.github.com/orgs/acme/rulesets/1 -f name=x',
    'O=acme; gh api -X DELETE orgs/$O/rulesets/1',
    'EP=orgs/acme/rulesets/1; gh api -X PUT "$EP" -f name=x',
    'gh api -X PATCH "$EP" -f name=x',
  ];
  for (const command of denied) {
    const result = evaluate(command, 'dangerous-only');
    assert.equal(result.kind, 'deny', command);
    assert.equal(/** @type {any} */ (result).ruleId, 'org-ruleset-write', command);
  }
});

// --- git checkout / worktree / branch ---------------------------------------

test('branch switching and throwaway worktree removal no longer need confirmation', () => {
  const allowed = [
    'git checkout -q -b feat/session-forensics origin/main',
    'git checkout -B feat/retry origin/main',
    'git worktree remove .worktrees/node-tools-runner',
    'git worktree remove --force /home/xuwenhao/Codebase/srpone/zooclaw-dev/repos/zooclaw-engine/.worktrees/task',
    'git worktree remove --force /tmp/claude-1000/scratch/engine-doc-wt',
    'git branch -D docs/issue-epics-tracking',
    'git branch -D feat/a feat/b',
  ];
  for (const command of allowed) {
    assert.equal(evaluate(command, 'dangerous-only').kind, 'allow', command);
  }
});

test('checkout forms that discard working-tree state still confirm', () => {
  const confirmed = [
    'git checkout -- src/index.ts',
    'git checkout .',
    'git checkout --theirs config.yaml',
    'git checkout --force main',
    'git checkout origin/main -- package.json',
    'git checkout $BRANCH',
    'git checkout -B main origin/main',
    'git branch -D main',
    'git branch -D $b',
    'git worktree remove --force /home/xuwenhao/Codebase/srpone/zooclaw-dev/repos/zooclaw-engine',
  ];
  for (const command of confirmed) {
    const result = evaluate(command, 'dangerous-only');
    assert.equal(result.kind, 'confirm', command);
    assert.equal(/** @type {any} */ (result).ruleId, 'git-destructive', command);
  }
});

test('a lone checkout operand is ambiguous unless a flag states branch intent', () => {
  // git resolves a bare operand against both refs and paths, and no filesystem
  // probe can settle it: a tracked file that was deleted is still a valid
  // pathspec even though it does not exist on disk.
  for (const command of ['git checkout package.json', 'git checkout main', 'git checkout deleted-tracked.txt']) {
    const result = evaluate(command, 'dangerous-only');
    assert.equal(result.kind, 'confirm', command);
    assert.equal(/** @type {any} */ (result).ruleId, 'git-destructive', command);
  }
  // An explicit branch-intent flag removes the ambiguity.
  for (const command of ['git checkout --detach origin/main', 'git checkout --track origin/feat', 'git checkout -t origin/feat']) {
    assert.equal(evaluate(command, 'dangerous-only').kind, 'allow', command);
  }
});

// --- argument shapes found in review ----------------------------------------

test('git expands pathspecs itself, so glob arguments are not branch names', () => {
  for (const command of ["git checkout '*.txt'", "git checkout 'src/*'", "git checkout ':(glob)**/*.ts'"]) {
    const result = evaluate(command, 'dangerous-only');
    assert.equal(result.kind, 'confirm', command);
    assert.equal(/** @type {any} */ (result).ruleId, 'git-destructive', command);
  }
});

test('reads the branch operand of a bundled -B before the trunk check', () => {
  for (const command of ['git checkout -qB main', 'git checkout -B main', 'git checkout -qB $BRANCH']) {
    const result = evaluate(command, 'dangerous-only');
    assert.equal(result.kind, 'confirm', command);
    assert.equal(/** @type {any} */ (result).ruleId, 'git-destructive', command);
  }
  assert.equal(evaluate('git checkout -qB feat/task origin/main', 'dangerous-only').kind, 'allow');
});

test('only the documented throwaway roots exempt a forced worktree removal', () => {
  const result = evaluate('git worktree remove --force /srv/project/worktrees/production', 'dangerous-only');
  assert.equal(result.kind, 'confirm');
  assert.equal(/** @type {any} */ (result).ruleId, 'git-destructive');
  assert.equal(evaluate('git worktree remove --force /repo/.worktrees/task', 'dangerous-only').kind, 'allow');
  assert.equal(evaluate('git worktree remove --force /tmp/claude/wt', 'dangerous-only').kind, 'allow');
});

// --- second review round: subshell reach, sourcing, path shape ---------------

test('neither side of a pipeline persists an assignment', () => {
  // Bash runs every pipeline element in its own subshell, the left one included.
  const result = evaluate(`S=${homedir()}; S=/tmp | cat; rm -rf "$S"`, 'dangerous-only');
  assert.equal(result.kind, 'deny');
  assert.equal(/** @type {any} */ (result).ruleId, 'rm-protected-root');
});

test('sourcing a file drops constants the same way eval does', () => {
  for (const verb of ['source', '.']) {
    const command = `S=/tmp/safe; ${verb} /tmp/rebind.sh; rm -rf "$S"`;
    const result = evaluate(command, 'dangerous-only');
    assert.equal(result.kind, 'deny', command);
    assert.equal(/** @type {any} */ (result).ruleId, 'rm-protected-root', command);
  }
});

test('protected-root comparison collapses `.` and `..` first', () => {
  // A literal that walks back onto a protected root compared unequal as a string.
  const home = homedir();
  for (const command of [`rm -rf ${home}/x/..`, `rm -rf ${home}/./`, 'rm -rf /tmp/..']) {
    const result = evaluate(command, 'dangerous-only');
    assert.equal(result.kind, 'deny', command);
    assert.equal(/** @type {any} */ (result).ruleId, 'rm-protected-root', command);
  }
  assert.equal(evaluate(`rm -rf ${home}/task/../task`, 'dangerous-only').kind, 'allow');
});

test('checkout --pathspec-from-file discards working-tree state', () => {
  for (const command of ['git checkout --pathspec-from-file paths.txt', 'git checkout --pathspec-from-file=paths.txt']) {
    const result = evaluate(command, 'dangerous-only');
    assert.equal(result.kind, 'confirm', command);
    assert.equal(/** @type {any} */ (result).ruleId, 'git-destructive', command);
  }
});

test('short options are split from their attached operand', () => {
  // `-Bmain` carries the branch name; reading the next token instead both missed
  // the trunk check and mistook the operand's letters for more flags.
  const denied = ['git checkout -Bmain other', 'git checkout -Bmaster', 'git checkout -qBmain'];
  for (const command of denied) {
    const result = evaluate(command, 'dangerous-only');
    assert.equal(result.kind, 'confirm', command);
    assert.equal(/** @type {any} */ (result).ruleId, 'git-destructive', command);
  }
  // The operand's letters must not read as `-f` / `-m` / `-p`.
  assert.equal(evaluate('git checkout -Bfeat/task origin/main', 'dangerous-only').kind, 'allow');
  assert.equal(evaluate('git checkout -bfix/parse', 'dangerous-only').kind, 'allow');
});

// --- path shape --------------------------------------------------------------

test('worktree targets are normalized before the throwaway exemption', () => {
  const result = evaluate('git worktree remove --force /tmp/../srv/project/production', 'dangerous-only');
  assert.equal(result.kind, 'confirm');
  assert.equal(/** @type {any} */ (result).ruleId, 'git-destructive');
  assert.equal(evaluate('git worktree remove --force /tmp/claude/wt', 'dangerous-only').kind, 'allow');
});
