// @ts-check

import assert from 'node:assert/strict';
import { homedir, tmpdir } from 'node:os';
import { mkdtempSync, writeFileSync, readFileSync, existsSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
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

test('dangerous-only defers soft rules; ask-level rules confirm only in legacy/full here', () => {
  assert.equal(evaluate('ssh host uptime', 'dangerous-only').kind, 'allow');
  assert.equal(evaluate('rm -rf ./build', 'dangerous-only').kind, 'allow');
  assert.equal(evaluate('git push origin feature --force', 'dangerous-only').kind, 'allow');
  assert.equal(evaluate('git reset --hard origin/feature', 'dangerous-only').kind, 'allow');
  // No permission_mode in the event: relaxed tier, the host decides.
  assert.equal(evaluate('psql -c "DROP TABLE users"', 'dangerous-only').kind, 'allow');
  assert.equal(evaluate('psql -c "DROP TABLE users"', 'legacy-dangerous').kind, 'confirm');
});

test('gh repo delete is a hard deny in every profile but off', () => {
  for (const profile of ['full', 'dangerous-only', 'legacy-dangerous']) {
    const result = evaluate('gh repo delete acme/old --yes', profile);
    assert.equal(result.kind, 'deny', profile);
    assert.equal(/** @type {any} */ (result).ruleId, 'gh-repo-delete', profile);
  }
  assert.equal(evaluate('gh repo delete acme/old --yes', 'off').kind, 'allow');
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
    'gh api -X PUT https://API.GITHUB.COM/orgs/acme/rulesets/1 -f name=x',
    'gh api -X PUT https://api.github.com.:443/orgs/acme/rulesets/1 -f name=x',
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

test('branch switching no longer needs confirmation', () => {
  const allowed = [
    'git checkout -q -b feat/session-forensics origin/main',
    'git branch -d docs/issue-epics-tracking',
    'git branch --delete feat/a feat/b',
  ];
  for (const command of allowed) {
    assert.equal(evaluate(command, 'legacy-dangerous').kind, 'allow', command);
  }
});

test('checkout forms that discard working-tree state still confirm (legacy profile)', () => {
  const confirmed = [
    ['git checkout -- src/index.ts', 'git-discard'],
    ['git checkout .', 'git-discard'],
    ['git checkout --theirs config.yaml', 'git-discard'],
    ['git checkout --force main', 'git-discard'],
    ['git checkout origin/main -- package.json', 'git-discard'],
    ['git checkout $BRANCH', 'git-discard'],
    ['git checkout -B main origin/main', 'git-trunk-ref'],
    ['git branch -D main', 'git-trunk-ref'],
    ['git branch -d main', 'git-trunk-ref'],
    ['git branch -d $b', 'git-trunk-ref'],
    // `-D` drops unmerged commits and the branch's own reflog with them.
    ['git branch -D docs/issue-epics-tracking', 'git-ref-change'],
    ['git branch --delete --force feat/a', 'git-ref-change'],
    // git follows a symlinked path and discards gitignored files without
    // --force, so no spelling of the path proves the removal is throwaway.
    ['git worktree remove .worktrees/node-tools-runner', 'git-ref-change'],
    ['git worktree remove --force /tmp/claude-1000/scratch/engine-doc-wt', 'git-discard'],
    ['git worktree remove --force /home/xuwenhao/Codebase/srpone/zooclaw-dev/repos/zooclaw-engine', 'git-discard'],
  ];
  for (const [command, ruleId] of confirmed) {
    const result = evaluate(command, 'legacy-dangerous');
    assert.equal(result.kind, 'confirm', command);
    assert.equal(/** @type {any} */ (result).ruleId, ruleId, command);
  }
});

test('a lone checkout operand is ambiguous unless a flag states branch intent', () => {
  // git resolves a bare operand against both refs and paths, and no filesystem
  // probe can settle it: a tracked file that was deleted is still a valid
  // pathspec even though it does not exist on disk.
  for (const command of ['git checkout package.json', 'git checkout main', 'git checkout deleted-tracked.txt']) {
    const result = evaluate(command, 'legacy-dangerous');
    assert.equal(result.kind, 'confirm', command);
    assert.equal(/** @type {any} */ (result).ruleId, 'git-discard', command);
  }
  // An explicit branch-intent flag removes the ambiguity.
  for (const command of ['git checkout --detach origin/main', 'git checkout --track origin/feat', 'git checkout -t origin/feat']) {
    assert.equal(evaluate(command, 'legacy-dangerous').kind, 'allow', command);
  }
});

// --- argument shapes found in review ----------------------------------------

test('git expands pathspecs itself, so glob arguments are not branch names', () => {
  for (const command of ["git checkout '*.txt'", "git checkout 'src/*'", "git checkout ':(glob)**/*.ts'"]) {
    const result = evaluate(command, 'legacy-dangerous');
    assert.equal(result.kind, 'confirm', command);
    assert.equal(/** @type {any} */ (result).ruleId, 'git-discard', command);
  }
});

test('reads the branch operand of a bundled -B before the trunk check', () => {
  for (const command of [
    'git checkout -qB main', 'git checkout -B main', 'git checkout -qB $BRANCH',
    // `-B '@{-1}'` resets whatever branch was checked out before, main included.
    "git checkout -B '@{-1}' HEAD", 'git checkout -B -', 'git checkout -B main@{yesterday}',
  ]) {
    const result = evaluate(command, 'legacy-dangerous');
    assert.equal(result.kind, 'confirm', command);
    assert.equal(/** @type {any} */ (result).ruleId, 'git-trunk-ref', command);
  }
  assert.equal(evaluate('git checkout -qB feat/task origin/main', 'legacy-dangerous').kind, 'confirm');
});

// --- second review round: subshell reach, sourcing, path shape ---------------

test('neither side of a pipeline persists an assignment', () => {
  // Bash runs every pipeline element in its own subshell, the left one included.
  const result = evaluate(`S=${homedir()}; S=/tmp | cat; rm -rf "$S"`, 'legacy-dangerous');
  assert.equal(result.kind, 'deny');
  assert.equal(/** @type {any} */ (result).ruleId, 'rm-protected-root');
});

test('sourcing a file drops constants the same way eval does', () => {
  for (const verb of ['source', '.']) {
    const command = `S=/tmp/safe; ${verb} /tmp/rebind.sh; rm -rf "$S"`;
    const result = evaluate(command, 'legacy-dangerous');
    assert.equal(result.kind, 'deny', command);
    assert.equal(/** @type {any} */ (result).ruleId, 'rm-protected-root', command);
  }
});

test('protected-root comparison collapses `.` and `..` first', () => {
  // A literal that walks back onto a protected root compared unequal as a string.
  const home = homedir();
  for (const command of [`rm -rf ${home}/x/..`, `rm -rf ${home}/./`, 'rm -rf /tmp/..']) {
    const result = evaluate(command, 'legacy-dangerous');
    assert.equal(result.kind, 'deny', command);
    assert.equal(/** @type {any} */ (result).ruleId, 'rm-protected-root', command);
  }
  assert.equal(evaluate(`rm -rf ${home}/task/../task`, 'legacy-dangerous').kind, 'allow');
});

test('checkout --pathspec-from-file discards working-tree state', () => {
  for (const command of ['git checkout --pathspec-from-file paths.txt', 'git checkout --pathspec-from-file=paths.txt']) {
    const result = evaluate(command, 'legacy-dangerous');
    assert.equal(result.kind, 'confirm', command);
    assert.equal(/** @type {any} */ (result).ruleId, 'git-discard', command);
  }
});

test('short options are split from their attached operand', () => {
  // `-Bmain` carries the branch name; reading the next token instead both missed
  // the trunk check and mistook the operand's letters for more flags.
  const denied = ['git checkout -Bmain other', 'git checkout -Bmaster', 'git checkout -qBmain'];
  for (const command of denied) {
    const result = evaluate(command, 'legacy-dangerous');
    assert.equal(result.kind, 'confirm', command);
    assert.equal(/** @type {any} */ (result).ruleId, 'git-trunk-ref', command);
  }
  // The operand's letters must not read as `-f` / `-m` / `-p`.
  assert.equal(evaluate('git checkout -Bfeat/task origin/main', 'legacy-dangerous').kind, 'confirm');
  assert.equal(evaluate('git checkout -bfix/parse', 'legacy-dangerous').kind, 'allow');
});

// --- long-option abbreviations ----------------------------------------------

test('git accepts unambiguous long-option prefixes, so the rules must too', () => {
  // Verified against git 2.43: each of these runs as the full option.
  const confirmed = [
    ['git checkout --pathspec-from-f=paths.txt', 'git-discard'],
    ['git checkout --forc main', 'git-discard'],
    ['git worktree remove --for /home/xuwenhao/Codebase/srpone/zooclaw-dev/repos/zooclaw-engine', 'git-discard'],
    ['git branch --del main', 'git-trunk-ref'],
    ['git branch --dele $b', 'git-trunk-ref'],
    ['git branch --forc -m main release', 'git-trunk-ref'],
    ['git config --glo user.email x@example.com', 'git-config-global'],
    ['git push --del origin feat/task', 'git-ref-change'],
    ['git tag --forc v1.0.0', 'git-discard'],
  ];
  for (const [command, ruleId] of confirmed) {
    const result = evaluate(command, 'legacy-dangerous');
    assert.equal(result.kind, 'confirm', command);
    assert.equal(/** @type {any} */ (result).ruleId, ruleId, command);
  }
  // A force push spelled with an abbreviation is still a hard deny, not a confirm.
  for (const command of ['git push --for origin main', 'git push --force-with-l origin main',
    'git push --force-with-lease=main origin main']) {
    const forced = evaluate(command, 'legacy-dangerous');
    assert.equal(forced.kind, 'deny', command);
    assert.equal(/** @type {any} */ (forced).ruleId, 'force-push-main', command);
  }
});

test('an abbreviation never loosens a classification', () => {
  // `--det` is a valid abbreviation of `--detach`, but ref intent is only read
  // from the exact spelling, so the ambiguous lone operand stays a confirm.
  assert.equal(evaluate('git checkout --det origin/main', 'legacy-dangerous').kind, 'confirm');
  assert.equal(evaluate('git checkout --detach origin/main', 'legacy-dangerous').kind, 'allow');
});

test('only flags git refuses to pair with a path count as branch intent', () => {
  // Verified on git 2.43: each of these errors out on `git checkout <flag> file`.
  for (const command of ['git checkout --detach origin/main', 'git checkout --track origin/feat',
    'git checkout --no-track feat']) {
    assert.equal(evaluate(command, 'legacy-dangerous').kind, 'allow', command);
  }
  // `--guess` only changes how a nonexistent *branch* name is second-guessed;
  // `git checkout --guess tracked.txt` still discards the file's edits.
  for (const command of ['git checkout --guess tracked.txt', 'git checkout --no-guess tracked.txt']) {
    const result = evaluate(command, 'legacy-dangerous');
    assert.equal(result.kind, 'confirm', command);
    assert.equal(/** @type {any} */ (result).ruleId, 'git-discard', command);
  }
});

test('checkout -d is the short form of --detach, not a deletion', () => {
  assert.equal(evaluate('git checkout -d origin/main', 'legacy-dangerous').kind, 'allow');
  // The same letter means --delete under `git branch`, which is a different rule.
  assert.equal(evaluate('git branch -d feat/task', 'legacy-dangerous').kind, 'allow');
  assert.equal(evaluate('git branch -d main', 'legacy-dangerous').kind, 'confirm');
  // A force letter in the same cluster still wins.
  assert.equal(evaluate('git checkout -df origin/main', 'legacy-dangerous').kind, 'confirm');
});

// --- path shape --------------------------------------------------------------


test('clean dry-run is read-only only with explicit static option semantics', () => {
  for (const command of ['git clean -n', 'git clean --dry-run', 'git clean -ndfx',
    'git clean -fn -- scratch', 'git clean -n -e cache', 'git clean -necache',
    'git -C /tmp/repo clean --dry-run -- scratch']) {
    assert.equal(evaluate(command, 'legacy-dangerous').kind, 'allow', command);
    assert.equal(evaluate(command, 'full').kind, 'allow', command);
  }
  for (const command of ['git clean', 'git clean -f', 'git clean -- -n',
    'git clean -e -n', 'git clean -en', 'git clean --exclude=--dry-run',
    'git clean -n -i', 'git clean --dry-r', 'git clean -n --unknown', 'git clean -n -e']) {
    assert.equal(evaluate(command, 'legacy-dangerous').kind, 'confirm', command);
  }
  // A dynamic option word can carry a second -f, so 0.5 denies it outright.
  for (const command of ['git clean --dry-run "$TARGET"', 'git clean "$FLAGS"']) {
    const result = evaluate(command, 'dangerous-only');
    assert.equal(result.kind, 'deny', command);
    assert.equal(/** @type {any} */ (result).ruleId, 'git-clean-root', command);
  }
});

test('checkout explicit branch intent never loosens unresolved create targets', () => {
  for (const command of ['git checkout -b "$BRANCH"', 'git checkout --orphan "$BRANCH"',
    'git checkout -b feat "$START"', 'git checkout --detach "$START"']) {
    assert.equal(evaluate(command, 'legacy-dangerous').kind, 'confirm', command);
  }
  for (const command of ['git checkout -b feat origin/main', 'git checkout --detach origin/main',
    'git checkout --track origin/feat']) assert.equal(evaluate(command, 'legacy-dangerous').kind, 'allow', command);
});


test('accepted clean dry-run combinations preserve real untracked and ignored files', () => {
  const directory = mkdtempSync(join(tmpdir(), 'guard-clean-dry-run-'));
  try {
    const init = spawnSync('git', ['init', '-q', directory], { encoding: 'utf8' });
    assert.equal(init.status, 0, init.stderr);
    writeFileSync(join(directory, '.gitignore'), 'ignored.txt\n');
    writeFileSync(join(directory, 'ignored.txt'), 'keep ignored');
    writeFileSync(join(directory, 'untracked.txt'), 'keep untracked');
    for (const args of [['clean', '-fn'], ['clean', '-ndfx'], ['clean', '--dry-run', '--force'],
      ['clean', '-neignored.txt'], ['clean', '-n', '--', 'untracked.txt']]) {
      const result = spawnSync('git', args, { cwd: directory, encoding: 'utf8' });
      assert.equal(result.status, 0, result.stderr);
      assert.ok(existsSync(join(directory, 'ignored.txt')), args.join(' '));
      assert.ok(existsSync(join(directory, 'untracked.txt')), args.join(' '));
    }
  } finally { rmSync(directory, { recursive: true, force: true }); }
});


test('checkout optional tracking value cannot swallow force; explicit ref intent rejects file restoration', () => {
  const cases = [
    { args: ['--no-track', 'tracked.txt'], destructive: false },
    { args: ['--track', 'tracked.txt'], destructive: false },
    { args: ['--detach', 'tracked.txt'], destructive: false },
    { args: ['--track', '--force', '-b', 'new', 'main'], destructive: true },
    { args: ['--track', '-f', '-b', 'new', 'main'], destructive: true },
    { args: ['--detach', '--no-detach', 'tracked.txt'], destructive: true },
    { args: ['-d', '--no-detach', 'tracked.txt'], destructive: true },
    { args: ['--orphan', 'new', '--no-orphan', 'tracked.txt'], destructive: true },
    { args: ['-2', 'tracked.txt'], destructive: true },
  ];
  for (const { args, destructive } of cases) {
    const directory = mkdtempSync(join(tmpdir(), 'guard-checkout-intent-'));
    try {
      assert.equal(spawnSync('git', ['init', '-q', '-b', 'main', directory]).status, 0);
      const file = join(directory, 'tracked.txt');
      writeFileSync(file, 'original\n');
      assert.equal(spawnSync('git', ['add', 'tracked.txt'], { cwd: directory }).status, 0);
      assert.equal(spawnSync('git', ['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
        'commit', '-qm', 'fixture'], { cwd: directory }).status, 0);
      writeFileSync(file, 'dirty\n');
      const command = `git checkout ${args.join(' ')}`;
      assert.equal(evaluate(command, 'legacy-dangerous').kind, destructive ? 'confirm' : 'allow', command);
      const actual = spawnSync('git', ['checkout', ...args], { cwd: directory, encoding: 'utf8' });
      if (destructive) assert.equal(actual.status, 0, actual.stderr);
      else assert.notEqual(actual.status, 0, command);
      assert.equal(readFileSync(file, 'utf8'), destructive ? 'original\n' : 'dirty\n', command);
    } finally { rmSync(directory, { recursive: true, force: true }); }
  }
});
