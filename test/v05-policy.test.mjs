// @ts-check
// 0.5 behavior: permission-mode tiers, new hard boundaries, cwd-relative
// protected roots, bypass project-sandbox checks and the unsandboxed log.
// Command strings here are data handed to the evaluator; nothing is executed.

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { adaptClaude } from '../src/adapters/claude.mjs';
import { resolveShfmtPath } from '../src/config.mjs';
import { evaluateHookEvent } from '../src/guard-core.mjs';
import { inspectDirectory } from '../src/project.mjs';

const SHFMT = resolveShfmtPath();
const FIXTURE = mkdtempSync(join(tmpdir(), 'guard-v05-'));
after(() => rmSync(FIXTURE, { recursive: true, force: true }));

/** @param {string} path @param {unknown} [json] */
function put(path, json) {
  mkdirSync(join(path, '..'), { recursive: true });
  writeFileSync(path, json === undefined ? '' : JSON.stringify(json));
}

// proj: thin project root with a member repo and a project sandbox config.
const PROJECT = join(FIXTURE, 'proj');
const MEMBER = join(PROJECT, 'member');
mkdirSync(join(PROJECT, '.git'), { recursive: true });
mkdirSync(join(MEMBER, '.git'), { recursive: true });
put(join(PROJECT, '.claude', 'settings.json'), { sandbox: { filesystem: { allowWrite: [PROJECT] } } });
put(join(MEMBER, '.claude', 'settings.local.json'), { sandbox: { enabled: true } });
// bare: a repo without any project sandbox config.
const BARE = join(FIXTURE, 'bare');
mkdirSync(join(BARE, '.git'), { recursive: true });
mkdirSync(join(BARE, 'src'), { recursive: true });
// disabled: allowWrite present but sandbox explicitly disabled.
const DISABLED = join(FIXTURE, 'disabled');
mkdirSync(join(DISABLED, '.git'), { recursive: true });
put(join(DISABLED, '.claude', 'settings.json'), { sandbox: { enabled: false, filesystem: { allowWrite: ['x'] } } });
// localonly: config only in settings.local.json; settings.json is a 0-byte placeholder.
const LOCAL_ONLY = join(FIXTURE, 'localonly');
mkdirSync(join(LOCAL_ONLY, '.git'), { recursive: true });
put(join(LOCAL_ONLY, '.claude', 'settings.json'));
put(join(LOCAL_ONLY, '.claude', 'settings.local.json'), { sandbox: { filesystem: { allowWrite: ['.'] } } });

// The fixture lives under tmpdir, which the default inspector treats as
// scratch space; tests opt out of that so the project logic is exercised.
/** @param {string} directory */
const inspect = (directory) => inspectDirectory(directory, { ephemeralRoots: [] });

const CODEBASE = join(FIXTURE, 'Codebase', 'personal');
const PROTECTED_ROOTS = ['/', homedir(), CODEBASE, join(CODEBASE, 'dotfiles'), PROJECT, MEMBER];

/**
 * @param {string} command
 * @param {{mode?: string, cwd?: string, profile?: string, unsandboxed?: boolean, protectedPaths?: string[], inspector?: any}} [options]
 */
function evaluate(command, options = {}) {
  /** @type {Record<string, unknown>} */
  const toolInput = { command };
  if (options.unsandboxed) toolInput.dangerouslyDisableSandbox = true;
  /** @type {Record<string, unknown>} */
  const event = { tool_name: 'Bash', tool_input: toolInput };
  if (options.mode) event.permission_mode = options.mode;
  if (options.cwd) event.cwd = options.cwd;
  const result = evaluateHookEvent(event, {
    profile: options.profile ?? 'dangerous-only',
    shfmtPath: SHFMT,
    protectedRoots: PROTECTED_ROOTS,
    protectedPaths: options.protectedPaths ?? [],
    inspectDirectory: options.inspector ?? inspect,
  });
  assert.ok(result);
  return /** @type {any} */ (result);
}

/** @param {any} result */
const outcome = (result) => result.kind === 'allow' ? 'allow' : `${result.kind}:${result.ruleId}`;

// --- tiers ---------------------------------------------------------------------

test('ask-level rules: silent in auto/default/acceptEdits/missing mode, ask in bypass', () => {
  const cases = [
    ['psql -c "DROP TABLE users"', 'destructive-sql'],
    ['git reset --hard origin/main', 'reset-hard-main'],
    ['git config --global user.name x', 'git-config-global'],
    ['git lfs migrate import --everything', 'git-lfs'],
    ['git rebase -x "npm test" main', 'git-exec'],
    ['git submodule foreach git pull', 'git-exec'],
    ['git push --mirror backup', 'git-push-bulk'],
    ['git push --prune origin', 'git-push-bulk'],
    ['gh api -X DELETE repos/acme/demo/keys/7', 'gh-api-delete-sensitive'],
    ['gh api -X DELETE repos/acme/demo/hooks/1', 'gh-api-delete-sensitive'],
    ['gh api -X DELETE repos/acme/demo/actions/secrets/TOKEN', 'gh-api-delete-sensitive'],
    ['gh api -X DELETE repos/acme/demo/environments/prod', 'gh-api-delete-sensitive'],
    ['git branch -D main', 'git-trunk-ref'],
    ['git branch -d master', 'git-trunk-ref'],
    ['git checkout -B main origin/main', 'git-trunk-ref'],
    ['git switch -C main', 'git-trunk-ref'],
  ];
  for (const [command, ruleId] of cases) {
    for (const mode of [undefined, 'auto', 'default', 'acceptEdits', 'plan']) {
      assert.equal(outcome(evaluate(command, { mode, cwd: PROJECT })), 'allow', `${mode}: ${command}`);
    }
    assert.equal(outcome(evaluate(command, { mode: 'bypassPermissions', cwd: PROJECT })), `confirm:${ruleId}`, command);
  }
});

test('git config reads are never git-config-global', () => {
  for (const command of ['git config --global core.excludesFile', 'git config --global --get user.name',
    'git config --global --list', 'git config --system -l', 'git config --global get user.name']) {
    assert.equal(outcome(evaluate(command, { mode: 'bypassPermissions', cwd: PROJECT })), 'allow', command);
    assert.equal(outcome(evaluate(command, { mode: 'bypassPermissions', cwd: BARE })), 'allow', command);
  }
  for (const command of ['git config --global core.excludesFile ~/.gitignore', 'git config --global --unset user.name',
    'git config --global set user.name x', 'git config --global "$KEY"']) {
    assert.equal(outcome(evaluate(command, { mode: 'bypassPermissions', cwd: PROJECT })), 'confirm:git-config-global', command);
  }
});

test('relaxed git operations are silent in both tiers when the project has a sandbox', () => {
  for (const command of [
    'git branch -D feat/old', 'git branch -M feat/a feat/b', 'git worktree remove .worktrees/x',
    'git worktree add -B feat/x .worktrees/x origin/main', 'git push origin --delete feat/old',
    'git reset --hard HEAD~1', 'git restore src/a.ts', 'git clean -fd', 'git stash drop',
    'git stash clear', 'git checkout -- a.ts', 'git switch -f main', 'git worktree remove --force .worktrees/x',
    'git tag -f v1', 'git rm -r old', 'chmod 777 ./public', 'gh api -X DELETE repos/acme/demo/releases/1',
  ]) {
    for (const mode of ['auto', 'bypassPermissions']) {
      assert.equal(outcome(evaluate(command, { mode, cwd: PROJECT })), 'allow', `${mode}: ${command}`);
    }
  }
});

test('deny-level rules are identical in both tiers', () => {
  const cases = [
    ['gh repo delete acme/old --yes', 'gh-repo-delete'],
    ['gh api -X DELETE repos/acme/demo', 'gh-api-delete-protected'],
    ['gh api --method DELETE repos/acme/demo/rulesets/12', 'gh-api-delete-protected'],
    ['gh api -X DELETE repos/acme/demo/branches/main/protection', 'gh-api-delete-protected'],
    ['gh api -XDELETE repos/acme/demo/git/refs/heads/main', 'gh-api-delete-protected'],
    ['gh api -X DELETE https://api.github.com/repos/acme/demo', 'gh-api-delete-protected'],
    ['git push origin :main', 'push-delete-trunk'],
    ['git push origin --delete main', 'push-delete-trunk'],
    ['git push -d origin refs/heads/master', 'push-delete-trunk'],
    ['git push origin --delete "$BRANCH"', 'push-delete-trunk'],
    ['git push origin main --force', 'force-push-main'],
    ['rm -rf .git', 'rm-git-dir'],
    ['rm -rf ./member/.git/', 'rm-git-dir'],
    ['rm -fr vendor/lib/.git', 'rm-git-dir'],
    ['git clean -ffdx', 'git-clean-root'],
    ['gh api -X PUT orgs/acme/rulesets/1 -f name=x', 'org-ruleset-write'],
  ];
  for (const [command, ruleId] of cases) {
    for (const mode of [undefined, 'auto', 'bypassPermissions']) {
      assert.equal(outcome(evaluate(command, { mode, cwd: MEMBER })), `deny:${ruleId}`, `${mode}: ${command}`);
    }
  }
});

test('gh api DELETE: other endpoints are no decision; non-DELETE methods untouched', () => {
  for (const command of ['gh api -X DELETE repos/acme/demo/issues/comments/9',
    'gh api -X DELETE repos/acme/demo/git/refs/heads/feat/x', 'gh api repos/acme/demo',
    'gh api -X GET repos/acme/demo/rulesets', 'gh api -X DELETE repos/acme/demo/labels/bug']) {
    for (const mode of ['auto', 'bypassPermissions']) {
      assert.equal(outcome(evaluate(command, { mode, cwd: PROJECT })), 'allow', `${mode}: ${command}`);
    }
  }
  // full and legacy keep the generic confirmation.
  assert.equal(outcome(evaluate('gh api -X DELETE repos/acme/demo/labels/bug', { profile: 'legacy-dangerous' })), 'confirm:gh-api-delete');
});

test('push --delete of non-trunk refs and colon refspecs to them are not trunk deletes', () => {
  for (const command of ['git push origin :feat/x', 'git push origin --delete feat/main-fix', 'git push --dry-run origin --delete main']) {
    assert.equal(outcome(evaluate(command, { mode: 'bypassPermissions', cwd: PROJECT })), 'allow', command);
  }
});

// --- git clean at a project root ------------------------------------------------

test('git clean -ff is denied anywhere; -x/-X only at a thin project root or unknown cwd', () => {
  for (const cwd of [PROJECT, MEMBER, BARE]) {
    assert.equal(outcome(evaluate('git clean -ffd', { cwd })), 'deny:git-clean-root', cwd);
    assert.equal(outcome(evaluate('git clean -f -f -d', { cwd })), 'deny:git-clean-root', cwd);
    assert.equal(outcome(evaluate('git clean --force -fd', { cwd })), 'deny:git-clean-root', cwd);
  }
  // Project root (has nested member repos): -x and -X are denied.
  for (const command of ['git clean -fdx', 'git clean -fdX', 'git clean -f -x -d']) {
    assert.equal(outcome(evaluate(command, { cwd: PROJECT })), 'deny:git-clean-root', command);
  }
  // Member repo / ordinary repo: allowed.
  for (const cwd of [MEMBER, BARE]) assert.equal(outcome(evaluate('git clean -fdx', { cwd })), 'allow', cwd);
  // Subdirectory of the project root only cleans that subdirectory...
  mkdirSync(join(PROJECT, 'docs'), { recursive: true });
  assert.equal(outcome(evaluate('git clean -fdx', { cwd: join(PROJECT, 'docs') })), 'allow');
  // ...unless the pathspec widens it back to the root.
  assert.equal(outcome(evaluate('git clean -fdx :/', { cwd: join(PROJECT, 'docs') })), 'deny:git-clean-root');
  // git -C into the root, or no usable cwd at all.
  assert.equal(outcome(evaluate(`git -C ${PROJECT} clean -fdx`, { cwd: BARE })), 'deny:git-clean-root');
  assert.equal(outcome(evaluate('git -C .. clean -fdx', { cwd: MEMBER })), 'deny:git-clean-root');
  assert.equal(outcome(evaluate('git clean -fdx')), 'deny:git-clean-root');
  assert.equal(outcome(evaluate('cd member && git clean -fdx', { cwd: PROJECT })), 'deny:git-clean-root');
  // Plain clean and dry runs stay out of the hard rule.
  assert.equal(outcome(evaluate('git clean -fd', { cwd: PROJECT })), 'allow');
  assert.equal(outcome(evaluate('git clean -ndffx', { cwd: PROJECT })), 'allow');
});

test('git clean -fdx against a real thin root really does remove ignored assets (why the rule exists)', () => {
  const root = mkdtempSync(join(tmpdir(), 'guard-clean-root-'));
  try {
    const git = (/** @type {string[]} */ ...args) => spawnSync('git', args, { cwd: root, encoding: 'utf8' });
    assert.equal(git('init', '-q').status, 0);
    writeFileSync(join(root, '.gitignore'), 'media/\n');
    mkdirSync(join(root, 'media'));
    writeFileSync(join(root, 'media', 'take1.wav'), 'x');
    assert.equal(spawnSync('git', ['init', '-q', join(root, 'member')]).status, 0);
    assert.equal(outcome(evaluate('git clean -fdx', { cwd: root, inspector: inspect })), 'deny:git-clean-root');
    assert.equal(git('clean', '-ndx').stdout.includes('media/'), true);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

// --- protected roots and paths ---------------------------------------------------

test('relative recursive deletes resolve against the hook cwd', () => {
  // cwd is the parent of a protected root.
  assert.equal(outcome(evaluate('rm -rf dotfiles', { cwd: CODEBASE })), 'deny:rm-protected-root');
  assert.equal(outcome(evaluate('rm -rf ./dotfiles/', { cwd: CODEBASE })), 'deny:rm-protected-root');
  assert.equal(outcome(evaluate('rm -rf ..', { cwd: join(CODEBASE, 'dotfiles') })), 'deny:rm-protected-root');
  assert.equal(outcome(evaluate('rm -rf *', { cwd: CODEBASE })), 'deny:rm-protected-root');
  assert.equal(outcome(evaluate('rm -rf member', { cwd: PROJECT })), 'deny:rm-protected-root');
  // Deleting an ancestor of a protected root destroys it too.
  assert.equal(outcome(evaluate(`rm -rf ${join(FIXTURE, 'Codebase')}`)), 'deny:rm-protected-root');
  assert.equal(outcome(evaluate(`rm -rf ${join(FIXTURE, 'Codebase')}/*`)), 'deny:rm-protected-root');
  // Ordinary relative targets stay allowed.
  assert.equal(outcome(evaluate('rm -rf build', { cwd: CODEBASE })), 'allow');
  assert.equal(outcome(evaluate('rm -rf dotfiles/tmp', { cwd: CODEBASE })), 'allow');
  assert.equal(outcome(evaluate(`rm -rf ${join(FIXTURE, 'Codebase')}/*/node_modules`)), 'allow');
});

test('an untrusted cwd (cd in the command, or none) is strict for names on protected paths', () => {
  assert.equal(evaluate('cd /var/empty && rm -rf dotfiles', { cwd: BARE }).ruleId, 'rm-protected-root');
  assert.equal(evaluate('cd /var/empty && rm -rf dotfiles', { cwd: BARE }).evaluation, 'unknown');
  assert.equal(outcome(evaluate('rm -rf personal/dotfiles')), 'deny:rm-protected-root');
  assert.equal(outcome(evaluate('cd sub && rm -rf .')), 'deny:rm-protected-root');
  assert.equal(outcome(evaluate('cd sub && rm -rf build', { cwd: BARE })), 'allow');
});

test('protectedPaths: rm, unlink and mv on the literal path are denied', () => {
  const link = join(CODEBASE, 'podcast-production');
  const protectedPaths = [link];
  for (const command of [`rm ${link}`, `unlink ${link}`, `mv ${link} /tmp/elsewhere`, `rm -rf ${link}/`,
    'rm podcast-production', `mv /tmp/x ${link}`]) {
    assert.equal(outcome(evaluate(command, { cwd: CODEBASE, protectedPaths })), 'deny:rm-protected-path', command);
  }
  for (const command of [`rm ${link}-old`, `cat ${link}/README.md`, `rm ${link}/inside.txt`]) {
    assert.equal(outcome(evaluate(command, { cwd: CODEBASE, protectedPaths })), 'allow', command);
  }
});

// --- bypass without project sandbox ---------------------------------------------

test('bypass: project sandbox detection follows the git root of cwd', () => {
  assert.equal(inspect(PROJECT).sandboxConfigured, true);
  assert.equal(inspect(join(PROJECT, 'docs')).sandboxConfigured, true);
  assert.equal(inspect(MEMBER).sandboxConfigured, true);
  assert.equal(inspect(LOCAL_ONLY).sandboxConfigured, true);
  assert.equal(inspect(BARE).sandboxConfigured, false);
  assert.equal(inspect(DISABLED).sandboxConfigured, false);
  assert.equal(inspect(PROJECT).nestedRepos, true);
  assert.equal(inspect(MEMBER).nestedRepos, false);
  // The default inspector treats tmp/scratch locations as non-projects.
  assert.equal(inspectDirectory(PROJECT).sandboxConfigured, false);
  assert.equal(inspectDirectory('/').gitRoot, null);
});

test('bypass without a project sandbox denies write-class commands and allows reads', () => {
  const denied = ['echo hi > x', 'touch x', 'npm test', 'git commit -m x', 'git fetch', 'python3 script.py',
    'sed -i s/a/b/ f', 'find . -delete', 'cat a | tee b', 'git branch -D feat', 'ls; touch y', 'gh pr merge 1'];
  const allowed = ['ls', 'git status', 'git log --oneline -5', 'cat README.md | head -n 5', 'rg TODO src 2>/dev/null',
    'git diff main...HEAD', 'git branch --show-current', 'gh pr view 3', 'gh api repos/acme/demo/pulls',
    'echo hi', 'find . -name "*.mjs"', 'sed -n 1,20p a.txt', 'ls > /dev/null 2>&1', 'cd src && ls', 'jq . a.json'];
  for (const cwd of [BARE, DISABLED, '/', undefined]) {
    for (const command of denied) {
      assert.equal(outcome(evaluate(command, { mode: 'bypassPermissions', cwd })), 'deny:bypass-no-project-sandbox', `${cwd}: ${command}`);
    }
    for (const command of allowed) {
      assert.equal(outcome(evaluate(command, { mode: 'bypassPermissions', cwd })), 'allow', `${cwd}: ${command}`);
    }
  }
  // Same commands are fine once the project has a sandbox, and in auto mode anywhere.
  for (const command of denied.filter((item) => item !== 'git branch -D feat')) {
    assert.equal(outcome(evaluate(command, { mode: 'bypassPermissions', cwd: PROJECT })), 'allow', command);
    assert.equal(outcome(evaluate(command, { mode: 'auto', cwd: BARE })), 'allow', command);
  }
  // tmp/scratch directories never count, even with a config.
  assert.equal(outcome(evaluate('touch x', { mode: 'bypassPermissions', cwd: PROJECT, inspector: (/** @type {string} */ d) => inspectDirectory(d) })),
    'deny:bypass-no-project-sandbox');
  const reason = adaptClaude({ tool_name: 'Bash', tool_input: { command: 'touch x' }, permission_mode: 'bypassPermissions', cwd: BARE },
    { mode: 'strict', profile: 'dangerous-only', shfmtPath: SHFMT, protectedRoots: ['/'], protectedPaths: [], nativePrompt: { codex: false, grok: false, kimi: false }, reviewer: null });
  assert.equal(reason?.hookSpecificOutput.permissionDecision, 'deny');
  assert.match(reason?.hookSpecificOutput.permissionDecisionReason ?? '', /bypass 只能在配好项目沙盒的项目里用；先配 \.claude\/settings\.json 或切 auto/);
});

// --- bypass + unsandboxed --------------------------------------------------------

test('bypass + dangerouslyDisableSandbox: recursive delete or mv outside the git root asks', () => {
  const outside = join(FIXTURE, 'elsewhere');
  const ask = [`rm -rf ${outside}`, `mv ${PROJECT}/a.txt ${outside}/a.txt`, 'rm -rf ../elsewhere', 'mv "$SRC" notes.txt'];
  for (const command of ask) {
    assert.equal(outcome(evaluate(command, { mode: 'bypassPermissions', cwd: PROJECT, unsandboxed: true })),
      'confirm:unsandboxed-outside-project', command);
    // Without the flag the sandbox confines it; in auto the classifier decides.
    assert.notEqual(outcome(evaluate(command, { mode: 'bypassPermissions', cwd: PROJECT })), 'confirm:unsandboxed-outside-project', command);
    assert.notEqual(outcome(evaluate(command, { mode: 'auto', cwd: PROJECT, unsandboxed: true })), 'confirm:unsandboxed-outside-project', command);
  }
  for (const command of [`rm -rf ${PROJECT}/build`, 'rm -rf build', 'mv a.txt b.txt', 'touch x']) {
    assert.equal(outcome(evaluate(command, { mode: 'bypassPermissions', cwd: PROJECT, unsandboxed: true })), 'allow', command);
  }
  // From a member repo, the thin root's own worktrees are still inside the project.
  for (const command of [`rm -rf ${PROJECT}/.worktrees/old`, 'git worktree remove ../.worktrees/old']) {
    assert.equal(outcome(evaluate(command, { mode: 'bypassPermissions', cwd: MEMBER, unsandboxed: true })), 'allow', command);
  }
  assert.equal(inspect(MEMBER).projectRoot, PROJECT);
  assert.equal(inspect(MEMBER).gitRoot, MEMBER);
});

test('bypass: excludedCommands-style commands are checked like unsandboxed calls', () => {
  assert.equal(outcome(evaluate('git worktree remove /var/empty/old-wt', { mode: 'bypassPermissions', cwd: PROJECT })),
    'confirm:unsandboxed-outside-project');
  assert.equal(outcome(evaluate('git worktree remove .worktrees/x', { mode: 'bypassPermissions', cwd: PROJECT })), 'allow');
  assert.equal(outcome(evaluate('rsync -a --delete src/ /var/empty/mirror/', { mode: 'bypassPermissions', cwd: PROJECT })),
    'confirm:unsandboxed-outside-project');
});

// --- unsandboxed log ----------------------------------------------------------------

/** @param {string} stateDir @param {() => void} body */
function withStateDir(stateDir, body) {
  const previous = process.env.AGENT_SHELL_GUARD_STATE_DIR;
  process.env.AGENT_SHELL_GUARD_STATE_DIR = stateDir;
  try { body(); } finally {
    if (previous === undefined) delete process.env.AGENT_SHELL_GUARD_STATE_DIR;
    else process.env.AGENT_SHELL_GUARD_STATE_DIR = previous;
  }
}

const CLAUDE_CONFIG = {
  mode: 'strict', profile: 'dangerous-only', shfmtPath: SHFMT, protectedRoots: ['/', homedir()], protectedPaths: [],
  nativePrompt: { codex: false, grok: false, kimi: false }, reviewer: null,
};

test('dangerouslyDisableSandbox calls are appended to unsandboxed.jsonl in every tier', () => {
  const stateDir = join(FIXTURE, 'state-a');
  withStateDir(stateDir, () => {
    for (const mode of ['auto', 'bypassPermissions', undefined]) {
      adaptClaude({
        tool_name: 'Bash', cwd: MEMBER, session_id: 'sess-1', permission_mode: mode,
        tool_input: { command: `ls ${'x'.repeat(600)} --token=ghp_${'a'.repeat(20)}`, dangerouslyDisableSandbox: true },
      }, CLAUDE_CONFIG);
    }
    // Key absent or false: nothing is logged.
    adaptClaude({ tool_name: 'Bash', cwd: MEMBER, tool_input: { command: 'ls' } }, CLAUDE_CONFIG);
    adaptClaude({ tool_name: 'Bash', cwd: MEMBER, tool_input: { command: 'ls', dangerouslyDisableSandbox: false } }, CLAUDE_CONFIG);
  });
  const lines = readFileSync(join(stateDir, 'unsandboxed.jsonl'), 'utf8').trim().split('\n').map((line) => JSON.parse(line));
  assert.equal(lines.length, 3);
  assert.deepEqual(lines.map((line) => line.permission_mode), ['auto', 'bypassPermissions', null]);
  for (const line of lines) {
    assert.equal(line.cwd, MEMBER);
    assert.equal(line.gitRoot, MEMBER);
    assert.equal(line.session_id, 'sess-1');
    assert.equal(line.command.length, 500);
    assert.ok(!Number.isNaN(Date.parse(line.ts)));
    assert.equal(typeof line.decision, 'string');
  }
});

test('an unwritable state dir never changes the decision or throws', () => {
  const blocker = join(FIXTURE, 'not-a-dir');
  writeFileSync(blocker, '');
  withStateDir(join(blocker, 'state'), () => {
    const allowed = adaptClaude({ tool_name: 'Bash', cwd: MEMBER, tool_input: { command: 'ls', dangerouslyDisableSandbox: true } }, CLAUDE_CONFIG);
    assert.equal(allowed, null);
    const denied = adaptClaude({ tool_name: 'Bash', cwd: MEMBER, tool_input: { command: 'gh repo delete a/b --yes', dangerouslyDisableSandbox: true } }, CLAUDE_CONFIG);
    assert.equal(denied?.hookSpecificOutput.permissionDecision, 'deny');
  });
  assert.equal(existsSync(join(blocker, 'state')), false);
});

test('CLI hook reads the event from stdin and logs unsandboxed calls', () => {
  const stateDir = join(FIXTURE, 'state-cli');
  const eventFile = join(FIXTURE, 'event.json');
  writeFileSync(eventFile, JSON.stringify({
    hook_event_name: 'PreToolUse', tool_name: 'Bash', cwd: BARE, permission_mode: 'bypassPermissions', session_id: 's-cli',
    tool_input: { command: 'rm -rf .git', dangerouslyDisableSandbox: true },
  }));
  const cli = fileURLToPath(new URL('../src/cli.mjs', import.meta.url));
  const result = spawnSync(process.execPath, [cli, 'hook', 'claude'], {
    input: readFileSync(eventFile),
    encoding: 'utf8',
    env: { ...process.env, AGENT_SHELL_GUARD_STATE_DIR: stateDir, AGENT_SHELL_GUARD_CONFIG: join(FIXTURE, 'missing.json'), AGENT_SHELL_GUARD_SHFMT: SHFMT },
  });
  assert.equal(result.status, 0, result.stderr);
  const output = JSON.parse(result.stdout);
  assert.equal(output.hookSpecificOutput.permissionDecision, 'deny');
  assert.match(output.hookSpecificOutput.permissionDecisionReason, /rm-git-dir/);
  const [line] = readFileSync(join(stateDir, 'unsandboxed.jsonl'), 'utf8').trim().split('\n').map((item) => JSON.parse(item));
  assert.equal(line.session_id, 's-cli');
  assert.equal(line.decision, 'deny');
});

// --- profiles ---------------------------------------------------------------------

test('legacy-dangerous restores the 0.4 confirmation set in every mode', () => {
  for (const mode of ['auto', 'bypassPermissions']) {
    for (const [command, ruleId] of [['git branch -D feat/old', 'git-ref-change'], ['git reset --hard HEAD~1', 'git-discard'],
      ['chmod 777 x', 'chmod-777'], ['psql -c "DROP TABLE t"', 'destructive-sql']]) {
      assert.equal(outcome(evaluate(command, { mode, cwd: PROJECT, profile: 'legacy-dangerous' })), `confirm:${ruleId}`, command);
    }
  }
});

test('off disables the bypass checks too', () => {
  assert.equal(outcome(evaluate('touch x', { mode: 'bypassPermissions', cwd: BARE, profile: 'off' })), 'allow');
});
