// @ts-check
// Fixes from the independent review of the 0.5 branch. Command strings are data
// handed to the evaluator; nothing is executed.

import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';

import { resolveShfmtPath } from '../src/config.mjs';
import { evaluateHookEvent } from '../src/guard-core.mjs';
import { inspectDirectory, inspectProjectDir } from '../src/project.mjs';
import { redact } from '../src/reviewer.mjs';

const SHFMT = resolveShfmtPath();
const FIXTURE = mkdtempSync(join(tmpdir(), 'guard-review-'));
after(() => rmSync(FIXTURE, { recursive: true, force: true }));

/** @param {string} path @param {string|object} [content] */
function put(path, content = '') {
  mkdirSync(join(path, '..'), { recursive: true });
  writeFileSync(path, typeof content === 'string' ? content : JSON.stringify(content));
}

/**
 * A repository whose HEAD is on `branch` (null = detached), optionally with an
 * upstream for it.
 * @param {string} root @param {string|null} branch @param {string} [merge]
 */
function repo(root, branch, merge) {
  put(join(root, '.git', 'HEAD'), branch === null ? `${'a'.repeat(40)}\n` : `ref: refs/heads/${branch}\n`);
  put(join(root, '.git', 'config'), merge ? `[core]\n\tbare = false\n[branch "${branch}"]\n\tremote = origin\n\tmerge = ${merge}\n` : '[core]\n');
}

/**
 * A linked worktree of `main` at `path`, the way `git worktree add` lays it out.
 * @param {string} main @param {string} path @param {string} name @param {string} branch
 */
function linkedWorktree(main, path, name, branch) {
  const admin = join(main, '.git', 'worktrees', name);
  put(join(admin, 'HEAD'), `ref: refs/heads/${branch}\n`);
  put(join(admin, 'commondir'), '../..\n');
  put(join(admin, 'gitdir'), `${join(path, '.git')}\n`);
  put(join(path, '.git'), `gitdir: ${admin}\n`);
}

const PROJECT = join(FIXTURE, 'proj');
const MEMBER = join(PROJECT, 'member');
repo(PROJECT, 'main');
repo(MEMBER, 'feat/x');
put(join(PROJECT, '.claude', 'settings.json'), { sandbox: { filesystem: { allowWrite: ['.'] } } });
// The member's sandbox config is untracked: only the main worktree has it.
put(join(MEMBER, '.claude', 'settings.local.json'), { sandbox: { filesystem: { allowWrite: ['.'] } } });
const MEMBER_WT = join(MEMBER, '.worktrees', 'wt');
linkedWorktree(MEMBER, MEMBER_WT, 'wt', 'feat/wt');
const AGENT_WT = join(MEMBER, '.claude', 'worktrees', 'agent-1');
linkedWorktree(MEMBER, AGENT_WT, 'agent-1', 'agent/1');
const BARE = join(FIXTURE, 'bare');
repo(BARE, 'feat/y');
const TRUNK_UPSTREAM = join(FIXTURE, 'tracks-main');
repo(TRUNK_UPSTREAM, 'feat/z', 'refs/heads/main');
const DETACHED = join(FIXTURE, 'detached');
repo(DETACHED, null);
const ENABLED_ONLY = join(FIXTURE, 'enabled-only');
repo(ENABLED_ONLY, 'main');
put(join(ENABLED_ONLY, '.claude', 'settings.json'), { sandbox: { enabled: true } });
const OUTSIDE = join(FIXTURE, 'outside');
repo(OUTSIDE, 'feat/o');

const CODEBASE = join(FIXTURE, 'Codebase', 'personal');
const PROTECTED_ROOTS = ['/', homedir(), CODEBASE, join(CODEBASE, 'dotfiles'), join(CODEBASE, 'data'), PROJECT, MEMBER];

/** @param {string} directory */
const inspect = (directory) => inspectDirectory(directory, { ephemeralRoots: [] });
/** @param {string} directory */
const inspectProject = (directory) => inspectProjectDir(directory, { ephemeralRoots: [] });

/**
 * @param {string} command
 * @param {{mode?: string, cwd?: string, profile?: string, unsandboxed?: boolean, projectDir?: string,
 *   host?: 'claude'|'codex'|'grok'|'kimi', caseInsensitivePaths?: boolean}} [options]
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
    inspectDirectory: inspect,
    inspectProjectDir: inspectProject,
    projectDir: options.projectDir,
    host: options.host,
    caseInsensitivePaths: options.caseInsensitivePaths ?? false,
  });
  assert.ok(result);
  return /** @type {any} */ (result);
}

/** @param {any} result */
const outcome = (result) => result.kind === 'allow' ? 'allow' : `${result.kind}:${result.ruleId}`;

test('H1: brace expansion is expanded and each alternative is checked', () => {
  for (const command of [`rm -rf ${CODEBASE}{,}`, `rm -rf ${CODEBASE}/{dotfiles,data}`, `rm -rf ${CODEBASE}/{x,dotfiles}/`,
    `rm -rf ${FIXTURE}/Codebase/{personal,other}`, `rm -rf ${CODEBASE}/{.git,x}`]) {
    assert.match(outcome(evaluate(command, { mode: 'auto' })), /^deny:(rm-protected-root|rm-git-dir)$/, command);
  }
  assert.equal(evaluate(`rm -rf ${CODEBASE}{,}`, { mode: 'auto' }).evaluation, 'matched');
  for (const command of ['rm -rf build/{a,b} dist', `rm -rf ${CODEBASE}/dotfiles/{node_modules,dist}`, 'rm -rf out{1..3}']) {
    assert.equal(outcome(evaluate(command, { mode: 'auto', cwd: BARE })), 'allow', command);
  }
  // Quoted braces are literal.
  assert.equal(outcome(evaluate(`rm -rf "${CODEBASE}{,}"`, { mode: 'auto' })), 'allow');
});

test('H2: case-insensitive path comparison on macOS volumes', () => {
  const upper = CODEBASE.replace('Codebase/personal', 'codebase/PERSONAL');
  assert.equal(outcome(evaluate(`rm -rf ${upper}`, { mode: 'auto', caseInsensitivePaths: true })), 'deny:rm-protected-root');
  assert.equal(outcome(evaluate('rm -rf .GIT', { mode: 'auto', caseInsensitivePaths: true })), 'deny:rm-git-dir');
  assert.equal(outcome(evaluate(`rm -rf ${upper}`, { mode: 'auto', caseInsensitivePaths: false })), 'allow');
  assert.equal(outcome(evaluate('rm -rf .GIT', { mode: 'auto', caseInsensitivePaths: false })), 'allow');
});

test('H3: HEAD, @ and a missing refspec resolve to the checked-out branch', () => {
  for (const command of ['git push -f', 'git push --force-with-lease', 'git push -f origin HEAD', 'git push -f origin @',
    'git push origin +HEAD']) {
    assert.equal(outcome(evaluate(command, { mode: 'auto', cwd: PROJECT })), 'deny:force-push-main', command);
    assert.equal(evaluate(command, { mode: 'auto', cwd: PROJECT }).evaluation, 'matched', command);
    assert.equal(outcome(evaluate(command, { mode: 'auto', cwd: MEMBER })), 'allow', command);
  }
  // Linked worktree HEAD is read from its own admin dir.
  assert.equal(outcome(evaluate('git push --force-with-lease', { mode: 'auto', cwd: MEMBER_WT })), 'allow');
  // git -C picks the repository.
  assert.equal(outcome(evaluate(`git -C ${PROJECT} push -f`, { mode: 'auto', cwd: MEMBER })), 'deny:force-push-main');
  // Unknown: detached HEAD, upstream on the trunk, no cwd.
  for (const cwd of [DETACHED, TRUNK_UPSTREAM, undefined]) {
    const result = evaluate('git push --force-with-lease', { mode: 'auto', cwd });
    assert.equal(outcome(result), 'deny:force-push-main', String(cwd));
    assert.equal(result.evaluation, 'unknown', String(cwd));
  }
  // An explicit refspec is used as written.
  assert.equal(outcome(evaluate('git push -f origin feat/x', { mode: 'auto', cwd: PROJECT })), 'allow');
  assert.equal(outcome(evaluate('git push -f origin HEAD:main', { mode: 'auto', cwd: MEMBER })), 'deny:force-push-main');
  assert.equal(outcome(evaluate('git push -f --all origin', { mode: 'auto', cwd: MEMBER })), 'deny:force-push-main');
  assert.equal(outcome(evaluate('git push -f --tags origin', { mode: 'auto', cwd: PROJECT })), 'allow');
});

test('M1: project settings come from CLAUDE_PROJECT_DIR, with linked worktrees reading the main worktree', () => {
  assert.equal(inspectProject(PROJECT).sandboxConfigured, true);
  assert.equal(inspectProject(ENABLED_ONLY).sandboxConfigured, false);
  assert.equal(inspectProject(BARE).sandboxConfigured, false);
  for (const worktree of [MEMBER_WT, AGENT_WT]) {
    assert.equal(inspectProject(worktree).sandboxConfigured, true, worktree);
    assert.equal(inspect(join(worktree)).sandboxConfigured, true, worktree);
    assert.equal(inspect(worktree).projectRoot, PROJECT, worktree);
  }
  // The launch directory wins over the hook cwd, both ways.
  assert.equal(outcome(evaluate('touch x', { mode: 'bypassPermissions', cwd: BARE, projectDir: PROJECT })), 'allow');
  assert.equal(outcome(evaluate('touch x', { mode: 'bypassPermissions', cwd: PROJECT, projectDir: BARE })), 'deny:bypass-no-project-sandbox');
  assert.equal(outcome(evaluate('touch x', { mode: 'bypassPermissions', cwd: PROJECT, projectDir: ENABLED_ONLY })), 'deny:bypass-no-project-sandbox');
  // Without it, the cwd's git root (and its main worktree) decide.
  assert.equal(outcome(evaluate('touch x', { mode: 'bypassPermissions', cwd: MEMBER_WT })), 'allow');
  assert.equal(outcome(evaluate('touch x', { mode: 'bypassPermissions', cwd: join(AGENT_WT, 'src') })), 'allow');
  assert.equal(outcome(evaluate('touch x', { mode: 'bypassPermissions', cwd: ENABLED_ONLY })), 'deny:bypass-no-project-sandbox');
});

test('M2: Codex, Grok and Kimi keep the 0.4 confirmation set; Claude tiers do not apply to them', () => {
  for (const host of /** @type {const} */ (['codex', 'grok', 'kimi'])) {
    for (const [command, ruleId] of [['git reset --hard HEAD~1', 'git-discard'], ['git branch -D old', 'git-ref-change'],
      ['chmod 777 x', 'chmod-777'], ['psql -c "DROP TABLE t"', 'destructive-sql'], ['git config --global a.b c', 'git-config-global']]) {
      assert.equal(outcome(evaluate(command, { host, cwd: PROJECT })), `confirm:${ruleId}`, `${host}: ${command}`);
      // permission_mode on the event does not change a non-Claude host.
      assert.equal(outcome(evaluate(command, { host, cwd: PROJECT, mode: 'auto' })), `confirm:${ruleId}`, `${host}: ${command}`);
    }
    assert.equal(outcome(evaluate('touch x', { host, cwd: BARE, mode: 'bypassPermissions' })), 'allow', host);
  }
  assert.equal(outcome(evaluate('git reset --hard HEAD~1', { host: 'claude', cwd: PROJECT, mode: 'auto' })), 'allow');
});

test('M3: a dynamic remote delete asks only in bypass; a literal trunk delete is denied', () => {
  for (const command of ['git push origin --delete "$b"', 'for b in $(git branch --merged); do git push origin --delete "$b"; done']) {
    assert.equal(outcome(evaluate(command, { mode: 'auto', cwd: PROJECT })), 'allow', command);
    assert.equal(outcome(evaluate(command, { mode: 'bypassPermissions', cwd: PROJECT })), 'confirm:push-delete-dynamic', command);
  }
  assert.equal(outcome(evaluate('git push origin --delete main', { mode: 'auto', cwd: PROJECT })), 'deny:push-delete-trunk');
});

test('M4: only whole-directory globs hit the protected root they sit in', () => {
  for (const command of ['rm -rf tmp-*', 'rm -rf *.egg-info', 'rm -rf build dist *.egg-info', 'rm -rf .worktrees/feat-*', 'rm -rf ./out-?']) {
    assert.equal(outcome(evaluate(command, { mode: 'auto', cwd: MEMBER })), 'allow', command);
  }
  for (const command of ['rm -rf *', 'rm -rf ./*', `rm -rf ${MEMBER}/*`]) {
    assert.equal(outcome(evaluate(command, { mode: 'auto', cwd: MEMBER })), 'deny:rm-protected-root', command);
  }
  // From the parent, a pattern that matches the protected root's name still hits it.
  assert.equal(outcome(evaluate('rm -rf mem*', { mode: 'auto', cwd: PROJECT })), 'deny:rm-protected-root');
  assert.equal(outcome(evaluate('rm -rf tmp-*', { mode: 'auto', cwd: PROJECT })), 'allow');
});

test('M5: anything inside .git, and find deleting .git, is rm-git-dir', () => {
  for (const command of ['rm -rf .git/objects', 'rm -rf member/.git/refs/heads', 'rm -r ./.git/', 'rm -rf */.git',
    'find . -name .git -type d -exec rm -rf {} +', 'find . -path "*/.git/*" -delete', 'find .git -delete',
    'find . -iname ".git" -execdir rm -rf {} \\;']) {
    assert.equal(outcome(evaluate(command, { mode: 'auto', cwd: OUTSIDE })), 'deny:rm-git-dir', command);
  }
  for (const command of ['rm -rf .github/workflows', 'rm -rf .gitignore', 'find . -name "*.pyc" -delete',
    'find . -name .git -type d', 'rm -rf *']) {
    assert.equal(outcome(evaluate(command, { mode: 'auto', cwd: OUTSIDE })), 'allow', command);
  }
});

test('M6: unsandboxed git -C, discards outside the project, and find -delete outside ask in bypass', () => {
  const ask = 'confirm:unsandboxed-outside-project';
  assert.equal(outcome(evaluate(`git -C ${OUTSIDE} worktree remove old`, { mode: 'bypassPermissions', cwd: PROJECT })), ask);
  assert.equal(outcome(evaluate('git -C . worktree remove .worktrees/old', { mode: 'bypassPermissions', cwd: PROJECT })), 'allow');
  // git branch -D is an excludedCommands-style command: it leaves the sandbox even without the flag.
  assert.equal(outcome(evaluate(`git -C ${OUTSIDE} branch -D feat/o`, { mode: 'bypassPermissions', cwd: PROJECT })), ask);
  for (const command of [`git -C ${OUTSIDE} reset --hard HEAD~1`, `cd ${OUTSIDE} && git checkout -- a.txt`,
    `find ${OUTSIDE}/build -delete`, 'git -C "$R" restore .']) {
    assert.equal(outcome(evaluate(command, { mode: 'bypassPermissions', cwd: PROJECT, unsandboxed: true })), ask, command);
    // Inside the sandbox, or in auto, nothing changes.
    assert.notEqual(outcome(evaluate(command, { mode: 'bypassPermissions', cwd: PROJECT })), ask, command);
    assert.notEqual(outcome(evaluate(command, { mode: 'auto', cwd: PROJECT, unsandboxed: true })), ask, command);
  }
  for (const command of ['git reset --hard HEAD~1', `git -C ${MEMBER} checkout -- a.txt`, 'find build -delete']) {
    assert.equal(outcome(evaluate(command, { mode: 'bypassPermissions', cwd: PROJECT, unsandboxed: true })), 'allow', command);
  }
});

test('L1: expansions inside double-quoted bash -c / eval, find and xargs deletes reach the hard boundary', () => {
  for (const command of ['bash -c "rm -rf $HOME/x"', `sh -c "rm -rf ${CODEBASE}/$X"`, 'eval "rm -rf $D"',
    `bash -c "cd /tmp && rm -rf ${CODEBASE}"`, `find ${FIXTURE}/Codebase -maxdepth 1 -name personal -exec rm -rf {} +`,
    `find ${CODEBASE} -delete`, `find ${FIXTURE}/Codebase -maxdepth 1 -type d | xargs rm -rf`,
    `find ${FIXTURE}/Codebase -type d -print0 | xargs -0 -I{} rm -rf {}`]) {
    assert.equal(outcome(evaluate(command, { mode: 'auto', cwd: BARE })), 'deny:rm-protected-root', command);
  }
  for (const command of ['bash -c "echo $HOME"', `find ${FIXTURE}/Codebase -name node_modules -prune -exec rm -rf {} +`,
    'find . -name "*.log" -delete', 'find . -name node_modules -type d | xargs rm -rf', 'git ls-files -o | xargs rm -f']) {
    assert.equal(outcome(evaluate(command, { mode: 'auto', cwd: BARE })), 'allow', command);
  }
});

test('L2/L3: bypass read-only allowlist', () => {
  const writes = ['git -c core.pager=less log -1', 'git --config-env=core.pager=P log', 'git diff --ext-diff',
    'git log -p --textconv', 'rg --pre ./x foo', 'rg --pre=./x foo', "sed 's/a/b/e' f", "sed '1e date' f", 'sed -f s.sed f',
    'awk -f p.awk f', "man -P 'sh -c id' ls", 'curl -s -o out https://x', 'curl -sSO https://x', 'curl -X POST https://x',
    'curl -d a=b https://x', 'curl --data-binary @f https://x', "gh api graphql -f query='mutation { a }'",
    'gh api graphql -F query=@q.graphql', 'npm install', 'node script.js', 'git log --output=x'];
  const reads = ['git ls-files -o --exclude-standard', 'git grep -o foo', "gh api graphql -f query='{ viewer { login } }'",
    'npm ls --depth=0', 'npm view left-pad version', 'node --version', 'gh auth status', 'gh auth status 2>&1 | head -5',
    'curl -s https://x | head', 'curl -sSfL -H "Accept: text/plain" https://x', 'curl -I https://x', 'man ls',
    "sed -n 's/a/b/p' f", "sed 's/signingkey .*/signingkey <redacted>/' f", 'rg -n foo src', 'find . -name x | xargs grep -n foo'];
  for (const command of writes) {
    assert.equal(outcome(evaluate(command, { mode: 'bypassPermissions', cwd: BARE })), 'deny:bypass-no-project-sandbox', command);
  }
  for (const command of reads) {
    assert.equal(outcome(evaluate(command, { mode: 'bypassPermissions', cwd: BARE })), 'allow', command);
  }
});

test('L4: the unsandboxed log redacts common credential spellings', () => {
  const fake = `Zq9${'x'.repeat(30)}`;
  for (const command of [
    `curl -H "Authorization: Bearer ${fake}" https://x`, `curl -H 'X-Api-Key: ${fake}' https://x`,
    `psql postgres://admin:${fake}@db/prod`, `git clone https://oauth2:${fake}@gitlab.com/x/y.git`,
    `mysql -uroot -p${fake} -e 'show databases'`, `mysql --password=${fake}`, `curl --password "${fake}"`,
    `TOKEN="${fake}" ./deploy.sh`, `MY_API_KEY='${fake}' node x`, `SECRET=${fake} x`,
    `npm config set //registry.npmjs.org/:_authToken ${fake}`, `npm config set //r/:_authToken=${fake}`,
    `curl https://hooks.slack.com/services/T0/B0/${fake}`, `sshpass -p ${fake} ssh host`,
  ]) {
    assert.ok(!redact(command).includes(fake), command);
  }
  assert.ok(!redact(`aws s3 ls # AKIA${'A'.repeat(16)}`).includes('AKIA'));
  for (const command of ['mkdir -p build/x', 'ssh -p 22 host', 'git commit -m "rotate key"']) {
    assert.equal(redact(command), command);
  }
});

test('L5: reset --hard to refs/remotes/<r>/main or to an upstream that is the trunk asks in bypass', () => {
  for (const command of ['git reset --hard refs/remotes/origin/main', 'git reset --hard refs/heads/master']) {
    assert.equal(outcome(evaluate(command, { mode: 'bypassPermissions', cwd: PROJECT })), 'confirm:reset-hard-main', command);
  }
  assert.equal(outcome(evaluate('git reset --hard @{u}', { mode: 'bypassPermissions', cwd: TRUNK_UPSTREAM, projectDir: PROJECT })), 'confirm:reset-hard-main');
  assert.equal(outcome(evaluate('git reset --hard HEAD@{upstream}', { mode: 'bypassPermissions', cwd: TRUNK_UPSTREAM, projectDir: PROJECT })), 'confirm:reset-hard-main');
  assert.equal(outcome(evaluate('git reset --hard @{u}', { mode: 'bypassPermissions', cwd: MEMBER })), 'allow');
  assert.equal(outcome(evaluate('git reset --hard @{u}', { mode: 'auto', cwd: TRUNK_UPSTREAM })), 'allow');
});

test('L8: legacy-dangerous has no bypass-session rules', () => {
  assert.equal(outcome(evaluate('touch x', { mode: 'bypassPermissions', cwd: BARE, profile: 'legacy-dangerous' })), 'allow');
  assert.equal(outcome(evaluate(`rm -rf ${OUTSIDE}`, { mode: 'bypassPermissions', cwd: PROJECT, unsandboxed: true, profile: 'legacy-dangerous' })), 'allow');
  assert.equal(outcome(evaluate('git reset --hard HEAD~1', { mode: 'auto', cwd: PROJECT, profile: 'legacy-dangerous' })), 'confirm:git-discard');
});

test('L9: a literal cd leading an && chain sets the cwd; otherwise common names are not protected roots', () => {
  assert.equal(outcome(evaluate('cd /tmp/x && rm -rf data', { mode: 'auto', cwd: CODEBASE })), 'allow');
  assert.equal(outcome(evaluate('rm -rf data', { mode: 'auto', cwd: CODEBASE })), 'deny:rm-protected-root');
  assert.equal(outcome(evaluate(`cd ${FIXTURE} && cd Codebase/personal && rm -rf data`, { mode: 'auto' })), 'deny:rm-protected-root');
  assert.equal(outcome(evaluate('cd "$T" && rm -rf data', { mode: 'auto', cwd: CODEBASE })), 'allow');
  assert.equal(outcome(evaluate('cd "$T" && rm -rf dotfiles', { mode: 'auto', cwd: CODEBASE })), 'deny:rm-protected-root');
  assert.equal(outcome(evaluate('cd "$T" && rm -rf personal/data', { mode: 'auto', cwd: CODEBASE })), 'deny:rm-protected-root');
  // A cd to the directory the command already runs in changes nothing.
  assert.equal(outcome(evaluate(`cd ${CODEBASE}; rm -rf build; cd ${CODEBASE} || true`, { mode: 'auto', cwd: CODEBASE })), 'allow');
  // `||`, `;` and subshells do not guarantee the cd happened.
  for (const command of ['cd /tmp/x || rm -rf dotfiles', '(cd /tmp/x) && rm -rf dotfiles', 'cd /tmp/x; rm -rf dotfiles']) {
    assert.equal(outcome(evaluate(command, { mode: 'auto', cwd: CODEBASE })), 'deny:rm-protected-root', command);
  }
});

test('other bypasses found by the review probes', () => {
  const link = join(CODEBASE, 'podcast-production');
  for (const [command, ruleId] of [
    ['gh -R acme/demo repo delete --yes', 'gh-repo-delete'],
    [`rsync -a --delete /tmp/empty/ ${CODEBASE}/`, 'rm-protected-root'],
    [`echo ${CODEBASE} | xargs rm -rf`, 'rm-protected-root'],
    ['git push origin --delete HEAD', 'push-delete-trunk'],
    [`ln -sfn /tmp/x ${link}`, 'rm-protected-path'],
  ]) {
    const result = evaluateHookEvent({ tool_name: 'Bash', tool_input: { command }, cwd: PROJECT, permission_mode: 'auto' }, {
      profile: 'dangerous-only', shfmtPath: SHFMT, protectedRoots: PROTECTED_ROOTS, protectedPaths: [link],
      inspectDirectory: inspect, caseInsensitivePaths: false,
    });
    assert.equal(result && outcome(result), `deny:${ruleId}`, command);
  }
  for (const command of [`rsync -a --delete src/ ${CODEBASE}/dotfiles/build/`, 'git push origin --delete HEAD', 'echo build | xargs rm -rf']) {
    assert.equal(outcome(evaluate(command, { mode: 'auto', cwd: MEMBER })), 'allow', command);
  }
});

test('gh api DELETE with a dynamic endpoint is denied', () => {
  assert.equal(evaluate('gh api -X DELETE "$ENDPOINT"', { mode: 'auto' }).kind, 'deny');
  assert.equal(evaluate('gh api --method DELETE "repos/$R"', { mode: 'auto' }).kind, 'deny');
});
