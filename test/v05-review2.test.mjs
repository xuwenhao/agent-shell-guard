// @ts-check
// Regressions from the second independent review of the 0.5 branch, the Codex
// inline findings and the Claude bot review on 61c54d8. Command strings are
// data handed to the evaluator (or the analyzer / redactor); nothing is
// executed.

import assert from 'node:assert/strict';
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';

import { isGrokNativePromptCovered } from '../src/adapters/grok-native.mjs';
import { isKimiNativePromptCovered } from '../src/adapters/kimi-native.mjs';
import { isCodexNativePromptCovered } from '../src/adapters/codex-native.mjs';
import { resolveShfmtPath } from '../src/config.mjs';
import { evaluateHookEvent } from '../src/guard-core.mjs';
import { foldCase, isFullMatchPattern, setCaseInsensitivePaths } from '../src/path-targets.mjs';
import { gitHead, inspectDirectory, inspectProjectDir, stripConfigComment } from '../src/project.mjs';
import { redact } from '../src/reviewer.mjs';
import { analyzeShellInput, decodeAnsiC } from '../src/shell-analyzer.mjs';

const SHFMT = resolveShfmtPath();
const FIXTURE = mkdtempSync(join(tmpdir(), 'guard-review2-'));
after(() => rmSync(FIXTURE, { recursive: true, force: true }));

/** @param {string} path @param {string|object} [content] */
function put(path, content = '') {
  mkdirSync(join(path, '..'), { recursive: true });
  writeFileSync(path, typeof content === 'string' ? content : JSON.stringify(content));
}

/** @param {string} root @param {string|null} branch @param {string} [config] */
function repo(root, branch, config = '[core]\n') {
  put(join(root, '.git', 'HEAD'), branch === null ? `${'a'.repeat(40)}\n` : `ref: refs/heads/${branch}\n`);
  put(join(root, '.git', 'config'), config);
}

const CODEBASE = join(FIXTURE, 'Codebase', 'personal');
const DEVINFRA = join(CODEBASE, 'devinfra');
const SCRATCH = join(FIXTURE, 'scratch');
const PROTECTED_ROOTS = ['/', homedir(), CODEBASE, DEVINFRA, join(DEVINFRA, 'dotfiles'), join(DEVINFRA, 'data'),
  join(DEVINFRA, 'infra'), join(DEVINFRA, '.worktrees')];
const PROTECTED_PATHS = [join(CODEBASE, 'podcast-production')];

// A thin project root (members as nested repos) and assorted HEAD layouts.
repo(DEVINFRA, 'main');
repo(join(DEVINFRA, 'member'), 'main');
const PROJECT = join(FIXTURE, 'proj');
repo(PROJECT, 'feat/p');
put(join(PROJECT, '.claude', 'settings.json'), { sandbox: { filesystem: { allowWrite: ['.'] } } });
const BARE = join(FIXTURE, 'bare');
repo(BARE, 'feat/y');
const ON_MAIN = join(FIXTURE, 'onmain');
repo(ON_MAIN, 'main');
const SYMREF = join(FIXTURE, 'symref');
repo(SYMREF, 'alias');
put(join(SYMREF, '.git', 'refs', 'heads', 'alias'), 'ref: refs/heads/main\n');
const REFTABLE = join(FIXTURE, 'reftable');
repo(REFTABLE, '.invalid', '[core]\n\trepositoryformatversion = 1\n[extensions]\n\trefStorage = reftable\n');
const COMMENTED = join(FIXTURE, 'commented');
repo(COMMENTED, 'feat', '[core]\n[branch "feat"] # tracks the trunk\n\tremote = origin\n\tmerge = refs/heads/main ; trunk\n');
const QUOTED = join(FIXTURE, 'quoted');
repo(QUOTED, 'feat', '[branch "feat"]\n\tremote = origin\n\tmerge = "refs/heads/main" # quoted\n');
mkdirSync(SCRATCH, { recursive: true });
// CI runners have no zsh; a validator that accepts everything keeps the zsh
// dialect cases about glob handling, not about zsh's own syntax check.
const ACCEPTING_ZSH = join(FIXTURE, 'zsh');
writeFileSync(ACCEPTING_ZSH, '#!/bin/sh\nexit 0\n');
chmodSync(ACCEPTING_ZSH, 0o755);

/** @param {string} directory */
const inspect = (directory) => inspectDirectory(directory, { ephemeralRoots: [] });
/** @param {string} directory */
const inspectProject = (directory) => inspectProjectDir(directory, { ephemeralRoots: [] });

/**
 * @param {string} command
 * @param {{mode?: string, cwd?: string|null, profile?: string, unsandboxed?: boolean, projectDir?: string,
 *   host?: 'claude'|'codex'|'grok'|'kimi', shell?: string, caseInsensitivePaths?: boolean}} [options]
 */
function evaluate(command, options = {}) {
  /** @type {Record<string, unknown>} */
  const toolInput = { command };
  if (options.unsandboxed) toolInput.dangerouslyDisableSandbox = true;
  const host = options.host ?? 'claude';
  /** @type {Record<string, unknown>} */
  const event = { tool_name: host === 'claude' ? 'Bash' : 'shell', tool_input: toolInput };
  if (options.mode) event.permission_mode = options.mode;
  const cwd = options.cwd === undefined ? SCRATCH : options.cwd;
  if (cwd !== null) event.cwd = cwd;
  const result = evaluateHookEvent(event, {
    profile: options.profile ?? 'dangerous-only',
    shfmtPath: SHFMT,
    envShell: options.shell ?? '/bin/bash',
    zshPath: ACCEPTING_ZSH,
    protectedRoots: PROTECTED_ROOTS,
    protectedPaths: PROTECTED_PATHS,
    inspectDirectory: inspect,
    inspectProjectDir: inspectProject,
    projectDir: options.projectDir,
    host,
    caseInsensitivePaths: options.caseInsensitivePaths ?? false,
  });
  assert.ok(result);
  return /** @type {any} */ (result);
}

/** @param {any} result */
const outcome = (result) => result.kind === 'allow' ? 'allow' : `${result.kind}:${result.ruleId}`;

/**
 * @param {Array<[string, string]>} table command → expected outcome
 * @param {Parameters<typeof evaluate>[1]} [options]
 */
function expectAll(table, options) {
  for (const [command, expected] of table) assert.equal(outcome(evaluate(command, options)), expected, command);
}

// --- P1: shfmt byte offsets ----------------------------------------------------

test('P1: multibyte text before a command does not shift its source words', () => {
  const graph = analyzeShellInput({ kind: 'script', text: `echo 中文说明🙂 && rm -rf ${CODEBASE}/* "$X"` }, { dialect: 'bash', shfmtPath: SHFMT });
  assert.deepEqual(graph.commands[1].displayArgv, ['rm', '-rf', `${CODEBASE}/*`, '"$X"']);
  assert.equal(graph.hasCompound, true);
  const piped = analyzeShellInput({ kind: 'script', text: 'echo 中文 | rm -rf "$X"' }, { dialect: 'bash', shfmtPath: SHFMT });
  assert.equal(piped.hasPipeline, true);

  expectAll([
    [`echo 中文说明 && rm -rf ${CODEBASE}/*`, 'deny:rm-protected-root'],
    [`echo 中文说明 && rm -rf ${FIXTURE}/Codebase/{personal,x}`, 'deny:rm-protected-root'],
    ['echo 中文说明中文说明中文说明 && rm -rf "$X"', 'deny:rm-protected-root'],
    [`# 清理一下\nrm -rf ${FIXTURE}/Codebase/*`, 'deny:rm-protected-root'],
    ['echo 中文 && rm -rf .g*', 'deny:rm-git-dir'],
    [`echo 中文说明 && find ${FIXTURE}/Codebase/{personal,x} -delete`, 'deny:rm-protected-root'],
    [`echo 中文 && rm -rf ${DEVINFRA}/*`, 'deny:rm-protected-root'],
    [`echo 🙂🙂 && rm -rf ${CODEBASE}/*`, 'deny:rm-protected-root'],
    [`echo 一二三四五六七八九十一二三四五六七八九十 && rm -rf ${DEVINFRA}/da*`, 'deny:rm-protected-root'],
    [`git commit -m "修复" && rm -rf "$DIR"`, 'deny:rm-protected-root'],
  ], { mode: 'auto' });
});

test('P1: a CJK heredoc followed by a narrow glob delete is not a false positive', () => {
  const link = PROTECTED_PATHS[0];
  expectAll([
    [`cat > notes.md <<'EOF'\n# 播客制作说明：先剪辑再合成，完成后清理临时文件\nEOF\nrm -f ${link}/tmp-*.wav`, 'allow'],
    [`echo "中文 🙂" > a.txt && rm -f ${CODEBASE}/podcast-production-*.bak`, 'allow'],
    [`echo 中文 && rm -rf build/*`, 'allow'],
  ], { mode: 'auto', cwd: join(DEVINFRA, 'dotfiles') });
});

// --- P2: cd candidates -----------------------------------------------------------

test('P2: literal cds make every reachable directory a candidate cwd', () => {
  expectAll([
    [`cd ${DEVINFRA} && rm -rf data || true`, 'deny:rm-protected-root'],
    [`cd ${DEVINFRA} 2>/dev/null && rm -rf data`, 'deny:rm-protected-root'],
    [`cd ${DEVINFRA} && rm -rf data; echo done`, 'deny:rm-protected-root'],
    [`cd ${DEVINFRA} && rm -rf data && cd -`, 'deny:rm-protected-root'],
    [`cd ${DEVINFRA}\nrm -rf data`, 'deny:rm-protected-root'],
    [`cd ${DEVINFRA} && rm -rf infra; ls`, 'deny:rm-protected-root'],
    [`cd ${DEVINFRA}; rm -rf data`, 'deny:rm-protected-root'],
    [`(cd ${DEVINFRA} && rm -rf data)`, 'deny:rm-protected-root'],
    [`pushd ${DEVINFRA} && rm -rf data`, 'deny:rm-protected-root'],
    [`pushd ${DEVINFRA} >/dev/null && rm -rf data`, 'deny:rm-protected-root'],
    [`sh -c 'cd ${DEVINFRA} && rm -rf data'`, 'deny:rm-protected-root'],
    [`cd ${DEVINFRA} || exit 1; rm -rf data`, 'deny:rm-protected-root'],
    [`chdir ${DEVINFRA} && rm -rf dotfiles`, 'deny:rm-protected-root'],
    [`cd ${DEVINFRA}; rm -rf ./data`, 'deny:rm-protected-root'],
    [`if cd ${DEVINFRA}; then rm -rf data; fi`, 'deny:rm-protected-root'],
    [`eval cd ${DEVINFRA} && rm -rf data`, 'deny:rm-protected-root'],
    [`cd ${CODEBASE} && cd devinfra && rm -rf data`, 'deny:rm-protected-root'],
    [`make && cd ${DEVINFRA} && rm -rf data`, 'deny:rm-protected-root'],
    [`cd ${CODEBASE} && ls && cd devinfra && rm -rf infra`, 'deny:rm-protected-root'],
  ], { mode: 'auto', cwd: SCRATCH });
  // A cd chain that fully determines the cwd stays 'matched'.
  assert.equal(evaluate(`cd ${DEVINFRA} 2>/dev/null && rm -rf data`, { mode: 'auto' }).evaluation, 'matched');
  assert.equal(evaluate(`if cd ${DEVINFRA}; then rm -rf data; fi`, { mode: 'auto' }).evaluation, 'matched');
});

test('P2: the hook cwd stays a candidate when a cd may fail first', () => {
  expectAll([
    // cd fails → rm runs in the hook cwd (the protected thin root).
    [`cd ${SCRATCH}/x; rm -rf data`, 'deny:rm-protected-root'],
    [`cd ${SCRATCH} && rm -rf data && cd - && rm -rf data`, 'deny:rm-protected-root'],
    [`cd ${SCRATCH} || true; rm -rf infra`, 'deny:rm-protected-root'],
    [`x=$(cd ${SCRATCH} && pwd); rm -rf data`, 'deny:rm-protected-root'],
    // && guarantees the cd succeeded before rm runs.
    [`cd ${SCRATCH} && rm -rf data`, 'allow'],
    [`(cd ${SCRATCH} && rm -rf data)`, 'allow'],
    [`if cd ${SCRATCH}; then rm -rf data; fi`, 'allow'],
    [`cd ${SCRATCH} && rm -rf data || true`, 'allow'],
    // Each element of an && chain runs after every cd before it.
    [`cd ${SCRATCH} && make && cd sub && rm -rf data`, 'allow'],
    [`echo start && cd ${SCRATCH} && rm -rf data`, 'allow'],
    // A cd to the cwd itself changes nothing.
    [`cd ${DEVINFRA} && rm -rf build; rm -rf node_modules`, 'allow'],
  ], { mode: 'auto', cwd: DEVINFRA });
});

test('P2: the common-name exemption only applies after a dynamic cd', () => {
  expectAll([
    ['cd "$X" && rm -rf data', 'allow'],
    ['cd "$X" && rm -rf infra', 'allow'],
    ['cd "$X" && rm -rf dotfiles', 'deny:rm-protected-root'],
    ['cd "$X"; rm -rf data', 'allow'],
  ], { mode: 'auto', cwd: SCRATCH });
  // ...but the hook cwd is still a candidate when that cd may fail.
  assert.equal(outcome(evaluate('cd "$X"; rm -rf data', { mode: 'auto', cwd: DEVINFRA })), 'deny:rm-protected-root');
  assert.equal(outcome(evaluate('cd "$X" && rm -rf data', { mode: 'auto', cwd: DEVINFRA })), 'allow');
});

// --- Codex inline findings --------------------------------------------------------

test('Codex P1-a/P1-b: dynamic git reader options and less log files are writes', () => {
  expectAll([
    ['OPT=--output=/tmp/x; git log "$OPT"', 'deny:bypass-no-project-sandbox'],
    ['git diff "$@"', 'deny:bypass-no-project-sandbox'],
    ['git show "$REV"', 'deny:bypass-no-project-sandbox'],
    ['cat input | less -O /tmp/copy', 'deny:bypass-no-project-sandbox'],
    ['less -o/tmp/copy f', 'deny:bypass-no-project-sandbox'],
    ['less -So /tmp/copy f', 'deny:bypass-no-project-sandbox'],
    ['less --log-file=/tmp/copy f', 'deny:bypass-no-project-sandbox'],
    ['less --LOG-FILE /tmp/copy f', 'deny:bypass-no-project-sandbox'],
    ["less +'!touch x' f", 'deny:bypass-no-project-sandbox'],
    ['git log --oneline -5', 'allow'],
    ['git show HEAD:README.md', 'allow'],
    ['less -R f', 'allow'],
    ['git log | less -S', 'allow'],
  ], { mode: 'bypassPermissions', cwd: BARE });
});

test('Claude bot (55c4fac): sed w/W commands after a numeric, $ or range address are writes', () => {
  expectAll([
    ["sed '1w /tmp/out' input", 'deny:bypass-no-project-sandbox'],
    ["sed '$w /tmp/last' input", 'deny:bypass-no-project-sandbox'],
    ["sed -n '1,5w /tmp/out' input", 'deny:bypass-no-project-sandbox'],
    ["sed -n '1W /tmp/out' input", 'deny:bypass-no-project-sandbox'],
    ["sed '/re/w /tmp/out' input", 'deny:bypass-no-project-sandbox'],
    ["sed 's/a/b/w /tmp/out' input", 'deny:bypass-no-project-sandbox'],
    ["sed 's/a/b/gw /tmp/out' input", 'deny:bypass-no-project-sandbox'],
    ["sed -n 'p; w /tmp/out' input", 'deny:bypass-no-project-sandbox'],
    ["sed -n '1,5p' input", 'allow'],
    ["sed -n '/warn/,/whatever/p' input", 'allow'],
    ["sed 's/warn/WARN/g' input", 'allow'],
    ["sed -n '/warn/p' input", 'allow'],
  ], { mode: 'bypassPermissions', cwd: BARE });
});

test('Claude bot (55c4fac): unknown project root makes unsandboxed-outside-project unknown, not matched', () => {
  const result = evaluate(`rm -rf ${SCRATCH}/x`, { mode: 'bypassPermissions', cwd: BARE, unsandboxed: true });
  if (result?.ruleId === 'unsandboxed-outside-project') {
    assert.equal(result.evaluation, 'unknown');
    assert.doesNotMatch(result.why, /目标在项目外/);
  }
});

// --- P3/P4: push refspecs and option clusters -------------------------------------

test('P3: matching and wildcard refspecs force-push the trunk', () => {
  expectAll([
    ['git push -f origin :', 'deny:force-push-main'],
    ['git push origin +:', 'deny:force-push-main'],
    ["git push -f origin 'refs/heads/*:refs/heads/*'", 'deny:force-push-main'],
    ["git push origin '+refs/heads/*:refs/heads/*'", 'deny:force-push-main'],
    ["git push -f origin 'refs/heads/mai*:refs/heads/mai*'", 'deny:force-push-main'],
    ['git push -f origin feat/x', 'allow'],
    ['git push origin :feat/old', 'allow'],
  ], { mode: 'auto', cwd: BARE });
  assert.equal(evaluate('git push -f origin :', { mode: 'auto', cwd: BARE }).evaluation, 'matched');
});

test('P4: -o takes the rest of its cluster; the last --[no-]dry-run wins', () => {
  expectAll([
    ['git push --mirror -onone origin', 'deny:force-push-main'],
    ['git push -onone origin :main', 'deny:push-delete-trunk'],
    ['git push origin --delete main -onotify', 'deny:push-delete-trunk'],
    ['git push --mirror --dry-run --no-dry-run origin', 'deny:force-push-main'],
    ['git push --dry-run --no-dry-run origin --delete main', 'deny:push-delete-trunk'],
    ['git push --no-dry-run --dry-run origin --delete main', 'allow'],
    ['git push -dn origin main', 'allow'],
    ['git push -nd origin main', 'allow'],
    ['git push --mirror -n origin', 'allow'],
  ], { mode: 'auto', cwd: BARE });
});

// --- P5: ANSI-C quoting --------------------------------------------------------------

test('P5: $\'…\' words are decoded; undecodable ones stay dynamic', () => {
  assert.equal(decodeAnsiC(String.raw`perso\x6eal\té\101\cA`), 'personal\téA\x01');
  assert.equal(decodeAnsiC(String.raw`a\xff`), null);
  assert.equal(decodeAnsiC(String.raw`a\0`), null);
  assert.equal(decodeAnsiC(String.raw`a\q`), null);
  expectAll([
    [`rm -rf $'${CODEBASE.replace(/l$/, '\\x6c')}'`, 'deny:rm-protected-root'],
    ["rm -rf $'.gi\\x74'", 'deny:rm-git-dir'],
    [`bash -c $'rm -rf ${CODEBASE.replace(/l$/, '\\x6c')}'`, 'deny:rm-protected-root'],
    ["rm -rf $'.gi\\xff'", 'deny:rm-protected-root'],
    ["rm -rf $'build\\tdir'", 'allow'],
  ], { mode: 'auto' });
});

// --- P6: find -exec ---------------------------------------------------------------------

test('P6: find -exec unwraps wrappers and treats a shell evaluator as a delete', () => {
  expectAll([
    [`find ${CODEBASE} -maxdepth 0 -exec sh -c 'rm -rf "$1"' _ {} \\;`, 'deny:rm-protected-root'],
    [`find ${CODEBASE} -maxdepth 0 -exec command rm -rf {} +`, 'deny:rm-protected-root'],
    [`find ${CODEBASE} -maxdepth 0 -exec env rm -rf {} +`, 'deny:rm-protected-root'],
    [`find ${CODEBASE} -maxdepth 0 -exec sudo rm -rf {} +`, 'deny:rm-protected-root'],
    ['find . -name .git -exec sh -c \'rm -rf "$0"\' {} \\;', 'deny:rm-git-dir'],
    [`find ${CODEBASE} -name '*.pyc' -exec command rm -f {} +`, 'allow'],
    [`find ${CODEBASE} -name '*.log' -exec sh -c 'wc -l "$1"' _ {} \\;`, 'allow'],
    // A negated test excludes; it does not select .git.
    ["find . -name 'x.conf' -not -path './.git/*' -exec sh -c 'cat \"$1\"' _ {} \\;", 'allow'],
    ["find . ! -path './.git/*' -name '*.tmp' -delete", 'allow'],
  ], { mode: 'auto' });
});

// --- P7: git location environment ---------------------------------------------------------

test('P7: GIT_DIR / GIT_WORK_TREE / GIT_CONFIG_* in the graph make the repository unknown', () => {
  expectAll([
    ['GIT_DIR=/other/.git git push -f origin HEAD', 'deny:force-push-main'],
    ['env GIT_DIR=/x/.git git push -f origin HEAD', 'deny:force-push-main'],
    ['GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=push.default GIT_CONFIG_VALUE_0=matching git push -f', 'deny:force-push-main'],
    [`export GIT_DIR=${ON_MAIN}/.git; git push -f origin HEAD`, 'deny:force-push-main'],
    ['git -c push.default=matching push -f', 'deny:force-push-main'],
    [`GIT_DIR=${DEVINFRA}/.git GIT_WORK_TREE=${DEVINFRA} git clean -fdx`, 'deny:git-clean-root'],
    [`export GIT_DIR=${DEVINFRA}/.git GIT_WORK_TREE=${DEVINFRA}; git clean -fdx`, 'deny:git-clean-root'],
    ['GIT_INDEX_FILE=/tmp/i git clean -fdx', 'deny:git-clean-root'],
    // An explicit non-trunk refspec does not depend on the repository.
    ['GIT_DIR=/other/.git git push -f origin feat/x', 'allow'],
    ['git push -f origin HEAD', 'allow'],
  ], { mode: 'auto', cwd: BARE });
  assert.equal(evaluate('GIT_DIR=/other/.git git push -f origin HEAD', { mode: 'auto', cwd: BARE }).evaluation, 'unknown');
});

// --- P8: native prompt tables -----------------------------------------------------------

test('P8: Grok and Kimi delegate chmod 777 and gh api DELETE again, as in 0.4', () => {
  for (const [host, covered] of /** @type {const} */ ([['grok', isGrokNativePromptCovered], ['kimi', isKimiNativePromptCovered]])) {
    for (const [command, ruleId] of [['chmod 777 build/out', 'chmod-777'], ['gh api -X DELETE repos/o/r/issues/comments/1', 'gh-api-delete']]) {
      const result = evaluate(command, { host });
      assert.equal(outcome(result), `confirm:${ruleId}`, `${host}: ${command}`);
      assert.equal(covered(result.ruleId, result.analysis, command), true, `${host}: ${command}`);
    }
  }
  // Codex keeps no prefix for them (0.4 had none either): the adapter denies.
  const codex = evaluate('chmod 777 x', { host: 'codex' });
  assert.equal(isCodexNativePromptCovered(codex.ruleId, codex.analysis), false);
});

// --- P9/P10: brace overflow and glob shapes ---------------------------------------------

test('P9: an over-long brace followed by .. is unknown', () => {
  const many = Array.from({ length: 70 }, (_, index) => `a${index}`).join(',');
  expectAll([
    [`rm -rf /opt/{${many},homebrew}/../..${CODEBASE}`, 'deny:rm-protected-root'],
    [`rm -rf /usr/{1..70,bin}/../..${CODEBASE}`, 'deny:rm-protected-root'],
    [`rm -rf ${SCRATCH}/{${many}}`, 'allow'],
  ], { mode: 'auto' });
});

test('P10: zsh qualifiers are dropped and literal-free patterns match everything', () => {
  assert.equal(isFullMatchPattern('[[:alnum:]]*'), true);
  assert.equal(isFullMatchPattern('?*?'), true);
  assert.equal(isFullMatchPattern('[!~]*'), true);
  assert.equal(isFullMatchPattern('[a-z]*'), true);
  assert.equal(isFullMatchPattern('tmp-*'), false);
  assert.equal(isFullMatchPattern('*.log'), false);
  assert.equal(isFullMatchPattern('[ab]*'), false);
  expectAll([
    [`rm -rf ${DEVINFRA}/dotfiles/[[:alnum:]]*`, 'deny:rm-protected-root'],
    [`rm -rf ${DEVINFRA}/dotfiles/?*`, 'deny:rm-protected-root'],
    [`rm -rf ${DEVINFRA}/dotfiles/*.log`, 'allow'],
  ], { mode: 'auto' });
  expectAll([
    [`rm -rf ${DEVINFRA}/*(D)`, 'deny:rm-protected-root'],
    [`rm -rf ${DEVINFRA}/*(.N)`, 'deny:rm-protected-root'],
  ], { host: 'codex', shell: '/bin/zsh' });
  assert.equal(outcome(evaluate(`rm -rf ${DEVINFRA}/*.log(N)`, { host: 'codex', shell: '/bin/zsh' })), 'allow');
});

// --- L1-L5 ------------------------------------------------------------------------------

test('L1: case folding covers the long s and NFC forms', () => {
  const previous = setCaseInsensitivePaths(true);
  try {
    assert.equal(foldCase('perſonal'), foldCase('PERSONAL'));
    assert.equal(foldCase('café'), foldCase('CAFÉ'));
  } finally { setCaseInsensitivePaths(previous); }
  assert.equal(outcome(evaluate(`rm -rf ${CODEBASE.replace(/personal$/, 'perſonal')}`, { mode: 'auto', caseInsensitivePaths: true })), 'deny:rm-protected-root');
});

test('L2: HEAD follows symbolic refs; reftable is unknown; config comments are stripped', () => {
  assert.equal(gitHead(SYMREF).branch, 'main');
  assert.equal(gitHead(REFTABLE).branch, null);
  assert.deepEqual(gitHead(COMMENTED).upstream, { remote: 'origin', merge: 'refs/heads/main' });
  assert.deepEqual(gitHead(QUOTED).upstream, { remote: 'origin', merge: 'refs/heads/main' });
  assert.equal(stripConfigComment('\tmerge = "a;b" ; c'), 'merge = "a;b"');
  expectAll([
    ['git push -f origin HEAD', 'deny:force-push-main'],
  ], { mode: 'auto', cwd: SYMREF });
  assert.equal(outcome(evaluate('git push -f origin HEAD', { mode: 'auto', cwd: REFTABLE })), 'deny:force-push-main');
  assert.equal(evaluate('git push -f origin HEAD', { mode: 'auto', cwd: REFTABLE }).evaluation, 'unknown');
  assert.equal(outcome(evaluate('git push -f', { mode: 'auto', cwd: REFTABLE })), 'deny:force-push-main');
  assert.equal(outcome(evaluate('git push -f', { mode: 'auto', cwd: COMMENTED })), 'deny:force-push-main');
  assert.equal(outcome(evaluate('git push -f', { mode: 'auto', cwd: QUOTED })), 'deny:force-push-main');
});

test('L3: recovery paths inside .git may be removed; .git and its stores may not', () => {
  expectAll([
    ['rm -rf .git/modules/vendor/lib', 'allow'],
    ['rm -rf .git/worktrees/feat-x', 'allow'],
    ['rm -rf .git/worktrees/*', 'allow'],
    ['rm -rf .git/rebase-merge', 'allow'],
    ['rm -rf .git/rebase-apply', 'allow'],
    ['rm -rf .git/index.lock', 'allow'],
    ['rm -rf .git/refs/heads/feat.lock', 'allow'],
    ['rm -rf .git/*.lock', 'allow'],
    ['rm -rf .git', 'deny:rm-git-dir'],
    ['rm -rf .git/', 'deny:rm-git-dir'],
    ['rm -rf .git/modules', 'deny:rm-git-dir'],
    ['rm -rf .git/worktrees', 'deny:rm-git-dir'],
    ['rm -rf .git/objects', 'deny:rm-git-dir'],
    ['rm -rf .git/refs', 'deny:rm-git-dir'],
    ['rm -rf .git/*', 'deny:rm-git-dir'],
    ['rm -rf .git/modules/x/../../objects', 'deny:rm-git-dir'],
    ['rm -rf sub/.git', 'deny:rm-git-dir'],
  ], { mode: 'auto' });
});

test('L4: exec-channel variables and export make a bypass "read" a write', () => {
  expectAll([
    ["GIT_PAGER='touch x' git -p log", 'deny:bypass-no-project-sandbox'],
    ["GIT_EXTERNAL_DIFF='touch x' git diff", 'deny:bypass-no-project-sandbox'],
    ["PAGER='touch x' man ls", 'deny:bypass-no-project-sandbox'],
    ["MANPAGER='touch x' man ls", 'deny:bypass-no-project-sandbox'],
    ["GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.pager GIT_CONFIG_VALUE_0='touch x' git -p log", 'deny:bypass-no-project-sandbox'],
    ["LESSOPEN='|touch x %s' less f", 'deny:bypass-no-project-sandbox'],
    ["LESSCLOSE='touch x' less f", 'deny:bypass-no-project-sandbox'],
    ["GIT_SSH_COMMAND='touch x' git ls-remote origin", 'deny:bypass-no-project-sandbox'],
    ["export GIT_PAGER='touch x'; git log", 'deny:bypass-no-project-sandbox'],
    ["PAGER='touch x'; man ls", 'deny:bypass-no-project-sandbox'],
    ['export FOO=1; ls', 'deny:bypass-no-project-sandbox'],
    ['declare -x FOO=1; ls', 'deny:bypass-no-project-sandbox'],
    ['GIT_TRACE=/tmp/trace git status', 'deny:bypass-no-project-sandbox'],
    ['GIT_PAGER=cat git log -3', 'allow'],
    ["PAGER='' git log -3", 'allow'],
    ['GIT_TRACE=1 git status', 'allow'],
    ['LESS=-R git log', 'allow'],
    ['LC_ALL=C grep -r foo .', 'allow'],
    ['FOO=1; echo "$FOO"', 'allow'],
  ], { mode: 'bypassPermissions', cwd: BARE });
});

test('L5: redaction covers aws configure set, gh secret set --body and sudo -S', () => {
  const fake = `Zq9${'x'.repeat(30)}`;
  for (const command of [
    `aws configure set aws_secret_access_key ${fake}`,
    `aws configure set default.aws_secret_access_key "${fake}"`,
    `aws configure set aws_session_token '${fake}' --profile p`,
    `gh secret set API_KEY --body ${fake} --repo o/r`,
    `gh secret set API_KEY -b "${fake}"`,
    `gh secret set API_KEY -b${fake}`,
    `gh secret set API_KEY --body=${fake}`,
    `printf '%s\\n' ${fake} | sudo -S true`,
    `echo "${fake}" | sudo -kS ls`,
    `curl --password "${fake}" https://x`,
    `PASSWORD="${fake}" ./deploy`,
  ]) {
    assert.ok(!redact(command).includes(fake), command);
  }
  for (const command of ['echo hello | grep h', 'gh secret list', 'aws configure list', 'printf x | sudo tee /etc/x']) {
    assert.equal(redact(command), command);
  }
});

// --- Claude bot review on 61c54d8 -------------------------------------------------------

test('bot 1: an unsandboxed git worktree add outside the project asks in bypass', () => {
  const options = { mode: 'bypassPermissions', cwd: PROJECT, projectDir: PROJECT, unsandboxed: true };
  assert.equal(outcome(evaluate(`git worktree add ${SCRATCH}/wt -b feat/wt`, options)), 'confirm:unsandboxed-outside-project');
  assert.equal(outcome(evaluate('git worktree add -b feat/wt ../elsewhere', options)), 'confirm:unsandboxed-outside-project');
  assert.equal(outcome(evaluate('git worktree add "$DIR"', options)), 'confirm:unsandboxed-outside-project');
  assert.equal(outcome(evaluate('git worktree add .worktrees/wt -b feat/wt', options)), 'allow');
  assert.equal(outcome(evaluate(`git worktree add -B feat/wt ${PROJECT}/.worktrees/wt`, options)), 'allow');
});

test('bot 2: checkout/switch --orphan of the trunk is git-trunk-ref', () => {
  const options = { mode: 'bypassPermissions', cwd: PROJECT, projectDir: PROJECT };
  expectAll([
    ['git checkout --orphan main', 'confirm:git-trunk-ref'],
    ['git checkout --orphan=master', 'confirm:git-trunk-ref'],
    ['git checkout --orphan "$B"', 'confirm:git-trunk-ref'],
    ['git switch --orphan main', 'confirm:git-trunk-ref'],
    ['git checkout --orphan gh-pages', 'allow'],
    ['git switch --orphan gh-pages', 'allow'],
  ], options);
  assert.equal(outcome(evaluate('git checkout --orphan gh-pages', { ...options, profile: 'full' })), 'review:git-low-risk');
});

test('bot 3: gh api DELETE with a dynamic endpoint fails closed', () => {
  for (const command of ['gh api -X DELETE "$ENDPOINT"', 'gh api --method DELETE "repos/$R"']) {
    assert.equal(evaluate(command, { mode: 'auto' }).kind, 'deny', command);
  }
});

test('bot 4: awk reads unless its program writes or runs something', () => {
  expectAll([
    ["awk 'NR > 5 { print }' f", 'allow'],
    ["awk -F: '$3 >= 1000 { print $1 }' /etc/passwd", 'allow'],
    ["awk '{ if ($1 > max) max = $1 } END { print max }' f", 'allow'],
    ["awk -v n=3 'NR <= n' f", 'allow'],
    ["awk '{ print > \"/tmp/x\" }' f", 'deny:bypass-no-project-sandbox'],
    ["awk '{ printf \"%s\", $0 >> \"out\" }' f", 'deny:bypass-no-project-sandbox'],
    ["awk '{ print | \"sh\" }' f", 'deny:bypass-no-project-sandbox'],
    ["awk '{ print | cmd }' f", 'deny:bypass-no-project-sandbox'],
    ["awk 'BEGIN { system(\"touch x\") }'", 'deny:bypass-no-project-sandbox'],
    ["awk 'BEGIN { \"date\" | getline d }'", 'deny:bypass-no-project-sandbox'],
    ['awk -f prog.awk f', 'deny:bypass-no-project-sandbox'],
    ['awk "$PROG" f', 'deny:bypass-no-project-sandbox'],
  ], { mode: 'bypassPermissions', cwd: BARE });
});

test('bot 6: --no-detach / --no-orphan cancel the earlier option instead of counting as a discard', () => {
  const options = { mode: 'auto', cwd: PROJECT, profile: 'full' };
  expectAll([
    ['git checkout --detach v1.0', 'review:git-low-risk'],
    // Cancelled detach: a lone operand is ambiguous again (ref or path).
    ['git checkout --detach --no-detach v1.0', 'confirm:git-discard'],
    ['git checkout --no-detach feat/x', 'confirm:git-discard'],
    ['git checkout -b feat/new --no-detach', 'review:git-low-risk'],
    ['git checkout --orphan main --no-orphan', 'review:git-low-risk'],
  ], options);
});

test('bot 7: quoted credentials are redacted before they reach the unsandboxed log', () => {
  assert.equal(redact('curl --password "hunter2" https://x'), 'curl --password <redacted-secret> https://x');
  assert.equal(redact("PASSWORD='hunter2' cmd"), 'PASSWORD=<redacted-secret> cmd');
});

test('git worktree remove of a protected root is a recursive delete of it', () => {
  expectAll([
    [`git worktree remove --force ${DEVINFRA}/dotfiles`, 'deny:rm-protected-root'],
    ['git worktree remove dotfiles', 'deny:rm-protected-root'],
    [`git -C ${DEVINFRA} worktree remove data`, 'deny:rm-protected-root'],
    [`git worktree remove ${DEVINFRA}/.worktrees/feat-x`, 'allow'],
    ['git worktree remove "$S/wt-x"', 'allow'],
  ], { mode: 'auto', cwd: DEVINFRA });
});

test('known limitations stay documented: aliases and piped shells are not followed', () => {
  // README "已知局限": these run their content through a shell the guard never sees.
  expectAll([
    [`printf 'rm -rf %s\\n' ${CODEBASE} | sh`, 'allow'],
    [`gpf! origin main`, 'allow'],
  ], { mode: 'auto' });
});
