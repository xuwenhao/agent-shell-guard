// @ts-check
// All command strings are parser input only; never execute them.
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';
import { evaluateHookEvent } from '../src/guard-core.mjs';
import { inspectDirectory } from '../src/project.mjs';

const root = mkdtempSync(join(tmpdir(), 'guard-wrapper-'));
after(() => rmSync(root, { recursive: true, force: true }));
mkdirSync(join(root, '.git'));
mkdirSync(join(root, '.claude'));
writeFileSync(join(root, '.claude/settings.json'), JSON.stringify({ sandbox: { filesystem: { allowWrite: [root] } } }));
const hooked = join(root, 'hooked');
mkdirSync(join(hooked, '.beads/hooks'), { recursive: true });
writeFileSync(join(hooked, '.beads/hooks/on_create'), '');
const plain = join(root, 'plain');
mkdirSync(plain);
/** @param {string} text */
const quote = (text) => "'" + text.replaceAll("'", "'\\''") + "'";
/** @param {string|string[]} command @param {'relaxed'|'bypass'|'native'} tier @param {string} [cwd] */
function evaluate(command, tier, cwd = root) {
  const result = evaluateHookEvent({ tool_name: 'Bash', tool_input: { command }, cwd,
    permission_mode: tier === 'bypass' ? 'bypassPermissions' : 'auto' }, {
    profile: 'dangerous-only', host: tier === 'native' ? 'codex' : 'claude',
    inspectDirectory: (directory) => inspectDirectory(directory, { ephemeralRoots: [] }),
  });
  assert.ok(result);
  return result;
}
const init = 'bd ' + 'init';
const push = 'git push --' + 'force origin ma' + 'in';
for (const tier of /** @type {const} */ (['relaxed', 'bypass', 'native'])) {
  for (const [body, rule] of [[init, 'bd-forbidden-subcommand'], [push, 'force-push-main']]) {
    for (const command of [`env -S ${quote(body)}`, `sudo FOO=1 ${body}`,
      `env -S${quote(body)}`, `env --split-string=${quote(body)}`, `env --split-string ${quote(body)}`,
      `env -iS ${quote(body)}`, `env -vS${quote(body)}`, `sudo -u root FOO=1 ${body}`,
      `env --unset=NAME ${body}`, `env -u NAME ${body}`]) {
      test(`${tier} rejects wrapper ${command}`, () => {
        const result = evaluate(command, tier);
        assert.equal(result.kind, 'deny');
        assert.equal(result.ruleId, rule);
      });
    }
  }
  for (const command of ['sudo BEADS_MEM_PROFILE=/tmp/x bd list', 'sudo BEADS_MEM_PROFILE="$P" bd list',
    'sudo BEADS_MEM_PROFILE=/tmp/x env -S "bd list"']) {
    test(`${tier} sudo profile ${command}`, () => {
      const result = evaluate(command, tier);
      assert.equal(result.kind, 'deny');
      assert.equal(result.ruleId, 'bd-profile-write');
    });
  }
  for (const command of [`env -C ${quote(hooked)} bd create --title=x`,
    `env -C${quote(hooked)} bd create`, `env --chdir=${quote(hooked)} bd create`,
    `env --chdir ${quote(hooked)} bd create`, 'env -C hooked bd create',
    `env -C ${quote(root)} env -C hooked bd create`,
    `env -C ${quote(hooked)} -S 'bd create'`, `env -S ${quote('-C ' + quote(hooked) + ' bd create')}`,
    `env -C ${quote(hooked)} sh -c 'bd create'`,
    `sudo BEADS_DIR=${quote(join(hooked, '.beads'))} bd create`]) {
    test(`${tier} command cwd ${command}`, () => {
      const result = evaluate(command, tier);
      assert.equal(result.kind, tier === 'relaxed' ? 'allow' : 'confirm');
      if (result.kind !== 'allow') assert.equal(result.ruleId, 'bd-repo-hooks');
    });
  }
  for (const command of ['env -C "$D" bd create', 'env --chdir="$D" bd create',
    'sudo BEADS_DIR="$D" bd create']) {
    test(`${tier} unknown cwd ${command}`, () => {
      const result = evaluate(command, tier);
      assert.equal(result.kind, tier === 'relaxed' ? 'allow' : 'confirm');
      if (result.kind !== 'allow') assert.equal(result.evaluation, 'unknown');
    });
  }
  for (const command of [`env -C ${quote(hooked)} bd list`, `env -C ${quote(plain)} bd create`,
    'env -C /x true; bd create', `env -C ${quote(hooked)} true; bd create`,
    'env -S "bd create" --title="a; b"']) {
    test(`${tier} quiet ${command}`, () => assert.equal(evaluate(command, tier).kind, 'allow'));
  }
  test(`${tier} directory override does not leak to next command`, () => {
    const result = evaluate(`env -C ${quote(plain)} true; bd create`, tier, hooked);
    assert.equal(result.kind, tier === 'relaxed' ? 'allow' : 'confirm');
  });
  test(`${tier} dynamic split matches shell evaluator`, () => {
    const result = evaluate('env -S "$X"', tier);
    assert.equal(result.kind, evaluate('sh -c "$X"', tier).kind);
    assert.ok(result.analysis.unknowns.some((item) => item.reason === 'dynamic-evaluator'));
  });
  test(`${tier} split preserves trailing argv`, () => {
    assert.equal(evaluate('env -S "bd" ' + 'init', tier).kind, 'deny');
  });
}
test('argv input recursively evaluates split string', () => {
  assert.equal(evaluate(['env', '-S', init], 'native').kind, 'deny');
});
test('split recursion remains bounded', () => {
  let command = init;
  for (let i = 0; i < 9; i++) command = 'env -S ' + quote(command);
  assert.ok(evaluate(command, 'native').analysis.unknowns.some((item) => item.reason === 'recursion-limit'));
});
test('relative rm uses env directory', () => {
  const removal = 'rm -' + 'rf .git';
  const result = evaluate(`env -C ${quote(root)} ${removal}`, 'native', plain);
  assert.equal(result.kind, 'deny');
  const baseline = evaluate(removal, 'native', root);
  assert.equal(baseline.kind, 'deny');
  assert.equal(result.ruleId, baseline.ruleId);
});
for (const option of ['-C', '--chdir=']) {
  test(`cwd operand containing S is not a split option: ${option}`, () => {
    const directory = join(root, 'Somewhere');
    mkdirSync(directory, { recursive: true });
    assert.equal(evaluate(`env ${option}${quote(directory)} bd create`, 'native').kind, 'allow');
  });
}
for (const option of ['-S"$X"', '--split-string="$X"', '-iS "$X"']) {
  test(`attached and combined dynamic split: ${option}`, () => {
    assert.ok(evaluate(`env ${option}`, 'native').analysis.unknowns.some((item) => item.reason === 'dynamic-evaluator'));
  });
}
test('git branch lookup uses wrapper cwd without leaking to the next command', () => {
  mkdirSync(join(plain, '.git'), { recursive: true });
  writeFileSync(join(root, '.git/HEAD'), 'ref: refs/heads/main\n');
  writeFileSync(join(root, '.git/config'), '[core]\n');
  writeFileSync(join(plain, '.git/HEAD'), 'ref: refs/heads/feature\n');
  writeFileSync(join(plain, '.git/config'), '[core]\n');
  const command = 'git push --' + 'force origin HEAD';
  const wrapped = evaluate(`env -C ${quote(root)} ${command}`, 'native', plain);
  assert.equal(wrapped.kind, 'deny');
  assert.equal(wrapped.ruleId, 'force-push-main');
  const untouched = evaluate(`env -C ${quote(root)} true; ${command}`, 'native', plain);
  assert.notEqual(untouched.kind, 'deny');
});
