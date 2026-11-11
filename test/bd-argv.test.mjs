// @ts-check
// Inputs below are parsed only, never executed.
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';
import { evaluateHookEvent } from '../src/guard-core.mjs';
import { inspectDirectory } from '../src/project.mjs';

const root = mkdtempSync(join(tmpdir(), 'guard-bd-'));
after(() => rmSync(root, { recursive: true, force: true }));
mkdirSync(join(root, '.git'));
mkdirSync(join(root, '.claude'));
writeFileSync(join(root, '.claude/settings.json'), JSON.stringify({ sandbox: { filesystem: { allowWrite: [root] } } }));
const hooked = join(root, 'hooked');
mkdirSync(join(hooked, '.beads/hooks'), { recursive: true });
writeFileSync(join(hooked, '.beads/hooks/on_create'), '');
mkdirSync(join(hooked, 'child'));
const empty = join(root, 'empty');
mkdirSync(join(empty, '.beads/hooks'), { recursive: true });
mkdirSync(join(hooked, 'nested/.beads'), { recursive: true });

/** @param {string} command @param {'relaxed'|'bypass'|'native'} [tier] @param {string} [cwd] */
function evaluate(command, tier = 'relaxed', cwd = root) {
  const result = evaluateHookEvent({ tool_name: 'Bash', tool_input: { command }, cwd,
    permission_mode: tier === 'bypass' ? 'bypassPermissions' : 'auto' }, {
    profile: 'dangerous-only', host: tier === 'native' ? 'codex' : 'claude',
    inspectDirectory: (directory) => inspectDirectory(directory, { ephemeralRoots: [] }),
  });
  assert.ok(result);
  return result;
}

const forbidden = ['bd init', 'bd --json setup', 'bd -C /tmp/x init', 'bd --db=foo hooks install',
  'bd --actor me dolt start', '/usr/local/bin/bd init', 'FOO=1 bd setup', 'env BEADS_X=1 bd init',
  'command bd init', 'bd -- init', 'bd $SUB', 'bd $(echo init)', 'bd --weird-flag init',
  'echo x | bd init', 'echo x && bd init', 'bd --directory=/tmp/x init', 'bd --actor init setup'];
const profiles = ['bd list --mem-profile /tmp/x', 'bd --mem-profile=/tmp/x list', 'bd --cpu-profile list',
  'BEADS_MEM_PROFILE=/tmp/x bd list', 'env BEADS_MEM_PROFILE=/tmp/x bd list', 'BEADS_MEM_PROFILE=$P bd list', 'env BEADS_MEM_PROFILE=$P bd list', 'bd list --mem-profile=$P'];
for (const tier of /** @type {const} */ (['relaxed', 'bypass', 'native'])) {
  for (const [rule, commands] of /** @type {Array<[string, string[]]>} */ ([['bd-forbidden-subcommand', forbidden], ['bd-profile-write', profiles]])) {
    for (const command of commands) test(`${tier} deny ${command}`, () => {
      const result = evaluate(command, tier);
      assert.equal(result.kind, 'deny');
      assert.equal(result.ruleId, rule);
    });
  }
}
for (const command of ['bd list --json', 'bd ready', 'bd show dev-1', 'bd create --title="init setup"',
  'bd update x --notes "bd init"', 'bd', 'bd --help', 'bd --version', 'echo bd init', "grep 'bd init' file",
  'BEADS_MEM_PROFILE=/tmp/x echo hi; bd list', 'bd --actor setup list', 'bd --json=true list']) {
  test(`allow ${command}`, () => assert.equal(evaluate(command).kind, 'allow'));
}
for (const command of ['bd $SUB', 'bd $(echo init)', 'bd --weird-flag init']) {
  test(`unknown ${command}`, () => {
    const result = evaluate(command);
    if (result.kind !== 'allow') assert.equal(result.evaluation, 'unknown');
    else assert.fail('must deny');
  });
}
for (const tier of /** @type {const} */ (['relaxed', 'bypass', 'native'])) {
  for (const [command, cwd] of [['bd create --title=x', hooked], ['bd create --title=x', join(hooked, 'child')],
    [`bd -C ${hooked} create --title=x`, root], ['bd create -C hooked --title=x', root],
    ['bd --directory=hooked create --title=x', root], ['bd doctor --fix', hooked]]) {
    test(`${tier} hooks ${command} in ${cwd}`, () => {
      const result = evaluate(command, tier, cwd);
      assert.equal(result.kind, tier === 'relaxed' ? 'allow' : 'confirm');
      if (result.kind !== 'allow') assert.equal(result.ruleId, 'bd-repo-hooks');
    });
  }
}
for (const [command, cwd] of [['bd list', hooked], ['bd doctor', hooked], ['bd', hooked],
  ['bd --help', hooked], ['bd create --title=x', empty], ['bd create', join(hooked, 'nested')], ['bd create', root]]) {
  test(`no hooks confirmation ${command} in ${cwd}`, () => assert.equal(evaluate(command, 'native', cwd).kind, 'allow'));
}

test('every documented global flag is skipped before the subcommand', () => {
  for (const flag of ['--actor', '--database', '--db', '-C', '--directory', '--dolt-auto-commit']) {
    for (const option of [`${flag} value`, `${flag}=value`]) {
      const result = evaluate(`bd ${option} init`);
      assert.equal(result.kind, 'deny');
      assert.equal(result.evaluation, 'matched');
    }
  }
  for (const flag of ['--global', '-h', '--help', '--ignore-schema-skew', '--json', '--no-color',
    '-q', '--quiet', '--readonly', '--sandbox', '-v', '--verbose', '-V', '--version']) {
    assert.equal(evaluate(`bd ${flag} init`).kind, 'deny');
  }
});

test('unreadable hooks entry stays silent', () => {
  const broken = join(root, 'broken');
  mkdirSync(join(broken, '.beads'), { recursive: true });
  writeFileSync(join(broken, '.beads/hooks'), 'not a directory');
  assert.equal(evaluate('bd create', 'native', broken).kind, 'allow');
});
