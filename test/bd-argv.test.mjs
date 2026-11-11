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

for (const tier of /** @type {const} */ (['relaxed', 'bypass', 'native'])) {
  for (const command of ['bd -C "$DIR" create --title=x', 'bd --directory "$DIR" update x', 'bd -C $(pwd) close x']) {
    test(`${tier} dynamic directory ${command} confirms as unknown`, () => {
      const result = evaluate(command, tier, root);
      assert.equal(result.kind, tier === 'relaxed' ? 'allow' : 'confirm');
      if (result.kind !== 'allow') { assert.equal(result.ruleId, 'bd-repo-hooks'); assert.equal(result.evaluation, 'unknown'); }
    });
  }
}
for (const tier of /** @type {const} */ (['relaxed', 'bypass', 'native'])) {
  for (const command of ['bd list "$FLAG"', 'bd doctor "$FLAG"', 'bd create --title=x "$OPT"', 'cd "$DIR" && bd create --title=x',
    'bd list --json "$FLAG"', 'bd -q list "$FLAG"']) {
    test(`${tier} unknown option or cwd ${command} confirms as unknown`, () => {
      const result = evaluate(command, tier, root);
      assert.equal(result.kind, tier === 'relaxed' ? 'allow' : 'confirm');
      if (result.kind !== 'allow') { assert.equal(result.ruleId, 'bd-repo-hooks'); assert.equal(result.evaluation, 'unknown'); }
    });
  }
}
for (const command of ['bd update x --notes "$N"', 'bd create --title "$T"', 'bd list -- "$X"', 'cd "$DIR" && bd list', `cd "$DIR" && bd -C ${root} create --title=x`]) {
  test(`dynamic value or read-only verb stays quiet: ${command}`, () => assert.equal(evaluate(command, 'native', root).kind, 'allow'));
}
for (const command of ['export BEADS_MEM_PROFILE=/tmp/out; bd list', 'BEADS_MEM_PROFILE=/tmp/out; export BEADS_MEM_PROFILE; bd list',
  "sh -c 'export BEADS_MEM_PROFILE=/tmp/out; bd list'"]) {
  test(`graph-wide BEADS_MEM_PROFILE is denied: ${command}`, () => {
    const result = evaluate(command, 'relaxed', root);
    assert.equal(result.kind, 'deny');
    assert.equal('ruleId' in result ? result.ruleId : null, 'bd-profile-write');
  });
}
for (const command of ['beads init', '/usr/local/bin/beads --json setup', 'bd.exe init', 'beads --mem-profile=/tmp/x list']) {
  test(`beads alias is guarded: ${command}`, () => assert.equal(evaluate(command).kind, 'deny'));
}
test('beads alias triggers hooks confirmation', () => {
  assert.equal(evaluate('beads create --title=x', 'native', hooked).kind, 'confirm');
});
for (const tier of /** @type {const} */ (['bypass', 'native'])) {
  test(`${tier} BEADS_DIR pointing at a hooked workspace confirms`, () => {
    const result = evaluate(`BEADS_DIR=${join(hooked, '.beads')} bd create --title=x`, tier, root);
    assert.equal(result.kind, 'confirm');
    assert.equal('evaluation' in result ? result.evaluation : null, 'matched');
  });
  test(`${tier} dynamic BEADS_DIR confirms as unknown`, () => {
    const result = evaluate('BEADS_DIR="$D" bd create --title=x', tier, root);
    assert.equal(result.kind, 'confirm');
    assert.equal('evaluation' in result ? result.evaluation : null, 'unknown');
  });
}
test('BEADS_DIR overrides a hooked cwd', () => {
  assert.equal(evaluate(`BEADS_DIR=${join(empty, '.beads')} bd create --title=x`, 'native', hooked).kind, 'allow');
});
test('BEADS_DIR with a read-only verb stays silent', () => {
  assert.equal(evaluate('BEADS_DIR="$D" bd list', 'native', root).kind, 'allow');
});
// bd 1.3.4 walks past a non-directory .beads (verified with `bd where`); pin that parity.
test('.beads plain file keeps walking to ancestor hooks', () => {
  const sub = join(hooked, 'filesub');
  mkdirSync(sub, { recursive: true });
  writeFileSync(join(sub, '.beads'), '');
  assert.equal(evaluate('bd create', 'native', sub).kind, 'confirm');
});
test('dynamic directory with a read-only subcommand stays silent', () => {
  assert.equal(evaluate('bd -C "$DIR" list', 'native', root).kind, 'allow');
});
// --dolt-auto-commit takes a value in bd 1.3.4 (`bd help`: "--dolt-auto-commit string"), so
// `bd --dolt-auto-commit init` passes init as the policy value; bd itself runs no subcommand.
test('a value flag consumes the next word exactly like bd does', () => {
  assert.equal(evaluate('bd --dolt-auto-commit init').kind, 'allow');
});
// A fully dynamic word cannot even be recognised as a flag, so the verb is unknown: fail closed.
test('fully dynamic --directory=$DIR word is denied as unknown', () => {
  const result = evaluate('bd --directory=$DIR update x', 'native', root);
  assert.equal(result.kind, 'deny');
  assert.equal('ruleId' in result ? result.ruleId : null, 'bd-forbidden-subcommand');
});

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
