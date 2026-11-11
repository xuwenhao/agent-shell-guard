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
      `sudo FOO=1 -i ${body}`, `sudo FOO=1 -u root BAR=2 ${body}`, `sudo FOO=1 -- ${body}`,
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
  // Inner layers use GNU quoting; only the outer layer is shell input.
  const gnuQuote = (/** @type {string} */ text) => "'" + text.replaceAll('\\', '\\\\').replaceAll("'", "\\'") + "'";
  for (let i = 0; i < 8; i++) command = 'env -S ' + gnuQuote(command);
  command = 'env -S ' + quote(command);
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

// GNU split strings are data for evaluateHookEvent, never shell execution.
for (const tier of /** @type {const} */ (['relaxed', 'bypass', 'native'])) {
  for (const body of ['bd\\_' + 'init', 'bd "' + 'init"', "bd '" + "init'", init + ' #x']) {
    test(`${tier} GNU split denies ${JSON.stringify(body)}`, () => {
      assert.equal(evaluate('env -S ' + quote(body), tier).kind, 'deny');
    });
  }
  test(`${tier} GNU split double-quoted shell operand`, () => {
    assert.equal(evaluate('env -S "bd \'init\'"', tier).kind, 'deny');
  });
  for (const body of ['bd\\_list', 'bd list # ignored']) {
    test(`${tier} GNU split allows ${JSON.stringify(body)}`, () => {
      assert.equal(evaluate('env -S ' + quote(body), tier).kind, 'allow');
    });
  }
  test(`${tier} GNU split truncates at backslash c`, () => {
    assert.equal(evaluate('env -S ' + quote('bd\\c' + 'init'), tier).kind, evaluate('bd', tier).kind);
    assert.deepEqual(evaluate('env -S ' + quote('bd\\c' + 'init'), tier).analysis.commands.at(-1)?.argv, ['bd']);
  });
  for (const body of ['bd ${X}', 'bd $X', 'bd\\q' + 'init', 'bd "init', "bd 'init", 'bd\\', 'bd li\\\nst', 'bd "a\\cb"']) {
    test(`${tier} GNU split fails closed ${JSON.stringify(body)}`, () => {
      const result = evaluate('env -S ' + quote(body), tier);
      assert.equal(result.kind, evaluate('env -S "$X"', tier).kind);
      assert.ok(result.analysis.unknowns.some((item) => item.reason === 'dynamic-evaluator'));
    });
  }
  for (const option of ['-iC' + quote(hooked), '-iC ' + quote(hooked)]) {
    test(`${tier} clustered chdir ${option}`, () => {
      assert.equal(evaluate('env ' + option + ' bd create', tier).kind, tier === 'relaxed' ? 'allow' : 'confirm');
    });
  }
  test(`${tier} clustered unset consumes next word`, () => {
    assert.equal(evaluate('env -iu FOO ' + init, tier).kind, 'deny');
  });
}
for (const [body, argv] of /** @type {Array<[string, string[]]>} */ ([
  ['bd "a\\_b"', ['bd', 'a b']],
  ["bd 'a\\_b'", ['bd', 'a\\_b']],
  ['bd \\#x \\$X', ['bd', '#x', '$X']],
  ['bd ""', ['bd', '']],
  ['bd x#y', ['bd', 'x#y']],
  ['bd "a\\"b"', ['bd', 'a"b']],
  ["bd 'a\\'b'", ['bd', "a'b"]],
  ['bd a\\\\b', ['bd', 'a\\b']],
])) {
  test(`GNU split argv ${JSON.stringify(body)}`, () => {
    assert.deepEqual(evaluate('env -S ' + quote(body), 'native').analysis.commands.at(-1)?.argv, argv);
  });
}
test('wrapper cwd followed by nested cd cannot hide main branch', () => {
  const safe = join(root, 'safe');
  const main = join(safe, 'main-repo');
  for (const [directory, branch] of [[safe, 'feature'], [main, 'main']]) {
    mkdirSync(join(directory, '.git'), { recursive: true });
    writeFileSync(join(directory, '.git/HEAD'), 'ref: refs/heads/' + branch + '\n');
    writeFileSync(join(directory, '.git/config'), '[core]\n');
  }
  const force = 'git push --' + 'force origin HEAD';
  assert.notEqual(evaluate(force, 'native', safe).kind, 'deny');
  const result = evaluate('env -C ' + quote(safe) + ' sh -c ' + quote('cd main-repo && ' + force), 'native', safe);
  assert.equal(result.kind, 'deny');
  assert.equal(result.ruleId, 'force-push-main');
  // Codex's exact case: hook cwd elsewhere, absolute wrapper cwd, relative nested cd.
  for (const tier of /** @type {const} */ (['relaxed', 'bypass', 'native'])) {
    const elsewhere = evaluate('env -C ' + quote(safe) + ' sh -c ' + quote('cd main-repo && ' + force), tier, root);
    assert.equal(elsewhere.kind, 'deny');
    assert.equal(elsewhere.ruleId, 'force-push-main');
  }
});

for (const [escape, character] of Object.entries({ t: '\t', n: '\n', r: '\r', f: '\f', v: '\v' })) {
  test(`GNU split preserves escaped whitespace ${escape} inside argument`, () => {
    const result = evaluate('env -S ' + quote('bd a\\' + escape + 'b'), 'native');
    assert.deepEqual(result.analysis.commands.at(-1)?.argv, ['bd', 'a' + character + 'b']);
  });
}
for (const option of ['-iC"$D"']) {
  test(`cluster marker respects first value-taking option ${option}`, () => {
    const result = evaluate('env ' + option + ' bd create', 'native');
    assert.equal(result.kind, 'confirm');
    assert.ok(!result.analysis.unknowns.some((item) => item.reason === 'dynamic-evaluator'));
  });
}
