#!/usr/bin/env node
// @ts-check

import assert from 'node:assert/strict';
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { resolveShfmtPath } from '../src/config.mjs';
import { analyzeShellInput, selectShellDialect } from '../src/shell-analyzer.mjs';

const SHFMT = resolveShfmtPath();

/** @param {string} text @param {'bash'|'posix'|'zsh'} [dialect] @param {Record<string, unknown>} [options] */
function analyze(text, dialect = 'bash', options = {}) {
  return analyzeShellInput({ kind: 'script', text }, { dialect, shfmtPath: SHFMT, ...options });
}

test('selects the adapter dialect deterministically', () => {
  assert.equal(selectShellDialect({ toolName: 'Bash', explicitShell: '/bin/zsh', envShell: '/bin/zsh' }), 'bash');
  assert.equal(selectShellDialect({ toolName: 'bash', explicitShell: '/bin/zsh', envShell: '/bin/zsh' }), 'bash');
  assert.equal(selectShellDialect({ toolName: 'shell', explicitShell: '/bin/bash', envShell: '/bin/zsh' }), 'bash');
  assert.equal(selectShellDialect({ toolName: 'exec_command', envShell: '/bin/zsh' }), 'zsh');
  assert.equal(selectShellDialect({ toolName: 'exec_command', envShell: '/bin/dash' }), 'posix');
  assert.equal(selectShellDialect({ toolName: 'exec_command', envShell: '/usr/bin/fish' }), 'posix');
  assert.equal(selectShellDialect({ toolName: 'exec_command' }), 'posix');
});

test('unknown shells do not require a zsh validator', () => {
  const dialect = selectShellDialect({ toolName: 'exec_command', envShell: '/usr/bin/fish' });
  const graph = analyzeShellInput(
    { kind: 'script', text: 'printf ok' },
    { dialect, shfmtPath: SHFMT, zshPath: '/definitely/missing/zsh' },
  );
  assert.equal(graph.status, 'safe');
});

test('does not treat an assignment-only statement as a dynamic command', () => {
  const graph = analyze('VALUE=literal');
  assert.equal(graph.status, 'safe');
  assert.deepEqual(graph.commands, []);
  assert.equal(graph.nativePromptArgv, null);
});

test('reconstructs static words, quotes, escapes, and adjacent fragments', () => {
  const graph = analyze("printf '%s\\n' pre\"mid\"post a\\ b \"x\\`y\\$z\\\\q\"");
  assert.equal(graph.status, 'safe');
  assert.deepEqual(graph.commands[0].argv, ['printf', '%s\\n', 'premidpost', 'a b', 'x`y$z\\q']);
  assert.deepEqual(graph.nativePromptArgv, ['printf', '%s\\n', 'premidpost', 'a b', 'x`y$z\\q']);
});

test('expands the current-home tilde while keeping other tilde commands unknown', () => {
  const currentHome = analyze('~/.local/bin/shfmt --version');
  assert.equal(currentHome.status, 'safe');
  assert.deepEqual(currentHome.commands[0].argv, [`${homedir()}/.local/bin/shfmt`, '--version']);
  assert.deepEqual(currentHome.nativePromptArgv, [`${homedir()}/.local/bin/shfmt`, '--version']);

  for (const command of ['~other/bin/tool --version', '~+/bin/tool --version', '~-/bin/tool --version', '~"/bin/tool" --version']) {
    const graph = analyze(command);
    assert.equal(graph.status, 'unknown');
    assert.ok(graph.unknowns.some((item) => item.reason === 'dynamic-command'));
  }
});

test('keeps the POSIX test command literal while detecting bracket globs', () => {
  const testCommand = analyze('[ -f "$FILE" ]');
  assert.equal(testCommand.status, 'safe');
  assert.deepEqual(testCommand.commands[0].argv, ['[', '-f', null, ']']);
  assert.equal(testCommand.unknowns.length, 0);

  const unmatchedBracket = analyze('[literal --version');
  assert.equal(unmatchedBracket.status, 'safe');
  assert.equal(unmatchedBracket.commands[0].argv[0], '[literal');

  const bracketGlob = analyze('[abc] --version');
  assert.equal(bracketGlob.status, 'unknown');
  assert.ok(bracketGlob.unknowns.some((item) => item.reason === 'dynamic-command'));
});

test('marks dynamic data unknown without turning the command into execution unknown', () => {
  const graph = analyze('printf "%s\\n" "$VALUE"');
  assert.equal(graph.status, 'safe');
  assert.deepEqual(graph.commands[0].argv, ['printf', '%s\\n', null]);
  assert.equal(graph.unknowns.length, 0);
  assert.equal(graph.nativePromptArgv, null);
});

test('marks a dynamic command name as execution unknown', () => {
  const graph = analyze('$COMMAND harmless');
  assert.equal(graph.status, 'unknown');
  assert.ok(graph.unknowns.some((item) => item.reason === 'dynamic-command'));
});

test('records pipeline, redirection, command substitution, backticks, and process substitution', () => {
  const graph = analyze('echo "$(ssh host uptime)" | cat <(printf x) >out; echo `date`');
  assert.equal(graph.status, 'safe');
  assert.deepEqual(graph.commands.map((command) => command.argv?.[0]), ['echo', 'ssh', 'cat', 'printf', 'echo', 'date']);
  assert.ok(graph.commands.some((command) => command.source === 'command-substitution'));
  assert.ok(graph.commands.some((command) => command.source === 'process-substitution'));
  assert.ok(graph.commands.some((command) => command.source === 'backtick-substitution'));
  assert.equal(graph.hasPipeline, true);
  assert.equal(graph.hasRedirection, true);
  assert.equal(graph.nativePromptArgv, null);
});

test('recursively parses static shell -c scripts and switches dialect', () => {
  const directory = mkdtempSync(join(tmpdir(), 'guard-analyzer-zsh-'));
  const acceptingZsh = join(directory, 'zsh');
  writeFileSync(acceptingZsh, '#!/bin/sh\nexit 0\n');
  chmodSync(acceptingZsh, 0o755);
  try {
    const graph = analyze('bash -lc -- "ssh host uptime"; zsh -c "print ok"', 'bash', {
      zshPath: acceptingZsh,
    });
    const nested = graph.commands.filter((command) => command.source === 'shell-c');
    assert.deepEqual(nested.map((command) => [command.dialect, command.argv?.[0]]), [['bash', 'ssh'], ['zsh', 'print']]);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test('unwraps common static command wrappers before policy matching', () => {
  const remote = analyze('nohup env VAR=x /usr/bin/ssh host uptime');
  assert.deepEqual(remote.commands[0].argv, ['/usr/bin/ssh', 'host', 'uptime']);
  assert.deepEqual(remote.commands[0].wrappers, ['nohup', 'env']);
  assert.equal(remote.nativePromptArgv, null);

  const busybox = analyze('busybox rm -rf /');
  assert.deepEqual(busybox.commands[0].argv, ['rm', '-rf', '/']);

  const timeout = analyze('timeout --signal TERM 5 bash -c "ssh host uptime"');
  assert.ok(timeout.commands.some((command) => command.source === 'shell-c' && command.argv[0] === 'ssh'));
});

test('joins all static eval arguments with spaces before recursive parsing', () => {
  const inert = analyze('eval "echo" "ssh host uptime"');
  assert.deepEqual(inert.commands.filter((command) => command.source === 'eval').map((command) => command.argv), [
    ['echo', 'ssh', 'host', 'uptime'],
  ]);
  const executable = analyze('eval "echo;" "ssh host uptime"');
  assert.deepEqual(executable.commands.filter((command) => command.source === 'eval').map((command) => command.argv?.[0]), ['echo', 'ssh']);
});

test('marks dynamic evaluator input as execution unknown', () => {
  for (const text of ['eval "$SCRIPT"', 'bash -c "$SCRIPT"']) {
    const graph = analyze(text);
    assert.equal(graph.status, 'unknown');
    assert.ok(graph.unknowns.some((item) => item.reason === 'dynamic-evaluator'));
  }
});

test('treats non-shell evaluator payloads as data instead of shell execution', () => {
  const graph = analyze('python3 -c "$PYTHON_CODE"');
  assert.equal(graph.status, 'safe');
  assert.deepEqual(graph.commands[0].argv, ['python3', '-c', null]);
  assert.equal(graph.unknowns.length, 0);
  assert.equal(graph.nativePromptArgv, null);
});

test('keeps already-tokenized argv literal and eligible for native prompt', () => {
  const graph = analyzeShellInput({ kind: 'argv', argv: ['ssh', 'host name', 'a;b'] }, { dialect: 'zsh', shfmtPath: SHFMT });
  assert.equal(graph.status, 'safe');
  assert.deepEqual(graph.commands[0].argv, ['ssh', 'host name', 'a;b']);
  assert.deepEqual(graph.nativePromptArgv, ['ssh', 'host name', 'a;b']);
});

test('recursively parses shell evaluators received as tokenized argv', () => {
  const direct = analyzeShellInput({ kind: 'argv', argv: ['bash', '-c', 'ssh host uptime'] }, { dialect: 'zsh', shfmtPath: SHFMT });
  assert.ok(direct.commands.some((command) => command.source === 'shell-c' && command.argv[0] === 'ssh'));
  assert.equal(direct.nativePromptArgv, null);

  const withOptionValue = analyze('bash -o pipefail -c "ssh host uptime"');
  assert.ok(withOptionValue.commands.some((command) => command.source === 'shell-c' && command.argv[0] === 'ssh'));
});

test('fails closed when the parser is missing or times out', () => {
  const missing = analyze('echo ok', 'bash', { shfmtPath: '/definitely/missing/shfmt' });
  assert.equal(missing.status, 'unknown');
  assert.equal(missing.unknowns[0].reason, 'parser-missing');

  const dir = mkdtempSync(join(tmpdir(), 'guard-analyzer-timeout-'));
  const slow = join(dir, 'shfmt');
  writeFileSync(slow, '#!/bin/sh\nsleep 2\n');
  chmodSync(slow, 0o755);
  try {
    const timeout = analyze('echo ok', 'bash', { shfmtPath: slow, timeoutMs: 20 });
    assert.equal(timeout.status, 'unknown');
    assert.equal(timeout.unknowns[0].reason, 'parser-timeout');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('fails closed when zsh syntax validation conflicts with shfmt', () => {
  const dir = mkdtempSync(join(tmpdir(), 'guard-analyzer-zsh-'));
  const rejectingZsh = join(dir, 'zsh');
  writeFileSync(rejectingZsh, '#!/bin/sh\nexit 1\n');
  chmodSync(rejectingZsh, 0o755);
  try {
    const graph = analyze('print ok', 'zsh', { zshPath: rejectingZsh, timeoutMs: 2000 });
    assert.equal(graph.status, 'unknown');
    assert.equal(graph.unknowns[0].reason, 'zsh-validation-conflict');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('fails closed for unsupported zsh syntax instead of falling back', () => {
  const graph = analyze('print ${^array}', 'zsh');
  assert.equal(graph.status, 'unknown');
  assert.ok(graph.unknowns.some((item) => item.reason === 'parser-failed'));
});

test('uses the managed shfmt resolver for direct library calls', () => {
  const graph = analyzeShellInput(
    { kind: 'script', text: 'printf ok' },
    { dialect: 'bash' },
  );
  assert.equal(graph.status, 'safe');
  assert.equal(graph.commands[0].argv[0], 'printf');
});

test('enforces input, recursion, and command-node limits', () => {
  const tooLarge = analyze(`echo ${'x'.repeat(65536)}`);
  assert.equal(tooLarge.status, 'unknown');
  assert.equal(tooLarge.unknowns[0].reason, 'input-too-large');

  let nested = 'echo ok';
  for (let i = 0; i < 10; i++) nested = `eval ${JSON.stringify(nested)}`;
  const tooDeep = analyze(nested);
  assert.equal(tooDeep.status, 'unknown');
  assert.ok(tooDeep.unknowns.some((item) => item.reason === 'recursion-limit'));

  const tooMany = analyze(Array.from({ length: 257 }, () => 'echo ok').join(';'));
  assert.equal(tooMany.status, 'unknown');
  assert.ok(tooMany.unknowns.some((item) => item.reason === 'command-limit'));
});
