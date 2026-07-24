// @ts-check

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { Readable } from 'node:stream';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

import {
  HookInputError,
  MAX_HOOK_INPUT_BYTES,
  readJsonStream,
} from '../src/io.mjs';

const CLI = fileURLToPath(new URL('../src/cli.mjs', import.meta.url));

test('parses bounded hook JSON objects', async () => {
  const event = await readJsonStream(Readable.from(['{"tool_name":"Bash"}']));
  assert.deepEqual(event, { tool_name: 'Bash' });
});

test('rejects oversized and malformed hook input', async () => {
  await assert.rejects(
    readJsonStream(Readable.from(['x'.repeat(17)]), 16),
    (error) => error instanceof HookInputError && error.code === 'input-too-large',
  );
  await assert.rejects(
    readJsonStream(Readable.from(['not-json'])),
    (error) => error instanceof HookInputError && error.code === 'input-invalid',
  );
});

test('CLI fails closed for invalid hook input', () => {
  for (const input of ['not-json', 'x'.repeat(MAX_HOOK_INPUT_BYTES + 1)]) {
    const result = spawnSync(process.execPath, [CLI, 'hook', 'codex'], {
      input,
      encoding: 'utf8',
      maxBuffer: 2 * 1024 * 1024,
    });
    assert.equal(result.status, 0);
    const output = JSON.parse(result.stdout);
    assert.equal(output.hookSpecificOutput.permissionDecision, 'deny');
    assert.match(output.hookSpecificOutput.permissionDecisionReason, /fail-closed/);
  }
});
