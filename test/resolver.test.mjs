// @ts-check

import assert from 'node:assert/strict';
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { evaluateHookEvent } from '../src/guard-core.mjs';
import { resolveDecision } from '../src/resolver.mjs';

const SHFMT = join(homedir(), '.local', 'bin', 'shfmt');

/** @param {string} command @param {string} [profile] */
function decision(command, profile = 'full') {
  const result = evaluateHookEvent({
    tool_name: 'Bash',
    tool_input: { command },
  }, { profile, shfmtPath: SHFMT });
  assert.ok(result && result.kind !== 'allow');
  return result;
}

test('strict mode prompts when supported and otherwise denies', () => {
  const result = decision('psql -c "DROP TABLE users"');
  assert.equal(resolveDecision(result, {
    supportsHookPrompt: true,
    nativePromptCovered: false,
    mode: 'strict',
    reviewer: null,
  }).action, 'prompt');
  assert.equal(resolveDecision(result, {
    supportsHookPrompt: false,
    nativePromptCovered: true,
    mode: 'strict',
    reviewer: null,
  }).action, 'delegate');
  assert.equal(resolveDecision(result, {
    supportsHookPrompt: false,
    nativePromptCovered: false,
    mode: 'strict',
    reviewer: null,
  }).action, 'deny');
});

test('reviewed mode uses a configured second model and fails closed', () => {
  const directory = mkdtempSync(join(tmpdir(), 'agent-shell-guard-reviewer-'));
  const allowScript = join(directory, 'allow.mjs');
  const invalidScript = join(directory, 'invalid.mjs');
  writeFileSync(allowScript, 'process.stdout.write(JSON.stringify({decision:"allow",reason:"bounded fixture"}));\n');
  writeFileSync(invalidScript, 'process.stdout.write("not json");\n');
  chmodSync(allowScript, 0o755);
  chmodSync(invalidScript, 0o755);
  try {
    const result = decision('psql -c "DROP TABLE users"');
    const base = /** @type {const} */ ({
      supportsHookPrompt: false,
      nativePromptCovered: false,
      mode: 'reviewed',
    });
    assert.equal(resolveDecision(result, {
      ...base,
      reviewer: { command: process.execPath, args: [allowScript], timeoutMs: 2_000 },
    }).action, 'allow');
    assert.equal(resolveDecision(result, {
      ...base,
      reviewer: { command: process.execPath, args: [invalidScript], timeoutMs: 2_000 },
    }).action, 'deny');
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test('strict mode never invokes the second-model reviewer', () => {
  const directory = mkdtempSync(join(tmpdir(), 'agent-shell-guard-reviewer-'));
  const allowScript = join(directory, 'allow.mjs');
  writeFileSync(allowScript, 'process.stdout.write(JSON.stringify({decision:"allow",reason:"fixture"}));\n');
  chmodSync(allowScript, 0o755);
  try {
    const result = decision('git branch -d old-branch');
    assert.equal(result.kind, 'review');
    const resolved = resolveDecision(result, {
      supportsHookPrompt: false,
      nativePromptCovered: false,
      mode: 'strict',
      reviewer: { command: process.execPath, args: [allowScript], timeoutMs: 2_000 },
    });
    assert.equal(resolved.action, 'deny');
    assert.match(resolved.reason ?? '', /启用 reviewed 模式/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test('hard deny never reaches a reviewer', () => {
  const result = decision('git push origin main --force');
  assert.equal(resolveDecision(result, {
    supportsHookPrompt: false,
    nativePromptCovered: false,
    mode: 'reviewed',
    reviewer: { command: '/definitely/missing', args: [], timeoutMs: 500 },
  }).action, 'deny');
});
