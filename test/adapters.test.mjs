// @ts-check

import assert from 'node:assert/strict';
import { homedir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { adaptClaude } from '../src/adapters/claude.mjs';
import { adaptCodex } from '../src/adapters/codex.mjs';
import { adaptKimi } from '../src/adapters/kimi.mjs';

const BASE_CONFIG = {
  mode: 'strict',
  profile: 'full',
  shfmtPath: join(homedir(), '.local', 'bin', 'shfmt'),
  protectedRoots: ['/', homedir()],
  nativePrompt: { codex: true, kimi: true },
  reviewer: null,
};

/** @param {string} command */
const event = (command) => ({
  hook_event_name: 'PreToolUse',
  tool_name: 'Bash',
  tool_input: { command },
});

/** @param {any} output */
const permission = (output) => output?.hookSpecificOutput?.permissionDecision ?? 'pass';

test('Claude maps confirm to native hook ask', () => {
  assert.equal(permission(adaptClaude(event('psql -c "DROP TABLE users"'), BASE_CONFIG)), 'ask');
});

test('Codex delegates exact native prefixes and denies uncovered confirms in strict mode', () => {
  assert.equal(permission(adaptCodex(event('git branch -D old-feature'), BASE_CONFIG)), 'pass');
  assert.equal(permission(adaptCodex(event('git branch -q -D old-feature'), BASE_CONFIG)), 'deny');
  assert.equal(permission(adaptCodex(event('psql -c "DROP TABLE users"'), BASE_CONFIG)), 'deny');
});

test('native delegation is disabled until the host rules are explicitly installed', () => {
  const config = {
    ...BASE_CONFIG,
    nativePrompt: { codex: false, kimi: false },
  };
  assert.equal(permission(adaptCodex(event('git branch -D old-feature'), config)), 'deny');
  assert.equal(permission(adaptKimi(event('git branch -D old-feature'), config)), 'deny');
});

test('Kimi delegates only when normalized argv and raw permission prefix both match', () => {
  assert.equal(permission(adaptKimi(event('git branch -D old-feature'), BASE_CONFIG)), 'pass');
  assert.equal(permission(adaptKimi(event('git branch "-D" old-feature'), BASE_CONFIG)), 'deny');
  assert.equal(permission(adaptKimi(event('psql -c "DROP TABLE users"'), BASE_CONFIG)), 'pass');
});

test('all adapters preserve hard deny', () => {
  for (const adapt of [adaptClaude, adaptCodex, adaptKimi]) {
    assert.equal(permission(adapt(event('git push origin main --force'), BASE_CONFIG)), 'deny');
  }
});

test('reviewer subprocesses cannot call shell tools recursively', () => {
  const previous = process.env.AGENT_SHELL_GUARD_REVIEW_DEPTH;
  process.env.AGENT_SHELL_GUARD_REVIEW_DEPTH = '1';
  try {
    for (const adapt of [adaptClaude, adaptCodex, adaptKimi]) {
      assert.equal(permission(adapt(event('git status'), BASE_CONFIG)), 'deny');
    }
  } finally {
    if (previous === undefined) delete process.env.AGENT_SHELL_GUARD_REVIEW_DEPTH;
    else process.env.AGENT_SHELL_GUARD_REVIEW_DEPTH = previous;
  }
});
