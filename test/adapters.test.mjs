// @ts-check

import assert from 'node:assert/strict';
import { homedir } from 'node:os';
import test from 'node:test';

import { adaptClaude } from '../src/adapters/claude.mjs';
import { adaptCodex } from '../src/adapters/codex.mjs';
import { adaptGrok } from '../src/adapters/grok.mjs';
import { adaptKimi } from '../src/adapters/kimi.mjs';
import { resolveShfmtPath } from '../src/config.mjs';

const BASE_CONFIG = {
  mode: 'strict',
  profile: 'full',
  shfmtPath: resolveShfmtPath(),
  protectedRoots: ['/', homedir()],
  nativePrompt: { codex: true, grok: true, kimi: true },
  reviewer: null,
};

/** @param {string} command */
const event = (command) => ({
  hook_event_name: 'PreToolUse',
  tool_name: 'Bash',
  tool_input: { command },
});

/** @param {string} command */
const grokEvent = (command) => ({
  hookEventName: 'pre_tool_use',
  toolName: 'run_terminal_command',
  toolInput: { command },
});

/** @param {any} output */
const permission = (output) => output?.hookSpecificOutput?.permissionDecision ?? 'pass';

/** @param {any} output */
const grokPermission = (output) => output?.decision ?? 'pass';

test('Claude maps confirm to native hook ask', () => {
  assert.equal(permission(adaptClaude(event('psql -c "DROP TABLE users"'), BASE_CONFIG)), 'ask');
});

test('Codex delegates exact native prefixes and denies uncovered confirms in strict mode', () => {
  assert.equal(permission(adaptCodex(event('git branch -D main'), BASE_CONFIG)), 'pass');
  assert.equal(permission(adaptCodex(event('git branch -q -D old-feature'), BASE_CONFIG)), 'deny');
  assert.equal(permission(adaptCodex(event('psql -c "DROP TABLE users"'), BASE_CONFIG)), 'deny');
});

test('native delegation is disabled until the host rules are explicitly installed', () => {
  const config = {
    ...BASE_CONFIG,
    nativePrompt: { codex: false, grok: false, kimi: false },
  };
  assert.equal(permission(adaptCodex(event('git branch -D main'), config)), 'deny');
  assert.equal(grokPermission(adaptGrok(grokEvent('git branch -D main'), config)), 'deny');
  assert.equal(permission(adaptKimi(event('git branch -D main'), config)), 'deny');
});

test('Grok delegates only when normalized argv and raw ask-rule prefix both match', () => {
  assert.equal(grokPermission(adaptGrok(grokEvent('git branch -D main'), BASE_CONFIG)), 'pass');
  assert.equal(grokPermission(adaptGrok(grokEvent('git branch "-D" main'), BASE_CONFIG)), 'deny');
  assert.equal(grokPermission(adaptGrok(grokEvent('psql -c "DROP TABLE users"'), BASE_CONFIG)), 'pass');
});

test('Kimi delegates only when normalized argv and raw permission prefix both match', () => {
  assert.equal(permission(adaptKimi(event('git branch -D main'), BASE_CONFIG)), 'pass');
  assert.equal(permission(adaptKimi(event('git branch "-D" main'), BASE_CONFIG)), 'deny');
  assert.equal(permission(adaptKimi(event('psql -c "DROP TABLE users"'), BASE_CONFIG)), 'pass');
});

test('all adapters preserve hard deny', () => {
  for (const adapt of [adaptClaude, adaptCodex, adaptKimi]) {
    assert.equal(permission(adapt(event('git push origin main --force'), BASE_CONFIG)), 'deny');
  }
  assert.equal(
    grokPermission(adaptGrok(grokEvent('git push origin main --force'), BASE_CONFIG)),
    'deny',
  );
});

test('reviewer subprocesses cannot call shell tools recursively', () => {
  const previous = process.env.AGENT_SHELL_GUARD_REVIEW_DEPTH;
  process.env.AGENT_SHELL_GUARD_REVIEW_DEPTH = '1';
  try {
    for (const adapt of [adaptClaude, adaptCodex, adaptKimi]) {
      assert.equal(permission(adapt(event('git status'), BASE_CONFIG)), 'deny');
    }
    assert.equal(grokPermission(adaptGrok(grokEvent('git status'), BASE_CONFIG)), 'deny');
  } finally {
    if (previous === undefined) delete process.env.AGENT_SHELL_GUARD_REVIEW_DEPTH;
    else process.env.AGENT_SHELL_GUARD_REVIEW_DEPTH = previous;
  }
});

test('Codex native coverage never silently delegates removed broad Git prefixes', () => {
  const config = { ...BASE_CONFIG, profile: 'dangerous-only' };
  for (const command of ['git clean', 'git clean -df', 'git checkout tracked.txt',
    'git checkout --forc main', 'git checkout -b feat --force',
    'git clean --dry-run "$TARGET"', 'git clean -n --no-dry-run',
    'git checkout --detach HEAD --theirs', 'git checkout -b feat -- a.ts',
    'git checkout -b "$BRANCH"', 'git -C "$REPO" clean -n',
    'git checkout -Bfeat', 'git checkout -qB feat', 'git checkout -b feat -B other',
    'git checkout -b feat --conflict=merge', 'git checkout --detach HEAD --conflict=diff3']) {
    assert.equal(permission(adaptCodex(event(command), config)), 'deny', command);
  }
  for (const command of ['git clean -n', 'git clean --dry-run', 'git checkout -b feat',
    'git checkout --detach origin/main', 'git clean -f', 'git checkout -- tracked.txt',
    'git checkout --force main', 'git checkout -B feat']) {
    assert.equal(permission(adaptCodex(event(command), config)), 'pass', command);
  }
});

test('Codex blocked delegation exposes stable diagnostic codes and bounded recovery', () => {
  const config = { ...BASE_CONFIG, profile: 'dangerous-only' };
  for (const [command, code] of [
    ['git restore a.ts && git status', 'native-prompt-shape-unsupported'],
    ['git -C /tmp/repo restore a.ts', 'native-prompt-prefix-uncovered'],
    ['git clean -df', 'native-prompt-prefix-uncovered'],
  ]) {
    const output = adaptCodex(event(command), config);
    const reason = output?.hookSpecificOutput.permissionDecisionReason ?? '';
    assert.equal(permission(output), 'deny');
    const marker = reason.split('\n').find(line => line.startsWith('[guard-diagnostic] '));
    assert.ok(marker);
    assert.deepEqual(JSON.parse(marker.slice('[guard-diagnostic] '.length)), {
      reasonCode: code, ruleId: 'git-destructive', decisionSource: 'hook',
    });
    assert.match(reason, /workdir/);
    assert.match(reason, /require_escalated 不会解除/);
  }
  const disabled = adaptCodex(event('git restore a.ts'), { ...config, nativePrompt: { ...config.nativePrompt, codex: false } });
  assert.match(disabled?.hookSpecificOutput.permissionDecisionReason ?? '', /native-prompt-disabled/);
  const hard = adaptCodex(event('git push origin main --force'), config);
  assert.equal(permission(hard), 'deny');
  assert.doesNotMatch(hard?.hookSpecificOutput.permissionDecisionReason ?? '', /恢复：|guard-diagnostic/);
});


test('Codex-only prefix migration preserves Kimi and Grok broad native confirmations', () => {
  for (const command of ['git checkout tracked.txt', 'git clean -df', 'git checkout -Bfeat']) {
    assert.equal(permission(adaptCodex(event(command), BASE_CONFIG)), 'deny', command);
    assert.equal(permission(adaptKimi(event(command), BASE_CONFIG)), 'pass', command);
    assert.equal(grokPermission(adaptGrok(grokEvent(command), BASE_CONFIG)), 'pass', command);
  }
});
