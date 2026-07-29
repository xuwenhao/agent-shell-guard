// @ts-check

import assert from 'node:assert/strict';
import test from 'node:test';

import { GROK_PERMISSION_PATTERNS } from '../src/adapters/grok-native.mjs';
import { KIMI_PERMISSION_PATTERNS } from '../src/adapters/kimi-native.mjs';
import { configSnippet, nativeRulesSnippet } from '../src/setup.mjs';

test('Kimi hook and native ask rules are emitted separately', () => {
  const hookSnippet = configSnippet('kimi');
  const rulesSnippet = nativeRulesSnippet('kimi');
  assert.match(hookSnippet, /\.local\/bin\/agent-shell-guard.*hook kimi/);
  assert.doesNotMatch(hookSnippet, /\[\[permission\.rules\]\]/);
  assert.ok(KIMI_PERMISSION_PATTERNS.length > 10);
  for (const pattern of KIMI_PERMISSION_PATTERNS) {
    assert.match(rulesSnippet, new RegExp(pattern.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  }
});

test('Claude, Codex, and Grok config snippets select their adapters', () => {
  assert.match(configSnippet('claude'), /\.local\/bin\/agent-shell-guard.*hook claude/);
  assert.match(configSnippet('codex'), /\.local\/bin\/agent-shell-guard.*hook codex/);
  const grok = JSON.parse(configSnippet('grok'));
  assert.equal(grok.hooks.PreToolUse[0].matcher, 'run_terminal_command');
  assert.match(grok.hooks.PreToolUse[0].hooks[0].command, /agent-shell-guard.*hook grok/);
});

test('Codex native rules are generated from the adapter policy', () => {
  const snippet = nativeRulesSnippet('codex');
  assert.match(snippet, /pattern=\["gh","repo","delete"\]/);
  assert.match(snippet, /decision="prompt"/);
});

test('Grok native ask rules are generated from the adapter policy', () => {
  const snippet = nativeRulesSnippet('grok');
  assert.match(snippet, /^\[\[permission\.rules\]\]\naction = "ask"\ntool = "bash"/);
  assert.ok(GROK_PERMISSION_PATTERNS.length > 10);
  assert.ok(GROK_PERMISSION_PATTERNS.includes('git reset'));
  assert.ok(GROK_PERMISSION_PATTERNS.includes('git reset *'));
  assert.ok(!GROK_PERMISSION_PATTERNS.includes('git reset*'));
  for (const pattern of GROK_PERMISSION_PATTERNS) {
    assert.match(snippet, new RegExp(pattern.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  }
});
