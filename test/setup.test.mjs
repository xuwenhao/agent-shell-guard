// @ts-check

import assert from 'node:assert/strict';
import test from 'node:test';

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

test('Claude and Codex config snippets select their adapters', () => {
  assert.match(configSnippet('claude'), /\.local\/bin\/agent-shell-guard.*hook claude/);
  assert.match(configSnippet('codex'), /\.local\/bin\/agent-shell-guard.*hook codex/);
});

test('Codex native rules are generated from the adapter policy', () => {
  const snippet = nativeRulesSnippet('codex');
  assert.match(snippet, /pattern=\["gh","repo","delete"\]/);
  assert.match(snippet, /decision="prompt"/);
});
