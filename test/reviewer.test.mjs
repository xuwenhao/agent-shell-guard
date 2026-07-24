// @ts-check

import assert from 'node:assert/strict';
import test from 'node:test';

import { buildReviewerPrompt } from '../src/reviewer.mjs';

test('redacts secrets from every reviewer payload representation', () => {
  const secrets = [
    'opaque-header-secret',
    'opaque-api-key-secret',
    'opaque-env-secret',
    'opaque-operation-secret',
  ];
  const prompt = buildReviewerPrompt({
    ruleId: 'fixture',
    evaluation: 'matched',
    detail: 'operation --token opaque-operation-secret',
    why: 'fixture policy',
    command: 'curl -H "Authorization: Bearer opaque-header-secret" --api-key opaque-api-key-secret TOKEN=opaque-env-secret',
    analysis: {
      commands: [{
        argv: [
          'curl',
          '-H',
          'Authorization: Bearer opaque-header-secret',
          '--api-key',
          'opaque-api-key-secret',
          'TOKEN=opaque-env-secret',
        ],
        dialect: 'bash',
        source: 'top-level',
        wrappers: [],
        hasRedirection: false,
        pipelineGroup: null,
      }],
    },
  });
  for (const secret of secrets) assert.doesNotMatch(prompt, new RegExp(secret));

  const payload = JSON.parse(prompt.split('\n').at(-1) ?? '{}');
  assert.deepEqual(payload.commands[0].argv, [
    'curl',
    '-H',
    'Authorization: Bearer <redacted>',
    '--api-key',
    '<redacted-secret>',
    'TOKEN=<redacted-secret>',
  ]);
});

test('clears sensitive-value state after a dynamic argv element', () => {
  const prompt = buildReviewerPrompt({
    ruleId: 'fixture',
    evaluation: 'matched',
    detail: 'dynamic token fixture',
    why: 'fixture policy',
    command: 'curl --token "$TOKEN" https://api.example.com',
    analysis: {
      commands: [{
        argv: ['curl', '--token', null, 'https://api.example.com'],
        dialect: 'bash',
        source: 'top-level',
        wrappers: [],
        hasRedirection: false,
        pipelineGroup: null,
      }],
    },
  });
  const payload = JSON.parse(prompt.split('\n').at(-1) ?? '{}');
  assert.deepEqual(payload.commands[0].argv, [
    'curl',
    '--token',
    null,
    'https://api.example.com',
  ]);
});
