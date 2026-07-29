// @ts-check

import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { loadConfig } from '../src/config.mjs';

test('native prompt delegation is opt-in and config path honors the supplied environment', () => {
  const directory = mkdtempSync(join(tmpdir(), 'agent-shell-guard-config-'));
  const configPath = join(directory, 'config.json');
  writeFileSync(configPath, JSON.stringify({
    mode: 'reviewed',
    nativePrompt: { codex: true, grok: false, kimi: false },
    reviewer: { command: process.execPath, timeoutMs: 90_000 },
  }));
  try {
    const config = loadConfig({
      env: {
        AGENT_SHELL_GUARD_CONFIG: configPath,
        AGENT_SHELL_GUARD_SHFMT: '/not/installed/in-test',
        AGENT_SHELL_GUARD_NATIVE_PROMPT_GROK: 'true',
        AGENT_SHELL_GUARD_NATIVE_PROMPT_KIMI: 'yes',
        AGENT_SHELL_GUARD_PROTECTED_ROOTS: '~/Codebase,/srv/work',
        PATH: '',
      },
    });
    assert.equal(config.mode, 'reviewed');
    assert.deepEqual(config.nativePrompt, { codex: true, grok: true, kimi: true });
    assert.ok(config.protectedRoots.includes(join(homedir(), 'Codebase')));
    assert.ok(config.protectedRoots.includes('/srv/work'));
    assert.equal(config.reviewer?.timeoutMs, 20_000);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test('native prompt delegation defaults to disabled', () => {
  const config = loadConfig({
    configPath: '/definitely/missing/agent-shell-guard.json',
    env: { PATH: '' },
  });
  assert.deepEqual(config.nativePrompt, { codex: false, grok: false, kimi: false });
});
