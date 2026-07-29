// @ts-check

import { createHash } from 'node:crypto';
import {
  chmodSync,
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { CONFIG_PATH, LAUNCHER_PATH, MANAGED_SHFMT_PATH } from './config.mjs';
import { CODEX_NATIVE_PROMPT_PREFIXES } from './adapters/codex-native.mjs';
import { GROK_PERMISSION_PATTERNS } from './adapters/grok-native.mjs';
import { KIMI_PERMISSION_PATTERNS } from './adapters/kimi-native.mjs';

export const SHFMT_VERSION = '3.13.1';

/** @type {Record<string, {name: string, sha256: string}>} */
const ASSETS = {
  'darwin:x64': {
    name: `shfmt_v${SHFMT_VERSION}_darwin_amd64`,
    sha256: '6feedafc72915794163114f512348e2437d080d0047ef8b8fa2ec63b575f12af',
  },
  'darwin:arm64': {
    name: `shfmt_v${SHFMT_VERSION}_darwin_arm64`,
    sha256: '9680526be4a66ea1ffe988ed08af58e1400fe1e4f4aef5bd88b20bb9b3da33f8',
  },
  'linux:x64': {
    name: `shfmt_v${SHFMT_VERSION}_linux_amd64`,
    sha256: 'fb096c5d1ac6beabbdbaa2874d025badb03ee07929f0c9ff67563ce8c75398b1',
  },
  'linux:arm64': {
    name: `shfmt_v${SHFMT_VERSION}_linux_arm64`,
    sha256: '32d92acaa5cd8abb29fc49dac123dc412442d5713967819d8af2c29f1b3857c7',
  },
};

function currentAsset() {
  const key = `${process.platform}:${process.arch}`;
  const asset = ASSETS[key];
  if (!asset) throw new Error(`unsupported platform: ${key}`);
  return asset;
}

/** @param {Buffer} data */
const sha256 = (data) => createHash('sha256').update(data).digest('hex');

/** @param {string} path */
export function verifyManagedShfmt(path = MANAGED_SHFMT_PATH) {
  if (!existsSync(path)) return { ok: false, reason: `missing: ${path}` };
  const expected = currentAsset().sha256;
  const actual = sha256(readFileSync(path));
  return actual === expected
    ? { ok: true, path }
    : { ok: false, reason: `checksum mismatch: expected ${expected}, got ${actual}` };
}

/** @param {{destination?: string, fetchImpl?: typeof fetch}} [options] */
export async function installManagedShfmt(options = {}) {
  const destination = options.destination ?? MANAGED_SHFMT_PATH;
  const fetchImpl = options.fetchImpl ?? fetch;
  const asset = currentAsset();
  const url = `https://github.com/mvdan/sh/releases/download/v${SHFMT_VERSION}/${asset.name}`;
  const response = await fetchImpl(url, { redirect: 'follow' });
  if (!response.ok) throw new Error(`download failed: HTTP ${response.status}`);
  const data = Buffer.from(await response.arrayBuffer());
  const actual = sha256(data);
  if (actual !== asset.sha256) {
    throw new Error(`downloaded shfmt checksum mismatch: expected ${asset.sha256}, got ${actual}`);
  }
  mkdirSync(dirname(destination), { recursive: true });
  const temporary = `${destination}.tmp-${process.pid}`;
  try {
    writeFileSync(temporary, data, { mode: 0o755 });
    // Creation mode is masked by process umask; normalize the executable mode.
    chmodSync(temporary, 0o755);
    renameSync(temporary, destination);
  } finally {
    rmSync(temporary, { force: true });
  }
  return destination;
}

export function ensureDefaultConfig() {
  if (existsSync(CONFIG_PATH)) return { created: false, path: CONFIG_PATH };
  mkdirSync(dirname(CONFIG_PATH), { recursive: true });
  writeFileSync(
    CONFIG_PATH,
    `${JSON.stringify({
      mode: 'strict',
      profile: 'dangerous-only',
      nativePrompt: { codex: false, grok: false, kimi: false },
    }, null, 2)}\n`,
    { flag: 'wx' },
  );
  return { created: true, path: CONFIG_PATH };
}

/** @param {string} value */
const shellQuote = (value) => `'${value.replaceAll("'", "'\\''")}'`;

export function installLauncher() {
  const cliPath = fileURLToPath(new URL('./cli.mjs', import.meta.url));
  mkdirSync(dirname(LAUNCHER_PATH), { recursive: true });
  writeFileSync(
    LAUNCHER_PATH,
    `#!/bin/sh\nexec ${shellQuote(process.execPath)} ${shellQuote(cliPath)} "$@"\n`,
    { mode: 0o755 },
  );
  // Creation mode is masked by process umask; normalize the executable mode.
  chmodSync(LAUNCHER_PATH, 0o755);
  return LAUNCHER_PATH;
}

/** @param {'claude'|'codex'|'grok'|'kimi'} host */
export function configSnippet(host) {
  if (host === 'grok') {
    return JSON.stringify({
      hooks: {
        PreToolUse: [{
          matcher: 'run_terminal_command',
          hooks: [{
            type: 'command',
            command: '"$HOME/.local/bin/agent-shell-guard" hook grok',
            timeout: 30,
          }],
        }],
      },
    }, null, 2);
  }
  if (host === 'kimi') {
    return [
      '[[hooks]]',
      'event = "PreToolUse"',
      'matcher = "Bash"',
      'command = "\\"$HOME/.local/bin/agent-shell-guard\\" hook kimi"',
      'timeout = 30',
    ].join('\n');
  }
  if (host === 'codex') {
    return JSON.stringify({
      hooks: {
        PreToolUse: [{
          matcher: '.*',
          hooks: [{
            type: 'command',
            command: '"$HOME/.local/bin/agent-shell-guard" hook codex',
            timeout: 30,
          }],
        }],
      },
    }, null, 2);
  }
  return JSON.stringify({
    hooks: {
      PreToolUse: [{
        matcher: 'Bash',
        hooks: [{
          type: 'command',
          command: '"$HOME/.local/bin/agent-shell-guard" hook claude',
          timeout: 30,
        }],
      }],
    },
  }, null, 2);
}

/** @param {'codex'|'grok'|'kimi'} host */
export function nativeRulesSnippet(host) {
  if (host === 'grok') {
    return GROK_PERMISSION_PATTERNS.map((pattern) =>
      `[[permission.rules]]\naction = "ask"\ntool = "bash"\npattern = ${JSON.stringify(pattern)}`,
    ).join('\n\n');
  }
  if (host === 'kimi') {
    return KIMI_PERMISSION_PATTERNS.map((pattern) =>
      `[[permission.rules]]\ndecision = "ask"\npattern = ${JSON.stringify(pattern)}\nreason = "agent-shell-guard native confirmation"`,
    ).join('\n\n');
  }
  return [...CODEX_NATIVE_PROMPT_PREFIXES.values()]
    .flat()
    .map((prefix) =>
      `prefix_rule(pattern=${JSON.stringify(prefix)}, decision="prompt", ` +
      'justification="agent-shell-guard native confirmation")',
    )
    .join('\n');
}
