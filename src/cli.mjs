#!/usr/bin/env node
// @ts-check

import { adaptClaude } from './adapters/claude.mjs';
import { adaptCodex } from './adapters/codex.mjs';
import { adaptGrok, grokDenyOutput } from './adapters/grok.mjs';
import { adaptKimi } from './adapters/kimi.mjs';
import { hookOutput } from './adapters/common.mjs';
import { LAUNCHER_PATH, loadConfig, MANAGED_SHFMT_PATH } from './config.mjs';
import { HookInputError, readJsonFromStdin, writeJson } from './io.mjs';
import {
  configSnippet,
  ensureDefaultConfig,
  installManagedShfmt,
  installLauncher,
  nativeRulesSnippet,
  verifyManagedShfmt,
} from './setup.mjs';

const [, , subcommand, argument] = process.argv;

if (subcommand === 'hook' && ['claude', 'codex', 'grok', 'kimi'].includes(argument ?? '')) {
  /** @type {Record<string, unknown>|null} */
  let event = null;
  try {
    event = await readJsonFromStdin();
  } catch (error) {
    const code = error instanceof HookInputError ? error.code : 'input-invalid';
    const reason = `hook 输入无效（${code}）；无法建立可靠的安全判定，已按 fail-closed 拒绝。`;
    writeJson(argument === 'grok' ? grokDenyOutput(reason) : hookOutput('deny', reason));
  }
  if (event) {
    const config = loadConfig();
    const output = argument === 'claude'
      ? adaptClaude(event, config)
      : argument === 'codex'
        ? adaptCodex(event, config)
        : argument === 'grok'
          ? adaptGrok(event, config)
          : adaptKimi(event, config);
    if (output) writeJson(output);
  }
} else if (subcommand === 'setup') {
  const installed = await installManagedShfmt();
  const launcher = installLauncher();
  const config = ensureDefaultConfig();
  process.stdout.write(`shfmt installed: ${installed}\n`);
  process.stdout.write(`launcher installed: ${launcher}\n`);
  process.stdout.write(`config ${config.created ? 'created' : 'kept'}: ${config.path}\n`);
} else if (subcommand === 'doctor') {
  const result = verifyManagedShfmt();
  if (result.ok) {
    process.stdout.write(`ok: shfmt v3.13.1 verified at ${result.path}\n`);
  } else {
    process.stderr.write(`error: ${result.reason}\nrun: agent-shell-guard setup\n`);
    process.exitCode = 1;
  }
} else if (subcommand === 'print-config' && ['claude', 'codex', 'grok', 'kimi'].includes(argument ?? '')) {
  process.stdout.write(`${configSnippet(/** @type {'claude'|'codex'|'grok'|'kimi'} */ (argument))}\n`);
} else if (subcommand === 'print-native-rules' && ['codex', 'grok', 'kimi'].includes(argument ?? '')) {
  process.stdout.write(`${nativeRulesSnippet(/** @type {'codex'|'grok'|'kimi'} */ (argument))}\n`);
} else {
  process.stderr.write(
    'usage:\n' +
    '  agent-shell-guard hook <claude|codex|grok|kimi>\n' +
    '  agent-shell-guard setup\n' +
    '  agent-shell-guard doctor\n' +
    '  agent-shell-guard print-config <claude|codex|grok|kimi>\n' +
    '  agent-shell-guard print-native-rules <codex|grok|kimi>\n' +
    `managed shfmt: ${MANAGED_SHFMT_PATH}\n` +
    `launcher: ${LAUNCHER_PATH}\n`,
  );
  process.exitCode = 2;
}
