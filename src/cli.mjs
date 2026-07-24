#!/usr/bin/env node
// @ts-check

import { adaptClaude } from './adapters/claude.mjs';
import { adaptCodex } from './adapters/codex.mjs';
import { adaptKimi } from './adapters/kimi.mjs';
import { LAUNCHER_PATH, loadConfig, MANAGED_SHFMT_PATH } from './config.mjs';
import { readJsonFromStdin, writeJson } from './io.mjs';
import {
  configSnippet,
  ensureDefaultConfig,
  installManagedShfmt,
  installLauncher,
  nativeRulesSnippet,
  verifyManagedShfmt,
} from './setup.mjs';

const [, , subcommand, argument] = process.argv;

if (subcommand === 'hook' && ['claude', 'codex', 'kimi'].includes(argument ?? '')) {
  const event = await readJsonFromStdin();
  if (event) {
    const config = loadConfig();
    const output = argument === 'claude'
      ? adaptClaude(event, config)
      : argument === 'codex'
        ? adaptCodex(event, config)
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
} else if (subcommand === 'print-config' && ['claude', 'codex', 'kimi'].includes(argument ?? '')) {
  process.stdout.write(`${configSnippet(/** @type {'claude'|'codex'|'kimi'} */ (argument))}\n`);
} else if (subcommand === 'print-native-rules' && ['codex', 'kimi'].includes(argument ?? '')) {
  process.stdout.write(`${nativeRulesSnippet(/** @type {'codex'|'kimi'} */ (argument))}\n`);
} else {
  process.stderr.write(
    'usage:\n' +
    '  agent-shell-guard hook <claude|codex|kimi>\n' +
    '  agent-shell-guard setup\n' +
    '  agent-shell-guard doctor\n' +
    '  agent-shell-guard print-config <claude|codex|kimi>\n' +
    '  agent-shell-guard print-native-rules <codex|kimi>\n' +
    `managed shfmt: ${MANAGED_SHFMT_PATH}\n` +
    `launcher: ${LAUNCHER_PATH}\n`,
  );
  process.exitCode = 2;
}
