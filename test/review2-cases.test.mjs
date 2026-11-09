// @ts-check
// Every probe case of the second independent review (fixtures/review2-cases.jsonl),
// replayed through the library with its reviewed outcome. Commands are data
// handed to evaluateHookEvent; nothing is executed. `{HOME}` is the real home
// directory (the protected roots sit under it, as in the review), `{FX}` a
// temporary directory holding the small repositories the HEAD/thin-root cases
// need. Regenerate the `expect` column with UPDATE_REVIEW2_CASES=1 after a
// deliberate behaviour change, and review the diff.

import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';

import { isCodexNativePromptCovered } from '../src/adapters/codex-native.mjs';
import { isGrokNativePromptCovered } from '../src/adapters/grok-native.mjs';
import { isKimiNativePromptCovered } from '../src/adapters/kimi-native.mjs';
import { resolveShfmtPath } from '../src/config.mjs';
import { evaluateHookEvent } from '../src/guard-core.mjs';
import { inspectDirectory } from '../src/project.mjs';

const CASES_FILE = new URL('./fixtures/review2-cases.jsonl', import.meta.url);
const SHFMT = resolveShfmtPath();
const HOME = homedir();
const FX = mkdtempSync(join(tmpdir(), 'guard-review2-fx-'));
after(() => rmSync(FX, { recursive: true, force: true }));

/** @param {string} path @param {string} content */
function put(path, content) {
  mkdirSync(join(path, '..'), { recursive: true });
  writeFileSync(path, content);
}
/** @param {string} name @param {string} head @param {string} [config] */
function repo(name, head, config = '[core]\n') {
  put(join(FX, name, '.git', 'HEAD'), head);
  put(join(FX, name, '.git', 'config'), config);
}
repo('base', 'ref: refs/heads/feat\n');
repo('onmain', 'ref: refs/heads/main\n');
mkdirSync(join(FX, 'onmain', 'sub'), { recursive: true });
repo('det', `${'8'.repeat(40)}\n`);
repo('sym', 'ref: refs/heads/alias\n');
put(join(FX, 'sym', '.git', 'refs', 'heads', 'alias'), 'ref: refs/heads/main\n');
repo('packed', 'ref: refs/heads/main\n');
put(join(FX, 'packed', '.git', 'packed-refs'), `${'8'.repeat(40)} refs/heads/main\n`);
repo('rt', 'ref: refs/heads/.invalid\n', '[extensions]\n\trefstorage = reftable\n[core]\n\trepositoryformatversion = 1\n');
repo('cmt', 'ref: refs/heads/feat\n', '[core]\n[branch "feat"]\n\tremote = origin\n\tmerge = refs/heads/main ; trunk\n');
repo('thin', 'ref: refs/heads/main\n');
repo(join('thin', 'member'), 'ref: refs/heads/main\n');
mkdirSync(join(FX, 'thin', 'docs'), { recursive: true });
// A linked worktree of base, checked out on main.
put(join(FX, 'base', '.git', 'worktrees', 'wt-main', 'HEAD'), 'ref: refs/heads/main\n');
put(join(FX, 'base', '.git', 'worktrees', 'wt-main', 'commondir'), '../..\n');
put(join(FX, 'wt-main', '.git'), `gitdir: ${join(FX, 'base', '.git', 'worktrees', 'wt-main')}\n`);

const C = `${HOME}/Codebase`;
const DEVINFRA = `${C}/personal/devinfra`;
const PROTECTED_ROOTS = ['/', HOME, C, `${C}/personal`, `${C}/srpone`, `${C}/opensource`, `${C}/shoppal`,
  DEVINFRA, `${DEVINFRA}/dotfiles`, `${DEVINFRA}/.worktrees`, `${DEVINFRA}/data`, `${DEVINFRA}/infra`];
const PROTECTED_PATHS = [`${C}/personal/podcast-production`];

/** @param {string|undefined} value @returns {string|undefined} */
const expand = (value) => typeof value === 'string' ? value.replaceAll('{FX}', FX).replaceAll('{HOME}', HOME) : value;

/**
 * Outside {FX} nothing on disk is consulted: the review's `fake` project
 * info when given, otherwise a repository rooted at the directory, with the
 * devinfra thin root (and anything under it) holding member repositories.
 * @param {any} c
 */
function inspectorFor(c) {
  return (/** @type {string} */ directory) => {
    if (directory === FX || directory.startsWith(`${FX}/`)) return inspectDirectory(directory, { ephemeralRoots: [] });
    const underThin = directory === DEVINFRA || directory.startsWith(`${DEVINFRA}/`);
    const gitRoot = underThin ? DEVINFRA : directory;
    return {
      gitRoot, projectRoot: gitRoot,
      sandboxConfigured: c.fake?.configured ?? false,
      nestedRepos: c.fake?.nested ?? underThin,
      branch: c.fake?.branch ?? null,
      upstream: c.fake?.upstream ? { remote: 'origin', merge: c.fake.upstream } : null,
    };
  };
}

/** @param {any} c */
function run(c) {
  const host = c.host ?? 'claude';
  const cwd = c.cwd === null ? undefined : String(expand(c.cwd ?? DEVINFRA)).replace(/^~/, HOME);
  const command = /** @type {string} */ (expand(c.cmd));
  const event = {
    tool_name: c.tool ?? (host === 'claude' ? 'Bash' : 'shell'),
    tool_input: { command, ...(c.dds ? { dangerouslyDisableSandbox: true } : {}) },
    ...(cwd ? { cwd } : {}),
    ...(c.mode ? { permission_mode: c.mode } : {}),
  };
  const inspect = inspectorFor(c);
  const result = /** @type {any} */ (evaluateHookEvent(event, {
    profile: c.profile ?? 'dangerous-only',
    shfmtPath: SHFMT,
    envShell: '/bin/bash',
    protectedRoots: PROTECTED_ROOTS,
    protectedPaths: PROTECTED_PATHS,
    inspectDirectory: inspect,
    inspectProjectDir: inspect,
    projectDir: expand(c.projectDir),
    host,
    caseInsensitivePaths: true,
  }));
  if (result === null) return 'null';
  if (result.kind === 'allow') return 'allow';
  let out = `${result.kind}:${result.ruleId}${result.evaluation === 'unknown' ? '?' : ''}`;
  if (host !== 'claude' && result.kind === 'confirm') {
    const covered = host === 'codex' ? isCodexNativePromptCovered(result.ruleId, result.analysis)
      : host === 'grok' ? isGrokNativePromptCovered(result.ruleId, result.analysis, command)
        : isKimiNativePromptCovered(result.ruleId, result.analysis, command);
    out += covered ? ' =>native' : ' =>deny';
  }
  return out;
}

const lines = readFileSync(CASES_FILE, 'utf8').split('\n').filter((line) => line.trim());
const cases = lines.map((line) => JSON.parse(line));

if (process.env.UPDATE_REVIEW2_CASES === '1') {
  for (const c of cases) c.expect = run(c);
  writeFileSync(CASES_FILE, `${cases.map((c) => JSON.stringify(c)).join('\n')}\n`);
}

test('second-review probe cases keep their reviewed outcome', () => {
  /** @type {string[]} */
  const failures = [];
  for (const c of cases) {
    const actual = run(c);
    if (actual !== c.expect) failures.push(`[${c.set}] ${c.note}: expected ${c.expect}, got ${actual} — ${c.cmd}`);
  }
  assert.deepEqual(failures, []);
});
