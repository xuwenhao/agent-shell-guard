// @ts-check
// Lexical path resolution for delete/move targets. Nothing here touches the
// filesystem: a PreToolUse hook only sees the command text and the hook's
// `cwd`, so symlinks are out of reach and every approximation errs towards
// treating more paths as protected.

import { homedir } from 'node:os';

// macOS volumes are case-insensitive by default: `rm -rf ~/codebase/Personal`
// removes `~/Codebase/personal`. Comparisons fold case there. Tests flip it
// with setCaseInsensitivePaths().
let caseInsensitive = process.platform === 'darwin';

/**
 * @param {boolean} value
 * @returns {boolean} the previous setting
 */
export function setCaseInsensitivePaths(value) {
  const previous = caseInsensitive;
  caseInsensitive = value;
  return previous;
}

export const pathsCaseInsensitive = () => caseInsensitive;

/**
 * APFS compares names after Unicode normalization and case folding, so
 * `perſonal` (long s) and `PERSONAL` both reach `personal`. Upper- then
 * lower-casing approximates full case folding (`ſ` → `S` → `s`).
 * @param {string} value
 */
export const foldCase = (value) => caseInsensitive ? value.normalize('NFC').toUpperCase().toLowerCase() : value;

/** @param {string} a @param {string} b */
const sameName = (a, b) => foldCase(a) === foldCase(b);

/**
 * Marker the analyzer substitutes for an expansion inside a double-quoted
 * `bash -c` / `eval` script, so the script can be parsed again for its
 * structure. A word containing it is as dynamic as a `$VAR`.
 */
export const DYNAMIC_MARKER = '__agent_shell_guard_dynamic__';

/**
 * Collapse `.` and `..` and trailing slashes / `*` suffixes, so
 * `rm -rf /tmp/../root` is judged as `/root`.
 * @param {string} value
 */
export function normalizePath(value) {
  const trimmed = value.replace(/\/\*{1,2}$/, '').replace(/\/+$/, '') || (value.startsWith('/') ? '/' : '.');
  const absolute = trimmed.startsWith('/');
  /** @type {string[]} */
  const stack = [];
  for (const segment of trimmed.split('/')) {
    if (segment === '' || segment === '.') continue;
    if (segment === '..') {
      if (stack.length && stack[stack.length - 1] !== '..') stack.pop();
      else if (!absolute) stack.push('..');
      continue;
    }
    stack.push(segment);
  }
  return absolute ? `/${stack.join('/')}`.replace(/\/$/, '') || '/' : stack.join('/') || '.';
}

/** @param {string} value */
export function expandHome(value) {
  if (value === '~') return homedir();
  if (value.startsWith('~/')) return `${homedir()}${value.slice(1)}`;
  return value;
}

/** @param {string} path */
const segmentsOf = (path) => path === '/' ? [] : path.slice(1).split('/');

/**
 * `ancestor` equals `path` or contains it.
 * @param {string} ancestor @param {string} path
 */
export function isAncestorOrSelf(ancestor, path) {
  const a = foldCase(ancestor);
  const p = foldCase(path);
  return a === p || a === '/' || p.startsWith(`${a}/`);
}

/**
 * Names that are too common to mean a specific protected root when the
 * directory they are relative to is unknown. `cd "$X" && rm -rf data` says
 * nothing about which `data` it is; `rm -rf dotfiles` does.
 */
export const COMMON_TARGET_NAMES = new Set([
  'data', 'build', 'dist', 'out', 'output', 'tmp', 'temp', 'cache', '.cache', 'node_modules', 'src', 'lib',
  'bin', 'target', 'vendor', 'log', 'logs', 'test', 'tests', 'doc', 'docs', 'coverage', 'public', 'assets',
  'media', 'config', 'scripts', 'archive', 'backup', 'old', 'new', 'work', 'files', 'example', 'examples',
  'pkg', 'packages', 'app', 'apps', 'web', 'site', 'static', 'infra', 'deploy', '.venv', 'venv', 'env',
]);

/**
 * @typedef {{kind: 'absolute', path: string}
 *   | {kind: 'relative', segments: string[]}} ResolvedTarget
 */

/**
 * Resolve a static target. With a trusted absolute cwd a relative target is
 * joined literally; without one it stays relative and the caller must assume
 * it can sit under any directory. Leading `..` segments of an unanchored
 * relative path carry no information and are dropped.
 * @param {string} value @param {string|null} cwd
 * @returns {ResolvedTarget}
 */
export function resolveTarget(value, cwd) {
  const expanded = expandHome(value);
  if (expanded.startsWith('/')) return { kind: 'absolute', path: normalizePath(expanded) };
  if (cwd) return { kind: 'absolute', path: normalizePath(`${cwd}/${expanded}`) };
  const normalized = normalizePath(expanded);
  const segments = normalized === '.' ? [] : normalized.split('/');
  let up = 0;
  while (segments[up] === '..') up++;
  return { kind: 'relative', segments: segments.slice(up) };
}

/**
 * Could acting on `target` hit `protectedPath`? With `ancestors` a target that
 * contains the protected path also counts (a recursive delete of a parent
 * destroys the child). A relative target with an unknown cwd matches when its
 * segments occur contiguously inside the protected path, i.e. when some cwd
 * would make it land on (or above) the protected path — except a single
 * common name (`data`, `build`), which identifies nothing without a cwd.
 * @param {ResolvedTarget} target @param {string} protectedPath @param {{ancestors: boolean}} options
 */
export function targetCovers(target, protectedPath, options) {
  const root = normalizePath(expandHome(protectedPath));
  if (target.kind === 'absolute') {
    return options.ancestors ? isAncestorOrSelf(target.path, root) : sameName(target.path, root);
  }
  if (target.segments.length === 0) return true;
  if (target.segments.length === 1 && COMMON_TARGET_NAMES.has(foldCase(target.segments[0]))) return false;
  const rootSegments = segmentsOf(root);
  const size = target.segments.length;
  for (let index = 0; index + size <= rootSegments.length; index++) {
    if (!target.segments.every((segment, offset) => sameName(rootSegments[index + offset], segment))) continue;
    if (options.ancestors || index + size === rootSegments.length) return true;
  }
  return false;
}

/**
 * Shell glob match of one path segment. By default a leading `.` must be
 * matched literally, as in bash and zsh without dotglob; `find -name` matches
 * dot entries with `*` and passes `{dotRule: false}`.
 * @param {string} pattern @param {string} name @param {{dotRule?: boolean}} [options]
 */
export function segmentMatches(pattern, name, options = {}) {
  if ((options.dotRule ?? true) && name.startsWith('.') && !pattern.startsWith('.') && !pattern.startsWith('\\.')) return false;
  let source = '';
  for (let index = 0; index < pattern.length; index++) {
    const char = pattern[index];
    if (char === '\\' && index + 1 < pattern.length) { source += pattern[++index].replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); continue; }
    if (char === '*') { source += '.*'; continue; }
    if (char === '?') { source += '.'; continue; }
    if (char === '[') {
      const close = pattern.indexOf(']', index + 2);
      if (close > index) {
        const body = pattern.slice(index + 1, close).replace(/^!/, '^').replace(/\\/g, '\\\\');
        source += `[${body}]`;
        index = close;
        continue;
      }
    }
    source += char.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }
  try { return new RegExp(`^${source}$`, caseInsensitive ? 'i' : '').test(name); } catch { return true; }
}

/** @param {string} text */
export function firstGlobIndex(text) {
  for (let index = 0; index < text.length; index++) {
    if (text[index] === '\\') { index++; continue; }
    if (text[index] === '*' || text[index] === '?' || text[index] === '[') return index;
  }
  return -1;
}

/**
 * Patterns that match every entry of a directory (or every non-dot entry), so
 * a recursive delete of `<root>/<pattern>` empties the root itself.
 * @param {string} segment
 */
export function isFullMatchPattern(segment) {
  if (/^\*+$/.test(segment) || /^\?\*+$/.test(segment) || /^\*+\?$/.test(segment) ||
    ['.*', '.[!.]*', '.[^.]*', '..?*', '.??*', '[!.]*', '[^.]*'].includes(segment)) return true;
  // A pattern without a single literal character (`[[:alnum:]]*`, `?*?`,
  // `[!~]*`) is judged as matching everything: deciding which names a class
  // admits is beyond a lexical check.
  return segment.includes('*') && withoutClassesAndWildcards(segment) === '';
}

/**
 * Remove `*`, `?` and bracket expressions that are not plain character lists
 * (POSIX classes, negations, ranges). What remains are literal characters.
 * @param {string} segment
 */
function withoutClassesAndWildcards(segment) {
  let rest = '';
  for (let index = 0; index < segment.length; index++) {
    const char = segment[index];
    if (char === '*' || char === '?') continue;
    if (char === '[') {
      let close = segment.indexOf(']', index + 2);
      if (segment.startsWith('[[:', index)) close = segment.indexOf(':]]', index) + 2;
      if (close > index) {
        const body = segment.slice(index + 1, close);
        if (/^[!^]/.test(body) || body.includes('-') || body.startsWith('[:')) { index = close; continue; }
      }
    }
    rest += char;
  }
  return rest;
}

/**
 * @typedef {{prefix: ResolvedTarget, pattern: string[]}} GlobTarget
 */

/**
 * Split a glob word (quotes already removed) at its first glob character.
 * @param {string} text @param {string|null} cwd
 * @returns {GlobTarget|null}
 */
function splitGlob(text, cwd) {
  const glob = firstGlobIndex(text);
  if (glob < 0) return null;
  const slash = text.lastIndexOf('/', glob);
  const prefixText = slash < 0 ? '.' : slash === 0 ? '/' : text.slice(0, slash);
  const pattern = text.slice(slash + 1).split('/').filter((segment) => segment !== '' && segment !== '.');
  return { prefix: resolveTarget(prefixText.replace(/\\(.)/g, '$1'), cwd), pattern };
}

/** @param {string} display */
export const isDynamicDisplay = (display) => /[`$]|<\(|>\(/.test(display) || display.includes(DYNAMIC_MARKER);

/**
 * Split an unresolved (null) argv word by its source text. Returns null when
 * the word is dynamic for reasons other than a glob or brace expansion
 * (variables, command substitution), in which case nothing about its target is
 * known.
 * @param {string} display @param {string|null} cwd
 * @returns {GlobTarget|null}
 */
export function parseGlobTarget(display, cwd) {
  if (isDynamicDisplay(display)) return null;
  return splitGlob(expandHome(display.replace(/["']/g, '')), cwd);
}

const BRACE_LIMIT = 64;

/**
 * Bash/zsh brace expansion of an unquoted word: `a{b,c}` → `ab ac`,
 * `x{1..3}` → `x1 x2 x3`. `{}` and `{a}` stay literal. Returns null when the
 * expansion would exceed BRACE_LIMIT words.
 * @param {string} text
 * @returns {string[]|null}
 */
export function expandBraces(text) {
  /** @type {string[]} */
  const done = [];
  const queue = [text];
  while (queue.length) {
    const word = /** @type {string} */ (queue.shift());
    const brace = findBrace(word);
    if (!brace) { done.push(word); if (done.length > BRACE_LIMIT) return null; continue; }
    const head = word.slice(0, brace.start);
    const tail = word.slice(brace.end + 1);
    for (const alternative of brace.alternatives) queue.push(`${head}${alternative}${tail}`);
    if (queue.length + done.length > BRACE_LIMIT) return null;
  }
  return done;
}

/**
 * First expandable `{…}` in a word, with its alternatives.
 * @param {string} word
 * @returns {{start: number, end: number, alternatives: string[]}|null}
 */
function findBrace(word) {
  for (let start = 0; start < word.length; start++) {
    if (word[start] === '\\') { start++; continue; }
    if (word[start] !== '{') continue;
    let depth = 0;
    /** @type {number[]} */
    const commas = [];
    let end = -1;
    for (let cursor = start; cursor < word.length; cursor++) {
      const char = word[cursor];
      if (char === '\\') { cursor++; continue; }
      if (char === '{') depth++;
      else if (char === '}') { depth--; if (depth === 0) { end = cursor; break; } }
      else if (char === ',' && depth === 1) commas.push(cursor);
    }
    if (end < 0) return null;
    const body = word.slice(start + 1, end);
    if (commas.length) {
      /** @type {string[]} */
      const alternatives = [];
      let from = start + 1;
      for (const comma of [...commas, end]) { alternatives.push(word.slice(from, comma)); from = comma + 1; }
      return { start, end, alternatives };
    }
    const sequence = sequenceAlternatives(body);
    if (sequence) return { start, end, alternatives: sequence };
  }
  return null;
}

/** @param {string} body @returns {string[]|null} */
function sequenceAlternatives(body) {
  const numeric = /^(-?\d+)\.\.(-?\d+)(?:\.\.(-?\d+))?$/.exec(body);
  if (numeric) {
    const from = Number(numeric[1]);
    const to = Number(numeric[2]);
    const step = Math.abs(Number(numeric[3] ?? 1)) || 1;
    const count = Math.floor(Math.abs(to - from) / step) + 1;
    if (count > BRACE_LIMIT) return Array.from({ length: BRACE_LIMIT + 1 }, () => '');
    return Array.from({ length: count }, (_, index) => String(from + Math.sign(to - from) * step * index));
  }
  const letters = /^([A-Za-z])\.\.([A-Za-z])$/.exec(body);
  if (letters) {
    const from = letters[1].charCodeAt(0);
    const to = letters[2].charCodeAt(0);
    const direction = Math.sign(to - from) || 1;
    return Array.from({ length: Math.abs(to - from) + 1 }, (_, index) => String.fromCharCode(from + direction * index));
  }
  return null;
}

/**
 * @typedef {{kind: 'static', target: ResolvedTarget}|{kind: 'glob', glob: GlobTarget}} TargetCandidate
 */

/**
 * Candidates for an unresolved (null) argv word: brace alternatives, each a
 * static path or a glob. `null` means the word is genuinely dynamic
 * (variables, substitutions). `overflow` is the resolved literal prefix of a
 * word whose brace expansion was too large to enumerate; `climbs` says a `..`
 * segment follows the brace, so that prefix bounds nothing.
 * @param {string} display @param {string|null} cwd
 * @returns {{candidates: TargetCandidate[]}|{overflow: ResolvedTarget, climbs: boolean}|null}
 */
export function expandTargetWord(display, cwd) {
  if (isDynamicDisplay(display)) return null;
  const text = display.replace(/["']/g, '');
  const words = expandBraces(text);
  if (words === null) {
    const brace = text.indexOf('{');
    const head = text.slice(0, brace);
    const slash = head.lastIndexOf('/');
    const prefix = slash < 0 ? '.' : slash === 0 ? '/' : head.slice(0, slash);
    const climbs = text.slice(brace).split('/').includes('..');
    return { overflow: resolveTarget(prefix, cwd), climbs };
  }
  return {
    candidates: words.map((word) => {
      const expanded = expandHome(word);
      const glob = splitGlob(expanded, cwd);
      return glob
        ? /** @type {TargetCandidate} */ ({ kind: 'glob', glob })
        : /** @type {TargetCandidate} */ ({ kind: 'static', target: resolveTarget(word.replace(/\\(.)/g, '$1'), cwd) });
    }),
  };
}

/**
 * Could a recursive delete of a glob reach `protectedPath` (or an ancestor of
 * it)? `rm -rf ~/*` covers home itself; `rm -rf ~/Codebase/*` covers
 * `~/Codebase/personal`; `rm -rf ~/Codebase/*\/node_modules` does not. When the
 * glob's directory is the protected root itself, only a pattern that matches
 * every entry (`*`, `.*`, `.[!.]*`) empties it; `tmp-*` or `*.egg-info` do not.
 * @param {GlobTarget} glob @param {string} protectedPath
 */
export function globCovers(glob, protectedPath) {
  const root = normalizePath(expandHome(protectedPath));
  const rootSegments = segmentsOf(root);
  if (glob.pattern.includes('..')) return true;
  /** @param {string[]} below */
  const patternReaches = (below) => {
    if (below.length === 0) return glob.pattern.length === 1 && isFullMatchPattern(glob.pattern[0]);
    if (glob.pattern.includes('**')) return true;
    if (below.length < glob.pattern.length) return false;
    return glob.pattern.every((segment, index) => segmentMatches(segment, below[index]));
  };
  if (glob.prefix.kind === 'absolute') {
    const prefix = glob.prefix.path;
    if (!isAncestorOrSelf(prefix, root)) return false;
    return patternReaches(rootSegments.slice(segmentsOf(prefix).length));
  }
  const segments = glob.prefix.segments;
  if (segments.length === 1 && COMMON_TARGET_NAMES.has(foldCase(segments[0]))) return false;
  for (let index = 0; index + segments.length <= rootSegments.length; index++) {
    if (!segments.every((segment, offset) => sameName(rootSegments[index + offset], segment))) continue;
    if (patternReaches(rootSegments.slice(index + segments.length))) return true;
  }
  return false;
}

/** @param {ResolvedTarget} target */
export function lastSegment(target) {
  if (target.kind === 'absolute') return target.path.split('/').pop() ?? '';
  return target.segments[target.segments.length - 1] ?? '';
}

/** @param {ResolvedTarget} target */
export function targetSegments(target) {
  return target.kind === 'absolute' ? segmentsOf(target.path) : target.segments;
}
