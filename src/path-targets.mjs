// @ts-check
// Lexical path resolution for delete/move targets. Nothing here touches the
// filesystem: a PreToolUse hook only sees the command text and the hook's
// `cwd`, so symlinks are out of reach and every approximation errs towards
// treating more paths as protected.

import { homedir } from 'node:os';

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
  return ancestor === path || ancestor === '/' || path.startsWith(`${ancestor}/`);
}

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
 * would make it land on (or above) the protected path.
 * @param {ResolvedTarget} target @param {string} protectedPath @param {{ancestors: boolean}} options
 */
export function targetCovers(target, protectedPath, options) {
  const root = normalizePath(expandHome(protectedPath));
  if (target.kind === 'absolute') {
    return options.ancestors ? isAncestorOrSelf(target.path, root) : target.path === root;
  }
  if (target.segments.length === 0) return true;
  const rootSegments = segmentsOf(root);
  const size = target.segments.length;
  for (let index = 0; index + size <= rootSegments.length; index++) {
    if (!target.segments.every((segment, offset) => rootSegments[index + offset] === segment)) continue;
    if (options.ancestors || index + size === rootSegments.length) return true;
  }
  return false;
}

/** @param {string} pattern @param {string} name */
function segmentMatches(pattern, name) {
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
  try { return new RegExp(`^${source}$`).test(name); } catch { return true; }
}

/** @param {string} text */
function firstGlobIndex(text) {
  for (let index = 0; index < text.length; index++) {
    if (text[index] === '\\') { index++; continue; }
    if (text[index] === '*' || text[index] === '?' || text[index] === '[') return index;
  }
  return -1;
}

/**
 * Split an unresolved (null) argv word by its source text. Returns null when
 * the word is dynamic for reasons other than a glob (variables, command
 * substitution), in which case nothing about its target is known.
 * @param {string} display @param {string|null} cwd
 * @returns {{prefix: ResolvedTarget, pattern: string[]}|null}
 */
export function parseGlobTarget(display, cwd) {
  if (/[`$]|<\(|>\(/.test(display)) return null;
  const text = expandHome(display.replace(/["']/g, ''));
  const glob = firstGlobIndex(text);
  if (glob < 0) return null;
  const slash = text.lastIndexOf('/', glob);
  const prefixText = slash < 0 ? '.' : slash === 0 ? '/' : text.slice(0, slash);
  const pattern = text.slice(slash + 1).split('/').filter((segment) => segment !== '' && segment !== '.');
  return { prefix: resolveTarget(prefixText.replace(/\\(.)/g, '$1'), cwd), pattern };
}

/**
 * Could a recursive delete of a glob reach `protectedPath` (or an ancestor of
 * it)? `rm -rf ~/*` covers home itself; `rm -rf ~/Codebase/*` covers
 * `~/Codebase/personal`; `rm -rf ~/Codebase/*\/node_modules` does not.
 * @param {{prefix: ResolvedTarget, pattern: string[]}} glob @param {string} protectedPath
 */
export function globCovers(glob, protectedPath) {
  const root = normalizePath(expandHome(protectedPath));
  const rootSegments = segmentsOf(root);
  if (glob.pattern.includes('..')) return true;
  /** @param {string[]} below */
  const patternReaches = (below) => {
    if (below.length === 0) return true;
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
  if (segments.length === 0) return true;
  for (let index = 0; index + segments.length <= rootSegments.length; index++) {
    if (!segments.every((segment, offset) => rootSegments[index + offset] === segment)) continue;
    if (patternReaches(rootSegments.slice(index + segments.length))) return true;
  }
  return false;
}

/** @param {ResolvedTarget} target */
export function lastSegment(target) {
  if (target.kind === 'absolute') return target.path.split('/').pop() ?? '';
  return target.segments[target.segments.length - 1] ?? '';
}
