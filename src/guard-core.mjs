// @ts-check
// Host-independent shell guard core.
//
// Shell syntax is parsed by the pinned shfmt AST analyzer. Policy rules only
// inspect normalized command argv or one already-parsed data argument; they do
// not infer quoting, command boundaries, or evaluator semantics with regex.

import { basename } from 'node:path';
import { analyzeShellInput, selectShellDialect } from './shell-analyzer.mjs';
import { isPolicyEnabled, resolvePolicyProfile } from './policies/profiles.mjs';

/** @param {string} value @param {number} [length] */
const trunc = (value, length = 160) => value.length > length ? `${value.slice(0, length)}…` : value;

/** @typedef {ReturnType<typeof analyzeShellInput>} ShellGraph */
/** @typedef {ShellGraph['commands'][number]} AnalyzedCommand */
/** @typedef {Parameters<typeof analyzeShellInput>[0]} ShellInput */
/** @typedef {(ruleId: string) => boolean} PolicyEnabled */
/** @typedef {{ruleId: string, evaluation: 'matched'|'unknown', detail: string, why: string}} PolicyMatch */

/** @param {AnalyzedCommand} command */
function effectiveDisplayArgv(command) {
  const offset = Math.max(0, command.rawArgv.length - command.argv.length);
  const raw = command.displayArgv.slice(offset);
  return command.argv.map((arg, index) => arg ?? raw[index] ?? '<?>');
}

/** @param {AnalyzedCommand} command */
const displayCommand = (command) => effectiveDisplayArgv(command).join(' ');

/** @param {AnalyzedCommand} command */
const commandName = (command) => typeof command.argv[0] === 'string' ? basename(command.argv[0]) : '';

/** @param {AnalyzedCommand} command @param {string} name */
const isCommand = (command, name) => commandName(command) === name;

/** @param {Array<string|null>} argv @param {string} flag */
function hasFlag(argv, flag) {
  return argv.some((arg) => arg === flag || (typeof arg === 'string' && arg.startsWith(`${flag}=`)));
}

/** @param {Array<string|null>} argv */
function hasRecursiveFlag(argv) {
  return argv.slice(1).some((arg) => typeof arg === 'string' && (arg === '--recursive' || /^-[^-]*[rR]/.test(arg)));
}

/** @param {AnalyzedCommand} command */
function commandTargets(command) {
  /** @type {Array<{value: string|null, display: string}>} */
  const targets = [];
  const display = effectiveDisplayArgv(command);
  let options = true;
  for (let index = 1; index < command.argv.length; index++) {
    const arg = command.argv[index];
    if (options && arg === '--') { options = false; continue; }
    if (options && typeof arg === 'string' && arg.startsWith('-')) continue;
    targets.push({ value: arg, display: arg ?? display[index] ?? '<?>' });
  }
  return targets;
}

/** @param {string} value */
function normalizeProtectedRoot(value) {
  return value.replace(/\/\*{1,2}$/, '').replace(/\/+$/, '') || '/';
}

/** @param {string} value @param {string[]} protectedRoots */
function isProtectedRoot(value, protectedRoots) {
  const normalized = normalizeProtectedRoot(value);
  return protectedRoots.some((root) => normalizeProtectedRoot(root) === normalized);
}

/** @param {string} display @param {string[]} protectedRoots */
function unknownTargetMayBeProtected(display, protectedRoots) {
  if (/[`$]|<\(|>\(/.test(display)) return true;
  let escaped = false;
  let expansion = -1;
  for (let index = 0; index < display.length; index++) {
    if (escaped) { escaped = false; continue; }
    if (display[index] === '\\') { escaped = true; continue; }
    if (display[index] === '*' || display[index] === '?' || display[index] === '[') { expansion = index; break; }
  }
  if (expansion >= 0) {
    const prefix = display.slice(0, expansion).replace(/\/+$/, '') || (display.startsWith('/') ? '/' : '.');
    return isProtectedRoot(prefix, protectedRoots);
  }
  return true;
}

/** @param {string} value */
function isProtectedRef(value) {
  const ref = value.replace(/^\+/, '');
  return /^(?:refs\/heads\/)?(?:main|master)$/.test(ref) || /:(?:refs\/heads\/)?(?:main|master)$/.test(ref);
}

/** @param {AnalyzedCommand} command */
function parseGitCommand(command) {
  if (!isCommand(command, 'git')) return null;
  const valueFlags = new Set(['-C', '-c', '--git-dir', '--work-tree', '--namespace', '--super-prefix', '--config-env']);
  let index = 1;
  for (; index < command.argv.length; index++) {
    const arg = command.argv[index];
    if (arg === '--') { index++; break; }
    if (typeof arg !== 'string') return null;
    if (!arg.startsWith('-')) break;
    if (valueFlags.has(arg)) index++;
  }
  const subcommand = command.argv[index];
  if (typeof subcommand !== 'string') return null;
  return { subcommand, args: command.argv.slice(index + 1), argOffset: index + 1 };
}

/** @param {AnalyzedCommand} command */
function hardResetOriginRef(command) {
  const git = parseGitCommand(command);
  if (git?.subcommand !== 'reset' || !hasFlag(git.args, '--hard')) return null;
  // 只对用户明确配置的 origin/<ref> 做 main/非 main 分流；其他 ref 仍按通用高风险 reset 处理。
  return git.args.find((arg) => typeof arg === 'string' && /^origin\//.test(arg)) ?? null;
}

/** @param {AnalyzedCommand} command */
function forcePush(command) {
  const git = parseGitCommand(command);
  if (git?.subcommand !== 'push') return false;
  const display = effectiveDisplayArgv(command).slice(git.argOffset);
  return git.args.some((arg, index) => {
    const token = arg ?? display[index] ?? '';
    return token === '--force' || token.startsWith('--force-with-lease') || shortOptionHas(token, /f/) || /^\+\S+/.test(token);
  });
}

/** @param {AnalyzedCommand} command */
function pushRefs(command) {
  const git = parseGitCommand(command);
  if (git?.subcommand !== 'push') return [];
  const display = effectiveDisplayArgv(command).slice(git.argOffset);
  const valueFlags = new Set(['--repo', '--receive-pack', '--exec', '--push-option']);
  /** @type {Array<{value: string|null, display: string}>} */
  const positionals = [];
  let options = true;
  for (let index = 0; index < git.args.length; index++) {
    const arg = git.args[index];
    const token = arg ?? display[index] ?? '<?>';
    if (options && token === '--') { options = false; continue; }
    if (options && token.startsWith('-')) {
      if (valueFlags.has(token)) index++;
      continue;
    }
    positionals.push({ value: arg, display: token });
  }
  return positionals.slice(1);
}

/** @param {string|null} arg @param {RegExp} letters */
function shortOptionHas(arg, letters) {
  return typeof arg === 'string' && /^-[^-]/.test(arg) && letters.test(arg.slice(1));
}

/** @param {AnalyzedCommand} command @returns {'git-destructive'|'git-low-risk'|null} */
function destructiveGitRule(command) {
  const git = parseGitCommand(command);
  if (!git) return null;
  const { subcommand, args } = git;

  if (['clean', 'reset', 'restore', 'checkout', 'rm'].includes(String(subcommand))) return 'git-destructive';
  if (subcommand === 'worktree') {
    return args[0] === 'remove' || (args[0] === 'add' && args.slice(1).some((arg) => shortOptionHas(arg, /B/)))
      ? 'git-destructive' : null;
  }
  if (subcommand === 'stash') return args[0] === 'drop' || args[0] === 'clear' ? 'git-destructive' : null;
  if (subcommand === 'config') return args.some((arg) => arg === '--global' || arg === '--system') ? 'git-destructive' : null;
  if (subcommand === 'branch') {
    const highRisk = args.some((arg) => arg === '--force' || shortOptionHas(arg, /[DfMC]/));
    if (highRisk) return 'git-destructive';
    return args.some((arg) => arg === '--delete' || shortOptionHas(arg, /d/)) ? 'git-low-risk' : null;
  }
  if (subcommand === 'tag') {
    const force = args.some((arg) => arg === '--force' || shortOptionHas(arg, /f/));
    if (force) return 'git-destructive';
    return args.some((arg) => arg === '--delete' || shortOptionHas(arg, /d/)) ? 'git-low-risk' : null;
  }
  if (subcommand === 'switch') {
    const highRisk = args.some((arg) => arg === '--discard-changes' || arg === '--force' || arg === '--force-create' ||
      shortOptionHas(arg, /[Cf]/));
    if (highRisk) return 'git-destructive';
    return args.some((arg) => shortOptionHas(arg, /d/)) ? 'git-low-risk' : null;
  }
  if (subcommand === 'submodule') {
    const action = args.find((arg) => typeof arg === 'string' && !arg.startsWith('-'));
    if (action === 'foreach') return 'git-destructive';
    return action === 'deinit' ? 'git-low-risk' : null;
  }
  if (subcommand === 'lfs') {
    const action = args.find((arg) => typeof arg === 'string' && !arg.startsWith('-'));
    return ['install', 'migrate', 'uninstall', 'prune'].includes(String(action)) ? 'git-destructive' : null;
  }
  if (subcommand === 'rebase') {
    return args.some((arg) => arg === '--exec' || (typeof arg === 'string' && arg.startsWith('--exec=')) ||
      arg === '--reschedule-failed-exec' || shortOptionHas(arg, /x/)) ? 'git-destructive' : null;
  }
  if (subcommand === 'push') {
    return args.some((arg) =>
      arg === '--delete' || arg === '--mirror' || arg === '--prune' ||
      shortOptionHas(arg, /d/) || (typeof arg === 'string' && /^\+?:\S+/.test(arg))) ? 'git-destructive' : null;
  }
  return null;
}

/** @param {AnalyzedCommand} command */
function parseSsh(command) {
  const valueFlags = new Set(['-p', '-i', '-o', '-l', '-F', '-J', '-L', '-R', '-D', '-W', '-E', '-b', '-c', '-e', '-m', '-O', '-S']);
  const display = effectiveDisplayArgv(command);
  for (let index = 1; index < command.argv.length; index++) {
    const arg = command.argv[index];
    if (typeof arg === 'string' && arg.startsWith('-')) {
      if (valueFlags.has(arg)) index++;
      continue;
    }
    return {
      host: arg ?? display[index] ?? '(未解析出主机)',
      rest: command.argv.slice(index + 1).map((value, restIndex) => value ?? display[index + 1 + restIndex] ?? '<?>').join(' '),
    };
  }
  return { host: '(未解析出主机)', rest: '' };
}

/** @param {AnalyzedCommand} command @returns {{kind: 'matched'|'unknown', endpoint: string}|null} */
function orgRulesetWrite(command) {
  if (!isCommand(command, 'gh') || command.argv[1] !== 'api') return null;
  const args = command.argv.slice(2);
  const display = effectiveDisplayArgv(command).slice(2);
  const tokens = args.map((arg, index) => arg ?? display[index] ?? '<?>');
  const endpointValueFlags = new Set(['-X', '--method', '-f', '-F', '--field', '--raw-field', '--input', '-H', '--header', '--preview', '--cache']);
  /** @type {{value: string|null, display: string}|null} */
  let endpointInfo = null;
  for (let index = 0; index < args.length; index++) {
    const token = tokens[index];
    if (token === '--') {
      index++;
      endpointInfo = index < args.length ? { value: args[index], display: tokens[index] } : null;
      break;
    }
    if (token.startsWith('-')) {
      if (endpointValueFlags.has(token)) index++;
      continue;
    }
    endpointInfo = { value: args[index], display: token };
    break;
  }
  const endpoint = typeof endpointInfo?.value === 'string' && /^\/?orgs\/[^/\s]+\/rulesets(?:\/|$)/.test(endpointInfo.value)
    ? endpointInfo.value
    : null;
  const fieldWrite = tokens.some((arg) =>
    arg === '-f' || arg === '-F' || arg === '--field' || arg.startsWith('--field=') ||
    arg === '--raw-field' || arg.startsWith('--raw-field=') || arg === '--input' || arg.startsWith('--input='));
  let method = '';
  let methodUnknown = false;
  for (let index = 0; index < args.length; index++) {
    const arg = args[index];
    const token = tokens[index];
    if (token === '-X' || token === '--method') {
      const value = args[index + 1];
      if (value === null || value === undefined) methodUnknown = true;
      else if (typeof value === 'string') method = value;
    } else if (token.startsWith('--method=') || (token.startsWith('-X') && token !== '-X')) {
      if (arg === null) methodUnknown = true;
      else method = token.startsWith('--method=') ? token.slice('--method='.length) : token.slice(2);
    }
  }
  const write = fieldWrite || /^(?:PUT|POST|PATCH|DELETE)$/i.test(method);
  const unknownEndpoint = endpointInfo?.value === null;
  if (endpoint && write) return { kind: 'matched', endpoint };
  if ((endpoint && methodUnknown) || (unknownEndpoint && (write || methodUnknown || fieldWrite))) return { kind: 'unknown', endpoint: endpoint ?? '<?>' };
  return null;
}

/** @param {ShellGraph} graph @param {PolicyEnabled} enabled @param {string[]} protectedRoots @returns {PolicyMatch|null} */
function hardPolicy(graph, enabled, protectedRoots) {
  for (const command of graph.commands) {
    const orgWrite = orgRulesetWrite(command);
    if (orgWrite && enabled('org-ruleset-write')) {
      return {
        ruleId: 'org-ruleset-write', evaluation: orgWrite.kind,
        detail: `修改 org-level ruleset（${trunc(orgWrite.endpoint)}）`,
        why: orgWrite.kind === 'unknown'
          ? 'endpoint 或写入方法无法静态还原，可能隐藏组织级 ruleset 写入；按全局约定必须拒绝。'
          : '按全局约定，组织级分支保护规则只能由人在 GitHub UI 修改，AI/CLI 一律不得写入。需要变更时把改动内容写清楚交给用户手动操作。',
      };
    }

    if (isCommand(command, 'rm') && hasRecursiveFlag(command.argv)) {
      const targets = commandTargets(command);
      const protectedTarget = targets.find((target) =>
        target.value !== null && isProtectedRoot(target.value, protectedRoots));
      const unknownTarget = targets.find((target) =>
        target.value === null && unknownTargetMayBeProtected(target.display, protectedRoots));
      if ((protectedTarget || unknownTarget) && enabled('rm-protected-root')) {
        const target = protectedTarget ?? unknownTarget;
        return {
          ruleId: 'rm-protected-root', evaluation: protectedTarget ? 'matched' : 'unknown',
          detail: `递归删除 ${target?.display ?? '<?>'}（root / home / Codebase 顶层目录）`,
          why: protectedTarget
            ? '一旦执行整个目录树不可恢复、影响面过大。若确需清理，请改用指向具体子目录的精确路径。'
            : '递归删除目标无法静态还原，可能指向 root / home / Codebase 顶层目录，必须拒绝。',
        };
      }
    }

    if (forcePush(command)) {
      const refs = pushRefs(command);
      const protectedRef = refs.find((ref) => ref.value !== null && isProtectedRef(ref.value));
      const unknownRef = refs.find((ref) => ref.value === null);
      if ((protectedRef || unknownRef) && enabled('force-push-main')) {
        return {
          ruleId: 'force-push-main', evaluation: protectedRef ? 'matched' : 'unknown',
          detail: `force push 到 main/master（${trunc(displayCommand(command))}，含 --force-with-lease / +refspec 形式）`,
          why: protectedRef
            ? '会重写 main/master 的提交历史，其他人基于旧历史的工作会被破坏；主干改动请走 PR 流程。'
            : 'force push 的目标 ref 无法静态还原，可能是 main/master，必须拒绝。',
        };
      }
    }
  }
  return null;
}

/** @param {ShellGraph} graph @param {PolicyEnabled} enabled @returns {PolicyMatch|null} */
function confirmationPolicy(graph, enabled) {
  for (const command of graph.commands) {
    const tool = commandName(command);
    if (enabled('remote-exec') && ['ssh', 'scp', 'rsync'].includes(tool) && (tool === 'rsync' || !hasFlag(command.argv, '-G'))) {
      if (tool === 'ssh') {
        const { host, rest } = parseSsh(command);
        return {
          ruleId: 'remote-exec', evaluation: 'matched',
          detail: `通过 ssh 连接远程机器 ${host}${rest ? `，执行：${trunc(rest)}` : '（交互式会话）'}`,
          why: '远程机器上的操作本机无法回滚，请确认目标主机和命令是否符合预期。',
        };
      }
      return {
        ruleId: 'remote-exec', evaluation: 'matched',
        detail: `用 ${tool} 在本机与远程之间传输/同步文件：${trunc(effectiveDisplayArgv(command).slice(1).join(' '))}`,
        why: '传输会覆盖目标路径的同名文件，请确认方向（谁覆盖谁）和路径。',
      };
    }

    if (enabled('recursive-delete') && isCommand(command, 'rm') && hasRecursiveFlag(command.argv)) {
      const targets = commandTargets(command).map((target) => target.display).join(' ');
      return {
        ruleId: 'recursive-delete', evaluation: 'matched',
        detail: `递归删除：${trunc(targets) || '(未解析出目标)'}`,
        why: '删除不可逆，请确认路径正确、通配符不会扩大到预期之外。',
      };
    }

    if (enabled('force-push') && forcePush(command)) {
      return {
        ruleId: 'force-push', evaluation: 'matched',
        detail: `force push：${trunc(displayCommand(command))}`,
        why: '会覆盖远端分支历史，协作者基于旧历史的提交会被破坏，请确认分支正确且无人依赖旧历史。',
      };
    }

    const sqlCommand = ['psql', 'mysql', 'mysqlsh', 'sqlite3'].includes(commandName(command));
    const sql = sqlCommand && command.argv.find((arg) => typeof arg === 'string' &&
      /(?:DROP\s+(?:TABLE|DATABASE|SCHEMA)|TRUNCATE\s+(?:TABLE\s+)?\w+)/i.test(arg));
    if (typeof sql === 'string' && enabled('destructive-sql')) {
      const match = sql.match(/(?:DROP\s+(?:TABLE|DATABASE|SCHEMA)|TRUNCATE\s+(?:TABLE\s+)?\w+)[^;]*/i);
      return {
        ruleId: 'destructive-sql', evaluation: 'matched',
        detail: `执行破坏性 SQL：${trunc(match?.[0] ?? sql)}`,
        why: '表结构或数据会被删除且通常没有回收站，请确认目标库和表名。',
      };
    }
    const dynamicSql = ['psql', 'mysql', 'mysqlsh', 'sqlite3'].includes(commandName(command)) &&
      command.argv.some((arg, index) => (arg === '-c' || arg === '-e') && command.argv[index + 1] === null);
    const dynamicSqlitePositional = isCommand(command, 'sqlite3') &&
      commandTargets(command).slice(1).some((target) => target.value === null);
    if ((dynamicSql || dynamicSqlitePositional) && enabled('dynamic-sql')) {
      return {
        ruleId: 'dynamic-sql', evaluation: 'unknown',
        detail: '执行内容无法静态还原的 SQL',
        why: 'SQL 执行参数是动态值，无法确认是否包含 DROP/TRUNCATE，需要人工确认。',
      };
    }

    if (enabled('chmod-777') && isCommand(command, 'chmod') && command.argv.some((arg) => arg === '777' || arg === '0777')) {
      return {
        ruleId: 'chmod-777', evaluation: 'matched',
        detail: `把 ${trunc(commandTargets(command).map((target) => target.display).join(' ')) || '目标文件'} 的权限改为 777（所有用户可读写执行）`,
        why: '会移除文件的访问保护，请确认确有必要、范围没有过大。',
      };
    }

    if (enabled('gh-repo-delete') && isCommand(command, 'gh') && command.argv[1] === 'repo' && command.argv[2] === 'delete') {
      return {
        ruleId: 'gh-repo-delete', evaluation: 'matched',
        detail: `GitHub 删除操作：${trunc(displayCommand(command))}`,
        why: 'GitHub 上删除仓库/资源通常不可恢复，请确认目标无误。',
      };
    }

    if (isCommand(command, 'gh') && command.argv[1] === 'api') {
      const deleteMethod = command.argv.some((arg, index) =>
        (arg === '-X' || arg === '--method') && /^DELETE$/i.test(String(command.argv[index + 1] ?? ''))) ||
        command.argv.some((arg) => typeof arg === 'string' && /^(?:--method=DELETE|-X=?DELETE)$/i.test(arg));
      if (deleteMethod && enabled('gh-api-delete')) {
        return {
          ruleId: 'gh-api-delete', evaluation: 'matched',
          detail: `GitHub API 删除操作：${trunc(displayCommand(command))}`,
          why: 'GitHub API DELETE 通常不可恢复，请确认 endpoint 与目标资源无误。',
        };
      }
    }

    const remote = hardResetOriginRef(command);
    if (typeof remote === 'string') {
      const ruleId = /^origin\/(?:main|master)$/.test(remote) ? 'reset-hard-main' : 'reset-hard-remote';
      if (enabled(ruleId)) {
        return {
          ruleId, evaluation: 'matched',
          detail: `把当前分支硬重置到 ${remote}`,
          why: '本地未推送的提交和工作区改动会被丢弃，请先确认没有需要保留的工作。',
        };
      }
      // 已按 remote reset 专用开关决定放行，不能再落入通用 git-destructive。
      continue;
    }

    const gitRule = destructiveGitRule(command);
    if (gitRule && enabled(gitRule)) {
      const lowRisk = gitRule === 'git-low-risk';
      return {
        ruleId: gitRule, evaluation: 'matched',
        detail: lowRisk
          ? `执行会改变本地引用或工作区状态的低风险 Git 操作：${trunc(displayCommand(command))}`
          : `执行可能丢弃本地状态或修改全局配置的 Git 操作：${trunc(displayCommand(command))}`,
        why: lowRisk
          ? '该操作不属于重写历史或强制覆盖，但可能删除本地分支/tag、进入 detached HEAD 或解除 submodule 初始化状态。'
          : '这类操作可能删除文件、提交或 worktree，或者改变整台机器的 Git 行为，请确认目标和参数。',
      };
    }
  }

  /** @type {Map<number, AnalyzedCommand[]>} */
  const pipelineGroups = new Map();
  for (const command of graph.commands) {
    if (command.pipelineGroup === null) continue;
    const group = pipelineGroups.get(command.pipelineGroup) ?? [];
    group.push(command);
    pipelineGroups.set(command.pipelineGroup, group);
  }
  for (const commands of pipelineGroups.values()) {
    const download = commands.find((command) => isCommand(command, 'curl') || isCommand(command, 'wget'));
    const shell = commands.find((command) => ['sh', 'bash', 'zsh', 'dash'].includes(commandName(command)));
    if (download && shell && enabled('curl-pipe-sh')) {
      const url = download.argv.find((arg) => typeof arg === 'string' && /^https?:\/\//.test(arg));
      return {
        ruleId: 'curl-pipe-sh', evaluation: 'matched',
        detail: `下载远程脚本${typeof url === 'string' ? `（${trunc(url)}）` : ''}并直接交给 shell 执行`,
        why: '脚本内容未经审查就以当前用户权限运行，请确认来源可信。',
      };
    }
  }
  return null;
}

/**
 * @typedef {{
 *   kind: 'deny'|'confirm'|'review',
 *   evaluation: 'matched'|'unknown',
 *   ruleId: string,
 *   command: string,
 *   description: string,
 *   detail: string,
 *   why: string,
 *   analysis: ShellGraph,
 * }} GuardDecision
 */
/**
 * @typedef {{
 *   profile?: string,
 *   envShell?: string,
 *   shfmtPath?: string,
 *   zshPath?: string,
 *   timeoutMs?: number,
 *   maxInputBytes?: number,
 *   maxRecursion?: number,
 *   maxCommands?: number,
 *   protectedRoots?: string[],
 * }} GuardOptions
 */

/** @param {unknown} input @returns {{shellInput: ShellInput|null, command: string, description: string, explicitShell: string}} */
function extractInput(input) {
  if (typeof input !== 'object' || input === null) return { shellInput: null, command: '', description: '', explicitShell: '' };
  const toolInput = /** @type {Record<string, unknown>} */ (input);
  const rawCommand = toolInput.command;
  const description = typeof toolInput.description === 'string' ? toolInput.description : '';
  const explicit = [toolInput.shell, toolInput.shell_path, toolInput.executable].find((value) => typeof value === 'string');
  const explicitShell = typeof explicit === 'string' ? explicit : '';
  if (typeof rawCommand === 'string') {
    return { shellInput: { kind: 'script', text: rawCommand }, command: rawCommand, description, explicitShell };
  }
  if (Array.isArray(rawCommand)) {
    const argv = rawCommand.map(String);
    return { shellInput: { kind: 'argv', argv }, command: argv.join(' '), description, explicitShell };
  }
  return { shellInput: null, command: '', description, explicitShell };
}

/**
 * Evaluate a host hook event without reading process I/O or environment state.
 * A null result means the event is outside this guard's shell-tool scope.
 * An `allow` result means the shell input was analyzed and no enabled rule
 * requested intervention.
 *
 * @param {Record<string, unknown>} event
 * @param {GuardOptions} [options]
 * @returns {GuardDecision|{kind: 'allow', command: string, description: string, analysis: ShellGraph}|null}
 */
export function evaluateHookEvent(event, options = {}) {
  const toolName = String(event.tool_name ?? '');
  if (!/^(Bash|shell|local_shell|exec_command)$/i.test(toolName)) return null;
  const { shellInput, command, description, explicitShell } = extractInput(event.tool_input);
  if (!shellInput) return null;
  const dialect = selectShellDialect({ toolName, explicitShell, envShell: options.envShell });
  const analysis = analyzeShellInput(shellInput, {
    dialect,
    shfmtPath: options.shfmtPath,
    zshPath: options.zshPath,
    timeoutMs: options.timeoutMs,
    maxInputBytes: options.maxInputBytes,
    maxRecursion: options.maxRecursion,
    maxCommands: options.maxCommands,
  });
  const profile = resolvePolicyProfile(options.profile);
  const enabled = (/** @type {string} */ ruleId) => isPolicyEnabled(ruleId, profile);

  const hard = hardPolicy(analysis, enabled, options.protectedRoots ?? ['/']);
  if (hard) return { kind: 'deny', command, description, analysis, ...hard };

  const infrastructureFailure = analysis.unknowns.find((item) =>
    ['parser-missing', 'parser-timeout', 'parser-output-invalid'].includes(item.reason));
  if (infrastructureFailure) {
    return {
      kind: 'deny', evaluation: 'unknown', ruleId: 'guard-unavailable', command, description, analysis,
      detail: `shell parser 不可用（${infrastructureFailure.reason}）`,
      why: 'guard 无法建立可靠的 command graph；基础设施故障不受 policy profile 放宽，必须 fail-closed。',
    };
  }

  if (analysis.status === 'unknown' && enabled('shell-analysis-unknown')) {
    const reasons = analysis.unknowns.map((item) => item.reason).join(', ') || 'unknown';
    const hardUnknownReasons = new Set(['dynamic-command', 'dynamic-evaluator', 'input-too-large', 'recursion-limit', 'command-limit']);
    const kind = analysis.unknowns.some((item) => hardUnknownReasons.has(item.reason)) ? 'deny' : 'confirm';
    return {
      kind, evaluation: 'unknown', ruleId: 'shell-analysis-unknown', command, description, analysis,
      detail: `shell 结构无法静态确认（${reasons}）：${trunc(command)}`,
      why: kind === 'deny'
        ? '无法证明动态执行内容没有隐藏硬禁区，guard 按 fail-closed 拒绝。'
        : 'parser 无法确认执行结构，需要外部确认后再继续。',
    };
  }

  const confirmation = confirmationPolicy(analysis, enabled);
  if (confirmation) {
    const kind = confirmation.ruleId === 'git-low-risk' ? 'review' : 'confirm';
    return { kind, command, description, analysis, ...confirmation };
  }
  return { kind: 'allow', command, description, analysis };
}

/** @param {GuardDecision} result */
function decisionReasons(result) {
  return result.ruleId === 'shell-analysis-unknown'
    ? [...new Set(result.analysis.unknowns.map((item) => item.reason))].sort()
    : [];
}

/** @param {GuardDecision} result */
export function explainGuardDecision(result) {
  const reasons = decisionReasons(result);
  const fields = [
    `触发规则: ${result.ruleId}`,
    `匹配状态: ${result.evaluation}`,
    ...(reasons.length ? [`分析原因: ${reasons.join(', ')}`] : []),
    `处置: ${result.kind}`,
    `规则依据: ${result.why}`,
  ];
  const prefix = result.kind === 'deny' ? `已拒绝：${result.detail}。` : `需要确认：${result.detail}。`;
  return `${prefix}（${fields.join('；')}）`;
}
