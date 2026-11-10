# agent-shell-guard

AST-based shell safety guard shared by Claude Code, Codex, Grok Build, and
Kimi Code.
It parses shell input with a pinned `shfmt` build, evaluates deterministic
policies, and adapts the result to each host's approval protocol.

## Install

```bash
npm install --global @xuwenhao83/agent-shell-guard
agent-shell-guard setup
agent-shell-guard doctor
```

`setup` installs the verified `shfmt v3.13.1` binary under
`~/.local/share/agent-shell-guard/bin/`, writes a stable launcher to
`~/.local/bin/agent-shell-guard`, and creates a conservative default
configuration at `~/.config/agent-shell-guard/config.json`.

### Upgrading

Re-run `setup` after every upgrade, and after switching Node versions — but run
it from the copy that was just installed, **not** through the launcher on
`PATH`:

```bash
npm install --global @xuwenhao83/agent-shell-guard@latest
node "$(npm root --global)/@xuwenhao83/agent-shell-guard/src/cli.mjs" setup
agent-shell-guard doctor
```

The launcher is a two-line shell script holding the **absolute** path of the
`node` binary and of the `src/cli.mjs` that installed it, so that hooks keep
working regardless of which Node is on `PATH` when they fire. Two consequences:

- The launcher does not follow a later `npm install --global`. With a version
  manager, a global install goes to whichever prefix is active, which may be a
  different tree from the one the launcher points at. The launcher then keeps
  executing the older copy while `npm ls --global` reports the new version.
- A bare `agent-shell-guard setup` cannot repair that, and usually makes it
  permanent. `~/.local/bin` normally precedes the npm global bin on `PATH`, so
  the bare name resolves to the launcher, which executes its own pinned old
  `cli.mjs`; `setup` writes the path of whichever copy is running back into the
  launcher, so the old copy simply re-pins itself. Invoking the freshly
  installed `cli.mjs` by path is what makes `setup` write the new paths.

`npm root --global` is the right source for that path because it reports the
same location the preceding `npm install --global` wrote to. If the package was
installed into an explicit `--prefix`, use that prefix's
`lib/node_modules/@xuwenhao83/agent-shell-guard/src/cli.mjs` instead.

`doctor` verifies the managed `shfmt`; it does not check which package version
the launcher resolves to. Confirm the upgrade took effect directly:

```bash
sed -n "s#.*'\(/.*\)/src/cli\.mjs'.*#\1#p" ~/.local/bin/agent-shell-guard \
  | xargs -I{} node -p "require('{}/package.json').version"
```

Print the host configuration to merge into the corresponding config file:

```bash
agent-shell-guard print-config claude
agent-shell-guard print-config codex
agent-shell-guard print-config grok
agent-shell-guard print-config kimi
```

Merge the outputs into:

- Claude Code: `~/.claude/settings.json`
- Codex: `~/.codex/hooks.json`
- Grok Build: `~/.grok/hooks/agent-shell-guard.json`
- Kimi Code: `~/.kimi/config.toml`

Install native confirmation rules separately:

```bash
agent-shell-guard print-native-rules codex
agent-shell-guard print-native-rules grok
agent-shell-guard print-native-rules kimi
```

Merge Codex rules into `~/.codex/rules/default.rules`, Grok rules into
`~/.grok/config.toml`, and Kimi rules into `~/.kimi/config.toml`. Keep the Kimi
`ask` rules before broader `allow` rules.

After merging and verifying those rules, opt the corresponding host into native
delegation:

```json
{
  "nativePrompt": {
    "codex": true,
    "grok": true,
    "kimi": true
  }
}
```

All flags default to `false`. The guard never assumes that printing a snippet
means it was installed. Grok and Kimi delegation also require both normalized
argv and the original command prefix to prove that the permission rule will
match.

## Decisions

The core returns four states:

1. `deny`: deterministic hard block; never delegated to a model.
2. `confirm`: prefer a host-native human prompt.
3. `review`: eligible for a configured second-model review.
4. `allow`: no guard intervention.

Claude supports hook-level prompts. Codex, Grok, and Kimi only receive a
delegated confirmation when a matching native rule is guaranteed. Otherwise
the configured mode controls the fallback. Grok's hook adapter accepts its
camelCase `run_terminal_command` events and emits Grok's native deny response;
an omitted response continues into Grok's permission pipeline.

## Modes

Strict mode is the default:

```json
{
  "mode": "strict",
  "profile": "dangerous-only",
  "protectedRoots": ["~/Codebase"],
  "protectedPaths": ["~/Codebase/personal/podcast-production"]
}
```

It uses a native prompt where available and denies when a confirmation cannot be
represented safely.

Reviewed mode lets a configured second model adjudicate `review` decisions and
`confirm` decisions for which the host cannot guarantee a native prompt:

```json
{
  "mode": "reviewed",
  "profile": "dangerous-only",
  "reviewer": {
    "command": "kimi",
    "model": "kimi-code-2.7",
    "timeoutMs": 12000
  }
}
```

The reviewer must return exactly:

```json
{"decision":"allow|deny|uncertain","reason":"..."}
```

Invalid output, incomplete shell analysis, a timeout, or reviewer failure is
treated as `uncertain` and denied. Reviewer subprocesses receive
`AGENT_SHELL_GUARD_REVIEW_DEPTH=1`; nested reviews are rejected.
Before a command graph is sent to the reviewer, common credential forms are
redacted from both the raw command and normalized argv. Reviewer timeouts are
capped at 20 seconds to leave headroom inside the 30-second host hook timeout.

Environment overrides:

```text
AGENT_SHELL_GUARD_CONFIG
AGENT_SHELL_GUARD_MODE
AGENT_SHELL_GUARD_PROFILE
AGENT_SHELL_GUARD_SHFMT
AGENT_SHELL_GUARD_PROTECTED_ROOTS
AGENT_SHELL_GUARD_PROTECTED_PATHS
AGENT_SHELL_GUARD_STATE_DIR
AGENT_SHELL_GUARD_NATIVE_PROMPT_CODEX
AGENT_SHELL_GUARD_NATIVE_PROMPT_GROK
AGENT_SHELL_GUARD_NATIVE_PROMPT_KIMI
AGENT_SHELL_GUARD_REVIEWER_COMMAND
AGENT_SHELL_GUARD_REVIEWER_MODEL
AGENT_SHELL_GUARD_REVIEWER_TIMEOUT_MS
```

## Policy profiles

- `dangerous-only` (default): hard boundaries everywhere. In Claude Code a
  short list of ask-level confirmations only in bypass sessions; on Codex,
  Grok and Kimi the 0.4 confirmation set (see the tier table).
- `legacy-dangerous`: rollback switch. The 0.4 `dangerous-only` confirmation
  set (including working-tree discards, non-trunk branch deletion, `chmod 777`,
  generic `gh api` DELETE) in every permission mode and on every host, without
  the 0.5 bypass-session rules (`bypass-no-project-sandbox`,
  `unsandboxed-outside-project`). The 0.5 hard boundaries stay.
- `full`: every bundled confirmation and review rule, in every mode.
- `off`: disables policy rules, but parser infrastructure failure still denies.

Both the CLI configuration and direct library calls default to
`dangerous-only`.

### Permission-mode tiers

Claude Code sends `permission_mode` on hook input. Under `dangerous-only`:

| Host / hook `permission_mode` | Tier | Ask-level rules | 0.4 confirmations relaxed in 0.5 | Deny rules | Extra |
|---|---|---|---|---|---|
| Claude: `auto`, `default`, `acceptEdits`, `plan`, unknown, missing | relaxed | silent — the auto classifier decides | silent | deny | — |
| Claude: `bypassPermissions` | bypass | `ask` | silent (project sandbox) | deny | project-sandbox check, unsandboxed-call check |
| Codex, Grok, Kimi (any input) | native | confirm | confirm | deny | — |

A hook `ask` in auto mode forces a human prompt the classifier cannot answer,
so ask-level rules stay silent there. In bypass mode nothing else asks, so the
guard does. Codex, Grok and Kimi have neither permission modes nor a
classifier, so they keep the 0.4 behaviour: a confirmation is delegated to the
host's native prompt rule when one covers the exact command (a single static
argv), and denied otherwise. The adapter, not the event, decides the host.

### Rules (`dangerous-only`)

| Rule | Decision | Matches |
|---|---|---|
| `org-ruleset-write` | deny | `gh api` writes to `orgs/<org>/rulesets` (path or URL; dynamic endpoint with a write method also denies) |
| `rm-protected-root` | deny | recursive `rm` of a protected root **or any ancestor of one**; relative targets, globs and brace expansions resolved against the hook `cwd` (below). Also `find <ancestor> … -delete` / `-exec rm -r…` whose name tests can select the root, `find … \| xargs rm -r…` and `echo <path> \| xargs rm -r…`, `rsync --delete` into a root, `git worktree remove` of a root, and the same inside a double-quoted `bash -c` / `sh -c` / `eval` script whose expansions are treated as unknown words. `find -exec` sees through `command`/`env`/`sudo` and counts `-exec sh -c …` as deleting |
| `rm-git-dir` | deny | recursive `rm` with a `.git` segment anywhere in the target (`rm -rf .git`, `sub/.git/`, `.git/objects`, `.g*`); `find` that deletes `.git` (`-name .git -exec rm -rf`, `-path '*/.git/*' -delete`; a negated `-not -path` test does not select). Recovery paths stay allowed: `.git/modules/<name>…`, `.git/worktrees/<name>…`, `.git/rebase-merge`, `.git/rebase-apply`, `*.lock` |
| `rm-protected-path` | deny | `rm` / `unlink` / `mv` / `ln -f` on a literal `protectedPaths` entry (recursive `rm` and `mv` also on its ancestors) |
| `git-clean-root` | deny | `git clean` with two `-f` anywhere; or `-x`/`-X` when the run directory is a thin project root (a repo with nested member repos), a pathspec widens to it (`:/`, `..`, absolute), or the directory is unknown; or a dynamic option word |
| `force-push-main` | deny | force push whose target is main/master: an explicit refspec, `--all`/`--branches`, a matching (`:`, `+:`) or `*` refspec, or `HEAD`/`@`/no refspec while main/master is checked out (read from the repository's `HEAD`, following symbolic refs); `push --mirror`. Unknown — a dynamic refspec, detached, unreadable or reftable `HEAD`, a current branch whose upstream is main/master, `GIT_DIR`/`GIT_WORK_TREE`/`GIT_CONFIG_*` set in the command, or `-c push.*`/`-c remote.*` without a refspec — also denies. Write an explicit refspec to hand a non-trunk force push to the host |
| `push-delete-trunk` | deny | `git push --delete main`, `git push origin :main` (also `refs/heads/`, `master`, `HEAD`/`@` while on main) |
| `gh-repo-delete` | deny | `gh [-R owner/repo] repo delete` |
| `gh-api-delete-protected` | deny | `gh api` DELETE on `repos/<o>/<r>`, `…/rulesets…`, `…/branches/<b>/protection…`, `…/git/refs/heads/(main\|master)`, or on a dynamic endpoint |
| `guard-unavailable` | deny | parser missing / timeout / invalid output (independent of profile, including `off`) |
| `bypass-no-project-sandbox` | deny (bypass) | write-class command while the session's project has no project sandbox config |
| `destructive-sql` | ask (bypass) | `psql`/`mysql`/`mysqlsh`/`sqlite3` with DROP TABLE/DATABASE/SCHEMA or TRUNCATE |
| `reset-hard-main` | ask (bypass) | `git reset --hard` to `main`/`master`, `origin/…`/`upstream/…`, `refs/remotes/<r>/…`, `refs/heads/…`, or `@{u}`/`@{upstream}` when the configured upstream is main/master |
| `git-trunk-ref` | ask (bypass) | `branch -d/-D/-M/-C/-f` on main/master or an unresolvable name; `checkout -B`, `checkout --orphan`, `switch -C`, `switch --orphan`, `worktree add -B` on main/master/`-`/`@{…}`/unresolvable |
| `git-config-global` | ask (bypass) | `git config --global/--system` writes (reads such as `--get`, `--list`, `<key>` alone are silent) |
| `git-lfs` | ask (bypass) | `git lfs install/uninstall/migrate` |
| `git-exec` | ask (bypass) | `git rebase -x/--exec`, `git submodule foreach` |
| `git-push-bulk` | ask (bypass) | `git push --prune` |
| `push-delete-dynamic` | ask (bypass) | `git push --delete "$b"`: the deleted ref is a variable |
| `gh-api-delete-sensitive` | ask (bypass) | `gh api` DELETE on `keys`, `hooks`, `actions/secrets`, `environments` (repo or org), `user/keys` |
| `unsandboxed-outside-project` | ask (bypass) | an unsandboxed call (below) whose recursive `rm`, `mv`, `find -delete`, `git worktree add/remove/move` (relative to `git -C`) or `rsync --delete` target is outside the project root; or a discarding / ref-changing git command (`git-discard`, `git-ref-change`) whose repository (`git -C`, `cd`) is outside it |

Silent under `dangerous-only` in Claude sessions (the classifier or the
project sandbox handles them), confirmed on Codex/Grok/Kimi: working-tree discards (`git-discard`: `reset`,
`restore`, `rm`, `clean -f`, `stash drop/clear`, path-restoring `checkout`,
`switch -f/--discard-changes`, `worktree remove --force`, `tag -f`),
non-trunk ref changes (`git-ref-change`: `branch -D/-M/-C`, `worktree remove`
without force, `worktree add -B`, `checkout -B`, `switch -C`, `push --delete`
of a non-trunk ref, `lfs prune`), `chmod 777`, and `gh api` DELETE on other
endpoints. `legacy-dangerous` and `full` confirm all of these everywhere.

### Paths: protected roots, protected paths and the hook cwd

`protectedRoots` always includes `/` and the home directory; config and
`AGENT_SHELL_GUARD_PROTECTED_ROOTS` add more. `protectedPaths` (new in 0.5;
config array plus comma-separated `AGENT_SHELL_GUARD_PROTECTED_PATHS`, `~`
expanded, merged like `protectedRoots`) lists individual paths such as
compatibility symlinks.

Comparisons stay lexical — no filesystem access, `.`/`..` collapsed — so
`rm -rf /tmp/../root` is judged as `/root`. On macOS (case-insensitive by
default) paths and `.git` are compared case-insensitively, so
`rm -rf ~/codebase/Personal` and `rm -rf .GIT` are caught. A relative target is
joined to the hook event's `cwd` literally, so `rm -rf dotfiles` from the
parent of a protected `…/dotfiles` is denied.

The command's own directory changes (`cd`, `chdir`, `pushd`, `popd`, also
inside `sh -c`/`eval`) are followed:

- A command in an `&&` chain runs after every `cd` before it succeeded, so it
  runs where those `cd`s lead: `cd /tmp/x && rm -rf data`,
  `(cd /x && …)`, `if cd /x; then …; fi`, `cd /x 2>/dev/null && …`,
  `cd /x && make && cd sub && …`, with a `|| tail` or `; more` after the
  chain (the tail itself is not covered).
- Every other command, when all directory changes are literal, is checked in
  every directory the script can be in: the hook `cwd` (a `cd` that fails
  leaves it unchanged) and each `cd` target. `cd ~/p/devinfra; rm -rf data`
  is denied, and so is `cd /tmp/x; rm -rf data` from inside `devinfra`.
- A `cd` whose operand is not literal (`cd "$X"`, `source`, `popd` without an
  earlier change) adds an unknown directory. Only then — or when the hook has
  no `cwd` — is a relative target judged without a base: denied when its
  segments appear inside a protected path, except a single common name
  (`data`, `build`, `src`, `tmp`, `node_modules`, `infra`, …), which
  identifies no particular root; `.` and `..` are denied outright. The
  trade-off: `cd "$X" && rm -rf data` is allowed even though `$X` might be the
  parent of a protected `…/data`, while `cd "$X" && rm -rf dotfiles` and
  `rm -rf devinfra/data` stay denied.

Globs and unquoted brace expansions are expanded into candidates (up to 64;
beyond that the literal prefix decides, and a `..` after the brace makes the
target unknown). `$'…'` words are decoded like bash does. Each glob is
matched segment-wise: `rm -rf ~/Codebase/*` covers `~/Codebase/personal`,
`rm -rf ~/Codebase/*/node_modules` does not. Inside a protected root only a
pattern that matches every entry empties it: `*`, `.*`, `.[!.]*`, and any
pattern with `*` and no literal character (`[[:alnum:]]*`, `?*`, `[a-z]*`);
`tmp-*`, `*.egg-info` or `.worktrees/feat-*` do not. Under zsh a trailing glob
qualifier (`*(D)`, `*(.N)`) is dropped before judging. Deletion through a
symlink is out of reach; the sandbox's write scope is the backstop.

### Bypass sessions

**Project sandbox check.** Claude Code gives hook processes
`CLAUDE_PROJECT_DIR`, the directory the session started in and the place it
reads project settings from (the hook `cwd` follows the Bash tool's persisted
`cd` instead). The guard reads `.claude/settings.json` merged with
`.claude/settings.local.json` there (objects merge, arrays concatenate, local
scalars win). Without `CLAUDE_PROJECT_DIR` it walks up from the hook `cwd` to
the nearest directory containing `.git` (a plain stat, no git subprocess). A
linked worktree (`.git` is a file: `member/.worktrees/x`,
`.claude/worktrees/agent-*`) also reads the main worktree's settings, found
through `gitdir`/`commondir`, because an untracked `settings.local.json` only
exists there. The project counts as configured when
`sandbox.filesystem.allowWrite` is a non-empty array and `sandbox.enabled` is
not `false`; `enabled: true` alone does not count, since the user-level
settings already enable the sandbox. `permissions.blockWritesOutsideWorkingDirectories`
comes from user-level settings and is not checked. No project directory, no
git root, unreadable or invalid JSON, and any location under `/tmp`,
`/private/tmp`, `/var/folders`, `/private/var/folders` or the OS temp dir all
count as not configured.

Without a configured project, bypass sessions get `bypass-no-project-sandbox`
for every **write-class** command: *"bypass 只能在配好项目沙盒的项目里用；先配
.claude/settings.json 或切 auto"*. Write-class is everything that is not
provably read-only. A command graph is read-only only when the parser fully
understood it, every redirection reads or targets `/dev/null`,
`/dev/stdout`, `/dev/stderr`, `/dev/tty` or an fd, and every command is on the
reader allowlist:

- plain readers (`ls`, `cat`, `head`, `tail`, `grep`, `wc`, `stat`, `du`,
  `diff`, `jq`, `echo`, `printf`, `pwd`, `cd`, `which`, `ps`, …), also behind
  `xargs`;
- readers with their writing options excluded: `find` (no `-delete`,
  `-exec*`, `-ok*`, `-fprint*`), `fd` (no exec), `rg` (no `--pre`), `sed` (no
  `-i`, `-f`, `w`, `e` command or `s///e` flag), `awk` (static program; no
  `-f`/`-i`/`-l`/`-E`/`--inplace`, and no `print … >`, `print … |`, `| "cmd"`,
  `system(`, `getline` in the program — comparisons such as `NR > 5` are
  fine), `less` (no `-o`/`-O`/`--log-file`/`--LOG-FILE`/`+cmd`), `man` (no
  `-P`/`-H`), `sort` (no
  `-o`), `uniq` (one operand), `tree` (no `-o`), `yq` (no `-i`), `command -v`,
  `curl` to stdout with GET/HEAD (no `-o`/`-O`/`-T`/`-d`/`--data*`/`-F`/`-K`/
  `-c`/`-D`, no other `-X`), `npm ls/view/info/outdated/explain`,
  `node --version`;
- `git` read subcommands (`status`, `log`, `show`, `diff`, `rev-parse`,
  `ls-files`, `blame`, `grep`, …) and the listing forms of `branch`, `tag`,
  `remote`, `worktree list`, `stash list/show`, `config` reads, `reflog`,
  `submodule status` — never with a global `-c`/`--config-env` (pager,
  fsmonitor, alias and diff drivers run commands), `--ext-diff`,
  `--textconv`, or a dynamic argument (it may expand to `--output=<file>`);
- `gh` view/list subcommands, `gh search`, `gh auth status`, `gh api`
  without fields and with no method or `GET`/`HEAD`, and `gh api graphql`
  whose static fields contain no `mutation`.

A graph that sets an execution channel — `GIT_PAGER`, `GIT_EXTERNAL_DIFF`,
`PAGER`, `MANPAGER`, `LESSOPEN`/`LESSCLOSE`, `LESS` with a log option,
`GIT_CONFIG_COUNT/KEY_*/VALUE_*`, `GIT_SSH_COMMAND`, `GIT_DIR`/`GIT_WORK_TREE`,
`EDITOR`, `PATH`, `LD_PRELOAD`, `GIT_TRACE=<file>` and the like, as a prefix,
plain assignment or `env` operand — is a write, and so is any `export` /
`declare -x`. `GIT_PAGER=cat`, `PAGER=`, `GIT_TRACE=1` and `LESS=-R` stay
reads.

Everything else — interpreters, package managers, `git fetch`/`commit`,
`touch`, `tee`, `sudo …`, unknown tools — is a write. False positives only cost
a deny in a session that should be in auto anyway.

**Unsandboxed calls.** A bypass call is unsandboxed when
`tool_input.dangerouslyDisableSandbox === true` (key absent counts as false)
or the whole command is one of the commands typically listed in
`sandbox.excludedCommands` (`gh`, `ssh`, `scp`, `rsync`, `tailscale`, `op`,
`kubectl`, `gcloud`, `docker`, `git push/fetch/pull/clone/worktree`,
`git branch -d/-D`). Its recursive `rm`, `mv`, `find -delete`,
`git worktree remove/move` (resolved against `git -C`) and `rsync --delete`
targets must be strictly inside the project root — the outermost repository
enclosing the project directory (`CLAUDE_PROJECT_DIR`, else the hook `cwd`)
below the home directory, so a thin root's members and `.worktrees/` are
inside even from a member session — and so must the repository of a
discarding or ref-changing git command. Anything else, including unresolvable
targets, asks.

### Unsandboxed-call log

Every shell call with `tool_input.dangerouslyDisableSandbox: true`, in every
mode and profile, appends one JSON line to
`~/.local/state/agent-shell-guard/unsandboxed.jsonl` (override the directory
with `AGENT_SHELL_GUARD_STATE_DIR`):

```json
{"ts":"…","cwd":"…","gitRoot":"…","command":"first 500 chars, credentials redacted","permission_mode":"bypassPermissions","session_id":"…","decision":"allow"}
```

The write is best effort; failures are swallowed and never change the
decision. Redaction covers `Authorization`/`X-Api-Key`/`Cookie` headers, URL
`user:password@`, `--password=`/`--token …` style flags (quoted or not),
`-p<password>`, `sshpass -p`, `NAME=value` where the name contains TOKEN, KEY,
SECRET, PASSWORD or CREDENTIAL (quoted or not), npm `_authToken`,
`aws configure set aws_secret_access_key|aws_session_token|aws_access_key_id`,
`gh secret set … --body/-b`, the words piped into `sudo -S`
(`printf <pw> | sudo -S …`), Slack webhook paths, `AKIA…` access key ids and
common token prefixes (`sk-`, `ghp_`,
`github_pat_`, `glpat-`, `xox?-`). It is pattern-based, not a guarantee.

### Argument parsing details

`git checkout` is classified by its arguments, not by its name. Creating a
branch (`-b` / `--orphan`) or an explicit ref intent (`--detach`/`-d`,
`--track`/`-t`, `--no-track` — the flags git itself refuses to pair with a
path; `--guess` is not one of them) is a branch switch; everything else that
can replace working-tree content is a discard: `--`, `.`, `--force`, `--ours`,
`--theirs`, `--merge`, `--conflict`, `-p`, `--pathspec-from-file`, a second
positional, a glob or `:`-magic pathspec, an unresolvable operand — and a lone
operand with no branch-intent flag, because git resolves it against both refs
and paths. Short options are split from their operand the way git does —
`-qB main`, `-Bmain` and `-qBmain` all yield the branch name, and `-d` is read
as `--detach` under `checkout` but `--delete` under `branch`. `--no-detach`
and `--no-orphan` cancel an earlier `--detach` / `--orphan` instead of adding
a mode of their own; `--orphan` on main/master is `git-trunk-ref`.

`git push` short options cluster up to `o`, whose operand is the rest of the
word (`-onone` is a push option, not `-n`), and the last of `--dry-run` /
`--no-dry-run` wins.

Long options are matched by prefix, because git accepts any unambiguous
abbreviation: `git worktree remove --for`, `git branch --del`, `git push --for`
and `git checkout --pathspec-from-f=` all reach the full option. Prefix matching
can only put more commands in a stricter class; the flags that *loosen* a
classification (checkout's ref intent) keep their exact spelling.

Explicit static `git clean -n` / `--dry-run` is read-only, including `-fn` /
`-ndfx`. Exclude-pattern operands and paths after `--` cannot supply the
dry-run flag.

`gh api` endpoint detection accepts a full URL as well as a path, and
canonicalizes it first — host case-folded, trailing dot and an explicit `:443`
dropped, query string ignored.

Explicit zsh shells are syntax-checked with zsh and therefore require a working
zsh executable. Missing or unrecognized shell metadata falls back to POSIX
parsing instead of assuming zsh.

## Development

```bash
npm install
npm test
npm run typecheck
npm pack --dry-run
```

The package currently supports macOS and Linux on x64 and arm64, with Node.js 24
or newer.

### 0.5 native-rule migration

Codex, Grok and Kimi keep the 0.4 confirmation set (native tier), so their
native rules keep the 0.4 prefixes, now generated per rule id. Regenerate them
with `print-native-rules` after the launcher points at 0.5.0 and remove
entries that are gone — the host applies the strictest matching rule.

- **Codex**: the 0.4 `git-destructive` list (branch `-D/-M/-C`, trunk
  `branch -d main|master`, `worktree remove`, `worktree add -B`,
  `clean -f/--force/-i`, `reset`, `restore`, path-restoring `checkout`
  forms, `checkout -B`, `rm`, `config --global/--system`, `stash drop/clear`,
  `tag -f`, `switch -f/--discard-changes/-C/--force-create`,
  `submodule foreach`, `lfs install/migrate/uninstall/prune`, rebase exec,
  `push --delete/-d`, `push --prune`). Removed: `gh repo delete` and
  `push --mirror` (hook denies now). `chmod 777` and generic `gh api` DELETE
  have no prefix, as in 0.4, and fail closed.
- **Grok and Kimi**: the Codex list with a wider discard family (`git clean`,
  `git checkout`, `git reset`, `git restore`, `git rm`, …) plus destructive SQL
  clients, `chmod` and `gh api` (as their 0.4 rules).

Differences from 0.4 on the native tier, all deliberate:

| Command | 0.4 | 0.5 |
|---|---|---|
| `gh repo delete …` | confirm (native prompt) | deny (`gh-repo-delete`) |
| `git push --mirror …` | confirm (native prompt) | deny (`force-push-main`) |
| Codex `git branch -d main` | deny (no prefix) | native prompt (`git-trunk-ref`, `git branch -d main` prefix) |
| Codex `git reset --hard origin/main` | deny (no prefix) | native prompt (`reset-hard-main`, `git reset` prefix) |
| `git checkout --orphan main` | silent | `git-trunk-ref` confirm; no native prefix, so deny on Codex, Grok and Kimi |

The hard boundaries new in 0.5 (`rm-git-dir`, `rm-protected-path`,
`git-clean-root`, `push-delete-trunk`, `gh-api-delete-protected`,
`rm-protected-root` on relative targets and ancestors) apply on every host.

With nativePrompt disabled, or for commands no prefix covers (compound
chains, `git -C`, variables, attached option values), the confirmation fails
closed (deny) with a `[guard-diagnostic]` marker, as in 0.4.

### Changes in 0.5.0

- Relaxed `dangerous-only` for Claude Code: working-tree discards, non-trunk
  ref changes, `chmod 777` and generic `gh api` DELETE no longer confirm;
  ask-level rules confirm only in bypass sessions. Codex, Grok and Kimi keep
  the 0.4 set.
- New hard denies: `rm-git-dir`, `rm-protected-path`, `git-clean-root`,
  `push-delete-trunk`, `gh-api-delete-protected`; `gh repo delete` upgraded to
  deny; `rm-protected-root` resolves relative targets against the hook cwd and
  covers ancestors of protected roots.
- Bypass sessions: `bypass-no-project-sandbox` and
  `unsandboxed-outside-project`.
- `unsandboxed.jsonl` log; `protectedPaths` config; `legacy-dangerous` profile.
- The `git-destructive` rule id is split into `git-discard`, `git-trunk-ref`,
  `git-ref-change`, `git-config-global`, `git-lfs`, `git-exec`,
  `git-push-bulk`; `push-delete-dynamic` is new. `git push --mirror` is a
  `force-push-main` deny.

## Known limitations

The guard reads command text and a few repository files. It does not run
anything, so these are out of reach; the sandbox and the host's own approval
are the backstop.

- **Symlinks and other aliases of a path.** Targets are compared lexically. A
  symlink, bind mount, hard link or `$PWD`-relative trick that points into a
  protected root is not resolved, and `realpath`-style canonicalization
  (Unicode normalization, `/private/tmp` vs `/tmp`) is not applied.
- **Deletion by other programs.** Interpreters (`python -c 'shutil.rmtree…'`,
  `perl`, `node -e`), `rmdir`, `trash`, `git -C <dir> rm -r`, `cp`/`ln`
  without `-f` over a protected path, `mv .git elsewhere`, a dynamic command
  name (`$RM -rf …`), aliases and shell functions are not modelled as
  deletes. `xargs rm -r` is judged only when a `find`, `echo` or `printf` in
  the same pipeline supplies the list (not here-strings or files).
- **GitHub writes outside `gh api` REST paths.** GraphQL mutations
  (`deleteRepository`), `curl` to the REST API, `gh ruleset delete`,
  `gh repo archive/edit` and `PATCH`/`PUT`/`POST` on protection endpoints are
  not hard boundaries.
- **Git configuration that changes a push target.** `HEAD` is resolved from
  the repository (loose symbolic refs followed; reftable repositories count as
  unknown), and `-c push.*`/`-c remote.*` or `GIT_CONFIG_*` in the command make
  a refspec-less push unknown, but the repository's own `push.default`,
  `remote.<r>.push` refspecs, global git config and case-folded ref names
  (`MAIN` on a case-insensitive remote) are not read.
- **excludedCommands is mirrored, not read.** The list of commands treated as
  unsandboxed in bypass sessions is a static copy of the managing dotfiles'
  default, not the live `sandbox.excludedCommands`.
- **Hosts without `cwd`.** Grok/Kimi payloads may omit `cwd`; relative targets
  are then judged with the unknown-cwd rule above and `git clean -x` is denied.
- **Shell content fed through stdin or produced at run time.** Under
  `dangerous-only` these are not inspected and not denied:
  `printf 'rm -rf %s' <root> | sh`, `echo … | bash`, a heredoc fed to `sh`,
  `bash -s <<< '…'`, `sh -c "$(…)"`, `eval "$(…)"`, `source <(…)`, a script
  file written and then run, and two-step deletes such as
  `mv <protected root> /tmp/t && rm -rf /tmp/t` or `find … -exec mv {} …`.
  `ls -d <root> | xargs rm -rf` and `cat list | xargs rm -rf` are not followed
  either.
- **Shell aliases and functions.** The guard sees the command name as typed.
  Aliases from the user's shell snapshot — for example oh-my-zsh's git plugin
  (`g`, `gpf!`, `gpod`, `gpristine`) — bypass every git rule. Keep such
  aliases out of the shell the agent's tool runs, or unalias them there.
- **zsh-only globbing.** `EXTENDED_GLOB` negation (`^pattern`) and other
  options that widen a pattern are not modelled.
