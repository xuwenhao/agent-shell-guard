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

- `dangerous-only` (default): hard boundaries everywhere; a short list of
  ask-level confirmations only in Claude bypass sessions (see below).
- `legacy-dangerous`: rollback switch. The 0.4 `dangerous-only` confirmation
  set (including working-tree discards, non-trunk branch deletion, `chmod 777`,
  generic `gh api` DELETE) in every permission mode, on top of the 0.5 hard
  boundaries.
- `full`: every bundled confirmation and review rule, in every mode.
- `off`: disables policy rules, but parser infrastructure failure still denies.

Both the CLI configuration and direct library calls default to
`dangerous-only`.

### Permission-mode tiers

Claude Code sends `permission_mode` on hook input. Under `dangerous-only`:

| Hook `permission_mode` | Tier | Ask-level rules | Deny rules | Extra |
|---|---|---|---|---|
| `auto`, `default`, `acceptEdits`, `plan`, unknown | relaxed | silent — the auto classifier or host decides | deny | — |
| missing (Codex, Grok, Kimi, older Claude Code) | relaxed | silent — native rules decide | deny | — |
| `bypassPermissions` | bypass | `ask` | deny | project-sandbox check, unsandboxed-call check |

A hook `ask` in auto mode forces a human prompt the classifier cannot answer,
so ask-level rules stay silent there. In bypass mode nothing else asks, so the
guard does.

### Rules (`dangerous-only`)

| Rule | Decision | Matches |
|---|---|---|
| `org-ruleset-write` | deny | `gh api` writes to `orgs/<org>/rulesets` (path or URL; dynamic endpoint with a write method also denies) |
| `rm-protected-root` | deny | recursive `rm` of a protected root **or any ancestor of one**; relative targets and globs resolved against the hook `cwd` (below) |
| `rm-git-dir` | deny | recursive `rm` whose target basename is `.git` (`rm -rf .git`, `rm -rf sub/.git/`, `rm -rf .git/*`) |
| `rm-protected-path` | deny | `rm` / `unlink` / `mv` on a literal `protectedPaths` entry (recursive `rm` and `mv` also on its ancestors) |
| `git-clean-root` | deny | `git clean` with two `-f` anywhere; or `-x`/`-X` when the run directory is a thin project root (a repo with nested member repos), a pathspec widens to it (`:/`, `..`, absolute), or the directory is unknown; or a dynamic option word |
| `force-push-main` | deny | force push to main/master, or to an unresolvable ref. Write an explicit refspec to hand a non-trunk force push to the host |
| `push-delete-trunk` | deny | `git push --delete main`, `git push origin :main` (also `refs/heads/`, `master`, unresolvable ref) |
| `gh-repo-delete` | deny | `gh repo delete` |
| `gh-api-delete-protected` | deny | `gh api` DELETE on `repos/<o>/<r>`, `…/rulesets…`, `…/branches/<b>/protection…`, `…/git/refs/heads/(main\|master)` |
| `guard-unavailable` | deny | parser missing / timeout / invalid output (independent of profile) |
| `bypass-no-project-sandbox` | deny (bypass) | write-class command while the session's project has no project sandbox config |
| `destructive-sql` | ask (bypass) | `psql`/`mysql`/`mysqlsh`/`sqlite3` with DROP TABLE/DATABASE/SCHEMA or TRUNCATE |
| `reset-hard-main` | ask (bypass) | `git reset --hard` to `main`/`master`/`origin/…`/`upstream/…` |
| `git-trunk-ref` | ask (bypass) | `branch -d/-D/-M/-C/-f` on main/master or an unresolvable name; `checkout -B`, `switch -C`, `worktree add -B` on main/master/`-`/`@{…}`/unresolvable |
| `git-config-global` | ask (bypass) | `git config --global/--system` writes (reads such as `--get`, `--list`, `<key>` alone are silent) |
| `git-lfs` | ask (bypass) | `git lfs install/uninstall/migrate` |
| `git-exec` | ask (bypass) | `git rebase -x/--exec`, `git submodule foreach` |
| `git-push-bulk` | ask (bypass) | `git push --mirror/--prune` |
| `gh-api-delete-sensitive` | ask (bypass) | `gh api` DELETE on `keys`, `hooks`, `actions/secrets`, `environments` (repo or org), `user/keys` |
| `unsandboxed-outside-project` | ask (bypass) | an unsandboxed call (below) whose recursive `rm`, `mv`, `git worktree remove/move` or `rsync --delete` target is outside the project root |

Silent under `dangerous-only` in every tier (the host, the classifier, or the
project sandbox handles them): working-tree discards (`git-discard`: `reset`,
`restore`, `rm`, `clean -f`, `stash drop/clear`, path-restoring `checkout`,
`switch -f/--discard-changes`, `worktree remove --force`, `tag -f`),
non-trunk ref changes (`git-ref-change`: `branch -D/-M/-C`, `worktree remove`
without force, `worktree add -B`, `checkout -B`, `switch -C`, `push --delete`
of a non-trunk ref, `lfs prune`), `chmod 777`, and `gh api` DELETE on other
endpoints. `legacy-dangerous` and `full` still confirm all of these.

### Paths: protected roots, protected paths and the hook cwd

`protectedRoots` always includes `/` and the home directory; config and
`AGENT_SHELL_GUARD_PROTECTED_ROOTS` add more. `protectedPaths` (new in 0.5;
config array plus comma-separated `AGENT_SHELL_GUARD_PROTECTED_PATHS`, `~`
expanded, merged like `protectedRoots`) lists individual paths such as
compatibility symlinks.

Comparisons stay lexical — no filesystem access, `.`/`..` collapsed — so
`rm -rf /tmp/../root` is judged as `/root`. A relative target is joined to the
hook event's `cwd` literally, so `rm -rf dotfiles` from the parent of a
protected `…/dotfiles` is denied. When the cwd cannot be trusted — the command
contains `cd`/`pushd`/`popd`/`source`, or the host sent no `cwd` — a relative
target is denied if its segments appear inside any protected path (some cwd
would make it land there), and `.`/`..` are denied outright. Globs are
matched segment-wise against protected paths: `rm -rf ~/Codebase/*` covers
`~/Codebase/personal`, `rm -rf ~/Codebase/*/node_modules` does not. Deletion
through a symlink is out of reach; the sandbox's write scope is the backstop.

### Bypass sessions

**Project sandbox check.** From the hook `cwd` the guard walks up to the
nearest directory containing `.git` (a plain stat, no git subprocess) and reads
`.claude/settings.json` merged with `.claude/settings.local.json` there
(objects merge, arrays concatenate, local scalars win). The project counts as
configured when `sandbox` is an object and either `sandbox.enabled === true`,
or `sandbox.enabled !== false` and `sandbox.filesystem.allowWrite` is a
non-empty array. `permissions.blockWritesOutsideWorkingDirectories` comes from
user-level settings and is not checked. No `cwd`, no git root, unreadable or
invalid JSON, and any repository under `/tmp`, `/private/tmp`, `/var/folders`,
`/private/var/folders` or the OS temp dir all count as not configured.

Without a configured project, bypass sessions get `bypass-no-project-sandbox`
for every **write-class** command: *"bypass 只能在配好项目沙盒的项目里用；先配
.claude/settings.json 或切 auto"*. Write-class is everything that is not
provably read-only. A command graph is read-only only when the parser fully
understood it, every redirection reads or targets `/dev/null`,
`/dev/stdout`, `/dev/stderr`, `/dev/tty` or an fd, and every command is on the
reader allowlist:

- plain readers (`ls`, `cat`, `head`, `tail`, `grep`, `rg`, `wc`, `stat`, `du`,
  `diff`, `jq`, `echo`, `printf`, `pwd`, `cd`, `which`, `ps`, …);
- readers with their writing options excluded: `find` (no `-delete`,
  `-exec*`, `-ok*`, `-fprint*`), `fd` (no exec), `sed` (no `-i`, no `w`),
  `awk` (no `-i inplace`, redirection, pipe, `system`, `getline`), `sort` (no
  `-o`), `uniq` (one operand), `tree` (no `-o`), `yq` (no `-i`), `command -v`;
- `git` read subcommands (`status`, `log`, `show`, `diff`, `rev-parse`,
  `ls-files`, `blame`, `grep`, …) and the listing forms of `branch`, `tag`,
  `remote`, `worktree list`, `stash list/show`, `config` reads, `reflog`,
  `submodule status`;
- `gh` view/list subcommands, `gh search`, `gh auth status`, and `gh api`
  without fields and with no method or `GET`/`HEAD`.

Everything else — interpreters, package managers, `git fetch`/`commit`,
`touch`, `tee`, `sudo …`, unknown tools — is a write. False positives only cost
a deny in a session that should be in auto anyway.

**Unsandboxed calls.** A bypass call is unsandboxed when
`tool_input.dangerouslyDisableSandbox === true` (key absent counts as false)
or the whole command is one of the commands typically listed in
`sandbox.excludedCommands` (`gh`, `ssh`, `scp`, `rsync`, `tailscale`, `op`,
`kubectl`, `gcloud`, `docker`, `git push/fetch/pull/clone/worktree`,
`git branch -d/-D`). Its recursive `rm`, `mv`, `git worktree remove/move`
and `rsync --delete` targets must be strictly inside the project root, the
outermost repository enclosing `cwd` below the home directory — so a thin
root's members and `.worktrees/` are inside even from a member session.
Anything else, including unresolvable targets, asks.

### Unsandboxed-call log

Every shell call with `tool_input.dangerouslyDisableSandbox: true`, in every
mode and profile, appends one JSON line to
`~/.local/state/agent-shell-guard/unsandboxed.jsonl` (override the directory
with `AGENT_SHELL_GUARD_STATE_DIR`):

```json
{"ts":"…","cwd":"…","gitRoot":"…","command":"first 500 chars, credentials redacted","permission_mode":"bypassPermissions","session_id":"…","decision":"allow"}
```

The write is best effort; failures are swallowed and never change the
decision.

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
as `--detach` under `checkout` but `--delete` under `branch`.

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

Hosts without `permission_mode` (Codex, Grok, Kimi) use the relaxed tier, so
under `dangerous-only` the hook only denies; confirmation comes from each
host's native rules. Regenerate them with `print-native-rules` after the
launcher points at 0.5.0, and remove the old entries — the host applies the
strictest matching rule, so a stale broad prompt keeps prompting.

- **Codex** keeps only the ask-level prefixes: trunk `branch -d/-D <main|master>`,
  `checkout -B <main|master>`, `switch -C <main|master>`, `reset --hard
  <origin/>main|master`, `config --global/--system`, `lfs install/migrate/uninstall`,
  `submodule foreach`, `rebase -x/--exec/--reschedule-failed-exec`,
  `push --mirror/--prune`. Removed: `gh repo delete` (hook deny now),
  `branch -D/-M/-C`, `worktree remove`, `worktree add -B`, every `clean`,
  `reset`, `restore`, `checkout`, `rm`, `stash`, `tag`, `switch` discard prefix,
  `lfs prune`, `push --delete/-d`.
- **Grok and Kimi** keep a medium list: the Codex list plus the discard
  family (`git clean`, `git checkout`, `git reset`, `git restore`, `git rm`,
  `stash drop/clear`, `tag -f/--force`, `switch --discard-changes/-f/--force`,
  `worktree remove --force/-f`) and destructive SQL clients. Removed:
  `branch -D/-M/-C`, plain `worktree remove`, `worktree add -B`, `lfs prune`,
  `push --delete/-d`, `gh repo delete`, broad `chmod` and `gh api`.

With `legacy-dangerous` or `full` the hook still emits confirmations; on
Codex/Grok/Kimi in strict mode those that no 0.5 native prefix covers fail
closed (deny) with a `[guard-diagnostic]` marker, as in 0.4.

Codex native delegation failures in strict mode include a `[guard-diagnostic]` JSON marker with
`reasonCode`, `ruleId` and `decisionSource`, without adding unsupported fields to
the host hook schema. Codes distinguish disabled delegation, unsupported shell
shape, and uncovered native prefixes. For Git rules the message
explains that `require_escalated` does not bypass hooks: use the tool's `workdir`,
one static command, and separate subsequent status/read commands. Hard denials do
not receive this recovery advice. `resolveDecision()` also exposes a typed
`reasonCode` for consumers.

### Changes in 0.5.0

- Relaxed `dangerous-only`: working-tree discards, non-trunk ref changes,
  `chmod 777` and generic `gh api` DELETE no longer confirm; ask-level rules
  confirm only in Claude bypass sessions.
- New hard denies: `rm-git-dir`, `rm-protected-path`, `git-clean-root`,
  `push-delete-trunk`, `gh-api-delete-protected`; `gh repo delete` upgraded to
  deny; `rm-protected-root` resolves relative targets against the hook cwd and
  covers ancestors of protected roots.
- Bypass sessions: `bypass-no-project-sandbox` and
  `unsandboxed-outside-project`.
- `unsandboxed.jsonl` log; `protectedPaths` config; `legacy-dangerous` profile.
- The `git-destructive` rule id is split into `git-discard`, `git-trunk-ref`,
  `git-ref-change`, `git-config-global`, `git-lfs`, `git-exec`,
  `git-push-bulk`.
