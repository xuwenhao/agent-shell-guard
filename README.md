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
  "protectedRoots": ["~/Codebase"]
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
AGENT_SHELL_GUARD_NATIVE_PROMPT_CODEX
AGENT_SHELL_GUARD_NATIVE_PROMPT_GROK
AGENT_SHELL_GUARD_NATIVE_PROMPT_KIMI
AGENT_SHELL_GUARD_REVIEWER_COMMAND
AGENT_SHELL_GUARD_REVIEWER_MODEL
AGENT_SHELL_GUARD_REVIEWER_TIMEOUT_MS
```

## Policy profiles

- `dangerous-only`: hard safety boundaries plus a small set of destructive
  confirmation rules.
- `full`: all bundled confirmation and review rules.
- `off`: disables policy rules, but parser infrastructure failure still denies.

Both the CLI configuration and direct library calls default to
`dangerous-only`. This profile intentionally leaves explicit force pushes to a
known non-main ref and `git reset --hard origin/<non-main>` to the host's own
approval layer; `full` adds guard-level confirmation for them. A force push
whose target ref cannot be resolved remains a hard deny.

`git checkout` is classified by its arguments, not by its name. Creating a branch
(`-b` / `-B` / `--orphan`) or an explicit ref intent (`--detach`, `--track`) is
left to the host's approval layer; everything else that can replace working-tree
content stays destructive: `--`, `.`, `--force`, `--ours`, `--theirs`, `--merge`,
`-p`, `--pathspec-from-file`, a second positional, a glob or `:`-magic pathspec,
an unresolvable operand — and a lone operand with no branch-intent flag, because
git resolves it against both refs and paths and nothing static can settle which.
A filesystem probe in particular cannot: a tracked file that has been deleted is
still a valid pathspec while it does not exist on disk. Short options are split from their
operand the way git does — `-qB main`, `-Bmain` and `-qBmain` all yield the
branch name — so force-creating a trunk branch is never mistaken for a plain
switch, and an operand's letters are never mistaken for more flags.
`--pathspec-from-file` is destructive in its own right: it restores every path
listed in the file without a positional argument to notice it by. `git worktree remove` is only
destructive when `--force` is used on a path outside a throwaway location
(`.worktrees/`, `.claude/worktrees/`, `/tmp` — a bare `worktrees/` component is
not enough), because git itself refuses to drop
a dirty worktree otherwise. `git branch -d/-D` is destructive only for `main` /
`master` or an unresolvable branch name; deleting a task branch leaves the
commits reachable through the reflog.

Targets and endpoints written as `$VAR` are resolved when the assignment sits on
the same straight line of the same script (`S=/tmp/x; rm -rf "$S/art"`). Only
top-level statements and the *left* side of `&&` / `||` count as straight line:
their right side is conditional, and a pipeline subshells **both** sides, so
neither `S=$HOME; false && S=/tmp/safe; rm -rf "$S"` nor `S=/root; S=/tmp | cat;
rm -rf "$S"` may resolve to the assignment that never reached the command.
Assignments inside `if` / `for` / `while` / `case` / functions / subshells,
`NAME=value cmd` prefixes, appends, and every other channel that writes a shell
variable — `read`, `unset`, `mapfile`, `getopts`, `printf -v NAME`, and the
assigning expansions `${name=…}` / `${name:=…}` — poison the name for the same
reason. `eval`, `source` and `.` drop every binding in the script, since they
execute in the current shell and may rebind a name already resolved.

A resolved value is only used when it survives the shell's own word processing:
an *unquoted* expansion is field-split and globbed, so a value carrying
whitespace or a glob character is not the single argument being judged
(`S='/root /tmp/safe'; rm -rf $S` removes two paths). Quoted expansions, and
unquoted ones whose value is a single plain word, resolve normally.

Resolved paths are lexically normalized (`.` and `..` collapsed, no filesystem
access) before any protected-root comparison, so `S=/tmp/../root` is judged as
`/root`.

A word that stays unresolved may still be judged by its literal tail, but only
when no protected root ends with that tail: `"$SCRATCH/issue-1055"` is provably
not a root, while `"$BASE/alice"` can *be* `/home/alice`, and `"$X"`, `"$X/.."`,
`"$X/*"` and `"$X"base` can be anything. All of those remain denied.

`off` does not disable the parser health check: without a reliable command graph,
the guard cannot prove that hard-deny rules were not bypassed.

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
