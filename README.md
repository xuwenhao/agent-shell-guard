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

`git checkout` is classified by its arguments, not by its name. Creating a
branch (`-b` / `--orphan`) or an explicit ref intent (`--detach`/`-d`,
`--track`/`-t`, `--no-track` — the flags git itself refuses to pair with a path;
`--guess` is not one of them) is left to the host's approval layer; everything else that can replace
working-tree content stays destructive: `--`, `.`, `--force`, `--ours`,
`--theirs`, `--merge`, `--conflict`, `-p`, `--pathspec-from-file`, a second positional, a glob
or `:`-magic pathspec, an unresolvable operand — and a lone operand with no
branch-intent flag, because git resolves it against both refs and paths and
nothing static can settle which. A filesystem probe in particular cannot: a
tracked file that has been deleted is still a valid pathspec while it does not
exist on disk. Short options are split from their operand the way git does —
`-qB main`, `-Bmain` and `-qBmain` all yield the branch name, and `-d` is read as
`--detach` under `checkout` but `--delete` under `branch`. `-B` always stays destructive, including literal non-trunk targets and attached
or bundled forms: resetting an existing branch can discard its previous tip.


Long options are matched by prefix, because git accepts any unambiguous
abbreviation: `git worktree remove --for`, `git branch --del`, `git push --for`
and `git checkout --pathspec-from-f=` all reach the full option. Prefix matching
can only put more commands in the destructive class; the flags that *loosen* a
classification (checkout's ref intent) keep their exact spelling, so
an abbreviation there simply fails to loosen.

`git worktree remove` stays destructive whatever the path looks like: git follows
a symlinked path to the real worktree, and it deletes gitignored files (`.env`,
`.venv`) even without `--force` — both verified on git 2.43 — so nothing in the
argv proves where the removal lands or what it discards, and this guard has no
filesystem access to find out. `git branch -d` is destructive only for `main` / `master` or an
unresolvable branch name, since git itself refuses to `-d` an unmerged branch.
`-D` stays destructive in every case: it deletes unmerged work and removes the
branch's own reflog along with it.

Protected-root comparisons lexically normalize the path first (`.` and `..`
collapsed, no filesystem access), so `rm -rf /tmp/../root` is judged as `/root`.
`gh api` org-ruleset detection accepts a full URL as well as a path, and
canonicalizes it first — host case-folded, trailing dot and an explicit `:443`
dropped — so `https://API.GITHUB.COM/orgs/<org>/rulesets` matches too.

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

### Codex 0.4 native-rule migration

Update the guard **before** replacing Codex native rules, and generate the matching
prompt entries with `agent-shell-guard print-native-rules codex`. Do not remove the
old broad rules while an older guard is still deployed. Verify the stable launcher
points at the installed 0.4.0 package; installing into a different Node prefix is
not sufficient. This repository does not publish or replace a live installation
as part of tests.

The `git clean` and `git checkout` catch-all prompt entries are replaced by exact
first-argument prefixes. All other Codex native entries are unchanged; Kimi and Grok retain their broad
clean/checkout confirmation entries and need no native-rule migration:

- `git clean`: `-f`, `--force`, `-i`, `--interactive`.
- `git checkout`: `--`, `-f`, `--force`, `--ours`, `--theirs`, `-m`, `--merge`,
  `-p`, `--patch`, `-B`, `--pathspec-from-file`.

Under the default `dangerous-only` profile, explicit static `git clean -n` /
`--dry-run` is read-only, including `-fn` / `-ndfx`. Exclude-pattern operands and
paths after `--` cannot supply the dry-run flag. Dynamic arguments, interactive
mode, abbreviations and unrecognized options do not qualify. The guard still
examines other commands in compound scripts. Put `--dry-run` first to avoid a
remaining `git clean --force` native prompt: the host chooses the strictest
matching rule even when a later option makes a command read-only.

Checkout keeps its parameter-based classification: explicit static `-b`,
`--detach`, `--track` and `--no-track` can identify branch intent. A bare operand
is still ambiguous with a path; force/pathspec options and dynamic operands stay
protected. `-B` is now always destructive, including literal non-trunk targets that older
core versions considered low-risk. Exact `-B` retains a native prompt; attached
and bundled forms fail closed. Existing accepted branch-switch behavior for
ignored files is unchanged.

`--conflict` (which selects merge conflict handling) also stays destructive even
when combined with branch-intent flags.

Some dangerous forms that previously matched a catch-all prompt now **deny** in
strict mode, for example `git clean -df`, `git checkout tracked.txt`, abbreviated
options or flags placed after a safe first argument. This is deliberate: no
uncovered destructive operation silently delegates. Use standard independently
reviewable commands where authorized; for path restoration prefer the existing
`git restore` prompt path. Do not rewrite hard denials to evade policy.

Checkout parsing treats `--track[=(direct|inherit)]` as an optional attached value;
it never consumes a following `--force` or `-f`. Negated branch-intent flags
`--no-detach` / `--no-orphan` remain destructive: they can cancel an earlier
branch intent and make a trailing operand restore a path. Short `-2` / `-3`
are protected just like `--ours` / `--theirs`. Real temporary-repository tests
cover this destructive combination and prove ref-intent flags reject tracked-file
restoration rather than discarding dirty content.

Codex delegation failures now include a `[guard-diagnostic]` JSON marker with
`reasonCode`, `ruleId` and `decisionSource`, without adding unsupported fields to
the host hook schema. Codes distinguish disabled delegation, unsupported shell
shape, and uncovered native prefixes. For authorized Git operations the message
explains that `require_escalated` does not bypass hooks: use the tool's `workdir`,
one static command, and separate subsequent status/read commands. Hard denials do
not receive this recovery advice. `resolveDecision()` also exposes a typed
`reasonCode` for consumers.
