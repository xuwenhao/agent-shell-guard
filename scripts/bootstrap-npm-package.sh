#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

EXPECTED_NAME="@xuwenhao83/agent-shell-guard"
EXPECTED_VERSION="0.1.0"
EXPECTED_ACCOUNT="xuwenhao83"

if [[ "$(git branch --show-current)" != "main" ]]; then
  echo "error: bootstrap publish must run from main" >&2
  exit 1
fi

if [[ -n "$(git status --porcelain)" ]]; then
  echo "error: working tree must be clean" >&2
  exit 1
fi

git fetch --quiet origin main
if [[ "$(git rev-parse HEAD)" != "$(git rev-parse origin/main)" ]]; then
  echo "error: local main is not identical to origin/main; run git pull --ff-only" >&2
  exit 1
fi

PACKAGE_NAME="$(node -p "require('./package.json').name")"
PACKAGE_VERSION="$(node -p "require('./package.json').version")"
if [[ "$PACKAGE_NAME" != "$EXPECTED_NAME" || "$PACKAGE_VERSION" != "$EXPECTED_VERSION" ]]; then
  echo "error: expected $EXPECTED_NAME@$EXPECTED_VERSION, got $PACKAGE_NAME@$PACKAGE_VERSION" >&2
  exit 1
fi

NPM_ACCOUNT="$(npm whoami 2>/dev/null || true)"
if [[ "$NPM_ACCOUNT" != "$EXPECTED_ACCOUNT" ]]; then
  echo "error: npm account must be $EXPECTED_ACCOUNT; run npm login first" >&2
  exit 1
fi

npm ping >/dev/null

VIEW_ERROR="$(mktemp)"
trap 'rm -f "$VIEW_ERROR"' EXIT
if npm view "$PACKAGE_NAME@$PACKAGE_VERSION" version --json >/dev/null 2>"$VIEW_ERROR"; then
  echo "$PACKAGE_NAME@$PACKAGE_VERSION is already published; nothing to do"
  exit 0
fi
if ! grep -qE 'E404|404 Not Found' "$VIEW_ERROR"; then
  cat "$VIEW_ERROR" >&2
  echo "error: could not confirm that the package version is unpublished" >&2
  exit 1
fi

npm ci
if ! node src/cli.mjs doctor; then
  node src/cli.mjs setup
fi
npm pack --dry-run

CONFIRMATION="publish $PACKAGE_NAME@$PACKAGE_VERSION"
printf 'Type "%s" to publish the public npm package: ' "$CONFIRMATION"
read -r ANSWER
if [[ "$ANSWER" != "$CONFIRMATION" ]]; then
  echo "publish cancelled"
  exit 1
fi

# The local bootstrap cannot create GitHub OIDC provenance. Later releases
# override this through the trusted GitHub Actions workflow.
npm publish --access public --provenance=false
