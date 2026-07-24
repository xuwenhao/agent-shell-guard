# Releasing

Releases are published from `.github/workflows/publish.yml` when a GitHub
Release is published. The release tag must exactly match the package version,
with a `v` prefix.

## First publish

The npm package must exist before npm Trusted Publishing can be configured.
Bootstrap the first publish interactively from a clean `main` checkout:

1. Confirm `package.json` is named `@xuwenhao83/agent-shell-guard` at version
   `0.1.0`.
2. Authenticate interactively:

   ```bash
   npm login
   ```

3. Run the guarded bootstrap script:

   ```bash
   bash scripts/bootstrap-npm-package.sh
   ```

   It verifies the branch, clean worktree, remote commit, npm account, package
   identity, unpublished version, tests, and package contents before asking for
   an exact confirmation. The bootstrap explicitly disables provenance because
   local publishing cannot use GitHub OIDC; later workflow releases include
   provenance automatically.
4. Verify the published package:

   ```bash
   npm view @xuwenhao83/agent-shell-guard version
   npm install --global @xuwenhao83/agent-shell-guard@0.1.0
   agent-shell-guard doctor
   ```

## Switch to Trusted Publishing

After the first package version exists:

1. Open
   <https://www.npmjs.com/package/@xuwenhao83/agent-shell-guard/access>,
   find **Trusted publishing**, and add a GitHub Actions publisher:
   - organization or user: `xuwenhao`
   - repository: `agent-shell-guard`
   - workflow filename: `publish.yml`
   - environment: leave blank
   - allowed actions: `npm publish`
2. Set npm publishing access to require 2FA and disallow tokens.
3. Publish the GitHub Release `v0.1.0`. The workflow validates the tag and
   detects that the bootstrap version already exists without republishing it.

Future publishes use GitHub OIDC with short-lived credentials and automatic
provenance.

## Later releases

1. Update the package version without creating a local tag:

   ```bash
   npm version patch --no-git-tag-version
   ```

   Use `minor` or `major` when appropriate.
2. Open and merge the version bump PR after CI passes.
3. Publish a GitHub Release whose tag is exactly `v<package version>`.
4. Verify the npm version and provenance after the publish workflow succeeds.
