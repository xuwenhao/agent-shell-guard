# Releasing

Releases are published from `.github/workflows/publish.yml` when a GitHub
Release is published. The release tag must exactly match the package version,
with a `v` prefix.

## First publish

The npm package must exist before npm Trusted Publishing can be configured.
Bootstrap the first publish with a short-lived granular npm token:

1. Create a granular npm token for the `xuwenhao` scope with package
   read/write access, a short expiration, and 2FA bypass for automation.
2. Add it as the `NPM_TOKEN` Actions secret in
   `xuwenhao/agent-shell-guard`.
3. Confirm `package.json` is at version `0.1.0` on `main`.
4. Publish the GitHub Release `v0.1.0`. The workflow runs tests, validates the
   tag, and publishes the public package with provenance.
5. Verify the published package:

   ```bash
   npm view @xuwenhao/agent-shell-guard version
   npm install --global @xuwenhao/agent-shell-guard@0.1.0
   agent-shell-guard doctor
   ```

## Switch to Trusted Publishing

After the first package version exists:

1. Open the package settings on npmjs.com and add a GitHub Actions Trusted
   Publisher:
   - organization or user: `xuwenhao`
   - repository: `agent-shell-guard`
   - workflow filename: `publish.yml`
   - environment: leave blank
   - allowed action: `npm publish`
2. Delete the repository's `NPM_TOKEN` Actions secret.
3. Set npm publishing access to require 2FA and disallow tokens.

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
