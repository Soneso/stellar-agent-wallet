# Releasing

This page covers cutting a release tag, the checks the release and publish
workflows run, the GitHub settings they rely on, and the crates.io publish
dispatch.

## Cut a release tag

1. Merge the release preparation into `main` through a pull request. It bumps
   the workspace version and every internal dependency pin (see
   [Building and testing](building.md)) and adds a `## [<version>]` heading to
   `CHANGELOG.md`.
2. Wait for CI to pass on that `main` commit.
3. Tag that commit and push the tag:

   ```bash
   git fetch origin
   git tag v<version> origin/main
   git push origin v<version>
   ```

The tag push starts `.github/workflows/release.yml`. Tag only a commit on
`main`: the preflight refuses any other commit.

## What the release preflight refuses

The `preflight` job runs before any build. It stops the release when any of
these holds:

- The tag name does not match `v<major>.<minor>.<patch>`, with an optional
  `-<prerelease>` suffix of letters, digits, and dots.
- The tagged commit is not an ancestor of `origin/main`
  (`.github/scripts/check-ref-on-main.sh`).
- A workspace member's version differs from the tag.
- A workspace member's `repository` differs from this repository's URL.
- `CHANGELOG.md` has no heading for the version.
- The documented install surface fails
  `.github/scripts/check-install-surface.py`.
- `cargo deny check` fails.
- The checkout has uncommitted or untracked files.

A tag push runs the `release.yml` of the tagged commit. These checks therefore
bind only tags whose commit carries them. The settings in
[GitHub settings](#github-settings) bind the rest.

## Jobs and credentials

No job that holds a credential compiles code or runs dependency code.

| Workflow | Job | Credential | Compiles code |
|---|---|---|---|
| `release.yml` | `preflight` | none | no |
| `release.yml` | `build` | none | yes |
| `release.yml` | `sign-macos` | Apple secrets of `release-signing` | no |
| `release.yml` | `hashes` | none | no |
| `release.yml` | `sign` | OIDC token for cosign | no |
| `release.yml` | `provenance` | OIDC token, `contents: write` | no |
| `release.yml` | `publish` | `contents: write` | no |
| `publish.yml` | `verify` | none | yes |
| `publish.yml` | `publish` | OIDC token for crates.io, in `crates-io` | no |
| `notarize-smoke.yml` | `build` | none | yes |
| `notarize-smoke.yml` | `sign` | Apple secrets of `release-signing` | no |

A credentialed job downloads artifacts of other jobs under the runner's temp
directory and reads them as data. It reads outputs of other jobs only through
environment variables that it validates against a fixed pattern. The
`provenance` job is the exception. It calls the reusable SLSA generator
workflow, which has no step to validate its inputs, and passes it the
subjects that the `hashes` job computes and the version that the preflight
validates.

In CI, `.github/scripts/check-workflow-invariants.py` checks where these jobs
download artifacts and where they read outputs of other jobs. It requires a
step that reads such an output to hold a regular-expression test. It also
finds the following checks by their command text. The signing jobs must
check the checkout after the download, validate the unsigned binaries, and
check the checkout again before they sign. The publish job must check the
checkout after the download and run the ancestry, checksum, and toolchain
checks. It must check the checkout again after the checksum comparison and
before it mints the registry token. None of these steps may be conditional,
turn off errexit, or chain a check with a shell operator.

The `sign-macos` job receives the unsigned binaries as a tar.
`.github/scripts/validate-unsigned-archive.py` refuses the tar unless it holds
exactly the two binaries as regular files, each a thin Mach-O executable for
the target. The job then signs, notarizes, and packs the archive through the
composite action in `.github/actions/macos-sign-notarize/`.

## GitHub settings

The repository owner applies these settings. A workflow that references a
missing environment makes GitHub create it without protection rules, so apply
them before the next release.

- A tag ruleset on `refs/tags/v*` that restricts creations, updates, and
  deletions, with a bypass list of release maintainers only.
- The `release-signing` environment:
  - The five secrets `APPLE_DEVELOPER_ID_P12`,
    `APPLE_DEVELOPER_ID_P12_PASSWORD`, `APPLE_ASC_API_KEY_P8`,
    `APPLE_ASC_KEY_ID`, and `APPLE_ASC_ISSUER_ID` as environment secrets.
  - The repository copies of those secrets deleted. A repository secret
    reaches every job in the repository.
  - Required reviewers.
  - Deployment refs limited to tags `v*` and the branch `main`.
- The `crates-io` environment: deployment branches limited to `main`, and
  required reviewers.

On crates.io, the trusted publisher of every crate must name `publish.yml`
and the `crates-io` environment. A run outside that environment then cannot
mint a registry token.

When more than one maintainer can approve, also enable "Prevent self-review"
on both environments.

Apply the `release-signing` settings in this order:

1. Create the environment and add the five secrets.
2. Set the required reviewers and the deployment refs.
3. Delete the repository copies of the secrets.
4. Run the notarization smoke from `main`.

## Bump the publish toolchain

`publish.yml` sets `RELEASE_TOOLCHAIN` to an exact Rust release. Both publish
jobs install that release and set `RUSTUP_TOOLCHAIN` to it. The publish job
refuses any other `cargo` or `rustc` version, since the archive bytes can
depend on the cargo version.

To bump it, change the value in a pull request and merge it before the
dispatch. `rustup check` and
`https://static.rust-lang.org/dist/channel-rust-stable.toml` show the current
stable release.

## Publish to crates.io

Dispatch the publish workflow from `main` after the release workflow
succeeded:

```bash
gh workflow run publish.yml --ref main -f tag=v<version>
```

- `verify` checks out the tag and runs `cargo package --workspace --locked`,
  which builds and packages every crate. It uploads the archive checksums as
  `SHA256SUMS` and holds no credential.
- `publish` starts after the `crates-io` approval. It regenerates the archives
  without building and requires them to equal `SHA256SUMS`. It then mints a
  short-lived token through Trusted Publishing and uploads each crate with
  `cargo publish --no-verify`.
- After each upload, and for each crate crates.io already holds, the publish
  job requires crates.io to serve the checksum that `SHA256SUMS` records. A
  different checksum halts the run and prints both values.
- After a partial run, dispatch the same tag again. A crate already on
  crates.io passes when its checksum matches.

`-f verify_only=true` runs only `verify`, for example to rehearse a tag before
the approval.

Both jobs package the tag's tree and run the scripts of the commit the
dispatch runs on, which is `main` for a publish. The tier lists in
`publish-crates.sh` must match the tag's workspace members, so a tag with
another member set stops before any upload. Every tag up to `v0.1.0-alpha.9`
has another member set, so none of them can be published again through this
workflow.

## Run the notarization smoke

```bash
gh workflow run notarize-smoke.yml --ref main
```

Run it from `main` after rotating the Developer ID certificate or the App
Store Connect API key, and before the first release that relies on either.
The build job builds `aarch64-apple-darwin` with no secrets. The sign job runs
in `release-signing`, signs and notarizes the binaries with the version
`0.0.0-smoke`, and checks the archive layout and the signature authority.
