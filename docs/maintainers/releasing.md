# Releasing

See [Mainnet configurations and scope](../getting-started.md#mainnet-configurations-and-scope)
for build configuration, admitted operations, and exclusions.

This page covers cutting a release tag, the checks the release and publish
workflows run, the GitHub settings they rely on, and the crates.io publish
dispatch.

## Cut a release tag

1. Merge the release preparation into `main` through a pull request. It bumps
   the workspace version and every internal dependency pin (see
   [Building and testing](building.md)) and adds a `## [<version>]` heading to
   `CHANGELOG.md`.
2. Wait for CI to pass on that `main` commit.
3. From a checkout of that commit, check the workspace members on crates.io:

   ```bash
   .github/scripts/check-crates-exist.sh
   ```

   The script exits 1 and names every publishable member missing on
   crates.io. The publish run halts at each of them, so have the crates.io
   token for each first upload ready, as
   [Publish a new crate for the first time](#publish-a-new-crate-for-the-first-time)
   describes.
4. Tag that commit and push the tag:

   ```bash
   git fetch origin
   git tag v<version> origin/main
   git push origin v<version>
   ```

The tag push starts `.github/workflows/release.yml`. Tag only a commit on
`main`: the preflight refuses any other commit. The `preflight` job runs the
same script with `--warn`, annotates the run with one warning per missing
member, and the release proceeds.

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
| `release.yml` | `vendored-wasm` | none | yes |
| `release.yml` | `build` | none | yes |
| `release.yml` | `sign-macos` | Apple secrets of `release-signing` | no |
| `release.yml` | `verify-packaged` | none | no |
| `release.yml` | `verify-provenance` | none | no |
| `release.yml` | `hashes` | none | no |
| `release.yml` | `sign` | OIDC token for cosign | no |
| `release.yml` | `provenance` | OIDC token, `contents: write` | no |
| `release.yml` | `publish` | `contents: write` | no |
| `publish.yml` | `verify` | none | yes |
| `publish.yml` | `publish` | OIDC token for crates.io, in `crates-io` | no |
| `publish.yml` | `verify-install` | none | yes |
| `notarize-smoke.yml` | `build` | none | yes |
| `notarize-smoke.yml` | `sign` | Apple secrets of `release-signing` | no |
| `release-rehearsal.yml` | `build` | none | yes |
| `release-rehearsal.yml` | `verify-packaged` | none | no |
| `release-rehearsal.yml` | `verify-crates` | none | yes |

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
turn off errexit, or chain a check with a shell operator, and a line before a
check that ends in `&&`, `||`, `|`, or `|&` fails the check. An inline comment
after the operator, as in `false && # note`, hides the operator from that
test, so the check on the next line is counted although the shell may skip it
or pipe into it. A function defined earlier in the step that shadows the
checked command, such as `bash() { return 0; }`, makes the check count a call
that runs the function.

The same check holds every job of `release-rehearsal.yml` to a token that
reads the repository contents and nothing else, with no environment, no
secret, and no expression that reads the workflow token. Both build jobs must
call the shared build, Perl and libsodium scripts under `.github/scripts/release/`.
The build immediately follows the environment setup, and its first action
checks compiler overrides and cargo configuration files.

Each release verification step must run its check as an unconditional
command: the archive check, the provenance content and source discipline
checks, the packaged marker check, and the install check. A comment, an
operator that ignores the status, or a condition fails the check. The
verification jobs hold no publishing or signing credential, their token has
`contents: read`, and they download the run's artifacts and the registry
dependencies. The archive checks run on a runner of each release target, and
the rehearsal packages with the toolchain that `publish.yml` packages with.
The feature jobs of `ci.yml` run unconditionally and run their defining
commands.

The `release-cache` rule refuses cache actions in the release and rehearsal.
Both build cold from locked sources. The `release-toolchain` rule requires
both builds to install `RELEASE_TOOLCHAIN` and pin `RUSTUP_TOOLCHAIN` before
compilation, with the same value as `publish.yml`.

The `release-wasm-gate` rule requires `hashes` and `publish` to depend on the
local vendored Wasm workflow call, without conditions, inputs, or secrets, so
signing, provenance, and publication wait for the rebuild. The called
workflow declares `workflow_call`; every cache step starts its condition with
`github.ref_type != 'tag'`. Its rebuild runs exactly when the tree check asks
for one, reads both stellar-cli artifacts of its own run, uses no cache, and
rebuilds and compares unconditionally. No job or step of it continues on an
error, and no step of the tree check, the rebuild, or the gate suppresses a
failure. The gate job runs on `always()`, needs the four other jobs, and runs
the gate command with each job result and the run's ref type. On a tag the
gate passes only after a rebuild.

The `release-publish-sums` rule requires an unconditional checksum check before
publication. The archives under `all-artifacts` must equal `SHA256SUMS` by
name, count, and digest.

The `sign-macos` job receives the unsigned binaries as a tar.
`.github/scripts/validate-unsigned-archive.py` refuses the tar unless it holds
exactly the two binaries as regular files, each a thin Mach-O executable for
the target. The job then signs, notarizes, and packs the archive through the
composite action in `.github/actions/macos-sign-notarize/`.

The Windows build leg links libsodium from `libsodium-1.0.22-stable-msvc.zip`,
and `.github/scripts/release/sodium.sh` pins its SHA-256 in
`SODIUM_MSVC_SHA256`. Upstream replaces that stable archive in place when the
stable branch moves, and the Windows build then fails at the sodium step. To
update the pin, download the archive and its `.minisig` from the URL that
`sodium.sh` uses, verify the signature with the key that
`libsodium-sys-stable` embeds in its build script, and set
`SODIUM_MSVC_SHA256` to the archive's digest. A `libsodium-sys-stable` update
that changes the libsodium version changes the file names and the pin
together.

```sh
base=https://download.libsodium.org/libsodium/releases
curl --fail --location --remote-name "$base/libsodium-1.0.22-stable-msvc.zip"
curl --fail --location --remote-name "$base/libsodium-1.0.22-stable-msvc.zip.minisig"
minisign -Vm libsodium-1.0.22-stable-msvc.zip -P RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3
sha256sum libsodium-1.0.22-stable-msvc.zip
```

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

To bump it, change `RELEASE_TOOLCHAIN` in `publish.yml`, `release.yml`, and
`release-rehearsal.yml` in one pull request and merge it before the dispatch.
`rustup check` and `https://static.rust-lang.org/dist/channel-rust-stable.toml`
show the current stable release.

## Publish to crates.io

Dispatch the publish workflow from `main` after the release workflow
succeeded:

```bash
gh workflow run publish.yml --ref main -f tag=v<version>
```

- `verify` checks out the tag and runs `cargo package --workspace --locked`,
  which builds and packages every workspace member, the unpublished
  acceptance member included. It uploads the archive checksums as
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
`publish-crates.sh` must match the tag's publishable workspace members, so a
tag with another member set stops before any upload. Every tag up to
`v0.1.0-alpha.9` has another member set, so none of them can be published
again through this workflow.

## Publish a new crate for the first time

Trusted Publishing updates crates that exist on crates.io, and it cannot
create a crate. The `publish` job therefore halts at every new publishable
workspace member, with the crates.io answer "Trusted Publishing tokens do not
support creating new crates". A maintainer then uploads that crate once by
hand:

1. On Linux or macOS, clone the tagged commit with LF line endings. The `-c`
   option sets `core.autocrlf` to `false` before the checkout:

   ```bash
   git clone -c core.autocrlf=false --branch v<version> https://github.com/Soneso/stellar-agent-wallet.git
   cd stellar-agent-wallet
   ```

2. Package the crate with the toolchain that `publish.yml` on `main` pins as
   `RELEASE_TOOLCHAIN`, since the publish run uses the workflow and scripts of
   `main`:

   ```bash
   cargo +<RELEASE_TOOLCHAIN> package -p <crate> --no-verify --locked
   ```

3. Download the `verify-sums` artifact of the halted run and compare the
   archive with its line in `SHA256SUMS`. `<run-id>` is the number at the end
   of the run's URL:

   ```bash
   gh run download <run-id> -n verify-sums -D ../verify-sums
   expected=$(awk '$2 == "<crate>-<version>.crate" { print $1 }' ../verify-sums/SHA256SUMS)
   actual=$(sha256sum target/package/<crate>-<version>.crate | cut -d ' ' -f 1)
   if [ -n "$expected" ] && [ "$actual" = "$expected" ]; then echo match; else echo MISMATCH; fi
   ```

   On a mismatch, stop. A published version is immutable, so fix the checkout
   or the toolchain first. The artifact expires after seven days. A dispatch
   of the same tag with `-f verify_only=true` records it again.
4. A maintainer who owns the crates creates a crates.io API token scoped to
   `publish-new` and the crate name. They log in with `cargo login` in a
   terminal of their own and upload the crate from the same checkout:

   ```bash
   cargo +<RELEASE_TOOLCHAIN> publish -p <crate> --no-verify --locked
   ```

5. On crates.io, add the owners `soneso-crates` and
   `github:soneso:crates-owners` to the crate.
6. Add the trusted publisher: repository `Soneso/stellar-agent-wallet`,
   workflow `publish.yml`, environment `crates-io`.
7. Turn on "Require trusted publishing" for the crate.
8. Revoke the token on crates.io and run `cargo logout`.
9. Confirm the upload. The script exits 0:

   ```bash
   .github/scripts/check-crates-exist.sh <crate>
   ```

10. Dispatch the same tag again. The run resumes at that crate: every crate
    already on crates.io passes when its checksum matches.

## Rehearse the release build

```bash
gh workflow run release-rehearsal.yml --ref <branch>
```

The rehearsal builds the five release targets of `release.yml` from the head
of `<branch>`, with no tag. Each target builds on the runner the release uses,
with the release's setup steps and its build command. The version is the
`stellar-agent-cli` version of that checkout. The run packs one archive per
target as the release does and uploads each as the artifact
`rehearsal-<target>`, kept for 7 days. The macOS archives are unsigned and not
notarized, and the run hashes, attests, and publishes nothing.

The workflow holds no credential: its token reads the repository contents and
nothing else. The release and rehearsal restore and save no cache, so both
build cold from locked sources.

GitHub runs a `workflow_dispatch` workflow only once its file exists on the
default branch. From then on, `--ref` selects any branch that holds the file,
and the run uses that branch's workflow file and tree.

## Run the notarization smoke

```bash
gh workflow run notarize-smoke.yml --ref main
```

Run it from `main` after rotating the Developer ID certificate or the App
Store Connect API key, and before the first release that relies on either.
The build job builds `aarch64-apple-darwin` with no secrets. The sign job runs
in `release-signing`, signs and notarizes the binaries with the version
`0.0.0-smoke`, and checks the archive layout and the signature authority.

### Feature-state checks

Release, publish and rehearsal expect `mainnet-write` to be on. The shared
build script runs the environment guard immediately before the release recipe.
Archive verification executes both packaged binaries and checks their embedded
markers. Archive and host checks also refuse either test-override literal,
`STELLAR_AGENT_HOME` or `STELLAR_AGENT_TEST_`. Hashing depends on archive
verification and on the vendored Wasm rebuild of the tagged commit, so
signing and provenance wait for that rebuild. Publication depends on the
provenance content check, the source discipline check, and the rebuild.

The publish verification job checks the binaries produced from unpacked crate
sources, including their freshness. The install check runs only after a real
publish, retries index propagation a bounded number of times, and verifies both
installed binaries. It holds no publishing credential.

The checks that the ruleset of `main` requires include the five feature jobs
of `ci.yml`: `feature-on-clippy`, `feature-on-test`, `feature-on-doc`,
`feature-discipline`, and `release-shape`. The `coverage` required check
measures and enforces both feature configurations.
