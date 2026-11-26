# Verifying releases

`cargo binstall` checks a release download over TLS only, with no signature.
Each release also publishes a `SHA256SUMS` manifest, a
[cosign](https://docs.sigstore.dev/cosign/system_config/installation/) keyless
signature bundle for each archive and for `SHA256SUMS`, and SLSA build
provenance. Signing requires five archives and the manifest as regular files.
Before publication, a job without signing credentials verifies all six bundles
with cosign v3.1.4 against the exact files, workflow identity, issuer, and SHA.
Missing, duplicate, extra, symlinked, or non-file bundles fail the release.
Crate publication verifies these six bundles again from the published GitHub
Release. It verifies SLSA signatures for all five archives with slsa-verifier
v2.7.1, whose binary must match the pinned SHA-256 before execution.
Its compile-free `release-evidence` job requires a successful Release run for
the same tag and commit. The provenance names that run and an attempt no
later than its latest. The job also checks the tagged Wasm tree offline.
It refuses drafts and any release asset inventory beyond the five manifest
archives, `SHA256SUMS`, their six bundles, and the provenance file.
The checks on this page use them to confirm that an archive is the one this repository's release
workflow built. The commands name the `.tar.xz` archive; for the Windows
archive, substitute `.zip`.

## Check the SHA256SUMS manifest

Download `SHA256SUMS` from the same release as the archive. On Linux:

```bash
sha256sum --ignore-missing --check SHA256SUMS
```

On macOS:

```bash
shasum -a 256 --ignore-missing --check SHA256SUMS
```

On Windows, the PowerShell steps in
[Download an archive directly](getting-started.md#download-an-archive-directly)
compare `Get-FileHash -Algorithm SHA256` with the archive's entry in
`SHA256SUMS` before they call `Expand-Archive`.

## Verify the cosign signature

The keyless signature shows that this repository's release workflow signed the
archive. The certificate identity names that workflow at the release tag, so a
signature from any other identity fails the check. Read `<commit>` with
`git rev-parse v<version>^{commit}` in a clone to bind the certificate to that
commit. The workflow uses `${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}` for the
repository URL, `${GITHUB_REF}` for the tag ref, and `$GITHUB_SHA` for the commit.
Signing and verification both install cosign v3.1.4. The verification script
requires a non-empty identity, issuer, and workflow SHA:

```bash
cosign verify-blob \
  --bundle stellar-agent-<version>-<target>.tar.xz.sigstore.json \
  --certificate-identity "https://github.com/Soneso/stellar-agent-wallet/.github/workflows/release.yml@refs/tags/v<version>" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --certificate-github-workflow-sha <commit> \
  stellar-agent-<version>-<target>.tar.xz
```

## Verify the SLSA provenance

[slsa-verifier](https://github.com/slsa-framework/slsa-verifier) checks that
this repository's release workflow built the archive from the tagged commit:

```bash
slsa-verifier verify-artifact stellar-agent-<version>-<target>.tar.xz \
  --provenance-path stellar-agent-<version>.intoto.jsonl \
  --source-uri github.com/Soneso/stellar-agent-wallet \
  --source-tag v<version>
```

[Releasing](maintainers/releasing.md#jobs-and-credentials) describes the
release jobs that build, sign, and attest these files.
