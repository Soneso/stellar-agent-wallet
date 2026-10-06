# Verifying releases

`cargo binstall` checks a release download over TLS only, with no signature.
Each release also publishes a `SHA256SUMS` manifest, a
[cosign](https://docs.sigstore.dev/cosign/system_config/installation/) keyless
signature bundle per archive, and SLSA build provenance. The checks on this
page use them to confirm that an archive is the one this repository's release
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
signature from any other identity fails the check:

```bash
cosign verify-blob \
  --bundle stellar-agent-<version>-<target>.tar.xz.sigstore.json \
  --certificate-identity "https://github.com/Soneso/stellar-agent-wallet/.github/workflows/release.yml@refs/tags/v<version>" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
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
