# OZ multisig-webauthn-verifier-example v0.7.2 — vendored WASM provenance

- **Source:** OpenZeppelin/stellar-contracts at SHA `a9c42169000638da937577f592ebf61a7a3c94ca`
  (tag `v0.7.2`, repo `https://github.com/OpenZeppelin/stellar-contracts`).
- **What changed vs v0.7.1:** v0.7.2 bumps `soroban_sdk` to 26.1.0 (upstream
  `Context`-type fix, `rs-soroban-sdk#1875`). The contract source
  (`examples/multisig-smart-account/webauthn-verifier/src/contract.rs`) is byte-identical
  to v0.7.1; only the SDK pin changed, so the exported `Verifier` surface and ABI are
  unchanged. The WASM bytes differ only because of the toolchain and SDK bump. Verifier
  contracts already deployed on-chain from the v0.7.1 bytes remain recognised (their hash
  stays in `VERIFIER_ALLOWLIST`); only NEW deployments use these v0.7.2 bytes.
- **Package name:** `multisig-webauthn-verifier-example` (per
  `examples/multisig-smart-account/webauthn-verifier/Cargo.toml`).  The compiled WASM
  filename derives from the package name: `multisig_webauthn_verifier_example.wasm`.
  Do NOT rename the file without re-running this build.sh step and updating this
  PROVENANCE.md.
- **Build host:** macOS (Apple Silicon, Darwin 25.3.0).
- **Toolchain:** rustc 1.96.0 (ac68faa20 2026-05-25) — stable channel as declared in
  `rust-toolchain.toml` in the OpenZeppelin stellar-contracts repository; `wasm32v1-none` target.
- **Build command:** `stellar contract build --package multisig-webauthn-verifier-example`
  (stellar-cli 25.2.0) inside a local clone of the OpenZeppelin stellar-contracts repository
  (https://github.com/OpenZeppelin/stellar-contracts) at v0.7.2.
  See `vendor/oz-webauthn-verifier/v0.7.2/build.sh` for the full reproducibility script
  including the EXIT-trap HEAD-restoration discipline.
- **stellar-cli version:** `stellar 25.2.0` (captured at build time; pin this specific
  version so `experimental_spec_shaking_v2` behaviour is reproducible).
- **Optimiser version:** not used; `wasm-opt` was not available on the build host.
  The artefact is the `release` profile output (`stellar contract build` release mode).
  `stellar contract build` applies spec-shaking internally when the OZ workspace enables
  `experimental_spec_shaking_v2`; the result is a self-contained deployable WASM with no
  external `contractspecv0` dependency.
- **sha256(multisig_webauthn_verifier_example.wasm):**
  `9427e3dd71fb29115c6f0efdf2f703b32fec566b151421f991c3b4e248ebb1f7`
- **Size:** 14 097 bytes.
- **Exported functions** (`Verifier` trait impl per
  `examples/multisig-smart-account/webauthn-verifier/src/contract.rs:51-90`):
  - `verify(signature_payload: Bytes, key_data: Bytes, sig_data: Bytes) -> bool` —
     the WebAuthn-2 P-256 assertion verification entry point.
     - `key_data` is the concat of a 65-byte uncompressed-SEC1 P-256 pubkey
       (`0x04 ‖ X ‖ Y`) and the variable-length credential_id (the suffix is
       unused inside `verify` and is what `canonicalize_key` strips).
     - `sig_data` is an XDR-encoded `WebAuthnSigData { authenticator_data,
       client_data_json, signature }` blob.
     - Body: extracts the 65-byte pubkey from `key_data`, decodes `sig_data`
       via `WebAuthnSigData::from_xdr`, then delegates to
       `stellar_accounts::verifiers::webauthn::verify` (at
       `packages/accounts/src/verifiers/webauthn.rs:302-355`, SHA `a9c4216`)
       which validates `client_data.type == "webauthn.get"`,
       `client_data.challenge == base64url(signature_payload)`, the `UP` (and
       `UV` if required) flag bits in `authenticator_data`, and the
       ECDSA-P-256 signature over `authenticator_data ‖ sha256(client_data_json)`.
  - `canonicalize_key(key_data: Bytes) -> Bytes` — returns the 65-byte
     uncompressed-SEC1 P-256 pubkey prefix of `key_data`, stripping the
     credential_id suffix which is not part of the cryptographic identity.
  - `batch_canonicalize_key(keys_data: Vec<Bytes>) -> Vec<Bytes>` — batch
     variant of `canonicalize_key`.
- **Why deployable (release/), not deps/:** This contract is deployed on-chain via
  `UploadContractWasm` and called by the smart-account's `__check_auth` to validate
  WebAuthn signatures.  On-chain storage cost scales with size; the `release` profile
  output is the production deployment artefact.  Off-chain type-binding parity is NOT
  a requirement — the wallet does not `contractimport!` against this WASM; the
  invocation is a typed Soroban call to `verify(...)` from `__check_auth`.
- **Cross-reference:** `vendor/oz-stellar-accounts/v0.7.2/stellar_accounts.wasm` is the
  contracts-library WASM used for `contractimport!`-based type bindings.
  `vendor/oz-smart-account-multisig/v0.7.2/multisig_account_example.wasm` is the
  deployable smart-account contract.  This WebAuthn-verifier artefact is the third
  vendored OZ WASM; it is deployed once per network and referenced by the `External`
  signer arm's `verifier` field in installed context rules.
- **Verifier allowlist posture:** this v0.7.2 hash is `VERIFIER_ALLOWLIST[0]`
  (`VerifierAuditStatus::Provisional { attested_by: "OpenZeppelin", attested_at: "2026-07-04" }`
  — an OZ internal artefact review; no external audit report yet), the entry the
  deploy CLI uploads for new verifiers; the v0.7.1 hash remains at index 1
  (`Provisional { attested_by: "OpenZeppelin", attested_at: "2025-11-01" }`) as a
  still-recognised legacy entry.
- **24-month retention policy:** `VERIFIER_ALLOWLIST` entries are never dropped
  immediately on revocation. `Revoked` entries persist for at least 24 months, then
  rotate to `Retired`, so operators running older wallet releases still receive the
  startup advisory before silently losing protection.
- **Integrity gate (CI side):** CI re-hashes the in-repo WASM against the SHA-256 in this
  `PROVENANCE.md` at every run. This catches uncoordinated mutation of the WASM, such as
  a commit that changes WASM bytes without updating `PROVENANCE.md`. It does not catch
  coordinated mutation, where both the WASM and `PROVENANCE.md` change in the same commit.
  The defence against coordinated mutation is the Rust compile-time SHA pin in
  `crates/stellar-agent-smart-account/src/webauthn_verifier.rs` (`include_bytes!` +
  `WEBAUTHN_VERIFIER_WASM_SHA256` const + unit tests) and `build.rs`.
- **Reproducibility caveat:** Rust → WASM compilation is **not always bit-identical**
  across patch-version drifts of `rustc` or `stellar-cli`.  If the CI gate flags a
  benign drift after a toolchain bump, the response is to bump the toolchain pin in
  this PROVENANCE.md (with operator authorisation), re-vendor, and re-attest — NOT to
  silently accept the diff.
