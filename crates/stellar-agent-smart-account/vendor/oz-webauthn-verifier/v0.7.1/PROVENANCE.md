# OZ multisig-webauthn-verifier-example v0.7.1 — vendored WASM provenance

- **Source:** OpenZeppelin/stellar-contracts at SHA `3f81125bed3114cc93f5fca6d13240082050269a`
  (tag `v0.7.1`, repo `https://github.com/OpenZeppelin/stellar-contracts`).
- **Package name:** `multisig-webauthn-verifier-example` (per
  `examples/multisig-smart-account/webauthn-verifier/Cargo.toml`).  The compiled WASM
  filename derives from the package name: `multisig_webauthn_verifier_example.wasm`.
  Do NOT rename the file without re-running this build.sh step and updating this
  PROVENANCE.md.
- **Build host:** macOS (Apple Silicon, Darwin 25.3.0).
- **Toolchain:** rustc 1.94.0 (4a4ef493e 2026-03-02) — stable channel as declared in
  `rust-toolchain.toml` in the OpenZeppelin stellar-contracts repository; `wasm32v1-none` target.
- **Build command:** `stellar contract build --package multisig-webauthn-verifier-example`
  (stellar-cli 25.2.0) inside a local clone of the OpenZeppelin stellar-contracts repository
  (https://github.com/OpenZeppelin/stellar-contracts) at v0.7.1.
  See `vendor/oz-webauthn-verifier/v0.7.1/build.sh` for the full reproducibility script
  including the EXIT-trap HEAD-restoration discipline.
- **stellar-cli version:** `stellar 25.2.0` (captured at build time; pin this specific
  version so `experimental_spec_shaking_v2` behaviour is reproducible).
- **Optimiser version:** not used; `wasm-opt` was not available on the build host.
  The artefact is the `release` profile output (`stellar contract build` release mode).
  `stellar contract build` applies spec-shaking internally when the OZ workspace enables
  `experimental_spec_shaking_v2`; the result is a self-contained deployable WASM with no
  external `contractspecv0` dependency.
- **sha256(multisig_webauthn_verifier_example.wasm):**
  `678006909b50c6c365c033f137197e910d8396a2c68e9281327a2ed7dbf4b27a`
- **Size:** 12 696 bytes.
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
       `packages/accounts/src/verifiers/webauthn.rs:302-355`, SHA `3f81125`)
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
- **Cross-reference:** `vendor/oz-stellar-accounts/v0.7.1/stellar_accounts.wasm` is the
  contracts-library WASM used for `contractimport!`-based type bindings.
  `vendor/oz-smart-account-multisig/v0.7.1/multisig_account_example.wasm` is the
  deployable smart-account contract.  This WebAuthn-verifier artefact is the third
  vendored OZ WASM; it is deployed once per network and referenced by the `External`
  signer arm's `verifier` field in installed context rules.
- **Integrity gate (CI side):** CI re-hashes the in-repo WASM against the SHA-256 in this
  `PROVENANCE.md` at every run. This catches uncoordinated mutation of the WASM, such as
  a commit that changes WASM bytes without updating `PROVENANCE.md`. It does not catch
  coordinated mutation, where both the WASM and `PROVENANCE.md` change in the same commit.
  The defence against coordinated mutation is the Rust compile-time SHA pin in
  `crates/stellar-agent-smart-account/src/webauthn_verifier.rs` (`include_bytes!` +
  `WEBAUTHN_VERIFIER_WASM_SHA256` const + unit tests).
- **Reproducibility caveat:** Rust → WASM compilation is **not always bit-identical**
  across patch-version drifts of `rustc` or `stellar-cli`.  If the CI gate flags a
  benign drift after a toolchain bump, the response is to bump the toolchain pin in
  this PROVENANCE.md (with operator authorisation), re-vendor, and re-attest — NOT to
  silently accept the diff.
