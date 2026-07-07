# OZ multisig-ed25519-verifier-example v0.7.2 — vendored WASM provenance

- **Source:** OpenZeppelin/stellar-contracts at SHA `a9c42169000638da937577f592ebf61a7a3c94ca`
  (tag `v0.7.2`, repo `https://github.com/OpenZeppelin/stellar-contracts`).
- **Package name:** `multisig-ed25519-verifier-example` (per
  `examples/multisig-smart-account/ed25519-verifier/Cargo.toml`).  The compiled WASM
  filename derives from the package name: `multisig_ed25519_verifier_example.wasm`.
  Do NOT rename the file without re-running this build.sh step and updating this
  PROVENANCE.md.
- **Build host:** macOS (Apple Silicon, Darwin 25.3.0).
- **Toolchain:** rustc 1.96.0 (ac68faa20 2026-05-25) — stable channel as declared in
  `rust-toolchain.toml` in the OpenZeppelin stellar-contracts repository; `wasm32v1-none` target.
- **Build command:** `stellar contract build --package multisig-ed25519-verifier-example`
  (stellar-cli 25.2.0) inside a local clone of the OpenZeppelin stellar-contracts repository
  (https://github.com/OpenZeppelin/stellar-contracts) at v0.7.2.
  See `vendor/oz-ed25519-verifier/v0.7.2/build.sh` for the full reproducibility script
  including the EXIT-trap HEAD-restoration discipline.
- **stellar-cli version:** `stellar 25.2.0` (captured at build time; pin this specific
  version so `experimental_spec_shaking_v2` behaviour is reproducible).
- **Optimiser version:** not used; `wasm-opt` was not available on the build host.
  The artefact is the `release` profile output (`stellar contract build` release mode).
  `stellar contract build` applies spec-shaking internally when the OZ workspace enables
  `experimental_spec_shaking_v2`; the result is a self-contained deployable WASM with no
  external `contractspecv0` dependency.
- **sha256(multisig_ed25519_verifier_example.wasm):**
  `ea13b07083a8275e7bade954e4ccc1827495f253c18dc06edcc49104c11fb725`
- **Size:** 1 972 bytes.
- **Exported functions** (`Verifier` trait impl per
  `examples/multisig-smart-account/ed25519-verifier/src/contract.rs:14-70` at SHA `a9c4216`):
  - `verify(signature_payload: Bytes, key_data: BytesN<32>, sig_data: BytesN<64>) -> bool` —
     the Ed25519 signature-verification entry point.  `key_data` is exactly the raw
     32-byte Ed25519 public key (nothing appended — no credential-id, no XDR ceremony
     blob, unlike the WebAuthn verifier).  `sig_data` is exactly the raw 64-byte Ed25519
     signature.  `signature_payload` is verified as-is.  Body delegates to
     `stellar_accounts::verifiers::ed25519::verify`
     (`packages/accounts/src/verifiers/ed25519.rs:31-40`, SHA `a9c4216`), which calls
     `e.crypto().ed25519_verify(public_key, signature_payload, signature)` — a standard
     Ed25519 verification of the signature over `signature_payload` with no additional
     hashing or wrapping.
  - `canonicalize_key(key_data: BytesN<32>) -> Bytes` — returns the 32-byte key
     verbatim as `Bytes` (the Ed25519 public-key encoding is already canonical).
  - `batch_canonicalize_key(keys_data: Vec<BytesN<32>>) -> Vec<Bytes>` — batch variant
     of `canonicalize_key`.
- **How the wallet uses it:** an Ed25519-backed `Signer::External(verifier, key_data)`
  in an installed context rule names this verifier address; the 32-byte `key_data` is the
  agent's raw Ed25519 public key.  At signing time the smart-account's `__check_auth`
  invokes `verify(signature_payload, key_data, sig_data)` where `signature_payload` is the
  raw 32-byte `auth_digest` (`storage.rs:346`, `sig_payload = auth_digest.to_bytes()`) and
  `sig_data` is the raw 64-byte Ed25519 signature the agent produced over that digest.
  There is no nested host-level auth entry for an External signer (unlike a Delegated
  signer, which requires a separate `SorobanAuthorizationEntry` for its G-key); possession
  is proven entirely inside the WASM-to-WASM call to this verifier
  (`packages/accounts/src/smart_account/storage.rs:341-355`, SHA `a9c4216`).
- **Why deployable (release/), not deps/:** This contract is deployed on-chain via
  `UploadContractWasm` and called by the smart-account's `__check_auth` to verify Ed25519
  signatures at signing time.  On-chain storage cost scales with size; the `release`
  profile output is the production deployment artefact.  The wallet does not
  `contractimport!` against this WASM; invocations are typed Soroban calls into the
  deployed verifier from the smart account itself.
- **Cross-reference:** `vendor/oz-webauthn-verifier/v0.7.2/multisig_webauthn_verifier_example.wasm`
  is the deployable WebAuthn-verifier contract (the other `Verifier` implementation).
  This ed25519-verifier artefact is deployed via `smart-account deploy-ed25519-verifier`.
- **Integrity gate (CI side):** CI re-hashes the in-repo WASM against the SHA-256 in this
  `PROVENANCE.md` at every run (iterates `vendor/*/v*/PROVENANCE.md` with per-file
  expected-SHA extraction).  This catches uncoordinated mutation of the WASM.  The defence
  against coordinated mutation is the Rust compile-time SHA pin in
  `crates/stellar-agent-smart-account/src/ed25519_verifier.rs`
  (`ED25519_VERIFIER_WASM_SHA256` const + unit tests) and the `build.rs` WASM pin.  The
  verifier's wasm hash is also pinned in `verifier_allowlist.rs` so install-time gates
  trust an External signer that references this verifier.
- **Reproducibility caveat:** Rust → WASM compilation is **not always bit-identical**
  across patch-version drifts of `rustc` or `stellar-cli`.  If the CI gate flags a
  benign drift after a toolchain bump, the response is to bump the toolchain pin in
  this PROVENANCE.md (with operator authorisation), re-vendor, and re-attest — NOT to
  silently accept the diff.
