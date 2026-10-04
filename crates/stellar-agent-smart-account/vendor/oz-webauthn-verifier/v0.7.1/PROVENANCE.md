# OZ multisig-webauthn-verifier-example v0.7.1: vendored Wasm provenance

- **Source:** `https://github.com/OpenZeppelin/stellar-contracts`, tag `v0.7.1`,
  commit `3f81125bed3114cc93f5fca6d13240082050269a`.
- **Package:** `multisig-webauthn-verifier-example`
  (`examples/multisig-smart-account/webauthn-verifier/Cargo.toml`). The Wasm file
  name derives from the package name. Renaming the file takes a rebuild with
  `build.sh` and an update of this record.
- **Toolchain:** `rustc 1.94.0 (4a4ef493e 2026-03-02)`, selected with
  `RUSTUP_TOOLCHAIN=1.94.0`, since the OZ `rust-toolchain.toml` names the
  floating `stable` channel. Target `wasm32v1-none`.
- **stellar-cli:** the first line of `stellar --version` is `stellar 25.2.0`.
  The binary is built by `cargo install --locked --path cmd/stellar-cli` from a
  `git archive` of stellar-cli tag `v25.2.0` (commit
  `28484880988199233a7e8e87c97cb12dac323cb3`) with host rustc 1.94.0, outside
  any git work tree. Its `cliver` meta entry then reads `25.2.0#`. A crates.io
  install of 25.2.0 records its revision in `cliver`, which adds 40 bytes.
- **Build command:** in a checkout of the source commit, with `RUSTFLAGS` unset,
  `RUSTUP_TOOLCHAIN=1.94.0 stellar contract build --locked --package multisig-webauthn-verifier-example`.
  The output is `<target dir>/wasm32v1-none/release/multisig_webauthn_verifier_example.wasm`.
  `build.sh` beside this record runs this build and copies the output here.
- **Optimizer:** none. stellar-cli 25.2.0 bundles `wasm-opt` and runs it only
  with `--optimize`, which this build does not pass. The `release/` output
  differs from cargo's `deps/` output only by the CLI's `contractspecv0`
  filtering (spec shaking, which the OZ workspace enables with
  `experimental_spec_shaking_v2`) and its meta entries. The result is a
  self-contained deployable Wasm.
- **Build host:** macOS (Apple Silicon, Darwin 25.3.0). The bytes reproduce
  byte for byte on macOS (Apple Silicon); a rebuild on Linux is not tested.
- **sha256(multisig_webauthn_verifier_example.wasm):**
  `678006909b50c6c365c033f137197e910d8396a2c68e9281327a2ed7dbf4b27a`
- **Size:** 12 696 bytes.
- **Exported functions** (`Verifier` trait impl per
  `examples/multisig-smart-account/webauthn-verifier/src/contract.rs:51-90`):
  - `verify(signature_payload: Bytes, key_data: Bytes, sig_data: Bytes) -> bool`:
     the WebAuthn-2 P-256 assertion verification entry point.
     - `key_data` is the concatenation of a 65-byte uncompressed-SEC1 P-256 pubkey
       (`0x04 ‖ X ‖ Y`) and the variable-length credential_id (the suffix is
       unused inside `verify` and is what `canonicalize_key` strips).
     - `sig_data` is an XDR-encoded `WebAuthnSigData { authenticator_data,
       client_data_json, signature }` blob.
     - Body: extracts the 65-byte pubkey from `key_data`, decodes `sig_data`
       with `WebAuthnSigData::from_xdr`, then delegates to
       `stellar_accounts::verifiers::webauthn::verify` (at
       `packages/accounts/src/verifiers/webauthn.rs:302-355`, commit `3f81125`).
       That function validates `client_data.type == "webauthn.get"`,
       `client_data.challenge == base64url(signature_payload)`, and the `UP` (and
       `UV` if required) flag bits in `authenticator_data`. It then verifies the
       ECDSA-P-256 signature over `authenticator_data ‖ sha256(client_data_json)`.
  - `canonicalize_key(key_data: Bytes) -> Bytes`: returns the 65-byte
     uncompressed-SEC1 P-256 pubkey prefix of `key_data`, stripping the
     credential_id suffix, which is not part of the cryptographic identity.
  - `batch_canonicalize_key(keys_data: Vec<Bytes>) -> Vec<Bytes>`: batch
     variant of `canonicalize_key`.
- **Why deployable (release/), not deps/:** verifier contracts deployed on-chain from
  these bytes validate WebAuthn signatures when a smart account's `__check_auth` calls
  them. On-chain storage cost scales with size; the `release` output is the production
  deployment artifact. The wallet does not `contractimport!` against this Wasm, and
  `__check_auth` makes a typed Soroban call to `verify(...)`.
- **Cross-reference:** `vendor/oz-stellar-accounts/v0.7.1/stellar_accounts.wasm` is the
  v0.7.1 contracts-library Wasm. `vendor/oz-smart-account-multisig/v0.7.1/multisig_account_example.wasm`
  is the v0.7.1 smart-account contract. New verifier deployments use the v0.7.2 bytes;
  this hash stays at `VERIFIER_ALLOWLIST[1]` so verifiers deployed from these bytes
  remain recognized.
- **Integrity:** the `vendored-wasm` workflow rebuilds this file from the
  source commit with the pinned toolchain and stellar-cli, and fails unless the
  rebuilt bytes equal this file. Its tree check fails unless the file's sha256
  equals the digest in this record. `build.rs` carries no `WASM_PINS` row for
  this file, since the package excludes the v0.7.1 files and `build.rs` runs
  during `cargo package` verification. The unit tests in `src/vendored_wasm_tests.rs` fail unless
  `VERIFIER_ALLOWLIST[1]` equals this file's sha256.
- **Reproducibility:** Rust to Wasm builds are not bit-identical across rustc or
  stellar-cli versions, so this record pins both. A rebuild with any other
  version is a re-vendor that replaces the file, this record, and every pin of
  its digest in one change.
