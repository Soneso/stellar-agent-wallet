# OZ multisig-ed25519-verifier-example v0.7.2: vendored Wasm provenance

- **Source:** `https://github.com/OpenZeppelin/stellar-contracts`, tag `v0.7.2`,
  commit `a9c42169000638da937577f592ebf61a7a3c94ca`.
- **Package:** `multisig-ed25519-verifier-example`
  (`examples/multisig-smart-account/ed25519-verifier/Cargo.toml`). The Wasm file
  name derives from the package name. Renaming the file takes a rebuild with
  `build.sh` and an update of this record.
- **Toolchain:** `rustc 1.96.0 (ac68faa20 2026-05-25)`, selected with
  `RUSTUP_TOOLCHAIN=1.96.0`, since the OZ `rust-toolchain.toml` names the
  floating `stable` channel. Target `wasm32v1-none`.
- **stellar-cli:** the first line of `stellar --version` is `stellar 25.2.0`.
  The binary is built by `cargo install --locked --path cmd/stellar-cli` from a
  `git archive` of stellar-cli tag `v25.2.0` (commit
  `28484880988199233a7e8e87c97cb12dac323cb3`) with host rustc 1.94.0, outside
  any git work tree. Its `cliver` meta entry then reads `25.2.0#`. A crates.io
  install of 25.2.0 records its revision in `cliver`, which adds 40 bytes.
- **Build command:** in a checkout of the source commit, with `RUSTFLAGS` unset,
  `RUSTUP_TOOLCHAIN=1.96.0 stellar contract build --locked --package multisig-ed25519-verifier-example`.
  The output is `<target dir>/wasm32v1-none/release/multisig_ed25519_verifier_example.wasm`.
  `build.sh` beside this record runs this build and copies the output here.
- **Optimizer:** none. stellar-cli 25.2.0 bundles `wasm-opt` and runs it only
  with `--optimize`, which this build does not pass. The `release/` output
  differs from cargo's `deps/` output only by the CLI's `contractspecv0`
  filtering (spec shaking, which the OZ workspace enables with
  `experimental_spec_shaking_v2`) and its meta entries. The result is a
  self-contained deployable Wasm.
- **Build host:** macOS (Apple Silicon, Darwin 25.3.0). The bytes reproduce
  byte for byte on macOS (Apple Silicon); a rebuild on Linux is not tested.
- **sha256(multisig_ed25519_verifier_example.wasm):**
  `ea13b07083a8275e7bade954e4ccc1827495f253c18dc06edcc49104c11fb725`
- **Size:** 1 972 bytes.
- **Exported functions** (`Verifier` trait impl per
  `examples/multisig-smart-account/ed25519-verifier/src/contract.rs:14-70` at commit `a9c4216`):
  - `verify(signature_payload: Bytes, key_data: BytesN<32>, sig_data: BytesN<64>) -> bool`:
     the Ed25519 signature-verification entry point. `key_data` is exactly the raw
     32-byte Ed25519 public key, with nothing appended (no credential ID and no XDR
     ceremony blob, unlike the WebAuthn verifier). `sig_data` is exactly the raw 64-byte
     Ed25519 signature. `signature_payload` is verified as-is. The body delegates to
     `stellar_accounts::verifiers::ed25519::verify`
     (`packages/accounts/src/verifiers/ed25519.rs:31-40`, commit `a9c4216`), which calls
     `e.crypto().ed25519_verify(public_key, signature_payload, signature)`: a standard
     Ed25519 verification of the signature over `signature_payload` with no additional
     hashing or wrapping.
  - `canonicalize_key(key_data: BytesN<32>) -> Bytes`: returns the 32-byte key
     verbatim as `Bytes` (the Ed25519 public-key encoding is already canonical).
  - `batch_canonicalize_key(keys_data: Vec<BytesN<32>>) -> Vec<Bytes>`: batch variant
     of `canonicalize_key`.
- **How the wallet uses it:** an Ed25519-backed `Signer::External(verifier, key_data)`
  in an installed context rule names this verifier address; the 32-byte `key_data` is the
  agent's raw Ed25519 public key. At signing time the smart account's `__check_auth`
  invokes `verify(signature_payload, key_data, sig_data)`. There `signature_payload` is
  the raw 32-byte `auth_digest` (`storage.rs:346`, `sig_payload = auth_digest.to_bytes()`),
  and `sig_data` is the raw 64-byte Ed25519 signature the agent produced over that digest.
  An External signer has no nested host-level auth entry (a Delegated signer requires a
  separate `SorobanAuthorizationEntry` for its G-key); possession is proven entirely
  inside the Wasm-to-Wasm call to this verifier
  (`packages/accounts/src/smart_account/storage.rs:341-355`, commit `a9c4216`).
- **Why deployable (release/), not deps/:** the wallet uploads this contract with
  `UploadContractWasm`, and the smart account's `__check_auth` calls it to verify Ed25519
  signatures at signing time. On-chain storage cost scales with size; the `release`
  output is the production deployment artifact. The wallet does not
  `contractimport!` against this Wasm; the smart account itself makes typed Soroban
  calls into the deployed verifier.
- **Cross-reference:** `vendor/oz-webauthn-verifier/v0.7.2/multisig_webauthn_verifier_example.wasm`
  is the deployable WebAuthn-verifier contract (the other `Verifier` implementation).
  The wallet deploys this Ed25519 verifier with `smart-account deploy-ed25519-verifier`.
- **Integrity:** the `vendored-wasm` workflow rebuilds this file from the
  source commit with the pinned toolchain and stellar-cli, and fails unless the
  rebuilt bytes equal this file. Its tree check fails unless the file's sha256
  equals the digest in this record and the file's `WASM_PINS` row in `build.rs`.
  That row also fails every build of the crate on a mismatch. The unit tests in
  `src/vendored_wasm_tests.rs` fail unless `ED25519_VERIFIER_WASM` equals this
  file, `ED25519_VERIFIER_WASM_SHA256` equals its sha256, and the third
  production entry of `VERIFIER_ALLOWLIST` equals that sha256.
- **Reproducibility:** Rust to Wasm builds are not bit-identical across rustc or
  stellar-cli versions, so this record pins both. A rebuild with any other
  version is a re-vendor that replaces the file, this record, and every pin of
  its digest in one change.
