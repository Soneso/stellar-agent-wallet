# multicall v0.1.0: vendored Wasm provenance

- **Ported from:** the router of `https://github.com/stellar/smart-wallet-demo-app`,
  `contracts/router/src/lib.rs` at commit `8f4bfdcd3a60d125073534db298de2f297001bb4`.
  That file names its own base: Creit Tech's Stellar-Router-Contract at commit
  `04975c434dec362584aa99458ae2c25d803ec570`.
- **Source of this build:** not in this repository, so this file cannot be rebuilt
  from it. The upstream router at that commit pins soroban-sdk 22.0.8 and does not
  build these bytes.
- **Toolchain and SDK:** the file's own `contractmetav0` custom section records
  `rsver` = `1.94.0` (the rustc version) and `rssdkver` =
  `25.3.0#dcbea44513feb7734af6b6c4aced2c4a7a2715d0` (the soroban-sdk version and
  commit). `stellar contract info meta --wasm multicall.wasm` prints both.
- **sha256(multicall.wasm):**
  `267e94a092df01fa02ad4edf8320a98bd65e4d4d6575254ac9521cb65727f3d4`
- **Size:** 11825 bytes.
- **Where the digest is pinned:** the `multicall.wasm` row of `WASM_PINS` in
  `crates/stellar-agent-smart-account/build.rs`, the `MULTICALL_WASM_SHA256`
  constant in `src/multicall.rs`, and the exception list of
  `.github/scripts/rebuild-vendored-wasm.sh`, which holds this file at this
  digest.
- **Integrity:** the `vendored-wasm` workflow does not rebuild this file. Its
  tree check fails unless the file's sha256 equals the digest in this record,
  its `WASM_PINS` row, and the frozen digest of the exception list. The
  `WASM_PINS` row also fails every build of the crate on a mismatch. The unit
  test `multicall_wasm_sha256_matches_provenance` fails unless
  `MULTICALL_WASM` hashes to `MULTICALL_WASM_SHA256`. The unit tests in
  `src/vendored_wasm_tests.rs` fail unless `MULTICALL_WASM` equals this file and
  `MULTICALL_WASM_SHA256` equals its sha256. Every pin of this digest lives in
  this repository; no source the repository holds reproduces it.
