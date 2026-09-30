# Building and testing

This guide is for maintainers and contributors building the `stellar-agent-wallet`
workspace and running the gates every change must pass. The workspace is a Cargo
workspace of `stellar-agent-*` crates that produces two binaries: `stellar-agent`
(the CLI, from crate `stellar-agent-cli`) and `stellar-agent-mcp` (the MCP stdio
server, from crate `stellar-agent-mcp`). For the crate layout and dependency
layering, see [architecture.md](architecture.md).

## Prerequisites

### Toolchain

The toolchain is pinned in `rust-toolchain.toml`:

```toml
[toolchain]
channel = "stable"
components = ["rustfmt", "clippy"]
profile = "default"
```

The channel is `stable` (not a fixed version). With `rustup` installed, the pinned
channel and the `rustfmt` and `clippy` components are provisioned automatically on
first build in the workspace. Run `rustup update stable` before a gate pass so
`clippy` matches the latest stable lints.

The workspace targets Rust edition 2024.

### Gate tools

The gate suite uses three auxiliary Cargo subcommands. Install them with:

```bash
cargo install cargo-llvm-cov
cargo install cargo-machete
cargo install cargo-deny
```

`cargo-llvm-cov` also needs the `llvm-tools-preview` rustup component:

```bash
rustup component add llvm-tools-preview
```

## Building

Build the whole workspace:

```bash
cargo build
```

Release build:

```bash
cargo build --release
```

A release build (no `--all-targets`) surfaces dead code that a test-targets build
can mask, so run it before sealing a change.

### Platform note: `windows-identity`

`stellar-agent-windows-identity` reads the process-token user SID to bind approval
attestations to the OS user. Its Win32 FFI dependency (`windows-sys`) is gated under
`[target.'cfg(target_os = "windows")'.dependencies]`, and `stellar-agent-core`
depends on the crate only under the same `cfg(target_os = "windows")` gate. On
macOS and Linux the crate compiles to a dependency-free shim whose lookup returns
a `WindowsIdentityError::UnsupportedPlatform` error and pulls in no Win32
dependency, so nothing extra is required to build the workspace off Windows.

## Gate suite

Every change is reviewed for production readiness and must pass all of the gates
below before commit. They mirror the build-gate dimension of the
[review checklist](review-checklist.md); run them locally before requesting review.

### Format

```bash
cargo fmt --all -- --check
```

Run `cargo fmt --all` immediately before staging; late edits made after an earlier
format pass otherwise slip through and fail the format gate.

### Lint

```bash
cargo clippy --all-targets --all-features -- -D warnings
```

Warnings are denied. The workspace lints (declared in the root `Cargo.toml`)
already deny `unsafe_code`, `missing_docs`, the full clippy `all` group, and the
restriction lints `unwrap_used`, `expect_used`, `panic`, `print_stdout`,
`print_stderr`, and `dbg_macro`, among others. Run clippy unscoped (not
`-p <crate>`) so new rustdoc and public-API lints are caught across the workspace.

### Test

```bash
cargo test --all-features
```

This runs unit, integration, and doc-tests. `--all-features` enables every crate
feature across the workspace, including each crate's `testnet-acceptance` feature
(see [Test tiers](#test-tiers)), so the live tests compile in and attempt testnet
RPC and Friendbot access. Those tests self-skip with an early return only when the
network is unreachable. For a strictly offline run, use plain `cargo test` (no
`--features`).

### Coverage

```bash
cargo llvm-cov --workspace --features test-helpers,test-hooks,test-loopback,verifier-registry --json --output-path cov.json
python3 .github/scripts/check-coverage.py cov.json
```

The enforced gate is the per-crate floor set in
`.github/scripts/check-coverage.py`: a default floor of 85% offline line
coverage, with explicit lower floors for the crates whose remaining lines are
live-network or on-chain paths exercised only by the `testnet-acceptance` /
`testnet-integration` suites (which do not run in this offline gate). The
floors are a regression ratchet, set a few points below each crate's current
offline coverage, and 90% per crate remains the aspirational target new code
is reviewed against. The measurement uses the offline feature set (deliberately not
`--all-features`, which would compile in the live tiers and attempt real RPC
and Friendbot access).

### Unused dependencies

```bash
cargo machete
```

Fails on any declared-but-unused dependency.

### License and advisory check

```bash
cargo deny check
```

See [Licenses](#licenses) for the allow-list posture.

### Windows storage regression (CI-only)

CI runs a `windows-storage` job on a Windows runner covering the storage
behaviors that differ on Windows and cannot be exercised locally on
macOS/Linux: the audit-log module (including the writer's sidecar-lock
semantics, where `LockFileEx` on the log file itself would block readers) and
the approval / toolset-grant store persistence tests, scoped to
`stellar-agent-core`. There is no local equivalent off Windows; changes to
`audit_log`, the approval store, or file-locking behavior should expect this
job to be the deciding signal.

## Test tiers

Tests fall into two tiers, selected by per-crate Cargo features.

### Offline tests

Unit, integration, and doc-tests run with no network access. They are the default
under `cargo test`. The feature flags that gate the offline test surface, all
declared on individual crates (and on `stellar-agent-test-support`), are:

- `test-helpers` — exposes test-only helpers and fixtures. Must not be enabled in
  production builds.
- `test-hooks` — test-only observation and fault-injection hooks in
  `stellar-agent-network` and `stellar-agent-nonce`.
- `test-loopback` — loopback-listener test surface in `stellar-agent-network`.
- `testnet-helpers` — keypair generation, Friendbot HTTP, and live-network client
  helpers in `stellar-agent-test-support`. Pulled in transitively by the
  `testnet-acceptance` feature of the crates that submit on-chain.
- `verifier-registry` — temp-dir-backed verifier-registry fixtures in
  `stellar-agent-test-support`.
- `wiremock-helpers` — `wiremock`-based HTTP doubles in
  `stellar-agent-test-support`.

The CI `test (offline)` and coverage jobs run the offline tier with
`--features test-helpers,test-hooks,test-loopback,verifier-registry`.

MPP development should run its focused protocol/security suite and both binary
adapters before the full workspace gates:

```bash
cargo test -p stellar-agent-mpp
cargo test -p stellar-agent-core -p stellar-agent-approval-ui \
  -p stellar-agent-approval-remote
cargo test -p stellar-agent-cli -p stellar-agent-mcp
bash .github/scripts/publish-crates.sh --check
bash .github/scripts/test-publish-crates-check.sh
bash .github/scripts/package-skill.sh --check
bash .github/scripts/check-no-direct-sasignersetbaselined-emit.sh
bash .github/scripts/test-check-no-direct-sasignersetbaselined-emit.sh
```

Release preparation must bump the workspace and every internal dependency pin
to the next unpublished version before verifying the packaged MPP crate with
`cargo package -p stellar-agent-mpp`. Before that bump, Cargo correctly resolves
the already-published registry copies of the current-version `core` and
`network` crates during package verification; those copies do not contain the
new MPP APIs. `cargo package -p stellar-agent-mpp --no-verify` may be used on the
feature branch to inspect the source archive, but it is not a substitute for
the post-bump verification.

MPP storage uses the same cross-platform locking contract as the approval and
policy stores. Windows CI must cover MPP state lock contention, atomic replace,
symlink/reparse-point refusal, tamper failure, and restart behavior whenever the
store changes. The new crate has an explicit coverage floor and a 90% offline
target; live SDK/RPC paths do not justify weakening parser, state, or signing
branch coverage.

### Live testnet-acceptance tests

The `testnet-acceptance` feature gates end-to-end tests that hit the live Stellar
testnet RPC and Friendbot. These tests are not run under default `cargo test`; each
is enabled per crate. For example:

```bash
cargo test -p stellar-agent-mcp --features testnet-acceptance \
  --test sep43_sign_and_submit_transaction_testnet_acceptance
```

```bash
cargo test -p stellar-agent-network --features testnet-acceptance
```

The `testnet-acceptance` feature is dev- and CI-only and must not be enabled in any
release-artifact feature set. The crates that submit on-chain (for example
`stellar-agent-defindex`, `stellar-agent-dex`,
`stellar-agent-stablecoin`) pull `stellar-agent-test-support/testnet-helpers` in
through their own `testnet-acceptance` feature. A sibling `testnet-integration`
feature on `stellar-agent-sep10`, `stellar-agent-sep45`, and
`stellar-agent-smart-account` gates their live suites the same way; the
serialized driver and the `Testnet acceptance` workflow run both.

These tests require network reachability to testnet RPC and Friendbot. Testnet is
the default network; Friendbot funding is testnet-only. Write and signing commands
structurally refuse mainnet in this alpha, so there is no mainnet acceptance tier.

The MPP acceptance target also requires Node.js and pnpm for the pinned released
`@stellar/mpp` server harness. Its package and lock files must contain the exact
SDK/runtime versions. The suite is registered in the serialized driver and a
skip marker does not count as MPP acceptance.

To run the full live leg, use the serialized driver, which paces the suites so
Friendbot and the RPC load balancer are not hit back-to-back:

```bash
.github/scripts/run-testnet-acceptance.sh                # everything
FILTER=stellar-agent-dex .github/scripts/run-testnet-acceptance.sh   # one crate
```

The driver enforces a completeness guard: it fails the run if any `tests/*testnet*.rs`
file on disk is missing from its suite list, so a new live suite must be added to
`SUITES` in `.github/scripts/run-testnet-acceptance.sh`.

The same script backs the `Testnet acceptance` workflow
(`.github/workflows/testnet.yml`), which runs on manual dispatch (with an
optional suite filter input) and on a weekly schedule; it is deliberately not
part of per-push CI. The WebAuthn suite needs a Chromium binary on `PATH` (or
the `CHROME` env var); the multicall happy-path test skips itself unless
`STELLAR_AGENT_TESTNET_MULTICALL_ROUTER_ADDRESS` and
`STELLAR_AGENT_TESTNET_SECONDARY_RPC_URL` are set. The workflow does not set
those variables, so the multicall happy path runs only where a router
deployment is available; the driver surfaces such self-skips as skip markers
in the run summary so a green leg stays explicit about what did not execute.

#### CAP-85 external-reference suites

Two live suites prove the wallet's handling of contracts whose executable is a
CAP-85 external reference, a Wasm hash that the owning contract can repoint:

- `stellar-agent-smart-account` / `cap85_external_ref_testnet_acceptance`
  (feature `testnet-integration`): invocation through the reference and its
  footprint, the rule-install refusal and pin, a transfer signed through a
  rule whose verifier is the reference with the pinned-hash drift check,
  drift detection after a repoint on the execute path
  (`submit_signed_invoke`), the passkey signing path and in
  `verify_rule_wasm_pins`, the SEP-48 spec fetch, and the DeFi and DeFindex
  pin gates.
- `stellar-agent-cli` / `cap85_external_ref_cli_testnet_acceptance` (feature
  `testnet-acceptance`): `smart-account rules create` refusing and then
  pinning the reference, `smart-account execute` confirming through the rule
  and then refusing with `sa.verifier_hash_drift` after the repoint, and
  `smart-account rules verify-pins` reporting drift after the repoint,
  through the `stellar-agent` binary.

Both suites deploy a beacon contract that owns the executable reference,
deploys the reference contract and repoints it. Its source is the independent
Cargo workspace `contracts/cap85-beacon/` (excluded from the wallet
workspace, `publish = false`). The built Wasm, its build record and the build
script live in
`crates/stellar-agent-smart-account/vendor/cap85-beacon/v0.1.0/`; the
smart-account crate embeds it as `cap85_beacon::CAP85_BEACON_WASM` under the
`test-helpers` feature and in its own unit-test build, where the digest test
runs, and pins its SHA-256 in `build.rs`.

To rebuild the beacon, install stellar-cli 28.1.0 and the `wasm32v1-none`
target, then run:

```bash
crates/stellar-agent-smart-account/vendor/cap85-beacon/v0.1.0/build.sh
```

The script builds with `stellar contract build --locked`, copies the Wasm into
the vendor directory, and prints the rustc, stellar-cli and soroban-sdk
versions, the optimizer state and version, and the SHA-256. When the digest
changes, update `REFERENCE.md` in the vendor directory, the
`cap85_beacon.wasm` row of `WASM_PINS` in the crate's `build.rs`, and
`CAP85_BEACON_WASM_SHA256` in `src/cap85_beacon.rs` together.

## Review process

A fixed reviewer team checks every change against the
[review checklist](review-checklist.md) before it is committed. The team is the
Security reviewer (security and key hygiene, dependency licensing, project
invariants), the Code reviewer (documentation, public API and dead code, reuse and
duplication, test quality and coverage), and the Architecture reviewer
(reuse-versus-build and dependency choices, module architecture, production
readiness). Review repeats on a fresh pass until every reviewer approves with no
blocking findings. The build gates above are one dimension of that checklist; the
other dimensions cover correctness, key hygiene, tests and coverage, documentation,
reuse and dependencies, public API and dead code, and licensing and invariants.

See [../../CONTRIBUTING.md](../../CONTRIBUTING.md) for the contribution workflow.

## Licenses

`cargo deny check` enforces a permissive-only license allow-list, configured in
`deny.toml`. Accepted licenses are `MIT`, `Apache-2.0`, `BSD-3-Clause`,
`BSD-2-Clause`, `CC0-1.0`, `Unicode-3.0`, `Zlib`, `ISC`, `CDLA-Permissive-2.0`,
`MPL-2.0`, and `Apache-2.0 WITH LLVM-exception`. One narrowly scoped per-crate
exception allows `LGPL-3.0-or-later` for `nacl`, a wasm32-only transitive of
`stellar-baselib` that is never compiled into the native binaries this project
builds. The advisories section denies yanked crates and active security
advisories, with one unmaintained-class advisory ignored (RUSTSEC-2024-0436, on
the `paste` macro helper pulled deep through the OpenZeppelin Stellar contract
crates), which has no fixed release. Unknown registries and
unknown git sources are denied.
