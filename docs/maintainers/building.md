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
cargo install --locked cargo-llvm-cov --version 0.8.7
cargo install --locked cargo-machete --version 0.9.2
cargo install --locked cargo-deny --version 0.19.9
```

These versions match the `tool:` pins in `.github/workflows/ci.yml`. The
`Install surface` workflow runs `.github/scripts/check-gate-tool-versions.sh`,
which fails when a version in this guide differs from its pin in `ci.yml`.

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

### Install surface

```bash
python3 .github/scripts/check-install-surface.py
python3 .github/scripts/test-check-install-surface.py
python3 .github/scripts/check-docs-style.py
python3 .github/scripts/test-check-docs-style.py
bash .github/scripts/check-gate-tool-versions.sh
bash .github/scripts/test-check-gate-tool-versions.sh
actionlint
```

The install surface check covers the documented install commands, version
pins, and secret-seed procedures, and the binstall metadata of both wallet
crates; its header defines each rule. Its self-test runs the check on copies of
the tree, with one violation injected per case. The docs style check applies
the writing rules of CONTRIBUTING.md to the tracked Markdown files; its header
defines each rule and the baseline. The Python scripts need Python 3.11 or
later.

The gate tool check compares the versions in [Gate tools](#gate-tools), in the
other workflows, and in the composite actions with the `tool:` pins in
`ci.yml`. Its header defines the accepted line shapes, and its self-test runs
it on fixture trees with one drift form per case.

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

- `test-helpers`: exposes test-only helpers and fixtures. Must not be enabled in
  production builds.
- `test-hooks`: test-only observation and fault-injection hooks in
  `stellar-agent-network` and `stellar-agent-nonce`.
- `test-loopback`: loopback-listener test surface in `stellar-agent-network`.
- `testnet-helpers`: keypair generation, Friendbot HTTP, and live-network client
  helpers in `stellar-agent-test-support`. Pulled in transitively by the
  `testnet-acceptance` feature of the crates that submit on-chain.
- `verifier-registry`: temp-dir-backed verifier-registry fixtures in
  `stellar-agent-test-support`.
- `wiremock-helpers`: `wiremock`-based HTTP doubles in
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

Release preparation also bumps the version pins in the documentation and the
crate READMEs, which a CI check compares with the workspace version.

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

To rebuild the beacon, install the toolchain and stellar-cli 28.1.0, built
with host rustc 1.98.0, then run the build script:

```bash
rustup toolchain install 1.98.0 --profile minimal --target wasm32v1-none
RUSTUP_TOOLCHAIN=1.98.0 cargo install --locked stellar-cli --version 28.1.0
crates/stellar-agent-smart-account/vendor/cap85-beacon/v0.1.0/build.sh
```

The script refuses a `stellar` whose first `--version` line is not
`stellar 28.1.0 (c0f4d0da891bbf214c08b8c5035ae6db80e9a3bd)`. It builds a copy
of the tracked source with `RUSTUP_TOOLCHAIN=1.98.0` and
`stellar contract build --locked`, and copies the Wasm into the vendor
directory. It prints the rustc, stellar-cli, and soroban-sdk versions, the
optimizer state and version, and the SHA-256. When the digest changes, update
`REFERENCE.md` in the vendor directory, the `cap85_beacon.wasm` row of
`WASM_PINS` in the crate's `build.rs`, and `CAP85_BEACON_WASM_SHA256` in
`src/cap85_beacon.rs` together.

## Vendored Wasm rebuild

The smart-account crate vendors the contract Wasm files that the wallet uploads
or recognizes under `crates/stellar-agent-smart-account/vendor/`.
Each rebuildable file has a record naming its source, toolchain, stellar-cli
binary, build command, and digest. The multicall record documents its frozen
exception.

### What the workflow proves

The `vendored-wasm` workflow (`.github/workflows/vendored-wasm.yml`) runs
`.github/scripts/rebuild-vendored-wasm.sh`, which holds the manifest of
rebuildable files, the one exception, and every pinned version.

- The tree check runs on every pull request, every push to `main`, every tag,
  twice a week, and on dispatch. It fails unless every tracked Wasm file is a
  manifest file, the exception, or out of scope. Each vendored file must equal
  its record and, where one exists, its `WASM_PINS` row in `build.rs`. Every
  `include_bytes!` or `include_str!` in the crate's `src/` must name one string
  literal that resolves to a vendored file. In every other crate's `src/`, each
  include of a `.wasm` file must resolve to a vendored file too.
- The tree check constrains source spellings in the crate's `src/` as defense
  in depth. It refuses negated `cfg` predicates other than `unix` and `windows`,
  `cfg!`, `include!`, `#[path]`, renamed `cfg` or `include` imports, and
  non-ASCII code text. It also refuses `cfg_attr` applying `cfg`, `cfg_attr`,
  or `path`, and negated `cfg_attr` applying attributes other than lint levels.
  It refuses `macro_use`, including under `cfg_attr`, and `macro_rules!`
  definitions outside its known list. That list pins the function-local
  `early_err` in `managers/credentials.rs` by name, owner function, and body.
  It refuses macro metavariables in attributes and the token sequences
  `$name!`, `#$name`, and `#!$name`.
  Definition files and their module-chain files cannot carry inner `cfg` or
  `cfg_attr` attributes. Watched definitions and module declarations occur
  exactly once, unindented, at the top level of their file, with only their
  permitted configuration attributes.
  Watched definitions need literal initializers. Verifier entries need literal
  hashes and `VerifierAuditStatus::<Variant>`, with literal string fields for a
  variant that has them.
  The fixture occurs once under its own permitted attribute.
  Raw identifiers count as their names. Spellings outside the self-test corpus
  may pass; the identity tests bind values in the builds they run.
  Glob-import shadowing inside a consumer is a spelling the lexical check
  does not see; compiled dry runs catch it on the dry-run path of the public
  deployment wrappers, in the builds they run.
- When a change touches `vendor/`, `build.rs`, `contracts/`, the two scripts,
  or the workflow, and on every tag, scheduled, or dispatched run, two macOS
  jobs build the pinned stellar-cli binaries. The `rebuild` job then rebuilds
  every manifest file from its pinned source with its pinned toolchain and
  fails unless the rebuilt bytes equal the vendored file.
- The unit tests in `src/vendored_wasm_tests.rs` and the integration target
  `tests/vendored_wasm_release_cfg.rs` bind the table, embedded constants,
  digest constants, and three allowlists to vendored files. The integration
  target also binds the production audit statuses and the dry run of every
  public deployment wrapper.
  Both paths are relative to `crates/stellar-agent-smart-account/`.
  The integration target links the library compiled without `cfg(test)`.
  Its `test-helpers` and `deploy-cli` assertions run when those features are
  enabled. Its fixture-exclusion test runs without `test-helpers`.
  The ordinary `ci.yml` test job runs both feature selections.
- The multicall router is the exception: its source is not in the repository,
  so the workflow holds it at one frozen digest.

The `vendored-wasm` job reads every job result and is the check to require.

Run the identity and deployment gates locally with:

```sh
CARGO_BUILD_JOBS=6 cargo test -p stellar-agent-smart-account \
  --features test-helpers,deploy-cli
CARGO_BUILD_JOBS=6 cargo test -p stellar-agent-smart-account \
  --test vendored_wasm_release_cfg
CARGO_BUILD_JOBS=6 cargo test --release -p stellar-agent-smart-account \
  --features test-helpers,deploy-cli --lib --test vendored_wasm_release_cfg -- \
  vendored_wasm_tests deployment::deploy::tests:: \
  vendored_table_entries embedded_wasm_constants digest_constants \
  verifier_allowlist_ threshold_policy_hashes weighted_threshold_policy_hashes \
  deploy_smart_account_dry_run deploy_webauthn_verifier_dry_run \
  deploy_ed25519_verifier_dry_run deploy_spending_limit_policy_dry_run \
  deploy_timelock_controller_dry_run deploy_policy_dry_run
```

### Run the rebuild locally

Use a work directory outside any directory whose parents hold a
`.cargo/config.toml`, since cargo reads every parent's config and the script
refuses one. A temporary directory works. The script also refuses `RUSTFLAGS`,
`RUSTC_WRAPPER`, `CARGO_PROFILE_*`, and the other variables that change what
rustc compiles, and a cargo home with a config file or whitespace in its path.

```bash
W=$(mktemp -d)
# The subshell stops at the first failing command.
(
set -euo pipefail

# The pinned toolchains, and the host toolchains of the two stellar-cli builds.
/bin/bash .github/scripts/rebuild-vendored-wasm.sh --list-toolchains >"$W/toolchains"
while read -r toolchain target; do
  rustup toolchain install "$toolchain" --profile minimal --target "$target"
done <"$W/toolchains"

# stellar-cli 25.2.0 from a git archive of its tag, built outside any git work
# tree, so its cliver meta entry carries no revision. The tag must resolve to
# the pinned commit before anything is archived or built.
git init -q "$W/stellar-cli-git"
git -C "$W/stellar-cli-git" fetch --depth 1 --no-tags \
  https://github.com/stellar/stellar-cli.git '+refs/tags/v25.2.0:refs/tags/v25.2.0'
commit=$(git -C "$W/stellar-cli-git" rev-parse 'v25.2.0^{commit}')
if [ "$commit" != 28484880988199233a7e8e87c97cb12dac323cb3 ]; then
  echo "tag v25.2.0 resolves to $commit, not 28484880988199233a7e8e87c97cb12dac323cb3" >&2
  exit 1
fi
mkdir "$W/stellar-cli-export"
git -C "$W/stellar-cli-git" archive v25.2.0 | tar -x -C "$W/stellar-cli-export"
(cd "$W/stellar-cli-export" && GIT_CEILING_DIRECTORIES="$W" RUSTUP_TOOLCHAIN=1.94.0 \
  CARGO_TARGET_DIR="$W/target-25" cargo install --locked --path cmd/stellar-cli --root "$W/stellar-cli-25")

# stellar-cli 28.1.0 from crates.io.
(cd "$W" && RUSTUP_TOOLCHAIN=1.98.0 CARGO_TARGET_DIR="$W/target-28" \
  cargo install --locked stellar-cli --version 28.1.0 --root "$W/stellar-cli-28")
rm -rf "$W/target-25" "$W/target-28"

# The OpenZeppelin tags.
git init -q "$W/oz"
git -C "$W/oz" fetch --depth 1 --no-tags https://github.com/OpenZeppelin/stellar-contracts.git \
  '+refs/tags/v0.7.2:refs/tags/v0.7.2' '+refs/tags/v0.7.1:refs/tags/v0.7.1'

# The rebuild, with a fresh and empty cargo home.
mkdir "$W/cargo-home"
CARGO_HOME="$W/cargo-home" /bin/bash .github/scripts/rebuild-vendored-wasm.sh \
  --repo-root . --oz-clone "$W/oz" \
  --stellar-25 "$W/stellar-cli-25/bin/stellar" --stellar-28 "$W/stellar-cli-28/bin/stellar" \
  --work "$W/work"
)
```

The script prints one table row per vendored file and exits 0 only when every
row matches. A row's `cmp` column reads `MISMATCH` when the rebuilt bytes
differ; the row then also prints the vendored file's sha256 and size. The
offline checks alone run with `--check-tree --repo-root .`.

`.github/scripts/test-rebuild-vendored-wasm.sh` tests the script with stub
builders, a stub `rustc`, and a stub `git`. It runs every git command with no
global or system configuration and a placeholder identity, and sets
`CARGO_HOME` to an empty scratch directory, so the host's settings never reach
its cases.

### Add or re-vendor a file

Adding a vendored file takes, in one change:

- its manifest row in `.github/scripts/rebuild-vendored-wasm.sh`;
- its record and `build.sh` beside the file;
- its `WASM_PINS` row in `build.rs` when the crate embeds it;
- its entries in the `VENDORED` tables of `src/vendored_wasm_tests.rs` and
  `tests/vendored_wasm_release_cfg.rs`.

A constant or allowlist entry pinned to the file also takes its assertion in
both `src/vendored_wasm_tests.rs` and `tests/vendored_wasm_release_cfg.rs`,
plus its entry in the script's `DEFINITIONS` list. Removing the exception is
deleting its line. A new toolchain or target needs no workflow change:
the `rebuild` job installs every pair that `--list-toolchains` prints.

Each `build.sh` re-vendors its file through the script's `--exec` mode, with the
same refusals and environment allowlist as the workflow. When the printed digest
differs from the committed one, update the file's record, its `WASM_PINS` row,
and every constant and allowlist entry that pins it in the same change.

### Limits and maintainer actions

- The `vendored-wasm` job blocks a merge only when it is a required check, and
  the identity tests block only when the `ci.yml` test job is required. With a
  merge queue, the workflow needs a `merge_group` trigger.
- A pull request that changes the script or the workflow together with the
  bytes passes. So does one that points an embedded constant at another
  vendored file and edits both identity-test mappings to match. Review of
  `vendor/`, `.github/`, `src/vendored_wasm_tests.rs`, and
  `tests/vendored_wasm_release_cfg.rs` by named owners needs a `CODEOWNERS`
  file and a ruleset that requires code-owner review.
- The tree check lexes the smart-account source for its attribute rules.
  A workspace dependency can export a macro that expands in this crate.
  The integration test checks the resulting compiled value for each mapped
  constant and allowlist, including values produced by dependency macros.
  The identity tests also bind the public deployment wrappers.
  Crate-internal consumers with test-only imports remain outside those assertions.
- Dev-dependency feature unification can enable features in the integration
  build. Feature sets and other build settings that differ from the tested
  builds remain a residual. Review must check those configuration changes.
- Wasm bytes can reach the binary without a tracked Wasm file or an include
  that the tree check sees. Such bytes can come from a byte-array or
  encoded-string literal, from a tracked file without the Wasm magic that the
  build decodes, or from a file that a build script writes to `OUT_DIR`. Each is
  a visible code change.
- For an in-tree source (`contracts/cap85-beacon/`), the rebuild proves the
  bytes match the committed source; review of the source diff remains the
  defense. A compromise of an upstream source at its pinned commit is outside
  this check.
- Two checks prove a cached stellar-cli binary: its version line and the byte
  comparison of its output. A binary that writes the vendored bytes whatever
  its input passes both. Every workflow of a branch shares the cache. Code that
  runs in any job on `main` can therefore create an entry under a key that does
  not exist yet, such as after an eviction or a recipe revision bump. An
  existing entry never changes. Delete the stellar-cli cache entries after any
  suspected compromise of a workflow run on `main`, and after reverting a
  change to the workflow or the scripts.
- A failed cache save is a warning in the stellar-cli job, and the `rebuild`
  job then fails on the cache miss. Two concurrent cold runs on `main` can do
  the same. A re-run clears both.
- A tag run does not gate the release workflow.
- Pull-request CI does not run the release-profile tests. The deploy's digest
  check runs in every profile; review and the release-profile test run keep it
  out of a `debug_assertions` gate. The local release gate also checks the
  integration target against the library compiled in the release profile.
- GitHub disables scheduled runs of a public repository after 60 days without
  repository activity.
- The first workflow run proves what a local run cannot: the runner image's C++
  compiler for the optimizer that stellar-cli 28.1.0 bundles, the runner's own
  toolchain installs, and the cold timing. A cold run builds both stellar-cli
  binaries and takes roughly an hour.
- Outside this check: `crates/stellar-agent-sep48/tests/fixtures/sep41_token.wasm`
  (a test fixture), the simplewebauthn browser bundle (pinned beside it in
  `stellar-agent-webauthn-bridge`), and the on-chain digests of third-party
  contracts in `stellar-agent-defindex/src/pins.rs` and
  `stellar-agent-dex/src/pins.rs`, which have no vendored bytes.

## Review process

The depth of the review follows what a change touches:

- A maintainer reviews a change to documentation, scripts, or workflows from the
  diff and the CI checks.
- A change to Rust code gets the same review and must also pass the
  [gate suite](#gate-suite).
- A change to signing paths, key handling, or serialized state also gets a
  second review pass against the full [review checklist](review-checklist.md).

The second review pass keeps the three reviewer roles of the checklist. The
security review covers security and key hygiene, dependency licensing, and
project invariants. The code review covers documentation, public API and dead
code, reuse and duplication, and test quality and coverage. The architecture
review covers reuse-versus-build and dependency choices, module architecture,
and production readiness. Review repeats until a pass ends with no blocking
findings. The build gates above are one dimension of that checklist; the other
dimensions cover correctness, key hygiene, tests and coverage, documentation,
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
