# Building and testing

This guide is for maintainers and contributors building the `stellar-agent-wallet`
workspace and running the gates that apply to each change. The workspace is a Cargo
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
profile = "minimal"
```

The channel is `stable` (not a fixed version). With `rustup` installed, the pinned
channel and the `rustfmt` and `clippy` components are provisioned automatically on
first build in the workspace. Run `rustup update stable` before a gate pass so
`clippy` matches the latest stable lints.

The minimal profile avoids installing `rust-docs` on a fresh toolchain.
It does not remove components from an existing installation.
The workspace targets Rust edition 2024.

### Gate tools

The gate suite uses three auxiliary Cargo subcommands. Install them with:

```bash
cargo install --locked cargo-llvm-cov --version 0.8.7
cargo install --locked cargo-machete --version 0.9.2
cargo install --locked cargo-deny --version 0.19.9
```

`cargo-llvm-cov` uses the reference pin in `.github/workflows/coverage.yml`.
`cargo-machete` and `cargo-deny` use the reference pins in
`.github/workflows/ci.yml`. The `Install surface` workflow checks this guide
against those pins with `.github/scripts/check-gate-tool-versions.sh`.

`cargo-llvm-cov` also needs the `llvm-tools-preview` rustup component:

```bash
rustup component add llvm-tools-preview
```

## Building

Build the whole workspace:

```bash
cargo build
```

For maintainer release validation:

```bash
cargo build --release
```

A release build without `--all-targets` surfaces dead code that a test-targets
build can mask.

### Platform note: `windows-identity`

`stellar-agent-windows-identity` reads the process-token user SID to bind approval
attestations to the OS user. Its Win32 FFI dependency (`windows-sys`) is gated under
`[target.'cfg(target_os = "windows")'.dependencies]`, and `stellar-agent-core`
depends on the crate only under the same `cfg(target_os = "windows")` gate. On
macOS and Linux the crate compiles to a dependency-free shim whose lookup returns
a `WindowsIdentityError::UnsupportedPlatform` error and pulls in no Win32
dependency, so nothing extra is required to build the workspace off Windows.

## Disk use

The dev profile gives workspace members line tables, including members built
as dependencies. Non-workspace dependencies receive no debuginfo. Workspace
variable and type inspection and non-workspace dependency source-line debugging
are unavailable. The test profile inherits these debug settings and prevents
new incremental caches. Existing incremental caches remain until cleaned.
Repeated test compilation can take longer without incremental caches.

Dev-profile build and check loops remain incremental unless configuration or
environment overrides them. Debug assertions stay enabled. Panic behavior,
optimization levels, and release profiles retain their defaults.
Distinct feature and profile builds can retain multiple artifact variants.

For full debugging, remove conflicting profile or debug overrides and append
these options to the selected offline test command:

```sh
--config 'profile.dev.debug=true' --config 'profile.dev.package."*".debug=true'
```

### Measurements

Each run starts with an empty target directory. Paired runs use the same
machine, toolchain, build jobs, Cargo configuration, environment overrides,
and download-cache conditions. Pause housekeeping throughout the measurements.
Use isolated committed snapshots for baseline and current runs.
Keep the toolchain fixed between paired runs.

Record the OS, architecture, exact Rust, Cargo, and gate-tool versions, commit,
lockfile hash, commands, package and feature selection, elapsed time, and every
gate exit status. Keep Cargo-home, rustup, and interop storage separate.

Sample target size before execution, every 30 seconds, and immediately after
completion. The maximum is the 30-second sampled peak. Ratios divide current
sizes by baseline sizes. Failed or unavailable runs do not establish comparable
savings.

The tables in this section record runs on one Mac with macOS 26.6.2 on arm64.
The toolchain was `rustc 1.99.0 (b940084d7 2026-09-28)` with Cargo 1.99.0, and
the gate tools were cargo-llvm-cov 0.8.7, cargo-machete 0.9.2, cargo-deny
0.19.9, shellcheck 0.11.0, actionlint 1.7.12, and Node.js v24.5.0. Every run
used the default number of build jobs, left `CARGO_INCREMENTAL` unset, and
started with a fresh target directory. A `du -sk` sample of the target
directory ran every 30 seconds, and housekeeping stayed paused. The Interop row
measures the checkout's `interop/` tree with `du -sk`, separately from the
target directory. The baseline is main at commit `38dabdd`. The current runs
use the same tree with the Cargo profile settings, rustup profile, and
preflight gate selection in this guide applied. Both trees have the same
lockfile, whose SHA-256 hash starts with `6a0d7f74eb27`. Both full-suite runs
reported `33 gates run, 0 failed, 5 unavailable`. The five unavailable gates
are Python checks that need PyYAML and build nothing: `workflow-invariants` and
the `test-check-workflow-invariants.py`, `test-sync-labels.py`,
`test-take-workflow.py`, and `test-triage-workflow.py` self-tests. The
docs-only run selected no Cargo gate, so its target directory stayed empty. The
coverage-alone run shared the machine with three unrelated builds, so its
elapsed time is not comparable. In every run, the 30-second sampled peak equals
the retained size because no gate removed build output while the run executed.

| Run | Retained KiB | 30-second sampled peak KiB | Retained ratio | Peak ratio | Elapsed seconds |
| --- | --- | --- | --- | --- | --- |
| Docs-only, current | 0 | 0 | Not paired | Not paired | 316 |
| CLI, baseline | 8,803,364 | 8,803,364 | Not applicable | Not applicable | 737 |
| CLI, current | 3,756,896 | 3,756,896 | 0.43 | 0.43 | 400 |
| Full suite, baseline | 41,384,108 | 41,384,108 | Not applicable | Not applicable | 3,410 |
| Full suite, current | 21,188,348 | 21,188,348 | 0.51 | 0.51 | 2,361 |
| Coverage alone, current | 9,363,136 | 9,363,136 | Not paired | Not paired | 1,953 |

Measure each existing path with `du -sk`; record absent paths as zero.
Subdirectories are breakdowns, not additive totals. Paths below are relative
to the effective target directory.

| Run | debug/deps KiB | debug/incremental KiB | debug/build KiB | doc KiB | llvm-cov-target KiB |
| --- | --- | --- | --- | --- | --- |
| Docs-only, current | 0 | 0 | 0 | 0 | 0 |
| CLI, baseline | 5,250,728 | 3,922,276 | 240,988 | 200,852 | 0 |
| CLI, current | 2,703,700 | 791,076 | 143,072 | 53,396 | 0 |
| Full suite, baseline | 16,986,688 | 10,229,008 | 259,104 | 200,852 | 17,567,904 |
| Full suite, current | 9,511,672 | 1,938,852 | 148,388 | 200,852 | 9,131,900 |
| Coverage alone, current | 0 | 0 | 0 | 0 | 9,274,808 |

| Separate storage | KiB |
| --- | --- |
| Cargo-home | 1,879,332 |
| Rustup | 4,174,448 |
| Interop | 217,188 |

Docs-only and CLI runs use `bash .github/scripts/preflight.sh --base HEAD`
after verifying the selection with `--list`. Add a temporary probe to
`README.md` for docs-only runs or `crates/stellar-agent-cli/Cargo.toml` for CLI
runs, then remove it afterward. The full suite uses
`bash .github/scripts/preflight.sh --full`, including coverage and its floor
check. Coverage alone uses the command in [Coverage](#coverage).

### Cleanup

Cleanup is opt-in. Run it only after builds, tests, and debugging sessions
using the affected target directory finish.

`cargo clean` removes the effective target directory, including shared
artifacts when `CARGO_TARGET_DIR` is set. `cargo clean --doc` removes generated
documentation selectively. Removing the effective target's `debug/incremental`
directory discards incremental caches. Both selective cleanup operations cause
later rebuilding.

Compatible worktrees may share `CARGO_TARGET_DIR`. Coordinate Cargo runs and
cleanup across every user of that directory. Cargo downloads, rustup
toolchains, and other storage remain outside this cleanup. Coverage uses a
separate `llvm-cov-target` subtree.

## Gate suite

Start local verification with `bash .github/scripts/preflight.sh` and run the
issue-specific acceptance commands. `bash .github/scripts/preflight.sh --full`
runs the complete local registry, including coverage.

CI runs the offline workspace suite on every pull request. Pull-request
coverage requires the `coverage` label; live acceptance uses its separate
workflow. Local coverage, `cargo machete`, and `cargo deny check` are optional
reproductions. See the build-gate dimension of the
[review checklist](review-checklist.md#8-build-gates).

### Preflight

`.github/scripts/preflight.sh` runs the local CI checks that apply to the files
a branch changes. It then prints one line per gate in the form the pull request
template asks for.

```bash
bash .github/scripts/preflight.sh
```

- `--base <ref>` compares the branch with its merge base with `<ref>`. The
  default is `origin/main`, or `main` when `origin/main` does not exist.
- `--full` runs every gate in the registry, with workspace Cargo commands.
  It includes coverage and its floor check.
- `--list` prints the selected gates, one `<id><TAB><command>` line each in
  registry order, and runs nothing.

Run it from a Git checkout with bash 3.2 or later, Git, Python 3.11 or later,
and the standard Unix utilities; new Markdown must be tracked for the style
check to read it.

The changed set is the union of the paths that differ from the merge base and
the paths that `git status` lists. It includes untracked and deleted files.
Every run includes the three always gates: `docs-style`, `install-surface`,
and `gate-tool-versions`. Each path selects the gates of every scope class it
matches:

- A file that the install surface check reads, as its `is_scanned` function
  decides, selects that check's self-test, which injects violations into
  copies of those files. A deleted path counts too.
- Any other docs file adds no gates beyond the three always gates. Directory
  scopes also apply to Markdown files.
- A workflow under `.github/workflows/`, a file under `.github/actions/`, or
  `.github/labels.yml` selects `actionlint`.
- A file under `.github/scripts/` selects the self-test of the script it
  changes, and a changed shell script also selects shellcheck.
- A file under `skills/` or `.claude-plugin/` selects the skill archive check.
- A file under `crates/`, `tests/`, or `examples/`, or a root `Cargo.toml`,
  `Cargo.lock`, `rust-toolchain.toml`, `rustfmt.toml`, `Cross.toml`, or
  `deny.toml`, selects the Rust gates.
- A file under `interop/` adds no gate of its own, since the interop
  harnesses run under `--full`.

Clippy, rustdoc, and tests select the packages that own the changed Rust
paths, in path order, followed by their direct dependents, sorted by name.
Cargo builds the required dependency closures. A dependent names an owner by
`path`, directly or through `workspace = true`, in `[dependencies]`,
`[dev-dependencies]`, or a target-specific dependency table.

Clippy and rustdoc use the same `-p` list as tests, with `--all-features`.
Tests use the offline features that at least one selected package declares:
`test-helpers`, `test-hooks`, `test-loopback`, and `verifier-registry`, in that
order.

A Rust path outside every member selects workspace commands. This includes
root manifests, the lockfile, the toolchain, paths under `tests/`, and deleted
member manifests. Scoped checks provide less workspace-wide assurance, so CI
remains authoritative for the offline workspace suite.

Each gate lists the tools and Python modules it needs. A missing one makes the
gate unavailable: its line names the requirement and an install hint, the later
gates still run, and the run fails. The hints read their versions from the
files that pin them: `actionlint` and `shellcheck` from the Install surface
workflow, `cargo-llvm-cov` from the Coverage workflow, and the other cargo
subcommands and Node from `ci.yml`.

Each gate prints `=== <id>: <command>` before its own output and `RC=<n>` after
it, and a failing gate does not stop the later ones. The run ends with the
table for the pull request description and a summary line:

```text
- `python3 .github/scripts/check-docs-style.py`: exit 0
- `python3 .github/scripts/check-install-surface.py`: exit 0
- `bash .github/scripts/check-gate-tool-versions.sh`: exit 1
- `actionlint`: unavailable (actionlint: brew install actionlint, or the <version> release archive)
- `.github/scripts/test-mpp-interop.sh`: not run (--full; needs Node <version> and Corepack)
- `.github/scripts/test-sdk-v17-interop.sh`: not run (--full; needs Node <version> and Corepack)
preflight: 3 gates run, 1 failed, 1 unavailable
```

A gate that ran reads `exit <n>`. The two interop harnesses read `not run`
without `--full`, and so do the coverage floors when the coverage run failed or
was unavailable. The script exits 0 when no gate failed and none was
unavailable, and 1 otherwise. It exits 2 for a usage error, a missing
prerequisite, a base without a merge base, an unreadable workspace manifest,
or, without `--full`, an install surface check that Python cannot load.

The registry, in run order, with what selects each gate. `--full` selects every
gate except `shellcheck-changed`, which needs a changed shell script.

1. `docs-style`, `install-surface`, and `gate-tool-versions`: every run.
2. `actionlint`: a workflow change.
3. `workflow-invariants`: a change to `release.yml`, `publish.yml`,
   `notarize-smoke.yml`, `labels.yml`, `stale.yml`, `triage.yml`,
   `welcome.yml`, or `coverage.yml` under `.github/workflows/`, to
   `.github/actions/`, or to a file under `.github/scripts/` that one of them
   names.
4. The self-tests, in filename order. Each runs when the file it tests or the
   self-test itself changes:
   - `test-check-crates-exist.sh`: `check-crates-exist.sh`
   - `test-check-docs-style.py`: `check-docs-style.py`
   - `test-check-gate-tool-versions.sh`: `check-gate-tool-versions.sh`
   - `test-check-install-surface.py`: `check-install-surface.py`, or a file
     that check reads
   - `test-check-no-direct-sasignersetbaselined-emit.sh`:
     `check-no-direct-sasignersetbaselined-emit.sh`
   - `test-check-ref-on-main.sh`: `check-ref-on-main.sh`
   - `test-check-workflow-invariants.py`: `check-workflow-invariants.py`
   - `test-compare-crate-sums.py`: `compare-crate-sums.py`
   - `test-preflight.sh`: `preflight.sh`
   - `test-publish-crates-check.sh`: `publish-crates.sh`
   - `test-publish-crates-verify.sh`: `publish-crates.sh`
   - `test-rebuild-vendored-wasm.sh`: `rebuild-vendored-wasm.sh`
   - `test-sync-labels.py`: `sync-labels.py`, `.github/labels.yml`, or
     `.github/workflows/labels.yml`
   - `test-take-workflow.py`: `.github/workflows/take.yml`
   - `test-triage-workflow.py`: `.github/workflows/triage.yml`
   - `test-validate-unsigned-archive.py`: `validate-unsigned-archive.py`
   - `test-welcome-workflow.py`: `.github/workflows/welcome.yml`
5. `shellcheck-preflight`: a change to `preflight.sh` or `test-preflight.sh`.
6. `shellcheck-changed`: any other changed shell script under
   `.github/scripts/` or `.github/actions/` that still exists, under `--full`
   too.
7. `package-skill`: a change under `skills/` or `.claude-plugin/`.
8. `vendored-tree-check`: a change under `crates/stellar-agent-smart-account/`
   or `contracts/`, or to `rebuild-vendored-wasm.sh`.
9. `publish-check` and `baseline-gate`: `--full` only.
10. `fmt`, `clippy`, `rustdoc`, and `test`: a Rust change.
11. `test-vendored-release-cfg`: a Rust change whose test packages include
    `stellar-agent-smart-account`, or that selects the workspace command.
12. `machete`, `deny`, `coverage`, and `coverage-floors`: `--full` only.
13. `interop:mpp` and `interop:sdk-v17`: `--full` only.

`package-skill.sh`, `check-coverage.py`, `run-testnet-acceptance.sh`, and
`release-preflight-version-check.sh` have no self-test. The preflight runs the
workflow checks with `python3`, which needs PyYAML importable.

The preflight does not carry these CI checks: the `windows-storage` job, the
`stellar-agent-test-support` feature matrix of the `test` job, the setup steps,
and the virtual environment of the workflow checks. Nor does it carry the
rebuild of the `vendored-wasm` workflow: its two stellar-cli build jobs, its
`rebuild` and `vendored-wasm` jobs, and the rebuild decision of its `check` job.

Each registry entry names the workflow, job, and step of the CI step it
mirrors, and the self-test checks those names against the workflows. Every
step of a cited job that runs a command needs a registry entry or an entry in
the not-carried list of `.github/scripts/test-preflight.sh`. A new, removed,
or renamed step fails the self-test with the workflow, job, and step. The
check reads step names, not commands, so a changed CI command needs the same
change in the registry by hand.
Package-scoped tests use the offline features the selected packages declare.

### Full suite

`bash .github/scripts/preflight.sh --full` runs the complete local registry.
The commands below reproduce its workspace Rust checks individually.
Coverage, machete, and deny remain optional local reproductions.

#### Format

```bash
cargo fmt --all -- --check
```

Run `cargo fmt --all` to format Rust sources.

#### Lint

```bash
cargo clippy --all-targets --all-features -- -D warnings
```

Warnings are denied. The workspace lints (declared in the root `Cargo.toml`)
already deny `unsafe_code`, `missing_docs`, the full clippy `all` group, and the
restriction lints `unwrap_used`, `expect_used`, `panic`, `print_stdout`,
`print_stderr`, and `dbg_macro`, among others.

#### Rustdoc

```bash
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features
```

Rustdoc warnings are denied.

#### Test

```bash
cargo test --workspace --features test-helpers,test-hooks,test-loopback,verifier-registry
```

This runs the offline unit, integration, and doc-tests. Live acceptance uses
its separate workflow and feature selections; see [Test tiers](#test-tiers).

#### Coverage

```bash
cargo llvm-cov --workspace --features test-helpers,test-hooks,test-loopback,verifier-registry --json --output-path cov.json
python3 .github/scripts/check-coverage.py cov.json
```

Coverage enforces the per-crate floors in `.github/scripts/check-coverage.py`.
The default floor is 85% offline line coverage. Explicit lower floors cover
crates whose remaining lines require live network or on-chain tests.
Those paths run in the separate `testnet-acceptance` and `testnet-integration`
suites.

The floors form a regression ratchet, set a few points below each crate's
current offline coverage. The aspirational target for new code is 90% per
crate. Coverage uses the offline feature set; `--all-features` enables the
live tiers that attempt RPC and Friendbot access.

CI runs this gate in the Coverage workflow: weekly on main, on a pull request
that carries the `coverage` label, and on demand through `workflow_dispatch`.
A maintainer adds the label to a pull request that changes Rust code.
Local reproduction is optional.

#### Unused dependencies

```bash
cargo machete
```

Fails on any declared-but-unused dependency.

#### License and advisory check

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
other workflows, and in the composite actions with each tool's reference
workflow pin: `coverage.yml` for `cargo-llvm-cov`, `ci.yml` for
`cargo-machete` and `cargo-deny`. Its header defines the accepted line shapes,
and its self-test runs it on fixture trees with one drift form per case.

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

The CI `test (offline)` job and the Coverage workflow run the offline tier
with `--features test-helpers,test-hooks,test-loopback,verifier-registry`.

MPP changes can reproduce their focused protocol and security checks and
both binary adapters with:

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
feature on `stellar-agent-sep10`, `stellar-agent-sep45`,
`stellar-agent-smart-account`, and `stellar-agent-smart-account-acceptance`
gates their live suites the same way; the serialized driver and the
`Testnet acceptance` workflow run both. The unpublished acceptance member
holds the smart-account suites that need a browser, the MCP server, the
WebAuthn bridge, or the SEP-48, DeFi, DeFindex, and soroban-spec-tools
crates, so a test build of `stellar-agent-smart-account` alone compiles none
of them.

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

- `stellar-agent-smart-account-acceptance` /
  `cap85_external_ref_testnet_acceptance` (feature `testnet-integration`):
  invocation through the reference and its footprint, and the rule-install
  refusal and pin. A transfer signed through a rule whose verifier is the
  reference confirms with the pinned-hash drift check on. After a repoint,
  the suite detects the drift on the execute path (`submit_signed_invoke`),
  on the passkey signing path, and in `verify_rule_wasm_pins`. It also covers
  the SEP-48 spec fetch and the DeFi and DeFindex pin gates.
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

The second review pass checks the change against every dimension of the
checklist. Review repeats until a pass ends with no blocking findings.

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
