# Architecture

This document maps the workspace for maintainers and contributors. It describes how the 34 crates are layered, which crate owns which responsibility, and how the two shipped binaries wire the tool surface to the policy, approval, and audit substrate.

For concept-level background read [../concepts.md](../concepts.md). For build and toolchain instructions read [building.md](building.md). For the security-relevant internals read [security-internals.md](security-internals.md). The contributor gate checklist is [review-checklist.md](review-checklist.md).

## Workspace overview

The repository is a single Cargo workspace (`resolver = "2"`) with 34 member crates under `crates/`, all named `stellar-agent-*`. Shared package metadata is inherited from `[workspace.package]`: version `0.1.0-alpha.2`, Rust edition `2024`, license `Apache-2.0`, repository `https://github.com/Soneso/stellar-agent-wallet`, author `Soneso`. Every member crate is prepared for crates.io publication (publish-enabled manifests with per-crate metadata); a future release will publish the whole workspace at one shared version via `cargo publish --workspace` from the tagged commit. Nothing is on crates.io yet.

Shared dependency pins live in `[workspace.dependencies]` in the root `Cargo.toml` and are added when a crate first needs them, so the workspace only carries dependencies it actually uses.

### Workspace lints

Lints are defined once in `[workspace.lints]` and inherited by each crate via `[lints] workspace = true`.

```toml
[workspace.lints.rust]
unsafe_code = "deny"
missing_docs = "deny"

[workspace.lints.clippy]
all = { level = "deny", priority = -1 }
missing_errors_doc = "deny"
missing_panics_doc = "deny"
needless_pass_by_value = "deny"
unwrap_used = "deny"
expect_used = "deny"
panic = "deny"
print_stdout = "deny"
print_stderr = "deny"
dbg_macro = "deny"
```

`unsafe_code` is denied workspace-wide, with narrowly-scoped `#[allow(unsafe_code)]` sites where FFI is required: `stellar-agent-windows-identity` for its Win32 token API (its core capability), and `stellar-agent-cli` for a POSIX `geteuid` FFI declaration in the audit-verify owner check. `unwrap_used`, `expect_used`, and `panic` are denied so library and command code surface typed errors rather than aborting. `print_stdout` and `print_stderr` are denied so output is routed through the JSON envelope and the redacting log subscriber rather than ad-hoc prints; the few legitimate fallback writes carry a scoped `#[allow]`.

## Dependency layering

Crates form a directed acyclic graph from foundational substrate up to the two binaries. No crate depends on a binary.

### Layer 0 — substrate

`stellar-agent-core`, `stellar-agent-network` (depends on `core`), `stellar-agent-sep5`, `stellar-agent-xdr-limits`, and `stellar-agent-nonce`. These carry the typed errors, amounts, envelopes, RPC transport, key derivation, untrusted-XDR bounds, and replay-nonce primitives that every higher layer builds on. `xdr-limits`, `sep5`, and `nonce` are independent leaves; `network` depends on `core`.

### Layer 1 — orchestration and platform

`stellar-agent-smart-account` (off-chain orchestration over OpenZeppelin `stellar-accounts`), `stellar-agent-webauthn-bridge` (loopback HTTP listener into the core approval store), `stellar-agent-loopback-http` (shared loopback-HTTP middleware behind the browser-facing listeners), `stellar-agent-approval-ui` and `stellar-agent-approval-remote` (the loopback and TLS-plus-passkey operator approval surfaces), `stellar-agent-claimable` (claimable-balance domain logic over `core`/`network`), `stellar-agent-pool` (channel-account pool over `core`/`network`/`sep5`), and `stellar-agent-windows-identity` (platform leaf).

### Layer 2 — protocol and SEP crates

`stellar-agent-sep7`, `stellar-agent-sep10`, `stellar-agent-sep43`, `stellar-agent-sep45`, `stellar-agent-sep48`, `stellar-agent-sep53`, `stellar-agent-anchor`, `stellar-agent-x402`, `stellar-agent-x402-identity`, and the toolsets triad `stellar-agent-toolsets` with `stellar-agent-toolsets-install` and `stellar-agent-toolsets-runtime`. Several lean SEP crates depend only on `xdr-limits` for untrusted-XDR bounds rather than on the heavier `core`. These protocol crates are consumed on the MCP side (directly or transitively), never by the CLI.

### Layer 3 — DeFi substrate and adapters

`stellar-agent-defi` is the adapter substrate: the contract-pin framework, the typed-preview trait, and the dispatch-verb seam (`lend`/`trade`/`vault`/`bridge`). It ships no live verb. The adapters `stellar-agent-blend`, `stellar-agent-defindex`, `stellar-agent-dex`, and `stellar-agent-stablecoin` implement that substrate and register the `lend`, `vault`, `trade`/`quote`, and `trustline` verbs; the adapters whose submit path runs through a smart account also depend on `smart-account`.

### Layer 4 — binaries

`stellar-agent-mcp-macros` is the proc-macro crate feeding the MCP registry. `stellar-agent-mcp` and `stellar-agent-cli` are the two sibling binaries; both consume the library crates and neither depends on the other.

## The two-sibling-binary model

The wallet ships two surfaces from two binary crates.

- `stellar-agent` is built from `stellar-agent-cli`. It is installed on `PATH` and is also discovered as `stellar agent ...` by the incumbent `stellar-cli` through its external-binary plugin convention. The crate root is `crates/stellar-agent-cli/src/main.rs`.
- `stellar-agent-mcp` is built from `stellar-agent-mcp`. It is an MCP server spoken over stdio. The crate has both `src/lib.rs` (re-exported for integration tests) and `src/main.rs` (the binary entry point that starts the server process).

The two binaries are siblings, not a dependency pair. `stellar-agent-cli` does not depend on `stellar-agent-mcp`. The CLI carries none of the SEP, anchor, or x402 protocol crates; the MCP binary adds that protocol surface plus the `mcp-macros` proc-macro with the `inventory` runtime. The per-crate table below carries the detail.

Both binaries share a single release archive. The `[package.metadata.binstall]` blocks in both crates point at the same `stellar-agent-{version}-{target}.tar.xz` (`.zip` on Windows), and `{ bin }` resolves to each crate's own binary name. Those archives and the `cargo binstall` assets they reference are published with each tagged release; `cargo binstall` resolves them via the `--git` URL until crates.io publication lands. Building from source with `cargo build --release` (or `cargo install --git https://github.com/Soneso/stellar-agent-wallet`) always works. See [building.md](building.md) for the build flow.

## Per-crate responsibility

| Crate | Responsibility |
| --- | --- |
| `stellar-agent-core` | Synchronous, runtime-free substrate: typed amounts, nine-category `WalletError`, JSON `Envelope`, profiles, observability, smart-account auth-digest helpers, the policy-engine trait and Noop/V1 implementations, the approval spine, and the audit log. |
| `stellar-agent-network` | Async Stellar RPC client, account-view projection, transaction assembly, SEP-29 memo enforcement, hardware-signer preparation, Friendbot funding, and the idempotent submit primitive. |
| `stellar-agent-claimable` | Claimable-balance domain logic: balance-id normalization, predicate evaluation, entry and trustline fetch, and claim preview; drives the `claim` verb. |
| `stellar-agent-sep5` | SEP-5 / BIP-44 HD ed25519 key derivation (`m/44'/148'/index'`, SLIP-0010 hardened) from a BIP-39 mnemonic or seed; no I/O or RNG. |
| `stellar-agent-xdr-limits` | Leaf crate supplying recursion-depth and length bounds for decoding untrusted XDR. |
| `stellar-agent-nonce` | HMAC-SHA256 wallet-issued nonce, in-memory TTL replay window, `ToolCatalogue` trait, and nonce-key rotation. |
| `stellar-agent-smart-account` | Off-chain orchestration over OpenZeppelin `stellar-accounts`: deployment, context-rule install, WebAuthn passkey signer, threshold updates, wasm-hash pinning, verifier migration, multicall, upgrade timelock. |
| `stellar-agent-webauthn-bridge` | Loopback-only HTTP listener ferrying browser WebAuthn ceremony bytes into the core approval store, behind a host/origin/CSP/body-limit middleware stack. |
| `stellar-agent-loopback-http` | Shared tower/axum defence-in-depth middleware for the wallet's loopback-only HTTP listeners: Host and Origin allowlists and hardened security headers. |
| `stellar-agent-approval-ui` | Localhost approval-inbox web UI: a loopback HTTP server surfacing the pending-approval queue for browser approve/reject (`approve serve`). |
| `stellar-agent-approval-remote` | TLS-protected, passkey-authenticated remote approval surface: approve or reject pending actions from a device other than the wallet host (`approve serve --remote`). |
| `stellar-agent-windows-identity` | Windows-only safe wrapper reading the process token user SID to bind approval attestations to the OS user. Absent off Windows; uses `unsafe` for its Win32 FFI. |
| `stellar-agent-pool` | SEP-5-derived channel-account pool with in-pool sequence management for concurrent submission without `tx_bad_seq`. |
| `stellar-agent-sep7` | Inbound `web+stellar:` URI parse and anti-phishing origin-domain signature verification; never signs, submits, or auto-POSTs. |
| `stellar-agent-sep10` | SEP-10 web-auth client: challenge parse and validation, JWT session, HTTP challenge fetch and submit, ephemeral-key flow. |
| `stellar-agent-sep43` | SEP-43 `ModuleInterface` dispatch substrate (`get_address`, `sign_transaction`, `sign_auth_entry`, `sign_message`, `get_network`). |
| `stellar-agent-sep45` | SEP-45 contract-account web-auth: challenge validation, JWT session, ephemeral and persistent auth-entry signing. |
| `stellar-agent-sep48` | SEP-48 contract-interface typed-arg preview and SEP-47 contract-interface discovery; non-authoritative display only. |
| `stellar-agent-sep53` | SEP-53 prefixed message sign and verify over ed25519. |
| `stellar-agent-anchor` | Privacy-first anchor client: SEP-6 `/info` discovery and SEP-24 interactive-URL hand-off with same-domain SSRF bind; never opens or follows the URL. |
| `stellar-agent-toolsets` | `TOOLSET.md` format parse, capability-manifest validation, and the pre-canonicalisation argument-validation guard; format and parse substrate only. |
| `stellar-agent-toolsets-install` | Toolset install and uninstall with hash verification, ed25519 publisher signature and trust set, safe tar extraction, attestation gate, and atomic pin record. |
| `stellar-agent-toolsets-runtime` | Capability-to-tool matrix, gated resolver, signing denylist, and the enforcement forming the toolset isolation boundary. |
| `stellar-agent-defi` | DeFi-adapter substrate: contract-pin framework, the typed-preview trait, and the dispatch-verb seam (`lend`/`trade`/`vault`/`bridge`); ships no live verb. |
| `stellar-agent-blend` | Blend lending adapter: typed request submit, pool-WASM version pin, simulate-authoritative health guard, oracle-staleness policy; drives the `lend` verb. |
| `stellar-agent-defindex` | DeFindex vault adapter: typed deposit and withdraw with mandatory `min_out`, role disclosure, upgradable-flag refusal gate; drives the `vault` verb. |
| `stellar-agent-dex` | Soroswap router-direct swap adapter with absolute `amount_out_min`, pre-sign slippage re-verify, token canonicalisation, bounded deadline, venue allowlist and router pin; drives `trade`/`quote`. |
| `stellar-agent-stablecoin` | Stablecoin substrate: USDC/EURC issuer pins, denomination resolver, USDT hard-refusal, clawback disclosure, typed trustline preview; backs the `trustline` verb. |
| `stellar-agent-x402` | Payer-side x402 Exact-Stellar payment payload builder (validate, build, simulate, sign, re-simulate, finalize). |
| `stellar-agent-x402-identity` | SEP-10 counterparty-identity pre-payment gate for x402, returning a JWT Bearer companion bound at the HTTP layer; never mutates the payment XDR. |
| `stellar-agent-mcp-macros` | Proc-macro crate exporting `#[mcp_tool_router]`, which scans `#[mcp_tool_item(...)]` markers and emits `inventory::submit!` tool-registry entries. |
| `stellar-agent-mcp` | MCP stdio server library and binary: `WalletServer`, the bounded stdio transport, per-family tool modules, and the inventory-collected tool registry feeding the policy engine. |
| `stellar-agent-cli` | The `stellar-agent` CLI binary (discovered as `stellar agent ...`); a clap dispatch layer over the library crates. |
| `stellar-agent-test-support` | Dev-only harness: log-capture and secret-leakage assertions, in-memory keyring mock, XDR and strkey fixtures, HTTP and contract doubles, live-network testnet helpers. |

## Crate classification

- **Binaries (2):** `stellar-agent-cli` (binary `stellar-agent`) and `stellar-agent-mcp` (binary `stellar-agent-mcp`, plus a library re-export for integration tests).
- **Plain libraries:** `core`, `network`, `claimable`, `sep5`, `xdr-limits`, `nonce`, `smart-account`, `webauthn-bridge`, `loopback-http`, `approval-ui`, `approval-remote`, `pool`, `sep7`, `sep10`, `sep43`, `sep45`, `sep48`, `sep53`, `anchor`, `toolsets`, `toolsets-install`, `toolsets-runtime`, `defi`, `blend`, `defindex`, `dex`, `stablecoin`, `x402`, `x402-identity`.
- **Proc-macro library:** `mcp-macros`, the compiler-plugin companion to the `inventory` runtime in `mcp`.
- **Platform-gated:** `windows-identity`, target-gated to `cfg(target_os = "windows")`. It uses `unsafe` for Win32 FFI as its core capability and is absent off Windows. (The CLI also carries a narrowly-scoped `#[allow(unsafe_code)]` for a POSIX `geteuid` FFI declaration in the audit-verify owner check.)
- **Dev-only:** `test-support`, consumed strictly as a `[dev-dependencies]` entry behind gated test-harness features and never as a runtime dependency.

## Where the policy, approval, and audit substrate lives

The policy engine, approval spine, and audit log all live in `stellar-agent-core`. The relevant modules:

- `policy` — the `PolicyEngine` trait, the typed `Decision` surface, the `NoopPolicyEngine`, and `policy::v1::PolicyEngineV1` (signature-verified typed `Criterion` rules, first-match default-deny). The server-side `build_tool_registry` lives here and is fail-closed: a duplicate registration name is a fatal startup error, not a silent first-wins drop.
- `approval` — the per-profile `PendingApprovalStore` (TOML-backed, single-writer with an exclusive advisory lock), the HMAC-SHA256 attestation primitive, and the process-uid helper that binds an attestation to the OS user.
- `audit_log` — the append-only hash-chained JSONL writer, the chain primitives, and `verify_log` for end-to-end chain verification.

These primitives are synchronous and runtime-free; `core` uses Tokio only for the unlock-window TTL timer in `Wallet::unlock`. The security rationale for each is in [security-internals.md](security-internals.md).

## How the binaries wire the tool registry to the substrate

The MCP server registers tools at link time. Each tool function inside the `#[mcp_tool_router]` impl block carries an `#[mcp_tool_item(...)]` annotation; the `mcp-macros` proc-macro emits an `inventory::submit!` record per tool. `WalletServer::new` iterates `inventory::iter::<McpToolRegistration>()` to build the descriptor map, and the same map is what `PolicyEngine::evaluate` is called against at `tools/call` dispatch. The policy-engine call site at dispatch is identical whether the active engine is `NoopPolicyEngine` or `PolicyEngineV1`; only the resolved engine differs per profile. The MCP crate also bridges the network account view into the policy engine's `AccountReservesView` via its `policy_adapter` module when populating the evaluation context. The MCP transport is a bounded stdio codec with a 1 MiB maximum line length, set explicitly rather than using the framework default.

The CLI registers no MCP tools. It is a clap `Subcommand` tree in `main.rs` dispatching to per-command `run` functions over the library crates. The top-level subcommands are `approve`, `audit`, `accounts`, `balances`, `counterparty`, `friendbot`, `fees`, `pay`, `claim`, `pool`, `profile`, `credentials`, `lend`, `vault`, `trade`, `trustline`, `toolsets`, and `smart-account`. Before dispatch, `main` installs the redacting log subscriber and runs a local-only startup advisory that scans the active profile's audit log for context rules referencing retired verifier wasm hashes; the advisory makes no network calls and never aborts startup. Each command renders a JSON `Envelope` and the process exits `0` on success or `1` on error.
