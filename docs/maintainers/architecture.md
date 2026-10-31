# Architecture

This document maps the workspace for maintainers and contributors. It describes how the 37 workspace members are layered, which crate owns which responsibility, and how the two shipped binaries wire the tool surface to the policy, approval, and audit substrate.

For concept-level background read [../concepts.md](../concepts.md). For build and toolchain instructions read [building.md](building.md). For the security-relevant internals read [security-internals.md](security-internals.md). The contributor gate checklist is [review-checklist.md](review-checklist.md).

## Workspace overview

The repository is a single Cargo workspace (`resolver = "2"`) with 37 member crates under `crates/`, all named `stellar-agent-*`. Shared package metadata is inherited from `[workspace.package]`: version `0.1.0-alpha.13`, Rust edition `2024`, license `Apache-2.0`, repository `https://github.com/Soneso/stellar-agent-wallet`, author `Soneso`. Of these, 36 are published on crates.io at the shared workspace version, in dependency order from the tagged release commit. The unpublished `stellar-agent-smart-account-acceptance` member holds the smart-account live suites that need a browser, the MCP server, the WebAuthn bridge, or the SEP-48, DeFi, DeFindex, and soroban-spec-tools crates.

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

Crates form a directed acyclic graph from foundational substrate up to the two binaries. No published crate depends on a binary. The unpublished `stellar-agent-smart-account-acceptance` member sits above layer 4 as a test-only leaf that nothing depends on.

### Layer 0: substrate

`stellar-agent-sep5`, `stellar-agent-xdr-limits`, `stellar-agent-soroban-auth`, `stellar-agent-windows-identity`, `stellar-agent-loopback-http`, `stellar-agent-toolsets`, `stellar-agent-mcp-macros`, and `stellar-agent-test-support` have no workspace dependencies. `stellar-agent-core` builds on `xdr-limits`, with `windows-identity` on Windows and optional test helpers from `test-support`. `stellar-agent-headless-keyring` also uses `windows-identity` on Windows. `stellar-agent-network` builds on `core`, `headless-keyring`, and `xdr-limits`; `stellar-agent-nonce` builds on `core` and `network`. Together they provide types, storage, RPC transport, key derivation, XDR bounds, authorization preimages, and replay nonces.

### Layer 1: orchestration and toolsets

`stellar-agent-smart-account` orchestrates OpenZeppelin `stellar-accounts` over `core` and `network`. `stellar-agent-webauthn-bridge` uses `smart-account`, `core`, and `loopback-http` for browser ceremonies. `stellar-agent-claimable` supplies claimable-balance logic over `core` and `network`; `stellar-agent-pool` adds channel accounts over those crates and `sep5`. `stellar-agent-toolsets-install` builds on `toolsets` and `core`; `stellar-agent-toolsets-runtime` builds on both and `toolsets-install`.

### Layer 2: protocols and approval surfaces

`stellar-agent-sep7`, `stellar-agent-sep10`, `stellar-agent-sep45`, `stellar-agent-sep48`, `stellar-agent-sep53`, `stellar-agent-anchor`, and `stellar-agent-x402-identity` provide protocol helpers. Within this layer, `x402-identity` depends on `sep10`; `stellar-agent-sep43` depends on `sep53`; `stellar-agent-x402` and `stellar-agent-mpp` depend on `sep43`. The browser approval surfaces also sit here: `stellar-agent-approval-ui` depends on `toolsets-runtime`, and `stellar-agent-approval-remote` depends on `approval-ui` and `smart-account`. `stellar-agent-mpp` is shared by both binaries; the CLI and MCP crates adapt its library.

### Layer 3: DeFi substrate and adapters

`stellar-agent-defi` is the adapter substrate: the contract-pin framework, the typed-preview trait, and the dispatch-verb seam (`lend`/`trade`/`vault`/`bridge`). It ships no live verb. The `stellar-agent-defindex` and `stellar-agent-dex` adapters implement that substrate for `vault` and `trade`/`quote`, with submit paths through `smart-account`. `stellar-agent-stablecoin` depends on `core` and `network` and supplies classic trustline helpers. The CLI and MCP crates wire the `trustline` verb.

### Layer 4: binaries

The Layer 0 `stellar-agent-mcp-macros` crate feeds the MCP registry. `stellar-agent-mcp` and `stellar-agent-cli` are the two sibling binaries; both consume the library crates and neither depends on the other.

## The two-sibling-binary model

The wallet ships two surfaces from two binary crates.

- `stellar-agent` is built from `stellar-agent-cli`. It is installed on `PATH` and is also discovered as `stellar agent ...` by the incumbent `stellar-cli` through its external-binary plugin convention. The crate root is `crates/stellar-agent-cli/src/main.rs`.
- `stellar-agent-mcp` is built from `stellar-agent-mcp`. It is an MCP server spoken over stdio. The crate has both `src/lib.rs` (re-exported for integration tests) and `src/main.rs` (the binary entry point that starts the server process).

The two binaries are siblings, not a dependency pair. `stellar-agent-cli` does not depend on `stellar-agent-mcp`. Most SEP, anchor, and x402 protocol crates remain MCP-only; `stellar-agent-mpp` is shared by both binaries because MPP has a first-class operator CLI. The MCP binary adds the wider protocol surface plus the `mcp-macros` proc-macro with the `inventory` runtime. The per-crate table below carries the detail.

Both binaries share a single release archive. The `[package.metadata.binstall]` blocks in both crates point at the same `stellar-agent-{version}-{target}.tar.xz` (`.zip` on Windows), and `{ bin }` resolves to each crate's own binary name. Each tagged release publishes those archives; `cargo binstall` resolves the crate on crates.io and fetches the matching archive from the release assets. It installs this repository's release archive for the host's target, or for a compatible target the host runs, such as the x86_64 Windows archive under emulation. Both blocks set `disabled-strategies = ["quick-install", "compile"]`, so binstall fails when no such archive exists; it checks the download over TLS only, with no signature. On a host outside the release matrix in `release.yml`, `cargo install --locked stellar-agent-cli@<version> stellar-agent-mcp@<version>` from crates.io, or a source build with `cargo build --release --locked`, applies. See [building.md](building.md) for the build flow.

## Per-crate responsibility

| Crate | Responsibility |
| --- | --- |
| `stellar-agent-core` | Shared substrate: typed amounts, typed `WalletError`, JSON `Envelope`, profiles, observability, smart-account auth-digest helpers, the policy-engine trait and Noop/V1 implementations, the approval spine, and the audit log. The `rpc_budget` module (`SequentialRpcBudget` / async `bound_stage`) uses Tokio deadlines to bound sequential RPC flows: deployment stages, rule scans, list operations, and retry attempts. |
| `stellar-agent-network` | Async Stellar RPC client, account views, assembly, SEP-29 checks, hardware signers, and Friendbot. Enforces endpoint identity, signature-network binding, cross-check witnesses, and submission recording; owns keyring/headless-store initialization, the policy window store, counterparty cache, and sequence-floor hook. The idempotent-submit APIs are library-only; shipped verbs use `submit_transaction_and_wait`. |
| `stellar-agent-claimable` | Claimable-balance domain logic: balance-id normalization, predicate evaluation, entry and trustline fetch, and claim preview; drives the `claim` verb. |
| `stellar-agent-sep5` | SEP-5 / BIP-44 HD ed25519 key derivation (`m/44'/148'/index'`, SLIP-0010 hardened) from a BIP-39 mnemonic or seed; no I/O or RNG. |
| `stellar-agent-xdr-limits` | Leaf crate supplying recursion-depth and length bounds for decoding untrusted XDR. |
| `stellar-agent-soroban-auth` | Leaf crate mapping a Soroban credential arm to its authorization preimage (envelope type 9, or CAP-71 envelope type 10), building the preimage, and hashing it into the signature payload. |
| `stellar-agent-nonce` | HMAC-SHA256 wallet-issued nonce, in-memory TTL replay window, `ToolCatalogue` trait, and nonce-key rotation. |
| `stellar-agent-smart-account` | Off-chain orchestration over OpenZeppelin `stellar-accounts`: deployment, context-rule install, WebAuthn passkey signer, threshold updates, signer-set baseline checks before signing, wasm-hash pinning, verifier migration, multicall, and upgrade timelock. |
| `stellar-agent-webauthn-bridge` | Loopback-only HTTP listener ferrying browser WebAuthn ceremony bytes into the core approval store, behind a host/origin/CSP/body-limit middleware stack. |
| `stellar-agent-loopback-http` | Shared tower/axum defence-in-depth middleware for the wallet's browser-facing HTTP listeners (Host and Origin allowlists, hardened security headers), plus the `brand` module holding the stylesheet, the inline project mark, and `PageIdentity` (the optional per-deployment name and mark those listeners' pages render), and the `escape` module holding the one HTML-escaping definition every page applies to dynamic text. |
| `stellar-agent-approval-ui` | Localhost approval-inbox web UI: a loopback HTTP server surfacing the pending-approval queue for browser approve/reject (`approve serve`). |
| `stellar-agent-approval-remote` | TLS-protected, passkey-authenticated remote approval surface: approve or reject pending actions from a device other than the wallet host (`approve serve --remote`). |
| `stellar-agent-windows-identity` | Windows-only safe wrapper reading the process token user SID to bind approval attestations to the OS user, plus DPAPI protect/unprotect wrappers for the headless keyring store. Absent off Windows; uses `unsafe` for its Win32 FFI. |
| `stellar-agent-headless-keyring` | Opt-in, file-backed `keyring-core` credential store for non-interactive deployments (services, SSH sessions, scheduled tasks) where the platform keyring is unreachable: XChaCha20-Poly1305 under an operator-supplied environment key, or DPAPI protection on Windows; sidecar-locked, fail-closed, never a silent fallback. |
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
| `stellar-agent-defindex` | DeFindex vault adapter: typed deposit and withdraw with mandatory `min_out`, role disclosure, upgradable-flag refusal gate; drives the `vault` verb. |
| `stellar-agent-dex` | Soroswap router-direct swap adapter with absolute `amount_out_min`, pre-sign slippage re-verify, token canonicalisation, bounded deadline, venue allowlist and router pin; drives `trade`/`quote`. |
| `stellar-agent-stablecoin` | Stablecoin substrate: USDC/EURC issuer pins, denomination resolver, USDT hard-refusal, clawback disclosure, typed trustline preview; backs the `trustline` verb. |
| `stellar-agent-x402` | Payer-side x402 Exact-Stellar payment payload builder (validate, build, simulate, sign, re-simulate, finalize). |
| `stellar-agent-x402-identity` | SEP-10 counterparty-identity pre-payment gate for x402, returning a JWT Bearer companion bound at the HTTP layer; never mutates the payment XDR. |
| `stellar-agent-mpp` | Strict testnet sponsored MPP charge parsing, request binding, simulation, one-shot payer authorization, durable lifecycle, credential encoding, receipt observation, and ledger reconciliation; shared by CLI and MCP. |
| `stellar-agent-mcp-macros` | Proc-macro crate exporting `#[mcp_tool_router]`, which scans `#[mcp_tool_item(...)]` markers and emits `inventory::submit!` tool-registry entries. |
| `stellar-agent-mcp` | MCP stdio server library and binary: `WalletServer`, the bounded stdio transport, per-family tool modules, and the inventory-collected tool registry feeding the policy engine. |
| `stellar-agent-cli` | The `stellar-agent` CLI binary (discovered as `stellar agent ...`); a clap dispatch layer over the library crates. |
| `stellar-agent-test-support` | Dev-only harness: log-capture and secret-leakage assertions, in-memory keyring mock, XDR and strkey fixtures, HTTP and contract doubles, live-network testnet helpers. |
| `stellar-agent-smart-account-acceptance` | Unpublished member holding the smart-account live testnet suites that drive a browser, the MCP server, the WebAuthn bridge, or the SEP-48, DeFi, and DeFindex crates. Its `testnet-integration` feature activates every dependency, so offline builds compile an empty library. |

## Crate classification

- **Binaries (2):** `stellar-agent-cli` (binary `stellar-agent`) and `stellar-agent-mcp` (binary `stellar-agent-mcp`, plus a library re-export for integration tests).
- **Plain libraries:** `core`, `network`, `claimable`, `sep5`, `xdr-limits`, `soroban-auth`, `nonce`, `headless-keyring`, `smart-account`, `webauthn-bridge`, `loopback-http`, `approval-ui`, `approval-remote`, `pool`, `sep7`, `sep10`, `sep43`, `sep45`, `sep48`, `sep53`, `anchor`, `toolsets`, `toolsets-install`, `toolsets-runtime`, `defi`, `defindex`, `dex`, `stablecoin`, `x402`, `x402-identity`, `mpp`.
- **Proc-macro library:** `mcp-macros`, the compiler-plugin companion to the `inventory` runtime in `mcp`.
- **Platform-gated:** `windows-identity`, target-gated to `cfg(target_os = "windows")`. It uses `unsafe` for Win32 FFI as its core capability and is absent off Windows. (The CLI also carries a narrowly-scoped `#[allow(unsafe_code)]` for a POSIX `geteuid` FFI declaration in the audit-verify owner check.)
- **Dev-only:** `test-support`, consumed only by tests and test-only members and never by a shipped code path. Most members take it as a `[dev-dependencies]` entry; `core` and the acceptance member take it as an optional `[dependencies]` entry behind a test feature.
- **Unpublished test member:** `smart-account-acceptance`, which holds live acceptance suites only and is never published.

## Where the policy, approval, and audit substrate lives

The policy engine, approval spine, and audit log all live in `stellar-agent-core`. The relevant modules:

- `policy`: the `PolicyEngine` trait, the typed `Decision` surface, the `NoopPolicyEngine`, and `policy::v1::PolicyEngineV1` (signature-verified typed `Criterion` rules, first-match default-deny). The registry these policy types serve is built in the MCP crate: `build_tool_registry` in `stellar-agent-mcp`'s `tools/common.rs` fails closed: a duplicate registration name is a fatal startup error, not a silent first-wins drop.
- `approval`: the per-profile `PendingApprovalStore` (TOML-backed, with an exclusive lifetime advisory lock that refuses a second opener), the HMAC-SHA256 attestation primitive, and the process-uid helper that binds an attestation to the OS user.
- `audit_log`: the append-only hash-chained JSONL writer, chain verification through `verify_log`, keyring tip-anchor and binding primitives, and the consent-row outbox. The `profile::receipt` module stores durable submission receipts. The network crate's `submission_record` recorder writes the pending audit row before sending; its `policy_state` window store reserves and settles spend for stateful criteria.

Policy evaluation and the approval and audit stores are synchronous. `core` also uses Tokio for the unlock-window TTL timer in `Wallet::unlock` and deadline enforcement in `rpc_budget::bound_stage`. The security rationale for each is in [security-internals.md](security-internals.md).

### Approval error taxonomy

`WalletError::Approval(ApprovalFailure)` belongs to `ErrorCategory::Approval`.
Each variant exposes an `approval.*` wire code and a plain diagnostic message.
The CLI and shared attestation API map store errors in their call-site context.
`approval::error::ApprovalError` is the store error type.
The UI classifies failures through `WalletError::code()`.
The shared MCP envelope carries these codes; direct JSON-RPC approval errors use their message form.
MCP attestation validation reports missing and expired approvals as `policy.approval_required`.

## How the binaries wire the tool registry to the substrate

The MCP server registers tools at link time. Each tool function inside the `#[mcp_tool_router]` impl block carries an `#[mcp_tool_item(...)]` annotation; the `mcp-macros` proc-macro emits an `inventory::submit!` record per tool. `WalletServer::new` iterates `inventory::iter::<McpToolRegistration>()` to build the descriptor map, and gated handlers evaluate those descriptors through `PolicyEngine::evaluate_full` or `evaluate_with_value_full`. These return the decision and sized value effects for audit recording. The policy-engine call site at dispatch is identical whether the active engine is `NoopPolicyEngine` or `PolicyEngineV1`; only the resolved engine differs per profile. The bridge from the network account view to the policy engine's `AccountReservesView` / `AccountIdentityView` lives in `stellar-agent-network::policy_view` (`AccountViewAdapter`). It is hosted there rather than in `core` or `mcp` because `AccountView` is defined in `network`, which already depends on `core`, so no new dependency edge is needed. Both the MCP tool handlers and the CLI's classic verbs (`pay`, `claim`, `accounts create`) construct the adapter directly when populating the evaluation context. `stellar-agent-mcp::policy_adapter` re-exports `AccountViewAdapter`. The MCP transport is a bounded stdio codec with a 1 MiB maximum line length, set explicitly rather than using the framework default. For payments, `stellar_pay` runs policy, builds the envelope, mints a commit nonce, and persists a pending approval when required. `stellar_pay_commit` refuses mainnet, decodes authoritative arguments, checks endpoint identity, and evaluates policy and any required attestation. It then checks envelope agreement, obtains any required witness, acquires the audit writer, verifies and consumes the nonce, signs, and submits through the recorder. The recorder persists the receipt and pending row before sending, then records the outcome; an unknown outcome stays pending for reconciliation.

`WalletServer` holds a small amount of in-process, long-lived state alongside the tool registry, each behind its own `TokioMutex` for async-safe access across concurrent dispatches. This includes the nonce replay window (`stellar-agent-nonce::ReplayWindow`), and `stellar-agent-mcp::sequence_floor::SequenceFloorTracker`. The latter is a bounded, FIFO-evicted map from source account to the highest sequence number a confirmed submit in this process consumed. The `stellar_pay_commit` / `stellar_claim_commit` / `stellar_trustline_commit` / `stellar_create_account_commit` build paths (and their simulate-phase twins) consult the tracker after every `fetch_account`. A fetched sequence below the tracked floor triggers a bounded re-poll before the build proceeds. This closes an ordinary read-after-write propagation-lag window between the RPC node that served a just-confirmed submit and the node that serves the next build. The tracker is advisory only: a build that still observes a stale sequence after the bounded window proceeds with it. The eventual submit fails typed `submission.sequence_number_stale` exactly as it would without the tracker. It is MCP-server-only: the CLI is a fresh process per invocation with no history to track against.

The replay window belongs to one `WalletServer` instance; the boot salt belongs
to the process. The sequence floor is advisory and never invents a sequence.
See [Two sessions on one profile](security-internals.md#two-sessions-on-one-profile)
for durable stores, contention results and restart limits.

The same tracker also backs the DeFi adapter submit paths (`stellar_dex_trade`, `stellar_defindex_vault_deposit`/`_withdraw`), via a `SequenceFloorHook` trait (`stellar-agent-network::sequence_floor`) that decouples the tracker's concrete type from the lower crates in the dependency graph. Each MCP DeFi tool wraps `WalletServer`'s tracker in a local `TrackerHook` and sets it on `DefiAdapterCtx::sequence_floor`, which the adapter crates (`stellar-agent-dex`, `stellar-agent-defindex`) forward into `SubmitInvokeArgs::sequence_floor` at their `submit_signed_invoke` call site (`stellar-agent-smart-account::submit`). `submit_signed_invoke`'s own account fetch consults the SAME hook for the bounded catch-up poll, and records the consumed sequence back into it on confirmed submit. There is one shared floor per source account across the classic commit verbs and the DeFi adapters, not two independent ones. `SubmitInvokeArgs::sequence_floor` defaults to `None` for every other caller of `submit_signed_invoke` (rules/signers self-calls, the multicall bundle path), which is CLI-only and out of scope for the same reason the tracker itself is MCP-server-only.

The CLI registers no MCP tools. It is a clap `Subcommand` tree in `main.rs` dispatching to per-command `run` functions over the library crates. The top-level subcommands are `approve`, `tx`, `audit`, `accounts`, `balances`, `counterparty`, `friendbot`, `fees`, `pay`, `mpp`, `pool`, `profile`, `credentials`, `vault`, `trade`, `trustline`, `claim`, `toolsets`, and `smart-account`. Before dispatch, `main` installs the redacting log subscriber and runs a local-only startup advisory that scans the active profile's audit log for context rules referencing retired verifier wasm hashes. The advisory makes no network calls and never aborts startup. Each command renders a JSON `Envelope` and the process exits `0` on success or `1` on error.
