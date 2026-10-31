# Maintainer architecture

For the wallet's actors, trust boundaries, payment flow, and custody model, start with the [public architecture page](../architecture.md).
This page maps crate ownership, dependency rules, lints, and binary wiring.
Build instructions are in [Building and testing](building.md); contribution checks are in the [review checklist](review-checklist.md).

## Workspace overview

The Cargo workspace contains 37 members under `crates/`, named `stellar-agent-*`.
Shared package metadata uses Rust edition 2024 and the Apache-2.0 license.
Of these members, 36 are published; `stellar-agent-smart-account-acceptance` holds unpublished live acceptance suites.
Shared dependency pins live in `[workspace.dependencies]` in the root `Cargo.toml`.

## Dependency layers

The layers below order normal workspace dependencies, including optional and target-gated dependencies.
Crate names omit the `stellar-agent-` prefix.
A crate depends on lower layers; the listed composite exceptions depend on earlier members of their own layer.
Neither binary depends on the other, and no published library depends on a binary.

| Layer | Members and rules |
| --- | --- |
| Foundations | `xdr-limits`, `soroban-auth`, `sep5`, `windows-identity`, `loopback-http`, `toolsets`, `mcp-macros`, and `test-support` have no normal workspace dependencies. |
| Core | `core` uses `xdr-limits`, optional `test-support`, and `windows-identity` on Windows. `headless-keyring` uses `windows-identity` on Windows. |
| Network and installation | `network` builds on `core`, `headless-keyring`, `soroban-auth`, and `xdr-limits`. `toolsets-install` uses `toolsets` and `core`. `sep45` uses `core` and `xdr-limits`. |
| Domain libraries | `nonce`, `pool`, `claimable`, `smart-account`, `defi`, `stablecoin`, `sep7`, `sep10`, `sep48`, `sep53`, `anchor`, and `toolsets-runtime` depend only on earlier layers. |
| Composite libraries | `sep43`, `x402`, `x402-identity`, `mpp`, `dex`, `defindex`, `webauthn-bridge`, `approval-ui`, and `approval-remote`. Within this layer, `x402` and `mpp` depend on `sep43`; `approval-remote` depends on `approval-ui`. |
| Binaries | `cli` and `mcp` consume library crates. |
| Acceptance | `smart-account-acceptance` is a test-only leaf above the binaries. |

`defi` defines contract pins, typed previews, and adapter interfaces.
`dex` and `defindex` implement its trade and vault adapters through `smart-account` submission.
`stablecoin` supplies classic trustline helpers over `core` and `network`; the binaries wire the trustline commands.

## Workspace lints

Each crate inherits `[workspace.lints]` through `[lints] workspace = true`.

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

Production code has four scoped `unsafe_code` allow sites across three areas: Windows identity and DPAPI, the CLI audit verifier's POSIX user check, and MCP Linux process hardening.
Tests have additional scoped allowances.
Errors use typed results; output uses JSON envelopes and redacting logs.
Scoped allowances document necessary exceptions.
The [lint gate](building.md#lint) enforces these rules.

## The two binaries

`stellar-agent-cli` builds `stellar-agent` from `src/main.rs`.
The external-command convention also makes it discoverable as `stellar agent ...`.
`stellar-agent-mcp` builds the MCP server, with a library entry point used by integration tests.

MCP directly links `sep7`, `sep43`, `sep48`, `sep53`, `anchor`, `x402`, and `x402-identity`.
Both binaries link `mpp`, which uses `sep43`.
`sep10` reaches MCP through `x402-identity`; neither binary links `sep45`.

Both binaries share the release archive referenced by their `package.metadata.binstall` blocks.
See [Getting started](../getting-started.md) for installation and [Building](building.md#building) for source builds.

## Per-crate responsibility

| Crate | Responsibility |
| --- | --- |
| `stellar-agent-core` | Typed amounts, errors, envelopes, profiles, policy engines, approvals, and audit records. Its `policy`, `approval`, and `audit_log` modules provide synchronous evaluation and stores, including the TOML approval store with its exclusive lifetime lock. Owns the receipt store, audit tip anchor, binding, and consent outbox. Wallet unlock and seed access are synchronous and runtime-free; Tokio bounds sequential RPC deadlines. |
| `stellar-agent-network` | Async Stellar RPC client, account views, assembly, SEP-29 checks, hardware signers, and Friendbot. Enforces endpoint identity, signature-network binding, witnesses, and submission recording. Owns keyring initialization, the policy window store, counterparty cache, and sequence-floor hook. The idempotent-submit APIs are library-only; shipped verbs use `submit_transaction_and_wait`. |
| `stellar-agent-claimable` | Claimable-balance domain logic: balance-id normalization, predicate evaluation, entry and trustline fetch, and claim preview; drives the `claim` verb. |
| `stellar-agent-sep5` | SEP-5 / BIP-44 HD ed25519 key derivation (`m/44'/148'/index'`, SLIP-0010 hardened) from a BIP-39 mnemonic or seed; no I/O or RNG. |
| `stellar-agent-xdr-limits` | Leaf crate supplying recursion-depth and length bounds for decoding untrusted XDR. |
| `stellar-agent-soroban-auth` | Leaf crate mapping a Soroban credential arm to its authorization preimage (envelope type 9, or CAP-71 envelope type 10), building the preimage, and hashing it into the signature payload. |
| `stellar-agent-nonce` | HMAC-SHA256 wallet-issued nonce, in-memory TTL replay window, `ToolCatalogue` trait, and nonce-key rotation. |
| `stellar-agent-smart-account` | Off-chain orchestration over OpenZeppelin `stellar-accounts`: deployment, context-rule install, WebAuthn passkey signer, threshold updates, signer-set baseline checks before signing, wasm-hash pinning, verifier migration, multicall, and upgrade timelock. |
| `stellar-agent-webauthn-bridge` | Loopback-only HTTP listener ferrying browser WebAuthn ceremony bytes into the core approval store, behind a host/origin/CSP/body-limit middleware stack. |
| `stellar-agent-loopback-http` | Shared HTTP middleware for Host and Origin allowlists and security headers. The `brand` module supplies page identity and styles; `escape` provides HTML escaping for dynamic text. |
| `stellar-agent-approval-ui` | Localhost approval-inbox web UI: a loopback HTTP server surfacing the pending-approval queue for browser approve/reject (`approve serve`). |
| `stellar-agent-approval-remote` | TLS-protected, passkey-authenticated remote approval surface: approve or reject pending actions from a device other than the wallet host (`approve serve --remote`). |
| `stellar-agent-windows-identity` | Safe wrappers for Windows user identity and DPAPI encryption, with scoped `unsafe` calls to Win32. Builds on other platforms as a shim returning `UnsupportedPlatform`; consumers gate the dependency to Windows. |
| `stellar-agent-headless-keyring` | Explicitly selected file-backed credential store with sidecar locks. Uses XChaCha20-Poly1305 with an operator-supplied key or Windows DPAPI. Configuration failures refuse access. |
| `stellar-agent-pool` | SEP-5-derived channel-account pool with in-pool sequence management for concurrent submission without `tx_bad_seq`. |
| `stellar-agent-sep7` | Inbound `web+stellar:` URI parse and anti-phishing origin-domain signature verification; never signs, submits, or auto-POSTs. |
| `stellar-agent-sep10` | SEP-10 web-auth client: challenge parse and validation, JWT session, HTTP challenge fetch and submit, ephemeral-key flow, and the authorized mainnet completion that takes a message-use receipt. |
| `stellar-agent-sep43` | SEP-43 `ModuleInterface` dispatch substrate (`get_address`, `sign_transaction`, `sign_auth_entry`, `sign_message`, `get_network`). |
| `stellar-agent-sep45` | SEP-45 contract-account web-auth: challenge validation, JWT session, ephemeral and persistent auth-entry signing. |
| `stellar-agent-sep48` | SEP-48 contract-interface typed-arg preview and SEP-47 contract-interface discovery; non-authoritative display only. |
| `stellar-agent-sep53` | SEP-53 prefixed message sign and verify over ed25519. |
| `stellar-agent-anchor` | Privacy-first anchor client: SEP-6 `/info` discovery and SEP-24 interactive-URL hand-off with same-domain SSRF bind; never opens or follows the URL. |
| `stellar-agent-toolsets` | `TOOLSET.md` format parse, capability-manifest validation, and the pre-canonicalization argument-validation guard; format and parse substrate only. |
| `stellar-agent-toolsets-install` | Toolset install and uninstall with hash verification, ed25519 publisher signature and trust set, safe tar extraction, attestation gate, toolsets directory lock, and an atomic pin record authenticated by an HMAC under the installation's pin key. |
| `stellar-agent-toolsets-runtime` | Capability-to-tool matrix, gated resolver, signing denylist, pin and manifest-digest verification, and the enforcement bounding what the toolset dispatcher routes (not the server's native tools). |
| `stellar-agent-defi` | DeFi-adapter substrate: contract-pin framework, the typed-preview trait, and the dispatch-verb seam (`lend`/`trade`/`vault`/`bridge`); ships no live verb. |
| `stellar-agent-defindex` | DeFindex vault adapter: typed deposit and withdraw with mandatory `min_out`, role disclosure, upgradable-flag refusal gate; drives the `vault` verb. |
| `stellar-agent-dex` | Soroswap router-direct swap adapter with absolute `amount_out_min`, pre-sign slippage re-verify, token canonicalization, bounded deadline, venue allowlist and router pin; drives `trade`/`quote`. |
| `stellar-agent-stablecoin` | Stablecoin substrate: USDC/EURC issuer pins, denomination resolver, USDT hard-refusal, clawback disclosure, typed trustline preview; backs the `trustline` verb. |
| `stellar-agent-x402` | Payer-side x402 Exact-Stellar payment payload builder (validate, build, simulate, sign, re-simulate, finalize), and the authorized mainnet path that consumes the payment intent before signed re-simulation and returns the release authorization. |
| `stellar-agent-x402-identity` | SEP-10 counterparty-identity pre-payment gate for x402, returning a JWT Bearer companion bound at the HTTP layer; never mutates the payment XDR. It also holds the authorized mainnet gate that binds the authentication to the approved payment and returns the receipt continuation. |
| `stellar-agent-mpp` | Strict testnet sponsored MPP charge parsing, request binding, simulation, one-shot payer authorization, durable lifecycle, credential encoding, receipt observation, and ledger reconciliation; shared by CLI and MCP. |
| `stellar-agent-mcp-macros` | Proc-macro crate exporting `#[mcp_tool_router]`, which scans `#[mcp_tool_item(...)]` markers and emits `inventory::submit!` tool-registry entries. |
| `stellar-agent-mcp` | MCP stdio server library and binary: `WalletServer`, the bounded stdio transport, per-family tool modules, and the inventory-collected tool registry feeding the policy engine. |
| `stellar-agent-cli` | The `stellar-agent` CLI binary (discovered as `stellar agent ...`); a clap dispatch layer over the library crates. |
| `stellar-agent-test-support` | Dev-only harness: log-capture and secret-leakage assertions, in-memory keyring mock, XDR and strkey fixtures, HTTP and contract doubles, live-network testnet helpers. |
| `stellar-agent-smart-account-acceptance` | Unpublished member holding the smart-account live testnet suites that drive a browser, the MCP server, the WebAuthn bridge, or the SEP-48, DeFi, and DeFindex crates. Its `testnet-integration` feature activates every dependency, so offline builds compile an empty library. |

## Crate kinds

The workspace contains two binary packages, the `mcp-macros` procedural macro, ordinary libraries, and test helpers.
`test-support` serves test code; `core` and the acceptance member enable it through optional dependencies.
`windows-identity` builds on every platform; `core` and `headless-keyring` gate their dependency to Windows.
The acceptance member's dependencies activate through its test feature.

### Approval error taxonomy

`WalletError::Approval(ApprovalFailure)` belongs to `ErrorCategory::Approval`.
Each variant exposes an `approval.*` wire code and a plain diagnostic message.
The CLI and shared attestation API map store errors in their call-site context.
`approval::error::ApprovalError` is the store error type.
The UI classifies failures through `WalletError::code()`.
The shared MCP envelope carries these codes; direct JSON-RPC approval errors use their message form.
MCP attestation validation reports missing and expired approvals as `policy.approval_required`.

## Link-time tool wiring

Each MCP tool carries `#[mcp_tool_item(...)]` inside a `#[mcp_tool_router]` implementation.
The macro emits an `inventory::submit!` registration; `WalletServer::new` collects the records into the descriptor map.
Duplicate names are fatal startup errors.

Gated handlers call `PolicyEngine::evaluate_full` or `evaluate_with_value_full` with a descriptor and arguments.
The result includes the decision and sized value effects, which submission recording uses without deriving them again.
The profile selects Noop or the signature-verified V1 engine.
See the [payment flow](../architecture.md#one-agent-payment-end-to-end) for the order of checks, approval, and submission.

### Account views

`stellar-agent-network::policy_view::AccountViewAdapter` connects network account data to the policy engine's reserve and identity views.
Keeping the adapter in `network` uses its existing dependency on `core`.
MCP handlers and CLI `pay`, `claim`, `accounts create`, and `trustline` construct it directly.
`stellar-agent-mcp::policy_adapter` re-exports the type.

### In-process state

`WalletServer` holds a nonce replay window and a sequence-floor tracker behind separate Tokio mutexes.
The replay window belongs to one server instance; the nonce boot salt belongs to the process.
The tracker records the highest confirmed sequence per source in a bounded map with oldest-entry eviction.

Classic payment, claim, trustline, and account-creation handlers consult the tracker after fetching an account.
If a read is behind the floor, they poll again for a bounded interval.
The floor is advisory: an unresolved stale read proceeds and can receive `submission.sequence_number_stale` at submission.

One shared `TrackerHook` type implements the network crate's `SequenceFloorHook` trait for MCP callers.
DeFi handlers pass it through `DefiAdapterCtx` into `SubmitInvokeArgs`.
The smart-account submit path polls through that hook and records confirmed sequences back into it.
Classic and DeFi handlers therefore share the same floor for each source.
Other callers can leave the hook unset.

The CLI starts a fresh process per invocation.
See [Two sessions on one profile](security-internals.md#two-sessions-on-one-profile) for durable stores, lock contention, and restart limits.

## CLI dispatch

The CLI uses a clap `Subcommand` tree in `main.rs`, dispatching to command `run` functions over library crates.
Its top-level commands are `approve`, `tx`, `audit`, `accounts`, `balances`, `counterparty`, `friendbot`, `fees`, `pay`, `mpp`, `pool`, `profile`, `credentials`, `vault`, `trade`, `trustline`, `claim`, `toolsets`, and `smart-account`.

Before dispatch, `main` installs redacting logs and scans the active profile's audit log for context rules referencing retired verifier hashes.
This local advisory makes no network calls and never aborts startup.
Commands render a JSON `Envelope`; success exits with `0`, and errors exit with `1`.

## Security detail

The public page describes [guarantees and enforcement](../architecture.md#guarantees-and-who-enforces-them).
Implementation detail lives in [Security internals](security-internals.md):

- [Attestations](security-internals.md#attestation-primitive) and [nonces](security-internals.md#nonce-scheme).
- [Audit records](security-internals.md#audit-hash-chain), tip anchors, bindings, and the consent outbox.
- [Network binding](security-internals.md#submit-layer-network-binding) and submission recording.
- [Policy evaluation](security-internals.md#policy-v1-evaluator) and its persistent spending windows.
