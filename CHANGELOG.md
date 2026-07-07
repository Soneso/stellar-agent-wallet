# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0-alpha.2] - 2026-07-07

### Added

- Remote operator approval: `approve serve --remote` binds a TLS-protected,
  passkey-authenticated listener so an operator can approve or reject pending
  wallet actions from another device, with per-entry WebAuthn assertions on
  every decision.
- Bounded agent delegation: context rules can be scoped to a single contract
  (`--context call-contract:<C>`) or wasm hash, first-class External-Ed25519
  signers attach to rules via a registered verifier, and a spending-limit
  policy enforces a per-rule rolling-window budget on-chain.
- Spending-limit observability and retuning: `smart-account rules
  get-spending-limit` reads an installed policy's live budget state,
  `set-spending-limit` retunes the limit without resetting spend history, and
  the read-only MCP tools `stellar_rules_list` / `stellar_rules_get` expose
  rule and budget state to agents.
- Agent-proposed context rules: the two-phase `stellar_rule_create` /
  `stellar_rule_create_commit` MCP pair routes rule installation through the
  operator-approval spine, with the fully resolved rule rendered on every
  approval surface before consent and the proposal digest bound into the
  attestation.
- Smart-account ergonomics: typed simple-threshold and weighted-threshold
  policy builders, a unified `deploy-policy --kind` verb, weighted-threshold
  mutators (`set-weighted-threshold`, `set-signer-weight`), batch signer
  addition, passkey/Ed25519/external genesis signers on `accounts deploy-c`,
  and new rule/signer read APIs.
- Interactive WebAuthn operator enrollment: `approve operator enroll
  --interactive` runs the passkey registration ceremony in the browser against
  a one-shot loopback server (bootstrap-token gated) and persists the
  credential without it passing through the shell; the argument mode remains
  the import path for credentials created on a remote listener's domain.
- `smart-account execute`: submit a CallContract invocation against an
  external contract, authorized by named context rules and signed by an
  External-Ed25519 rule key, with a separate fee-paying envelope signer.
  `rules create` gains `--signer-ed25519` / `--verifier` so an Ed25519-only
  rule can be installed entirely from the CLI.
- A provisional audit status in the verifier allowlist taxonomy: the vendored
  OpenZeppelin verifier entries now report `provisional` (named-party internal
  review) rather than overstating an external audit; `list-verifiers` carries
  the attestor and date as additive fields.
- All 34 workspace crates are published to crates.io, so the binaries install
  with `cargo install stellar-agent-cli` / `cargo install stellar-agent-mcp`
  (or `cargo binstall` without a `--git` URL) and the library crates resolve
  as normal registry dependencies.

### Changed

- Value-denominated fields on the machine-readable JSON wire are decimal
  strings, never JSON numbers: all i128 token quantities (dex, blend, vault,
  spending-limit budgets) and the residual i64/u64 stroop and fee fields
  (payment, account-creation, claim, trustline amounts and limits, fee-stats
  percentiles, served approval summaries). Raw JSON numbers on the migrated
  input fields are rejected. This is a breaking wire change; JSON numbers are
  exact only up to 2^53 in f64-backed parsers, and trustline limits routinely
  carry i64::MAX. The policy cap and reserve criteria now read the resolved
  stroop amounts on every dispatch shape, and pay's simulate gate arguments
  include the asset, so cap and reserve policies evaluate calls they
  previously refused or under-counted.
- Every CLI secret-env signing path handles the seed through an
  mlock-protected unlock window with explicit residue zeroization; when mlock
  is unavailable and the profile policy allows degraded operation, the
  degradation is recorded in the audit log as a `wallet_mlock_failed` event.
- Renamed the `wallet` CLI command group to `smart-account` (with `sa` as a
  shorter alias), and flattened the former nested `sa` admin subgroup so its
  verbs (`deploy-webauthn-verifier`, `migrate-verifier`, `list-verifiers`,
  `list-rules`, `register-multicall`, `unregister-multicall`, `timelock`) are now
  direct children of `smart-account` alongside `rules`, `signers`, and
  `multicall`. This is a breaking change to the CLI command surface.
- Bumped the vendored OpenZeppelin `stellar-accounts` and `stellar-governance`
  dependencies from `0.7.1` to `0.7.2` (a `soroban_sdk` 26.1.0 fix upstream, no
  entrypoint or ABI changes) and rebuilt all five vendored OZ WASM artifacts at
  the new tag. New smart-account, threshold-policy, timelock-controller, and
  WebAuthn-verifier deployments now use the `0.7.2` artifacts. Verifier and
  threshold-policy contracts already deployed from the `0.7.1` artifacts remain
  recognized and valid; nothing on-chain is redeployed.

## [0.1.0-alpha.1] - 2026-07-03

First public alpha of the Stellar Agent Wallet: a Stellar wallet for AI agents.
It provides a `stellar-agent` CLI and a `stellar-agent-mcp` MCP server over a shared
policy engine, operator-approval spine, and tamper-evident audit log.

### Added

- `stellar-agent` CLI for accounts, payments, balances, trustlines,
  claimable-balance claims, Friendbot funding, fee stats, counterparty identity,
  smart-account governance, DeFi, the channel-account pool, profiles,
  credentials, approvals, audit verification, and agent toolsets.
- `stellar-agent-mcp` MCP stdio server exposing the wallet capabilities as tools
  to an MCP client. It starts on hosts without an OS keyring backend (for example
  headless servers), serving read-only and simulate tools; signing tools are
  refused with a keyring error until a backend is configured.
- Policy engine with a no-op gate and a typed first-match, default-deny V1 engine
  evaluating each action to allow, deny, or require operator approval.
- Operator-approval spine: a per-profile pending-approval store and an
  HMAC attestation binding each approval to the executed envelope and the
  approving OS user.
- Hash-chained, append-only JSONL audit log that records key names only (never
  argument values), with `audit verify` chain and HMAC-sidecar verification.
- Key custody via the platform keyring with a TTL-bounded, zeroize-on-drop,
  memory-locked unlock window; profiles name keyring entries and hold no secrets.
- OpenZeppelin smart-account governance: context rules, ed25519 and WebAuthn
  passkey signers, quorum, verifier/policy WASM-hash pinning, multicall, and an
  upgrade timelock.
- DeFi adapters: Blend lending (`lend`), Soroswap swaps (`trade`/`quote`), and
  DeFindex vaults (`vault`), each with venue pinning and fail-closed guardrails.
- Protocol support: SEP-7, SEP-10, SEP-24 and SEP-6, SEP-43, SEP-45, SEP-47,
  SEP-48, and SEP-53.
- Operator approval inbox: `approve list` enumerates pending approvals with
  their wallet-controlled summaries, and `approve serve` runs a loopback-only
  web inbox that lists pending approvals live, notifies the operator, and
  approves (minting the same attestation as `approve --id`) or rejects.
  Rejection records a short-lived marker so the agent's commit is refused
  with `policy.approval_rejected` instead of waiting out the TTL. Session
  bootstrap is a single-use URL token exchanged for an HttpOnly cookie;
  actions require a per-session CSRF header. Approvals now emit audit
  events from both the terminal and inbox surfaces. For a remote agent
  host, the inbox is reached through an SSH port-forward; the approving
  user must be the wallet's OS user.
- Claimable-balance claims by ID (CLI `claim`, MCP `stellar_claim` /
  `stellar_claim_commit` two-phase pair): RPC-backed preview with claimant,
  predicate, clawback, and trustline pre-flight guards. Balance IDs are taken
  as 72-hex, bare 64-hex, or `B...` strkey; listing balances by claimant is a
  Horizon-only query and stays out of scope for the RPC-only wallet.
- x402 v2 Exact Stellar agent payments with an optional SEP-10 counterparty
  identity gate.
- Signed agent toolsets with capability isolation, publisher-signature verification,
  a first-invoke gate, and unconditional per-action approval for toolset-routed
  payments.
- `approve` returns the `approval_attestation` for a payment approval so the agent
  surface can present it to the matching `*_commit` tool, completing the
  simulate-approve-commit flow over MCP.
- An agent knowledge skill under `skills/` (agentskills.io format, with a Claude
  Code marketplace plugin and a downloadable archive) that teaches an AI agent to
  operate the wallet's CLI and MCP server without cloning the repository.
- An agent integration guide (`docs/agents.md`) and capability-isolation example
  toolsets under `examples/toolsets/`.

[Unreleased]: https://github.com/Soneso/stellar-agent-wallet/compare/v0.1.0-alpha.2...HEAD
[0.1.0-alpha.2]: https://github.com/Soneso/stellar-agent-wallet/compare/v0.1.0-alpha.1...v0.1.0-alpha.2
[0.1.0-alpha.1]: https://github.com/Soneso/stellar-agent-wallet/releases/tag/v0.1.0-alpha.1
