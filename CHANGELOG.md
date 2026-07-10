# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `profile enroll-owner-key` enrols the policy-file owner ed25519 PUBLIC key
  from an operator-held seed, and `profile sign-policy` signs a V1 policy file
  with that seed so the engine accepts it. Together they make
  `policy.engine = "v1"` usable end to end: no shipped command previously
  produced the `[signature]` table the engine requires, so selecting `v1`
  failed closed. (#30)
- `stellar_agent_core::policy::v1::signature::sign`, the owner-signature
  primitive that is the exact inverse of `verify`. (#30)
- Value-moving verbs now write a hash-chained, HMAC-signed
  `value_action_submitted` audit row after a confirmed on-chain submit,
  recording the SAME value legs the policy gate sized (single-derivation
  invariant), the redacted transaction hash, and the ledger. This covers the MCP
  `stellar_pay` / `stellar_create_account` / `stellar_claim` / `stellar_trustline`
  commit tools, the Blend / DEX / DeFindex adapters, the x402 payment
  authorizers, the opaque `stellar_sep43_sign_and_submit_transaction` path, and
  the CLI `pay` / `claim` / `accounts create` (sponsored) / `trustline` verbs. A
  DeFi adapter that fails on submit records a `sa_raw_invocation` row instead.
  Emission is non-fatal post-submit: a row-write failure logs a warning and
  never changes the result. (#21)
- `PolicyEngine` gains `evaluate_full` / `evaluate_with_value_full`, which return
  an `Evaluation { decision, value_effects }` surfacing the value descriptor the
  gate sized on the allow path; the decision-only `evaluate` /
  `evaluate_with_value` remain as thin views. Value-verb dispatch uses the
  `_full` methods so the post-submit audit row records exactly the legs the gate
  evaluated rather than re-deriving them. (#21)
- The six key-writing profile commands — `enroll-signer`, `enroll-owner-key`,
  `rotate-nonce-key`, `rotate-attestation-key`, `rotate-counterparty-key`, and
  `rotate-audit-key` — now write a `keyring_key_written` audit row recording the
  key purpose and, where applicable, the redacted public address. (#34)
- `profile rotate-audit-key` rotates the audit chain-root HMAC key and re-signs
  every per-file chain-root sidecar with the new key so `audit verify` stays
  green across the rotation; the new key is persisted before any sidecar is
  re-signed. (#34)
- Offline envelope-shape regression coverage for the `nonce.mint_failed`
  business error on the four two-phase simulate handlers (`stellar_pay`,
  `stellar_create_account`, `stellar_claim`, `stellar_trustline`) and for the
  RPC-dependent `sep48.spec_fetch_failed` / `sep48.render_failed` /
  `sep47.discovery_failed` arms of `stellar_sep48_preview_invocation` /
  `stellar_sep47_discover`, each asserting the full normalised envelope
  (`ok:false`, the documented wire code, a non-empty `request_id`,
  `is_error == Some(true)`). (#36)
- Testnet acceptance coverage for a sponsored `stellar_create_account` /
  `stellar_create_account_commit` two-phase call: the destination account
  exists on-chain afterward with the sponsored starting balance, and the
  commit recorded a `value_action_submitted` audit row. (#43)
- Testnet acceptance coverage for a classic `stellar_trustline` /
  `stellar_trustline_commit` two-phase call against the pinned testnet USDC
  issuer, run under a `minimum_reserve` policy rule the funded source account
  satisfies: the simulate and commit steps both reaching `ok:true` (rather
  than `policy.criterion_evaluation_failed`) is on-chain proof that both
  dispatch points supply a genuinely populated `account_view` (#47). Asserts
  the on-chain trustline limit and the commit's `value_action_submitted`
  audit row. (#43)
- `profile rotate-audit-key` gained the `run_with_dependencies` seam already
  used by the other key-writing profile commands, so its unit coverage now
  drives the actual persist → re-sign → emit sequence rather than a parallel
  reimplementation of it; reordering the three steps turns the test red. A
  V1-engine testnet acceptance variant of the `stellar_pay_commit` flow now
  asserts the confirmed commit's `value_action_submitted` audit row's leg
  content (`action`, `amount`, `asset`, redacted `destination`) equals exactly
  the values submitted on-chain, not merely that a row of the right kind
  exists. (#44)

### Changed

- Documented that `minimum_reserve` and identity-class criteria
  (`home_domain_resolved`) are inapplicable to the smart-account verbs
  (`stellar_blend_lend`, `stellar_dex_trade`, `stellar_defindex_vault_deposit`,
  `stellar_defindex_vault_withdraw`, and the CLI `lend`/`trade`/`vault`
  equivalents): the acting account is a smart-account contract with no classic
  `AccountEntry`, so `account_view` and `identity_view` stay unset permanently
  on these tools, by design. A rule configuring either criterion on one of
  these verbs fails closed on every call. (#38)
- Value criteria (`per_tx_cap`, `per_period_cap`, `minimum_reserve`,
  `counterparty_allowlist`) now size a call through a typed value descriptor
  derived at the dispatch gate, instead of matching hard-coded tool names. A
  rule that matches a value-moving tool constrains every debit leg it carries
  (classic pay/create, Blend supply/repay, DEX trades, vault deposits, x402
  payments), and per-asset caps aggregate across the legs of a multi-leg call.
  A value rule that matches a call whose value cannot be sized — a tool that
  reached the gate without resolved effects, or a raw signing tool
  (`stellar_sep43_*`) — now denies fail-closed with
  `policy.deny.unsizable_value_effect` rather than passing silently. A rule may
  opt a signing tool back in with `allow_opaque_signing = true`.
  `minimum_reserve` now counts only native-XLM outflow legs; a token-only move
  no longer reduces the native reserve. Operators with existing value rules
  should expect previously-unconstrained value tools to be gated. (#18, #19,
  #20)
- CLI `pay`, `claim`, and `accounts create` (sponsored mode) now evaluate
  operator policy before signing, through the same `PolicyEngine::evaluate`
  path the `trade`/`lend`/`vault`/`trustline` CLI verbs already use and with
  value descriptors identical to their `stellar_pay` / `stellar_claim` /
  `stellar_create_account` MCP twins. Previously these three verbs signed and
  submitted unconditionally, bypassing the engine entirely. All three verbs
  gain a `--profile` flag (default `"default"`). With no persisted profile
  file, an in-memory `Noop`-engine testnet profile is synthesized, so the verbs
  keep working without an authored profile and `policy.engine = "noop"`
  behavior on testnet is unchanged. The gate only bites when `--profile`
  resolves to a
  persisted profile with `policy.engine = "v1"`. `accounts create` Friendbot
  mode is not gated (it debits no wallet funds). (#19)
- CLI `trade`, `lend`, and `vault` now size their policy gate with the same
  value descriptor their `stellar_dex_trade` / `stellar_blend_lend` /
  `stellar_defindex_vault_deposit` / `stellar_defindex_vault_withdraw` MCP
  twins use: each verb builds its value legs from the same parsed inputs it
  submits and evaluates them through `PolicyEngine::evaluate_with_value`, so
  `per_tx_cap` / `per_period_cap` / `minimum_reserve` constrain CLI DeFi debits
  exactly as they constrain the MCP calls. Previously these verbs gated on the
  tool name alone — with `trade` classified read-only — leaving the traded,
  lent, and deposited amounts unconstrained. CLI `trustline` gates through the
  shared args-path descriptor builder; its refusals now carry the shared
  `policy.deny.<code>` / `policy.approval_required` / `policy.unexpected_decision`
  / `policy.engine_required` wire codes instead of the previous
  `trustline.policy_denied.<code>` / `trustline.policy_*` codes (a
  wire-observable parity change). Operators with `policy.engine = "v1"` value
  rules should expect CLI DeFi debits to be gated. (#20)
- Value caps (`per_tx_cap`, `per_period_cap`, `minimum_reserve`, and their
  `bundle_*` variants) and the amount fields of their deny reasons
  (`max_stroops`, `attempted_stroops`, `period_used_stroops`,
  `reserve_required_stroops`, `balance_stroops`) are `i128`: the comparison
  path and the emitted deny-reason amounts are exact across the full `i128`
  range and are no longer clamped to `i64::MAX`, so a cap or an attempted
  single-transaction debit above `i64::MAX` is represented exactly instead of
  saturating. These amounts cross the MCP wire as decimal strings
  (JSON-number-unsafe beyond 2^53); consumers must parse them as `i128` /
  decimal strings rather than `i64`. The persisted per-period window
  accumulator remains `i64`-width: cumulative recorded spend within a rolling
  window is tracked exactly up to `i64::MAX` stroops per asset per window, and a
  per-period rule refuses fail-closed rather than silently saturating when a
  call's resulting window total would exceed that bound; single-transaction
  sizing is unaffected. (#20)
- Breaking (policy file behavior): `counterparty_allowlist`'s `HOME_DOMAIN`
  kind now requires the destination's on-chain `home_domain` to be
  independently VERIFIED through the operator's counterparty cache before the
  allowlist is even consulted — a resolved cache entry for that domain, whose
  cached `stellar.toml` `ACCOUNTS` list names the counterparty account.
  Previously a bare self-asserted `home_domain` match sufficed: any account
  could set `home_domain` to an allowlisted string via `SetOptions` at zero
  cost and pass. Existing `HOME_DOMAIN` rules now deny until the operator
  populates the cache for the domains they allowlist — `stellar-agent
  counterparty warm-up` refreshes every domain already in the policy file's
  `HOME_DOMAIN` allowlists in one pass; `stellar-agent counterparty refresh
  <domain>` refreshes one domain. `G_ACCOUNT` / `C_ACCOUNT` / `KNOWN_ISSUER`
  are unaffected. `CounterpartyCacheView` gains `is_account_listed`
  (default `false`, fail-closed) and `StellarTomlBinding` gains an `accounts`
  field carrying the cached `stellar.toml`'s `ACCOUNTS` G-strkeys. (#49)

### Removed

- Breaking (policy file): the `soroban_resource_fee_cap` criterion. It gated on
  a `stellar_invoke*` tool-name prefix that no registered tool matches, so it
  never constrained a real call. A policy file that references
  `soroban_resource_fee_cap` now fails to load with the unknown-criterion
  error. A future contract-invocation tool should reintroduce a
  descriptor-based resource criterion sized against `ContractInvoke` value
  legs. (#22)
- The remaining hard-coded per-tool arms inside the value criteria. A criterion
  now sizes a call solely from its typed value legs, never from the tool name.
  (#22)

### Fixed

- MCP `stellar_pay_commit`, `stellar_claim_commit`, and
  `stellar_create_account_commit` now supply the source account (and, for
  `stellar_pay_commit`, the destination) as the policy gate's
  `account_view`/`identity_view` — mirroring `stellar_trustline_commit` — so a
  `minimum_reserve` criterion configured on these verbs is actually evaluated
  at commit instead of failing closed on every call, even when the same rule
  passed at simulate. The account fetch each commit path already made for the
  sequence number is reused; no second fetch. `identity_view` stays `None` for
  `stellar_claim_commit` / `stellar_create_account_commit`, matching their
  simulate phases. (#48)
- `ContextRuleManager::check_divergence_for_auth_rule_ids`,
  `deploy_smart_account` (and its five sibling deploy flows:
  `deploy_ed25519_verifier`, `deploy_webauthn_verifier`, `deploy_policy`,
  `deploy_spending_limit_policy`, `deploy_timelock_controller`), and
  `retry_with_backoff` each now enforce a collective wall-clock budget across
  their fixed-count multi-stage RPC sequence, instead of leaving each stage
  bounded only by the transport's own per-call timeout. A `SignersManager`
  divergence check across up to 50 `auth_rule_ids`, a deploy flow's
  fetch/simulate/submit/verify sequence, and a blind-backoff retry loop could
  previously run for up to (stage count) × (transport timeout) with no total
  cap; each now refuses with a "collective budget elapsed" error once its
  budget (the manager's/flow's existing configured timeout) is exhausted.
  `retry_with_backoff` additionally races each attempt against the shared
  deadline, so one hung attempt cannot overshoot the deadline by the
  transport's own bound; a deadline cutoff surfaces as the SAME
  `TransactionSubmissionTimeout` variant the existing poll-timeout path
  returns and is never retried. (#46)
- MCP `stellar_trustline` / `stellar_trustline_commit` and CLI `trustline` now
  supply the source account as the policy gate's `account_view` (previously
  `None`), so a `minimum_reserve` criterion configured on `stellar_trustline`
  is actually evaluated instead of failing closed on every call. The source
  fetch was already made by the existing ordered gate (for the sequence
  number); the policy gate now runs after it. `identity_view` stays `None` on
  this verb: the only counterparty account is the asset issuer, whose on-chain
  `home_domain` is self-asserted — supplying it to `counterparty_allowlist`
  HOME_DOMAIN matching would let an issuer alias an allowlisted domain, so
  identity-class criteria configured on `stellar_trustline` fail closed by
  design. (#47)
- `approve --id` writes the human-readable approval summary and the y/n prompt
  to stderr; stdout carries exactly one JSON envelope, so
  `approve --id <ID> --yes > out.json` yields parseable JSON with the
  `approval_attestation`, as the output contract documents. Summary field
  lines are consistently indented. (#32)
- `audit verify` no longer doubles the wire-code prefix in error details, and
  a missing primary log file is classified as the actionable
  `audit.log_not_found` validation error instead of an internal error. (#29)
- CLI `pay`, `claim`, and `accounts create` now initialize the platform
  keyring store before reading the owner key on the `policy.engine = "v1"`
  path, so v1 policy evaluation works on a real install (previously failed
  `policy.engine_unavailable` with `NoDefaultStore`). (#41)
- A rule carrying any value-summing bundle cap (`bundle_aggregate_cap`,
  `bundle_per_tx_cap`, or `bundle_per_period_cap`) now implicitly enforces the
  `restrict_bundle_to_recognised_kinds` Generic-rejection check at evaluation
  time, regardless of whether that criterion is configured on the rule or its
  `enabled` value. These caps sum only `TokenTransfer` inners, so a multicall
  bundle containing a `Generic` inner now denies under a cap-only rule instead
  of bypassing the cap. (#23)
- `ContextRuleManager::list_active_context_rules`, Blend's
  `query_oracle_lastprice_timestamps`, and the timelock `list_pending` scan
  each now enforce a collective wall-clock budget across their per-item RPC
  loop, instead of only bounding iteration COUNT. A large scan bound, request
  batch, or scheduling history against a slow RPC endpoint previously had no
  total time cap; each of the three now refuses with a "collective ... budget
  elapsed" message once its budget (the manager's configured `timeout` for
  the rule scan; a fixed constant for the other two) is exhausted, rather
  than continuing to probe for up to iteration-count times the transport's
  60s per-call bound. (#33)
- `cargo build --workspace --tests` (and any bare `cargo test`/`cargo build
  --tests` invocation omitting `--features test-helpers`) no longer fails to
  compile `stellar-agent-approval-remote`: its `test_helpers` module was
  gated on `cfg(any(test, feature = "test-helpers"))`, which let `cfg(test)`
  alone compile the module's `p256` imports without the optional `p256`
  dependency they need (gated solely on the `test-helpers` feature). The
  module is now gated on the feature alone. (#37)
- CLI `pay`, `claim`, and `accounts create` (sponsored) now supply the same
  `account_view` / `identity_view` their MCP twins supply — `pay` a source
  `account_view` plus a destination-derived `identity_view`; `claim` and
  `accounts create` a source/sponsor `account_view` only — so a `minimum_reserve`
  or identity-class criterion configured on these verbs is actually evaluated
  instead of failing closed on every call. `trustline` is unchanged: its MCP
  twin supplies no views at all, so the CLI mirrors that exactly. The
  `AccountReservesView` / `AccountIdentityView` bridge adapter
  (`AccountViewAdapter`) moved from `stellar-agent-mcp::policy_adapter` to
  `stellar-agent-network::policy_view` (re-exported from its former path for
  compatibility) so the CLI can use it without a new dependency on the MCP
  crate. (#45)

### Changed

- Breaking (MCP wire): tool business errors now use one uniform result envelope
  `{ ok: false, error: { code, message }, request_id }` with `is_error` set, in
  place of the previous mix of JSON-RPC `ErrorData`, bare `{ error, detail }`
  (SEP-53), and `{ code: "x402.error" }` shapes. Branch on `error.code`. x402
  errors carry per-variant codes (`x402.<reason>`); SEP-53 failures use
  `sep53.keyring_load_failed` / `sep53.sign_failed` / `sep53.verify_failed`; a
  keyring-unavailable nonce mint at simulate time returns `nonce.mint_failed`;
  and a trustline to a clawback-enabled issuer returns the
  `trustline.clawback_opt_in_required` business error instead of an `ok` result.
  Genuine protocol faults (malformed arguments, internal invariants) remain
  JSON-RPC errors. The six `stellar_sep43_*` tools keep the SEP-43 v1.2.1
  `{ code, message }` object (numeric codes) for signing results and their
  protocol, mainnet, and keyring-unlock errors to preserve wire compatibility;
  the one case those tools use the standard envelope is a policy
  `RequireApproval` verdict, refused as `policy.approval_required_unsupported`.
  The SEP-43 sign-and-submit submit-layer mainnet backstop now reports the
  unified `MainnetSigningForbidden` (SEP-43 code -3) instead of the generic
  rpc-error code (-2). (#35)
- Breaking: removed `profile rotate-owner-key`. The policy owner keyring entry
  now holds the owner PUBLIC key that the always-online engine verifies
  against, not the private seed. Enrol the public key with
  `profile enroll-owner-key` and sign policy files with `profile sign-policy`,
  keeping the owner seed offline. Profiles that relied on `rotate-owner-key`
  must re-enrol the owner public key and re-sign their policy files. (#30)

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
