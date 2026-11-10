# stellar-agent-mcp — tool documentation

See [Mainnet configurations and scope](../../../docs/getting-started.md#mainnet-configurations-and-scope)
for build configuration, admitted operations, and exclusions.

> **Note:** This document covers the core payment and account-management flows
> only. The server exposes many additional tools (SEP-43, SEP-53, x402, toolsets,
> DeFi, and others). For the full and authoritative list of tools and their
> schemas, send a `tools/list` request to the running server or consult the
> live tool `instructions` returned in the `initialize` response.

Startup checks the selected profile's keyring scope after reconciling its name.
A mainnet conflict exits with `profile.key_scope_conflict` on stderr. Testnet
logs a warning and starts. Unreadable siblings warn on both chains and are
skipped. `profile show` displays a conflicting document for diagnosis.
Stop the MCP server before `profile reset-window-state`: it holds the profile's
audit writer, and the reset refuses while that writer is held.

## Classic mainnet authorization

A feature-enabled server admits `stellar_pay_commit`, `stellar_claim_commit`,
`stellar_create_account_commit`, and `stellar_trustline_commit` after setup.
Both prepare and commit policy names need matching rules. The four pairs require
approval even under Allow. A pending approval uses the shorter lifetime from
the prepare and commit evaluations. Allow contributes 600 seconds;
RequireApproval supplies its configured lifetime. Authorization defaults to
120 seconds and cannot outlive approval.

Paired preparation refuses an undecodable envelope with `simulation.divergence`.
A denied rule retains `policy.deny.*`; an unknown decision uses
`policy.unexpected_decision`. None of these refusals persists an approval.
Each commit forces confirmation before attestation validation.

Feature-on startup loads the mainnet write context for a verified enabled
profile. Failed enablement or policy checks abort startup. Admission refusals
use `network.mainnet_write_forbidden` for unsupported tools or missing V1 engine,
verified policy, enablement, enabled context, or profiles directory. A stored
profile without `oracle_provider_url` refuses at admission with
`profile.mainnet_oracle_required`, before signing. The server reads the
profile at startup, so it applies an oracle change from its next start.

After `profile enable-mainnet` or `profile sign-policy`, restart the MCP server.
Freshness compares current policy and enablement facts without advancing the pin.
A changed binding reports `network.mainnet_write_forbidden` with
`enablement or policy changed, restart the server`. Missing startup authority
instead names the missing prerequisite.

Preparation and commit use the smaller signed/profile fee cap, or the one
available value. A higher profile cap warns. The enabled-policy minimum
requires the signed cap. The resolver independently reevaluates effective fees
and thresholds. An admitted mainnet prepare probes endpoint identity before
action reads, as does commit before consuming its nonce.

Every classic prepare, on any network, checks that the endpoint reports a
healthy status and that its latest ledger closed within 60 seconds of the host
clock, before it reads the account it signs against. A failed check refuses with
`network.endpoint_not_ready`. The prepare result carries the observed ledger as
`operational`: `{latest_ledger, close_time_unix, close_lag_seconds}`.

Endpoint refusals preserve `network.endpoint_network_mismatch`,
`network.endpoint_identity_unavailable`, `network.unsupported_protocol_version`,
`network.endpoint_not_ready`, and `network.rpc_credential_refused`.
`network.envelope_signed_for_mainnet` means a signature fails under the endpoint network but verifies under mainnet.

Missing, invalid, expired, or unverifiable approvals use `policy.approval_required`.
A live rejection uses `policy.approval_rejected`. A live consumed approval or an
approval held by a submission receipt uses `policy.approval_consumed`.
Expired tombstones use `policy.approval_required`. Authorization consumption
followed by pre-send recording failure can leave an unspent pending approval.
Reusing it can produce `network.mainnet_authorization_refused` without a tombstone.

Ordinary signing and submission refuse mainnet. Authorized entry points check
sealed authority independently. Durable consumption precedes sending.
Classic MCP authorization refusal renders
`the mainnet write was refused before submission; nothing was sent`.
Classic MCP uses this message at both signing and submission boundaries.
A signer may run before its result is rejected. An envelope may already carry
a signature.

Report authorization refusal to the operator. Fresh preparation and fresh
approval are required for a retry; do not switch networks. The operator reads
`path` and `precondition` in the warn-level `mainnet authorization refused` log.
A submission timeout has an unknown outcome and requires transaction reconciliation.

## stellar_balances

Fetches the native XLM balance and trustlines for a Stellar account.

**Arguments:**
- `chain_id` (string, required): CAIP-2 chain identifier. Accepted values: `stellar:testnet`, `stellar:mainnet`.
- `account_id` (string, required): Stellar G-strkey (ed25519 public key, 56 chars).

- `assets` (array, optional): Non-native trustlines to include. Each element is `{ "code": "USDC", "issuer": "GA5Z..." }`. Returns the native XLM balance plus any trustlines listed in the optional `assets` argument. Up to 100 trustline assets may be queried per call; assets the account does not currently trust are omitted from the returned `balances` list.

**Returns:** JSON envelope identical to `stellar-agent balances --account <G>`.

**Annotations:** `readOnlyHint=true`, `destructiveHint=false`.

## stellar_friendbot

Funds a testnet account via the Stellar Friendbot HTTP endpoint.

**Arguments:**
- `chain_id` (string, required): CAIP-2 chain identifier. Only `stellar:testnet` is accepted. On mainnet the dispatch gate answers first: the Noop engine returns `policy.engine_required`, and a V1 engine denial returns its `policy.deny.*` code. A call the policy lets through without `friendbot_url` returns `invalid_params`, because mainnet has no default Friendbot URL. Only a call with an explicit, allow-listed `friendbot_url` reaches the inner guard, `network.friendbot_mainnet_forbidden`.
- `account_id` (string, required): Stellar G-strkey to fund (ed25519 public key, 56 chars).
- `friendbot_url` (string, optional): Override Friendbot endpoint URL. When supplied, must be in the production allow-list (friendbot.stellar.org or friendbot-futurenet.stellar.org over HTTPS). Defaults to `https://friendbot.stellar.org` for testnet.

**Returns:** JSON envelope identical to `stellar-agent friendbot --account <G>`.

**Annotations:** `readOnlyHint=false`, `destructiveHint=true`.

**Security note:** This tool has no unchecked URL escape. Every supplied `friendbot_url` is validated against the allow-list unconditionally.

## stellar_create_account

Simulate step: builds a CreateAccount transaction envelope and mints a single-use nonce. Returns `{envelope_xdr, nonce, expires_at_unix_ms, simulation}`. Pass all three values unmodified to `stellar_create_account_commit`.

**Arguments:**
- `chain_id` (string, required): CAIP-2 chain identifier.
- `source` (string, required): G-strkey of the funding account.
- `destination` (string, required): G-strkey of the new account to create.
- `starting_balance` (string, required): Amount with unit suffix, e.g. `"1 XLM"`.
- `fee` (string, optional): Classic fee per operation: `<stroops>`, `auto`, or `auto:pNN`.

**Returns:** `{envelope_xdr, nonce, expires_at_unix_ms, simulation, operational}`.

**Annotations:** `readOnlyHint=false`, `destructiveHint=false`.

**Fee cap:** The resolved per-operation fee is checked against the effective signed/profile
`classic_max_fee_per_op_stroops`. A fee above the cap returns
`fees.percentile_exceeds_cap`; the message names an auto-selected fee and its
percentile, an explicit `classic_base`, or the profile's
`classic_fee_per_op_stroops`. A mainnet action without an effective cap returns
`validation.mainnet_fee_cap_required`.

## stellar_create_account_commit

Commit step: verifies the nonce, re-builds the envelope for divergence check, signs via the profile keyring, and submits the transaction. Configured mainnet writes require a feature-enabled build and per-action authorization. Before the nonce is burned, the tool establishes which network the RPC endpoint actually serves and refuses a mismatch, so a wrongly-configured endpoint does not consume the nonce. The submit layer then verifies every signature on the envelope against the network the endpoint reported.

**Arguments:**
- `chain_id` (string, required): CAIP-2 chain identifier.
- `source` (string, required): G-strkey of the funding account.
- `destination` (string, required): G-strkey of the new account.
- `starting_balance` (string, required): Amount with unit suffix (same as simulate).
- `nonce` (string, required): Base64 nonce from the simulate step.
- `expires_at_unix_ms` (number, required): Expiry from the simulate step.
- `envelope_xdr` (string, required): Base64 envelope from the simulate step.
- `approval_nonce` (string, optional): Approval nonce from the simulate step's `approval` block. Required, with `approval_attestation`, when the simulate step reported that approval is required.
- `approval_attestation` (string, optional): URL-safe base64 attestation that `stellar-agent approve` writes after the operator confirms.

**Returns:** `{tx_hash, ledger, cross_check}` on success.

**Annotations:** `readOnlyHint=false`, `destructiveHint=true`.

**Submission record:** Before the transaction is sent, the wallet records it as submitted with an unknown outcome: a submission receipt, a spending-window reservation under a policy with a stateful criterion, and a `value_action_pending` audit row. A confirmed success is recorded on the receipt as a report, and no network answer releases the reservation. A submission that ends without a confirmed outcome keeps the record and returns `submission.tx_timeout`. On that code the outcome is unknown: pass `error.details.tx_hash` to `stellar_transaction_status`, and never resubmit. See "Unresolved submissions" below.

**Fee cap:** Before signing, the presented envelope's per-operation fee is
checked against the effective signed/profile `classic_max_fee_per_op_stroops`. A fee above the
cap returns `fees.percentile_exceeds_cap` with a message naming the envelope's
fee; prepare the transaction again with a fee within the cap. A mainnet action
without an effective cap returns `validation.mainnet_fee_cap_required`.

**Error codes:** `nonce.expired`, `nonce.replayed`, `simulation.divergence`,
`fees.percentile_exceeds_cap`, `validation.mainnet_fee_cap_required`,
`network.witness_unavailable`, `policy.engine_required`, `policy.approval_required`,
`policy.approval_rejected`, `policy.approval_consumed`,
`network.endpoint_network_mismatch`, `network.endpoint_identity_unavailable`,
`network.rpc_credential_refused`, `auth.keyring_not_found`,
`network.envelope_signed_for_mainnet`, `network.envelope_signature_unverifiable`,
`network.envelope_unsigned`, `submission.tx_timeout`, `submission.tx_already_submitted`,
`submission.hash_mismatch`, `submission.record_unavailable`.

**Approval outcomes:** `policy.approval_required` means no valid approval was presented: retry the commit with `approval_nonce` and `approval_attestation` once the operator approves. `policy.approval_rejected` means the operator declined: stop retrying.

`cross_check` reports `passed` with `provider` and `ledger`, `skipped` with a
reason, or `not_required` with reason `below_threshold`.

## stellar_pay

Simulate step: builds a Payment transaction envelope for a native XLM or non-native asset payment, runs SEP-29 memo-required enforcement against the destination account, and mints a single-use nonce. Returns `{envelope_xdr, nonce, expires_at_unix_ms, simulation}`. Pass all three values unmodified to `stellar_pay_commit`.

**Arguments:**
- `chain_id` (string, required): CAIP-2 chain identifier.
- `source` (string, required): G-strkey of the source (funding) account.
- `destination` (string, required): G-strkey of the recipient account.
- `amount` (string, optional): Amount with unit suffix, e.g. `"10 XLM"`. Mutually exclusive with
  `amount_in_stroops`.
- `amount_in_stroops` (string, optional): Raw positive stroop integer as a decimal string, e.g. `"10000000"`. Mutually exclusive with `amount`.
- `asset` (string, required): `"native"` / `"XLM"` or `"CODE:G…ISSUER"`.
- `memo_text` (string, optional): UTF-8 text memo (≤ 28 bytes). Mutually exclusive.
- `memo_id` (number, optional): Integer memo (u64). Mutually exclusive.
- `memo_hash_hex` (string, optional): 32-byte hash memo as 64 hex chars. Mutually exclusive.
- `memo_return_hex` (string, optional): 32-byte return memo as 64 hex chars. Mutually exclusive.
- `fee` (string, optional): Classic fee per operation: `<stroops>`, `auto`, or `auto:pNN`.

**Returns:** `{envelope_xdr, nonce, expires_at_unix_ms, simulation, operational}`.

**Annotations:** `readOnlyHint=false`, `destructiveHint=false`.

**SEP-29:** If the destination's `config.memo_required` data entry is set to `"1"` and no memo is provided, returns `validation.memo_required`.

**Fee cap:** The resolved per-operation fee is checked against the effective signed/profile
`classic_max_fee_per_op_stroops`. A fee above the cap returns
`fees.percentile_exceeds_cap`; the message names an auto-selected fee and its
percentile, an explicit `classic_base`, or the profile's
`classic_fee_per_op_stroops`. A mainnet action without an effective cap returns
`validation.mainnet_fee_cap_required`.

## stellar_pay_commit

Commit step: verifies the nonce, re-builds the Payment envelope for divergence check, signs via the profile keyring, and submits the transaction. Configured mainnet writes require a feature-enabled build and per-action authorization. Before the nonce is burned, the tool establishes which network the RPC endpoint actually serves and refuses a mismatch, so a wrongly-configured endpoint does not consume the nonce. The submit layer then verifies every signature on the envelope against the network the endpoint reported.

**Arguments:**
- `chain_id` (string, required): CAIP-2 chain identifier.
- `source` (string, required): G-strkey of the source account.
- `destination` (string, required): G-strkey of the recipient account.
- `amount` (string, optional): Amount with unit suffix (same as simulate). Mutually exclusive with
  `amount_in_stroops`.
- `amount_in_stroops` (string, optional): Raw positive stroop integer as a decimal string (same as
  simulate). Mutually exclusive with `amount`.
- `asset` (string, required): Asset descriptor (same as simulate).
- `memo_text` / `memo_id` / `memo_hash_hex` / `memo_return_hex` (optional, same as simulate).
- `nonce` (string, required): Base64 nonce from the simulate step.
- `expires_at_unix_ms` (number, required): Expiry from the simulate step.
- `envelope_xdr` (string, required): Base64 envelope from the simulate step.
- `approval_nonce` (string, optional): Approval nonce from the simulate step's `approval` block. Required, with `approval_attestation`, when the simulate step reported that approval is required.
- `approval_attestation` (string, optional): URL-safe base64 attestation that `stellar-agent approve` writes after the operator confirms.

**Returns:** `{tx_hash, ledger, cross_check}` on success.

**Annotations:** `readOnlyHint=false`, `destructiveHint=true`.

**Submission record:** Before the transaction is sent, the wallet records it as submitted with an unknown outcome: a submission receipt, a spending-window reservation under a policy with a stateful criterion, and a `value_action_pending` audit row. A confirmed success is recorded on the receipt as a report, and no network answer releases the reservation. A submission that ends without a confirmed outcome keeps the record and returns `submission.tx_timeout`. On that code the outcome is unknown: pass `error.details.tx_hash` to `stellar_transaction_status`, and never resubmit. See "Unresolved submissions" below.

**Destination read:** Only an absent destination account counts as absent; any
other failed destination read refuses with the read's own code.

**Fee cap:** Before signing, the presented envelope's per-operation fee is
checked against the effective signed/profile `classic_max_fee_per_op_stroops`. A fee above the
cap returns `fees.percentile_exceeds_cap` with a message naming the envelope's
fee; prepare the transaction again with a fee within the cap. A mainnet action
without an effective cap returns `validation.mainnet_fee_cap_required`.

**Error codes:** `nonce.expired`, `nonce.replayed`, `simulation.divergence`,
`fees.percentile_exceeds_cap`, `validation.mainnet_fee_cap_required`,
`network.witness_unavailable`, `network.rpc_divergence`, `validation.memo_required`,
`policy.engine_required`, `policy.approval_required`, `policy.approval_rejected`,
`policy.approval_consumed`, `validation.memo_mutually_exclusive`, `network.endpoint_network_mismatch`,
`network.endpoint_identity_unavailable`, `network.rpc_credential_refused`,
`auth.keyring_not_found`, `network.envelope_signed_for_mainnet`,
`network.envelope_signature_unverifiable`, `network.envelope_unsigned`, `submission.tx_timeout`,
`submission.tx_already_submitted`, `submission.hash_mismatch`, `submission.record_unavailable`.

**Approval outcomes:** `policy.approval_required` means no valid approval was presented: retry the commit with `approval_nonce` and `approval_attestation` once the operator approves. `policy.approval_rejected` means the operator declined: stop retrying.

`cross_check` reports `passed` with `provider` and `ledger`, `skipped` with a
reason, or `not_required` with reason `below_threshold`.

## stellar_claim

Simulate step: fetches the claimable-balance entry, renders a typed preview, enforces the claim guards (claimant, predicate, trustline, fee affordability), builds a `ClaimClaimableBalance` envelope, and mints a single-use nonce. Pass `envelope_xdr`, `nonce`, and `expires_at_unix_ms` unmodified to `stellar_claim_commit`.

**Arguments:**
- `chain_id` (string, required): CAIP-2 chain identifier.
- `balance_id` (string, required): Claimable-balance id: a `B...` strkey, the canonical 72-hex id, or the bare 64-hex hash.
- `source_account` (string, optional): G-strkey of the claiming account. Defaults to the profile's default MCP signer account.

**Returns:** `{envelope_xdr, nonce, expires_at_unix_ms, preview, operational}`.

**Annotations:** `readOnlyHint=false`, `destructiveHint=false`.

## stellar_claim_commit

Commit step for `stellar_claim`: verifies the nonce, re-builds the `ClaimClaimableBalance` envelope for the divergence check, signs via the profile keyring, and submits. Configured mainnet writes require a feature-enabled build and per-action authorization. Carries the same pre-send endpoint-identity probe, signature-binding check and submission record as the other commit tools.

**Arguments:**
- `chain_id` (string, required): CAIP-2 chain identifier.
- `balance_id` (string, required): Claimable-balance id (same as simulate).
- `source_account` (string, optional): G-strkey of the claiming account (same as simulate).
- `nonce` (string, required): Base64 nonce from the simulate step.
- `expires_at_unix_ms` (number, required): Expiry from the simulate step.
- `envelope_xdr` (string, required): Base64 envelope from the simulate step.
- `approval_nonce` (string, optional): Approval nonce from the simulate step's `approval` block. Required, with `approval_attestation`, when the simulate step reported that approval is required.
- `approval_attestation` (string, optional): URL-safe base64 attestation that `stellar-agent approve` writes after the operator confirms.

**Returns:** `{tx_hash, ledger, cross_check}` on success.

`stellar_claim_commit` witnesses the source account and complete fresh
claimable-balance record. It does not re-read the source trustline at commit.

The commit obtains its unvalued witness before nonce consumption and signer
loading. `cross_check` reports `passed` with provider and ledger, or `skipped`
with a reason. A witness refusal keeps the nonce usable.

**Annotations:** `readOnlyHint=false`, `destructiveHint=true`.

**Fee cap:** Before signing, the presented envelope's per-operation fee is
checked against the effective signed/profile `classic_max_fee_per_op_stroops`. A fee above the
cap returns `fees.percentile_exceeds_cap` with a message naming the envelope's
fee; prepare the transaction again with a fee within the cap. A mainnet action
without an effective cap returns `validation.mainnet_fee_cap_required`.

**Error codes:** `nonce.expired`, `nonce.replayed`, `simulation.divergence`,
`fees.percentile_exceeds_cap`, `validation.mainnet_fee_cap_required`,
`network.witness_unavailable`, `policy.engine_required`, `policy.approval_required`,
`policy.approval_rejected`, `policy.approval_consumed`,
`network.endpoint_network_mismatch`,
`network.endpoint_identity_unavailable`, `network.rpc_credential_refused`,
`auth.keyring_not_found`, `network.envelope_signed_for_mainnet`,
`network.envelope_signature_unverifiable`, `network.envelope_unsigned`,
`submission.tx_timeout`, `submission.tx_already_submitted`, `submission.hash_mismatch`,
`submission.record_unavailable`.

**Approval outcomes:** `policy.approval_required` means no valid approval was presented: retry the commit with `approval_nonce` and `approval_attestation` once the operator approves. `policy.approval_rejected` means the operator declined: stop retrying.

## stellar_trustline

Simulate step: resolves the asset, fetches the issuer's live flags, runs the clawback gate, builds a `ChangeTrust` envelope, and mints a single-use nonce. USDT is refused unconditionally. Pass `envelope_xdr`, `nonce`, and `expires_at_unix_ms` unmodified to `stellar_trustline_commit`.

**Arguments:**
- `chain_id` (string, required): CAIP-2 chain identifier.
- `from` (string, required): G-strkey of the account that holds the trustline.
- `asset` (string, required): A bare code such as `"USDC"`, resolved through the pin table, or `"CODE:G…ISSUER"`. A SAC `C…` address returns a typed error.
- `limit_stroops` (string, optional): Trustline limit in stroops as a decimal string. Absent sets the protocol default (`i64::MAX`); `"0"` removes the trustline.
- `fee` (string, optional): Classic fee per operation: `<stroops>`, `auto`, or `auto:pNN`.

**Returns:** `{envelope_xdr, nonce, expires_at_unix_ms, preview, operational}`.

**Annotations:** `readOnlyHint=false`, `destructiveHint=false`.

## stellar_trustline_commit

Commit step for `stellar_trustline`: verifies the nonce, re-builds the `ChangeTrust` envelope for the divergence check, signs via the profile keyring, and submits. Configured mainnet writes require a feature-enabled build and per-action authorization. Carries the same pre-send endpoint-identity probe, signature-binding check and submission record as the other commit tools.

**Arguments:**
- `chain_id` (string, required): CAIP-2 chain identifier (same as simulate).
- `from` (string, required): G-strkey of the trustline account (same as simulate).
- `nonce` (string, required): Base64 nonce from the simulate step.
- `expires_at_unix_ms` (number, required): Expiry from the simulate step.
- `envelope_xdr` (string, required): Base64 envelope from the simulate step. The commit derives the asset, issuer, and limit from it.
- `approval_nonce` (string, optional): Approval nonce from the simulate step's `approval` block. Required, with `approval_attestation`, when the simulate step reported that approval is required.
- `approval_attestation` (string, optional): URL-safe base64 attestation that `stellar-agent approve` writes after the operator confirms.

**Returns:** `{tx_hash, ledger, cross_check}` on success.

`stellar_trustline_commit` reads the issuer again and verifies the stored
clawback opt-in for that trustline. An absent issuer refuses `trustline.gate_refused`.
Other issuer read errors keep their own codes and scrubbed messages.
Clawback without a current, verified opt-in refuses
`trustline.clawback_opt_in_required`, including when the issuer enables clawback
after prepare. Nothing is signed and no new approval is minted.
Re-invoke `stellar_trustline` to obtain a new opt-in request.
A verified opt-in permits the commit to continue to its witness.

The commit obtains its unvalued witness before nonce consumption and signer
loading. `cross_check` reports `passed` with provider and ledger, or `skipped`
with a reason. A witness refusal keeps the nonce usable.

**Annotations:** `readOnlyHint=false`, `destructiveHint=true`.

**Fee cap:** Before signing, the presented envelope's per-operation fee is
checked against the effective signed/profile `classic_max_fee_per_op_stroops`. A fee above the
cap returns `fees.percentile_exceeds_cap` with a message naming the envelope's
fee; prepare the transaction again with a fee within the cap. A mainnet action
without an effective cap returns `validation.mainnet_fee_cap_required`.

**Error codes:** `nonce.expired`, `nonce.replayed`, `simulation.divergence`,
`fees.percentile_exceeds_cap`, `validation.mainnet_fee_cap_required`,
`network.witness_unavailable`, `policy.engine_required`, `policy.approval_required`,
`policy.approval_rejected`, `policy.approval_consumed`,
`network.endpoint_network_mismatch`,
`network.endpoint_identity_unavailable`, `network.rpc_credential_refused`,
`auth.keyring_not_found`, `network.envelope_signed_for_mainnet`,
`network.envelope_signature_unverifiable`, `network.envelope_unsigned`,
`submission.tx_timeout`, `submission.tx_already_submitted`, `submission.hash_mismatch`,
`submission.record_unavailable`.
Clawback re-check refusals use `trustline.gate_refused` or
`trustline.clawback_opt_in_required`, as described above.

**Approval outcomes:** `policy.approval_required` means no valid approval was presented: retry the commit with `approval_nonce` and `approval_attestation` once the operator approves. `policy.approval_rejected` means the operator declined: stop retrying.

## stellar_transaction_status

Reconciles one submitted transaction against the chain and records a reported success on the wallet's record of it.

**Arguments:**
- `chain_id` (string, required): CAIP-2 chain identifier.
- `tx_hash` (string, required): 64 lowercase hex characters: the `details.tx_hash` a `submission.tx_timeout` response carries.

**Returns:** `{tx_hash, chain_status, ledger, record, reservation}`. `chain_status` is what the endpoint reported (`SUCCESS`, `FAILED` or `NOT_FOUND`).

- `record` is the wallet's record of the submission, or `null` when it holds none: `settlement_evidence`, `settlement_decision_id`, `envelope_hash`, `status`, `failure_code`, `release_code`, `ledger`, `source_redacted`, `sequence`, `submitted` and `reservation_open`. The record is display data. `settlement_evidence` is always `"unavailable"`, and `settlement_decision_id` only locates an authenticated accounting decision. Once the reservation's accounting horizon has passed, a `pending` or `ambiguous` receipt reads `ambiguous` with `release_code` `submission.accounting_expired`, the outcome unknown. A receipt with any other status keeps its status and code, and every receipt the expiry projects onto carries its `settlement_decision_id`. A receipt can also carry `submission.sequence_consumed` or `submission.time_bound_passed`, which name an observation and release nothing. Read `status` and `release_code`, not `reservation_open`.
- `reservation` is a hold that remains after reconciliation, `{envelope_hash, operator_required}`, or `null`. `operator_required: true` marks a reservation whose receipt is missing and whose submission ledger is below the endpoint's retention floor: no endpoint answer resolves it. A time-bounded one ends at its accounting horizon; otherwise only the operator's `stellar-agent tx receipt clear` resolves it.

The tool reconciles a submission by its receipt, or by its reservation when the receipt is missing, and sends nothing.

**Annotations:** `readOnlyHint=false`, `destructiveHint=false`. The pairing is deliberate: the call moves no value, and it does change the wallet's record. It records a success report on the receipt and in the spending window, and ends a reservation whose accounting horizon has passed. A failure report leaves the receipt and the reservation as they were. No receipt status writes an audit row: a reported success writes no submitted row, and an accounting expiry writes no `value_action_failed` row.

**Error codes:** `validation.address_invalid`, `submission.record_unavailable`, `network.rpc_unreachable`, `audit.chain_key_unavailable`, `audit.tip_anchor_mismatch`.

## Unresolved submissions

Three error codes describe a submission whose outcome the wallet cannot settle on its own. All three carry a `details` object alongside the redacted message, and all three are resolved the same way.

| Code | What happened |
|---|---|
| `submission.tx_timeout` | The submission ended without a confirmed outcome: the confirmation deadline passed, the endpoint reported an unexpected status, or a transport failure struck during or after the send. It may still apply; settle it by its transaction hash. |
| `submission.tx_already_submitted` | A pending record already holds this transaction's source account and sequence, or, under a policy with a stateful criterion, the spending window already holds these signed bytes. Nothing was sent. |
| `submission.hash_mismatch` | The endpoint reported a transaction hash that does not describe the transaction that was sent. |

`details` carries:

- `tx_hash`: the transaction to reconcile, 64 lowercase hex characters, in full.
- `envelope_hash`: the submission record's identity, which `stellar-agent tx receipt clear` takes. Present where the reporting surface holds the signed bytes, the DeFi verbs included. Recover it from `stellar_transaction_status`'s `record.envelope_hash` when it is absent.
- `timeout_seconds`: present on `submission.tx_timeout`.
- `server_tx_hash`: present on `submission.hash_mismatch`.
- `outcome`: always `"unknown"`.
- `reconcile_with`: `"stellar_transaction_status"`.

**Recovery protocol.** Call `stellar_transaction_status` with `details.tx_hash`. Do not re-simulate, rebuild, or resubmit the payment: the transaction may still apply, and the sequence number it consumes may already be spent by it. A second submission at that sequence is refused with `submission.tx_already_submitted` while the first one's receipt remains pending. `stellar_transaction_status` reports what the endpoint says and records a success as a report. A reported failure or missing transaction does not release possible spending:

- `SUCCESS`: the endpoint reports that the transaction applied. The receipt records `success`, unless it belongs to an untimed reservation and already records another network answer, which it keeps. The reservation keeps counting through its accounting horizon. No submitted row is written, and the pending row stays open.
- `FAILED`: the endpoint reports that the transaction applied and failed. The report changes neither the reservation nor the receipt, and no `value_action_failed` row is owed.
- `NOT_FOUND`: the endpoint has no record of it. Within the retention window, an observed ledger close time strictly past its time bound, or a source account sequence that has reached the transaction's, is followed by a second transaction lookup. Neither observation proves that the transaction can no longer apply. A second `NOT_FOUND` keeps the reservation, and a `SUCCESS` is recorded as above. Without such an observation the record stands: call again later.

Accounting expiry ends a reservation whatever the endpoint reports. The accounting horizon is the later of the signed time bound and a recorded success observation, plus each affected window's duration. Once it has passed on this host's clock, the reservation ends with the outcome unknown. A `pending` or `ambiguous` receipt then reads `ambiguous` with `release_code` `submission.accounting_expired`. A receipt with any other status keeps its status and code, and every projected receipt carries the decision identifier. An absent receipt is rebuilt from the committed expiry. The expiry owes one `submission_accounting_expired` audit event, which the call delivers from the authenticated window state. Repeated calls append no second event, and no `value_action_failed` row is written. A reservation without a time bound has no accounting horizon.

On a mainnet profile the primary endpoint's `FAILED` and `NOT_FOUND` are claims the oracle has to confirm. The call asks the oracle named by `oracle_provider_url` about the same transaction. The oracle's `SUCCESS` is recorded as a report, as above, and its `FAILED` keeps the reservation. Its `NOT_FOUND` runs the rule above with the oracle as the endpoint: the retention window, the ledger close time, the account sequence and the second lookup are all the oracle's. The oracle's answers count only once it reports the mainnet passphrase, which the call checks first. An oracle that reports another network, whose identity cannot be read, or that cannot answer, and a mainnet profile without an oracle, preserve the existing receipt status and the reservation. Accounting expiry is checked before any endpoint or oracle lookup, so it ends a time-bounded reservation in each of these cases.

On a mainnet profile the wallet's commit tools build classic envelopes with
a deadline 120 seconds after the build, so their accounting horizon is
bounded. On a testnet profile they build classic envelopes without a time
bound. A presented envelope, such as one the SEP-43 tool submits, can carry a
time bound, and so can the inner transaction of a fee-bump.

A `release_code` is display data and releases nothing by itself: a receipt
that carries one while its reservation is still held is reconciled like any
other. A receipt that reads `ambiguous` with no `release_code` names an
outcome nothing establishes, and no row is written for it.
When the expiry event cannot be delivered, for example because another process
holds the profile's audit writer, the call still answers. It logs the refusal,
and the event stays owed until a later call delivers it.

Automatic reconciliation applies the same checks when the receipts file is
absent. A success report or an accounting expiry restores the receipt's
transaction identity from its authenticated reservation.
An approval nonce is held durably in its submission receipt before sending. If
the approval-store consumption write fails, the commit gate still reports
`policy.approval_consumed`; a status call completes the owed write. Repeating
status is safe.

No endpoint answer establishes the outcome of a submission whose ledger has fallen outside the endpoint's retention window. When the endpoint answers `NOT_FOUND` for it, `stellar_transaction_status` reports a `pending` or `ambiguous` receipt as `ambiguous` without adding a `release_code`. When its receipt is missing and no success is recorded on the reservation, it reports a `reservation` with `operator_required: true`. A `SUCCESS` is recorded as above, and an untimed reservation's receipt that already records a network answer keeps it. A time-bounded reservation still ends at its accounting horizon without an operator clear. Once its execution bound has passed, an eligible receipt clears with `stellar-agent tx receipt clear <ENVELOPE_HASH> --acknowledge`, and the bounded spend stays charged through the horizon. An untimed hold clears with `--acknowledge --acknowledge-unbounded`.

On a testnet profile, a send the endpoint refused outright returns the refusal's code at the send, not `submission.tx_timeout`. When `sendTransaction` answers `ERROR` with a transaction result, the endpoint has reported a validation error for the envelope. The commit returns that error's code, and the wallet never sends those bytes again. The bytes did leave the wallet, so the receipt stays `pending`. The pending row and the reservation stand through the accounting horizon, and an operator clear of the receipt keeps a bounded spend charged until then. A reservation without a time bound has no accounting horizon, so the clear needs `--acknowledge --acknowledge-unbounded`. A copy relayed elsewhere that later becomes valid counts against the window while the reservation stands.

On a mainnet profile no second endpoint confirms a refusal at the send, so the commit returns `submission.tx_timeout`. The receipt, the pending row and the reservation stand: `stellar_transaction_status` records the oracle's answers as reports, and the reservation ends at its accounting horizon. A consumed sequence releases nothing. A refused envelope without a time bound keeps its reservation until the operator clears it with `stellar-agent tx receipt clear <ENVELOPE_HASH> --acknowledge --acknowledge-unbounded`.

No recovery path sends a transaction again.

`submission.record_unavailable` is different: the wallet could not write the record, so nothing was sent. The condition is local: an unwritable receipt store, an unreadable spending-window file, an audit log that cannot be appended, or a pending audit row the audit log's tip anchor does not cover, whose message carries `audit.tip_anchor_unavailable`. The submission is safe to retry once it is fixed.

Every submitting tool reports these codes, `stellar_dex_trade`, the two vault tools and `stellar_sep43_sign_and_submit_transaction` included. The SEP-43 tool keeps its own `status: "pending"` response shape for a timeout and records the submission the same way, so `stellar_transaction_status` reconciles it too.

An operator policy that lists tools explicitly must include `stellar_transaction_status`, or a timed-out submission cannot be resolved through this server.
