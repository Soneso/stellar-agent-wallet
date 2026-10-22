# stellar-agent-mcp — tool documentation

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
- `chain_id` (string, required): CAIP-2 chain identifier. Only `stellar:testnet` is accepted — mainnet profiles are rejected by the policy gate.
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

**Returns:** `{envelope_xdr, nonce, expires_at_unix_ms, simulation}`.

**Annotations:** `readOnlyHint=false`, `destructiveHint=false`.

**Fee cap:** The resolved per-operation fee is checked against the profile's
`classic_max_fee_per_op_stroops`. A fee above the cap returns
`fees.percentile_exceeds_cap`; the message names an auto-selected fee and its
percentile, an explicit `classic_base`, or the profile's
`classic_fee_per_op_stroops`. A mainnet profile without the cap returns
`validation.mainnet_fee_cap_required`.

## stellar_create_account_commit

Commit step: verifies the nonce, re-builds the envelope for divergence check, signs via the profile keyring, and submits the transaction. Testnet-only — mainnet profiles are rejected by the policy gate. Before the nonce is burned, the tool establishes which network the RPC endpoint actually serves and refuses a mismatch, so a wrongly-configured endpoint does not consume the nonce. The submit layer then verifies every signature on the envelope against the network the endpoint reported.

**Arguments:**
- `chain_id` (string, required): CAIP-2 chain identifier.
- `source` (string, required): G-strkey of the funding account.
- `destination` (string, required): G-strkey of the new account.
- `starting_balance` (string, required): Amount with unit suffix (same as simulate).
- `nonce` (string, required): Base64 nonce from the simulate step.
- `expires_at_unix_ms` (number, required): Expiry from the simulate step.
- `envelope_xdr` (string, required): Base64 envelope from the simulate step.

**Returns:** `{tx_hash, ledger, cross_check}` on success.

**Annotations:** `readOnlyHint=false`, `destructiveHint=true`.

**Submission record:** Before the transaction is sent, the wallet records it as submitted with an unknown outcome: a submission receipt, a spending-window reservation under a policy with a stateful criterion, and a `value_action_pending` audit row. The record is settled by what the network answers; a submission that ends without a confirmed outcome keeps it and returns `submission.tx_timeout`. On that code the outcome is unknown: pass `error.details.tx_hash` to `stellar_transaction_status`, and never resubmit. See "Unresolved submissions" below.

**Fee cap:** Before signing, the presented envelope's per-operation fee is
checked against the profile's `classic_max_fee_per_op_stroops`. A fee above the
cap returns `fees.percentile_exceeds_cap` with a message naming the envelope's
fee; prepare the transaction again with a fee within the cap. A mainnet profile
without the cap returns `validation.mainnet_fee_cap_required`.

**Error codes:** `nonce.expired`, `nonce.replayed`, `simulation.divergence`,
`fees.percentile_exceeds_cap`, `validation.mainnet_fee_cap_required`,
`network.witness_unavailable`, `policy.engine_required`, `policy.approval_consumed`,
`network.endpoint_network_mismatch`, `network.endpoint_identity_unavailable`,
`network.rpc_credential_refused`, `auth.keyring_not_found`,
`network.envelope_signed_for_mainnet`, `network.envelope_signature_unverifiable`,
`network.envelope_unsigned`, `submission.tx_timeout`, `submission.tx_already_submitted`,
`submission.hash_mismatch`, `submission.record_unavailable`.

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
- `amount_in_stroops` (number, optional): Raw positive stroop integer. Mutually exclusive with `amount`.
- `asset` (string, required): `"native"` / `"XLM"` or `"CODE:G…ISSUER"`.
- `memo_text` (string, optional): UTF-8 text memo (≤ 28 bytes). Mutually exclusive.
- `memo_id` (number, optional): Integer memo (u64). Mutually exclusive.
- `memo_hash_hex` (string, optional): 32-byte hash memo as 64 hex chars. Mutually exclusive.
- `memo_return_hex` (string, optional): 32-byte return memo as 64 hex chars. Mutually exclusive.

**Returns:** `{envelope_xdr, nonce, expires_at_unix_ms, simulation}`.

**Annotations:** `readOnlyHint=false`, `destructiveHint=false`.

**SEP-29:** If the destination's `config.memo_required` data entry is set to `"1"` and no memo is provided, returns `validation.memo_required`.

**Fee cap:** The resolved per-operation fee is checked against the profile's
`classic_max_fee_per_op_stroops`. A fee above the cap returns
`fees.percentile_exceeds_cap`; the message names an auto-selected fee and its
percentile, an explicit `classic_base`, or the profile's
`classic_fee_per_op_stroops`. A mainnet profile without the cap returns
`validation.mainnet_fee_cap_required`.

## stellar_pay_commit

Commit step: verifies the nonce, re-builds the Payment envelope for divergence check, signs via the profile keyring, and submits the transaction. Testnet-only — mainnet profiles are rejected by the policy gate. Before the nonce is burned, the tool establishes which network the RPC endpoint actually serves and refuses a mismatch, so a wrongly-configured endpoint does not consume the nonce. The submit layer then verifies every signature on the envelope against the network the endpoint reported.

**Arguments:**
- `chain_id` (string, required): CAIP-2 chain identifier.
- `source` (string, required): G-strkey of the source account.
- `destination` (string, required): G-strkey of the recipient account.
- `amount` (string, optional): Amount with unit suffix (same as simulate). Mutually exclusive with
  `amount_in_stroops`.
- `amount_in_stroops` (number, optional): Raw positive stroop integer (same as simulate). Mutually
  exclusive with `amount`.
- `asset` (string, required): Asset descriptor (same as simulate).
- `memo_text` / `memo_id` / `memo_hash_hex` / `memo_return_hex` (optional, same as simulate).
- `nonce` (string, required): Base64 nonce from the simulate step.
- `expires_at_unix_ms` (number, required): Expiry from the simulate step.
- `envelope_xdr` (string, required): Base64 envelope from the simulate step.

**Returns:** `{tx_hash, ledger, cross_check}` on success.

**Annotations:** `readOnlyHint=false`, `destructiveHint=true`.

**Submission record:** Before the transaction is sent, the wallet records it as submitted with an unknown outcome: a submission receipt, a spending-window reservation under a policy with a stateful criterion, and a `value_action_pending` audit row. The record is settled by what the network answers; a submission that ends without a confirmed outcome keeps it and returns `submission.tx_timeout`. On that code the outcome is unknown: pass `error.details.tx_hash` to `stellar_transaction_status`, and never resubmit. See "Unresolved submissions" below.

**Destination read:** Only an absent destination account counts as absent; any
other failed destination read refuses with the read's own code.

**Fee cap:** Before signing, the presented envelope's per-operation fee is
checked against the profile's `classic_max_fee_per_op_stroops`. A fee above the
cap returns `fees.percentile_exceeds_cap` with a message naming the envelope's
fee; prepare the transaction again with a fee within the cap. A mainnet profile
without the cap returns `validation.mainnet_fee_cap_required`.

**Error codes:** `nonce.expired`, `nonce.replayed`, `simulation.divergence`,
`fees.percentile_exceeds_cap`, `validation.mainnet_fee_cap_required`,
`network.witness_unavailable`, `network.rpc_divergence`, `validation.memo_required`,
`policy.engine_required`, `policy.approval_consumed`,
`validation.memo_mutually_exclusive`, `network.endpoint_network_mismatch`,
`network.endpoint_identity_unavailable`, `network.rpc_credential_refused`,
`auth.keyring_not_found`, `network.envelope_signed_for_mainnet`,
`network.envelope_signature_unverifiable`, `network.envelope_unsigned`, `submission.tx_timeout`,
`submission.tx_already_submitted`, `submission.hash_mismatch`, `submission.record_unavailable`.

`cross_check` reports `passed` with `provider` and `ledger`, `skipped` with a
reason, or `not_required` with reason `below_threshold`.

## stellar_claim_commit

Commit step for `stellar_claim`: verifies the nonce, re-builds the `ClaimClaimableBalance` envelope for the divergence check, signs via the profile keyring, and submits. Testnet-only. Carries the same pre-send endpoint-identity probe, signature-binding check and submission record as the other commit tools.

**Returns:** `{tx_hash, ledger, cross_check}` on success.

`stellar_claim_commit` witnesses the source account and complete fresh
claimable-balance record. It does not re-read the source trustline at commit.

The commit obtains its unvalued witness before nonce consumption and signer
loading. `cross_check` reports `passed` with provider and ledger, or `skipped`
with a reason. A witness refusal keeps the nonce usable.

**Annotations:** `readOnlyHint=false`, `destructiveHint=true`.

**Fee cap:** Before signing, the presented envelope's per-operation fee is
checked against the profile's `classic_max_fee_per_op_stroops`. A fee above the
cap returns `fees.percentile_exceeds_cap` with a message naming the envelope's
fee; prepare the transaction again with a fee within the cap. A mainnet profile
without the cap returns `validation.mainnet_fee_cap_required`.

**Error codes:** `nonce.expired`, `nonce.replayed`, `simulation.divergence`,
`fees.percentile_exceeds_cap`, `validation.mainnet_fee_cap_required`,
`network.witness_unavailable`, `policy.engine_required`, `policy.approval_consumed`,
`network.endpoint_network_mismatch`,
`network.endpoint_identity_unavailable`, `network.rpc_credential_refused`,
`auth.keyring_not_found`, `network.envelope_signed_for_mainnet`,
`network.envelope_signature_unverifiable`, `network.envelope_unsigned`,
`submission.tx_timeout`, `submission.tx_already_submitted`, `submission.hash_mismatch`,
`submission.record_unavailable`.

## stellar_trustline_commit

Commit step for `stellar_trustline`: verifies the nonce, re-builds the `ChangeTrust` envelope for the divergence check, signs via the profile keyring, and submits. Testnet-only. Carries the same pre-send endpoint-identity probe, signature-binding check and submission record as the other commit tools.

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
checked against the profile's `classic_max_fee_per_op_stroops`. A fee above the
cap returns `fees.percentile_exceeds_cap` with a message naming the envelope's
fee; prepare the transaction again with a fee within the cap. A mainnet profile
without the cap returns `validation.mainnet_fee_cap_required`.

**Error codes:** `nonce.expired`, `nonce.replayed`, `simulation.divergence`,
`fees.percentile_exceeds_cap`, `validation.mainnet_fee_cap_required`,
`network.witness_unavailable`, `policy.engine_required`, `policy.approval_consumed`,
`network.endpoint_network_mismatch`,
`network.endpoint_identity_unavailable`, `network.rpc_credential_refused`,
`auth.keyring_not_found`, `network.envelope_signed_for_mainnet`,
`network.envelope_signature_unverifiable`, `network.envelope_unsigned`,
`submission.tx_timeout`, `submission.tx_already_submitted`, `submission.hash_mismatch`,
`submission.record_unavailable`.
Clawback re-check refusals use `trustline.gate_refused` or
`trustline.clawback_opt_in_required`, as described above.

## stellar_transaction_status

Reconciles one submitted transaction against the chain and settles the wallet's record of it.

**Arguments:**
- `chain_id` (string, required): CAIP-2 chain identifier.
- `tx_hash` (string, required): 64 lowercase hex characters: the `details.tx_hash` a `submission.tx_timeout` response carries.

**Returns:** `{tx_hash, chain_status, ledger, record, reservation}`. `chain_status` is what the endpoint reported (`SUCCESS`, `FAILED` or `NOT_FOUND`).

- `record` is the wallet's settled record of the submission, or `null` when it holds none: `envelope_hash`, `status`, `failure_code`, `release_code`, `ledger`, `source_redacted`, `sequence`, `submitted` and `reservation_open`. `release_code` names the chain evidence a reservation was released on, `submission.sequence_consumed` or `submission.time_bound_passed`, and is `null` otherwise. It is how an agent tells a release on evidence (`status: "ambiguous"` with a `release_code`) from an outcome nothing can establish (`status: "ambiguous"` without one). Read `status` and `release_code`, not `reservation_open`.
- `reservation` is a hold that remains after reconciliation, `{envelope_hash, operator_required}`, or `null`. `operator_required: true` marks a reservation whose receipt is missing and whose submission ledger is below the endpoint's retention floor: only the operator's `stellar-agent tx receipt clear` resolves it.

The tool settles a submission by its receipt, or by its reservation when the receipt is missing, and sends nothing.

**Annotations:** `readOnlyHint=false`, `destructiveHint=false`. The pairing is deliberate: the call moves no value, and it does change the wallet's record. A confirmed transaction records its spend and writes the value-action row the submission never got to write, and one that can no longer apply releases its spending-window reservation and writes a `value_action_failed` row under its `release_code`.

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
- `envelope_hash`: the submission record's identity, which `stellar-agent tx receipt clear` takes. Present only where the reporting surface holds the signed bytes; the DeFi verbs do not. Recover it from `stellar_transaction_status`'s `record.envelope_hash` when it is absent.
- `timeout_seconds`: present on `submission.tx_timeout`.
- `server_tx_hash`: present on `submission.hash_mismatch`.
- `outcome`: always `"unknown"`.
- `reconcile_with`: `"stellar_transaction_status"`.

**Recovery protocol.** Call `stellar_transaction_status` with `details.tx_hash`. Do not re-simulate, rebuild, or resubmit the payment: the transaction may still apply, the sequence number it consumes may already be spent by it, and a second submission at that sequence is refused with `submission.tx_already_submitted` until the first is settled. `stellar_transaction_status` reports what the chain says and settles the record:

- `SUCCESS`: the payment went through. The spend is recorded and the value-action row is written. Calling again appends no second row.
- `FAILED`: the transaction applied and failed. Nothing moved, and the reservation is released.
- `NOT_FOUND`: the endpoint has no record of it. Within the retention window, two kinds of chain evidence say the transaction can no longer apply: an observed ledger close time strictly past its time bound, or a source account sequence that has reached the transaction's. Either is followed by a second transaction lookup: `SUCCESS` records the spend, `FAILED` releases it, and a second `NOT_FOUND` releases the reservation. The record becomes `ambiguous` with `release_code` set to `submission.sequence_consumed` or `submission.time_bound_passed`, and a `value_action_failed` row is written under that code. Without such evidence the record stands: call again later.

`submission.time_bound_passed` needs a transaction with a time bound. The
wallet's commit tools build classic envelopes without one, so on those the
evidence is a consumed sequence. A presented envelope, such as one the SEP-43
tool submits, can carry a time bound, and so can the inner transaction of a
fee-bump.

The receipt keeps its `release_code`, so a settled row that could not be
written when the reservation was released is written by the next call. A
receipt released without recorded evidence, for example by an older binary,
reads as `ambiguous` with no `release_code`, and no row is written for it.

Automatic reconciliation applies the same chain and retention checks when the
receipts file is absent. A definitive chain answer or a release on chain
evidence restores the receipt's transaction identity from its reservation.
An approval nonce is held durably in its submission receipt before sending. If
the approval-store consumption write fails, the commit gate still reports
`policy.approval_consumed`; a status call completes the owed write. Repeating
status is safe.

A submission whose ledger has fallen outside the endpoint's retention window can never be settled this way. `stellar_transaction_status` reports it as `ambiguous` with no `release_code`, or, when its receipt is missing, as `reservation` with `operator_required: true`; the operator resolves it with `stellar-agent tx receipt clear <ENVELOPE_HASH> --acknowledge`.

A send the endpoint refused outright is settled at the send and never reaches this protocol. When `sendTransaction` answers `ERROR` with a transaction result, the endpoint has reported a validation error for the envelope: the commit returns that error's code, the receipt records the failure, the reservation is released, and the wallet never sends those bytes again. They did leave the wallet, though. A copy relayed elsewhere that later becomes valid applies without being counted against the window, and its receipt stays `failed`.

No recovery path sends a transaction again.

`submission.record_unavailable` is different: the wallet could not write the record, so nothing was sent. The condition is local — an unwritable receipt store, an unreadable spending-window file, an audit log that cannot be appended — and the submission is safe to retry once it is fixed.

Every submitting tool reports these codes, `stellar_dex_trade`, the two vault tools and `stellar_sep43_sign_and_submit_transaction` included. The SEP-43 tool keeps its own `status: "pending"` response shape for a timeout and records the submission the same way, so `stellar_transaction_status` settles it too.

An operator policy that lists tools explicitly must include `stellar_transaction_status`, or a timed-out submission cannot be resolved through this server.
