# stellar-agent-mcp — tool documentation

> **Note:** This document covers the core payment and account-management flows
> only. The server exposes many additional tools (SEP-43, SEP-53, x402, toolsets,
> DeFi, and others). For the full and authoritative list of tools and their
> schemas, send a `tools/list` request to the running server or consult the
> live tool `instructions` returned in the `initialize` response.

## stellar_balances

Fetches the native XLM balance and trustlines for a Stellar account.

**Arguments:**
- `chain_id` (string, required): CAIP-2 chain identifier. Accepted values: `stellar:testnet`, `stellar:mainnet`.
- `account_id` (string, required): Stellar G-strkey (ed25519 public key, 56 chars).

- `assets` (array, optional): Non-native trustlines to include. Each element is `{ "code": "USDC", "issuer": "GA5Z..." }`. Returns the native XLM balance plus any trustlines listed in the optional `assets` argument. Up to 100 trustline assets may be queried per call; assets the account does not currently trust are omitted from the returned `balances` list.

**Returns:** JSON envelope identical to `stellar-agent balances <account_id>`.

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

**Returns:** `{tx_hash, ledger}` on success.

**Annotations:** `readOnlyHint=false`, `destructiveHint=true`.

**Submission record:** Before the transaction is sent, the wallet records it as submitted with an unknown outcome: a submission receipt, a spending-window reservation, and a `value_action_pending` audit row. The record is settled by what the network answers; a submission whose outcome never comes back keeps it. See "Unresolved submissions" below.

**Error codes:** `nonce.expired`, `nonce.replayed`, `simulation.divergence`, `policy.engine_required`, `policy.approval_consumed`, `network.endpoint_network_mismatch`, `network.endpoint_identity_unavailable`, `network.envelope_signed_for_mainnet`, `network.envelope_signature_unverifiable`, `network.envelope_unsigned`, `submission.tx_timeout`, `submission.tx_already_submitted`, `submission.hash_mismatch`, `submission.record_unavailable`.

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

**Returns:** `{tx_hash, ledger}` on success.

**Annotations:** `readOnlyHint=false`, `destructiveHint=true`.

**Submission record:** Before the transaction is sent, the wallet records it as submitted with an unknown outcome: a submission receipt, a spending-window reservation, and a `value_action_pending` audit row. The record is settled by what the network answers; a submission whose outcome never comes back keeps it. See "Unresolved submissions" below.

**Error codes:** `nonce.expired`, `nonce.replayed`, `simulation.divergence`, `policy.engine_required`, `policy.approval_consumed`, `validation.memo_required`, `validation.memo_mutually_exclusive`, `network.endpoint_network_mismatch`, `network.endpoint_identity_unavailable`, `network.envelope_signed_for_mainnet`, `network.envelope_signature_unverifiable`, `network.envelope_unsigned`, `submission.tx_timeout`, `submission.tx_already_submitted`, `submission.hash_mismatch`, `submission.record_unavailable`.

## stellar_claim_commit

Commit step for `stellar_claim`: verifies the nonce, re-builds the `ClaimClaimableBalance` envelope for the divergence check, signs via the profile keyring, and submits. Testnet-only. Carries the same pre-send endpoint-identity probe, signature-binding check and submission record as the other commit tools.

**Returns:** `{tx_hash, ledger}` on success.

**Annotations:** `readOnlyHint=false`, `destructiveHint=true`.

**Error codes:** the same set as `stellar_pay_commit`, without the memo codes.

## stellar_trustline_commit

Commit step for `stellar_trustline`: verifies the nonce, re-builds the `ChangeTrust` envelope for the divergence check, signs via the profile keyring, and submits. Testnet-only. Carries the same pre-send endpoint-identity probe, signature-binding check and submission record as the other commit tools.

**Returns:** `{tx_hash, ledger}` on success.

**Annotations:** `readOnlyHint=false`, `destructiveHint=true`.

**Error codes:** the same set as `stellar_pay_commit`, without the memo codes, plus `policy.approval_required` when the issuer has clawback enabled and no operator opt-in is recorded.

## stellar_transaction_status

Reconciles one submitted transaction against the chain and settles the wallet's record of it.

**Arguments:**
- `chain_id` (string, required): CAIP-2 chain identifier.
- `tx_hash` (string, required): 64 lowercase hex characters — the `details.tx_hash` a `submission.tx_timeout` response carries.

**Returns:** `{tx_hash, chain_status, ledger, record}`. `chain_status` is what the endpoint reported (`SUCCESS`, `FAILED` or `NOT_FOUND`); `record` is the wallet's settled record of the submission, or absent when it holds none.

**Annotations:** `readOnlyHint=false`, `destructiveHint=false`. The pairing is deliberate: the call moves no value, and it does change the wallet's record — a confirmed transaction records its spend and writes the value-action row the submission never got to write, and one that can no longer apply releases its spending-window reservation.

**Error codes:** `validation.address_invalid`, `submission.record_unavailable`, `network.rpc_unreachable`, `audit.chain_key_unavailable`, `audit.tip_anchor_mismatch`.

## Unresolved submissions

Three error codes describe a submission whose outcome the wallet cannot settle on its own. All three carry a `details` object alongside the redacted message, and all three are resolved the same way.

| Code | What happened |
|---|---|
| `submission.tx_timeout` | The transaction was accepted for inclusion and was not confirmed within the submission timeout. It may still apply. |
| `submission.tx_already_submitted` | A pending record already holds this transaction's source account and sequence. Nothing was sent. |
| `submission.hash_mismatch` | The endpoint reported a transaction hash that does not describe the transaction that was sent. |

`details` carries:

- `tx_hash` — the transaction to reconcile, 64 lowercase hex characters, in full.
- `envelope_hash` — the submission record's identity, which `stellar-agent tx receipt clear` takes. Present only where the reporting surface holds the signed bytes; the DeFi verbs do not. Recover it from `stellar_transaction_status`'s `record.envelope_hash` when it is absent.
- `timeout_seconds` — present on `submission.tx_timeout`.
- `server_tx_hash` — present on `submission.hash_mismatch`.
- `outcome` — always `"unknown"`.
- `reconcile_with` — `"stellar_transaction_status"`.

**Recovery protocol.** Call `stellar_transaction_status` with `details.tx_hash`. Do not re-simulate and do not rebuild the payment: the sequence number the transaction consumes may already be spent by it, and a second submission at that sequence is refused with `submission.tx_already_submitted` until the first is settled. `stellar_transaction_status` reports what the chain says and settles the record:

- `SUCCESS` — the payment went through. The spend is recorded and the value-action row is written. Calling again appends no second row.
- `FAILED` — the transaction applied and failed. Nothing moved, and the reservation is released.
- `NOT_FOUND` — the endpoint has no record of it. Within the retention window, an expired time bound permits release. A consumed sequence requires a second transaction lookup: `SUCCESS` records the spend, `FAILED` releases it, and a second `NOT_FOUND` permits release as `ambiguous`. Otherwise the record stands: call again later.

Automatic reconciliation applies the same chain and retention checks when the
receipts file is absent. A definitive chain answer restores the receipt's
transaction identity from its reservation.
An approval nonce is held durably in its submission receipt before sending. If
the approval-store consumption write fails, the commit gate still reports
`policy.approval_consumed`; a status call completes the owed write. Repeating
status is safe.

A submission whose ledger has fallen outside the endpoint's retention window can never be settled this way. `stellar_transaction_status` reports it as `ambiguous` with `reservation_open: true`; the operator resolves it with `stellar-agent tx receipt clear <ENVELOPE_HASH> --acknowledge`.

`submission.record_unavailable` is different: the wallet could not write the record, so nothing was sent. The condition is local — an unwritable receipt store, an unreadable spending-window file, an audit log that cannot be appended — and the submission is safe to retry once it is fixed.

Every submitting tool reports these codes, `stellar_dex_trade`, the two vault tools and `stellar_sep43_sign_and_submit_transaction` included. The SEP-43 tool keeps its own `status: "pending"` response shape for a timeout and records the submission the same way, so `stellar_transaction_status` settles it too.

An operator policy that lists tools explicitly must include `stellar_transaction_status`, or a timed-out submission cannot be resolved through this server.
