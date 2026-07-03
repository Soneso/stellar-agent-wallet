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

Commit step: verifies the nonce, re-builds the envelope for divergence check, signs via the profile keyring, and submits the transaction. Testnet-only — mainnet profiles are rejected by the policy gate.

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

**Error codes:** `nonce.expired`, `nonce.replayed`, `simulation.divergence`, `policy.engine_required`.

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

Commit step: verifies the nonce, re-builds the Payment envelope for divergence check, signs via the profile keyring, and submits the transaction. Testnet-only — mainnet profiles are rejected by the policy gate.

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

**Error codes:** `nonce.expired`, `nonce.replayed`, `simulation.divergence`, `policy.engine_required`, `validation.memo_required`, `validation.memo_mutually_exclusive`.
