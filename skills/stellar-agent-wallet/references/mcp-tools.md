# MCP tools

The `stellar-agent-mcp` server exposes the Stellar Agent Wallet to an MCP client
over JSON-RPC on stdio. It presents wallet capabilities as MCP tools so an AI
assistant can read account state and submit Stellar transactions through the same
policy engine, operator-approval spine, and tamper-evident audit log that back
the `stellar-agent` CLI. A tool call is gated exactly as the equivalent CLI
command is.

This file documents the tool catalog: each tool name, purpose, gating, and key
arguments. For the gating model itself (policy engines, the mainnet-write gate,
approval attestations) see `./approvals-and-audit.md` and `./security.md`.

## Transport and identity

- One process: the `stellar-agent-mcp` binary. It takes no command-line
  arguments; configuration comes from the active profile resolved from disk and
  the platform keyring.
- Transport: MCP JSON-RPC over stdio (newline-delimited). `stdout` is the
  protocol wire; logs go to `stderr` (already redacted). The transport enforces a
  1 MiB maximum line length on inbound and outbound frames. There is no HTTP or
  SSE transport.
- Protocol version `2024-11-05`. Declared capabilities: `tools` and `resources`.
- Server identity at `initialize`: name `stellar-agent-mcp`, version matching
  the crate's package version (`0.1.0-alpha.1` as of this release).
- The server refuses to start if the active profile sets `mcp_disabled = true`,
  exiting non-zero with `mcp.disabled_per_profile`.

A generic client stanza points the spawn command at the binary:

```json
{
  "mcpServers": {
    "stellar-agent": {
      "command": "/absolute/path/to/stellar-agent-mcp",
      "args": []
    }
  }
}
```

## The result envelope

Every tool returns the same JSON envelope:

```json
{ "ok": true, "data": { }, "request_id": "..." }
```

On failure, `ok` is `false` and `error` carries a stable wire `code` (such as
`policy.deny.<reason>` or `policy.approval_required`) instead of `data`. Branch on
`ok`; use `code` for control flow, not the human message. The `request_id`
correlates the call with the audit log. Argument values are never written to the
audit log; only key names and lifecycle metadata are recorded.

## Gating model in brief

Every call is dispatched through one gate before the tool's logic runs. The
policy engine returns one verdict:

- `Allow` — the tool proceeds.
- `Deny` — refused with wire code `policy.deny.<reason>`.
- `RequireApproval` — an out-of-band operator approval is required.

Separately, on `stellar:mainnet` the Noop engine fails closed for any
destructive tool, returning `policy.engine_required` before any RPC call or
signing. The two engines are Noop (testnet allow-all; mainnet read-only allow,
mainnet destructive refused) and V1 (signature-verified typed criteria,
first-match default-deny).

How `RequireApproval` is satisfied depends on tool shape:

- Two-phase signing verbs (`stellar_pay`, `stellar_create_account`,
  `stellar_trustline`, each paired with a `*_commit`) split into a simulate step
  and a commit step. The simulate step builds an envelope and mints a single-use
  nonce; if approval is required it records the pending approval. The commit step
  re-checks the nonce, byte-compares the envelope against a fresh rebuild,
  verifies the HMAC-SHA256 attestation minted at approve time, signs from the
  keyring, and submits. The wire error on any approval-path failure is the
  uniform `policy.approval_required`.
- One-shot signing verbs sign in a single call. If the policy returns
  `RequireApproval` for one of these, the call is refused fail-closed with
  `policy.approval_required_unsupported`; the wallet never signs without a
  verified approval.

## chain_id requirement

`chain_id` carries the CAIP-2 chain id (`stellar:testnet` or `stellar:mainnet`;
x402 tools also accept `stellar:pubnet`) and must match the loaded profile.

- Required by every tool EXCEPT: `stellar_x402_parse_receipt`,
  `stellar_toolset_list`, `stellar_toolset_invoke`.
- `stellar_toolset_invoke` accepts an optional `chain_id` that it forwards to the
  routed tool, which may itself require it.
- For `stellar_sep43_get_address` and `stellar_sep43_get_network`, `chain_id` is
  optional and defaults to the profile chain when omitted, but is still validated
  against the profile when supplied.

A mismatch is refused before any network call.

## Amount and asset conventions

- Dual-unit amount fields (`amount`, `starting_balance`) are decimal strings with
  an explicit unit suffix, never JSON numbers. Example: `"10 XLM"`, `"1 XLM"`.
- Asset descriptors: `"native"` or `"XLM"` (case-insensitive) for XLM, or
  `"CODE:GISSUER"` for non-native assets.
- Raw on-chain integer fields use distinct names and carry NO unit label:
  `amount_in_stroops` (u64), `limit_stroops` (i64) are JSON numbers; they are
  exact only up to `2^53` (about 900 million XLM in stroops) — an `f64`-backed
  JSON parser silently rounds larger values. `qty_in` / `qty_out_min` / `qty`
  (i128),
  `amounts_desired` / `amounts_min` / `min_amounts_out` (i128 arrays), and
  `withdraw_shares` (i128) are DECIMAL STRINGS, not JSON numbers — a raw JSON
  number above `2^53` cannot be represented exactly by an `f64`-backed parser,
  so these fields are String-typed and a raw number is rejected. Anchor-facing
  amounts (`deposit_hint`) are plain decimal strings without XLM-stroop
  semantics.
- Classic fee selector (`fee` field): `<stroops>`, `auto`, or `auto:pNN`.

## Payments and accounts

| Tool | Purpose | Gating |
| --- | --- | --- |
| `stellar_pay` | Build a Payment envelope, run the SEP-29 memo-required check, mint a single-use nonce. | No signing; no submission. Mints the nonce the commit step consumes. |
| `stellar_pay_commit` | Verify the nonce, re-check the envelope, sign from the keyring, submit. | Signs and submits. Two-phase; approval spine. |
| `stellar_create_account` | Build the CreateAccount envelope, mint a single-use nonce. | No signing; no submission. Mints the nonce the commit step consumes. |
| `stellar_create_account_commit` | Verify the nonce, re-check the envelope, sign, submit. | Signs and submits. Two-phase; approval spine. |
| `stellar_balances` | Fetch native XLM balance and optional trustline balances. | Read-only. |
| `stellar_friendbot` | Fund a testnet account via Friendbot. | Mutating, testnet-only; gated. |

### stellar_pay (simulate) arguments

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `chain_id` | string | yes | CAIP-2; must match profile. |
| `source` | string | yes | G-strkey of the funding account. |
| `destination` | string | yes | G-strkey of the recipient. |
| `amount` | string | one of amount/stroops | Decimal + unit, e.g. `"10 XLM"`. |
| `amount_in_stroops` | integer (u64) | one of amount/stroops | Raw stroops, no unit; mutually exclusive with `amount`; rejected if > i64::MAX. |
| `asset` | string | yes | `"native"`/`"XLM"` or `"CODE:GISSUER"`. |
| `memo_text` | string | no | UTF-8, at most 28 bytes; mutually exclusive with other memo fields. |
| `memo_id` | integer (u64) | no | Mutually exclusive with other memo fields. |
| `memo_hash_hex` | string | no | 64 hex chars (32 bytes); mutually exclusive. |
| `memo_return_hex` | string | no | 64 hex chars (32 bytes); mutually exclusive. |
| `fee` | string | no | Classic fee selector: `<stroops>`, `auto`, `auto:pNN`. |

Returns `{ envelope_xdr, nonce, expires_at_unix_ms, simulation }`. When the
policy requires approval, the simulation includes an `approval` block carrying
`approval_nonce` and `expires_at_unix_ms`.

### stellar_pay_commit arguments

Repeats the simulate arguments (`chain_id`, `source`, `destination`, `amount` /
`amount_in_stroops`, `asset`, and any memo fields — same values as simulate) plus
the binding triple and the optional approval pair:

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `nonce` | string | yes | Base64-url-no-pad nonce from simulate; HMAC-verified against `envelope_xdr`, `expires_at_unix_ms`, and the chain. |
| `expires_at_unix_ms` | integer (u64) | yes | Unix milliseconds at which the nonce expires. |
| `envelope_xdr` | string | yes | Base64 envelope from simulate; byte-compared against a fresh rebuild. |
| `approval_nonce` | string | when approval required | Wallet-issued approval nonce from the simulate-step `approval` block. |
| `approval_attestation` | string | when approval required | HMAC-SHA256 attestation minted by the operator at approve time; constant-time verified alongside `approval_nonce`. |

Example simulate then commit:

```json
{ "chain_id": "stellar:testnet", "source": "GABC...SRC", "destination": "GDEF...DST", "amount": "10 XLM", "asset": "native" }
```
```json
{ "chain_id": "stellar:testnet", "source": "GABC...SRC", "destination": "GDEF...DST", "amount": "10 XLM", "asset": "native",
  "nonce": "<from simulate>", "expires_at_unix_ms": 1234567890000, "envelope_xdr": "<from simulate>" }
```

### stellar_create_account / stellar_create_account_commit arguments

Simulate: `chain_id`, `source` (G-strkey funding account), `destination`
(G-strkey new account, must not yet exist), `starting_balance` (decimal + unit,
e.g. `"1 XLM"`), optional `fee`.

Commit: repeats `chain_id`, `source`, `destination`, `starting_balance`, plus the
same binding triple (`nonce`, `expires_at_unix_ms`, `envelope_xdr`) and the
optional `approval_nonce` / `approval_attestation` pair as `stellar_pay_commit`.

### stellar_balances arguments

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `chain_id` | string | yes | |
| `account_id` | string | yes | G-strkey, 56 chars. |
| `assets` | array | no | Each entry `{ "code": "USDC", "issuer": "GA5Z..." }`. Empty/absent returns native XLM only. |

### stellar_friendbot arguments

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `chain_id` | string | yes | Only `stellar:testnet` succeeds; mainnet returns `policy.engine_required`. |
| `account_id` | string | yes | G-strkey to fund. |

(An optional Friendbot endpoint override is accepted; the default URL for the
resolved chain is used when omitted.)

## Trustline

| Tool | Purpose | Gating |
| --- | --- | --- |
| `stellar_trustline` | Build the ChangeTrust envelope, run the issuer clawback-flag gate, mint a single-use nonce. | No signing; no submission. Mints the nonce the commit step consumes. |
| `stellar_trustline_commit` | Verify the nonce, re-derive the authoritative asset/issuer/limit from the envelope, sign, submit. | Signs and submits. Two-phase; approval spine. |

### stellar_trustline (simulate) arguments

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `chain_id` | string | yes | |
| `from` | string | yes | G-strkey of the account that will hold the trustline. |
| `asset` | string | yes | `"USDC"` (bare code, pin-table resolved) or `"USDC:GISSUER"`. A 56-char `C...` SAC address is parsed but deferred and returns a typed error. |
| `limit_stroops` | integer (i64) | no | Absent/null → protocol default (unlimited). `0` removes the trustline. |
| `fee` | string | no | Classic fee selector. |

Commit: `chain_id`, `from`, plus the binding triple (`nonce`,
`expires_at_unix_ms`, `envelope_xdr`) and the optional `approval_nonce` /
`approval_attestation` pair. The authoritative asset/issuer/limit are re-derived
from `envelope_xdr`, not from caller-supplied args.

## Claimable balances

| Tool | Purpose | Gating |
| --- | --- | --- |
| `stellar_claim` | Fetch the on-chain claimable-balance entry, render a typed preview, enforce the claim guards (claimant, predicate, trustline, fee affordability), build the `ClaimClaimableBalance` envelope, mint a single-use nonce. | No signing; no submission. Mints the nonce the commit step consumes. |
| `stellar_claim_commit` | Re-derive the authoritative args from the envelope, re-fetch and re-check the entry, verify the nonce, rebuild and byte-compare the envelope, sign from the keyring, submit. | Signs and submits. Two-phase; approval spine. |

### stellar_claim (simulate) arguments

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `chain_id` | string | yes | CAIP-2; must match profile. |
| `balance_id` | string | yes | A `B...` strkey, a canonical 72-hex id, or a bare 64-hex hash. |
| `source_account` | string | no | G-strkey of the claiming account. Defaults to the profile's default MCP signer account when omitted. |

Returns `{ envelope_xdr, nonce, expires_at_unix_ms, preview }`. `preview`
carries the balance id (both hex72 and strkey forms), asset code/issuer
(absent for native XLM), `amount_stroops`, `amount_display`, the entry's
claimants, whether `source_account` is a claimant, and the matched predicate
verdict. When the policy requires approval, the response includes an
`approval` block with `approval_nonce` and `expires_at_unix_ms`.

Claim guards enforced before the nonce is minted, in order: claimant
membership (`claim.not_claimant`), predicate satisfaction
(`claim.predicate_not_satisfied`), non-native trustline state
(`claim.trustline_missing` / `claim.trustline_not_authorized` /
`claim.trustline_limit`), and native-XLM fee affordability
(`ledger.insufficient_balance` — claiming credits the account, so only the fee
is checked, never the claimed amount).

### stellar_claim_commit arguments

Repeats the simulate arguments (`chain_id`, `balance_id`, `source_account` —
same values as simulate) plus the binding triple and the optional approval
pair:

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `nonce` | string | yes | Base64-url-no-pad nonce from `stellar_claim`. |
| `expires_at_unix_ms` | integer (u64) | yes | Unix milliseconds at which the nonce expires. |
| `envelope_xdr` | string | yes | Base64 envelope from `stellar_claim`; byte-compared against a fresh rebuild. |
| `approval_nonce` | string | when approval required | Wallet-issued approval nonce from the simulate-step `approval` block. |
| `approval_attestation` | string | when approval required | HMAC-SHA256 attestation minted by the operator at approve time. |

`stellar_claim_commit` re-fetches the claimable-balance entry and re-runs the
claimant and predicate guards against fresh on-chain state (the trustline and
account checks are not re-run at commit time — a between-phase trustline
change fails cleanly on submission instead). A rebuilt envelope that does not
byte-match the presented `envelope_xdr` returns `simulation.divergence`.

## Fees

| Tool | Purpose | Gating |
| --- | --- | --- |
| `stellar_fee_stats` | Fetch classic and Soroban inclusion-fee distributions for fee estimation. | Read-only. |

Arguments: `chain_id` only.

## Smart-account rules

| Tool | Purpose | Gating |
| --- | --- | --- |
| `stellar_rules_list` | Enumerate active context rules on a smart account: `rule_id`, `name`, `context_type_label`, `valid_until`, `signer_count`, `policy_count`, plus `as_of_ledger`. | Read-only. |
| `stellar_rules_get` | Read one context rule's metadata, its policies (`address`, `identified_kind`), and — when exactly one policy identifies as `spending-limit` — the budget snapshot. | Read-only. |

Both tools are grantable to a toolset via the `read-rules` capability token,
separately from `read-balance` (see [Toolsets](toolsets-feature.md)).

### stellar_rules_list arguments

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `chain_id` | string | yes | |
| `smart_account` | string | yes | Smart-account contract C-strkey. |

Scans up to the same `max_scan_id` default the CLI `smart-account rules
list` uses. Returns `{ rules: [{ rule_id, name, context_type_label,
valid_until, signer_count, policy_count }], as_of_ledger }`.

### stellar_rules_get arguments

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `chain_id` | string | yes | |
| `smart_account` | string | yes | Smart-account contract C-strkey. |
| `rule_id` | integer (u32) | yes | Context rule id to read. |

Returns the list fields for that one rule, plus `expires_in_ledgers`
(derived from `valid_until − as_of_ledger` when `valid_until` is set),
`policies: [{ address, identified_kind }]` (`identified_kind` is
`"threshold"`, `"spending-limit"`, or `"unknown"` — identification failure
degrades to `"unknown"` rather than failing the call), and, when exactly one
policy identifies as `spending-limit`, a `spending_limit` block:
`{ spending_limit, period_ledgers, in_window_spent, remaining_budget,
as_of_ledger }`. `spending_limit`, `in_window_spent`, and `remaining_budget`
are decimal strings (i128, stroops); `period_ledgers` and `as_of_ledger` are
integers (u32).

`in_window_spent` and `remaining_budget` are exact only as of
`as_of_ledger`: forward ledger movement only grows headroom (older spend
entries fall out of the rolling window), but an intervening spend shrinks
it — the numbers are a point-in-time estimate, not a guarantee for a future
submission, which can still fail `SpendingLimitExceeded`.

## Agent-proposed context rules

| Tool | Purpose | Gating |
| --- | --- | --- |
| `stellar_rule_create` | Testnet-only. Resolve and simulate an `add_context_rule` installation you are proposing — signers, policies, context, name, expiry, `auth_rule_ids` — and park it as a pending approval. | No signing; no submission. Always mints an `approval_nonce`. |
| `stellar_rule_create_commit` | Testnet-only. Verify the operator's attestation over the resolved definition and install the rule. | Signs and submits. Two-phase verb; approval spine. ALWAYS requires operator attestation, regardless of any policy verdict. |

You never hold rule-write authority: `stellar_rule_create` only resolves and
simulates; `stellar_rule_create_commit` installs only after the operator has
attested to the EXACT definition you proposed, reviewed on one of the
operator's approval surfaces (CLI, loopback inbox, or remote inbox), which
render the full rule — every signer, every policy, the context, and a
prominent callout if you proposed `Default` (account-wide authority).
Unlike the payment/claim commit tools, a policy engine `Allow` verdict can
never let `stellar_rule_create_commit` skip the operator attestation step —
this pair only operates on testnet.

### stellar_rule_create arguments

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `chain_id` | string | yes | |
| `smart_account` | string | yes | Smart-account contract C-strkey. |
| `context` | string | no | `"default"` (default), `"call-contract:<C-strkey>"`, or `"create-contract:<64-hex-wasm-hash>"`. |
| `name` | string | yes | 1–20 bytes (OZ cap). |
| `valid_until` | integer (u32) | no | Ledger sequence at which the rule expires; omit for permanent. |
| `signers` | array | yes | At least one entry (OZ cap 15). Each is `{"kind": "delegated", "address": <G-or-C-strkey>}`, `{"kind": "external", "verifier": <C-strkey>, "pubkey_data_hex": <hex>}`, or `{"kind": "webauthn", "credential_name": <name>}` (resolved from the passkey store at propose time). |
| `policies` | array | no | Up to 5. Each is `{"kind": "raw", "policy_address": <C-strkey>, "install_param_xdr_b64": <base64>}` or `{"kind": "spending_limit", "limit_stroops": <decimal string>, "period_ledgers": <u32>, "policy_address": <C-strkey, optional>}`. |
| `auth_rule_ids` | array of integer | no | Defaults to `[0]` (the bootstrap rule). |
| `accept_mutable_verifier` | bool | no | Opt in to a mutable-admin verifier/policy contract. Rendered as a warning on every approval surface when set. |
| `accept_unknown_verifier` | bool | no | Opt in to a verifier/policy wasm hash outside the compile-time allowlist. Rendered as a warning when set. |
| `accept_no_delegated_fallback` | bool | no | Required `true` when every signer is `webauthn` and no `delegated` entry is present — otherwise the rule has no ed25519 fallback if the passkey device is lost. |

Returns `{ approval_nonce, expires_at_unix_ms, requires_operator_approval,
proposal_sha256_hex, summary: { context_type_label, name, signer_count,
policy_count, auth_rule_ids, summary_line } }`. `approval_nonce` is always
present — unlike `stellar_pay` / `stellar_claim`, there is no envelope
fallback for the commit step, so the pending approval is the sole carrier of
the resolved definition.

### stellar_rule_create_commit arguments

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `chain_id` | string | yes | |
| `approval_nonce` | string | yes | From `stellar_rule_create`'s response. REQUIRED (not optional, unlike the pay/claim commit pair). |
| `approval_attestation` | string | when `requires_operator_approval` was `true` | HMAC-SHA256 attestation blob the operator's `approve` produced. |

Returns `{ rule_id, tx_hash }` on success. Verifies the attestation through a
DEDICATED gate (distinct from the payment/claim attestation gate) and
recomputes the digest from the stored snapshot UNCONDITIONALLY before
installing — a mismatch refuses with `simulation.divergence` regardless of
the policy verdict.

## DeFi

| Tool | Purpose | Gating |
| --- | --- | --- |
| `stellar_blend_lend` | Supply/withdraw/borrow/repay on a Blend pool behind an ordered trust gate (pool WASM-hash pin, oracle allowlist, oracle staleness), then a smart-account submit. | Signs via the smart account and submits; policy gate. |
| `stellar_defindex_vault_deposit` | Deposit into a DeFindex vault behind an ordered trust gate (vault WASM-hash pin, upgradable-flag check, role and asset disclosure), then a smart-account submit. | Signs via the smart account and submits; policy gate. |
| `stellar_defindex_vault_withdraw` | Withdraw from a DeFindex vault by redeeming shares, behind the same trust gate. | Signs via the smart account and submits; policy gate. |
| `stellar_dex_trade` | Soroswap router-direct swap behind a venue allowlist, router WASM-hash pin, and on-chain slippage re-verify, then a smart-account submit. | Signs via the smart account and submits; policy gate. |
| `stellar_dex_quote` | On-chain Soroswap `router_get_amounts_out` quote for a token path. | Read-only. |

### stellar_blend_lend arguments

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `chain_id` | string | yes | |
| `pool_address` | string | yes | Blend pool contract C-strkey. |
| `from_address` | string | yes | Wallet smart-account address (C-strkey). |
| `requests` | array | yes | Each `{ "request_type": <u32>, "address": "<C-strkey>", "qty": "<decimal i128 string>" }`. |
| `override_oracle_staleness` | bool | no | Default `false`; overridable staleness only — pin-verify and oracle-allowlist refusals are non-overridable. |
| `secondary_rpc_url` | string | no | Second RPC for the two-RPC WASM-hash cross-check. |
| `max_staleness_secs` | integer (u64) | no | Default 600. |

`request_type`: 0 Supply, 1 Withdraw, 2 SupplyCollateral, 3 WithdrawCollateral,
4 Borrow, 5 Repay. `qty` is a raw 7-decimal i128 as a decimal string (e.g.
`"250000000"`), no unit label; a raw JSON number is rejected.

### stellar_defindex_vault_deposit arguments

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `chain_id` | string | yes | |
| `vault_address` | string | yes | DeFindex vault C-strkey. |
| `from_address` | string | yes | Wallet smart-account address (C-strkey). |
| `amounts_desired` | array (i128 decimal strings) | yes | One per vault asset, in declaration order. A raw JSON number is rejected. |
| `amounts_min` | array (i128 decimal strings) | yes | Same length; zero = no slippage protection (not defaulted). A raw JSON number is rejected. |
| `invest` | bool | no | Auto-invest after deposit; default `false`. |
| `override_upgradable` | bool | no | Proceed on an upgradable vault; WASM-pin refusal stays non-overridable. |
| `secondary_rpc_url` | string | no | Two-RPC WASM-hash cross-check. |

### stellar_defindex_vault_withdraw arguments

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `chain_id` | string | yes | |
| `vault_address` | string | yes | DeFindex vault C-strkey. |
| `from_address` | string | yes | Wallet smart-account address (C-strkey). |
| `withdraw_shares` | i128 decimal string | yes | Vault shares to redeem. A raw JSON number is rejected. |
| `min_amounts_out` | array (i128 decimal strings) | yes | One per asset in `total_managed_funds` order; zero = no slippage protection (not defaulted). A raw JSON number is rejected. |
| `override_upgradable` | bool | no | |
| `secondary_rpc_url` | string | no | |

### stellar_dex_trade arguments

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `chain_id` | string | yes | |
| `from_address` | string | yes | Wallet smart-account address (C-strkey). |
| `qty_in` | i128 decimal string | yes | Exact input amount, native base units (7-decimal). A raw JSON number is rejected. |
| `qty_out_min` | i128 decimal string | yes | Absolute minimum output (non-negative integer, not a percent). A raw JSON number is rejected. |
| `path` | array (string) | yes | First element input token, last output token; each a C-strkey, `"native"`, or `"CODE:ISSUER"`. |
| `deadline` | integer (u64) | no | Unix seconds; defaults to `now + 300s`. |
| `secondary_rpc_url` | string | no | Two-RPC WASM-hash cross-check. |

### stellar_dex_quote arguments

`chain_id`, `qty_in` (i128 input amount, decimal string; a raw JSON number is
rejected), `path` (same format as `stellar_dex_trade.path`).

Response fields `qty_in`, `expected_out`, and each element of `amounts` are
decimal strings, not JSON numbers.

## SEP-43 (wallet interface)

| Tool | Purpose | Gating |
| --- | --- | --- |
| `stellar_sep43_get_address` | Return the active wallet address. | Read-only. |
| `stellar_sep43_get_network` | Return the active network name and passphrase. | Read-only. |
| `stellar_sep43_sign_transaction` | Sign a `TransactionEnvelope` XDR; return `signedTxXdr` and `signerAddress`. | Signs; no submit. |
| `stellar_sep43_sign_auth_entry` | Sign a `SorobanAuthorizationEntry` XDR for G-key credentials; return `signedAuthEntry` and `signerAddress`. | Signs; no submit. |
| `stellar_sep43_sign_message` | Sign an arbitrary UTF-8 message via `sha256(message)` then ed25519; return `signedMessage` (hex) and `signerAddress`. | Signs; no submit. |
| `stellar_sep43_sign_and_submit_transaction` | Sign a `TransactionEnvelope` XDR, submit, poll until confirmed; return `signedTxXdr`, `txHash`, `status`. | Signs and submits; policy gate. |

Arguments:

- `stellar_sep43_get_address`, `stellar_sep43_get_network`: optional `chain_id`
  only (defaults to profile chain, validated when supplied).
- `stellar_sep43_sign_transaction`, `stellar_sep43_sign_and_submit_transaction`:
  required `chain_id`, required `transaction_xdr` (base64); optional
  `network_passphrase` and optional `address` (G-strkey signer; must match the
  enrolled signer when supplied).
- `stellar_sep43_sign_auth_entry`: required `chain_id`, required `auth_entry_xdr`
  (base64); optional `network_passphrase`, optional `address`.
- `stellar_sep43_sign_message`: required `chain_id`, required `message` (UTF-8
  string); optional `network_passphrase`, optional `address`.

The optional `network_passphrase` is validated as a caller-intent gate
(fail-closed `InvalidNetworkPassphrase` on mismatch); it is not mixed into the
signed bytes.

## SEP-45, SEP-47, SEP-48, SEP-53

| Tool | Purpose | Gating |
| --- | --- | --- |
| `stellar_sep47_discover` | Read the `contractmetav0` `sep` meta entry of a contract and return the SEPs it claims. | Read-only. |
| `stellar_sep48_preview_invocation` | Fetch the on-chain contract spec and render typed argument names and JSON values for an `InvokeHostFunction`, from a transaction XDR or a contract id plus function name. | Read-only. |
| `stellar_sep53_sign_message` | Sign a prefixed message: `SHA-256('Stellar Signed Message:\n' + message)` then ed25519; return base64 signature and signer public key. Not compatible with SEP-43 `signMessage`. | Signs; no submit. |
| `stellar_sep53_verify_message` | Verify a SEP-53 base64 signature against a G-strkey public key and message. | Read-only; no keyring. |

Arguments:

- `stellar_sep47_discover`: required `contract_id` (C-strkey), required
  `chain_id`.
- `stellar_sep48_preview_invocation`: required `chain_id`; either
  `transaction_xdr` (base64, auto-decodes contract/function/args) OR
  `contract_id` plus `function`.
- `stellar_sep53_sign_message`: required `chain_id`, required `message`; optional
  `message_encoding`. Returns `{ signature (base64), signer_public_key (G-strkey),
  message_encoding }`.
- `stellar_sep53_verify_message`: required `chain_id`, `message`, `signature`
  (base64), `public_key` (G-strkey); optional `message_encoding`.

SEP-45 is the contract-account authentication scheme used by the SEP-10/45 JWT
that `stellar_sep24_interactive_url` consumes; it has no standalone tool.

## SEP-6, SEP-7, SEP-24

| Tool | Purpose | Gating |
| --- | --- | --- |
| `stellar_sep6_deposit_info` | SEP-6 anchor capability discovery: `GET /info` only. Returns decoded capabilities including `authentication_required` per asset. Never calls `/deposit`, `/withdraw`, or any KYC endpoint. | Read-only. |
| `stellar_sep7_parse_uri` | Parse an inbound `web+stellar:tx?...` or `web+stellar:pay?...` URI into a structured preview, optionally fetching `stellar.toml` and verifying the ed25519 origin signature. Never auto-signs or auto-POSTs. | Read-only. |
| `stellar_sep24_interactive_url` | SEP-24 interactive deposit/withdraw hand-off: resolve the transfer server, POST the interactive endpoint with a SEP-10/45 JWT, return the interactive URL, transaction id, and a hand-off note. Never opens or scrapes the URL; never transmits KYC fields. | Hand-off; does not sign or submit. |

Arguments:

- `stellar_sep6_deposit_info`: required `chain_id`; one of `anchor_domain` or
  `transfer_server`; optional `asset_code`, optional `lang`.
- `stellar_sep7_parse_uri`: required `chain_id`, required `uri`; `verify_origin`
  (bool).
- `stellar_sep24_interactive_url`:

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `chain_id` | string | yes | |
| `anchor_domain` | string | one of domain/server | Resolve `TRANSFER_SERVER_SEP0024`; mutually exclusive with `transfer_server_sep0024`. |
| `transfer_server_sep0024` | string | one of domain/server | Direct HTTPS URL; mutually exclusive with `anchor_domain`. |
| `operation` | string | yes | `"deposit"` or `"withdraw"`. |
| `asset_code` | string | yes | |
| `asset_issuer` | string | no | G-strkey. |
| `account` | string | no | Classic, contract, or muxed account id. |
| `deposit_hint` | string | no | Pre-fill amount; positive decimal string in `asset_code` units (sent to the anchor as the `amount` form param). |
| `lang` | string | no | RFC 4646. |
| `claimable_balances_ok` | bool | no | Sent to the anchor as `claimable_balance_supported`. |
| `jwt` | string | yes | SEP-10 or SEP-45 Bearer JWT from the anchor web-auth flow. Never logged. |

## x402

| Tool | Purpose | Gating |
| --- | --- | --- |
| `stellar_x402_create_payment` | Construct and sign an x402 v2 Exact Stellar `PAYMENT-SIGNATURE` from a `PaymentRequirements` object; return the payment signature and its fields. | Signs the payment authorization entry; does not submit. |
| `stellar_x402_parse_receipt` | Decode an x402 v2 `PAYMENT-RESPONSE` into a structured settlement receipt. | Read-only; no keyring, no network. No `chain_id`. |
| `stellar_x402_authenticated_payment` | Run a SEP-10 identity gate against a `home_domain` (stellar.toml, SSRF bind, ephemeral challenge/response, JWT), then construct the `PAYMENT-SIGNATURE`. Any identity failure aborts before payment. | Signs the payment authorization entry; does not submit. |

Arguments:

- `stellar_x402_create_payment`: required `payment_required` (base64
  `PAYMENT-REQUIRED` header value OR raw JSON `PaymentRequirements`), required
  `chain_id` (`stellar:pubnet` or `stellar:testnet`); optional `address`
  (G-strkey signer; must match the enrolled signer when supplied).
- `stellar_x402_parse_receipt`: `payment_response` only (base64 / JSON). No
  `chain_id`.
- `stellar_x402_authenticated_payment`: required `payment_required`, required
  `chain_id`, required `home_domain` (the SEP-10 counterparty domain); optional
  `address`.

## Toolsets

| Tool | Purpose | Gating |
| --- | --- | --- |
| `stellar_toolset_list` | Enumerate installed toolsets and their invocable actions. | Read-only. No `chain_id`. |
| `stellar_toolset_invoke` | Invoke a named action of an installed toolset, routed to a registered tool through capability enforcement. | Dispatcher. The toolset signs nothing directly; the routed tool's own policy gate still applies. |

Arguments:

- `stellar_toolset_list`: none (`{}`).
- `stellar_toolset_invoke`: required `toolset` (string), required `action` (string),
  optional `chain_id` (forwarded to the routed tool, which may require it),
  `args` (a JSON object forwarded to the routed tool).

The toolsets dispatcher enforces a toolset's declared capabilities and never reaches
a signing tool directly regardless of those declarations. The routed tool runs
under its normal gate, so the first-invoke gate and per-action approval still
fire.

## Resources

The server exposes three MCP resources; none contains a secret.

- `mcp-resource://usage.md` — tool usage documentation.
- `mcp-resource://profiles/<name>` — non-secret profile metadata (chain id, RPC
  URL, network passphrase, `mcp_disabled`, and the USD threshold).
- `mcp-resource://accounts/<G>` — public account directory for the enrolled
  accounts across all configured profiles.
