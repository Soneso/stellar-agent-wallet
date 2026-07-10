# Protocols (SEP and x402)

The supported Stellar ecosystem protocols, the wallet surface for each, and the deliberate refusals that keep an autonomous agent safe. Every SEP/x402 capability listed here is exposed as an MCP tool on the `stellar-agent-mcp` stdio server. For the wider tool catalog see `./mcp-tools.md`; for keys, signers, and profiles see `./profiles-and-keys.md`.

## Three invariants

- **Privacy-first.** No SEP-9 KYC field is ever transmitted. The audit log records argument key names only, never argument values. Interactive flows are handed back to the operator, never scraped.
- **Fail-closed.** Validation refuses on any failed check rather than guessing. Unknown discriminants, ambiguous tokens, missing floors, and stale reads are refused before signing.
- **Never auto-submit untrusted requests.** Inbound requests (a SEP-7 URI, a contract invocation) are parsed into a preview for the operator and policy engine. The wallet does not sign or submit on a dApp's behalf without the policy engine and approval flow.

Write and signing paths are testnet-only in this alpha. Every signing tool structurally refuses `stellar:mainnet` (wire code `network.mainnet_write_forbidden`) before any RPC call or signing. Read-only tools accept mainnet.

## Result envelope and conventions

- MCP result envelope: `{ ok, data | error, request_id }`. On success `ok` is true and the payload is in `data`; on failure `error` carries a stable wire code.
- `chain_id` is the CAIP-2 chain id (`"stellar:testnet"` or `"stellar:mainnet"`) and is **required** by most tools. SEP-43 `get_address`/`get_network` accept it as optional and fall back to the active profile's chain; the WalletConnect host passes `{}`. (Note: x402 uses the distinct wire-network string `stellar:pubnet` for mainnet in its `network` field; that is not a `chain_id` value.)
- Asset format: `"native"`/`"XLM"`, or `"CODE:GISSUER"`. Amounts are decimal strings with a unit, e.g. `"10 XLM"` — never JSON numbers.
- A `chain_id` that does not match the active profile is rejected by the dispatch gate as a JSON-RPC-level error before any work runs.
- Signing tools are single-shot: if the policy engine returns `RequireApproval`, the tool is fail-closed with wire code `policy.approval_required_unsupported` (message mentions "single-shot") and **no signature is produced**. Two-phase approval is not supported on the single-shot signing tools (the SEP-43 sign verbs and SEP-53 `sign_message`).

## SEP support matrix

| SEP | Spec version | Capability | Tool(s) | Read-only |
|---|---|---|---|---|
| SEP-7 | 0007 | Parse `web+stellar:` URI into a preview; optional fresh-`stellar.toml` origin-signature verify | `stellar_sep7_parse_uri` | yes |
| SEP-10 | 3.4.1 | Client Web Auth (fetch, 13-point validate, submit) → JWT; ephemeral-key flow | used by anchor + x402 flows | — |
| SEP-6 | 0006 | Discovery only — `GET /info` capability set | `stellar_sep6_deposit_info` | yes |
| SEP-24 | 0024 | Interactive deposit/withdraw URL via `POST .../interactive`; returned for browser hand-off | `stellar_sep24_interactive_url` | no (uses JWT) |
| SEP-43 | 1.2.1 | Wallet signing: address/network/sign tx/sign auth entry/sign message/sign+submit | six tools (below) | mixed |
| SEP-45 | 0.1.1 | Client Web Auth for contract (C-) accounts (steps 1–12); ephemeral + persistent-signer | used by anchor flows | — |
| SEP-47 | 0047 | Discover SEPs a contract claims via `contractmetav0` `sep` meta | `stellar_sep47_discover` | yes |
| SEP-48 | 0048 | Typed-argument preview of an `InvokeHostFunction` (display only) | `stellar_sep48_preview_invocation` | yes |
| SEP-53 | 0053 | Sign and verify prefixed off-chain messages | `stellar_sep53_sign_message`, `stellar_sep53_verify_message` | mixed |

## SEP-7 — `web+stellar:` URI parsing

Parses an inbound `web+stellar:tx?...` or `web+stellar:pay?...` URI from an untrusted dApp into a structured preview, and optionally verifies the dApp's origin-domain signature.

Tool `stellar_sep7_parse_uri`:

| Arg | Type | Required | Notes |
|---|---|---|---|
| `chain_id` | string | yes | CAIP-2; e.g. `"stellar:testnet"` |
| `uri` | string | yes | the `web+stellar:` URI |
| `verify_origin` | bool | no (default `true`) | when `true`, fresh `stellar.toml` fetch + ed25519 verify if `origin_domain`+`signature` present; `false` = structural parse, no network I/O |

Preview fields: `operation` (`"tx"`/`"pay"`), parsed operation fields, `callback` (authority host for SSRF inspection), `origin_domain`, `origin_verified`, `signature_status` (`verified`/`failed`/`missing_required`/`absent`), `will_auto_submit` (always `false`), `will_auto_post_callback` (always `false`).

Does NOT: sign a URI; auto-POST to a `callback`; auto-submit. Origin-domain verification always fetches a fresh `stellar.toml` (never cached). SEP-7 carries no nonce/timestamp, so replay protection is the host's responsibility. Parse and verify failures are business errors under the standard envelope with `sep7.*` wire codes (e.g. `sep7.malformed_uri`, `sep7.missing_required_param`, `sep7.invalid_param_value`, `sep7.msg_too_long` [`msg` max 300 chars], `sep7.too_many_chain_levels` [max 7], `sep7.toml_fetch_failed` [URL redacted], `sep7.signing_key_not_in_toml`, `sep7.signature_verification_failed`, `sep7.signature_missing_with_origin_domain`).

## SEP-10 — Stellar Web Authentication

Client-side Web Auth: fetch the challenge transaction, run the 13-point challenge validation, submit the signed challenge to obtain a JWT session. A per-request ephemeral ed25519 key flow is provided. There is no standalone SEP-10 MCP tool; it is consumed internally by the anchor (SEP-24) and the x402 identity gate.

Does NOT: verify the server-issued JWT signature (the JWT is trusted via TLS). Challenge validation is fail-closed on every check. Ephemeral keys are generated fresh per call from the OS RNG and zeroized on drop.

## SEP-6 and SEP-24 — anchor deposit/withdraw

SEP-6 discovery is `GET {transfer_server}/info` only. SEP-24 obtains the anchor's interactive URL via `POST .../transactions/{op}/interactive` using a caller-supplied JWT and returns that URL for browser hand-off.

Tool `stellar_sep6_deposit_info` (read-only):

| Arg | Type | Required | Notes |
|---|---|---|---|
| `chain_id` | string | yes | CAIP-2 |
| `anchor_domain` | string | one of these two | resolve `TRANSFER_SERVER` from `stellar.toml`; takes precedence if both given |
| `transfer_server` | string | one of these two | direct URL; HTTPS + public FQDN required |
| `asset_code` | string | no | passed as `?asset_code=` |
| `lang` | string | no | RFC 4646; default `"en"` |

Tool `stellar_sep24_interactive_url`:

| Arg | Type | Required | Notes |
|---|---|---|---|
| `chain_id` | string | yes | CAIP-2 |
| `anchor_domain` | string | one of these two | resolve `TRANSFER_SERVER_SEP0024`; mutually exclusive with the direct URL |
| `transfer_server_sep0024` | string | one of these two | direct URL; HTTPS required |
| `operation` | string | yes | `"deposit"` or `"withdraw"` |
| `asset_code` | string | yes | Stellar asset code |
| `asset_issuer` | string | no | issuer G-strkey |
| `account` | string | no | classic, contract, or muxed account id |
| `deposit_hint` | decimal string | no | maps to the wire param `amount`; positive decimal in `asset_code` units (e.g. `"100.50"`); rejects negatives, scientific notation, multiple/leading/trailing dots, zero, over-precision |
| `lang` | string | no | RFC 4646 |
| `claimable_balances_ok` | bool | no | sent on the wire as `claimable_balance_supported` |
| `jwt` | string | yes | SEP-10 or SEP-45 Bearer JWT from web-auth; never logged |

Returns: `interactive_url` (HTTPS, anchor-hosted), `transaction_id`, `handoff_note`.

Both tools do NOT: transmit any SEP-9 KYC field — the arg structs have none by design. SEP-6 is structurally incapable of calling `/deposit`, `/withdraw`, `/deposit-exchange`, `/withdraw-exchange`, `/customer` (SEP-12), `/fee`, or `/transaction(s)`. The wallet does not perform SEP-10/45 itself (the caller supplies the opaque JWT) and never opens, scrapes, or follows the interactive URL. Same-domain SSRF bind: the resolved transfer-server host must equal the operator-typed anchor domain or be a subdomain of it; the anchor domain is validated as a public FQDN first.

## SEP-43 — Wallet Protocol (signing)

Agent-side `ModuleInterface` dispatch. Results use the standard `{ ok, data | error, request_id }` envelope like every other tool; the SEP-43 raw protocol payload (`{ address }`, `{ signedTxXdr, signerAddress }`, etc.) is carried inside `data` on success.

| Tool | Method | Read-only | Submits | Returns |
|---|---|---|---|---|
| `stellar_sep43_get_address` | `getAddress` | yes | no | `{ address }` |
| `stellar_sep43_get_network` | `getNetwork` | yes | no | `{ network, networkPassphrase }` |
| `stellar_sep43_sign_transaction` | `signTransaction` | no | no | `{ signedTxXdr, signerAddress }` |
| `stellar_sep43_sign_auth_entry` | `signAuthEntry` | no | no | `{ signedAuthEntry, signerAddress }` |
| `stellar_sep43_sign_message` | `signMessage` | no | no | `{ signedMessage (hex), signerAddress }` |
| `stellar_sep43_sign_and_submit_transaction` | sign + submit | no | yes (destructive) | `{ signedTxXdr, txHash, status }` |

Common signing args: `chain_id` (required), the payload field, optional `network_passphrase` (if provided must equal the profile passphrase exactly; mismatch → `sep43.invalid_network_passphrase`), optional `address` G-strkey (if provided must match the active signer; mismatch → `sep43.invalid_address`).

- `get_address` / `get_network`: `chain_id` is optional (chain-agnostic per spec); when omitted, the profile's chain is used. No keyring access.
- `sign_transaction`: arg `transaction_xdr` (base64 `TransactionEnvelope`). Signs only; the optional SEP-43 `submit`/`submitUrl` opts are NOT implemented here.
- `sign_auth_entry`: arg `auth_entry_xdr` (base64 `SorobanAuthorizationEntry`). Signs the `HashIdPreimage::SorobanAuthorization` preimage with one ed25519 G-key and returns the raw signature; the requester assembles credentials. Entry credentials must be `SorobanCredentials::Address`. No multi-signer quorum. The Protocol-23 `SorobanAuthorizationWithAddress` preimage variant is refused.
- `sign_message`: arg `message` (non-empty UTF-8). Computes `sha256(message_bytes)` with **no prefix** and signs; result `signedMessage` is hex. Optional `network_passphrase` is a caller-intent gate only — it is not mixed into the signed bytes (message signing is network-independent).
- `sign_and_submit_transaction`: arg `transaction_xdr`. Signs, submits via Stellar RPC, and polls until ledger confirmation. `status` is `"success"` (confirmed; `txHash` is a hex64) or `"pending"` (polling window expired before confirmation; `txHash` empty, the tx may still confirm). RPC endpoint/timeout errors strip the URL before surfacing.

SEP-43 wire codes (`error.code` under the standard envelope, from `Sep43Error::wire_code()`):

| Code | Meaning |
|---|---|
| `sep43.wallet_unlock_failed`, `sep43.signer_unavailable`, `sep43.xdr_serialization_failed`, `sep43.keyring_error` | Internal wallet error |
| `sep43.horizon_error`, `sep43.rpc_error` | External service error |
| `sep43.invalid_xdr`, `sep43.invalid_address`, `sep43.invalid_network_passphrase`, `sep43.missing_address`, `sep43.malformed_auth_entry`, `sep43.invalid_message` | Client-invalid request |
| `sep43.user_rejected` | User rejected |

The structural mainnet refusal (sign-only tools, before any key access) carries the canonical `network.mainnet_write_forbidden` code shared with every other signing surface, not a `sep43.*` code.

SEP-43 opens no HTTP/HTTPS connections of its own (interop is stdio via MCP); `sign_and_submit` is the only path that submits, via the profile-configured RPC.

## SEP-45 — Web Authentication for Contract Accounts

Client-side Web Auth for contract (C-) accounts: fetch the challenge, validate the authorization entries, submit the signed challenge to obtain a JWT. Both an ephemeral-key flow and a persistent-signer flow exist. Consumed internally by anchor flows; no standalone tool.

Steps 1 through 12 of the 13-point validation are enforced; step 13 (footprint `read_write` keys) is deferred because it requires simulation results unavailable at challenge-fetch time. Fail-closed on any step. The JWT signature is not verified (trusted via TLS). HTTPS-only at the transport layer. Does not access the keyring or wallet seed (pure decode and validate); the ephemeral path suits only contracts that accept the ephemeral public key or need no client signature.

## SEP-47 — Contract Interface Discovery

Discovers the SEPs a contract claims to implement by reading the `sep` entry of its `contractmetav0` metadata (comma-separated, leading zeros stripped, e.g. `"41,40"`).

Tool `stellar_sep47_discover` (read-only): args `contract_id` (C-strkey, required), `chain_id` (required, resolves the RPC endpoint). Returns `{ supported_seps: ["41", "40"] }`; returns `{ supported_seps: [] }` (not an error) when the contract has no `contractmetav0` section or no `sep` entry. Errors on invalid C-strkey, unreachable RPC, or unfetchable WASM. Submits nothing; modifies no chain state.

## SEP-48 — Contract Interface Specification

Renders a typed-argument preview of an `InvokeHostFunction` against the on-chain contract spec (`contractspecv0`).

Tool `stellar_sep48_preview_invocation` (read-only):

| Arg | Type | Notes |
|---|---|---|
| `transaction_xdr` | string, optional | Mode A: base64 `TransactionEnvelope` with an invoke op; contract/function/args decoded automatically |
| `contract_id` | string, optional | Mode B: C-strkey, used when `transaction_xdr` absent |
| `function` | string, optional | Mode B: function name |
| `chain_id` | string, required | resolves the RPC endpoint |

At least one of `transaction_xdr` or (`contract_id` + `function`) must be supplied; if both, `transaction_xdr` wins. Does NOT submit or modify chain state. Does not validate spec semantics beyond a bounded XDR parse; upstream specs are treated as trusted. The typed preview is non-authoritative display only and does not gate signing.

## SEP-53 — signed messages

Canonical prefixed message sign and verify. Signing computes `SHA-256("Stellar Signed Message:\n" ‖ message)` and ed25519-signs the 32-byte digest, producing a 64-byte signature; verification recomputes the digest and ed25519-verifies it.

Tool `stellar_sep53_sign_message`:

| Arg | Type | Notes |
|---|---|---|
| `chain_id` | string, required | CAIP-2 |
| `message` | string, required | UTF-8 string, or standard base64 when `message_encoding="base64"` |
| `message_encoding` | string, optional | `"utf8"` (default) or `"base64"` |

Returns `{ signature (base64), signer_public_key (G...), message_encoding }`.

Tool `stellar_sep53_verify_message` (read-only): args `chain_id` (required, dispatch-gate compat — verification is chain-agnostic), `message`, `message_encoding` (`"utf8"`/`"base64"`, must match signing), `signature` (standard base64, 64-byte ed25519), `public_key` (G-strkey). Returns `{ valid: true }` or an error envelope on failure.

Distinct from SEP-43 `signMessage`: SEP-53 applies the 24-byte `"Stellar Signed Message:\n"` prefix, SEP-43 does not. The two signatures are incompatible and not interchangeable. SEP-53 is a pure off-chain scheme; it submits no transaction, does not base64-encode the message for you, and caps message length at 64 KiB (65,536 bytes).

## x402 v2 Exact Stellar — agent payments

Payer-side construction and signing of a `PAYMENT-SIGNATURE` payload for the x402 v2 Exact Stellar scheme, wire-compatible with the published `@x402/stellar` package. The wallet is the **payer**; the MCP host performs the actual HTTP request/retry to the facilitator.

`payment_required` may be a base64-encoded `PAYMENT-REQUIRED` header value or a raw JSON `PaymentRequirements` object (the tool tries base64-decode first, then raw JSON). Pass ONE selected `accepts[]` element, not a full 402 envelope. RPC URL and network passphrase always come from the active profile, never from the input.

### `stellar_x402_create_payment`

| Arg | Type | Required | Notes |
|---|---|---|---|
| `payment_required` | string | yes | base64 `PAYMENT-REQUIRED` or raw JSON `PaymentRequirements` |
| `chain_id` | string | yes | CAIP-2; validated against the profile |
| `address` | string | no | signer G-strkey; must match the active signer if given |

Flow: validate → build SAC transfer → simulate → sign auth entry → re-simulate → serialize. Returns `{ paymentSignature, payer, asset, amount, payTo, network }` (`paymentSignature` is the standard-base64 `PAYMENT-SIGNATURE` header value; `asset` is the SAC C-strkey; `amount` is the atomic-unit string from `PaymentRequirements`). Errors carry per-variant codes `x402.<reason>` (for example `x402.invalid_payment_required`, `x402.unsupported_scheme`, `x402.rpc_simulate_failed`) in the standard `{ok:false, error:{code, message}, request_id}` envelope with `is_error` set.

### `stellar_x402_authenticated_payment`

Runs the SEP-10 counterparty-identity gate BEFORE building the payment. Any identity-gate failure aborts before `create_payment` runs — no `PaymentPayload`, no SAC auth entry, no nonce is generated.

| Arg | Type | Required | Notes |
|---|---|---|---|
| `payment_required` | string | yes | as above |
| `chain_id` | string | yes | CAIP-2 |
| `home_domain` | string | yes | operator-supplied domain for SEP-10 identity verification (e.g. `"testanchor.stellar.org"`); the gate resolves its `stellar.toml`, extracts `WEB_AUTH_ENDPOINT` + `SIGNING_KEY`, verifies the SSRF bind, and runs the SEP-10 ephemeral challenge/response |
| `address` | string | no | signer G-strkey; must match the active signer if given |

Returns `{ paymentSignature, authorization, payer, asset, amount, payTo, home_domain, network, payto_anchored }`. `authorization` is the `Bearer <jwt>` value for the HTTP `Authorization:` header. The JWT is an HTTP-layer companion only — the Soroban transaction XDR, the SAC auth entry, and the payment memo are NEVER mutated to carry it. The SEP-10 ephemeral key is unfunded, fresh per call, not persisted, and not the payment funding signer. `payto_anchored` is a display signal (`"anchored"`/`"not_anchored"`/`"unknown"`) of whether `payTo` appears in the verified domain's `stellar.toml` `ACCOUNTS` list; the tool does NOT hard-deny on `"not_anchored"`.

### `stellar_x402_parse_receipt`

Read-only. Arg `payment_response` (base64 `PAYMENT-RESPONSE` header value or raw JSON `SettleResponse`). Returns `{ success, transaction, payer, network, errorReason }` (`payer` and `errorReason` are `null` when absent). No keyring or network access.

### x402 constraints

- Payer/client only — no payee or facilitator logic.
- Stellar only — no EVM or other chains.
- `exact` scheme only — no `upto`.
- Targets x402 v2, not v3.x.
- No HTTP retry loop; the host orchestrates the HTTP exchange. The wallet produces the signed payload (and, for the authenticated variant, the Bearer token); it does not submit.
- `create_payment` validation refuses when `scheme != "exact"`, `network` is not `"stellar:pubnet"`/`"stellar:testnet"`, the x402 `network` passphrase mismatches the profile, `extra.areFeesSponsored != true`, or `amount` cannot be parsed as `i128`.
