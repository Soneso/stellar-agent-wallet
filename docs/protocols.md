# Protocols and integrations

This page lists the Stellar ecosystem protocols and venues the wallet speaks, what it does on each, and the deliberate refusals that keep an autonomous agent safe.

Three principles shape every integration:

- **Privacy-first.** The wallet does not transmit KYC fields, does not log argument values (only key names in the [audit log](concepts.md#the-hash-chained-audit-log)), and hands interactive flows back to the operator rather than scraping them.
- **Fail-closed.** Validation refuses on any failed check rather than proceeding on a guess. Unknown discriminants, ambiguous tokens, missing slippage floors, and stale oracle reads are refused before signing.
- **Never auto-submit untrusted requests.** Inbound requests (a SEP-7 URI, a contract invocation) are parsed into a preview for the operator and policy engine. The wallet does not sign or submit on a dApp's behalf without going through the policy engine and [approval spine](concepts.md#the-approval-spine).

All write and signing paths are testnet-only in this alpha: every signing command structurally refuses `stellar:mainnet` (wire code `network.mainnet_write_forbidden`) before any RPC call or signing. Read-only commands accept mainnet.

## SEP protocols

### SEP-7 — `web+stellar:` URI parsing

- **Spec:** SEP-7 (`sep-0007.md`).
- **Capability:** Parses an inbound `web+stellar:tx?...` or `web+stellar:pay?...` URI from an untrusted dApp into a structured preview, and optionally verifies the dApp's origin-domain signature.
- **Side:** Client/wallet (receiving side). Surfaced as the `stellar_sep7_parse_uri` MCP tool.
- **Refusals and constraints:**
  - Never signs a URI, never auto-POSTs to a `callback` endpoint, never auto-submits.
  - Origin-domain signature verification always fetches a fresh `stellar.toml`; it is never cached.
  - Stateless with no replay protection: SEP-7 signatures carry no nonce or timestamp, so idempotency is the operator/host's responsibility.

### SEP-10 — Stellar Web Authentication

- **Spec:** SEP-10 version 3.4.1.
- **Capability:** Client-side Web Auth: fetch the challenge transaction, run the full 13-point challenge validation, and submit the signed challenge to obtain a JWT session. A per-request ephemeral ed25519 key flow is also provided.
- **Side:** Client side (obtains a JWT session from an anchor or server).
- **Refusals and constraints:**
  - Challenge validation is fail-closed on every check.
  - The server-issued JWT signature is not verified by the client; the JWT is trusted via TLS.
  - Ephemeral keys are generated fresh per call from the OS RNG and zeroized on drop.

### SEP-24 and SEP-6 — anchor deposit/withdraw

- **Spec:** SEP-6 (discovery) and SEP-24 (interactive).
- **Capability:**
  - SEP-6 discovery is `GET {transfer_server}/info` only — it reads the anchor's capability set and `authentication_required` flags.
  - SEP-24 interactive obtains the anchor's interactive deposit/withdraw URL via `POST .../transactions/{op}/interactive` (using a SEP-10 or SEP-45 JWT supplied by the caller) and returns that URL to the operator for browser hand-off.
- **Side:** Client side, privacy-first. Surfaced as the `stellar_sep6_deposit_info` and `stellar_sep24_interactive_url` MCP tools.
- **Refusals and constraints:**
  - Structurally incapable of calling `/deposit`, `/withdraw`, `/deposit-exchange`, `/withdraw-exchange`, `/customer` (SEP-12), `/fee`, or `/transaction(s)`.
  - Transmits no SEP-9 KYC field.
  - Does not auto-open, scrape, or follow the SEP-24 interactive URL.
  - Does not perform the SEP-10/SEP-45 authentication itself; the caller supplies an opaque JWT string.
  - Same-domain SSRF bind: the resolved `TRANSFER_SERVER*` host must equal the operator-typed anchor domain or be a subdomain of it. The anchor domain is validated as a public FQDN first.

### SEP-43 — Wallet Protocol (message and transaction signing)

- **Spec:** SEP-43 version 1.2.1.
- **Capability:** Agent-side `ModuleInterface` dispatch over five methods: `get_address`, `sign_transaction`, `sign_auth_entry`, `sign_message`, `get_network`. Errors use the spec's stable wire codes and `{ code, message, ext? }` JSON shape.
- **Side:** Agent/wallet (signer) side. Surfaced as five MCP tools (`stellar_sep43_get_address`, `stellar_sep43_sign_transaction`, `stellar_sep43_sign_auth_entry`, `stellar_sep43_sign_message`, `stellar_sep43_get_network`).
- **Refusals and constraints:**
  - Does not implement the optional `submit`/`submitUrl` options of `signTransaction`; transactions are returned signed, never submitted.
  - No multi-signer quorum. `sign_auth_entry` signs a single-signer `HashIdPreimage::SorobanAuthorization` preimage with one ed25519 G-key and returns the raw signature; the requester assembles the credentials.
  - The Protocol-23 `SorobanAuthorizationWithAddress` preimage variant is refused.
  - Opens no HTTP/HTTPS connections; interop is stdio via MCP only.

### SEP-45 — Web Authentication for Contract Accounts

- **Spec:** SEP-45 version 0.1.1.
- **Capability:** Client-side Web Auth for contract (C-) accounts: fetch the challenge, validate the authorization entries, and submit the signed challenge to obtain a JWT session. Both an ephemeral-key flow and a persistent-signer flow are provided.
- **Side:** Client side (obtains a SEP-45 JWT session).
- **Refusals and constraints:**
  - Fail-closed on any validation step. Steps 1 through 12 of the 13-point validation are enforced; step 13 (footprint `read_write` keys) is deferred because it requires simulation results unavailable at challenge-fetch time.
  - The JWT signature is not verified; the JWT is trusted via TLS.
  - HTTPS-only floor enforced at the transport layer.
  - Does not access the keyring or wallet seed (pure decode and validate). The ephemeral path suits only contracts that accept the ephemeral public key or need no client signature.

### SEP-47 — Contract Interface Discovery

- **Spec:** SEP-47 (Contract Interface Discovery).
- **Capability:** Discovers the SEPs a contract claims to implement by reading the `sep` entry of its `contractmetav0` metadata.
- **Side:** Agent/wallet (read side). Surfaced as the `stellar_sep47_discover` MCP tool. Shipped together with SEP-48.
- **Refusals and constraints:** Read-only discovery; submits nothing and modifies no chain state.

### SEP-48 — Contract Interface Specification

- **Spec:** SEP-48 (Contract Interface Specification).
- **Capability:** Renders a typed-argument preview of an `InvokeHostFunction` XDR against the on-chain contract spec.
- **Side:** Agent/wallet (read/preview side). Surfaced as the `stellar_sep48_preview_invocation` MCP tool.
- **Refusals and constraints:**
  - Does not submit transactions or modify chain state.
  - Does not validate spec semantics beyond a bounded XDR parse; upstream contract specs are treated as trusted.
  - The typed preview is non-authoritative display only and does not gate signing.

### SEP-53 — message signing

- **Spec:** SEP-53 (`sep-0053.md`).
- **Capability:** Canonical prefixed message sign and verify. Signing computes `SHA-256("Stellar Signed Message:\n" ‖ message)` and ed25519-signs the 32-byte digest, producing a 64-byte signature; verification recomputes the digest and ed25519-verifies it.
- **Side:** Both signing and verification. Surfaced as the `stellar_sep53_sign_message` and `stellar_sep53_verify_message` MCP tools.
- **Refusals and constraints:**
  - Pure off-chain scheme; submits no transaction.
  - Does not base64-encode the message; that is the caller's responsibility.
  - Message length is capped at 64 KiB (65,536 bytes); larger messages are refused.

## Agent payments (x402)

### x402 v2 Exact Stellar — payer side

- **Spec:** x402 v2 wire format, Exact Stellar scheme; wire-compatible with the published `@x402/stellar` package.
- **Capability:** Payer-side construction and signing of a `PAYMENT-SIGNATURE` payload through a validate, build, simulate, sign, re-simulate, finalize flow.
- **Side:** Payer/client only.
- **Refusals and constraints:**
  - Payer-only; no payee or facilitator logic.
  - Stellar only — no EVM or other chains.
  - The `exact` scheme only — no `upto`.
  - No HTTP retry loop; the host orchestrates the HTTP exchange.
  - Targets x402 v2, not v3.x.

### x402 SEP-10 counterparty-identity gate

- **Spec:** SEP-10 identity gate layered onto x402 v2 Exact Stellar.
- **Capability:** Wallet-side pre-payment identity gate. Before building a payment, it resolves the server's identity via SEP-10 and returns a verified JWT Bearer token to accompany the payment. Surfaced as the `stellar_x402_authenticated_payment` MCP tool.
- **Side:** Payer/client only.
- **Refusals and constraints:**
  - The identity is bound only as an HTTP-layer companion (`Authorization: Bearer <jwt>`). The Soroban transaction XDR, the SAC auth-entry, and the payment memo are never mutated to carry the JWT.
  - The ephemeral SEP-10 key is unfunded and is not the payment funding signer.
  - No SEP-45, no payee or facilitator logic, no caching or session reuse (a fresh ephemeral key per call), no on-chain submission.

## Machine Payments Protocol (MPP)

- **Protocol pins:** MPP HTTP/native-MCP payment challenge and credential shapes
  validated against the released `@stellar/mpp` 0.7.1 SDK behavior; Stellar
  settlement uses SEP-41 transfer semantics and SEP-43 authorization signing.
- **Capability:** Payer-side, testnet-only sponsored `charge` authorization for
  one classic G-account. The wallet binds the challenge to the exact HTTP or MCP
  request context, simulates, evaluates value policy, optionally obtains a
  dedicated approval, signs once, re-simulates, and returns a credential.
- **Surfaces:** `stellar-agent mpp ...` and five `stellar_mpp_*` MCP tools.
- **Boundary:** The wallet does not send the paid request or submit the
  transaction. The trusted host protects and delivers the credential, records
  any receipt, and invokes reconciliation when ledger proof is required.
- **Unsupported:** mainnet, unsponsored and push payment modes, smart-account
  payers, automatic transport, channels, and toolset routing.

MPP and x402 are separate wire protocols. x402 returns an x402 v2
`PAYMENT-SIGNATURE`; MPP returns an HTTP `Payment` or native MCP credential bound
to a Payment challenge. See [Agent payments with MPP](agent-payments.md).

## DeFi venues

Each DeFi venue is a signing adapter behind a common interface. They share a posture: no raw-vector or opaque-calldata signing, a venue/WASM pin verified before any signing, and predicted post-op figures shown for display only — never as a signing gate. See [DeFi and pool commands](cli-reference/defi-and-pool.md) for the CLI surface.

### Blend — lending (`lend`)

- **Protocol:** Blend lending, v1 and v2.
- **Capability:** Typed lend preview and submit over a typed request vector. The `lend` verb is dispatched through MCP and the CLI.
- **Refusals and constraints:**
  - No raw-vector or opaque-calldata signing; unknown request discriminants are refused before signing.
  - The pool WASM is verified against a version-pinned hash set before any oracle read or signing.
  - Simulate-authoritative, fail-closed health guard. The predicted post-op health factor is display-only and never gates signing.
  - Oracle allowlist is Reflector-only. Oracle staleness is bounded (600s default); a per-invocation override emits a distinct audit event.
  - The `liquidate` verb is deferred; flash-loan and `submit_with_allowance` (v2-only) are out of scope.

### Soroswap — trade (`trade`, `stellar_dex_quote`)

- **Protocol:** Soroswap router-direct swap.
- **Capability:** Real on-chain swap with an absolute `amount_out_min`, plus a read-only quote. The `trade` (signing) verb is dispatched through both MCP and the CLI. The read-only quote is the MCP `stellar_dex_quote` tool; the CLI has no separate `quote` subcommand, so CLI price discovery happens inside `trade` via the on-chain `router_get_amounts_out` re-check at signing time.
- **Refusals and constraints:**
  - Slippage must be an absolute floor (`amount_out_min`). A percent-string slippage is refused, fail-closed.
  - An on-chain `router_get_amounts_out` re-fetch runs immediately before signing; an absent quote or a quote below the absolute floor refuses the swap. This re-check is a front-run floor using the same routine the swap uses, not an independent price oracle.
  - Token inputs are SEP-41/SAC canonicalised; ambiguous inputs (bare code, non-canonicalising code+issuer) are refused before signing.
  - The swap deadline is a bounded Unix timestamp (default now+300s); a missing, zero, or excessively-far deadline is refused.
  - The swap path is an explicit address vector; it is never auto-routed.
  - Soroswap is the only wired venue; routes through an un-allowlisted venue are refused, and the router WASM pin is verified first.
  - The Soroswap aggregator, Aquarius/Phoenix execution, classic SDEX limit orders (`CreatePassiveSellOffer`), and oracle price-deviation checks are out of scope.

### DeFindex — vault (`vault`)

- **Protocol:** DeFindex vault.
- **Capability:** Typed deposit and withdraw preview and submit, with four-role disclosure (Manager, EmergencyManager, RebalanceManager, VaultFeeReceiver), self-managed versus delegated detection, and Blend-strategy detection by WASM hash. The `vault` verb is dispatched through MCP and the CLI.
- **Refusals and constraints:**
  - No raw-vector or opaque-calldata signing; `min_out` is required, and its absence is a structural pre-sign refusal.
  - Per-network WASM pins.
  - The ordered trust gate refuses by default when the vault is `Upgradable:true`; an opt-in override emits a distinct audit event.
  - Flash-loan, zapper, and `rebalance` are out of scope.

## Support matrix

| Protocol | What is supported | Surface |
|---|---|---|
| SEP-7 | Parse inbound `web+stellar:` URI into a preview; optional fresh-`stellar.toml` origin-signature verify; never signs or submits | MCP |
| SEP-10 | Client Web Auth (fetch, 13-point validate, submit) to obtain a JWT; ephemeral-key flow | (used by anchor and x402 flows) |
| SEP-6 | Discovery only — `GET /info` capability set | MCP |
| SEP-24 | Interactive deposit/withdraw URL via `POST .../interactive`; returned to operator, never followed | MCP |
| SEP-43 | Agent `ModuleInterface`: `get_address`, `sign_transaction`, `sign_auth_entry`, `sign_message`, `get_network`; never submits | MCP |
| SEP-45 | Client Web Auth for contract accounts (steps 1–12); ephemeral and persistent-signer flows | (used by anchor flows) |
| SEP-47 | Discover SEPs a contract claims via `contractmetav0` | MCP |
| SEP-48 | Typed-argument preview of `InvokeHostFunction` (display-only, does not gate signing) | MCP |
| SEP-53 | Sign and verify prefixed off-chain messages | MCP |
| x402 v2 Exact Stellar | Payer-side `PAYMENT-SIGNATURE` construction and signing (Stellar-only, `exact`-only) | MCP |
| x402 identity gate | SEP-10 counterparty-identity gate returning a Bearer JWT companion (never in the XDR) | MCP |
| MPP sponsored Stellar charge | Testnet G-account payer authorization; returns one HTTP/native-MCP credential, records a host receipt, and independently reconciles settlement | CLI, MCP |
| Blend | `lend` preview and submit; Reflector-only oracle, WASM-pinned, fail-closed health guard | CLI, MCP |
| Soroswap | `trade` (signing, CLI + MCP) and the read-only `stellar_dex_quote` (MCP only); absolute slippage floor, pre-sign re-verify, WASM-pinned | CLI, MCP |
| DeFindex | `vault` deposit/withdraw; `min_out` required, role disclosure, `Upgradable:true` refused by default | CLI, MCP |

## Related pages

- [Stellar operations CLI reference](cli-reference/stellar-ops.md) — core on-chain commands.
- [DeFi and pool commands](cli-reference/defi-and-pool.md) — `lend`, `trade`, `vault`, and channel-account pool commands.
- [MCP server](mcp.md) — the `stellar-agent-mcp` stdio server and its tool catalog.
- [Toolsets](toolsets.md) — how toolset-routed capabilities reach signing-adjacent tools under the first-invoke gate and per-action approval.
