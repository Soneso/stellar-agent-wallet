# Protocols and integrations

See [Mainnet configurations and scope](getting-started.md#mainnet-configurations-and-scope)
for build configuration, admitted operations, and exclusions.

This page lists the Stellar ecosystem protocols and venues the wallet speaks, what it does on each, and the deliberate refusals that keep an autonomous agent safe.

Three principles shape every integration:

- **Privacy-first.** The wallet does not transmit KYC fields, does not log argument values (only key names in the [audit log](concepts.md#the-hash-chained-audit-log)), and hands interactive flows back to the operator rather than scraping them.
- **Fail-closed.** Validation refuses on any failed check rather than proceeding on a guess. Unknown discriminants, ambiguous tokens, missing slippage floors, and stale oracle reads are refused before signing.
- **Never auto-submit untrusted requests.** Inbound requests (a SEP-7 URI, a contract invocation) are parsed into a preview for the operator and policy engine. The wallet does not sign or submit on a dApp's behalf without going through the policy engine and [approval spine](concepts.md#the-approval-spine).

The scope table defines mainnet admission for each build configuration. Public SEP-43 and generic SEP-45/53 signing remain excluded. Wallet entry guards use `network.mainnet_write_forbidden`; library refusals retain their namespaced codes. MPP refuses with `mpp.network_forbidden`. The wallet's own signing paths sign mainnet payloads only under mainnet authorization. The library signers enforce it too: every `Signer`, the public keyring handle included, signs a mainnet transaction or Soroban authorization payload only under a mainnet authorization. Code running as the same OS user with access to a keyring entry can read its seed directly. The keyring entry is the custody boundary. Ordinary submission refuses the declared mainnet passphrase or known mainnet host before RPC. In every build, submission verifies each signature under the network the endpoint reports. Authorized submission also requires the bound endpoint, the bound signer's signature, and the bound transaction hash, and records the authorization as consumed before sending.

## SEP protocols

### SEP-7: `web+stellar:` URI parsing

- **Spec:** SEP-7 (`sep-0007.md`).
- **Capability:** Parses an inbound `web+stellar:tx?...` or `web+stellar:pay?...` URI from an untrusted dApp into a structured preview, and optionally verifies the dApp's origin-domain signature.
- **Side:** Client/wallet (receiving side). Surfaced as the `stellar_sep7_parse_uri` MCP tool.
- **Refusals and constraints:**
  - Never signs a URI, never auto-POSTs to a `callback` endpoint, never auto-submits.
  - Origin-domain signature verification always fetches a fresh `stellar.toml`; it is never cached.
  - A URI with any parameter after `signature`, a trailing `&` included, or with a percent-encoded `signature` name, refuses with `sep7.invalid_param_value`; the verified payload therefore covers every parameter the preview shows.
  - Stateless with no replay protection: SEP-7 signatures carry no nonce or timestamp, so idempotency is the operator/host's responsibility.

### SEP-10: Stellar Web Authentication

- **Spec:** SEP-10 version 3.4.1.
- **Capability:** Client-side Web Auth: fetch the challenge transaction, run the full 13-point challenge validation, and submit the signed challenge to obtain a JWT session. A per-request ephemeral ed25519 key flow is also provided.
- **Side:** Client side (obtains a JWT session from an anchor or server).
- **Refusals and constraints:**
  - Challenge validation is fail-closed on every check.
  - The server-issued JWT signature is not verified by the client; the JWT is trusted via TLS.
  - Ephemeral keys are generated fresh per call from the OS RNG and zeroized on drop.
  - Ordinary ephemeral authentication refuses a mainnet passphrase before key generation. Mainnet challenge signing requires the authorized completion used by bound x402 identity authentication.
  - `auth_with_ephemeral_key` refuses mainnet before generating an ephemeral key. The ordinary SEP-10 signing entry refuses a mainnet passphrase with `sep10.mainnet_signing_forbidden`.
  - `sign_challenge_for_test` exists only with the `test-helpers` feature and signs with a caller-supplied key. It refuses mainnet before signing.
  - `prepare_ephemeral_auth` generates the ephemeral key, fetches and validates the challenge, and seals its digest and validated network before authorization. It does not sign the challenge.
  - `web_auth_domain_for_endpoint` derives the web-auth domain from the endpoint's host.
  - In the authorized flow, the challenge must name the ephemeral account before message authorization and again before signing.
  - `complete_ephemeral_auth_authorized` consumes the prepared challenge and checks it against the message-use receipt before signing and submitting it. It exists only in builds with the `mainnet-write` feature.
  - `sep10.mainnet_authorization_refused` reports that the authorized SEP-10 completion refused before submitting a signed challenge.

### SEP-24 and SEP-6: anchor deposit/withdraw

- **Spec:** SEP-6 (discovery) and SEP-24 (interactive).
- **Capability:**
  - SEP-6 discovery is `GET {transfer_server}/info` only: it reads the anchor's capability set and `authentication_required` flags.
  - SEP-24 interactive obtains the anchor's interactive deposit/withdraw URL via `POST .../transactions/{op}/interactive` (using a SEP-10 or SEP-45 JWT supplied by the caller) and returns that URL to the operator for browser hand-off.
- **Side:** Client side, privacy-first. Surfaced as the `stellar_sep6_deposit_info` and `stellar_sep24_interactive_url` MCP tools.
- **Refusals and constraints:**
  - Structurally incapable of calling `/deposit`, `/withdraw`, `/deposit-exchange`, `/withdraw-exchange`, `/customer` (SEP-12), `/fee`, or `/transaction(s)`.
  - Transmits no SEP-9 KYC field.
  - Does not auto-open, scrape, or follow the SEP-24 interactive URL.
  - Does not perform the SEP-10/SEP-45 authentication itself; the caller supplies an opaque JWT string.
  - Same-domain SSRF bind: the resolved `TRANSFER_SERVER*` host must equal the operator-typed anchor domain or be a subdomain of it. The anchor domain is validated as a public FQDN first.

### SEP-43: Wallet Protocol (message and transaction signing)

- **Spec:** SEP-43 version 1.2.1.
- **Capability:** Agent-side `ModuleInterface` dispatch over five methods: `get_address`, `sign_transaction`, `sign_auth_entry`, `sign_message`, `get_network`. Errors use the spec's stable wire codes and `{ code, message, ext? }` JSON shape.
- **Side:** Agent/wallet (signer) side. Surfaced as six MCP tools: one per method (`stellar_sep43_get_address`, `stellar_sep43_sign_transaction`, `stellar_sep43_sign_auth_entry`, `stellar_sep43_sign_message`, `stellar_sep43_get_network`) and `stellar_sep43_sign_and_submit_transaction`, which signs and submits.
- **Refusals and constraints:**
  - Does not implement the optional `submit`/`submitUrl` options of `signTransaction`; `sign_transaction` returns the transaction signed and never submits it. The separate `stellar_sep43_sign_and_submit_transaction` tool submits through the profile's RPC endpoint.
  - No multi-signer quorum. `sign_auth_entry` signs the base64 `HashIdPreimage` of a single-signer authorization entry with one ed25519 G-key and returns the raw signature; the requester assembles the credentials. Both Soroban authorization preimage types are signed for the wallet's own G-key: envelope type 9 (`SorobanAuthorization`) and envelope type 10 (`SorobanAuthorizationWithAddress`, CAP-71). The preimage does not carry the credential arm: a type 10 preimage is signed only when it is bound to the signing key's `ScAddress::Account`, whichever credential type the entry uses, and a preimage bound to any other address is refused with `sep43.invalid_address`. Every other preimage case is refused with `sep43.malformed_auth_entry`.
  - The five-method module opens no HTTP/HTTPS connections; interop is stdio via MCP only.

### SEP-45: Web Authentication for Contract Accounts

- **Spec:** SEP-45 version 0.1.1.
- **Capability:** Client-side Web Auth for contract (C-) accounts: fetch the challenge, validate the authorization entries, and submit the signed challenge to obtain a JWT session. Both an ephemeral-key flow and a persistent-signer flow are provided.
- **Side:** Client side (obtains a SEP-45 JWT session).
- **Refusals and constraints:**
  - Fail-closed on any validation step. Steps 1 through 12 of the 13-point validation are enforced; step 13 (footprint `read_write` keys) is deferred because it requires simulation results unavailable at challenge-fetch time.
  - The JWT signature is not verified; the JWT is trusted via TLS.
  - HTTPS-only floor enforced at the transport layer.
  - Does not access the keyring or wallet seed (pure decode and validate). The ephemeral path suits only contracts that accept the ephemeral public key or need no client signature.

### SEP-47: Contract Interface Discovery

- **Spec:** SEP-47 (Contract Interface Discovery).
- **Capability:** Discovers the SEPs a contract claims to implement by reading the `sep` entry of its `contractmetav0` metadata.
- **Side:** Agent/wallet (read side). Surfaced as the `stellar_sep47_discover` MCP tool. Shipped together with SEP-48.
- **Refusals and constraints:** Read-only discovery; submits nothing and modifies no chain state.

### SEP-48: Contract Interface Specification

- **Spec:** SEP-48 (Contract Interface Specification).
- **Capability:** Renders a typed-argument preview of an `InvokeHostFunction` XDR against the on-chain contract spec.
- **Side:** Agent/wallet (read/preview side). Surfaced as the `stellar_sep48_preview_invocation` MCP tool.
- **Refusals and constraints:**
  - Does not submit transactions or modify chain state.
  - Does not validate spec semantics beyond a bounded XDR parse; upstream contract specs are treated as trusted.
  - The typed preview is non-authoritative display only and does not gate signing.

### SEP-53: message signing

- **Spec:** SEP-53 (`sep-0053.md`).
- **Capability:** Canonical prefixed message sign and verify. Signing computes `SHA-256("Stellar Signed Message:\n" ‖ message)` and ed25519-signs the 32-byte digest, producing a 64-byte signature; verification recomputes the digest and ed25519-verifies it.
- **Side:** Both signing and verification. Surfaced as the `stellar_sep53_sign_message` and `stellar_sep53_verify_message` MCP tools.
- **Refusals and constraints:**
  - Pure off-chain scheme; submits no transaction.
  - Does not base64-encode the message; that is the caller's responsibility.
  - Message length is capped at 64 KiB (65,536 bytes); larger messages are refused.

## Agent payments (x402)

### x402 v2 Exact Stellar: payer side

- **Spec:** x402 v2 wire format, Exact Stellar scheme; wire-compatible with the published `@x402/stellar` package.
- **Capability:** Payer-side construction and signing of a `PAYMENT-SIGNATURE` payload through a validate, identify, build, simulate, cross-check, sign, re-simulate, finalize flow. In a feature-enabled build, mainnet payments use an approved intent for signing and a separate authorization for payload release. Authenticated payments first consume a bound SEP-10 message authorization.
- **Side:** Payer/client only.
- **Refusals and constraints:**
  - Payer-only; no payee or facilitator logic.
  - Stellar only, no EVM or other chains.
  - The `exact` scheme only, no `upto`.
  - No HTTP retry loop; the host orchestrates the HTTP exchange.
  - Targets x402 v2, not v3.x.
  - Before signing, the first simulation must return exactly one authorization entry. It carries legacy `Address` credentials for the payer, a zero expiration ledger, and no signature.
  - That entry's root invocation must equal the SAC `transfer` the wallet built, contract and every argument included, with no nested calls. Any other answer refuses before signing.
  - The signed re-simulation must return a decodable result whose authorization entries are empty or equal to the signed entry. Any other answer refuses, and no payment payload is returned.
  - The requirements are validated before any request. Requirement validation checks the scheme, network, profile passphrase, asset, sponsorship, amount, recipient, and timeout. It requires a C-strkey asset, a strict `areFeesSponsored: true`, a positive amount, a G-, C-, or M-strkey `payTo`, and a `maxTimeoutSeconds` of at least one.
  - The authorized path validates these fields without refusing the mainnet network itself. The ordinary entry `validate_requirements` refuses a mainnet passphrase or a mainnet-pattern endpoint before any request.
  - Header fields named in an error are escaped and cut at 200 characters. A header that does not decode reports the JSON error class and position, not its values.
  - Every request of one payment goes to the primary client built from the operator's profile. Its first request is `getNetwork`. The authorized path checks that the configured endpoint serves mainnet before its first simulation. The ordinary path retains its endpoint network restrictions: an endpoint serving another network, reporting mainnet, or not identified before the caller's deadline refuses with its `network.*` code before any simulation.
  - The first simulation must hold exactly one result. When the amount reaches the asset's cross-check threshold and the profile names an oracle, the oracle simulates the same unsigned transfer before the payer signs. Its answer must hold the same authorization entries apart from the nonce and the expiration. Its `minResourceFee` lies between 1 and 10,000,000 stroops. Its ledger trails the primary's by at most two and lies before the expiration ledger. A disagreement refuses with `simulation.divergence`. The results carry `cross_check`, and the `x402_payment_authorized` audit row carries a passed witness when the payment required one. In a feature-enabled build, mainnet witness thresholds combine the signed policy and profile. A required witness compares the oracle's unsigned simulation before the payer signs.
  - `maxTimeoutSeconds` is clamped to 300 seconds as input; the requirement names a maximum, so a shorter validity meets it. With the five-second ledger estimate, the clamped value gives a window of `ceil(min(t, 300) / 5)` ledgers, from 1 to 60. The window counts ledger advances, not a guaranteed wall-clock lifetime.
  - The expiration ledger is the unsigned simulation's latest ledger plus the window; an overflow refuses. A `getHealth` read on the same endpoint must report `healthy`.
  - The unsigned simulation's ledger is above zero and at most one ledger ahead of the health ledger. The re-simulation's ledger is at most one ledger behind the health ledger. The health and re-simulation ledgers lie before the expiration ledger.
  - A `maxTimeoutSeconds` of five seconds or less gives a one-ledger window. Such a payment refuses when the endpoint's ledger advances between the simulation and the health read or the re-simulation.
  - These ledger checks compare answers of the primary endpoint. They bound the signed window at sixty ledger advances plus one ledger of skew between load-balanced backends. The oracle's ledger is the independent evidence that the primary's ledger is current. On mainnet the oracle provides it for every payment. At or above the threshold, its simulation carries it. Below the threshold, the oracle answers `getNetwork` and then `getLatestLedger`, under the same two bounds. A mainnet profile without `oracle_provider_url` refuses every x402 payment with `network.witness_unavailable` before the payer signs. On testnet the oracle provides it only when the witness is required.
  - Both simulations' `minResourceFee` lies between 1 and 10,000,000 stroops, and the resource fee their transaction data embeds lies between zero and that minimum. The ceiling is a local sanity bound, separate from any facilitator fee policy.
  - A restore preamble in either simulation refuses, and so do archived entries in either simulation's transaction data, which mark a restoration inside the simulation. On this path they come from an archived asset contract instance or the archived balance of a contract-address recipient.
  - The wallet has no restore path, and a restoration made elsewhere unblocks the payment. The reference client checks only the restore preamble; refusing the in-simulation restoration as well is an intentional difference.
  - The nonce, the resource data, and the fee still come from the configured RPC; the oracle's answer is compared, never signed or used.

### x402 SEP-10 counterparty-identity gate

- **Spec:** SEP-10 identity gate layered onto x402 v2 Exact Stellar.
- **Capability:** Wallet-side pre-payment identity gate. Before building a payment, it resolves the server's identity via SEP-10, verifies the challenge, and returns the JWT Bearer token the server issued over TLS. The wallet parses the JWT's claims but does not verify its signature. Surfaced as the `stellar_x402_authenticated_payment` MCP tool.
- **Side:** Payer/client only.
- **Refusals and constraints:**
  - The identity is bound only as an HTTP-layer companion (`Authorization: Bearer <jwt>`). The Soroban transaction XDR, the SAC auth-entry, and the payment memo are never mutated to carry the JWT.
  - The ephemeral SEP-10 key is unfunded and is not the payment funding signer.
  - No SEP-45, no payee or facilitator logic, no caching or session reuse (a fresh ephemeral key per call), no on-chain submission.
  - A refused challenge or token answer reports the HTTP method, the status, and the web-auth endpoint's host. The wallet does not read the answer body.
  - A stellar.toml syntax error reports its line and column.
  - The token must be a compact JWT of at most 8192 bytes, with base64url characters in every segment. Any other token refuses.
  - A mismatched SEP-10 challenge passphrase is reported as the public testnet or mainnet passphrase, or `<other network>`, including for multibyte input.
  - On an admitted mainnet server, one approval binds the payment intent and home domain. Call 2 prepares and validates the SEP-10 challenge, consumes its message authorization, and completes authentication before building the payment.
  - `resolve_and_verify_counterparty` and its transport seam, which exists only with the `test-helpers` feature, refuse mainnet before fetching `stellar.toml`. An ordinary x402 identity entry reports `identity.mainnet_signing_forbidden` before any request.
  - `resolve_and_verify_counterparty_authorized` takes `MainnetIdentityInputs` and returns `MainnetCounterpartySession`. Its `into_parts` method transfers the session and receipt to the payment caller.
  - `identity.mainnet_authorization_refused` reports that the bound identity authentication refused before submitting a signed challenge.
  - The authorized gate, `MainnetIdentityInputs`, and `MainnetCounterpartySession` exist only in builds with the `mainnet-write` feature.

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

Each DeFi venue is a signing adapter behind a common interface. They share a posture: no raw-vector or opaque-calldata signing, a venue/WASM pin verified before any signing, and predicted post-op figures shown for display only, never as a signing gate. See [DeFi and pool commands](cli-reference/defi-and-pool.md) for the CLI surface.

### Blend: removed

The Blend lending integration was removed after the August 2026 incident in
which the Comet pool holding Blend's backstop insurance capital was drained.
The wallet's lending verb depended on that backstop for depositor protection,
so the integration does not ship while the protocol's insurance layer is
unavailable. Existing published `stellar-agent-blend` crate versions remain on
crates.io; no new versions are published. Re-integration would require a
published post-mortem, a backstop rebuilt on an audited AMM, and a fresh
integration review of the rebuilt protocol.

### Soroswap: trade (`trade`, `stellar_dex_quote`)

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

### DeFindex: vault (`vault`)

- **Protocol:** DeFindex vault.
- **Capability:** Typed deposit and withdraw preview and submit, with four-role disclosure (Manager, EmergencyManager, RebalanceManager, VaultFeeReceiver), self-managed versus delegated detection, and Blend-strategy detection by WASM hash. The `vault` verb is dispatched through MCP and the CLI.
- **Refusals and constraints:**
  - No raw-vector or opaque-calldata signing; `min_out` is required, and its absence is a structural pre-sign refusal.
  - Per-network WASM pins.
  - The ordered trust gate refuses an `Upgradable:true` vault by default; an opt-in override emits a distinct audit event. A self-managed vault, whose depositor controls every fund-affecting role, is exempt.
  - Flash-loan, zapper, and `rebalance` are out of scope.

## Support matrix

| Protocol | What is supported | Surface |
|---|---|---|
| SEP-7 | Parse inbound `web+stellar:` URI into a preview; optional fresh-`stellar.toml` origin-signature verify; never signs or submits | MCP |
| SEP-10 | Client Web Auth (fetch, 13-point validate, submit) with an ephemeral key; authorized mainnet completion for bound x402 identity authentication | (used by the x402 identity gate; anchor tools take a caller-supplied JWT) |
| SEP-6 | Discovery only, `GET /info` capability set | MCP |
| SEP-24 | Interactive deposit/withdraw URL via `POST .../interactive`; returned to operator, never followed | MCP |
| SEP-43 | Agent `ModuleInterface`: `get_address`, `sign_transaction`, `sign_auth_entry`, `sign_message`, `get_network`, none of which submits; plus `stellar_sep43_sign_and_submit_transaction`, which signs and submits | MCP |
| SEP-45 | Client Web Auth for contract accounts (steps 1 to 12); ephemeral and persistent-signer flows | no workspace consumer; refuses mainnet signing |
| SEP-47 | Discover SEPs a contract claims via `contractmetav0` | MCP |
| SEP-48 | Typed-argument preview of `InvokeHostFunction` (display-only, does not gate signing) | MCP |
| SEP-53 | Sign and verify prefixed off-chain messages | MCP |
| x402 v2 Exact Stellar | Payer-side payment construction, authorized mainnet signing, and authorized payload release (Stellar-only, `exact`-only) | MCP |
| x402 identity gate | Bound SEP-10 authentication for an approved x402 payment; returns a Bearer JWT companion outside the payment XDR | MCP |
| MPP sponsored Stellar charge | Testnet G-account payer authorization; returns one HTTP/native-MCP credential, records a host receipt, and independently reconciles settlement | CLI, MCP |
| Blend | removed (see above) | n/a |
| Soroswap | `trade` (signing, CLI + MCP) and the read-only `stellar_dex_quote` (MCP only); absolute slippage floor, pre-sign re-verify, WASM-pinned | CLI, MCP |
| DeFindex | `vault` deposit/withdraw; `min_out` required, role disclosure, `Upgradable:true` refused by default unless self-managed | CLI, MCP |

## Related pages

- [Stellar operations CLI reference](cli-reference/stellar-ops.md): core on-chain commands.
- [DeFi and pool commands](cli-reference/defi-and-pool.md): `trade`, `vault`, and channel-account pool commands.
- [MCP server](mcp.md): the `stellar-agent-mcp` stdio server and its tool catalog.
- [Toolsets](toolsets.md): how toolset-routed capabilities reach signing-adjacent tools under the first-invoke gate and per-action approval.
