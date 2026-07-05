# The MCP server

`stellar-agent-mcp` is a [Model Context Protocol](https://modelcontextprotocol.io)
server that exposes the Stellar Agent Wallet to an MCP client. It speaks
JSON-RPC over stdio and presents wallet capabilities as MCP tools, so an AI
assistant can read account state and submit Stellar transactions through the
same policy engine, operator-approval spine, and tamper-evident audit log that
back the `stellar-agent` CLI.

A tool call is gated exactly as the equivalent CLI command is. The policy
engine evaluates every call to `Allow`, `Deny`, or `RequireApproval`; signing
verbs route through the approval spine; and the mainnet-write gate refuses every
write on `stellar:mainnet`. See [Concepts](./concepts.md) for the shared
guardrail model.

## What it is

- One process: the `stellar-agent-mcp` binary, built from the
  `stellar-agent-mcp` crate.
- Transport: MCP JSON-RPC over stdio. The client spawns the binary as a
  subprocess and exchanges newline-delimited JSON-RPC on the subprocess
  stdin/stdout.
- Protocol version: `2024-11-05`. Declared capabilities: `tools` and
  `resources`.
- Server identity reported at initialize: name `stellar-agent-mcp`, version
  matching the crate's package version (`0.1.0-alpha.1` as of this release).

`stdout` is reserved for the JSON-RPC wire. Structured logs go to `stderr`, and
they pass through a redaction layer before they are written, so a client that
captures `stderr` receives already-redacted output. Mixing log lines into
`stdout` would corrupt the protocol stream, which is why the split is strict.

The transport enforces a 1 MiB maximum line length on inbound and outbound
JSON-RPC frames. Frames longer than that are rejected.

This alpha does not offer an HTTP or SSE transport. stdio is the only transport.

### Availability

This is a public alpha. Build `stellar-agent-mcp` from source, or install a
prebuilt binary from the `v0.1.0-alpha.1` release once it is tagged. See
[the CLI reference](./cli-reference/) and the repository README for build
instructions; the build that produces `stellar-agent` produces
`stellar-agent-mcp` alongside it.

## Launching the server

The server is started by running the binary. It takes no command-line
arguments; configuration comes from the active profile.

```bash
stellar-agent-mcp
```

On startup the process, in order:

1. Applies process-isolation hardening on Linux (`PR_SET_DUMPABLE 0`,
   `PR_SET_NO_NEW_PRIVS 1`). On macOS and Windows it relies on the platform
   keyring's per-application access model and operator policy instead.
2. Installs the redacting log subscriber on `stderr`.
3. Initialises the platform keyring store. If the platform has no supported
   keyring backend, the process exits non-zero with a diagnostic.
4. Loads the active profile. A `--profile` flag is not wired; the server loads
   the default profile, or synthesises a testnet fallback profile if no profile
   file exists yet (the first-run case).
5. Refuses to start if the active profile sets `mcp_disabled = true` (the
   operator kill-switch), exiting non-zero with `mcp.disabled_per_profile`.
6. Serves the MCP loop until the client disconnects.

You normally do not launch `stellar-agent-mcp` by hand. The MCP client spawns
it. The command above is what the client is configured to run.

### How a profile selects the signer and keys

The wallet holds no secrets in its config. A [profile](./profiles.md) is a
per-environment TOML file (schema version 2) that binds a CAIP-2 chain id, an
RPC endpoint, keyring entry references, thresholds, and the active policy
engine. Each keyring entry reference is a service-plus-account pair naming a
secret held in the platform keyring; it is never the secret itself.

The loaded profile therefore determines:

- which network the server operates on (`stellar:testnet` by default;
  `stellar:mainnet` is accepted for read-only tools but structurally refuses
  every write before any RPC call or signing);
- which keyring entries the signing tools resolve their seed from;
- which policy engine evaluates each tool call.

The synthesised testnet fallback profile carries placeholder keyring
coordinates. Read-only tools and the simulate step of the two-phase signing
verbs work under it, but any tool that touches the signer keyring returns a
keyring-not-found error until a profile that names a populated signer keyring
entry is in place.

The profile field `mcp_disabled` is a per-profile kill-switch. When `true`, the
server refuses to start, exiting non-zero with `mcp.disabled_per_profile`. The
flag is also surfaced as non-secret metadata on the
`mcp-resource://profiles/<name>` resource so a client can read whether the MCP
surface is enabled for that profile.

## Configuring an MCP client

Most MCP clients are configured with a JSON stanza that names a command to spawn
and its arguments. Point the command at the `stellar-agent-mcp` binary. A
generic stanza:

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

Notes:

- Use an absolute path to the binary, or ensure it is on the `PATH` the client
  uses to spawn subprocesses.
- No arguments are required or accepted; the active profile is resolved from
  disk and the platform keyring as described above.
- The exact location and schema of the configuration file depend on the MCP
  client. Consult that client's documentation for where to place the stanza.

After the client connects it issues an MCP `initialize`, then `tools/list` and
`resources/list`. The tool catalog below is what `tools/list` returns.

## Resources

The server exposes three MCP resources. None contains a secret.

- `mcp-resource://usage.md` — tool usage documentation.
- `mcp-resource://profiles/<name>` — non-secret profile metadata (chain id, RPC
  URL, network passphrase, `mcp_disabled`, and the USD threshold).
- `mcp-resource://accounts/<G>` — public account directory for the enrolled
  accounts across all configured profiles.

## How gating applies to every tool call

Every tool call is dispatched through the same gate before the tool's own logic
runs. The gate looks up the tool's registry descriptor and calls
`policy_engine.evaluate(...)`. The verdict is one of:

- `Allow` — the tool proceeds.
- `Deny` — the call is refused with wire code `policy.deny.<reason>`.
- `RequireApproval` — an out-of-band operator approval is required.

Separately, on `stellar:mainnet` the Noop engine fails closed for any
destructive tool by returning the engine error `policy.engine_required` before
producing a verdict, so every write is refused before any RPC call or signing.

The two [policy engines](./concepts.md) are Noop (testnet allow-all; mainnet
read-only allow, mainnet destructive refused) and V1 (signature-verified typed
criteria, first-match default-deny).

How a `RequireApproval` verdict is satisfied depends on the tool shape:

- Two-phase signing verbs (`stellar_pay`, `stellar_create_account`,
  `stellar_trustline`, `stellar_claim`, each paired with a `*_commit`) split into a simulate step
  and a commit step. The simulate step builds an envelope and mints a single-use
  nonce; if the policy required approval it records the pending approval. The
  commit step re-checks the nonce, byte-compares the envelope against a fresh
  rebuild, verifies the HMAC-SHA256 [attestation](./concepts.md) minted at
  approve time, signs from the keyring, and submits. The wire error on any
  approval-path failure is the uniform `policy.approval_required`, except an
  explicit operator rejection recorded via the approval inbox, which commits
  report as `policy.approval_rejected` so the agent stops retrying.
- One-shot signing verbs sign in a single call. If the policy returns
  `RequireApproval` for one of these tools, the call is refused fail-closed with
  `policy.approval_required_unsupported`; the wallet never signs without a
  verified approval.

Argument values are never written to the [audit log](./concepts.md); only key
names and lifecycle metadata are recorded. Verify the chain with
`stellar-agent audit verify`.

## Tool catalog

The server registers 36 tools. For each tool below: the exact registered name,
its purpose, and whether it is read-only, signs without submitting, or signs and
submits. Every tool except `stellar_x402_parse_receipt`, `stellar_toolset_list`,
and `stellar_toolset_invoke` requires a `chain_id` argument carrying the CAIP-2
chain id, which must match the profile. For `stellar_sep43_get_address` and
`stellar_sep43_get_network` the `chain_id` is optional and defaults to the
profile chain when omitted, but is still validated against the profile when
supplied.

### Payments and accounts

| Tool | Purpose | Gating |
| --- | --- | --- |
| `stellar_pay` | Simulate a payment: build the Payment envelope, run the SEP-29 memo-required check, mint a single-use nonce. | No signing; no submission. Not annotated read-only (mints the single-use nonce the commit step consumes). |
| `stellar_pay_commit` | Verify the nonce, re-check the envelope, sign from the keyring, submit. | Signs and submits. Two-phase verb; approval spine. |
| `stellar_create_account` | Simulate account creation: build the CreateAccount envelope, mint a single-use nonce. | No signing; no submission. Not annotated read-only (mints the single-use nonce the commit step consumes). |
| `stellar_create_account_commit` | Verify the nonce, re-check the envelope, sign, submit. | Signs and submits. Two-phase verb; approval spine. |
| `stellar_claim` | Simulate claiming a claimable balance by ID: fetch the entry, run the claimant / predicate / trustline guards, render the typed preview, mint a single-use nonce. | No signing; no submission. Not annotated read-only (mints the single-use nonce the commit step consumes). |
| `stellar_claim_commit` | Verify the nonce, re-derive the balance ID from the envelope, re-fetch the entry and re-run the claimant and predicate guards, sign, submit. | Signs and submits. Two-phase verb; approval spine. |
| `stellar_balances` | Fetch native XLM balance and optional trustline balances for an account. | Read-only. |
| `stellar_friendbot` | Fund a testnet account via Friendbot. | Mutating, testnet-only; gated. |

### Trustline

| Tool | Purpose | Gating |
| --- | --- | --- |
| `stellar_trustline` | Simulate a trustline change: build the ChangeTrust envelope, run the issuer clawback-flag gate, mint a single-use nonce. | No signing; no submission. Not annotated read-only (mints the single-use nonce the commit step consumes). |
| `stellar_trustline_commit` | Verify the nonce, re-derive the authoritative asset/issuer/limit from the envelope, sign, submit. | Signs and submits. Two-phase verb; approval spine. |

### Fees

| Tool | Purpose | Gating |
| --- | --- | --- |
| `stellar_fee_stats` | Fetch network fee statistics (classic and Soroban inclusion-fee distributions) for fee estimation. | Read-only. |

### Smart-account rules

| Tool | Purpose | Gating |
| --- | --- | --- |
| `stellar_rules_list` | Enumerate active context rules on a smart account: `rule_id`, `name`, `context_type_label`, `valid_until`, `signer_count`, `policy_count`, plus `as_of_ledger`. Scans up to the same `max_scan_id` default as the CLI `smart-account rules list`. | Read-only. |
| `stellar_rules_get` | Read one context rule's metadata plus its attached policies (`address`, `identified_kind`: `threshold`, `spending-limit`, or `unknown`), and, when exactly one policy identifies as `spending-limit`, the budget snapshot (`spending_limit`, `period_ledgers`, `in_window_spent`, `remaining_budget`, `as_of_ledger`). Identification failure or an absent policy degrades to the metadata-only shape rather than failing. | Read-only. |

`in_window_spent` and `remaining_budget` are exact only as of `as_of_ledger`:
forward ledger movement past that point only grows headroom (older spend
entries fall out of the rolling window), but an intervening spend shrinks it.
The numbers are a point-in-time estimate, not a guarantee for a future
submission — a later write can still fail with `SpendingLimitExceeded`.

Both tools are grantable to a toolset via the `read-rules` capability token,
separately from `read-balance`. See [Toolsets](./toolsets.md).

### DeFi

| Tool | Purpose | Gating |
| --- | --- | --- |
| `stellar_blend_lend` | Supply, withdraw, borrow, or repay on a Blend pool, behind an ordered trust gate (pool WASM-hash pin, oracle allowlist, oracle staleness), then a smart-account submit. | Signs via the smart account and submits; policy gate. |
| `stellar_defindex_vault_deposit` | Deposit into a DeFindex vault behind an ordered trust gate (vault WASM-hash pin, upgradable-flag check, role and asset disclosure), then a smart-account submit. | Signs via the smart account and submits; policy gate. |
| `stellar_defindex_vault_withdraw` | Withdraw from a DeFindex vault by redeeming shares, behind the same trust gate. | Signs via the smart account and submits; policy gate. |
| `stellar_dex_trade` | Soroswap router-direct swap, behind a venue allowlist, router WASM-hash pin, and on-chain slippage re-verify, then a smart-account submit. | Signs via the smart account and submits; policy gate. |
| `stellar_dex_quote` | On-chain Soroswap `router_get_amounts_out` quote for a token path. | Read-only. |

### SEP-43 (wallet interface)

| Tool | Purpose | Gating |
| --- | --- | --- |
| `stellar_sep43_get_address` | Return the active wallet address. | Read-only. |
| `stellar_sep43_get_network` | Return the active network name and passphrase. | Read-only. |
| `stellar_sep43_sign_transaction` | Sign a `TransactionEnvelope` XDR; return `signedTxXdr` and `signerAddress`. | Signs; does not submit. |
| `stellar_sep43_sign_auth_entry` | Sign a `SorobanAuthorizationEntry` XDR for G-key credentials; return `signedAuthEntry` and `signerAddress`. | Signs; does not submit. |
| `stellar_sep43_sign_message` | Sign an arbitrary UTF-8 message via `sha256(message)` then ed25519; return `signedMessage` (hex) and `signerAddress`. | Signs; does not submit. |
| `stellar_sep43_sign_and_submit_transaction` | Sign a `TransactionEnvelope` XDR, submit it, and poll until confirmed; return `signedTxXdr`, `txHash`, and `status`. | Signs and submits; policy gate. |

### SEP-45, SEP-47, SEP-48, SEP-53

| Tool | Purpose | Gating |
| --- | --- | --- |
| `stellar_sep47_discover` | Read the `contractmetav0` `sep` meta entry of a contract and return the SEPs it claims to implement. | Read-only. |
| `stellar_sep48_preview_invocation` | Fetch the on-chain contract spec and render typed argument names and JSON values for an `InvokeHostFunction`, from a transaction XDR or a contract id plus function name. | Read-only. |
| `stellar_sep53_sign_message` | Sign a prefixed message: `SHA-256('Stellar Signed Message:\n' + message)` then ed25519; return the base64 signature and signer public key. Not compatible with SEP-43 `signMessage`. | Signs; does not submit. |
| `stellar_sep53_verify_message` | Verify a SEP-53 base64 signature against a G-strkey public key and message. | Read-only; no keyring. |

SEP-45 is the contract-account authentication scheme used by the SEP-10/45 JWT
that `stellar_sep24_interactive_url` consumes; it has no standalone tool. See
[Protocols](./protocols.md) for the SEP coverage in detail.

### SEP-6, SEP-7, SEP-24

| Tool | Purpose | Gating |
| --- | --- | --- |
| `stellar_sep6_deposit_info` | SEP-6 anchor capability discovery: `GET /info` only. Returns the decoded anchor capabilities, including `authentication_required` per asset. Never calls `/deposit`, `/withdraw`, or any KYC endpoint. | Read-only. |
| `stellar_sep7_parse_uri` | Parse an inbound `web+stellar:tx?...` or `web+stellar:pay?...` URI into a structured preview, optionally fetching the `stellar.toml` and verifying the ed25519 origin signature. Never auto-signs or auto-POSTs. | Read-only. |
| `stellar_sep24_interactive_url` | SEP-24 interactive deposit/withdraw hand-off: resolve the SEP-24 transfer server, POST the interactive endpoint with a SEP-10/45 JWT, and return the interactive URL, transaction id, and a hand-off note. The wallet never opens or scrapes the URL and never transmits KYC fields. | Hand-off; does not sign or submit. |

### x402

| Tool | Purpose | Gating |
| --- | --- | --- |
| `stellar_x402_create_payment` | Construct and sign an x402 v2 Exact Stellar `PAYMENT-SIGNATURE` from a `PaymentRequirements` object; return the payment signature and its fields. The wallet does not submit. | Signs the payment authorization entry; does not submit. |
| `stellar_x402_parse_receipt` | Decode an x402 v2 `PAYMENT-RESPONSE` into a structured settlement receipt. | Read-only; no keyring, no network. No `chain_id`. |
| `stellar_x402_authenticated_payment` | Run a SEP-10 identity gate against a `home_domain` (stellar.toml, SSRF bind, ephemeral challenge/response, JWT), then construct the `PAYMENT-SIGNATURE`. Any identity failure aborts before payment. | Signs the payment authorization entry; does not submit. |

### Toolsets

| Tool | Purpose | Gating |
| --- | --- | --- |
| `stellar_toolset_list` | Enumerate installed toolsets and their invocable actions. | Read-only. No `chain_id`. |
| `stellar_toolset_invoke` | Invoke a named action of an installed toolset, routed to a registered tool through capability enforcement. | Dispatcher. The toolset signs nothing directly; the routed tool's own policy gate still applies. No `chain_id`. |

The toolsets dispatcher enforces a toolset's declared capabilities and never reaches
a signing tool directly regardless of those declarations. The routed tool runs
under its normal gate, so the first-invoke gate and per-action approval still
fire as described in [Toolsets](./toolsets.md).

## Output and exit behavior

Tool results are returned as MCP tool-call content; read-only tools return JSON
shaped like their CLI counterparts. The server runs until the MCP client closes
the connection. Startup failures (no supported keyring backend, an unloadable
profile, or a duplicate tool registration) cause the process to exit non-zero
before serving any request.
