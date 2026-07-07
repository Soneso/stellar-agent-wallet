---
name: stellar-agent-wallet
description: Operate the Stellar Agent Wallet — a self-custodial Stellar wallet built for AI agents — through its stellar-agent CLI and stellar-agent-mcp MCP server. Use when an agent needs to read Stellar account state, send XLM or asset payments, create accounts, manage trustlines, claim claimable balances, run OpenZeppelin smart-account governance, lend/trade/deposit on DeFi, or handle SEP and x402 flows, all under a local policy engine, an operator-approval gate (satisfiable via the CLI, a local web inbox, or a TLS-protected remote-approval surface), and a tamper-evident audit log. Covers the two-phase build-then-commit signing pattern, the simulate-approve-commit handshake, chain_id and the JSON result envelope, and the mainnet write gate. Reach for it when the user mentions the stellar-agent wallet, an AI-agent wallet on Stellar, MCP-driven Stellar payments, or autonomous-agent key custody.
license: Apache-2.0
compatibility: Requires the stellar-agent CLI and stellar-agent-mcp server (v0.1.0-alpha.2 public alpha; install with cargo binstall/install --git from the GitHub repository, or build from source). Targets Stellar testnet (default) and mainnet.
metadata:
  version: "0.1.1"
  wallet_version: "0.1.0-alpha.2"
---

# Stellar Agent Wallet

## Overview

The Stellar Agent Wallet is a self-custodial Stellar wallet for AI agents. It has
two surfaces over one shared core:

- **`stellar-agent`** — the CLI. The operator uses it to create profiles, custody
  keys, approve gated actions, and verify the audit log.
- **`stellar-agent-mcp`** — a Model Context Protocol server over stdio. An agent
  drives the wallet by calling its MCP tools.

Both surfaces run every action through the same **policy engine**, **operator-approval
spine**, and **tamper-evident audit log**, so an MCP tool call is gated exactly as
the equivalent CLI command. As an agent, you operate through the MCP tools; the
human operator holds the keys and grants approvals through the CLI. The agent
never holds key material and never approves its own actions.

The wallet is self-custodial and runs with no project-operated backend: keys live
in the host platform keyring, policy is evaluated locally, and nothing is sent to
a central server.

## Installation

This is a public alpha; build the binaries from source:

```bash
cargo build --release -p stellar-agent-cli -p stellar-agent-mcp
# produces target/release/stellar-agent and target/release/stellar-agent-mcp
```

Point your MCP client at the server binary:

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

The server takes no arguments; it resolves the active profile from disk and the
platform keyring. After connecting, the client issues `initialize`, then
`tools/list` and `resources/list`. The schemas returned by `tools/list` are the
authoritative argument contract — prefer them over any example here.

## 1. Core conventions

### The result envelope

Every tool returns the same JSON envelope:

```json
{ "ok": true, "data": { }, "request_id": "..." }
```

On failure, `ok` is `false` and `error` carries a stable wire `code` (such as
`policy.deny.<reason>`, `policy.approval_required`, or `policy.engine_required`)
instead of `data`. Branch on `ok`; use `code` for control flow, never the human
message. `request_id` correlates the call with the audit log.

### chain_id

Every tool requires a `chain_id` argument — the CAIP-2 chain id (`stellar:testnet`
or `stellar:mainnet`) — that must match the active profile. Exceptions:
`stellar_x402_parse_receipt` and `stellar_toolset_list` take none; the two SEP-43
read tools make it optional; `stellar_toolset_invoke` accepts an optional `chain_id`
it forwards to the routed tool.

## 2. Reading account state

Read-only tools never sign and are safe to call freely.

```json
// stellar_balances — native XLM plus optional trustline balances
{ "chain_id": "stellar:testnet", "account_id": "GABC...WXYZ" }
```

`stellar_fee_stats` returns network fee statistics; `stellar_dex_quote` returns an
on-chain Soroswap quote. On testnet, fund a fresh account with `stellar_friendbot`.

`stellar_rules_list` and `stellar_rules_get` read the agent's own context rules —
including any spending-limit budget (`spending_limit`, `in_window_spent`,
`remaining_budget`) and expiry (`expires_in_ledgers`). Read these before a
transfer that might be near a cap: `in_window_spent`/`remaining_budget` are
exact only as of the `as_of_ledger` they were read at, so treat them as an
estimate, not a guarantee — an intervening spend can still make a later
submission fail `SpendingLimitExceeded`. See
[references/smart-accounts.md](references/smart-accounts.md).

## 3. Sending a payment — the two-phase pattern

Fund-moving classic verbs split into a **build** call and a **commit** call. This
is the core safe pattern; it also applies to `stellar_create_account` and
`stellar_trustline` (each paired with a `*_commit`).

**Step 1 — build.** `stellar_pay` builds an unsigned envelope, runs the SEP-29
memo check, and mints a single-use nonce. Nothing is signed.

```json
{
  "chain_id": "stellar:testnet",
  "source": "GABC...WXYZ",
  "destination": "GDEF...UVWX",
  "amount": "10 XLM",
  "asset": "native"
}
```

It returns `envelope_xdr`, `nonce`, and `expires_at_unix_ms`.

**Step 2 — commit.** `stellar_pay_commit` re-derives the authoritative
destination, asset, and amount from the envelope, verifies the nonce, signs from
the keyring, and submits.

```json
{
  "chain_id": "stellar:testnet",
  "source": "GABC...WXYZ",
  "destination": "GDEF...UVWX",
  "amount": "10 XLM",
  "asset": "native",
  "nonce": "<from step 1>",
  "expires_at_unix_ms": 0,
  "envelope_xdr": "<from step 1>"
}
```

On success `data` carries `tx_hash` and `ledger`.

### When approval is required

If the policy engine returns `RequireApproval` (a V1 policy rule, the high-value
cross-check, or any toolset-routed payment), the build call returns an `approval`
block with an `approval_nonce` and the commit is held. The handshake:

1. The operator consents out-of-band — `stellar-agent approve --id
   <approval_nonce>` at a terminal, `approve list` / `approve serve` (a local
   web inbox), or `approve serve --remote` (a TLS-protected, passkey-authenticated
   inbox for a device other than the wallet host) — and reviews the
   wallet-rendered summary before consenting. See
   `references/approvals-and-audit.md` for all three surfaces.
2. That step returns an `approval_attestation` — an HMAC blob bound to that
   exact envelope. The operator relays it to you.
3. Re-invoke `stellar_pay_commit` with `approval_nonce` and `approval_attestation`
   added. The wallet verifies the attestation, then signs and submits.

You cannot mint or guess the attestation. Treat `policy.approval_required` as "ask
the operator to approve, then retry the commit with the attestation" — never as a
transient error to retry blindly.

## 4. Accounts and trustlines

`stellar_create_account` / `stellar_create_account_commit` fund and create a new
account; `stellar_trustline` / `stellar_trustline_commit` add or change a
trustline. `stellar_claim` / `stellar_claim_commit` claim a Stellar claimable
balance the agent already holds the id of, behind claimant/predicate/trustline
guards. All three pairs follow the same two-phase build-then-commit pattern as
payments. See `references/cli-reference.md` and `references/mcp-tools.md`.

## 5. Smart-account governance

The wallet manages OpenZeppelin smart accounts: context rules, ed25519
(delegated and first-class external) and WebAuthn passkey signers, quorum
thresholds, verifier/policy WASM-hash pinning, multicall, and an upgrade
timelock. A context rule scoped to one contract (`--context call-contract:<C>`)
combined with a fresh external Ed25519 signer and a spending-limit policy is
the bounded-agent-delegation shape: an operator can hand an autonomous agent
its own key, capped to one contract and a spending limit, without exposing the
account's full authority. These run under the CLI `smart-account` (alias `sa`)
command group and submit through the smart account. See
`references/smart-accounts.md`.

You can also PROPOSE a new rule yourself via `stellar_rule_create` /
`stellar_rule_create_commit` instead of asking the operator to run the CLI —
you resolve and simulate the definition, but the rule installs only after the
operator attests to the exact definition you proposed. See
`references/mcp-tools.md#agent-proposed-context-rules`.

## 6. DeFi

`stellar_blend_lend` (supply/withdraw/borrow/repay), `stellar_dex_trade`
(Soroswap swaps) with `stellar_dex_quote`, and `stellar_defindex_vault_deposit` /
`_withdraw` each run behind an ordered trust gate (WASM-hash pin, oracle/venue
allowlist, slippage re-verify) and submit through the smart account. See
`references/defi.md`.

## 7. Protocols

SEP-7 URI parsing, SEP-10/45 web auth, SEP-24/6 transfer hand-off, SEP-43 wallet
signing (`get_address`, `get_network`, `sign_transaction`, `sign_auth_entry`,
`sign_message`, `sign_and_submit_transaction`), SEP-47/48 contract discovery, and
SEP-53 signed messages. The wallet also signs x402 v2 Exact Stellar agent
payments. See `references/protocols.md`.

## 8. The wallet's toolsets feature

Separately from this knowledge skill, the wallet has a built-in **toolsets**
feature: a signed, installed package that grants an agent a narrow, wallet-enforced
set of capabilities (least privilege). It is the opposite of this skill — it
restricts what an agent may do rather than teaching it. Drive installed toolsets
with `stellar_toolset_list` and `stellar_toolset_invoke`. See
`references/toolsets-feature.md`.

## 9. Safety model

- On `stellar:mainnet` the default policy engine allows read-only tools and
  refuses every fund-moving tool with `policy.engine_required`, before any RPC
  call. Mainnet writes require the operator to rotate keys and opt in to the V1
  engine.
- Argument values are never written to the audit log — only key names. The
  operator verifies the chain with `stellar-agent audit verify`.

See `references/security.md` and `references/approvals-and-audit.md`.

## Reference Documentation

- [CLI reference](./references/cli-reference.md) — the full `stellar-agent` command surface
- [MCP tools](./references/mcp-tools.md) — the `stellar-agent-mcp` tool catalog with arguments
- [Profiles and keys](./references/profiles-and-keys.md) — profile schema, the keyring, key rotation
- [Approvals and audit](./references/approvals-and-audit.md) — policy engine, the approval spine, the audit log
- [Smart accounts](./references/smart-accounts.md) — OpenZeppelin governance: rules, signers, passkeys, timelock, multicall
- [DeFi](./references/defi.md) — Blend, Soroswap, DeFindex, and the channel pool
- [Protocols](./references/protocols.md) — SEP coverage and x402 agent payments
- [Toolsets feature](./references/toolsets-feature.md) — the wallet's capability-isolation packages
- [Troubleshooting](./references/troubleshooting.md) — wire and error codes
- [Security](./references/security.md) — the security model and safe operation

## Common Pitfalls

**Amounts are strings, not numbers.** Pass `"amount": "10 XLM"` (a decimal string
with a unit), not a JSON number. `asset` is `"native"` or `"XLM"` for XLM, or
`"CODE:GISSUER..."` for a credit asset.

```json
// WRONG: numeric amount loses precision and is rejected
{ "amount": 10, "asset": "native" }
// CORRECT
{ "amount": "10 XLM", "asset": "native" }
```

**Build does not move funds; commit does.** `stellar_pay` only simulates and mints
a nonce — it signs nothing. Funds move only when `stellar_pay_commit` succeeds.
Do not treat a successful `stellar_pay` as a sent payment.

**The envelope is authoritative at commit.** `stellar_pay_commit` decodes the
destination, asset, and amount from `envelope_xdr`, not from re-supplied
arguments. Re-submitting a commit with altered amounts to get under a limit does
not work and is recorded in the audit log.

**Each build mints a fresh single-use nonce.** You cannot reuse a `nonce` across
commits or call commit twice with the same one. Build again to get a new nonce.

**`policy.approval_required` is not a transient error.** It means the operator
must approve and relay the `approval_attestation`. Retrying the commit unchanged
will keep failing.

**Mainnet writes are refused by default.** Expect `policy.engine_required` for any
fund-moving tool on `stellar:mainnet` until the operator opts in to the V1 engine.

**Branch on `ok` and the error `code`, not the message.** The human message text
is not a stable contract; the wire `code` is.

**The toolsets feature is not this skill.** `stellar_toolset_list` /
`stellar_toolset_invoke` drive the wallet's capability-restriction packages, a
runtime permission mechanism — not downloadable knowledge like this skill.
