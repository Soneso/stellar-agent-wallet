---
name: stellar-agent-wallet
description: Operate the Stellar Agent Wallet, a self-custodial Stellar wallet built for AI agents, through its stellar-agent CLI and stellar-agent-mcp MCP server. Use when an agent needs to read Stellar account state, send XLM or asset payments, create accounts, manage trustlines, or claim claimable balances. Also use for OpenZeppelin smart-account governance, DeFi lending/trading/deposits, and SEP, x402, and sponsored MPP charge flows. All operations run under a local policy engine, an operator-approval gate, and a tamper-evident audit log. Approval is satisfiable via the CLI, a local web inbox, or a TLS-protected remote-approval surface. Covers the two-phase build-then-commit signing pattern, the simulate-approve-commit handshake, chain_id and the JSON result envelope, and the mainnet write gate. Reach for it when the user mentions the stellar-agent wallet, an AI-agent wallet on Stellar, MCP-driven Stellar payments, or autonomous-agent key custody.
license: Apache-2.0
compatibility: Requires the stellar-agent CLI and stellar-agent-mcp server (v0.1.0-alpha.9 public alpha; install from crates.io with a pinned version, e.g. cargo binstall stellar-agent-cli@0.1.0-alpha.9 stellar-agent-mcp@0.1.0-alpha.9, or build from source). Targets Stellar testnet (default) and mainnet.
metadata:
  version: "0.4.7"
  wallet_version: "0.1.0-alpha.9"
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

This is a public alpha. Install the two binaries from crates.io — while only
prerelease versions are published, the version must be spelled out:

```bash
# Prebuilt binaries (fetched from the GitHub release archive):
cargo binstall stellar-agent-cli@0.1.0-alpha.9 stellar-agent-mcp@0.1.0-alpha.9
# Or build from the published sources:
cargo install stellar-agent-cli@0.1.0-alpha.9 stellar-agent-mcp@0.1.0-alpha.9
```

Building from a repository clone also works
(`cargo build --release -p stellar-agent-cli -p stellar-agent-mcp` produces
`target/release/stellar-agent` and `target/release/stellar-agent-mcp`).

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

The server serves the `default` profile unless another is named: pass
`"args": ["--profile", "alice"]`, or set `STELLAR_AGENT_PROFILE` in the
environment the client spawns it with. The flag wins over the variable. The
selected profile binds at startup and stays bound; keys are resolved from the
platform keyring that profile names. After connecting, the client issues
`initialize`, then
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
message. `request_id` correlates the call with the audit log. Every business
error uses this envelope — domain refusals, policy and approval outcomes,
keyring and signing failures, submit failures, and the SEP-53, x402, and DeFi
verbs alike; codes follow a `<family>.<reason>` convention (for example
`x402.insufficient_funds`, `sep53.sign_failed`, `nonce.mint_failed`).

The six `stellar_sep43_*` tools use this same standard envelope: the SEP-43
raw protocol payload (`{ address }`, `{ signedTxXdr, signerAddress }`, and so
on) is carried inside `data` on success, and failures surface as
`{ ok: false, error: { code, message } }` with dotted `sep43.*` codes (for
example `sep43.invalid_xdr`, `sep43.invalid_network_passphrase`); the
structural mainnet-signing refusal carries the canonical
`network.mainnet_write_forbidden` code shared with every signing surface. Do
not expect the raw SEP-43 `{ code, message }` numeric-code object at the top
level. See references/protocols.md for the per-tool payloads and the full
wire-code table.

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

`stellar_rules_list` and `stellar_rules_get` read the agent's own context rules,
including spending-limit budget and expiry. Their `baseline` field reports
`none`, `v1`, `v2`, `unreadable`, or `unknown`. A non-zero rule reporting `none`
refuses every signature until the operator runs `signers list` at the CLI.
A rule reporting `v1` signs the agent's commits through the version 1 projection.
The operator runs `signers refresh` before signer or policy mutations and a
`migrate-verifier` removal. MCP has no tool for either step.
Read budget fields before transfers near a cap. `in_window_spent` and
`remaining_budget` are exact only at `as_of_ledger`. An intervening spend can
make submission fail `SpendingLimitExceeded`. See
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
block with `approval_nonce`, `profile`, and `chain_id`; the commit is held. The handshake:

1. The operator consents out-of-band with `stellar-agent approve --id
   <approval_nonce> --profile <name>` at a terminal, `approve list` / `approve serve` (a local
   web inbox), or `approve serve --remote` (a TLS-protected, passkey-authenticated
   inbox for a device other than the wallet host). The operator reviews the
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
timelock. Every signature under a non-zero rule compares its live signer set
with its audit-log baseline and checks executable pins. The operator runs
`signers list` once for `none` and `signers refresh` once for `v1` before
signer or policy mutations or a `migrate-verifier` removal.
A context rule scoped to one contract (`--context call-contract:<C>`) with an
external Ed25519 signer and a spending-limit policy bounds agent delegation.
The operator gives the agent its own key, capped to one contract and a spending
limit, without exposing the account's full authority. These governance features
run under the CLI `smart-account` (alias `sa`) command group and submit through
the smart account. See
`references/smart-accounts.md`.

You can also PROPOSE a new rule yourself via `stellar_rule_create` /
`stellar_rule_create_commit` instead of asking the operator to run the CLI —
you resolve and simulate the definition, but the rule installs only after the
operator attests to the exact definition you proposed. See
`references/mcp-tools.md#agent-proposed-context-rules`.

## 6. DeFi

`stellar_dex_trade`
(Soroswap swaps) with `stellar_dex_quote`, and `stellar_defindex_vault_deposit` /
`_withdraw` each run behind an ordered trust gate (WASM-hash pin, oracle/venue
allowlist, slippage re-verify) and submit through the smart account. See
`references/defi.md`.

## 7. Protocols

SEP-7 URI parsing, SEP-10/45 web auth, SEP-24/6 transfer hand-off, SEP-43 wallet
signing (`get_address`, `get_network`, `sign_transaction`, `sign_auth_entry`,
`sign_message`, `sign_and_submit_transaction`), SEP-47/48 contract discovery, and
SEP-53 signed messages. The wallet also signs x402 v2 Exact Stellar agent
payments and testnet sponsored MPP charges. MPP uses
`stellar_mpp_charge_prepare` then one `stellar_mpp_charge_commit`; the trusted
host sends the returned credential to the exact bound HTTP or MCP request. See
`references/protocols.md`.

## 8. The wallet's toolsets feature

Separately from this knowledge skill, the wallet has a built-in **toolsets**
feature: a signed, installed package that grants an agent a narrow, wallet-enforced
set of capabilities (least privilege). It is the opposite of this skill — it
restricts what an agent may do rather than teaching it. Drive installed toolsets
with `stellar_toolset_list` and `stellar_toolset_invoke`. See
`references/toolsets-feature.md`.

## 9. Safety model

- On `stellar:mainnet` read-only tools work. The DeFi, sign-and-submit, commit,
  and rule-commit tools refuse a mainnet profile at handler entry with
  `network.mainnet_write_forbidden`, before the policy gate and any RPC call. A
  profile on the Noop engine refuses the other destructive tools on mainnet with
  `policy.engine_required`. Below the policy layer, the network layer
  structurally refuses every mainnet write with `network.mainnet_write_forbidden`
  regardless of engine or keys. No configuration unlocks mainnet writes in this
  alpha.
- The submit layer does not trust the declared network. It asks the RPC endpoint
  which network it serves and binds the submission to that answer, then verifies
  every signature on the envelope against it. Five codes carry those refusals:
  `network.endpoint_network_mismatch` (endpoint serves a different network than
  declared), `network.endpoint_identity_unavailable` (endpoint identity could
  not be established in time), `network.envelope_signed_for_mainnet`,
  `network.envelope_signature_unverifiable`, and `network.envelope_unsigned`.
  See references/troubleshooting.md.
- These tools refuse `stellar:mainnet` structurally at handler entry with
  `network.mainnet_write_forbidden`, before the policy gate and regardless of
  engine:
  - the sign-only tools: the SEP-43 sign verbs, SEP-53 `sign_message`, and the
    two x402 payment tools;
  - `stellar_sep43_sign_and_submit_transaction` and the DeFi tools;
  - the commit tools, `stellar_rule_create_commit`, and the toolset signing
    actions.
- Every MPP tool refuses `stellar:mainnet` at handler entry with
  `mpp.network_forbidden`. Branch on all three codes when handling a mainnet
  refusal.
- Argument values are never written to the audit log — only key names. The
  operator verifies the chain with `stellar-agent audit verify`.

See `references/security.md` and `references/approvals-and-audit.md`.

## Reference Documentation

- [CLI reference](./references/cli-reference.md) — the full `stellar-agent` command surface
- [MCP tools](./references/mcp-tools.md) — the `stellar-agent-mcp` tool catalog with arguments
- [Profiles and keys](./references/profiles-and-keys.md) — profile schema, the keyring, key rotation
- [Approvals and audit](./references/approvals-and-audit.md) — policy engine, the approval spine, the audit log
- [Smart accounts](./references/smart-accounts.md) — OpenZeppelin governance: rules, signers, passkeys, timelock, multicall
- [DeFi](./references/defi.md) — Soroswap, DeFindex, and the channel pool
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

**An MPP credential is one-shot.** Never retry MPP commit, replace its stored
terms, switch transport, or create an x402/classic fallback after an ambiguous
result. Query `stellar_mpp_authorization_status`, record the host receipt, and
reconcile the transaction. Keep credential and receipt values out of logs.

**`policy.approval_required` is not a transient error.** It means the operator
must approve and relay the `approval_attestation`. Retrying the commit unchanged
will keep failing.

**Mainnet writes are refused in this alpha.** Expect
`network.mainnet_write_forbidden` at handler entry from the DeFi,
sign-and-submit, commit, rule-commit, and sign-only tools, before the policy
gate. The network layer refuses every mainnet write with the same code,
regardless of engine or keys. No configuration unlocks mainnet writes. MPP tools
refuse with `mpp.network_forbidden`. A profile on the Noop engine refuses the
other destructive tools on mainnet with `policy.engine_required`. Branch on all
three codes for mainnet refusals.

**The endpoint decides which network you are on, not `chain_id`.** The submit
layer asks the RPC endpoint which network it serves and binds the submission to
that answer. An endpoint serving a different network than the profile declares
is `network.endpoint_network_mismatch`; an endpoint whose identity cannot be
established in time is `network.endpoint_identity_unavailable`. Signatures are
then checked against the network the endpoint reported: an envelope signed for
mainnet is `network.envelope_signed_for_mainnet`, one whose signatures verify
under neither that network nor mainnet is
`network.envelope_signature_unverifiable`, and an
envelope with no signature, or a fee-bump whose outer or inner transaction
has none, is `network.envelope_unsigned`. On the
four two-phase commit tools this runs before the single-use nonce is burned, so
a refusal here leaves the nonce usable.

**Branch on `ok` and the error `code`, not the message.** The human message text
is not a stable contract; the wire `code` is.

**The toolsets feature is not this skill.** `stellar_toolset_list` /
`stellar_toolset_invoke` drive the wallet's capability-restriction packages, a
runtime permission mechanism — not downloadable knowledge like this skill.
