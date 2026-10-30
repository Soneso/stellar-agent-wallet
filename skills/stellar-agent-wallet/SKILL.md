---
name: stellar-agent-wallet
description: Operate the Stellar Agent Wallet, a self-custodial Stellar wallet built for AI agents, through its stellar-agent CLI and stellar-agent-mcp MCP server. Use when an agent needs to read Stellar account state, send XLM or asset payments, create accounts, manage trustlines, or claim claimable balances. Also use for OpenZeppelin smart-account governance, DeFi trading/deposits, and SEP, x402, and sponsored MPP charge flows. The wallet provides a local policy engine and an operator-approval gate. Its audit log records transaction submissions, signed authorizations, approvals, and explicit key-management and lifecycle events. MCP balance reads and payment simulations produce no automatic invocation row. Under V1, payment simulations can reconcile overdue reservations and write settlement audit rows. Testnet approval is satisfiable via the CLI, a local web inbox, or a TLS-protected remote-approval surface; mainnet consent requires an owner-pinned passkey through the local browser. Covers the two-phase build-then-commit signing pattern, the simulate-approve-commit handshake, chain_id and the JSON result envelope, and configured mainnet authorization. Reach for it when the user mentions the stellar-agent wallet, an AI-agent wallet on Stellar, MCP-driven Stellar payments, or autonomous-agent key custody.
license: Apache-2.0
compatibility: Requires the stellar-agent CLI and stellar-agent-mcp server (v0.1.0-alpha.12 public alpha; install from crates.io with a pinned version, for example cargo binstall --locked --disable-strategies quick-install,compile stellar-agent-cli@0.1.0-alpha.12 stellar-agent-mcp@0.1.0-alpha.12, or build from source). Targets Stellar testnet (default) and mainnet.
metadata:
  version: "0.4.10"
  wallet_version: "0.1.0-alpha.12"
---

# Stellar Agent Wallet

## Overview

See [Mainnet configurations and scope](https://github.com/Soneso/stellar-agent-wallet/blob/main/docs/getting-started.md#mainnet-configurations-and-scope)
for build configuration, admitted operations, and exclusions.

The Stellar Agent Wallet is a self-custodial Stellar wallet for AI agents. It has
two surfaces over one shared core:

- **`stellar-agent`** — the CLI. The operator uses it to create profiles, custody
  keys, approve gated actions, and verify the audit log.
- **`stellar-agent-mcp`** — a Model Context Protocol server over stdio. An agent
  drives the wallet by calling its MCP tools.

Both surfaces share the **policy engine**, **operator-approval spine**, and
**tamper-evident audit log**. The log records transaction submissions, signed
authorizations, approvals, and explicit key-management and lifecycle events.
MCP balance reads and payment simulations produce no automatic invocation row.
Under V1, payment simulations can reconcile overdue reservations and write
settlement audit rows. As an agent, you
operate through the MCP tools; the human operator holds the keys and grants
approvals through the CLI. The agent
never holds key material and never approves its own actions.

The wallet is self-custodial and runs with no project-operated backend: keys live
in the host platform keyring, policy is evaluated locally, and nothing is sent to
a central server.

## Installation

This is a public alpha. Install the two binaries from crates.io — while only
prerelease versions are published, the version must be spelled out:

```bash
# Prebuilt binaries (fetched from the GitHub release archive):
cargo binstall --locked --disable-strategies quick-install,compile stellar-agent-cli@0.1.0-alpha.12 stellar-agent-mcp@0.1.0-alpha.12
# Or build from the published sources:
cargo install --locked stellar-agent-cli@0.1.0-alpha.12 stellar-agent-mcp@0.1.0-alpha.12
```

`--locked` builds with the `Cargo.lock` published in each crate. With the
strategy flag, binstall installs only this repository's release archive and
fails on a host for which none exists; use `cargo install --locked` there.

Building from a clone of the release tag also works
(`cargo build --release --locked -p stellar-agent-cli -p stellar-agent-mcp`
produces `target/release/stellar-agent` and `target/release/stellar-agent-mcp`).

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

Every tool returns the same JSON envelope, with five success-path exceptions:

```json
{ "ok": true, "data": { }, "request_id": "..." }
```

`stellar_toolset_list` returns a bare JSON array. `stellar_dex_trade`,
`stellar_dex_quote`, `stellar_defindex_vault_deposit`, and
`stellar_defindex_vault_withdraw` return a bare object carrying a `status`
field on success; their business errors use the envelope.

Some refusals use the JSON-RPC error channel instead of the envelope: invalid
arguments, a `chain_id` mismatch, and the toolset capability refusals.
`toolset.first_invoke_approval_required` is a JSON-RPC error too, and its error
data carries the `approval_nonce`.

On failure, `ok` is `false` and `error` carries a stable wire `code` (such as
`policy.deny.<reason>`, `policy.approval_required`, or `policy.engine_required`)
instead of `data`. Branch on `ok`; use `code` for control flow, never the human
message. `request_id` correlates the call with the audit log. Every business
error uses this envelope — domain refusals, policy and approval outcomes,
keyring and signing failures, submit failures, and the SEP-53, x402, and DeFi
verbs alike; codes follow a `<family>.<reason>` convention (for example
`x402.insufficient_funds`, `sep53.sign_failed`, `nonce.mint_failed`).

The six `stellar_sep43_*` tools use this same standard envelope.
The SEP-43 raw protocol payload, such as `{ address }`, appears inside `data`
on success. Failures use `{ ok: false, error: { code, message } }` with dotted
`sep43.*` codes, including `sep43.invalid_xdr` and `sep43.invalid_network_passphrase`.
Wallet entry guards report structural mainnet signing refusal with
`network.mainnet_write_forbidden`. Do
not expect the raw SEP-43 `{ code, message }` numeric-code object at the top
level. See references/protocols.md for the per-tool payloads and the full
wire-code table.

### chain_id

Every tool requires a `chain_id` argument — the CAIP-2 chain id (`stellar:testnet`
or `stellar:mainnet`) — that must match the active profile. Exceptions:
`stellar_x402_parse_receipt` and `stellar_toolset_list` take none; the two SEP-43
read tools make it optional; `stellar_toolset_invoke` accepts an optional `chain_id`
it forwards to the routed tool. The five `stellar_mpp_*` tools reject a `chain_id`
field as unknown and act on the chain of the server's profile.
`stellar_dex_quote` requires a `chain_id` but never matches it against the
profile; it selects the router from it and reads through the profile's RPC.

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

For pay, create-account, trustline, and claim, the simulate call records a pending
approval when policy requires approval for either the simulate tool or its paired
commit tool. It returns an `approval` block with `approval_nonce`, `profile`, and
`chain_id`. Toolset-routed payments also require operator approval at commit. The
handshake:

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

MPP prepare records a request when policy requires approval for prepare or
`stellar_mpp_charge_commit`. Its preview returns the nonce as
`authorization.approval_id`. After the operator approves that nonce,
`stellar_mpp_charge_commit` reads the recorded attestation, so you pass none.

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
payments and testnet sponsored MPP charges. Both x402 payment tools support
approved mainnet payments in a feature-enabled build. Authenticated payments
bind their SEP-10 identity operation to the payment approval. MPP uses
`stellar_mpp_charge_prepare` then one `stellar_mpp_charge_commit`; the trusted
host sends the returned credential to the exact bound HTTP or MCP request. See
`references/protocols.md`.

## 8. The wallet's toolsets feature

Separately from this knowledge skill, the wallet has a built-in **toolsets**
feature: a signed, installed package that declares a narrow set of capabilities
the toolset dispatcher routes for an agent. It is the opposite of this skill: it
narrows what the dispatcher routes rather than teaching. It does not restrict the
other tools the server exposes; the operator policy and approvals bound every call.
Drive installed toolsets with `stellar_toolset_list` and `stellar_toolset_invoke`
(a destructive tool, refused on mainnet). See `references/toolsets-feature.md`.

## 9. Safety model

- Released binaries have `mainnet-write` on and admit the four classic
  full-mode CLI operations and classic MCP commits after operator setup and
  approval for each action. See
  [profiles and keys](references/profiles-and-keys.md#mainnet-policy-body) and
  [classic MCP authorization](references/mcp-tools.md#classic-mainnet-authorization).
  Mainnet reads retain selection, key-scope, and policy requirements.
  Noop refuses destructive mainnet decisions with `policy.engine_required`.
  Policy evaluation alone grants no signing authority. Signing and submission
  independently check sealed authorization. Smart-account writes, DeFi, pool
  submission, MPP, generic signing, and toolset signing remain excluded.
  A feature-enabled build moves real funds on mainnet, and the operator uses it
  at their own risk. Before the first mainnet write of a session, confirm that
  the operator intends mainnet, and suggest a testnet run and a small amount.

- `profile.key_scope_conflict` refuses mainnet startup or CLI reconciliation
  for shared or invalid key scope; testnet logs a warning. Do not retry under
  another profile. Follow the named recovery in
  [troubleshooting](references/troubleshooting.md).
- The submit layer does not trust the declared network. It asks the RPC endpoint
  which network it serves and which protocol it runs, binds the submission to
  that answer, then verifies every signature on the envelope against it. The
  classic payment, sponsored account creation, trustline, claim, and pool paths
  ask the same question earlier, before the first read whose answer they sign
  or gate on. They ask on the client that sends, and the MCP simulate tools ask
  on their own client.
  Seven codes carry those refusals:
  - `network.endpoint_network_mismatch`: the endpoint serves a different
    network than declared.
  - `network.endpoint_identity_unavailable`: the endpoint identity cannot be
    established in time.
  - `network.rpc_credential_refused`: the endpoint answered a
    request with HTTP 401 or 403, or the stored RPC credential is unusable.
  - `network.unsupported_protocol_version`: a mainnet endpoint reports a version
    outside the supported range. Authorized mainnet paths enforce this check.
  - `network.envelope_signed_for_mainnet`: a signature fails under the endpoint
    network but verifies under mainnet.
  - `network.envelope_signature_unverifiable`: a signature does not verify.
  - `network.envelope_unsigned`: a required signature set is empty.

  `network.witness_unavailable` separately reports an unavailable required oracle
  witness for all four classic MCP commits and CLI `pay`, `claim`, sponsored
  `accounts create`, `trustline`, and sending `pool init` paths. The x402
  payment tools are covered by a second simulation on the oracle, which
  simulates the same unsigned transfer before the payer signs. Mainnet x402
  witnesses use the signed policy and profile thresholds. The oracle compares
  the unsigned transfer before the payer signs.
  Opaque staged envelopes and the SEP-43 signing tools remain uncovered.
  `fees.percentile_exceeds_cap` and
  `validation.mainnet_fee_cap_required` report the classic fee cap.
  See references/troubleshooting.md.
- These tools refuse `stellar:mainnet` at handler entry with
  `network.mainnet_write_forbidden`, before the policy gate. The refusal holds
  in every build, except for the six tools named after the list:
  - the sign-only tools: the SEP-43 sign verbs, SEP-53 `sign_message`, and the
    two x402 payment tools;
  - `stellar_sep43_sign_and_submit_transaction` and the DeFi tools;
  - the commit tools, `stellar_rule_create_commit`, and the toolset signing
    actions.

  Both x402 payment tools, `stellar_x402_create_payment` and
  `stellar_x402_authenticated_payment`, and the four classic commits depend on
  the feature. With the feature off, they refuse at entry with the same code. A
  feature-enabled build admits them after setup, as
  [classic MCP authorization](references/mcp-tools.md#classic-mainnet-authorization)
  describes. With the feature enabled, both x402 tools use the approved two-call
  flow.
- Every MPP tool refuses `stellar:mainnet` at handler entry with
  `mpp.network_forbidden`. Branch on all three codes,
  `network.mainnet_write_forbidden`, `policy.engine_required`, and
  `mpp.network_forbidden`, when handling a mainnet refusal.
- Raw argument values are never written to the audit log, only key names.
  Typed value events retain each leg's amount, asset, and redacted destination. The
  operator verifies the chain with
  `stellar-agent audit verify <LOG_PATH> --profile <NAME>`.

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

**Mainnet actions require operator setup and approval.** Mainnet consent
requires a verified passkey assertion from an approval credential in the
owner-signed policy. The operator approves through the local browser.
Never attempt the approval yourself. The version marker
reports compiled state. `network.mainnet_write_forbidden` identifies an excluded
operation, a feature-off build, or a missing admitted context. Resolver gaps
use `network.mainnet_authorization_refused`; policy denials retain `policy.deny.*`.
Report authorization refusal to the operator. Do not switch networks. A retry
needs fresh preparation and approval. Restart MCP after enablement or policy
signing; stale startup bindings report the restart requirement.

**The endpoint binds the network.** Prepare and commit probe the client before
its first action read. Submission checks it again before send. A network
mismatch uses `network.endpoint_network_mismatch`; unavailable identity uses
`network.endpoint_identity_unavailable`. Credential refusals use
`network.rpc_credential_refused`. Authorized mainnet operations require protocol 29.
Signatures must verify under the endpoint network. See
[network-binding codes](references/troubleshooting.md#network-binding-codes-submit-layer).
A submission timeout requires reconciliation, not a new payment attempt.

**Branch on `ok` and the error `code`, not the message.** The human message text
is not a stable contract; the wire `code` is.

**The toolsets feature is not this skill.** `stellar_toolset_list` /
`stellar_toolset_invoke` drive the wallet's capability packages, which narrow what
the toolset dispatcher routes; they are not downloadable knowledge like this skill.
