---
name: balance-reporter
description: Reports a Stellar account's native XLM balance and any trustline balances. Use when the user asks how much the account holds or wants a balance overview.
license: Apache-2.0
allowed-tools: stellar_balances
metadata:
  stellar-agent-capabilities: read-balance
---

# balance-reporter

A read-only toolset. It declares the `read-balance` capability, which the wallet
maps to exactly one tool, `stellar_balances`. It can read balances and nothing
else: no signing, key, or policy tool is reachable through this toolset, and the
`allowed-tools` line narrows the grant to `stellar_balances` only.

## Action

`stellar_balances` — fetch the account's native XLM balance and, optionally, the
balances of named trustlines.

Arguments:

- `chain_id` (required) — the CAIP-2 chain id, e.g. `stellar:testnet`. Must match
  the active profile.
- `account_id` (required) — the G-strkey account to read.
- `assets` (optional) — a list of `{ "code", "issuer" }` objects to also report
  trustline balances for.

## Instructions

1. Invoke the `stellar_balances` action with the target `account_id` and the
   profile's `chain_id`.
2. Read the native XLM balance from the result. If the user named specific
   assets, pass them in `assets` and report those trustline balances too.
3. Present the balances as a short, human-readable summary.

This toolset never moves funds. It cannot send a payment or sign anything, because
those tools are not in any capability it declares.
