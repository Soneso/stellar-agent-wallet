---
name: portfolio-summary
description: Displays a morning portfolio summary including XLM balance and recent transactions. Use when the user asks for a portfolio overview or wants a daily briefing.
license: Apache-2.0
compatibility: Requires access to the Stellar testnet RPC endpoint.
metadata:
  author: example-org
  version: "1.0"
  stellar-agent-capabilities: read-balance observe-event
allowed-tools: Bash(git:*) Read
---

## Instructions

1. Call `stellar_get_balance` to get the current XLM balance.
2. Call `stellar_observe_event` to list recent transactions from the last 24 hours.
3. Format the results as a human-readable summary.

## Example output

```
Morning Portfolio Summary
  Balance: 1234.5678901 XLM
  Recent transactions: 3
```
