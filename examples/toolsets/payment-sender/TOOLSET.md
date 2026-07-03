---
name: payment-sender
description: Sends a native XLM payment that the operator has approved. Builds the payment, then signs and submits it under the wallet's per-action approval gate. Use when the user asks to send XLM to a destination.
license: Apache-2.0
allowed-tools: stellar_pay stellar_pay_commit
metadata:
  stellar-agent-capabilities: propose-transaction sign-payment
---

# payment-sender

A payment toolset. It declares two capabilities:

- `propose-transaction`, which the wallet maps to `stellar_pay` — build an
  unsigned payment envelope. This is the ungated build step; it signs nothing.
- `sign-payment`, the one signing-adjacent capability, which the wallet maps to
  the gated `stellar_pay_commit` — sign the built envelope and submit it.

This toolset can move funds, but it cannot do so silently. Every payment it routes
passes the wallet's first-invoke gate and an unconditional per-action operator
approval. The toolset cannot bypass either: a tampered or forged grant can at most
suppress a re-prompt; it can never bypass the per-action approval, whose key
lives only in the keyring.

## Actions

`stellar_pay` (build) — arguments: `chain_id`, `source`, `destination`,
`amount` (e.g. `"10 XLM"`), `asset` (`"native"` for XLM). Returns an unsigned
`envelope_xdr`, a single-use `nonce`, and `expires_at_unix_ms`.

`stellar_pay_commit` (sign and submit) — arguments: the same
`chain_id`/`source`/`destination`/`amount`/`asset`, plus the `nonce`,
`expires_at_unix_ms`, and `envelope_xdr` returned by the build step. The
destination, asset, and amount that the gate matches on are decoded from the
envelope itself, never from toolset-supplied text.

## Instructions

1. Build the payment: invoke `stellar_pay` with `chain_id`, `source`,
   `destination`, `amount`, and `asset`. Keep the `envelope_xdr`, `nonce`, and
   `expires_at_unix_ms` it returns. Nothing is signed yet.
2. Commit: invoke `stellar_pay_commit` with the same payment fields and the
   `nonce`, `expires_at_unix_ms`, and `envelope_xdr` from step 1.
   - On the first commit to a new destination, asset, and amount, the wallet
     refuses with `toolset.first_invoke_approval_required` and returns an approval
     nonce. The operator approves out of band with
     `stellar-agent approve --id <nonce>` in a trusted context. Then re-invoke
     the commit; once a grant exists, the first-invoke re-prompt is suppressed.
   - The per-action approval still fires on every toolset-routed payment, even
     after a first-invoke grant exists. Wait for the operator to approve before
     treating the payment as sent.
3. Report the submitted transaction's hash and status from the commit result.

Stop and tell the user if either step is refused. Do not retry a refused commit
with altered amounts to get under a limit; the gate matches the authoritative
envelope, and the audit log records every attempt.
