---
name: payment-sender
description: Sends a native XLM payment that the operator has approved. Builds the payment, then signs and submits it under the wallet's first-invoke gate and payment policy. Use when the user asks to send XLM to a destination.
license: Apache-2.0
allowed-tools: stellar_pay stellar_pay_commit
metadata:
  stellar-agent-capabilities: propose-transaction sign-payment
---

# payment-sender

A payment toolset. It declares two capabilities:

- `propose-transaction`, which the wallet maps to `stellar_pay`: build an
  unsigned payment envelope. This is the ungated build step; it signs nothing.
- `sign-payment`, a signing-adjacent capability, which the wallet maps to
  the gated `stellar_pay_commit`: sign the built envelope and submit it.

This toolset can move funds, but it cannot do so silently. Every payment it routes
passes the wallet's first-invoke gate and the payment and outer toolset policies.
A tampered or forged grant fails verification and suppresses nothing. When either
policy requires approval, the commit refuses until the operator approves.

## Actions

`stellar_pay` (build). Arguments: `chain_id`, `source`, `destination`,
`amount` (e.g. `"10 XLM"`), `asset` (`"native"` for XLM), and optionally one
of `memo_text`, `memo_id`, `memo_hash_hex`, or `memo_return_hex`. Returns an
unsigned `envelope_xdr`, a single-use `nonce`, and `expires_at_unix_ms`. When
the owner policy binds the destination's memo, the wallet evaluates the
parsed memo argument and refuses a missing or different memo with
`policy.deny.memo_binding_mismatch`; the commit evaluates the memo encoded in
the envelope.

`stellar_pay_commit` (sign and submit) takes the same `chain_id`, `source`,
`destination`, `amount`, `asset`, and memo field as the build step, plus the
`nonce`, `expires_at_unix_ms`, and `envelope_xdr` it returned. On
`stellar:mainnet`, both steps also take the same `business_id`. When a policy
requires approval, a commit also carries `approval_nonce` and
`approval_attestation`. The destination, asset, and amount that the gate matches on are decoded from the
envelope itself, never from toolset-supplied text.

## Instructions

1. Build the payment: invoke `stellar_pay` with `chain_id`, `source`,
   `destination`, `amount`, and `asset`. Keep the `envelope_xdr`, `nonce`, and
   `expires_at_unix_ms` it returns. Nothing is signed yet.
2. Commit: invoke `stellar_pay_commit` with the same payment fields and the
   `nonce`, `expires_at_unix_ms`, and `envelope_xdr` from step 1.
   - On the first commit to a new destination or asset, or for an amount above the
     granted maximum, the wallet
     refuses with `toolset.first_invoke_approval_required` and returns an approval
     nonce. The operator approves out of band with
     `stellar-agent approve --id <nonce> --profile <name>` in a trusted context. Then re-invoke
     the commit; once a grant exists, the first-invoke re-prompt is suppressed.
   - After a first-invoke grant exists, the payment and outer toolset policies
     decide whether a per-action approval is required. Under a composed `Allow`
     the commit submits. When either policy requires approval, a commit without
     approval fields refuses with `policy.approval_required`. Once the operator approves, re-invoke the
     commit with `approval_nonce` and the `approval_attestation` the operator
     relays. Treat the payment as sent only when the commit returns its
     transaction hash.
3. Report the `tx_hash` and `ledger` from the commit result.

Stop and tell the user if either step is refused. Do not retry a refused commit
with altered amounts to get under a limit; the gate matches the authoritative
envelope, and the audit log records the operator's approval and the
submission's lifecycle events.
