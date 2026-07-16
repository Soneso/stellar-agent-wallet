# Agent payments with MPP

The wallet implements a narrow Machine Payments Protocol (MPP) payer flow for
sponsored Stellar charges. This feature is testnet-only and credential-only:
the wallet validates a challenge, prepares and signs the payer authorization,
and returns a credential to a trusted host. It never sends the paid HTTP or MCP
request and never submits the sponsored transaction itself.

## Supported boundary

| Dimension | Supported |
|---|---|
| Network | `stellar:testnet` only |
| Payer | One classic G-account from the active profile |
| Intent and method | `charge` with `method="stellar"` |
| Settlement shape | Sponsored pull; the server pays fees and submits |
| Transport | HTTP `Payment` authentication or native MCP payment metadata |
| Credential | One SEP-41 transfer in a sponsored Soroban transaction |
| Policy | Existing V1 value policy and dedicated operator approval |
| Observation | Trusted-host receipt plus independent RPC reconciliation |

Mainnet, unsponsored transactions, push payments, smart-account payers,
automatic transport retries, channel settlement, and toolset routing are not
implemented. Every MPP entry point rejects a mainnet profile before RPC, state,
keyring, or signer access.

MPP is separate from the wallet's x402 v2 support. x402 accepts an x402
`PaymentRequirements` object and returns a `PAYMENT-SIGNATURE`. MPP accepts a
Payment challenge bound to the request context and returns an HTTP or native MCP
Payment credential. Neither path sends the merchant request.

## Request binding

The host must give the wallet both the challenge and the exact request context.
For HTTP, the context contains the HTTPS origin, method, canonical absolute
resource URL, and optional content and idempotency-key digests. For native MCP,
it contains the server identity, operation kind, target, and the SHA-256 digest
of whether parameters were absent or of their canonical JSON value.

An HTTP CLI input has this shape:

```json
{
  "transport": "http",
  "www_authenticate": [
    "Payment id=\"order-7\", realm=\"merchant.example\", method=\"stellar\", intent=\"charge\", request=<base64url-json>"
  ],
  "selected_challenge_id": "order-7",
  "context": {
    "origin": "https://merchant.example",
    "http_method": "POST",
    "canonical_resource": "https://merchant.example/checkout",
    "content_digest": null,
    "idempotency_key_hash": null
  }
}
```

Input is strict and bounded. Unknown members, duplicate JSON members or auth
parameters, ambiguous supported challenges, non-canonical amounts, invalid
addresses, cross-origin resources, unsupported modes, and expired or near-expiry
challenges fail before signing. Examples use synthetic account values; obtain
real testnet terms from the server challenge.

## CLI workflow

Authorize from exactly one bounded regular file or stdin:

```bash
stellar-agent mpp charge authorize --profile default --input-file challenge.json
stellar-agent mpp charge authorize --profile default --input-stdin < challenge.json
```

If policy allows, this command prepares, atomically claims, signs, re-simulates,
audits, and returns one credential. If policy requires consent, it returns
`mpp.approval_required`, an authorization ID, and an approval ID. The operator
reviews and approves it through the normal `approve` command or approval inbox;
then resume only the stored authorization:

```bash
stellar-agent approve --id <approval-id>
stellar-agent mpp charge authorize --profile default --approval-id <approval-id>
```

The resume command accepts no replacement challenge or context. A credential is
returned at most once. If delivery is interrupted or the result is lost, query
status and reconcile; never retry commit or create a fallback payment.

```bash
stellar-agent mpp authorization status --profile default --authorization-id <authorization-id>
stellar-agent mpp receipt record --profile default --authorization-id <authorization-id> \
  --transport http --receipt-file receipt.txt
printf '%s' '<lowercase-transaction-hash>' | \
  stellar-agent mpp settlement reconcile --profile default \
    --authorization-id <authorization-id> --reference-stdin
```

State maintenance is explicit and audited. It retains live replay markers and
all indeterminate records, and removes only expired terminal records after the
30-day retention window:

```bash
printf '%s' 'scheduled retention cleanup' | \
  stellar-agent mpp state prune --profile default --reason-stdin
```

All commands return the standard JSON envelope and exit `0` only for
`{"ok":true}`. Credential-bearing output is sensitive; do not place it in logs,
shell history, telemetry, or an untrusted agent transcript.

## MCP workflow

The MCP server exposes five tools. They are available only on the full wallet
server, never through installed toolsets.

| Tool | Arguments | Result and role |
|---|---|---|
| `stellar_mpp_charge_prepare` | `profile`, tagged `challenge` | Validates, simulates, evaluates policy, persists exact terms, and returns a preview plus commit nonce. Never signs. |
| `stellar_mpp_charge_commit` | `authorization_id`, `nonce`, `expires_at_unix_ms` | Reloads stored terms, verifies approval and policy, signs once, re-simulates, audits, and returns one credential. |
| `stellar_mpp_record_receipt` | `authorization_id`, tagged `receipt` | Records a trusted-host observation. It does not prove settlement. |
| `stellar_mpp_reconcile_transaction` | `authorization_id`, `transaction_hash` | Queries RPC and independently verifies the exact final direct or fee-bump transaction and payer signature. |
| `stellar_mpp_authorization_status` | `authorization_id` | Returns redacted lifecycle, policy-accounting, receipt-observation, and ledger-outcome state. |

The commit schema deliberately has no amount, asset, recipient, payer, challenge,
or context fields. Terms cannot be replaced between prepare and commit. The
receipt and transaction hash remain required inputs at their respective tools;
the durable state retains only their digests.

## Credential delivery

An HTTP result contains an `authorization` value beginning with `Payment`; use
it as the exact `Authorization` field value on the request that was bound during
prepare. A native MCP result contains the `org.paymentauth/credential` object for
the bound operation. Do not translate a credential between transports.

The trusted host is responsible for all transport behavior:

- use HTTPS/TLS and the exact origin, method, resource, body digest, and
  idempotency binding supplied during prepare;
- keep credentials and receipts secret and out of logs;
- send the credential once and use an idempotency key where the server supports
  it;
- do not create a second payment after an ambiguous response;
- return the server receipt to the wallet; and
- use reconciliation when final ledger proof is needed.

The configured Stellar RPC sees the signed Soroban authorization during the
mandatory post-sign re-simulation. Operators must choose an RPC endpoint they
trust with that visibility.

## Authorization, receipt, and settlement

These are three separate facts:

1. **Authorized** means the wallet consumed policy budget, signed once, passed
   re-simulation and audit, and attempted one-shot credential delivery. Budget
   remains consumed even if no receipt or settlement follows.
2. **Receipt observed** means a trusted host reported a syntactically valid
   successful receipt correlated to the authorization. It is not ledger proof.
3. **Settled or failed** means RPC reconciliation found a final transaction and
   verified its hash, envelope, exact transfer invocation, payer authorization,
   signature, and ledger outcome.

`authorized_withheld` and `indeterminate` are no-fallback states. The former
means a credential was constructed but a final delivery gate failed; the latter
means key access or accounting may have begun and safe replay cannot be proven.
In both cases, inspect status and audit records and reconcile any known
transaction. Never sign again for the same charge.

Stable errors use the `mpp.*` namespace, including `mpp.challenge_invalid`,
`mpp.challenge_ambiguous`, `mpp.challenge_mismatch`, `mpp.challenge_expired`,
`mpp.unsupported_method`, `mpp.unsupported_intent`, `mpp.unsupported_mode`,
`mpp.input_too_large`, `mpp.approval_invalid`, `mpp.network_forbidden`,
`mpp.authorization_replayed`, `mpp.state_unavailable`, `mpp.simulation_failed`,
`mpp.signing_failed`, `mpp.credential_too_large`, `mpp.receipt_invalid`,
`mpp.receipt_conflict`, and `mpp.reconciliation_unavailable`.
