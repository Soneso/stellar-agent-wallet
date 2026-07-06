# Driving the wallet from an AI agent

This guide is for an engineer wiring the Stellar Agent Wallet into an AI agent
runtime. It covers how an agent connects, the call patterns that keep funds safe,
and how operator approval fits in.

An agent talks to the wallet through the **MCP server** (`stellar-agent-mcp`),
which exposes wallet capabilities as MCP tools over stdio. A human **operator**
uses the `stellar-agent` CLI for setup, key custody, and approvals. The two share
one policy engine, approval spine, and audit log, so a tool call is gated exactly
as the equivalent CLI command is. The CLI is the source of truth; the MCP surface
is a transport over the same dispatch path.

For the full tool catalog see [mcp.md](mcp.md); for the guardrail model see
[concepts.md](concepts.md); for signed toolsets see [toolsets.md](toolsets.md).

## The two roles

| Role | Surface | Does |
|---|---|---|
| Agent | MCP tools over stdio | Reads state, builds and submits transactions, invokes installed toolsets. |
| Operator | `stellar-agent` CLI | Creates profiles, holds keys in the platform keyring, approves gated actions, verifies the audit log. |

The agent never holds key material and never approves its own actions. Signing
keys live in the operator's platform keyring; approvals are minted by the
operator running `stellar-agent approve` in a trusted context.

## Connect the MCP server

The client spawns the binary as a subprocess and exchanges JSON-RPC over its
stdin/stdout. A generic client stanza:

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
`tools/list` and `resources/list`. The tool schemas returned by `tools/list` are
the authoritative argument contract — prefer them over any example here. See
[mcp.md](mcp.md#configuring-an-mcp-client) for startup details and the resources
the server exposes.

## Every call carries `chain_id`

Every tool requires a `chain_id` argument (the CAIP-2 chain id, e.g.
`stellar:testnet`) that must match the active profile. `stellar_x402_parse_receipt`
and `stellar_toolset_list` take none, and the two SEP-43 read tools make it
optional. `stellar_toolset_invoke` accepts an optional `chain_id` that it forwards
to the routed tool, which may itself require it (a routed `stellar_balances` or
`stellar_pay` does). A mismatch is refused before any network call.

## The result envelope

Every tool returns the same JSON envelope:

```json
{ "ok": true, "data": { }, "request_id": "..." }
```

On failure, `ok` is `false` and `error` carries a stable wire `code` (such as
`policy.deny.<reason>` or `policy.approval_required`) instead of `data`. Branch on
`ok`; use `code` for control flow, not the human message. The `request_id`
correlates the call with the audit log.

## Tool shapes

Each tool is read-only, signs without submitting, or signs and submits; the
[catalog](mcp.md#tool-catalog) marks every tool so the classification stays in
one place. Only the sign-and-submit tools move funds and run the full gate: the
two-phase payment verbs, the DeFi tools, and
`stellar_sep43_sign_and_submit_transaction`. Read-only tools are safe to call
freely; sign-without-submit tools (the other SEP-43 signing tools and
`stellar_x402_create_payment`) return a signature the caller forwards elsewhere.

## The two-phase signing pattern

Fund-moving classic verbs split into a **build/simulate** call and a **commit**
call. This is the core safe pattern; follow it for `stellar_pay`,
`stellar_create_account`, and `stellar_trustline` (each paired with a `*_commit`).

1. **Build.** Call `stellar_pay` with the payment fields. It builds an unsigned
   envelope, runs the SEP-29 memo check, mints a single-use nonce, and returns
   `envelope_xdr`, `nonce`, and `expires_at_unix_ms`. Nothing is signed.

   ```json
   {
     "chain_id": "stellar:testnet",
     "source": "GABC...",
     "destination": "GDEF...",
     "amount": "10 XLM",
     "asset": "native"
   }
   ```

2. **Commit.** Call `stellar_pay_commit` with the same payment fields plus the
   `nonce`, `expires_at_unix_ms`, and `envelope_xdr` from step 1. The wallet
   re-derives the authoritative destination, asset, and amount from the envelope
   (never from re-supplied arguments), verifies the nonce, signs from the
   keyring, and submits. On success `data` carries `tx_hash` and `ledger`.

If the policy engine allows the action outright, the commit signs and submits
directly. If it returns `RequireApproval`, the commit is held until the operator
approves — see below.

## When approval is required

A `RequireApproval` verdict (a V1 policy rule, the high-value cross-check, or any
toolset-routed payment) routes through the operator. The handshake:

1. The build/simulate call returns an `approval` block carrying an
   `approval_nonce` instead of executing.
2. The operator runs `stellar-agent approve --id <approval_nonce>` in a trusted
   context, reviews the wallet-rendered summary, and consents. The command
   returns an `approval_attestation` — an HMAC blob bound to that exact envelope.
3. The operator relays the `approval_attestation` to the agent over a trusted
   channel. The agent re-invokes the commit with `approval_nonce` and
   `approval_attestation` added. The wallet verifies the attestation against its
   keyring-held key, then signs and submits.

The agent cannot mint or guess the attestation; the key never leaves the keyring.
A commit that reaches the gate without a valid attestation is refused with
`policy.approval_required` (the same envelope whether the attestation is absent,
forged, or expired, so a caller learns nothing from the failure). Treat
`policy.approval_required` as "ask the operator to approve, then retry the commit"
— never as a transient error to retry blindly.

## Mainnet is read-only by default

On `stellar:mainnet` the default Noop engine allows read-only tools and refuses
every fund-moving tool with `policy.engine_required`, before any RPC call or
signing. Writes on mainnet require the operator to rotate keys and opt in to the
V1 engine (see [profiles.md](profiles.md)). Design the agent to expect refusal of
mainnet writes until the operator has done so.

## Using installed toolsets

A [toolset](toolsets.md) grants the agent a narrow, declared set of capabilities. Two
tools drive them:

- `stellar_toolset_list` — enumerate installed toolsets and their invocable actions.
- `stellar_toolset_invoke` — run a named action, routed through capability
  enforcement to a trusted tool.

```json
{
  "toolset": "balance-reporter",
  "action": "stellar_balances",
  "chain_id": "stellar:testnet",
  "args": { "account_id": "GABC..." }
}
```

No signing, key, or policy tool is reachable through any capability, so an
`action` naming one returns `toolset.unknown_action`. Two signing-adjacent
capabilities route through the gated path: `sign-payment` reaches
`stellar_pay_commit`, and `sign-rule-create` reaches `stellar_rule_create_commit`
(agent-proposed context rules). Each is guarded by a first-invoke gate — the
first use with no matching grant returns `toolset.first_invoke_approval_required`
with a nonce for the operator to approve — and for `sign-payment` an
unconditional per-action approval additionally fires on every toolset-routed
payment regardless of policy. To drive a payment, invoke `action: "stellar_pay"`
to build the envelope, then `action: "stellar_pay_commit"` with `args` carrying
the `envelope_xdr` (and `nonce`, `expires_at_unix_ms`) returned by that build. See
[toolsets.md](toolsets.md) and the runnable [examples](../examples/toolsets/).

## Agent-payments (x402)

The wallet signs x402 v2 Exact Stellar payments without submitting:
`stellar_x402_create_payment` constructs and signs a `PAYMENT-SIGNATURE` from a
`PaymentRequirements` object; `stellar_x402_authenticated_payment` adds a SEP-10
identity gate against a `home_domain` first; `stellar_x402_parse_receipt` decodes
the settlement receipt. See [protocols.md](protocols.md) for the flow.

## Operating safely

- Branch on `ok` and the error `code`, not the human message.
- Expect `policy.deny.*`, `policy.approval_required`, and `policy.engine_required`
  as normal control flow, not failures to retry.
- Never try to get under a limit by re-submitting a commit with altered amounts;
  the gate matches the authoritative envelope and the audit log records every
  attempt.
- The operator verifies the tamper-evident log with `stellar-agent audit verify`.
  Argument values are never logged — only key names — so passing data through the
  wallet does not leak it into the audit trail.
