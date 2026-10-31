# Driving the wallet from an AI agent

See [Mainnet configurations and scope](getting-started.md#mainnet-configurations-and-scope)
for build configuration, admitted operations, and exclusions.

This guide is for an engineer wiring the Stellar Agent Wallet into an AI agent
runtime. It covers how an agent connects, the call patterns that keep funds safe,
and how operator approval fits in.

An agent talks to the wallet through the **MCP server** (`stellar-agent-mcp`),
which exposes wallet capabilities as MCP tools over stdio. A human **operator**
uses the `stellar-agent` CLI for setup, key custody, and approvals. The two share
policy-engine, approval, and audit primitives. Their handlers determine policy
coverage: MCP balance reads pass through policy, while CLI balance reads fetch
account state directly.

For the full tool catalog see [mcp.md](mcp.md); for the guardrail model see
[concepts.md](concepts.md); for signed toolsets see [toolsets.md](toolsets.md).

## The two roles

| Role | Surface | Does |
|---|---|---|
| Agent | MCP tools over stdio | Reads state, builds and submits transactions, invokes installed toolsets. |
| Operator | `stellar-agent` CLI | Creates profiles, holds keys in the platform keyring, approves gated actions, verifies the audit log. |

MCP tools return no signing keys and expose no operator approval command.
Signing keys live in the operator's platform keyring; the operator approves
requests in a trusted context. An agent with shell access has additional
authority, described in [Coding agents with a shell](#coding-agents-with-a-shell).

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

The server resolves its profile from `--profile <NAME>`, then
`STELLAR_AGENT_PROFILE`, then the name `default`; pass
`"args": ["--profile", "alice"]` to bind it to a different one. Keys are
resolved from the platform keyring named by that profile. After connecting, the
client issues `initialize`, then
`tools/list` and `resources/list`. The tool schemas returned by `tools/list` are
the authoritative argument contract. Prefer them over any example here. See
[mcp.md](mcp.md#configuring-an-mcp-client) for startup details and the resources
the server exposes.

## Every call carries `chain_id`

Every tool requires a `chain_id` argument (the CAIP-2 chain id, e.g.
`stellar:testnet`) that must match the active profile. `stellar_x402_parse_receipt`
and `stellar_toolset_list` take none, and the two SEP-43 read tools make it
optional. The five `stellar_mpp_*` tools reject a `chain_id` field as unknown;
they act on the chain of the profile the server was started with. `stellar_toolset_invoke` accepts an optional `chain_id` that it forwards
to the routed tool, which may itself require it (a routed `stellar_balances` or
`stellar_pay` does). `stellar_dex_quote` requires a `chain_id` but never
matches it against the profile; it selects the router from it. A mismatch is
refused before signing. The classic simulate and commit tools read the
endpoint and the accounts first.

## The result envelope

Every tool returns the same JSON envelope, with five success-path exceptions:

```json
{ "ok": true, "data": { }, "request_id": "..." }
```

`stellar_toolset_list` returns a bare JSON array. `stellar_dex_trade`,
`stellar_dex_quote`, `stellar_defindex_vault_deposit`, and
`stellar_defindex_vault_withdraw` return a bare object carrying a `status`
field on success. Their business errors use the envelope.

Some refusals use the JSON-RPC error channel instead of the envelope: invalid
arguments, a `chain_id` mismatch, and the toolset capability refusals.
`toolset.first_invoke_approval_required` is a JSON-RPC error too, and its error
data carries the `approval_nonce`.

On failure, `ok` is `false` and `error` carries a stable wire `code` (such as
`policy.deny.<reason>` or `policy.approval_required`) instead of `data`. Branch on
`ok`; use `code` for control flow, not the human message. The `request_id`
correlates the call with the audit log.

Three codes carry an `error.details` object as well: `submission.tx_timeout`,
`submission.tx_already_submitted` and `submission.hash_mismatch`. Each reports
a submission whose outcome is unknown, and resolving one needs the full
transaction hash that the message redacts. `details` carries that hash and the
verb or tool that reconciles it. No other code carries `details`, and the field
is absent from the envelope when it is not set.

A `submission.tx_timeout` submission may still apply, whether the deadline
passed or a transport failure struck during or after the send. Settle it by
passing `details.tx_hash` to `stellar_transaction_status` (or
`stellar-agent tx status`), and never resubmit: no recovery path sends a
transaction again.

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
`stellar_create_account`, `stellar_trustline`, and `stellar_claim` (each paired
with a `*_commit`).

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
approves. See below.

## When approval is required

A `RequireApproval` verdict (a V1 policy rule or any toolset-routed payment)
routes through the operator. The handshake:

1. The build/simulate call returns an `approval` block carrying an
   `approval_nonce` instead of executing.
2. The operator runs `stellar-agent approve --id <approval_nonce> --profile <name>` in a trusted
   context, reviews the wallet-rendered summary, and consents. The command
   returns an `approval_attestation`, an HMAC blob bound to that exact envelope.
3. The operator relays the `approval_attestation` to the agent over a trusted
   channel. The agent re-invokes the commit with `approval_nonce` and
   `approval_attestation` added. The wallet verifies the attestation against its
   keyring-held key, then signs and submits.

An agent limited to MCP cannot mint the attestation; the approval key stays in
the operator's keyring.
A commit that reaches the gate without a valid attestation is refused with
`policy.approval_required` (the same envelope whether the attestation is absent,
forged, or expired, so a caller learns nothing from the failure). Treat
`policy.approval_required` as "ask the operator to approve, then retry the commit"
and never as a transient error to retry blindly.

## Mainnet actions and refusal recovery

Released binaries have `mainnet-write` on. The server admits
`stellar_pay_commit`, `stellar_claim_commit`, `stellar_create_account_commit`,
and `stellar_trustline_commit` after operator setup. Every action needs approval,
even under an Allow rule. Both prepare and commit names need policy rules.

The operator enrolls identities, runs `profile enable-mainnet`, completes the
v2 policy, and runs `profile sign-policy`. Restart the MCP server afterward.
A stale startup binding reports `network.mainnet_write_forbidden` with
`enablement or policy changed, restart the server`. Missing startup authority
instead names its missing prerequisite. Unsupported tools and contexts use the
same wire code. The version marker reports compiled state, not setup completion.

CLI engine construction preserves enablement errors and wraps other failures as
`policy.engine_unavailable` or `trustline.policy_engine_unavailable`.
Evaluation failure uses `policy.engine_required`; unknown decisions use
`policy.unexpected_decision`. Policy denials retain `policy.deny.*`.

After `network.mainnet_authorization_refused`, report the refusal to the operator.
Do not switch networks. A retry requires fresh preparation and fresh approval.
The operator reads the failed check in the `precondition` field of the warn-level
log entry `mainnet authorization refused`.

CLI refusal messages distinguish signature withholding from submission refusal
after signing. The signature message is
`the mainnet write was refused; the signature was withheld and nothing was sent`.
A signer can run before its result is rejected. Classic MCP uses
`the mainnet write was refused before submission; nothing was sent`.
A submission timeout has an unknown outcome. Reconcile it with
`stellar_transaction_status`; do not apply authorization-refusal retry guidance.

## Using installed toolsets

A [toolset](toolsets.md) declares a narrow set of capabilities that the toolset
dispatcher routes for the agent. It narrows only the dispatcher's routes, not the
other tools of the server, and the `toolset` argument is yours to choose; the
operator policy and approvals bound every call. Two tools drive them:

- `stellar_toolset_list`: enumerate installed toolsets and their invocable actions.
- `stellar_toolset_invoke`: run a named action, routed through capability
  enforcement to a trusted tool.

```json
{
  "toolset": "balance-reporter",
  "action": "stellar_balances",
  "chain_id": "stellar:testnet",
  "args": { "account_id": "GABC..." }
}
```

No signing, key, or policy tool is reachable through an ungated capability, so
an `action` naming one returns `toolset.unknown_action`. A toolset whose install
record does not verify returns `toolset.pin_unverifiable`; the operator
uninstalls and installs it again. `stellar_toolset_invoke` is a destructive tool
and is refused on a mainnet profile. Two signing-adjacent
capabilities route through the gated path: `sign-payment` reaches
`stellar_pay_commit`, and `sign-rule-create` reaches `stellar_rule_create_commit`
(agent-proposed context rules). Each is guarded by a first-invoke gate. The
first use with no matching grant returns `toolset.first_invoke_approval_required`
with a nonce for the operator to approve. And for `sign-payment` an
unconditional per-action approval additionally fires on every toolset-routed
payment regardless of policy. To drive a payment, invoke `action: "stellar_pay"`
to build the envelope, then `action: "stellar_pay_commit"` with `args` carrying
the `envelope_xdr` (and `nonce`, `expires_at_unix_ms`) returned by that build. See
[toolsets.md](toolsets.md) and the runnable [examples](../examples/toolsets/README.md).

## Agent-payments (x402)

The wallet signs x402 v2 Exact Stellar payments without submitting:
`stellar_x402_create_payment` constructs and signs a `PAYMENT-SIGNATURE` from a
`PaymentRequirements` object; `stellar_x402_authenticated_payment` adds a SEP-10
identity gate against a `home_domain` first; `stellar_x402_parse_receipt` decodes
the settlement receipt. See [protocols.md](protocols.md) for the flow.

On an admitted mainnet server, call either payment tool without approval
arguments to obtain pending approval. After CLI approval, repeat the same request
with both approval arguments. For authenticated payments, keep the approved home
domain unchanged.

## Sponsored MPP charges

For an MPP Payment challenge, call `stellar_mpp_charge_prepare` with the exact
HTTP or MCP request context. Prepare records a pending approval when policy
requires approval for either `stellar_mpp_charge_prepare` or
`stellar_mpp_charge_commit`. Review the returned preview and nonce. If approval
is required, wait for the operator; then call `stellar_mpp_charge_commit` once
with only the authorization ID and returned nonce fields. Deliver the resulting
credential only through the trusted host to the exact bound request.

Never retry commit, alter terms, switch transports, route MPP through a toolset,
or create an x402/classic-payment fallback after an ambiguous result. Use
`stellar_mpp_authorization_status`, record a host receipt, and reconcile the
server transaction instead. The complete testnet-only workflow is in
[Agent payments with MPP](agent-payments.md).

## Coding agents with a shell

A process that runs as the operator's OS user holds the operator's authority.
Through the CLI it can re-enroll the owner key of an installation that holds no
owner continuity records, a policy pin or a mainnet enablement nonce, and then
sign a policy of its own. With direct access to files and keyring entries it can
delete the halt marker, and on Linux and Windows read the keyring entries. The
wallet does not distinguish such a process from the operator.

An MCP-only host reaches only wallet tools: signed policy applies where
evaluated, approval separates agent and operator, and the halt and audit log
hold. The MCP server exposes paired request and commit tools over the core the
CLI also uses.
On testnet, CLI approval checks the local OS identity; it reads consent from
standard input or `--yes` and does not establish that a human confirmed. On
mainnet it refuses `--yes` and terminal input and runs the passkey ceremony,
which requires a verified passkey assertion from an approval credential in the
owner-signed policy.

Delegated execution runs through the CLI's operator authority under the agent
key's on-chain rules. Other signing paths have distinct policy and
pending-approval checks; see
[CLI signing coverage](../skills/stellar-agent-wallet/references/cli-reference.md#signing-and-approval-coverage).
Without `per_tx_cap`, an `approval_above` rule has no per-payment ceiling;
period caps still deny.

Every transaction-signing or submitting verb checks the halt marker, including
smart-account governance, deployment, and `pool init`.
Reads, key, policy, and approval ceremonies, and CLI state recording and
reconciliation stay usable; see [Halt marker](profiles.md#halt-marker).
Audit events carry request IDs that connect related rows; see the
[hash-chained audit log](concepts.md#the-hash-chained-audit-log).

Current limits of the OS-user boundary:

- Owner key re-enrollment needs no previous seed while the installation holds
  no owner continuity records. Replacing an owner protected by these records
  requires a policy signed by the new owner with a rotation statement signed by
  the pinned owner.
- The profile's `[policy] engine` and `policy_owner_key_id` fields are unsigned.
- The halt marker has no MAC.
- `profile reset-window-state` requires no owner signature until
  `profile enable-mainnet` has run. An enabled installation requires the pinned
  owner's authorization through `--owner-secret-env`.
- These rules bind the wallet's commands. Deleting or rewriting the pin, the
  enablement nonce, or the owner entry outside the wallet rests on the platform
  keyring.
- Same-user processes can read keyring entries on Linux (Secret Service) and
  Windows (Credential Manager). With the `headless-env` backend, any process that
  can read `STELLAR_AGENT_HEADLESS_KEYRING_KEY` can decrypt every entry, on any
  platform.

**Default permission prompts.** Review the pending request before permitting
CLI approval. Shell prompts are a guard rail for a cooperative agent, not a
boundary.

**Deny rules.** Use MCP for agent actions and a separate operator approval
surface. Deny rules apply in every mode. The list covers authority, keys,
policy state, and `pool init`.
Only `pool init` signs transactions with the agent's enrolled MCP signer
without evaluating wallet policy; it creates channel accounts with sponsored
reserves and zero starting balances.

```json
{
  "permissions": {
    "deny": [
      "Bash(stellar-agent approve *)",
      "Bash(stellar agent approve *)",
      "Bash(stellar-agent profile resume *)",
      "Bash(stellar agent profile resume *)",
      "Bash(stellar-agent profile enroll-signer *)",
      "Bash(stellar agent profile enroll-signer *)",
      "Bash(stellar-agent profile enroll-owner-key *)",
      "Bash(stellar agent profile enroll-owner-key *)",
      "Bash(stellar-agent profile enroll-rpc-credential *)",
      "Bash(stellar agent profile enroll-rpc-credential *)",
      "Bash(stellar-agent profile sign-policy *)",
      "Bash(stellar agent profile sign-policy *)",
      "Bash(stellar-agent profile rotate-nonce-key *)",
      "Bash(stellar agent profile rotate-nonce-key *)",
      "Bash(stellar-agent profile rotate-attestation-key *)",
      "Bash(stellar agent profile rotate-attestation-key *)",
      "Bash(stellar-agent profile rotate-audit-key *)",
      "Bash(stellar agent profile rotate-audit-key *)",
      "Bash(stellar-agent profile rotate-counterparty-key *)",
      "Bash(stellar agent profile rotate-counterparty-key *)",
      "Bash(stellar-agent counterparty rotate-hmac-key *)",
      "Bash(stellar agent counterparty rotate-hmac-key *)",
      "Bash(stellar-agent profile rotate-policy-state-key *)",
      "Bash(stellar agent profile rotate-policy-state-key *)",
      "Bash(stellar-agent profile reset-window-state *)",
      "Bash(stellar agent profile reset-window-state *)",
      "Bash(stellar-agent profile reset-mpp-state *)",
      "Bash(stellar agent profile reset-mpp-state *)",
      "Bash(stellar-agent pool init *)",
      "Bash(stellar agent pool init *)",
      "Bash(stellar-agent credentials add-passkey *)",
      "Bash(stellar agent credentials add-passkey *)",
      "Bash(stellar-agent credentials delete *)",
      "Bash(stellar agent credentials delete *)",
      "Bash(stellar-agent audit reanchor *)",
      "Bash(stellar agent audit reanchor *)",
      "Bash(stellar-agent toolsets install *)",
      "Bash(stellar agent toolsets install *)",
      "Bash(stellar-agent toolsets uninstall *)",
      "Bash(stellar agent toolsets uninstall *)"
    ]
  }
}
```

Absolute paths such as `~/.cargo/bin/stellar-agent` and shell wrappers such as
`sh -c` can escape these prefixes. `profile halt` stays allowed.

**Bypass permissions.** With `bypassPermissions`, the deny list is the only
permission-rule guard rail, and it still applies. A denying `PreToolUse` hook
also blocks in every mode.

## Operating safely

- Branch on `ok` and the error `code`, not the human message.
- Expect `policy.deny.*`, `policy.approval_required`, and `policy.engine_required`
  as normal control flow, not failures to retry.
- Never try to get under a limit by re-submitting a commit with altered amounts;
  the gate matches the authoritative envelope. Audit rows come from explicit
  submission, signing, approval, key-management, and lifecycle events; early
  refusals do not automatically write a row.
- The operator verifies the tamper-evident log with
  `stellar-agent audit verify <LOG_PATH> --profile <NAME>`.
  Raw argument values are never logged; only key names are. Typed event fields do
  keep data: a value-moving row records each leg's amount, asset, and redacted
  destination.
- A commit/submit tool refuses `audit.chain_key_unavailable` if the profile's audit
  chain-root key was never minted (an `init`-minted profile, before the operator runs
  `rotate-audit-key`). This is an operator setup gap, not agent misuse: report the
  error back and stop retrying until the operator has minted the key.
