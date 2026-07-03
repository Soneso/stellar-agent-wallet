# Troubleshooting (wire and error codes)

Reference for the stable wire and error codes the Stellar Agent Wallet returns,
and the action an agent should take for each. The wallet places fixed controls
between every tool call and any network or signing action: a policy engine, an
out-of-band operator-approval step, single-use nonces, and a tamper-evident
audit log. Error codes are typed and stable; recover by code, not by message
text.

## The result envelope

Tool and command results use a uniform envelope:

```json
{ "ok": true,  "data": { /* result */ }, "request_id": "..." }
{ "ok": false, "error": { "code": "policy.deny.per_tx_cap_exceeded", "...": "..." }, "request_id": "..." }
```

- `ok` is `true` on success, `false` on any failure.
- `data` is present only when `ok` is `true`; `error` only when `ok` is `false`.
- `error.code` is the stable wire code. Branch on it.
- `request_id` correlates the call with the audit log. Quote it when asking the
  operator to investigate.

At the MCP boundary, account, strkey, and contract-id fields inside an error are
redacted to first-five-last-five characters, and transaction hashes to
first-eight-last-eight. The wallet never logs argument values, only argument key
names.

## Argument-format reminders (prevent most input errors)

- `chain_id` is the CAIP-2 id, `stellar:testnet` (default) or `stellar:mainnet`.
  Most MCP tools require it and it must match the active profile. (Exceptions:
  `stellar_x402_parse_receipt`, `stellar_toolset_list`, `stellar_toolset_invoke`
  take no `chain_id`; `stellar_sep43_get_address` and `stellar_sep43_get_network`
  treat it as optional, defaulting to the profile chain, still validated when
  supplied.)
- Amounts are decimal strings with an explicit unit, e.g. `"10 XLM"`,
  `"10.5 USDC"`. Never a JSON number; raw stroop strings are rejected.
- Asset is `"native"` / `"XLM"` for the native asset, or `"CODE:GISSUER"` for an
  issued asset.

## Policy-engine codes

The policy engine evaluates every call before any RPC or signing, returning
Allow, Deny, or RequireApproval. The Noop engine allows everything on testnet,
allows read-only on mainnet, and refuses destructive tools on mainnet. The V1
engine is first-match, default-deny over signed, typed criteria.

| Code | Meaning | Agent action |
|---|---|---|
| `policy.deny.<reason>` | A V1 criterion denied the call (`<reason>` is the typed reason: `per_tx_cap_exceeded`, `per_period_cap_exceeded`, `rate_limit_exceeded`, `counterparty_denied`, `minimum_reserve_breached`, `no_matching_rule`). The payload carries the redacted reason. | Do not retry as-is; the policy forbids this operation. Report the reason to the operator. Only the operator can change policy. |
| `policy.approval_required` | A two-phase signing verb reached its commit step without a valid operator approval, or the attestation was absent, invalid, or expired. This single code intentionally covers every approval-path failure mode (missing, expired, wrong-kind, hash mismatch, HMAC mismatch) so callers cannot probe which. | Ask the operator to run `stellar-agent approve --id <nonce>`, then re-submit the commit with the returned `approval_nonce` and `approval_attestation`. The nonce came from the simulate step. |
| `policy.approval_required_unsupported` | The policy returned RequireApproval for a single-shot sign tool (no simulate/commit split: SEP-43 sign verbs, `stellar_sep43_sign_and_submit_transaction`, SEP-53 `sign_message`, x402 `create_payment` / `authenticated_payment`). The wallet refuses fail-closed rather than sign without approval. | Cannot proceed via the agent. Ask the operator to either adjust policy so this operation does not require approval, or perform it through a two-phase tool (`stellar_pay`, `stellar_create_account`, `stellar_trustline` and their `*_commit`). |
| `policy.engine_required` | The active engine cannot decide the call. Fires for the Noop engine on a destructive tool on `stellar:mainnet`, and for V1 engine errors such as a missing or unverifiable policy document. | Do not retry on mainnet (writes are structurally refused in this alpha; use `stellar:testnet`). Otherwise the profile needs a valid V1 policy installed by the operator. |
| `policy.unexpected_decision` | Forward-compatibility catch-all for an engine decision the gate does not recognize. Fail-closed. | Treat as a hard refusal. Report to the operator; do not retry. |

Separately, every write or signing command refuses `stellar:mainnet` before any
RPC call or signing with `network.mainnet_write_forbidden`. Read-only commands
accept mainnet. Action: run write and signing operations on `stellar:testnet` in
this alpha.

## Nonce codes (two-phase signing verbs)

A simulate step (`stellar_pay`, `stellar_create_account`, `stellar_trustline`)
mints a single-use nonce bound to the exact envelope, tool, and chain. The
commit step (`*_commit`) verifies it. Nonces are single-use and TTL-bounded, and
the replay window is wiped on process restart.

| Code | Meaning | Agent action |
|---|---|---|
| `nonce.expired` | The nonce passed its expiry, or its HMAC tag does not match (these two are deliberately indistinguishable; the second covers a wrong envelope/tool/chain or a process restart since mint). | Re-run the simulate step to obtain a fresh nonce and envelope, then commit promptly. |
| `nonce.replayed` | The nonce was already consumed. Each nonce signs exactly once. | Re-simulate for a new nonce. Do not re-send the same commit. |
| `nonce.chain_mismatch` | The `chain_id` supplied to commit differs from the profile / the nonce's chain. | Re-issue with the profile's `chain_id` for both simulate and commit. |
| `nonce.invalid_envelope` | The envelope XDR is empty or cannot be hashed. | Pass the exact `envelope_xdr` returned by the simulate step; do not modify it. |
| `nonce.ttl_exceeded` | The requested TTL exceeds the profile maximum. | Request a shorter TTL within the profile bound. |
| `nonce.ttl_too_short` | The requested TTL is below the minimum floor. | Request a longer TTL at or above the floor. |
| `nonce.key_too_short` | The keyring nonce key has fewer than 32 bytes. | Operator must repair the keyring nonce key. Not agent-recoverable. |
| `nonce.input_too_long` | A length-prefixed field (`tool_name` or `chain_id`) exceeds the encoding bound. | Use a valid registered tool name and a valid CAIP-2 `chain_id`. |
| `nonce.serialise_failed` | Base64 encode/decode of the nonce failed. | Pass the nonce string exactly as returned by simulate. |
| `tool.unknown` | The `tool_name` carried by the nonce is not in the registered catalog. | Use a registered tool name; do not hand-build nonces. |
| `nonce.unknown_error` | Forward-compatibility fallback for an unrecognized nonce error variant. | Treat as a hard failure; re-simulate. Report to the operator if it persists. |

Note: a wrong, edited, or stale envelope at commit surfaces as `nonce.expired`,
not a distinct code. The commit step also byte-compares the envelope against a
fresh rebuild before signing.

## Simulation cross-check

| Code | Meaning | Agent action |
|---|---|---|
| `simulation.divergence` | An independent-RPC cross-check (run for high-value operations and toolset-routed payments) failed: the second RPC rebuilt a different envelope, was unreachable, or timed out. Fail-closed; the wallet will not sign. | Re-simulate to obtain a fresh envelope and retry. If it persists, the two RPC endpoints disagree; report to the operator. |

## Toolset codes

`stellar_toolset_invoke` routes a toolset action to a registered tool through a
four-part capability gate. Signing tools are never reachable through a toolset
regardless of declared capabilities; the routed tool's own policy gate still
applies.

| Code | Meaning | Agent action |
|---|---|---|
| `toolset.first_invoke_approval_required` | The first time a toolset uses a signing-adjacent capability with no matching grant, a one-time gate fires and queues an approval. | Ask the operator to approve the queued entry with `stellar-agent approve --id <nonce>`. Once approved, a time-boxed grant suppresses only this re-prompt; the per-action payment approval still fires on every payment. |
| `toolset.unknown_action` | The action is not in the toolset's capability-to-tool matrix. | Call `stellar_toolset_list` to see the toolset's invocable actions; use one of those. |
| `toolset.capability_not_declared` | The toolset's manifest does not declare the capability needed to grant this action. | The toolset cannot perform this action. Report to the operator; do not retry. |
| `toolset.tool_not_allowed` | The resolved tool is excluded by the toolset's `allowed_tools` narrowing. | The toolset is configured not to use that tool. Report to the operator. |
| `toolset.not_installed` | The named toolset is not installed. | Verify the toolset name with `stellar_toolset_list`; install via the operator if missing. |
| `toolset.gated_missing_envelope` | A toolset sign-payment route was called without `args.envelope_xdr`. | Run `stellar_pay` (simulate) first and pass its `envelope_xdr` into the gated invoke. |
| `toolset.args_not_object` | `args` was not a JSON object. | Pass `args` as a JSON object. |
| `toolset.args_validation` / `toolset.args_deserialise` / `toolset.gated_args_deserialise` | The toolset arguments failed validation or deserialization. | Fix the argument shape to match the routed tool's schema and retry. |
| `toolset.route_missing` / `toolset.gated_route_missing` | No tool route resolved for the action. | Re-check the action name with `stellar_toolset_list`. |

## MCP server availability

| Code | Meaning | Agent action |
|---|---|---|
| `mcp.disabled_per_profile` | The active profile sets `mcp_disabled = true`, the operator kill-switch. The server refuses to start (exits non-zero); no tool calls are served. | The MCP surface is disabled for this profile. Ask the operator to select a profile with the MCP surface enabled, or clear the kill-switch. The `mcp-resource://profiles/<name>` resource reports `mcp_disabled`. |

Other startup failures (no supported platform keyring backend, an unloadable
profile, a duplicate tool registration) also cause the process to exit non-zero
before serving any request. These are operator-side environment problems, not
agent-recoverable at runtime.

## Keyring codes

| Code | Meaning | Agent action |
|---|---|---|
| `keyring.error` | A platform keyring read failed while loading the nonce key or an HMAC key on a two-phase verb. | Often the active profile names a keyring entry that holds no secret yet (the first-run testnet fallback profile uses placeholder coordinates). Read-only tools and the simulate step still work; the commit step does not until the operator populates the keyring entry. Report to the operator. |

A missing or empty **signer** keyring entry on a single-shot SEP-43 sign tool
surfaces as a SEP-43 error envelope (a wallet-unlock failure), not a `keyring.*`
code. At the auth layer a missing keyring entry maps to `auth.keyring_not_found`.
In every case the operator must enroll the secret for the active profile.

Keyring failures on the attestation key during a commit do not surface as a
keyring code: they are folded into the uniform `policy.approval_required` so the
approval path cannot be probed. Recovery is the same as for any
`policy.approval_required`.

## SEP-24 interactive POST contract

`stellar_sep24_interactive_url` performs the interactive deposit/withdraw
hand-off by `POST .../transactions/{op}/interactive` with a caller-supplied
SEP-10/45 JWT, and returns the interactive URL, transaction id, and a hand-off
note. The wallet never opens, scrapes, or follows the URL and transmits no KYC
field.

Wire-contract note for anyone building the request the wallet relays: the
interactive POST body must be sent as `application/json` (form-urlencoded is
rejected by Anchor Platform with HTTP 500), and every value must be a JSON
string, not a native JSON type:

- `amount` is a string (`"10"`, not `10`).
- `claimable_balance_supported` is the string `"true"` / `"false"`, not a
  boolean.

If the anchor returns HTTP 500 on a request that looks correct, suspect a
form-urlencoded body or a non-string field value.

## Recovery quick reference

- Approval needed (`policy.approval_required`, `toolset.first_invoke_approval_required`):
  ask the operator to run `stellar-agent approve --id <nonce>`, then re-submit
  the commit with `approval_nonce` and `approval_attestation`.
- Approval not honorable on this tool (`policy.approval_required_unsupported`):
  operator must change policy or use a two-phase tool.
- Stale or used nonce (`nonce.expired`, `nonce.replayed`),
  cross-check failure (`simulation.divergence`): re-run the simulate step and
  commit promptly.
- Hard policy refusal (`policy.deny.*`, `policy.engine_required`,
  `network.mainnet_write_forbidden`): do not retry; only the operator can change
  policy or network posture.
- Environment or key problems (`keyring.*`, `mcp.disabled_per_profile`, other
  non-zero startup exits): operator-side; not agent-recoverable at runtime.
