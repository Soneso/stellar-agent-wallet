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
- By default every CLI command prints exactly one envelope on stdout and exits
  `0` on success, `1` on any error. An argument the parser refuses (an unknown flag,
  a missing required flag, a malformed value) returns `validation.usage_error`
  with the parser's message; correct the invocation and retry. `--help` and
  `--version` print text, not an envelope.

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
| `policy.deny.unsizable_value_effect` | A value rule matched a tool whose value cannot be sized, including the raw signing tools. | Size the call through a supported verb, or ask the operator to set `allow_opaque_signing = true` on the matched rule if raw signing is intended. |
| `trustline.clawback_opt_in_required` | Trusting a clawback-enabled issuer requires a recorded operator opt-in. | Ask the operator to run the printed `stellar-agent approve --id <nonce> --profile <name>` opt-in, then re-invoke. |
| `policy.approval_required` | A two-phase signing verb reached its commit step without a valid operator approval, or the attestation was absent, invalid, or expired. This single code intentionally covers every approval-path failure mode (missing, expired, wrong-kind, hash mismatch, HMAC mismatch) so callers cannot probe which. | Ask the operator to run `stellar-agent approve --id <nonce> --profile <name>`, then re-submit the commit with the returned `approval_nonce` and `approval_attestation`. The nonce came from the simulate step. |
| `policy.approval_required_unsupported` | The policy returned RequireApproval for a single-shot sign tool (no simulate/commit split: SEP-43 sign verbs, `stellar_sep43_sign_and_submit_transaction`, SEP-53 `sign_message`, x402 `create_payment` / `authenticated_payment`). The wallet refuses fail-closed rather than sign without approval. | Cannot proceed via the agent. Ask the operator to either adjust policy so this operation does not require approval, or perform it through a two-phase tool (`stellar_pay`, `stellar_create_account`, `stellar_trustline`, `stellar_claim`, `stellar_rule_create` and their `*_commit`). |
| `policy.engine_required` | The active engine cannot decide the call. Fires for the Noop engine on a destructive tool on `stellar:mainnet`, and for V1 engine errors such as a missing or unverifiable policy document. | Do not retry on mainnet (writes are structurally refused in this alpha; use `stellar:testnet`). Otherwise the profile needs a valid V1 policy installed by the operator. |
| `policy.unexpected_decision` | Forward-compatibility catch-all for an engine decision the gate does not recognize. Fail-closed. | Treat as a hard refusal. Report to the operator; do not retry. |

Separately, every write or signing command refuses `stellar:mainnet` before any
RPC call or signing with `network.mainnet_write_forbidden`, except MPP, which
refuses with `mpp.network_forbidden`. Read-only commands accept mainnet. Action: run write and signing operations on `stellar:testnet` in
this alpha.

## Network-binding codes (submit layer)

Before it sends, the submit layer asks the RPC endpoint which network it serves
and binds the submission to that answer, not to the declared network or
`chain_id`. It then verifies every signature on the envelope against the network
the endpoint reported. On the two-phase commit tools this runs before the
single-use nonce is burned, so a refusal here leaves the nonce usable.

| Code | Meaning | Agent action |
|---|---|---|
| `network.endpoint_network_mismatch` | The endpoint serves a different network than the one declared (an RPC URL and a `chain_id` / network passphrase that disagree). | Do not retry as-is. Report to the operator: the profile's `rpc_url` and its network do not name the same chain. |
| `network.endpoint_identity_unavailable` | The endpoint's network identity could not be established within the submission timeout. The probe is retried with bounded backoff and never falls back to the declared network. | Nothing was sent. Treat the endpoint as unusable and surface it to the operator; do not switch to a different endpoint on your own. |
| `network.envelope_signed_for_mainnet` | A signature on the envelope was made for mainnet, not for the network the endpoint serves. | Do not retry; the envelope cannot be relayed onto this chain. Re-run the simulate step for the intended network. |
| `network.envelope_signature_unverifiable` | A signature verifies under neither the endpoint's network nor mainnet, or no eligible ed25519 signer accounts for it (hash-x and pre-auth-tx signers contribute no ed25519 key). | Do not retry the same envelope. Re-run the simulate step and sign with a key the source account lists as a signer. |
| `network.envelope_unsigned` | The envelope carries no signature, or on a fee-bump the outer or the inner transaction carries none; typically a build-only envelope handed straight to a submit step. | Sign the envelope first, then submit. On a fee-bump, both the inner transaction and the fee source must sign. |
| `network.account_not_found` | A transaction-source or operation-source account on the envelope is absent from the ledger, so its signer set cannot be read. | Nothing was sent. Confirm the account exists and is funded on the target network. |

## Friendbot code

| Code | Meaning | Agent action |
|---|---|---|
| `network.friendbot_account_already_funded` | Friendbot refused to fund the account because it already exists and is funded. `stellar-agent friendbot`, `accounts create --fund-with-friendbot`, and `stellar_friendbot` report it; the message names the account. | Do not retry. The account is usable as it is: continue with it, or fund a new account if a fresh one was intended. |

## Submission codes (unresolved outcomes)

Every value-moving verb records its transaction before it is sent: a submission
receipt, a spending-window reservation, and a `value_action_pending` audit row.
A submission whose outcome never comes back keeps that record, and the codes
below report one. Three of them carry an `error.details` object with the full
transaction hash the message redacts.

The rule for all of them is the same: **reconcile, never rebuild.** At most one
transaction per source account and sequence can ever apply, and the wallet
cannot tell whether the recorded one did. A second submission at that sequence
is refused until the first is settled, and a different fee does not get around
it.

| Code | Meaning | Agent action |
|---|---|---|
| `submission.tx_timeout` | The transaction was accepted for inclusion and was not confirmed within the submission timeout. It may still apply. `details` carries `tx_hash`, `timeout_seconds`, `outcome: "unknown"`, `reconcile_with`, and `envelope_hash` where the reporting surface holds the signed bytes. | Call `stellar_transaction_status` with `details.tx_hash` (CLI: `stellar-agent tx status <HASH>`). Do not re-simulate and do not rebuild. |
| `submission.tx_already_submitted` | A pending record already holds this transaction's source account and sequence. Nothing was sent. `details.tx_hash` names the transaction to reconcile. | Reconcile `details.tx_hash` first. Once it is settled, the sequence is free and a fresh simulate-and-commit proceeds. |
| `submission.hash_mismatch` | The endpoint reported a transaction hash that does not describe the transaction that was sent. `details` carries both hashes. | Reconcile `details.tx_hash`. Report the mismatch to the operator: the endpoint is not describing what it was handed. |
| `submission.record_unavailable` | The wallet could not durably record the submission, so nothing was sent. The condition is local: an unwritable receipt store, an unreadable spending-window file, or an audit log that cannot be appended. | Not agent-recoverable. Report to the operator; the submission is safe to retry once it is fixed. |
| `submission.tx_malformed` | The network refused the transaction outright (for example the fee was below the current floor). Nothing was queued and no value moved. | A fresh simulate-and-commit is the next step; the sequence is free. |
| `policy.approval_consumed` | The approval presented was already spent on a submission. | Check that transaction's status before asking for the action again. Do not re-present the same approval. |

What `stellar_transaction_status` reports, and what it means:

- `chain_status: "SUCCESS"`: the payment went through. Report it as done.
- `chain_status: "FAILED"`: the transaction applied and failed. Nothing moved.
- `chain_status: "NOT_FOUND"` with `record.status: "pending"`: nothing is
  settled. The transaction can still apply. Wait and call again.
- `chain_status: "NOT_FOUND"` with `record.status: "failed"`: the transaction
  can no longer apply. A fresh simulate-and-commit is the next step.
- `chain_status: "NOT_FOUND"` with `record.status: "ambiguous"`: the endpoint
  can no longer answer for it at all, and only the operator can resolve it, with
  `stellar-agent tx receipt clear <ENVELOPE_HASH> --acknowledge`.

Read `record.status`, not `record.reservation_open`. An action the policy engine
sized no value for takes no reservation at all, so `reservation_open` is `false`
for it from the start and says nothing about whether the submission settled.

An operator policy that lists tools explicitly must include
`stellar_transaction_status`, or a timed-out submission cannot be resolved
through the MCP server. The CLI verb is not policy-gated.

## Nonce codes (two-phase signing verbs)

A simulate step (`stellar_pay`, `stellar_create_account`, `stellar_trustline`,
`stellar_claim`, `stellar_rule_create`) mints a single-use nonce bound to the
exact envelope, tool, and chain. The
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
| `nonce.mint_failed` | The simulate step could not mint the single-use nonce, almost always because the profile's keyring nonce key is missing or unreadable. This fires at simulate time, before any commit, so an unpopulated keyring blocks the flow at the first write step, not at commit. | Not agent-recoverable: the operator must populate the profile's keyring nonce key. Report to the operator. |
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
| `toolset.first_invoke_approval_required` | The first time a toolset uses a signing-adjacent capability with no matching grant, a one-time gate fires and queues an approval. | Ask the operator to approve the queued entry with `stellar-agent approve --id <nonce> --profile <name>`. Once approved, a time-boxed grant suppresses only this re-prompt; the per-action payment approval still fires on every payment. |
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
| `keyring.error` | A platform keyring read failed while loading the nonce key or an HMAC key on a two-phase verb. | Often the active profile names a keyring entry that holds no secret yet (the first-run testnet fallback profile uses placeholder coordinates). Only read-only tools that never touch the keyring still work: the simulate step already fails at nonce mint (`nonce.mint_failed`) when the nonce key is missing, so the flow stops there, before any commit. The operator must populate the keyring entry. Report to the operator. |
| `auth.keyring_interactive_session_required` | Windows Credential Manager requires an interactive logon session; the process is running non-interactively (service, SSH, scheduled task). | Not retryable in-place. The operator must either run from an interactive desktop session or opt into the headless keyring store (`STELLAR_AGENT_KEYRING_BACKEND=headless-dpapi` or `headless-env`, see profiles-and-keys.md). Report to the operator. |
| `auth.keyring_config_invalid` | The headless keyring store cannot be set up from the environment. `STELLAR_AGENT_KEYRING_BACKEND` names an unknown backend, or `STELLAR_AGENT_HEADLESS_KEYRING_KEY` is missing or malformed: base64 padding, the standard alphabet, or not 32 bytes. The backend may also be unsupported on the platform, or the state directory undeterminable. The message names the cause, never the key. | Not agent-recoverable. Report the message; the operator fixes the environment variable, for example by encoding the key as URL-safe base64 without padding (43 characters). |
| `io.audit_writer_setup` | A smart-account verb could not load its profile file: the file is missing, unreadable, malformed, or of an unsupported schema version. A name mismatch, a non-overlayable field, the mainnet rules, and the endpoint rule keep their own codes. | Not agent-recoverable. Report the message; the operator corrects the profile file. An audit directory that cannot be created, or a writer lock another process holds, reports `audit.chain_key_unavailable` with the `audit.io_error` or `audit.writer_locked` detail instead. |

A missing or empty **signer** keyring entry on a single-shot SEP-43 sign tool
surfaces as `sep43.wallet_unlock_failed` under the standard envelope, not a
`keyring.*` code. At the auth layer a missing keyring entry maps to
`auth.keyring_not_found`. In every case the operator must enroll the secret for
the active profile.

Keyring failures on the attestation key during a commit do not surface as a
keyring code: they are folded into the uniform `policy.approval_required` so the
approval path cannot be probed. Recovery is the same as for any
`policy.approval_required`.

## Audit verification codes

`audit verify` emits the verifier's code and diagnostic text.
A missing log has a remediation message.
Profile and ownership pre-checks carry their own codes.

| Code | Meaning | Agent action |
|---|---|---|
| `audit.chain_broken` | An entry hash or link fails verification. | Stop using the log as verified evidence. Report the diagnostic so the operator can investigate the chain. |
| `audit.rotation_gap` | A file in the rotation chain is missing or its handoff is invalid. | Report the gap. Have the operator investigate the handoff and recover and verify the complete rotation set. |
| `audit.hmac_mismatch` | A chain-root HMAC fails verification with the supplied key. | Report the mismatch. Have the operator investigate the key and log provenance. |
| `audit.hmac_sidecar_missing` | HMAC verification requires a missing sidecar. | Report the missing sidecar. Have the operator recover it from a trusted source. |
| `audit.parse_error` | A log entry cannot be parsed. | Report the line and diagnostic. Have the operator inspect the malformed entry before trusting the log. |
| `audit.signer_set_canonical_body` | A signer-set audit entry violates canonical-body invariants. | Report the diagnostic. Have the operator investigate the malformed signer-set evidence. |
| `audit.partial_rotation` | The audit files show an incomplete rotation. | Stop and report the recovery hint. Have the operator follow the audit recovery runbook. |
| `audit.tip_anchor_mismatch` | The log does not contain the chain tip recorded in the keyring anchor. | Follow the `audit.tip_anchor_mismatch` action in the [Audit-key code table](#audit-key-code). |
| `audit.too_many_rotated_files`, `audit.non_regular_file_log_path`, `audit.path_contract`, `audit.log_not_found`, `audit.io_error` | Verification cannot accept or read the requested path or file set. | Report the diagnostic. Have the operator check the log path, file type, archive count, existence, and access before retrying. |

## Approval codes

The table covers failures from `approve`, `approve gc`, `approve list`, `approve serve`, and the shared attestation API.
CLI envelopes carry `error.code` and a plain diagnostic message.
Authentication, validation, and audit failures on these paths carry their own codes.
The MCP server's direct JSON-RPC approval errors use their message form.
`approve operator` codes are outside this list.

These failures carry `approval.*` codes:

| Code | Meaning | Agent action |
|---|---|---|
| `approval.expired` | The pending approval's lifetime has ended. | Request a fresh simulation and ask the operator to review the new approval. |
| `approval.not_found` | The selected store has no pending entry for the nonce. | Check the profile and nonce. Request a new approval if the entry is unavailable. |
| `approval.denied` | The operator declines the CLI prompt or closes its input. | Stop the requested action. Proceed only after fresh operator consent. |
| `approval.user_mismatch` | The approving identity is not authorized for the pending entry. | Have the authorized operator approve through the trusted local or enrolled remote surface. |
| `approval.already_attested` | Consent is already recorded for this entry. | Use the recorded consent for the pending action. |
| `approval.rejected` | The operator refused this approval. | Stop the requested action. |
| `approval.consumed` | This approval has already been used. | Request a new simulation before seeking another approval. |
| `approval.clock_error`, `approval.sha256_hex_error`, `approval.key_decode_failed`, `approval.key_length_error`, `approval.binding_mismatch`, `approval.grant_persist`, `approval.wrong_kind`, `approval.record_failed`, `approval.uid_unavailable`, `approval.store_dir_error`, `approval.permission_denied`, `approval.invalid_nonce_length`, `approval.writer_locked`, `approval.store_open_failed`, `approval.gc_failed` | Approval validation, attestation, storage, or expired-entry collection refuses. | Report the code and diagnostic. Have the operator resolve the approval state, key, identity, clock, or store condition before requesting fresh consent. |

## Audit-key code

| Code | Meaning | Agent action |
|---|---|---|
| `audit.tip_anchor_mismatch` | Acquiring the audit writer proved the profile's audit log no longer contains the chain tip its keyring-held anchor names. The log was restored from an older copy, truncated, or substituted, or it was replaced, truncated or overwritten while a long-lived process held the original open. The chain walk alone does not catch this: it verifies a prefix, which an older copy satisfies. A log that moved FORWARD past its anchor is not this code; that case is absorbed silently. The message says which of the shapes it was. When a row was refused mid-flight the anchor ends up one entry ahead of an otherwise clean log, which is a row the wallet owed and did not write. The MPP verbs answer with this code too, in place of `mpp.state_unavailable`. | Not agent-recoverable, and do NOT retry: the refusal is stable until an operator acts. Report it. The operator must establish why the log changed, then run `stellar-agent audit reanchor --profile <name> --acknowledge-rollback` (stopping the MCP server first if it holds that profile's audit writer). |
| `audit.writer_locked` | A verb that needs the audit writer (`audit reanchor`, `profile rotate-audit-key`, `approve serve` at startup) found the writer's exclusive lock held by another process, normally a running `stellar-agent-mcp` server. `approve --id` queues its consent row in the audit outbox beside a process that drains it: the MCP server or `approve serve` of this version. Beside one that does not, for example an older server, it refuses with this code. | Not agent-recoverable. The operator must stop the MCP server, run the verb, and start the server again. For `approve --id` beside an older server, restart that server on the current version. |
| `audit.outbox_busy` | The audit outbox lock stayed held for its 2 s wait: another process was appending to or draining the outbox. `approve --id` refuses with it and persists nothing; a drain refuses the acquisition it runs in. | Retry once. If it persists, report it; the operator follows the recovery runbook. |
| `audit.outbox_unusable` | A complete line of the audit outbox does not parse as an audit entry, so every drain, and every keyed acquisition, refuses. The outbox is left unchanged. | Not agent-recoverable. Report it; the operator inspects the outbox, moves it aside, and re-queues the intact lines per the recovery runbook. |
| `x402.transmit_gate_refused` | The x402 transmit gate refused, so the signed authorization was never sent. The x402 tools answer the gate's own `audit.*` code instead; this code reaches a caller only from a gate that keeps no reason of its own. | Report it. Do not retry blindly. |
| `audit.rotation_bridge_unusable` | Opening the audit log needs the rotation-handoff entry from the newest archive to seed the active file's chain, and that archive's last entry is not a handoff naming it: the archive was truncated, or a foreign file sits in the audit directory under a rotated-sibling name. | Not agent-recoverable. Report it; the operator inspects the audit directory per the recovery runbook. |
| `audit.log_binding_changed` | The profile names an audit log path or audit key other than the binding recorded for it in the keyring, or the recorded binding cannot be parsed. Every keyed audit writer refuses before the audit key loads. Value-moving verbs and tools, on the zero-config profile too, exit with this code before signing, as do the read-only smart-account verbs, `approve --id <nonce>`, `approve serve`, `audit verify --profile`, and `profile rotate-audit-key`. `credentials add-passkey`, `profile reset-window-state`, and the other `profile` enroll and rotate verbs skip their audit row and continue. Nothing is created at the path the profile names. The MPP state verbs report this as `mpp.state_unavailable`. | Not agent-recoverable, and do NOT retry. Report it. The operator must establish who changed the profile and why, then run `stellar-agent audit reanchor --profile <name> --acknowledge-binding-change`, adding `--acknowledge-rollback` when the command says so. The zero-config profile has no profile file, and `audit reanchor` loads only a profile file: restore the `default.toml` that recorded the binding, or write one that names the log, then run the reanchor. |
| `validation.key_matches_owner_public_key` | A symmetric key (attestation, audit chain, nonce, policy window state, MPP state, or counterparty cache) is the profile's owner public key, or its keyring coordinate sits in the owner namespace (`stellar-agent-owner-...`). The message names the profile field, never key material. `audit verify`, `pool init`, `accounts deploy-c`, the counterparty commands, the MCP nonce check, and the `profile` rotate verbs report this code. The MCP approval gate keeps answering `policy.approval_required` and logs this code at `warn`. The value verbs report it under `audit.chain_key_unavailable`, and the MPP state store under `mpp.state_unavailable`. A policy window key refusal arrives inside the caller's code, for example `trustline.policy_engine_unavailable`. | Not agent-recoverable. Report it. The operator points the field at its own coordinate in the profile file and mints the key with its rotate verb. |
| `validation.acknowledgement_required` | `audit reanchor` was run without an acknowledgement flag it needs: `--acknowledge-rollback` for a rolled-back log, `--acknowledge-binding-change` for a changed audit binding, or both. The message names the missing flag. It changed nothing. | Not an agent action at all. Accepting a rolled-back audit log or a changed binding is an operator judgement. |
| `audit.chain_key_unavailable` (detail begins `audit.writer_locked`, `audit.rotation_bridge_unusable`, `audit.chain_broken`, `audit.tip_anchor_unavailable`, `audit.io_error`, `audit.parse_error`, `audit.partial_rotation`, `audit.outbox_unusable`, or `audit.outbox_busy`) | The pre-flight refused on a condition about the audit LOG rather than about the chain-root key. The message names the condition; the sub-code at the head of the detail is what to match on. | Not agent-recoverable and do NOT rotate the audit key: none of these is fixed by minting or rotating one. Report the detail; the operator follows the recovery runbook section for that sub-code. |
| `audit.chain_key_unavailable` | A verb that writes audit rows proved the profile's audit chain-root key is NOT acquirable, before touching a signer or submitting anything. This covers the value-moving signing verbs (`pay`, `claim`, `accounts create` sponsored mode, `trustline`, `trade`, `vault`, and their MCP equivalents), the x402 payment tools, `stellar_sep43_sign_and_submit_transaction`, and `stellar_mpp_charge_commit`. It also covers the smart-account signing verbs and `smart-account rules verify-pins`, `signers list`, and `signers refresh`, which load no signer and refuse before any RPC. `profile init` mints the audit-log keyring coordinate only, no key material. This pre-flight fails closed only for a persisted profile. The zero-config synthesized profile `pay`/`claim`/`accounts create` fall back to when no profile was NAMED and no `default.toml` exists stays fail-open here. A profile named through `--profile` or `STELLAR_AGENT_PROFILE` whose file does not exist is refused with `profile.load_failed` instead. The SEP-43 sign-only pair (`signTransaction`, `signAuthEntry`) runs the same pre-flight. | Not agent-recoverable. The operator must run `stellar-agent profile rotate-audit-key <name>`, then retry. |

This is distinct from `io.audit_writer_setup` above, which reports a smart-account
verb whose profile cannot be resolved for its audit writer. An audit directory
that cannot be created, or a writer lock another process holds, reports
`audit.chain_key_unavailable` with the `audit.io_error` or `audit.writer_locked`
detail.

## Profile-selection code

| Code | Meaning | Agent action |
|---|---|---|
| `profile.load_failed` | The profile the operator NAMED through `--profile` or `STELLAR_AGENT_PROFILE` could not be loaded. Most often no such file exists. On the value-moving verbs (`pay`, `claim`, `accounts create`, `accounts deploy-c`, `trade`, `vault`, and the four `smart-account deploy-*` commands; `trustline` uses `trustline.profile_load_failed`) a malformed TOML or an unsupported schema version produces this same code with a different cause in the message. Every other command reports those two as `validation.config_invalid` and an absent file as `validation.profile_not_found`; the smart-account verbs report both, and an absent file, as `io.audit_writer_setup`. Do not treat this code as the only shape a load failure takes. On every command, a mainnet profile without `rpc_url` reports `validation.mainnet_rpc_url_required`, and an endpoint URL that breaks the endpoint rule reports `validation.config_invalid`. `pay`, `claim`, and `accounts create` substitute the in-memory zero-config profile ONLY when no name was given at all. So a named profile is never silently replaced by it, including `--profile default` on a host with no `default.toml`. | Not agent-recoverable by retry. Report the name in the message to the operator. Either it is a typo (or a stale `STELLAR_AGENT_PROFILE`) and the correct name should be used. Or the profile has not been created yet and the operator must run `stellar-agent profile init --profile <name>`. Do not re-run without a name to make the error go away. That silently switches which policy engine governs the call. |
| `profile.non_overlayable_field` | A profile field was supplied outside the file (an environment variable, an overlay, or a command-line flag) that its class does not allow there, including a value equal to the file's. Overlays may set `submit_timeout_seconds` on every chain; `rpc_url`, `secondary_rpc_url`, `oracle_provider_url`, `mcp_signer_default`, the threshold, fee, and scan-bound keys on testnet only; and `mcp_disabled` only to `true`. Every other key, keyring coordinates and `audit_log_path` included, comes from the file only. The message names the field. | Not agent-recoverable by retry. Drop the flag or input that supplies the field; the value comes from the profile file only. Report an environment variable or overlay to the operator. |
| `profile.network_flag_mismatch` | `--network` names a chain other than the loaded profile's. The flag asserts the chain and never selects one. | Remove `--network`, or select a profile on that chain with `--profile <name>`. |
| `auth.enrolled_signer_unpinned` | The mainnet profile's `mcp_signer_default.account` is the placeholder or malformed, so the profile has no enrolled signer identity. | Not agent-recoverable. Report it to the operator, who corrects a malformed `mcp_signer_default.account` and runs `stellar-agent profile enroll-signer --profile <name>`. |
| `auth.enrolled_signer_mismatch` | The resolved signer's key differs from the mainnet profile's enrolled identity. | Do not retry with another key. Use the enrolled seed, Ledger account, or keyring entry, and report both keys in the message to the operator. |
| `profile.mainnet_requires_explicit_profile` | The environment or the default source selected a mainnet profile. | Pass `--profile <name>`. For a mainnet `default.toml`, pass `--profile default`; keep the filename because its identity binds the keyring entries. |
| `profile.name_mismatch` | The profile FILE that was loaded belongs to a different profile: its `policy_owner_key_id.service` names another profile, or carries no `stellar-agent-owner-` prefix at all. Both binaries refuse it: the MCP server at startup, the CLI at every command that loads a profile. The refusal applies because the signed policy file and the owner-key keyring entry resolve through the name the FILE carries. The approval store, audit log, and policy-window state key on the name that was ASKED for. Almost always a copied or renamed `<name>.toml`. Distinct from `validation.config_invalid`, which covers the profile CONFIGURATION being unusable: a name that is not a valid path component, a malformed TOML, an unsupported schema version, an out-of-range field. None of these conditions is covered by this code. Here the file parses and the name is valid; it simply belongs to another profile. | Not agent-recoverable by retry, and do NOT retry under a different profile name. Report the message to the operator: it names both profiles and quotes the offending field. Recovery is `stellar-agent profile init --profile <name>` for a genuinely new profile, or correcting `policy_owner_key_id.service` to `stellar-agent-owner-<name>`. `stellar-agent profile show <name>` still displays the file so the field can be read. |

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

MPP codes are closed and redacted. Input/selection failures include
`mpp.challenge_invalid`, `mpp.challenge_ambiguous`,
`mpp.challenge_mismatch`, `mpp.challenge_expired`, `mpp.unsupported_method`,
`mpp.unsupported_intent`, `mpp.unsupported_mode`, `mpp.network_forbidden`, and
`mpp.input_too_large`. Approval/state/signing failures include
`mpp.approval_required`, `mpp.approval_invalid`,
`mpp.authorization_not_found`, `mpp.authorization_replayed`,
`mpp.authorization_indeterminate`, `mpp.state_unavailable`,
`mpp.simulation_failed`, `mpp.signing_failed`, and
`mpp.credential_too_large`. Observation failures are `mpp.receipt_invalid`,
`mpp.receipt_conflict`, and `mpp.reconciliation_unavailable`.

`mpp.authorization_not_found` means no authorization matches the identifier
you supplied, including on a profile that has never prepared a charge. It is a
normal answer: correct the identifier or prepare a charge. Do not report it as
a wallet fault. `mpp.state_unavailable` means the durable state or a
prerequisite of it exists and cannot be used. Its store causes (unreadable or
unverifiable store, unreadable state key, unusable clock, capacity ceiling) are
operator problems that retrying will not clear. The exception is a concurrent update, whose message says the state changed during the update and asks for a retry. Its call causes (malformed
identifier, an input file that is not a bounded regular file) mean the call was
wrong. Correct it and retry. A malformed identifier answers this way on every
store state, so it never reveals whether a profile has MPP state.

The MPP verbs that write an audit row before returning (charge commit, record
receipt, reconcile, prune) answer an audit-log problem under its own `audit.*`
code rather than `mpp.state_unavailable`. The remedy is a different one: the MPP state file is intact and the audit log is what needs attention. Treat
`audit.chain_key_unavailable`, `audit.tip_anchor_mismatch`, and
`audit.log_binding_changed` from an MPP verb exactly as the rows above say.

`mpp state prune` on a profile with no MPP history succeeds with `pruned: 0`
once the profile's audit key is minted (`stellar-agent profile
rotate-audit-key <profile>`); like every audited verb it refuses without one,
here with `audit.chain_key_unavailable`.

For `mpp.approval_required`, wait for the operator and resume the exact stored
authorization. For replayed, indeterminate, withheld, signing, state, receipt,
or reconciliation ambiguity, do not retry commit or create another payment;
query authorization status and reconcile any known server transaction.

- Approval needed (`policy.approval_required`, `toolset.first_invoke_approval_required`):
  ask the operator to run `stellar-agent approve --id <nonce> --profile <name>`, then re-submit
  the commit with `approval_nonce` and `approval_attestation`.
- Approval not honorable on this tool (`policy.approval_required_unsupported`):
  operator must change policy or use a two-phase tool.
- Stale or used nonce (`nonce.expired`, `nonce.replayed`),
  cross-check failure (`simulation.divergence`): re-run the simulate step and
  commit promptly.
- Hard policy refusal (`policy.deny.*`, `policy.engine_required`,
  `network.mainnet_write_forbidden`): do not retry; only the operator can change
  policy or network posture.
- Network binding refusal (`network.endpoint_network_mismatch`,
  `network.endpoint_identity_unavailable`, `network.envelope_signed_for_mainnet`,
  `network.envelope_signature_unverifiable`, `network.envelope_unsigned`,
  `network.account_not_found`): nothing was sent. Do not resubmit the same
  envelope against the same endpoint; report the mismatch to the operator.
- Environment or key problems (`keyring.*`, `mcp.disabled_per_profile`,
  `audit.chain_key_unavailable`, other non-zero startup exits): operator-side;
  not agent-recoverable at runtime.
