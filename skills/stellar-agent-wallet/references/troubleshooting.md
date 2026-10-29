# Troubleshooting (wire and error codes)

See [Mainnet configurations and scope](https://github.com/Soneso/stellar-agent-wallet/blob/main/docs/getting-started.md#mainnet-configurations-and-scope)
for build configuration, admitted operations, and exclusions.

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
- Five MCP tools return a bare success payload: `stellar_toolset_list` returns a
  JSON array, and `stellar_dex_trade`, `stellar_dex_quote`,
  `stellar_defindex_vault_deposit`, and `stellar_defindex_vault_withdraw` return
  an object carrying `status`. Their business errors use the envelope.
- Some refusals use the JSON-RPC error channel instead of the envelope: invalid
  arguments, a `chain_id` mismatch, and the toolset capability refusals.
  `toolset.first_invoke_approval_required` is a JSON-RPC error too, and its error
  data carries the `approval_nonce`.
- By default every CLI command prints exactly one envelope on stdout and exits
  `0` on success, `1` on any error. An argument the parser refuses (an unknown flag,
  a missing required flag, a malformed value) returns `validation.usage_error`
  with the parser's message; correct the invocation and retry. `--help` and
  `--version` print text, not an envelope.

At the MCP boundary, account, strkey, and contract-id fields inside an error are
redacted to first-five-last-five characters, and transaction hashes to
first-eight-last-eight. The wallet never logs raw argument values, only argument
key names. Typed value events retain each leg's amount, asset, and redacted destination.

## Argument-format reminders (prevent most input errors)

- `chain_id` is the CAIP-2 id, `stellar:testnet` (default) or `stellar:mainnet`.
  Most MCP tools require it and it must match the active profile. The
  exceptions follow.
  - `stellar_x402_parse_receipt` and `stellar_toolset_list` take no `chain_id`.
  - The five `stellar_mpp_*` tools reject it as an unknown field and act on the
    profile chain.
  - `stellar_toolset_invoke` accepts an optional `chain_id` and forwards it to
    the routed tool.
  - `stellar_sep43_get_address` and `stellar_sep43_get_network` treat it as
    optional. They default to the profile chain and still validate a supplied
    value.
  - `stellar_dex_quote` requires it but never matches it against the profile;
    it selects the router from it.
- Classic `amount` fields are decimal strings with an explicit unit, e.g.
  `"10 XLM"`, `"10.5 USDC"`. `stellar_pay` and `stellar_pay_commit` accept
  `amount_in_stroops`, a raw stroop integer string, in place of `amount`. DeFi
  quantity fields are raw base-unit integer strings. Never a JSON number.
- Asset is `"native"` / `"XLM"` for the native asset, or `"CODE:GISSUER"` for an
  issued asset.

## Policy-engine codes

The policy engine evaluates every gated call before any signing, returning
Allow, Deny, or RequireApproval. Reads the decision needs, such as the source
account, can run first. The Noop engine allows everything on testnet,
allows read-only on mainnet, and refuses destructive tools on mainnet. The V1
engine is first-match, default-deny over signed, typed criteria.

| Code | Meaning | Agent action |
|---|---|---|
| `policy.deny.<reason>` | A V1 criterion denied the call (`<reason>` is the typed reason: `per_tx_cap_exceeded`, `per_period_cap_exceeded`, `rate_limit_exceeded`, `counterparty_denied`, `minimum_reserve_breached`, `no_matching_rule`). The payload carries the redacted reason. | Do not retry as-is; the policy forbids this operation. Report the reason to the operator. Only the operator can change policy. |
| `policy.deny.unsizable_value_effect` | A value rule matched a tool whose value cannot be sized, including the raw signing tools. | Size the call through a supported verb, or ask the operator to set `allow_opaque_signing = true` on the matched rule if raw signing is intended. |
| `trustline.clawback_opt_in_required` | Trusting a clawback-enabled issuer requires a recorded operator opt-in. | Ask the operator to run the printed `stellar-agent approve --id <nonce> --profile <name>` opt-in, then re-invoke. |
| `policy.approval_required` | A two-phase signing verb reached its commit step without a valid operator approval, or the attestation was absent, invalid, or expired. This single code intentionally covers every approval-path failure mode (missing, expired, wrong-kind, hash mismatch, HMAC mismatch) so callers cannot probe which. | Ask the operator to run `stellar-agent approve --id <nonce> --profile <name>`, then re-submit the commit with the returned `approval_nonce` and `approval_attestation`. Use the approval nonce from simulation, which checks both tool names. If the request expires or no request exists, simulate again and review the new response. |
| `policy.approval_required_unsupported` | The policy returned RequireApproval for a single-shot sign tool (no simulate/commit split: SEP-43 sign verbs, `stellar_sep43_sign_and_submit_transaction`, SEP-53 `sign_message`, and on testnet x402 `create_payment` / `authenticated_payment`). The wallet refuses fail-closed rather than sign without approval. | Cannot proceed via the agent. Ask the operator to either adjust policy so this operation does not require approval, or perform it through a two-phase tool (`stellar_pay`, `stellar_create_account`, `stellar_trustline`, `stellar_claim`, `stellar_rule_create` and their `*_commit`). On an admitted mainnet server, x402 payments use two calls. Call without approval arguments. After terminal CLI approval, repeat with both approval arguments. The operator approves with `stellar-agent approve --id <nonce> --profile <name>`. Only CLI approval attests x402 payments. |
| `policy.engine_required` | The active engine cannot decide the call. Fires for the Noop engine on a destructive tool on `stellar:mainnet`, and for V1 engine errors such as a missing or unverifiable policy document. | Report the refusal to the operator. The profile needs a valid V1 policy and admitted context. Do not switch networks. |
| `policy.unexpected_decision` | Forward-compatibility catch-all for an engine decision the gate does not recognize. Fail-closed. | Treat as a hard refusal. Report to the operator; do not retry. |

### Mainnet refusal recovery

`network.mainnet_write_forbidden` identifies a feature-off build, excluded
operation, or unavailable admitted context. CLI missing engine, verified policy,
or enablement is an entry refusal with the prerequisite named.
CLI engine construction preserves enablement errors and wraps other failures
as `policy.engine_unavailable` or `trustline.policy_engine_unavailable`.
Evaluation failure uses `policy.engine_required`; unknown decisions use
`policy.unexpected_decision`. Policy denials retain `policy.deny.*`.

`network.mainnet_keyring_backend_unsupported` means the process uses a
headless keyring backend (`STELLAR_AGENT_KEYRING_BACKEND` is set). Mainnet
readiness and `profile enable-mainnet` refuse it; mainnet needs the platform
keyring. Do not retry and do not switch networks. Report it to the operator.

After `network.mainnet_authorization_refused`, report the refusal to the operator.
Do not switch networks. A retry requires fresh preparation and fresh approval.
The operator reads the failed check in the `precondition` field of the warn-level
log entry `mainnet authorization refused`. Its `path` identifies the consumer.
The stable snake-case precondition labels are not additional wire codes.
`STELLAR_AGENT_LOG` overrides `RUST_LOG`; the default is `info` on stderr.

After `profile enable-mainnet` or `profile sign-policy`, restart the MCP server.
Stale policy or enablement reports `network.mainnet_write_forbidden` with
`enablement or policy changed, restart the server`. Missing startup authority
instead identifies its prerequisite.

The core and classic MCP message is
`the mainnet write was refused before submission; nothing was sent`.
CLI messages distinguish these boundaries:

- Signature: `the mainnet write was refused; the signature was withheld and nothing was sent`.
- Submission: `the mainnet write was refused; the submission was refused after signing and nothing was sent`.

Other signature-stage errors append `The signature was withheld and nothing was sent.`
Other post-signing errors retain their outcome semantics. A signer can run
before signature rejection. Submission refusal can follow signing.
A submission timeout has an unknown outcome and requires reconciliation.

Live rejected MCP approvals use `policy.approval_rejected`. Live consumed or
receipt-held approvals use `policy.approval_consumed`. Missing, expired, invalid,
or unverifiable approvals use `policy.approval_required`, including expired
tombstones. Pre-send recording failure after authorization consumption can
leave no tombstone; reuse can then return authorization refusal.
CLI `approval.*` errors retain their codes.

The x402 payment tools report these mainnet refusals:

- The SEP-10 and identity libraries refuse mainnet in their ordinary entries
  with `sep10.mainnet_signing_forbidden` and `identity.mainnet_signing_forbidden`.
  The authorized completion, which exists only in builds with the
  `mainnet-write` feature, refuses with `sep10.mainnet_authorization_refused`
  or `identity.mainnet_authorization_refused`. The MCP tool maps these signing
  and authorization refusals to `network.mainnet_write_forbidden` and
  `network.mainnet_authorization_refused`, respectively.
- For the plain tool, authorization refusals use
  `network.mainnet_authorization_refused`. Policy denials keep `policy.deny.*`.
  Other payment errors keep their own codes.
- For the authenticated tool, authorization refusals identify the withheld
  payment payload. Policy, endpoint, and witness errors keep their codes. Other
  payment-build failures use `x402.payment_build_failed`. Other identity
  failures keep their `identity.*` codes, such as `identity.sep10_auth_failed`
  after a failed challenge submission.
- `the mainnet authorization for this SEP-10 authentication was refused; no signed challenge was submitted`
  means the authenticated tool withheld the SEP-10 challenge.
- `the mainnet authorization for this payment was refused; the payment payload was withheld`
  means the authenticated tool withheld the payment payload. A withheld payment
  payload does not establish that no signature exists. The configured RPC can
  already have received the signed authorization during re-simulation.
- Call 2 rechecks the startup binding and refuses a changed one with
  `network.mainnet_write_forbidden`: `enablement or policy changed, restart the server`.
  After `profile enable-mainnet` or `profile sign-policy`, restart the MCP server.
- After release authorization is consumed, the tool consumes the pending
  approval. A failed or absent pending-record consume withholds the payload.
  The `payment withheld at terminal approval` prefix marks a refusal after the
  signed re-simulation. Report it to the operator; the payment authorization is
  spent.
- A live consumed approval returns `policy.approval_consumed`. Without its
  pending-store tombstone, the authorization ledger refuses reuse. If a repeated
  call 2 returns `network.mainnet_authorization_refused`, run call 1 again and
  ask the operator for a new approval.
- After a failed SEP-10 challenge submission, the Message record stays used and
  the approval stays pending. A repeat of the same call 2 refuses with
  `network.mainnet_authorization_refused`. Run call 1 again and ask the operator
  for a fresh approval.
- A challenge that names another client account refuses before the Message
  record is minted. The approval stays unspent, and the same call 2 can be
  repeated.
- `identity.home_domain_invalid` means `home_domain` is not a lowercase LDH
  name, for example `Anchor.Example.com`. Pass the lowercase domain. On mainnet,
  call 1 refuses it before any approval is stored.

### Mainnet refusal order

A mainnet write passes four states in this order: nothing sent or signed,
unsigned requests sent, signed locally, signed material sent. The states refer
to the transaction or payment signature. Authenticated x402 also signs and
submits a SEP-10 challenge with an ephemeral key inside the second state. Each
row names the checks that can refuse in that state, grouped by class, and the
codes they report. Inside a row, the order of the checks differs by command and
tool.

| State when a check refuses | Checks, by class | Codes |
|---|---|---|
| Nothing sent or signed | Entry: the compiled feature, an explicit nondefault mainnet profile with matching stored configuration and an oracle, full mode and keyring access (CLI), envelope and address decoding (classic MCP). Policy: the V1 engine; classic MCP and x402 also check the verified policy and enablement here. URL: client construction and its credential (CLI, classic MCP, plain x402). x402: call 1 ends here. Plain x402 call 2 sends nothing before the payment build. Its checks up to there: requirements, `chain_id`, the approval pair, enrollment and address, local policy evaluation, forced approval, the attestation, audit readiness, the signing handle. Authenticated x402 call 2 runs the same checks through the attestation, plus the home domain, the audit pre-flight, and identity audit readiness. It leaves this state at the identity exchange. | `network.mainnet_write_forbidden`, profile and validation codes, keyring codes, `network.rpc_unreachable`, `network.rpc_credential_refused`, `simulation.divergence` (classic MCP), JSON-RPC invalid params, `x402.*` requirement codes, `identity.home_domain_invalid`, `policy.approval_required`, `policy.approval_rejected`, `policy.approval_consumed`, `policy.deny.*`, `policy.engine_required`, `policy.unexpected_decision`, `auth.enrolled_*`, `audit.*`, approval-store codes |
| Unsigned requests sent: the endpoint identity probe, account and chain reads, the oracle simulation, the unsigned payment simulation (x402) | URL: endpoint identity, protocol version. Entry: the remaining input decoding (CLI, classic MCP). Policy: the verified policy and enablement (CLI), the rebuilt envelope (classic MCP), the policy evaluation, the fee cap and the operation conditions (CLI, classic MCP), the required witness, the health read (x402). Authorization: the attestation or the terminal confirmation, audit readiness, the nonce, signer enrollment, the resolver's sealed checks (CLI, classic MCP); the payment intent authorization (x402). Authenticated x402: the bound SEP-10 authentication runs in this state, and its signed challenge reaches the web-auth server before the payment checks. Payment audit readiness, the signing handle, the payment asset, and client construction follow it. | `network.endpoint_network_mismatch`, `network.endpoint_identity_unavailable`, `network.unsupported_protocol_version`, `network.rpc_credential_refused`, `network.rpc_unreachable` (authenticated x402), read codes, keyring codes, `simulation.divergence`, `network.mainnet_write_forbidden` (CLI), `profile.mainnet_enablement_invalid`, `policy.engine_unavailable`, `trustline.policy_engine_unavailable`, `policy.deny.*`, `policy.engine_required`, `policy.unexpected_decision`, fee-cap codes, `trustline.*`, `network.witness_unavailable`, `confirm.*`, `policy.approval_required`, `policy.approval_rejected`, `policy.approval_consumed`, `audit.*`, `nonce.*`, `auth.enrolled_*`, `identity.*`, `x402.rpc_simulate_failed`, `x402.unexpected_auth_entries`, `x402.invalid_asset_address` (authenticated x402), `x402.payment_build_failed` (authenticated), `network.mainnet_authorization_refused` |
| Signed locally, no signed material sent | Authorization: the signer and the signature check. Submission (CLI, classic MCP): the shared checks before the send: authorization, envelope shape, endpoint identity recheck, signature network binding, transaction hash, pre-send record, consumption proof. x402: the entry signature, the audit row, and the intent consumption before the re-simulation. | `network.mainnet_authorization_refused`, keyring and signer codes, `audit.*`, `protocol.xdr_codec_failed`, endpoint and protocol codes, `submission.record_unavailable`, `submission.tx_already_submitted`, `policy.deny.*`, `x402.transaction_build_failed`, `x402.payment_build_failed` (authenticated) |
| Signed material sent | Submission (CLI, classic MCP): the send and the confirmation; reconcile an unknown outcome. x402: the signed re-simulation sends the signed authorization to the configured RPC. After it, the re-simulation answer checks, the release authorization, the payload encoding, the release consumption, and the pending-approval consumption withhold the payload. | `submission.*`, `x402.rpc_simulate_failed`, `x402.transaction_build_failed`, `x402.unexpected_auth_entries`, `x402.payment_build_failed` (authenticated), encoding codes, approval-store codes, `network.mainnet_authorization_refused` (payload withheld) |

A code can appear in more than one row. For the plain x402 tool, the message
prefix names the stage: `payment withheld before signed transmission`,
`at intent transmit gate`, `after intent authorization`, `at payload encoding`,
`at payload release`, or `at terminal approval`. A withheld payment payload
does not mean the configured RPC saw no signed authorization. For authenticated
x402, a refusal after the identity exchange does not mean the web-auth server
saw nothing: the wallet can already have submitted the signed SEP-10 challenge.

The boundary key maps what the plain x402 tool reports to the state of the
call. The message prefix is in the error message. The `failure_stage` label is
in the `x402_authorization_withheld` audit row.

| Reported marker | Kind | State when the check refused |
|---|---|---|
| `payment withheld before signed transmission` | message prefix | Nothing sent or signed, unsigned requests sent, or signed locally |
| `payment withheld at intent transmit gate` | message prefix | Signed locally, no signed material sent |
| `payment withheld after intent authorization` | message prefix | Signed locally, no signed material sent, or signed material sent |
| `payment withheld at payload encoding` | message prefix | Signed material sent |
| `payment withheld at payload release` | message prefix | Signed material sent |
| `payment withheld at terminal approval` | message prefix | Signed material sent |
| `anchor_unavailable` | `failure_stage` | Signed locally, no signed material sent |
| `resimulation` | `failure_stage` | Signed material sent |
| `response_processing` | `failure_stage` | Signed locally, no signed material sent (a refused mainnet intent consumption), or signed material sent |
| `encoding` | `failure_stage` | Signed material sent |
| `payload_release` | `failure_stage` | Signed material sent |
| `terminal_approval` | `failure_stage` | Signed material sent |


### Library and substrate refusals

Wallet entry guards and library boundaries have distinct codes.
Setup and policy cannot admit excluded signing surfaces.

| Code, reason, or message | Meaning |
|---|---|
| `network.witness_unavailable` | A required independent witness cannot be established. Resolver-detected witness gaps instead use `network.mainnet_authorization_refused`. |
| `wallet.clock_error` | The authorization clock cannot provide a valid time. |
| `network.witness_unavailable`: `cross-check refused: the transaction's {part} does not match the observations the witness compares` | The witness binds another envelope or intent. The message names `source`, `sequence`, `operation`, `memo`, `value`, `envelope`, or `authorization` as `{part}`. The wallet refuses signing and sending. Build the action again. |
| `sep43.mainnet_signing_forbidden` | An ordinary SEP-43 library signing path refuses mainnet. |
| `sep43.mainnet_authorization_refused` | The authorized SEP-43 primitive refuses its bound authority. Public SEP-43 tools remain excluded. |
| `sep45.mainnet_signing_forbidden` | SEP-45 refuses mainnet signing in either build. |
| `feebump.mainnet_signing_forbidden` | The fee-bump signing path refuses mainnet. |
| `sa.quorum.mainnet_write_forbidden` | Smart-account quorum writes refuse mainnet. |
| `sa.credentials.mainnet_write_forbidden` | CLI smart-account credentials refuse mainnet writes. |

### Policy and setup diagnostics

These are policy-library and setup codes. CLI engine construction preserves
enablement errors but wraps other build failures as `policy.engine_unavailable`
or `trustline.policy_engine_unavailable`.

| Code | Meaning or remedy |
|---|---|
| `policy.engine_required` | Noop refuses destructive mainnet policy decisions. Surface entry checks can refuse earlier. |
| `policy.engine_unavailable` | The policy engine cannot be built. Enabled mainnet refuses `test_owner_key` before pin advancement. |
| `policy.mainnet_table_on_testnet` | The policy contains `[mainnet]` on a testnet profile. |
| `policy.sequence_rollback` | The policy is older than the installation pin, or uses v1 after a pin exists. |
| `policy.pin_absent` | An installation with a mainnet enablement nonce has no readable pin, so every mainnet write and `profile enable-mainnet` refuse; no wallet command establishes a missing pin. Not agent-recoverable. When the message names a missing policy-state lock file, the pin entry still exists: a command that builds the V1 policy engine, such as starting the MCP server, recreates the lock file, and the nonce stays. When the pin itself is missing, the operator removes the keyring entry with service `stellar-agent-policy-window-<NAME>` and account `default-mainnet-enablement` with the platform keyring tool, runs `profile enable-mainnet --profile <NAME>`, which pins the installed signed policy and stores a new nonce, and signs the rebound policy at a higher sequence. That enablement trusts the installed signed policy and its owner, as a first enablement does. |
| `policy.owner_rotation_required` | A higher sequence changes owner without a previous-owner statement. Sign with `--previous-owner-secret-env` and install the policy before enrollment. |
| `policy.owner_rotation_invalid` | The statement names other owners or does not verify for this policy body. Review and sign it with the pinned owner's seed. |
| `enroll_owner_key.rotation_statement_required` | Enrolling a key other than the pinned owner requires an installed policy signed by the new owner and carrying a valid statement from the pinned owner. The message names the cause. No owner entry changes. Re-enrolling the pinned owner key needs no statement. Lock, pin, keyring and policy errors keep their own codes. |
| `policy.sequence_fork` | The pinned sequence has a different digest or owner. |
| `policy.state_lock_busy` | The state lock remains held through the bounded acquisition attempts. |
| `policy.state_lock_io` | The lock cannot be opened. The detail identifies the I/O failure. |
| `policy.mainnet_minimum_unmet` | The enabled policy fails a named minimum requirement. |
| `policy.pin_unusable` | The installation pin cannot be read or is malformed. |
| `profile.mainnet_enablement_invalid` | The message names the failed binding: `mainnet_table`, `profile`, `source`, `default`, `on_disk`, `chain_id`, `on_disk_host`, `merged_host`, or `nonce_digest`. |
| `profile.enable_mainnet_profile_flag_required` | Supply an explicit `--profile`. |
| `profile.enable_mainnet_default_refused` | Select a dedicated profile whose name is not `default`. |
| `profile.enable_mainnet_not_mainnet` | Select a mainnet profile. |
| `profile.enable_mainnet_precondition` | A named ceremony prerequisite or effect failed. |
| `profile.mainnet_oracle_required` | The mainnet profile sets no `oracle_provider_url`. Enablement refuses before any keyring read, and every mainnet write before any signature; the MCP server applies an oracle change from its next start. Set `oracle_provider_url` and its `providers.oracle` record in the profile file. |
| `profile.enable_mainnet_nonce_exists` | Use `--rotate` to replace the installation nonce. |
| `sign_policy.sequence_exhausted` | The maximum of body and pinned sequence is `i64::MAX`. |
| `profile.enroll_signer_identity_incomplete` | Follow the reported repair or enrollment remedy. |
| `enroll_signer.repair_unpinned` | Identity repair requires the stored public-key pin. |
| `enroll_signer.identity_conflict` | The stored identity conflicts with the enrolled signer. |
| `auth.enrolled_identity_unusable` | The enrolled identity cannot establish the signer proof. Ledger enrollment is unavailable. |
| `profile.reset_window_state_newer_version` | This build cannot reset an unsupported newer state format. |
| `policy.window_state_unverifiable` | Enabled-mainnet state cannot be verified. Follow the operator recovery procedure. |
| `profile.reset_window_state_open_authorizations` | Effective open authorizations prevent reset. |
| `confirm.tty_required` | Direct mainnet confirmation requires terminal stdin and stderr. |
| `confirm.profile_name_mismatch` | The entered line must equal the selected profile name. |
| `confirm.input_unavailable` | Input, render, or flush failure prevents confirmation. |
| `approve.yes_refused_on_mainnet` | On mainnet, `--yes` refuses before terminal or store checks in either build. CLI `approve` uses a y/n prompt. |
| `accounts.create.generate_refused_on_mainnet` | Mainnet creation requires a destination public key. Generated-key creation is a testnet convenience. |

### Policy denial codes

| Code | Meaning |
|---|---|
| `policy.deny.asset_not_allowlisted` | Asset outside the rule's allowlist. |
| `policy.deny.per_tx_cap_exceeded` | Transaction cap exceeded. |
| `policy.deny.per_period_cap_exceeded` | Period cap exceeded. |
| `policy.deny.rate_limit_exceeded` | Rate limit exceeded. |
| `policy.deny.counterparty_denied` | Counterparty restriction failed. |
| `policy.deny.minimum_reserve_breached` | Minimum reserve breached. |
| `policy.deny.owner_signature_stale` | Owner signature stale. |
| `policy.deny.no_matching_rule` | No rule matches this policy-tool name and action. |
| `policy.deny.counterparty_kind_unsupported` | Counterparty kind cannot be evaluated. |
| `policy.deny.evaluation_error` | Policy evaluation failed. |
| `policy.deny.unsizable_value_effect` | Value effect cannot be sized. |
| `policy.deny.explicit_rule_deny` | Matching rule denies the action. |
| `policy.deny.inner_invocation_count_cap_exceeded` | Invocation-count cap exceeded. |
| `policy.deny.bundle_aggregate_cap_exceeded` | Bundle aggregate cap exceeded. |
| `policy.deny.bundle_contains_generic_kind` | Bundle contains a generic invocation kind. |
| `policy.deny.bundle_denied` | Bundle restriction failed. |
| `policy.deny.quorum_not_satisfied` | Required quorum absent. |
| `policy.deny.home_domain_not_resolved` | Required home domain unresolved. |
| `policy.deny.sep10.session_missing` | Required SEP-10 session absent. |
| `policy.deny.sep45.session_missing` | Required SEP-45 session absent. |

## Network-binding codes (submit layer)

Before it sends, the submit layer asks the RPC endpoint which network it serves
and which protocol it runs, and binds the submission to that answer, not to the
declared network or `chain_id`. It then verifies every signature on the envelope
against the network the endpoint reports. The classic payment, sponsored
account creation, trustline, claim, and pool paths ask the same question
earlier, before their first read. They ask on the client that sends, and the
MCP simulate tools ask on their own client. The pay, create-account, trustline,
and claim commit tools ask it before the single-use nonce is burned, so a
refusal at that check leaves the nonce usable. A refusal by the submit layer's
own check comes after the nonce is consumed.

| Code | Meaning | Agent action |
|---|---|---|
| `network.endpoint_network_mismatch` | The endpoint serves a different network than the one declared (an RPC URL and a `chain_id` / network passphrase that disagree). | Do not retry as-is. Report to the operator: the profile's `rpc_url` and its network do not name the same chain. |
| `network.endpoint_identity_unavailable` | The endpoint's network identity could not be established within the submission timeout, or its `getNetwork` answer did not parse. A transport failure is retried with bounded backoff; an answer that does not parse is not retried. The probe never falls back to the declared network. | No transaction or payment was sent. Treat the endpoint as unusable and surface it to the operator; do not switch to a different endpoint on your own. |
| `network.rpc_credential_refused` | RPC credential invalid or rejected. | See below. |
| `network.unsupported_protocol_version` | A mainnet endpoint runs a protocol version outside the range this release supports (protocol 29). The message names the version and the range. Ordinary submission refuses mainnet before this check. Authorized submission enforces it. On testnet and other networks the same version is a logged warning, not a refusal. | No transaction or payment was sent. Report the version to the operator; do not switch to a different endpoint on your own. |
| `network.envelope_signed_for_mainnet` | A signature fails under the endpoint network and verifies under mainnet. | Do not retry; the envelope cannot be relayed onto this chain. Re-run the simulate step for the intended network. |
| `network.envelope_signature_unverifiable` | A signature verifies under neither the endpoint's network nor mainnet, or no eligible ed25519 signer accounts for it (hash-x and pre-auth-tx signers contribute no ed25519 key). | Do not retry the same envelope. Re-run the simulate step and sign with a key the source account lists as a signer. |
| `network.envelope_unsigned` | The envelope carries no signature, or on a fee-bump the outer or the inner transaction carries none; typically a build-only envelope handed straight to a submit step. | Sign the envelope first, then submit. On a fee-bump, both the inner transaction and the fee source must sign. |
| `network.account_not_found` | A transaction-source or operation-source account on the envelope is absent from the ledger, so its signer set cannot be read. | Nothing was sent. Confirm the account exists and is funded on the target network. |

`network.rpc_credential_refused` means the credential is empty, exceeds 1024 bytes,
holds a control character, or an endpoint answers a request with HTTP 401 or 403.
A rejected request is not retried. No transaction was sent.

For the x402 payment tools, a payment endpoint refusal occurs before the payer
signs. For authenticated payment, the SEP-10 challenge can already have been
signed and submitted.
Report it to the operator, who reruns
`stellar-agent profile enroll-rpc-credential --role <role> --force` and checks the
placement against the provider's documentation.

## Friendbot code

| Code | Meaning | Agent action |
|---|---|---|
| `network.friendbot_account_already_funded` | Friendbot refuses to fund the account because its XLM balance is at or above the Friendbot starting balance (10,000 XLM on the SDF testnet). `stellar-agent friendbot`, `accounts create --fund-with-friendbot`, and `stellar_friendbot` report it; the message names the account. An existing account below the starting balance receives that amount instead. | Do not retry. The account is usable as it is: continue with it, or fund a new account if you need a fresh account. |

## Submission codes (unresolved outcomes)

Every value-moving verb records its transaction before it is sent: a submission
receipt, a spending-window reservation under a policy with a stateful
criterion, and a `value_action_pending` audit row.
A submission whose outcome never comes back keeps that record, and the codes
below report one. Three of them carry an `error.details` object with the full
transaction hash the message redacts.

The rule for all of them is the same: **reconcile, never rebuild or resubmit.**
At most one transaction per source account and sequence can ever apply, and the
wallet cannot tell whether the recorded one did. A second submission at that
sequence is refused until the first is settled, and a different fee does not get
around it. No recovery path sends a transaction again.

| Code | Meaning | Agent action |
|---|---|---|
| `submission.tx_timeout` | The submission ended without a confirmed outcome: the deadline passed, the endpoint reported an unexpected status, or a transport failure struck during or after the send. On a mainnet profile it also reports a failure or a refusal the primary endpoint reported and the oracle did not confirm. It may still apply; the message says to settle it by its transaction hash and not to resubmit. `details` carries `tx_hash`, `timeout_seconds`, `outcome: "unknown"`, `reconcile_with`, and `envelope_hash` where the reporting surface holds the signed bytes. | Call `stellar_transaction_status` with `details.tx_hash` (CLI: `stellar-agent tx status <HASH>`). Do not re-simulate, rebuild, or resubmit. |
| `submission.tx_already_submitted` | A pending record already holds this transaction's source account and sequence, or the spending window already holds these signed bytes. Nothing was sent. `details.tx_hash` names the transaction to reconcile. | Reconcile `details.tx_hash` first. Once it is settled, the sequence is free and a fresh simulate-and-commit proceeds. |
| `submission.hash_mismatch` | The endpoint reported a transaction hash that does not describe the transaction that was sent. `details` carries both hashes. | Reconcile `details.tx_hash`. Report the mismatch to the operator: the endpoint is not describing what it was handed. |
| `submission.record_unavailable` | The wallet could not durably record the submission, so nothing was sent. The condition is local: an unwritable receipt store, an unreadable spending-window file, an audit log that cannot be appended, or a pending audit row the audit log's tip anchor does not cover, whose message carries `audit.tip_anchor_unavailable`. | Not agent-recoverable. Report to the operator; the submission is safe to retry once it is fixed. |
| `submission.tx_malformed` | The endpoint refused the transaction outright, reporting a validation error for the envelope (for example the fee was below the current floor). The wallet never sends those bytes again and releases the reservation. On a mainnet profile a refusal is reported as `submission.tx_timeout` instead, because no second endpoint confirms it. | A fresh simulate-and-commit is the next step; the sequence is free. |
| `policy.approval_consumed` | The approval presented was already spent. A classic approval was spent on a submission. A consumed x402 approval cannot be replayed. Its stored digest identifies the final envelope, not a chain transaction. | Do not re-present the same approval. For a classic approval, check that transaction's status before asking for the action again. For an x402 payment, request a new payment intent with call 1 and a fresh approval. |

What `stellar_transaction_status` reports, and what it means:

- `chain_status: "SUCCESS"`: the payment went through. Report it as done.
- `chain_status: "FAILED"`: the transaction applied and failed. Nothing moved.
- `chain_status: "NOT_FOUND"` with `record.status: "pending"`: nothing is
  settled. The transaction can still apply. Wait and call again.
- On a mainnet profile, `chain_status` is the primary endpoint's answer, and
  its `FAILED` or `NOT_FOUND` settles nothing until the oracle confirms it. A
  profile without `oracle_provider_url` keeps such a record `pending`, and a
  refused send without a time bound stays `pending` too, until the operator
  clears it with `stellar-agent tx receipt clear <ENVELOPE_HASH> --acknowledge`.
- `chain_status: "NOT_FOUND"` with `record.status: "ambiguous"` and a
  `record.release_code`: the transaction can no longer apply.
  `submission.sequence_consumed` means another transaction used its sequence;
  `submission.time_bound_passed` means its time bound passed, which needs an
  envelope that carries one. The reservation is released and a
  `value_action_failed` row is written under that code. A fresh
  simulate-and-commit is the next step.
- `chain_status: "NOT_FOUND"` with `record.status: "ambiguous"` and no
  `release_code`: the endpoint can no longer answer for it at all, and only the
  operator can resolve it, with
  `stellar-agent tx receipt clear <ENVELOPE_HASH> --acknowledge`.
- `chain_status: "NOT_FOUND"` with `record.status: "failed"`: the endpoint
  reported a validation error for the envelope or previously reported an
  on-chain `FAILED` that has left its retained history. The wallet never sends
  those bytes again. A fresh simulate-and-commit is the next step.
- No `record`, and a `reservation` with `operator_required: true`: the receipt
  is missing and the endpoint can no longer answer for the transaction. Only
  the operator resolves it, with `tx receipt clear`.

Read `record.status` and `record.release_code`, not `record.reservation_open`.
An action the policy engine sized no value for takes no reservation at all, so
`reservation_open` is `false` for it from the start and says nothing about
whether the submission settled.

`tx receipt clear --acknowledge` reconciles before it clears. It refuses with
`submission.still_pending` while a sent transaction's time bound is open and
its sequence unconsumed. On a mainnet profile with an oracle it also asks the
oracle, and refuses with `submission.not_clearable` when the oracle does not
report the mainnet passphrase, reports `SUCCESS` or `FAILED`, or cannot
answer. Without an oracle the endpoint's `FAILED` does not refuse the clear. A failed ledger-time read refuses sent, timed
submissions with `network.rpc_unreachable`; other failed reconciliation reads
also refuse. Both are operator conditions: wait, or ask the operator.

An operator policy that lists tools explicitly must include
`stellar_transaction_status`, or a timed-out submission cannot be resolved
through the MCP server. The CLI verb is not policy-gated.

## Nonce codes (two-phase signing verbs)

A simulate step (`stellar_pay`, `stellar_create_account`, `stellar_trustline`,
`stellar_claim`) mints a single-use nonce bound to the
exact envelope, tool, and chain. The
commit step (`*_commit`) verifies it. `stellar_rule_create` mints no envelope
nonce: it parks the resolved rule definition as a pending approval, and
`stellar_rule_create_commit` requires that approval's `approval_nonce`. Nonces are single-use and TTL-bounded, and
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

The classic witness covers CLI `pay`, `claim`, sponsored `accounts create`,
`trustline`, and every sending `pool init` path. It also covers MCP
`stellar_pay_commit`, `stellar_create_account_commit`, `stellar_trustline_commit`,
and `stellar_claim_commit`. The x402 payment tools `stellar_x402_create_payment`
and `stellar_x402_authenticated_payment` are covered by a second simulation on
the oracle: before the payer signs, the oracle simulates the same unsigned
transfer, and the answers are compared. Opaque staged envelopes and the SEP-43
signing tools remain uncovered.

| Code | Meaning | Agent action |
|---|---|---|
| `simulation.divergence` | Entry or envelope disagreement. | Re-simulate; see below. |
| `network.witness_unavailable` | Required oracle witness unavailable. | See below. |

For a cross-check, `simulation.divergence` means the primary and oracle disagree
on a ledger entry the decision uses. The message names the entry and field.
For the x402 payment tools the entry is the `soroban simulation`, and the field
is one of `result`, `authorization count`, `credentials`, `address`, `signature`,
`invocation`, `resource fee ceiling`, `ledger skew`, or `expiration`.
A witness refusal precedes the payer signature. Authenticated identity exchange
can already be complete. Re-simulate and retry; report persistent disagreements
to the operator. Envelope-decode and rebuild producers of this code remain.

The x402 witness runs before the health read, which keeps the deadline of
`submit_timeout_seconds`. A witness that overruns it surfaces at the health read,
as `x402.rpc_simulate_failed` in `stellar_x402_create_payment` and as
`x402.payment_build_failed` in `stellar_x402_authenticated_payment`.

`network.witness_unavailable` means the required oracle or asset threshold is
missing, or the oracle cannot be constructed, identified, or read successfully.
Its message gives a safe reason and at most the oracle authority.
It also reports an envelope mismatch when the witness binds another envelope or
intent. The operator then builds the action again.
The operator corrects `oracle_provider_url`, `[providers.oracle]`, or
`[cross_check_thresholds]`. Retry after a transient failure.

## Fee-cap codes

| Code | Meaning | Agent action |
|---|---|---|
| `fees.percentile_exceeds_cap` | Fee exceeds cap. | Follow the remedy below. |
| `validation.mainnet_fee_cap_required` | Mainnet cap missing. | Operator sets the signed cap. |
| `validation.fee_total_overflow` | Pool fee overflows. | Lower the profile fee. |

## Memo codes

| Code | Meaning | Agent action |
|---|---|---|
| `validation.memo_control_character` | A text memo holds a control character (U+0000 to U+001F, U+007F to U+009F) or a Unicode format character (category Cf), line separator (U+2028), or paragraph separator (U+2029), on any network. The format characters include U+200C and U+200D. The message names the character, not the memo. | Send the memo without that character. |

`fees.percentile_exceeds_cap` means the per-operation fee exceeds
`classic_max_fee_per_op_stroops`. The message names the source: an auto-selected
fee and percentile, an explicit fee, the profile's `classic_fee_per_op_stroops`,
a command's default fee, or a presented or staged envelope's fee.
Nothing was signed or sent.

Follow the remedy in the message. Accept a lower percentile, lower the explicit
fee, pass an explicit fee within the cap, or prepare again with a fee within
the cap. Raising the cap or lowering `classic_fee_per_op_stroops` is an
operator decision.

`validation.mainnet_fee_cap_required` means an action has no effective classic
fee cap. Nothing was sent. This is not agent-recoverable. The operator sets the
signed cap, which the enabled-policy minimum requires. The effective cap is the
smaller signed/profile value, or the one available value. MCP preparation checks
the effective cap, and the resolver independently reevaluates it.
A higher profile cap warns. Resolver fee failures become
`network.mainnet_authorization_refused`. Over-cap fees retain
`fees.percentile_exceeds_cap`; total overflow uses `validation.fee_total_overflow`.

`validation.fee_total_overflow` means the `pool init` per-operation fee times
the operation count exceeds the transaction fee limit. Nothing was built,
signed, or sent. This is not agent-recoverable. The operator lowers
`classic_fee_per_op_stroops`. A fresh refusal leaves no initialization checkpoint.
An existing checkpoint remains resumable, without consuming a retry attempt.

## Toolset codes

`stellar_toolset_invoke` routes a toolset action to a registered tool through a
four-part capability gate. Two signing tools are reachable, only through gated
capabilities: `stellar_pay_commit` (`sign-payment`) and
`stellar_rule_create_commit` (`sign-rule-create`). Each needs a first-invoke
grant plus its per-action approval. No other signing tool is reachable through
a toolset. The routed tool's own policy gate still applies.

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
the active profile. An RPC credential entry reports `auth.keyring_not_found`
with its `service/account`; the operator stores it with
`stellar-agent profile enroll-rpc-credential`.

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
| `audit.tip_anchor_missing` | No anchor is stored for the profile's log, but a recorded audit binding, a chain-root sidecar, or an `audit_tip_anchored` row shows one was written. The message says `anchor: missing`. | Follow the `audit.tip_anchor_missing` action in the [Audit-key code table](#audit-key-code). |
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
| `approval.operator_credential_revoked` | The remote operator credential that approved the entry is missing from the profile's `allowed_credentials` list or from the operator-credential store, so its approvals do not count. | Stop. Ask the operator to approve the action again through a surface they still authorize. |
| `approval.remote_authorization_unavailable` | The profile's remote-approval authorization or the operator-credential store cannot be read, or the profile does not enable remote approval for that chain and relying-party ID. A remote approval cannot be honored while this holds. | Report the code. Have the operator repair the profile or the credential store, then request fresh consent. |
| `approval.entry_inconsistent` | The pending payment, claim, or trustline request's stored digest is not the digest of its stored envelope, or its envelope does not decode; or the pending MPP charge shows terms that do not match what it would authorize, holds no binding digests, or at commit shows another transport, authority, or target than the prepared request. No surface approves it. | Stop. Report it: the approval store was changed outside the wallet. Request a fresh simulation for the intended action. |
| `approval.clock_error`, `approval.sha256_hex_error`, `approval.key_decode_failed`, `approval.key_length_error`, `approval.binding_mismatch`, `approval.grant_persist`, `approval.wrong_kind`, `approval.record_failed`, `approval.uid_unavailable`, `approval.store_dir_error`, `approval.permission_denied`, `approval.invalid_nonce_length`, `approval.writer_locked`, `approval.store_open_failed`, `approval.gc_failed` | Approval validation, attestation, storage, or expired-entry collection refuses. | Report the code and diagnostic. Have the operator resolve the approval state, key, identity, clock, or store condition before requesting fresh consent. |

## Audit-key code

| Code | Meaning | Agent action |
|---|---|---|
| `audit.tip_anchor_mismatch` | Acquiring the audit writer proved the profile's audit log no longer contains the chain tip its keyring-held anchor names. The log was restored from an older copy, truncated, or substituted, or it was replaced, truncated or overwritten while a long-lived process held the original open. The chain walk alone does not catch this: it verifies a prefix, which an older copy satisfies. A log that moved FORWARD past its anchor is not this code; that case is absorbed silently. The message says which of the shapes it was. When a row was refused mid-flight the anchor ends up one entry ahead of an otherwise clean log, which is a row the wallet owed and did not write. The MPP verbs answer with this code too, in place of `mpp.state_unavailable`. | Not agent-recoverable, and do NOT retry: the refusal is stable until an operator acts. Report it. The operator must establish why the log changed, then run `stellar-agent audit reanchor --profile <name> --acknowledge-rollback` (stopping the MCP server first if it holds that profile's audit writer). |
| `audit.tip_anchor_missing` | Acquiring the audit writer found no tip anchor in the keyring for a log that shows it was anchored: the audit binding is recorded, the active file has a chain-root sidecar, or the log holds an `audit_tip_anchored` row. The refusal names which. The anchor entry was deleted, or a crash fell between a file's first keyed entry and its first anchor write. Adopting the log as found would accept a truncation without a trace, so nothing is written. The MPP verbs answer with this code too. | Not agent-recoverable, and do NOT retry. Report it. The operator establishes why the anchor is gone, then runs `stellar-agent audit reanchor --profile <name> --acknowledge-rollback` (stopping the MCP server first if it holds that profile's audit writer). |
| `audit.writer_locked` | A verb that needs the audit writer (`audit reanchor`, `profile rotate-audit-key`, `approve serve` at startup) found the writer's exclusive lock held by another process, normally a running `stellar-agent-mcp` server. `approve --id` queues its consent row in the audit outbox beside a process that drains it: the MCP server or `approve serve` of this version. Beside one that does not, for example an older server, it refuses with this code. | Not agent-recoverable. The operator must stop the MCP server, run the verb, and start the server again. For `approve --id` beside an older server, restart that server on the current version. |
| `audit.outbox_busy` | The audit outbox lock stayed held for its 2 s wait: another process was appending to or draining the outbox. `approve --id` refuses with it and persists nothing; a drain refuses the acquisition it runs in. | Retry once. If it persists, report it; the operator follows the recovery runbook. |
| `audit.outbox_unusable` | A complete line of the audit outbox does not parse as an audit entry, so every drain, and every keyed acquisition, refuses. The outbox is left unchanged. | Not agent-recoverable. Report it; the operator inspects the outbox, moves it aside, and re-queues the intact lines per the recovery runbook. |
| `x402.transmit_gate_refused` | The x402 transmit gate refused, so the signed authorization was never sent. The x402 tools answer the gate's own `audit.*` code instead; this code reaches a caller only from a gate that keeps no reason of its own. | Report it. Do not retry blindly. |
| `audit.rotation_bridge_unusable` | Opening the audit log needs the rotation-handoff entry from the newest archive to seed the active file's chain, and that archive's last entry is not a handoff naming it: the archive was truncated, or a foreign file sits in the audit directory under a rotated-sibling name. | Not agent-recoverable. Report it; the operator inspects the audit directory per the recovery runbook. |
| `audit.log_binding_changed` | The profile names an audit log path or audit key other than the binding recorded for it in the keyring, or the recorded binding cannot be parsed. Every keyed audit writer refuses before the audit key loads. Value-moving verbs and tools, on the zero-config profile too, exit with this code before signing, as do the read-only smart-account verbs, `approve --id <nonce>`, `approve serve`, `audit verify --profile`, `profile rotate-audit-key`, and `profile reset-window-state`. `credentials add-passkey` and the other `profile` enroll and rotate verbs skip their audit row and continue. Nothing is created at the path the profile names. The MPP state verbs report this as `mpp.state_unavailable`. | Not agent-recoverable, and do NOT retry. Report it. The operator must establish who changed the profile and why, then run `stellar-agent audit reanchor --profile <name> --acknowledge-binding-change`, adding `--acknowledge-rollback` when the command says so. The zero-config profile has no profile file, and `audit reanchor` loads only a profile file: restore the `default.toml` that recorded the binding, or write one that names the log, then run the reanchor. |
| `validation.key_matches_owner_public_key` | A symmetric key (attestation, audit chain, nonce, policy window state, MPP state, or counterparty cache) is the profile's owner public key, or its keyring coordinate sits in the owner namespace (`stellar-agent-owner-...`). The message names the profile field, never key material. `audit verify`, `pool init`, `accounts deploy-c`, the counterparty commands, the MCP nonce check, and the `profile` rotate verbs report this code. The MCP approval gate keeps answering `policy.approval_required` and logs this code at `warn`. The value verbs report it under `audit.chain_key_unavailable`, and the MPP state store under `mpp.state_unavailable`. A policy window key refusal arrives inside the caller's code, for example `trustline.policy_engine_unavailable`. | Not agent-recoverable. Report it. The operator points the field at its own coordinate in the profile file and mints the key with its rotate verb. |
| `validation.acknowledgement_required` | `audit reanchor` was run without an acknowledgement flag it needs: `--acknowledge-rollback` for a rolled-back log, `--acknowledge-binding-change` for a changed audit binding, or both. The message names the missing flag. It changed nothing. | Not an agent action at all. Accepting a rolled-back audit log or a changed binding is an operator judgement. |
| `audit.chain_key_unavailable` (detail begins `audit.writer_locked`, `audit.rotation_bridge_unusable`, `audit.chain_broken`, `audit.tip_anchor_unavailable`, `audit.io_error`, `audit.parse_error`, `audit.partial_rotation`, `audit.outbox_unusable`, or `audit.outbox_busy`) | The pre-flight refused on a condition about the audit LOG rather than about the chain-root key. The message names the condition; the sub-code at the head of the detail is what to match on. | Not agent-recoverable and do NOT rotate the audit key: none of these is fixed by minting or rotating one. Report the detail; the operator follows the recovery runbook section for that sub-code. |
| `audit.chain_key_unavailable` | A verb that writes audit rows proved the profile's audit chain-root key is NOT acquirable, before touching a signer or submitting anything. This covers the value-moving signing verbs (`pay`, `claim`, `accounts create` sponsored mode, `trustline`, `trade`, `vault`, and their MCP equivalents), the x402 payment tools, `stellar_sep43_sign_and_submit_transaction`, and `stellar_mpp_charge_commit`. It also covers the smart-account signing verbs and `smart-account rules verify-pins`, `signers list`, and `signers refresh`, which load no signer and refuse before any RPC. `profile init` mints the audit-log keyring coordinate only, no key material. This pre-flight fails closed only for a persisted profile. The zero-config synthesized profile `pay`/`claim`/`accounts create` fall back to when no profile was NAMED and no `default.toml` exists stays fail-open here. A profile named through `--profile` or `STELLAR_AGENT_PROFILE` whose file does not exist is refused with `profile.load_failed` instead. The SEP-43 sign-only pair (`signTransaction`, `signAuthEntry`) runs the same pre-flight. | Not agent-recoverable. Report it. For a profile with no audit key, the operator runs `stellar-agent profile rotate-audit-key <name>`, then retries. A stored key that cannot be read or decoded is refused by that command too: the operator investigates, and if the stored audit key is corrupt, removes that keyring entry with the platform keyring tool, runs `rotate-audit-key` to mint a new key, and runs `stellar-agent audit reanchor --profile <name> --acknowledge-rollback` if the log's anchor is gone. |

This is distinct from `io.audit_writer_setup` above, which reports a smart-account
verb whose profile cannot be resolved for its audit writer. An audit directory
that cannot be created, or a writer lock another process holds, reports
`audit.chain_key_unavailable` with the `audit.io_error` or `audit.writer_locked`
detail.

For `audit.tip_anchor_unavailable`, restore keyring access and retry. Keyed
appends retry once immediately and keep an owed repair after two failures.
The window reset and x402 gate refuse while repair fails. A submission recorded
through the pending row reports `submission.record_unavailable` with this
sub-code. A rotation-spanning outage can require `audit reanchor` after restart.

## Profile-selection code

| Code | Meaning | Agent action |
|---|---|---|
| `validation.provider_attestation_invalid` | A provider record is missing, malformed, or disagrees with its endpoint or independence assertion. A credential reference or placement is malformed, names a wallet key's keyring entry, or meets an insecure endpoint, a URL with userinfo, or a repeated query parameter. A mainnet secondary or oracle record names the primary's operator. | Correct the named field in the profile file. Mainnet requires a record for each configured secondary or oracle URL, and a `[providers.primary]` record. |
| `network.rpc_divergence` | SEP-29 memo flag disagreement. | Re-simulate; report if persistent. |
| `profile.load_failed` | The profile the operator NAMED through `--profile` or `STELLAR_AGENT_PROFILE` could not be loaded. Most often no such file exists. On the value-moving verbs (`pay`, `claim`, `accounts create`, `accounts deploy-c`, `trade`, `vault`, and the four `smart-account deploy-*` commands; `trustline` uses `trustline.profile_load_failed`) a malformed TOML or an unsupported schema version produces this same code with a different cause in the message. Every other command reports those two as `validation.config_invalid` and an absent file as `validation.profile_not_found`; the smart-account verbs report both, and an absent file, as `io.audit_writer_setup`. Do not treat this code as the only shape a load failure takes. On every command, a mainnet profile without `rpc_url` reports `validation.mainnet_rpc_url_required`, and an endpoint URL that breaks the endpoint rule reports `validation.config_invalid`. An invalid provider attestation reports `validation.provider_attestation_invalid`. `pay`, `claim`, and `accounts create` substitute the in-memory zero-config profile ONLY when no name was given at all. So a named profile is never silently replaced by it, including `--profile default` on a host with no `default.toml`. | Not agent-recoverable by retry. Report the name in the message to the operator. Either it is a typo (or a stale `STELLAR_AGENT_PROFILE`) and the correct name should be used. Or the profile has not been created yet and the operator must run `stellar-agent profile init --profile <name>`. Do not re-run without a name to make the error go away. That silently switches which policy engine governs the call. |
| `profile.non_overlayable_field` | A profile field was supplied outside the file (an environment variable, an overlay, or a command-line flag) that its class does not allow there, including a value equal to the file's. Overlays may set `submit_timeout_seconds` on every chain; `rpc_url`, `secondary_rpc_url`, `oracle_provider_url`, `mcp_signer_default`, the threshold, fee, and scan-bound keys on testnet only; and `mcp_disabled` only to `true`. Every other key, keyring coordinates and `audit_log_path` included, comes from the file only. The message names the field. | Not agent-recoverable by retry. Drop the flag or input that supplies the field; the value comes from the profile file only. Report an environment variable or overlay to the operator. |
| `profile.network_flag_mismatch` | `--network` names a chain other than the loaded profile's. The flag asserts the chain and never selects one. | Remove `--network`, or select a profile on that chain with `--profile <name>`. |
| `auth.enrolled_signer_unpinned` | The mainnet profile's `mcp_signer_default.account` is the placeholder or malformed, so the profile has no enrolled signer identity. | Not agent-recoverable. Report it to the operator, who corrects a malformed `mcp_signer_default.account` and runs `stellar-agent profile enroll-signer --profile <name>`. |
| `auth.enrolled_signer_mismatch` | The resolved signer's key differs from the mainnet profile's enrolled identity. | Do not retry with another key. Use the enrolled seed, Ledger account, or keyring entry, and report both keys in the message to the operator. |
| `profile.mainnet_requires_explicit_profile` | The environment or the default source selected a mainnet profile. | Pass `--profile <name>`. For a mainnet `default.toml`, pass `--profile default`; keep the filename because its identity binds the keyring entries. |
| `profile.key_scope_conflict` | A profile shares a wallet or derived entry with a sibling, two of its fields collide, an overlay names another scope, its owner account is not `default`, or a mainnet profile's `policy_window_state_key_id` is not its default entry. An unreadable selected document or profiles directory also triggers it. Mainnet refuses; testnet warns. Unreadable siblings only warn. Backups in the profiles directory count as siblings. | Do not retry under another name. Give this profile its own entry when it claims another profile's coordinate; correct the sibling file when it claims this profile's canonical entry. Read the offending field with `profile show`. Moving an enrolled reference orphans the stored key; enroll or rotate at its replacement. |
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
`mpp.receipt_conflict`, and `mpp.reconciliation_unavailable`. A charge commit
whose pending approval shows another transport, authority, or target than the
prepared request refuses with `approval.entry_inconsistent` and commits nothing.

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
`audit.chain_key_unavailable`, `audit.tip_anchor_mismatch`,
`audit.tip_anchor_missing`, and `audit.log_binding_changed` from an MPP verb
exactly as the rows above say.

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
  cross-check disagreement (`simulation.divergence`, `network.rpc_divergence`):
  re-run the simulate step and
  commit promptly.
- Hard policy refusal (`policy.deny.*`, `policy.engine_required`,
  `network.mainnet_write_forbidden`): do not retry; only the operator can change
  policy or network posture.
- Network binding refusal (`network.endpoint_network_mismatch`,
  `network.endpoint_identity_unavailable`, `network.rpc_credential_refused`,
  `network.unsupported_protocol_version`, `network.envelope_signed_for_mainnet`,
  `network.envelope_signature_unverifiable`, `network.envelope_unsigned`,
  `network.account_not_found`): nothing was sent. Do not resubmit the same
  envelope against the same endpoint; report the mismatch to the operator.
- Environment or key problems (`keyring.*`, `mcp.disabled_per_profile`,
  `audit.chain_key_unavailable`, other non-zero startup exits): operator-side;
  not agent-recoverable at runtime.
