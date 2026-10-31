# Security and safe operation

This wallet places fixed controls between every tool call an agent makes and any
network or signing action. The agent is not assumed to be correct or honest: a
policy engine evaluates calls and operator approval covers gated cases.
Approval is cryptographically bound to the exact transaction. The audit log
records transaction submissions, signed authorizations, approvals, and explicit
key-management and lifecycle events. MCP balance reads add no audit rows. A payment
simulation adds no invocation row; under V1 it can reconcile overdue
reservations and write their settlement rows. The signing seed stays out of the agent's reach.
This file describes the security
model an operator should understand and the safe-operation rules an agent must
follow. For the tool list and argument shapes see `./mcp-tools.md`.

After name reconciliation, both binaries compare keyring entries with sibling
profile files in the same profiles directory. Mainnet conflicts refuse with
`profile.key_scope_conflict`; testnet conflicts warn and keep the verb's behavior.
The check includes wallet keys, provider credentials and derived entries.
Provider credentials may share with other provider credentials, but cannot share
with wallet or derived entries. Two fields in one profile cannot name one entry,
and the owner account must be `default`. Explicit wallet references must be set
in the file; an out-of-scope overlay is a conflict.

A copied profile file, including a backup in that directory, counts as a sibling.
If this profile names a sibling's entry, give this profile its own entry.
If the sibling claims this profile's canonical entry, correct the sibling file.
Moving an enrolled reference orphans its stored key; enroll or rotate at the new
entry before use. An unreadable sibling warns and is skipped on both chains.
An unreadable selected document or profiles directory refuses on mainnet and
warns on testnet. `profile show` still displays the document for diagnosis.

`profile reset-window-state` writes its `policy_window_state_reset` audit row,
with the wiped accrual, before it mints a key, advances the generation or
replaces the store. A reset whose row cannot be written does not happen.
The `profile` section of `./cli-reference.md` describes the row, the refusals,
the failure windows and the recovery.

The reset requires a current tip anchor before and after its row. If repair
fails, `audit.chain_key_unavailable` carries `audit.tip_anchor_unavailable`,
and the window state and generation remain unchanged. A reset row can therefore
describe an attempted reset that did not take effect.

## Quick rules for an agent

- Branch on the result envelope and wire codes. Never re-issue a refused commit
  with an altered amount, asset, or destination to "get around" a deny.
- A `policy.approval_required` or `RequireApproval` outcome means a human operator
  must run `approve` out-of-band. Wait for that; do not retry in a loop.
- Amounts are decimal strings with a unit, e.g. `"10 XLM"` or `"2.5 USDC"`. Never
  a JSON number.
- Asset is `"native"` / `"XLM"` for the native asset, or `"CODE:GISSUER"` for an
  issued asset, e.g. `"USDC:GA5ZSE...KZVN"` (the issuer is a G-strkey).
- `chain_id` is the CAIP-2 id (`stellar:testnet` or `stellar:mainnet`) and is
  required by most MCP tools. Where it is omittable (the SEP-43 read tools) it
  defaults to the active profile's chain; the wallet's default network is
  `stellar:testnet`.
- Writes and signing are testnet-only in this alpha; a write/sign on
  `stellar:mainnet` is structurally refused with `network.mainnet_write_forbidden`.
- A single-use nonce is minted by the wallet at simulation time and must be passed
  back unchanged at commit time. Do not generate, cache across restarts, reuse, or
  mutate it.

## The result envelope

Every tool returns one envelope shape, with five success-path exceptions:
`stellar_toolset_list` returns a bare JSON array, and `stellar_dex_trade`,
`stellar_dex_quote`, `stellar_defindex_vault_deposit`, and
`stellar_defindex_vault_withdraw` return a bare object carrying a `status`
field. Their business errors use the envelope.
Some refusals use the JSON-RPC error channel instead of the envelope: invalid
arguments, a `chain_id` mismatch, and the toolset capability refusals.
`toolset.first_invoke_approval_required` is a JSON-RPC error too, and its error
data carries the `approval_nonce`.

```json
{ "ok": true,  "data": { ... }, "request_id": "..." }
{ "ok": false, "error": { "code": "...", "message": "..." }, "request_id": "..." }
```

- `ok` is the boolean success flag. Branch on it first.
- On success, read `data`. On failure, read `error.code` (a stable wire code) and
  decide what to do from the code, not by parsing `error.message`.
- `request_id` correlates the call with its audit-log entry; carry it in logs and
  bug reports.

Wire codes are stable and closed-set. Treat the code as the contract; the message
is human-facing detail and may change.

## Self-custody and the platform keyring

Keys are never stored in configuration. A profile is a per-environment TOML
file (schema version 2) that binds a CAIP-2 chain id, an RPC endpoint, keyring
entry references, thresholds, and the active policy engine. It holds no key
material. An endpoint URL can embed a credential in its path or query on any
network. Mainnet refuses only a username or password in the URL.

- Each `*_key_id` field in a profile is a keyring entry reference: a
  `service` + `account` pair that names a platform-keyring secret. It is never the
  secret itself.
- The signing seed, the nonce key, and every HMAC key (attestation, audit-chain)
  live in the platform keyring: macOS Keychain, Linux Secret Service, Windows
  Credential Manager.
- The TOML names keys but does not contain them, so profile TOML is safe to back
  up when no endpoint URL embeds a credential. The profile's `Debug` output additionally redacts `rpc_url`,
  `secondary_rpc_url` and `oracle_provider_url`, since those may embed RPC credentials.
- The core library compiles under `#![forbid(unsafe_code)]`. Secret material is
  never written to logs at any level.

The custody boundary is the keyring secret. An attacker who already holds the
seed, nonce key, or HMAC keys is outside the threat model; everything below
assumes those secrets stay in the keyring.

## The unlock window: TTL-bounded, zeroize-on-drop, memory-locked

When a CLI command signs with a seed read from a `--*-secret-env` variable, the
32-byte signing seed is loaded into a short unlock window. Keyring signers, the
Ledger, and the MCP server never enter it. A keyring signer loads its key for
each signature into a zeroize-on-drop buffer without a memory lock. The unlock
window itself works as follows:

- The seed is moved into a zeroize-on-drop buffer, and its backing page is pinned
  in physical RAM via `mlock` (Linux/macOS) or `VirtualLock` (Windows). Pinning the
  page keeps that buffer out of swap when pinning succeeds. The pin is eager: pages are populated and locked
  at lock time, so there is no pre-first-fault swap-disclosure window.
- The window is TTL-bounded. The default is 30 seconds; `wallet.unlock_ttl_seconds`
  honors any value from 1 through 600 seconds. `ttl_seconds == 0` or `> 600` is
  rejected, never clamped.
- A background timer fires at the TTL and marks the wallet disposed.
- On every exit path, including normal return, error propagation (`?`), and
  panic-unwind, the seed is zeroized and the lock released.

The `mlock_required` posture in `[wallet]` controls what happens when pinning
fails:

| Value | Behaviour on `mlock` failure |
|-------|------------------------------|
| `true` (default Linux/macOS) | Fail closed: unlock aborts, seed zeroed. |
| `"warn"` (default Windows) | Proceed with unprotected memory; emit a warning. |
| `false` | No lock attempted, no warning; operator accepts swap-disclosure risk. |

The posture is set in the profile file and is not overlayable.

On failure the wallet emits a structured warning carrying `profile`, `reason`, and
`errno` only. No path logs the seed.

```toml
[wallet]
mlock_required = true       # default on Linux/macOS
unlock_ttl_seconds = 30     # default; 1 through 600 honored
```

CLI transaction signing copies the seed into an unpinned, zeroize-on-drop
`SoftwareSigningKey` and disposes the window before returning the signer.
The TTL does not bound that copy. `profile sign-policy` signs while the window
is open. Keyring signers and Ledger signing do not use an unlock window.

## The mainnet write gate (structurally read-only)

Two structural rules apply across all surfaces:

1. The default network is `stellar:testnet`.
2. Every write or signing command structurally refuses `stellar:mainnet` before
   any RPC call or signing, with wire code `network.mainnet_write_forbidden`,
   except MPP, which refuses with `mpp.network_forbidden`. `stellar:mainnet`
   stays accepted for read-only commands.

Mainnet writes are structurally refused regardless of the engine selected in
`[policy]`. The Noop engine also applies these fixed policy decisions:

| Profile | Tool | Result |
|---------|------|--------|
| testnet | any | Allow |
| mainnet | read-only (`destructive_hint = false`) | Allow |
| mainnet | destructive | refused with `policy.engine_required` |

A destructive tool on a mainnet profile cannot pass the Noop engine. New profiles
default to V1, which verifies signed policies and evaluates typed criteria with
first-match, default-deny rules.
Enrolling a V1 owner key changes policy evaluation but does not enable mainnet
writes.

There are no consent-gated mainnet write exceptions: every write surface refuses
mainnet structurally. Friendbot funding is scoped to `testnet` and `futurenet`
and refuses `mainnet` with `network.friendbot_mainnet_forbidden`.

The gate does not rest on the declared network alone. The classic payment,
sponsored account creation, trustline, claim, and pool paths ask the RPC
endpoint which network it serves before the first read whose answer they sign
or gate on. They ask on the client that sends, and the MCP simulate tools ask
on their own client. Before it sends, the submit layer asks again on the
sending client.
Both treat the answer as authoritative. An endpoint reporting mainnet is
refused with `network.mainnet_write_forbidden` even when the caller declared
testnet. An endpoint reporting a different network than declared is refused
with `network.endpoint_network_mismatch`. An endpoint whose identity cannot be
established within the timeout is refused with
`network.endpoint_identity_unavailable`. An endpoint that answers the identity
request with HTTP 401 or 403 is refused with `network.rpc_credential_refused`,
without a retry. The same answer carries the endpoint's
protocol version. This release supports protocol 29: outside it, testnet and
other networks log a warning, and a mainnet endpoint is refused with
`network.unsupported_protocol_version`. While mainnet writes are refused, a
mainnet endpoint is refused with `network.mainnet_write_forbidden` first. The
submit layer then verifies every signature on the envelope against the network
the endpoint reported. An envelope with a signature made for mainnet is refused
with `network.envelope_signed_for_mainnet`. One with a signature that verifies
under neither network is refused with `network.envelope_signature_unverifiable`.
An envelope without a signature, or a fee-bump whose outer or inner transaction
carries none, is refused with `network.envelope_unsigned`. An envelope signed
for one network therefore cannot be relayed onto another.

Agent rule: if you receive `network.mainnet_write_forbidden`,
`policy.engine_required`, or any of the network-binding codes above, the action
is structurally blocked on that chain and nothing was sent. Switching `chain_id`
to mainnet to retry a write will not work and is not a valid path; neither will
pointing at a different RPC endpoint to get past a binding refusal. Surface the
block to the operator.

## Arguments are never logged: only key names

The audit log records the **argument key names** (`arg_keys`), never the argument
values, at any log level. The same redaction discipline applies to wire output:

- Strkeys (`G` / `C` / `T` / `M` / `P`) appearing in a decision reason are
  redacted to first-five-last-five, e.g. `GABCD...VWXYZ`.
- Transaction hashes are redacted to first-eight-last-eight.
- The `envelope_hash` is recorded unredacted because it is a SHA-256 digest
  carrying no user data.

On the classic and x402 paths, server-derived text that the wallet does not
validate to a fixed shape reaches an error, a tool result, or a log line
scrubbed. Values validated to a fixed shape (an LDH endpoint host, strkeys, the
network, amounts) are printed as validated. The scrub covers RPC errors, the
simulation `error`, SEP-10 and stellar.toml answers, and x402 header fields.
Each URL keeps its host and port, and each whitespace run becomes one space.
Other control characters and non-ASCII characters become `\u{...}` escapes, and
the text is cut at 200 characters. An error quotes the text.

At the MCP boundary, account, strkey, and contract-id fields inside a deny reason
are redacted before they cross the wire. Policy deny states that an attacker could
otherwise probe are collapsed: the commit-path verifier maps the internal
outcomes `Expired`, `NotFound`, and `AlreadyAttested` all onto the single wire
code `policy.approval_required`, so a caller cannot tell which state a nonce is in.

Agent rule: do not depend on argument values appearing in the audit log; they do
not. Correlate with `request_id`, the envelope hash, and `arg_keys`.

## The wallet-issued single-use nonce for commit

The MCP server mints a nonce at simulation time and verifies it at commit time
through a single-use replay window.

- A nonce is 48 bytes, transmitted as URL-safe base64 with no padding (a 16-byte
  random salt plus a 32-byte HMAC tag). Treat it as an opaque token.
- The HMAC binds the envelope, the tool name, the `chain_id`, an expiry, and a
  per-process boot value. Change any of those and the nonce no longer verifies.
- It is single-use: presenting the same nonce twice is rejected.
- It is fail-closed on restart: the per-process boot value is never persisted, so a
  nonce minted before a server restart is rejected (`HmacMismatch`) afterward.
- The replay window is in-memory and not persisted across process restarts.

Agent flow:

1. Call the simulate step for a write; the wallet returns a nonce in `data`.
2. Pass that exact nonce, unchanged, to the matching commit step.
3. If commit fails because the nonce is invalid, expired, or already used,
   restart from a fresh simulate. Never fabricate, reuse, or edit a nonce.

A nonce binds the commit to one specific transaction envelope. You cannot mint a
nonce for one envelope and commit a different one.

## Operator approval for gated actions

See [approval thresholds](approvals-and-audit.md#v1-engine) for the `approval_above` criterion.

When the policy engine returns `RequireApproval`, the action does not proceed on
the agent's say-so. It is held in a per-profile pending-approval store until the
operator approves it out-of-band:

```text
stellar-agent approve --id <nonce> --profile <name>
```

`approve` renders a wallet-controlled summary (the destination G-strkey and asset
are validated on deserialize so a hostile entry cannot inject terminal content),
the operator confirms at the terminal, and the command records an HMAC-SHA256
attestation. The attestation:

- Is keyed by the profile's attestation key, which lives only in the keyring.
- Binds the profile name, CAIP-2 chain id, approval nonce, envelope digest, and OS process uid under a versioned domain tag.
- Is recorded one-shot: a nonce that is expired, of the wrong kind, or already
  attested is rejected.
- Is verified in constant time on the commit path.

What this means for the threat model: the attestation proves the keyring holder
ran `approve`. The agent's own UI is not a trust input. An attacker who can write
to the store file can at most delete a pending entry (forcing re-approval, a
denial-of-service nuisance) but cannot forge an attestation, because the HMAC key
is in the keyring, not in the file. Rotating the attestation key invalidates all
outstanding pending approvals; the operator must re-approve.

Pending entries are kinded: `PaymentSimulated`, `TrustlineSimulated`, `ClaimSimulated`,
`SignWithPasskey`, `RegisterPasskey`, `ToolsetFirstInvokeGate`,
`TrustlineClawbackOptIn`, `RuleProposalSimulated`, `MppChargeSimulated`, `Rejected`,
and `Consumed`. The store
holds a single exclusive lock, writes atomically with owner-only permissions, caps
the number of pending entries, and applies a default entry TTL of 24 hours.

### First-invoke gate vs. per-action payment approval

Toolset-routed payments use two distinct controls, and only one is suppressible:

- The **first-invoke gate** (`ToolsetFirstInvokeGate`) fires the first time a
  toolset uses a signing-adjacent capability with no matching grant. Once approved,
  a time-boxed grant (default TTL 30 days) is persisted and matched on later
  invocations by toolset, capability, destination, asset, and an amount range. The
  grant suppresses only the first-invoke re-prompt.
- The **per-action payment approval** (`PaymentSimulated`) fires unconditionally on
  every toolset-routed payment, and its attestation binds the actual executed
  envelope.

A forged or tampered grant can at most suppress a re-prompt; it cannot bypass the
per-action approval, because that approval is forced regardless of any grant and is
bound to the real transaction.

Agent rule: expect a gated action to pause for operator approval. Do not interpret
a `RequireApproval` / `policy.approval_required` outcome as a failure to retry; it
is a hold awaiting the operator. Do not attempt to self-approve through any
agent-controlled surface.

## The tamper-evident audit log

The per-profile, append-only, hash-chained JSONL audit log records transaction
submissions, signed authorizations, approvals, and explicit key-management and
lifecycle events. MCP balance reads and payment simulations produce no automatic
invocation row. Under V1, payment simulations can reconcile overdue reservations
and write settlement audit rows.
The writer is a per-profile singleton
holding an exclusive lock and appending with an fsync per line; a second opener is
rejected. Files rotate at a size bound with a fixed number of rotated files
retained.

Each entry carries a timestamp, the tool name, the chain id, the argument key
names (`arg_keys`), the envelope hash, the nonce id, the policy decision
(`allow` / `deny:<reason>` / `require_approval`), an optional decision reason, a
request id, the event kind, and the previous entry's hash. Each entry is
hash-chained to the one before it; each file carries a root-HMAC sidecar signed
with the profile's audit key.

The log records `value_action_submitted` on every
confirmed value-moving submit (carrying the gate-sized value legs) and
`keyring_key_written` on each key-writing profile command. It records
`x402_payment_authorized`, with a passed cross-check witness when the payment
required one, before a signed x402 authorization leaves the wallet
in the RPC re-simulation, and `x402_authorization_withheld` when that payment
then fails. The configured RPC observes the signed x402 authorization.
Approval and rejection rows are written before the decision takes effect.

The `x402_authorization_withheld` stages are `anchor_unavailable`,
`resimulation`, `response_processing`, and `encoding`. The transmit gate checks
the anchor before and after its authorization row. At `anchor_unavailable`,
the signature stays in the wallet and the previously admitted spend remains.

MPP credentials follow a stricter one-shot rule. Durable state is atomically
claimed before policy accounting or signer access; value budget is recorded
before signing. A post-key-access ambiguity becomes `indeterminate` or
`authorized_withheld`, and the same charge can never sign or deliver again.
Never retry MPP commit or create a fallback payment. Use redacted status, host
receipt recording, and independent transaction reconciliation. MPP is
testnet-only and absent from toolset routing; its configured RPC sees signed
authorization during mandatory re-simulation.

Every value-moving signing verb loaded from a persisted profile proves the
audit writer is acquirable BEFORE the signing key is touched or a transaction
is submitted, refusing `audit.chain_key_unavailable` if the profile's audit
chain-root key was never minted (`profile init` mints the keyring coordinate
only; run `profile rotate-audit-key <name>` to mint the key). The zero-config
synthesized profile `pay`/`claim`/`accounts create` fall back to when no
profile was NAMED and no `default.toml` exists stays fail-open for this
specific check. A profile named through `--profile` or `STELLAR_AGENT_PROFILE`
whose file does not exist is refused outright (`profile.load_failed`), not
replaced by that fallback, and a profile file whose owner-key coordinate names
a DIFFERENT profile is refused with `profile.name_mismatch` rather than used to
sign under a name it does not own. The SEP-43
sign-only pair (`signTransaction`, `signAuthEntry`) runs the same pre-flight
before signing. See [Troubleshooting](troubleshooting.md#audit-key-code).

Operators verify the chain end-to-end:

```text
stellar-agent audit verify <LOG_PATH> --profile <NAME>
```

Verification checks per-entry chaining, cross-file rotation handoff (defeating
file substitution), and, when an HMAC key is supplied, the root sidecar. Failures
use a closed set of wire codes, e.g. `audit.chain_broken`, `audit.rotation_gap`,
`audit.hmac_mismatch`, `audit.hmac_sidecar_missing`. A detected mid-rotation crash
(`audit.partial_rotation`) is surfaced as an error and requires operator
intervention; it is never auto-recovered.

## Reporting a vulnerability

Report security issues privately through GitHub private security advisories on the
repository's Security tab ("Report a vulnerability"). Do not open a public issue,
discussion, or pull request for a security report.

Include a description and impact, steps to reproduce (with any required profile
configuration), the affected version or source build, and any proof-of-concept
input with secrets redacted. Do not include real secret seeds, private keys, or
keyring secrets; a redacted strkey or a SHA-256 digest is enough to identify an
affected account or envelope.

In scope and of high interest: an agent escaping or bypassing the guardrails (for
example executing a signing action that should have been denied, forced to
approval, or recorded), or reaching `stellar:mainnet` for a write or signing
action despite the structural refusal (outside the consent-gated exceptions). Out
of scope: defects in your own keyring backend, OS, RPC endpoint, or anchor; and
any issue that requires already holding the wallet's keyring secrets, since custody
of those secrets is the security boundary.
