# Security and safe operation

This wallet places fixed controls between every tool call an agent makes and any
network or signing action. The agent is not assumed to be correct or honest: a
policy engine evaluates each call before any RPC or signature, operator approval
is required for gated cases and is cryptographically bound to the exact
transaction, every invocation is recorded in a tamper-evident audit log, and the
signing seed is kept out of the agent's reach. This file describes the security
model an operator should understand and the safe-operation rules an agent must
follow. For the tool list and argument shapes see `./mcp-tools.md`.

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

Every tool returns one envelope shape:

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

Secrets are never stored in configuration. A profile is a per-environment TOML
file (schema version 2) that binds a CAIP-2 chain id, an RPC endpoint, keyring
entry references, thresholds, and the active policy engine. It holds no secret
material.

- Each `*_key_id` field in a profile is a keyring entry reference: a
  `service` + `account` pair that names a platform-keyring secret. It is never the
  secret itself.
- The signing seed, the nonce key, and every HMAC key (attestation, audit-chain)
  live in the platform keyring: macOS Keychain, Linux Secret Service, Windows
  Credential Manager.
- Because the TOML names secrets but does not contain them, profile TOML is safe to
  back up. The profile's `Debug` output additionally redacts `rpc_url` and
  `secondary_rpc_url`, since those may embed RPC credentials.
- The core library compiles under `#![forbid(unsafe_code)]`. Secret material is
  never written to logs at any level.

The custody boundary is the keyring secret. An attacker who already holds the
seed, nonce key, or HMAC keys is outside the threat model; everything below
assumes those secrets stay in the keyring.

## The unlock window: TTL-bounded, zeroize-on-drop, memory-locked

When a tool needs to sign, the 32-byte signing seed is loaded into a short unlock
window:

- The seed is moved into a zeroize-on-drop buffer, and its backing page is pinned
  in physical RAM via `mlock` (Linux/macOS) or `VirtualLock` (Windows). Pinning the
  page keeps the seed out of swap. The pin is eager: pages are populated and locked
  at lock time, so there is no pre-first-fault swap-disclosure window.
- The window is TTL-bounded. The default is 30 seconds; `wallet.unlock_ttl_seconds`
  is downward-only (a value above 30 is clamped to 30 with a warning) and the hard
  cap is 600 seconds. `ttl_seconds == 0` or `> 600` is rejected.
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

On failure the wallet emits a structured warning carrying `profile`, `reason`, and
`errno` only. No path logs the seed.

```toml
[wallet]
mlock_required = true       # default on Linux/macOS
unlock_ttl_seconds = 30     # default; downward-only, hard cap 600
```

Operational implication for an agent: the window is short. Do not assume an unlock
persists between unrelated calls; each signing action stands up its own bounded
window.

## The mainnet write gate (read-only by default under Noop)

Two structural rules apply across all surfaces:

1. The default network is `stellar:testnet`.
2. Every write or signing command structurally refuses `stellar:mainnet` before
   any RPC call or signing, with wire code `network.mainnet_write_forbidden`.
   `stellar:mainnet` stays accepted for read-only commands.

The policy engine selected per profile in `[policy]` enforces the gate. When no
full engine is configured, the Noop engine is the binding gate, with fixed
behaviour:

| Profile | Tool | Result |
|---------|------|--------|
| testnet | any | Allow |
| mainnet | read-only (`destructive_hint = false`) | Allow |
| mainnet | destructive | refused with `policy.engine_required` |

A destructive tool on a mainnet profile cannot pass the Noop engine. Newly minted
profiles default to the V1 engine (signature-verified typed criteria, first-match
default-deny); profiles carried over from an older schema are set to Noop
explicitly so the mainnet gate stays in place until the operator stands up a V1
owner key.

The narrow exceptions are explicit, consent-gated mainnet operations, e.g.
`smart-account migrate-verifier` which requires `--confirm-mainnet-migrate`. Friendbot
funding is scoped to `testnet` and `futurenet` and refuses `mainnet` with
`network.friendbot_mainnet_forbidden`.

Agent rule: if you receive `network.mainnet_write_forbidden` or
`policy.engine_required`, the action is structurally blocked on that chain.
Switching `chain_id` to mainnet to retry a write will not work and is not a valid
path; surface the block to the operator.

## Arguments are never logged: only key names

The audit log records the **argument key names** (`arg_keys`), never the argument
values, at any log level. The same redaction discipline applies to wire output:

- Strkeys (`G` / `C` / `T` / `M` / `P`) appearing in a decision reason are
  redacted to first-five-last-five, e.g. `GABCD...VWXYZ`.
- Transaction hashes are redacted to first-eight-last-eight.
- The `envelope_hash` is recorded unredacted because it is a SHA-256 digest
  carrying no user data.

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

When the policy engine returns `RequireApproval`, the action does not proceed on
the agent's say-so. It is held in a per-profile pending-approval store until the
operator approves it out-of-band:

```text
stellar-agent approve --id <nonce>
```

`approve` renders a wallet-controlled summary (the destination G-strkey and asset
are validated on deserialize so a hostile entry cannot inject terminal content),
the operator confirms at the terminal, and the command records an HMAC-SHA256
attestation. The attestation:

- Is keyed by the profile's attestation key, which lives only in the keyring.
- Binds the approval nonce, the SHA-256 of the exact transaction envelope that will
  be signed, and the OS process uid.
- Is recorded one-shot: a nonce that is expired, of the wrong kind, or already
  attested is rejected.
- Is verified in constant time on the commit path.

What this means for the threat model: the attestation proves the keyring holder
ran `approve`. The agent's own UI is not a trust input. An attacker who can write
to the store file can at most delete a pending entry (forcing re-approval, a
denial-of-service nuisance) but cannot forge an attestation, because the HMAC key
is in the keyring, not in the file. Rotating the attestation key invalidates all
outstanding pending approvals; the operator must re-approve.

Pending entries are kinded: `PaymentSimulated`, `ClaimSimulated`,
`SignWithPasskey`, `RegisterPasskey`, `ToolsetFirstInvokeGate`,
`TrustlineClawbackOptIn`, and `RuleProposalSimulated`. The store
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

Every tool invocation and lifecycle event is appended to a per-profile,
append-only, hash-chained JSONL audit log. The writer is a per-profile singleton
holding an exclusive lock and appending with an fsync per line; a second opener is
rejected. Files rotate at a size bound with a fixed number of rotated files
retained.

Each entry carries a timestamp, the tool name, the chain id, the argument key
names (`arg_keys`), the envelope hash, the nonce id, the policy decision
(`allow` / `deny:<reason>` / `require_approval`), an optional decision reason, a
request id, the event kind, and the previous entry's hash. Each entry is
hash-chained to the one before it; each file carries a root-HMAC sidecar signed
with the profile's audit key.

Operators verify the chain end-to-end:

```text
stellar-agent audit verify
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
