# Security and safe operation

See [Mainnet configurations and scope](https://github.com/Soneso/stellar-agent-wallet/blob/main/docs/getting-started.md#mainnet-configurations-and-scope)
for build configuration, admitted operations, and exclusions.

The wallet evaluates policy on gated signing paths and enforces approvals on
its two-phase MCP actions. Use those tools for agent payments, account creation,
trustlines, and claims; the CLI serves reads, setup, and operator ceremonies.
CLI signing coverage varies by verb; see
[signing coverage](cli-reference.md#signing-and-approval-coverage).
Approval is cryptographically bound to the exact transaction. The audit log
records transaction submissions, signed authorizations, approvals, and explicit
key-management and lifecycle events. MCP balance reads add no audit rows. A payment
simulation adds no invocation row; under V1 it can reconcile overdue
reservations and write their settlement rows. MCP tools expose no signing seed
or operator approval command. A process running as the operator's OS user holds
the operator's authority; the wallet does not distinguish it from the operator.
See the [trust model](../SKILL.md#overview) for the current limits.
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
A mainnet profile's `policy_window_state_key_id` must name its default entry,
`stellar-agent-policy-window-<name>` with account `default`, even when the file
sets it explicitly. The policy pin and the mainnet enablement nonce sit beside
that entry, so another entry would start from an empty pin and nonce.

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
An enablement nonce requires `--owner-secret-env VAR` with the pinned owner's
seed in every build. With the flag, the row records that owner's signature
over the profile, chain, store digest, generations, bounded reason and request id.
Owner and pin refusals write no reset row and change no store state.
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
- Mainnet writes require a feature-enabled build, installation setup, and
  per-action approval. Excluded operations retain their refusal codes.
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

## The unlock window: clock-checked seed access in a zeroize-on-drop home

When a CLI command signs with a seed read from a `--*-secret-env` variable, the
32-byte signing seed is loaded into a short unlock window. Keyring signers, the
Ledger, and the MCP server never enter it. A keyring signer loads its key for
each signature into a zeroize-on-drop buffer without a memory lock. The unlock
window works as follows:

- The wallet allocates an isolated zeroed home, attempts the configured memory
  lock, then copies the borrowed seed into it. A successful lock keeps it out of swap.
- The clock bounds wallet seed access and transfer. The default is 30 seconds;
  `wallet.unlock_ttl_seconds` accepts 1 through 600 seconds and refuses other values.
- The seed stays in a zeroize-on-drop page, locked when the lock succeeds, until
  its wallet or signer drops it. Drop zeroizes before unlocking and freeing,
  including on panic unwind.
- Mainnet environment signers unlock once per signature and drop the seed afterward.
  Testnet environment signers keep it for the command, which can outlast the TTL.

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

Operational implication for an agent: the window is short. Do not assume an unlock
persists between unrelated calls; each signing action stands up its own bounded
window.

## Mainnet authorization boundaries

Released binaries have `mainnet-write` on. With the feature on, only a typed
authorization issued for the action can satisfy the mainnet-write guard, and
the binary attests its feature state. A build with `--no-default-features` has
the feature off, and no code path in it can satisfy the guard.
The guarantee has one precondition: the claim holds only under the dependency
set pinned and verified by the release.

Feature-enabled builds admit only configured operations. See the local
[CLI](cli-reference.md#mainnet-write-behavior),
[MCP](mcp-tools.md#classic-mainnet-authorization), and
[policy](profiles-and-keys.md#mainnet-policy-body) references for setup.
Policy evaluation alone grants no authority.
The wallet's own signing paths sign mainnet payloads only under mainnet
authorization. The library signers enforce it too: every `Signer`, the public
keyring handle included, signs a mainnet transaction or Soroban authorization
payload only under a mainnet authorization. Code running as the same OS user
with access to a keyring entry can read its seed directly. The keyring entry
is the custody boundary.
Authorized signing and submission independently check sealed authority.
Durable consumption precedes sending.
A signer can run before verification rejects its signature.

| Profile | Noop policy decision |
|---|---|
| Testnet | Allow. |
| Mainnet read | Allow. |
| Mainnet destructive action | Refuse with `policy.engine_required`. |

Smart-account multicall independently requires V1 even on testnet.
Mainnet selection requires an explicit profile. Writes require a dedicated
nondefault profile and matching stored chain, endpoint, and installation binding.
Friendbot remains scoped to testnet and futurenet. MPP, smart-account writes,
DeFi, pool submission, generic signing, and toolset signing remain excluded.

Prepare and commit probe the endpoint before action reads on their client.
Submission checks the sending client again. The endpoint network binds every
signature. `network.envelope_signed_for_mainnet` means verification fails under
the endpoint network and succeeds under mainnet. Authorized mainnet paths also
check the supported protocol version.

After authorization refusal, report the failed action to the operator.
Do not switch networks, nor point at a different RPC endpoint to get past a
binding refusal. A retry requires fresh preparation and fresh approval.
After enablement or policy signing, restart the MCP server. Stale startup
bindings require restart; missing authority names its prerequisite.
A submission timeout has an unknown outcome and requires reconciliation.

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
are validated on deserialize so a hostile entry cannot inject terminal content).
On testnet the operator confirms at the terminal, and the command records an
HMAC-SHA256 attestation. On mainnet a consent also needs a fresh WebAuthn
assertion, with user presence and user verification, from an approval
credential in the owner-signed policy; terminal input and the HMAC key alone
record no mainnet consent. The local browser obtains the signed assertion. The attestation:

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

A matching grant requires a version 3 HMAC that verifies under the profile's
attestation key and profile/chain binding. It must be unexpired, with a lifetime
of at most 30 days, and issued no later than the current time and at or after
the second following the current installation. An invalid install time honors
no grant. Consent issued in the install second re-prompts once. A forged or
edited grant suppresses nothing.

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
`resimulation`, `response_processing`, `encoding`, `payload_release`, and
`terminal_approval`. The transmit gate checks the anchor before and after its
authorization row. At `anchor_unavailable`, the signature stays in the wallet.
On testnet, the spend that policy admitted earlier in the call remains.

The RPC receives the signed authorization during re-simulation. On an admitted
mainnet server, payload release additionally requires consumed release
authorization and pending approval. For an authenticated payment, the ephemeral
key signs the SEP-10 challenge and the wallet submits it to the web-auth server
before the payment build. On mainnet, that submission follows the consumption of
its Message authorization.

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

Report an agent bypassing the guardrails, including signing that policy denies,
needs approval for, or that the audit log records.
Unauthorized mainnet signing, payload release, or submission is also in scope. Out
of scope: defects in your own keyring backend, OS, RPC endpoint, or anchor; and
any issue that requires already holding the wallet's keyring secrets, since custody
of those secrets is the security boundary. Two residues remain on mainnet: a
same-user process that holds the attestation HMAC key can wrap a version 5
record around a user-verified assertion that its own localhost page obtained,
and the owner seed admits approval credentials, so signing the policy on a host
where same-user code runs exposes that seed.

For code running as the same OS user, the owner of an enabled mainnet profile
changes only with a statement signed by the previous owner. The policy pin and
the enablement nonce that carry this continuity sit at the profile's default
window-state entry, and a mainnet profile that names another entry is refused.
Raw deletion of the pin, enablement, and owner entry outside the wallet rests
on the platform keyring.
