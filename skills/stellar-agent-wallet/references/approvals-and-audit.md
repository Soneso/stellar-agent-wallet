# Approvals and audit

See [Mainnet configurations and scope](https://github.com/Soneso/stellar-agent-wallet/blob/main/docs/getting-started.md#mainnet-configurations-and-scope)
for build configuration, admitted operations, and exclusions.

The guardrail loop that sits between an agent's tool call and any signing or
network action: the policy engine, the operator-approval spine, attestations,
and the hash-chained audit log. This file is self-contained; for the MCP tool
surface that drives the simulate/commit handshake see `./mcp-tools.md`.

## The model in one paragraph

Every gated tool/command invocation is evaluated by the active policy engine
before any signature. Reads the decision needs, such as the source account, can
run first. The engine returns Allow, Deny, or RequireApproval.
A RequireApproval action does not execute on the agent's say-so: it is held in a
per-profile pending-approval store. For pay, create-account, trustline, and
claim, simulation records a pending approval when policy requires approval for
either the simulate tool or its paired commit tool, and returns an
`approval_nonce`. The wallet owner runs
`stellar-agent approve --id <nonce> --profile <name>` out-of-band in a trusted
context, reads a wallet-controlled summary, and consents. The command records an
HMAC attestation bound to the profile name, CAIP-2 chain id, exact envelope, nonce, and
local user, and returns `approval_attestation`. The agent presents that blob to
the matching `*_commit` tool, which constant-time-verifies it before executing.
MPP prepare records a request when policy requires approval for prepare or
`stellar_mpp_charge_commit`, and its preview returns the nonce as
`authorization.approval_id`. After the operator approves that nonce, charge
commit reads the recorded attestation from the store; the agent passes none.
Transaction submissions, signed authorizations, approvals, and explicit
key-management and lifecycle events enter a hash-chained audit log.
MCP balance reads and payment simulations produce no automatic invocation row.
Under V1, payment simulations can reconcile overdue reservations and write
settlement audit rows.
`stellar-agent audit verify` checks the log for tampering.

## Conventions used across these surfaces

- Result envelope: `{ok, data, request_id}` on success, `{ok: false, error,
  request_id}` on failure, used by every command group including `profile`,
  `approve`, `audit`, `credentials`, and `toolsets`.
- Exit code: `0` on success, `1` on any error.
- Amounts are decimal strings with a unit (for example `"10 XLM"`), never JSON
  numbers. Asset is `native`/`XLM` or `CODE:GISSUER`.
- `chain_id` is the CAIP-2 id, `stellar:testnet` (default) or `stellar:mainnet`.
- The `profile`, `credentials`, `approve`, and `audit` groups operate only on
  local state (TOML files and platform-keyring entries). None submits a
  transaction. Profile selection and enablement still enforce their
  mainnet-specific prerequisites.

## The policy engine

Each gated invocation is evaluated before it signs. Three decisions:

| Decision | Meaning |
|---|---|
| Allow | The call proceeds. |
| Deny | The call is refused, carrying a typed reason with a stable wire code. |
| RequireApproval | The call is held pending an out-of-band operator approval. |

The engine in `[policy]` governs policy evaluation. Mainnet writes also need a
feature-enabled build, installation setup, and sealed authorization. Signing
and submission independently verify authority. The endpoint network binds every
envelope signature. Reads retain their selection and key-scope checks.

### Classic mainnet confirmation

Testnet pending-approval attestations use version 4: approval kind, creation
time, expiry, and the approver (the local operator or the remote operator
credential the listener verified); an approval recorded under version 2 or 3
needs fresh consent. A mainnet consent is a version 5 attestation that also
binds a verified WebAuthn presence receipt from an approval credential in the
owner-signed policy. `approval.attestation_invalid` covers missing coverage or
a mismatched subject. MCP reports failed approval proofs as
`policy.approval_required`.

This release connects no presence ceremony to the consent surfaces. Direct CLI
confirmation and `approve` render the summary, then refuse every mainnet
consent with `approval.presence_required` before anything is recorded; neither
reads terminal input. The local inbox refuses mainnet approval the same way,
and the remote listener refuses it with `approval.mainnet_remote_unsupported`.
Mainnet writes therefore remain unavailable. Never attempt a mainnet approval
on the operator's behalf.

Allow supplies a 600-second confirmation lifetime. RequireApproval supplies its
configured lifetime. Classic MCP approvals expire at the shorter prepare/commit
lifetime, with Allow contributing 600 seconds. Both names need matching rules.
All four classic pairs require approval even under Allow.

Authorization defaults to 120 seconds, bounded by approval expiry.
Minted authorization holds count against window headroom. Consumption,
invalidation, or expiry releases or converts them. Consumption is single-use
within retained history and checks the policy pin under the state lock.

On mainnet, CLI `approve` refuses `--yes` before store access in both builds
with `approve.yes_refused_on_mainnet`. Testnet approvals keep the CLI y/n
prompt, the local inbox, and the remote listener. CLI `approval.*` errors
retain their codes.

Live consumed or receipt-held MCP approvals use `policy.approval_consumed`.
Consumption followed by pre-send recording failure can leave no tombstone.
Reusing that approval can produce `network.mainnet_authorization_refused`.
After authorization refusal, obtain fresh preparation and approval. Unknown
submission outcomes require reconciliation. Restart MCP after enablement or
policy signing; a stale binding requires restart.

### Noop engine

The policy boundary used when no full engine is configured. Behavior is fixed:

| Profile | Tool | Result |
|---|---|---|
| testnet | any except `smart-account multicall` | Allow |
| testnet | `smart-account multicall` | refused with `policy.engine_required` |
| mainnet | read-only | Allow |
| mainnet | destructive | refused with `policy.engine_required` |

A destructive tool on a mainnet profile cannot pass the Noop engine.
`smart-account multicall` requires the V1 engine and refuses a Noop profile
with `policy.engine_required`. Newly minted profiles default to the V1 engine.

### V1 engine

Evaluates a signed policy document against typed Criteria. The document carries
an ed25519 owner signature over its canonical form; an invalid signature, or a
signature from a key rotated after signing, is rejected.

Evaluation is first-match, default-deny:

1. Rules are walked in declaration order.
2. The first rule whose match (tool name plus chain-id filter) applies is selected.
3. That rule's criteria run in order; the first failing criterion produces a Deny.
4. If all criteria pass, the rule's decision is returned.
5. If no rule matches, the call is denied (`no_matching_rule`).

A Criterion is one typed check: per-transaction cap, per-period (windowed) cap,
rate limit, counterparty allowlist (by classic account, contract account, asset
issuer, or resolved home domain), minimum-reserve guard, multicall bundle-level
checks (inner-count cap, aggregate cap, rejection of
unrecognized inner shapes), quorum satisfaction, a home-domain-resolved guard,
and SEP-10 / SEP-45 session-active checks. Criteria needing external state
(reserves, identity, the counterparty cache, an active session) receive it as an
injected view at the dispatch site; when a required view is absent the criterion
fails closed.

A `HOME_DOMAIN` binding is evidence for one hour from its fetch. An entry
whose fetch time lies more than five minutes in the future counts as expired.
Expired entries satisfy neither the `HOME_DOMAIN` kind of
`counterparty_allowlist` nor `home_domain_resolved`. A policy that relies on
the `HOME_DOMAIN` kind needs `counterparty warm-up` on a schedule shorter than
one hour. Warm-up refreshes only the domains named in `counterparty_allowlist`
criteria that contain `HOME_DOMAIN`. A policy that uses `home_domain_resolved`
keeps each domain it relies on live with a scheduled
`stellar-agent counterparty refresh <domain>` per domain.

At the MCP boundary, account, strkey, and contract-id fields inside a deny
reason are redacted to first-five-last-five before crossing the wire. The tool
registry is fail-closed at startup: a duplicate tool registration or an
unrecognized policy-engine kind is a fatal error, not a silent fallback.

## The simulate / approve / commit handshake

For a signing-adjacent action the agent uses a two-call pattern across the MCP
tools, with the operator's `approve` step in between:

```
1. agent  -> *_build / *_simulate tool
              returns { ..., approval_nonce } and records a pending entry
2. operator: stellar-agent approve --id <approval_nonce> --profile <name>
              reads wallet-controlled summary, consents,
              returns { ..., approval_attestation }
   (operator relays approval_attestation to the agent over a trusted channel)
3. agent  -> *_commit tool, with approval_attestation = <blob>
              commit verifier recomputes + constant-time-compares, then executes
```

Step 1 returns the nonce instead of executing. Step 3 presents the attestation
blob as the `approval_attestation` argument of the matching `*_commit` tool.
The attestation binds the specific envelope, so it authorises exactly one
transaction.

### What `approve --id <nonce> --profile <name>` returns

For a payment-style approval the response includes `approval_attestation`, the
HMAC blob (URL-safe base64, no padding) the agent must present to `*_commit`.
The field is omitted for approval kinds whose gate reads the recorded consent
from the store directly (toolset first-invoke grants, trustline clawback opt-ins).

The `approval_attested` row is written before the approval is persisted. `audit`
is `"written"` when the command wrote it to the log. It is `"queued"` when a
running MCP server or `approve serve` inbox held the audit writer and the row
went to the audit outbox. That process appends it to the log before any process
loads a signing key for the approved action. The command refuses and persists nothing
beside a process that does not drain the outbox (`audit.writer_locked`), and on
any other audit failure. After upgrading, restart a running MCP server and
`approve serve`: `approve --id` refuses beside an older one.
The queue's count and chain head are committed in the platform keyring before approval persists. Removed or changed committed rows refuse acquisition with `audit.outbox_rows_missing`.

```json
{"ok":true,"data":{"approval_nonce":"ABCxyzNonce","attested":true,"process_uid":"501","expires_at_unix_ms":1717000000000,"approval_attestation":"q83vEjRWeJq83v...","audit":"written"},"request_id":"..."}
```

## The approval spine

When the policy engine returns RequireApproval, the action is held in the
approval spine: a per-profile pending-approval store plus a cryptographic
attestation minted at approve time.

### The pending-approval store

A per-profile TOML file at `<approval_dir>/<profile>.toml` holding a flat list
of pending entries:

- A single exclusive advisory lock on a sidecar lock file is held for the
  store's lifetime; a second opener is rejected immediately
  (`approval.writer_locked`).
- Writes are atomic (write-to-temp then rename, with a parent-directory fsync);
  the file is created owner-only.
- Nonces are validated on load; malformed nonces are rejected. The store has a
  hard cap on pending entries (expired entries pruned first) and a default entry
  TTL of 24 hours.

Entry kinds: `PaymentSimulated`, `TrustlineSimulated`, `ClaimSimulated`, `SignWithPasskey`,
`RegisterPasskey`, `ToolsetFirstInvokeGate`, `TrustlineClawbackOptIn`,
`RuleProposalSimulated` and `MppChargeSimulated`.
`Rejected` and `Consumed` record resolved requests and cannot be approved.

### What `approve` does

`stellar-agent approve --id <nonce> --profile <name>` loads the store and renders a
wallet-controlled summary of the pending action. For payments, trustlines and
claims the summary is decoded from the stored transaction envelope, the bytes the
attestation binds, and every value is rendered with control characters, line
and paragraph separators and Unicode format characters (category Cf) shown as
visible escapes, so the operator reads what is signed and memo text cannot
rewrite the terminal. An entry whose envelope does not decode or does not match
its stored digest, or an MPP charge whose shown terms do not match its
authorization fingerprint, is shown as inconsistent and cannot be approved
(`approval.entry_inconsistent`). The operator confirms at the
terminal; the command then records the consent. Recording is one-shot: a nonce
that is expired, of the wrong kind, or already attested is rejected. Approval is
bound to the local user: the process uid recorded at create time is re-derived
at approve time and must match, so a different local user cannot consent on the
holder's behalf.

Per kind:

| Kind | What `approve` records |
|---|---|
| `PaymentSimulated` / `ClaimSimulated` / `TrustlineSimulated` | Refuses with `approval.entry_inconsistent`, before the consent row, unless the stored digest is the SHA-256 of the stored envelope and the envelope decodes. Then computes the HMAC attestation over that digest and persists it; returns `approval_attestation`. Each commit tool accepts its own approval kind. |
| `TrustlineClawbackOptIn` | Computes a domain-separated HMAC over `(network, code, issuer)` and stores it; the trustline gate recomputes and verifies it. No `approval_attestation` returned. |
| `ToolsetFirstInvokeGate` | Builds and persists a time-boxed toolset grant, then consumes (removes) the pending entry. Does not set an attestation blob on the entry. No `approval_attestation` returned. |
| `RuleProposalSimulated` | Computes the HMAC attestation over `proposal_sha256` (the domain-separated digest of the FULL resolved rule definition), not an envelope hash; persists it and returns `approval_attestation`. A DEDICATED gate verifies it at commit. The envelope approval gate rejects this kind. |
| `MppChargeSimulated` | Attests the prepared artifact hash under the profile and chain binding; returns `approval_attestation`. |
| `Consumed` | Already resolved; cannot be attested again. |

For every kind the consent row is written first and is fatal: when it cannot be
written, nothing is recorded. The store entry is re-read under its lock just
before the row. An entry another process attested, rejected, or consumed since
validation is refused with `approval.already_attested`, `approval.rejected`, or
`approval.consumed`, and no row is written.

The CLI summary and both inbox detail pages show the profile name, CAIP-2 chain id, endpoint authority, and enrolled signer.
An enrollment placeholder appears as `(not enrolled)`.
Payment, claim, and trustline summaries are decoded from the envelope the approval attests: every destination, amount, asset, memo, limit, balance id, fee, and sequence number shown is the envelope's.
The effective source is the operation source when the operation has one, otherwise the transaction source.
A claim names the balance by id only, so its asset and amount read `not part of the signed claim transaction`.
Every value renders control characters as visible escapes such as `\u{1b}`.
A request whose stored digest is not the digest of its stored envelope, or whose envelope does not decode, shows as `INCONSISTENT`, offers no approve action, and is refused with `approval.entry_inconsistent`.
Trustline summaries show the holder account, asset code, issuer, limit,
fee, and sequence number.
The CLI names the action `trustline change (ChangeTrust)`.
The CLI limit reads `unlimited`, `0 stroops (removes the trustline)`, or the exact
stroop count and decimal asset amount.
Both inboxes label it `TRUSTLINE` and offer `Approve trustline`.

### The attestation

The attestation is an HMAC-SHA256 tag, keyed by the profile's attestation key
(which lives only in the platform keyring), over a length-prefixed canonical
input:

```text
mac.update(b"stellar-agent-approval-attestation:v2")
mac.update(u32_be(len(profile_name)))   mac.update(profile_name)
mac.update(u32_be(len(chain_id)))       mac.update(chain_id)
mac.update(u32_be(len(approval_nonce))) mac.update(approval_nonce)
mac.update(envelope_sha256)
mac.update(u32_be(len(process_uid)))    mac.update(process_uid)
```

Lengths count UTF-8 bytes, encoded as big-endian `u32` with saturation at `u32::MAX`.
The 37-byte tag has no length prefix or NUL terminator; the digest is 32 bytes with no prefix.
The tag separates this HMAC from every other use of the key.
The profile name and CAIP-2 chain id make a blob unverifiable under another profile or chain.
A layout change bumps the tag; blobs under the previous tag do not verify.
Pending approvals use version 4 of this input, under the tag `stellar-agent-approval-attestation:v4`: the fields above, then the approval's kind, creation time and expiry, then the approver.
Every commit requires version 4, so an approval recorded under an earlier layout needs fresh consent.

The length prefixes prevent boundary-collision attacks. The `envelope_sha256`
slot binds the tag to the exact transaction envelope that will be signed. The
`process_uid` (numeric OS uid on Unix) gives cross-account-on-host non-replay: a
tag minted by one local user cannot be replayed by another.

The MCP commit-path verifier recomputes the tag and compares it in constant
time. It collapses the distinct internal outcomes (Expired, NotFound,
AlreadyAttested, forged) into the single wire code `policy.approval_required`,
so a caller cannot probe which state a nonce is in. The CLI `approve` path
surfaces distinguishable errors to the operator, who is the wallet owner.

The attestation proves the keyring holder ran `approve`, not that a human
clicked "yes" in an agent-controlled UI. An attacker who can write to the store
file can delete a pending entry (a denial-of-service nuisance forcing
re-approval) but cannot forge an attestation, because the HMAC key is in the
keyring, not the file. Rotating the attestation key invalidates all outstanding
pending approvals.

### `approve` command reference

`stellar-agent approve --id <NONCE> --profile <name>`: state-changing (records an attestation or
a grant in the on-disk store).

| Flag | Required | Default / resolution | Meaning |
|---|---|---|---|
| `--id <NONCE>` | yes (this form) | none | The approval nonce from the agent surface's simulate/build response. |
| `--profile <NAME>` | no | `--profile`, then `STELLAR_AGENT_PROFILE`, then `default` | Profile whose attestation key and store to use. |
| `--yes` | no | off | Non-interactive auto-approve. Bypasses the stdin prompt; the wallet-controlled summary is still printed for a visible record. For trusted automation and tests, not routine operator use. |

Interactively the command prints the summary and prompts `Approve? [y/N]:`;
only `y`/`yes` (case-insensitive) consents, everything else (including empty
input, `n`, EOF) denies. Exits `1` when the nonce is unknown, expired, already
attested, created by a different local user, denied at the prompt, or on I/O
error.

```bash
stellar-agent approve --id ABCxyzNonce --profile <name>
stellar-agent approve --id ABCxyzNonce --profile myprofile --yes
```

`stellar-agent approve gc`: state-changing. Evicts every pending entry whose
TTL has elapsed and reports the count. When `gc` is present, any `--id` is
ignored. Evicting zero entries is a success.

| Flag | Required | Meaning |
|---|---|---|
| `--profile <NAME>` | no | Profile whose store to garbage-collect (same resolution as above). |

```bash
stellar-agent approve gc --profile default
```
```json
{"ok":true,"data":{"profile":"default","evicted_count":3},"request_id":"..."}
```

## Operator approval surfaces

The agent's job is the same regardless of how the operator consents: present
the `approval_nonce` from the simulate/build response, wait for the operator
to produce an `approval_attestation`, then call the matching `*_commit` tool
with it. Three surfaces exist for the operator side of that handshake:

- **CLI, one at a time**: `stellar-agent approve --id <NONCE> --profile <name>` (see the command reference), or
  `stellar-agent approve list` to enumerate every pending entry first
  (read-only; `--include-expired` also shows expired ones).
- **Loopback web inbox**: `stellar-agent approve serve` binds a local HTTP
  server and opens a browser to the pending-approval queue, so the operator
  clicks Approve/Reject per entry without running `approve --id <nonce> --profile <name>` per nonce.
  The browser opens through a private redirect file, so the launcher never
  receives the bootstrap URL. Approve and Reject require the session cookie,
  an origin-scoped session proof, and a CSRF value. The inbox session expires
  after 15 minutes without operator activity or 8 hours after bootstrap;
  background polling does not extend it, and the operator restarts
  `approve serve` for a new session.
- **Remote approval**: `stellar-agent approve serve --remote
  --confirm-remote-exposure` binds a TLS-protected listener reachable from a
  device other than the wallet host, authenticated by a registered WebAuthn passkey. Use it when the agent runs on a headless machine. Every approve or
  reject additionally requires a fresh passkey assertion bound to the exact
  entry.

None of this changes what the agent does. The attestation also records which
surface approved: the local operator, or the remote operator credential. When
the operator revokes that credential before the commit, a mainnet commit
returns `policy.approval_required`, and the action needs fresh consent. See
"The attestation" above. Setup for remote approval (the profile's
`[remote_approval]` block, enrolling a passkey via `approve operator enroll`,
the trust model, DNS requirements) is out of scope here; see
`docs/remote-approval.md` in the wallet repository for the full operator
guide.

A remote approve or reject is recorded in the audit log under
`ApprovalAttestedRemote` / `ApprovalRejectedRemote` event kinds rather than
the loopback `ApprovalAttested` / `ApprovalRejected` ones. This is the distinguishing detail when reading the audit log directly. Both remote kinds also carry
`operator_credential_id_redacted`, a stable, non-reversible pseudonym for
which passkey credential consented (the first 8 hex characters of
`SHA-256(credential_id_b64url)`). Nothing else about the attestation or its
binding differs from a local approval.

## First-invoke gate vs. per-action payment approval

Toolset-routed payments use two distinct controls, and only one is suppressible.

- The first-invoke gate fires the first time a toolset uses a signing-adjacent
  capability with no matching grant. It queues a one-time `ToolsetFirstInvokeGate`
  entry. Once the operator approves it, a time-boxed toolset grant is persisted
  (default TTL 30 days) and matched on later invocations by toolset, capability,
  destination, asset, an amount range, plus its TTL. The grant suppresses only
  the first-invoke re-prompt.
- The per-action payment approval (`PaymentSimulated`) fires unconditionally on
  every toolset-routed payment, and its attestation binds the actual executed
  envelope.

A matching grant requires a version 3 HMAC that verifies under the profile's
attestation key and profile/chain binding. It must be unexpired, with a lifetime
of at most 30 days, and issued no later than the current time and at or after
the second following the current installation. An invalid install time honors
no grant. Consent issued in the install second re-prompts once. A forged or
edited grant suppresses nothing.

## The hash-chained audit log

The MCP server acquires its audit writer when an operation needs it, such as a commit preflight before signing. MCP balance reads do not acquire it. Under V1, payment simulations can reconcile overdue reservations, acquire the writer, and write settlement audit rows.

The registry normally caches the writer and holds its lock until process exit. A replaced-file refusal during acquisition marks the cached writer for eviction. After callers release it, the next acquisition drops it and checks the file at the path against the anchor.

A server holding that profile's writer blocks rotation or repair, even if the
operation that acquired it later fails.

A per-profile, append-only JSONL file records transaction submissions, signed
authorizations, approvals, and explicit key-management and lifecycle events.
MCP balance reads and payment simulations produce no automatic invocation row.
Under V1, payment simulations can reconcile overdue reservations and write
settlement audit rows. The writer is a per-profile singleton holding an
exclusive
lock, appending with an fsync per line; a second opener is rejected. Files
rotate at a size bound with a fixed number of rotated files retained.

Each entry carries: a timestamp, the tool name, the chain id, the argument key
names (`arg_keys`), the envelope hash, the nonce id, the policy decision
(`allow` / `deny:<reason>` / `require_approval`), an optional decision reason, a
request id, the event kind, and the previous entry's hash. Argument values are
never logged; only their key names are. Strkeys in a decision reason are redacted to
first-five-last-five and transaction hashes to first-eight-last-eight; the
envelope hash is left intact (it is a SHA-256 digest carrying no user data).

The log records `value_action_submitted` on every
confirmed value-moving submit (carrying the gate-sized value legs) and
`keyring_key_written` on each key-writing profile command. It records
`x402_payment_authorized`, with a passed cross-check witness when the payment
required one, before a signed x402 authorization leaves the wallet
in the RPC re-simulation. When that payment then fails, it records
`x402_authorization_withheld` with the same request id and a `failure_stage`
of `anchor_unavailable`, `resimulation`, `response_processing`, `encoding`,
`payload_release`, or `terminal_approval`. At `anchor_unavailable`, the signed
authorization stays in the wallet. On testnet, the admitted spend remains
recorded. Mainnet `x402_payment_authorized` rows record `RequireApproval`, the
payment value leg, network, scheme, any required witness, and
`signature_expiration_ledger`, the last ledger at which the signed
authorization is valid. On mainnet, three
consumption boundaries apply. The Message authorization of an authenticated
payment is consumed before the SEP-10 signature. The payment intent is consumed
before the signed simulation. The submit authorization is consumed before
payload release. MPP adds
`mpp_charge_authorized`, `mpp_authorization_withheld`, `mpp_receipt_observed`,
and `mpp_settlement_reconciled`; these carry only hashes, redacted references,
the exact policy-sized legs, and closed status labels, never a credential,
challenge, receipt, XDR, or signature.

`MppChargeSimulated` is a dedicated short-lived approval kind. It binds the
authorization fingerprint and prepared artifact hash. Every surface checks the
profile, payer, amount, token, recipient, and challenge expiry against the
fingerprint, and the network against its passphrase digest; the commit checks
the transport, authority, and target against the prepared request
(`approval.entry_inconsistent`). The simulated fee reads `not bound to this
approval`. A mismatch, or an entry without binding digests, makes the entry
inconsistent; prepare the charge again. Local and remote views
redact payer/recipient. Prepare records
the request when policy requires approval for prepare or charge commit. Commit
re-evaluates its own tool name against current state and requires the matching
attestation. An exhausted cap returns `policy.deny.per_period_cap_exceeded`.
The loaded policy document stays fixed for the server's lifetime.

Each entry's hash is computed over its own canonical JSON (with the previous-hash
field treated as empty) concatenated with the previous entry's hash, chaining
every entry to the one before it. The first entry of the very first file chains
off a fixed zero block; the first entry of each later file chains off the prior
file's rotation-handoff entry. Each file also carries a `root_hmac` sidecar
signing the chain root with the profile's audit key.

### The tip anchor

The chain and the per-file `root_hmac` sidecars verify a PREFIX of the log, so
restoring an older copy of the active file, or truncating it, leaves a log that
still verifies. The tip anchor closes that: for each log PATH the keyring holds
the active file's entry count, last-entry hash, and byte offset.

The anchor, the re-anchor counter, and the audit binding live in the keyring,
outside the log file. Anyone who can restore the keyring's own storage together
with the log can restore an older state. With a headless keyring backend these
entries are kept in a file on the same host. Anyone who can write that file can
restore older entries or delete one, which needs no key material. A deleted
binding is recorded again from the profile file at the next keyed use. A
deleted anchor is refused while anything shows it was written (see the table
below). Mainnet readiness refuses a headless backend with
`network.mainnet_keyring_backend_unsupported`, because a restored copy of its
file can make a truncated log and its anchor agree.

Every value-moving verb checks the anchor before signing, on every acquisition of
the audit writer. Eight outcomes:

| Log versus anchor | Result |
|---|---|
| The file at the log path is not the one the process already has open | Refuses `audit.tip_anchor_mismatch`; the cached writer is dropped so the next call reads the path afresh |
| An anchor write in this process failed and its retry fails again | Refuses `audit.chain_key_unavailable` with `audit.tip_anchor_unavailable`, before the log is compared with the anchor |
| Exactly the anchored tip | Proceeds |
| Ahead of the anchor, anchored entry intact | Proceeds; the tail is absorbed and the anchor advances |
| Behind the anchor, or the anchored entry is not at the anchored offset | Refuses `audit.tip_anchor_mismatch` |
| No anchor, and a recorded audit binding, a chain-root sidecar, or an `audit_tip_anchored` row in the file shows one was written | Refuses `audit.tip_anchor_missing`, naming the evidence |
| No anchor, file has entries, chain verifies, none of that evidence | Adopts the current tip and records `audit_tip_anchored { reason: adopted }` |
| No anchor, file empty, no chain-root sidecar | Proceeds; no anchor and no row until the first append |

The ahead-of-anchor case is ordinary, not an exception. Writers opened without
the audit key append without moving the anchor: the CLI startup advisory, and
the zero-config and read-only smart-account paths of a profile whose audit key
is not minted. Adoption needs
no operator action and is what happens on the first keyed use of a log that
only unkeyed writers wrote. An adoption writes its row only for a non-empty
file.

The anchor names a PATH, not a profile, so a changed `audit_log_path` or audit
key has an anchor coordinate of its own. The audit binding guards that change.

### The audit binding

For each persisted profile the keyring records the SHA-256 of its lexically
normalized `audit_log_path` and its audit-key coordinate, at service
`stellar-agent-auditbinding-<profile>`, account `default`. The first keyed use
records it from the profile file, once the audit key has loaded. Before the audit key loads, every keyed audit
writer compares the profile with the record:

| Record | Persisted profile | Synthesized zero-config profile |
|---|---|---|
| Absent | Records it and proceeds | Proceeds; records nothing |
| Equal | Proceeds | Proceeds |
| Different or unparseable | Refuses `audit.log_binding_changed` | Refuses `audit.log_binding_changed` |

The refusal names the profile and the remedy, never a path or coordinate. It
covers the value-moving verbs and tools, the read-only smart-account verbs,
`approve --id <nonce>`, `approve serve`, `audit verify --profile`,
`profile rotate-audit-key`, and `profile reset-window-state`. It
creates nothing at the path the profile names. A command whose audit row is
best effort skips the row and continues:
`credentials add-passkey` and the other `profile`
enroll and rotate verbs.
Not agent-recoverable: the operator establishes
why the profile changed, then runs `stellar-agent audit reanchor --profile
<NAME> --acknowledge-binding-change`. The zero-config profile has no profile
file, and `audit reanchor` loads only a profile file: restore the `default.toml`
that recorded the binding, or write one that names the log, then run the
reanchor.

The default `audit_log_path` derives from the OS data directory, which follows
`$HOME` and `$XDG_DATA_HOME`. Two profile files of one name in two data roots
that share one keyring bind different digests and refuse each other; set an
explicit `audit_log_path` there.

A rotation leaves the anchor on the outgoing file's handoff entry until the new
file's first append, so restoring the whole audit directory to an earlier
snapshot is refused rather than absorbed.

Keyed appends commit their in-memory state and retry the anchor once under the
sidecar lock. Plain appends stay best-effort. A submission recorded through the
pending row, the window-state reset, and an x402 payment require a current
anchor before and after their pre-action row. `audit.tip_anchor_unavailable`
refuses the send or the wipe while repair fails. A pending-row refusal before
the row writes no receipt and no row. After the row, the recorder attempts the
release of the reservation, a `value_action_failed` row under
`submission.record_unavailable` that closes the pending row, and the removal of
the receipt, each best-effort and logged. A resend that the reservation's
duplicate check refuses after its row leaves that row open for the original
submission's settlement. MPP's charge row keeps its existing flow. On testnet,
an x402 refusal keeps the admitted spend. On mainnet, a consumed payment intent
retains its debit after a later failure. A refusal before consumption
invalidates the open intent and releases its holds.

`resolve_message_sign` checks the consumer, verified policy and enablement,
intent network, approval binding and lifetime, and audit readiness before
minting. The Message record binds the home domain, web-auth domain, server key,
challenge digest, ephemeral key, policy, enablement, and approval. It reserves
no value. `consume_message_sign` consumes the authorization and returns
`MessageUseReceipt`. The receipt carries the bound facts and owns the audit
lease. `X402MainnetProofs::with_authenticated` moves the receipt into the owned
payment proofs. The authenticated payment continues its used Message record with
one Soroban intent. The intent permits one payload-release child under the same
approval.

A minted Message record is open. Successful consumption makes it used. Refused
consumption attempts invalidation. An already settled record stays settled. If
cleanup fails, the record remains open until expiry. The cleanup warning retains
the primary refusal. Each authorization refusal emits one warn-level
`mainnet authorization refused` entry with `path` and `precondition`. The MCP
identity mapper does not log that refusal again. A failed cleanup after a
refused Message consumption emits `mainnet authorization cleanup failed`. It is
separate from the primary refusal.

On mainnet, after release authorization is consumed, the tool consumes the pending approval.
A failed or absent pending-record consume withholds the payload. The
`payment withheld at terminal approval` prefix marks a refusal after the signed
re-simulation. The x402 tombstone's `tx_hash` contains the lowercase
final-envelope digest. The digest hashes the final envelope's base64 text,
rather than a chain transaction. `approve list` shows it as
`spent (X402Payment), final-envelope digest <redacted digest>, outcome <outcome>`.

For `audit.tip_anchor_unavailable`, restore keyring access and retry. A live
writer repairs the anchor value it still owes; an honest same-generation tail
is absorbed at keyed acquisition. A mismatch requires the acknowledging repair.

An outage covering both the handoff and first new-file anchor leaves the anchor
on the pre-handoff tip. After process exit, open and verify report a mismatch
on the honest log; investigate and use `audit reanchor` to recover.

Retention keeps ten archives plus the active file when pruning succeeds. Before
each deletion, `<log>.pruned` records the successor's seed, the outgoing file's
seed, and a count of pruned files. A keyed writer signs that marker.
`audit verify` uses the marker to walk retained history and reports
`pruned_prefix`; it still refuses edits and deletions beyond that boundary. An
interrupted deletion keeps its outgoing seed available for verification. The
writer prunes after the new active file exists, and a prune never fails the
rotation. It deletes only archives of one fully validated chain that ends at
the archive just rotated: every archive opens as a regular file within a read
budget, every entry chains from the one before it, under a keyed writer every
archive's first entry carries a chain-root tag that verifies under its key, and
the just-rotated archive matches the seed and handoff the writer holds in
memory. The oldest archive must chain from the seed the marker records for it,
or from the zero seed when none exists; `audit verify` reads that start by the
same rule. A log whose oldest archives or marker were removed outside the
writer stalls pruning until the operator moves it aside and runs
`audit reanchor --acknowledge-rollback` on a new log. A planted, edited, split,
unreadable, or oversized file in that range stalls pruning until it is removed.
The writer names each archive so it sorts after every existing one, also after
the clock is set back, so a sibling placed under a later name precedes the next
archive and stalls pruning too. An append whose row exceeds 1 MiB refuses with
`audit.row_too_large` and never writes the row. A rotation handoff is always
its file's last entry, keyed or unkeyed, and a rotation never renames over an
existing file. A keyed open writes a missing chain-root tag only for a file its
anchor proves from byte 0; an anchored file that fails the proof refuses with
`audit.tip_anchor_mismatch`.
A marker that does not parse, does not authenticate, or names neither
boundary, a failed marker write, or a failed removal also stops the prune.
Every stop logs a warning and keeps excess archives in place. Past 21 rotated
files, open and verify refuse with `audit.too_many_rotated_files`.

Settlement and receipt-clear lookups walk retained files newest first, and a
match leaves older files unvisited. Each visited file's own chain is verified;
in a log with no archives the first row must chain from the zero hash. The
eleventh rotation deletes the oldest archive. The lookup runs outside the
writer lock: two reconciliations of one hash can both find an owed row, and a
concurrent append that rotates the log can move the matching file out of the
walk. When the settlement lookup cannot read the history, `tx status` and
`stellar_transaction_status` log the error and write no settled row. Where
the profile has an audit writer, `tx receipt clear` refuses with the verifier's
code, such as `audit.chain_broken` for a broken chain, and keeps the receipt.

The anchor is written after the entry it covers is fsynced, so it is not
continuous in time. Three states, differing in kind:

- **Lagging**: between an entry's fsync and its anchor write, the anchor names
  the previous entry of this file. A rollback to that entry or later is
  absorbed; anything earlier is still refused. The anchor retries once
  immediately, then on the next append or keyed acquisition. After process
  exit, rollback to the previous anchor silently loses the unanchored tail.
- **Off, nothing anchored yet**: until the first keyed append on a log path (a
  new profile, a log written before the anchor existed). Adoption takes the file
  as it finds it. A changed `audit_log_path` is refused by the audit binding
  until it is acknowledged.
- **Off, freshly rotated file**: from a rotation until the first append into
  the new file is anchored. Any prefix of that file is accepted if it chains
  from the archive's handoff.

Entries already in an archive stay guarded in all three.

What it does NOT do is detect forgery. The entry-to-entry chain hash is unkeyed,
so an appended well-formed entry moves the tip forward and is accepted, exactly
as an honest append is. The anchor detects rollback, truncation, and
substitution, within the keyring scope stated above.

Recovery from a mismatch is `stellar-agent audit reanchor --profile <NAME>
--acknowledge-rollback`. Recovery from a changed binding is the same verb with
`--acknowledge-binding-change`. Not agent-recoverable: the operator has to
establish why the log or the profile changed before accepting it.

### Fail-closed on an unminted audit key

`profile init` mints the audit chain-root key's keyring coordinate only, no key
material. Every value-moving signing verb, CLI and MCP alike, loaded from a
persisted profile proves the audit writer is acquirable BEFORE the signing key
is touched or a transaction is submitted. If the key was never minted (run
`stellar-agent profile rotate-audit-key <name>`), the verb refuses
`audit.chain_key_unavailable` instead of signing unaudited. This applies on
both policy engines. It is distinct from the writer's post-confirm emission
(the `value_action_submitted` row above), which stays non-fatal: the
transaction has already committed by then, so refusing helps nobody.
Read-only tools and the build/simulate stages of two-phase verbs never reach
this pre-flight. `smart-account rules verify-pins`, `signers list`, and
`signers refresh` record audit rows, so they reach it without loading a signer.
The zero-config synthesized profile `pay`/`claim`/
`accounts create` fall back to when no profile was NAMED and no `default.toml`
exists stays fail-open for this specific check, matching its documented
no-profile-required posture; a profile named through `--profile` or
`STELLAR_AGENT_PROFILE` whose file does not exist is refused outright. The
SEP-43 sign-only pair (`signTransaction`, `signAuthEntry`) runs the same
pre-flight and records an `opaque_payload_signed` row when the signature is
produced.

### `audit verify` command reference

`stellar-agent audit verify <LOG_PATH>`: read-only. Walks the log oldest-first,
follows rotation manifests across rotated files, and verifies the hash chain end to end. Each entry's recorded previous-hash matches the recomputed prior-entry hash. Each file's first entry chains correctly across the rotation boundary. Each rotation handoff names the actual next file (defeating file-substitution).
When `--profile` is supplied it also verifies the chain-root HMAC sidecars;
without it, only the hash chain is checked and `hmac_verified` is `false`.

The tip anchor is checked only when `--profile` is supplied AND `<LOG_PATH>` is
the log that profile configures, since the anchor names a path. Every other case
reports `anchor.status` as `"not_checked"` with the reason and still verifies the
chain in full. The check applies the same rule the writer applies, including
proving the anchored entry is still at the anchored offset, so a longer
internally consistent log that does not contain it refuses rather than passing on
length alone. With `--profile` the profile's audit binding is read and never
written: a changed or unparseable binding exits `1` with
`audit.log_binding_changed`.

| Argument | Required | Meaning |
|---|---|---|
| `<LOG_PATH>` (positional) | yes | Path to the audit log file. |
| `--profile <NAME>` | no | Profile whose chain-root HMAC key verifies the sidecars. |
| `--output <FORMAT>` | no | Output format; `json` is the default and only stable format. |

Default log path by OS:

| OS | Path |
|---|---|
| Linux | `~/.local/share/stellar-agent/audit/<profile>.jsonl` |
| macOS | `~/Library/Application Support/Soneso.stellar-agent/audit/<profile>.jsonl` |
| Windows | `%LOCALAPPDATA%\Soneso\stellar-agent\data\audit\<profile>.jsonl` |

On Unix, the command refuses to verify a log whose parent directory is owned by
a different user (such a directory could be used to substitute files or
sidecars). Exits `0` when the chain is intact, `1` on any integrity violation, a
path-contract failure, or an I/O error. Verification failures use a closed set
of wire codes, for example `audit.chain_broken`, `audit.rotation_gap`,
`audit.hmac_mismatch`, `audit.tip_anchor_mismatch`, `audit.tip_anchor_missing`, with line and file detail
kept out of the code.

A `pruned_prefix` warning reports `first_file`, the oldest file walked, and
`pruned_files`, the count in `<log>.pruned`. The marker seeds that file's first
entry and is authenticated when an audit key is supplied. Verification checks
every retained entry and bridge, and the warning leaves the verdict successful.

`outbox_pending` counts complete queued consent lines. With `--profile` and the profile's log path, verification checks the keyring commitment under the outbox lock after the chain walk. A missing or changed committed prefix fails with `audit.outbox_rows_missing`; a held lock fails with `audit.outbox_busy`. Without a profile, no commitment is checked. The separate count inspection can report `outbox_torn_tail`, `outbox_unparseable`, or `outbox_unreadable` warnings.

An `outbox_loss_acknowledged` warning names each loss acknowledgement's file, line, `expected_rows`, and `found_rows`. It leaves the chain verdict unchanged.

```bash
stellar-agent audit verify ~/.local/share/stellar-agent/audit/default.jsonl --profile default
```
```json
{"ok":true,"data":{"entries_verified":42,"files_walked":2,"hmac_verified":true,"per_file":[],"warnings":[],"audit_writer_degraded":false,"anchor":{"status":"verified","reason":null},"outbox_pending":0},"request_id":"..."}
```

### `audit reanchor` command reference

`stellar-agent audit reanchor --profile <NAME>` with `--acknowledge-rollback`,
`--acknowledge-binding-change`, or both: the only way out of an
`audit.tip_anchor_mismatch`, `audit.tip_anchor_missing`, or
`audit.log_binding_changed` refusal.
Operator-only; an agent must never run it on its own initiative, because it
accepts a log or a profile change that may have been tampered with.

| Argument | Required | Meaning |
|---|---|---|
| `--profile <NAME>` | yes | Profile whose configured log path identifies the anchor. |
| `--acknowledge-rollback` | per the matrix below | Accept the log's current tip as authoritative. |
| `--acknowledge-binding-change` | per the matrix below | Accept a log path or audit key that differs from the recorded binding. |

| Recorded binding | Current path's anchor | Flags required | Rows appended |
|---|---|---|---|
| Equal or absent | Any | `--acknowledge-rollback` | `rollback_acknowledged` |
| Changed or unreadable | Agrees, or absent without prior anchoring evidence | `--acknowledge-binding-change` | `binding_changed` |
| Changed or unreadable | Disagrees, cannot be parsed, or absent with prior anchoring evidence | Both | `rollback_acknowledged`, then `binding_changed` |

The first row covers a disagreeing anchor and a missing one
(`audit.tip_anchor_missing`). In the binding-changed rows an absent anchor
disagrees when a chain-root sidecar or an `audit_tip_anchored` row shows prior
anchoring. Without evidence it agrees.

A flag the matrix does not require is ignored. A missing flag changes nothing
and exits `1` with `validation.acknowledgement_required`, naming the flag. With
the required flags it replays the whole log and refuses a broken chain. It then
writes the current tip, bumps the current path's re-anchor counter once, and
appends the rows, each carrying that count. `rollback_acknowledged`
names the superseded anchor; `binding_changed` names the old path's anchor, or
none when the record was unreadable. The new binding is stored last, and an
absent binding is recorded after a rollback repair. It takes the audit writer's
exclusive lock. While an MCP server holds that profile's writer, repair
refuses with `audit.writer_locked`. Stop that server before a rollback repair. A binding change needs
no stop: a server running the edited profile refuses before it opens the new
path, so it holds no lock there. A server still running the old profile refuses
after the acknowledgement until it restarts.

Queued consent rows follow the repair rows and are counted in `outbox_drained`. A drain refusal leaves the repair in force and exits `0`. It omits `outbox_drained`, since every queued row stays queued, and lists the refusal under `warnings`: `audit.outbox_unusable`, `audit.outbox_busy`, `audit.outbox_rows_missing`, or the condition an append refused on, such as `audit.io_error`.

```json
{"ok":true,"data":{"profile":"default","previous_anchor":"42:18104","current_anchor":"39:16820","reanchor_count":1,"acknowledged":["rollback"],"recorded_binding":"equal","previous_binding_anchor":null,"outbox_drained":0},"request_id":"..."}
```

### `audit acknowledge-outbox-loss --profile <NAME> --reason <TEXT>`

Operator-only recovery for `audit.outbox_rows_missing`; an agent must not run it on its own initiative.
Stop the process holding the profile's writer and inspect the queued rows first.
`--reason` is required, non-empty, and recorded with the audit string bound.

The command checks the tip anchor, checks that the loss holds and that every remaining queued row parses, and then revokes every decided, unexpired, unconsumed approval and every toolset grant.
Mainnet confirmations and recorded passkey assertions count as decided approvals.
It records `audit_outbox_loss_acknowledged`, drains the remaining complete rows, resets the commitment, and empties the outbox.
Approve affected actions again to record fresh consent.

The result contains `profile`, `expected_rows`, `found_rows`, `drained`, `revoked_approvals`, and `revoked_grants`.
No loss returns `audit.outbox_loss_not_found` without an acknowledgement; a held writer returns `audit.writer_locked`; a log rolled back behind its tip anchor returns `audit.tip_anchor_mismatch`.
A remaining row that does not parse returns `audit.outbox_unusable` before anything is revoked or written.
A row that cannot append leaves the queue and commitment in place for inspection and retry.

```bash
stellar-agent audit acknowledge-outbox-loss --profile default --reason "Queue inspected; fresh approval required"
```

## The governance loop end to end

1. The agent surface evaluates an action against the policy engine. An action
   needing operator consent records a pending approval and returns its nonce
   instead of executing.
2. The wallet owner runs `approve --id <nonce> --profile <name>` in a trusted context, reads the
   wallet-controlled summary, and consents. The command writes an HMAC
   attestation (or a toolset grant) bound to the profile name, chain id, nonce,
   envelope digest, and local user.
3. The agent surface verifies the attestation and executes. The commit writes its transaction audit events to
   the hash-chained audit log.
4. The operator periodically runs `audit verify` with `--profile` to confirm the
   hash chain, the chain-root HMAC sidecars, and the tip anchor are all intact.

## Key rotation that backs the loop

Rotation subcommands generate a fresh 32-byte secret from the OS CSPRNG and
atomically replace one keyring entry the profile names. The raw bytes never
leave the keyring, are never logged, and are never returned. Rotation is not
reversible; each one invalidates material minted under the old key. Each takes
the profile as either a positional `<NAME>` or a `--profile <NAME>` flag
(exactly one).

The policy-file owner key is not rotated here. It is enrolled with `profile enroll-owner-key` (public key stored) and used by `profile sign-policy`. The rotation subcommands below mint 32-byte HMAC keys.

| Subcommand | Key kind | Effect on outstanding material |
|---|---|---|
| `profile rotate-attestation-key <NAME>` | 32-byte HMAC | All pending approvals invalidated; re-run the simulate-and-approve round trip. |
| `profile rotate-audit-key <NAME>` | 32-byte HMAC | Re-signs every existing per-file chain-root sidecar with the new key; `audit verify <LOG_PATH> --profile <p>` stays green across the rotation and the old key stops verifying; the response carries `sidecars_resigned`. Takes the audit writer's exclusive lock, so it refuses while an MCP server holds the writer. |
| `profile rotate-nonce-key <NAME>` | 32-byte HMAC | All outstanding nonces minted with the old key are invalidated. |
| `profile rotate-counterparty-key <NAME>` | 32-byte HMAC | Invalidates cached bindings. `counterparty refresh <domain>` rewrites one binding, and `counterparty warm-up` refreshes only the `HOME_DOMAIN` entries of the policy allowlist. |
| `profile rotate-policy-state-key <NAME>` | 32-byte HMAC | Verifies the window-state store under the old key, then re-signs it under the new key, so accumulated `per_period_cap` / `rate_limit` history is preserved. A store that does not verify refuses the rotation; use `profile reset-window-state`. |

```bash
stellar-agent profile rotate-attestation-key default
```
```json
{"ok":true,"data":{"profile":"default","rotated":true,"key_kind":"hmac_32_bytes"},"request_id":"..."}
```
