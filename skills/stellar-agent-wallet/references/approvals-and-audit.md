# Approvals and audit

The guardrail loop that sits between an agent's tool call and any signing or
network action: the policy engine, the operator-approval spine, attestations,
and the hash-chained audit log. This file is self-contained; for the MCP tool
surface that drives the simulate/commit handshake see `./mcp-tools.md`.

## The model in one paragraph

Every tool/command invocation is evaluated by the active policy engine before
any RPC call or signature. The engine returns Allow, Deny, or RequireApproval.
A RequireApproval action does not execute on the agent's say-so: it is held in a
per-profile pending-approval store and returns an `approval_nonce`. The wallet
owner runs `stellar-agent approve --id <nonce>` out-of-band in a trusted
context, reads a wallet-controlled summary, and consents. The command records an
HMAC attestation bound to the exact transaction envelope, the nonce, and the
local user, and returns `approval_attestation`. The agent presents that blob to
the matching `*_commit` tool, which constant-time-verifies it before executing.
Every invocation and lifecycle event is appended to a hash-chained audit log
that `stellar-agent audit verify` checks for tampering.

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
  transaction, so the network flags and the mainnet-write gate do not apply to
  them.

## The policy engine

Each invocation is evaluated before it does anything. Three decisions:

| Decision | Meaning |
|---|---|
| Allow | The call proceeds. |
| Deny | The call is refused, carrying a typed reason with a stable wire code. |
| RequireApproval | The call is held pending an out-of-band operator approval. |

The engine that runs is selected per profile in `[policy]`. Two structural rules
apply on every surface: the default network is `stellar:testnet`, and every
write or signing command structurally refuses `stellar:mainnet`
(`network.mainnet_write_forbidden`) before any RPC call or signature, while
`stellar:mainnet` stays accepted for read-only commands.

### Noop engine

The binding gate used when no full engine is configured. Behavior is fixed:

| Profile | Tool | Result |
|---|---|---|
| testnet | any | Allow |
| mainnet | read-only | Allow |
| mainnet | destructive | refused with `policy.engine_required` |

A destructive tool on a mainnet profile cannot pass the Noop engine. Newly
minted profiles default to the V1 engine.

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
2. operator: stellar-agent approve --id <approval_nonce>
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

### What `approve --id <nonce>` returns

For a payment-style approval the response includes `approval_attestation`, the
HMAC blob (URL-safe base64, no padding) the agent must present to `*_commit`.
The field is omitted for approval kinds whose gate reads the recorded consent
from the store directly (toolset first-invoke grants, trustline clawback opt-ins).

```json
{"ok":true,"data":{"approval_nonce":"ABCxyzNonce","attested":true,"process_uid":"501","expires_at_unix_ms":1717000000000,"approval_attestation":"q83vEjRWeJq83v..."},"request_id":"..."}
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

Entry kinds: `PaymentSimulated`, `ClaimSimulated`, `SignWithPasskey`,
`RegisterPasskey`, `ToolsetFirstInvokeGate`, `TrustlineClawbackOptIn`,
`RuleProposalSimulated`. An eighth kind, `Rejected`, is not a fresh entry an
agent's build/simulate step creates — it is the short-TTL tombstone the
store writes in place of an entry after the operator rejects it.

### What `approve` does

`stellar-agent approve --id <nonce>` loads the store and renders a
wallet-controlled summary of the pending action. The summary is produced by the
command from the stored, validated entry fields, never from anything the agent
supplied, so the agent cannot influence what the operator sees (it cannot inject
terminal-rendering content into the summary). The operator confirms at the
terminal; the command then records the consent. Recording is one-shot: a nonce
that is expired, of the wrong kind, or already attested is rejected. Approval is
bound to the local user: the process uid recorded at create time is re-derived
at approve time and must match, so a different local user cannot consent on the
holder's behalf.

Per kind:

| Kind | What `approve` records |
|---|---|
| `PaymentSimulated` / `ClaimSimulated` | Computes the HMAC attestation over the envelope SHA-256 and persists it; returns `approval_attestation`. Both kinds share the same attestation path. |
| `TrustlineClawbackOptIn` | Computes a domain-separated HMAC over `(network, code, issuer)` and stores it; the trustline gate recomputes and verifies it. No `approval_attestation` returned. |
| `ToolsetFirstInvokeGate` | Builds and persists a time-boxed toolset grant, then consumes (removes) the pending entry. Does not set an attestation blob on the entry. No `approval_attestation` returned. |
| `RuleProposalSimulated` | Computes the HMAC attestation over `proposal_sha256` (the domain-separated digest of the FULL resolved rule definition), not an envelope hash; persists it and returns `approval_attestation`. A DEDICATED gate verifies it at commit — the shared `PaymentSimulated`/`ClaimSimulated` gate rejects this kind outright. |

### The attestation

The attestation is an HMAC-SHA256 tag, keyed by the profile's attestation key
(which lives only in the platform keyring), over a length-prefixed canonical
input:

```text
HMAC-SHA256(attestation_key,
    len(approval_nonce) || approval_nonce
    || envelope_sha256            (32 bytes)
    || len(process_uid) || process_uid)
```

The length prefixes prevent boundary-collision attacks. The `envelope_sha256`
slot binds the tag to the exact transaction envelope that will be signed. The
`process_uid` (numeric OS uid on Unix) gives cross-account-on-host non-replay: a
tag minted by one local user cannot be replayed by another.

The MCP commit-path verifier recomputes the tag and compares it in constant
time. It collapses the distinct internal outcomes (Expired, NotFound,
AlreadyAttested, forged) into the single wire code `policy.approval_required`,
so a caller cannot probe which state a nonce is in. The CLI `approve` path
surfaces distinguishable errors to the operator, who is the wallet owner.

The attestation proves the keyring holder ran `approve` — not that a human
clicked "yes" in an agent-controlled UI. An attacker who can write to the store
file can delete a pending entry (a denial-of-service nuisance forcing
re-approval) but cannot forge an attestation, because the HMAC key is in the
keyring, not the file. Rotating the attestation key invalidates all outstanding
pending approvals.

### `approve` command reference

`stellar-agent approve --id <NONCE>` — state-changing (records an attestation or
a grant in the on-disk store).

| Flag | Required | Default / resolution | Meaning |
|---|---|---|---|
| `--id <NONCE>` | yes (this form) | — | The approval nonce from the agent surface's simulate/build response. |
| `--profile <NAME>` | no | `--profile`, then `STELLAR_AGENT_PROFILE`, then `default` | Profile whose attestation key and store to use. |
| `--yes` | no | off | Non-interactive auto-approve. Bypasses the stdin prompt; the wallet-controlled summary is still printed for a visible record. For trusted automation and tests, not routine operator use. |

Interactively the command prints the summary and prompts `Approve? [y/N]:`;
only `y`/`yes` (case-insensitive) consents, everything else (including empty
input, `n`, EOF) denies. Exits `1` when the nonce is unknown, expired, already
attested, created by a different local user, denied at the prompt, or on I/O
error.

```bash
stellar-agent approve --id ABCxyzNonce
stellar-agent approve --id ABCxyzNonce --profile myprofile --yes
```

`stellar-agent approve gc` — state-changing. Evicts every pending entry whose
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

- **CLI, one at a time** — `stellar-agent approve --id <NONCE>` (above), or
  `stellar-agent approve list` to enumerate every pending entry first
  (read-only; `--include-expired` also shows expired ones).
- **Loopback web inbox** — `stellar-agent approve serve` binds a local HTTP
  server and opens a browser to the pending-approval queue, so the operator
  clicks Approve/Reject per entry instead of running `approve --id` per nonce.
- **Remote approval** — `stellar-agent approve serve --remote
  --confirm-remote-exposure` binds a TLS-protected listener reachable from a
  device other than the wallet host, authenticated by a registered WebAuthn
  passkey, for when the agent runs on a headless machine. Every approve or
  reject additionally requires a fresh passkey assertion bound to the exact
  entry.

None of this changes what the agent does or what an attestation proves — see
"The attestation" above. Setup for remote approval (the profile's
`[remote_approval]` block, enrolling a passkey via `approve operator enroll`,
the trust model, DNS requirements) is out of scope here; see
`docs/remote-approval.md` in the wallet repository for the full operator
guide.

A remote approve or reject is recorded in the audit log under
`ApprovalAttestedRemote` / `ApprovalRejectedRemote` event kinds rather than
the loopback `ApprovalAttested` / `ApprovalRejected` ones — the distinguishing
detail when reading the audit log directly. Both remote kinds also carry
`operator_credential_id_redacted`, a stable, non-reversible pseudonym for
which passkey credential consented (the first 8 hex characters of
`SHA-256(credential_id_b64url)`); nothing else about the attestation or its
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
  envelope. A forged or tampered grant can at most suppress a re-prompt; it
  cannot bypass the per-action approval, because that approval is forced
  regardless of any grant and is bound to the real transaction.

## The hash-chained audit log

A per-profile, append-only JSONL file recording every tool invocation and
lifecycle event. The writer is a per-profile singleton holding an exclusive
lock, appending with an fsync per line; a second opener is rejected. Files
rotate at a size bound with a fixed number of rotated files retained.

Each entry carries: a timestamp, the tool name, the chain id, the argument key
names (`arg_keys`), the envelope hash, the nonce id, the policy decision
(`allow` / `deny:<reason>` / `require_approval`), an optional decision reason, a
request id, the event kind, and the previous entry's hash. Argument values are
never logged — only their key names. Strkeys in a decision reason are redacted to
first-five-last-five and transaction hashes to first-eight-last-eight; the
envelope hash is left intact (it is a SHA-256 digest carrying no user data).

Beyond tool invocations, the log records `value_action_submitted` on every
confirmed value-moving submit (carrying the gate-sized value legs),
`keyring_key_written` on each key-writing profile command, and
`x402_payment_authorized` on x402 authorization signing.

Each entry's hash is computed over its own canonical JSON (with the previous-hash
field treated as empty) concatenated with the previous entry's hash, chaining
every entry to the one before it. The first entry of the very first file chains
off a fixed zero block; the first entry of each later file chains off the prior
file's rotation-handoff entry. Each file also carries a `root_hmac` sidecar
signing the chain root with the profile's audit key.

### `audit verify` command reference

`stellar-agent audit verify <LOG_PATH>` — read-only. Walks the log oldest-first,
follows rotation manifests across rotated files, and verifies the hash chain end
to end: each entry's recorded previous-hash matches the recomputed prior-entry
hash, each file's first entry chains correctly across the rotation boundary, and
each rotation handoff names the actual next file (defeating file-substitution).
When `--profile` is supplied it also verifies the chain-root HMAC sidecars;
without it, only the hash chain is checked and `hmac_verified` is `false`.

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
`audit.hmac_mismatch`, with line and file detail kept out of the code.

```bash
stellar-agent audit verify ~/.local/share/stellar-agent/audit/default.jsonl --profile default
```
```json
{"ok":true,"data":{"entries_verified":42,"files_walked":2,"hmac_verified":true,"per_file":[],"warnings":[],"audit_writer_degraded":false},"request_id":"..."}
```

## The governance loop end to end

1. The agent surface evaluates an action against the policy engine. An action
   needing operator consent records a pending approval and returns its nonce
   instead of executing.
2. The wallet owner runs `approve --id <nonce>` in a trusted context, reads the
   wallet-controlled summary, and consents. The command writes an HMAC
   attestation (or a toolset grant) bound to the nonce, the executed envelope's
   hash, and the local user.
3. The agent surface verifies the attestation and executes. Every invocation and
   lifecycle event is appended to the hash-chained audit log.
4. The operator periodically runs `audit verify` with `--profile` to confirm
   both the hash chain and the chain-root HMAC sidecars are intact.

## Key rotation that backs the loop

Rotation subcommands generate a fresh 32-byte secret from the OS CSPRNG and
atomically replace one keyring entry the profile names. The raw bytes never
leave the keyring, are never logged, and are never returned. Rotation is not
reversible; each one invalidates material minted under the old key. All take the
profile as a positional `<NAME>`.

The policy-file owner key is not rotated here — it is enrolled with `profile enroll-owner-key` (public key stored) and used by `profile sign-policy`. The rotation subcommands below mint 32-byte HMAC keys.

| Subcommand | Key kind | Effect on outstanding material |
|---|---|---|
| `profile rotate-attestation-key <NAME>` | 32-byte HMAC | All pending approvals invalidated; re-run the simulate-and-approve round trip. |
| `profile rotate-audit-key <NAME>` | 32-byte HMAC | Re-signs every existing per-file chain-root sidecar with the new key; `audit verify --profile <p>` stays green across the rotation and the old key stops verifying; the response carries `sidecars_resigned`. |
| `profile rotate-nonce-key <NAME>` | 32-byte HMAC | All outstanding nonces minted with the old key are invalidated. |
| `profile rotate-counterparty-key <NAME>` | 32-byte HMAC | Invalidates every cached counterparty binding; the wallet re-fetches on the next counterparty-allowlist check. |

```bash
stellar-agent profile rotate-attestation-key default
```
```json
{"ok":true,"data":{"profile":"default","rotated":true,"key_kind":"hmac_32_bytes"},"request_id":"..."}
```
