# MPP internals

This page owns maintainer detail for the testnet sponsored Machine Payments
Protocol charge path. User behavior and host duties are documented in
[Agent payments with MPP](../agent-payments.md).

## Protocol and dependency pins

The implemented wire contract follows the released `@stellar/mpp` 0.7.1
HTTP/native-MCP challenge, credential, and receipt shapes. Stellar execution is
one SEP-41 token `transfer` authorization signed with the existing SEP-43
Ed25519 preimage machinery. The Rust `mpp-rs`, `mppx`, and Stellar MPP SDK
repositories are research references, not runtime dependencies.

`stellar-agent-mpp` owns strict parsing and execution. It depends on core for
policy/approval/profile types, network for signer and keyring boundaries, and
SEP-43 for authorization signing. Shared SEP-41 transfer construction remains in
`stellar-agent-x402::sac_transfer`/the extracted network-facing builder so x402
and MPP do not diverge on transfer argument encoding.

The crate is publish tier 5: it must be published after `stellar-agent-sep43`
and before the tier-6 CLI and MCP binaries. Validate the complete DAG with:

```bash
bash .github/scripts/publish-crates.sh --check
bash .github/scripts/test-publish-crates-check.sh
```

## Module ownership

| Module | Responsibility |
|---|---|
| `challenge` | Bounded HTTP auth-param and native MCP challenge selection; exact challenge echo. |
| `context` | HTTPS/MCP request normalization and domain-separated context digest. |
| `json` | Duplicate-member rejection and canonical JSON. |
| `policy` | One canonical `MppCharge` value leg. |
| `sponsored` | Zero-source prepare simulation, auth-entry inspection, signing, mandatory re-simulation, final envelope inspection. |
| `credential` | HTTP `Payment` or native MCP credential encoding. |
| `state` | Authorization fingerprint, record invariants, lifecycle graph. |
| `store` | Per-profile HMAC file, locking, atomic replace, replay lookup and retention. |
| `service` | Shared CLI/MCP prepare, approval, commit and delivery gates. |
| `receipt` | Strict trusted-host receipt parsing and digesting. |
| `reconcile` | Final RPC lookup and independent direct/fee-bump envelope and signature verification. |

CLI adaptation is `stellar-agent-cli/src/commands/mpp.rs`. MCP schemas and tools
are in `stellar-agent-mcp/src/tools/mpp.rs`. Do not duplicate parser, policy,
fingerprint, signing, or state-machine logic in either binary.

## Supported flow

Prepare checks testnet before all side effects, parses and context-binds one
sponsored Stellar charge, constructs one neutral transfer invocation, simulates
with the all-zero transaction source, inspects exactly one payer address auth
entry, evaluates the canonical value leg, and persists the prepared artifact.
Only after successful simulation may first-use MPP state key material be minted.

Commit re-evaluates policy from persisted terms and verifies the dedicated MPP
approval when present. It atomically claims `ready` before value-window
accounting or signer access, records policy usage before signing, lazily opens
the payer key, signs the address authorization, re-simulates, re-inspects the
final envelope, stores only the credential digest, appends the authorization
audit event, persists `authorized`, and returns the credential once.

The configured RPC observes signed authorization during re-simulation and is a
trusted endpoint. Simulation responses expose encoded authorization entries,
result values, and transaction data; the wallet decodes those fields with
`untrusted_decode_limits(encoded.len())`, bounding depth to 500 and length to
the encoded input size.

Reconciliation reads `get_transaction` from `stellar-rpc-client`, which decodes
the response metadata, events, envelope, and result inside the client and hands
the wallet values that are already decoded. Those decodes carry no XDR depth or
length bound, and there is no point at which the wallet can impose its own, so
reconciliation relies on the configured endpoint at that boundary. The test at
`crates/stellar-agent-mpp/tests/rpc_decode_boundary.rs` holds the inventory of
those decode sites in the pinned version and fails when the locked version
changes, so a bump reinspects them.

## Fingerprints and approval binding

`authorization_fingerprint` is SHA-256 over the versioned domain plus
length-prefixed profile name, network-passphrase digest, payer, normalized
context digest, exact challenge digest, method, intent, sponsored-pull mode,
canonical amount, token contract, recipient, and effective expiry. The opaque
authorization ID contains a prefix of this digest; the full digest remains in
authenticated state.

`MppChargeSimulated` binds the full authorization fingerprint and prepared
artifact hash plus operator-visible profile, network, payer, transport,
authority, target, amount, token, recipient, challenge expiry and simulated fee.
Its attestation uses the prepared artifact hash and the normal approval nonce
and process-identity binding. Its lifetime is capped at five minutes and by the
challenge expiry. Local and remote approval views redact payer and recipient and
never render XDR, credentials, challenge bodies, or raw context parameters.

## Durable state

The per-profile file is below the canonical data root in `mpp/`; its filename is
the SHA-256 of the profile name. A dedicated 32-byte HMAC key occupies keyring
service `stellar-agent-mpp-state-<profile>`, account `default`. The monotonic
counter occupies the same service, account `default-generation`. Version 2 JSON
includes a `generation` and is prefixed by HMAC-SHA256 over a domain and body.
The counter is trusted independently of the state file.

`open_for_prepare` provisions generation zero and a state key under the store
lock for a new profile. Only a proven absent key may be minted; keyring access
errors refuse. `open_for_read` returns `Ok(None)` when the key and state file are
provably absent and no advanced counter exists. A minted key with counter zero
and no file is a valid empty store: policy denial after minting must leave the
first prepare possible. Missing files with an advanced counter refuse even when
the state key is also missing.

Every read checks non-symlink regular-file shape, size, HMAC in constant time,
schema version, equality with the keyring generation, record count,
reconstructed prepared-artifact semantics, lifecycle invariants, and uniqueness
of authorization IDs, fingerprints and approval nonces. When the counter is
proven absent by the keyring, opening adopts a verifying snapshot under the
store lock. It records `mpp_state_adopted` with the profile and generation before
anchoring. Only version 1, which has no generation, is adopted; it is rewritten
as version 2 at generation one with all records preserved. A version 2 file is
published only after its counter, so one with an absent counter refuses as an
invalid anchor. Generation zero remains reserved for an unwritten store. A
present counter, an unverifiable file, or a keyring access error cannot trigger
adoption. A state key with neither counter nor file refuses the same way; it
holds no history, and reset recovers it without discarding records.
Concurrent opens share the lock, and an anchored read emits no adoption row.

Mutation holds a sibling-file cross-process lock, increments the generation
with overflow checking, and advances the keyring counter before writing any
authenticated snapshot, including temporary files. It then writes, flushes,
atomically renames, and synchronizes the parent directory. A failure after the
counter advances leaves a mismatch and refuses further use; generations are
never reused for an abandoned snapshot. Reads never reset or lower the counter.
Immediately before advancing, a write re-reads the counter. If another writer
has moved it, the write refuses with `mpp.state_unavailable` and a message
asking for a retry, and the other writer's snapshot stays in place.

Deletion or generation mismatch returns `mpp.state_unavailable` with a message
identifying the state as rolled back and naming `profile reset-mpp-state`.

`stellar-agent profile reset-mpp-state <NAME> --acknowledge --reason <REASON>`
recovers refused state. Under the store lock it writes `mpp_state_reset` with
the profile, discarded generation, and bounded reason; rotates the state HMAC
key; removes the file and synchronizes its directory; and sets the counter to
zero. A missing or malformed counter is represented by a null discarded
generation. Keyring access errors and audit failures refuse without resetting.
The audit row records the operator's request even if a later reset step fails.
The command can be retried with acknowledgement after a partial failure.

Reset discards every prepared, authorized, indeterminate and settled replay
marker. A charge settled before reset is no longer recognized as settled. The
fresh key invalidates snapshots from discarded history even when a new store
reuses their generation numbers; profile handles check that their cached key
still matches the keyring before reading or writing. The first prepare after
reset starts from an empty store. There is no automatic reset on read failure.

Filesystem rollback cannot restore older protected history while the keyring
remains trusted. Access to the keyring, which also holds the HMAC key, is outside
this boundary; a filesystem-backed keyring needs independent protection from
state-file rollback.

The store never persists a credential, signature output, raw receipt, or exact
transaction hash. It retains only the prepared unsigned artifact needed for one
commit and post-event digests.

## Lifecycle

```text
prepared -> approval_pending -> ready -> authorizing -> delivery_pending -> authorized
prepared ----------------------> ready
ready -> approval_pending                 (policy changed before commit)
authorized -> receipt_observed
authorized|receipt_observed -> settled|failed|expired_unresolved
prepared|approval_pending|ready -> expired_unresolved
authorizing -> refused|failed|indeterminate
delivery_pending -> authorized_withheld
```

Terminal states are `settled`, `failed`, `refused`, `expired_unresolved`,
`authorized_withheld`, and `indeterminate`. No terminal state transitions or
signs again. Status derives expiry without mutating state. Explicit audited
prune persists eligible expiry markers and removes terminal records only after
30 days; it never removes `indeterminate`.

A failure after signer access begins becomes `indeterminate` unless the
credential is known to exist, in which case a final-gate failure becomes
`authorized_withheld`. Policy accounting ambiguity is also conservative:
budget is treated as consumed and signing does not proceed. A typed policy
refusal writes no window usage: the authorization becomes `refused`, and its
withheld row records `policy_refusal` with the budget unconsumed. When the
refusal itself cannot be persisted, the authorization stays `authorizing`, the
withheld row records `policy_refusal_persist_failed` with the budget
unconsumed, and the persistence error is returned.
`BeforeSignError` distinguishes these outcomes at the accounting callback.

## Audit and redaction

The four typed events are `MppChargeAuthorized`,
`MppAuthorizationWithheld`, `MppReceiptObserved`, and
`MppSettlementReconciled`. Authorization audit append is a mandatory delivery
gate. Withheld audit is best-effort after the primary failure. Receipt and
reconciliation events state observation provenance but never conflate it with
settlement. Explicit pruning emits a normal tool-invocation row carrying only
the bounded reason SHA-256.

Never place raw challenges, request bodies, credentials, receipts, prepared or
signed XDR, signatures, full transaction hashes, key values, or sensitive URLs
in `Debug`, errors, logs, metrics, snapshots, or audit fields. The operator-
facing approval summary, prepare preview, and status views display the HTTP
target as origin plus path only; the query and fragment are stripped for
display while the full canonical resource stays bound in the context digest
and the authorization fingerprint.

Two transport-boundary properties are deliberate:

- The decoded-request bound (16 KiB) is enforced directly on the native MCP
  transport. An HTTP challenge is additionally bounded by the 16 KiB header
  field limit, whose base64url capacity (~12 KiB decoded) is tighter; the
  HTTP-side decode check remains as defense-in-depth.
- Duplicate JSON members are rejected on the HTTP wire, where the wallet is
  the first parser. On the native MCP transport the challenge objects arrive
  through the host's JSON parser, so duplicate members are resolved (last
  wins) before the wallet sees them; the canonical digest binds the value the
  wallet actually validated.

## Fixtures and tests

Offline deterministic RPC and signer fixtures exercise prepare, commit,
re-simulation, direct and fee-bump reconciliation without network access.
Parser property tests cover auth-param ordering, canonical digest input, and the
closed state graph. Run:

```bash
cargo test -p stellar-agent-mpp
cargo test -p stellar-agent-core
cargo test -p stellar-agent-approval-ui
cargo test -p stellar-agent-approval-remote
cargo test -p stellar-agent-cli
cargo test -p stellar-agent-mcp
```

When a released SDK fixture changes, record the exact package and runtime pin,
regenerate only the synthetic challenge/credential/receipt vectors, and prove
the old vector either remains compatible or is deliberately rejected. Never
copy secrets or live merchant data into fixtures.

The feature-gated live suite must not self-skip: it runs the released TypeScript
server, uses the production wallet orchestration, submits on testnet, verifies
the recipient delta, records the receipt, and reconciles the final transaction.
The serialized acceptance driver owns registration and reports any skip marker.

## Review focus

Apply the general [review checklist](review-checklist.md), then verify:

- all mainnet paths fail before state, RPC, keyring and signing;
- prepare has no signer capability and commit accepts no replacement terms;
- every post-claim failure has an unambiguous no-retry state;
- value effects are identical at policy preview, accounting and audit;
- no credential can be returned twice, including concurrent CLI/MCP commits;
- host receipt observation remains independent from verified ledger outcome;
- all public docs and skill references retain the testnet, sponsored-pull,
  G-account and credential-only boundary; and
- MPP remains absent from toolset routing.
