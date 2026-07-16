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

The configured RPC observes signed authorization during re-simulation. It is a
trust boundary, not a passive read endpoint.

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
the SHA-256 of the profile name. A dedicated 32-byte HMAC key is stored in the
platform keyring. Missing key plus existing file fails closed. The file format
is versioned JSON prefixed by HMAC-SHA256 over a domain and body.

Every read checks non-symlink regular-file shape, size, HMAC in constant time,
schema version, record count, reconstructed prepared-artifact semantics,
lifecycle invariants, and uniqueness of authorization IDs, fingerprints and
approval nonces. Mutation holds a sibling-file cross-process lock and performs
write, flush, atomic rename, and parent-directory synchronization. The store
does not claim rollback resistance against a privileged whole-machine attacker.

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
authorizing -> failed|indeterminate
delivery_pending -> authorized_withheld
```

Terminal states are `settled`, `failed`, `expired_unresolved`,
`authorized_withheld`, and `indeterminate`. No terminal state transitions or
signs again. Status derives expiry without mutating state. Explicit audited
prune persists eligible expiry markers and removes terminal records only after
30 days; it never removes `indeterminate`.

A failure after signer access begins becomes `indeterminate` unless the
credential is known to exist, in which case a final-gate failure becomes
`authorized_withheld`. Policy accounting ambiguity is also conservative:
budget is treated as consumed and signing does not proceed.

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
