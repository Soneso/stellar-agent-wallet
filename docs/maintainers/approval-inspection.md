# Approval inspection

The core `approval::inspection` API verifies stored consent without granting
signing, submission, or retry authority. Callers select the existing public
approval nonce. Durable identities are internal storage keys.

`read_pending_approval` uses the strict inbox loader, clones the first matching
nonce, and releases the inbox sidecar lock. It does not collect expired records.
Every opening failure maps to `approval.store_open_failed` with a safe cause
class. The `approve`, `approve gc`, and `approve list` paths map store-open
failures through their own function, with distinct codes for permission, nonce
length, and writer lock.

`inspect_stored_approval` dispatches unsupported inbox kinds before loading
verification context. It returns `None` for those kinds; a surface must display
unsupported verification and null validity. Missing or malformed proof is invalid.
Unknown accepted provenance and unavailable keys or policy produce unavailable
verification. Strict decoding failures remain opening failures.

The context loads the same HMAC key as commit verification. Mainnet loads one
signed policy through compare-only inspection. Testnet does not load policy.
The receipt verifier checks the retained WebAuthn assertion with the policy's
credential key. Credential membership alone is insufficient.

The reason order is stored consumption, rejection or revocation, structure,
context availability, expiry, policy signature, credential membership, kind,
execution window, cryptography, and success. A policy signature change precedes
credential removal. Persisted tombstones precede clock-based expiry.

Expiry is a view at the supplied time, so a backward clock can revive an
observational expiry because inspection stores no durable watermark.

Envelope consent keeps its exact-envelope binding. Canonical verification uses
the durable record's intent digest and retained original challenge subject.
An inbox-only canonical record lacks that digest and reports unavailable
verification. Released proof is never reconstructed from its receipt digest.
An additional execution window only narrows the signed lifetime.

Inspection returns no approval witness. Commit retains its independent expected
kind and subject, presented proof checks, receipt-spend guard, and nonce gate.
Inspection takes no window writer, receipt, nonce, or outbox lock and writes no
domain audit row. Callers release the inbox lock before policy inspection,
which takes only the existing shared policy-state lock and never upgrades it.

`approve status` and `stellar_approval_status` share the network approval status
facade. It selects durable records by nonce and joins business IDs through their
authenticated operation links. An absent durable record permits strict inbox
fallback; an unreadable durable image refuses.

The MCP handler retains policy decisions and writes no audit row.
It hydrates the gate from the facade's authenticated image, without another
window read. Legacy hydration applies existing retirement rules to an in-memory
copy. Inspection never persists that copy or acquires a writer lock.
Other tools retain ordinary hydration. Positive approval reuse requires canonical
commit support; both status surfaces report reuse as unavailable.
