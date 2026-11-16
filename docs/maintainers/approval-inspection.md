# Approval inspection

The core `approval::inspection` API verifies stored consent without granting
signing, submission or retry authority. Callers select the existing public
approval nonce. Durable identities are internal storage keys.

`read_pending_approval` uses the strict inbox loader, clones the first matching
nonce and releases the inbox sidecar lock. It does not collect expired records.
Every opening failure maps to `approval.store_open_failed` with a safe cause
class. Existing approval commands keep their own error mapping.

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
execution window, cryptography and success. A policy signature change precedes
credential removal. Persisted tombstones precede clock-based expiry.

Expiry is a view at the supplied time, so a backward clock can revive an
observational expiry because inspection stores no durable watermark.

Envelope consent keeps its exact-envelope binding. Canonical verification uses
the durable record's intent digest and retained original challenge subject.
An inbox-only canonical record lacks that digest and reports unavailable
verification. Released proof is never reconstructed from its receipt digest.
An additional execution window only narrows the signed lifetime.

Inspection returns no approval witness. Commit retains its independent expected
kind and subject, presented proof checks, receipt-spend guard and nonce gate.
Inspection takes no window writer, receipt, nonce or outbox lock and writes no
domain audit row. Callers release the inbox lock before policy inspection,
which takes only the existing shared policy-state lock and never upgrades it.

This library API does not add a CLI command or MCP tool. Public status adapters
must retain policy denial and read-audit behavior, use one authenticated window
image through dispatch, and preserve durable integrity failures before considering
an inbox fallback. Positive approval reuse requires canonical commit support.
