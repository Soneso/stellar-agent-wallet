- Authenticated storage for consent delivery evidence. Two fixed evidence files
  beside the audit outbox hold a tagged snapshot that a version 2 owner value
  commits. Initialization turns earlier recent digests into migration pins. A
  restored older owner entry recommits the newest authenticated snapshot, and
  two distinct newest snapshots refuse with `owner rollback`. Every evidence
  refusal uses the code `audit.outbox_evidence_unusable` with a fixed reason.
  Existing profiles keep their version 1 owner value until initialization.
