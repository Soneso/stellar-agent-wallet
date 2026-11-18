- CLI mainnet writes under an approval rule now verify the presented consent
  against its committed durable record before granting authority. A revoked
  record refuses with `approval.revoked` and a missing one with
  `approval.not_found`. A nonce that a submission receipt names, or a record
  of another operation, refuses with `approval.consumed`.
