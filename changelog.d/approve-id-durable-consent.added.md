- `approve --id` commits consent for an existing mainnet value approval record
  before reporting success. A queued consent row keeps its outbox reference in
  the durable record. A retry recovers missing consent from the stored receipt.
  It then returns `approval.already_attested`. A revoked, consumed, or expired
  record, or one that does not match the inbox entry, refuses with its approval
  code before presence and before recovery. These refusals write nothing.
