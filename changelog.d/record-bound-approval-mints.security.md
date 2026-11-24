- Transaction and Soroban resolution check retained approval state. The mint
  checks it again under the lock. For retained records, durable consent bounds
  authorizations and operation execution. Retained records refuse in this order:
  revoked, unconsented while waiting, expired, then bound to another operation.
  Receipt mismatches have a distinct refusal.
