- Policy loads that only compare the policy pin share the policy-state lock.
  A load takes the lock exclusively only to advance the pin, and compares the
  pin again under that lock before it writes. A load that cannot take the
  required lock through its retries fails before it checks freshness. A
  writer causes this, and so does a reader when the load must advance the pin.
  The mainnet approval surfaces then answer `approval.presence_policy_busy`,
  and the remote approval listener answers a retriable `503` `store_busy`.
  Other policy callers keep their own codes. A signed-origin login, consent
  assertion, or rejection takes the lock shared, and a revocation takes it
  exclusively, before it consumes its challenge. Each holds that one guard
  until it answers, and a revocation writes its durable record under it. Its
  busy answer leaves the challenge, the counter, the session, and the entry
  unchanged. No busy answer
  grants a session, a consent, or a pin change. The lock does not order edits
  of the policy file. A rolled-back policy answers busy while the lock is
  busy, and its rollback refusal once the lock is free. A login or consent
  refused after its assertion verified needs a fresh ceremony.
