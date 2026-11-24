- Queued consent APIs return durable row references for delivery evidence.
  Mainnet consent through `attest_and_persist_with_row` or
  `attest_mainnet_confirmation_with_row` requires a keyed outbox, or a direct
  writer whose configured tip anchor can be made current. A direct writer
  without an anchor store completes after row durability. Non-mainnet
  `attest_and_persist_with_row` accepts unkeyed queues and uses best-effort direct anchoring.
  Existing `attest_and_persist` and `attest_mainnet_confirmation` callers observe
  no change in results or written rows, retaining unkeyed queue acceptance and
  best-effort direct anchoring. Their queue writes use ordinary append with
  marker `r=0`; only reference-returning entries request delivery evidence with `r=1`.
