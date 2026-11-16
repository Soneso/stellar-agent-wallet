- Add canonical intent rebuild helpers for classic mainnet operations.
  `canonical_slot_intent` validates a stored canonical intent against its digest and the current chain, source, and policy.
  `match_envelope` checks a rebuilt envelope's shape, source, fee, and deadline, and requires the intent rebuilt from its memo and operation to hash to the stored digest.
  `rebuild_canonical` builds a fresh envelope after the readiness check, the account read, and the fee selection, and binds a new oracle proof to it.
  `require_intent_claim` checks a fresh claimable balance against the intent and its first matching claimant.
  No command or tool uses these helpers yet.
