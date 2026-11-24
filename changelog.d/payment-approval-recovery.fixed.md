- Repeated payment preparation queued another approval nonce for the same payment.
  A retry of the same payment under the same profile, chain, verified policy, and operation now reuses the original approval nonce and interval.
  While its recovery binding is retained, a recorded expiry, rejection, consumption, or collection keeps its refusal, also after the clock moves backward.
  The binding is written atomically with the approval inbox.
  Recovery needs a verified policy. Without one, the forced toolset approval still queues an entry with no recovery binding.
  A payment approval under split rules ends at the earlier decision end, also off mainnet.
