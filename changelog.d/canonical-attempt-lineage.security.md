- A canonical operation's authorization is now minted only inside its
  attempt's begin, together with the approval's consumption and the
  `sending` attempt. The public mint refuses with
  `network.mainnet_authorization_refused` (logged as `intent_mismatch`) a
  request whose link or approval operation names one. The CLI and MCP
  surfaces still create envelope records only, so no command or tool takes
  the canonical route yet.
- A canonical operation's successor attempt may reuse its approval nonce
  after each earlier attempt's checked non-inclusion. The mint admits the
  nonce only when every earlier holder is such an attempt of the same
  operation or an unused carrier of it: an earlier authorization that was
  never claimed and that no exposure names. The receipt claim and the CLI and
  MCP receipt checks admit it only when every other receipt that holds it
  belongs to such an attempt. Any other holder keeps its refusal.
- On mainnet, where canonical records exist, the approval tombstone of a
  canonical attempt waits until its operation is terminal or past its
  execution expiry. The next repair after that, by the status call or by the
  send recorder, writes the tombstone and acknowledges its receipt and every
  other sent receipt of the nonce.
- A canonical transaction now refuses with `simulation.divergence` when a
  field of its envelope differs from its stored intent. A claim refuses the
  same way when the claimable balance the resolver rereads from the ledger
  differs in asset or amount, or no longer exists. Every other mainnet
  authorization refusal keeps `network.mainnet_authorization_refused`.
- A business id that holds an envelope record keeps that record's exact
  envelope under a canonical preparation: the request resumes or replays it,
  and the record is never rebuilt with a fresh sequence.
- When two preparations open an approval on one profile at the same time,
  the one that finds the producer lock held refuses with
  `approval.writer_locked`, opens nothing, and can be retried with the same
  business id.
