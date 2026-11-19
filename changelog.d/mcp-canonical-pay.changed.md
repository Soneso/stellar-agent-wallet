- On mainnet, `stellar_pay` now stores the lasting payment intent under the
  business id, as the other three classic tools do. Under an approval
  requirement the approval binds the intent digest, and a retried
  preparation recovers the same approval nonce. A retry after a crash before
  the first approval record opened queues a new entry over the decision's
  whole lifetime, and its consent admits the payment on either route. A
  crash after that record's reservation and before its inbox entry ends the
  business id with `approval.not_found`; prepare again under a new one.
- `stellar_pay_commit` on mainnet rebuilds the envelope from the stored
  intent with a fresh sequence, deadline and oracle witness, at the fee per
  operation of the envelope the preparation returned, so it proceeds more
  than 120 seconds after the preparation and after a server restart. The
  deadline is the earlier of 120 seconds after the commit and the last whole
  second strictly before the end of its authority; a successor's deadline
  also stays before the record's execution end. Its `nonce`,
  `expires_at_unix_ms` and `envelope_xdr` arguments are optional on that
  route. A source, destination, asset, amount or memo
  other than the stored intent's refuses with
  `operation.business_id_conflict`, also after the payment was sent.
- On mainnet one payment has one record per business id, and its first
  preparation decides its kind: `stellar_pay` stores the intent, a toolset
  preparation the exact envelope. Either route resumes that record.
- A toolset commit, a direct commit of a record with its exact envelope, and
  every payment off mainnet keep the envelope route and its 120-second
  nonce lifetime. A toolset commit of a `stellar_pay` record signs only an
  envelope of its stored intent; any other refuses
  `operation.business_id_conflict` and sends nothing. The envelope a mainnet
  `stellar_pay` preparation stores carries the earlier of 120 seconds after
  the preparation and the last whole second before its decision's end. A
  toolset commit of a direct-first payment signs that envelope unchanged
  while the authority it adds outlasts the stored deadline; an authority
  that ends sooner refuses with `network.mainnet_authorization_refused` and
  sends nothing, and a direct commit of the record completes it. On the
  envelope route an omitted `nonce`, `expires_at_unix_ms` or `envelope_xdr`
  answers the tool's fixed argument refusal, and a present value, empty or
  zero included, keeps its own refusal.
