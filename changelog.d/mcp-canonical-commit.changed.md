- On mainnet, `stellar_create_account`, `stellar_trustline` and
  `stellar_claim` now store the lasting intent under the business id. Under
  an approval requirement the approval binds that intent's digest; under
  `Allow` no approval record opens.
- Their commits look the business id up, rebuild the envelope from the stored
  intent with a fresh sequence, deadline and oracle witness at the prepared
  envelope's fee per operation, and sign under the stored record's approval
  or a fresh policy decision. The deadline is the earlier of 120 seconds
  after the commit and the last whole second strictly before the end of the
  authority: an approval's execution end, or a policy decision's governing
  end; a successor's deadline also stays before the record's execution end.
  The resolver refuses a canonical envelope whose deadline does not lie
  before that end. The `nonce`, `expires_at_unix_ms` and `envelope_xdr`
  arguments are optional on that route and play no part, so a commit after
  a server restart proceeds.
  A lasting argument other than the stored intent's refuses with
  `operation.business_id_conflict`, and a claimable balance that changed
  since the preparation refuses with `simulation.divergence`.
- An operation recorded with its exact envelope and every call off mainnet
  keep the envelope route, which answers an omitted `nonce`,
  `expires_at_unix_ms` or `envelope_xdr` with the tool's fixed argument
  refusal.
