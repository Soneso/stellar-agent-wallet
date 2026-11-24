- Mainnet approvals without a durable record refuse with
  `approval_not_found` at the resolver and at the mint, also in a store
  without a file, so no gate admits on inbox material alone. SEP-10 message
  signing checks the record of the operation it names and never links it.
  A used message proof keeps its authenticated payment through a later
  revocation, within the record's bound.
