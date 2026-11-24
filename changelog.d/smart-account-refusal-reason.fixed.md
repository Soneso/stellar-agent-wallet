- A smart-account refusal names the contract error when the simulation
  reports it in a diagnostic event, for example
  `Error(Contract, #3221) [OZ:SpendingLimitExceeded]`. The code comes from an
  `error` event of the invoked contract or of a smart account the auth entries
  name. Without such an event the message carries the top-level error.
