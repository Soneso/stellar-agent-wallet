- Recovery resumes its two-endpoint ledger scan across bounded runs, starting
  from the authenticated record of the ledger recorded before the payment was
  exposed. A pruned ledger or a missing starting record stops the scan with an
  explicit reason, and a configuration change restarts a stopped scan.
