- Transaction status reports `recovery` results for managed mainnet attempts in
  both the CLI and MCP output. The new default-off `--retry-recovery` flag and
  `retry_recovery` argument start one bounded evidence run for a stopped
  attempt, also after its runs are exhausted. That run never resubmits.
