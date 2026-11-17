- Native balance criteria count the current network's native asset contract and
  use checked debit and fee arithmetic. The policy engine refuses negative or
  malformed native facts with `AccountingInvalid` and overflow with
  `AccountingOverflow`; the CLI and MCP server surface both as
  `policy.engine_required`.
- Every classic prepare in the MCP server (pay, claim, create account,
  trustline) selects the fee and runs the fee-cap check before policy
  evaluation, so a request that policy would deny can return a fee-cap or
  network refusal first.
- The durable store exposes a strict native reservation projection and rechecks
  checked floor facts under its mint lock. Missing legacy amounts and ambiguous
  Soroban zeros refuse floor use while lifecycle and recovery remain available.
  Public payment paths still refuse configured floors until observed reads and
  retained-history coverage are supplied. No stored format or migration changes.
