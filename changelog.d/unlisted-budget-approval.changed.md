- On a mainnet profile, a payment to an unlisted recipient beyond the
  `unlisted` budget's per-payment or rolling bound requests a per-payment
  approval instead of failing with `policy.deny.unlisted_budget_exceeded`.
  The approved payment counts in full, and every cap, rate limit, and total
  budget still applies. Other networks keep the denial.
- Every spelling of an unlisted budget's asset, such as a classic asset and
  its asset contract, counts in one budget, including rows an earlier build
  stored.
- An unlisted budget sum that overflows refuses with
  `policy.accounting_overflow`, and a negative stored amount with
  `policy.accounting_invalid`. A mainnet authorization under policy authority
  that finds the budget spent refuses with `policy.approval_required`.
- The spending summary states `unlisted_exhaustion = "approval"` on mainnet.
  Its largest unlisted payment is the hard maximum available with approval,
  which neither unlisted budget bound limits, while the unattended bounds
  still keep the budget's window counter.
