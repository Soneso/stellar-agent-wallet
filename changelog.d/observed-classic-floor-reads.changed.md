- A matched `balance_floor` on a mainnet classic action reads the operating
  account after a readiness check and counts its retained native reservations.
  The CLI `pay`, `claim`, `trustline`, and `accounts create` verbs, the MCP
  claim, create-account, and trustline tools, and signing resolution use these
  facts, so a breach refuses with `account.floor_refused` and an old read with
  `account.stale`. A floor that passes still refuses with `account.unread`,
  because retained history cannot prove that it counts every native
  obligation. MCP `stellar_pay` and the x402 tools keep refusing configured
  floors with `account.unread`.
- Account denials keep their codes under a policy authority at signing
  resolution, and accounting errors of a mainnet evaluation keep
  `policy.accounting_invalid` and `policy.accounting_overflow` on the CLI and
  MCP paths and at classic signing resolution.
