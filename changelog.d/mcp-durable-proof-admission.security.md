- MCP mainnet commits verify a supplied approval against its durable record
  and the operation the call continues, never against the approval inbox.
  A collected, locked or edited inbox entry changes no outcome, except that a
  live rejection entry answers `policy.approval_rejected`, and an inbox
  consent without a record refuses with `policy.approval_required`. A revoked
  approval returns `approval.revoked`, and a proof of another operation
  returns `policy.approval_consumed`.
