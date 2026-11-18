- Refuse approvals revoked during the CLI presence ceremony before writing
  consent, and preserve the MCP protocol error channel for approval directory
  and initial inbox-open failures.
- An x402 retry no longer opens a second approval record, an authenticated
  message mint no longer uses an approval without its operation, and CLI or
  inbox presence no longer starts for a value approval without its durable
  record. On mainnet, the second x402 call reuses the first
  call's `business_id`; another `business_id` refuses with
  `policy.approval_consumed`.
