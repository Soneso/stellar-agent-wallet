- Refuse approvals revoked during the CLI presence ceremony before writing
  consent, and preserve the MCP protocol error channel for approval directory
  and initial inbox-open failures.
- Persist and reuse x402 approval records, bind authenticated message mints to
  their approval operation, and require durable value records before CLI or
  inbox presence starts. On mainnet, the second x402 call reuses the first
  call's `business_id`; another `business_id` refuses with
  `network.mainnet_authorization_refused`.
