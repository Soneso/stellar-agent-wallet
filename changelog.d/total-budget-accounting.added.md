- The codes `policy.total_epoch_unavailable` and `policy.total_epoch_stale`
  refuse total-budget accounting without a readable, matching policy pin.
  CLI, MCP, MPP, x402, and mainnet authorization paths report them, and
  `policy.total_epoch_retired`, under their own codes.
