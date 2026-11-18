- CLI help and MCP tool descriptions match the code. They state the mainnet
  refusals of the signing, vault, trade, and SEP-43 tools, and the mainnet
  admission of the classic commit tools. They name the approval proof fields
  each commit step takes and the codes a refused approval returns. They list
  every subcommand of `approve`, `audit`, `counterparty`, `profile`,
  `toolsets`, and `smart-account`.
- `toolsets run` help states that the command checks an action and does not
  execute the routed tool. `stellar_rules_list` states its fixed scan of rule
  IDs 0 to 49.
- `--profile` help states that a mainnet profile must be named with the flag.
  The `approve` help states the mainnet limits of `--open-by-operator`,
  `--no-open`, and `--remote`. The classic MCP tool descriptions state the
  account read a mainnet `balance_floor` rule adds.
