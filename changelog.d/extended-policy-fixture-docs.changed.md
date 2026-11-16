- Documentation now describes the version 2 policy additions as the loader
  and evaluator enforce them. The skill policy reference covers unlisted
  recipient modes, total budgets, balance floors, and memo bindings. The
  profile guides state that each `profile sign-policy` starts a new total
  allocation and that `profile reset-window-state` keeps total-budget usage.
  They state that a matched balance floor refuses a payment with
  `account.unread` on the shipped CLI and MCP payment paths. Memo bindings are
  documented beside SEP-29, and the skill troubleshooting reference lists the
  six refusal codes of the version 2 additions. Mainnet pages distinguish
  Allow, which signs without an approval, from RequireApproval, which needs
  one. The `minimum_reserve` description names the CLI commands that count the
  envelope fee. It states that a balance equal to reserve plus margin passes
  and that the paired MCP commit check counts the encoded fee during
  preparation.
