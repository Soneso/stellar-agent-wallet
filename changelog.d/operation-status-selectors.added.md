- Select a transaction status by business id. `stellar-agent tx status`
  takes `--business-id` beside an optional hash, and `stellar_transaction_status`
  takes `business_id` beside an optional `tx_hash`. On mainnet both must name
  the same operation, and an unknown business id refuses with
  `operation.unknown`; neither selector refuses with `validation.usage_error`.
  A business id without an exposed hash reads no network. On testnet the id is
  checked and echoed.
- Report the stored mainnet operation as `operation`: its state, attempts
  with their exposed identity, last transition, bucket hold, awaiting approval
  and result, from one authenticated read. It is `null` for an unrecorded hash
  and on testnet, and it carries no amounts, next action or recovery outcome.
