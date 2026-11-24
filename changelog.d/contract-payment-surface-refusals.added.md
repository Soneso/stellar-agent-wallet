- Refuse payments to C contract recipients on every payment surface with
  `validation.contract_payment_unavailable`, or
  `validation.contract_payment_memo_unsupported` with a text, id, hash, or
  return memo. MCP preparation and commit, both toolset payment actions, CLI
  full and build-only payments, and the mainnet CLI refuse before any
  request, approval, nonce, or signing. On mainnet the mode, feature,
  admission, and freshness refusals come first.
- Refuse an envelope holding one contract transfer on CLI `--sign-only` and
  `--submit-only`, MCP and toolset commit, the paired commit evaluation, and
  the mainnet resolver. It refuses with `validation.contract_payment_invalid`
  without a valid asset. Otherwise it refuses with
  `validation.contract_payment_memo_unsupported` when it carries a memo,
  `validation.contract_payment_unavailable` once proven for the asset, and
  `validation.contract_payment_invalid` when not proven. The paired evaluation has no asset, so it always answers
  `validation.contract_payment_invalid`. Such a transfer never signs under
  the opaque-signing posture. SEP-43 transaction tools keep their own policy
  decision.
