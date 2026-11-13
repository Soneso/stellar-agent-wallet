- `stellar_agent_core::policy::transaction_effects` decodes a caller-supplied
  transaction into the operations a payment rule decides, the effects the
  wallet cannot value, and the fee the wallet account pays.
  An account merge and a signer, weight or threshold change refuse.
  A negative operation amount refuses the whole transaction before valuation.
  The refusal identifies the operation index, kind, and field.
