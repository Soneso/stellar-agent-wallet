- Add an optional toolset context to the shared payment commit handler. With
  it, the routed and the toolset's outer policy rule both govern the payment:
  either approval requirement applies, the earlier end bounds the approval,
  and an outer denial refuses. Off mainnet, a required approval is queued with
  that interval before any nonce use or send. On mainnet, a required approval
  is queued through the durable approval record of the prepared operation,
  before any nonce use or send. The verified grant stays leased from before
  nonce verification until submission returns. Public toolset payments
  require approval only when the composed policies require it. On mainnet,
  toolset signing admits only the exact `stellar_pay` and `stellar_pay_commit`
  actions.
