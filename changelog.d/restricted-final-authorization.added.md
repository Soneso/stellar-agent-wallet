- Add a restricted classic payment authorization for a live toolset grant. It
  binds the checked grant, installation, and exact invocation, evaluates the
  routed and toolset rules in one private policy frame, expires no later than
  the grant, and holds the grant's lease until the authorization drops or,
  once submission starts, until submission returns.
  Composition of one payment's holds pairs each accounting key and epoch
  across the two evaluations only, so each evaluation keeps its repeated
  criteria and a shared key takes the larger count and the tighter compatible
  limit. The mainnet toolset payment commit supplies this restriction.
  On mainnet, toolset signing admits only the exact `stellar_pay` and
  `stellar_pay_commit` actions.
