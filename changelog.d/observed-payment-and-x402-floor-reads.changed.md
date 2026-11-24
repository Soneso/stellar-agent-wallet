- A mainnet `balance_floor` that passes now admits the action when the window
  store carries its native coverage marker and the balance read lies past
  both admissible floors. The mint checks the floor again under its lock with
  the action's amounts: when native exposure committed after the read takes
  the balance below the floor, the action refuses with
  `account.floor_refused`. Without the marker the floor still refuses with
  `account.unread`.
- MCP `stellar_pay` and `stellar_pay_commit` read the operating account and
  its reservations for a floor on mainnet, and the commit reads them again.
- A mainnet MCP pay, claim, create-account, or trustline commit refuses with
  `account.unread` when the preparation tool's rule carries a
  `balance_floor` and the commit tool's rule carries none, or a lower one.
  Put the same floor on both tool names.
- Both mainnet x402 tools read the enrolled payer before their preparation:
  under a `balance_floor` with its reservations, and under a
  `minimum_reserve` alone as a bounded account read. A reserve rule no longer
  refuses with `policy.engine_required`.
- A mainnet x402 payment on the native asset contract records its amount as
  a native debit. The resolver refuses an amount above the 64-bit range with
  `policy.accounting_overflow` when it records the debit. Such an amount
  always needs the cross-check witness, which the resolver checks first; a
  call without one refuses there.
- When the resolver refuses an x402 payment with an accounting refusal, the
  x402 tool result carries `policy.accounting_overflow`,
  `policy.accounting_invalid`, or `policy.approval_required` in place of
  `network.mainnet_authorization_refused`.
- The policy summary describes a mainnet x402 floor as a funding condition;
  off mainnet such a floor still denies every call.
