- `approve revoke` on a mainnet approval whose stored state is pending now
  writes `revoked` and appends its `approval_revoked` audit row at any time,
  also after the waiting expiry. An inbox revocation admitted on a live,
  unconsented record also revokes when the waiting expiry passes before the
  record is read again. Before, a revocation after that expiry reported
  `expired`, wrote nothing, and a consent received before the expiry could
  still commit and be used. A later consent commit refuses with
  `approval.revoked`, and every later mint refuses as revoked.
- A revocation now also refuses the payment authorization of an
  authenticated x402 approval under its used SEP-10 message authorization,
  and the x402 payload-release authorization under a used Soroban intent
  authorization. Before, these legs were still authorized after
  `approve revoke` reported `revoked`. An authorization minted before the
  revocation keeps its lifetime.
