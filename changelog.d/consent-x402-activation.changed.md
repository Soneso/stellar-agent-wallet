- Mainnet x402 payment approvals now enforce consent delivery evidence, for
  both the plain and the authenticated x402 tools. A request reserves its
  evidence slot before it returns the approval, and a payment call refuses
  consent without exact delivery before it mints the Soroban intent. A live
  x402 grant without delivery facts blocks new requests of every enforced
  kind in its scope until it ends or is revoked. With this change, all four
  approval kinds enforce consent delivery evidence: payment, which covers
  account creation, claim, trustline, and x402 payment.
