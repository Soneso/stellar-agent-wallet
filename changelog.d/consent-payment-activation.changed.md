- Mainnet payment and account creation approvals now enforce consent
  delivery evidence. A request reserves its evidence slot before it is
  shown, and its consent records delivery facts. A commit refuses consent
  without exact delivery. A live payment grant without delivery facts
  blocks new requests of every enforced kind in its scope until it ends or
  is revoked.
  A payment or account creation request pending from before the upgrade
  refuses approval with `audit.outbox_evidence_unusable` and the reason
  `unresolved migration pin`, or `consent evidence not initialized` when
  the scope holds no consent evidence. In that second case a new request
  initializes the evidence, so the payment must be requested again.
- A testnet `trade` or `vault` refusal that requires approval names only
  the approval requirement. It no longer points to the MCP server, which
  has no approval path for either verb.
