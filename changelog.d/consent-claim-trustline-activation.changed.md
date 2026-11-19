- Mainnet claim and trustline approvals now enforce consent delivery
  evidence. A request reserves its evidence slot before it is shown, and
  its consent records delivery facts. A commit refuses consent without
  exact delivery. A live claim or trustline grant without delivery facts
  blocks new requests of every enforced kind in its scope until it ends or
  is revoked. A request pending from before the upgrade whose scope holds
  no consent evidence refuses approval with `audit.outbox_evidence_unusable`
  and the reason `consent evidence not initialized`, and must be prepared
  again. A scope whose evidence holds a migration pin that no live grant
  adopts refuses every request, a fresh one included, with the reason
  `unresolved migration pin`.
- A CLI confirmation of a canonical intent request of an enforced kind
  compares the approval with the intent digest its entry binds, and
  completes its consent through the intent verifier.
