- Mainnet dispatch reconciliation and transaction status now free native holds
  that both recovery endpoints prove due: expired x402 signatures and terminal
  classic transactions whose `maxTime` both latest closes passed. Each release
  uses the smaller paired ledger and close time and commits its release row
  atomically; live x402 expiry also records its transition audit row. Stores
  with only such obligations read one identity and health prefix, and the
  releases take no classic recovery slot. Untimed holds still need
  `tx receipt clear --acknowledge --acknowledge-unbounded`.
- `OperationStatus::release_candidates` lists the authenticated release
  obligations before their proof, optionally for one transaction hash.
