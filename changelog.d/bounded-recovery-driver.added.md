- Public `recover_outcomes` filters runnable attempts and writes owned run reservations, stops, and resolved decisions.
  A call can commit matched expiry evidence and a checked account decision together.
  The public API adds `RecoveryAttemptResult` and `RecoveryReport::attempts`; `RecoveryError` and `RecoveryReport` are `#[non_exhaustive]`, and `RecoveryReport` is no longer `Copy`.
  Recovery uses a read-only identity and health prefix, up to four shared requests and six requests per timed attempt.
  One 20-second network deadline covers up to four reached attempts; each spends one of sixteen reservations.
  Failed prefixes leave attempts unchanged and can repeat without a durable throttle or a reservation charge.
  Prefix invocations are outside the spent-run cap and its associated cost totals.
  Successful partial evidence remains authenticated but cannot complete a paired proof.
  Production dispatch, sequence recovery, and status retain their existing behavior and do not call this driver.
  Status still makes its separate diagnostic lookup; these recovery budgets do not bound status.
  A diagnostic failure can mask an earlier recovery result; structured CLI and MCP reporting remains deferred.
  Receipt replacement and acknowledgement remain separate from the checked accounting decision.
  `stellar-agent tx receipt clear <ENVELOPE_HASH> --acknowledge` records an accounting acknowledgement.
  Untimed holds also require `--acknowledge-unbounded`; neither acknowledgement proves an outcome or permits a successor.
  No chain-proof command or retry flag resolves high account sequences, exhausted runs, or unusable records.
  Frozen targets and production activation remain separate deliveries.
