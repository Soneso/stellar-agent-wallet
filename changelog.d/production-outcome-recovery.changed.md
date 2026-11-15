- Production dispatch and targeted transaction status now run the bounded outcome driver of `recover_outcomes` once per call.
  The driver applies the runnable filter before the four oldest attempts, so isolated, exhausted, live-lease, and future-due attempts send no recovery request.
  Each reached attempt reserves one of sixteen runs with a 20-second lease, stores a contextual stop with automatic backoff, or commits a checked decision in the same call.
  A store refusal of the reservation, the release or stop, or the decision write returns `RecoveryError::Context` with the store root code, the verified progress of the selected attempts, and `; decided: N`.
  `recover_sequences` keeps its signature and returns the driver's report, with per-attempt results, evaluated counts, and selection of attempts that hold a matched release.
  The public `OperationStatus::recovery_snapshot` is removed; `outcome_snapshot` selects attempts with a matched release as well.
  The legacy sequence collector, its health refresh, and its saved-upper target veto are removed; shared requests stay at four per call.
  Targeted status acquires the audit writer at most once after reconciliation and shares it with recovery, accounting delivery, and receipt repair.
  Status still makes its separate diagnostic lookup outside the recovery budget; its failure can replace the returned answer while committed recovery state persists.
  Failed identity or health prefixes leave attempts unchanged and are not bounded by the run cap; structured CLI and MCP recovery reporting remains deferred.
  `stellar-agent tx receipt clear <ENVELOPE_HASH> --acknowledge` records an accounting acknowledgement, not chain proof or permission for a successor.
  No chain-proof command or retry flag resolves high account sequences, exhausted runs, or unusable records.
