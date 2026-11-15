- Operation recorders collect each state edge whose generation commit returns success as a `CommittedTransition` in a `CommittedBatch`.
  `OperationRecorder`, `ApprovalRecorder`, `WalletSubmissionRecorder`, and `StageMarkedRecorder` expose `take_committed`, which drains the batch once.
  An exposure, pure evidence, a refused step, a replay, or a commit that returns an error adds no entry.
  Edges committed before a later refusal in the same call stay in the batch.
  `begin_classic_attempt_committed`, `end_operation_attempt_committed`, `reconcile_pass_committed`, `reconcile_legacy_pass_committed`, and `transaction_status_committed` append their commits to a caller's batch.
  The existing functions keep their signatures, results, and request order.
  `OperationStatus::watch_classes` classifies the operations `list_since` selects as settled, needing attention, or pending, from one verified read.
