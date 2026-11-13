- `audit acknowledge-outbox-loss` acknowledges a loss of a keyed audit outbox
  under owner state. Without a loss it refuses with
  `audit.outbox_loss_not_found` before any write.
