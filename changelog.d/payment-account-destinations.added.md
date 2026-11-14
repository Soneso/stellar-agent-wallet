- `stellar_agent_core::payment_accounts::PaymentAccount` parses the canonical,
  checksum-valid G account or M address of a classic payment. An M address
  keeps its complete text and ID, including ID zero. C, W, bad checksums,
  whitespace, and other spellings refuse with `validation.address_invalid`.
- Core `sign-payment` first-invoke grants accept G and M destinations. A G
  grant covers its account and every M address of that account. An M grant
  covers only its complete address. The attestation binds the stored
  destination bytes exactly, and `sign-rule-create` keeps its C destination.
- Payment summaries and `sign-payment` grants validate the destination at
  construction, deserialization, and store insertion. Existing checksum-valid
  G records load without changing their destination or attestation bytes.
- A stored grant or pending entry whose destination fails the canonical
  check loads and lives as an ordinary record: it is listed, found,
  rejected, revoked, expired, and counted like any other. A grant matches
  nothing. Approval, consumption before a send, and commit return
  `approval.entry_inconsistent`. Rejection, revocation, and the receipt
  repair after a send read no destination.
- `ApprovalSummaryView::ToolsetFirstInvokeGate` adds `destination`, the
  complete validated destination, and keeps `destination_redacted`.
- `ValueLegRecord::from_payment_leg` adds `destination_sha256`, the lowercase
  hexadecimal SHA-256 of the complete payment destination. The generic
  conversion adds no hash. Rows without the field read, serialize, and verify
  unchanged.
- These core interfaces do not change which destinations the CLI and MCP
  payment paths admit.
