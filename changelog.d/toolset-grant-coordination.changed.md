- Toolset grant writers and installers now coordinate through advisory locks.
  Every grant insertion and revocation holds an exclusive lock on a sidecar of
  the grant store, so concurrent `approve`, approval UI, and outbox-loss
  recovery writes no longer lose or resurrect a grant. The gated toolset
  resolver holds the toolsets lock shared and the grant lock while it looks for
  a grant, and releases both before it queues a first-invoke approval. A held
  lock refuses outbox-loss recovery with `approval.writer_locked` before it
  revokes anything. The resolver and the grant writer return the library
  result `toolset.coordination_busy`. MCP nests it in an internal error whose
  message starts with `toolset.enforcement_error:`, and `approve` nests it in
  the detail of `approval.grant_persist`.
  Existing grants keep matching, and the resolver returns the verified grant's
  identity and stored expiry. A library recheck verifies that exact grant and
  installation under shared locks, creates no file, and never renews expiry.
  Its library results are `toolset.grant_invocation_mismatch`,
  `toolset.coordination_busy`, `toolset.coordination_unavailable`,
  `toolset.grant_changed`, `toolset.grant_expired`, and
  `toolset.io_error: clock_unavailable` for a clock failure.
- `stellar_toolset_invoke` compares its `toolset` and `action` arguments
  exactly as sent, at the server's halt check and in routing. A name that
  differs only by an escape sequence or a control character no longer reaches
  the tool its display form names; it answers `toolset.not_installed` or
  `toolset.unknown_action`, and a halted profile refuses it as an unknown tool.
