- The startup advisory names only rules without an `sa_context_rule_deleted`
  row in the local audit log. A rule removed with `smart-account rules delete`
  produces no warning on any command for its revoked or retired
  verifier or for its pin record of eight-byte hash prefixes, and the advisory
  appends no `sa_verifier_allowlist_advisory` row for it.
