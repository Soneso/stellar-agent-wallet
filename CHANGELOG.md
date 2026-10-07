# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Dev and test profiles use workspace line tables and omit dependency debuginfo;
  tests disable incremental caches. The toolchain uses the minimal installation
  profile with rustfmt and clippy.
- Preflight scopes clippy, rustdoc, and tests to changed packages and their direct
  dependents. Contribution guides start local verification with preflight and
  use CI for the offline workspace suite.
- The building guide documents disk use, debugging overrides, and opt-in cleanup.

- The three log lines of the CLI's shared value audit writer acquisition end in
  `refusing`, which fits the callers that neither sign nor submit. Two tests pin
  the Enforce binding check at the `approve` site and at the value audit
  pre-flight. The audit log recovery guide names the `audit reanchor` repair rows
  in the plural. Thanks to @ngybnc.

## [0.1.0-alpha.11] - 2026-10-07

A security fix for MCP policy evaluation with chain-bound rules, and the fixes from the alpha.10 release tests on macOS and Windows.

### Security

- In `0.1.0-alpha.1` through `0.1.0-alpha.10`, the MCP server and the CLI
  `smart-account multicall` command match policy rules against an empty chain,
  so a rule with an exact `chain` never applies there. The MCP server now
  evaluates policy rules and records spending with the profile's chain, so an
  exact `chain` rule applies on the MCP path as on the CLI. A wrong `chain_id`
  argument fails with `invalid_params` before any policy decision. SEP-43
  sign-and-submit counts toward the rate limit of its matching rule. The CLI
  `smart-account multicall` command evaluates and records its bundle with the
  profile's chain.

### Added

- `WalletError::Approval(ApprovalFailure)` and `ErrorCategory::Approval` classify approval-specific failures. Library callers of `load_and_validate_entry` and `attest_and_persist` receive the new variant for these failures.
- The shortened README gives an overview, and the getting-started guide holds
  the direct download, the Windows PowerShell steps, the macOS Gatekeeper note,
  and the profile setup details. `docs/verifying-releases.md` shows how to check
  a release archive against `SHA256SUMS`, its cosign signature, and its SLSA
  provenance.

### Changed

- The getting-started sample policy allows testnet payments up to 100 XLM per day and requests operator approval for other calls except balance reads.

### Fixed

- `profile init` lists audit-key rotation before signer enrollment on both engines so the first enrollment writes its audit row.
- `accounts create --profile` help describes the profile's chain and endpoints for either funding mode.
- `audit verify` reports each verifier failure with its `audit.*` code and diagnostic text. A missing log has a remediation message.
- Approval-specific failures from the CLI and shared attestation API use `approval.*` envelope codes. Their messages omit the code prefix and internal wrapper. The MCP server's direct JSON-RPC approval errors are outside this change.
- Multicall submission requires the call chain to match the profile chain at entry, before bundle validation or side effects.

- CLI help names `--account` as required for balances and describes JSON profile-list output and audit sidecar re-signing. The `stellar_balances` MCP description uses `--account` in its CLI equivalent.
- `trustline` and `claim` print one JSON envelope. The typed preview is in `data.preview` on success and in `error.details.preview` when a later step fails.
- An argument the CLI parser refuses prints one `validation.usage_error` envelope on stdout and exits `1`, with nothing on stderr. `--help` and `--version` still print their text and exit `0`.
- Friendbot's refusal to fund an existing account reports `network.friendbot_account_already_funded`, naming the account. The `friendbot` command, `accounts create --fund-with-friendbot`, and `stellar_friendbot` share the code.
- `balances` requires `--account` at the argument parser, so omitting it reports `validation.usage_error`.
- A headless keyring backend that cannot be set up reports `auth.keyring_config_invalid`. A padded or standard-alphabet `STELLAR_AGENT_HEADLESS_KEYRING_KEY` is refused with a message naming that cause.
- `profile init` next steps include `profile rotate-nonce-key` and, for a V1 profile, creating the policy file before `profile sign-policy`.

## [0.1.0-alpha.10] - 2026-10-05

First contributions from outside the maintainers: @Revan0809 (#280), @harshit3355 (#308), @thadidaniel-ctrl (#305, #306), and @abhicodes-007 (#312).

### Added

- Wire codes `profile.network_flag_mismatch`, `auth.enrolled_signer_unpinned`, and `auth.enrolled_signer_mismatch` identify network assertions and signer enrollment refusals.
- Core `check_enrolled_signer` and network `enrolled_keyring_signer` enforce the enrolled identity on mainnet.
- `--profile` selects profiles for `smart-account rules get`, `rules get-spending-limit`, `deploy-policy`, `deploy-ed25519-verifier`, `deploy-spending-limit-policy`, and `deploy-webauthn-verifier`.
- Core `redact::CREDENTIALED_URL_INPUT_REFUSAL` is the refusal text for an RPC URL input that carries credentials.
- Core `check_endpoint_url` and `Profile::validate_endpoint_urls` apply the endpoint rule to a profile's three endpoint fields. A refusal is an `EndpointUrlError` naming the field and an `EndpointUrlRejection`, never the URL. The loader reports one as `ProfileLoadError::InvalidEndpointUrl`, and a mainnet file without `rpc_url` as `ProfileLoadError::MainnetRpcUrlRequired`.
- `stellar_agent_network::NetworkContext` carries the chain identity and RPC endpoints for a command, with a canonical passphrase and redacted `Debug` output.
- Core profile APIs `check_mainnet_selection` and `ResolvedProfileName::from_flag` preserve explicit profile selection. `ProfileLoadError::to_validation_error` maps loader refusals to validation errors.
- Wire codes `profile.non_overlayable_field` and `profile.mainnet_requires_explicit_profile` identify refused overlays and implicit mainnet selection.
- `AttestationBinding` and `ApprovalContext` name the profile and the chain an approval is bound to and rendered under.
- `envelope_source_account` returns the effective source of a single-operation envelope; `approve list` reports it as `source` on payments and `envelope_source` on claims.
- `approve` prints the profile, the network, the endpoint host, the enrolled signer, and the envelope source before the approval prompt; the loopback and remote inbox pages show the same rows.
- The approve hints name the profile; the simulate responses name the profile and the chain id.
- `shell_word` quotes a word for a POSIX shell.
- `test_helpers::HeldRuleLock` and `test_helpers::hold_rule_lock`, under the
  `test-helpers` feature, hold a rule lock until the returned value is dropped.
- `DELEGATED_SIGNER_ADDRESS_REASON` states the G-strkey or C-strkey input requirement.
- `PendingAddStep::new_for_test` constructs a pending add under `test-helpers`.
- `Caip2::from_passphrase` maps a network passphrase to its chain id.
- `stellar_agent_core::redact` holds the URL redaction helpers; the network crate re-exports them.
- `Profile::redacted` returns a `RedactedProfile`, the serialized view with URL fields reduced to scheme, host, and port.
- Four audit event kinds record a version-2 signer-set state:
  `SaSignerSetBaselinedV2`, `SaSignerAddedV2`, `SaSignerRemovedV2` and
  `SaThresholdChangedV2`. Each row carries every signer's full identity (an
  Ed25519 key, an External verifier with the SHA-256 and length of its key
  data, or a delegated contract), a threshold observation that is `null` when
  the rule has no simple-threshold policy, and an account digest that binds
  the smart account to its network passphrase. Their 32-byte fields are
  lowercase hex. The snapshot is the value type `SignerSetSnapshotV2`, built
  from `SignerEntryV2`, `SignerIdentityV2` and `ThresholdObservation`;
  `SignerSetSnapshotV2::validate` refuses unsorted or duplicate signer ids and
  empty External key data with `SignerSetCanonicalBodyError::MalformedSnapshotV2`.
  `AuditEntry::new_sa_signer_set_baselined_v2`, `new_sa_signer_added_v2`,
  `new_sa_signer_removed_v2` and `new_sa_threshold_changed_v2` construct the
  rows. `compute_signer_set_digest_v2` hashes a snapshot under the domain
  `sa.signer_set.v2.divergence`, `account_digest` hashes the account under
  `sa.account_id.v1`, and `BaselineReason` gains `ConfirmedInstall`. The four
  value types, `SignerSetView` and `SignerSetViewPayload` are re-exported from
  `stellar_agent_core::audit_log` and `stellar_agent_smart_account::signers`;
  the digest functions and domain constants from `stellar_agent_core::audit_log`.
- SEP-43 `signAuthEntry` signs CAP-71 envelope type 10
  (`SorobanAuthorizationWithAddress`) preimages, the preimages
  `@stellar/stellar-sdk` v17 builds for `SorobanCredentials::AddressV2`
  entries, beside envelope type 9 (`SorobanAuthorization`). A type 10
  preimage must be bound to the signing key's `ScAddress::Account`; a preimage
  bound to another account, a contract or a muxed account is refused with
  `sep43.invalid_address` before any signing. Every other preimage case is
  refused with `sep43.malformed_auth_entry`.
- The `stellar-agent-soroban-auth` crate maps a `SorobanCredentials` arm to its
  authorization preimage version, builds the envelope type 9 or type 10
  preimage, and hashes it into the signature payload.
- The signers manager observes a rule's signer set in version 2 through both
  RPC endpoints: each endpoint reads the rule, then each attached policy's
  executable, then the simple-threshold value, and the endpoints must agree.
  A rule without a simple-threshold policy observes no threshold. `signers
  list` and `signers refresh` record `SaSignerSetBaselinedV2` rows, and the
  signer verbs record `SaSignerAddedV2`, `SaSignerRemovedV2` and
  `SaThresholdChangedV2` rows.
- `signers list` over an existing baseline compares the chain with it and
  reports `baseline` (`matched`, `diverged` or `not_comparable`, or `none`
  for a first observation). `signers refresh` compares before it re-anchors
  and reports `previous_baseline`; `--accept-divergence` records a changed
  set or a version-1 baseline the chain cannot be compared with.
- `sa.signer_set_baseline_legacy` (`SaError::SignerSetBaselineLegacy`)
  refuses `signers add`, `remove`, `set-threshold`, and `batch-add` on version 1.
  It also refuses `rules add-policy` and `rules remove-policy` for any policy,
  and a `migrate-verifier` removal.
  `sa.baseline_write_failed` (`SaError::BaselineWriteFailed`, stages in
  `BASELINE_WRITE_STAGES`, reason capped at
  `BASELINE_WRITE_REASON_MAX_BYTES`) reports a signer-set state row that was
  not recorded, with the transaction hash when a signer mutation confirmed.
- `ListOutcome`, `RefreshOutcome` and `PreviousBaseline` in
  `stellar_agent_smart_account::managers::signers`, and `Display` for
  `SignerSetView` (`v{version} count={n} threshold={t|none}`).
- A rule the wallet installs is recorded as its own signer-set baseline.
  After the install confirms, both endpoints are read at or past the
  confirmation ledger. The observed signers and simple-threshold policy must
  be the authorized definition, and the wallet writes a
  `SaSignerSetBaselinedV2` row with reason `confirmed_install`. The signer
  verbs work on the new rule without a `signers list` first.
- `sa.install_state_mismatch` (`SaError::InstallStateMismatch`) reports an
  install that confirmed and was not baselined: the observed rule is not the
  definition, or the return value carried no rule id. Its message names the
  transaction and two ways to settle the rule: delete it under rule 0 or
  accept it with `signers refresh`. An install whose baseline is not
  observed or not written reports `sa.baseline_write_failed` with the
  transaction hash.
- `simple_threshold_policy::parse_simple_threshold_install_param` reads the
  threshold from the simple-threshold policy's install parameter.
- The `test_helpers` module (feature `test-helpers`) builds a signers
  manager and a rule manager that share one audit writer.
- `sa.pinned_verifier_absent` (`SaError::PinnedVerifierAbsent`) refuses
  signing under a rule that holds an `External` signer while its pin record
  pins no verifier, since the live verifier would sign unchecked. The
  pinned-hash drift check raises it before anything is simulated, writes no
  drift row, and passes it through unfolded; `multicall` reports it at phase
  `policy_gate`, and `rules verify-pins` reports the verifier as `drift`.
  `signers refresh --rule-id N` repairs the record.
- `signers refresh` pins the live verifier of a rule whose pin record pins
  none while the rule holds `External` signers. Each live verifier is probed
  as `rules create` probes one; the new `--accept-mutable-verifier` and
  `--accept-unknown-verifier` flags admit a mutable or unknown one. After the
  baseline row, the override rows and a `SaContextRulePinsUpdated` row with
  the new reason `baseline_refreshed` record the pin, and the envelope
  reports `verifier_pinned`. Two verifier addresses whose pins are equal, in
  hash and executable reference, share one pin. Live verifiers whose pins
  differ refuse with `sa.multiple_pinned_hashes_unsupported` before the
  baseline or any pin row is written.
- `PinsUpdateReason::BaselineRefreshed` (`baseline_refreshed`), and
  `RefreshOptions` in `stellar_agent_smart_account::managers::signers`, the
  options of `refresh_signer_baseline`. `RefreshOutcome` gains
  `verifier_pinned`.
- `PendingAddStep` (re-exported at the crate root) and
  `MigrationSubmitResult::pending_add`: the add that completes a migration
  pair whose removal was sent. It carries the rule, the removed signer's
  id, the destination verifier and the key data. It also carries the
  removal's hash, whether the removal confirmed, and the add's hash when its
  outcome is unknown. `SignerStepSubmitOutcome::new_signer_id` is the id the
  chain assigned to the restored signer.
- The `migrate-verifier` envelope reports `pending_add` (with
  `recovery_command`, the exact `signers add` with the invocation's
  signer-source, `--profile`, `--network` and `--timeout-seconds` flags),
  each step's `key_data_hex`, and `new_signer_id` for a completed pair. On a
  pair that stopped after its removal was sent, the command prints the line
  that completes it on stderr before the envelope. The line is the
  `signers add`, or the `signers refresh --accept-divergence` then the add
  after `sa.baseline_write_failed` or `sa.signer_set_diverged`, or the wait
  for a transaction whose outcome is unknown. On a rule with remaining
  source signers the line names the re-run of `migrate-verifier` for them
  after the refresh or the wait, and before the add.
- `stellar_agent_network::refuse_mainnet_write` refuses a mainnet passphrase
  or a mainnet-pattern RPC URL with `NetworkError::MainnetWriteForbidden`. It
  performs no I/O.
- `SaError::MainnetWriteForbidden` reports `network.mainnet_write_forbidden`
  from the smart-account crate.
- `DefiAdapterError::MainnetWriteForbidden` carries the same refusal through
  the DeFi adapters.
- `stellar_agent_core::error::MAINNET_SIGNING_REFUSAL_DETAIL` is the refusal
  detail of every sign-only mainnet refusal, and it carries the canonical
  code.
- Wire code `audit.log_binding_changed` (`ValidationError::AuditLogBindingChanged`)
  reports a profile whose audit log path or audit key differs from its
  recorded audit binding.
- Wire code `validation.key_matches_owner_public_key`
  (`ValidationError::KeyMatchesOwnerPublicKey`) reports a symmetric key that
  is, or may be, the profile's owner public key. `NonceError`,
  `WindowStoreError`, and `CounterpartyError` gain a `KeyMatchesOwnerPublicKey`
  variant, and `NonceError` gains `KeyTooLong` (`nonce.key_too_long`).
- `ValidationError::AuditBindingChangeNotAcknowledged` reports the missing
  `audit reanchor` flag under `validation.acknowledgement_required`.
- `ProfileLoadError::OverlayMayOnlyTighten` and
  `ValidationError::ProfileOverlayMayOnlyTighten` report an `mcp_disabled`
  overlay other than `true` under `profile.non_overlayable_field`.
- `TipAnchorReason::BindingChanged`, wire `binding_changed`, on the
  `audit_tip_anchored` row an acknowledged binding change appends.
- Core `audit_log::binding` with `AuditBinding`, `BindingCheck`,
  `RecordedBinding`, and `AuditBindingParseError`.
- Network `KeyringAuditBindingStore`, the keyring store of a profile's audit
  binding, and `check_audit_binding`.
- `KeyringEntryRef::default_audit_binding`, service
  `stellar-agent-auditbinding-<profile>` and account `default`.
- Core `audit_log::tip_anchor::log_path_sha256`,
  `tip_anchor_account_for_digest`, `reanchor_count_account_for_digest`, and
  network `KeyringTipAnchorStore::for_path_digest`.
- Core `audit_log::verify::check_anchor_against_walk` is public, beside
  `stored_anchor_disagrees_with_walk`. `StoredTipAnchor::from_raw`,
  `AuditWriter::stored_anchor_disagrees`, `ReanchorAcknowledgement`, and
  `AuditWriter::reanchor_acknowledging` back the binding acknowledgement.
- Core `profile::owner_key` decodes both owner key forms, rewrites older-form
  entries, and holds `OwnerKeyContext`, `refuse_owner_key_coordinate`, and
  `refuse_owner_public_key`.
- Core `profile::loader::ProfileOrigin` and
  `load_default_or_testnet_fallback_from_dir`.
- `WalletServer::with_audit_binding_check`.
- MCP `transport::load_selected_profile` resolves the server's startup profile
  with its origin.
- Network `keyring::AUDIT_KEY_FIELD` and `policy_state::POLICY_STATE_KEY_FIELD`,
  core `approval::attest::ATTESTATION_KEY_FIELD`, and nonce
  `mint::NONCE_KEY_FIELD` name the profile fields an owner key refusal
  reports.
- Test support `keyring_mock::install_with_write_error` fails the next write at
  one coordinate.
- `x402_authorization_withheld`, an audit event kind written when an x402
  payment fails after its `x402_payment_authorized` row. It carries the
  network, the scheme, and a `failure_stage` of `resimulation`,
  `response_processing`, or `encoding`, and shares the authorized row's
  `request_id`. `AuditEntry::new_x402_authorization_withheld` constructs it.
- The audit outbox: `<log>.outbox` queues consent rows while a draining writer
  in another process holds the log, beside `<log>.outbox.lock` and
  `<log>.drain.lock`. `AuditOutbox` appends to it; `drain_lock_is_held`,
  `inspect_outbox`, and `OutboxInspection` read its state.
- `ConsentAudit` names where `attest_and_persist` writes the consent row: an
  `AuditWriter` or an `AuditOutbox`.
- `stellar_agent_core::audit_log::audit_writer_refusal` maps an audit-writer
  failure to the wallet error that names it. The consent row, the CLI audit
  pre-flight, and the MCP audit pre-flight all refuse through it.
- `AuditWriter::drain_outbox` appends the queued rows and empties the outbox.
  `AuditWriter::write_built` drains, completes any rotation the append needs,
  builds an entry from the current tip, and appends it with nothing in
  between.
- `audit verify` reports `outbox_pending`, the number of queued rows, and warns
  `outbox_torn_tail`, `outbox_unparseable`, or `outbox_unreadable` without
  changing the chain verdict. An unreadable outbox omits `outbox_pending`. The
  warnings are the `VerifyWarning` variants `OutboxTornTail`,
  `OutboxUnparseable`, and `OutboxUnreadable`.
- `stellar_agent_x402::exact::AuthorizationToTransmit` and
  `X402Error::TransmitGateRefused`, wire code `x402.transmit_gate_refused`.
- Detail sub-codes `audit.outbox_unusable` and `audit.outbox_busy`, under
  `audit.chain_key_unavailable`. `audit.outbox_unusable` names the line, the
  column, and the class of the parse failure, never the line's content.
- `ReanchorReport::outbox_drained` and `ReanchorReport::outbox_refusal`.
- `ApprovalKind` and `RegistrationInput` implement `PartialEq`.

### Changed

- CLI transaction commands read their chain and endpoints from the loaded profile. An unnamed, missing profile uses the zero-config testnet profile.
- `--network` is optional and must match the profile's chain.
- `--rpc-url` and `--secondary-rpc-url` are optional testnet overrides. Mainnet profiles refuse either flag, including equal values.
- An absent `--secondary-rpc-url` uses the profile's secondary endpoint. Smart-account rule commands perform their cross-RPC check when a secondary endpoint is configured.
- An environment or programmatic overlay may set only operational profile fields, in three classes. `submit_timeout_seconds` is overlayable on every chain. `rpc_url`, `secondary_rpc_url`, `oracle_provider_url`, `mcp_signer_default`, `cross_check_threshold_stroops` and its alias `usd_threshold`, `classic_fee_per_op_stroops`, `classic_max_fee_per_op_stroops`, `smart_account_max_context_rule_scan_id`, and `session_rule_max_horizon_ledgers` are overlayable on testnet only. `mcp_disabled` is overlayable on every chain, and only to `true`. Every other profile key is refused on every chain with `profile.non_overlayable_field`, even when the value equals the file. That includes `chain_id`, `version`, every keyring coordinate, `audit_log_path`, `policy`, `wallet`, `remote_approval`, `served_pages`, and the pool fields. A `STELLAR_AGENT_*` variable that names no profile key is ignored.
- A mainnet profile names its RPC endpoint; mainnet has no default endpoint. A mainnet profile file without `rpc_url` refuses to load, and `profile migrate` refuses such a v1 file, both with `validation.mainnet_rpc_url_required`.
- `rpc_url`, `secondary_rpc_url`, and `oracle_provider_url` must be HTTP or HTTPS URLs on every chain, and HTTPS URLs with no userinfo on mainnet. The profile loader, `profile init`, and `profile migrate` refuse a URL that breaks the rule with `validation.config_invalid`. The message names the field, not the URL.
- `profile migrate` reports load refusals with validation codes: `validation.profile_not_found` for a missing file, and `validation.config_invalid` for a file it cannot read. A refused migration writes nothing.
- `pay`, `claim`, `accounts create`, `accounts deploy-c`, `trade`, `vault`, `trustline`, and the four `smart-account deploy-*` commands keep two load refusals typed. A named profile's endpoint URL that breaks the endpoint rule reports `validation.config_invalid`, and a mainnet profile without `rpc_url` reports `validation.mainnet_rpc_url_required`. Their other load failures keep `profile.load_failed` (`trustline.profile_load_failed` on `trustline`).
- `approve operator enroll` and `credentials add-passkey` refuse a mainnet profile without `rpc_url` and a profile whose endpoint URL breaks the endpoint rule.
- `Profile::builder_mainnet` and `Profile::builder_mainnet_named` take the RPC URL. `Caip2::default_rpc_url` returns an `Option`, `None` for mainnet. `ValidationError::MainnetRpcUrlRequired` carries the profile name.
- The `secondary_rpc_url` inputs of `stellar_dex_trade`, `stellar_defindex_vault_deposit`, and `stellar_defindex_vault_withdraw` default to the profile's secondary endpoint. Mainnet profiles refuse these inputs before other handler work.
- Mainnet seed, Ledger, and keyring signers must match the enrolled signer. Missing or malformed enrollment pins are refused.
- `smart-account multicall` refuses a mainnet profile before registry, writer, or signer access.
- RPC URL flags, including `profile init --rpc-url`, and MCP `secondary_rpc_url` inputs refuse URLs containing credentials; the refusal states that only a testnet profile file may hold a credentialed endpoint.
- `pay`, `claim`, and `accounts create` apply the profile's `[wallet]` unlock controls to the signing seed.
- `accounts create --fund-with-friendbot`, `accounts deploy-c`, and `fees stats --profile` read their network from the resolved profile. `accounts deploy-c` opens an audit writer only with `--profile`.
- `accounts deploy-c`, the four smart-account deployment commands, `rules get`, `rules get-spending-limit`, `register-multicall`, and `unregister-multicall` refuse an explicitly named missing profile.
- `NetworkContext::from_profile` copies `secondary_rpc_url`; `NetworkContext::from_flags` is renamed `NetworkContext::new`.
- `SignersManagerConfig` and `ContextRuleManagerConfig` redact endpoint URLs and audit writers in `Debug`. Signers manager construction errors redact endpoint URLs too.
- The MCP tools `stellar_rule_create`, `stellar_rule_create_commit`, `stellar_rules_list`, and `stellar_rules_get` build their smart-account managers with the profile's secondary endpoint. The rule submission's cross-RPC check uses it when one is set.
- A mainnet profile loads only through `--profile <name>`. `STELLAR_AGENT_PROFILE` never selects one, and a mainnet `default.toml` needs `--profile default`. Keep the filename: its identity is bound to its keyring entries.
- Before the first run after upgrading, move every value a refused environment variable sets into the profile file, `STELLAR_AGENT_AUDIT_LOG_PATH` for example. The first keyed use records the audit binding from the file, so the file must name the log the profile writes. Unset the refused variables, remove refused keys from programmatic overlays, then run `stellar-agent profile show --profile <name>` to confirm the file's chain and endpoint.
- MCP tools and CLI transaction verbs read their network identity from one context per invocation.
- A profile under a refused overlay reads as `profile_resource_unloadable` on MCP profile resources. Account enumeration skips profiles whose load is refused.
- The approval attestation binds the profile name and the chain id under a versioned domain tag. The commit refuses an approval attested on an earlier build; the inbox shows it as resolved until it expires, and the agent simulates and approves again. The CLI and the MCP server must run the same build.
- Pending entries without an attestation can be approved under the new layout. The store needs no migration. Earlier blobs receive the existing payment, claim, MPP, or clawback refusal and expire normally.
- Toolset grants recorded on an earlier build keep suppressing the first-invoke prompt; each action still needs its own approval.
- `compute_attestation`, `verify_attestation`, `verify_toolset_gate_attestation`, `attest_and_persist`, `record_first_invoke_grant`, `build_attested_grant`, and `ToolsetGrant::verify_attestation` take the attestation binding. The three `PendingApprovalStore` verifiers, `commit_authorization`, and `verify_pending_approval` also take it. `DecisionContext::new` takes the approval context; `ToolsetGrantRequest` carries the binding.
- `approval_required_indistinguishable` names the profile in its hint.
- `EVENT_KIND_VARIANT_COUNT` increases from 65 to 69.
- Under `test-helpers`, `SignerStepSubmitOutcome::new_for_test` takes
  `new_signer_id`. `MigrationSubmitResult::new_for_test` takes
  `failed_step_remove_tx_hash` and `pending_add` for the failed pair.
- `rules create --signer-delegated` takes `<STRKEY>`.
- `Profile`'s debug output redacts `oracle_provider_url`.
- `profile show`, `profile init` and the MCP profile resource report URL fields as scheme, host, and port only.
- The `rpc_url` parse error names the parse failure and omits the URL text.
- `DecodedOnChainSigner` gains `DelegatedContract` for a `Delegated` signer
  with a contract address and is `#[non_exhaustive]`, its `External` variant
  included. `to_identity_v2` and `to_signer_pubkey_v1` project a decoded
  signer; the second refuses a contract delegate with
  `SignerDecodeError::DelegatedAddressNotAnAccount`. A rule holding a
  contract delegate is readable.
- `SignerDecodeError::ExternalKeyDataEmpty` refuses an `External` signer with
  empty key data, so a rule holding one is unreadable for every signer-set
  read and for the executable pin check of every rule-authorized signing
  verb.
- `SignersManager::get_rule_signers` returns `Vec<SignerEntryV2>`.
  `list_signers` returns `ListOutcome`. `add_signer` and
  `batch_add_signers` take the signer `ScVal`s only and decode each identity
  from it; `batch_add_signers` returns the id the chain assigned to each
  signer, in input order.
- `SaError::SignerSetDiverged` carries a `SignerSetView` on both sides (on the
  wire, `expected` and `observed` gain a `version` tag) and an optional
  `tx_hash`. Its message names `signers list` to inspect and `signers refresh
  --accept-divergence` to accept. `SignerSetMissingBaseline` names `signers
  list --rule-id N`.
- `FrozenChainStateTuple::observed_chain_state` returns a `SignerSetView`, and
  `simulation_ledger` carries the ledger of the observation.
- The `SaSignerSetDiverged` audit row's `expected_threshold` and
  `observed_threshold` are optional and omitted when absent, and a new
  `snapshot_version` is `2` for a version-2 comparison and omitted for version
  1, so existing rows re-serialize unchanged.
  `AuditEntry::new_sa_signer_set_diverged` takes the two views.
- `signers add`, `remove`, `set-threshold` and `batch-add` compare the chain
  with the rule's baseline before they submit and refuse a changed set with
  `sa.signer_set_diverged`. After the transaction confirms they read both
  endpoints at or past the confirmation ledger, require exactly the intended
  change and record it; any other result is `sa.signer_set_diverged` with the
  transaction hash.
- A version 1 baseline needs one `signers refresh --rule-id N` before
  `signers add`, `remove`, `set-threshold`, or `batch-add`. The same step is
  required before `rules add-policy` or `rules remove-policy` for any policy,
  and a `migrate-verifier` removal. Refresh compares the version 1 projection
  and records version 2 state.
- The `signers list` and `signers refresh` envelopes carry `threshold` as
  optional (`null` without a simple-threshold policy) and
  `snapshot_version`; `list` adds `signer_summaries` and `baseline`, and
  `signer_kinds` gains `delegated_contract`.
- `signers list` and `signers refresh` accept a rule without a
  simple-threshold policy. `signers remove` on a rule whose policies include
  none refuses with `sa.threshold_policy_identification_failed`, and `signers
  set-threshold` on a rule without one with `sa.threshold_policy_not_installed`.
  `signers batch-add` accepts a rule without a simple-threshold policy.
- The passkey signing path works on a rule without a simple-threshold policy
  once the rule has a version-2 baseline.
- A passkey signer added to a pinned rule pins its WebAuthn verifier like any
  other `External` verifier. For a passkey, the `signers list` entry in
  `signer_kinds` and a `sa.threshold_unreachable` refusal's
  `requested_op.signer_type` read `external`. The `signers add` envelope
  keeps `signer_source` as `webauthn`.
- A rule whose policy instance is an external reference with no live tag
  entry refuses signer-set reads with `sa.contract_instance_unsupported`.
- `rules add-policy` and `rules remove-policy` observe the policy's
  executable through both endpoints before submission. Attaching the
  simple-threshold policy refuses a rule that already has one with
  `sa.threshold_policy_identification_failed`, and requires a non-zero
  `{ threshold: u32 }` parameter. Once it confirms, a `SaThresholdChangedV2`
  row records the new threshold. Detaching it records the cleared threshold
  the same way. A rule with two simple-threshold policies accepts the detach of one of
  them when it has a version-2 signer-set state row, recorded before the rule
  gained its second policy, and its signers equal the row's; the wallet then
  records the remaining policy's threshold. Such a rule with no state row
  refuses with `sa.signer_set_missing_baseline`, and only `rules delete
  --rule-id N --auth-rule-id 0` removes it; removing a policy other than the
  two from such a rule refuses with
  `sa.threshold_policy_identification_failed`. A confirmed attach or detach
  whose result is not the intended change refuses with
  `sa.signer_set_diverged` and the transaction hash; its pin and policy rows
  are still written.
- `rules add-policy` and `rules remove-policy` lock the target rule and their
  non-zero auth rules. Under the locks they compare the target with its
  version-2 signer-set state, observe the policy, plan the pin record,
  submit, record the threshold change and write the pin rows; the policy and
  raw rows follow. A concurrent `signers add` on the rule runs before or
  after the whole verb. The comparison runs for any policy. A rule without a
  version-2 state therefore refuses an attach or removal of any policy with
  `sa.signer_set_missing_baseline` or `sa.signer_set_baseline_legacy` before
  submission. The row order of a confirmed attach is `SaThresholdChangedV2`
  (simple-threshold policy only), the override rows,
  `SaContextRulePinsUpdated`, `SaPolicyAdded`, `SaRawInvocation`; of a
  confirmed removal `SaThresholdChangedV2` (simple-threshold policy only),
  `SaContextRulePinsUpdated`, `SaPolicyRemoved`, `SaRawInvocation`.
- `rules remove-policy` refuses before submission when the rule has no
  signer-set state (`sa.signer_set_missing_baseline`, before any RPC), and
  when a rule with a state is not on chain (from the comparison's rule read).
  It refuses a policy id the rule does not hold (`sa.deployment_failed`,
  after the comparison), and a policy whose executable cannot be read
  (`sa.deployment_failed`, `sa.contract_instance_unsupported` or
  `network.rpc_divergence`). `rules delete --rule-id N --auth-rule-id 0`
  removes a rule whose policy stays unreadable.
- A confirmed `rules add-policy` whose return value carries no policy id
  returns `sa.baseline_write_failed` at stage `observe` with the transaction
  hash and writes its pin rows, for any policy.
- `SignersManager::refresh_signer_baseline` takes `RefreshOptions` and returns
  `RefreshOutcome`.
- The `sa.verifier_wasm_not_in_allowlist` and
  `sa.policy_wasm_not_in_allowlist` messages name
  `--accept-unknown-verifier`.
- The multicall testnet suite installs a rule other than 0, submits a bundle
  under it, and asserts that a signer added through another audit log makes
  the next bundle refuse with `sa.signer_set_diverged` at phase
  `policy_gate`.
- `ContextRuleManager::install_rule` and `simulate_install_rule` require a
  signers manager and refuse without one with
  `sa.signers_manager_not_configured` before any RPC; so do `add_policy` and
  `remove_policy`. An install and its simulation also refuse before
  submission in three cases. A definition that names a policy address twice
  or attaches more than one simple-threshold policy refuses with
  `sa.deployment_failed` (phase `build`). A simple-threshold install
  parameter that is not a non-zero `{ threshold: u32 }` map refuses with
  `sa.simple_threshold_install_refused`. An `External` signer with empty key
  data refuses with `sa.auth_entry_construction_failed`.
- A rule created under an earlier release has no state row unless that
  release recorded it through `signers list` or `signers refresh` while it
  held a simple-threshold policy. Such a recorded rule holds version 1 state.
  `rules list` reports `none` or `v1`. A non-zero rule reporting `none`
  needs one `signers list --rule-id N` before any signature it authorizes.
  This includes `execute`, `multicall`, `rules set-name`, `rules set-valid-until`,
  and `rules delete`, alongside policy, signer, passkey, and migration paths.
  A rule reporting `v1` signs through the version 1 projection.
  `set-weighted-threshold`, `set-signer-weight`, and `set-spending-limit` use
  that projection. A lost simple-threshold policy or a contract delegate
  makes version 1 incomparable; `signers refresh --accept-divergence`
  records the current state.
- `SaError::SignersManagerNotConfigured.rule_id` is optional. An install's
  refusal omits it on the wire; a refusal scoped to a rule keeps the bare
  number.
- `CredentialsManager::sign_with_passkey_rule` takes `Arc<SignersManager>`.
  Every passkey signing runs the divergence and drift checks and writes its
  `PasskeyAssertion` row through the signers manager's audit writer.
- A context rule can hold a signer delegated to a contract address: `rules
  create --signer-delegated`, `stellar_rule_create`, the rule proposal check
  and `context_rule_definition_from_snapshot` accept a C-strkey beside a
  G-strkey, through `parse_delegated_signer_address`. A contract delegate is
  not the delegated fallback signer of a passkey or Ed25519 rule, so such a
  rule still needs `--accept-no-delegated-fallback`
  (`accept_no_delegated_fallback` in the MCP).
- The signer-set observation after a confirmed transaction reads an endpoint
  again when its read reports a ledger behind the confirmation, whether the
  read succeeded or failed. A lagging endpoint that does not hold a new rule
  or threshold yet is read again until the recording budget ends.
- `smart-account migrate-verifier` runs each pair as two checked signer
  mutations under the rule's lock. The removal compares the rule with its
  version-2 state row, checks the pair's plan and the removal's
  preconditions (`sa.threshold_unreachable`,
  `sa.threshold_policy_identification_failed`) before anything is sent, and
  records `SaSignerRemovedV2`. The pin record then names the destination,
  and the add compares against the removal's row and records
  `SaSignerAddedV2`, then `SaVerifierMigrated`. A migrated rule needs no
  refresh. A failure after a removal was sent returns the pending add; a
  re-run of `migrate-verifier` does not find a removed signer.
- A migration step returns the drift check's policy findings,
  `sa.pin_check_unavailable`, `sa.auth_entry_construction_failed` at every
  stage and an unresolved submission (`submission.*`, with its transaction
  and envelope hashes) as themselves. Every other failure of a step is
  `sa.verifier_migration_failed` at phase `submit_simulate` or
  `submit_send`. A pair whose plan does not match the rule refuses at phase
  `plan_build` before anything is sent.
- `signers add`, `rules add-policy` and `rules create` check the simulated
  return value before signing: a value that is not the id they read refuses
  with `sa.deployment_failed` (phase `simulate`), and nothing is signed or
  sent. The add step of `migrate-verifier` runs the same check and reports
  it as `sa.verifier_migration_failed` at phase `submit_simulate`.
- `signers add` and `signers batch-add` on a pinned rule add no pin for a
  new verifier whose pin equals a recorded one, in hash and executable
  reference; the record keeps one pin per distinct pin.
- `signers refresh` on a pinned rule with no `External` signer drops the
  record's one verifier pin and writes a `SaContextRulePinsUpdated` row
  (reason `baseline_refreshed`) without it, the policy pins unchanged.
- A confirmed `signers add` or `signers batch-add` on a pinned rule writes
  its pin rows before it refuses when its resulting state is not observed or
  not the intended change. When the audit log refuses the state row, the pin
  rows are attempted and are usually refused too.
- `AuditReader::find_latest_signer_set_view` replaces
  `find_latest_signer_set_state`. It takes the account digest beside the
  redacted account and returns the newest state row of either version as a
  versioned `SignerSetView`, with the file and line of the row. A version-2
  row with a malformed snapshot is an audit parse error. The signer-set
  checks compare a rule's newest state row in that row's version.
- `stellar_agent_sep43::signing::sign_soroban_auth_entry` takes the expected
  signer's public key after the signer. The key must be the signer's own; the
  function checks a type 10 preimage's address against it.
- Every submission signed under a rule other than rule 0 runs four checks
  for each such rule before anything is simulated or signed, under one
  pre-submit deadline: the rule's lock, its signer-set baseline read with no
  RPC, the pinned-hash drift check, and the comparison of the rule's signer
  set through both endpoints with the baseline. A version-1 baseline is
  compared through its version-1 projection. This covers `execute`,
  `multicall`, `rules create`, `set-name`, `set-valid-until`,
  `delete`, `add-policy`, `remove-policy`, `set-spending-limit`,
  `set-weighted-threshold`, `set-signer-weight`, the signer verbs and the
  passkey signing path.
- When the checks find several faults, the refusal follows their order:
  `sa.auth_entry_construction_failed` at stage `rule_lock`, then
  `sa.audit_log` or `sa.signer_set_missing_baseline`, then the pin
  refusals, then `sa.signer_set_diverged` or `network.rpc_divergence`. An
  audit-log integrity error under a rule other than rule 0 is reported as
  `sa.audit_log` by the baseline read, under the migrating rule of
  `migrate-verifier` too.
- `sa.auth_entry_construction_failed` has five signer-set check stages:

  - `rule_lock`: the rule's lock was not acquired within the pre-submit deadline
    or the locking verb's timeout.
  - `baseline_read`: the pre-submit deadline elapsed during or immediately after
    a baseline read.
  - `signer_set_compare`: the pre-submit deadline elapsed during comparison.
  - `rule_lock_missing`: the caller's held-lock context lacks an authorizing rule.
  - `rule_locks_without_pin_check`: a held-lock context has no pin check.

  The last two stages are submit API invariant violations a correct build
  never emits; CLI and MCP inputs cannot reach them.
  Signer mutations and migration pairs hold their caller-held locks through
  confirmation.
  A concurrent verb waits for a held lock until its budget ends.
  A submission that acquires its own locks releases them before sending.
- `set-spending-limit`, `set-weighted-threshold` and `set-signer-weight`
  lock their `--auth-rule-id` rules beside the target rule, and the
  submission compares those rules with their baselines.
- The passkey signing path runs its checks in the same order under one
  deadline, the signers manager's timeout: the rule locks, the baseline
  reads, the pinned-hash drift check and the signer-set comparison. Every
  refusal of the locks, the baseline reads, and the comparisons is
  `CredentialsError::SignerSetDivergence`, a deadline elapse included.
- `signers list`, `signers refresh` and the other signer verbs wait for the
  rule's lock at most the manager's timeout (`--timeout-seconds`), then
  refuse with `sa.auth_entry_construction_failed` at stage `rule_lock`.
- `PinCheck::migrating_rule` is `Option<MigratingRule>`. Only the migration
  step constructs a `MigratingRule`; its rule is exempt from the verifier
  check, and the migration compares it under the lock it holds.
- `rules list`, `list-rules`, `stellar_rules_list` and `stellar_rules_get`
  report each rule's signer-set baseline in the audit log as `baseline`:
  `none`, `v1`, `v2`, `unreadable` or `unknown`. `ContextRuleSummary`
  carries it as `BaselineState`. The two MCP tools read the profile's audit
  log and report `unknown` for every rule when they cannot open it.
- `multicall` reports a refusal of its rule's signer-set checks at phase
  `policy_gate`: `sa.signer_set_missing_baseline`,
  `sa.signer_set_baseline_legacy`, `sa.signer_set_diverged`,
  `sa.audit_log`, `network.rpc_divergence`, the threshold identification
  and read refusals, and `sa.auth_entry_construction_failed` at the lock
  and signer-set stages.
- On a mainnet profile, the DeFi, sign-and-submit, commit, and rule-commit
  MCP tools answer a `network.mainnet_write_forbidden` business envelope at
  entry, before the policy gate and any RPC request. The toolset route
  refuses its signing actions the same way and queues no approval.
- CLI `vault deposit`, `vault withdraw`, `trade`, `trustline`, `pool init`,
  and `smart-account rules verify-pins` report
  `network.mainnet_write_forbidden` on a mainnet profile, before signer access
  and any request.
- A submit-layer mainnet refusal inside the smart-account crate reports
  `network.mainnet_write_forbidden`. `MigrationPlan::submit` and
  `submit_multicall_bundle` return it unwrapped, and the DeFi adapters
  return `DefiAdapterError::MainnetWriteForbidden`.
- `submit_signed_invoke`, `timelock::schedule_upgrade`, `timelock::cancel`,
  and `timelock::execute` refuse a mainnet passphrase or a mainnet-pattern
  primary RPC URL before any signing call and any request.
- `stellar_agent_x402::exact::create_payment` and
  `submit_fee_bump_idempotent` refuse mainnet inputs before any signing call
  and any request. `submit_fee_bump_idempotent` serves no cached receipt on
  mainnet.
- `cargo binstall` of the wallet crates fails on a host for which no release
  archive exists, including any target outside the five release targets. Use
  `cargo install --locked` there.
- A CI check covers the documented install commands, the secret-seed
  procedures, and the binstall metadata on every pull request and every push
  to `main`, including changes that touch only Markdown.
- The release workflow signs and notarizes the macOS binaries in a separate
  `sign-macos` job, which runs in the `release-signing` environment. The
  build job holds no Apple secret.
- The notarization smoke workflow builds in one job and signs in another,
  which runs in the `release-signing` environment.
- The publish workflow runs a `verify` job, which builds every crate without
  credentials, and a `publish` job, which uploads without building. Both jobs
  install the exact toolchain that `RELEASE_TOOLCHAIN` in `publish.yml` names.
- The publish workflow takes a `verify_only` input that runs only the
  `verify` job.
- `keyed_audit_access` takes the selected profile name and a `BindingCheck`,
  and checks the audit binding before the audit key loads. The MPP store
  openers `open_for_prepare`, `open_for_read`, and `reset_for_profile` take a
  `BindingCheck`. MCP `build_server` and `transport::run` take the check the
  profile's origin implies.
- `load_default_or_testnet_fallback` returns the profile with its
  `ProfileOrigin`: a `default.toml` that exists is persisted, and only the
  synthesized fallback is synthesized.
- The CLI audit helpers `open_audit_writer_read_only`,
  `acquire_best_effort_audit_writer`, `acquire_value_audit_writer`, and
  `reconcile_open_reservations` take the profile's origin, and
  `emit_value_audit_row_strict` takes its binding check.
- `load_attestation_key` and `DecisionContext::new` take the owner context,
  an `OwnerKeyContext`. `NonceMint::from_profile` takes the profile name.
- `AuditWriter::reanchor` is `reanchor_acknowledging` with one rollback
  acknowledgement; `reanchor_acknowledging` takes the acknowledged conditions
  and the previous binding's anchor, and bumps the re-anchor counter once.
- `audit reanchor --acknowledge-binding-change` accepts a changed or
  unreadable audit binding. With an absent or agreeing anchor it needs that
  flag alone and appends `binding_changed`; with a disagreeing or unusable
  anchor it needs both flags and appends `rollback_acknowledged`, then
  `binding_changed`. On an equal or absent binding it requires
  `--acknowledge-rollback`, appends `rollback_acknowledged`, and records an
  absent binding. The envelope gains `acknowledged`,
  `recorded_binding`, and `previous_binding_anchor`.
- The read-only smart-account verbs (`rules get-spending-limit`,
  `list-rules`, `timelock list-pending`, and the `migrate-verifier` dry run)
  refuse a changed audit binding with `audit.log_binding_changed` and create
  nothing at the path the profile names. `audit verify --profile` and
  `profile rotate-audit-key` refuse it the same way.
- On the synthesized zero-config profile, `pay`, `claim`, `accounts create`,
  and `tx receipt clear` refuse a recorded audit binding that differs with
  `audit.log_binding_changed` before they sign or clear anything, and record no
  binding. The window reconciliation these verbs run records none either.
- `profile enroll-owner-key` stores the owner public key as its G-strkey.
  Every owner reader accepts the G-strkey and the older base64 form. The first
  V1 engine build in a process, and `enroll-owner-key`, rewrite the older-form
  owner entry of every profile in the profile directory, best effort.
- Symmetric-key loaders refuse a coordinate in the owner key namespace before
  any keyring read, and a loaded key equal to the profile's owner public key.
  The MCP approval gate keeps answering `policy.approval_required` and logs
  the new code. `profile rotate-attestation-key`, `rotate-audit-key`,
  `rotate-nonce-key`, `rotate-counterparty-key`, `rotate-policy-state-key`,
  and `counterparty rotate-hmac-key` refuse such a coordinate with
  `validation.key_matches_owner_public_key` and write nothing, so no rotation
  overwrites an owner entry.
- The nonce key loader requires exactly 32 decoded bytes; a longer value is
  refused, never truncated.
- An older binary cannot replay or verify a log holding a `binding_changed`
  row, and cannot read an owner entry stored as a G-strkey.
- `deploy_smart_account` returns `SaError::DeploymentFailed` with phase
  `build` when `MULTISIG_ACCOUNT_WASM` does not hash to
  `MULTISIG_ACCOUNT_WASM_SHA256`, in every build profile.
- The vendored Wasm records name the exact rustc and stellar-cli versions,
  how each stellar-cli binary is built, and the command that rebuilds the
  file. The multicall record states that its source is not in the
  repository.
- The coverage gate runs in its own Coverage workflow: weekly on main, on a
  pull request that carries the `coverage` label, and on demand.
- `stellar_agent_x402::exact::create_payment` takes a fifth argument,
  `before_transmit`. It is called with an `AuthorizationToTransmit`
  immediately before the signed re-simulation, and an error from it returns at
  once with nothing sent.
- `stellar_x402_create_payment` and `stellar_x402_authenticated_payment` write
  `x402_payment_authorized` in that gate. When the row cannot be written they
  answer the `audit.*` code of the refusal and return no signature.
- The `mpp_authorization_withheld` row of a failed sponsored commit records
  `failure_stage` `pre_signing` with `key_access_began` `false`, `signing`, or
  `resimulation`, naming the side of the signed re-simulation send.
  `sign_or_resimulation` is not written. A withheld row that cannot be written
  is logged at `error` with its code, and the primary error is returned.
- `approve --id` writes `approval_attested` before it persists the approval.
  Beside a running MCP server or `approve serve` that drains the outbox it
  queues the row there. Beside a writer that does not drain it refuses with
  `audit.writer_locked`.
- `approve --id` refuses, persists nothing, and exits 1 on any other audit
  failure, including a missing audit key, a rolled-back log, and
  `audit.outbox_busy`. Its envelope carries `audit`: `"written"` or `"queued"`.
- The approval inbox and the remote inbox write each decision's row before
  persisting the decision. When the row cannot be written, or the writer mutex
  is poisoned, they answer `unavailable` and leave the entry pending. A
  poisoned mutex refuses every later decision until the inbox restarts.
- `attest_and_persist` takes a required `ConsentAudit` sink in place of
  `Option<&mut AuditWriter>`. It re-reads the entry under the store lock and
  writes the consent row before persisting; a refused row persists nothing.
- `WriterError` gains `OutboxBusy` and `OutboxUnusable`. The enum is not
  `#[non_exhaustive]`, so an exhaustive match on it needs the two arms.
- A writer opened with a tip-anchor store, through `AuditWriter::open` with
  access or `AuditWriter::open_with_tip_anchor`, holds `<log>.drain.lock` and
  drains the outbox at open, in `AuditWriter::verify_tip_anchor`, and before
  each of its own rows. The open and `verify_tip_anchor` return the drain's
  errors, and every registry cache hit runs `verify_tip_anchor`. When either
  adopts the log, the adoption row is appended even if the drain refuses.
- `stellar_mpp_charge_commit`, `mpp charge authorize`,
  `stellar_rule_create_commit`, and CLI `trustline` acquire the audit writer
  after reading their approval and before loading the signing key. The
  acquisition drains the outbox, and a failure refuses with its `audit.*` code.
- `audit reanchor` drains the outbox after its repair rows, with either
  acknowledgement, and reports `outbox_drained`. A drain refusal leaves the
  repair in force, omits `outbox_drained`, and is listed under `warnings`.
- A binary that predates `x402_authorization_withheld` refuses to replay or
  verify a log that holds one.
- After upgrading, restart a running MCP server and `approve serve`.
  `approve --id` refuses beside an older one, which does not drain the outbox.

### Removed

- `trustline --chain-id`; the chain comes from the profile.
- Transaction commands' clap defaults for `--network` and `--rpc-url`.
- The `rules verify-pins` endpoint fallback by network; endpoints come from the profile.
- `MigrationSubmitResult::new_for_test_with_failed_remove_tx_hash`; use
  `MigrationSubmitResult::new_for_test` under `test-helpers`.

- `MAINNET_RPC_URL`, `Profile::validate_rpc_url`, `RpcUrlParseError`, and `ProfileLoadError::InvalidRpcUrl`; use `Profile::validate_endpoint_urls`, `EndpointUrlError`, and `ProfileLoadError::InvalidEndpointUrl`.
- `SignersManager::identify_threshold_policy`; the signer-set observation
  identifies the simple-threshold policy through both endpoints.
- The install-time pin-check skip of a rule manager without a signers
  manager: install and its simulation refuse instead.
- The rule verbs' own signer-set check before submission, with its separate
  budget; the submission's checks cover their authorizing rules.

### Fixed

- `approve --id`, `mpp charge authorize --approval-id`, and `approve operator enroll --credential-id` accept a value that starts with `-` in the space-separated form.
- The friendbot funding debug log records the URL authority only.
- The baseline emitter gate rejects macro variant arguments, constructions
  after test modules, and constructions with a brace on a later line.
- The cross-RPC consumer audit scans production code after individual
  `#[cfg(test)]` items.
- A policy removal confirmed beside a concurrent signer add on the same rule
  keeps the add's verifier pin. The removal reads the pin record and writes
  its row under the rule's lock, so it plans from the record the add left.
- The `stellar_sep43_sign_auth_entry` MCP tool, its server instructions and
  the skill references described the `auth_entry_xdr` argument as a full
  `SorobanAuthorizationEntry`. They describe it as the base64 `HashIdPreimage`
  of the entry, which is what the tool signs, and the result as the raw
  signature the requester assembles into the entry.
- The README and the getting-started guide described the macOS release
  binaries as ad-hoc signed and gave a quarantine override. They describe the
  Developer ID signature and the notarization, and how to check both with
  `codesign` and `spctl`.
- The `profile enroll-owner-key` reference said the operator keeps the owner
  seed offline. It says that `enroll-owner-key` and `sign-policy` read the
  owner seed from the environment of the shell that runs them, and that the
  MCP server holds only the enrolled owner public key.
- The smart-account verbs registered no keyring store before opening their
  audit writer. A persisted profile's signing verbs refused with
  `audit.chain_key_unavailable` even with a minted audit key, and the read-only
  verbs opened an unkeyed writer. These verbs register the platform keyring
  store, or the headless store `STELLAR_AGENT_KEYRING_BACKEND` names, when none
  is registered. The read-only verbs read the keyring and record an absent
  audit binding for a persisted profile.
- A file in the audit directory whose name put a multi-byte character across
  the ninth byte of a rotated-sibling suffix panicked the writer's open, its
  rotation, and `audit verify`. Such a name is not a rotated sibling.
- In `0.1.0-alpha.1` through `0.1.0-alpha.9`, approving a trustline clawback
  opt-in made the profile's approval store unloadable. The approval stored its
  attestation on the opt-in entry, and the store refused that field for the
  opt-in kind when it reopened. Every later approval read on the profile then
  failed, the trustline gate included, until the entry was removed by hand.
  An attested opt-in reloads with its attestation, and the trustline gate
  verifies it.

### Security

- In `0.1.0-alpha.1` through `0.1.0-alpha.9`, the DeFindex vault deposit and
  withdraw commands and MCP tools could sign Soroban authorization entries on
  a mainnet profile. This required the V1 policy engine and an operator-signed
  rule allowing the operation. The wallet sent the signed entries to the RPC
  endpoint in a simulation request before its mainnet refusal, so the
  endpoint operator could submit them on mainnet. A profile on the Noop engine
  refused them with `policy.engine_required` before signing. Library callers
  of the public `submit_signed_invoke` that passed mainnet inputs sent signed
  entries the same way. So did callers of the public functions built on it:
  `DefindexVaultAdapter::submit`, the smart-account manager writes,
  `MigrationPlan::submit`, and `submit_multicall_bundle`.
  `submit_multicall_bundle` did so with a multicall router registered for
  mainnet and a caller-supplied policy engine allowing the bundle. Callers of
  the timelock functions and `create_payment` sent them as well, and
  `create_payment` also returned a signed mainnet payment. These commands,
  tools, and functions refuse mainnet with `network.mainnet_write_forbidden`
  before any signing call. All but the functions built on
  `submit_signed_invoke`, which may read state first, also refuse before any
  request.
- The documented `cargo install` of the wallet crates resolved current
  dependency versions and ignored the `Cargo.lock`. This affects
  `0.1.0-alpha.1`, `0.1.0-alpha.3`, and `0.1.0-alpha.4`, whose docs name
  `cargo install --git` of this repository, and `0.1.0-alpha.5` through
  `0.1.0-alpha.9`, whose docs pin the crates.io versions. For `--git`, cargo
  asks for a package name, and the command that names one ignores the
  repository's `Cargo.lock`. The docs of `0.1.0-alpha.2` give bare crate names,
  which match no prerelease, so cargo installs nothing while crates.io holds
  only prereleases. This required a malicious release within a dependency's
  version range to be live on crates.io at install time. For example, `arrayref`
  0.3.10 was published on 2026-08-20 with a malicious dependency whose build
  script ran on install, and was removed about 86 minutes later
  (RUSTSEC-2026-0260). The documented commands pass `--locked`. For any version
  up to `0.1.0-alpha.9`, use `cargo install --locked`, whatever its docs or its
  crates.io page say.
- In `0.1.0-alpha.1` through `0.1.0-alpha.9`, the documented procedures had the
  reader type secret seeds into `export` lines. This required an interactive
  shell that saves its history to a file, the default for bash and for zsh on
  macOS. The procedures read each seed without echo, export it only for the
  commands that need it, and unset it afterwards. If you typed a seed into a
  command line, follow "Remove a seed from shell history" in the getting-started
  guide.
- `cargo binstall` could fall back to a third-party binary host or to an
  unlocked source build. This affects `0.1.0-alpha.3` and `0.1.0-alpha.4`, whose
  docs name `cargo binstall --git` of this repository, and `0.1.0-alpha.5`
  through `0.1.0-alpha.9`, whose docs pin the crates.io versions. In
  `0.1.0-alpha.1` and `0.1.0-alpha.2`, the docs give bare crate names, which
  match no prerelease, so binstall stops at version resolution while crates.io
  holds only prereleases. This required that binstall could not download a
  release archive for the host's target, including on a target outside the five
  release targets and for a version without published archives. Both wallet
  crates set `disabled-strategies = ["quick-install", "compile"]`, which applies
  from the next published version and needs cargo-binstall 1.8.0 or later. For
  any version up to `0.1.0-alpha.9`, pass
  `--locked --disable-strategies quick-install,compile`, which needs
  cargo-binstall 0.17.0 or later.
- In `0.1.0-alpha.6` through `0.1.0-alpha.9`, the macOS release builds ran
  dependency build scripts in the job that held the Developer ID certificate
  and the notarization key. This required a dependency release with a
  malicious build script that a release then built. Signing and notarization
  run in a separate job that compiles nothing and validates the unsigned
  binaries it receives.
- In `0.1.0-alpha.5` through `0.1.0-alpha.9`, the crates.io publish job ran
  the verify build of every crate while it could mint a registry token. This
  required a dependency release with a malicious build script. A job without
  credentials runs the verify builds, and the upload job compiles nothing.
- In `0.1.0-alpha.5` through `0.1.0-alpha.9`, the publish workflow
  interpolated the tag input into a shell step of the job that could mint a
  registry token. In `0.1.0-alpha.1` through `0.1.0-alpha.9`, the release
  workflow interpolated the tag-derived version into a shell step. This
  required a user who can dispatch workflows or push a tag. Both workflows
  validate these values and read them through the environment.
- In `0.1.0-alpha.5` through `0.1.0-alpha.9`, the publish script counted a
  crate as published when crates.io reported its version as already
  uploaded, without comparing bytes. This required a version of the same name
  uploaded from other bytes, for example by an earlier run from another
  commit. The script compares the published checksum with the checksum the
  verify job recorded.
- In `0.1.0-alpha.1` through `0.1.0-alpha.9`, the release workflow accepted a
  tag on any commit. In `0.1.0-alpha.5` through `0.1.0-alpha.9`, the publish
  workflow could check out a branch named like the tag. This required a
  repository writer. Both workflows check that the tag's commit is on `main`,
  and the publish workflow checks out the tag by its full ref. The release
  checks bind tags whose commit carries them, and the publish checks bind
  dispatches from `main`. The tag ruleset, the environment settings, and the
  trusted-publisher setting in the maintainer documentation bind the rest.
- In `0.1.0-alpha.1` through `0.1.0-alpha.9`, an environment or programmatic
  overlay could set any profile field, trust roots included. Anyone who could
  set the wallet process's environment could repoint `audit_log_path`, any
  keyring coordinate, the policy engine, the `[wallet]` posture, or the
  remote-approval settings without editing the profile file. Overlays accept
  only the operational fields of the three overlay classes, and refuse every
  other key with `profile.non_overlayable_field`.
- In `0.1.0-alpha.7` through `0.1.0-alpha.9`, a profile whose
  `audit_log_path` or audit key changed started a fresh tip anchor at the new
  coordinate and adopted whatever file it found there. This required write
  access to the profile file or to the wallet process's environment. A file
  copied or rolled back before that first use became the baseline, and an
  empty file left no row. The keyring records each persisted profile's audit
  binding, and every keyed audit writer refuses a changed binding with
  `audit.log_binding_changed` until the operator runs `audit reanchor
  --acknowledge-binding-change`, which records the change in the log. Signing
  verbs and tools refuse before signing; a command whose audit row is best
  effort skips the row.
- In `0.1.0-alpha.1` through `0.1.0-alpha.9`, a symmetric-key loader accepted
  the profile's owner public key as its key, because the owner entry held the
  key's 32 bytes in the encoding the loaders read. A coordinate overlay could
  point the attestation key at the owner entry on every release. Under
  `headless-dpapi` (`0.1.0-alpha.4` onward), anyone who could write the
  headless keyring file could copy an owner entry to another coordinate, where
  it opened. A party who knew the owner public key could then compute approval
  attestations. Loaders refuse an owner-namespace coordinate and a key equal to
  the owner public key, and the rotate verbs refuse to write at an
  owner-namespace coordinate. Owner keys are stored as G-strkeys.
  Under `headless-dpapi` an older-form owner entry stays relocatable until it
  is rewritten: run one V1 verb, or `enroll-owner-key`, after upgrading, which
  rewrites every profile's entry.
- With a headless keyring backend, the audit anchor, the re-anchor counter,
  the audit binding, and the policy window state live in a file on the same
  host. Anyone who can write that file can restore older entries or delete
  one.
- In `0.1.0-alpha.1` through `0.1.0-alpha.9`, the vendored contract Wasm
  files that the wallet deploys or recognizes were pinned only by digests
  inside this repository. Several of their build records, and the
  smart-account crate's documentation, described a CI check of those digests
  that did not exist. A merged pull request could replace a Wasm file
  together with its pins and pass every check. The vendored files are
  unchanged since they were added, and every file except the multicall
  router rebuilds byte for byte from its source. The `vendored-wasm`
  workflow rebuilds every vendored Wasm file except the multicall router
  from its pinned source with pinned tools. It fails unless the rebuilt
  bytes equal the vendored file and the file matches its record and, where
  one exists, its `build.rs` pin. Unit tests bind every embedded Wasm
  constant and every pinned digest to its vendored file. The multicall
  router Wasm is not rebuilt, since its source is not in the repository;
  its digest remains pinned only inside the repository. In those versions,
  release builds of `deploy_smart_account` uploaded the embedded
  smart-account Wasm without comparing it with
  `MULTISIG_ACCOUNT_WASM_SHA256`. This needed a build from a tree whose own
  unit tests fail. Such a build could upload the differing bytes; the deploy
  then failed, or created the account from the Wasm that the constant names.
  The deploy checks the digest in every build profile, before any network
  request.
- In `0.1.0-alpha.1` through `0.1.0-alpha.9`, the x402 payment tools sent
  the signed payment authorization to the profile's RPC endpoint, in the
  re-simulation request, before any audit row recorded it. This needed only a
  testnet profile whose policy allowed the payment. `0.1.0-alpha.1` and
  `0.1.0-alpha.2` wrote no row for an x402 authorization. Later releases wrote
  `x402_payment_authorized` after the re-simulation, logged a failure to write
  it, and returned the signature anyway. A failed re-simulation, or a failure
  after it, left no row for an authorization the endpoint had already
  received. The x402 tools write `x402_payment_authorized` before the signed
  authorization leaves the wallet, and withhold it when that row cannot be
  written.
- In `0.1.0-alpha.1` through `0.1.0-alpha.9`, an approval took effect before
  its audit row was written. `approve --id` persisted the attestation or the
  grant, then wrote `approval_attested` best-effort. With the audit writer
  unavailable it wrote no row and exited 0, which was the ordinary case beside
  a running MCP server or `approve serve`. The approval inbox persisted
  approvals and rejections before their rows, and skipped the row without a
  log line when its writer mutex was poisoned. An approval or a rejection
  takes effect only after its row is durable, in the log or in the log's
  outbox. A queued row reaches the log before the process that consumes the
  approval loads a signing key.

## [0.1.0-alpha.9] - 2026-09-30

### Added

- The contract Wasm-hash fetch resolves Protocol 28 external-reference
  executables (CAP-85). It reads the owner's executable-tag entry from the
  endpoint that returned the instance and reports the owner, the tag and the
  resolved hash, or no hash when there is no live tag entry. Both endpoints
  must agree on the resolved hash. An instance or tag entry with an unexpected
  shape is reported as malformed, not as an absent contract.
- Smart-account audit rows, errors and envelopes carry external-reference
  details. `SaContextRuleCreated` gains `pinned_verifier_executable_refs` and
  `pinned_policy_executable_refs`, aligned with the first-8 hash lists;
  `SaMutableContractOverride` gains `executable_owner_redacted` and
  `executable_tag`; `SaVerifierHashDrift`, `SaPolicyHashDrift`,
  `sa.verifier_hash_drift` and `sa.policy_hash_drift` gain
  `observed_executable`; `sa.verifier_mutable` and `sa.policy_mutable` gain
  `detail`; the `smart-account rules create` and `stellar_rule_create`
  envelopes gain `pinned_verifier_executable_refs` and
  `pinned_policy_executable_refs`. Every new field is optional, and rows
  without it keep reading. A pin record whose reference lists are misaligned
  with its hash lists or disagree with them is refused as an audit parse
  error. Passkey signing reports that refusal, and any other audit-log
  integrity failure while reading the pin record, as
  `failure:drift_check_unavailable` with the integrity error as its source.
- `sa.contract_instance_unsupported` has the reasons
  `external reference with no live tag entry` and
  `executable changed during install`.
- The `SaContextRulePinsUpdated` audit row records a pinned rule's whole pin
  record after a wallet mutation changed its verifiers or policies: both first-8 hash
  lists, their aligned executable-reference lists, the override flags and a
  `reason` (`verifier_migrated`, `signer_added`, `policy_added` or
  `policy_removed`); the entry's request id
  joins it to the mutation's other rows. A rule's pin record is the newest
  `SaContextRuleCreated` or `SaContextRulePinsUpdated` row for it; logs
  without the new row keep reading.

### Changed

- Every smart-account operation authorized by a context rule other than `0`
  checks that rule against its pin record before anything is simulated or
  signed: `smart-account execute`, `smart-account multicall`, the
  `smart-account rules` and `smart-account signers` write verbs,
  `smart-account migrate-verifier` (the migrating rule's policies only) and
  the `stellar_rule_create_commit` MCP tool. A live verifier or policy that
  differs from its pin refuses with `sa.verifier_hash_drift` /
  `sa.policy_hash_drift` and writes the drift audit row with the operation's
  request id. A check that cannot run (RPC failure, audit-log integrity
  error, a record with more than one verifier or policy pin, an unreadable
  instance) refuses with the new `sa.pin_check_unavailable`, whose reason
  leads with the inner wire code. A rule without a pin record is not
  checked; rule `0` never is. `multicall` reports these refusals as
  `sa.multicall_failed` at phase `policy_gate`. In the library,
  `SubmitInvokeArgs` takes `pin_check` and refuses a non-zero rule without
  one (stage `pin_check_required`); `MulticallSubmitArgs` takes
  `signers_manager`; a `ContextRuleManager` without a signers manager
  refuses a non-zero authorizing rule with
  `sa.signers_manager_not_configured`; a `multicall_check` without
  `"multicall"` in `required_checks` is refused with stage
  `multicall_check_undeclared` in every build.
- `smart-account migrate-verifier` and `smart-account signers add` /
  `signers batch-add` keep a pinned rule's pin record in step. After each
  confirmed migration pair, a `SaContextRulePinsUpdated` row names the
  destination verifier's hash as the rule's verifier pin. An External signer
  added on a verifier the rule does not use yet is identified and probed
  first, under the allowlist and mutability rules of `rules create` and its
  new `--accept-mutable-verifier` / `--accept-unknown-verifier` flags on
  `signers add` and `signers batch-add`; after the add confirms, the row
  records one verifier pin per distinct verifier address. A second distinct
  verifier yields a two-pin record, which every checked signing verb refuses
  with `sa.pin_check_unavailable` (`sa.multiple_pinned_hashes_unsupported`),
  as for a rule installed with two verifiers. A rule without a pin record
  stays unpinned. `SignersManager::add_signer` and `batch_add_signers` take
  the two override flags.
- `smart-account rules add-policy` and `rules remove-policy` keep a pinned
  rule's policy pins in step. A policy the rule does not hold yet is probed
  first, under the policy allowlist and the mutability rules of
  `rules create`, with the new `--accept-mutable-verifier` /
  `--accept-unknown-verifier` flags on `rules add-policy`; after the add
  confirms, a `SaContextRulePinsUpdated` row (reason `policy_added`) appends
  its pin. After a removal confirms, the row (reason `policy_removed`) drops
  the pin equal to the removed policy's hash, or the single pin of a rule's
  only policy even when the policy differs from its pin or cannot be read.
  A second policy pin yields a record every checked signing verb refuses, as
  for a rule installed with two policies. `ContextRuleManager::add_policy` takes the two override flags.
- A rule whose pin record holds policy pins while the rule has no policy on
  chain is refused before signing with the new `sa.pinned_policy_absent`,
  and `smart-account rules verify-pins` reports its policy status as
  `drift`. `rules add-policy` on a pinned rule with no policy on chain
  replaces the policy pins with the added policy's pin, so an add authorized
  under rule `0` repairs the rule.
- The policy pin allowlist accepts every policy Wasm the wallet vendors: the
  simple-threshold, weighted-threshold and spending-limit policies. It
  applies to `rules create` and `rules add-policy`.
- Protocol 28 crate versions: `stellar-xdr` 28.0.0, `stellar-baselib` 0.6.0,
  `stellar-rpc-client` 28.0.0, `soroban-spec-tools` 28.0.0 and
  `stellar-ledger` 28.0.0.
- SEP-48 argument previews and SEP-47 discovery read the code a contract
  currently runs. An external-reference contract resolves through its owner's
  executable-tag entry; one with no live tag entry is refused with a message
  naming the owner and the tag. The parsed spec is cached per Wasm hash: every
  call resolves the contract's current Wasm hash first, so a contract whose
  code changes returns the spec of its new code, and contracts running the
  same code share one cached spec and one code fetch.
  Only the code entry returned under the requested hash is read, and code
  whose bytes do not hash to it is refused and not cached.
- Transaction status reads do not decode the result meta. Status, ledger
  and created-at are read as received, so a transaction whose meta the
  wallet's XDR cannot decode still confirms. The result is decoded only for
  a failed transaction; a failed result that does not decode is reported as
  `ledger.op_failed` naming the undecodable result. Contract events and the
  envelope are decoded on demand under the wallet's untrusted-decode bounds:
  timelock event confirmation reads contract events independently of the
  meta and fails closed on an event that does not decode, and MPP
  reconciliation refuses an undecodable envelope with
  `mpp.reconciliation_unavailable`.
- The wallet refuses a contract whose executable is an owner-managed external
  reference, even when the owner's tag entry currently holds the expected
  hash, because the owner can repoint it at any time. DeFi pin checks refuse
  with `defi.pin.external_ref`. DeFindex vault, Soroswap router and multicall
  router checks and post-deploy verification refuse with a message naming the
  owner and the tag. Smart-account verifier and policy installation treats
  such a contract as mutable: it refuses with
  `sa.verifier_mutable` / `sa.policy_mutable`, reason
  `owner-managed external reference`, naming the owner and the tag, unless
  `--accept-mutable-verifier` is set, and then pins the owner, the tag and
  the resolved hash; `--accept-unknown-verifier` is also required when the
  resolved hash is outside the allowlist. Signing refuses with
  `sa.verifier_hash_drift` / `sa.policy_hash_drift` when the owner repoints
  the tag, the reference changes or the executable kind changes, and also
  when a contract pinned by its Wasm hash becomes an external reference. An
  external reference with no live tag entry is refused with
  `sa.contract_instance_unsupported` whatever the flags. On-chain policy
  identification for signer, threshold and spending-limit changes resolves an
  external-reference policy to the allowlisted code its tag points at.
  Verifier migration refuses an external-reference destination as mutable,
  and refuses an unresolved or undecodable destination with
  `sa.contract_instance_unsupported`.
- `WasmHashDivergenceError` names its fields `primary_summary` and
  `secondary_summary`; each holds a bounded summary of that endpoint's outcome.
- Verifier and policy installation refuses an undecodable instance entry while
  identifying the contract, before any override flag applies, so no override
  audit row is written for it.
- Errors that describe an unexpected ledger value name its variant through
  `stellar_agent_core::scval::scval_variant_name` and never render the value
  itself: in `stellar-agent-smart-account` for rule-context, signer-weight,
  threshold, migration and timelock reads, and in `stellar-agent-defindex`
  for vault storage and role reads. An unknown context-type tag renders
  escaped and bounded, so a large or hostile payload yields a short reason.
  `scval_variant_name` moves to `stellar_agent_core::scval`;
  `stellar_agent_defi::simulate` does not export it.
- The panic hook logs at most 256 bytes of the panic message, followed by
  the `...[TRUNCATED]` marker when it is cut. Secret strkeys are redacted on
  the full message before the cut, so no fragment of a strkey that straddles
  the limit is logged.
- The contract-instance mutability probe treats a response entry whose key
  does not decode, or that was returned under a key the wallet did not
  request, as an undecodable instance at every requested position, so rule
  installation refuses the contract with `sa.contract_instance_unsupported`.
  The multicall router Wasm-hash fetch reads only the entry returned under
  the requested instance key and refuses a response whose key does not
  decode or that has no entry under that key.
- `smart-account rules verify-pins` names external-reference executables:
  `observed_verifier_executable` and `observed_policy_executable` hold the
  bounded summary of each observed external reference (or `no code`),
  aligned with the observed first-8 lists, and
  `pinned_verifier_executable_refs` and `pinned_policy_executable_refs`
  carry the pinned owner and tag, aligned with the pinned first-8 lists.
  The four fields are omitted when empty.
- The passkey signing diversification gate counts parties, not pins: each
  distinct Wasm hash is one party, and all external-reference verifiers whose
  tags one owner manages are one party together. A high-value rule whose
  pinned verifiers belong to one party requires the `accept_single_verifier`
  opt-in of `sign_with_passkey_rule`.
- `sa.verifier_mutable`, `sa.policy_mutable`,
  `sa.contract_instance_unsupported`, `sa.verifier_wasm_not_in_allowlist`,
  `sa.policy_wasm_not_in_allowlist` and `network.rpc_divergence` carry
  `rule_id` only when the refusal names a rule. A refusal raised while a rule
  is being installed, before it has an on-chain id, and a divergence on a
  query no rule scopes (a timelock query) omit it, and the message omits the
  rule. `detect_contract_mutability` and `pin_referenced_contracts` take the
  rule id as `Option<u32>`.
- `SaMutableContractOverride` and `SaUnknownContractOverride` are written
  after the rule install or the verifier or policy add confirms, carry the
  rule id and the operation's `request_id`, and precede the row that records
  the rule's pins: `SaContextRuleCreated` on install,
  `SaContextRulePinsUpdated` on an add. A refused operation writes no
  override row, and proposing a rule through `stellar_rule_create` writes
  none; the rows are written when the rule is installed.
  `pin_referenced_contracts` writes no audit row and takes no audit writer
  or chain id; `PinResult` gains `pending_overrides`, the overrides the
  install writes once it confirms. The audit-entry constructors take the
  rule id as `Option<u32>`, and rows without it keep reading.
- Every read of a rule's signer set decodes the whole set. A rule holding a
  signer the wallet cannot decode (an unknown signer kind, a malformed
  signer, or a delegated signer with a contract address), a missing or
  non-list `signer_ids` or `signers` field, a `signer_ids` entry that is not
  a `u32`, or `signer_ids` and `signers` lists of different lengths is
  refused with `sa.deployment_failed`, and the reason names the offending
  field or index. This covers `smart-account signers list` and `refresh`,
  the signer-set baseline and divergence checks, the signer verbs, policy
  identification, the pinned-hash drift check, passkey signing and the MCP
  `stellar_rules_get` tool. `smart-account migrate-verifier` refuses the
  whole plan with `sa.verifier_migration_failed` at phase `plan_build`,
  naming the rule; `rules_skipped_count` counts only rule IDs the
  enumeration skipped. Delete such a rule with `smart-account rules delete`,
  authorized by a rule the wallet can read.
  `decode_signer_scval_full` returns `Result<DecodedOnChainSigner,
  SignerDecodeError>`, and `DecodedOnChainSigner::External` gains
  `verifier_address`.
- `stellar_rule_create` accepts a delegated signer as a G-strkey only; a
  C-strkey delegated signer is refused with `invalid_params` naming its
  index. A pending rule proposal whose delegated signer is a C-strkey fails
  validation when the approval store loads it, and approving it refuses.

### Fixed

- The startup advisory and `smart-account list-verifiers` render verifier
  hashes in the 16-character first-8 form of the pin records.

## [0.1.0-alpha.8] - 2026-09-25

### Added

- `profile reset-mpp-state <NAME> --acknowledge --reason <REASON>` recovers MPP
  authorization state by discarding replay history, rotating its HMAC key, and
  resetting the generation. The audit row names the discarded generation.

### Changed

- MPP authorization state uses wire format version 2 with a generation field
  and a `default-generation` counter beside its state key in the keyring.
  Verified version 1 state is adopted once under the store lock with an audit
  row and enters the protected format at generation one. A version 2 file
  without its counter refuses.
  `MppAuthorizationStore::at_path` requires the trusted generation entry;
  profile openers require the profile's audit configuration.

### Fixed

- Verifier and policy installation refuses a contract whose instance entry is
  undecodable or has a non-Wasm executable with
  `sa.contract_instance_unsupported`, naming the reason. The wallet cannot pin
  such a contract's code, so `--accept-mutable-verifier` does not override the
  refusal.
- Policy loading requires approval TTLs from one second through seven days
  and limits approval reasons to 512 characters.
- MPP state writes recheck the trusted generation before advancing it and
  refuse when another writer has moved the counter.
- MPP and spending-window reset commands reject blank reasons before changing
  state, keyring entries or audit logs.
- MPP policy refusals emit a withheld audit row when refusal persistence fails,
  with the budget unconsumed and the persistence failure identified.
- MPP state reads and mutations refuse deleted or stale authorization history
  against the keyring generation, naming rollback in the refusal. A minted key
  at generation zero with no file remains a valid empty store. Rolled-back
  refusals name `profile reset-mpp-state` as the acknowledged recovery.
- Ledger-dated spending-window confirmations count toward caps when the host
  clock trails the chain. Pending reservations retain the 30-second clock check,
  and clock refusals identify the host-clock offset.
- MPP and x402 authorized settlement check the shared spending cap under the
  store lock before releasing a credential. A refused authorization records no
  spend and reports the governing policy denial through CLI and MCP.
- An MPP authorization refused by the spending window ends in the `refused`
  status with its budget recorded as not consumed; an accounting failure keeps
  the authorization indeterminate.
- Value-action pending and outcome audit rows retain the policy gate decision
  and the approval nonce for approved submissions, including delayed settlement.
  An allowed commit records no approval nonce and spends no pending approval.
- Rule approval TTLs and reasons reach pending approvals, MCP responses and
  CLI approval displays, and a commit is refused once the rule's TTL has passed.
  Rules without a TTL use the 24-hour approval default.

## [0.1.0-alpha.7] - 2026-09-19

### Added

- The MCP server warns at startup when a v1 policy names tools explicitly and
  carries no rule for `stellar_transaction_status`, the tool that settles a
  timed-out submission.
- `docs/maintainers/stability-tiers.md`: per-crate support tiers (stable
  core, supported optional, experimental, internal, removed), the mainnet
  posture of each surface, and the intended-but-unimplemented feature groups
  and facades. The four internal crates' descriptions now state that they
  carry no API stability promise.

### Changed

- `stellar-agent-pool`: `InitParams` requires a `SubmissionRecorder` reference
  and an `attempt` memo ID; `submit_pooled` requires a recorder argument before
  its operation closure, and `InitParams` carries the confirmation deadline.
  Each submission records its receipt and audit state before transmission.
  Initialization attempt IDs distinguish retry receipts. `pool init` gains
  `--timeout-seconds`, default 120.

### Removed

- The Blend lending integration: the `stellar-agent-blend` crate, the CLI
  `lend` command, the MCP `stellar_blend_lend` tool, and the two Blend testnet
  acceptance suites. The wallet's lending verb depended on Blend's backstop for
  depositor protection; the August 2026 Comet pool exploit drained that
  backstop and the protocol's pools are winding down, so the integration does
  not ship while the insurance layer is unavailable. DeFindex vault Blend-
  strategy disclosure is unaffected, as are the DeFindex and Soroswap
  integrations. Published `stellar-agent-blend` crate versions remain on
  crates.io; no new versions are published.

### Security

- `rustls` 0.23.41 to 0.23.45 and `rustls-webpki` 0.103.13 to 0.103.15
  (RUSTSEC-2026-0285: TLS 1.3 handshake messages were accepted across
  encryption level boundaries). The remote approval server is the only
  consumer.

### Fixed

- A spending-window reservation is admitted under the store's lock: the write
  that reserves a submission's spend re-applies the governing criterion's
  comparison against the state on disk at that moment, and refuses a
  submission the window can no longer admit under the same
  `policy.deny.per_period_cap_exceeded` or `policy.deny.rate_limit_exceeded`
  code the policy gate reports. Two callers on one profile can no longer each
  pass the gate against the same window state and both spend against it.
  Nothing is sent and no record is left behind for a refused submission.

- `pool init` persists its seed and profile checkpoint before sending sponsored
  channel creation. `pool status` reports pending creation and its transaction
  hash; `pool init --resume` completes confirmed creation without another send,
  or retries a failed creation with the same keys. Pending initialization
  refuses seed replacement through `--force`. A creation whose receipt settles
  as ambiguous is retried only after `tx receipt clear --acknowledge` records
  that it did not apply; `pool status` names that command in `clear_with`.

- An unresolved submission holds its spending-window headroom until it
  settles, whatever its age. Confirmed spend ages from the close time of the
  ledger that applied it.
- Time-bound reconciliation releases a reservation only on an observed ledger
  close time past the bound and a fresh transaction answer, never on the host
  clock.
- `tx receipt clear --acknowledge` recovers an absent receipt from its
  authenticated reservation when the endpoint no longer retains the
  transaction, and `tx status` reports the holds that need that recovery.
- The spending-window store writes wire format version 3 and anchors each
  generation in the keyring together with a SHA-256 digest of the committed
  body. A build that reads only version 2 refuses a store this build has
  written once; on that build `profile reset-window-state` is the only
  recovery, and it discards the accumulated history.

- A value submission that proceeds under an approval carries the audit legs the
  policy sized and reserves its contribution to the spending caps before the
  send, the same as one that proceeds under an allow.

- The submission recorder reports `audit.tip_anchor_mismatch` with the writer's reason and the reanchor recovery command when a pre-send audit append detects rollback.
- Friendbot funding requests have a 20-second deadline covering connection, response headers, and response body.
- The startup verifier advisory scans the selected profile's configured
  `audit_log_path`, including a non-default location.
- Multicall reserves policy-sized bundle spend and writes its value legs before
  submission. Confirmation settles that reservation once, and timeouts retain
  the full transaction hash for reconciliation. Timelock execution writes a
  submission receipt and pending audit row and preserves unresolved-submission
  details.
- Reconciliation checks the transaction again after observing a consumed source
  sequence. A transaction confirmed during those reads keeps its counted spend.
  Reservations with missing receipt files use the same chain and retention
  checks, and confirmed outcomes restore the receipt identity.
- Submission receipts durably hold the approval nonce until a definitive send
  refusal releases it. The commit gate refuses a held approval while its
  consumption is owed; transaction status retries the tombstone and records
  completion. Receipt replacement also syncs the directory on Unix.
- A multicall bundle of two or more inner calls is submitted. The submit path
  required one authorization rule per inner call while multicall passes the one
  rule the verb takes, so every bundle past a single call was refused as it was
  built. The rule count is now checked against the simulated invocation tree,
  which is what the authorization entries are expanded across.

- A submission that lands but is not confirmed within the poll deadline is now
  recorded. It was recorded nowhere: every post-submit record sat in the
  success arm, so a timeout left no audit row, no spend against the operator's
  caps, a burned commit nonce, and a live attested approval entry for a
  transaction whose bytes had already been sent. The agent's only signal was a
  redacted error, and re-simulating was the only thing it could do, at a
  sequence the sent transaction might already be consuming.

  Before `sendTransaction`, the submit layer now records the signed transaction
  as submitted with an unknown outcome: a submission receipt keyed on the
  envelope hash, a reservation in the spending-window file, and a
  `value_action_pending` audit row carrying the value legs the policy gate
  sized. The receipt and the reservation fail closed; the audit row fails closed
  on a persisted profile. The record is settled by what the network answers: a
  confirmed transaction records its spend and its `value_action_submitted` row,
  a refused or on-chain-failed one releases the reservation and records
  `value_action_failed`, and a timeout or a transport failure after the send
  leaves everything standing. Nothing clears a record on a transport error. The
  transaction hash is computed locally from the envelope before the send and
  used for polling, recording and reporting; an endpoint that answers with a
  different hash is reported as `submission.hash_mismatch` and the record
  stands.

  `submission.tx_timeout` is terminal for the agent: the error now carries an
  `error.details` object with the full transaction hash, the envelope hash,
  `outcome: "unknown"` and the verb or tool that reconciles it, while the
  message stays redacted. Two other codes carry the same object:
  `submission.tx_already_submitted`, which refuses a second submission for a
  source account and sequence a pending record already holds, and
  `submission.hash_mismatch`. New refusal classes `submission.record_unavailable`
  (the record could not be written, so nothing was sent) and
  `policy.approval_consumed` (the approval was already spent on a submission)
  join them.

  Two new surfaces settle a record: `stellar_transaction_status` (MCP) and
  `stellar-agent tx status <HASH>` (CLI) reconcile one submission against the
  chain, and `stellar-agent tx receipt clear <ENVELOPE_HASH> --acknowledge` is
  the operator's way out of the two states reconciliation cannot settle.
  Reconciliation is repeatable: a submission a settled row already accounts for
  is owed no second row. `tx receipt clear` evaluates the record's own state
  first, then asks the endpoint what became of the transaction, and refuses when
  the chain has answered for it or cannot be reached; every precondition is
  checked before anything is released or written, and a re-run appends no second
  clear row. It accepts a record for a submission that was never sent, which is
  what a process killed between the record and the send leaves behind. A
  reservation whose record is gone is released once its sequence is consumed or
  its time bound has passed. Every value verb also settles the oldest open reservations, bounded
  at five per pass, only those older than five minutes, and skipping the ones
  whose receipt already records an unknown outcome so younger reservations are
  reached. A pass that settles a submission writes the value-action row it was
  owed. The MCP tool count moves from 42 to 43.

  The DeFi and smart-account verbs report an unresolved submission in the same
  vocabulary as the classic ones: `stellar_dex_trade`, both vault tools,
  `stellar-agent trade`, `stellar-agent vault`, `smart-account execute` and
  `smart-account multicall` carry the `submission.*` code and the `details`
  object. They reported a generic submit failure with no hash.
  `stellar_sep43_sign_and_submit_transaction` records its submission too: it
  takes no spending-window reservation, because the envelope is the caller's and
  the policy engine sizes no value for it, but it writes a receipt and a pending
  row and its timeout is reconcilable like any other. A confirmed submission
  writes one settled row, the opaque-action row that carries the tool's own
  contract, and the tool reports the `submission.*` codes.

  A submission the wallet cannot fully record is unwound: the receipt is
  removed, a reservation already taken is released, and the retry the refusal
  invites is admitted at the same sequence. `submission.record_unavailable`
  therefore means what it says, and carries no `details`, because nothing was
  sent and there is no transaction to reconcile.

  A spent approval entry is now kept as a `Consumed` tombstone (it was removed).
  The tombstone keeps its attestation and names the transaction it was spent
  on, and the commit gate refuses it with `policy.approval_consumed`. A send the
  network refuses outright leaves the approval untouched, because no value moved
  and the agent is expected to make a fresh attempt.

  The window-state file is written as version 2. Its records now carry the
  identity of the submission that wrote them: the envelope hash, the transaction
  hash, the source account, the sequence number, the time bound, and when the
  reservation was taken. The file is HMAC-tagged and 0600 on Unix, as before; it
  is not encrypted, and it now holds account identifiers and sequence numbers.
  A version 1 file reads as fully confirmed, and alpha.6 reads a version 2 file
  and counts pending records as confirmed spend. A file written by a newer build
  is refused.

  Submission receipts gain a `cleared_by_operator` status. `ReceiptStatus` is a
  serde-tagged non-exhaustive enum, so a reader older than this release treats
  the new tag as an error; no production path read the receipt store before this
  release.

- Submit derives the target network from the RPC endpoint instead of the
  caller's declaration, and verifies which network the envelope's signatures
  were made for. It previously trusted the declared passphrase and checked
  nothing about the signatures it was sending, so `pay --submit-only` and
  `claim --submit-only` would relay an envelope signed for one network onto
  whatever chain `--rpc-url` pointed at, and a consumer of the published crate
  could do the same with no CLI involved.

  Before sending, the layer asks the endpoint which network it serves, on the
  client instance that will send, and treats that answer as authoritative. The
  probe is retried under the caller's own timeout and is fail-closed: it never
  falls back to the declaration. It then fetches the ed25519 signer sets of the
  transaction source and every distinct operation-level source in one
  `getLedgerEntries` call, rebuilds the SEP-23 signing payload under the
  endpoint's network id, and requires every decorated signature to verify
  against it. On a fee-bump the fee source answers for the outer signatures and
  the inner transaction's sources for the inner ones. An operation source that
  the same transaction creates is verified against its own master key, so a
  sponsored-creation sandwich still submits.

  New wire codes: `network.endpoint_network_mismatch`,
  `network.endpoint_identity_unavailable`,
  `network.envelope_signed_for_mainnet`,
  `network.envelope_signature_unverifiable` and `network.envelope_unsigned`. An
  endpoint reporting mainnet still answers `network.mainnet_write_forbidden`,
  and a source account absent from the ledger `network.account_not_found`.

  A declared mainnet passphrase and a known mainnet RPC URL are still refused
  with zero RPC calls; every other submission costs two reads before the send.
  `pay --submit-only` and `claim --submit-only` probe ahead of the policy gate
  and the audit pre-flight. `stellar_pay_commit`, `stellar_claim_commit`,
  `stellar_trustline_commit` and `stellar_create_account_commit` probe before
  the nonce is burned, so a mismatch does not consume it. Handing an unsigned
  envelope to `--submit-only`, the natural mistake after `--build-only`, is
  refused with `network.envelope_unsigned` before anything is sent.

- The audit log's tip anchor is now checked on every keyed acquisition and on
  every append. Two paths skipped it: the MPP commit tools appended through a
  helper that took the cached writer without checking the anchor, so a running
  server kept writing to a log truncated or restored in place; and the check
  read the file through the writer's own handle, so a log replaced by rename
  under a live writer passed as current while later rows went to the unlinked
  file. The registry now reconciles the anchor before handing out a keyed
  writer, and the append verifies that the file at the path is the one the
  writer holds, is no shorter than its last append, and still ends with that
  entry. A refusal is `audit.tip_anchor_mismatch` with the reason named, evicts
  the writer, and anchors the row it owed, so every later open refuses until
  `stellar-agent audit reanchor --acknowledge-rollback`, whose report shows one
  more anchored entry than the log holds. Anchoring the owed row is best-effort,
  like every other anchor write: a keyring that rejects it leaves the refusal
  standing for that writer and its callers, but not past the process. The MPP
  verbs surface these refusals under their own `audit.*` codes, and an
  append-time refusal carries `audit.tip_anchor_mismatch` and its reason. A keyed writer cannot be constructed without
  an anchor store. `docs/maintainers/audit-log-recovery.md` now states that two
  profiles on one log path hold one anchor each and that the configuration is
  unsupported.

- The audit log's chain tip is anchored in the platform keyring, so restoring an
  older copy of the active log file, or truncating it, no longer verifies clean.
  The chain linkage and the per-file `.root_hmac` signature both verify a PREFIX
  and the tip lived only in the writer's memory, so an older copy passed
  `audit verify` and every value-verb pre-flight.

  For each log path the keyring now holds the active file's entry count,
  last-entry hash, and byte offset, advanced on every append. Writer open, the
  value-verb pre-flight on every acquisition, and `audit verify --profile` all
  check the file against it and refuse with the new wire code
  `audit.tip_anchor_mismatch`. A log that moved forward past its anchor is
  absorbed and re-anchored, so writers opened without the audit key keep
  appending as before. Upgrading needs no operator action: an unanchored log is
  adopted once its chain verifies, recording an `audit_tip_anchored` row.

  Recovery is the new `stellar-agent audit reanchor --profile <name>
  --acknowledge-rollback`; without the flag it reports both anchors and exits 1.
  `audit verify` gained an `anchor` field. A rotation leaves the anchor on the
  outgoing file's handoff entry until the new file's first append, so a restore
  of the whole audit directory is refused rather than absorbed. The anchor
  detects rollback, truncation, and substitution of a log at rest, not forgery.
  It is also not continuous in time: it lags between an entry's fsync and its
  anchor write, and it is inactive on a log path nothing has anchored yet and on
  a freshly rotated file until its first append. See
  `docs/maintainers/audit-log-recovery.md`.

- `profile rotate-audit-key` takes the audit writer's exclusive lock for the
  whole rotation. It re-signed every per-file chain-root sidecar without holding
  it, so a concurrent writer could append or rotate between the file walk and the
  rewrite and leave a sidecar signed with the destroyed key.

- Reopening an audit log whose active file was created by a rotation no longer
  refuses. The writer seeded its chain replay from the zero-block hash
  unconditionally, while such a file's first entry chains off the outgoing file's
  handoff entry, so any restart after a rotation reported a broken chain and the
  writer would not open. The replay now seeds from the newest archive's handoff,
  the same cross-file bridge `audit verify` walks.

## [0.1.0-alpha.6] - 2026-08-12

### Security

- `webbrowser` is bumped `1.2.1` to `1.2.4` (RUSTSEC advisory
  GHSA-2ph8-5cr8-hr33: a URL could smuggle extra arguments, such as
  `--remote-debugging-port` or `--proxy-server`, into the browser named by a
  `BROWSER` environment-variable template). The crate's `hardened` feature is
  also enabled: the passkey-registration handoff URL is the only thing this
  workspace ever opens, and it is always http(s), so launches of any other
  scheme are now refused by the dependency itself.

- The approval pages neutralise bidirectional and invisible-format code points
  in every rendered value: U+061C, U+200B-200F, U+202A-202E, U+2066-2069, and
  U+FEFF become U+FFFD before HTML escaping. A memo or asset code carrying
  U+202E reverses the rendering of everything after it, so an operator could
  read a different destination or amount than the one being signed while the
  page stayed well-formed.
- Both approval surfaces branch on the decision response's HTTP status. A
  refused decision (a rejected passkey assertion, a stale CSRF value, an entry
  already resolved) rendered as "Status: unknown" and could be read as
  success. It now renders in its own refusal treatment and states that nothing
  was recorded.

### Added

- `stellar_agent_core::profile::name` gained the profile-name reconciliation
  both binaries apply: `OWNER_KEY_SERVICE_PREFIX` (previously duplicated in each
  binary), `derive_profile_name_from_owner_key`,
  `profile_name_mismatch_refusal`, and the `ProfileNameMismatch` refusal with
  `requested()` / `derived()` / `service()` accessors and a `message()` renderer
  taking a `ProfileStateLayout`. `stellar-agent-mcp`'s `transport` module
  re-exports `ProfileNameMismatch` and `profile_name_mismatch_refusal`, so its
  public surface keeps both names, and adds
  `pub const STARTUP_STATE_LAYOUT: ProfileStateLayout` naming the layout that
  server renders under. `ValidationError::ProfileNameMismatch` carries the
  refusal on the wire as `profile.name_mismatch`. `ProfileStateLayout` is
  `#[non_exhaustive]`, so a third surface's layout stays additive.
- **API note on the re-exported `ProfileNameMismatch`.** Its `Display` is now
  layout-independent: it renders which profile was selected, the offending
  `policy_owner_key_id.service`, and which profile that names. It omits the per-profile-state consequence and the recovery text, because both differ between the two binaries. Callers that relied on `to_string()` for the full
  refusal, including the recovery sentence, call
  `message(ProfileStateLayout::DerivedThroughout)` to get the previous
  `stellar-agent-mcp` wording.
- `stellar-agent-mcp` now selects its profile per invocation. It accepts
  `--profile <NAME>` and `--profile=<NAME>`, and honours `STELLAR_AGENT_PROFILE`
  when the flag is absent, resolving flag > environment > `default`, the order
  the CLI already documented. The selected profile binds at startup and stays
  bound for the life of the process. `--help` documents both inputs. The
  resolved name and which input supplied it are logged at startup.
  Closes #105.
- The MCP server refuses to start when the profile file's
  `policy_owner_key_id.service` names a different profile than the one selected.
  The server derives the name it uses for the signed policy file, the
  pending-approval store, and the policy-window state from that field, so a
  profile file renamed or copied from another profile would otherwise read and
  write another profile's state under the selected name. The check runs for
  every policy engine, including `noop`, and names both profiles, the offending
  field, and the way out.
- The MCP server's refusals for an incomplete V1 startup ceremony now name the
  command that clears them. An absent owner key, an owner key that is not a
  usable ed25519 public key, and a missing or unverifiable signed policy file
  each point at `profile enroll-owner-key` or `profile sign-policy`, rather than
  reporting only the wall that was hit.

### Changed

- An MPP identifier lookup that matches no stored authorization now returns
  `mpp.authorization_not_found` instead of `mpp.state_unavailable`, on both
  binaries. This covers `mpp authorization status`, `mpp receipt record`,
  `mpp settlement reconcile`, `mpp charge authorize --approval-id`, and their
  `stellar_mpp_*` tool counterparts, whether the identifier is simply unknown
  or the profile has no MPP state at all. A malformed identifier stays
  `mpp.state_unavailable` on every store state, so the answer cannot be used to
  probe whether a profile has MPP state. `mpp.state_unavailable` now means the
  durable state, or a prerequisite of it, exists and cannot be used. Agents
  routing on `mpp.state_unavailable` to detect an unknown authorization must
  route on the new code.
- `stellar-agent-mpp` API: `MppAuthorizationStore::from_profile_keyring` is
  removed in favour of `open_for_prepare` (its minting form) and
  `open_for_read`, which returns `Ok(None)` for a profile that has never minted
  MPP state. `MppError::authorization_not_found` and the
  `absent_state_lookup_error` / `absent_state_approval_lookup_error`
  classifiers are added for adapters that must answer a lookup without a store
  handle. `MppErrorCode` gains an `AuthorizationNotFound` variant; the enum is
  not `#[non_exhaustive]` and is not being made so, since that would itself be
  breaking. An exhaustive `match` on it downstream needs one new arm.
- The operator-facing web pages now render the project's visual design. This covers the WebAuthn bridge's registration and approval pages, the approval inbox and detail pages, and the operator-enrollment page. It also covers the remote-approval sign-in, enrollment, inbox, detail, and message pages. `stellar-agent-loopback-http`
  gained a `brand` module carrying what the pages emit inline: `BRAND_STYLE`,
  `BUDDY_MARK_SVG`, `TRUST_LINE_LOOPBACK`, and `TRUST_LINE_SELF_HOSTED`. The
  pages fetch no external font, stylesheet, or image; the
  Content-Security-Policy and the data-island escaping are unchanged, and no
  status or result write reaches an HTML-interpreting sink.
- The served pages carry no identity unless the deployment configures one. An
  unconfigured wallet serves every page with a plain title, no display name,
  and no project mark; the design is unchanged in every case. The wallet is a
  self-hosted runtime that third parties deploy, so an identity default put
  this project's name and mark inside somebody else's deployment. The new
  optional profile block names the deployment instead:

  ```toml
  [served_pages]
  display_name = "Acme Ops"
  show_project_mark = false
  ```

  `display_name` renders in the page title and above each page's heading; it is
  HTML-escaped wherever it appears and is refused at profile load past 64
  characters (`ProfileLoadError::InvalidServedPageDisplayName`). Absent or
  empty means no name, never a fallback to the project's own.
  `show_project_mark` renders the project mark and defaults to `false`.

  Page styling is NOT configurable, and neither is anything the approval page
  says about a transaction: the amount, the destination, the facts grid, the
  approve and reject controls, the caution line, and the expiry sentence render
  from the approval entry alone, identically under every identity. The approval
  page is a consent surface, and configured CSS, markup, or asset URLs would
  let anything able to write the profile make it misstate what is being signed
  without touching a signing key.

  API: `stellar-agent-loopback-http` gains `brand::PageIdentity`,
  `brand::MAX_DISPLAY_NAME_CHARS`, and an `escape` module holding
  `html_escape`: the one escaping definition every served page now applies,
  re-exported unchanged as `stellar_agent_approval_ui::html_escape`. The
  `brand::CARD_BRAND_HEADER` constant is removed in favour of
  `PageIdentity::card_header_html`. `ServeConfig` and `RemoteServeConfig` gain
  a `page_identity` field with a `with_page_identity` setter, defaulting to
  `PageIdentity::neutral`; `start_bridge_register_only`,
  `start_bridge_with_pubkey_lookup`, and `start_operator_enroll_server` take
  the identity as a new trailing argument. `stellar-agent-core` gains
  `profile::schema::ServedPagesConfig`,
  `profile::schema::MAX_SERVED_PAGE_DISPLAY_NAME_CHARS`, and the
  `Profile::served_pages` field.
- The approval inbox lists each request as a row carrying its kind, a readable
  headline, its identifying detail, and a countdown that turns red under ten
  minutes. All nine approval kinds have a headline and a kind label, with a
  plain fallback for a kind a future build adds. An inbox with nothing pending
  shows an empty state rather than an empty page.
- Both approval servers now serve the row-and-decision rendering from one file,
  `stellar-agent-approval-ui`'s `APP_SHARED_JS`, at `GET /static/app-shared.js`,
  and render the decision card through that crate's `render_summary_html`,
  `kind_pill`, `approve_button_label`, and `html_escape`. The remote surface
  previously carried its own copies. Pages load the shared script before their
  own; both remain same-origin under `script-src 'self'`.
- The approval detail pages render a payment's or claim's amount in its human
  denomination alongside the stroop count, and the destination in full rather
  than inside a label/value row. An MPP charge stays in the token contract's
  own base units, whose decimal scale the wallet does not have at render time.
- The approval pages render the created and expiry timestamps as readable text
  ("today 12:41", "in 4 minutes (12:52)") instead of raw unix milliseconds, and
  the inbox shows a per-entry countdown. The absolute values remain on the page
  in `data-` attributes, so a page whose script does not run still shows them.
- The WebAuthn bridge reports a request that could not reach the wallet as
  "could not reach the wallet. The link has likely expired." rather than the
  browser's transport error; the raw reason goes to the browser console.
- **Wire-contract change.** `stellar-agent profile init` refuses an unusable
  `--profile` name with `validation.config_invalid` and the component
  `profile`, instead of `validation.address_invalid`. The refusal is about
  profile configuration, not a Stellar account address, and `profile show`
  already reports the same input class under the same code. An agent routing on
  `error.code` saw an address-parse failure for a name-validation refusal.
  Closes #119.
- **Behaviour change.** Every `stellar-agent` command that loads a profile now
  refuses a profile file whose `policy_owner_key_id.service` names a different
  profile than the one selected, with the wire code `profile.name_mismatch`.
  A `<name>.toml` copied or renamed from another profile used to load. The
  signed policy file and the owner-key keyring entry resolve through the name
  the FILE carries. The pending-approval store, the audit log, and the
  policy-window state key on the name the operator ASKED for. So the run was
  governed by one profile's policy and accounted against another's state, and
  every message named the profile that was asked for. `profile sign-policy` and
  `profile enroll-owner-key` were the sharpest edge: run against such a file
  they overwrote a DIFFERENT profile's signed policy or owner-key entry. The
  reconciliation is engine-independent, so `noop` profiles are checked too, and
  it applies to a file selected by `--profile`, by `STELLAR_AGENT_PROFILE`, or
  by the `default` fallback. A file that exists and mismatches is refused rather
  than replaced by the zero-config synthesised profile. `stellar-agent profile
  show <name>` is the one exemption: it displays the offending field, which is
  what the recovery needs. `stellar-agent-mcp` already refused the same input at
  startup; the check is now one implementation in `stellar-agent-core`, shared
  by both binaries, with a per-surface message because the two lay their
  per-profile state out differently. Closes #107.
- **Behaviour change.** `pay`, `claim`, and `accounts create` now refuse a
  profile that was named but has no file, where they previously ran under a
  synthesised permissive profile. Naming a profile that does not exist (a
  mistyped `--profile`, or a stale `STELLAR_AGENT_PROFILE` in a shell rc or a
  CI job) used to substitute the in-memory zero-config profile. That is a
  testnet, `noop`-engine configuration with no policy gate. The run signed
  and submitted under it. The substitution is now keyed on where the name came
  from, not on the name: it fires only when no profile was named at all, so the
  documented zero-config quickstart is unchanged, and `--profile default` on a
  host with no `default.toml` refuses like any other named profile. The same
  rule governs the smart-account audit-writer surface. These three verbs also
  gained `STELLAR_AGENT_PROFILE` resolution in this change, deliberately in
  the same commit as the refusal, since honouring the variable without it would
  have widened the substitution rather than closing it. Closes #112.

### Fixed

- `profile show` no longer reports an operator-correctable profile fault as
  `internal.unexpected_state`. An out-of-bounds cap, an unparseable `rpc_url`, a
  missing `[policy]` section, an over-long served-page display name, or a
  malformed TOML file now answer `validation.config_invalid` with the cause. The path in a path-bearing message is redacted as it already was on every
  other verb. `show` loads directly rather than through the profile-access choke point. It exists to display a profile the other verbs refuse. So the same
  malformed profile answered `internal.unexpected_state` from `show` and
  `validation.config_invalid` from everything else, sending an operator to the
  issue tracker over a file they could have edited. The disposition now lives
  beside `ProfileLoadError` in `stellar-agent-core`, where the match is
  exhaustive: because the enum is `#[non_exhaustive]`, no consumer crate can
  match it exhaustively, so a variant added without a classification previously
  fell into whichever catch-all the consumer had. Closes #124.
- MPP read verbs no longer report a profile with no MPP history as a broken
  store. `mpp authorization status` on a profile that has never prepared a
  charge answers `mpp.authorization_not_found`, and `mpp state prune` succeeds
  with `pruned: 0` while still recording the maintenance request and its reason
  digest in the audit log. The state key is minted only on the prepare path, so
  every read verb refused with `mpp.state_unavailable` until the first charge,
  indistinguishable from a genuinely unreadable store. A store that exists
  without a usable key still fails closed: only the provable never-minted state
  (no key and no state file) reads as first run, so deleting or rotating the
  key cannot reset replay protection. Closes #106.
- An MPP read against a store whose key is minted but whose first record was
  never written reported `mpp.state_unavailable` because the store directory did not exist yet. A prepare denied by policy leaves this state behind. Lock
  acquisition now establishes the directory on every path, so the read answers
  from the empty store it actually has.
- A symlink whose target does not exist at the MPP store's state or lock path
  no longer escapes the store's symlink refusal. Existence tests follow links,
  so a dangling one read as absent: the state path answered from an empty store
  instead of refusing, and the lock path skipped its check and then created and
  locked the file the link pointed at, because opening with `O_CREAT` follows
  symlinks. Both paths now treat only a proven absence as absent. The store
  directory is inspected before it is created for the same reason, though a
  symlinked directory path was already refused.
- The operator-enrollment page keeps the accurate status line when an
  authenticator returns no usable public key. That branch skips the POST, and
  the response handler then replaced its message with the generic "Passkey
  creation failed. Try again." A request that cannot reach the wallet now says
  so, rather than reporting a passkey-creation failure for a passkey that was
  already created.
- `profile enroll-owner-key`, `profile enroll-signer`, `profile sign-policy`,
  and `profile rotate-nonce-key` no longer report an unloadable profile as
  `internal.unexpected_state`. `internal.*` means the wallet is broken; an
  absent or malformed profile is operator-correctable input, and an agent that
  routes on the code family treated these as unrecoverable. An absent profile
  is now `validation.profile_not_found`, matching their sibling commands, and a
  malformed one is `validation.config_invalid` with the parse cause carried in
  the message rather than flattened into "not found". Closes #109.
- CLI policy-window state is read and written under one profile name. The
  rolling-window store was hydrated from the file for the name derived from
  `policy_owner_key_id.service` and appended to the file for the name the
  operator requested. On a `v1` profile whose owner coordinate names a
  different profile the two never met: the first value-moving command evaluated
  its caps against an empty window and recorded into a file the engine would
  not read, and every command after it refused to build the engine at all,
  because the store's anti-rollback generation counter had advanced while the
  file the read selects still did not exist. The refusal named the derived
  profile in its `profile reset-window-state` hint while the reset resets the
  requested profile's store, so following it did not clear the condition. The
  read now selects the requested name's file, the one both write paths
  (`record_confirmed_window_state`, `record_authorized_window_state`) already
  use and the one `profile reset-window-state` resets, and the hint names that
  same profile. Only the file selector moved: the name attached to hydrated
  entries and the engine's lookup namespace stay derived and stay equal to each
  other, so hydration still lands in the namespace the engine queries. Closes
  #114.
- `STELLAR_AGENT_PROFILE` selects the profile for the CLI verbs that
  substituted the literal `"default"` for an absent `--profile`.
  `trustline`, `lend`, `trade`, `vault deposit`, `vault withdraw`, the four
  `mpp` subcommands, the five `counterparty` subcommands, `profile init`,
  `profile enroll-signer`, `profile enroll-owner-key`, `profile sign-policy`,
  and `pool init` / `list` / `status` now resolve flag > environment >
  `default`, the order `docs/cli-reference/index.md` documents. Two shapes
  defeated it: a clap `default_value`, which substitutes the literal before the
  command runs (the DeFi, `mpp`, `counterparty`, and `profile` verbs), and a
  handler-side `.unwrap_or("default")` on an optional flag (the three `pool`
  verbs). A source-scan test refuses both, for any field named `profile` or
  declaring `long = "profile"`; its allow-set, which carried `pay`, `claim`,
  and `accounts create` while their synthesis fallback still accepted any
  absent profile, is now empty and asserted empty. Closes #113.
- The CLI's startup advisory scans the audit log of the profile the command
  itself uses, taking the name from the parsed subcommand and resolving it the
  way that subcommand does. It resolved the profile through a private argv scan
  that fell back to the literal `"default"` and never read
  `STELLAR_AGENT_PROFILE`. So under that variable the advisory read, and
  appended its advisory rows to, one profile's log while the command operated
  on another's. Closes #108.
- Profile names are validated as filesystem path components inside the profile
  loader, before the path is built, on both the read and the write half. A name
  carrying `..`, a path separator, or a control character is refused with a
  typed error instead of being joined into a path. The guard previously sat at individual call sites. Subcommands that did not call it reached the loader with an unvalidated operator-supplied name. These included `profile show`,
  `pool list`, `pool init`, `counterparty refresh`, `counterparty list`,
  `approve serve`, `audit verify`, `fees stats`, `mpp`, and
  `profile rotate-audit-key` among others.
- A profile named through `--profile` or `STELLAR_AGENT_PROFILE` is never
  replaced by the MCP server's synthesised first-run profile. That fallback is a
  testnet, `noop`-engine configuration, so substituting it for a named-but-
  missing profile answered on the wrong network and downgraded a `v1` profile's
  fail-closed governance to an unsigned-policy engine. The fallback now applies
  only when no profile was named at all, keyed on where the name came from
  rather than on the name itself, so `--profile default` on a host with no
  `default.toml` refuses like any other named profile.
- `stellar-agent-mcp` refuses arguments it does not recognise instead of
  ignoring them. A mistyped `--profil mainnet-prod` in a client configuration
  started the server on `default`, which is the silent wrong-profile start the
  selection flag exists to prevent. The flag is also read from the whole
  argument list rather than only the first position.
- `docs/mcp.md` no longer states that startup exits non-zero without a keyring
  backend; it warns and continues, with signing tools refusing at call time.
  `docs/profiles.md` no longer refers to a `stellar-agent mcp` subcommand, which
  does not exist.
- A profile name that names a Windows reserved device (`CON`, `PRN`, `AUX`,
  `NUL`, `COM1`-`COM9`, `LPT1`-`LPT9`) or begins with `-` is refused by both
  binaries. `<profile_dir>/NUL.toml` opens the NUL device on Windows rather than
  a file, so a write to that path is discarded and a read returns nothing while
  the path itself still reports as present; a name beginning with `-` is read as
  the next flag by every argument parser that has to take it, so `--profile -x`
  selects no profile at all. The device comparison is case-insensitive and
  reduces the name the way Windows does: cut at the first `.`, then drop trailing spaces. So `NUL.toml`, `nul `, and `nul .toml` are all refused, while
  `COM0`, `COM10`, and `LPT0` are not reserved and remain valid names. The
  audit-log and policy-window path builders, which sanitise such a stem rather
  than refusing it, now read the same reserved-name table, so the two surfaces
  cannot disagree about what is reserved. The console devices `CONIN$` and
  `CONOUT$` are refused as whole names only, matching the exact-name rule
  Windows resolves them under: a profile name reaches the filesystem unprefixed
  as the per-profile counterparty-cache directory, while `conin$.toml` and
  `myconin$` are ordinary files and remain valid names. Closes #110.
- **Behaviour change.** A profile literally named e.g. `con` or `-x` stops
  working after the change above. On Unix both are legal file names and such a
  profile may exist; on Windows a `-x` profile can exist, while a reserved-name
  profile never had a file. Recover with `stellar-agent profile init --profile
  <new-name>` and the enrollment steps it prints, or by renaming the file and
  correcting its `policy_owner_key_id.service` to
  `stellar-agent-owner-<new-name>`. A `v1` profile then also needs `profile
  enroll-owner-key` and `profile sign-policy` re-run under the new name. This is because
  the owner key is stored under the old name's coordinate and the signed policy
  file carries the old name in its signed scope.

## [0.1.0-alpha.5] - 2026-07-26

### Added

- Added testnet-only sponsored Machine Payments Protocol charges for classic
  G-account payers. The CLI and five MCP tools validate HTTP or native MCP
  challenges, simulate and authorize one SEP-41 transfer, use the existing
  value-policy and approval spine, return a one-shot credential, record trusted
  host receipts, and independently reconcile final direct or fee-bump
  transactions.
- Added a per-profile, keyring-HMAC-protected MPP authorization state file with
  cross-process locking, atomic writes, replay protection, terminal retention,
  and audited explicit pruning. The file stores prepared authorization material
  and digests, never credentials or raw receipts.
- Added `stellar-agent profile init`, which creates and persists a new profile
  TOML with per-profile-derived keyring entry references. `--profile` defaults
  to `default`, `--network` to `testnet`, `--engine` to `v1`. `--rpc-url` is
  optional for testnet (defaults to the built-in testnet endpoint) but
  required, and required to be `https://`, for `--network mainnet`. The
  built-in mainnet default requires an API key and answers HTTP 401
  unauthenticated, so persisting it would mint a broken configuration. Mainnet without `--rpc-url` is refused with
  `validation.mainnet_rpc_url_required`, and a plaintext mainnet endpoint
  with `validation.config_invalid`. Refuses without writing or modifying
  anything if the named profile already exists
  (`validation.profile_already_exists`); the write itself is no-clobber, so a
  file appearing concurrently is never overwritten. Mints no key material and
  emits no audit row; docs and the MCP server's first-run guidance, which
  already referenced this command, now match an implemented one.
- Every `profile` subcommand now accepts a `--profile <NAME>` flag. `show`,
  `migrate`, the `rotate-*` subcommands, and `reset-window-state` previously took only a positional `<NAME>`. They now accept either the positional
  `<NAME>` or `--profile <NAME>` (exactly one; supplying both, or neither, is a
  usage error). So a single profile-naming convention works across the group.
  The positional forms remain valid, and these subcommands still require a
  target with no default.

### Changed

- `stellar-agent profile enroll-signer` now pins the profile's
  `mcp_signer_default.account` to the enrolled seed's derived G-strkey when
  the on-disk account is the literal placeholder `init` mints, patching only
  that key in the profile TOML before the keyring write. Classification and
  the pin operate on the raw on-disk document, so `STELLAR_AGENT_*`
  environment overlays stay load-time-only and can never be persisted into
  the trust root. A profile whose account already pins a different G-strkey
  is unaffected: enrollment still refuses on a mismatch and never rewrites
  it; an account value that is neither the placeholder nor a valid G-strkey
  is refused with the new `enroll_signer.account_malformed` code instead of
  being replaced. Every refusal path leaves the profile unmodified. This
  closes the gap that made an `init`-minted profile otherwise unable to ever
  enroll a working signer. The success envelope adds `account_populated`,
  reporting which case a given run took.

- Renamed the profile field `usd_threshold` to `cross_check_threshold_stroops`
  (the accessor to `effective_cross_check_threshold_stroops()` and the builder
  method to `cross_check_threshold_stroops(...)`) because the value is
  compared against stroop-denominated transaction amounts, not a USD figure.
  The floor remains 1000 XLM (10^10 stroops). Profile TOML files carrying the
  legacy `usd_threshold` key still load via a serde alias; saved profiles now
  write only the new key. A profile rewritten by a save is read by alpha.4
  binaries as having no threshold, so their effective value falls back to the
  1000 XLM floor (the cross-check fires more often, never less).
  `stellar-agent profile show` and the MCP `mcp-resource://profiles/<name>`
  resource now emit `cross_check_threshold_stroops` in their JSON output.

- Breaking: every value-moving signing verb (`pay`, `claim`, `accounts create`
  sponsored mode, `trustline`, `trade`, `lend`, `vault` deposit and withdraw,
  the x402 authorizers, and `stellar_sep43_sign_and_submit_transaction`, CLI
  and MCP alike) now proves the active profile's audit chain-root key is
  acquirable BEFORE the signing key is touched or a transaction is
  submitted, refusing `audit.chain_key_unavailable` if not. Previously, a
  missing or unopenable audit writer logged a `tracing::warn!` and the
  action proceeded unaudited, silently, with no `value_action_submitted`
  row, and `lend`/`vault` had no pre-flight or audit row at all. `profile
  init` mints the audit-log keyring coordinate only, no key material, so an
  init-minted profile now requires `stellar-agent profile rotate-audit-key
  <name>` before any of these verbs will sign or submit, on both policy
  engines; `next_steps` in the `profile init` success payload names it,
  right after `enroll-signer`. This pre-flight fails closed only for a
  persisted `<name>.toml` profile. `pay`, `claim`, and `accounts create`
  keep their documented zero-config posture. The in-memory profile
  synthesized when no profile file exists stays fail-open on this specific
  check, so the no-setup quickstart is unaffected. The post-confirm
  `value_action_submitted` emission itself stays non-fatal. The transaction
  has already committed by then, so refusing would help nobody.
  `stellar_mpp_charge_commit` is unaffected: it already failed closed on the
  same condition via its own stricter authorization-withholding mechanism.
  The distinct failure mode of a key that loaded but whose writer could not
  be opened (e.g. a registry path/key mismatch) now carries its own error
  variant (`audit.chain_key_unavailable` wire code, distinct message) that
  does not suggest `rotate-audit-key` as a remedy, since rotating the key
  does not fix a path/key mismatch. (#88)

### Removed

- Breaking (CLI): the `smart-account migrate-verifier --confirm-mainnet-migrate`
  flag. The flag could never lead to a successful submit. The network layer
  forbids mainnet writes unconditionally in this alpha. So the command now
  structurally refuses mainnet submit up front with
  `network.mainnet_write_forbidden`, matching every other write surface.
  Mainnet dry-run stays available (read-only). The `mainnet_confirm_missing`
  migration phase is removed from the `sa.verifier_migration_failed` closed
  phase set, and comments referencing a nonexistent `--accept-mainnet` flag
  are removed.

### Fixed

- The MCP single-shot signing tools (`stellar_sep43_sign_transaction`,
  `stellar_sep43_sign_auth_entry`, `stellar_sep43_sign_and_submit_transaction`,
  `stellar_x402_create_payment`, `stellar_x402_authenticated_payment`) now
  evaluate the policy gate before the audit pre-flight, so a policy denial or
  approval escalation surfaces its own wire code instead of
  `audit.chain_key_unavailable` when the audit chain-root key is unminted. The
  pre-flight still precedes every signing-key access. Ordering is pinned by a
  per-tool test.

- Failures on non-keyring signing paths now report failure-domain-accurate
  error codes instead of being wrapped as `auth.keyring_not_found` (and, at
  eight signer-source sites, `auth.keyring_locked`). Ledger-availability
  failures during deployer and signer resolution report the classified
  `wallet_state.hardware_not_found` (or the timeout / wrong-app variant); a
  missing or malformed secret-env variable reports
  `validation.secret_env_not_set` / `validation.secret_env_invalid` (naming the
  variable, never its value); a failed wallet unlock reports
  `wallet_state.unlock_failed`; and invoking a value-moving verb with no
  signer-source flag reports `validation.signer_source_required`. The network
  library's public `signer_from_env` is retyped to the same
  `validation.secret_env_*` codes. Genuine keyring conditions still report
  `auth.keyring_not_found` / `auth.keyring_locked`.
- Keyring failures on the audit-HMAC and attestation-key READ paths are now
  classified instead of being reported as `auth.keyring_not_found` or
  discarded. `stellar-agent audit verify`, `accounts deploy-c`, the CLI, core,
  and MCP attestation-key loaders, the `profile sign-policy` owner-key read,
  and the MCP server's owner-key read now surface the precise cause. Most importantly, this includes `auth.keyring_interactive_session_required` for a non-interactive Windows session. Key absence still maps to
  `auth.keyring_not_found` (and to `OwnerKeyAbsent` for the MCP owner key).
  The fail-closed and indistinguishable read paths (the trustline opt-in
  verify, the MPP state-key read, the MCP attestation gate, the
  `credentials add-passkey` audit emission, the v1 policy-gate owner-key read,
  and the channel-pool master-seed read) keep their outward contract unchanged
  and now log the classified cause at debug for operator forensics. The single
  keyring classifier (`classify_keyring_error` / `map_keyring_error`) now lives
  in `stellar-agent-core` and is re-exported from `stellar_agent_network::keyring`,
  so no call site or wire code changed for existing callers.
- An unset `audit_log_path` now resolves to the per-profile location the
  field documents (`<root>/audit/<name>.jsonl`) in the profile builder, the
  loader, and the v1 migration. This replaces a host-global `audit.log` shared
  by every profile on the machine. Hash-chained logs from unrelated profiles no longer interleave. Explicit `audit_log_path` values are
  unchanged. The test-gated `STELLAR_AGENT_HOME` override now reaches every
  canonical-data-root-derived path, including the audit directory.
- Every audit-writer acquisition now registers the profile's configured
  `audit_log_path` under the profile's audit chain-root key discipline.
  `stellar_rule_create`/`stellar_rule_create_commit` and the smart-account,
  approve, and timelock command families previously registered a name-derived default path with no HMAC key. The first such open pinned the
  process-lifetime writer-registry entry and bricked every later keyed open
  for the same profile name. Rows written unkeyed fell outside
  `stellar-agent audit verify` coverage. For a persisted profile, every audit-writing signing verb in these families now fails closed. These include `smart-account execute`,
  `smart-account multicall`, the timelock `schedule`/`execute`/`cancel`
  commands, the rules write path, `migrate-verifier`'s submit path,
  `approve serve`, `rule_create`, and `pool init`. They report `audit.chain_key_unavailable` until `profile rotate-audit-key` mints the
  chain key. Read-only surfaces (`list-rules`, `timelock list-pending`,
  `rules get-spending-limit`, `migrate-verifier --dry-run`), `approve run`'s
  post-approval emission, and the local multicall registry commands
  (`register-multicall`, `unregister-multicall`) stay best-effort: they
  degrade with a warning. Their acquisition now goes through the same
  keyed-first discipline, so a failure never poisons the registry. The
  zero-config synthesized testnet profile keeps its quickstart behavior.
  Source-scan tests pin the discipline in both the CLI and the MCP server.
- The SEP-43 sign-only pair (`stellar_sep43_sign_transaction`,
  `stellar_sep43_sign_auth_entry`) now proves the audit writer acquirable
  before signing and records an `opaque_payload_signed` audit row. It records the redacted payload digest and redacted signer address, never the signature
  or payload, at the point the signature is produced. The caller broadcasts
  externally, so the row records signature production, not on-chain
  confirmation. `pool init` likewise acquires the audit writer before any
  seed generation or on-chain submit and reuses it for the post-confirm
  `channel_pool_initialised` row.
- Every value verb evaluates the operator policy gate BEFORE the audit
  pre-flight: a policy denial is a clean refusal that signs and submits
  nothing, so it no longer requires a minted audit chain key to be reported.
  `pay` and `claim` reorder all three stages (one-shot, `--sign-only`,
  `--submit-only`); `trustline` and `accounts create` reorder their single
  gated path; `trade`, `lend`, and `vault` already evaluated policy first.
  The MCP tools are unchanged: policy denials fire at the simulate stage,
  which has no pre-flight, and the commit-stage pre-flight stays ahead of
  nonce consumption. The pre-flight still runs before any signing key is
  touched or transaction submitted, pinned by a source-order test that
  checks every pre-flight call site per verb.
- Keyring write failures now classify through the same mapping as reads:
  `profile enroll-signer`, `profile enroll-owner-key`, the rotate commands
  (`rotate-nonce-key`, `rotate-audit-key`, `rotate-attestation-key`,
  `rotate-counterparty-key`, `rotate-policy-state-key`,
  `counterparty rotate-hmac-key`), the nonce-mint key
  load, and `pool init`'s existence probe and post-confirmation seed write
  report `auth.keyring_interactive_session_required` from a non-interactive
  Windows session and `auth.keyring_platform_error` for other backend
  failures, instead of collapsing every failure into
  `auth.keyring_not_found`. First-run setup over SSH on Windows now names
  the actual cause. The interactive-session message also names the
  `STELLAR_AGENT_KEYRING_BACKEND=headless-dpapi` escape hatch.
- The `windows-storage` CI job again runs the smart-account wire-code suite
  and the MCP rule-tool suite (which exercises the audit path end-to-end on
  Windows). The job provisions the same native Perl the release workflow's
  Windows target uses, which is all the vendored OpenSSL build in that
  closure needs on a `windows-latest` runner.
- `pool init` now persists its pool bookkeeping by patching only
  `pool_master_key_id` and `[pool_config]` on the raw on-disk profile document
  (`loader::set_pool_state`), instead of re-saving the loaded profile struct.
  The previous load-merge-save round trip wrote the env-merged view into the
  profile TOML: a transient `STELLAR_AGENT_*` environment override present
  during the one-time pool initialization became persistent configuration, and
  loader-derived defaults (`rpc_url`, `network_passphrase`, `audit_log_path`,
  derived key references) the file never held were baked in. A profile updated
  by `pool init` now differs from its previous on-disk form only in the two
  pool keys.
- Documentation: `docs/agents.md`, `docs/profiles.md`, and the agent skill no
  longer imply that key rotation plus V1 opt-in unlocks mainnet writes. The
  alpha refuses every mainnet write structurally at the network layer
  regardless of policy engine or enrolled keys; the docs now state both
  refusal layers and their wire codes. The `network.mainnet_write_forbidden`
  envelope message likewise no longer attributes the refusal to a missing
  policy-engine configuration.

### Security

- MPP mainnet, unsponsored, push, smart-account, transport-automation, channel,
  and toolset-routing modes are structurally unsupported. The wallet returns a
  credential but does not send the paid request or submit the server-sponsored
  transaction.
- The idempotent-submission retention-poll write path now carries the same
  URL-heuristic defence-in-depth mainnet guard as the primary submit path,
  which it previously lacked (the passphrase guard, the primary control, was
  already present on both paths). The idempotent entry point additionally
  refuses mainnet before decoding the envelope or writing any receipt state,
  so a refused mainnet submission no longer strands a pending receipt.

## [0.1.0-alpha.4] - 2026-07-11

### Fixed

- Windows: the audit-log writer acquired its exclusive lock on one file handle
  and performed reads/writes against the SAME active log file through separate
  handles (the partial-rotation last-entry scan, the chain-recovery read at
  open, and the append handle itself). `LockFileEx`'s exclusive lock is
  enforced against I/O issued through any OTHER handle to the same file,
  including a second handle opened by the SAME process. This differs from POSIX
  advisory locks, which never restrict I/O through a different descriptor.
  Re-opening a non-empty audit log (the common case once a profile has any
  history) failed with `ERROR_ACCESS_DENIED`, surfaced through the smart-account
  MCP flow as a misattributed `"networks.toml I/O error"` at the audit path.
  `AuditWriter` now locks a sidecar file (`<log>.lock`) instead of the log itself. The log file carries no OS lock on any platform. The writer keeps a
  single handle for every read and write against the active log. Adds
  `SaError::AuditWriterIo` so an audit-writer-open failure is attributed to
  the audit subsystem rather than the networks-registry subsystem. Adds a
  `windows-storage` CI job running the audit-log and touched-crate tests on
  `windows-latest`. (#59)
- Windows: audit-log READERS (`audit verify`, the `find_*` state scans) failed
  wholesale, and one blocked indefinitely, while any writer was alive. The writer's exclusive lock lived on the log file itself. Windows enforces such a lock against reads through every other handle. With
  the writer's lock on the sidecar, readers never contend with it. Readers
  and `verify` additionally tolerate the transient active-file absence during
  a concurrent rotation (bounded re-scan, gated on a live writer holding the
  sidecar lock; a genuine gap is still reported, only its detection is
  delayed by the bound). The blocking reader path was a line iterator
  treating per-read lock violations as ordinary items and never reaching
  end-of-file; readers now complete regardless of writer liveness, pinned by
  a dedicated concurrency test on the `windows-storage` CI job, which runs
  the full audit-log module again. (#64)
- Windows: Credential Manager refuses access from a non-interactive session
  (a service, an SSH session, a scheduled task) with Win32
  `ERROR_NO_SUCH_LOGON_SESSION`. The keyring error mapping surfaced this as
  the generic `auth.keyring_platform_error`; it now maps to a dedicated
  `auth.keyring_interactive_session_required` code whose message states the
  cause and the deployment implication. The headless-secret-path design for
  non-interactive deployments remains a separate, open item. (#57)
- Windows: `PendingApprovalStore` (the approval spine, including
  `credentials add-passkey`'s registration flow) and `ToolsetGrantStore`
  (toolset first-invoke grants) durably persist a write by renaming a temp file into place. They then open the PARENT DIRECTORY as a file to fsync it, a POSIX idiom. `std::fs::File::open` on a directory path requires
  `FILE_FLAG_BACKUP_SEMANTICS` on Windows (not set by the stable API) and
  fails with `ERROR_ACCESS_DENIED`, even though the content write and rename
  immediately before it succeed. Both stores now skip the directory fsync on
  non-Unix, matching the pattern already used by the policy-window store and
  the audit-log rotation sidecar writer. The `windows-storage` CI job now
  also runs the approval-store and toolset-grant-store persist tests. (#61)

### Changed

- Every SEP MCP tool (`stellar_sep43_*`, `stellar_sep7_parse_uri`,
  `stellar_sep53_sign_message`, `stellar_sep53_verify_message`,
  `stellar_sep47_discover`, `stellar_sep48_preview_invocation`,
  `stellar_sep6_deposit_info`, `stellar_sep24_interactive_url`) and the CLI
  `toolsets` and `credentials` command groups now use the standard
  `{ok:true,data,request_id}` / `{ok:false,error:{code,message},request_id}`
  result envelope. Business and validation failures that previously surfaced
  as bare objects, ad-hoc `{"status":...}` shapes, or (for SEP-43) the raw
  SEP-43 `{code,message}` object now carry a stable dotted wire code
  (`sep43.*`, `sep7.*`, `sep53.*`, `sep24.*`, `anchor.*`, `sep47.*`,
  `sep48.*`, `toolsets.*`/`toolset.*`, `credentials.*`); the structural
  mainnet-signing refusal on every sign-only tool now shares the canonical
  `network.mainnet_write_forbidden` code instead of a SEP-43-specific one.
  Docs (`docs/mcp.md`, `docs/toolsets.md`,
  `docs/cli-reference/profile-and-governance.md`) and the knowledge skill
  under `skills/stellar-agent-wallet/` are updated to match; the packaged
  skill zip is regenerated. The x402 tools' success payloads
  (`stellar_x402_create_payment`, `stellar_x402_authenticated_payment`,
  `stellar_x402_parse_receipt`) are wrapped under `data` for the same
  consistency; their business errors were already normalised. The agent-facing
  contract (one envelope shape, one dotted-code taxonomy) now holds across
  every MCP tool and CLI verb these fixes touch. (#60)
- `credentials add-passkey`'s declined-RP-ID-binding-warning outcome no longer
  leaks the internal requirement-tracking tag into the wire code: renamed to
  the semantic `credentials.rp_id_binding_warning_declined` (and the internal
  helper functions to matching names). The closed set of `credentials.*`
  wire codes is documented in `docs/cli-reference/profile-and-governance.md`
  and the knowledge skill's `cli-reference.md`. (#62)
- The MCP server's confirmed-sequence floor (`stellar_pay_commit`,
  `stellar_claim_commit`, `stellar_create_account_commit`,
  `stellar_trustline_commit`, sep43 sign-and-submit) now also covers the DeFi
  adapter submit paths (`stellar_dex_trade`, `stellar_blend_lend`,
  `stellar_defindex_vault_deposit`/`_withdraw`): `DefiAdapterCtx` and
  `SubmitInvokeArgs` gain an optional `sequence_floor` hook so the shared
  `submit_signed_invoke` substrate's own account fetch benefits from the same
  bounded catch-up poll, and a confirmed DeFi submit advances the same
  process-local tracker a classic commit verb for the same source account
  would consult next. Advisory only, as before: never fabricates a sequence,
  never blocks beyond the bounded window. (#55)
- `pay_policy_v1_testnet_acceptance.rs` now enrolls the operator owner key
  through the real OS keyring via the production `stellar-agent profile
  enroll-owner-key` subprocess (uniquely namespaced per run, cleaned up by an
  RAII guard) instead of a test-only file source, so the suite covers the
  full production owner-key path: profile load, keyring registration,
  keyring read, policy-signature verification, `per_tx_cap` evaluation,
  sign, submit, confirm. (#56)
- Every wallet-state platform-directory derivation now routes through one
  canonical root, `directories::ProjectDirs::from("", "Soneso",
  "stellar-agent").data_local_dir()`
  (`stellar_agent_core::profile::schema::canonical_data_root`; the
  `stellar-agent-headless-keyring` crate replicates the same derivation
  locally, pinned to the core function by a dev-dependency byte-equality
  test, to avoid pulling core's dependency closure into a minimal
  headless-deployment crate). The audit-log directory and the
  policy-window-state directory move off their prior `BaseDirs`-derived
  roots onto the canonical one; `networks.toml` moves from the OS config
  directory to the canonical data root, and its four independent
  derivations collapse to one shared helper,
  `stellar_agent_smart_account::verifiers::default_networks_toml_path`. No
  migration: no installation predates this change. `STELLAR_AGENT_HOME`
  override behaviour is unchanged everywhere it already applied. (#63)

### Added

- The getting-started guide documents the macOS Gatekeeper behavior for the
  prebuilt release binaries (ad-hoc signed, not notarized): verify the
  download against `SHA256SUMS` or its Sigstore bundle, then approve the
  binary once via `xattr -d com.apple.quarantine` or Finder's right-click
  Open. Developer-ID signing and notarization remain open. (#58)

- An opt-in, file-backed headless keyring store
  (`stellar-agent-headless-keyring`) for deployments where the platform
  keyring is unavailable or unusable. This covers a Windows service, an SSH/WinRM
  session, or a scheduled task (Windows Credential Manager requires an
  interactive logon session), and Linux services/CI. Activated via
  `STELLAR_AGENT_KEYRING_BACKEND=headless-env` (XChaCha20-Poly1305, key from
  `STELLAR_AGENT_HEADLESS_KEYRING_KEY`) or `STELLAR_AGENT_KEYRING_BACKEND=headless-dpapi`
  (Windows only; DPAPI CurrentUser scope via a new `stellar-agent-windows-identity`
  `dpapi_protect`/`dpapi_unprotect` wrapper). The platform keyring remains the
  default; the headless store never activates implicitly and never falls
  back to the platform keyring on any initialisation failure. Slots in
  behind the same `KeyringEntryRef` coordinates every existing enroll/rotate/
  sign call site already uses, so every existing keyring-consuming code path
  works unchanged once activated. See
  `docs/maintainers/security-internals.md`'s "Headless keyring store" section
  for the trust model and `docs/getting-started.md` / `docs/mcp.md` for the
  activation surface. (#57)

## [0.1.0-alpha.3] - 2026-07-10

### Added

- `counterparty_allowlist`'s `KNOWN_ISSUER` kind gains an opt-in `gate_inflows`
  flag (default `false`, so existing policy files parse and behave unchanged).
  When `true`, `KNOWN_ISSUER` evaluates every leg of the descriptor, debit
  and inflow alike, instead of debit legs only, so tokens received from an
  un-allowlisted issuer (Blend withdraw/borrow proceeds, vault withdrawals)
  are gated too. An inflow leg whose asset is unresolvable denies fail-closed,
  the same posture as the existing debit handling. The other counterparty
  kinds (`G_ACCOUNT` / `C_ACCOUNT` / `HOME_DOMAIN`) are unaffected. (#39)

- `profile enroll-owner-key` enrols the policy-file owner ed25519 PUBLIC key
  from an operator-held seed, and `profile sign-policy` signs a V1 policy file
  with that seed so the engine accepts it. Together they make
  `policy.engine = "v1"` usable end to end: no shipped command previously
  produced the `[signature]` table the engine requires, so selecting `v1`
  failed closed. (#30)
- `stellar_agent_core::policy::v1::signature::sign`, the owner-signature
  primitive that is the exact inverse of `verify`. (#30)
- Value-moving verbs now write a hash-chained, HMAC-signed
  `value_action_submitted` audit row after a confirmed on-chain submit,
  recording the SAME value legs the policy gate sized (single-derivation
  invariant), the redacted transaction hash, and the ledger. This covers the MCP
  `stellar_pay` / `stellar_create_account` / `stellar_claim` / `stellar_trustline`
  commit tools, the Blend / DEX / DeFindex adapters, the opaque
  `stellar_sep43_sign_and_submit_transaction` path, and the CLI `pay` /
  `claim` / `accounts create` (sponsored) / `trustline` verbs. The x402
  payment authorizers write their own `x402_payment_authorized` row at
  authorization signing (there is no on-chain submit on that path), carrying
  the gate-sized legs plus the settle network and scheme. A
  DeFi adapter that fails on submit records a `sa_raw_invocation` row instead.
  Emission is non-fatal post-submit: a row-write failure logs a warning and
  never changes the result. (#21)
- `PolicyEngine` gains `evaluate_full` / `evaluate_with_value_full`, which return
  an `Evaluation { decision, value_effects }` surfacing the value descriptor the
  gate sized on the allow path; the decision-only `evaluate` /
  `evaluate_with_value` remain as thin views. Value-verb dispatch uses the
  `_full` methods so the post-submit audit row records exactly the legs the gate
  evaluated rather than re-deriving them. (#21)
- The six key-writing profile commands (`enroll-signer`, `enroll-owner-key`,
  `rotate-nonce-key`, `rotate-attestation-key`, `rotate-counterparty-key`, and
  `rotate-audit-key`) now write a `keyring_key_written` audit row recording the
  key purpose and, where applicable, the redacted public address. (#34)
- `profile rotate-audit-key` rotates the audit chain-root HMAC key and re-signs
  every per-file chain-root sidecar with the new key so `audit verify` stays
  green across the rotation; the new key is persisted before any sidecar is
  re-signed. (#34)
- Offline envelope-shape regression coverage for the `nonce.mint_failed`
  business error on the four two-phase simulate handlers (`stellar_pay`,
  `stellar_create_account`, `stellar_claim`, `stellar_trustline`) and for the
  RPC-dependent `sep48.spec_fetch_failed` / `sep48.render_failed` /
  `sep47.discovery_failed` arms of `stellar_sep48_preview_invocation` /
  `stellar_sep47_discover`, each asserting the full normalised envelope
  (`ok:false`, the documented wire code, a non-empty `request_id`,
  `is_error == Some(true)`). (#36)
- Testnet acceptance coverage for a sponsored `stellar_create_account` /
  `stellar_create_account_commit` two-phase call: the destination account
  exists on-chain afterward with the sponsored starting balance, and the
  commit recorded a `value_action_submitted` audit row. (#43)
- Testnet acceptance coverage for a classic `stellar_trustline` /
  `stellar_trustline_commit` two-phase call against the pinned testnet USDC
  issuer, run under a `minimum_reserve` policy rule the funded source account
  satisfies: the simulate and commit steps both reaching `ok:true` (rather
  than `policy.criterion_evaluation_failed`) is on-chain proof that both
  dispatch points supply a genuinely populated `account_view` (#47). Asserts
  the on-chain trustline limit and the commit's `value_action_submitted`
  audit row. (#43)
- `profile rotate-audit-key` gained the `run_with_dependencies` seam already
  used by the other key-writing profile commands, so its unit coverage now
  drives the actual persist → re-sign → emit sequence rather than a parallel
  reimplementation of it; reordering the three steps turns the test red. A
  V1-engine testnet acceptance variant of the `stellar_pay_commit` flow now
  asserts the confirmed commit's `value_action_submitted` audit row's leg
  content (`action`, `amount`, `asset`, redacted `destination`) equals exactly
  the values submitted on-chain, not merely that a row of the right kind
  exists. (#44)

### Changed

- CLI `pay --sign-only` / `--submit-only` and `claim --sign-only` /
  `--submit-only` now evaluate operator policy on the supplied envelope before
  signing or broadcasting, instead of running unconditionally under
  `policy.engine = "v1"`. Each stage decodes the envelope through the same
  decoder the MCP `stellar_pay_commit` / `stellar_claim_commit` path uses and
  evaluates the decoded amount/asset/destination. Sizing comes from the
  envelope, not caller-supplied args. `--submit-only` gates even though the
  envelope arrives pre-signed, because broadcasting still spends funds. An
  envelope the decoder cannot classify into a sized shape follows the
  opaque-signing posture: denies `policy.deny.unsizable_value_effect` under a
  matched value rule unless it sets `allow_opaque_signing = true`, mirroring
  the `stellar_sep43_*` tools' posture. `policy.engine = "noop"` is unaffected. The staged flows remain ungated there, as before. The staged flows
  match policy rules under the `stellar_pay_commit` / `stellar_claim_commit`
  tool names (the same names the MCP commit phase matches), not `stellar_pay` / `stellar_claim`. A ruleset that names only the base tools default-denies
  the staged flows, so operators cover both names, or use `tool = "*"`, for
  uniform behavior across invocation modes. (#40)
- The per-period rolling-window accumulator (`PolicyStateStore`) is now
  `i128`-width: cumulative recorded spend within a rolling window is exact
  across the full `i128` range, superseding the previous `i64`-width
  accounting and its fail-closed refusal above `i64::MAX` (#20). The
  accumulator is in-process state only (no persistence across restarts, as
  before), so there is no legacy on-disk form to migrate. (#42)
- Documented that `minimum_reserve` and identity-class criteria
  (`home_domain_resolved`) are inapplicable to the smart-account verbs
  (`stellar_blend_lend`, `stellar_dex_trade`, `stellar_defindex_vault_deposit`,
  `stellar_defindex_vault_withdraw`, and the CLI `lend`/`trade`/`vault`
  equivalents): the acting account is a smart-account contract with no classic
  `AccountEntry`, so `account_view` and `identity_view` stay unset permanently
  on these tools, by design. A rule configuring either criterion on one of
  these verbs fails closed on every call. (#38)
- Value criteria (`per_tx_cap`, `per_period_cap`, `minimum_reserve`,
  `counterparty_allowlist`) now size a call through a typed value descriptor
  derived at the dispatch gate, instead of matching hard-coded tool names. A
  rule that matches a value-moving tool constrains every debit leg it carries
  (classic pay/create, Blend supply/repay, DEX trades, vault deposits, x402
  payments), and per-asset caps aggregate across the legs of a multi-leg call.
  A value rule that matches a call whose value cannot be sized now denies fail closed with `policy.deny.unsizable_value_effect` rather than passing silently. This covers a tool that reached the gate without resolved effects, or a raw signing tool (`stellar_sep43_*`). A rule may
  opt a signing tool back in with `allow_opaque_signing = true`.
  `minimum_reserve` now counts only native-XLM outflow legs; a token-only move
  no longer reduces the native reserve. Operators with existing value rules
  should expect previously-unconstrained value tools to be gated. (#18, #19,
  #20)
- CLI `pay`, `claim`, and `accounts create` (sponsored mode) now evaluate
  operator policy before signing, through the same `PolicyEngine::evaluate`
  path the `trade`/`lend`/`vault`/`trustline` CLI verbs already use and with
  value descriptors identical to their `stellar_pay` / `stellar_claim` /
  `stellar_create_account` MCP twins. Previously these three verbs signed and
  submitted unconditionally, bypassing the engine entirely. All three verbs
  gain a `--profile` flag (default `"default"`). With no persisted profile
  file, an in-memory `Noop`-engine testnet profile is synthesized, so the verbs
  keep working without an authored profile and `policy.engine = "noop"`
  behavior on testnet is unchanged. The gate only bites when `--profile`
  resolves to a
  persisted profile with `policy.engine = "v1"`. `accounts create` Friendbot
  mode is not gated (it debits no wallet funds). (#19)
- CLI `trade`, `lend`, and `vault` now size their policy gate with the same
  value descriptor their `stellar_dex_trade` / `stellar_blend_lend` /
  `stellar_defindex_vault_deposit` / `stellar_defindex_vault_withdraw` MCP
  twins use: each verb builds its value legs from the same parsed inputs it
  submits and evaluates them through `PolicyEngine::evaluate_with_value`, so
  `per_tx_cap` / `per_period_cap` / `minimum_reserve` constrain CLI DeFi debits
  exactly as they constrain the MCP calls. Previously these verbs gated on the
  tool name alone, with `trade` classified read-only, leaving the traded,
  lent, and deposited amounts unconstrained. CLI `trustline` gates through the
  shared args-path descriptor builder; its refusals now carry the shared
  `policy.deny.<code>` / `policy.approval_required` / `policy.unexpected_decision`
  / `policy.engine_required` wire codes instead of the previous
  `trustline.policy_denied.<code>` / `trustline.policy_*` codes (a
  wire-observable parity change). Operators with `policy.engine = "v1"` value
  rules should expect CLI DeFi debits to be gated. (#20)
- Value caps (`per_tx_cap`, `per_period_cap`, `minimum_reserve`, and their
  `bundle_*` variants) and the amount fields of their deny reasons
  (`max_stroops`, `attempted_stroops`, `period_used_stroops`,
  `reserve_required_stroops`, `balance_stroops`) are `i128`: the comparison
  path and the emitted deny-reason amounts are exact across the full `i128`
  range and are no longer clamped to `i64::MAX`, so a cap or an attempted
  single-transaction debit above `i64::MAX` is represented exactly instead of
  saturating. These amounts cross the MCP wire as decimal strings
  (JSON-number-unsafe beyond 2^53); consumers must parse them as `i128` /
  decimal strings rather than `i64`. (The per-period window accumulator's own
  width is covered separately above, (#42).) (#20)
- Breaking (policy file behavior): `counterparty_allowlist`'s `HOME_DOMAIN`
  kind now requires the destination's on-chain `home_domain` to be
  independently VERIFIED through the operator's counterparty cache before the
  allowlist is even consulted. This requires a resolved cache entry for that domain, whose
  cached `stellar.toml` `ACCOUNTS` list names the counterparty account.
  Previously a bare self-asserted `home_domain` match sufficed: any account
  could set `home_domain` to an allowlisted string via `SetOptions` at zero
  cost and pass. Existing `HOME_DOMAIN` rules now deny until the operator
  populates the cache for the domains they allowlist. `stellar-agent
  counterparty warm-up` refreshes every domain already in the policy file's
  `HOME_DOMAIN` allowlists in one pass; `stellar-agent counterparty refresh
  <domain>` refreshes one domain. `G_ACCOUNT` / `C_ACCOUNT` / `KNOWN_ISSUER`
  are unaffected. `CounterpartyCacheView` gains `is_account_listed`
  (default `false`, fail-closed) and `StellarTomlBinding` gains an `accounts`
  field carrying the cached `stellar.toml`'s `ACCOUNTS` G-strkeys. (#49)

### Removed

- Breaking (policy file): the `soroban_resource_fee_cap` criterion. It gated on
  a `stellar_invoke*` tool-name prefix that no registered tool matches, so it
  never constrained a real call. A policy file that references
  `soroban_resource_fee_cap` now fails to load with the unknown-criterion
  error. A future contract-invocation tool should reintroduce a
  descriptor-based resource criterion sized against `ContractInvoke` value
  legs. (#22)
- The remaining hard-coded per-tool arms inside the value criteria. A criterion
  now sizes a call solely from its typed value legs, never from the tool name.
  (#22)

### Fixed

- MCP `stellar_pay_commit`, `stellar_claim_commit`, and
  `stellar_create_account_commit` now supply the source account (and, for
  `stellar_pay_commit`, the destination) as the policy gate's
  `account_view`/`identity_view`, mirroring `stellar_trustline_commit`. So a
  `minimum_reserve` criterion configured on these verbs is actually evaluated
  at commit instead of failing closed on every call, even when the same rule
  passed at simulate. The account fetch each commit path already made for the
  sequence number is reused; no second fetch. `identity_view` stays `None` for
  `stellar_claim_commit` / `stellar_create_account_commit`, matching their
  simulate phases. (#48)
- `ContextRuleManager::check_divergence_for_auth_rule_ids`,
  `deploy_smart_account` (and its five sibling deploy flows:
  `deploy_ed25519_verifier`, `deploy_webauthn_verifier`, `deploy_policy`,
  `deploy_spending_limit_policy`, `deploy_timelock_controller`), and
  `retry_with_backoff` each now enforce a collective wall-clock budget across
  their fixed-count multi-stage RPC sequence, instead of leaving each stage
  bounded only by the transport's own per-call timeout. A `SignersManager`
  divergence check across up to 50 `auth_rule_ids`, a deploy flow's
  fetch/simulate/submit/verify sequence, and a blind-backoff retry loop could
  previously run for up to (stage count) × (transport timeout) with no total
  cap; each now refuses with a "collective budget elapsed" error once its
  budget (the manager's/flow's existing configured timeout) is exhausted.
  `retry_with_backoff` additionally races each attempt against the shared
  deadline, so one hung attempt cannot overshoot the deadline by the
  transport's own bound; a deadline cutoff surfaces as the SAME
  `TransactionSubmissionTimeout` variant the existing poll-timeout path
  returns and is never retried. (#46)
- MCP `stellar_trustline` / `stellar_trustline_commit` and CLI `trustline` now
  supply the source account as the policy gate's `account_view` (previously
  `None`), so a `minimum_reserve` criterion configured on `stellar_trustline`
  is actually evaluated instead of failing closed on every call. The source
  fetch was already made by the existing ordered gate (for the sequence
  number); the policy gate now runs after it. `identity_view` stays `None` on
  this verb: the only counterparty account is the asset issuer, whose on-chain
  `home_domain` is self-asserted. Supplying it to `counterparty_allowlist`
  HOME_DOMAIN matching would let an issuer alias an allowlisted domain. So
  identity-class criteria configured on `stellar_trustline` fail closed by
  design. (#47)
- `approve --id` writes the human-readable approval summary and the y/n prompt
  to stderr; stdout carries exactly one JSON envelope, so
  `approve --id <ID> --yes > out.json` yields parseable JSON with the
  `approval_attestation`, as the output contract documents. Summary field
  lines are consistently indented. (#32)
- `audit verify` no longer doubles the wire-code prefix in error details, and
  a missing primary log file is classified as the actionable
  `audit.log_not_found` validation error instead of an internal error. (#29)
- CLI `pay`, `claim`, and `accounts create` now initialize the platform
  keyring store before reading the owner key on the `policy.engine = "v1"`
  path, so v1 policy evaluation works on a real install (previously failed
  `policy.engine_unavailable` with `NoDefaultStore`). (#41)
- A rule carrying any value-summing bundle cap (`bundle_aggregate_cap`,
  `bundle_per_tx_cap`, or `bundle_per_period_cap`) now implicitly enforces the
  `restrict_bundle_to_recognised_kinds` Generic-rejection check at evaluation
  time, regardless of whether that criterion is configured on the rule or its
  `enabled` value. These caps sum only `TokenTransfer` inners, so a multicall
  bundle containing a `Generic` inner now denies under a cap-only rule instead
  of bypassing the cap. (#23)
- `ContextRuleManager::list_active_context_rules`, Blend's
  `query_oracle_lastprice_timestamps`, and the timelock `list_pending` scan
  each now enforce a collective wall-clock budget across their per-item RPC
  loop, instead of only bounding iteration COUNT. A large scan bound, request
  batch, or scheduling history against a slow RPC endpoint previously had no
  total time cap; each of the three now refuses with a "collective ... budget
  elapsed" message once its budget (the manager's configured `timeout` for
  the rule scan; a fixed constant for the other two) is exhausted, rather
  than continuing to probe for up to iteration-count times the transport's
  60s per-call bound. (#33)
- `cargo build --workspace --tests` (and any bare `cargo test`/`cargo build
  --tests` invocation omitting `--features test-helpers`) no longer fails to
  compile `stellar-agent-approval-remote`: its `test_helpers` module was
  gated on `cfg(any(test, feature = "test-helpers"))`, which let `cfg(test)`
  alone compile the module's `p256` imports without the optional `p256`
  dependency they need (gated solely on the `test-helpers` feature). The
  module is now gated on the feature alone. (#37)
- CLI `pay`, `claim`, and `accounts create` (sponsored) now supply the same
  `account_view` / `identity_view` their MCP twins supply. `pay` supplies a source
  `account_view` plus a destination-derived `identity_view`; `claim` and
  `accounts create` supply a source/sponsor `account_view` only. So a `minimum_reserve`
  or identity-class criterion configured on these verbs is actually evaluated
  instead of failing closed on every call. `trustline` is unchanged: its MCP
  twin supplies no views at all, so the CLI mirrors that exactly. The
  `AccountReservesView` / `AccountIdentityView` bridge adapter
  (`AccountViewAdapter`) moved from `stellar-agent-mcp::policy_adapter` to
  `stellar-agent-network::policy_view` (re-exported from its former path for
  compatibility) so the CLI can use it without a new dependency on the MCP
  crate. (#45)
- `per_period_cap` and `rate_limit` (and their bundle counterparts,
  `bundle_per_period_cap` / `bundle_rate_limit`) now actually accumulate
  across calls: a new HMAC-protected, single-writer, atomically-written
  per-profile window-state store (`<state>/stellar-agent/policy/<profile>.window`,
  keyed by the new `policy_window_state_key_id` profile coordinate) persists
  the rolling-window history that was previously reconstructed empty on every
  invocation, so these criteria evaluated every call against zero history and
  never actually capped anything across calls. `profile rotate-policy-state-key`
  rotates the HMAC key (re-signing the store so history is preserved, not
  invalidated); `profile reset-window-state` recovers from an unreadable,
  tampered, or unparseable store by re-initialising it to empty (audited via
  a new `PolicyWindowStateReset` audit row). The multicall bundle path's
  per-invocation throwaway state store is replaced with the persisted one.
  (#50)
- `stellar_pay` / `stellar_pay_commit` path-payment envelopes
  (`PathPaymentStrictReceive` / `PathPaymentStrictSend`) now size the policy
  gate's debit leg from the SEND side (`send_max` / `send_amount`), not the
  destination side (`dest_amount`). The SEND side is the wallet's actual spendable-balance
  debit. `PathPaymentStrictSend` additionally now uses `send_asset` (not
  `dest_asset`) for the debit's asset. The destination side is still
  surfaced, as a separate non-debit informational leg, so counterparty checks
  continue to see the recipient. (#51)

### Changed

- Breaking (MCP wire): tool business errors now use one uniform result envelope
  `{ ok: false, error: { code, message }, request_id }` with `is_error` set, in
  place of the previous mix of JSON-RPC `ErrorData`, bare `{ error, detail }`
  (SEP-53), and `{ code: "x402.error" }` shapes. Branch on `error.code`. x402
  errors carry per-variant codes (`x402.<reason>`); SEP-53 failures use
  `sep53.keyring_load_failed` / `sep53.sign_failed` / `sep53.verify_failed`; a
  keyring-unavailable nonce mint at simulate time returns `nonce.mint_failed`;
  and a trustline to a clawback-enabled issuer returns the
  `trustline.clawback_opt_in_required` business error instead of an `ok` result.
  Genuine protocol faults (malformed arguments, internal invariants) remain
  JSON-RPC errors. The six `stellar_sep43_*` tools keep the SEP-43 v1.2.1
  `{ code, message }` object (numeric codes) for signing results and their
  protocol, mainnet, and keyring-unlock errors to preserve wire compatibility;
  the one case those tools use the standard envelope is a policy
  `RequireApproval` verdict, refused as `policy.approval_required_unsupported`.
  The SEP-43 sign-and-submit submit-layer mainnet backstop now reports the
  unified `MainnetSigningForbidden` (SEP-43 code -3) instead of the generic
  rpc-error code (-2). (#35)
- Breaking: removed `profile rotate-owner-key`. The policy owner keyring entry
  now holds the owner PUBLIC key that the always-online engine verifies
  against, not the private seed. Enrol the public key with
  `profile enroll-owner-key` and sign policy files with `profile sign-policy`,
  keeping the owner seed offline. Profiles that relied on `rotate-owner-key`
  must re-enrol the owner public key and re-sign their policy files. (#30)

### Changed

- Testnet acceptance CI now provisions a headless Linux Secret Service
  (gnome-keyring under a private D-Bus session) for the CLI's `pay` v1-policy
  acceptance suite, which registers the platform keyring store before its
  policy gate. The suite's self-skip on missing keyring is removed. Keyring init failure now fails the suite instead of silently skipping it. (#52)
- Acceptance-suite environmental-flake hardening, none of it weakening any
  assertion: the shared test-support Friendbot funding helper re-requests
  funding once and re-confirms if the account is still absent after the
  confirm wait; the MCP high-value independent-RPC cross-check retries a
  rebuild FAILURE (not a byte mismatch) up to 3 times over a bounded window
  before treating it as divergence, distinguishing "the independent RPC
  hasn't caught up yet" from "the two RPCs disagree"; and browser-driven
  acceptance suites (WebAuthn, remote-approval, rule-proposal, operator
  enrollment) get one additional retry with a longer cooldown in the
  testnet-acceptance driver script, on top of the universal retry-once
  default. (#53)

### Fixed

- `fund_with_friendbot` (the CLI `friendbot` command, the MCP
  `stellar_friendbot` tool, and `accounts create --fund-with-friendbot`) now
  polls the RPC endpoint until the funded account is actually queryable
  before reporting success, instead of returning as soon as Friendbot's HTTP
  response arrives; a funded account that never becomes visible within the
  bounded window returns the new `network.friendbot_funding_not_confirmed`
  error instead of a premature success. `FriendbotResult` gains
  `funding_confirmed_after_ms`. The MCP server now tracks, per source
  account, the highest sequence number a confirmed submit in this process
  consumed; when a build-time account fetch observes a sequence below that
  floor, it re-polls within a bounded window before proceeding, removing
  avoidable read-after-write propagation lag on the `stellar_pay_commit` /
  `stellar_claim_commit` / `stellar_trustline_commit` /
  `stellar_create_account_commit` build paths (and their simulate-phase
  twins). Neither mitigation invents a sequence number or blocks
  indefinitely: a genuinely stale build still fails typed
  `submission.sequence_number_stale` exactly as before. (#54)

## [0.1.0-alpha.2] - 2026-07-07

### Added

- Remote operator approval: `approve serve --remote` binds a TLS-protected,
  passkey-authenticated listener so an operator can approve or reject pending
  wallet actions from another device, with per-entry WebAuthn assertions on
  every decision.
- Bounded agent delegation: context rules can be scoped to a single contract
  (`--context call-contract:<C>`) or wasm hash, first-class External-Ed25519
  signers attach to rules via a registered verifier, and a spending-limit
  policy enforces a per-rule rolling-window budget on-chain.
- Spending-limit observability and retuning: `smart-account rules
  get-spending-limit` reads an installed policy's live budget state,
  `set-spending-limit` retunes the limit without resetting spend history, and
  the read-only MCP tools `stellar_rules_list` / `stellar_rules_get` expose
  rule and budget state to agents.
- Agent-proposed context rules: the two-phase `stellar_rule_create` /
  `stellar_rule_create_commit` MCP pair routes rule installation through the
  operator-approval spine, with the fully resolved rule rendered on every
  approval surface before consent and the proposal digest bound into the
  attestation.
- Smart-account ergonomics: typed simple-threshold and weighted-threshold
  policy builders, a unified `deploy-policy --kind` verb, weighted-threshold
  mutators (`set-weighted-threshold`, `set-signer-weight`), batch signer
  addition, passkey/Ed25519/external genesis signers on `accounts deploy-c`,
  and new rule/signer read APIs.
- Interactive WebAuthn operator enrollment: `approve operator enroll
  --interactive` runs the passkey registration ceremony in the browser against
  a one-shot loopback server (bootstrap-token gated) and persists the
  credential without it passing through the shell; the argument mode remains
  the import path for credentials created on a remote listener's domain.
- `smart-account execute`: submit a CallContract invocation against an
  external contract, authorized by named context rules and signed by an
  External-Ed25519 rule key, with a separate fee-paying envelope signer.
  `rules create` gains `--signer-ed25519` / `--verifier` so an Ed25519-only
  rule can be installed entirely from the CLI.
- A provisional audit status in the verifier allowlist taxonomy: the vendored
  OpenZeppelin verifier entries now report `provisional` (named-party internal
  review) rather than overstating an external audit; `list-verifiers` carries
  the attestor and date as additive fields.

### Changed

- Value-denominated fields on the machine-readable JSON wire are decimal
  strings, never JSON numbers: all i128 token quantities (dex, blend, vault,
  spending-limit budgets) and the residual i64/u64 stroop and fee fields
  (payment, account-creation, claim, trustline amounts and limits, fee-stats
  percentiles, served approval summaries). Raw JSON numbers on the migrated
  input fields are rejected. This is a breaking wire change; JSON numbers are
  exact only up to 2^53 in f64-backed parsers, and trustline limits routinely
  carry i64::MAX. The policy cap and reserve criteria now read the resolved
  stroop amounts on every dispatch shape, and pay's simulate gate arguments
  include the asset, so cap and reserve policies evaluate calls they
  previously refused or under-counted.
- Every CLI secret-env signing path handles the seed through an
  mlock-protected unlock window with explicit residue zeroization; when mlock
  is unavailable and the profile policy allows degraded operation, the
  degradation is recorded in the audit log as a `wallet_mlock_failed` event.
- Renamed the `wallet` CLI command group to `smart-account` (with `sa` as a
  shorter alias), and flattened the former nested `sa` admin subgroup so its
  verbs (`deploy-webauthn-verifier`, `migrate-verifier`, `list-verifiers`,
  `list-rules`, `register-multicall`, `unregister-multicall`, `timelock`) are now
  direct children of `smart-account` alongside `rules`, `signers`, and
  `multicall`. This is a breaking change to the CLI command surface.
- Bumped the vendored OpenZeppelin `stellar-accounts` and `stellar-governance`
  dependencies from `0.7.1` to `0.7.2` (a `soroban_sdk` 26.1.0 fix upstream, no
  entrypoint or ABI changes) and rebuilt all five vendored OZ WASM artifacts at
  the new tag. New smart-account, threshold-policy, timelock-controller, and
  WebAuthn-verifier deployments now use the `0.7.2` artifacts. Verifier and
  threshold-policy contracts already deployed from the `0.7.1` artifacts remain
  recognized and valid; nothing on-chain is redeployed.

## [0.1.0-alpha.1] - 2026-07-03

First public alpha of the Stellar Agent Wallet: a Stellar wallet for AI agents.
It provides a `stellar-agent` CLI and a `stellar-agent-mcp` MCP server over a shared
policy engine, operator-approval spine, and tamper-evident audit log.

### Added

- `stellar-agent` CLI for accounts, payments, balances, trustlines,
  claimable-balance claims, Friendbot funding, fee stats, counterparty identity,
  smart-account governance, DeFi, the channel-account pool, profiles,
  credentials, approvals, audit verification, and agent toolsets.
- `stellar-agent-mcp` MCP stdio server exposing the wallet capabilities as tools
  to an MCP client. It starts on hosts without an OS keyring backend (for example
  headless servers), serving read-only and simulate tools; signing tools are
  refused with a keyring error until a backend is configured.
- Policy engine with a no-op gate and a typed first-match, default-deny V1 engine
  evaluating each action to allow, deny, or require operator approval.
- Operator-approval spine: a per-profile pending-approval store and an
  HMAC attestation binding each approval to the executed envelope and the
  approving OS user.
- Hash-chained, append-only JSONL audit log that records key names only (never
  argument values), with `audit verify` chain and HMAC-sidecar verification.
- Key custody via the platform keyring with a TTL-bounded, zeroize-on-drop,
  memory-locked unlock window; profiles name keyring entries and hold no secrets.
- OpenZeppelin smart-account governance: context rules, ed25519 and WebAuthn
  passkey signers, quorum, verifier/policy WASM-hash pinning, multicall, and an
  upgrade timelock.
- DeFi adapters: Blend lending (`lend`), Soroswap swaps (`trade`/`quote`), and
  DeFindex vaults (`vault`), each with venue pinning and fail-closed guardrails.
- Protocol support: SEP-7, SEP-10, SEP-24 and SEP-6, SEP-43, SEP-45, SEP-47,
  SEP-48, and SEP-53.
- Operator approval inbox: `approve list` enumerates pending approvals with
  their wallet-controlled summaries, and `approve serve` runs a loopback-only
  web inbox that lists pending approvals live, notifies the operator, and
  approves (minting the same attestation as `approve --id`) or rejects.
  Rejection records a short-lived marker so the agent's commit is refused
  with `policy.approval_rejected` instead of waiting out the TTL. Session
  bootstrap is a single-use URL token exchanged for an HttpOnly cookie;
  actions require a per-session CSRF header. Approvals now emit audit
  events from both the terminal and inbox surfaces. For a remote agent
  host, the inbox is reached through an SSH port-forward; the approving
  user must be the wallet's OS user.
- Claimable-balance claims by ID (CLI `claim`, MCP `stellar_claim` /
  `stellar_claim_commit` two-phase pair): RPC-backed preview with claimant,
  predicate, clawback, and trustline pre-flight guards. Balance IDs are taken
  as 72-hex, bare 64-hex, or `B...` strkey; listing balances by claimant is a
  Horizon-only query and stays out of scope for the RPC-only wallet.
- x402 v2 Exact Stellar agent payments with an optional SEP-10 counterparty
  identity gate.
- Signed agent toolsets with capability isolation, publisher-signature verification,
  a first-invoke gate, and unconditional per-action approval for toolset-routed
  payments.
- `approve` returns the `approval_attestation` for a payment approval so the agent
  surface can present it to the matching `*_commit` tool, completing the
  simulate-approve-commit flow over MCP.
- An agent knowledge skill under `skills/` (agentskills.io format, with a Claude
  Code marketplace plugin and a downloadable archive) that teaches an AI agent to
  operate the wallet's CLI and MCP server without cloning the repository.
- An agent integration guide (`docs/agents.md`) and capability-isolation example
  toolsets under `examples/toolsets/`.

[Unreleased]: https://github.com/Soneso/stellar-agent-wallet/compare/v0.1.0-alpha.11...HEAD
[0.1.0-alpha.11]: https://github.com/Soneso/stellar-agent-wallet/compare/v0.1.0-alpha.10...v0.1.0-alpha.11
[0.1.0-alpha.10]: https://github.com/Soneso/stellar-agent-wallet/compare/v0.1.0-alpha.9...v0.1.0-alpha.10
[0.1.0-alpha.9]: https://github.com/Soneso/stellar-agent-wallet/compare/v0.1.0-alpha.8...v0.1.0-alpha.9
[0.1.0-alpha.8]: https://github.com/Soneso/stellar-agent-wallet/compare/v0.1.0-alpha.7...v0.1.0-alpha.8
[0.1.0-alpha.7]: https://github.com/Soneso/stellar-agent-wallet/compare/v0.1.0-alpha.6...v0.1.0-alpha.7
[0.1.0-alpha.6]: https://github.com/Soneso/stellar-agent-wallet/compare/v0.1.0-alpha.5...v0.1.0-alpha.6
[0.1.0-alpha.5]: https://github.com/Soneso/stellar-agent-wallet/compare/v0.1.0-alpha.4...v0.1.0-alpha.5
[0.1.0-alpha.4]: https://github.com/Soneso/stellar-agent-wallet/compare/v0.1.0-alpha.3...v0.1.0-alpha.4
[0.1.0-alpha.3]: https://github.com/Soneso/stellar-agent-wallet/compare/v0.1.0-alpha.2...v0.1.0-alpha.3
[0.1.0-alpha.2]: https://github.com/Soneso/stellar-agent-wallet/compare/v0.1.0-alpha.1...v0.1.0-alpha.2
[0.1.0-alpha.1]: https://github.com/Soneso/stellar-agent-wallet/releases/tag/v0.1.0-alpha.1
