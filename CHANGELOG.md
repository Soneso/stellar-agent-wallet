# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- The approval pages neutralise bidirectional and invisible-format code points
  in every rendered value: U+061C, U+200B-200F, U+202A-202E, U+2066-2069, and
  U+FEFF become U+FFFD before HTML escaping. A memo or asset code carrying
  U+202E reverses the rendering of everything after it, so an operator could
  read a different destination or amount than the one being signed while the
  page stayed well-formed.
- Both approval surfaces branch on the decision response's HTTP status. A
  refused decision — a rejected passkey assertion, a stale CSRF value, an entry
  already resolved — rendered as "Status: unknown" and could be read as
  success; it now renders in its own refusal treatment and states that nothing
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
  `policy_owner_key_id.service`, and which profile that names — but NOT the
  per-profile-state consequence or the recovery text, because both differ
  between the two binaries. Callers that relied on `to_string()` for the full
  refusal, including the recovery sentence, call
  `message(ProfileStateLayout::DerivedThroughout)` to get the previous
  `stellar-agent-mcp` wording.
- `stellar-agent-mcp` now selects its profile per invocation. It accepts
  `--profile <NAME>` and `--profile=<NAME>`, and honours `STELLAR_AGENT_PROFILE`
  when the flag is absent, resolving flag > environment > `default` — the order
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
  breaking — an exhaustive `match` on it downstream needs one new arm.
- The operator-facing web pages now render the project's visual design: the
  WebAuthn bridge's registration and approval pages, the approval inbox and
  detail pages, the operator-enrollment page, and the remote-approval sign-in,
  enrollment, inbox, detail, and message pages. `stellar-agent-loopback-http`
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
  `html_escape` — the one escaping definition every served page now applies,
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
  A `<name>.toml` copied or renamed from another profile used to load: the
  signed policy file and the owner-key keyring entry resolve through the name
  the FILE carries, while the pending-approval store, the audit log, and the
  policy-window state key on the name the operator ASKED for, so the run was
  governed by one profile's policy and accounted against another's state — and
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
  synthesised permissive profile. Naming a profile that does not exist — a
  mistyped `--profile`, or a stale `STELLAR_AGENT_PROFILE` in a shell rc or a
  CI job — used to substitute the in-memory zero-config profile, which is a
  testnet, `noop`-engine configuration with no policy gate, and the run signed
  and submitted under it. The substitution is now keyed on where the name came
  from, not on the name: it fires only when no profile was named at all, so the
  documented zero-config quickstart is unchanged, and `--profile default` on a
  host with no `default.toml` refuses like any other named profile. The same
  rule governs the smart-account audit-writer surface. These three verbs also
  gained `STELLAR_AGENT_PROFILE` resolution in this change — deliberately in
  the same commit as the refusal, since honouring the variable without it would
  have widened the substitution rather than closing it. Closes #112.

### Fixed

- MPP read verbs no longer report a profile with no MPP history as a broken
  store. `mpp authorization status` on a profile that has never prepared a
  charge answers `mpp.authorization_not_found`, and `mpp state prune` succeeds
  with `pruned: 0` while still recording the maintenance request and its reason
  digest in the audit log. The state key is minted only on the prepare path, so
  every read verb refused with `mpp.state_unavailable` until the first charge —
  indistinguishable from a genuinely unreadable store. A store that exists
  without a usable key still fails closed: only the provable never-minted state
  (no key and no state file) reads as first run, so deleting or rotating the
  key cannot reset replay protection. Closes #106.
- An MPP read against a store whose key is minted but whose first record was
  never written — the state a prepare denied by policy leaves behind — reported
  `mpp.state_unavailable` because the store directory did not exist yet. Lock
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
  read now selects the requested name's file — the one both write paths
  (`record_confirmed_window_state`, `record_authorized_window_state`) already
  use and the one `profile reset-window-state` resets — and the hint names that
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
  `STELLAR_AGENT_PROFILE`, so under that variable the advisory read — and
  appended its advisory rows to — one profile's log while the command operated
  on another's. Closes #108.
- Profile names are validated as filesystem path components inside the profile
  loader, before the path is built, on both the read and the write half. A name
  carrying `..`, a path separator, or a control character is refused with a
  typed error instead of being joined into a path. The guard previously sat at
  individual call sites, so subcommands that did not call it — `profile show`,
  `pool list`, `pool init`, `counterparty refresh`, `counterparty list`,
  `approve serve`, `audit verify`, `fees stats`, `mpp`, and
  `profile rotate-audit-key` among them — reached the loader with an unvalidated
  operator-supplied name.
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
  reduces the name the way Windows does — cut at the first `.`, then drop
  trailing spaces — so `NUL.toml`, `nul `, and `nul .toml` are all refused, while
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
  `stellar-agent-owner-<new-name>` — a `v1` profile then also needs `profile
  enroll-owner-key` and `profile sign-policy` re-run under the new name, because
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
  required — and required to be `https://` — for `--network mainnet` (the
  built-in mainnet default requires an API key and answers HTTP 401
  unauthenticated, so persisting it would mint a broken configuration);
  mainnet without `--rpc-url` is refused with
  `validation.mainnet_rpc_url_required`, and a plaintext mainnet endpoint
  with `validation.config_invalid`. Refuses without writing or modifying
  anything if the named profile already exists
  (`validation.profile_already_exists`); the write itself is no-clobber, so a
  file appearing concurrently is never overwritten. Mints no key material and
  emits no audit row; docs and the MCP server's first-run guidance, which
  already referenced this command, now match an implemented one.
- Every `profile` subcommand now accepts a `--profile <NAME>` flag. `show`,
  `migrate`, the `rotate-*` subcommands, and `reset-window-state` — which
  previously took only a positional `<NAME>` — now accept either the positional
  `<NAME>` or `--profile <NAME>` (exactly one; supplying both, or neither, is a
  usage error), so a single profile-naming convention works across the group.
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
  action proceeded unaudited — silently, with no `value_action_submitted`
  row, and `lend`/`vault` had no pre-flight or audit row at all. `profile
  init` mints the audit-log keyring coordinate only, no key material, so an
  init-minted profile now requires `stellar-agent profile rotate-audit-key
  <name>` before any of these verbs will sign or submit, on both policy
  engines; `next_steps` in the `profile init` success payload names it,
  right after `enroll-signer`. This pre-flight fails closed only for a
  persisted `<name>.toml` profile: `pay`, `claim`, and `accounts create`
  keep their documented zero-config posture — the in-memory profile
  synthesized when no profile file exists stays fail-open on this specific
  check, so the no-setup quickstart is unaffected. The post-confirm
  `value_action_submitted` emission itself stays non-fatal — the transaction
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
  flag. The flag could never lead to a successful submit — the network layer
  forbids mainnet writes unconditionally in this alpha — so the command now
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
  and the MCP server's owner-key read now surface the precise cause — most
  importantly `auth.keyring_interactive_session_required` for a
  non-interactive Windows session — while key absence still maps to
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
  loader, and the v1 migration, instead of a host-global `audit.log` shared
  by every profile on the machine — hash-chained logs from unrelated
  profiles no longer interleave. Explicit `audit_log_path` values are
  unchanged. The test-gated `STELLAR_AGENT_HOME` override now reaches every
  canonical-data-root-derived path, including the audit directory.
- Every audit-writer acquisition now registers the profile's configured
  `audit_log_path` under the profile's audit chain-root key discipline.
  `stellar_rule_create`/`stellar_rule_create_commit` and the smart-account,
  approve, and timelock command families previously registered a
  name-derived default path with no HMAC key; the first such open pinned the
  process-lifetime writer-registry entry and bricked every later keyed open
  for the same profile name, and rows written unkeyed fell outside
  `stellar-agent audit verify` coverage. For a persisted profile, every
  audit-writing signing verb in these families — `smart-account execute`,
  `smart-account multicall`, the timelock `schedule`/`execute`/`cancel`
  commands, the rules write path, `migrate-verifier`'s submit path,
  `approve serve`, `rule_create`, and `pool init` — now fails closed
  (`audit.chain_key_unavailable` until `profile rotate-audit-key` mints the
  chain key). Read-only surfaces (`list-rules`, `timelock list-pending`,
  `rules get-spending-limit`, `migrate-verifier --dry-run`), `approve run`'s
  post-approval emission, and the local multicall registry commands
  (`register-multicall`, `unregister-multicall`) stay best-effort: they
  degrade with a warning, but their acquisition now goes through the same
  keyed-first discipline, so a failure never poisons the registry. The
  zero-config synthesized testnet profile keeps its quickstart behavior.
  Source-scan tests pin the discipline in both the CLI and the MCP server.
- The SEP-43 sign-only pair (`stellar_sep43_sign_transaction`,
  `stellar_sep43_sign_auth_entry`) now proves the audit writer acquirable
  before signing and records an `opaque_payload_signed` audit row — the
  redacted payload digest and redacted signer address, never the signature
  or payload — at the point the signature is produced. The caller broadcasts
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
  including a second handle opened by the SAME process — unlike POSIX
  advisory locks, which never restrict I/O through a different descriptor.
  Re-opening a non-empty audit log (the common case once a profile has any
  history) failed with `ERROR_ACCESS_DENIED`, surfaced through the smart-account
  MCP flow as a misattributed `"networks.toml I/O error"` at the audit path.
  `AuditWriter` now locks a sidecar file (`<log>.lock`) instead of the log
  itself — the log file carries no OS lock on any platform — and keeps a
  single handle for every read and write against the active log. Adds
  `SaError::AuditWriterIo` so an audit-writer-open failure is attributed to
  the audit subsystem rather than the networks-registry subsystem. Adds a
  `windows-storage` CI job running the audit-log and touched-crate tests on
  `windows-latest`. (#59)
- Windows: audit-log READERS (`audit verify`, the `find_*` state scans) failed
  wholesale — and one blocked indefinitely — while any writer was alive,
  because the writer's exclusive lock lived on the log file itself and
  Windows enforces such a lock against reads through every other handle. With
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
  (toolset first-invoke grants) durably persist a write by renaming a temp
  file into place, then opening the PARENT DIRECTORY as a file to fsync it —
  a POSIX idiom. `std::fs::File::open` on a directory path requires
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
  contract — one envelope shape, one dotted-code taxonomy — now holds across
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
  keyring is unavailable or unusable — a Windows service, an SSH/WinRM
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
  When `true`, `KNOWN_ISSUER` evaluates every leg of the descriptor — debit
  and inflow alike — instead of debit legs only, so tokens received from an
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
- The six key-writing profile commands — `enroll-signer`, `enroll-owner-key`,
  `rotate-nonce-key`, `rotate-attestation-key`, `rotate-counterparty-key`, and
  `rotate-audit-key` — now write a `keyring_key_written` audit row recording the
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
  evaluates the decoded amount/asset/destination — sizing comes from the
  envelope, not caller-supplied args. `--submit-only` gates even though the
  envelope arrives pre-signed, because broadcasting still spends funds. An
  envelope the decoder cannot classify into a sized shape follows the
  opaque-signing posture: denies `policy.deny.unsizable_value_effect` under a
  matched value rule unless it sets `allow_opaque_signing = true`, mirroring
  the `stellar_sep43_*` tools' posture. `policy.engine = "noop"` is unaffected
  — the staged flows remain ungated there, as before. The staged flows
  match policy rules under the `stellar_pay_commit` / `stellar_claim_commit`
  tool names (the same names the MCP commit phase matches), not `stellar_pay`
  / `stellar_claim`: a ruleset that names only the base tools default-denies
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
  A value rule that matches a call whose value cannot be sized — a tool that
  reached the gate without resolved effects, or a raw signing tool
  (`stellar_sep43_*`) — now denies fail-closed with
  `policy.deny.unsizable_value_effect` rather than passing silently. A rule may
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
  tool name alone — with `trade` classified read-only — leaving the traded,
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
  allowlist is even consulted — a resolved cache entry for that domain, whose
  cached `stellar.toml` `ACCOUNTS` list names the counterparty account.
  Previously a bare self-asserted `home_domain` match sufficed: any account
  could set `home_domain` to an allowlisted string via `SetOptions` at zero
  cost and pass. Existing `HOME_DOMAIN` rules now deny until the operator
  populates the cache for the domains they allowlist — `stellar-agent
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
  `account_view`/`identity_view` — mirroring `stellar_trustline_commit` — so a
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
  `home_domain` is self-asserted — supplying it to `counterparty_allowlist`
  HOME_DOMAIN matching would let an issuer alias an allowlisted domain, so
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
  `account_view` / `identity_view` their MCP twins supply — `pay` a source
  `account_view` plus a destination-derived `identity_view`; `claim` and
  `accounts create` a source/sponsor `account_view` only — so a `minimum_reserve`
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
  destination side (`dest_amount`) — the wallet's actual spendable-balance
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
  policy gate; the suite's self-skip on missing keyring is removed — keyring
  init failure now fails the suite instead of silently skipping it. (#52)
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

[Unreleased]: https://github.com/Soneso/stellar-agent-wallet/compare/v0.1.0-alpha.5...HEAD
[0.1.0-alpha.5]: https://github.com/Soneso/stellar-agent-wallet/compare/v0.1.0-alpha.4...v0.1.0-alpha.5
[0.1.0-alpha.4]: https://github.com/Soneso/stellar-agent-wallet/compare/v0.1.0-alpha.3...v0.1.0-alpha.4
[0.1.0-alpha.3]: https://github.com/Soneso/stellar-agent-wallet/compare/v0.1.0-alpha.2...v0.1.0-alpha.3
[0.1.0-alpha.2]: https://github.com/Soneso/stellar-agent-wallet/compare/v0.1.0-alpha.1...v0.1.0-alpha.2
[0.1.0-alpha.1]: https://github.com/Soneso/stellar-agent-wallet/releases/tag/v0.1.0-alpha.1
