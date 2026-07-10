//! Profile configuration schema — version 2.
//!
//! The [`Profile`] struct is the single source of truth for per-profile
//! configuration.  It is loaded by [`super::loader`], migrated by
//! [`super::migrate`], and consumed by the MCP server, CLI commands, and the
//! policy engine.
//!
//! # Schema versioning
//!
//! Every profile TOML carries a top-level `version` field.  The loader
//! dispatches on this field so old wallets reading new profiles fail fast with
//! `ProfileLoadError::VersionUnsupported` rather than silently
//! using defaults.
//!
//! Supported versions:
//! - `1` — baseline schema (no security substrate fields).
//! - `2` — current schema: adds `audit_log_hash_chain_key_id`,
//!   `policy_owner_key_id`, `attestation_key_id`, `counterparty_cache_key_id`,
//!   `oracle_provider_url`, `policy.engine`, the optional
//!   `classic_fee_per_op_stroops` classic-operation fee override, and
//!   `classic_max_fee_per_op_stroops` optional fee cap.
//!
//! # Secret-material discipline
//!
//! The profile TOML **never** holds secret material.  The nonce key, signer
//! seed, and all HMAC keys live in the platform keyring (macOS Keychain /
//! Linux Secret Service / Windows Credential Manager).
//! [`KeyringEntryRef`] is an opaque reference (`service` + `account`) used to
//! look up those entries.  The lookup itself happens in
//! `stellar-agent-network::keyring`.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use url::Url;

use super::caip2::Caip2;

// ─────────────────────────────────────────────────────────────────────────────
// MINIMUM_FLOOR
// ─────────────────────────────────────────────────────────────────────────────

/// Minimum effective USD threshold, expressed in XLM-equivalent stroops.
///
/// Represents 1 000 XLM × 10 000 000 stroops/XLM = 10 000 000 000 stroops.
///
/// The resolver caps the effective threshold at
/// `max(profile.usd_threshold, MINIMUM_FLOOR)` regardless of the profile
/// value.  A profile with `usd_threshold = 0` therefore behaves as if it had
/// `usd_threshold = MINIMUM_FLOOR`.
///
/// The floor ensures an agent cannot be configured to permit all operations
/// without a meaningful threshold check.  1 000 XLM equivalent is a
/// conservative constant.
///
/// # Security note
///
/// The high-value independent-RPC cross-check fires when
/// `value_stroops >= effective_usd_threshold()`.  The constant is
/// `10_000_000_000` (10^10 stroops = 1 000 XLM).
pub const MINIMUM_FLOOR: u64 = 10_000_000_000; // 1 000 XLM in stroops

// Compile-time assertion: locks MINIMUM_FLOOR to the correct value so that an
// accidental change to the constant fails the build immediately rather than
// silently raising the cross-check threshold and making it unreachable.
const _: () = {
    assert!(
        MINIMUM_FLOOR == 10_000_000_000,
        "MINIMUM_FLOOR must equal 1 000 XLM in stroops (10^10)"
    );
};

// ─────────────────────────────────────────────────────────────────────────────
// KeyringEntryRef
// ─────────────────────────────────────────────────────────────────────────────

/// Opaque reference to a platform-keyring entry.
///
/// Holds the `service` + `account` pair used to look up a secret from the
/// platform keyring (macOS Keychain, Linux Secret Service, Windows Credential
/// Manager).  The actual lookup is performed by
/// `stellar-agent-network::keyring::load_entry`.
///
/// **Never** includes the secret itself — only the addressing coordinates.
/// This type is safe to persist in the profile TOML.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::profile::schema::KeyringEntryRef;
///
/// let entry = KeyringEntryRef::new("stellar-agent-signer", "my-profile-default");
/// assert_eq!(entry.service, "stellar-agent-signer");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct KeyringEntryRef {
    /// Keyring service name (e.g. `"stellar-agent-signer-my-profile"`).
    pub service: String,
    /// Keyring account name (e.g. `"default"` or a G-strkey public key).
    pub account: String,
}

impl KeyringEntryRef {
    /// Constructs a new keyring entry reference.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::profile::schema::KeyringEntryRef;
    ///
    /// let r = KeyringEntryRef::new("stellar-agent-signer", "alice");
    /// assert_eq!(r.service, "stellar-agent-signer");
    /// assert_eq!(r.account, "alice");
    /// ```
    #[must_use]
    pub fn new(service: impl Into<String>, account: impl Into<String>) -> Self {
        Self {
            service: service.into(),
            account: account.into(),
        }
    }

    /// Constructs the default audit-key keyring entry reference for a profile.
    ///
    /// Entry name: `stellar-agent-audit-<profile>` / `default`.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::profile::schema::KeyringEntryRef;
    ///
    /// let r = KeyringEntryRef::default_audit_key("alice");
    /// assert_eq!(r.service, "stellar-agent-audit-alice");
    /// assert_eq!(r.account, "default");
    /// ```
    #[must_use]
    pub fn default_audit_key(profile_name: &str) -> Self {
        Self::new(format!("stellar-agent-audit-{profile_name}"), "default")
    }

    /// Constructs the default owner-key keyring entry reference for a profile.
    ///
    /// Entry name: `stellar-agent-owner-<profile>` / `default`.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::profile::schema::KeyringEntryRef;
    ///
    /// let r = KeyringEntryRef::default_owner_key("alice");
    /// assert_eq!(r.service, "stellar-agent-owner-alice");
    /// assert_eq!(r.account, "default");
    /// ```
    #[must_use]
    pub fn default_owner_key(profile_name: &str) -> Self {
        Self::new(format!("stellar-agent-owner-{profile_name}"), "default")
    }

    /// Constructs the default attestation-key keyring entry reference for a
    /// profile.
    ///
    /// Entry name: `stellar-agent-attestation-<profile>` / `default`.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::profile::schema::KeyringEntryRef;
    ///
    /// let r = KeyringEntryRef::default_attestation_key("alice");
    /// assert_eq!(r.service, "stellar-agent-attestation-alice");
    /// assert_eq!(r.account, "default");
    /// ```
    #[must_use]
    pub fn default_attestation_key(profile_name: &str) -> Self {
        Self::new(
            format!("stellar-agent-attestation-{profile_name}"),
            "default",
        )
    }

    /// Constructs the default pool-master-key keyring entry reference for a
    /// profile.
    ///
    /// Entry name: `stellar-agent-pool-<profile>` / `"master"`.
    ///
    /// The pool master BIP-39 seed lives in the OS keyring under this entry.
    /// Channel private keys are re-derived from it + index at runtime.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::profile::schema::KeyringEntryRef;
    ///
    /// let r = KeyringEntryRef::default_pool_master_key("alice");
    /// assert_eq!(r.service, "stellar-agent-pool-alice");
    /// assert_eq!(r.account, "master");
    /// ```
    #[must_use]
    pub fn default_pool_master_key(profile_name: &str) -> Self {
        Self::new(format!("stellar-agent-pool-{profile_name}"), "master")
    }

    /// Constructs the default counterparty-cache-key keyring entry reference
    /// for a profile.
    ///
    /// Entry name: `stellar-agent-counterparty-<profile>` / `default`.
    ///
    /// Used for the `stellar.toml` cache-integrity HMAC.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::profile::schema::KeyringEntryRef;
    ///
    /// let r = KeyringEntryRef::default_counterparty_key("alice");
    /// assert_eq!(r.service, "stellar-agent-counterparty-alice");
    /// assert_eq!(r.account, "default");
    /// ```
    #[must_use]
    pub fn default_counterparty_key(profile_name: &str) -> Self {
        Self::new(
            format!("stellar-agent-counterparty-{profile_name}"),
            "default",
        )
    }

    /// Constructs the default policy-window-state HMAC key keyring entry
    /// reference for a profile.
    ///
    /// Entry name: `stellar-agent-policy-window-<profile>` / `default`.
    ///
    /// Used to authenticate the persisted per-profile sliding-window store
    /// (`per_period_cap` / `rate_limit` / `bundle_per_period_cap` /
    /// `bundle_rate_limit` accumulated history) against post-write local
    /// tampering.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::profile::schema::KeyringEntryRef;
    ///
    /// let r = KeyringEntryRef::default_policy_window_state_key("alice");
    /// assert_eq!(r.service, "stellar-agent-policy-window-alice");
    /// assert_eq!(r.account, "default");
    /// ```
    #[must_use]
    pub fn default_policy_window_state_key(profile_name: &str) -> Self {
        Self::new(
            format!("stellar-agent-policy-window-{profile_name}"),
            "default",
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PolicyEngineKind
// ─────────────────────────────────────────────────────────────────────────────

/// Selects which policy-engine implementation is active for a profile.
///
/// Newly-minted profiles default to `V1` (the typed-criteria engine).
/// Profiles migrated from schema version 1 have `engine = "noop"` set
/// explicitly by `migrate_v1_to_v2` so that existing wallets retain the
/// mainnet gate until the operator completes the `enroll-owner-key`,
/// `rotate-attestation-key`, and `rotate-audit-key` sequence.  The asymmetry
/// is intentional: new profiles are minted with the policy-engine
/// infrastructure already in place; migrated profiles require an explicit
/// operator opt-in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum PolicyEngineKind {
    /// No-op policy engine — refuses all mainnet destructive operations.
    ///
    /// Assigned explicitly by `migrate_v1_to_v2` so that profiles migrated
    /// from schema v1 retain the mainnet gate until the operator opts in to V1
    /// by completing the rotate-key ceremony.
    ///
    /// **This variant is NOT the `Default`.**  New profiles created via
    /// `Profile::builder_testnet` / `Profile::builder_mainnet` receive `V1`.
    Noop,

    /// V1 typed-criteria policy engine.
    ///
    /// Default for newly-minted profiles.  The `PolicyEngineV1` evaluates a
    /// signed `PolicyDocument` against typed criteria before permitting any
    /// destructive tool on mainnet.
    ///
    /// Operators set `[policy]\nengine = "v1"` explicitly in migrated profiles
    /// after completing the `enroll-owner-key`, `rotate-attestation-key`, and
    /// `rotate-audit-key` runbook steps.
    #[default]
    V1,
}

// ─────────────────────────────────────────────────────────────────────────────
// PolicyConfig
// ─────────────────────────────────────────────────────────────────────────────

/// Per-profile policy-engine configuration.
///
/// Embedded as `[policy]` in the profile TOML.  The full `PolicyEngineV1`
/// configuration (typed criteria, rules, scope) lives in a separate
/// `~/.local/share/stellar-agent/policies/` TOML file; only the engine
/// selector is held here.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub struct PolicyConfig {
    /// Active policy engine for this profile.
    ///
    /// Default for newly-minted profiles is `V1`.  Profiles migrated from
    /// schema v1 have `Noop` set explicitly by `migrate_v1_to_v2`; they
    /// retain the mainnet gate until the operator opts in by completing the
    /// rotate-key ceremony.
    #[serde(default)]
    pub engine: PolicyEngineKind,
}

// ─────────────────────────────────────────────────────────────────────────────
// WalletConfig
// ─────────────────────────────────────────────────────────────────────────────

/// Per-profile short-in-memory-unlock-window configuration.
///
/// Embedded as `[wallet]` in the profile TOML.  Controls the [`Wallet`]
/// substrate's `mlock(2)` posture and unlock-window TTL.
///
/// [`Wallet`]: crate::wallet::Wallet
///
/// # TOML shape
///
/// ```toml
/// [wallet]
/// mlock_required = true       # default on Linux/macOS; "warn" on Windows
/// unlock_ttl_seconds = 30     # default; any value in (0, 600] is accepted
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct WalletConfig {
    /// `mlock(2)` failure posture — see [`crate::wallet::MlockRequired`].
    ///
    /// Linux/macOS default to `True` (fail-closed); Windows defaults to
    /// `Warn` (degraded-but-operable).  Operators opting out of memory
    /// pinning accept the residual swap-disclosure risk.
    #[serde(default)]
    pub mlock_required: crate::wallet::MlockRequired,

    /// Unlock-window TTL in seconds.  Default: 30.
    ///
    /// The wallet handle is held for at most this many seconds across
    /// approval + sign + submit; on TTL fire the seed is zeroized and
    /// the next sign attempt re-loads from the keyring.
    ///
    /// Passed directly to [`crate::wallet::Wallet::unlock`], which enforces
    /// `(0, MAX_TTL_SECONDS]` (`MAX_TTL_SECONDS` = 600 seconds): a value of
    /// `0` or greater than 600 is refused at unlock time rather than
    /// silently clamped.
    #[serde(default = "default_unlock_ttl_seconds")]
    pub unlock_ttl_seconds: u32,
}

impl Default for WalletConfig {
    fn default() -> Self {
        Self {
            mlock_required: crate::wallet::MlockRequired::default(),
            unlock_ttl_seconds: default_unlock_ttl_seconds(),
        }
    }
}

/// Default TTL for the short-in-memory-unlock window: 30 seconds.
///
/// The cap is enforced at handle-construction time.
#[must_use]
const fn default_unlock_ttl_seconds() -> u32 {
    30
}

// ─────────────────────────────────────────────────────────────────────────────
// Profile
// ─────────────────────────────────────────────────────────────────────────────

/// Per-profile wallet configuration (schema version 2).
///
/// Every profile maps a CAIP-2 chain ID to an RPC URL, network passphrase,
/// signer keyring reference, nonce-key keyring reference, and behavioural
/// thresholds.  Schema version 2 adds security substrate fields and optional
/// classic-operation fee shaping.
///
/// The struct is `#[non_exhaustive]` so fields can be added in future schema
/// versions without breaking existing serde round-trips.
///
/// # Schema versioning
///
/// `version` MUST be `2` for this struct to load successfully.  A TOML file
/// with `version = 1` is migrated via `migrate_v1_to_v2` before loading.  A
/// TOML file with `version > 2` returns
/// `ProfileLoadError::VersionUnsupported`.
///
/// # Secret-material note
///
/// No field in this struct holds a secret.  All `*_key_id` fields are
/// [`KeyringEntryRef`] values — they name a keyring entry but never contain
/// the secret itself.
///
/// # Examples
///
/// ```toml
/// version = 2
/// chain_id = "stellar:testnet"
/// rpc_url = "https://soroban-testnet.stellar.org"
/// usd_threshold = 50000000000
/// mcp_disabled = false
/// classic_fee_per_op_stroops = 100
/// # Include this only when an independent RPC is configured.
/// oracle_provider_url = "https://independent-rpc.example.com"
///
/// [mcp_signer_default]
/// service = "stellar-agent-signer"
/// account = "my-profile"
///
/// [mcp_nonce_key_alias]
/// service = "stellar-agent-nonce"
/// account = "my-profile"
///
/// [audit_log_hash_chain_key_id]
/// service = "stellar-agent-audit-my-profile"
/// account = "default"
///
/// [policy_owner_key_id]
/// service = "stellar-agent-owner-my-profile"
/// account = "default"
///
/// [attestation_key_id]
/// service = "stellar-agent-attestation-my-profile"
/// account = "default"
///
/// [counterparty_cache_key_id]
/// service = "stellar-agent-counterparty-my-profile"
/// account = "default"
///
/// [policy]
/// engine = "v1"
/// ```
/// `Debug` is implemented manually to redact `rpc_url` and `secondary_rpc_url`
/// (both may embed RPC credentials in the URL). All other fields use their
/// derived `Debug` output.
#[derive(Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Profile {
    /// Schema version.  Must be `2`.
    ///
    /// Forward-compatibility: a wallet reading a profile with `version > 2`
    /// fails fast rather than silently applying stale defaults.
    pub version: u32,

    /// CAIP-2 chain identifier (`stellar:testnet` or `stellar:mainnet`).
    ///
    /// Drives network-passphrase resolution and the mainnet write-tools gate.
    pub chain_id: Caip2,

    /// Soroban RPC endpoint URL.
    ///
    /// If omitted in the profile TOML, defaults to
    /// [`Caip2::default_rpc_url`] for the resolved `chain_id`.
    ///
    /// Validated as a well-formed URL at load time via
    /// [`url::Url::parse`].  A syntactically invalid URL returns
    /// `ProfileLoadError::InvalidRpcUrl`.
    pub rpc_url: String,

    /// Stellar network passphrase.
    ///
    /// Resolved from `chain_id` at load time; cannot be overridden from
    /// profile config.  Included here so callers don't need to re-derive it.
    pub network_passphrase: String,

    /// Default signer keyring entry reference.
    ///
    /// Identifies the keyring entry for the MCP signer.  The actual
    /// secret-key lookup is performed by
    /// `stellar-agent-network::keyring::load_entry`.
    pub mcp_signer_default: KeyringEntryRef,

    /// Nonce-key keyring entry reference.
    ///
    /// The HMAC nonce key lives in the keyring, not in this TOML file.
    /// This field names the keyring entry.  Never expose or log the
    /// `service` / `account` pair in contexts where it could leak key
    /// location information.
    pub mcp_nonce_key_alias: KeyringEntryRef,

    /// USD-equivalent threshold in stroops.
    ///
    /// The effective threshold is `max(usd_threshold, MINIMUM_FLOOR)` —
    /// callers MUST call [`Profile::effective_usd_threshold`] rather than
    /// reading this field directly.
    ///
    /// The floor ([`MINIMUM_FLOOR`]) is 1 000 XLM equivalent (10^10 stroops)
    /// and cannot be configured below this value.  Transactions at or above
    /// the effective threshold trigger the high-value independent-RPC
    /// cross-check when `oracle_provider_url` is configured.
    pub usd_threshold: u64,

    /// Optional classic-operation base fee override, in stroops per operation.
    ///
    /// Stellar classic transaction builders take a per-operation base fee and
    /// multiply it by the operation count when producing `Transaction.fee`.
    /// `None` means MCP classic tools use
    /// [`crate::DEFAULT_CLASSIC_FEE_STROOPS`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub classic_fee_per_op_stroops: Option<u32>,

    /// Optional classic-operation maximum fee, in stroops per operation.
    ///
    /// When set, classic-operation tools fail before envelope construction if
    /// the selected fee exceeds this cap. This is a guardrail, not a silent
    /// clamp, because silent underpricing during surge can strand transactions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub classic_max_fee_per_op_stroops: Option<u32>,

    /// Submit timeout in seconds.
    ///
    /// The wallet polls for transaction confirmation up to this duration.
    /// Defaults to 60 seconds when absent from the profile TOML.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub submit_timeout_seconds: Option<u64>,

    /// Path to the structured audit-log file.
    ///
    /// Defaults to the OS-conventional state directory:
    /// - Linux: `~/.local/share/stellar-agent/audit/<profile>.jsonl`
    /// - macOS: `~/Library/Application Support/stellar-agent/audit/<profile>.jsonl`
    /// - Windows: `%LOCALAPPDATA%\stellar-agent\audit\<profile>.jsonl`
    pub audit_log_path: PathBuf,

    /// Disables the MCP server when `true`.
    ///
    /// When `true`, `stellar-agent mcp` refuses to start with typed error
    /// `mcp.disabled_per_profile`.  Defaults to `false`.
    #[serde(default)]
    pub mcp_disabled: bool,

    /// Keyring entry for the hash-chain audit-log root signature key.
    ///
    /// A per-profile 32-byte HMAC key used to sign the first entry per audit
    /// log file (the chain root).  Subsequent entries chain off the previous
    /// hash without per-entry signature.  Operator rotates via
    /// `stellar-agent profile rotate-audit-key <profile>`.
    ///
    /// Lazy-mint semantics: migration populates this field with a
    /// default-derived name (`stellar-agent-audit-<profile>`).  No key
    /// material is minted at migration time — key material is minted on the
    /// first `rotate-audit-key` call (or on first write to the audit log if
    /// no rotation has occurred).
    pub audit_log_hash_chain_key_id: KeyringEntryRef,

    /// Keyring entry for the policy-file owner key (ed25519 keypair).
    ///
    /// Every policy file carries an ed25519 signature over its canonical
    /// form.  This field names the keyring entry for the public-key verifier
    /// and private-key signer.  Policy files signed by a previous owner key
    /// (after rotation) are rejected on load.
    ///
    /// Lazy-enrol semantics: the field is populated at migration time with
    /// `stellar-agent-owner-<profile>`; the owner PUBLIC key is enrolled into
    /// that entry by `enroll-owner-key`.
    pub policy_owner_key_id: KeyringEntryRef,

    /// Keyring entry for the wallet-owned approval spine attestation key.
    ///
    /// A per-profile 32-byte HMAC key used to sign
    /// `HMAC-SHA256(key, approval_nonce || envelope_hash || process_uid)`
    /// at `stellar-agent approve` time.  Pending approvals are invalidated
    /// when the key is rotated.
    ///
    /// Lazy-mint semantics: populated at migration time with
    /// `stellar-agent-attestation-<profile>`; key material minted by
    /// `rotate-attestation-key`.
    pub attestation_key_id: KeyringEntryRef,

    /// Keyring entry for the `stellar.toml` cache-integrity HMAC key.
    ///
    /// A per-profile 32-byte HMAC key used to protect the local
    /// `stellar.toml` cache against post-fetch file-write tampering.
    /// Rotating this key invalidates all cached `stellar.toml` entries —
    /// operator must re-fetch after rotation.
    ///
    /// Lazy-mint semantics: populated at migration time with
    /// `stellar-agent-counterparty-<profile>`; key material minted by
    /// `rotate-counterparty-key`.
    pub counterparty_cache_key_id: KeyringEntryRef,

    /// Optional independent RPC endpoint URL for high-value cross-check.
    ///
    /// Used by the commit path when the transaction value exceeds
    /// `usd_threshold` to re-simulate against a second independent RPC
    /// endpoint.  Mismatch surfaces as `simulation.divergence`.
    ///
    /// When this field is `None`, the high-value cross-check is skipped.
    /// Operators MUST set this field before enabling `policy.engine = "v1"` for
    /// mainnet high-value flows.
    ///
    /// Default: `None` (cross-check disabled).  In TOML, omit the field when
    /// unset; when configured, use `oracle_provider_url = "https://example.org"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oracle_provider_url: Option<Url>,

    /// Policy-engine selection and configuration.
    ///
    /// Newly-minted profiles default to `V1`.  Migrated profiles retain `Noop`
    /// until the operator completes the `enroll-owner-key`,
    /// `rotate-attestation-key`, and `rotate-audit-key` runbook.
    #[serde(default)]
    pub policy: PolicyConfig,

    /// Short-in-memory-unlock-window configuration.
    ///
    /// Controls `mlock(2)` posture and unlock-window TTL for the
    /// [`crate::wallet::Wallet`] substrate.  Default values are
    /// platform-aware: Linux/macOS default to `mlock_required = true`;
    /// Windows defaults to `mlock_required = "warn"`.
    #[serde(default)]
    pub wallet: WalletConfig,

    /// Optional override for the maximum rule-ID scan bound in
    /// `list_active_context_rules`. Defaults to
    /// `stellar_agent_smart_account::managers::rules::DEFAULT_MAX_SCAN_ID`
    /// (50) when `None`.
    ///
    /// Operators with active-rule counts approaching the default raise this
    /// to a higher bound; the scan cost is RTT × `max_scan_id` so the override
    /// is a deliberate latency-vs-coverage decision.
    ///
    /// **Bounded:** values exceeding `UPPER_BOUND_MAX_SCAN_ID` (10,000) are
    /// rejected at profile-load with
    /// [`crate::profile::loader::ProfileLoadError::InvalidScanIdBound`].
    /// This caps a profile-write threat vector where an attacker who can edit
    /// the profile TOML sets the field to `u32::MAX` and triggers up to ~4.3B
    /// simulate calls on any `smart-account list-rules` / `migrate-verifier`
    /// invocation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub smart_account_max_context_rule_scan_id: Option<u32>,

    /// Optional override for the maximum session-rule lookahead window
    /// (`valid_until - current_ledger`) in ledgers.
    ///
    /// Defaults to
    /// `stellar_agent_smart_account::managers::rules::DEFAULT_SESSION_RULE_HORIZON_LEDGERS`
    /// (1000 ledgers ≈ 80 minutes at 5 s ledger times) when `None`.
    ///
    /// Operators running scheduler-bound rules with longer windows may raise
    /// this override; the cap bounds the in-flight envelope race window.
    ///
    /// **Bounded:** values exceeding
    /// [`crate::profile::loader::MIRRORED_UPPER_BOUND_HORIZON_LEDGERS`]
    /// (10,000 ledgers; ~13.9–15.3 hours at 5 s ledgers) are rejected at
    /// profile-load with
    /// [`crate::profile::loader::ProfileLoadError::InvalidHorizonBound`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_rule_max_horizon_ledgers: Option<u32>,

    /// Secondary Soroban RPC endpoint URL for multicall cross-RPC trust-anchor check.
    ///
    /// Required when a multicall router is registered for the profile's network.
    /// The profile loader validates that this field is set when a multicall registry
    /// entry exists for `network_passphrase` via
    /// [`crate::profile::loader::ProfileLoadError::MulticallRequiresSecondaryRpc`].
    ///
    /// # Security
    ///
    /// This URL is used for the cross-RPC 4-way equality check.  It MUST point
    /// to an independent Soroban RPC node — not the same node as `rpc_url` —
    /// so that a compromised primary RPC cannot forge the trust-anchor equality.
    ///
    /// # Debug redaction
    ///
    /// The `Debug` implementation for `Profile` redacts this field to
    /// `"[redacted]"` to prevent accidental log emission of RPC credentials
    /// that may be embedded in the URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secondary_rpc_url: Option<String>,

    /// Keyring entry for the channel-account pool master BIP-39 seed.
    ///
    /// `None` when the channel-account pool has not been initialised for this
    /// profile.  Set by `pool init`; used by `pool list` / `pool status` to
    /// load the master seed for channel re-derivation.
    ///
    /// A per-profile reference to the OS keyring entry that holds the BIP-39
    /// mnemonic (or equivalent 64-byte seed) used to deterministically derive
    /// channel account keypairs via `stellar-agent-sep5`
    /// (`Sep5Wallet::from_bip39_seed`, path `m/44'/148'/<index>'`).
    ///
    /// Channel private keys are never persisted individually; they are
    /// re-derived on demand from this keyring entry + the channel index,
    /// keeping the pool deterministically rebuildable.
    ///
    /// Lazy-mint semantics: populated by `pool init` when the pool is first
    /// created.  Rotate via `pool rotate-master-key`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pool_master_key_id: Option<KeyringEntryRef>,

    /// Persisted channel-account pool configuration.
    ///
    /// `None` when the pool has not been initialised.  Written by `pool init`
    /// (atomically via `loader::save`) and read by `pool list` / `pool status`.
    ///
    /// Contains only public-safe data (pool size, channel G-strkeys, BIP-44
    /// indices).  The pool master seed lives separately in the OS keyring under
    /// `pool_master_key_id`; no secrets are stored in this struct.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pool_config: Option<PoolConfig>,

    /// Remote-approval HTTP surface configuration.
    ///
    /// `None` (the default) means remote approval is off: `approve serve`
    /// stays bound to loopback regardless of any other flag. Configuring
    /// this block is necessary but not sufficient to expose the surface
    /// beyond loopback — `approve serve --remote` additionally requires an
    /// explicit process-level consent flag at start time, matching the
    /// `--confirm-*` pattern used for other risky-write exceptions. A
    /// profile alone cannot silently turn on network exposure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_approval: Option<RemoteApprovalConfig>,

    /// Keyring entry for the persisted policy-window-state HMAC key.
    ///
    /// A per-profile 32-byte HMAC key authenticating the on-disk sliding-window
    /// store (`<state>/policy/<profile>.window`) that backs the `per_period_cap`,
    /// `rate_limit`, `bundle_per_period_cap`, and `bundle_rate_limit` criteria.
    /// Rotating this key invalidates the existing store file's tag; `profile
    /// rotate-policy-state-key` re-signs the file under the new key so
    /// accumulated history is not lost.
    ///
    /// Absent from profiles written before this field existed: the loader
    /// derives the conventional coordinate (`stellar-agent-policy-window-<profile>`)
    /// from the profile name when the TOML omits it, so existing profile files
    /// keep loading unchanged. Key material mints lazily on first store write.
    ///
    /// Resolved by the loader (mirroring `rpc_url` / `audit_log_path`), not by
    /// a serde field default — the conventional coordinate is derived from the
    /// profile name, which is not available to a per-field serde default.
    pub policy_window_state_key_id: KeyringEntryRef,
}

/// A single channel record within the channel-account pool.
///
/// Stores the BIP-44 derivation index and the `G...` Stellar strkey.  No
/// secret material is stored here; the channel private key is re-derived on
/// demand from the pool master seed in the OS keyring.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct PoolChannelRecord {
    /// BIP-44 account index (`m/44'/148'/index'`).
    ///
    /// Pool channels occupy indices `1..=N` (index `0` is reserved for the
    /// wallet's primary account).
    pub index: u32,

    /// The `G...` Stellar strkey of this channel's public key.
    ///
    /// Persisted for display and on-chain verification.
    pub public_key: String,
}

impl PoolChannelRecord {
    /// Constructs a new `PoolChannelRecord`.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::profile::schema::PoolChannelRecord;
    ///
    /// let rec = PoolChannelRecord::new(1, "GABC...XYZ");
    /// assert_eq!(rec.index, 1);
    /// ```
    #[must_use]
    pub fn new(index: u32, public_key: impl Into<String>) -> Self {
        Self {
            index,
            public_key: public_key.into(),
        }
    }
}

/// Persisted channel-account pool configuration.
///
/// Stored as `[pool_config]` in the profile TOML via
/// `Profile.pool_config: Option<PoolConfig>`.  Contains only public-safe data;
/// the pool master seed lives in the OS keyring under
/// `Profile.pool_master_key_id`.
///
/// # Secret discipline
///
/// No secrets here.  Channel private keys are re-derived on demand from the
/// keyring master at `m/44'/148'/<index>'` via `stellar-agent-sep5`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct PoolConfig {
    /// Total number of channels in this pool (`1..=33`).
    pub pool_size: usize,

    /// Per-channel public bookkeeping records (index + public key).
    ///
    /// Length MUST equal `pool_size`.
    pub channels: Vec<PoolChannelRecord>,
}

impl PoolConfig {
    /// Constructs a new `PoolConfig`.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::profile::schema::{PoolChannelRecord, PoolConfig};
    ///
    /// let cfg = PoolConfig::new(2, vec![
    ///     PoolChannelRecord::new(1, "GABC..."),
    ///     PoolChannelRecord::new(2, "GDEF..."),
    /// ]);
    /// assert_eq!(cfg.pool_size, 2);
    /// ```
    #[must_use]
    pub fn new(pool_size: usize, channels: Vec<PoolChannelRecord>) -> Self {
        Self {
            pool_size,
            channels,
        }
    }
}

/// Configuration for the network-exposed remote-approval HTTP surface.
///
/// Stored as `[remote_approval]` in the profile TOML via
/// `Profile.remote_approval: Option<RemoteApprovalConfig>`. Absent by
/// default: remote approval is off unless the operator explicitly writes
/// this block.
///
/// ```toml
/// [remote_approval]
/// enabled = true
/// bind = "0.0.0.0:8443"
/// rp_id = "wallet.internal"
/// allowed_credentials = ["<credential_id_b64url>"]
/// ```
///
/// # Security
///
/// This block only carries configuration; on its own it does not expose
/// anything to the network. `approve serve --remote` additionally requires
/// an explicit process-level consent flag before binding beyond loopback.
///
/// `allowed_credentials` is the authorization allowlist
/// `crate::approval::user_id::ApproverIdentity::is_authorized_for_entry`
/// consults for a `PasskeyCredential` identity: an assertion for a
/// credential ID absent from this list is refused by the in-core gate
/// regardless of what the HTTP layer verified.
///
/// `rp_id` MUST be a DNS hostname, never an IP literal — WebAuthn Level 2
/// §5.1.2 forbids IP-literal Relying Party IDs.
///
/// # Debug redaction
///
/// `Debug` is hand-implemented to redact each entry of `allowed_credentials`
/// to first-5-last-5 form (the same discipline used for credential IDs
/// elsewhere in the wallet); `bind` and `rp_id` are not secret and are shown
/// verbatim.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct RemoteApprovalConfig {
    /// Enables the remote-approval HTTP surface when `true`.
    ///
    /// `approve serve --remote` refuses to bind beyond loopback unless this
    /// is `true` AND the operator passes the process's explicit consent
    /// flag. Defaults to `false` when omitted, so a `[remote_approval]`
    /// block written without this key is off by default rather than
    /// silently enabled.
    #[serde(default)]
    pub enabled: bool,

    /// Socket address the remote-approval listener binds to (e.g.
    /// `"0.0.0.0:8443"`).
    pub bind: String,

    /// WebAuthn Relying Party ID: a DNS hostname, never an IP literal.
    ///
    /// The operator must give the wallet host a resolvable name from the
    /// approving device and reach it as `https://<rp_id>:<port>`.
    pub rp_id: String,

    /// Base64url WebAuthn credential IDs authorized to consent to pending
    /// approvals over the remote surface.
    ///
    /// Defaults to an empty list when omitted — fail-closed: no credential
    /// is authorized until the operator explicitly lists one.
    #[serde(default)]
    pub allowed_credentials: Vec<String>,
}

impl std::fmt::Debug for RemoteApprovalConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let redacted_credentials: Vec<String> = self
            .allowed_credentials
            .iter()
            .map(|c| crate::redact_first5_last5(c))
            .collect();
        f.debug_struct("RemoteApprovalConfig")
            .field("enabled", &self.enabled)
            .field("bind", &self.bind)
            .field("rp_id", &self.rp_id)
            .field("allowed_credentials", &redacted_credentials)
            .finish()
    }
}

impl std::fmt::Debug for Profile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `rpc_url` and `secondary_rpc_url` are redacted because they may
        // embed RPC credentials in the URL.
        f.debug_struct("Profile")
            .field("version", &self.version)
            .field("chain_id", &self.chain_id)
            .field("rpc_url", &"[redacted]")
            .field("network_passphrase", &self.network_passphrase)
            .field("mcp_signer_default", &self.mcp_signer_default)
            .field("mcp_nonce_key_alias", &self.mcp_nonce_key_alias)
            .field("usd_threshold", &self.usd_threshold)
            .field(
                "classic_fee_per_op_stroops",
                &self.classic_fee_per_op_stroops,
            )
            .field(
                "classic_max_fee_per_op_stroops",
                &self.classic_max_fee_per_op_stroops,
            )
            .field("submit_timeout_seconds", &self.submit_timeout_seconds)
            .field("audit_log_path", &self.audit_log_path)
            .field("mcp_disabled", &self.mcp_disabled)
            .field(
                "audit_log_hash_chain_key_id",
                &self.audit_log_hash_chain_key_id,
            )
            .field("policy_owner_key_id", &self.policy_owner_key_id)
            .field("attestation_key_id", &self.attestation_key_id)
            .field("counterparty_cache_key_id", &self.counterparty_cache_key_id)
            .field("oracle_provider_url", &self.oracle_provider_url)
            .field("policy", &self.policy)
            .field("wallet", &self.wallet)
            .field(
                "smart_account_max_context_rule_scan_id",
                &self.smart_account_max_context_rule_scan_id,
            )
            .field(
                "session_rule_max_horizon_ledgers",
                &self.session_rule_max_horizon_ledgers,
            )
            .field(
                "secondary_rpc_url",
                &self.secondary_rpc_url.as_deref().map(|_| "[redacted]"),
            )
            .field("pool_master_key_id", &self.pool_master_key_id)
            .field("pool_config", &self.pool_config)
            .field(
                "policy_window_state_key_id",
                &self.policy_window_state_key_id,
            )
            .field("remote_approval", &self.remote_approval)
            .finish()
    }
}

impl Profile {
    /// Returns the effective USD threshold, enforcing the minimum floor.
    ///
    /// Returns `max(self.usd_threshold, MINIMUM_FLOOR)`.  Callers MUST use
    /// this method rather than reading `usd_threshold` directly.
    ///
    /// A profile with `usd_threshold = 0` behaves as if the threshold were
    /// [`MINIMUM_FLOOR`].
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::profile::schema::{Profile, MINIMUM_FLOOR};
    ///
    /// let mut p = Profile::builder_testnet("svc", "acct", "nonce-svc", "nonce-acct").build();
    /// p.usd_threshold = 0;
    /// assert_eq!(p.effective_usd_threshold(), MINIMUM_FLOOR);
    ///
    /// p.usd_threshold = u64::MAX;
    /// assert_eq!(p.effective_usd_threshold(), u64::MAX);
    /// ```
    #[must_use]
    pub fn effective_usd_threshold(&self) -> u64 {
        self.usd_threshold.max(MINIMUM_FLOOR)
    }

    /// Validates the `rpc_url` field as a well-formed URL.
    ///
    /// Called by the loader after deserialisation.  Returns
    /// `Ok(Url)` on success; callers may discard the parsed URL if they only
    /// need validation.
    ///
    /// # Errors
    ///
    /// Returns [`RpcUrlParseError`] if `rpc_url` is not a valid URL.
    pub fn validate_rpc_url(&self) -> Result<Url, RpcUrlParseError> {
        Url::parse(&self.rpc_url).map_err(|e| RpcUrlParseError {
            raw: self.rpc_url.clone(),
            source: e,
        })
    }

    /// Convenience builder for testnet profiles.
    ///
    /// Returns a [`ProfileBuilder`] pre-configured for `stellar:testnet` with
    /// the default testnet RPC URL.  The v2 keyring entry references are
    /// derived from the `signer_account` value as the profile-name component
    /// (e.g. `stellar-agent-audit-<signer_account>`).  Call
    /// [`ProfileBuilder::with_profile_name`] to override the derivation base
    /// if `signer_account` is not a profile name.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::profile::schema::Profile;
    ///
    /// let p = Profile::builder_testnet(
    ///     "stellar-agent-signer",
    ///     "my-profile",
    ///     "stellar-agent-nonce",
    ///     "my-profile",
    /// )
    /// .build();
    /// assert_eq!(p.chain_id.caip2_str(), "stellar:testnet");
    /// assert_eq!(p.version, 2);
    /// ```
    pub fn builder_testnet(
        signer_service: impl Into<String>,
        signer_account: impl Into<String>,
        nonce_service: impl Into<String>,
        nonce_account: impl Into<String>,
    ) -> ProfileBuilder {
        use super::caip2::{TESTNET_PASSPHRASE, TESTNET_RPC_URL};
        let signer_account = signer_account.into();
        // Use signer_account as the profile-name base for v2 key derivation.
        // Callers that supply a distinct profile name should call
        // `with_profile_name` on the returned builder.
        let derived_name = signer_account.clone();
        ProfileBuilder {
            version: 2,
            chain_id: Caip2::Testnet,
            rpc_url: TESTNET_RPC_URL.to_owned(),
            network_passphrase: TESTNET_PASSPHRASE.to_owned(),
            mcp_signer_default: KeyringEntryRef::new(signer_service, signer_account),
            mcp_nonce_key_alias: KeyringEntryRef::new(nonce_service, nonce_account),
            usd_threshold: MINIMUM_FLOOR,
            classic_fee_per_op_stroops: None,
            classic_max_fee_per_op_stroops: None,
            submit_timeout_seconds: None,
            audit_log_path: None,
            mcp_disabled: false,
            audit_log_hash_chain_key_id: KeyringEntryRef::default_audit_key(&derived_name),
            policy_owner_key_id: KeyringEntryRef::default_owner_key(&derived_name),
            attestation_key_id: KeyringEntryRef::default_attestation_key(&derived_name),
            counterparty_cache_key_id: KeyringEntryRef::default_counterparty_key(&derived_name),
            policy_window_state_key_id: KeyringEntryRef::default_policy_window_state_key(
                &derived_name,
            ),
            oracle_provider_url: None,
            policy: PolicyConfig::default(),
            wallet: WalletConfig::default(),
            smart_account_max_context_rule_scan_id: None,
            session_rule_max_horizon_ledgers: None,
            secondary_rpc_url: None,
        }
    }

    /// Constructs a testnet [`ProfileBuilder`] with an explicit profile name.
    ///
    /// Use this when the signer account differs from the intended profile name
    /// (common in multi-profile setups). The existing four-argument
    /// [`Profile::builder_testnet`] derives v2 keyring entry names from
    /// `signer_account`; this variant takes the derivation base explicitly.
    pub fn builder_testnet_named(
        profile_name: &str,
        signer_service: &str,
        signer_account: &str,
        nonce_service: &str,
        nonce_account: &str,
    ) -> ProfileBuilder {
        Self::builder_testnet(signer_service, signer_account, nonce_service, nonce_account)
            .with_profile_name(profile_name)
    }

    /// Convenience builder for mainnet profiles.
    ///
    /// Returns a [`ProfileBuilder`] pre-configured for `stellar:mainnet` with
    /// the default mainnet RPC URL.  See [`Profile::builder_testnet`] for the
    /// v2 key-derivation note.
    pub fn builder_mainnet(
        signer_service: impl Into<String>,
        signer_account: impl Into<String>,
        nonce_service: impl Into<String>,
        nonce_account: impl Into<String>,
    ) -> ProfileBuilder {
        use super::caip2::{MAINNET_PASSPHRASE, MAINNET_RPC_URL};
        let signer_account = signer_account.into();
        let derived_name = signer_account.clone();
        ProfileBuilder {
            version: 2,
            chain_id: Caip2::Mainnet,
            rpc_url: MAINNET_RPC_URL.to_owned(),
            network_passphrase: MAINNET_PASSPHRASE.to_owned(),
            mcp_signer_default: KeyringEntryRef::new(signer_service, signer_account),
            mcp_nonce_key_alias: KeyringEntryRef::new(nonce_service, nonce_account),
            usd_threshold: MINIMUM_FLOOR,
            classic_fee_per_op_stroops: None,
            classic_max_fee_per_op_stroops: None,
            submit_timeout_seconds: None,
            audit_log_path: None,
            mcp_disabled: false,
            audit_log_hash_chain_key_id: KeyringEntryRef::default_audit_key(&derived_name),
            policy_owner_key_id: KeyringEntryRef::default_owner_key(&derived_name),
            attestation_key_id: KeyringEntryRef::default_attestation_key(&derived_name),
            counterparty_cache_key_id: KeyringEntryRef::default_counterparty_key(&derived_name),
            policy_window_state_key_id: KeyringEntryRef::default_policy_window_state_key(
                &derived_name,
            ),
            oracle_provider_url: None,
            policy: PolicyConfig::default(),
            wallet: WalletConfig::default(),
            smart_account_max_context_rule_scan_id: None,
            session_rule_max_horizon_ledgers: None,
            secondary_rpc_url: None,
        }
    }

    /// Mainnet equivalent of [`Profile::builder_testnet_named`].
    pub fn builder_mainnet_named(
        profile_name: &str,
        signer_service: &str,
        signer_account: &str,
        nonce_service: &str,
        nonce_account: &str,
    ) -> ProfileBuilder {
        Self::builder_mainnet(signer_service, signer_account, nonce_service, nonce_account)
            .with_profile_name(profile_name)
    }
}

/// Error returned when the `rpc_url` field fails URL validation.
#[derive(Debug, thiserror::Error)]
#[error("invalid rpc_url '{raw}': {source}")]
pub struct RpcUrlParseError {
    /// The raw string that failed to parse.
    pub raw: String,
    /// The underlying parse error from the `url` crate.
    #[source]
    pub source: url::ParseError,
}

// ─────────────────────────────────────────────────────────────────────────────
// ProfileBuilder
// ─────────────────────────────────────────────────────────────────────────────

/// Builder for [`Profile`] values used in tests and the loader.
///
/// Obtain a builder via [`Profile::builder_testnet`] or
/// [`Profile::builder_mainnet`].
#[must_use]
pub struct ProfileBuilder {
    version: u32,
    chain_id: Caip2,
    rpc_url: String,
    network_passphrase: String,
    mcp_signer_default: KeyringEntryRef,
    mcp_nonce_key_alias: KeyringEntryRef,
    usd_threshold: u64,
    classic_fee_per_op_stroops: Option<u32>,
    classic_max_fee_per_op_stroops: Option<u32>,
    submit_timeout_seconds: Option<u64>,
    audit_log_path: Option<PathBuf>,
    mcp_disabled: bool,
    audit_log_hash_chain_key_id: KeyringEntryRef,
    policy_owner_key_id: KeyringEntryRef,
    attestation_key_id: KeyringEntryRef,
    counterparty_cache_key_id: KeyringEntryRef,
    policy_window_state_key_id: KeyringEntryRef,
    oracle_provider_url: Option<Url>,
    policy: PolicyConfig,
    wallet: WalletConfig,
    smart_account_max_context_rule_scan_id: Option<u32>,
    session_rule_max_horizon_ledgers: Option<u32>,
    secondary_rpc_url: Option<String>,
}

impl ProfileBuilder {
    /// Re-derives the v2 keyring entry references from an explicit profile name.
    ///
    /// Use this when the profile name differs from the `signer_account` value
    /// that was passed to [`Profile::builder_testnet`] or
    /// [`Profile::builder_mainnet`].
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::profile::schema::Profile;
    ///
    /// let p = Profile::builder_testnet("svc", "acct", "n-svc", "n-acct")
    ///     .with_profile_name("my-named-profile")
    ///     .build();
    /// assert_eq!(
    ///     p.audit_log_hash_chain_key_id.service,
    ///     "stellar-agent-audit-my-named-profile"
    /// );
    /// ```
    #[must_use = "builder setters return the updated builder by value"]
    pub fn with_profile_name(mut self, profile_name: impl AsRef<str>) -> Self {
        let name = profile_name.as_ref();
        self.audit_log_hash_chain_key_id = KeyringEntryRef::default_audit_key(name);
        self.policy_owner_key_id = KeyringEntryRef::default_owner_key(name);
        self.attestation_key_id = KeyringEntryRef::default_attestation_key(name);
        self.counterparty_cache_key_id = KeyringEntryRef::default_counterparty_key(name);
        self.policy_window_state_key_id = KeyringEntryRef::default_policy_window_state_key(name);
        self
    }

    /// Overrides the RPC URL.
    #[must_use = "builder setters return the updated builder by value"]
    pub fn rpc_url(mut self, url: impl Into<String>) -> Self {
        self.rpc_url = url.into();
        self
    }

    /// Overrides the USD threshold (stroops).
    #[must_use = "builder setters return the updated builder by value"]
    pub fn usd_threshold(mut self, threshold: u64) -> Self {
        self.usd_threshold = threshold;
        self
    }

    /// Overrides the classic-operation base fee, in stroops per operation.
    #[must_use = "builder setters return the updated builder by value"]
    pub fn classic_fee_per_op_stroops(mut self, fee_per_op_stroops: Option<u32>) -> Self {
        self.classic_fee_per_op_stroops = fee_per_op_stroops;
        self
    }

    /// Overrides the classic-operation maximum fee, in stroops per operation.
    #[must_use = "builder setters return the updated builder by value"]
    pub fn classic_max_fee_per_op_stroops(mut self, cap_per_op_stroops: Option<u32>) -> Self {
        self.classic_max_fee_per_op_stroops = cap_per_op_stroops;
        self
    }

    /// Overrides the audit-log path.
    #[must_use = "builder setters return the updated builder by value"]
    pub fn audit_log_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.audit_log_path = Some(path.into());
        self
    }

    /// Sets `mcp_disabled = true`.
    #[must_use = "builder setters return the updated builder by value"]
    pub fn mcp_disabled(mut self) -> Self {
        self.mcp_disabled = true;
        self
    }

    /// Overrides the oracle-provider URL (for high-value RPC cross-check).
    #[must_use = "builder setters return the updated builder by value"]
    pub fn oracle_provider_url(mut self, url: impl Into<Option<Url>>) -> Self {
        self.oracle_provider_url = url.into();
        self
    }

    /// Overrides the policy configuration.
    #[must_use = "builder setters return the updated builder by value"]
    pub fn policy(mut self, policy: PolicyConfig) -> Self {
        self.policy = policy;
        self
    }

    /// Sets `policy.engine = Noop` on this builder.
    ///
    /// Use this when:
    ///
    /// - (a) An operator explicitly chooses the `Noop` engine for a
    ///   freshly-built profile that has not yet completed the
    ///   `enroll-owner-key`, `rotate-attestation-key`, and `rotate-audit-key`
    ///   ceremony.
    /// - (b) The loader fallback synthesises a first-run testnet profile that
    ///   must run without an owner-key keyring entry.  Since
    ///   `PolicyEngineKind::default()` is `V1`, `WalletServer::new` would
    ///   otherwise fail with `BuildRegistryError::OwnerKeyAbsent` on first run
    ///   before any profile file has been created.
    ///
    /// Calling this method opts the profile out of `PolicyEngineV1` rule
    /// evaluation.  `NoopPolicyEngine` enforces only the mainnet refusal
    /// contract (refuses destructive operations on mainnet); it does NOT
    /// evaluate per-tx caps, per-period caps, counterparty allowlists,
    /// oracle staleness, or owner-signature validation.  Use this method only
    /// when the `Noop` contract is sufficient for the deployment — see
    /// `crates/stellar-agent-core/src/policy/v1.rs` for the V1 evaluator's
    /// typed criteria.
    ///
    /// Returns the builder by value to preserve the chained-builder idiom.
    ///
    /// This helper also avoids the `#[non_exhaustive]` struct-literal
    /// restriction on [`PolicyConfig`] when constructing from outside the
    /// defining crate.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::profile::schema::{Profile, PolicyEngineKind};
    ///
    /// let p = Profile::builder_testnet("svc", "acct", "n-svc", "n-acct")
    ///     .with_noop_engine()
    ///     .build();
    /// assert_eq!(p.policy.engine, PolicyEngineKind::Noop);
    /// ```
    #[must_use = "builder setters return the updated builder by value"]
    pub fn with_noop_engine(mut self) -> Self {
        self.policy.engine = PolicyEngineKind::Noop;
        self
    }

    /// Overrides the `policy.engine` field to the supplied [`PolicyEngineKind`].
    ///
    /// This is the general-purpose setter that complements [`Self::with_noop_engine`]
    /// (which is retained as a convenience).  Prefer this method when callers want
    /// to self-document their engine choice or be explicit against future default
    /// changes.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::profile::schema::{Profile, PolicyEngineKind};
    ///
    /// let p = Profile::builder_testnet("svc", "acct", "n-svc", "n-acct")
    ///     .policy_engine(PolicyEngineKind::V1)
    ///     .build();
    /// assert_eq!(p.policy.engine, PolicyEngineKind::V1);
    /// ```
    #[must_use = "builder setters return the updated builder by value"]
    pub fn policy_engine(mut self, kind: PolicyEngineKind) -> Self {
        self.policy.engine = kind;
        self
    }

    /// Overrides the wallet (mlock + unlock-window) configuration.
    #[must_use = "builder setters return the updated builder by value"]
    pub fn wallet(mut self, wallet: WalletConfig) -> Self {
        self.wallet = wallet;
        self
    }

    /// Overrides `session_rule_max_horizon_ledgers`.
    ///
    /// Sets the maximum session-rule lookahead window in ledgers.  Values
    /// exceeding `UPPER_BOUND_HORIZON_LEDGERS` (10,000) are rejected at
    /// profile-load; this setter does not validate the bound (the loader does).
    #[must_use = "builder setters return the updated builder by value"]
    pub fn session_rule_max_horizon_ledgers(mut self, ledgers: Option<u32>) -> Self {
        self.session_rule_max_horizon_ledgers = ledgers;
        self
    }

    /// Sets the secondary (trust-anchor) RPC URL for cross-RPC multicall
    /// verification.
    ///
    /// When set, the multicall submit path fetches the on-chain WASM hash of
    /// the multicall registry entry from both the primary and secondary RPC
    /// nodes and asserts byte-exact agreement before allowing the bundle to
    /// proceed.  The URL is redacted in [`Debug`] output.
    ///
    /// Pass `None` (or `impl Into<Option<String>>` resolving to `None`) to
    /// clear a previously set value.
    ///
    /// [`Debug`]: std::fmt::Debug
    #[must_use = "builder setters return the updated builder by value"]
    pub fn secondary_rpc_url(mut self, url: impl Into<Option<String>>) -> Self {
        self.secondary_rpc_url = url.into();
        self
    }

    /// Builds the [`Profile`], using the default audit-log path if not set.
    ///
    /// If `audit_log_path` was not supplied via [`ProfileBuilder::audit_log_path`],
    /// the method calls `default_audit_log_path()` and falls back to
    /// `"audit.log"` (a relative path) when the OS-conventional directory
    /// cannot be determined.  It never panics.
    pub fn build(self) -> Profile {
        let audit_log_path = self.audit_log_path.unwrap_or_else(|| {
            default_audit_log_path().unwrap_or_else(|_| PathBuf::from("audit.log"))
        });
        Profile {
            version: self.version,
            chain_id: self.chain_id,
            rpc_url: self.rpc_url,
            network_passphrase: self.network_passphrase,
            mcp_signer_default: self.mcp_signer_default,
            mcp_nonce_key_alias: self.mcp_nonce_key_alias,
            usd_threshold: self.usd_threshold,
            classic_fee_per_op_stroops: self.classic_fee_per_op_stroops,
            classic_max_fee_per_op_stroops: self.classic_max_fee_per_op_stroops,
            submit_timeout_seconds: self.submit_timeout_seconds,
            audit_log_path,
            mcp_disabled: self.mcp_disabled,
            audit_log_hash_chain_key_id: self.audit_log_hash_chain_key_id,
            policy_owner_key_id: self.policy_owner_key_id,
            attestation_key_id: self.attestation_key_id,
            counterparty_cache_key_id: self.counterparty_cache_key_id,
            oracle_provider_url: self.oracle_provider_url,
            policy: self.policy,
            wallet: self.wallet,
            smart_account_max_context_rule_scan_id: self.smart_account_max_context_rule_scan_id,
            session_rule_max_horizon_ledgers: self.session_rule_max_horizon_ledgers,
            secondary_rpc_url: self.secondary_rpc_url,
            // Pool not yet initialised in newly-built profiles.
            pool_master_key_id: None,
            pool_config: None,
            // Remote approval is off by default; the operator opts in by
            // writing a `[remote_approval]` block to the profile TOML.
            remote_approval: None,
            policy_window_state_key_id: self.policy_window_state_key_id,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// OS-conventional state directory helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Error returned when the OS-conventional state directory cannot be
/// determined.
#[derive(Debug, thiserror::Error)]
#[error("could not determine OS-conventional state directory for stellar-agent")]
pub struct StateDirError;

/// Returns the OS-conventional default audit-log path for this process.
///
/// - Linux: `~/.local/share/stellar-agent/audit.log`
/// - macOS: `~/Library/Application Support/stellar-agent/audit.log`
/// - Windows: `%LOCALAPPDATA%\stellar-agent\audit.log`
///
/// # Errors
///
/// Returns [`StateDirError`] when the platform directories library cannot
/// determine the user's state directory.
pub fn default_audit_log_path() -> Result<PathBuf, StateDirError> {
    let dirs =
        directories::ProjectDirs::from("", "Soneso", "stellar-agent").ok_or(StateDirError)?;
    Ok(dirs.data_local_dir().join("audit.log"))
}

/// Returns the OS-conventional audit-log file path for `profile_name`.
///
/// On Linux: `~/.local/share/stellar-agent/audit/<profile_name>.jsonl`.
/// On macOS: `~/Library/Application Support/stellar-agent/audit/<profile_name>.jsonl`.
/// On Windows: `%LOCALAPPDATA%\stellar-agent\audit\<profile_name>.jsonl`.
///
/// Falls back to `./stellar-agent/audit/<profile_name>.jsonl` if
/// `directories::BaseDirs::new` returns `None` (rare; CI containers without
/// `$HOME`).
///
/// `profile_name` is normalised to a filename-safe stem before `.jsonl` is
/// appended. ASCII letters, digits, `-`, and `_` are preserved; all other
/// characters become `_`. Empty input uses `default`. Windows-reserved device
/// stems such as `CON`, `PRN`, `AUX`, `NUL`, `COM1`, and `LPT1` are prefixed
/// with `_`.
///
/// Used by audit-writer registry construction that needs the per-profile
/// path convention from one public schema-level helper.
#[must_use]
pub fn default_audit_log_path_for(profile_name: &str) -> PathBuf {
    let file_name = format!("{}.jsonl", audit_log_file_stem(profile_name));
    default_audit_log_dir()
        .map(|dir| dir.join(&file_name))
        .unwrap_or_else(|| PathBuf::from("stellar-agent/audit").join(file_name))
}

fn default_audit_log_dir() -> Option<PathBuf> {
    let dirs = directories::BaseDirs::new()?;

    #[cfg(target_os = "linux")]
    {
        Some(
            dirs.state_dir()
                .unwrap_or_else(|| dirs.data_local_dir())
                .join("stellar-agent")
                .join("audit"),
        )
    }

    #[cfg(target_os = "macos")]
    {
        Some(dirs.data_local_dir().join("stellar-agent").join("audit"))
    }

    #[cfg(target_os = "windows")]
    {
        Some(dirs.data_local_dir().join("stellar-agent").join("audit"))
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        Some(dirs.data_local_dir().join("stellar-agent").join("audit"))
    }
}

/// Returns the OS-conventional policy-window-state file path for
/// `profile_name`.
///
/// `<state>/stellar-agent/policy/<profile_name>.window`, mirroring
/// [`default_audit_log_path_for`]'s per-profile file-naming convention (same
/// `profile_name` sanitisation) with a sibling `policy/` leaf distinct from
/// the `policies/` directory [`default_policy_dir`] returns for signed policy
/// rule-set TOML files — this path holds accumulated runtime window state,
/// not policy configuration.
///
/// Tests may set `STELLAR_AGENT_HOME` to redirect the directory to
/// `$STELLAR_AGENT_HOME/policy`, mirroring [`default_policy_dir`]'s override.
/// The env-var read is **gated behind `#[cfg(any(test, feature =
/// "test-helpers"))]`** so production release builds never honour it —
/// closing the same env-injection store-swap surface `default_profile_dir`
/// documents.
#[must_use]
pub fn default_policy_window_state_path_for(profile_name: &str) -> PathBuf {
    let file_name = format!("{}.window", audit_log_file_stem(profile_name));
    #[cfg(any(test, feature = "test-helpers"))]
    if let Some(home) = std::env::var_os("STELLAR_AGENT_HOME") {
        return PathBuf::from(home).join("policy").join(&file_name);
    }
    default_policy_window_state_dir()
        .map(|dir| dir.join(&file_name))
        .unwrap_or_else(|| PathBuf::from("stellar-agent/policy").join(file_name))
}

fn default_policy_window_state_dir() -> Option<PathBuf> {
    let dirs = directories::BaseDirs::new()?;

    #[cfg(target_os = "linux")]
    {
        Some(
            dirs.state_dir()
                .unwrap_or_else(|| dirs.data_local_dir())
                .join("stellar-agent")
                .join("policy"),
        )
    }

    #[cfg(target_os = "macos")]
    {
        Some(dirs.data_local_dir().join("stellar-agent").join("policy"))
    }

    #[cfg(target_os = "windows")]
    {
        Some(dirs.data_local_dir().join("stellar-agent").join("policy"))
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        Some(dirs.data_local_dir().join("stellar-agent").join("policy"))
    }
}

fn audit_log_file_stem(profile_name: &str) -> String {
    let mut stem: String = profile_name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect();

    if stem.is_empty() {
        stem = "default".to_owned();
    }

    if is_windows_reserved_file_stem(&stem) {
        stem.insert(0, '_');
    }

    stem
}

fn is_windows_reserved_file_stem(stem: &str) -> bool {
    let upper = stem.to_ascii_uppercase();
    matches!(upper.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || matches!(
            upper.as_str(),
            "COM1"
                | "COM2"
                | "COM3"
                | "COM4"
                | "COM5"
                | "COM6"
                | "COM7"
                | "COM8"
                | "COM9"
                | "LPT1"
                | "LPT2"
                | "LPT3"
                | "LPT4"
                | "LPT5"
                | "LPT6"
                | "LPT7"
                | "LPT8"
                | "LPT9"
        )
}

/// Returns the OS-conventional profile directory.
///
/// Profile TOML files are stored as `<profile_dir>/<name>.toml`.
///
/// - Linux: `~/.local/share/stellar-agent/profiles/`
/// - macOS: `~/Library/Application Support/stellar-agent/profiles/`
/// - Windows: `%LOCALAPPDATA%\stellar-agent\profiles\`
///
/// Tests may set `STELLAR_AGENT_HOME` to redirect this directory to
/// `$STELLAR_AGENT_HOME/profiles`. The env-var read is **gated behind
/// `#[cfg(any(test, feature = "test-helpers"))]`** so production release builds
/// never honour it — this closes the env-injection profile-store-swap attack
/// surface. A profile file governs which policy engine and owner-key
/// coordinate a value-moving command trusts, so an unauthenticated override of
/// this path in a production binary would let an attacker substitute a
/// permissive profile.
///
/// # Errors
///
/// Returns [`StateDirError`] when the platform directories library cannot
/// determine the user's state directory.
pub fn default_profile_dir() -> Result<PathBuf, StateDirError> {
    // Gated env-var override: only honoured in test builds OR when the crate is
    // compiled with `--features test-helpers`. Production release builds never
    // read this variable, eliminating the env-injection profile-store-swap
    // surface.
    #[cfg(any(test, feature = "test-helpers"))]
    if let Some(home) = std::env::var_os("STELLAR_AGENT_HOME") {
        return Ok(PathBuf::from(home).join("profiles"));
    }

    let dirs =
        directories::ProjectDirs::from("", "Soneso", "stellar-agent").ok_or(StateDirError)?;
    Ok(dirs.data_local_dir().join("profiles"))
}

/// Returns the OS-conventional policy directory.
///
/// Owner-signed policy TOML files are stored as `<policy_dir>/<profile_name>.toml`.
///
/// - Linux: `~/.local/share/stellar-agent/policies/`
///   (`$XDG_DATA_HOME/stellar-agent/policies/` when `$XDG_DATA_HOME` is set)
/// - macOS: `~/Library/Application Support/stellar-agent/policies/`
/// - Windows: `%LOCALAPPDATA%\stellar-agent\policies\`
///
/// Tests may set `STELLAR_AGENT_HOME` to redirect this directory to
/// `$STELLAR_AGENT_HOME/policies`. The env-var read is **gated behind
/// `#[cfg(any(test, feature = "test-helpers"))]`** so production release builds
/// never honour it — this closes the env-injection policy-store-swap attack
/// surface. The policy directory holds the operator-signed root-of-trust
/// document `PolicyEngineV1` enforces; an unauthenticated override of this
/// path in a production binary would let an attacker substitute a forged or
/// permissive policy file.
///
/// # Errors
///
/// Returns [`StateDirError`] when the platform directories library cannot
/// determine the user's state directory.
pub fn default_policy_dir() -> Result<PathBuf, StateDirError> {
    // Gated env-var override: only honoured in test builds OR when the crate is
    // compiled with `--features test-helpers`. Production release builds never
    // read this variable, eliminating the env-injection policy-store-swap
    // surface.
    #[cfg(any(test, feature = "test-helpers"))]
    if let Some(home) = std::env::var_os("STELLAR_AGENT_HOME") {
        return Ok(PathBuf::from(home).join("policies"));
    }

    let dirs =
        directories::ProjectDirs::from("", "Soneso", "stellar-agent").ok_or(StateDirError)?;
    Ok(dirs.data_local_dir().join("policies"))
}

/// Returns the OS-conventional approvals directory.
///
/// Pending-approval TOML files are stored as
/// `<approvals_dir>/<profile_name>.toml`.  The sidecar lock files are stored
/// alongside as `<profile_name>.toml.lock`.
///
/// - Linux: `~/.local/share/stellar-agent/approvals/`
///   (`$XDG_DATA_HOME/stellar-agent/approvals/` when `$XDG_DATA_HOME` is set)
/// - macOS: `~/Library/Application Support/stellar-agent/approvals/`
/// - Windows: `%LOCALAPPDATA%\stellar-agent\approvals\`
///
/// # Errors
///
/// Returns [`StateDirError`] when the platform directories library cannot
/// determine the user's state directory.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::profile::schema::default_approval_dir;
///
/// // Returns Ok on any platform where home-dir resolution succeeds.
/// if let Ok(dir) = default_approval_dir() {
///     assert!(dir.ends_with("approvals"));
/// }
/// ```
pub fn default_approval_dir() -> Result<PathBuf, StateDirError> {
    let dirs =
        directories::ProjectDirs::from("", "Soneso", "stellar-agent").ok_or(StateDirError)?;
    Ok(dirs.data_local_dir().join("approvals"))
}

/// Returns the OS-conventional passkeys registry directory.
///
/// Per-profile passkey credential registries are stored as
/// `<passkeys_dir>/<profile_name>.toml`.
///
/// - Linux: `~/.local/share/stellar-agent/passkeys/`
///   (`$XDG_DATA_HOME/stellar-agent/passkeys/` when `$XDG_DATA_HOME` is set)
/// - macOS: `~/Library/Application Support/stellar-agent/passkeys/`
/// - Windows: `%LOCALAPPDATA%\stellar-agent\passkeys\`
///
/// Uses `directories::ProjectDirs::data_local_dir` which maps to
/// `$XDG_DATA_HOME` (default `~/.local/share`) on Linux, NOT `$XDG_STATE_HOME`
/// (`~/.local/state`). Verified against `directories` v6 source
/// (`src/lin.rs:15-16`, `src/lin.rs:70`).
///
/// Tests may set `STELLAR_AGENT_HOME` to redirect this directory to
/// `$STELLAR_AGENT_HOME/passkeys`. The env-var read is **gated behind
/// `#[cfg(any(test, feature = "test-helpers"))]`** so production release builds
/// never honour it — this closes the env-injection credential-store-swap attack
/// surface.  The passkeys registry stores `CredentialMetadata` records keyed
/// by `credential_name`.
///
/// # Errors
///
/// Returns [`StateDirError`] when the platform directories library cannot
/// determine the user's data-local directory.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::profile::schema::default_passkeys_dir;
///
/// // Returns Ok on any platform where home-dir resolution succeeds.
/// if let Ok(dir) = default_passkeys_dir() {
///     assert!(dir.ends_with("passkeys"));
/// }
/// ```
pub fn default_passkeys_dir() -> Result<PathBuf, StateDirError> {
    // Gated env-var override: only honoured in test builds OR when the crate is
    // compiled with `--features test-helpers`. Production release builds never
    // read this variable, eliminating the env-injection credential-store-swap
    // surface.
    #[cfg(any(test, feature = "test-helpers"))]
    if let Some(home) = std::env::var_os("STELLAR_AGENT_HOME") {
        return Ok(PathBuf::from(home).join("passkeys"));
    }

    let dirs =
        directories::ProjectDirs::from("", "Soneso", "stellar-agent").ok_or(StateDirError)?;
    Ok(dirs.data_local_dir().join("passkeys"))
}

/// Returns the OS-conventional toolsets root directory.
///
/// Platform-specific locations:
/// - **Linux:**   `~/.local/share/stellar-agent/toolsets/`
/// - **macOS:**   `~/Library/Application Support/stellar-agent/toolsets/`
/// - **Windows:** `%LOCALAPPDATA%\stellar-agent\toolsets\`
///
/// Toolset packages are installed as one sub-directory per package under this
/// root.  The `stellar-agent-toolsets-install` crate resolves this path once
/// per install/uninstall operation and never trusts caller-supplied path
/// arguments for the root.
///
/// # Errors
///
/// Returns [`StateDirError`] when the platform directories library cannot
/// determine the user's data-local directory.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::profile::schema::default_toolsets_dir;
///
/// // Returns Ok on any platform where home-dir resolution succeeds.
/// if let Ok(dir) = default_toolsets_dir() {
///     assert!(dir.ends_with("toolsets"));
/// }
/// ```
pub fn default_toolsets_dir() -> Result<PathBuf, StateDirError> {
    // Gated env-var override: only honoured in test builds OR when the crate is
    // compiled with `--features test-helpers`. Production release builds never
    // read this variable, eliminating the env-injection store-swap surface.
    #[cfg(any(test, feature = "test-helpers"))]
    if let Some(home) = std::env::var_os("STELLAR_AGENT_HOME") {
        return Ok(PathBuf::from(home).join("toolsets"));
    }

    let dirs =
        directories::ProjectDirs::from("", "Soneso", "stellar-agent").ok_or(StateDirError)?;
    Ok(dirs.data_local_dir().join("toolsets"))
}

/// Returns the OS-conventional operator-approval credential registry
/// directory.
///
/// Per-profile operator-approval credential registries are stored as
/// `<dir>/<profile_name>.toml`. This is a distinct directory from
/// [`default_passkeys_dir`]: the two registries hold credentials for
/// different trust roles (smart-account transaction signing vs. consenting
/// to a pending wallet-controlled approval from a remote device) and must
/// never be conflated by sharing storage.
///
/// - Linux: `~/.local/share/stellar-agent/operator-approval-credentials/`
///   (`$XDG_DATA_HOME/stellar-agent/operator-approval-credentials/` when
///   `$XDG_DATA_HOME` is set)
/// - macOS: `~/Library/Application Support/stellar-agent/operator-approval-credentials/`
/// - Windows: `%LOCALAPPDATA%\stellar-agent\operator-approval-credentials\`
///
/// Tests may set `STELLAR_AGENT_HOME` to redirect this directory to
/// `$STELLAR_AGENT_HOME/operator-approval-credentials`. The env-var read is
/// gated behind `#[cfg(any(test, feature = "test-helpers"))]` so production
/// release builds never honour it, closing the env-injection
/// credential-store-swap attack surface.
///
/// # Errors
///
/// Returns [`StateDirError`] when the platform directories library cannot
/// determine the user's data-local directory.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::profile::schema::default_operator_approval_credentials_dir;
///
/// // Returns Ok on any platform where home-dir resolution succeeds.
/// if let Ok(dir) = default_operator_approval_credentials_dir() {
///     assert!(dir.ends_with("operator-approval-credentials"));
/// }
/// ```
pub fn default_operator_approval_credentials_dir() -> Result<PathBuf, StateDirError> {
    #[cfg(any(test, feature = "test-helpers"))]
    if let Some(home) = std::env::var_os("STELLAR_AGENT_HOME") {
        return Ok(PathBuf::from(home).join("operator-approval-credentials"));
    }

    let dirs =
        directories::ProjectDirs::from("", "Soneso", "stellar-agent").ok_or(StateDirError)?;
    Ok(dirs.data_local_dir().join("operator-approval-credentials"))
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

// Compile-time assertion: MINIMUM_FLOOR must equal 1 000 XLM in stroops
// (10^10 = 10_000_000 stroops/XLM × 1_000 XLM).  Guards against accidental
// changes to the constant that would silently raise the cross-check threshold.
const _: () = {
    assert!(
        MINIMUM_FLOOR == 10_000_000_000,
        "MINIMUM_FLOOR must be 10_000_000_000 (1 000 XLM in stroops = 10^10)"
    );
};

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use super::*;
    use crate::profile::caip2::{MAINNET_PASSPHRASE, TESTNET_PASSPHRASE};

    fn make_testnet_profile() -> Profile {
        Profile::builder_testnet(
            "stellar-agent-signer",
            "test-profile",
            "stellar-agent-nonce",
            "test-profile",
        )
        .build()
    }

    #[test]
    fn testnet_builder_chain_id() {
        let p = make_testnet_profile();
        assert_eq!(p.chain_id, crate::profile::caip2::Caip2::Testnet);
        assert!(!p.chain_id.is_mainnet());
    }

    #[test]
    fn testnet_builder_passphrase_derived_from_chain_id() {
        let p = make_testnet_profile();
        assert_eq!(p.network_passphrase, TESTNET_PASSPHRASE);
    }

    #[test]
    fn mainnet_builder_passphrase_derived_from_chain_id() {
        let p = Profile::builder_mainnet("s", "a", "n", "a").build();
        assert_eq!(p.network_passphrase, MAINNET_PASSPHRASE);
    }

    #[test]
    fn builder_testnet_named_derives_v2_keys_from_explicit_name() {
        let p = Profile::builder_testnet_named(
            "alice",
            "stellar-agent-signer",
            "alice-signer",
            "stellar-agent-nonce",
            "alice-nonce",
        )
        .build();

        assert_eq!(p.chain_id, crate::profile::caip2::Caip2::Testnet);
        assert_eq!(
            p.audit_log_hash_chain_key_id.service,
            "stellar-agent-audit-alice"
        );
        assert_eq!(p.policy_owner_key_id.service, "stellar-agent-owner-alice");
        assert_eq!(
            p.attestation_key_id.service,
            "stellar-agent-attestation-alice"
        );
        assert_eq!(
            p.counterparty_cache_key_id.service,
            "stellar-agent-counterparty-alice"
        );
    }

    #[test]
    fn builder_mainnet_named_derives_v2_keys_from_explicit_name() {
        let p = Profile::builder_mainnet_named(
            "bob",
            "stellar-agent-signer",
            "bob-signer",
            "stellar-agent-nonce",
            "bob-nonce",
        )
        .build();

        assert_eq!(p.chain_id, crate::profile::caip2::Caip2::Mainnet);
        assert_eq!(
            p.audit_log_hash_chain_key_id.service,
            "stellar-agent-audit-bob"
        );
        assert_eq!(p.policy_owner_key_id.service, "stellar-agent-owner-bob");
        assert_eq!(
            p.attestation_key_id.service,
            "stellar-agent-attestation-bob"
        );
        assert_eq!(
            p.counterparty_cache_key_id.service,
            "stellar-agent-counterparty-bob"
        );
    }

    #[test]
    fn builder_testnet_named_matches_manual_with_profile_name_chain() {
        let named = Profile::builder_testnet_named(
            "alice",
            "stellar-agent-signer",
            "alice-signer",
            "stellar-agent-nonce",
            "alice-nonce",
        )
        .build();
        let manual = Profile::builder_testnet(
            "stellar-agent-signer",
            "alice-signer",
            "stellar-agent-nonce",
            "alice-nonce",
        )
        .with_profile_name("alice")
        .build();

        assert_eq!(named.chain_id, manual.chain_id);
        assert_eq!(named.rpc_url, manual.rpc_url);
        assert_eq!(named.network_passphrase, manual.network_passphrase);
        assert_eq!(named.mcp_signer_default, manual.mcp_signer_default);
        assert_eq!(named.mcp_nonce_key_alias, manual.mcp_nonce_key_alias);
        assert_eq!(
            named.audit_log_hash_chain_key_id,
            manual.audit_log_hash_chain_key_id
        );
        assert_eq!(named.policy_owner_key_id, manual.policy_owner_key_id);
        assert_eq!(named.attestation_key_id, manual.attestation_key_id);
        assert_eq!(
            named.counterparty_cache_key_id,
            manual.counterparty_cache_key_id
        );
    }

    #[test]
    fn effective_usd_threshold_floor_on_zero() {
        let mut p = make_testnet_profile();
        p.usd_threshold = 0;
        assert_eq!(p.effective_usd_threshold(), MINIMUM_FLOOR);
    }

    #[test]
    fn effective_usd_threshold_floor_on_below_minimum() {
        let mut p = make_testnet_profile();
        p.usd_threshold = MINIMUM_FLOOR - 1;
        assert_eq!(p.effective_usd_threshold(), MINIMUM_FLOOR);
    }

    #[test]
    fn effective_usd_threshold_above_floor_passes_through() {
        let mut p = make_testnet_profile();
        p.usd_threshold = MINIMUM_FLOOR + 500;
        assert_eq!(p.effective_usd_threshold(), MINIMUM_FLOOR + 500);
    }

    #[test]
    fn effective_usd_threshold_max_passthrough() {
        let mut p = make_testnet_profile();
        p.usd_threshold = u64::MAX;
        assert_eq!(p.effective_usd_threshold(), u64::MAX);
    }

    #[test]
    fn validate_rpc_url_valid() {
        let p = make_testnet_profile();
        assert!(p.validate_rpc_url().is_ok());
    }

    #[test]
    fn validate_rpc_url_invalid() {
        let mut p = make_testnet_profile();
        p.rpc_url = "not-a-url".to_owned();
        assert!(p.validate_rpc_url().is_err());
    }

    #[test]
    fn keyring_entry_ref_new() {
        let r = KeyringEntryRef::new("svc", "acct");
        assert_eq!(r.service, "svc");
        assert_eq!(r.account, "acct");
    }

    #[test]
    fn mcp_disabled_default_false() {
        let p = make_testnet_profile();
        assert!(!p.mcp_disabled);
    }

    #[test]
    fn mcp_disabled_builder() {
        let p = Profile::builder_testnet("s", "a", "n", "b")
            .mcp_disabled()
            .build();
        assert!(p.mcp_disabled);
    }

    #[test]
    fn classic_fee_per_op_default_none() {
        let p = make_testnet_profile();
        assert_eq!(p.classic_fee_per_op_stroops, None);
    }

    #[test]
    fn classic_fee_per_op_serde_round_trip() {
        let p = Profile::builder_testnet("s", "a", "n", "b")
            .classic_fee_per_op_stroops(Some(250))
            .build();
        let toml_str = toml::to_string(&p).unwrap();
        assert!(
            toml_str.contains("classic_fee_per_op_stroops = 250"),
            "profile TOML must persist the per-op fee override, got: {toml_str}"
        );

        let restored: Profile = toml::from_str(&toml_str).unwrap();
        assert_eq!(restored.classic_fee_per_op_stroops, Some(250));
    }

    #[test]
    fn classic_fee_per_op_absent_deserializes_to_none() {
        let p = make_testnet_profile();
        let toml_str = toml::to_string(&p).unwrap();
        assert!(
            !toml_str.contains("classic_fee_per_op_stroops"),
            "None fee override should be omitted from profile TOML"
        );

        let restored: Profile = toml::from_str(&toml_str).unwrap();
        assert_eq!(restored.classic_fee_per_op_stroops, None);
    }

    #[test]
    fn submit_timeout_seconds_defaults_to_none_when_absent() {
        let p = make_testnet_profile();
        let toml_str = toml::to_string(&p).unwrap();
        assert!(
            !toml_str.contains("submit_timeout_seconds"),
            "None submit timeout should be omitted from profile TOML"
        );

        let restored: Profile = toml::from_str(&toml_str).unwrap();
        assert_eq!(restored.submit_timeout_seconds, None);
    }

    #[test]
    fn submit_timeout_seconds_round_trips() {
        let mut p = make_testnet_profile();
        p.submit_timeout_seconds = Some(120);
        let toml_str = toml::to_string(&p).unwrap();
        assert!(
            toml_str.contains("submit_timeout_seconds = 120"),
            "profile TOML must persist submit timeout override, got: {toml_str}"
        );

        let restored: Profile = toml::from_str(&toml_str).unwrap();
        assert_eq!(restored.submit_timeout_seconds, Some(120));
    }

    #[test]
    fn version_is_2() {
        let p = make_testnet_profile();
        assert_eq!(p.version, 2);
    }

    #[test]
    fn audit_key_default_derived_name() {
        let p = make_testnet_profile();
        assert_eq!(
            p.audit_log_hash_chain_key_id.service,
            "stellar-agent-audit-test-profile"
        );
        assert_eq!(p.audit_log_hash_chain_key_id.account, "default");
    }

    #[test]
    fn default_audit_log_path_for_appends_profile_log_under_audit() {
        let path = default_audit_log_path_for("alice");

        assert_eq!(path.file_name().unwrap(), "alice.jsonl");
        assert_eq!(path.parent().unwrap().file_name().unwrap(), "audit");
    }

    #[test]
    fn default_audit_log_path_for_sanitises_profile_name() {
        let path = default_audit_log_path_for("../alice\\bob");

        assert_eq!(path.file_name().unwrap(), "___alice_bob.jsonl");
        assert_eq!(path.parent().unwrap().file_name().unwrap(), "audit");
    }

    #[test]
    fn default_audit_log_path_for_empty_profile_uses_default_stem() {
        let path = default_audit_log_path_for("");

        assert_eq!(path.file_name().unwrap(), "default.jsonl");
    }

    #[test]
    fn default_audit_log_path_for_prefixes_windows_reserved_stems() {
        let path = default_audit_log_path_for("CON");

        assert_eq!(path.file_name().unwrap(), "_CON.jsonl");
    }

    #[test]
    fn default_audit_log_path_for_uses_platform_project_dir_shape() {
        let path = default_audit_log_path_for("alice");
        let rendered = path.to_string_lossy();

        #[cfg(target_os = "linux")]
        {
            assert!(
                rendered.contains("/stellar-agent/audit/alice.jsonl"),
                "linux path should end under stellar-agent/audit: {rendered}"
            );
        }

        #[cfg(target_os = "macos")]
        {
            assert!(
                rendered.contains("/Library/Application Support/stellar-agent/audit/alice.jsonl"),
                "macOS path should use Application Support: {rendered}"
            );
        }

        #[cfg(target_os = "windows")]
        {
            assert!(
                rendered.ends_with(r"stellar-agent\audit\alice.jsonl"),
                "windows path should end under stellar-agent\\audit: {rendered}"
            );
        }
    }

    #[test]
    fn owner_key_default_derived_name() {
        let p = make_testnet_profile();
        assert_eq!(
            p.policy_owner_key_id.service,
            "stellar-agent-owner-test-profile"
        );
        assert_eq!(p.policy_owner_key_id.account, "default");
    }

    #[test]
    fn attestation_key_default_derived_name() {
        let p = make_testnet_profile();
        assert_eq!(
            p.attestation_key_id.service,
            "stellar-agent-attestation-test-profile"
        );
        assert_eq!(p.attestation_key_id.account, "default");
    }

    #[test]
    fn counterparty_key_default_derived_name() {
        let p = make_testnet_profile();
        assert_eq!(
            p.counterparty_cache_key_id.service,
            "stellar-agent-counterparty-test-profile"
        );
        assert_eq!(p.counterparty_cache_key_id.account, "default");
    }

    #[test]
    fn oracle_provider_url_default_none() {
        let p = make_testnet_profile();
        assert_eq!(p.oracle_provider_url, None);
    }

    /// New profiles minted via the builder default to `V1`.  Migrated profiles
    /// retain `Noop` — see `migrate_v1_to_v2_produces_noop_engine` in
    /// `migrate.rs`.
    #[test]
    fn policy_engine_default_v1_for_new_profiles() {
        let p = make_testnet_profile();
        assert_eq!(
            p.policy.engine,
            PolicyEngineKind::V1,
            "new profiles must default to V1"
        );
    }

    /// Both testnet and mainnet builder-produced profiles default to `V1`.
    #[test]
    fn policy_engine_default_v1_for_new_mainnet_profiles() {
        let p = Profile::builder_mainnet("s", "a", "n", "a").build();
        assert_eq!(
            p.policy.engine,
            PolicyEngineKind::V1,
            "new mainnet profiles must also default to V1"
        );
    }

    #[test]
    fn policy_engine_builder_sets_noop_for_testnet_profile() {
        let p = Profile::builder_testnet("s", "a", "n", "b")
            .policy_engine(PolicyEngineKind::Noop)
            .build();

        assert_eq!(p.policy.engine, PolicyEngineKind::Noop);
    }

    #[test]
    fn policy_engine_builder_sets_v1_for_mainnet_profile() {
        let p = Profile::builder_mainnet("s", "a", "n", "b")
            .policy_engine(PolicyEngineKind::V1)
            .build();

        assert_eq!(p.policy.engine, PolicyEngineKind::V1);
    }

    #[test]
    fn policy_engine_builder_overrides_prior_noop_choice() {
        let p = Profile::builder_testnet("s", "a", "n", "b")
            .with_noop_engine()
            .policy_engine(PolicyEngineKind::V1)
            .build();

        assert_eq!(p.policy.engine, PolicyEngineKind::V1);
    }

    #[test]
    fn with_noop_engine_overrides_prior_policy_engine_choice() {
        let p = Profile::builder_testnet("s", "a", "n", "b")
            .policy_engine(PolicyEngineKind::V1)
            .with_noop_engine()
            .build();

        assert_eq!(p.policy.engine, PolicyEngineKind::Noop);
    }

    #[test]
    fn policy_engine_kind_serde_round_trip() {
        let cfg = PolicyConfig {
            engine: PolicyEngineKind::V1,
        };
        let toml_str = toml::to_string(&cfg).unwrap();
        let restored: PolicyConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(restored.engine, PolicyEngineKind::V1);
    }

    #[test]
    fn policy_engine_kind_noop_serde() {
        let cfg = PolicyConfig {
            engine: PolicyEngineKind::Noop,
        };
        let toml_str = toml::to_string(&cfg).unwrap();
        assert!(toml_str.contains("noop"), "noop must serialise as 'noop'");
    }

    #[test]
    fn keyring_entry_ref_default_helpers() {
        let audit = KeyringEntryRef::default_audit_key("prof");
        assert_eq!(audit.service, "stellar-agent-audit-prof");

        let owner = KeyringEntryRef::default_owner_key("prof");
        assert_eq!(owner.service, "stellar-agent-owner-prof");

        let attest = KeyringEntryRef::default_attestation_key("prof");
        assert_eq!(attest.service, "stellar-agent-attestation-prof");

        let counter = KeyringEntryRef::default_counterparty_key("prof");
        assert_eq!(counter.service, "stellar-agent-counterparty-prof");
    }

    /// With `STELLAR_AGENT_HOME` set, `default_profile_dir` and
    /// `default_policy_dir` redirect to `$STELLAR_AGENT_HOME/profiles` and
    /// `$STELLAR_AGENT_HOME/policies` respectively, mirroring the
    /// `default_passkeys_dir` / `default_toolsets_dir` override contract.
    ///
    /// `#[serial]` because `STELLAR_AGENT_HOME` is a process-global env var;
    /// a concurrently-running sibling test that reads or sets it would race.
    #[test]
    #[serial_test::serial]
    fn stellar_agent_home_override_redirects_profile_and_policy_dirs() {
        let dir = tempfile::tempdir().expect("tempdir");
        let _guard = stellar_agent_test_support::StellarAgentHomeGuard::new(dir.path());

        let profile_dir = default_profile_dir().expect("default_profile_dir must succeed");
        assert_eq!(profile_dir, dir.path().join("profiles"));

        let policy_dir = default_policy_dir().expect("default_policy_dir must succeed");
        assert_eq!(policy_dir, dir.path().join("policies"));
    }

    /// `default_passkeys_dir` returns a path ending with the `passkeys`
    /// component and uses the OS-conventional project-dirs base.
    ///
    /// `#[serial]`: `default_passkeys_dir` honours the process-global
    /// `STELLAR_AGENT_HOME` override; serialising avoids a race against
    /// `stellar_agent_home_override_redirects_profile_and_policy_dirs` and the
    /// other `STELLAR_AGENT_HOME`-sensitive tests in this module.
    #[test]
    #[serial_test::serial]
    fn default_passkeys_dir_ends_with_passkeys_component() {
        let dir = default_passkeys_dir().expect("default_passkeys_dir must succeed on CI");
        assert!(
            dir.ends_with("passkeys"),
            "default_passkeys_dir must end with 'passkeys' component: {dir:?}"
        );

        let rendered = dir.to_string_lossy();

        #[cfg(target_os = "linux")]
        assert!(
            rendered.contains("/stellar-agent/passkeys"),
            "linux path must contain stellar-agent/passkeys: {rendered}"
        );

        #[cfg(target_os = "macos")]
        assert!(
            rendered.contains("stellar-agent/passkeys"),
            "macOS path must contain stellar-agent/passkeys: {rendered}"
        );

        #[cfg(target_os = "windows")]
        assert!(
            rendered.contains(r"stellar-agent\passkeys"),
            "windows path must contain stellar-agent\\passkeys: {rendered}"
        );
    }

    /// `default_operator_approval_credentials_dir` returns a path ending with
    /// the `operator-approval-credentials` component, distinct from
    /// `default_passkeys_dir`.
    ///
    /// `#[serial]`: both dir functions honour the `STELLAR_AGENT_HOME`
    /// override; see `default_passkeys_dir_ends_with_passkeys_component`.
    #[test]
    #[serial_test::serial]
    fn default_operator_approval_credentials_dir_ends_with_expected_component() {
        let dir = default_operator_approval_credentials_dir()
            .expect("default_operator_approval_credentials_dir must succeed on CI");
        assert!(
            dir.ends_with("operator-approval-credentials"),
            "must end with 'operator-approval-credentials' component: {dir:?}"
        );

        let passkeys_dir = default_passkeys_dir().expect("default_passkeys_dir must succeed on CI");
        assert_ne!(
            dir, passkeys_dir,
            "operator-approval credential dir must be distinct from the smart-account \
             passkeys dir"
        );
    }

    // ── KeyringEntryRef helpers ───────────────────────────────────────────────

    #[test]
    fn keyring_entry_ref_default_pool_master_key() {
        let r = KeyringEntryRef::default_pool_master_key("carol");
        assert_eq!(r.service, "stellar-agent-pool-carol");
        assert_eq!(r.account, "master");
    }

    #[test]
    fn keyring_entry_ref_clone_and_equality() {
        let a = KeyringEntryRef::new("svc", "acct");
        let b = a.clone();
        assert_eq!(a, b);
        let c = KeyringEntryRef::new("svc", "other");
        assert_ne!(a, c);
    }

    // ── PoolChannelRecord and PoolConfig ─────────────────────────────────────

    #[test]
    fn pool_channel_record_new_stores_fields() {
        let rec = PoolChannelRecord::new(7, "GABC123");
        assert_eq!(rec.index, 7);
        assert_eq!(rec.public_key, "GABC123");
    }

    #[test]
    fn pool_channel_record_serde_round_trip() {
        let rec = PoolChannelRecord::new(3, "GDEF456");
        let json = serde_json::to_string(&rec).unwrap();
        let restored: PoolChannelRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.index, 3);
        assert_eq!(restored.public_key, "GDEF456");
    }

    #[test]
    fn pool_config_new_stores_fields() {
        let channels = vec![
            PoolChannelRecord::new(1, "GAAA"),
            PoolChannelRecord::new(2, "GBBB"),
        ];
        let cfg = PoolConfig::new(2, channels.clone());
        assert_eq!(cfg.pool_size, 2);
        assert_eq!(cfg.channels.len(), 2);
        assert_eq!(cfg.channels[0].index, 1);
        assert_eq!(cfg.channels[1].public_key, "GBBB");
    }

    #[test]
    fn pool_config_serde_round_trip() {
        let cfg = PoolConfig::new(1, vec![PoolChannelRecord::new(1, "GCCC")]);
        let json = serde_json::to_string(&cfg).unwrap();
        let restored: PoolConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.pool_size, 1);
        assert_eq!(restored.channels[0].index, 1);
        assert_eq!(restored.channels[0].public_key, "GCCC");
    }

    // ── Profile::Debug redaction ──────────────────────────────────────────────

    #[test]
    fn profile_debug_redacts_rpc_url() {
        let mut p = Profile::builder_testnet(
            "stellar-agent-signer",
            "dbg-profile",
            "stellar-agent-nonce",
            "dbg-profile",
        )
        .rpc_url("https://user:secret-password@rpc.example.com/api")
        .build();
        p.secondary_rpc_url = Some("https://user:other-secret@secondary.example.com".to_owned());

        let dbg = format!("{p:?}");

        // The raw credential-bearing URLs must not appear.
        assert!(
            !dbg.contains("secret-password"),
            "rpc_url credentials must be redacted from Debug output; got: {dbg}"
        );
        assert!(
            !dbg.contains("other-secret"),
            "secondary_rpc_url credentials must be redacted from Debug output; got: {dbg}"
        );
        // The redaction placeholder must appear.
        assert!(
            dbg.contains("[redacted]"),
            "Debug output must contain '[redacted]' placeholder; got: {dbg}"
        );
    }

    #[test]
    fn profile_debug_secondary_rpc_url_none_shows_none() {
        let p = make_testnet_profile();
        // secondary_rpc_url is None on a freshly built profile.
        let dbg = format!("{p:?}");
        // Debug for Option<_>.map(|_| "[redacted]") when None renders as None.
        assert!(
            dbg.contains("secondary_rpc_url: None"),
            "secondary_rpc_url None must render as None in Debug; got: {dbg}"
        );
    }

    // ── RpcUrlParseError display ──────────────────────────────────────────────

    #[test]
    fn rpc_url_parse_error_display_contains_raw_url() {
        let mut p = make_testnet_profile();
        p.rpc_url = "not-a-url".to_owned();
        let err = p.validate_rpc_url().unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("not-a-url"),
            "RpcUrlParseError display must contain the raw URL; got: {msg}"
        );
        assert!(
            msg.starts_with("invalid rpc_url"),
            "RpcUrlParseError display must start with 'invalid rpc_url'; got: {msg}"
        );
    }

    // ── ProfileBuilder setters not yet tested ─────────────────────────────────

    #[test]
    fn builder_rpc_url_override() {
        let custom_url = "https://custom-rpc.example.com";
        let p = Profile::builder_testnet("s", "a", "n", "b")
            .rpc_url(custom_url)
            .build();
        assert_eq!(p.rpc_url, custom_url);
    }

    #[test]
    fn builder_usd_threshold_override() {
        let p = Profile::builder_testnet("s", "a", "n", "b")
            .usd_threshold(999_999_999_999)
            .build();
        assert_eq!(p.usd_threshold, 999_999_999_999);
    }

    #[test]
    fn builder_classic_max_fee_per_op_stroops_some_and_none() {
        let p_some = Profile::builder_testnet("s", "a", "n", "b")
            .classic_max_fee_per_op_stroops(Some(500))
            .build();
        assert_eq!(p_some.classic_max_fee_per_op_stroops, Some(500));

        let p_none = Profile::builder_testnet("s", "a", "n", "b")
            .classic_max_fee_per_op_stroops(None)
            .build();
        assert_eq!(p_none.classic_max_fee_per_op_stroops, None);
    }

    #[test]
    fn classic_max_fee_per_op_stroops_serde_round_trip() {
        let p = Profile::builder_testnet("s", "a", "n", "b")
            .classic_max_fee_per_op_stroops(Some(750))
            .build();
        let toml_str = toml::to_string(&p).unwrap();
        assert!(
            toml_str.contains("classic_max_fee_per_op_stroops = 750"),
            "profile TOML must persist the max-fee cap, got: {toml_str}"
        );
        let restored: Profile = toml::from_str(&toml_str).unwrap();
        assert_eq!(restored.classic_max_fee_per_op_stroops, Some(750));
    }

    #[test]
    fn classic_max_fee_per_op_none_absent_from_toml() {
        let p = make_testnet_profile();
        let toml_str = toml::to_string(&p).unwrap();
        assert!(
            !toml_str.contains("classic_max_fee_per_op_stroops"),
            "None max-fee cap must be omitted from profile TOML"
        );
    }

    #[test]
    fn builder_audit_log_path_override() {
        let custom = std::path::PathBuf::from("/tmp/stellar-agent/my-audit.log");
        let p = Profile::builder_testnet("s", "a", "n", "b")
            .audit_log_path(custom.clone())
            .build();
        assert_eq!(p.audit_log_path, custom);
    }

    #[test]
    fn builder_oracle_provider_url_some_and_none() {
        use url::Url;

        let url = Url::parse("https://oracle.example.com/rpc").unwrap();
        let p_some = Profile::builder_testnet("s", "a", "n", "b")
            .oracle_provider_url(url.clone())
            .build();
        assert_eq!(p_some.oracle_provider_url, Some(url));

        let p_none = Profile::builder_testnet("s", "a", "n", "b")
            .oracle_provider_url(None)
            .build();
        assert_eq!(p_none.oracle_provider_url, None);
    }

    #[test]
    fn oracle_provider_url_serde_round_trip() {
        use url::Url;

        let url = Url::parse("https://oracle.example.com/rpc").unwrap();
        let p = Profile::builder_testnet("s", "a", "n", "b")
            .oracle_provider_url(url.clone())
            .build();
        let toml_str = toml::to_string(&p).unwrap();
        assert!(
            toml_str.contains("oracle_provider_url"),
            "oracle_provider_url must appear in profile TOML when set"
        );
        let restored: Profile = toml::from_str(&toml_str).unwrap();
        assert_eq!(restored.oracle_provider_url, Some(url));
    }

    #[test]
    fn builder_wallet_override() {
        let cfg = WalletConfig {
            mlock_required: crate::wallet::MlockRequired::False,
            unlock_ttl_seconds: 15,
        };
        let p = Profile::builder_testnet("s", "a", "n", "b")
            .wallet(cfg)
            .build();
        assert_eq!(p.wallet.mlock_required, crate::wallet::MlockRequired::False);
        assert_eq!(p.wallet.unlock_ttl_seconds, 15);
    }

    #[test]
    fn wallet_config_serde_round_trip() {
        let p = Profile::builder_testnet("s", "a", "n", "b")
            .wallet(WalletConfig {
                mlock_required: crate::wallet::MlockRequired::Warn,
                unlock_ttl_seconds: 20,
            })
            .build();
        let toml_str = toml::to_string(&p).unwrap();
        let restored: Profile = toml::from_str(&toml_str).unwrap();
        assert_eq!(
            restored.wallet.mlock_required,
            crate::wallet::MlockRequired::Warn
        );
        assert_eq!(restored.wallet.unlock_ttl_seconds, 20);
    }

    #[test]
    fn wallet_config_default_unlock_ttl_is_30() {
        let p = make_testnet_profile();
        assert_eq!(p.wallet.unlock_ttl_seconds, 30);
    }

    #[test]
    fn builder_session_rule_max_horizon_ledgers_some_and_none() {
        let p_some = Profile::builder_testnet("s", "a", "n", "b")
            .session_rule_max_horizon_ledgers(Some(500))
            .build();
        assert_eq!(p_some.session_rule_max_horizon_ledgers, Some(500));

        let p_none = Profile::builder_testnet("s", "a", "n", "b")
            .session_rule_max_horizon_ledgers(None)
            .build();
        assert_eq!(p_none.session_rule_max_horizon_ledgers, None);
    }

    #[test]
    fn session_rule_max_horizon_ledgers_serde_round_trip() {
        let p = Profile::builder_testnet("s", "a", "n", "b")
            .session_rule_max_horizon_ledgers(Some(2000))
            .build();
        let toml_str = toml::to_string(&p).unwrap();
        assert!(
            toml_str.contains("session_rule_max_horizon_ledgers = 2000"),
            "session_rule_max_horizon_ledgers must appear in TOML when set; got: {toml_str}"
        );
        let restored: Profile = toml::from_str(&toml_str).unwrap();
        assert_eq!(restored.session_rule_max_horizon_ledgers, Some(2000));
    }

    #[test]
    fn builder_secondary_rpc_url_some_and_none() {
        let p_some = Profile::builder_testnet("s", "a", "n", "b")
            .secondary_rpc_url(Some("https://secondary.example.com".to_owned()))
            .build();
        assert_eq!(
            p_some.secondary_rpc_url.as_deref(),
            Some("https://secondary.example.com")
        );

        let p_none = Profile::builder_testnet("s", "a", "n", "b")
            .secondary_rpc_url(None)
            .build();
        assert_eq!(p_none.secondary_rpc_url, None);
    }

    #[test]
    fn secondary_rpc_url_omitted_from_toml_when_none() {
        let p = make_testnet_profile();
        let toml_str = toml::to_string(&p).unwrap();
        assert!(
            !toml_str.contains("secondary_rpc_url"),
            "None secondary_rpc_url must be absent from profile TOML"
        );
    }

    #[test]
    fn secondary_rpc_url_serde_round_trip_when_set() {
        let p = Profile::builder_testnet("s", "a", "n", "b")
            .secondary_rpc_url("https://secondary.example.com".to_owned())
            .build();
        let toml_str = toml::to_string(&p).unwrap();
        let restored: Profile = toml::from_str(&toml_str).unwrap();
        assert_eq!(
            restored.secondary_rpc_url.as_deref(),
            Some("https://secondary.example.com")
        );
    }

    // ── Pool fields are None in freshly built profiles ────────────────────────

    #[test]
    fn pool_fields_none_in_new_profile() {
        let p = make_testnet_profile();
        assert!(
            p.pool_master_key_id.is_none(),
            "pool_master_key_id must be None in a newly built profile"
        );
        assert!(
            p.pool_config.is_none(),
            "pool_config must be None in a newly built profile"
        );
    }

    // ── remote_approval is None by default, and round-trips when set ─────────

    #[test]
    fn remote_approval_none_in_new_profile() {
        let p = make_testnet_profile();
        assert!(
            p.remote_approval.is_none(),
            "remote_approval must be None in a newly built profile"
        );
        let toml_str = toml::to_string(&p).unwrap();
        assert!(
            !toml_str.contains("remote_approval"),
            "absent remote_approval must be omitted from serialised TOML: {toml_str}"
        );
    }

    #[test]
    fn remote_approval_serde_round_trip_when_set() {
        let mut p = make_testnet_profile();
        p.remote_approval = Some(RemoteApprovalConfig {
            enabled: true,
            bind: "0.0.0.0:8443".to_owned(),
            rp_id: "wallet.internal".to_owned(),
            allowed_credentials: vec!["AABBCCDDEEFFGGHHIIJJKK".to_owned()],
        });
        let toml_str = toml::to_string(&p).unwrap();
        let restored: Profile = toml::from_str(&toml_str).unwrap();
        let cfg = restored
            .remote_approval
            .expect("remote_approval must round-trip");
        assert!(cfg.enabled);
        assert_eq!(cfg.bind, "0.0.0.0:8443");
        assert_eq!(cfg.rp_id, "wallet.internal");
        assert_eq!(cfg.allowed_credentials, vec!["AABBCCDDEEFFGGHHIIJJKK"]);
    }

    #[test]
    fn remote_approval_enabled_defaults_to_false_when_omitted() {
        let toml_str = "bind = \"0.0.0.0:8443\"\nrp_id = \"wallet.internal\"\n";
        let cfg: RemoteApprovalConfig = toml::from_str(toml_str).unwrap();
        assert!(!cfg.enabled, "enabled must default to false when omitted");
        assert!(
            cfg.allowed_credentials.is_empty(),
            "allowed_credentials must default to empty when omitted"
        );
    }

    /// `Debug` output for `RemoteApprovalConfig` must redact allowlisted
    /// credential IDs, matching the redaction discipline used for credential
    /// IDs elsewhere in the wallet.
    #[test]
    fn remote_approval_config_debug_redacts_credential_ids() {
        let cfg = RemoteApprovalConfig {
            enabled: true,
            bind: "0.0.0.0:8443".to_owned(),
            rp_id: "wallet.internal".to_owned(),
            allowed_credentials: vec!["AABBCCDDEEFFGGHHIIJJKK".to_owned()],
        };
        let debug_str = format!("{cfg:?}");
        assert!(
            !debug_str.contains("AABBCCDDEEFFGGHHIIJJKK"),
            "full credential ID must not appear in Debug output: {debug_str}"
        );
        assert!(
            debug_str.contains("wallet.internal"),
            "rp_id is not secret and should appear verbatim: {debug_str}"
        );
    }

    // ── PolicyEngineKind::default is V1 ──────────────────────────────────────

    #[test]
    fn policy_engine_kind_default_is_v1() {
        assert_eq!(
            PolicyEngineKind::default(),
            PolicyEngineKind::V1,
            "PolicyEngineKind::default must be V1"
        );
    }

    // ── OS-conventional directory helpers ─────────────────────────────────────

    #[test]
    fn default_audit_log_path_ends_with_audit_log() {
        let path = default_audit_log_path().expect("default_audit_log_path must succeed on CI");
        assert_eq!(
            path.file_name().unwrap(),
            "audit.log",
            "default_audit_log_path must end with 'audit.log'; got: {path:?}"
        );
        assert!(
            path.to_string_lossy().contains("stellar-agent"),
            "default_audit_log_path must be under stellar-agent directory; got: {path:?}"
        );
    }

    /// `#[serial]`: see `default_passkeys_dir_ends_with_passkeys_component`.
    #[test]
    #[serial_test::serial]
    fn default_profile_dir_ends_with_profiles() {
        let dir = default_profile_dir().expect("default_profile_dir must succeed on CI");
        assert_eq!(
            dir.file_name().unwrap(),
            "profiles",
            "default_profile_dir must end with 'profiles'; got: {dir:?}"
        );
        assert!(
            dir.to_string_lossy().contains("stellar-agent"),
            "default_profile_dir must be under stellar-agent directory; got: {dir:?}"
        );
    }

    /// `#[serial]`: see `default_passkeys_dir_ends_with_passkeys_component`.
    #[test]
    #[serial_test::serial]
    fn default_policy_dir_ends_with_policies() {
        let dir = default_policy_dir().expect("default_policy_dir must succeed on CI");
        assert_eq!(
            dir.file_name().unwrap(),
            "policies",
            "default_policy_dir must end with 'policies'; got: {dir:?}"
        );
        assert!(
            dir.to_string_lossy().contains("stellar-agent"),
            "default_policy_dir must be under stellar-agent directory; got: {dir:?}"
        );
    }

    #[test]
    fn default_approval_dir_ends_with_approvals() {
        let dir = default_approval_dir().expect("default_approval_dir must succeed on CI");
        assert_eq!(
            dir.file_name().unwrap(),
            "approvals",
            "default_approval_dir must end with 'approvals'; got: {dir:?}"
        );
        assert!(
            dir.to_string_lossy().contains("stellar-agent"),
            "default_approval_dir must be under stellar-agent directory; got: {dir:?}"
        );
    }

    /// `#[serial]`: see `default_passkeys_dir_ends_with_passkeys_component`.
    #[test]
    #[serial_test::serial]
    fn default_toolsets_dir_ends_with_toolsets() {
        let dir = default_toolsets_dir().expect("default_toolsets_dir must succeed on CI");
        assert_eq!(
            dir.file_name().unwrap(),
            "toolsets",
            "default_toolsets_dir must end with 'toolsets'; got: {dir:?}"
        );
        assert!(
            dir.to_string_lossy().contains("stellar-agent"),
            "default_toolsets_dir must be under stellar-agent directory; got: {dir:?}"
        );
    }

    // ── audit_log_file_stem: Windows-reserved names (COM / LPT variants) ─────

    #[test]
    fn audit_log_file_stem_prefixes_all_com_variants() {
        for name in &[
            "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        ] {
            let path = default_audit_log_path_for(name);
            let stem = path.file_stem().unwrap().to_string_lossy().into_owned();
            assert!(
                stem.starts_with('_'),
                "Windows-reserved name {name} must be prefixed with '_'; got stem: {stem}"
            );
        }
    }

    #[test]
    fn audit_log_file_stem_prefixes_all_lpt_variants() {
        for name in &[
            "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
        ] {
            let path = default_audit_log_path_for(name);
            let stem = path.file_stem().unwrap().to_string_lossy().into_owned();
            assert!(
                stem.starts_with('_'),
                "Windows-reserved name {name} must be prefixed with '_'; got stem: {stem}"
            );
        }
    }

    #[test]
    fn audit_log_file_stem_prefixes_prn_aux_nul() {
        for name in &["PRN", "AUX", "NUL"] {
            let path = default_audit_log_path_for(name);
            let stem = path.file_stem().unwrap().to_string_lossy().into_owned();
            assert!(
                stem.starts_with('_'),
                "Windows-reserved name {name} must be prefixed with '_'; got stem: {stem}"
            );
        }
    }

    #[test]
    fn audit_log_file_stem_prefixes_reserved_names_case_insensitive() {
        // Lowercase forms must also be treated as reserved.
        for name in &["con", "prn", "aux", "nul", "com1", "lpt9"] {
            let path = default_audit_log_path_for(name);
            let stem = path.file_stem().unwrap().to_string_lossy().into_owned();
            assert!(
                stem.starts_with('_'),
                "Lowercase reserved name {name} must be prefixed with '_'; got stem: {stem}"
            );
        }
    }

    #[test]
    fn audit_log_file_stem_allows_normal_names() {
        // Names that look similar but are not reserved must not be prefixed.
        for name in &[
            "connect",
            "prolog",
            "auxiliary",
            "nullify",
            "combo",
            "laptop",
        ] {
            let path = default_audit_log_path_for(name);
            let stem = path.file_stem().unwrap().to_string_lossy().into_owned();
            assert!(
                !stem.starts_with('_'),
                "Non-reserved name {name} must not be prefixed with '_'; got stem: {stem}"
            );
        }
    }

    // ── ProfileBuilder::policy setter ─────────────────────────────────────────

    #[test]
    fn builder_policy_setter_overrides_default() {
        let cfg = PolicyConfig {
            engine: PolicyEngineKind::Noop,
        };
        let p = Profile::builder_testnet("s", "a", "n", "b")
            .policy(cfg)
            .build();
        assert_eq!(p.policy.engine, PolicyEngineKind::Noop);
    }

    // ── smart_account_max_context_rule_scan_id ────────────────────────────────

    #[test]
    fn smart_account_max_scan_id_defaults_to_none() {
        let p = make_testnet_profile();
        assert_eq!(p.smart_account_max_context_rule_scan_id, None);
    }

    #[test]
    fn smart_account_max_scan_id_serde_round_trip() {
        let mut p = make_testnet_profile();
        p.smart_account_max_context_rule_scan_id = Some(200);
        let toml_str = toml::to_string(&p).unwrap();
        assert!(
            toml_str.contains("smart_account_max_context_rule_scan_id = 200"),
            "scan id override must appear in TOML; got: {toml_str}"
        );
        let restored: Profile = toml::from_str(&toml_str).unwrap();
        assert_eq!(restored.smart_account_max_context_rule_scan_id, Some(200));
    }
}
