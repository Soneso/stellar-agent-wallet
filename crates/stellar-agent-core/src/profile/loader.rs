//! figment-backed profile loader.
//!
//! The profile file is the record the operator audits, and a profile's trust
//! roots come from that file only. An overlay may set a fixed allowlist of
//! operational fields. `submit_timeout_seconds` is overlayable on every chain.
//! The endpoint, signer, fee, threshold, and scan-bound fields are overlayable
//! on testnet only. `mcp_disabled` accepts only `true`. Naming any other
//! profile key, alias included, is refused even with an equal value, because
//! an overlay can hide a later edit to that record.
//!
//! Loads the permitted fields from three sources in priority order:
//!
//! 1. **Programmatic overlay**: key/value pairs a library caller passes to
//!    [`load_with_overlay`] (highest priority).
//! 2. **Environment variables**: `STELLAR_AGENT_<FIELD>` prefixed variables.
//! 3. **TOML file**: `<profile_dir>/<name>.toml` (lowest priority).
//!
//! # Path resolution
//!
//! Profile files live at the OS-conventional data directory:
//!
//! | Platform | Path |
//! |----------|------|
//! | Linux    | `~/.local/share/stellar-agent/profiles/<name>.toml` |
//! | macOS    | `~/Library/Application Support/Soneso.stellar-agent/profiles/<name>.toml` |
//! | Windows  | `%LOCALAPPDATA%\Soneso\stellar-agent\data\profiles\<name>.toml` |
//!
//! # Name safety
//!
//! The profile name becomes a path component, so every read and write entry
//! point validates it with
//! [`crate::profile::name::validate_path_component_ascii_safe`] **before** the
//! join, refusing with [`ProfileLoadError::InvalidName`] or
//! [`ProfileSaveError::InvalidName`]. The guard sits at the join rather than at
//! each caller so that a caller which does not validate still cannot address a
//! file outside the profile directory.
//!
//! # Version enforcement
//!
//! After loading, the `version` field is checked.  Any value other than `2`
//! (the current supported version) returns
//! [`ProfileLoadError::VersionUnsupported`].  A profile at version `1` must
//! first be migrated via `stellar-agent profile migrate <name>`.
//! Forward-compatibility: future wallets reading version-3+ profiles fail fast
//! rather than silently using stale defaults.
//!
//! # Loader dependency choice
//!
//! `figment` is used instead of the `config` crate because its source-merging
//! API is more idiomatic for the three-layer model used here.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use figment::{
    Figment,
    providers::{Env, Format, Serialized, Toml},
};

use super::name::validate_path_component_ascii_safe;
use super::schema::{
    KeyringEntryRef, MAX_SERVED_PAGE_DISPLAY_NAME_CHARS, PrimaryProviderRecord, Profile,
    ProviderAttestationError, ProviderAttestationRejection, ProviderRecord, ProviderRole,
    Providers, RpcCredentialPlacement, WALLET_KEY_REFERENCE_FIELDS, check_endpoint_url,
    check_provider_credential, check_rpc_credential_endpoint, check_rpc_credential_entry,
    check_rpc_credential_placement, default_audit_log_path_for, provider_host,
    rpc_credential_entry_is_reserved, same_provider_host, same_provider_operator,
};
pub use super::schema::{default_approval_dir, default_policy_dir, default_profile_dir};
use crate::profile::caip2::Caip2;
use crate::{asset_id::CanonicalAsset, cross_check::CrossCheckThresholds};

/// A safe reference to the part of `[cross_check_thresholds]` a refusal
/// names, without any rejected input.
#[derive(Debug, Clone)]
pub enum Entry {
    /// The field itself, when its value is not a table.
    Field,
    /// One-based position in lexicographic key order, for a key that did not
    /// parse.
    Position(usize),
    /// The canonical identity of a key that parsed.
    Asset(CanonicalAsset),
}

impl std::fmt::Display for Entry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Field => f.write_str("the field"),
            Self::Position(n) => write!(f, "entry {n} in key order"),
            Self::Asset(asset) => write!(f, "entry '{asset}'"),
        }
    }
}

/// Mirror of `stellar_agent_smart_account::managers::rules::UPPER_BOUND_MAX_SCAN_ID`.
///
/// Hoisted to module level so it is declared once and consumed by both
/// profile-load entry points.  The canonical constant lives in the smart-account
/// crate; this mirror avoids a crate-dependency cycle
/// (`stellar-agent-smart-account` already depends on `stellar-agent-core`).
///
/// **Drift-protection:** an integration test in
/// `crates/stellar-agent-smart-account/tests/smart_account/upper_bound_max_scan_id_parity_test.rs`
/// asserts `MIRRORED_UPPER_BOUND_MAX_SCAN_ID == UPPER_BOUND_MAX_SCAN_ID`
/// across crate boundaries — if either side changes, the parity test fails.
pub const MIRRORED_UPPER_BOUND_MAX_SCAN_ID: u32 = 10_000;

/// Mirror of
/// `stellar_agent_smart_account::managers::rules::UPPER_BOUND_HORIZON_LEDGERS`.
///
/// Hoisted to module level for the same reason as
/// [`MIRRORED_UPPER_BOUND_MAX_SCAN_ID`]: the canonical lives in the
/// smart-account crate; this mirror avoids a crate-dependency cycle.
///
/// **Drift-protection:** the integration test
/// `crates/stellar-agent-smart-account/tests/smart_account/horizon_bound_parity_test.rs`
/// asserts `MIRRORED_UPPER_BOUND_HORIZON_LEDGERS == UPPER_BOUND_HORIZON_LEDGERS`
/// across crate boundaries.
pub const MIRRORED_UPPER_BOUND_HORIZON_LEDGERS: u32 = 10_000;

/// Mirror of `stellar_agent_smart_account::multicall::MULTICALL_BUNDLE_CAP`.
///
/// The maximum number of inner operations allowed in a single multicall bundle.
/// Hoisted here to avoid a crate-dependency cycle; the canonical constant lives
/// in the smart-account crate.
///
/// **Drift-protection:** `crates/stellar-agent-smart-account/tests/multicall_cap_parity_test.rs`
/// asserts `MIRRORED_MULTICALL_BUNDLE_CAP == MULTICALL_BUNDLE_CAP` across
/// crate boundaries.
pub const MIRRORED_MULTICALL_BUNDLE_CAP: u32 = 50;

/// Mirror of
/// `stellar_agent_smart_account::multicall::UPPER_BOUND_MULTICALL_BUNDLE_CAP`.
///
/// Hard ceiling on bundle size used by the pre-load validation guard.  Values
/// beyond this cap are rejected at profile-load to prevent a maliciously-crafted
/// profile TOML from triggering unbounded multicall expansion.
///
/// **Drift-protection:** same parity test as [`MIRRORED_MULTICALL_BUNDLE_CAP`].
pub const MIRRORED_UPPER_BOUND_MULTICALL_BUNDLE_CAP: u32 = 75;

// ─────────────────────────────────────────────────────────────────────────────
// MulticallRegistryHook
// ─────────────────────────────────────────────────────────────────────────────

/// Trait-object hook for checking whether a multicall router is registered for
/// a given network passphrase.
///
/// This trait exists to avoid a crate-dependency cycle:
/// `stellar-agent-smart-account` depends on `stellar-agent-core`; making the
/// profile loader directly depend on `stellar-agent-smart-account::multicall`
/// would create a cycle.  Instead, the smart-account crate implements this
/// opaque presence-check trait on `MulticallRegistry` (or a thin wrapper) and
/// the caller wires the two together at the application layer.
///
/// The method returns `Some(())` if a registry entry exists for the given
/// network passphrase, `None` otherwise.  No entry data is returned — only
/// presence.  This is the minimum surface needed for the profile-load guard.
///
/// # Wiring path
///
/// ```text
/// stellar-agent-smart-account::multicall::MulticallRegistry
///   └─ impl MulticallRegistryHook → load_from_path(name, path, Some(&registry))
///         └─ ProfileLoadError::MulticallRequiresSecondaryRpc when:
///              hook.lookup(profile.network_passphrase).is_some()
///              && profile.secondary_rpc_url.is_none()
/// ```
///
/// CLI callers that know they don't use multicall pass `None`.
pub trait MulticallRegistryHook: Send + Sync {
    /// Returns `Some(())` if a multicall router entry exists for
    /// `network_passphrase`, `None` otherwise.
    ///
    /// Intentionally opaque — no entry data is leaked through this interface.
    fn lookup(&self, network_passphrase: &str) -> Option<()>;
}

/// The current supported schema version.
const SUPPORTED_VERSION: u32 = 2;

/// The environment-variable prefix used to override profile fields.
///
/// On a testnet profile, `STELLAR_AGENT_RPC_URL=https://...` overrides
/// `rpc_url`. [`OVERLAY_CLASSES`] lists the keys an overlay may set and on
/// which chains. A variable whose suffix names no profile key, such as
/// `STELLAR_AGENT_HOME`, is not an overlay and is ignored.
const ENV_PREFIX: &str = "STELLAR_AGENT_";

/// How an environment or programmatic overlay may set one profile key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OverlayClass {
    /// Any value, on every chain.
    EveryChain,
    /// Any value on a testnet profile; refused on every other chain.
    TestnetOnly,
    /// Only the boolean `true`, on every chain, so an overlay can tighten the
    /// profile and never loosen it.
    TightenOnly,
    /// Refused on every chain. The value comes from the profile file only.
    Never,
}

/// Every serde key `PartialProfile` accepts, field names and aliases alike,
/// with its overlay class.
///
/// The loader checks overlay keys in this table's order, so the key a refusal
/// names is deterministic. A key absent from this table is not a profile key,
/// and an overlay naming it is ignored.
const OVERLAY_CLASSES: &[(&str, OverlayClass)] = &[
    ("version", OverlayClass::Never),
    ("rpc_url", OverlayClass::TestnetOnly),
    ("mcp_signer_default", OverlayClass::TestnetOnly),
    ("mcp_nonce_key_alias", OverlayClass::Never),
    ("cross_check_threshold_stroops", OverlayClass::TestnetOnly),
    ("cross_check_thresholds", OverlayClass::TestnetOnly),
    ("usd_threshold", OverlayClass::TestnetOnly),
    ("classic_fee_per_op_stroops", OverlayClass::TestnetOnly),
    ("classic_max_fee_per_op_stroops", OverlayClass::TestnetOnly),
    ("submit_timeout_seconds", OverlayClass::EveryChain),
    ("audit_log_path", OverlayClass::Never),
    ("mcp_disabled", OverlayClass::TightenOnly),
    ("audit_log_hash_chain_key_id", OverlayClass::Never),
    ("policy_owner_key_id", OverlayClass::Never),
    ("attestation_key_id", OverlayClass::Never),
    ("counterparty_cache_key_id", OverlayClass::Never),
    ("oracle_provider_url", OverlayClass::TestnetOnly),
    ("providers", OverlayClass::Never),
    ("policy", OverlayClass::Never),
    ("wallet", OverlayClass::Never),
    (
        "smart_account_max_context_rule_scan_id",
        OverlayClass::TestnetOnly,
    ),
    (
        "session_rule_max_horizon_ledgers",
        OverlayClass::TestnetOnly,
    ),
    ("secondary_rpc_url", OverlayClass::TestnetOnly),
    ("pool_master_key_id", OverlayClass::Never),
    ("pool_config", OverlayClass::Never),
    ("pool_initialization", OverlayClass::Never),
    ("remote_approval", OverlayClass::Never),
    ("served_pages", OverlayClass::Never),
    ("policy_window_state_key_id", OverlayClass::Never),
];

/// Refuses an overlay that names a key its class forbids on `chain_id`.
///
/// `chain_id` is checked first and on every chain, then each row of
/// [`OVERLAY_CLASSES`] in order. A nested key reaches the check through its
/// top-level name, so `wallet.mlock_required` is checked as `wallet`.
fn check_overlay_keys(
    overlay_data: &figment::value::Map<figment::Profile, figment::value::Dict>,
    chain_id: Caip2,
) -> Result<(), ProfileLoadError> {
    fn named<'a>(
        overlay_data: &'a figment::value::Map<figment::Profile, figment::value::Dict>,
        key: &'a str,
    ) -> impl Iterator<Item = &'a figment::value::Value> + 'a {
        overlay_data.values().filter_map(move |dict| dict.get(key))
    }
    if named(overlay_data, "chain_id").next().is_some() {
        return Err(ProfileLoadError::NonOverlayableField { field: "chain_id" });
    }
    for &(field, class) in OVERLAY_CLASSES {
        let mut values = named(overlay_data, field).peekable();
        if values.peek().is_none() {
            continue;
        }
        match class {
            OverlayClass::EveryChain => {}
            OverlayClass::TestnetOnly => {
                if chain_id != Caip2::Testnet {
                    return Err(ProfileLoadError::NonOverlayableField { field });
                }
            }
            OverlayClass::TightenOnly => {
                if !values.all(|value| matches!(value, figment::value::Value::Bool(_, true))) {
                    return Err(ProfileLoadError::OverlayMayOnlyTighten { field });
                }
            }
            OverlayClass::Never => {
                return Err(ProfileLoadError::NonOverlayableField { field });
            }
        }
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────────────

/// Errors produced when loading a profile.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ProfileLoadError {
    /// A cross-check threshold has an invalid identity, value, or duplicate SAC.
    #[error("profile '{name}': [cross_check_thresholds] {entry} {reason}")]
    InvalidCrossCheckThreshold {
        /// Validated profile name.
        name: String,
        /// Safe entry reference.
        entry: Entry,
        /// Fixed explanation containing no rejected input.
        reason: String,
    },
    /// An overlay names a field whose value belongs to the profile file.
    #[error(
        "profile field `{field}` is read from the profile file only; remove it from the environment, the overlay, or the command line"
    )]
    NonOverlayableField {
        /// The non-overlayable field named by the overlay.
        field: &'static str,
    },

    /// An overlay sets a tighten-only field to a value other than `true`.
    ///
    /// Shares the wire code `profile.non_overlayable_field` with
    /// [`ProfileLoadError::NonOverlayableField`].
    #[error(
        "profile field `{field}` may only be set to `true` outside the profile file; set it in the profile file, or remove it from the environment and the overlay"
    )]
    OverlayMayOnlyTighten {
        /// The tighten-only field named by the overlay.
        field: &'static str,
    },

    /// A mainnet profile was selected without an explicit profile flag.
    #[error("profile `{name}` is a mainnet profile and loads only with `--profile {name}`; {}", named_by.mainnet_selection_description())]
    MainnetRequiresExplicitProfile {
        /// The selected profile name.
        name: String,
        /// The input that supplied the profile name.
        named_by: crate::profile::ProfileNameSource,
    },

    /// The profile file was not found at the expected path.
    #[error("profile '{name}' not found at '{path}'")]
    NotFound {
        /// The profile name as supplied by the caller.
        name: String,
        /// The full path that was checked.
        path: PathBuf,
    },

    /// The profile name is not safe to use as a filesystem path component.
    ///
    /// Every entry point that turns a name into `<dir>/<name>.toml` validates
    /// it first, so a traversal attempt (`../../etc/passwd`) or a name carrying
    /// path separators or control characters is refused before any path is
    /// joined and before any file is touched. Callers do not have to remember
    /// to validate: the join sites do it.
    ///
    /// # Fix
    ///
    /// Use a profile name of at most 64 printable-ASCII characters containing
    /// no `/`, `\`, `:`, or `..`.
    #[error("profile name '{name}' is not a valid profile name: {reason}")]
    InvalidName {
        /// The rejected profile name as supplied by the caller.
        name: String,
        /// Why it was rejected.
        reason: &'static str,
    },

    /// The OS-conventional state directory could not be determined.
    #[error("could not determine profile directory: {0}")]
    NoStateDir(#[from] super::schema::StateDirError),

    /// The profile's `version` field is not supported by this wallet.
    ///
    /// Fail-fast forward-compatibility: a profile written by a newer wallet is
    /// rejected rather than silently applying stale defaults.
    #[error(
        "profile '{name}' has unsupported version {found}; \
         this wallet supports version {supported}"
    )]
    VersionUnsupported {
        /// The profile name as supplied by the caller.
        name: String,
        /// The `version` value found in the TOML file.
        found: u32,
        /// The highest version this wallet supports.
        supported: u32,
    },

    /// A mainnet profile file names no `rpc_url`.
    ///
    /// Mainnet has no default endpoint, so the file must name one.
    ///
    /// # Fix
    ///
    /// Set `rpc_url` in the profile file to the HTTPS endpoint of a trusted
    /// mainnet RPC provider.
    #[error(
        "mainnet profile '{name}' names no RPC endpoint; set `rpc_url` in the profile file, \
         because mainnet has no default endpoint"
    )]
    MainnetRpcUrlRequired {
        /// The profile name as supplied by the caller.
        name: String,
    },

    /// An endpoint field (`rpc_url`, `secondary_rpc_url`, or
    /// `oracle_provider_url`) breaks the endpoint rule of
    /// [`super::schema::check_endpoint_url`].
    ///
    /// The message names the field and the rule, never the URL.
    #[error("profile '{name}': {source}")]
    InvalidEndpointUrl {
        /// The profile name as supplied by the caller.
        name: String,
        /// The field and the check it failed.
        #[source]
        source: super::schema::EndpointUrlError,
    },

    /// A provider attestation is invalid. The source contains no file values.
    #[error("profile '{name}': {source}")]
    InvalidProviderAttestation {
        /// The profile name supplied by the caller.
        name: String,
        /// The field and repair.
        #[source]
        source: ProviderAttestationError,
    },

    /// A v2 profile omitted the required `[policy]` TOML section.
    ///
    /// V2 profiles must explicitly choose `engine = "noop"` or `engine = "v1"`
    /// so hand-edited files cannot silently inherit `PolicyEngineKind::V1` and
    /// crash later at server construction.
    #[error("profile at '{path}' is missing required [policy] section")]
    MissingPolicySection {
        /// The profile path that omitted `[policy]`.
        path: PathBuf,
    },

    /// The on-disk `[mcp_signer_default]` reference could not be read
    /// verbatim (I/O, TOML parse, or missing table/keys).
    ///
    /// Produced by [`read_signer_ref_on_disk`], which reads the stored
    /// document without environment or CLI overlays.
    #[error("profile signer reference unreadable: {detail}")]
    SignerRefUnreadable {
        /// Human-readable failure detail (path and cause; no secrets).
        detail: String,
    },

    /// The stored `chain_id` and `rpc_url` of a profile file could not be
    /// read.
    ///
    /// Produced by [`read_mainnet_view_on_disk`], which reads the stored
    /// document without environment or CLI overlays.
    #[error("profile chain and endpoint unreadable: {detail}")]
    MainnetViewUnreadable {
        /// Human-readable failure detail (path and cause; no secrets).
        detail: String,
    },

    /// figment failed to extract or merge the configuration sources.
    #[error("profile '{name}' could not be loaded: {source}")]
    Figment {
        /// The profile name as supplied by the caller.
        name: String,
        /// The underlying figment error (boxed to keep the enum variant small).
        #[source]
        source: Box<figment::Error>,
    },

    /// The `smart_account_max_context_rule_scan_id` field exceeds the
    /// safety cap (`UPPER_BOUND_MAX_SCAN_ID = 10_000`).
    ///
    /// A value beyond the cap would allow an attacker who can edit the profile
    /// TOML to DoS the wallet's `smart-account list-rules` / `migrate-verifier`
    /// path by triggering up to ~4.3B simulate calls (u32::MAX iterations).
    ///
    /// # Fix
    ///
    /// Lower `smart_account_max_context_rule_scan_id` in the profile TOML to a
    /// value ≤ 10,000.
    #[error(
        "profile '{name}': smart_account_max_context_rule_scan_id value {value} \
         exceeds upper bound {upper_bound} (DoS-defence cap)"
    )]
    InvalidScanIdBound {
        /// The profile name as supplied by the caller.
        name: String,
        /// The value that was rejected.
        value: u32,
        /// The safety cap (`UPPER_BOUND_MAX_SCAN_ID`).
        upper_bound: u32,
    },

    /// The `session_rule_max_horizon_ledgers` field exceeds the safety cap
    /// (`UPPER_BOUND_HORIZON_LEDGERS = 10_000`).
    ///
    /// A value beyond the cap would allow an attacker who can edit the profile
    /// TOML to set an arbitrarily large horizon, extending the in-flight
    /// envelope race window.  The 10,000-ledger cap (~13.9–15.3 hours at
    /// 5 s ledgers) bounds the worst-case exposure.
    ///
    /// # Fix
    ///
    /// Lower `session_rule_max_horizon_ledgers` in the profile TOML to a
    /// value ≤ 10,000, or remove the field to use the 1000-ledger default.
    #[error(
        "profile '{name}': session_rule_max_horizon_ledgers value {value} \
         exceeds upper bound {upper_bound} (DoS-defence cap)"
    )]
    InvalidHorizonBound {
        /// The profile name as supplied by the caller.
        name: String,
        /// The value that was rejected.
        value: u32,
        /// The safety cap (`UPPER_BOUND_HORIZON_LEDGERS`).
        upper_bound: u32,
    },

    /// `[served_pages] display_name` is longer than the render bound.
    ///
    /// The served pages truncate a name to
    /// [`MAX_SERVED_PAGE_DISPLAY_NAME_CHARS`] characters, so a longer value
    /// would render as a prefix of what the operator wrote without saying so.
    ///
    /// # Fix
    ///
    /// Shorten `display_name` to at most
    /// [`MAX_SERVED_PAGE_DISPLAY_NAME_CHARS`] characters, or remove the field
    /// to serve pages with no name.
    #[error(
        "profile '{name}': [served_pages] display_name is {chars} characters, \
         exceeding the {upper_bound}-character bound the served pages render"
    )]
    InvalidServedPageDisplayName {
        /// The profile name as supplied by the caller.
        name: String,
        /// The rejected value's length in characters.
        chars: usize,
        /// The render bound (`MAX_SERVED_PAGE_DISPLAY_NAME_CHARS`).
        upper_bound: usize,
    },

    /// A multicall router is registered for this profile's network but the profile
    /// does not supply a `secondary_rpc_url`.
    ///
    /// Cross-RPC trust-anchor verification requires a second independent RPC
    /// endpoint.  When a multicall entry is present and no `secondary_rpc_url`
    /// is configured, the wallet refuses to load rather than proceeding without
    /// the cross-verification guard.
    ///
    /// # Fix
    ///
    /// Add `secondary_rpc_url = "https://..."` to the profile TOML, pointing to
    /// an RPC node operated independently of the primary node.
    #[error(
        "profile '{profile_name}' has a multicall rule for network '{network_safename}' \
         but no secondary_rpc_url is set; cross-RPC trust-anchor verification requires \
         a second independent RPC endpoint"
    )]
    MulticallRequiresSecondaryRpc {
        /// The profile name as supplied by the caller.
        profile_name: String,
        /// The network safe-name from the multicall registry entry.
        network_safename: String,
    },
}

/// How an operator-facing surface must report a [`ProfileLoadError`].
///
/// Surfaces render their own wording — one embeds a path it must redact,
/// another names the verb that refused — but the disposition they render it
/// under is decided here, once, so a single malformed profile cannot draw one
/// wire code from `profile show` and a different one from every other verb.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProfileLoadDisposition {
    /// No profile of that name exists.
    NotFound,
    /// The operator can repair this without a code change, by editing the
    /// profile file, choosing a different name, or fixing the environment that
    /// supplies the state directory.
    OperatorCorrectable,
}

impl ProfileLoadError {
    /// Maps a loader refusal to its operator-facing validation error.
    /// Absolute paths are redacted once in the generic configuration message.
    #[must_use]
    pub fn to_validation_error(&self, requested_name: &str) -> crate::error::ValidationError {
        use crate::error::ValidationError;
        match self {
            Self::NonOverlayableField { field } => {
                ValidationError::ProfileNonOverlayableField { field }
            }
            Self::OverlayMayOnlyTighten { field } => {
                ValidationError::ProfileOverlayMayOnlyTighten { field }
            }
            Self::MainnetRequiresExplicitProfile { name, named_by } => {
                ValidationError::MainnetRequiresExplicitProfile {
                    name: name.clone(),
                    named_by: *named_by,
                }
            }
            Self::NotFound { name, .. } => ValidationError::ProfileNotFound { name: name.clone() },
            Self::MainnetRpcUrlRequired { name } => {
                ValidationError::MainnetRpcUrlRequired { name: name.clone() }
            }
            Self::InvalidProviderAttestation { name, source } => {
                ValidationError::ProviderAttestationInvalid {
                    name: name.clone(),
                    source: source.clone(),
                }
            }
            _ => ValidationError::ConfigInvalid {
                component: "profile",
                reason: crate::observability::redact_path_in_message(&format!(
                    "profile '{requested_name}' failed to load: {self}"
                )),
            },
        }
    }

    /// The disposition an operator-facing surface reports this failure under.
    ///
    /// The match is exhaustive and lives in the crate that owns the enum, so a
    /// new variant fails to compile here until it is classified. That is the
    /// point: [`ProfileLoadError`] is `#[non_exhaustive]`, so a consumer crate
    /// cannot match it exhaustively and a variant added without a matching arm
    /// would silently fall into whatever that consumer's catch-all reports.
    ///
    /// No variant is a wallet defect. Every way a profile load can fail is
    /// either a missing file or something the operator controls, so none of
    /// them may be reported as an internal error.
    #[must_use]
    pub fn disposition(&self) -> ProfileLoadDisposition {
        match self {
            Self::NotFound { .. } => ProfileLoadDisposition::NotFound,
            // Operator-authored input: the name, the file's syntax, its
            // version, or a field whose value is out of bounds.
            Self::NonOverlayableField { .. }
            | Self::OverlayMayOnlyTighten { .. }
            | Self::MainnetRequiresExplicitProfile { .. }
            | Self::InvalidName { .. }
            | Self::VersionUnsupported { .. }
            | Self::MainnetRpcUrlRequired { .. }
            | Self::InvalidEndpointUrl { .. }
            | Self::InvalidProviderAttestation { .. }
            | Self::InvalidCrossCheckThreshold { .. }
            | Self::MissingPolicySection { .. }
            | Self::SignerRefUnreadable { .. }
            | Self::MainnetViewUnreadable { .. }
            | Self::Figment { .. }
            | Self::InvalidScanIdBound { .. }
            | Self::InvalidHorizonBound { .. }
            | Self::InvalidServedPageDisplayName { .. }
            | Self::MulticallRequiresSecondaryRpc { .. } => {
                ProfileLoadDisposition::OperatorCorrectable
            }
            // The environment supplies no state directory. Not the profile's
            // contents, but still the operator's to fix and still not a defect.
            Self::NoStateDir(_) => ProfileLoadDisposition::OperatorCorrectable,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Path-component guards
// ─────────────────────────────────────────────────────────────────────────────

/// Refuses a profile name that is unsafe as a filesystem path component.
///
/// Called by every read entry point that builds `<dir>/<name>.toml`, before the
/// join. Placing the guard at the join rather than at each caller is what makes
/// the rule hold for all of them: a caller that forgets to validate still
/// cannot reach outside the profile directory.
pub(crate) fn guard_name_for_load(name: &str) -> Result<(), ProfileLoadError> {
    validate_path_component_ascii_safe(name).map_err(|reason| ProfileLoadError::InvalidName {
        name: name.to_owned(),
        reason,
    })
}

/// Write-half counterpart of [`guard_name_for_load`].
fn guard_name_for_save(name: &str) -> Result<(), ProfileSaveError> {
    validate_path_component_ascii_safe(name).map_err(|reason| ProfileSaveError::InvalidName {
        name: name.to_owned(),
        reason,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

/// Loads the named profile from its TOML file, applying env-var overlays.
///
/// Profile files live at `<profile_dir>/<name>.toml`.  The platform-specific
/// `<profile_dir>` is resolved via `directories::ProjectDirs`.
///
/// Steps:
/// 1. Resolve the profile-file path via `default_profile_dir()`.
/// 2. Fail fast if the file does not exist.
/// 3. Reject `version != 2` with [`ProfileLoadError::VersionUnsupported`].
/// 4. Refuse an overlay that names `chain_id`, then check every other overlay
///    key against its class. `submit_timeout_seconds` is overlayable on every
///    chain. `rpc_url`, `secondary_rpc_url`, `oracle_provider_url`,
///    `mcp_signer_default`, `cross_check_threshold_stroops` (alias
///    `usd_threshold`), `cross_check_thresholds`, the two classic fee fields,
///    `smart_account_max_context_rule_scan_id`, and
///    `session_rule_max_horizon_ledgers` are overlayable on testnet only.
///    `mcp_disabled` accepts only `true`, refusing any other value with
///    [`ProfileLoadError::OverlayMayOnlyTighten`]. Every other profile key
///    refuses with [`ProfileLoadError::NonOverlayableField`]. A variable that
///    names no profile key is ignored.
/// 5. Merge sources: TOML file, then the permitted env-var overlay (env wins).
/// 6. Resolve the testnet `rpc_url` default if the TOML omitted it; a mainnet
///    file without `rpc_url` refuses with
///    [`ProfileLoadError::MainnetRpcUrlRequired`].
/// 7. Resolve `network_passphrase` from `chain_id` (always derived; not
///    overridable from profile config).
/// 8. Resolve `audit_log_path` default if the TOML omitted it.
/// 9. Check `rpc_url`, `secondary_rpc_url`, and `oracle_provider_url` against
///    the endpoint rule of [`super::schema::check_endpoint_url`], refusing
///    with [`ProfileLoadError::InvalidEndpointUrl`].
///
/// # Multicall guard
///
/// Pass `multicall_hook: Some(&registry)` when the caller has a
/// [`MulticallRegistryHook`] instance (e.g. `MulticallRegistry` from the
/// smart-account crate). The loader will refuse with
/// [`ProfileLoadError::MulticallRequiresSecondaryRpc`] if a multicall entry
/// exists for the profile's network but `secondary_rpc_url` is not set.
/// Pass `None` when multicall is not in use (pre-multicall CLI paths,
/// first-run fallback, migration).
///
/// # Errors
///
/// See [`ProfileLoadError`] for the full list of failure modes.
pub fn load(
    name: &str,
    multicall_hook: Option<&dyn MulticallRegistryHook>,
) -> Result<Profile, ProfileLoadError> {
    load_from_dir(name, &default_profile_dir()?, multicall_hook)
}

/// Loads the named profile from an explicit directory path.
///
/// Identical to [`load`] except the profile-directory path is caller-supplied.
/// Used in tests and by the `profile migrate` subcommand.
///
/// # Errors
///
/// See [`ProfileLoadError`] for the full list of failure modes.
pub fn load_from_dir(
    name: &str,
    profile_dir: &Path,
    multicall_hook: Option<&dyn MulticallRegistryHook>,
) -> Result<Profile, ProfileLoadError> {
    guard_name_for_load(name)?;
    let path = profile_dir.join(format!("{name}.toml"));

    if !path.exists() {
        return Err(ProfileLoadError::NotFound {
            name: name.to_owned(),
            path,
        });
    }

    load_from_path(name, &path, multicall_hook)
}

/// Loads a profile from an explicit file path.
///
/// Used by the migration command, which knows the exact path after walking the
/// profile directory.
///
/// # Multicall guard
///
/// When `multicall_hook` is `Some`, the loader checks whether a multicall
/// router is registered for the profile's resolved `network_passphrase`.
/// If so and `secondary_rpc_url` is `None`, loading fails with
/// [`ProfileLoadError::MulticallRequiresSecondaryRpc`].
///
/// Cross-RPC trust-anchor verification requires an independent secondary RPC.
///
/// # Errors
///
/// See [`ProfileLoadError`] for the full list of failure modes.
pub fn load_from_path(
    name: &str,
    path: &Path,
    multicall_hook: Option<&dyn MulticallRegistryHook>,
) -> Result<Profile, ProfileLoadError> {
    load_from_path_with_overlays(name, path, Env::prefixed(ENV_PREFIX), multicall_hook)
}

/// Reads identity from the file before applying permitted overlays.
/// The file is the operator's audited record. An overlay key is checked
/// against `chain_id` first and then against [`OVERLAY_CLASSES`], after the
/// version check and before any merge.
fn load_from_path_with_overlays(
    name: &str,
    path: &Path,
    overlays: impl figment::Provider,
    multicall_hook: Option<&dyn MulticallRegistryHook>,
) -> Result<Profile, ProfileLoadError> {
    // ── Step 1: read the raw `version` field before full extraction so we
    // can provide a typed error (VersionUnsupported) rather than a generic
    // figment error when the version is wrong.  figment does not allow us to
    // partially extract a single field without running the full extraction, so
    // we use a serde-based pre-check via a lightweight wrapper.
    let raw: RawVersion = Figment::new()
        .merge(Toml::file(path))
        .extract()
        .map_err(|e| ProfileLoadError::Figment {
            name: name.to_owned(),
            source: Box::new(e),
        })?;

    if raw.version != SUPPORTED_VERSION {
        return Err(ProfileLoadError::VersionUnsupported {
            name: name.to_owned(),
            found: raw.version,
            supported: SUPPORTED_VERSION,
        });
    }

    // ── Step 2: read the file identity, refuse non-overlayable keys, and extract the profile.
    let on_disk: OnDiskChainId = Figment::new()
        .merge(Toml::file(path))
        .extract()
        .map_err(|e| ProfileLoadError::Figment {
            name: name.to_owned(),
            source: Box::new(e),
        })?;
    let overlay_data = overlays.data().map_err(|e| ProfileLoadError::Figment {
        name: name.to_owned(),
        source: Box::new(e),
    })?;
    check_overlay_keys(&overlay_data, on_disk.chain_id)?;
    let partial: PartialProfile = Figment::new()
        .merge(Toml::file(path))
        .merge(&overlays)
        .extract()
        .map_err(|e| ProfileLoadError::Figment {
            name: name.to_owned(),
            source: Box::new(e),
        })?;
    let policy = require_policy_section(partial.policy, path)?;

    // ── Step 3: resolve derived fields.  Only testnet has a default endpoint;
    // a mainnet file that names none is refused.
    let chain_id = on_disk.chain_id;
    let rpc_url = match (partial.rpc_url, chain_id.default_rpc_url()) {
        (Some(explicit), _) => explicit,
        (None, Some(default)) => default.to_owned(),
        (None, None) => {
            return Err(ProfileLoadError::MainnetRpcUrlRequired {
                name: name.to_owned(),
            });
        }
    };
    let network_passphrase = chain_id.network_passphrase().to_owned();
    // Unset audit_log_path resolves to the PER-PROFILE location the field's
    // contract documents (`<root>/audit/<name>.jsonl`), never a host-global
    // shared file: hash-chained logs from unrelated profiles must not
    // interleave.
    let audit_log_path = partial
        .audit_log_path
        .unwrap_or_else(|| default_audit_log_path_for(name));
    let policy_window_state_key_id = partial
        .policy_window_state_key_id
        .clone()
        .unwrap_or_else(|| super::schema::KeyringEntryRef::default_policy_window_state_key(name));

    // ── Step 4: validate smart_account_max_context_rule_scan_id bound.
    // Uses module-level `MIRRORED_UPPER_BOUND_MAX_SCAN_ID`.
    if let Some(scan_id) = partial.smart_account_max_context_rule_scan_id
        && scan_id > MIRRORED_UPPER_BOUND_MAX_SCAN_ID
    {
        return Err(ProfileLoadError::InvalidScanIdBound {
            name: name.to_owned(),
            value: scan_id,
            upper_bound: MIRRORED_UPPER_BOUND_MAX_SCAN_ID,
        });
    }

    // ── Step 4b: validate session_rule_max_horizon_ledgers bound.
    // Uses module-level `MIRRORED_UPPER_BOUND_HORIZON_LEDGERS`.
    if let Some(horizon) = partial.session_rule_max_horizon_ledgers
        && horizon > MIRRORED_UPPER_BOUND_HORIZON_LEDGERS
    {
        return Err(ProfileLoadError::InvalidHorizonBound {
            name: name.to_owned(),
            value: horizon,
            upper_bound: MIRRORED_UPPER_BOUND_HORIZON_LEDGERS,
        });
    }

    // Validate the served-page display name's length bound. The renderer
    // truncates, so an over-long value would silently render as a prefix of
    // what the operator wrote; refusing at load says so instead.
    if let Some(name_value) = partial
        .served_pages
        .as_ref()
        .and_then(|cfg| cfg.display_name.as_deref())
    {
        let chars = name_value.chars().count();
        if chars > MAX_SERVED_PAGE_DISPLAY_NAME_CHARS {
            return Err(ProfileLoadError::InvalidServedPageDisplayName {
                name: name.to_owned(),
                chars,
                upper_bound: MAX_SERVED_PAGE_DISPLAY_NAME_CHARS,
            });
        }
    }

    // ── Step 5: check the three endpoint fields against the endpoint rule.
    // The raw strings are checked, so the endpoint rule also reports a
    // malformed `oracle_provider_url`.
    let invalid_endpoint = |source| ProfileLoadError::InvalidEndpointUrl {
        name: name.to_owned(),
        source,
    };
    check_endpoint_url("rpc_url", &rpc_url, chain_id).map_err(invalid_endpoint)?;
    if let Some(secondary) = partial.secondary_rpc_url.as_deref() {
        check_endpoint_url("secondary_rpc_url", secondary, chain_id).map_err(invalid_endpoint)?;
    }
    let oracle_provider_url = partial
        .oracle_provider_url
        .as_deref()
        .map(|oracle| check_endpoint_url("oracle_provider_url", oracle, chain_id))
        .transpose()
        .map_err(invalid_endpoint)?;

    // The provider credential rules compare against the wallet key references
    // of the merged profile and of the file alone, because a testnet overlay
    // can replace `mcp_signer_default`.
    let file_key_refs = file_wallet_key_references(name, path)?;
    let mut profile = Profile {
        version: partial.version,
        chain_id,
        rpc_url,
        network_passphrase,
        mcp_signer_default: partial.mcp_signer_default,
        mcp_nonce_key_alias: partial.mcp_nonce_key_alias,
        cross_check_threshold_stroops: partial.cross_check_threshold_stroops,
        cross_check_thresholds: parse_cross_check_thresholds(
            name,
            partial.cross_check_thresholds,
            chain_id.network_passphrase(),
        )?,
        classic_fee_per_op_stroops: partial.classic_fee_per_op_stroops,
        classic_max_fee_per_op_stroops: partial.classic_max_fee_per_op_stroops,
        submit_timeout_seconds: partial.submit_timeout_seconds,
        audit_log_path,
        mcp_disabled: partial.mcp_disabled,
        audit_log_hash_chain_key_id: partial.audit_log_hash_chain_key_id,
        policy_owner_key_id: partial.policy_owner_key_id,
        attestation_key_id: partial.attestation_key_id,
        counterparty_cache_key_id: partial.counterparty_cache_key_id,
        oracle_provider_url,
        providers: None,
        policy,
        wallet: partial.wallet,
        smart_account_max_context_rule_scan_id: partial.smart_account_max_context_rule_scan_id,
        session_rule_max_horizon_ledgers: partial.session_rule_max_horizon_ledgers,
        secondary_rpc_url: partial.secondary_rpc_url,
        pool_master_key_id: partial.pool_master_key_id,
        pool_config: partial.pool_config,
        pool_initialization: partial.pool_initialization,
        remote_approval: partial.remote_approval,
        served_pages: partial.served_pages,
        policy_window_state_key_id,
    };
    let providers = validate_providers(
        partial.providers.as_ref(),
        chain_id,
        &RoleUrls {
            primary: &profile.rpc_url,
            secondary: profile.secondary_rpc_url.as_deref(),
            oracle: partial.oracle_provider_url.as_deref(),
        },
        &wallet_refs_with_file(&profile, &file_key_refs),
    )
    .map_err(|source| ProfileLoadError::InvalidProviderAttestation {
        name: name.to_owned(),
        source,
    })?;
    profile.providers = providers;

    // ── Step 6: multicall guard.  When the caller wires in a
    // `MulticallRegistryHook` and the registry has an entry for the profile's
    // network, a missing `secondary_rpc_url` is a load-time error rather than
    // a silent misconfiguration that would surface only at multicall submit time.
    if let Some(hook) = multicall_hook
        && hook.lookup(&profile.network_passphrase).is_some()
        && profile.secondary_rpc_url.is_none()
    {
        return Err(ProfileLoadError::MulticallRequiresSecondaryRpc {
            profile_name: name.to_owned(),
            network_safename: network_safename_from_passphrase(&profile.network_passphrase),
        });
    }

    Ok(profile)
}

/// Derives a filesystem-safe name from a Stellar network passphrase.
///
/// Converts the passphrase to lowercase and replaces every non-alphanumeric
/// character with `_`, collapsing consecutive replacements.  The result is
/// suitable for use in error messages and file-system paths.
///
/// # Examples
///
/// ```
/// // "Test SDF Network ; September 2015" → "test_sdf_network_september_2015"
/// // "Public Global Stellar Network ; September 2015" → "public_global_stellar_network_september_2015"
/// ```
///
/// This mirrors the `network_safename_from_passphrase` function in
/// `stellar-agent-smart-account::multicall` — kept local to avoid a crate
/// dependency cycle (smart-account depends on core).
///
/// Drift-protection: the multicall crate's parity test
/// `multicall_cap_parity_test.rs` would require the same transformation, but
/// no byte-level agreement is contractual; this is only used in error messages
/// and file-system key derivation where readability matters more than bijection.
fn network_safename_from_passphrase(passphrase: &str) -> String {
    let raw: String = passphrase
        .to_lowercase()
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '_' })
        .collect();
    // Collapse consecutive underscores and strip leading/trailing ones.
    let mut result = String::with_capacity(raw.len());
    let mut prev_under = true; // starts true to strip a leading underscore
    for c in raw.chars() {
        if c == '_' {
            if !prev_under {
                result.push('_');
            }
            prev_under = true;
        } else {
            result.push(c);
            prev_under = false;
        }
    }
    // Strip trailing underscore if any.
    if result.ends_with('_') {
        result.pop();
    }
    result
}

/// Lists profile names available in the default profile directory.
///
/// Returns a sorted `Vec<String>` of profile names (without the `.toml`
/// extension).  Returns an empty vector when the directory does not exist.
///
/// # Errors
///
/// Returns [`ProfileLoadError::NoStateDir`] if the OS-conventional state
/// directory cannot be determined.
pub fn list_profiles() -> Result<Vec<String>, ProfileLoadError> {
    list_profiles_in_dir(&default_profile_dir()?)
}

/// Lists profiles in an explicit directory.
///
/// # Errors
///
/// Returns [`ProfileLoadError`] variants if the directory cannot be read.
pub fn list_profiles_in_dir(dir: &Path) -> Result<Vec<String>, ProfileLoadError> {
    if !dir.exists() {
        return Ok(Vec::new());
    }

    let mut names = Vec::new();
    let entries = std::fs::read_dir(dir).map_err(|_| super::schema::StateDirError)?;
    for entry in entries.flatten() {
        let p = entry.path();
        if p.extension().and_then(|e| e.to_str()) == Some("toml")
            && let Some(stem) = p.file_stem().and_then(|s| s.to_str())
        {
            names.push(stem.to_owned());
        }
    }
    names.sort();
    Ok(names)
}

/// Saves a profile to its canonical path in the default profile directory.
///
/// Creates the directory if it does not exist.  Writes the TOML atomically
/// (temp-file + rename).
///
/// **Atomicity caveat:** `rename` is atomic on single-host POSIX filesystems.
/// Networked filesystem mounts (NFSv3, SMB, FUSE) have weaker rename
/// semantics.  The keyring (NOT the profile TOML) is the actual defence for
/// secret material; the profile TOML never holds secrets, so an interrupted
/// rename at worst leaves a stale or partially-written TOML (the original is
/// unmodified because temp-file rename only atomically replaces the
/// destination on POSIX; on Windows, `persist()` from `tempfile` uses
/// `MoveFileExW(MOVEFILE_REPLACE_EXISTING)` which is not strictly atomic
/// against crash between write and rename).
///
/// # Errors
///
/// - [`ProfileSaveError::InvalidName`] when `name` is not safe as a path
///   component; refused before the destination path is built.
/// - Any other [`ProfileSaveError`] on I/O or serialization failure.
pub fn save(name: &str, profile: &Profile) -> Result<PathBuf, ProfileSaveError> {
    save_to_dir(
        name,
        profile,
        &default_profile_dir().map_err(ProfileSaveError::NoStateDir)?,
    )
}

/// Saves a profile to an explicit directory.
///
/// # Errors
///
/// - [`ProfileSaveError::InvalidName`] when `name` is not safe as a path
///   component; refused before the destination path is built.
/// - Any other [`ProfileSaveError`] on I/O or serialization failure.
pub fn save_to_dir(name: &str, profile: &Profile, dir: &Path) -> Result<PathBuf, ProfileSaveError> {
    guard_name_for_save(name)?;
    std::fs::create_dir_all(dir).map_err(ProfileSaveError::Io)?;
    let dest = dir.join(format!("{name}.toml"));

    let toml_str = toml::to_string_pretty(profile).map_err(ProfileSaveError::Serialize)?;

    // Atomic write: write to temp-file in the same directory, then rename.
    let mut tmp = tempfile::NamedTempFile::new_in(dir).map_err(ProfileSaveError::Io)?;
    std::io::Write::write_all(&mut tmp, toml_str.as_bytes()).map_err(ProfileSaveError::Io)?;
    tmp.persist(&dest)
        .map_err(|e| ProfileSaveError::Io(e.error))?;

    Ok(dest)
}

/// Saves a NEW profile to an explicit directory, refusing atomically when the
/// destination already exists.
///
/// [`save_to_dir`]'s rename-based persist replaces an existing destination;
/// creation paths use this variant so the no-overwrite guarantee holds even
/// against a file appearing between an existence check and the write.
///
/// # Errors
///
/// - [`ProfileSaveError::InvalidName`] when `name` is not safe as a path
///   component; refused before the destination path is built.
/// - [`ProfileSaveError::AlreadyExists`] when `<name>.toml` exists in `dir`.
/// - Any other [`ProfileSaveError`] on I/O or serialization failure.
pub fn save_new_to_dir(
    name: &str,
    profile: &Profile,
    dir: &Path,
) -> Result<PathBuf, ProfileSaveError> {
    guard_name_for_save(name)?;
    std::fs::create_dir_all(dir).map_err(ProfileSaveError::Io)?;
    let dest = dir.join(format!("{name}.toml"));

    let toml_str = toml::to_string_pretty(profile).map_err(ProfileSaveError::Serialize)?;

    let mut tmp = tempfile::NamedTempFile::new_in(dir).map_err(ProfileSaveError::Io)?;
    std::io::Write::write_all(&mut tmp, toml_str.as_bytes()).map_err(ProfileSaveError::Io)?;
    tmp.persist_noclobber(&dest).map_err(|e| {
        if e.error.kind() == std::io::ErrorKind::AlreadyExists {
            ProfileSaveError::AlreadyExists { path: dest.clone() }
        } else {
            ProfileSaveError::Io(e.error)
        }
    })?;

    Ok(dest)
}

/// Canonical-directory wrapper for [`read_signer_ref_on_disk`].
///
/// # Errors
///
/// See [`read_signer_ref_on_disk`]; additionally
/// [`ProfileLoadError::NoStateDir`] when the OS-conventional profile
/// directory cannot be determined.
pub fn read_signer_ref(name: &str) -> Result<super::schema::KeyringEntryRef, ProfileLoadError> {
    read_signer_ref_on_disk(name, &default_profile_dir()?)
}

/// Canonical-directory wrapper for [`pin_signer_account_on_disk`].
///
/// # Errors
///
/// See [`pin_signer_account_on_disk`]; additionally
/// [`ProfileSaveError::NoStateDir`] when the OS-conventional profile
/// directory cannot be determined.
pub fn pin_signer_account(name: &str, account: &str) -> Result<PathBuf, ProfileSaveError> {
    pin_signer_account_on_disk(
        name,
        &default_profile_dir().map_err(ProfileSaveError::NoStateDir)?,
        account,
    )
}

/// Canonical-directory wrapper for [`set_pool_state_on_disk`].
///
/// # Errors
///
/// See [`set_pool_state_on_disk`]; additionally
/// [`ProfileSaveError::NoStateDir`] when the OS-conventional profile
/// directory cannot be determined.
pub fn set_pool_state(
    name: &str,
    pool_master_key_id: &super::schema::KeyringEntryRef,
    pool_config: &super::schema::PoolConfig,
) -> Result<PathBuf, ProfileSaveError> {
    set_pool_state_on_disk(
        name,
        &default_profile_dir().map_err(ProfileSaveError::NoStateDir)?,
        pool_master_key_id,
        pool_config,
    )
}

/// Atomically patches the public pool initialization checkpoint and keyring
/// coordinate in the stored document. Active configuration is withheld while
/// creation is pending; clearing a completed checkpoint preserves that config.
/// The caller serialises the pool lifecycle across processes.
///
/// # Errors
/// Returns an error if the existing profile cannot be read or durably replaced.
pub fn set_pool_initialization(
    name: &str,
    master: &super::schema::KeyringEntryRef,
    pending: Option<&super::schema::PoolInitialization>,
) -> Result<PathBuf, ProfileSaveError> {
    guard_name_for_save(name)?;
    let dir = default_profile_dir().map_err(ProfileSaveError::NoStateDir)?;
    let dest = dir.join(format!("{name}.toml"));
    let raw = std::fs::read_to_string(&dest).map_err(ProfileSaveError::Io)?;
    let mut doc: toml::Value = toml::from_str(&raw).map_err(|e| {
        ProfileSaveError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    })?;
    let table = doc.as_table_mut().ok_or_else(|| {
        ProfileSaveError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "profile must be a table",
        ))
    })?;
    table.insert(
        "pool_master_key_id".to_owned(),
        toml::Value::try_from(master)?,
    );
    if let Some(pending) = pending {
        table.insert(
            "pool_initialization".to_owned(),
            toml::Value::try_from(pending)?,
        );
        if pending.completion_ledger.is_none() {
            table.remove("pool_config");
        }
    } else {
        table.remove("pool_initialization");
    }
    let bytes = toml::to_string_pretty(&doc).map_err(ProfileSaveError::Serialize)?;
    let mut tmp = tempfile::NamedTempFile::new_in(&dir).map_err(ProfileSaveError::Io)?;
    std::io::Write::write_all(&mut tmp, bytes.as_bytes()).map_err(ProfileSaveError::Io)?;
    tmp.as_file().sync_all().map_err(ProfileSaveError::Io)?;
    tmp.persist(&dest)
        .map_err(|e| ProfileSaveError::Io(e.error))?;
    #[cfg(unix)]
    std::fs::File::open(&dir)
        .and_then(|file| file.sync_all())
        .map_err(ProfileSaveError::Io)?;
    Ok(dest)
}

/// Reads the `[mcp_signer_default]` keyring reference exactly as stored in
/// the profile's on-disk TOML, with NO environment or CLI overlays applied.
///
/// The signer reference is part of the persistent trust root: enrollment
/// decisions (placeholder vs pinned identity) and the on-disk pin written by
/// `profile enroll-signer` are derived from the stored document alone, so a
/// transient `STELLAR_AGENT_*` environment overlay can never influence what
/// gets persisted. Environment overlays remain load-time-only ([`load`]).
///
/// # Errors
///
/// - [`ProfileLoadError::InvalidName`] when `name` is not safe as a path
///   component; refused before the path is built.
/// - [`ProfileLoadError::NotFound`] when the profile file does not exist.
/// - [`ProfileLoadError::SignerRefUnreadable`] on I/O or TOML parse failure,
///   or when the table or its `service`/`account` string keys are absent.
pub fn read_signer_ref_on_disk(
    name: &str,
    dir: &Path,
) -> Result<super::schema::KeyringEntryRef, ProfileLoadError> {
    guard_name_for_load(name)?;
    let path = dir.join(format!("{name}.toml"));
    if !path.exists() {
        return Err(ProfileLoadError::NotFound {
            name: name.to_owned(),
            path,
        });
    }
    let raw =
        std::fs::read_to_string(&path).map_err(|e| ProfileLoadError::SignerRefUnreadable {
            detail: format!("failed to read '{}': {e}", path.display()),
        })?;
    let doc: toml::Value =
        toml::from_str(&raw).map_err(|e| ProfileLoadError::SignerRefUnreadable {
            detail: format!("failed to parse '{}': {e}", path.display()),
        })?;
    let table =
        doc.get("mcp_signer_default")
            .ok_or_else(|| ProfileLoadError::SignerRefUnreadable {
                detail: format!("'{}' has no [mcp_signer_default] table", path.display()),
            })?;
    let service = table
        .get("service")
        .and_then(toml::Value::as_str)
        .ok_or_else(|| ProfileLoadError::SignerRefUnreadable {
            detail: format!(
                "'{}' [mcp_signer_default] has no string 'service' key",
                path.display()
            ),
        })?;
    let account = table
        .get("account")
        .and_then(toml::Value::as_str)
        .ok_or_else(|| ProfileLoadError::SignerRefUnreadable {
            detail: format!(
                "'{}' [mcp_signer_default] has no string 'account' key",
                path.display()
            ),
        })?;
    Ok(super::schema::KeyringEntryRef::new(service, account))
}

/// The mainnet fields read directly from the profile file, without overlays.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnDiskMainnetView {
    /// The stored chain identity.
    pub chain_id: super::caip2::Caip2,
    /// The stored RPC endpoint.
    pub rpc_url: String,
}

/// Reads the stored chain and endpoint without applying environment overlays.
///
/// # Errors
///
/// - [`ProfileLoadError::InvalidName`] for a name the loader refuses.
/// - [`ProfileLoadError::NotFound`] when the profile file is absent.
/// - [`ProfileLoadError::MainnetViewUnreadable`] on I/O or TOML parse
///   failure, or when `chain_id` or `rpc_url` is missing or invalid.
pub fn read_mainnet_view_on_disk(
    name: &str,
    dir: &Path,
) -> Result<OnDiskMainnetView, ProfileLoadError> {
    guard_name_for_load(name)?;
    let path = dir.join(format!("{name}.toml"));
    if !path.exists() {
        return Err(ProfileLoadError::NotFound {
            name: name.to_owned(),
            path,
        });
    }
    let failure = |detail: String| ProfileLoadError::MainnetViewUnreadable { detail };
    let raw = std::fs::read_to_string(&path)
        .map_err(|e| failure(format!("failed to read '{}': {e}", path.display())))?;
    let doc: toml::Value = toml::from_str(&raw)
        .map_err(|e| failure(format!("failed to parse '{}': {e}", path.display())))?;
    let field = |key: &str| {
        doc.get(key)
            .and_then(toml::Value::as_str)
            .ok_or_else(|| failure(format!("'{}' has no string '{key}' key", path.display())))
    };
    let chain_id = field("chain_id")?.parse().map_err(|e| {
        failure(format!(
            "'{}' has an invalid 'chain_id' ({e})",
            path.display()
        ))
    })?;
    let rpc_url = field("rpc_url")?.to_owned();
    Ok(OnDiskMainnetView { chain_id, rpc_url })
}

/// Sets ONLY `mcp_signer_default.account` in the profile's on-disk TOML
/// document, preserving every other stored key verbatim, and writes the
/// result atomically.
///
/// This is the persistence half of `profile enroll-signer`'s
/// placeholder-population step. It deliberately does NOT round-trip through
/// [`load`] + [`save`]: that pair would merge `STELLAR_AGENT_*` environment
/// overlays and materialise derived defaults into the stored document,
/// turning transient overrides into persistent trust-root state.
///
/// # Errors
///
/// - [`ProfileSaveError::InvalidName`] when `name` is not safe as a path
///   component; refused before the destination path is built.
/// - [`ProfileSaveError::Io`] when the file cannot be read, parsed, or
///   written (a parse failure is surfaced as `InvalidData`).
/// - [`ProfileSaveError::Serialize`] on TOML re-serialization failure.
pub fn pin_signer_account_on_disk(
    name: &str,
    dir: &Path,
    account: &str,
) -> Result<PathBuf, ProfileSaveError> {
    guard_name_for_save(name)?;
    let dest = dir.join(format!("{name}.toml"));
    let raw = std::fs::read_to_string(&dest).map_err(ProfileSaveError::Io)?;
    let mut doc: toml::Value = toml::from_str(&raw).map_err(|e| {
        ProfileSaveError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("failed to parse '{}': {e}", dest.display()),
        ))
    })?;
    let table = doc
        .get_mut("mcp_signer_default")
        .and_then(toml::Value::as_table_mut)
        .ok_or_else(|| {
            ProfileSaveError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("'{}' has no [mcp_signer_default] table", dest.display()),
            ))
        })?;
    table.insert(
        "account".to_owned(),
        toml::Value::String(account.to_owned()),
    );

    let toml_str = toml::to_string_pretty(&doc).map_err(ProfileSaveError::Serialize)?;
    write_profile_document_atomically(dir, &dest, &toml_str)?;
    Ok(dest)
}

/// Sets ONLY `pool_master_key_id` and `[pool_config]` in the profile's
/// on-disk TOML document, preserving every other stored key verbatim, and
/// writes the result atomically.
///
/// This is the persistence half of `pool init`. The pool bookkeeping is part
/// of the persistent trust root: this deliberately does NOT round-trip
/// through [`load`] + [`save`], because that pair would merge
/// `STELLAR_AGENT_*` environment overlays and materialise loader-derived
/// defaults (`rpc_url`, `audit_log_path`, `network_passphrase`, derived key
/// references) into the stored document, turning transient overrides into
/// persistent trust-root state. Environment overlays remain load-time-only
/// ([`load`]).
///
/// Both keys are replaced wholesale: a re-initialisation
/// (`pool init --force`) overwrites any previous pool bookkeeping rather
/// than merging with it.
///
/// # Errors
///
/// - [`ProfileSaveError::InvalidName`] when `name` is not safe as a path
///   component; refused before the destination path is built.
/// - [`ProfileSaveError::Io`] when the file cannot be read, parsed, or
///   written (a parse failure is surfaced as `InvalidData`).
/// - [`ProfileSaveError::Serialize`] on TOML value conversion or
///   re-serialization failure.
pub fn set_pool_state_on_disk(
    name: &str,
    dir: &Path,
    pool_master_key_id: &super::schema::KeyringEntryRef,
    pool_config: &super::schema::PoolConfig,
) -> Result<PathBuf, ProfileSaveError> {
    guard_name_for_save(name)?;
    let dest = dir.join(format!("{name}.toml"));
    let raw = std::fs::read_to_string(&dest).map_err(ProfileSaveError::Io)?;
    let mut doc: toml::Value = toml::from_str(&raw).map_err(|e| {
        ProfileSaveError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("failed to parse '{}': {e}", dest.display()),
        ))
    })?;
    let table = doc.as_table_mut().ok_or_else(|| {
        ProfileSaveError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("'{}' is not a TOML table document", dest.display()),
        ))
    })?;
    table.insert(
        "pool_master_key_id".to_owned(),
        toml::Value::try_from(pool_master_key_id)?,
    );
    table.insert(
        "pool_config".to_owned(),
        toml::Value::try_from(pool_config)?,
    );

    let toml_str = toml::to_string_pretty(&doc).map_err(ProfileSaveError::Serialize)?;
    write_profile_document_atomically(dir, &dest, &toml_str)?;
    Ok(dest)
}

/// Canonical-directory wrapper for [`set_provider_credential_on_disk`].
///
/// # Errors
///
/// See [`set_provider_credential_on_disk`]; additionally
/// [`ProfileSaveError::NoStateDir`] when the OS-conventional profile
/// directory cannot be determined.
pub fn set_provider_credential(
    name: &str,
    role: ProviderRole,
    credential: &KeyringEntryRef,
    placement: &RpcCredentialPlacement,
) -> Result<PathBuf, ProfileSaveError> {
    set_provider_credential_on_disk(
        name,
        &default_profile_dir().map_err(ProfileSaveError::NoStateDir)?,
        role,
        credential,
        placement,
    )
}

/// Adds ONLY `credential` and `placement` to the `[providers.<role>]` table
/// of the profile's on-disk TOML document, keeping the rest of the file
/// verbatim, and writes the result atomically.
///
/// This is the persistence half of `profile enroll-rpc-credential`. Like
/// [`set_pool_state_on_disk`], it does not round-trip through [`load`] and
/// [`save`], so no environment overlay or derived default reaches the file.
/// The record is patched in the parsed document itself. The two keys follow
/// the record's last key as inline tables: `credential = { service = "...",
/// account = "..." }` and `placement = { kind = "...", name = "..." }`, with
/// no `name` for a path placement. Apart from the line endings, every
/// comment, key order, and layout of the rest of the file stays byte for
/// byte.
///
/// The line endings follow the file. When every line of the file ends in
/// CRLF, every written line does too. Any other file is written as
/// `toml_edit` renders it, which ends every line in LF.
///
/// The record may be a `[providers.<role>]` table or an inline table. It
/// must exist and hold neither key: the command adds a reference to a record
/// the operator wrote and never replaces one.
///
/// # Errors
///
/// - [`ProfileSaveError::InvalidName`] when `name` is not safe as a path
///   component; refused before the destination path is built.
/// - [`ProfileSaveError::Io`] when the file cannot be read, parsed, or
///   written, when it has no `[providers.<role>]` table, or when that table
///   already holds `credential` or `placement` (all surfaced as
///   `InvalidData`); the file is unchanged on every refusal.
pub fn set_provider_credential_on_disk(
    name: &str,
    dir: &Path,
    role: ProviderRole,
    credential: &KeyringEntryRef,
    placement: &RpcCredentialPlacement,
) -> Result<PathBuf, ProfileSaveError> {
    guard_name_for_save(name)?;
    let dest = dir.join(format!("{name}.toml"));
    let invalid = |detail: String| {
        ProfileSaveError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, detail))
    };
    let raw = std::fs::read_to_string(&dest).map_err(ProfileSaveError::Io)?;
    let mut doc: toml_edit::DocumentMut = raw
        .parse()
        .map_err(|e| invalid(format!("failed to parse '{}': {e}", dest.display())))?;
    let record = doc
        .get_mut("providers")
        .and_then(|providers| providers.get_mut(role.as_str()))
        .filter(|record| record.is_table_like())
        .ok_or_else(|| {
            invalid(format!(
                "'{}' has no [{}] table",
                dest.display(),
                role.record_field()
            ))
        })?;
    let names_credential = record
        .as_table_like()
        .is_some_and(|table| table.contains_key("credential") || table.contains_key("placement"));
    if names_credential {
        return Err(invalid(format!(
            "'{}' [{}] already names a credential or a placement",
            dest.display(),
            role.record_field()
        )));
    }
    let credential = credential_inline_table(credential);
    let placement = placement_inline_table(placement);
    if let Some(inline) = record.as_inline_table_mut() {
        // The space before an inline table's closing brace is the suffix of
        // its last value; it moves to the new last value so the existing
        // pairs keep their exact text.
        let closing = inline.iter_mut().last().and_then(|(_, value)| {
            let decor = value.decor_mut();
            let suffix = decor.suffix().cloned();
            decor.set_suffix("");
            suffix
        });
        inline.insert("credential", credential.into());
        inline.insert("placement", placement.into());
        if let (Some(closing), Some(last)) = (closing, inline.get_mut("placement")) {
            last.decor_mut().set_suffix(closing);
        }
    } else if let Some(table) = record.as_table_like_mut() {
        table.insert("credential", toml_edit::value(credential));
        table.insert("placement", toml_edit::value(placement));
    }
    let rendered = doc.to_string();
    let text = if uses_crlf_throughout(&raw) {
        // `toml_edit` 0.25.12 drops every CR of the parsed text and ends each
        // line it writes in LF. The first replace guards against a renderer
        // that keeps a CR, so no line becomes CR CR LF.
        rendered.replace("\r\n", "\n").replace('\n', "\r\n")
    } else {
        rendered
    };
    write_profile_document_atomically(dir, &dest, &text)?;
    Ok(dest)
}

/// Whether `text` holds at least one CRLF and no LF without a CR before it.
fn uses_crlf_throughout(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut saw_crlf = false;
    for (index, byte) in bytes.iter().enumerate() {
        if *byte == b'\n' {
            if index == 0 || bytes[index - 1] != b'\r' {
                return false;
            }
            saw_crlf = true;
        }
    }
    saw_crlf
}

/// A credential reference as the inline table the loader decodes:
/// `{ service = "...", account = "..." }`.
fn credential_inline_table(credential: &KeyringEntryRef) -> toml_edit::InlineTable {
    let mut table = toml_edit::InlineTable::new();
    table.insert("service", credential.service.as_str().into());
    table.insert("account", credential.account.as_str().into());
    table
}

/// A placement as the inline table of its serde form: `kind`, then `name`
/// for a header or query placement.
fn placement_inline_table(placement: &RpcCredentialPlacement) -> toml_edit::InlineTable {
    let (kind, name) = match placement {
        RpcCredentialPlacement::Header { name } => ("header", Some(name)),
        RpcCredentialPlacement::Query { name } => ("query", Some(name)),
        RpcCredentialPlacement::Path {} => ("path", None),
    };
    let mut table = toml_edit::InlineTable::new();
    table.insert("kind", kind.into());
    if let Some(name) = name {
        table.insert("name", name.as_str().into());
    }
    table
}

/// Writes `text` to the profile file `dest` in the directory `dir`
/// atomically.
///
/// The text goes into a temporary file in `dir`, which is flushed to disk and
/// renamed over `dest`, so a reader sees either the old file or the new one.
/// On Unix the directory is flushed as well, so the rename survives a crash.
fn write_profile_document_atomically(
    dir: &Path,
    dest: &Path,
    text: &str,
) -> Result<(), ProfileSaveError> {
    let mut tmp = tempfile::NamedTempFile::new_in(dir).map_err(ProfileSaveError::Io)?;
    std::io::Write::write_all(&mut tmp, text.as_bytes()).map_err(ProfileSaveError::Io)?;
    tmp.as_file().sync_all().map_err(ProfileSaveError::Io)?;
    tmp.persist(dest)
        .map_err(|e| ProfileSaveError::Io(e.error))?;
    #[cfg(unix)]
    std::fs::File::open(dir)
        .and_then(|file| file.sync_all())
        .map_err(ProfileSaveError::Io)?;
    Ok(())
}

/// Errors produced when saving a profile.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ProfileSaveError {
    /// The profile name is not safe to use as a filesystem path component.
    ///
    /// The write half enforces the same rule as the read half
    /// ([`ProfileLoadError::InvalidName`]): a name is validated before it is
    /// joined into a destination path, so no file outside the profile
    /// directory can be created or patched.
    #[error("profile name '{name}' is not a valid profile name: {reason}")]
    InvalidName {
        /// The rejected profile name as supplied by the caller.
        name: String,
        /// Why it was rejected.
        reason: &'static str,
    },
    /// The OS-conventional state directory could not be determined.
    #[error("could not determine profile directory: {0}")]
    NoStateDir(#[from] super::schema::StateDirError),
    /// Serialisation to TOML failed.
    #[error("failed to serialise profile to TOML: {0}")]
    Serialize(#[from] toml::ser::Error),
    /// An I/O error occurred.
    #[error("I/O error writing profile: {0}")]
    Io(std::io::Error),
    /// The destination profile file already exists.
    ///
    /// Produced only by [`save_new_to_dir`], whose no-clobber persist makes
    /// creation refusals atomic (no check-then-write window).
    #[error("profile file already exists at '{path}'")]
    AlreadyExists {
        /// The destination path that already exists.
        path: PathBuf,
    },
}

// ─────────────────────────────────────────────────────────────────────────────
// CLI overlay support
// ─────────────────────────────────────────────────────────────────────────────

/// Loads a profile with an additional programmatic overlay map (highest
/// priority source).
///
/// The overlay keys pass the same class check as the environment overlay,
/// described in [`load`].
///
/// # Multicall guard
///
/// Pass `multicall_hook: Some(&registry)` when the caller has a
/// [`MulticallRegistryHook`] instance.  The same guard as in [`load`] applies.
/// Pass `None` for pre-multicall CLI paths.
///
/// # Errors
///
/// See [`ProfileLoadError`] for the full list of failure modes.
pub fn load_with_overlay(
    name: &str,
    overlay: HashMap<&'static str, serde_json::Value>,
    multicall_hook: Option<&dyn MulticallRegistryHook>,
) -> Result<Profile, ProfileLoadError> {
    load_with_overlay_from_dir(name, &default_profile_dir()?, overlay, multicall_hook)
}

/// Loads a profile from an explicit directory with a CLI overlay.
///
/// The environment and programmatic overlays are checked together against the
/// overlay classes described in [`load`].
///
/// # Multicall guard
///
/// Pass `multicall_hook: Some(&registry)` when the caller has a
/// [`MulticallRegistryHook`] instance.  The same guard as in [`load_from_path`] applies.
/// Pass `None` for pre-multicall CLI paths.
///
/// # Errors
///
/// See [`ProfileLoadError`] for the full list of failure modes.
pub fn load_with_overlay_from_dir(
    name: &str,
    profile_dir: &Path,
    overlay: HashMap<&'static str, serde_json::Value>,
    multicall_hook: Option<&dyn MulticallRegistryHook>,
) -> Result<Profile, ProfileLoadError> {
    guard_name_for_load(name)?;
    let path = profile_dir.join(format!("{name}.toml"));

    if !path.exists() {
        return Err(ProfileLoadError::NotFound {
            name: name.to_owned(),
            path,
        });
    }

    load_from_path_with_overlays(
        name,
        &path,
        Figment::new()
            .merge(Env::prefixed(ENV_PREFIX))
            .merge(Serialized::defaults(overlay)),
        multicall_hook,
    )
}

/// Loads the `default` profile, or returns a synthetic testnet profile if no
/// profile file exists yet.
///
/// This is the startup convenience path for `stellar-agent-mcp`.  On first run,
/// before the operator has created any profile, the MCP server falls back to a
/// minimal testnet configuration so that it can still serve `stellar_balances`
/// requests against the testnet RPC endpoint.
///
/// The fallback profile uses the following defaults:
/// - `chain_id = Caip2::Testnet`
/// - `rpc_url` = [`crate::profile::caip2::TESTNET_RPC_URL`]
/// - `network_passphrase = Caip2::Testnet.network_passphrase()`
/// - All optional fields at their schema defaults.
///
/// The returned [`ProfileOrigin`] says which arm answered: a `default.toml`
/// that exists is [`ProfileOrigin::Persisted`], and only the synthesized
/// fallback is [`ProfileOrigin::Synthesized`]. The audit binding check keys
/// on it through [`ProfileOrigin::binding_check`].
///
/// # Errors
///
/// Returns an error only if the OS-conventional state directory cannot be
/// determined (`directories::ProjectDirs` fails, which supported platforms do
/// not do), or if the profile file exists but fails to load.
pub fn load_default_or_testnet_fallback() -> Result<(Profile, ProfileOrigin), ProfileLoadError> {
    load_default_or_testnet_fallback_from_dir(&default_profile_dir()?)
}

/// [`load_default_or_testnet_fallback`] over an explicit profile directory.
///
/// # Errors
///
/// Returns an error if the `default.toml` in `profile_dir` exists but fails to
/// load.
pub fn load_default_or_testnet_fallback_from_dir(
    profile_dir: &Path,
) -> Result<(Profile, ProfileOrigin), ProfileLoadError> {
    // Pass `None` for the multicall hook: the testnet-fallback path is a
    // pre-multicall startup convenience; no registry is available at this point.
    match load_from_dir("default", profile_dir, None) {
        Ok(profile) => Ok((profile, ProfileOrigin::Persisted)),
        Err(ProfileLoadError::NotFound { .. }) => Ok((
            synthesise_default_first_run_profile(),
            ProfileOrigin::Synthesized,
        )),
        Err(e) => Err(e),
    }
}

/// Where a loaded profile came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileOrigin {
    /// Loaded from a profile file.
    Persisted,
    /// Synthesized in memory because no profile file exists.
    Synthesized,
}

impl ProfileOrigin {
    /// The audit binding check a keyed writer applies to a profile of this
    /// origin.
    ///
    /// A persisted profile records an absent binding; a synthesized one only
    /// compares, so a profile held only in memory leaves the coordinate
    /// unrecorded.
    #[must_use]
    pub fn binding_check(self) -> crate::audit_log::BindingCheck {
        match self {
            Self::Persisted => crate::audit_log::BindingCheck::Enforce,
            Self::Synthesized => crate::audit_log::BindingCheck::CheckOnly,
        }
    }
}

/// Synthesises the first-run testnet fallback profile.
///
/// Returns a profile with `policy.engine = Noop` so that `WalletServer::new`
/// can succeed without an owner-key keyring entry.  See
/// [`load_default_or_testnet_fallback`].
///
/// The asymmetry between this fallback and a newly-minted profile is
/// intentional: newly-minted profiles default to `V1`, but the synthesised
/// first-run fallback retains `Noop` because no owner-key has been minted yet.
/// V1 setup requires an enrolled owner key, an attestation key, and an
/// existing policy file signed with `sign-policy`. MCP payment simulation
/// requires a nonce key. MCP signing requires an audit key and an enrolled signer.
/// The CLI reference's `profile init` entry links the complete setup sequence.
///
/// # Design note
///
/// The synthesised profile is never persisted — it is in-memory only for the
/// duration of the current process.  A newly-initialised deployment creates
/// an explicit `default.toml` via `stellar-agent profile init` (which writes
/// `engine = "v1"` by default, or `engine = "noop"` with `--engine noop`);
/// from that point the fallback arm is no longer taken.
fn synthesise_default_first_run_profile() -> Profile {
    let signer = super::schema::KeyringEntryRef::default_signer("default");
    let nonce = super::schema::KeyringEntryRef::default_nonce("default");
    Profile::builder_testnet(
        &signer.service,
        &signer.account,
        &nonce.service,
        &nonce.account,
    )
    .with_profile_name("default")
    .with_noop_engine()
    .build()
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal deserialization helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Lightweight version-check struct for pre-validation before full extraction.
#[derive(serde::Deserialize)]
struct RawVersion {
    version: u32,
}

/// The chain identity read from the profile file alone; overlays never reach it.
#[derive(serde::Deserialize)]
struct OnDiskChainId {
    chain_id: Caip2,
}

/// Reads the wallet key references the profile file names, without overlays.
///
/// Each field of [`WALLET_KEY_REFERENCE_FIELDS`] is decoded on its own and a
/// malformed one is skipped, so this read never refuses a file the merged
/// extraction accepts.
fn file_wallet_key_references(
    name: &str,
    path: &Path,
) -> Result<Vec<KeyringEntryRef>, ProfileLoadError> {
    let fields: serde_json::Map<String, serde_json::Value> = Figment::new()
        .merge(Toml::file(path))
        .extract()
        .map_err(|e| ProfileLoadError::Figment {
            name: name.to_owned(),
            source: Box::new(e),
        })?;
    Ok(WALLET_KEY_REFERENCE_FIELDS
        .iter()
        .filter_map(|field| fields.get(*field))
        .filter_map(|value| serde_json::from_value(value.clone()).ok())
        .collect())
}

/// The wallet key references the provider credential rules compare against:
/// those of `profile` followed by those the file alone names.
fn wallet_refs_with_file<'a>(
    profile: &'a Profile,
    file_refs: &'a [KeyringEntryRef],
) -> Vec<&'a KeyringEntryRef> {
    profile
        .wallet_key_references()
        .into_iter()
        .flatten()
        .chain(file_refs)
        .collect()
}

/// Canonical-directory wrapper for [`check_provider_credential_for_write_in_dir`].
///
/// # Errors
///
/// See [`check_provider_credential_for_write_in_dir`]; additionally
/// [`ProfileLoadError::NoStateDir`] when the OS-conventional profile directory
/// cannot be determined.
pub fn check_provider_credential_for_write(
    name: &str,
    profile: &Profile,
    role: ProviderRole,
    credential: &KeyringEntryRef,
    placement: &RpcCredentialPlacement,
) -> Result<(), ProfileLoadError> {
    check_provider_credential_for_write_in_dir(
        name,
        &default_profile_dir()?,
        profile,
        role,
        credential,
        placement,
    )
}

/// Runs the loader's credential checks on a provider record of `role` that a
/// caller is about to write into the profile file `name` in `dir`.
///
/// `profile` is the loaded profile. The checks are the loader's credential
/// checks in the loader's order, against the role's merged endpoint URL and
/// the wallet key references of both the loaded profile and the file alone,
/// the same references the loader compares. A record that passes loads.
///
/// # Errors
///
/// - [`ProfileLoadError::InvalidName`] when `name` is not safe as a path
///   component.
/// - [`ProfileLoadError::Figment`] when the file cannot be read.
/// - [`ProfileLoadError::InvalidProviderAttestation`] with the refused field,
///   including [`ProviderAttestationRejection::UrlRequired`] when the role has
///   no endpoint URL.
pub fn check_provider_credential_for_write_in_dir(
    name: &str,
    dir: &Path,
    profile: &Profile,
    role: ProviderRole,
    credential: &KeyringEntryRef,
    placement: &RpcCredentialPlacement,
) -> Result<(), ProfileLoadError> {
    guard_name_for_load(name)?;
    let file_refs = file_wallet_key_references(name, &dir.join(format!("{name}.toml")))?;
    let invalid = |source| ProfileLoadError::InvalidProviderAttestation {
        name: name.to_owned(),
        source,
    };
    let url = profile.role_url(role).ok_or_else(|| {
        invalid(ProviderAttestationError {
            field: role.record_field(),
            reason: ProviderAttestationRejection::UrlRequired {
                url_field: role.url_field(),
            },
        })
    })?;
    check_provider_credential(
        role,
        credential,
        placement,
        url,
        &wallet_refs_with_file(profile, &file_refs),
    )
    .map_err(invalid)
}

/// The merged endpoint URLs of the three roles.
struct RoleUrls<'a> {
    primary: &'a str,
    secondary: Option<&'a str>,
    oracle: Option<&'a str>,
}

/// One provider record as the file states it, before the role checks.
struct DecodedRecord {
    operator: String,
    host: String,
    independent_of_primary: bool,
    credential: Option<KeyringEntryRef>,
    placement: Option<RpcCredentialPlacement>,
}

/// Checks the `providers` table and returns the validated records.
///
/// The checks run in a fixed order and the first refusal wins:
///
/// 1. The container is a table with no key besides `primary`, `secondary`,
///    and `oracle`.
/// 2. The primary record: its decode, the credential pairing, the
///    reserved-entry rule, its operator, its host against `rpc_url`, and the
///    credential endpoint rules.
/// 3. For the secondary, then the oracle record: its decode, the credential
///    pairing, the reserved-entry rule, the endpoint presence, its operator,
///    its host, the credential endpoint rules, the mainnet independence
///    assertion, and the distinct primary host.
/// 4. On mainnet, a primary record when a secondary or oracle URL is set.
/// 5. On mainnet, a secondary or oracle operator other than the primary's.
fn validate_providers(
    raw: Option<&serde_json::Value>,
    chain: Caip2,
    urls: &RoleUrls<'_>,
    wallet_refs: &[&KeyringEntryRef],
) -> Result<Option<Providers>, ProviderAttestationError> {
    use ProviderAttestationRejection as Reason;
    let reject = |field, reason| ProviderAttestationError { field, reason };
    let table = raw
        .map(|value| {
            value
                .as_object()
                .ok_or_else(|| reject("providers", Reason::InvalidContainer))
        })
        .transpose()?;
    if let Some(table) = table
        && table
            .keys()
            .any(|key| !matches!(key.as_str(), "primary" | "secondary" | "oracle"))
    {
        return Err(reject("providers", Reason::InvalidContainer));
    }
    let record_of = |role: ProviderRole| {
        table
            .and_then(|table| table.get(role.as_str()))
            .map(|value| decode_provider_record(value, role))
            .transpose()
    };

    let mut primary = None;
    if let Some(record) = record_of(ProviderRole::Primary)? {
        check_record_credential(&record, ProviderRole::Primary, wallet_refs)?;
        check_record_endpoint(&record, ProviderRole::Primary, urls.primary)?;
        primary = Some(PrimaryProviderRecord {
            operator: record.operator,
            host: record.host,
            credential: record.credential,
            placement: record.placement,
        });
    }

    let mut providers = Providers {
        primary,
        ..Providers::default()
    };
    for (role, url, slot) in [
        (
            ProviderRole::Secondary,
            urls.secondary,
            &mut providers.secondary,
        ),
        (ProviderRole::Oracle, urls.oracle, &mut providers.oracle),
    ] {
        let record = record_of(role)?;
        if let Some(record) = &record {
            check_record_credential(record, role, wallet_refs)?;
        }
        let url_field = role.url_field();
        let (record, url) = match (record, url) {
            (None, None) => continue,
            (Some(_), None) => {
                return Err(reject(
                    role.record_field(),
                    Reason::UrlRequired { url_field },
                ));
            }
            (None, Some(_)) if chain.is_mainnet() => {
                return Err(reject(
                    role.record_field(),
                    Reason::MissingRecord { url_field },
                ));
            }
            (None, Some(_)) => continue,
            (Some(record), Some(url)) => (record, url),
        };
        check_record_endpoint(&record, role, url)?;
        if chain.is_mainnet() && !record.independent_of_primary {
            return Err(reject(
                role.independence_field(),
                Reason::IndependenceRequired,
            ));
        }
        if record.independent_of_primary && same_provider_host(url, urls.primary) {
            return Err(reject(
                url_field,
                Reason::SamePrimaryHost {
                    record_field: role.record_field(),
                },
            ));
        }
        *slot = Some(ProviderRecord {
            operator: record.operator,
            host: record.host,
            independent_of_primary: record.independent_of_primary,
            credential: record.credential,
            placement: record.placement,
        });
    }

    if chain.is_mainnet() {
        let Some(primary) = &providers.primary else {
            if urls.secondary.is_some() || urls.oracle.is_some() {
                return Err(reject("providers.primary", Reason::PrimaryRecordRequired));
            }
            return Ok(raw.map(|_| providers));
        };
        for (role, record) in [
            (ProviderRole::Secondary, &providers.secondary),
            (ProviderRole::Oracle, &providers.oracle),
        ] {
            if let Some(record) = record
                && same_provider_operator(&record.operator, &primary.operator)
            {
                return Err(reject(role.operator_field(), Reason::SharedOperator));
            }
        }
    }
    Ok(raw.map(|_| providers))
}

/// Checks that a record names a credential and a placement together, and
/// that the credential is no wallet key's entry.
fn check_record_credential(
    record: &DecodedRecord,
    role: ProviderRole,
    wallet_refs: &[&KeyringEntryRef],
) -> Result<(), ProviderAttestationError> {
    use ProviderAttestationRejection as Reason;
    let reject = |field, reason| ProviderAttestationError { field, reason };
    match (&record.credential, &record.placement) {
        (Some(_), None) => Err(reject(
            role.credential_field(),
            Reason::IncompleteCredential {
                missing_field: "placement",
            },
        )),
        (None, Some(_)) => Err(reject(
            role.placement_field(),
            Reason::IncompleteCredential {
                missing_field: "credential",
            },
        )),
        (Some(credential), Some(_))
            if rpc_credential_entry_is_reserved(credential, wallet_refs) =>
        {
            Err(reject(
                role.credential_field(),
                Reason::ReservedCredentialEntry,
            ))
        }
        _ => Ok(()),
    }
}

/// Checks a record's operator and host against the role's endpoint URL, then
/// the endpoint rules of a record that names a credential.
fn check_record_endpoint(
    record: &DecodedRecord,
    role: ProviderRole,
    url: &str,
) -> Result<(), ProviderAttestationError> {
    use ProviderAttestationRejection as Reason;
    let reject = |field, reason| ProviderAttestationError { field, reason };
    if record.operator.trim().is_empty() {
        return Err(reject(role.operator_field(), Reason::EmptyOperator));
    }
    if !matches!(
        (normalized_record_host(&record.host), provider_host(url)),
        (Some(record_host), Some(url_host)) if record_host == url_host
    ) {
        return Err(reject(
            role.host_field(),
            Reason::HostMismatch {
                url_field: role.url_field(),
            },
        ));
    }
    if let (Some(_), Some(placement)) = (&record.credential, &record.placement) {
        check_rpc_credential_endpoint(role, url, placement)?;
    }
    Ok(())
}

// Decode each member without carrying serde's input-bearing diagnostics.
fn decode_provider_record(
    value: &serde_json::Value,
    role: ProviderRole,
) -> Result<DecodedRecord, ProviderAttestationError> {
    use ProviderAttestationRejection as Reason;
    let reject = |field, reason| ProviderAttestationError { field, reason };
    let shape = || reject(role.record_field(), Reason::InvalidShape);
    let table = value.as_object().ok_or_else(shape)?;
    if table.keys().any(|key| {
        !matches!(
            key.as_str(),
            "operator" | "host" | "independent_of_primary" | "credential" | "placement"
        )
    }) {
        return Err(shape());
    }
    let text = |key: &str| match table.get(key) {
        Some(value) => value.as_str().map(str::to_owned).ok_or_else(shape),
        None => Ok(String::new()),
    };
    let operator = text("operator")?;
    let host = text("host")?;
    let independent_of_primary = match (role, table.get("independent_of_primary")) {
        (_, None) => false,
        (ProviderRole::Primary, Some(_)) => {
            return Err(reject(
                role.independence_field(),
                Reason::PrimaryIndependence,
            ));
        }
        (_, Some(value)) => value.as_bool().ok_or_else(shape)?,
    };
    let credential = table
        .get("credential")
        .map(|value| {
            decode_credential(value).map_err(|reason| reject(role.credential_field(), reason))
        })
        .transpose()?;
    let placement = table
        .get("placement")
        .map(|value| {
            decode_placement(value).map_err(|reason| reject(role.placement_field(), reason))
        })
        .transpose()?;
    if let Some(placement) = &placement {
        check_rpc_credential_placement(placement)
            .map_err(|reason| reject(role.placement_name_field(), reason))?;
    }
    Ok(DecodedRecord {
        operator,
        host,
        independent_of_primary,
        credential,
        placement,
    })
}

/// Decodes a credential reference: a table with exactly the string keys
/// `service` and `account`, both passing [`check_rpc_credential_entry`].
fn decode_credential(
    value: &serde_json::Value,
) -> Result<KeyringEntryRef, ProviderAttestationRejection> {
    let invalid = || ProviderAttestationRejection::InvalidCredential;
    let table = value.as_object().ok_or_else(invalid)?;
    if table.len() != 2 {
        return Err(invalid());
    }
    let text = |key: &str| {
        table
            .get(key)
            .and_then(serde_json::Value::as_str)
            .ok_or_else(invalid)
    };
    let entry = KeyringEntryRef::new(text("service")?, text("account")?);
    check_rpc_credential_entry(&entry)?;
    Ok(entry)
}

/// Decodes a placement: `kind = "header"` or `kind = "query"` with a string
/// `name`, or `kind = "path"` alone.
fn decode_placement(
    value: &serde_json::Value,
) -> Result<RpcCredentialPlacement, ProviderAttestationRejection> {
    let invalid = || ProviderAttestationRejection::InvalidPlacement;
    let table = value.as_object().ok_or_else(invalid)?;
    let kind = table
        .get("kind")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(invalid)?;
    let name = || {
        if table.len() != 2 {
            return Err(invalid());
        }
        table
            .get("name")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
            .ok_or_else(invalid)
    };
    match kind {
        "header" => Ok(RpcCredentialPlacement::Header { name: name()? }),
        "query" => Ok(RpcCredentialPlacement::Query { name: name()? }),
        "path" if table.len() == 1 => Ok(RpcCredentialPlacement::Path {}),
        _ => Err(invalid()),
    }
}

fn normalized_record_host(raw: &str) -> Option<String> {
    // Host parsing preserves bracketed IPv6 and rejects URL components.
    let host = url::Host::parse(raw).ok()?.to_string();
    let host = host.strip_suffix('.').unwrap_or(&host);
    (!host.is_empty()).then(|| host.to_owned())
}

/// Partial profile with optional fields that have derived defaults.
///
/// `audit_log_path` is optional in the TOML and resolves from OS conventions
/// at load time.  `rpc_url` is optional on testnet, which resolves the chain's
/// default endpoint; a mainnet file must set it.  `network_passphrase` is NOT
/// present in the TOML: it is always derived from `chain_id`.
///
/// The v2 fields (`audit_log_hash_chain_key_id`, `policy_owner_key_id`,
/// `attestation_key_id`, `counterparty_cache_key_id`) are required in v2
/// profiles; they are populated by `migrate_v1_to_v2` with default-derived
/// names.  `oracle_provider_url` defaults to `None` and is read as a string,
/// so the endpoint rule reports a malformed value.
/// `policy` defaults to `PolicyConfig::default()` (engine `V1`).
/// `classic_fee_per_op_stroops`, `classic_max_fee_per_op_stroops`, and
/// `submit_timeout_seconds` default to `None` for pre-existing v2 profiles
/// that predate those optional fields.
#[derive(serde::Deserialize)]
struct PartialProfile {
    version: u32,
    rpc_url: Option<String>,
    mcp_signer_default: super::schema::KeyringEntryRef,
    mcp_nonce_key_alias: super::schema::KeyringEntryRef,
    #[serde(default, alias = "usd_threshold")]
    cross_check_threshold_stroops: u64,
    #[serde(default)]
    cross_check_thresholds: Option<figment::value::Value>,
    #[serde(default)]
    classic_fee_per_op_stroops: Option<u32>,
    #[serde(default)]
    classic_max_fee_per_op_stroops: Option<u32>,
    #[serde(default)]
    submit_timeout_seconds: Option<u64>,
    audit_log_path: Option<PathBuf>,
    #[serde(default)]
    mcp_disabled: bool,
    audit_log_hash_chain_key_id: super::schema::KeyringEntryRef,
    policy_owner_key_id: super::schema::KeyringEntryRef,
    attestation_key_id: super::schema::KeyringEntryRef,
    counterparty_cache_key_id: super::schema::KeyringEntryRef,
    #[serde(default)]
    oracle_provider_url: Option<String>,
    #[serde(default)]
    providers: Option<serde_json::Value>,
    policy: Option<super::schema::PolicyConfig>,
    #[serde(default)]
    wallet: super::schema::WalletConfig,
    /// Optional override for the maximum rule-ID scan bound.  Validated at
    /// load time against `UPPER_BOUND_MAX_SCAN_ID`.
    #[serde(default)]
    smart_account_max_context_rule_scan_id: Option<u32>,
    /// Optional override for the maximum session-rule lookahead window.
    /// Validated at load time against `MIRRORED_UPPER_BOUND_HORIZON_LEDGERS`.
    #[serde(default)]
    session_rule_max_horizon_ledgers: Option<u32>,
    /// Secondary (trust-anchor) RPC URL for cross-RPC multicall verification.
    /// Required when any policy rule references the multicall router.
    /// Absent from older profiles; defaults to `None`.
    #[serde(default)]
    secondary_rpc_url: Option<String>,
    /// Keyring entry reference for the channel-account pool master seed.
    /// `None` when the pool has not been initialised for this profile.
    #[serde(default)]
    pool_master_key_id: Option<super::schema::KeyringEntryRef>,
    /// Persisted channel-account pool configuration (public bookkeeping only).
    /// `None` when the pool has not been initialised.
    #[serde(default)]
    pool_config: Option<super::schema::PoolConfig>,
    #[serde(default)]
    pool_initialization: Option<super::schema::PoolInitialization>,
    /// Remote-approval HTTP surface configuration. Absent from profiles
    /// predating remote approval; defaults to `None` (off).
    #[serde(default)]
    remote_approval: Option<super::schema::RemoteApprovalConfig>,
    /// Served-page identity. Absent means the pages carry no identity.
    #[serde(default)]
    served_pages: Option<super::schema::ServedPagesConfig>,
    /// Keyring entry for the persisted policy-window-state HMAC key. Absent
    /// from profiles predating this field; the loader derives the
    /// conventional per-profile coordinate when `None`.
    #[serde(default)]
    policy_window_state_key_id: Option<super::schema::KeyringEntryRef>,
}

/// Lists every field of [`PartialProfile`] once.
///
/// The list expands into a destructure with no rest pattern, so a field added
/// to the struct and missing here fails to compile. The test build also gets
/// the field names, which a test compares with the field rows of
/// [`OVERLAY_CLASSES`].
macro_rules! partial_profile_fields {
    ($($field:ident),+ $(,)?) => {
        const _: fn(PartialProfile) = |PartialProfile { $($field: _),+ }| {};

        #[cfg(test)]
        const PARTIAL_PROFILE_FIELD_NAMES: &[&str] = &[$(stringify!($field)),+];
    };
}

partial_profile_fields!(
    version,
    rpc_url,
    mcp_signer_default,
    mcp_nonce_key_alias,
    cross_check_threshold_stroops,
    cross_check_thresholds,
    classic_fee_per_op_stroops,
    classic_max_fee_per_op_stroops,
    submit_timeout_seconds,
    audit_log_path,
    mcp_disabled,
    audit_log_hash_chain_key_id,
    policy_owner_key_id,
    attestation_key_id,
    counterparty_cache_key_id,
    oracle_provider_url,
    providers,
    policy,
    wallet,
    smart_account_max_context_rule_scan_id,
    session_rule_max_horizon_ledgers,
    secondary_rpc_url,
    pool_master_key_id,
    pool_config,
    pool_initialization,
    remote_approval,
    served_pages,
    policy_window_state_key_id,
);

fn parse_cross_check_thresholds(
    name: &str,
    raw: Option<figment::value::Value>,
    passphrase: &str,
) -> Result<CrossCheckThresholds, ProfileLoadError> {
    use figment::value::Value;
    let failure = |entry, reason: String| ProfileLoadError::InvalidCrossCheckThreshold {
        name: name.to_owned(),
        entry,
        reason,
    };
    let Some(raw) = raw else {
        return Ok(CrossCheckThresholds::default());
    };
    let Value::Dict(_, entries) = raw else {
        return Err(failure(
            Entry::Field,
            "is not a table of asset identities and thresholds".to_owned(),
        ));
    };
    let mut result = std::collections::BTreeMap::new();
    for (position, (key, raw_value)) in entries.into_iter().enumerate() {
        let asset = CanonicalAsset::parse_threshold_key(&key)
            .map_err(|error| failure(Entry::Position(position + 1), error.to_string()))?;
        let value_text = match raw_value {
            Value::String(_, text) => Some(text),
            Value::Num(_, num) => num.to_u128_lossy().map(|n| n.to_string()),
            _ => None,
        };
        let value = value_text
            .as_deref()
            .filter(|text| !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|text| text.parse::<i128>().ok())
            .ok_or_else(|| {
                failure(
                    Entry::Asset(asset.clone()),
                    "has a threshold that is not a non-negative integer".to_owned(),
                )
            })?;
        result.insert(asset, value);
    }
    if let Some(conflict) =
        threshold_identity_conflict(&result.keys().cloned().collect::<Vec<_>>(), passphrase)
    {
        return Err(match conflict {
            ThresholdIdentityConflict::NativeContract { asset } => failure(
                Entry::Asset(asset),
                "names the native asset's contract; set cross_check_threshold_stroops instead"
                    .to_owned(),
            ),
            ThresholdIdentityConflict::SameAsset { asset, other } => failure(
                Entry::Asset(asset),
                format!("names the same asset as entry '{other}'"),
            ),
        });
    }
    CrossCheckThresholds::new(result).map_err(|error| failure(Entry::Field, error.to_string()))
}

/// Two threshold entries that name one asset under the network passphrase.
pub(crate) enum ThresholdIdentityConflict {
    /// `asset` is the native asset's contract, which the native threshold
    /// already covers.
    NativeContract {
        /// The contract entry.
        asset: CanonicalAsset,
    },
    /// `asset` is the contract of the classic asset `other`.
    SameAsset {
        /// The contract entry.
        asset: CanonicalAsset,
        /// The classic entry the contract wraps.
        other: CanonicalAsset,
    },
}

/// Returns the first contract entry that aliases the native asset or another
/// entry's classic asset, so each caller can name the conflict in its own
/// configuration terms.
pub(crate) fn threshold_identity_conflict(
    assets: &[CanonicalAsset],
    passphrase: &str,
) -> Option<ThresholdIdentityConflict> {
    for asset in assets {
        if let CanonicalAsset::Contract(id) = asset {
            if CanonicalAsset::Native.sac_contract_id(passphrase).as_ref() == Some(id) {
                return Some(ThresholdIdentityConflict::NativeContract {
                    asset: asset.clone(),
                });
            }
            if let Some(other) = assets
                .iter()
                .find(|other| other.sac_contract_id(passphrase).as_ref() == Some(id))
            {
                return Some(ThresholdIdentityConflict::SameAsset {
                    asset: asset.clone(),
                    other: other.clone(),
                });
            }
        }
    }
    None
}

fn require_policy_section(
    policy: Option<super::schema::PolicyConfig>,
    path: &Path,
) -> Result<super::schema::PolicyConfig, ProfileLoadError> {
    policy.ok_or_else(|| ProfileLoadError::MissingPolicySection {
        path: path.to_path_buf(),
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only"
    )]

    use super::*;
    use crate::profile::schema::sentinel::{self, assert_no_sentinel};
    use crate::profile::schema::{EndpointUrlError, EndpointUrlRejection, MINIMUM_FLOOR};

    #[test]
    fn thresholds_refuse_native_key() {
        for key in ["native", "NATIVE", "xlm", "XlM"] {
            let input = format!(
                "{}\n[cross_check_thresholds]\n\"{key}\" = 1",
                minimal_toml()
            );
            let (dir, name) = write_profile(&input);
            let error = load_from_dir(&name, dir.path(), None).unwrap_err();
            assert!(matches!(
                error,
                ProfileLoadError::InvalidCrossCheckThreshold { .. }
            ));
            assert!(error.to_string().contains("is the native asset"));
        }
    }

    #[test]
    fn thresholds_overlay_is_testnet_only() {
        assert_eq!(
            OVERLAY_CLASSES
                .iter()
                .find(|(key, _)| *key == "cross_check_thresholds")
                .map(|(_, class)| *class),
            Some(OverlayClass::TestnetOnly)
        );
        assert!(matches!(
            provider_load(
                &mainnet_toml(),
                "cross_check_thresholds",
                serde_json::json!({})
            ),
            Err(ProfileLoadError::NonOverlayableField {
                field: "cross_check_thresholds"
            })
        ));
    }

    #[test]
    fn thresholds_invalid_inputs_never_reach_operator_text() {
        let issuer = stellar_strkey::ed25519::PublicKey([7; 32]).to_string();
        let key = format!("USD:{issuer}");
        let hostile = "https://user:credential-marker@example.invalid/private?token=secret-marker";
        let cases = [
            format!("[cross_check_thresholds]\n\"{hostile}\" = 1"),
            "[cross_check_thresholds]\n\"credential-marker\" = 1".to_owned(),
            format!("[cross_check_thresholds]\n\"{key}\" = true"),
            format!("[cross_check_thresholds]\n\"{key}\" = \"credential-marker\""),
            "cross_check_thresholds = \"credential-marker\"".to_owned(),
            "cross_check_thresholds = [\"credential-marker\"]".to_owned(),
        ];
        for input in cases {
            let field_form = !input.starts_with('[');
            let input = if field_form {
                minimal_toml_with_extra(&input)
            } else {
                format!("{}\n{input}", minimal_toml())
            };
            let (dir, name) = write_profile(&input);
            let error = load_from_dir(&name, dir.path(), None).unwrap_err();
            assert!(
                matches!(error, ProfileLoadError::InvalidCrossCheckThreshold { .. }),
                "{error:?}"
            );
            if field_form {
                assert_eq!(
                    error.to_string(),
                    format!(
                        "profile '{name}': [cross_check_thresholds] the field is not a table \
                         of asset identities and thresholds"
                    )
                );
            }
            let mapped = error.to_validation_error(&name);
            assert_eq!(mapped.code(), "validation.config_invalid");
            let text = mapped.to_string();
            for forbidden in [
                hostile,
                "credential-marker",
                "secret-marker",
                "true",
                "private?",
            ] {
                assert!(!text.contains(forbidden), "{text}");
            }
        }
    }

    #[test]
    fn thresholds_validate_values_and_sac_duplicates() {
        let issuer = stellar_strkey::ed25519::PublicKey([7; 32]).to_string();
        let classic = CanonicalAsset::classic("USD", &issuer).unwrap();
        let other = stellar_strkey::Contract([9; 32]).to_string();
        let input = format!(
            "{}\n[cross_check_thresholds]\n\"{classic}\" = 5\n\
            \"{other}\" = \"{}\"",
            minimal_toml(),
            i128::MAX
        );
        let (dir, name) = write_profile(&input);
        let profile = load_from_dir(&name, dir.path(), None).unwrap();
        assert_eq!(profile.cross_check_thresholds.get(&classic), Some(5));
        assert_eq!(
            profile
                .cross_check_thresholds
                .get(&CanonicalAsset::contract(&other).unwrap()),
            Some(i128::MAX)
        );
        for value in [
            "-1",
            "1.0",
            "true",
            "\"+1\"",
            "\" 1\"",
            "\"\"",
            "\"170141183460469231731687303715884105728\"",
        ] {
            let input = format!(
                "{}\n[cross_check_thresholds]\n\"{classic}\" = {value}",
                minimal_toml()
            );
            let (dir, name) = write_profile(&input);
            let error = load_from_dir(&name, dir.path(), None).unwrap_err();
            assert!(matches!(
                error,
                ProfileLoadError::InvalidCrossCheckThreshold { .. }
            ));
            assert!(error.to_string().contains("not a non-negative integer"));
        }
        for (asset, reason) in [
            (
                CanonicalAsset::Native,
                "names the native asset's contract; set cross_check_threshold_stroops instead"
                    .to_owned(),
            ),
            (
                classic.clone(),
                format!("names the same asset as entry '{classic}'"),
            ),
        ] {
            let sac = asset
                .sac_contract_id(Caip2::Testnet.network_passphrase())
                .unwrap();
            let input = format!(
                "{}\n[cross_check_thresholds]\n\"{classic}\" = 1\n\
                \"{sac}\" = 2",
                minimal_toml()
            );
            let (dir, name) = write_profile(&input);
            let error = load_from_dir(&name, dir.path(), None).unwrap_err();
            assert_eq!(
                error.to_string(),
                format!("profile '{name}': [cross_check_thresholds] entry '{sac}' {reason}")
            );
        }
    }

    /// The on-disk chain and endpoint reader reports its own error kind,
    /// naming the file and the missing field.
    #[test]
    fn mainnet_view_failure_names_the_file_and_field() {
        let (dir, name) = write_profile("chain_id = \"stellar:testnet\"\n");
        let path = dir.path().join(format!("{name}.toml"));
        let error = read_mainnet_view_on_disk(&name, dir.path()).unwrap_err();
        assert!(
            matches!(
                &error,
                ProfileLoadError::MainnetViewUnreadable { detail }
                    if *detail == format!("'{}' has no string 'rpc_url' key", path.display())
            ),
            "{error:?}"
        );
    }

    /// One constructed value per [`ProfileLoadError`] variant.
    ///
    /// Adding a variant without extending this list leaves it unpinned, so the
    /// count assertion in [`every_variant_is_pinned`] is what makes the
    /// disposition tests below exhaustive in practice — `disposition`'s own
    /// match already forces the classification decision at compile time.
    fn one_of_every_variant() -> Vec<ProfileLoadError> {
        vec![
            ProfileLoadError::InvalidCrossCheckThreshold {
                name: "p".to_owned(),
                entry: Entry::Position(1),
                reason: "invalid".to_owned(),
            },
            ProfileLoadError::InvalidProviderAttestation {
                name: "p".into(),
                source: ProviderAttestationError {
                    field: "providers",
                    reason: ProviderAttestationRejection::InvalidContainer,
                },
            },
            ProfileLoadError::NonOverlayableField { field: "chain_id" },
            ProfileLoadError::OverlayMayOnlyTighten {
                field: "mcp_disabled",
            },
            ProfileLoadError::MainnetRequiresExplicitProfile {
                name: "p".to_owned(),
                named_by: crate::profile::ProfileNameSource::Env,
            },
            ProfileLoadError::NotFound {
                name: "p".to_owned(),
                path: PathBuf::from("/tmp/p.toml"),
            },
            ProfileLoadError::InvalidName {
                name: "..".to_owned(),
                reason: "must not contain '..'",
            },
            ProfileLoadError::NoStateDir(crate::profile::schema::StateDirError),
            ProfileLoadError::MainnetRpcUrlRequired {
                name: "p".to_owned(),
            },
            ProfileLoadError::InvalidEndpointUrl {
                name: "p".to_owned(),
                source: crate::profile::schema::EndpointUrlError {
                    field: "rpc_url",
                    reason: EndpointUrlRejection::Unparseable(
                        url::ParseError::RelativeUrlWithoutBase,
                    ),
                },
            },
            ProfileLoadError::Figment {
                name: "p".to_owned(),
                source: Box::new(figment::Error::from("bad toml".to_owned())),
            },
            ProfileLoadError::VersionUnsupported {
                name: "p".to_owned(),
                found: 99,
                supported: 2,
            },
            ProfileLoadError::MissingPolicySection {
                path: PathBuf::from("/tmp/p.toml"),
            },
            ProfileLoadError::SignerRefUnreadable {
                detail: "missing [mcp_signer_default]".to_owned(),
            },
            ProfileLoadError::MainnetViewUnreadable {
                detail: "missing chain_id".to_owned(),
            },
            ProfileLoadError::InvalidScanIdBound {
                name: "p".to_owned(),
                value: 1,
                upper_bound: 0,
            },
            ProfileLoadError::InvalidHorizonBound {
                name: "p".to_owned(),
                value: 1,
                upper_bound: 0,
            },
            ProfileLoadError::InvalidServedPageDisplayName {
                name: "p".to_owned(),
                chars: 200,
                upper_bound: 64,
            },
            ProfileLoadError::MulticallRequiresSecondaryRpc {
                profile_name: "p".to_owned(),
                network_safename: "testnet".to_owned(),
            },
        ]
    }

    /// No profile-load failure may be reported as a wallet defect.
    ///
    /// Every variant is either a missing file or something the operator
    /// controls. `internal.unexpected_state` claims the wallet is broken, which
    /// sends an operator to the issue tracker over a file they could have
    /// edited — and it is what `profile show` did for nine of these before the
    /// disposition moved into this crate.
    #[test]
    fn no_variant_is_a_wallet_defect() {
        for err in one_of_every_variant() {
            let disposition = err.disposition();
            assert!(
                matches!(
                    disposition,
                    ProfileLoadDisposition::NotFound | ProfileLoadDisposition::OperatorCorrectable
                ),
                "{err:?} reports {disposition:?}, which no load failure may do"
            );
        }
    }

    /// Only an absent file is `NotFound`; everything else is the operator's to
    /// repair. A variant drifting into `NotFound` would make a malformed
    /// profile indistinguishable from a missing one.
    #[test]
    fn only_a_missing_file_is_not_found() {
        for err in one_of_every_variant() {
            let expected = match err {
                ProfileLoadError::NotFound { .. } => ProfileLoadDisposition::NotFound,
                _ => ProfileLoadDisposition::OperatorCorrectable,
            };
            assert_eq!(err.disposition(), expected, "wrong disposition for {err:?}");
        }
    }

    /// Guards the fixture list against a variant added without a pin.
    ///
    /// Counting the list against itself would prove nothing — it would still
    /// pass with a variant added and unpinned. So the count comes from the enum
    /// declaration in this file's own source. `disposition`'s match already
    /// fails to compile on an unclassified variant; this catches the other
    /// half, a variant classified but never exercised by the tests above.
    #[test]
    fn every_variant_is_pinned() {
        let source = include_str!("loader.rs");
        let enum_body = source
            .split_once("pub enum ProfileLoadError {")
            .expect("the enum declaration is in this file")
            .1
            .split_once("\n}")
            .expect("the enum declaration terminates")
            .0;

        // Variant declarations are the only lines at exactly four-space indent
        // that start with an uppercase letter; doc comments and attributes at
        // that indent start with `/` or `#`, and field lines sit deeper.
        let declared = enum_body
            .lines()
            .filter(|line| {
                line.strip_prefix("    ")
                    .is_some_and(|rest| rest.starts_with(|c: char| c.is_ascii_uppercase()))
            })
            .count();

        assert!(
            declared > 0,
            "variant scan matched nothing; the pattern broke"
        );
        assert_eq!(
            one_of_every_variant().len(),
            declared,
            "one_of_every_variant covers {} of {declared} ProfileLoadError variants; \
             classify the new one in `disposition` and add it to the fixture list",
            one_of_every_variant().len()
        );
    }

    /// Writes a minimal valid profile TOML to a temp directory and returns the
    /// directory handle (keeps the temp dir alive).
    fn write_profile(content: &str) -> (tempfile::TempDir, String) {
        let dir = tempfile::tempdir().unwrap();
        let name = "test-profile";
        let path = dir.path().join(format!("{name}.toml"));
        std::fs::write(&path, content).unwrap();
        (dir, name.to_owned())
    }

    fn provider_load(
        toml: &str,
        field: &'static str,
        value: serde_json::Value,
    ) -> Result<Profile, ProfileLoadError> {
        let (dir, name) = write_profile(toml);
        load_from_path_with_overlays(
            &name,
            &dir.path().join(format!("{name}.toml")),
            Serialized::defaults(HashMap::from([(field, value)])),
            None,
        )
    }

    #[test]
    fn protected_chain_overlay_refuses_different_value() {
        let result = provider_load(
            minimal_toml(),
            "chain_id",
            serde_json::json!("stellar:mainnet"),
        );
        assert!(
            matches!(
                result,
                Err(ProfileLoadError::NonOverlayableField { field: "chain_id" })
            ),
            "{result:?}"
        );
    }

    #[test]
    fn protected_chain_overlay_refuses_equal_value() {
        let result = provider_load(
            minimal_toml(),
            "chain_id",
            serde_json::json!("stellar:testnet"),
        );
        assert!(
            matches!(
                result,
                Err(ProfileLoadError::NonOverlayableField { field: "chain_id" })
            ),
            "{result:?}"
        );
    }

    #[test]
    fn protected_chain_overlay_public_entry_refuses() {
        let (dir, name) = write_profile(minimal_toml());
        let result = load_with_overlay_from_dir(
            &name,
            dir.path(),
            HashMap::from([("chain_id", serde_json::json!("stellar:mainnet"))]),
            None,
        );
        assert!(
            matches!(
                result,
                Err(ProfileLoadError::NonOverlayableField { field: "chain_id" })
            ),
            "{result:?}"
        );
    }

    fn mainnet_toml() -> String {
        minimal_toml()
            .replace("stellar:testnet", "stellar:mainnet")
            .replace(
                "version = 2",
                "version = 2\nrpc_url = \"https://file.example\"",
            )
    }

    #[test]
    fn protected_rpc_overlay_refuses_different_value() {
        let result = provider_load(
            &mainnet_toml(),
            "rpc_url",
            serde_json::json!("https://overlay.example"),
        );
        assert!(
            matches!(
                result,
                Err(ProfileLoadError::NonOverlayableField { field: "rpc_url" })
            ),
            "{result:?}"
        );
    }

    #[test]
    fn protected_rpc_overlay_refuses_equal_value() {
        let result = provider_load(
            &mainnet_toml(),
            "rpc_url",
            serde_json::json!("https://file.example"),
        );
        assert!(
            matches!(
                result,
                Err(ProfileLoadError::NonOverlayableField { field: "rpc_url" })
            ),
            "{result:?}"
        );
    }

    #[test]
    fn protected_secondary_rpc_url_overlay_refuses() {
        let result = provider_load(
            &mainnet_toml(),
            "secondary_rpc_url",
            serde_json::json!("https://secondary.example"),
        );
        assert!(
            matches!(
                result,
                Err(ProfileLoadError::NonOverlayableField {
                    field: "secondary_rpc_url"
                })
            ),
            "{result:?}"
        );
    }

    #[test]
    fn testnet_secondary_rpc_url_overlay_loads() {
        let profile = provider_load(
            minimal_toml(),
            "secondary_rpc_url",
            serde_json::json!("https://secondary.example"),
        )
        .unwrap();
        assert_eq!(
            profile.secondary_rpc_url.as_deref(),
            Some("https://secondary.example")
        );
    }

    #[test]
    fn protected_mcp_signer_default_overlay_refuses() {
        let result = provider_load(
            &mainnet_toml(),
            "mcp_signer_default",
            serde_json::json!({"account": "overlay-account"}),
        );
        assert!(
            matches!(
                result,
                Err(ProfileLoadError::NonOverlayableField {
                    field: "mcp_signer_default"
                })
            ),
            "{result:?}"
        );
    }

    #[test]
    fn testnet_mcp_signer_default_overlay_loads() {
        let profile = provider_load(
            minimal_toml(),
            "mcp_signer_default",
            serde_json::json!({"account": "overlay-account"}),
        )
        .unwrap();
        assert_eq!(profile.mcp_signer_default.account, "overlay-account");
    }

    #[test]
    fn testnet_rpc_overlay_loads() {
        let profile = provider_load(
            minimal_toml(),
            "rpc_url",
            serde_json::json!("https://overlay.example"),
        )
        .unwrap();
        assert_eq!(profile.rpc_url, "https://overlay.example");
    }

    /// The file of [`mainnet_toml`] with an oracle endpoint.
    fn mainnet_oracle_toml() -> String {
        mainnet_toml().replace(
            "version = 2",
            "version = 2\noracle_provider_url = \"https://oracle.example/\"",
        )
    }

    #[test]
    fn protected_oracle_provider_url_overlay_refuses_different_value() {
        let result = provider_load(
            &mainnet_oracle_toml(),
            "oracle_provider_url",
            serde_json::json!("https://overlay.example/"),
        );
        assert!(
            matches!(
                result,
                Err(ProfileLoadError::NonOverlayableField {
                    field: "oracle_provider_url"
                })
            ),
            "{result:?}"
        );
    }

    #[test]
    fn protected_oracle_provider_url_overlay_refuses_equal_value() {
        let result = provider_load(
            &mainnet_oracle_toml(),
            "oracle_provider_url",
            serde_json::json!("https://oracle.example/"),
        );
        assert!(
            matches!(
                result,
                Err(ProfileLoadError::NonOverlayableField {
                    field: "oracle_provider_url"
                })
            ),
            "{result:?}"
        );
    }

    #[test]
    fn testnet_oracle_provider_url_overlay_loads() {
        let profile = provider_load(
            minimal_toml(),
            "oracle_provider_url",
            serde_json::json!("https://overlay.example/"),
        )
        .unwrap();
        assert_eq!(
            profile.oracle_provider_url.as_ref().map(url::Url::as_str),
            Some("https://overlay.example/")
        );
    }

    #[test]
    fn mainnet_unprotected_overlay_loads() {
        let profile =
            provider_load(&mainnet_toml(), "mcp_disabled", serde_json::json!(true)).unwrap();
        assert!(profile.mcp_disabled);
        assert_eq!(profile.chain_id, Caip2::Mainnet);
    }

    /// A well-typed overlay value for every testnet-only key, with the field
    /// of [`Profile`] it lands in rendered for comparison.
    fn testnet_only_overlays() -> Vec<(&'static str, serde_json::Value)> {
        vec![
            ("rpc_url", serde_json::json!("https://overlay.example")),
            (
                "secondary_rpc_url",
                serde_json::json!("https://secondary.example"),
            ),
            (
                "oracle_provider_url",
                serde_json::json!("https://oracle-overlay.example/"),
            ),
            (
                "mcp_signer_default",
                serde_json::json!({"account": "overlay-account"}),
            ),
            ("cross_check_threshold_stroops", serde_json::json!(123_457)),
            ("cross_check_thresholds", serde_json::json!({})),
            ("usd_threshold", serde_json::json!(765_431)),
            ("classic_fee_per_op_stroops", serde_json::json!(211)),
            ("classic_max_fee_per_op_stroops", serde_json::json!(5_011)),
            (
                "smart_account_max_context_rule_scan_id",
                serde_json::json!(57),
            ),
            ("session_rule_max_horizon_ledgers", serde_json::json!(503)),
        ]
    }

    /// Reads the profile field a testnet-only overlay key sets.
    fn testnet_only_field(profile: &Profile, key: &str) -> serde_json::Value {
        match key {
            "rpc_url" => serde_json::json!(profile.rpc_url),
            "secondary_rpc_url" => serde_json::json!(profile.secondary_rpc_url),
            "oracle_provider_url" => {
                serde_json::json!(profile.oracle_provider_url.as_ref().map(url::Url::as_str))
            }
            "mcp_signer_default" => serde_json::json!({
                "account": profile.mcp_signer_default.account
            }),
            "cross_check_threshold_stroops" | "usd_threshold" => {
                serde_json::json!(profile.cross_check_threshold_stroops)
            }
            "cross_check_thresholds" => serde_json::json!(profile.cross_check_thresholds),
            "classic_fee_per_op_stroops" => serde_json::json!(profile.classic_fee_per_op_stroops),
            "classic_max_fee_per_op_stroops" => {
                serde_json::json!(profile.classic_max_fee_per_op_stroops)
            }
            "smart_account_max_context_rule_scan_id" => {
                serde_json::json!(profile.smart_account_max_context_rule_scan_id)
            }
            "session_rule_max_horizon_ledgers" => {
                serde_json::json!(profile.session_rule_max_horizon_ledgers)
            }
            other => panic!("no testnet-only key {other}"),
        }
    }

    /// A well-typed overlay value for every never-overlayable key, so a
    /// missing refusal shows up as an accepted load rather than a type error.
    fn never_overlays() -> Vec<(&'static str, serde_json::Value)> {
        let coordinate = serde_json::json!({"service": "overlay-svc", "account": "overlay"});
        vec![
            ("providers", serde_json::json!({})),
            ("version", serde_json::json!(2)),
            ("mcp_nonce_key_alias", coordinate.clone()),
            ("audit_log_path", serde_json::json!("/tmp/overlay.jsonl")),
            ("audit_log_hash_chain_key_id", coordinate.clone()),
            ("policy_owner_key_id", coordinate.clone()),
            ("attestation_key_id", coordinate.clone()),
            ("counterparty_cache_key_id", coordinate.clone()),
            ("policy", serde_json::json!({"engine": "noop"})),
            ("wallet", serde_json::json!({"mlock_required": "false"})),
            ("pool_master_key_id", coordinate.clone()),
            (
                "pool_config",
                serde_json::json!({"pool_size": 0, "channels": []}),
            ),
            (
                "pool_initialization",
                serde_json::json!({
                    "id": "overlay",
                    "network_passphrase": "Test SDF Network ; September 2015",
                    "funder": "GOVERLAY",
                    "channels": [],
                    "seed_ready": false,
                    "attempt": 1
                }),
            ),
            (
                "remote_approval",
                serde_json::json!({"enabled": true, "bind": "0.0.0.0:8443"}),
            ),
            (
                "served_pages",
                serde_json::json!({"display_name": "overlay"}),
            ),
            ("policy_window_state_key_id", coordinate),
        ]
    }

    #[test]
    fn testnet_only_overlays_load_on_testnet() {
        for (key, value) in testnet_only_overlays() {
            let profile = provider_load(minimal_toml(), key, value.clone())
                .unwrap_or_else(|e| panic!("testnet overlay of {key} must load: {e:?}"));
            assert_eq!(testnet_only_field(&profile, key), value, "{key}");
        }
    }

    #[test]
    fn testnet_only_overlays_refuse_on_mainnet() {
        for (key, value) in testnet_only_overlays() {
            let result = provider_load(&mainnet_toml(), key, value);
            assert!(
                matches!(
                    result,
                    Err(ProfileLoadError::NonOverlayableField { field }) if field == key
                ),
                "{key}: {result:?}"
            );
        }
    }

    /// The alias is its own key: accepted on testnet over a file that sets
    /// neither spelling, refused on mainnet whether the file uses the alias
    /// or neither spelling.
    #[test]
    fn usd_threshold_alias_follows_the_testnet_only_class() {
        assert!(!minimal_toml().contains("threshold"));
        let profile = provider_load(minimal_toml(), "usd_threshold", serde_json::json!(4_242))
            .expect("testnet alias overlay loads");
        assert_eq!(profile.cross_check_threshold_stroops, 4_242);

        let with_alias = mainnet_toml().replace("version = 2", "version = 2\nusd_threshold = 1000");
        for file in [mainnet_toml(), with_alias] {
            let result = provider_load(&file, "usd_threshold", serde_json::json!(4_242));
            assert!(
                matches!(
                    result,
                    Err(ProfileLoadError::NonOverlayableField {
                        field: "usd_threshold"
                    })
                ),
                "{result:?}"
            );
        }
    }

    #[test]
    fn never_overlays_refuse_on_every_chain() {
        for file in [minimal_toml().to_owned(), mainnet_toml()] {
            for (key, value) in never_overlays() {
                let result = provider_load(&file, key, value);
                assert!(
                    matches!(
                        result,
                        Err(ProfileLoadError::NonOverlayableField { field }) if field == key
                    ),
                    "{key}: {result:?}"
                );
            }
        }
    }

    #[test]
    fn submit_timeout_overlay_loads_on_every_chain() {
        for file in [minimal_toml().to_owned(), mainnet_toml()] {
            let profile = provider_load(&file, "submit_timeout_seconds", serde_json::json!(47))
                .expect("submit_timeout_seconds is overlayable on every chain");
            assert_eq!(profile.submit_timeout_seconds, Some(47));
        }
    }

    #[test]
    fn mcp_disabled_overlay_may_only_tighten() {
        for file in [minimal_toml().to_owned(), mainnet_toml()] {
            let profile = provider_load(&file, "mcp_disabled", serde_json::json!(true))
                .expect("an overlay may set mcp_disabled to true");
            assert!(profile.mcp_disabled);

            let file_disabled = file.replace("version = 2", "version = 2\nmcp_disabled = true");
            for value in [
                serde_json::json!(false),
                serde_json::json!("off"),
                serde_json::json!(0),
            ] {
                for toml in [file.as_str(), file_disabled.as_str()] {
                    let result = provider_load(toml, "mcp_disabled", value.clone());
                    assert!(
                        matches!(
                            result,
                            Err(ProfileLoadError::OverlayMayOnlyTighten {
                                field: "mcp_disabled"
                            })
                        ),
                        "{value}: {result:?}"
                    );
                }
            }
        }
    }

    /// The keys `Env::prefixed` yields for the non-profile `STELLAR_AGENT_*`
    /// variables name no profile key, so the class check ignores them.
    #[test]
    fn non_profile_overlay_keys_are_ignored() {
        let (dir, name) = write_profile(&mainnet_toml());
        let overlay = HashMap::from([
            ("home", serde_json::json!("/tmp/home")),
            ("profile", serde_json::json!("mainnet")),
            ("keyring_backend", serde_json::json!("headless-env")),
            ("headless_keyring_key", serde_json::json!("not-a-key")),
            ("log", serde_json::json!("debug")),
        ]);
        let profile = load_from_path_with_overlays(
            &name,
            &dir.path().join(format!("{name}.toml")),
            Serialized::defaults(overlay),
            None,
        )
        .expect("non-profile keys are ignored");
        assert_eq!(profile.chain_id, Caip2::Mainnet);
    }

    /// Two refused keys report the one listed first in the class table, not
    /// the alphabetically first one.
    #[test]
    fn the_first_refused_key_in_table_order_is_reported() {
        let (dir, name) = write_profile(minimal_toml());
        let overlay = HashMap::from([
            ("attestation_key_id", serde_json::json!({"account": "x"})),
            ("policy_owner_key_id", serde_json::json!({"account": "y"})),
        ]);
        let position = |key: &str| OVERLAY_CLASSES.iter().position(|(k, _)| *k == key);
        assert!(position("policy_owner_key_id") < position("attestation_key_id"));
        let result = load_from_path_with_overlays(
            &name,
            &dir.path().join(format!("{name}.toml")),
            Serialized::defaults(overlay),
            None,
        );
        assert!(
            matches!(
                result,
                Err(ProfileLoadError::NonOverlayableField {
                    field: "policy_owner_key_id"
                })
            ),
            "{result:?}"
        );
    }

    /// The programmatic overlay passes the same class check.
    #[test]
    fn programmatic_overlay_applies_the_class_table() {
        let (dir, name) = write_profile(minimal_toml());
        let refused = load_with_overlay_from_dir(
            &name,
            dir.path(),
            HashMap::from([("audit_log_path", serde_json::json!("/tmp/x.jsonl"))]),
            None,
        );
        assert!(
            matches!(
                refused,
                Err(ProfileLoadError::NonOverlayableField {
                    field: "audit_log_path"
                })
            ),
            "{refused:?}"
        );
        let loosened = load_with_overlay_from_dir(
            &name,
            dir.path(),
            HashMap::from([("mcp_disabled", serde_json::json!(false))]),
            None,
        );
        assert!(
            matches!(
                loosened,
                Err(ProfileLoadError::OverlayMayOnlyTighten {
                    field: "mcp_disabled"
                })
            ),
            "{loosened:?}"
        );
        let accepted = load_with_overlay_from_dir(
            &name,
            dir.path(),
            HashMap::from([("rpc_url", serde_json::json!("https://overlay.example"))]),
            None,
        )
        .expect("testnet rpc_url overlay loads");
        assert_eq!(accepted.rpc_url, "https://overlay.example");
    }

    /// The `PartialProfile` source between its attributes and its closing
    /// brace, with CRLF normalized.
    fn partial_profile_source() -> String {
        let source = include_str!("loader.rs").replace("\r\n", "\n");
        let start = source
            .find("struct PartialProfile {")
            .expect("PartialProfile is declared in this file");
        let attrs_start = source[..start].rfind("\n\n").map_or(0, |blank| blank + 2);
        let mut depth = 0usize;
        let mut end = None;
        for (offset, ch) in source[start..].char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = Some(start + offset + 1);
                        break;
                    }
                }
                _ => {}
            }
        }
        source[attrs_start..end.expect("PartialProfile closes")].to_owned()
    }

    /// Every serde alias or rename spelled in the `PartialProfile` block.
    fn partial_profile_serde_aliases(block: &str) -> Vec<String> {
        let mut aliases = Vec::new();
        for marker in ["alias = \"", "rename = \"", "rename(deserialize = \""] {
            let mut rest = block;
            while let Some(at) = rest.find(marker) {
                let after = &rest[at + marker.len()..];
                let close = after.find('"').expect("the attribute string closes");
                aliases.push(after[..close].to_owned());
                rest = &after[close..];
            }
        }
        aliases
    }

    /// The field rows of the class table are exactly `PartialProfile`'s
    /// fields; the remaining rows are its serde aliases.
    #[test]
    fn class_table_field_rows_equal_the_partial_profile_fields() {
        use std::collections::BTreeSet;
        let aliases: BTreeSet<String> = partial_profile_serde_aliases(&partial_profile_source())
            .into_iter()
            .collect();
        let field_rows: BTreeSet<&str> = OVERLAY_CLASSES
            .iter()
            .map(|(key, _)| *key)
            .filter(|key| !aliases.contains(*key))
            .collect();
        let fields: BTreeSet<&str> = PARTIAL_PROFILE_FIELD_NAMES.iter().copied().collect();
        assert_eq!(field_rows, fields);
        assert_eq!(
            OVERLAY_CLASSES.len(),
            fields.len() + aliases.len(),
            "every table key appears once"
        );
    }

    /// Every alias or rename in the `PartialProfile` block has a table row,
    /// and no attribute in the block renames or merges keys wholesale.
    #[test]
    fn every_partial_profile_alias_has_a_class_row() {
        let block = partial_profile_source();
        assert!(block.contains("struct PartialProfile {"));
        for forbidden in ["rename_all", "flatten", "untagged"] {
            assert!(
                !block.contains(forbidden),
                "PartialProfile uses `{forbidden}`, which the class table cannot list"
            );
        }
        let aliases = partial_profile_serde_aliases(&block);
        assert!(aliases.contains(&"usd_threshold".to_owned()));
        for alias in aliases {
            assert!(
                OVERLAY_CLASSES.iter().any(|(key, _)| *key == alias),
                "serde key `{alias}` has no overlay class row"
            );
        }
    }

    #[test]
    fn version_check_precedes_identity_and_overlay_checks() {
        let result = provider_load(
            "version = 99",
            "chain_id",
            serde_json::json!("stellar:mainnet"),
        );
        assert!(
            matches!(
                result,
                Err(ProfileLoadError::VersionUnsupported { found: 99, .. })
            ),
            "{result:?}"
        );
    }

    #[test]
    fn validation_mapping_preserves_protected_codes_and_redacts_paths() {
        for err in one_of_every_variant() {
            let validation = err.to_validation_error("p");
            let expected = match &err {
                ProfileLoadError::NonOverlayableField { .. }
                | ProfileLoadError::OverlayMayOnlyTighten { .. } => "profile.non_overlayable_field",
                ProfileLoadError::MainnetRequiresExplicitProfile { .. } => {
                    "profile.mainnet_requires_explicit_profile"
                }
                ProfileLoadError::NotFound { .. } => "validation.profile_not_found",
                ProfileLoadError::MainnetRpcUrlRequired { .. } => {
                    "validation.mainnet_rpc_url_required"
                }
                ProfileLoadError::InvalidProviderAttestation { .. } => {
                    "validation.provider_attestation_invalid"
                }
                _ => "validation.config_invalid",
            };
            assert_eq!(validation.code(), expected, "{err:?}");
        }
        let home = std::env::var("HOME").expect("HOME is set in the test environment");
        let error = ProfileLoadError::MissingPolicySection {
            path: PathBuf::from(&home).join("mapping-sentinel.toml"),
        };
        let message = error.to_validation_error("p").to_string();
        assert!(message.contains("<HOME>"), "home prefix must be redacted");
        assert!(!message.contains(home.as_str()));
        assert!(message.contains("mapping-sentinel.toml"));
    }

    fn minimal_toml() -> &'static str {
        r#"
version = 2
chain_id = "stellar:testnet"

[mcp_signer_default]
service = "stellar-agent-signer"
account = "test"

[mcp_nonce_key_alias]
service = "stellar-agent-nonce"
account = "test"

[audit_log_hash_chain_key_id]
service = "stellar-agent-audit-test-profile"
account = "default"

[policy_owner_key_id]
service = "stellar-agent-owner-test-profile"
account = "default"

[attestation_key_id]
service = "stellar-agent-attestation-test-profile"
account = "default"

	[counterparty_cache_key_id]
	service = "stellar-agent-counterparty-test-profile"
	account = "default"

	[policy]
	engine = "v1"
	"#
    }

    #[test]
    fn load_minimal_valid_profile() {
        let (dir, name) = write_profile(minimal_toml());
        let p = load_from_dir(&name, dir.path(), None).unwrap();
        assert_eq!(p.version, 2);
        assert_eq!(p.chain_id, crate::profile::caip2::Caip2::Testnet);
        assert_eq!(p.network_passphrase, "Test SDF Network ; September 2015");
        // rpc_url defaults to testnet default
        assert!(!p.rpc_url.is_empty());
        // v2 fields present
        assert_eq!(
            p.audit_log_hash_chain_key_id.service,
            "stellar-agent-audit-test-profile"
        );
        // V2 profiles must carry an explicit `[policy]` section; this fixture
        // opts into V1 directly.
        assert_eq!(
            p.policy.engine,
            crate::profile::schema::PolicyEngineKind::V1
        );
        assert_eq!(p.oracle_provider_url, None);
        // policy_window_state_key_id is absent from the fixture TOML; the
        // loader derives the conventional per-profile coordinate so existing
        // profile files (predating this field) keep loading unchanged.
        assert_eq!(
            p.policy_window_state_key_id.service,
            "stellar-agent-policy-window-test-profile"
        );
        assert_eq!(p.policy_window_state_key_id.account, "default");
    }

    /// A profile TOML that explicitly sets `[policy_window_state_key_id]`
    /// overrides the name-derived default.
    #[test]
    fn load_explicit_policy_window_state_key_id_overrides_derived_default() {
        let toml = format!(
            "{}\n[policy_window_state_key_id]\nservice = \"custom-window-service\"\naccount = \"custom-account\"\n",
            minimal_toml()
        );
        let (dir, name) = write_profile(&toml);
        let p = load_from_dir(&name, dir.path(), None).unwrap();
        assert_eq!(
            p.policy_window_state_key_id.service,
            "custom-window-service"
        );
        assert_eq!(p.policy_window_state_key_id.account, "custom-account");
    }

    #[test]
    fn load_rejects_v2_profile_missing_policy_section() {
        let toml = r#"
version = 2
chain_id = "stellar:testnet"

[mcp_signer_default]
service = "stellar-agent-signer"
account = "test"

[mcp_nonce_key_alias]
service = "stellar-agent-nonce"
account = "test"

[audit_log_hash_chain_key_id]
service = "stellar-agent-audit-test-profile"
account = "default"

[policy_owner_key_id]
service = "stellar-agent-owner-test-profile"
account = "default"

[attestation_key_id]
service = "stellar-agent-attestation-test-profile"
account = "default"

[counterparty_cache_key_id]
service = "stellar-agent-counterparty-test-profile"
account = "default"
"#;
        let (dir, name) = write_profile(toml);
        let err = load_from_dir(&name, dir.path(), None).unwrap_err();

        assert!(
            matches!(err, ProfileLoadError::MissingPolicySection { .. }),
            "expected MissingPolicySection, got {err}"
        );
    }

    #[test]
    fn load_accepts_v2_profile_with_explicit_noop_policy() {
        let toml = minimal_toml().replace("engine = \"v1\"", "engine = \"noop\"");
        let (dir, name) = write_profile(&toml);
        let p = load_from_dir(&name, dir.path(), None).unwrap();

        assert_eq!(
            p.policy.engine,
            crate::profile::schema::PolicyEngineKind::Noop
        );
    }

    #[test]
    fn load_accepts_v2_profile_with_v1_policy() {
        let (dir, name) = write_profile(minimal_toml());
        let p = load_from_dir(&name, dir.path(), None).unwrap();

        assert_eq!(
            p.policy.engine,
            crate::profile::schema::PolicyEngineKind::V1
        );
    }

    #[test]
    fn load_rpc_url_defaults_from_chain_id() {
        use crate::profile::caip2::TESTNET_RPC_URL;
        let (dir, name) = write_profile(minimal_toml());
        let p = load_from_dir(&name, dir.path(), None).unwrap();
        assert_eq!(p.rpc_url, TESTNET_RPC_URL);
    }

    /// A mainnet file without `rpc_url` refuses: mainnet has no default
    /// endpoint, so the file must name one.
    #[test]
    fn mainnet_file_without_rpc_url_refuses() {
        let toml = minimal_toml().replace("stellar:testnet", "stellar:mainnet");
        let (dir, name) = write_profile(&toml);
        let err = load_from_dir(&name, dir.path(), None).unwrap_err();
        assert!(
            matches!(&err, ProfileLoadError::MainnetRpcUrlRequired { name: refused } if refused == &name),
            "unexpected error: {err:?}"
        );
        assert_eq!(
            err.to_validation_error(&name).code(),
            "validation.mainnet_rpc_url_required"
        );
    }

    // ── Endpoint rule ────────────────────────────────────────────────────────

    /// A valid mainnet primary endpoint for rows that vary another field.
    const RULE_MAINNET_RPC: &str = "https://rpc.example.invalid";

    /// The endpoint fields of one rule-table row.
    #[derive(Clone, Copy)]
    struct Endpoints<'a> {
        rpc_url: Option<&'a str>,
        secondary_rpc_url: Option<&'a str>,
        oracle_provider_url: Option<&'a str>,
    }

    impl<'a> Endpoints<'a> {
        /// The endpoints with `field` set to `value` over the base `rpc_url`.
        fn with(rpc_url: Option<&'a str>, field: &str, value: &'a str) -> Self {
            let mut endpoints = Self {
                rpc_url,
                secondary_rpc_url: None,
                oracle_provider_url: None,
            };
            match field {
                "rpc_url" => endpoints.rpc_url = Some(value),
                "secondary_rpc_url" => endpoints.secondary_rpc_url = Some(value),
                "oracle_provider_url" => endpoints.oracle_provider_url = Some(value),
                other => panic!("no endpoint field `{other}`"),
            }
            endpoints
        }
    }

    /// A profile TOML on `chain_id` carrying the given endpoint fields.
    fn endpoint_toml(chain_id: &str, endpoints: Endpoints<'_>) -> String {
        let mut lines = vec!["version = 2".to_owned()];
        for (field, value) in [
            ("rpc_url", endpoints.rpc_url),
            ("secondary_rpc_url", endpoints.secondary_rpc_url),
            ("oracle_provider_url", endpoints.oracle_provider_url),
        ] {
            if let Some(value) = value {
                lines.push(format!("{field} = \"{value}\""));
            }
        }
        minimal_toml()
            .replace("stellar:testnet", chain_id)
            .replace("version = 2", &lines.join("\n"))
    }

    /// The exact parse failure `url` reports for `raw`.
    fn parse_failure(raw: &str) -> EndpointUrlRejection {
        EndpointUrlRejection::Unparseable(url::Url::parse(raw).unwrap_err())
    }

    /// Every refusal of the endpoint rule, on both chains and all three
    /// fields, with the exact field and reason, and no sentinel component in
    /// the error's `Display`, its `Debug`, or the rendered envelope.
    #[test]
    fn endpoint_rule_refuses_each_field_with_its_exact_reason() {
        let mut rows: Vec<(&str, Endpoints<'_>, &str, EndpointUrlRejection)> = Vec::new();
        for field in ["rpc_url", "secondary_rpc_url", "oracle_provider_url"] {
            let base = (field != "rpc_url").then_some(RULE_MAINNET_RPC);
            for (value, reason) in [
                (sentinel::UNPARSEABLE, parse_failure(sentinel::UNPARSEABLE)),
                (sentinel::FTP, EndpointUrlRejection::UnsupportedScheme),
                (sentinel::HTTP, EndpointUrlRejection::MainnetRequiresHttps),
                (
                    "http://127.0.0.1:8000",
                    EndpointUrlRejection::MainnetRequiresHttps,
                ),
                (
                    "http://localhost:8000",
                    EndpointUrlRejection::MainnetRequiresHttps,
                ),
                (
                    sentinel::HTTPS,
                    EndpointUrlRejection::MainnetCredentialInUrl,
                ),
            ] {
                rows.push((
                    "stellar:mainnet",
                    Endpoints::with(base, field, value),
                    field,
                    reason,
                ));
            }
            for (value, reason) in [
                (sentinel::UNPARSEABLE, parse_failure(sentinel::UNPARSEABLE)),
                (sentinel::FTP, EndpointUrlRejection::UnsupportedScheme),
                (
                    "ftp://host.invalid/",
                    EndpointUrlRejection::UnsupportedScheme,
                ),
            ] {
                rows.push((
                    "stellar:testnet",
                    Endpoints::with(None, field, value),
                    field,
                    reason,
                ));
            }
        }

        for (chain_id, endpoints, field, reason) in rows {
            let (dir, name) = write_profile(&endpoint_toml(chain_id, endpoints));
            let err = load_from_dir(&name, dir.path(), None).unwrap_err();
            match &err {
                ProfileLoadError::InvalidEndpointUrl { source, .. } => assert_eq!(
                    source,
                    &EndpointUrlError { field, reason },
                    "{chain_id} `{field}`"
                ),
                other => panic!("{chain_id} `{field}` ({reason:?}): unexpected {other:?}"),
            }
            assert_no_sentinel(&err.to_string());
            assert_no_sentinel(&format!("{err:?}"));
            let validation = err.to_validation_error(&name);
            assert_eq!(validation.code(), "validation.config_invalid");
            let envelope = crate::envelope::Envelope::<()>::err(
                &crate::error::WalletError::Validation(validation),
            );
            assert_no_sentinel(&serde_json::to_string(&envelope).unwrap());
        }
    }

    /// Testnet accepts a plaintext loopback endpoint and a URL with userinfo
    /// in all three fields, so the mainnet-only checks stay mainnet-only.
    #[test]
    fn endpoint_rule_accepts_testnet_plaintext_and_userinfo() {
        for value in [
            "http://127.0.0.1:8000",
            "https://user:pass@rpc.example.invalid/",
        ] {
            let endpoints = Endpoints {
                rpc_url: Some(value),
                secondary_rpc_url: Some(value),
                oracle_provider_url: Some(value),
            };
            let (dir, name) = write_profile(&endpoint_toml("stellar:testnet", endpoints));
            let profile = load_from_dir(&name, dir.path(), None).unwrap();
            assert_eq!(profile.rpc_url, value);
            assert_eq!(profile.secondary_rpc_url.as_deref(), Some(value));
            assert_eq!(
                profile.oracle_provider_url,
                Some(url::Url::parse(value).unwrap())
            );
        }
    }

    /// The loader reports the first broken field in the order `rpc_url`,
    /// `secondary_rpc_url`, `oracle_provider_url`.
    #[test]
    fn endpoint_rule_reports_the_first_broken_field() {
        for (rpc_url, expected) in [
            ("http://rpc.example.invalid", "rpc_url"),
            (RULE_MAINNET_RPC, "secondary_rpc_url"),
        ] {
            let endpoints = Endpoints {
                rpc_url: Some(rpc_url),
                secondary_rpc_url: Some("http://secondary.example.invalid"),
                oracle_provider_url: Some("https://user:pass@oracle.example.invalid/"),
            };
            let (dir, name) = write_profile(&endpoint_toml("stellar:mainnet", endpoints));
            match load_from_dir(&name, dir.path(), None) {
                Err(ProfileLoadError::InvalidEndpointUrl { source, .. }) => {
                    assert_eq!(source.field, expected, "rpc_url `{rpc_url}`");
                }
                other => panic!("rpc_url `{rpc_url}`: unexpected {other:?}"),
            }
        }
    }

    /// A mainnet file whose three endpoints pass the rule loads them as
    /// written, including an HTTPS loopback endpoint.
    #[test]
    fn endpoint_rule_accepts_mainnet_https_endpoints() {
        let endpoints = Endpoints {
            rpc_url: Some("https://127.0.0.1:8443"),
            secondary_rpc_url: Some("https://secondary.example.invalid"),
            oracle_provider_url: Some("https://oracle.example.invalid/"),
        };
        let mut file = endpoint_toml("stellar:mainnet", endpoints);
        file.push_str(
            &toml::to_string(&serde_json::json!({"providers": {
                "secondary": provider_record("secondary.example.invalid", true),
                "oracle": provider_record("oracle.example.invalid", true)
            }}))
            .unwrap(),
        );
        let file = with_primary_record(&file, "127.0.0.1");
        let (dir, name) = write_profile(&file);
        let profile = load_from_dir(&name, dir.path(), None).unwrap();
        assert_eq!(profile.rpc_url, "https://127.0.0.1:8443");
        assert_eq!(
            profile.secondary_rpc_url.as_deref(),
            Some("https://secondary.example.invalid")
        );
        assert_eq!(
            profile.oracle_provider_url.as_ref().map(url::Url::as_str),
            Some("https://oracle.example.invalid/")
        );
    }

    #[test]
    fn load_explicit_rpc_url_overrides_default() {
        let toml = r#"
version = 2
chain_id = "stellar:testnet"
rpc_url = "https://custom-rpc.example.com"

[mcp_signer_default]
service = "s"
account = "a"

[mcp_nonce_key_alias]
service = "n"
account = "a"

[audit_log_hash_chain_key_id]
service = "stellar-agent-audit-test"
account = "default"

[policy_owner_key_id]
service = "stellar-agent-owner-test"
account = "default"

[attestation_key_id]
service = "stellar-agent-attestation-test"
account = "default"

[counterparty_cache_key_id]
service = "stellar-agent-counterparty-test"
account = "default"

[policy]
engine = "v1"
	"#;
        let (dir, name) = write_profile(toml);
        let p = load_from_dir(&name, dir.path(), None).unwrap();
        assert_eq!(p.rpc_url, "https://custom-rpc.example.com");
    }

    #[test]
    fn load_explicit_oracle_provider_url_parses_url() {
        let toml = r#"
version = 2
chain_id = "stellar:testnet"
oracle_provider_url = "https://oracle-rpc.example.com"

[mcp_signer_default]
service = "s"
account = "a"

[mcp_nonce_key_alias]
service = "n"
account = "a"

[audit_log_hash_chain_key_id]
service = "stellar-agent-audit-test"
account = "default"

[policy_owner_key_id]
service = "stellar-agent-owner-test"
account = "default"

[attestation_key_id]
service = "stellar-agent-attestation-test"
account = "default"

[counterparty_cache_key_id]
service = "stellar-agent-counterparty-test"
account = "default"

[policy]
engine = "v1"
"#;
        let (dir, name) = write_profile(toml);
        let p = load_from_dir(&name, dir.path(), None).unwrap();
        assert_eq!(
            p.oracle_provider_url.as_ref().map(url::Url::as_str),
            Some("https://oracle-rpc.example.com/")
        );
    }

    #[test]
    fn load_version_unsupported_fails_fast() {
        let toml = r#"
version = 9
chain_id = "stellar:testnet"

[mcp_signer_default]
service = "s"
account = "a"

[mcp_nonce_key_alias]
service = "n"
account = "a"
"#;
        let (dir, name) = write_profile(toml);
        let err = load_from_dir(&name, dir.path(), None).unwrap_err();
        assert!(
            matches!(err, ProfileLoadError::VersionUnsupported { found: 9, .. }),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn load_not_found_error() {
        let dir = tempfile::tempdir().unwrap();
        let err = load_from_dir("nonexistent", dir.path(), None).unwrap_err();
        assert!(
            matches!(err, ProfileLoadError::NotFound { .. }),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn load_invalid_rpc_url_error() {
        let toml = r#"
version = 2
chain_id = "stellar:testnet"
rpc_url = "not-a-url"

[mcp_signer_default]
service = "s"
account = "a"

[mcp_nonce_key_alias]
service = "n"
account = "a"

[audit_log_hash_chain_key_id]
service = "stellar-agent-audit-t"
account = "default"

[policy_owner_key_id]
service = "stellar-agent-owner-t"
account = "default"

[attestation_key_id]
service = "stellar-agent-attestation-t"
account = "default"

	[counterparty_cache_key_id]
	service = "stellar-agent-counterparty-t"
	account = "default"

	[policy]
	engine = "v1"
	"#;
        let (dir, name) = write_profile(toml);
        let err = load_from_dir(&name, dir.path(), None).unwrap_err();
        assert!(
            matches!(
                err,
                ProfileLoadError::InvalidEndpointUrl {
                    source: EndpointUrlError {
                        field: "rpc_url",
                        reason: EndpointUrlRejection::Unparseable(_),
                    },
                    ..
                }
            ),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn save_and_reload_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let profile = Profile::builder_testnet("svc", "acct", "nonce-svc", "nonce-acct")
            .with_profile_name("round-trip")
            .audit_log_path(dir.path().join("audit.log"))
            .build();
        save_to_dir("round-trip", &profile, dir.path()).unwrap();

        let loaded = load_from_dir("round-trip", dir.path(), None).unwrap();
        assert_eq!(loaded.chain_id, profile.chain_id);
        assert_eq!(loaded.rpc_url, profile.rpc_url);
        assert_eq!(loaded.network_passphrase, profile.network_passphrase);
        assert_eq!(
            loaded.mcp_signer_default.service,
            profile.mcp_signer_default.service
        );
        assert_eq!(
            loaded.mcp_nonce_key_alias.service,
            profile.mcp_nonce_key_alias.service
        );
        assert_eq!(
            loaded.cross_check_threshold_stroops,
            profile.cross_check_threshold_stroops
        );
        assert!(!loaded.mcp_disabled);
        // v2 fields round-trip
        assert_eq!(
            loaded.audit_log_hash_chain_key_id.service,
            profile.audit_log_hash_chain_key_id.service
        );
        assert_eq!(
            loaded.policy_owner_key_id.service,
            profile.policy_owner_key_id.service
        );
        assert_eq!(
            loaded.attestation_key_id.service,
            profile.attestation_key_id.service
        );
        assert_eq!(
            loaded.counterparty_cache_key_id.service,
            profile.counterparty_cache_key_id.service
        );
        assert_eq!(loaded.policy.engine, profile.policy.engine);
    }

    #[test]
    fn list_profiles_empty_dir() {
        let dir = tempfile::tempdir().unwrap();
        let names = list_profiles_in_dir(dir.path()).unwrap();
        assert!(names.is_empty());
    }

    #[test]
    fn list_profiles_nonexistent_dir() {
        let dir = std::path::PathBuf::from("/nonexistent/path/that/does/not/exist");
        let names = list_profiles_in_dir(&dir).unwrap();
        assert!(names.is_empty());
    }

    #[test]
    fn list_profiles_multiple_sorted() {
        let dir = tempfile::tempdir().unwrap();
        for name in &["zebra", "alpha", "middle"] {
            let path = dir.path().join(format!("{name}.toml"));
            std::fs::write(path, minimal_toml()).unwrap();
        }
        let names = list_profiles_in_dir(dir.path()).unwrap();
        assert_eq!(names, vec!["alpha", "middle", "zebra"]);
    }

    #[test]
    fn cross_check_threshold_stroops_defaults_to_minimum_floor_on_load() {
        // A profile TOML with no cross_check_threshold_stroops field should
        // default to 0 (the serde default), and
        // effective_cross_check_threshold_stroops() returns MINIMUM_FLOOR.
        let (dir, name) = write_profile(minimal_toml());
        let p = load_from_dir(&name, dir.path(), None).unwrap();
        // raw value is 0 (omitted), effective is MINIMUM_FLOOR
        assert_eq!(p.effective_cross_check_threshold_stroops(), MINIMUM_FLOOR);
    }

    #[test]
    fn load_version_1_fails_fast_with_unsupported() {
        // v1 profiles must be migrated first; the loader rejects them directly.
        let toml = r#"
version = 1
chain_id = "stellar:testnet"

[mcp_signer_default]
service = "s"
account = "a"

[mcp_nonce_key_alias]
service = "n"
account = "a"
"#;
        let (dir, name) = write_profile(toml);
        let err = load_from_dir(&name, dir.path(), None).unwrap_err();
        assert!(
            matches!(err, ProfileLoadError::VersionUnsupported { found: 1, .. }),
            "expected VersionUnsupported for v1 profile, got {err}"
        );
    }

    /// The fallback reports a synthesized profile as `Synthesized` and an existing
    /// `default.toml` as `Persisted`, with the binding check each origin implies.
    #[test]
    fn load_default_or_testnet_fallback_reports_the_origin() {
        let dir = tempfile::tempdir().unwrap();
        let (synthesized, origin) = load_default_or_testnet_fallback_from_dir(dir.path()).unwrap();
        assert_eq!(origin, ProfileOrigin::Synthesized);
        assert_eq!(
            origin.binding_check(),
            crate::audit_log::BindingCheck::CheckOnly
        );
        assert_eq!(synthesized.chain_id, Caip2::Testnet);

        std::fs::write(
            dir.path().join("default.toml"),
            minimal_toml().replace("test-profile", "default"),
        )
        .unwrap();
        let (persisted, origin) = load_default_or_testnet_fallback_from_dir(dir.path()).unwrap();
        assert_eq!(origin, ProfileOrigin::Persisted);
        assert_eq!(
            origin.binding_check(),
            crate::audit_log::BindingCheck::Enforce
        );
        assert_eq!(
            persisted.audit_log_hash_chain_key_id.service,
            "stellar-agent-audit-default"
        );
    }

    /// The synthesised first-run profile must use `policy.engine = Noop`, not `V1`.
    ///
    /// The synthesised profile is never persisted and has no owner-key entry in
    /// the keyring.  If the engine were `V1` (`PolicyEngineKind::default()`),
    /// `WalletServer::new` would call `fetch_owner_pubkey_from_keyring("default")`
    /// and return `BuildRegistryError::OwnerKeyAbsent`, crashing the MCP server
    /// on first run before the operator has initialised any profile.
    ///
    /// The first-run MCP startup path must not crash when no profile file exists.
    ///
    /// Newly-minted profiles default to V1; the loader fallback synthesised for
    /// first-run is exempt because it is transient and keyring-less.
    ///
    /// This test calls `synthesise_default_first_run_profile()` directly so that
    /// removing `.with_noop_engine()` from the helper body causes this assertion
    /// to fail.  A tautology test that rebuilds the chain inline would survive
    /// such a deletion silently.
    #[test]
    fn load_default_or_testnet_fallback_synthesised_profile_retains_noop_engine() {
        use crate::profile::schema::PolicyEngineKind;

        let synthesised = super::synthesise_default_first_run_profile();

        assert_eq!(
            synthesised.policy.engine,
            PolicyEngineKind::Noop,
            "synthesise_default_first_run_profile must return Noop engine; \
             got {:?} — deleting .with_noop_engine() from the helper body will \
             crash WalletServer::new on first run",
            synthesised.policy.engine
        );
    }

    // ── Multicall guard tests ─────────────────────────────────────────────────

    /// Minimal `MulticallRegistryHook` stub that unconditionally reports a
    /// registry entry present, regardless of the passphrase.
    struct AlwaysPresentHook;

    impl MulticallRegistryHook for AlwaysPresentHook {
        fn lookup(&self, _network_passphrase: &str) -> Option<()> {
            Some(())
        }
    }

    /// Minimal hook that always reports no registry entry.
    struct NeverPresentHook;

    impl MulticallRegistryHook for NeverPresentHook {
        fn lookup(&self, _network_passphrase: &str) -> Option<()> {
            None
        }
    }

    /// When a multicall registry entry exists for the profile's network AND the
    /// profile has no `secondary_rpc_url`, `load_from_dir` must refuse with
    /// `ProfileLoadError::MulticallRequiresSecondaryRpc`.
    #[test]
    fn profile_load_refuses_when_multicall_registered_without_secondary_rpc_url() {
        // minimal_toml() has no secondary_rpc_url — it will trigger the guard.
        let (dir, name) = write_profile(minimal_toml());
        let hook = AlwaysPresentHook;

        let err = load_from_dir(&name, dir.path(), Some(&hook)).unwrap_err();

        assert!(
            matches!(err, ProfileLoadError::MulticallRequiresSecondaryRpc { .. }),
            "expected MulticallRequiresSecondaryRpc, got: {err}"
        );

        if let ProfileLoadError::MulticallRequiresSecondaryRpc {
            ref profile_name,
            ref network_safename,
        } = err
        {
            assert_eq!(profile_name, &name, "profile_name field must match");
            // testnet passphrase "Test SDF Network ; September 2015" →
            // "test_sdf_network_september_2015"
            assert!(
                !network_safename.is_empty(),
                "network_safename must be non-empty"
            );
            assert!(
                network_safename
                    .chars()
                    .all(|c| c.is_alphanumeric() || c == '_'),
                "network_safename must contain only alphanumeric + underscore; got: {network_safename}"
            );
        }

        let msg = err.to_string();
        assert!(
            msg.contains("secondary_rpc_url"),
            "error message must mention secondary_rpc_url; got: {msg}"
        );
    }

    /// When a multicall registry entry exists AND the profile has a
    /// `secondary_rpc_url`, loading must succeed (the guard must not fire).
    #[test]
    fn profile_load_accepts_when_multicall_registered_with_secondary_rpc_url() {
        // Write a complete profile TOML that includes `secondary_rpc_url` at the
        // root level (before any `[section]` headers).  Building on `minimal_toml()`
        // via string substitution is fragile because the raw string has
        // tab-indented section headers; use a standalone fixture instead.
        let toml = r#"
version = 2
chain_id = "stellar:testnet"
secondary_rpc_url = "https://secondary.example.com"

[mcp_signer_default]
service = "stellar-agent-signer"
account = "test"

[mcp_nonce_key_alias]
service = "stellar-agent-nonce"
account = "test"

[audit_log_hash_chain_key_id]
service = "stellar-agent-audit-test-profile"
account = "default"

[policy_owner_key_id]
service = "stellar-agent-owner-test-profile"
account = "default"

[attestation_key_id]
service = "stellar-agent-attestation-test-profile"
account = "default"

[counterparty_cache_key_id]
service = "stellar-agent-counterparty-test-profile"
account = "default"

[policy]
engine = "v1"
"#;
        let (dir, name) = write_profile(toml);
        let hook = AlwaysPresentHook;

        let profile = load_from_dir(&name, dir.path(), Some(&hook)).unwrap();
        assert_eq!(
            profile.secondary_rpc_url.as_deref(),
            Some("https://secondary.example.com"),
            "secondary_rpc_url must be preserved after load"
        );
    }

    /// When no multicall registry entry exists (`NeverPresentHook`), the guard
    /// must not fire even when `secondary_rpc_url` is absent.
    #[test]
    fn profile_load_accepts_when_no_multicall_registry_entry() {
        let (dir, name) = write_profile(minimal_toml());
        let hook = NeverPresentHook;

        // Should succeed — hook reports no entry, guard is skipped.
        let profile = load_from_dir(&name, dir.path(), Some(&hook)).unwrap();
        assert!(
            profile.secondary_rpc_url.is_none(),
            "secondary_rpc_url should be None (not set in minimal_toml)"
        );
    }

    /// `network_safename_from_passphrase` must produce a safe name for the
    /// known Stellar network passphrases.
    #[test]
    fn network_safename_from_passphrase_known_networks() {
        assert_eq!(
            network_safename_from_passphrase("Test SDF Network ; September 2015"),
            "test_sdf_network_september_2015"
        );
        assert_eq!(
            network_safename_from_passphrase("Public Global Stellar Network ; September 2015"),
            "public_global_stellar_network_september_2015"
        );
    }

    // ── scan_id_bound / horizon_bound validation ──────────────────────────────

    fn minimal_toml_with_extra(extra_kv: &str) -> String {
        format!(
            r#"
version = 2
chain_id = "stellar:testnet"
{extra_kv}

[mcp_signer_default]
service = "stellar-agent-signer"
account = "test"

[mcp_nonce_key_alias]
service = "stellar-agent-nonce"
account = "test"

[audit_log_hash_chain_key_id]
service = "stellar-agent-audit-test-profile"
account = "default"

[policy_owner_key_id]
service = "stellar-agent-owner-test-profile"
account = "default"

[attestation_key_id]
service = "stellar-agent-attestation-test-profile"
account = "default"

[counterparty_cache_key_id]
service = "stellar-agent-counterparty-test-profile"
account = "default"

[policy]
engine = "v1"
"#
        )
    }

    /// `smart_account_max_context_rule_scan_id` at exactly the upper bound
    /// (10_000) must be accepted.
    #[test]
    fn load_scan_id_at_upper_bound_is_accepted() {
        let toml = minimal_toml_with_extra("smart_account_max_context_rule_scan_id = 10000");
        let (dir, name) = write_profile(&toml);
        let p = load_from_dir(&name, dir.path(), None).unwrap();
        assert_eq!(p.smart_account_max_context_rule_scan_id, Some(10_000));
    }

    /// `smart_account_max_context_rule_scan_id` exceeding the upper bound
    /// (10_001) must be rejected with `ProfileLoadError::InvalidScanIdBound`.
    #[test]
    fn load_scan_id_above_upper_bound_is_rejected() {
        let toml = minimal_toml_with_extra("smart_account_max_context_rule_scan_id = 10001");
        let (dir, name) = write_profile(&toml);
        let err = load_from_dir(&name, dir.path(), None).unwrap_err();

        assert!(
            matches!(
                err,
                ProfileLoadError::InvalidScanIdBound {
                    value: 10_001,
                    upper_bound: 10_000,
                    ..
                }
            ),
            "expected InvalidScanIdBound(10001), got: {err}"
        );
        let msg = err.to_string();
        assert!(
            msg.contains("10001"),
            "error message must include the rejected value; got: {msg}"
        );
        assert!(
            msg.contains("10000"),
            "error message must include the cap; got: {msg}"
        );
    }

    /// A large `smart_account_max_context_rule_scan_id` (u32::MAX) is rejected.
    #[test]
    fn load_scan_id_max_u32_is_rejected() {
        let toml = minimal_toml_with_extra(&format!(
            "smart_account_max_context_rule_scan_id = {}",
            u32::MAX
        ));
        let (dir, name) = write_profile(&toml);
        let err = load_from_dir(&name, dir.path(), None).unwrap_err();
        assert!(
            matches!(err, ProfileLoadError::InvalidScanIdBound { .. }),
            "expected InvalidScanIdBound for u32::MAX, got: {err}"
        );
    }

    /// `session_rule_max_horizon_ledgers` at exactly the upper bound (10_000)
    /// must be accepted.
    #[test]
    fn load_horizon_at_upper_bound_is_accepted() {
        let toml = minimal_toml_with_extra("session_rule_max_horizon_ledgers = 10000");
        let (dir, name) = write_profile(&toml);
        let p = load_from_dir(&name, dir.path(), None).unwrap();
        assert_eq!(p.session_rule_max_horizon_ledgers, Some(10_000));
    }

    /// `session_rule_max_horizon_ledgers` exceeding the upper bound (10_001)
    /// must be rejected with `ProfileLoadError::InvalidHorizonBound`.
    #[test]
    fn load_horizon_above_upper_bound_is_rejected() {
        let toml = minimal_toml_with_extra("session_rule_max_horizon_ledgers = 10001");
        let (dir, name) = write_profile(&toml);
        let err = load_from_dir(&name, dir.path(), None).unwrap_err();

        assert!(
            matches!(
                err,
                ProfileLoadError::InvalidHorizonBound {
                    value: 10_001,
                    upper_bound: 10_000,
                    ..
                }
            ),
            "expected InvalidHorizonBound(10001), got: {err}"
        );
    }

    /// A large `session_rule_max_horizon_ledgers` (u32::MAX) is rejected.
    #[test]
    fn load_horizon_max_u32_is_rejected() {
        let toml =
            minimal_toml_with_extra(&format!("session_rule_max_horizon_ledgers = {}", u32::MAX));
        let (dir, name) = write_profile(&toml);
        let err = load_from_dir(&name, dir.path(), None).unwrap_err();
        assert!(
            matches!(err, ProfileLoadError::InvalidHorizonBound { .. }),
            "expected InvalidHorizonBound for u32::MAX, got: {err}"
        );
    }

    // ── [served_pages] ───────────────────────────────────────────────────────

    /// A profile with no `[served_pages]` block loads with no served-page
    /// identity: the pages render neutral rather than falling back to the
    /// project's own name and mark.
    #[test]
    fn load_without_served_pages_block_yields_no_identity() {
        let (dir, name) = write_profile(minimal_toml());
        let p = load_from_dir(&name, dir.path(), None).unwrap();
        assert!(p.served_pages.is_none());
    }

    #[test]
    fn load_served_pages_block_carries_the_name_and_the_mark_flag() {
        let toml = minimal_toml_with_extra(
            "[served_pages]\ndisplay_name = \"Acme Ops\"\nshow_project_mark = true",
        );
        let (dir, name) = write_profile(&toml);
        let p = load_from_dir(&name, dir.path(), None).unwrap();
        let cfg = p.served_pages.expect("[served_pages] must load");
        assert_eq!(cfg.display_name.as_deref(), Some("Acme Ops"));
        assert!(cfg.show_project_mark);
    }

    /// A `display_name` at exactly the render bound is accepted.
    #[test]
    fn load_served_page_display_name_at_bound_is_accepted() {
        let toml = minimal_toml_with_extra(&format!(
            "[served_pages]\ndisplay_name = \"{}\"",
            "n".repeat(MAX_SERVED_PAGE_DISPLAY_NAME_CHARS)
        ));
        let (dir, name) = write_profile(&toml);
        let p = load_from_dir(&name, dir.path(), None).unwrap();
        assert_eq!(
            p.served_pages
                .and_then(|cfg| cfg.display_name)
                .map(|n| n.chars().count()),
            Some(MAX_SERVED_PAGE_DISPLAY_NAME_CHARS)
        );
    }

    /// A `display_name` past the render bound is refused rather than silently
    /// rendered as a prefix of what the operator wrote.
    #[test]
    fn load_served_page_display_name_above_bound_is_rejected() {
        let toml = minimal_toml_with_extra(&format!(
            "[served_pages]\ndisplay_name = \"{}\"",
            "n".repeat(MAX_SERVED_PAGE_DISPLAY_NAME_CHARS + 1)
        ));
        let (dir, name) = write_profile(&toml);
        let err = load_from_dir(&name, dir.path(), None).unwrap_err();
        assert!(
            matches!(
                err,
                ProfileLoadError::InvalidServedPageDisplayName {
                    chars: 65,
                    upper_bound: 64,
                    ..
                }
            ),
            "expected InvalidServedPageDisplayName(65), got: {err}"
        );
        let msg = err.to_string();
        assert!(msg.contains("65"), "{msg}");
        assert!(msg.contains("64"), "{msg}");
    }

    /// The bound counts characters, so a multi-byte name is measured the way
    /// the renderer truncates it.
    #[test]
    fn load_served_page_display_name_bound_counts_characters() {
        let toml = minimal_toml_with_extra(&format!(
            "[served_pages]\ndisplay_name = \"{}\"",
            "\u{4E2D}".repeat(MAX_SERVED_PAGE_DISPLAY_NAME_CHARS)
        ));
        let (dir, name) = write_profile(&toml);
        let p = load_from_dir(&name, dir.path(), None).unwrap();
        assert!(
            p.served_pages.is_some(),
            "a 64-character name must load regardless of its byte length"
        );
    }

    /// When both bounds are at (or below) the limit, the profile loads successfully.
    #[test]
    fn load_both_bounds_within_limits_accepted() {
        let toml = minimal_toml_with_extra(
            "smart_account_max_context_rule_scan_id = 100\nsession_rule_max_horizon_ledgers = 1000",
        );
        let (dir, name) = write_profile(&toml);
        let p = load_from_dir(&name, dir.path(), None).unwrap();
        assert_eq!(p.smart_account_max_context_rule_scan_id, Some(100));
        assert_eq!(p.session_rule_max_horizon_ledgers, Some(1000));
    }

    // ── mcp_disabled field ────────────────────────────────────────────────────

    /// `mcp_disabled = true` round-trips through save + reload.
    #[test]
    fn mcp_disabled_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let mut profile = Profile::builder_testnet("svc", "acct", "n-svc", "n-acct")
            .with_profile_name("disabled-test")
            .audit_log_path(dir.path().join("audit.log"))
            .mcp_disabled()
            .build();
        profile.mcp_disabled = true;

        save_to_dir("disabled-test", &profile, dir.path()).unwrap();
        let loaded = load_from_dir("disabled-test", dir.path(), None).unwrap();
        assert!(
            loaded.mcp_disabled,
            "mcp_disabled=true must survive a round-trip"
        );
    }

    // ── classic fee fields round-trip ─────────────────────────────────────────

    /// `classic_fee_per_op_stroops` and `classic_max_fee_per_op_stroops` round-trip.
    #[test]
    fn classic_fee_fields_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let profile = Profile::builder_testnet("svc", "acct", "n-svc", "n-acct")
            .with_profile_name("fee-test")
            .audit_log_path(dir.path().join("audit.log"))
            .classic_fee_per_op_stroops(Some(200))
            .classic_max_fee_per_op_stroops(Some(1000))
            .build();

        save_to_dir("fee-test", &profile, dir.path()).unwrap();
        let loaded = load_from_dir("fee-test", dir.path(), None).unwrap();
        assert_eq!(loaded.classic_fee_per_op_stroops, Some(200));
        assert_eq!(loaded.classic_max_fee_per_op_stroops, Some(1000));
    }

    /// When `classic_fee_per_op_stroops` is `None`, it is omitted from the
    /// serialised TOML and reloads as `None`.
    #[test]
    fn classic_fee_none_round_trips_as_none() {
        let dir = tempfile::tempdir().unwrap();
        let profile = Profile::builder_testnet("svc", "acct", "n-svc", "n-acct")
            .with_profile_name("fee-none")
            .audit_log_path(dir.path().join("audit.log"))
            .build();

        save_to_dir("fee-none", &profile, dir.path()).unwrap();
        let loaded = load_from_dir("fee-none", dir.path(), None).unwrap();
        assert_eq!(loaded.classic_fee_per_op_stroops, None);
        assert_eq!(loaded.classic_max_fee_per_op_stroops, None);
    }

    // ── pool_config absent in fresh profile ───────────────────────────────────

    /// A freshly-built profile has `pool_config = None` and `pool_master_key_id = None`.
    #[test]
    fn fresh_profile_has_no_pool_config() {
        let dir = tempfile::tempdir().unwrap();
        let profile = Profile::builder_testnet("svc", "acct", "n-svc", "n-acct")
            .with_profile_name("pool-test")
            .audit_log_path(dir.path().join("audit.log"))
            .build();

        save_to_dir("pool-test", &profile, dir.path()).unwrap();
        let loaded = load_from_dir("pool-test", dir.path(), None).unwrap();
        assert!(
            loaded.pool_config.is_none(),
            "pool_config must be None in fresh profile"
        );
        assert!(
            loaded.pool_master_key_id.is_none(),
            "pool_master_key_id must be None in fresh profile"
        );
    }

    // ── set_pool_state_on_disk raw-document patch ─────────────────────────────

    /// Builds a pool-state fixture: a master keyring reference plus a
    /// two-channel config. The channel public keys are bookkeeping strings
    /// (never parsed as strkeys by the loader), so elided placeholders are
    /// sufficient.
    fn pool_state_fixture() -> (
        crate::profile::schema::KeyringEntryRef,
        crate::profile::schema::PoolConfig,
    ) {
        use crate::profile::schema::{KeyringEntryRef, PoolChannelRecord, PoolConfig};
        (
            KeyringEntryRef::new("stellar-agent-pool-test-profile", "default"),
            PoolConfig::new(
                2,
                vec![
                    PoolChannelRecord::new(1, "GABC...CH1"),
                    PoolChannelRecord::new(2, "GDEF...CH2"),
                ],
            ),
        )
    }

    /// The raw-document patch writes exactly the two pool keys and leaves the
    /// rest of the stored document semantically identical. In particular the
    /// loader-derived fields (`rpc_url`, `network_passphrase`,
    /// `audit_log_path`, `policy_window_state_key_id`) that a [`load`] +
    /// [`save`] round trip would materialise must NOT appear: the fixture
    /// TOML omits them, and they must still be absent after the patch.
    #[test]
    fn set_pool_state_on_disk_patches_only_the_pool_keys() {
        let (dir, name) = write_profile(minimal_toml());
        let before: toml::Value = toml::from_str(minimal_toml()).unwrap();
        let (master_ref, cfg) = pool_state_fixture();

        set_pool_state_on_disk(&name, dir.path(), &master_ref, &cfg).unwrap();

        let written = std::fs::read_to_string(dir.path().join(format!("{name}.toml"))).unwrap();
        let mut after: toml::Value = toml::from_str(&written).unwrap();
        let table = after.as_table_mut().unwrap();

        let got_ref: crate::profile::schema::KeyringEntryRef = table
            .remove("pool_master_key_id")
            .expect("pool_master_key_id must be written")
            .try_into()
            .unwrap();
        let got_cfg: crate::profile::schema::PoolConfig = table
            .remove("pool_config")
            .expect("pool_config must be written")
            .try_into()
            .unwrap();
        assert_eq!(got_ref, master_ref);
        assert_eq!(got_cfg, cfg);

        for derived in [
            "rpc_url",
            "network_passphrase",
            "audit_log_path",
            "policy_window_state_key_id",
        ] {
            assert!(
                !table.contains_key(derived),
                "loader-derived field '{derived}' must not be materialised \
                 into the stored document; got:\n{written}"
            );
        }
        assert_eq!(
            after, before,
            "with the pool keys removed, the patched document must equal the \
             original; got:\n{written}"
        );
    }

    /// Keys the profile schema does not model survive the patch: the raw
    /// document is preserved verbatim, not filtered through the schema.
    #[test]
    fn set_pool_state_on_disk_preserves_unmodelled_keys() {
        let toml_with_extra = format!("{}\nx_unmodelled_key = \"keep-me\"\n", minimal_toml());
        let (dir, name) = write_profile(&toml_with_extra);
        let (master_ref, cfg) = pool_state_fixture();

        set_pool_state_on_disk(&name, dir.path(), &master_ref, &cfg).unwrap();

        let written = std::fs::read_to_string(dir.path().join(format!("{name}.toml"))).unwrap();
        assert!(
            written.contains("x_unmodelled_key = \"keep-me\""),
            "keys outside the schema must survive the raw-document patch; got:\n{written}"
        );
    }

    /// A second `set_pool_state_on_disk` (the `pool init --force` shape)
    /// replaces the previous pool bookkeeping wholesale.
    #[test]
    fn set_pool_state_on_disk_overwrites_previous_pool_state() {
        use crate::profile::schema::{KeyringEntryRef, PoolChannelRecord, PoolConfig};
        let (dir, name) = write_profile(minimal_toml());
        let (master_ref, first_cfg) = pool_state_fixture();
        set_pool_state_on_disk(&name, dir.path(), &master_ref, &first_cfg).unwrap();

        let second_ref = KeyringEntryRef::new("stellar-agent-pool-test-profile", "rotated");
        let second_cfg = PoolConfig::new(1, vec![PoolChannelRecord::new(1, "GXYZ...NEW")]);
        set_pool_state_on_disk(&name, dir.path(), &second_ref, &second_cfg).unwrap();

        let loaded = load_from_dir(&name, dir.path(), None).unwrap();
        assert_eq!(loaded.pool_master_key_id, Some(second_ref));
        let cfg = loaded.pool_config.expect("pool_config must be present");
        assert_eq!(cfg, second_cfg);
        assert_eq!(
            cfg.channels.len(),
            1,
            "channels must be replaced, not appended"
        );
    }

    /// The patched document loads through the normal loader and yields the
    /// pool state as typed schema values (serde-shape parity with
    /// [`save`]'s full-profile serialisation).
    #[test]
    fn set_pool_state_on_disk_round_trips_through_load() {
        let (dir, name) = write_profile(minimal_toml());
        let (master_ref, cfg) = pool_state_fixture();
        set_pool_state_on_disk(&name, dir.path(), &master_ref, &cfg).unwrap();

        let loaded = load_from_dir(&name, dir.path(), None).unwrap();
        assert_eq!(loaded.pool_master_key_id, Some(master_ref));
        assert_eq!(loaded.pool_config, Some(cfg));
    }

    /// A TOML that omits `audit_log_path` loads with the PER-PROFILE default
    /// the field's contract documents (`<root>/audit/<name>.jsonl`), keyed by
    /// the profile name the loader was asked for — never a host-global
    /// shared file.
    #[test]
    fn load_unset_audit_log_path_defaults_per_profile() {
        let (dir, name) = write_profile(minimal_toml());
        let loaded = load_from_dir(&name, dir.path(), None).unwrap();
        assert_eq!(
            loaded.audit_log_path,
            crate::profile::schema::default_audit_log_path_for(&name),
            "unset audit_log_path must resolve per-profile"
        );
        assert_eq!(
            loaded.audit_log_path.file_name().unwrap(),
            format!("{name}.jsonl").as_str()
        );
    }

    /// A missing profile file is an I/O error, not a silent creation: pool
    /// state is only ever patched into an existing profile document.
    #[test]
    fn set_pool_state_on_disk_missing_profile_is_io_error() {
        let dir = tempfile::tempdir().unwrap();
        let (master_ref, cfg) = pool_state_fixture();
        let err = set_pool_state_on_disk("absent", dir.path(), &master_ref, &cfg).unwrap_err();
        match err {
            ProfileSaveError::Io(e) => {
                assert_eq!(e.kind(), std::io::ErrorKind::NotFound);
            }
            other => panic!("expected Io(NotFound), got {other:?}"),
        }
        assert!(
            !dir.path().join("absent.toml").exists(),
            "no profile file may be created by a failed patch"
        );
    }

    // ── list_profiles_in_dir ignores non-.toml files ──────────────────────────

    /// `list_profiles_in_dir` ignores files without a `.toml` extension and
    /// only returns names whose file has `.toml` extension.
    #[test]
    fn list_profiles_ignores_non_toml_files() {
        let dir = tempfile::tempdir().unwrap();
        // Write a .toml file and a .json file.
        std::fs::write(dir.path().join("alpha.toml"), minimal_toml()).unwrap();
        std::fs::write(dir.path().join("config.json"), "{}").unwrap();
        std::fs::write(dir.path().join("notes.txt"), "notes").unwrap();

        let names = list_profiles_in_dir(dir.path()).unwrap();
        assert_eq!(names, vec!["alpha"], "must return only .toml stems");
    }

    // ── load_with_overlay_from_dir ────────────────────────────────────────────

    /// `load_with_overlay_from_dir` applies an overlay that overrides a field
    /// present in the TOML.  We use `mcp_disabled` which is a bool and
    /// straightforward to serialize via `serde_json::Value`.
    #[test]
    fn load_with_overlay_overrides_mcp_disabled() {
        let (dir, name) = write_profile(minimal_toml());

        let mut overlay: HashMap<&'static str, serde_json::Value> = HashMap::new();
        overlay.insert("mcp_disabled", serde_json::Value::Bool(true));

        let p = load_with_overlay_from_dir(&name, dir.path(), overlay, None).unwrap();
        assert!(p.mcp_disabled, "overlay must override mcp_disabled to true");
    }

    /// `load_with_overlay_from_dir` returns `NotFound` when the profile file
    /// does not exist.
    #[test]
    fn load_with_overlay_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let overlay: HashMap<&'static str, serde_json::Value> = HashMap::new();
        let err = load_with_overlay_from_dir("ghost", dir.path(), overlay, None).unwrap_err();
        assert!(
            matches!(err, ProfileLoadError::NotFound { .. }),
            "expected NotFound, got: {err}"
        );
    }

    /// `load_with_overlay_from_dir` rejects an unsupported version even with an
    /// overlay supplied.
    #[test]
    fn load_with_overlay_rejects_wrong_version() {
        let bad_version_toml = r#"
version = 9
chain_id = "stellar:testnet"

[mcp_signer_default]
service = "s"
account = "a"

[mcp_nonce_key_alias]
service = "n"
account = "a"
"#;
        let (dir, name) = write_profile(bad_version_toml);
        let overlay: HashMap<&'static str, serde_json::Value> = HashMap::new();
        let err = load_with_overlay_from_dir(&name, dir.path(), overlay, None).unwrap_err();
        assert!(
            matches!(err, ProfileLoadError::VersionUnsupported { found: 9, .. }),
            "expected VersionUnsupported, got: {err}"
        );
    }

    // ── network_safename edge cases ───────────────────────────────────────────

    /// `network_safename_from_passphrase` strips leading and trailing separators.
    #[test]
    fn network_safename_strips_leading_trailing_separators() {
        // Passphrase starting with a non-alphanumeric character.
        let result = network_safename_from_passphrase("; leading");
        assert!(
            !result.starts_with('_'),
            "must strip leading underscore; got: {result}"
        );
        assert_eq!(result, "leading");

        // Passphrase ending with a non-alphanumeric character.
        let result2 = network_safename_from_passphrase("trailing ;");
        assert!(
            !result2.ends_with('_'),
            "must strip trailing underscore; got: {result2}"
        );
        assert_eq!(result2, "trailing");
    }

    /// `network_safename_from_passphrase` collapses consecutive non-alphanumeric
    /// runs into a single underscore.
    #[test]
    fn network_safename_collapses_consecutive_separators() {
        let result = network_safename_from_passphrase("foo   ;   bar");
        assert_eq!(result, "foo_bar");
    }

    /// `network_safename_from_passphrase` output contains only alphanumeric
    /// characters and underscores.
    #[test]
    fn network_safename_output_chars_are_safe() {
        let passphrases = [
            "Test SDF Network ; September 2015",
            "Public Global Stellar Network ; September 2015",
            "Standalone Network ; February 2017",
        ];
        for p in &passphrases {
            let safe = network_safename_from_passphrase(p);
            assert!(
                safe.chars().all(|c| c.is_alphanumeric() || c == '_'),
                "safename must contain only alphanumeric and underscore; got: {safe}"
            );
        }
    }

    // ── mirrored constants ────────────────────────────────────────────────────

    /// Module-level mirrored constants must equal their declared values.
    #[test]
    fn mirrored_constants_have_expected_values() {
        assert_eq!(MIRRORED_UPPER_BOUND_MAX_SCAN_ID, 10_000);
        assert_eq!(MIRRORED_UPPER_BOUND_HORIZON_LEDGERS, 10_000);
        assert_eq!(MIRRORED_MULTICALL_BUNDLE_CAP, 50);
        assert_eq!(MIRRORED_UPPER_BOUND_MULTICALL_BUNDLE_CAP, 75);
    }

    // ── multicall guard with None hook ────────────────────────────────────────

    /// When `multicall_hook` is `None`, the multicall guard is not evaluated
    /// regardless of profile content (no secondary_rpc_url required).
    #[test]
    fn multicall_guard_skipped_when_hook_is_none() {
        // minimal_toml has no secondary_rpc_url — would fail if guard fires.
        let (dir, name) = write_profile(minimal_toml());
        // Passing None should bypass the guard.
        let p = load_from_dir(&name, dir.path(), None).unwrap();
        assert!(
            p.secondary_rpc_url.is_none(),
            "secondary_rpc_url must be None when not set in TOML"
        );
    }

    // ── save_to_dir + list round-trip ─────────────────────────────────────────

    /// A profile saved via `save_to_dir` appears in `list_profiles_in_dir`.
    #[test]
    fn save_to_dir_then_list_includes_name() {
        let dir = tempfile::tempdir().unwrap();
        let profile = Profile::builder_testnet("svc", "acct", "n-svc", "n-acct")
            .with_profile_name("saved-profile")
            .audit_log_path(dir.path().join("audit.log"))
            .build();

        let saved_path = save_to_dir("saved-profile", &profile, dir.path()).unwrap();
        assert!(saved_path.exists(), "saved file must exist after save");

        let names = list_profiles_in_dir(dir.path()).unwrap();
        assert!(
            names.contains(&"saved-profile".to_owned()),
            "saved profile must appear in list; got: {names:?}"
        );
    }

    // ── cross_check_threshold_stroops above MINIMUM_FLOOR ────────────────────

    /// When `cross_check_threshold_stroops` in the TOML exceeds
    /// `MINIMUM_FLOOR`, the raw value is preserved and
    /// `effective_cross_check_threshold_stroops()` returns that higher value.
    /// The saved file carries only the current key: the legacy `usd_threshold`
    /// name is a deserialize-only alias and must never be written.
    #[test]
    fn cross_check_threshold_stroops_above_floor_preserved() {
        let dir = tempfile::tempdir().unwrap();
        let above_floor = MINIMUM_FLOOR + 1;
        let profile = Profile::builder_testnet("svc", "acct", "n-svc", "n-acct")
            .with_profile_name("cross-check-test")
            .audit_log_path(dir.path().join("audit.log"))
            .cross_check_threshold_stroops(above_floor)
            .build();

        save_to_dir("cross-check-test", &profile, dir.path()).unwrap();

        let written = std::fs::read_to_string(dir.path().join("cross-check-test.toml")).unwrap();
        assert!(
            written.contains("cross_check_threshold_stroops ="),
            "saved profile must serialize the current key; got:\n{written}"
        );
        assert!(
            !written.contains("usd_threshold"),
            "saved profile must not serialize the legacy key; got:\n{written}"
        );

        let loaded = load_from_dir("cross-check-test", dir.path(), None).unwrap();
        assert_eq!(loaded.cross_check_threshold_stroops, above_floor);
        assert_eq!(
            loaded.effective_cross_check_threshold_stroops(),
            above_floor
        );
    }

    // ── save_new_to_dir / read_signer_ref_on_disk / pin_signer_account ──────

    /// `save_new_to_dir` writes a fresh profile and refuses an existing
    /// destination atomically, leaving the existing file byte-identical.
    #[test]
    fn save_new_to_dir_refuses_existing_destination() {
        let dir = tempfile::tempdir().unwrap();
        let profile = Profile::builder_testnet("svc", "acct", "n-svc", "n-acct")
            .with_profile_name("fresh")
            .audit_log_path(dir.path().join("audit.log"))
            .build();

        let dest = save_new_to_dir("fresh", &profile, dir.path()).unwrap();
        let original = std::fs::read_to_string(&dest).unwrap();

        let second = save_new_to_dir("fresh", &profile, dir.path());
        assert!(
            matches!(second, Err(ProfileSaveError::AlreadyExists { .. })),
            "second save_new_to_dir must refuse; got: {second:?}"
        );
        assert_eq!(
            std::fs::read_to_string(&dest).unwrap(),
            original,
            "the existing file must be byte-identical after the refusal"
        );
    }

    /// `read_signer_ref_on_disk` returns the stored service/account verbatim.
    #[test]
    fn read_signer_ref_on_disk_reads_raw_values() {
        let (dir, name) = write_profile(minimal_toml());
        let raw_ref = read_signer_ref_on_disk(&name, dir.path()).unwrap();
        assert_eq!(raw_ref.service, "stellar-agent-signer");
        assert_eq!(raw_ref.account, "test");
    }

    /// A missing profile file surfaces as `NotFound`.
    #[test]
    fn read_signer_ref_on_disk_missing_profile_is_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let result = read_signer_ref_on_disk("absent", dir.path());
        assert!(
            matches!(result, Err(ProfileLoadError::NotFound { .. })),
            "missing profile must be NotFound; got: {result:?}"
        );
    }

    // `read_signer_ref_on_disk` is structurally environment-free: it reads
    // the file with std::fs and parses with `toml`, never through figment,
    // so no `STELLAR_AGENT_*` overlay can reach it. The dynamic pin (env set,
    // raw read unchanged) lives in the CLI's enroll-signer tests, where env
    // mutation is permitted; this crate forbids `unsafe_code` outright.

    /// `pin_signer_account_on_disk` patches exactly one key: every other
    /// stored key survives verbatim, including keys the loader does not
    /// model, and no derived field (`network_passphrase`,
    /// `policy_window_state_key_id`, explicit `rpc_url`) is materialised
    /// into the document.
    #[test]
    fn pin_signer_account_on_disk_patches_only_the_account() {
        const PINNED_G: &str = "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY";
        let toml = format!("future_key = \"kept\"\n{}", minimal_toml());
        let (dir, name) = write_profile(&toml);

        pin_signer_account_on_disk(&name, dir.path(), PINNED_G).unwrap();

        let written = std::fs::read_to_string(dir.path().join(format!("{name}.toml"))).unwrap();
        assert!(
            written.contains(&format!("account = \"{PINNED_G}\"")),
            "the signer account must be pinned; got:\n{written}"
        );
        assert!(
            written.contains("service = \"stellar-agent-signer\""),
            "the signer service must be preserved; got:\n{written}"
        );
        assert!(
            written.contains("future_key = \"kept\""),
            "unknown stored keys must survive the patch verbatim; got:\n{written}"
        );
        assert!(
            !written.contains("network_passphrase"),
            "derived fields must not be materialised into the document; got:\n{written}"
        );
        assert!(
            !written.contains("policy_window_state_key_id"),
            "derived key refs must not be materialised into the document; got:\n{written}"
        );

        let loaded = load_from_dir(&name, dir.path(), None).unwrap();
        assert_eq!(loaded.mcp_signer_default.account, PINNED_G);
        assert_eq!(loaded.mcp_signer_default.service, "stellar-agent-signer");
    }

    /// Pinning against a missing profile file errors instead of creating one.
    #[test]
    fn pin_signer_account_on_disk_missing_file_errors() {
        let dir = tempfile::tempdir().unwrap();
        let result = pin_signer_account_on_disk("absent", dir.path(), "GABC");
        assert!(
            matches!(result, Err(ProfileSaveError::Io(_))),
            "pinning a missing profile must error; got: {result:?}"
        );
    }

    /// A TOML carrying BOTH the legacy `usd_threshold` key and the current
    /// `cross_check_threshold_stroops` key is refused at load (serde rejects
    /// the alias collision as a duplicate field) — fail-closed rather than
    /// picking one value.
    #[test]
    fn both_threshold_keys_present_refuses_to_load() {
        let toml = minimal_toml_with_extra(&format!(
            "usd_threshold = {}\ncross_check_threshold_stroops = {}",
            MINIMUM_FLOOR + 3,
            MINIMUM_FLOOR + 5
        ));
        let (dir, name) = write_profile(&toml);
        let result = load_from_dir(&name, dir.path(), None);
        assert!(
            result.is_err(),
            "a profile carrying both threshold keys must refuse to load; got: {result:?}"
        );
    }

    /// A v2 profile TOML written with the legacy `usd_threshold` key still
    /// loads via `#[serde(alias = "usd_threshold")]`, and the value populates
    /// `cross_check_threshold_stroops`.
    #[test]
    fn legacy_usd_threshold_key_alias_loads_into_cross_check_threshold_stroops() {
        let above_floor = MINIMUM_FLOOR + 7;
        let toml = minimal_toml_with_extra(&format!("usd_threshold = {above_floor}"));
        let (dir, name) = write_profile(&toml);
        let loaded = load_from_dir(&name, dir.path(), None).unwrap();
        assert_eq!(loaded.cross_check_threshold_stroops, above_floor);
        assert_eq!(
            loaded.effective_cross_check_threshold_stroops(),
            above_floor
        );
    }

    /// A v2 profile TOML written with the current `cross_check_threshold_stroops`
    /// key loads identically to the legacy-key form.
    #[test]
    fn current_cross_check_threshold_stroops_key_loads() {
        let above_floor = MINIMUM_FLOOR + 7;
        let toml =
            minimal_toml_with_extra(&format!("cross_check_threshold_stroops = {above_floor}"));
        let (dir, name) = write_profile(&toml);
        let loaded = load_from_dir(&name, dir.path(), None).unwrap();
        assert_eq!(loaded.cross_check_threshold_stroops, above_floor);
        assert_eq!(
            loaded.effective_cross_check_threshold_stroops(),
            above_floor
        );
    }

    // ── Mainnet profile round-trip ────────────────────────────────────────────

    /// A mainnet profile saved and reloaded has the correct `chain_id` and
    /// the mainnet network passphrase.
    #[test]
    fn mainnet_profile_round_trip() {
        use crate::profile::caip2::{Caip2, MAINNET_PASSPHRASE};
        let dir = tempfile::tempdir().unwrap();
        let profile = Profile::builder_mainnet(
            "https://rpc.example.invalid",
            "svc",
            "acct",
            "n-svc",
            "n-acct",
        )
        .with_profile_name("mainnet-profile")
        .audit_log_path(dir.path().join("mainnet-audit.log"))
        .build();

        save_to_dir("mainnet-profile", &profile, dir.path()).unwrap();
        let loaded = load_from_dir("mainnet-profile", dir.path(), None).unwrap();
        assert_eq!(loaded.chain_id, Caip2::Mainnet);
        assert_eq!(loaded.network_passphrase, MAINNET_PASSPHRASE);
        assert_eq!(loaded.rpc_url, "https://rpc.example.invalid");
    }

    // ── MulticallRequiresSecondaryRpc error message content ───────────────────

    /// The `MulticallRequiresSecondaryRpc` error message contains the profile
    /// name and the network safe-name derived from the testnet passphrase.
    #[test]
    fn multicall_error_message_contains_profile_and_network() {
        let (dir, name) = write_profile(minimal_toml());
        let hook = AlwaysPresentHook;
        let err = load_from_dir(&name, dir.path(), Some(&hook)).unwrap_err();

        let msg = err.to_string();
        assert!(
            msg.contains(&name),
            "error must contain the profile name '{name}'; got: {msg}"
        );
        // The testnet passphrase → "test_sdf_network_september_2015"
        assert!(
            msg.contains("test_sdf_network"),
            "error must contain part of the network safename; got: {msg}"
        );
    }

    // ── SUPPORTED_VERSION constant ────────────────────────────────────────────

    /// The `SUPPORTED_VERSION` is 2 — the loader rejects v1 and v3.
    ///
    /// Tests that the constant used internally equals 2; if it drifts the
    /// VersionUnsupported tests above would need updating.
    #[test]
    fn supported_version_is_2() {
        // Proxy test via the loader: a v2 TOML loads, a v3 does not.
        let (dir, name) = write_profile(minimal_toml());
        let p = load_from_dir(&name, dir.path(), None).unwrap();
        assert_eq!(p.version, 2);

        let v3_toml = minimal_toml().replace("version = 2", "version = 3");
        let (dir3, name3) = write_profile(&v3_toml);
        let err = load_from_dir(&name3, dir3.path(), None).unwrap_err();
        assert!(
            matches!(
                err,
                ProfileLoadError::VersionUnsupported {
                    found: 3,
                    supported: 2,
                    ..
                }
            ),
            "expected VersionUnsupported found=3 supported=2, got: {err}"
        );
    }

    // ── Path-component guard on the name ──────────────────────────────────────
    //
    // The name is joined into `<dir>/<name>.toml` by every entry point below.
    // The guard lives at the join, so a caller that does not validate still
    // cannot address a file outside `dir`. These tests are the pin for that: if
    // the guard is removed, the traversal name reaches the filesystem and the
    // error becomes `NotFound` (or the write succeeds outside `dir`).

    #[test]
    fn load_from_dir_refuses_a_traversal_name_before_touching_the_filesystem() {
        let dir = tempfile::tempdir().unwrap();
        let err = load_from_dir("../foo", dir.path(), None).unwrap_err();
        match err {
            ProfileLoadError::InvalidName { name, reason } => {
                assert_eq!(name, "../foo");
                assert!(!reason.is_empty(), "the refusal must carry a reason");
            }
            other => panic!("expected InvalidName, got: {other}"),
        }

        // A traversal that carries no path separator is refused by the `..`
        // rule rather than the separator rule.
        let err = load_from_dir("foo..bar", dir.path(), None).unwrap_err();
        match err {
            ProfileLoadError::InvalidName { reason, .. } => assert!(
                reason.contains(".."),
                "reason must name the traversal rule: {reason}"
            ),
            other => panic!("expected InvalidName, got: {other}"),
        }
    }

    #[test]
    fn load_from_dir_refuses_a_name_carrying_a_path_separator() {
        let dir = tempfile::tempdir().unwrap();
        let err = load_from_dir("nested/profile", dir.path(), None).unwrap_err();
        assert!(
            matches!(err, ProfileLoadError::InvalidName { .. }),
            "expected InvalidName, got: {err}"
        );
    }

    #[test]
    fn load_from_dir_accepts_an_ordinary_name() {
        // The guard must not refuse the names operators actually use.
        let (dir, name) = write_profile(minimal_toml());
        assert!(load_from_dir(&name, dir.path(), None).is_ok());
    }

    #[test]
    fn load_with_overlay_from_dir_refuses_a_traversal_name() {
        let dir = tempfile::tempdir().unwrap();
        let err =
            load_with_overlay_from_dir("../foo", dir.path(), HashMap::new(), None).unwrap_err();
        assert!(
            matches!(err, ProfileLoadError::InvalidName { .. }),
            "expected InvalidName, got: {err}"
        );
    }

    #[test]
    fn read_signer_ref_on_disk_refuses_a_traversal_name() {
        let dir = tempfile::tempdir().unwrap();
        let err = read_signer_ref_on_disk("../foo", dir.path()).unwrap_err();
        assert!(
            matches!(err, ProfileLoadError::InvalidName { .. }),
            "expected InvalidName, got: {err}"
        );
    }

    #[test]
    fn save_to_dir_refuses_a_traversal_name_and_writes_nothing() {
        let root = tempfile::tempdir().unwrap();
        let profile_dir = root.path().join("profiles");
        std::fs::create_dir_all(&profile_dir).unwrap();
        let profile = Profile::builder_testnet("svc", "acct", "n-svc", "n-acct").build();

        let err = save_to_dir("../escaped", &profile, &profile_dir).unwrap_err();
        assert!(
            matches!(err, ProfileSaveError::InvalidName { .. }),
            "expected InvalidName, got: {err}"
        );
        assert!(
            !root.path().join("escaped.toml").exists(),
            "the write must not land outside the profile directory"
        );
    }

    #[test]
    fn save_new_to_dir_refuses_a_traversal_name_and_writes_nothing() {
        let root = tempfile::tempdir().unwrap();
        let profile_dir = root.path().join("profiles");
        std::fs::create_dir_all(&profile_dir).unwrap();
        let profile = Profile::builder_testnet("svc", "acct", "n-svc", "n-acct").build();

        let err = save_new_to_dir("../escaped", &profile, &profile_dir).unwrap_err();
        assert!(
            matches!(err, ProfileSaveError::InvalidName { .. }),
            "expected InvalidName, got: {err}"
        );
        assert!(!root.path().join("escaped.toml").exists());
    }

    #[test]
    fn on_disk_patch_helpers_refuse_a_traversal_name() {
        let dir = tempfile::tempdir().unwrap();
        let err = pin_signer_account_on_disk("../foo", dir.path(), "GABC").unwrap_err();
        assert!(
            matches!(err, ProfileSaveError::InvalidName { .. }),
            "expected InvalidName from pin_signer_account_on_disk, got: {err}"
        );

        let pool_key = super::super::schema::KeyringEntryRef::new("svc", "master");
        let pool_config = super::super::schema::PoolConfig::new(0, Vec::new());
        let err =
            set_pool_state_on_disk("../foo", dir.path(), &pool_key, &pool_config).unwrap_err();
        assert!(
            matches!(err, ProfileSaveError::InvalidName { .. }),
            "expected InvalidName from set_pool_state_on_disk, got: {err}"
        );
    }

    fn provider_record(host: &str, independent: bool) -> serde_json::Value {
        serde_json::json!({"operator": "Independent organization", "host": host, "independent_of_primary": independent})
    }

    /// Appends a `[providers.primary]` record for `host` under an operator of
    /// its own, which a mainnet profile with a second endpoint requires.
    fn with_primary_record(file: &str, host: &str) -> String {
        format!("{file}\n[providers.primary]\noperator = \"Primary operator\"\nhost = \"{host}\"\n")
    }

    fn provider_file(
        chain: &str,
        primary: &str,
        secondary: Option<&str>,
        oracle: Option<&str>,
        providers: Option<serde_json::Value>,
    ) -> String {
        let file = endpoint_toml(
            chain,
            Endpoints {
                rpc_url: Some(primary),
                secondary_rpc_url: secondary,
                oracle_provider_url: oracle,
            },
        );
        let mut value: toml::Value = toml::from_str(&file).unwrap();
        if let Some(providers) = providers {
            value.as_table_mut().unwrap().insert(
                "providers".into(),
                toml::Value::try_from(providers).unwrap(),
            );
        }
        toml::to_string(&value).unwrap()
    }

    fn load_provider_file(file: &str) -> Result<Profile, ProfileLoadError> {
        let (dir, name) = write_profile(file);
        load_from_dir(&name, dir.path(), None)
    }

    fn role_file(
        chain: &str,
        role: &str,
        url: Option<&str>,
        record: Option<serde_json::Value>,
    ) -> String {
        provider_file(
            chain,
            "https://primary.example",
            if role == "secondary" { url } else { None },
            if role == "oracle" { url } else { None },
            record.map(|record| serde_json::json!({role: record})),
        )
    }

    fn assert_provider_refusal(file: &str, field: &str, reason: ProviderAttestationRejection) {
        let err = load_provider_file(file).unwrap_err();
        let ProfileLoadError::InvalidProviderAttestation { source, .. } = &err else {
            panic!("{err:?}");
        };
        assert_eq!(source.field, field);
        assert_eq!(source.reason, reason);
        assert_eq!(
            err.disposition(),
            ProfileLoadDisposition::OperatorCorrectable
        );
        let validation = err.to_validation_error("fixture");
        assert_eq!(validation.code(), "validation.provider_attestation_invalid");
        assert!(validation.to_string().contains(field));
        assert!(validation.to_string().contains("profile file"));
        let wallet: crate::error::WalletError = validation.into();
        let envelope = crate::envelope::Envelope::<()>::err(&wallet)
            .to_json_pretty()
            .unwrap();
        assert!(envelope.contains("validation.provider_attestation_invalid"));
        for text in [
            err.to_string(),
            format!("{err:?}"),
            wallet.to_string(),
            format!("{wallet:?}"),
            envelope,
        ] {
            assert!(!text.contains("SECRET_SENTINEL"), "{text}");
        }
    }

    #[test]
    fn mainnet_provider_records_are_required_per_configured_role() {
        for (role, field) in [
            ("secondary", "secondary_rpc_url"),
            ("oracle", "oracle_provider_url"),
        ] {
            assert_provider_refusal(
                &role_file("stellar:mainnet", role, Some("https://other.example"), None),
                &format!("providers.{role}"),
                ProviderAttestationRejection::MissingRecord { url_field: field },
            );
        }
    }

    #[test]
    fn testnet_missing_provider_records_are_allowed() {
        for (secondary, oracle) in [
            (Some("https://primary.example/second"), None),
            (None, Some("https://primary.example/oracle")),
            (
                Some("https://primary.example/second"),
                Some("https://primary.example/oracle"),
            ),
        ] {
            assert!(
                load_provider_file(&provider_file(
                    "stellar:testnet",
                    "https://primary.example",
                    secondary,
                    oracle,
                    None
                ))
                .unwrap()
                .providers
                .is_none()
            );
        }
    }

    #[test]
    fn provider_operator_must_name_an_organization() {
        for chain in ["stellar:testnet", "stellar:mainnet"] {
            for role in ["secondary", "oracle"] {
                for operator in [None, Some(""), Some(" \t\n")] {
                    let mut record = provider_record("other.example", true);
                    record.as_object_mut().unwrap().remove("operator");
                    if let Some(operator) = operator {
                        record["operator"] = operator.into();
                    }
                    assert_provider_refusal(
                        &role_file(chain, role, Some("https://other.example"), Some(record)),
                        &format!("providers.{role}.operator"),
                        ProviderAttestationRejection::EmptyOperator,
                    );
                }
                let mut record = provider_record("other.example", true);
                record["operator"] = "  Meaningful organization  ".into();
                let loaded = load_provider_file(&with_primary_record(
                    &role_file(chain, role, Some("https://other.example"), Some(record)),
                    "primary.example",
                ))
                .unwrap();
                let providers = loaded.providers.unwrap();
                let record = if role == "secondary" {
                    providers.secondary
                } else {
                    providers.oracle
                }
                .unwrap();
                assert_eq!(record.operator, "  Meaningful organization  ");
            }
        }
    }

    #[test]
    fn provider_host_must_match_exactly() {
        for chain in ["stellar:testnet", "stellar:mainnet"] {
            for (role, url_field) in [
                ("secondary", "secondary_rpc_url"),
                ("oracle", "oracle_provider_url"),
            ] {
                for (url, host) in [
                    ("https://other.example", "OTHER.Example"),
                    ("https://other.example", "other.example."),
                    ("https://xn--bcher-kva.example", "BÜCHER.Example"),
                    ("https://127.0.0.1", "127.1"),
                    ("https://[2001:db8::1]", "[2001:0DB8::1]"),
                ] {
                    let loaded = load_provider_file(&with_primary_record(
                        &role_file(chain, role, Some(url), Some(provider_record(host, true))),
                        "primary.example",
                    ))
                    .unwrap();
                    let providers = loaded.providers.unwrap();
                    let record = if role == "secondary" {
                        providers.secondary
                    } else {
                        providers.oracle
                    }
                    .unwrap();
                    assert_eq!(record.host, host);
                }
                for host in [
                    Some("stale.example"),
                    Some("other.example:443"),
                    Some("https://other.example"),
                    Some("other.example/path"),
                    Some("user@other.example"),
                    Some(" other.example"),
                    Some("other.example\t"),
                    Some(""),
                    None,
                ] {
                    let mut record = provider_record(host.unwrap_or_default(), true);
                    if host.is_none() {
                        record.as_object_mut().unwrap().remove("host");
                    }
                    assert_provider_refusal(
                        &role_file(chain, role, Some("https://other.example"), Some(record)),
                        &format!("providers.{role}.host"),
                        ProviderAttestationRejection::HostMismatch { url_field },
                    );
                }
            }
        }
    }

    #[test]
    fn provider_host_requires_two_usable_hosts() {
        for chain in ["stellar:testnet", "stellar:mainnet"] {
            for (role, url_field) in [
                ("secondary", "secondary_rpc_url"),
                ("oracle", "oracle_provider_url"),
            ] {
                for host in ["", ".", "::1", "a b", "example.com"] {
                    assert_provider_refusal(
                        &role_file(
                            chain,
                            role,
                            Some("https://./"),
                            Some(provider_record(host, true)),
                        ),
                        &format!("providers.{role}.host"),
                        ProviderAttestationRejection::HostMismatch { url_field },
                    );
                }
            }
        }
        assert_provider_refusal(
            &provider_file(
                "stellar:mainnet",
                "https://./",
                Some("https://./"),
                None,
                Some(serde_json::json!({"secondary": provider_record(".", true)})),
            ),
            "providers.secondary.host",
            ProviderAttestationRejection::HostMismatch {
                url_field: "secondary_rpc_url",
            },
        );
    }

    #[test]
    fn mainnet_provider_independence_must_be_true() {
        for role in ["secondary", "oracle"] {
            for omitted in [false, true] {
                let mut record = provider_record("primary.example", false);
                if omitted {
                    record
                        .as_object_mut()
                        .unwrap()
                        .remove("independent_of_primary");
                }
                assert_provider_refusal(
                    &role_file(
                        "stellar:mainnet",
                        role,
                        Some("https://primary.example"),
                        Some(record),
                    ),
                    &format!("providers.{role}.independent_of_primary"),
                    ProviderAttestationRejection::IndependenceRequired,
                );
            }
        }
    }

    #[test]
    fn testnet_provider_independence_may_be_false() {
        for role in ["secondary", "oracle"] {
            for omitted in [false, true] {
                let mut record = provider_record("primary.example", false);
                if omitted {
                    record
                        .as_object_mut()
                        .unwrap()
                        .remove("independent_of_primary");
                }
                assert!(
                    load_provider_file(&role_file(
                        "stellar:testnet",
                        role,
                        Some("https://primary.example"),
                        Some(record)
                    ))
                    .is_ok()
                );
            }
        }
    }

    #[test]
    fn mainnet_provider_must_differ_from_primary() {
        for (role, field, record_field) in [
            ("secondary", "secondary_rpc_url", "providers.secondary"),
            ("oracle", "oracle_provider_url", "providers.oracle"),
        ] {
            for (primary, other, host) in [
                (
                    "https://PRIMARY.example.",
                    "https://primary.example:8443/path?key=SECRET_SENTINEL#fragment",
                    "primary.example",
                ),
                ("https://127.1", "https://127.0.0.1", "127.0.0.1"),
            ] {
                let file = role_file(
                    "stellar:mainnet",
                    role,
                    Some(other),
                    Some(provider_record(host, true)),
                )
                .replace("https://primary.example\"", &format!("{primary}\""));
                assert_provider_refusal(
                    &file,
                    field,
                    ProviderAttestationRejection::SamePrimaryHost { record_field },
                );
            }
        }
    }

    #[test]
    fn provider_true_attestation_refuses_on_the_primary_host() {
        for chain in ["stellar:testnet", "stellar:mainnet"] {
            for (role, field, record_field) in [
                ("secondary", "secondary_rpc_url", "providers.secondary"),
                ("oracle", "oracle_provider_url", "providers.oracle"),
            ] {
                assert_provider_refusal(
                    &role_file(
                        chain,
                        role,
                        Some("https://primary.example/other"),
                        Some(provider_record("PRIMARY.EXAMPLE.", true)),
                    ),
                    field,
                    ProviderAttestationRejection::SamePrimaryHost { record_field },
                );
            }
        }
    }

    #[test]
    fn provider_records_accept_distinct_hosts() {
        for chain in ["stellar:testnet", "stellar:mainnet"] {
            for role in ["secondary", "oracle"] {
                for host in ["other.example", "child.primary.example"] {
                    let file = role_file(
                        chain,
                        role,
                        Some(&format!("https://{host}")),
                        Some(provider_record(host, true)),
                    );
                    assert!(
                        load_provider_file(&with_primary_record(&file, "primary.example")).is_ok()
                    );
                }
            }
        }
    }

    #[test]
    fn secondary_and_oracle_may_share_a_provider() {
        for chain in ["stellar:testnet", "stellar:mainnet"] {
            let record = provider_record("shared.example", true);
            let file = provider_file(
                chain,
                "https://primary.example",
                Some("https://shared.example/secondary"),
                Some("https://shared.example/oracle"),
                Some(serde_json::json!({"secondary": record, "oracle": record})),
            );
            assert!(load_provider_file(&with_primary_record(&file, "primary.example")).is_ok());
        }
    }

    #[test]
    fn provider_url_absence_stays_optional() {
        for chain in ["stellar:testnet", "stellar:mainnet"] {
            for providers in [None, Some(serde_json::json!({}))] {
                assert!(
                    load_provider_file(&provider_file(
                        chain,
                        "https://primary.example",
                        None,
                        None,
                        providers
                    ))
                    .is_ok()
                );
            }
        }
    }

    #[test]
    fn provider_record_requires_its_url() {
        for chain in ["stellar:testnet", "stellar:mainnet"] {
            for (role, url_field) in [
                ("secondary", "secondary_rpc_url"),
                ("oracle", "oracle_provider_url"),
            ] {
                assert_provider_refusal(
                    &role_file(
                        chain,
                        role,
                        None,
                        Some(provider_record("other.example", true)),
                    ),
                    &format!("providers.{role}"),
                    ProviderAttestationRejection::UrlRequired { url_field },
                );
                assert!(load_provider_file(&role_file(chain, role, None, None)).is_ok());
            }
        }
    }

    #[test]
    fn provider_shape_errors_name_fields_without_values() {
        for chain in ["stellar:testnet", "stellar:mainnet"] {
            for value in [
                serde_json::json!("SECRET_SENTINEL"),
                serde_json::json!(false),
                serde_json::json!(["SECRET_SENTINEL"]),
                serde_json::json!({"SECRET_SENTINEL": "SECRET_SENTINEL"}),
            ] {
                assert_provider_refusal(
                    &provider_file(chain, "https://primary.example", None, None, Some(value)),
                    "providers",
                    ProviderAttestationRejection::InvalidContainer,
                );
            }
            for role in ["primary", "secondary", "oracle"] {
                for record in [
                    serde_json::json!("SECRET_SENTINEL"),
                    serde_json::json!({"SECRET_SENTINEL": 1}),
                    serde_json::json!({"operator": 1}),
                    serde_json::json!({"host": ["SECRET_SENTINEL"]}),
                    serde_json::json!({"independent_of_primary": "SECRET_SENTINEL"}),
                ] {
                    if role == "primary" && record.get("independent_of_primary").is_some() {
                        continue;
                    }
                    assert_provider_refusal(
                        &role_file(
                            chain,
                            role,
                            Some("https://other.example/SECRET_SENTINEL"),
                            Some(record),
                        ),
                        &format!("providers.{role}"),
                        ProviderAttestationRejection::InvalidShape,
                    );
                }
            }
        }
    }

    #[test]
    fn provider_checks_follow_endpoint_checks() {
        let file = provider_file(
            "stellar:mainnet",
            "http://primary.example",
            Some("https://other.example"),
            None,
            Some(serde_json::json!({"primary": {}, "secondary": "bad", "oracle": "bad"})),
        );
        assert!(matches!(
            load_provider_file(&file),
            Err(ProfileLoadError::InvalidEndpointUrl { .. })
        ));
        let file = file.replace("http://primary.example", "https://primary.example");
        assert_provider_refusal(
            &file,
            "providers.primary.operator",
            ProviderAttestationRejection::EmptyOperator,
        );
        let file = provider_file(
            "stellar:mainnet",
            "https://primary.example",
            Some("https://other.example"),
            Some("https://other.example"),
            Some(serde_json::json!({"secondary": {}, "oracle": "bad"})),
        );
        assert_provider_refusal(
            &file,
            "providers.secondary.operator",
            ProviderAttestationRejection::EmptyOperator,
        );
        let file = file.replace(
            "[providers.secondary]",
            "[providers.secondary]\noperator = 'Valid'",
        );
        assert_provider_refusal(
            &file,
            "providers.secondary.host",
            ProviderAttestationRejection::HostMismatch {
                url_field: "secondary_rpc_url",
            },
        );
        let file = file.replace(
            "operator = 'Valid'",
            "operator = 'Valid'\nhost = 'other.example'",
        );
        assert_provider_refusal(
            &file,
            "providers.secondary.independent_of_primary",
            ProviderAttestationRejection::IndependenceRequired,
        );
        let file = file.replace(
            "host = 'other.example'",
            "host = 'other.example'\nindependent_of_primary = true",
        );
        assert_provider_refusal(
            &file,
            "providers.oracle",
            ProviderAttestationRejection::InvalidShape,
        );
    }

    #[test]
    fn provider_errors_preserve_typed_wire_code_and_text() {
        use ProviderAttestationRejection as R;
        for reason in [
            R::InvalidContainer,
            R::InvalidShape,
            R::PrimaryIndependence,
            R::IncompleteCredential {
                missing_field: "placement",
            },
            R::InvalidCredential,
            R::InvalidPlacement,
            R::InvalidHeaderName,
            R::InvalidQueryParameterName,
            R::ReservedCredentialEntry,
            R::UserinfoWithCredential,
            R::InsecureCredentialEndpoint,
            R::PrimaryRecordRequired,
            R::SharedOperator,
            R::UrlRequired {
                url_field: "oracle_provider_url",
            },
            R::MissingRecord {
                url_field: "oracle_provider_url",
            },
            R::EmptyOperator,
            R::HostMismatch {
                url_field: "oracle_provider_url",
            },
            R::IndependenceRequired,
            R::SamePrimaryHost {
                record_field: "providers.oracle",
            },
        ] {
            let source = ProviderAttestationError {
                field: "providers.oracle",
                reason,
            };
            let error = ProfileLoadError::InvalidProviderAttestation {
                name: "fixture".into(),
                source: source.clone(),
            };
            let validation = error.to_validation_error("fixture");
            assert_eq!(validation.code(), "validation.provider_attestation_invalid");
            assert_eq!(validation.to_string(), error.to_string());
            assert!(
                matches!(validation, crate::error::ValidationError::ProviderAttestationInvalid { source: got, .. } if got == source)
            );
            assert_eq!(
                error.disposition(),
                ProfileLoadDisposition::OperatorCorrectable
            );
        }
    }

    #[test]
    fn provider_overlays_refuse_on_every_chain() {
        for chain in ["stellar:testnet", "stellar:mainnet"] {
            let file = role_file(
                chain,
                "oracle",
                Some("https://other.example"),
                Some(provider_record("other.example", true)),
            );
            for value in [
                serde_json::json!({}),
                serde_json::json!("bad"),
                serde_json::json!({"oracle": provider_record("other.example", true)}),
                serde_json::json!({"oracle": {"host": "changed.example"}}),
            ] {
                assert!(matches!(
                    provider_load(&file, "providers", value),
                    Err(ProfileLoadError::NonOverlayableField { field: "providers" })
                ));
            }
        }
    }

    #[test]
    fn testnet_url_overlay_revalidates_provider_host() {
        for (role, field) in [
            ("secondary", "secondary_rpc_url"),
            ("oracle", "oracle_provider_url"),
        ] {
            let file = role_file(
                "stellar:testnet",
                role,
                Some("https://other.example"),
                Some(provider_record("other.example", true)),
            );
            assert!(
                provider_load(
                    &file,
                    field,
                    serde_json::json!("https://other.example/path")
                )
                .is_ok()
            );
            assert!(matches!(
                provider_load(&file, "rpc_url", serde_json::json!("https://other.example")),
                Err(ProfileLoadError::InvalidProviderAttestation {
                    source: ProviderAttestationError {
                        reason: ProviderAttestationRejection::SamePrimaryHost { .. },
                        ..
                    },
                    ..
                })
            ));
            assert!(matches!(
                provider_load(&file, field, serde_json::json!("https://changed.example")),
                Err(ProfileLoadError::InvalidProviderAttestation {
                    source: ProviderAttestationError {
                        reason: ProviderAttestationRejection::HostMismatch { .. },
                        ..
                    },
                    ..
                })
            ));
        }
    }

    /// Provider records of all three roles that name a keyring credential, the
    /// primary record, and the mainnet operator rule.
    mod provider_credentials {
        use super::*;

        const CHAINS: [&str; 2] = ["stellar:testnet", "stellar:mainnet"];
        const ROLES: [&str; 3] = ["primary", "secondary", "oracle"];

        fn url_field(role: &str) -> &'static str {
            match role {
                "primary" => "rpc_url",
                "secondary" => "secondary_rpc_url",
                _ => "oracle_provider_url",
            }
        }

        fn field(role: &str, suffix: &str) -> String {
            if suffix.is_empty() {
                format!("providers.{role}")
            } else {
                format!("providers.{role}.{suffix}")
            }
        }

        fn header(name: &str) -> serde_json::Value {
            serde_json::json!({"kind": "header", "name": name})
        }

        fn query(name: &str) -> serde_json::Value {
            serde_json::json!({"kind": "query", "name": name})
        }

        fn entry(service: &str, account: &str) -> serde_json::Value {
            serde_json::json!({"service": service, "account": account})
        }

        fn default_entry(role: &str) -> serde_json::Value {
            entry("stellar-agent-rpc-test-profile", role)
        }

        /// A record for `role` on `host` naming `credential` and `placement`.
        fn credential_record(
            role: &str,
            host: &str,
            credential: serde_json::Value,
            placement: serde_json::Value,
        ) -> serde_json::Value {
            let mut record = provider_record(host, true);
            if role == "primary" {
                record
                    .as_object_mut()
                    .unwrap()
                    .remove("independent_of_primary");
            }
            record["credential"] = credential;
            record["placement"] = placement;
            record
        }

        /// A profile on `chain` whose `role` endpoint is `url` and whose `role`
        /// record is `record`. Secondary and oracle files use the primary
        /// endpoint `https://primary.example` with a primary record of
        /// another operator.
        fn role_credential_file(
            chain: &str,
            role: &str,
            url: Option<&str>,
            record: serde_json::Value,
        ) -> String {
            let mut providers = serde_json::Map::new();
            providers.insert(role.to_owned(), record);
            if role == "primary" {
                return provider_file(
                    chain,
                    url.unwrap(),
                    None,
                    None,
                    Some(serde_json::Value::Object(providers)),
                );
            }
            providers.insert(
                "primary".to_owned(),
                serde_json::json!({"operator": "Primary operator", "host": "primary.example"}),
            );
            provider_file(
                chain,
                "https://primary.example",
                if role == "secondary" { url } else { None },
                if role == "oracle" { url } else { None },
                Some(serde_json::Value::Object(providers)),
            )
        }

        /// The endpoint URL of `role` in the fixtures: the primary on
        /// `primary.example`, the others on `other.example`.
        fn role_host(role: &str) -> &'static str {
            if role == "primary" {
                "primary.example"
            } else {
                "other.example"
            }
        }

        /// Rewrites a profile file through `edit` on its parsed TOML.
        fn edit_file(file: &str, edit: impl FnOnce(&mut toml::Value)) -> String {
            let mut value: toml::Value = toml::from_str(file).unwrap();
            edit(&mut value);
            toml::to_string(&value).unwrap()
        }

        /// Sets the `[mcp_signer_default]` reference of a profile file.
        fn with_signer(file: &str, service: &str, account: &str) -> String {
            edit_file(file, |value| {
                value["mcp_signer_default"] =
                    toml::Value::try_from(entry(service, account)).unwrap();
            })
        }

        fn load_named(name: &str, file: &str) -> Result<Profile, ProfileLoadError> {
            let dir = tempfile::tempdir().unwrap();
            std::fs::write(dir.path().join(format!("{name}.toml")), file).unwrap();
            load_from_dir(name, dir.path(), None)
        }

        fn refusal(
            result: Result<Profile, ProfileLoadError>,
        ) -> (&'static str, ProviderAttestationRejection) {
            match result {
                Err(ProfileLoadError::InvalidProviderAttestation { source, .. }) => {
                    (source.field, source.reason)
                }
                other => panic!("expected a provider refusal, got {other:?}"),
            }
        }

        #[test]
        fn primary_record_loads_on_both_chains() {
            for chain in CHAINS {
                let file = provider_file(
                    chain,
                    "https://primary.example/rpc",
                    None,
                    None,
                    Some(serde_json::json!({"primary": {
                        "operator": "Primary RPC Ltd",
                        "host": "PRIMARY.example."
                    }})),
                );
                let providers = load_provider_file(&file).unwrap().providers.unwrap();
                assert_eq!(
                    providers.primary,
                    Some(PrimaryProviderRecord::new(
                        "Primary RPC Ltd",
                        "PRIMARY.example."
                    ))
                );
                assert_eq!(providers.secondary, None);
                assert_eq!(providers.oracle, None);

                let record = credential_record(
                    "primary",
                    "primary.example",
                    default_entry("primary"),
                    header("X-API-Key"),
                );
                let file =
                    role_credential_file(chain, "primary", Some("https://primary.example"), record);
                let primary = load_provider_file(&file)
                    .unwrap()
                    .providers
                    .unwrap()
                    .primary
                    .unwrap();
                assert_eq!(
                    primary,
                    PrimaryProviderRecord::new("Independent organization", "primary.example")
                        .with_credential(
                            KeyringEntryRef::new("stellar-agent-rpc-test-profile", "primary"),
                            RpcCredentialPlacement::Header {
                                name: "X-API-Key".to_owned()
                            },
                        )
                );
            }
        }

        #[test]
        fn primary_record_host_must_match_rpc_url() {
            let record =
                serde_json::json!({"operator": "Primary RPC Ltd", "host": "primary.example"});
            for chain in CHAINS {
                for url in ["https://other.example", "https://child.primary.example"] {
                    assert_provider_refusal(
                        &provider_file(
                            chain,
                            url,
                            None,
                            None,
                            Some(serde_json::json!({"primary": record})),
                        ),
                        "providers.primary.host",
                        ProviderAttestationRejection::HostMismatch {
                            url_field: "rpc_url",
                        },
                    );
                }
            }

            // A testnet file without `rpc_url` checks against the default endpoint.
            let mut defaulted: toml::Value = toml::from_str(&endpoint_toml(
                "stellar:testnet",
                Endpoints {
                    rpc_url: None,
                    secondary_rpc_url: None,
                    oracle_provider_url: None,
                },
            ))
            .unwrap();
            defaulted.as_table_mut().unwrap().insert(
                "providers".into(),
                toml::Value::try_from(serde_json::json!({"primary": record})).unwrap(),
            );
            assert_provider_refusal(
                &toml::to_string(&defaulted).unwrap(),
                "providers.primary.host",
                ProviderAttestationRejection::HostMismatch {
                    url_field: "rpc_url",
                },
            );
            let default_host = url::Url::parse(Caip2::Testnet.default_rpc_url().unwrap())
                .unwrap()
                .host_str()
                .unwrap()
                .to_owned();
            defaulted["providers"]["primary"]["host"] = toml::Value::String(default_host);
            assert!(load_provider_file(&toml::to_string(&defaulted).unwrap()).is_ok());

            // A testnet overlay of `rpc_url` is checked against the record.
            let file = provider_file(
                "stellar:testnet",
                "https://primary.example",
                None,
                None,
                Some(serde_json::json!({"primary": record})),
            );
            assert!(
                provider_load(
                    &file,
                    "rpc_url",
                    serde_json::json!("https://primary.example/v2")
                )
                .is_ok()
            );
            assert_eq!(
                refusal(provider_load(
                    &file,
                    "rpc_url",
                    serde_json::json!("https://changed.example")
                )),
                (
                    "providers.primary.host",
                    ProviderAttestationRejection::HostMismatch {
                        url_field: "rpc_url"
                    }
                )
            );
        }

        #[test]
        fn primary_record_requires_an_operator() {
            for chain in CHAINS {
                for operator in [None, Some(""), Some(" \t\n")] {
                    let mut record = serde_json::json!({"host": "primary.example"});
                    if let Some(operator) = operator {
                        record["operator"] = operator.into();
                    }
                    assert_provider_refusal(
                        &provider_file(
                            chain,
                            "https://primary.example",
                            None,
                            None,
                            Some(serde_json::json!({"primary": record})),
                        ),
                        "providers.primary.operator",
                        ProviderAttestationRejection::EmptyOperator,
                    );
                }
            }
        }

        #[test]
        fn primary_record_refuses_independent_of_primary() {
            for chain in CHAINS {
                for value in [
                    serde_json::json!(true),
                    serde_json::json!(false),
                    serde_json::json!("SECRET_SENTINEL"),
                ] {
                    let record = serde_json::json!({
                        "operator": "Primary RPC Ltd",
                        "host": "primary.example",
                        "independent_of_primary": value
                    });
                    assert_provider_refusal(
                        &provider_file(
                            chain,
                            "https://primary.example",
                            None,
                            None,
                            Some(serde_json::json!({"primary": record})),
                        ),
                        "providers.primary.independent_of_primary",
                        ProviderAttestationRejection::PrimaryIndependence,
                    );
                }
            }
        }

        #[test]
        fn primary_record_is_required_on_mainnet() {
            let secondary = provider_record("secondary.example", true);
            let oracle = provider_record("oracle.example", true);
            for (secondary_url, oracle_url, providers) in [
                (
                    Some("https://secondary.example"),
                    None,
                    serde_json::json!({"secondary": secondary}),
                ),
                (
                    None,
                    Some("https://oracle.example"),
                    serde_json::json!({"oracle": oracle}),
                ),
                (
                    Some("https://secondary.example"),
                    Some("https://oracle.example"),
                    serde_json::json!({"secondary": secondary, "oracle": oracle}),
                ),
            ] {
                for chain in CHAINS {
                    let file = provider_file(
                        chain,
                        "https://primary.example",
                        secondary_url,
                        oracle_url,
                        Some(providers.clone()),
                    );
                    if chain == "stellar:mainnet" {
                        assert_provider_refusal(
                            &file,
                            "providers.primary",
                            ProviderAttestationRejection::PrimaryRecordRequired,
                        );
                    } else {
                        assert!(load_provider_file(&file).is_ok());
                    }
                    assert!(
                        load_provider_file(&with_primary_record(&file, "primary.example")).is_ok()
                    );
                }
            }
        }

        #[test]
        fn provider_credential_and_placement_come_together() {
            for chain in CHAINS {
                for role in ROLES {
                    let url = format!("https://{}", role_host(role));
                    let mut record = credential_record(
                        role,
                        role_host(role),
                        default_entry(role),
                        header("X-API-Key"),
                    );
                    record.as_object_mut().unwrap().remove("placement");
                    assert_provider_refusal(
                        &role_credential_file(chain, role, Some(&url), record),
                        &field(role, "credential"),
                        ProviderAttestationRejection::IncompleteCredential {
                            missing_field: "placement",
                        },
                    );
                    let mut record = credential_record(
                        role,
                        role_host(role),
                        default_entry(role),
                        header("X-API-Key"),
                    );
                    record.as_object_mut().unwrap().remove("credential");
                    assert_provider_refusal(
                        &role_credential_file(chain, role, Some(&url), record),
                        &field(role, "placement"),
                        ProviderAttestationRejection::IncompleteCredential {
                            missing_field: "credential",
                        },
                    );
                }
            }
        }

        #[test]
        fn provider_credential_reference_shape_is_exact() {
            for chain in CHAINS {
                for role in ROLES {
                    let url = format!("https://{}", role_host(role));
                    for credential in [
                        serde_json::json!("stellar-agent-rpc-test-profile"),
                        serde_json::json!({"service": "stellar-agent-rpc-test-profile"}),
                        serde_json::json!({"account": "primary"}),
                        serde_json::json!({"service": 1, "account": "primary"}),
                        serde_json::json!({"service": "stellar-agent-rpc-p", "account": true}),
                        serde_json::json!({
                            "service": "stellar-agent-rpc-p",
                            "account": "primary",
                            "extra": "x"
                        }),
                        serde_json::json!({"service": "stellar-agent-rpc-p", "extra": "x"}),
                        entry("", "primary"),
                        entry("stellar-agent-rpc-p", ""),
                    ] {
                        assert_provider_refusal(
                            &role_credential_file(
                                chain,
                                role,
                                Some(&url),
                                credential_record(
                                    role,
                                    role_host(role),
                                    credential,
                                    header("X-API-Key"),
                                ),
                            ),
                            &field(role, "credential"),
                            ProviderAttestationRejection::InvalidCredential,
                        );
                    }
                }
            }
        }

        /// The reference bytes are printable ASCII without a leading or
        /// trailing space; a space inside is allowed.
        #[test]
        fn provider_credential_reference_is_printable_ascii() {
            for role in ROLES {
                let url = format!("https://{}", role_host(role));
                for credential in [
                    entry("\u{17f}tellar-agent-signer-p", "default"),
                    entry("stellar-agent-rpc-p", "prim\u{131}ry"),
                    entry("stellar-agent-rpc-p", "prim\u{7}ary"),
                    entry("stellar-agent-rpc-p", "primary\u{7f}"),
                    entry("stellar-agent-rpc-p\n", "primary"),
                    entry(" stellar-agent-rpc-p", "primary"),
                    entry("stellar-agent-rpc-p ", "primary"),
                    entry("stellar-agent-rpc-p", " primary"),
                    entry("stellar-agent-rpc-p", "primary "),
                    entry(" ", "primary"),
                ] {
                    assert_provider_refusal(
                        &role_credential_file(
                            "stellar:testnet",
                            role,
                            Some(&url),
                            credential_record(role, role_host(role), credential, header("X-Key")),
                        ),
                        &field(role, "credential"),
                        ProviderAttestationRejection::InvalidCredential,
                    );
                }
                let file = role_credential_file(
                    "stellar:testnet",
                    role,
                    Some(&url),
                    credential_record(
                        role,
                        role_host(role),
                        entry("stellar-agent-rpc-my prod", role),
                        header("X-Key"),
                    ),
                );
                assert!(load_provider_file(&file).is_ok());
            }
        }

        #[test]
        fn provider_placement_shapes_are_exact() {
            for chain in CHAINS {
                for role in ROLES {
                    let url = format!("https://{}", role_host(role));
                    for placement in [
                        serde_json::json!("header"),
                        serde_json::json!({"name": "X-API-Key"}),
                        serde_json::json!({"kind": 1, "name": "X-API-Key"}),
                        serde_json::json!({"kind": "cookie", "name": "X-API-Key"}),
                        serde_json::json!({"kind": "header"}),
                        serde_json::json!({"kind": "query"}),
                        serde_json::json!({"kind": "header", "name": 1}),
                        serde_json::json!({"kind": "path", "name": "key"}),
                        serde_json::json!({"kind": "path", "extra": true}),
                        serde_json::json!({"kind": "query", "name": "apikey", "extra": 1}),
                        serde_json::json!({"kind": "header", "value": "X-API-Key"}),
                    ] {
                        assert_provider_refusal(
                            &role_credential_file(
                                chain,
                                role,
                                Some(&url),
                                credential_record(
                                    role,
                                    role_host(role),
                                    default_entry(role),
                                    placement,
                                ),
                            ),
                            &field(role, "placement"),
                            ProviderAttestationRejection::InvalidPlacement,
                        );
                    }
                    for placement in [
                        header("X-API-Key"),
                        query("apikey"),
                        serde_json::json!({"kind": "path"}),
                    ] {
                        let file = role_credential_file(
                            chain,
                            role,
                            Some(&url),
                            credential_record(
                                role,
                                role_host(role),
                                default_entry(role),
                                placement,
                            ),
                        );
                        assert!(load_provider_file(&file).is_ok(), "{file}");
                    }
                }
            }
        }

        fn assert_placement_name(placement: &serde_json::Value, refused: bool) {
            for role in ROLES {
                let url = format!("https://{}", role_host(role));
                let file = role_credential_file(
                    "stellar:mainnet",
                    role,
                    Some(&url),
                    credential_record(
                        role,
                        role_host(role),
                        default_entry(role),
                        placement.clone(),
                    ),
                );
                if !refused {
                    assert!(load_provider_file(&file).is_ok(), "{placement}");
                    continue;
                }
                let reason = if placement["kind"] == "header" {
                    ProviderAttestationRejection::InvalidHeaderName
                } else {
                    ProviderAttestationRejection::InvalidQueryParameterName
                };
                assert_provider_refusal(&file, &field(role, "placement.name"), reason);
            }
        }

        #[test]
        fn provider_header_names_follow_the_token_rule() {
            for name in [
                "",
                "X API",
                "X:Key",
                "X-K\u{e9}y",
                "X(Key)",
                "X/Key",
                "X\"Key",
            ] {
                assert_placement_name(&header(name), true);
            }
            for name in [
                "X-API-Key",
                "Authorization",
                "x-token",
                "Drpc-Key",
                "a!#$%&'*+.^_`|~9",
            ] {
                assert_placement_name(&header(name), false);
            }
        }

        #[test]
        fn provider_header_names_refuse_transport_headers() {
            for name in [
                "HOST",
                "Content-Type",
                "content-LENGTH",
                "Accept",
                "Connection",
                "Transfer-Encoding",
                "TE",
                "Trailer",
                "Upgrade",
                "Keep-Alive",
            ] {
                assert_placement_name(&header(name), true);
            }
        }

        #[test]
        fn provider_query_names_are_unreserved_characters() {
            for name in ["a b", "a&b", "=", "", "\u{e4}", "a+b", "a%20b", "a#b"] {
                assert_placement_name(&query(name), true);
            }
            for name in ["apikey", "x_Api-key.1~"] {
                assert_placement_name(&query(name), false);
            }
        }

        /// A query placement repeats no parameter of the endpoint URL,
        /// compared byte for byte after decoding.
        #[test]
        fn query_placement_must_not_repeat_a_url_parameter() {
            for chain in CHAINS {
                for role in ROLES {
                    let host = role_host(role);
                    for url in [
                        format!("https://{host}/?apikey=old"),
                        format!("https://{host}/v1?x=1&apikey"),
                        format!("https://{host}/?api%6Bey=1"),
                    ] {
                        assert_provider_refusal(
                            &role_credential_file(
                                chain,
                                role,
                                Some(&url),
                                credential_record(role, host, default_entry(role), query("apikey")),
                            ),
                            &field(role, "placement.name"),
                            ProviderAttestationRejection::InvalidQueryParameterName,
                        );
                    }
                    for (url, placement) in [
                        (format!("https://{host}/?APIKEY=1"), query("apikey")),
                        (format!("https://{host}/?x=apikey"), query("apikey")),
                        (format!("https://{host}/?apikey=1"), header("apikey")),
                        (
                            format!("https://{host}/?apikey=1"),
                            serde_json::json!({"kind": "path"}),
                        ),
                    ] {
                        let file = role_credential_file(
                            chain,
                            role,
                            Some(&url),
                            credential_record(role, host, default_entry(role), placement),
                        );
                        assert!(load_provider_file(&file).is_ok(), "{file}");
                    }
                }
            }
        }

        /// A record that names a credential needs an https endpoint unless
        /// the host is a loopback address, from the file and from a testnet
        /// overlay alike.
        #[test]
        fn credential_endpoint_must_use_https() {
            for role in ROLES {
                let role_url = format!("http://{}:8000/rpc", role_host(role));
                for (url, host) in [
                    (role_url.as_str(), role_host(role)),
                    ("http://localhost.example", "localhost.example"),
                    ("http://127.example", "127.example"),
                    ("http://[::2]:8000", "[::2]"),
                ] {
                    assert_provider_refusal(
                        &role_credential_file(
                            "stellar:testnet",
                            role,
                            Some(url),
                            credential_record(role, host, default_entry(role), header("X-Key")),
                        ),
                        url_field(role),
                        ProviderAttestationRejection::InsecureCredentialEndpoint,
                    );
                    let mut plain = credential_record(role, host, default_entry(role), header("X"));
                    plain.as_object_mut().unwrap().remove("credential");
                    plain.as_object_mut().unwrap().remove("placement");
                    assert!(
                        load_provider_file(&role_credential_file(
                            "stellar:testnet",
                            role,
                            Some(url),
                            plain
                        ))
                        .is_ok()
                    );
                }
                for (url, host) in [
                    ("http://localhost:8000", "localhost"),
                    ("http://127.0.0.2:8000/rpc", "127.0.0.2"),
                    ("http://[::1]:8000", "[::1]"),
                ] {
                    let file = role_credential_file(
                        "stellar:testnet",
                        role,
                        Some(url),
                        credential_record(role, host, default_entry(role), header("X-Key")),
                    );
                    assert!(load_provider_file(&file).is_ok(), "{file}");
                }
                let host = role_host(role);
                let file = role_credential_file(
                    "stellar:testnet",
                    role,
                    Some(&format!("https://{host}")),
                    credential_record(role, host, default_entry(role), header("X-Key")),
                );
                assert!(load_provider_file(&file).is_ok());
                assert!(
                    provider_load(
                        &file,
                        url_field(role),
                        serde_json::json!(format!("https://{host}:8443/v2"))
                    )
                    .is_ok()
                );
                assert_eq!(
                    refusal(provider_load(
                        &file,
                        url_field(role),
                        serde_json::json!(format!("http://{host}:8080"))
                    )),
                    (
                        url_field(role),
                        ProviderAttestationRejection::InsecureCredentialEndpoint
                    )
                );
            }
        }

        /// A record that names a credential refuses an endpoint URL with a
        /// username or password: on testnet through this rule, on mainnet
        /// through the endpoint rule, which runs first.
        #[test]
        fn credential_endpoint_refuses_userinfo() {
            for role in ROLES {
                let host = role_host(role);
                for url in [
                    format!("https://user:SECRET_SENTINEL@{host}"),
                    format!("https://SECRET_SENTINEL@{host}/rpc"),
                    format!("https://:SECRET_SENTINEL@{host}"),
                ] {
                    let record =
                        credential_record(role, host, default_entry(role), header("X-Key"));
                    assert_provider_refusal(
                        &role_credential_file("stellar:testnet", role, Some(&url), record.clone()),
                        url_field(role),
                        ProviderAttestationRejection::UserinfoWithCredential,
                    );
                    let error = load_provider_file(&role_credential_file(
                        "stellar:mainnet",
                        role,
                        Some(&url),
                        record,
                    ))
                    .unwrap_err();
                    let ProfileLoadError::InvalidEndpointUrl { source, .. } = error else {
                        panic!("expected the endpoint rule, got {error:?}");
                    };
                    assert_eq!(source.field, url_field(role));
                    assert_eq!(source.reason, EndpointUrlRejection::MainnetCredentialInUrl);
                    let mut plain = provider_record(host, true);
                    if role == "primary" {
                        plain
                            .as_object_mut()
                            .unwrap()
                            .remove("independent_of_primary");
                    }
                    assert!(
                        load_provider_file(&role_credential_file(
                            "stellar:testnet",
                            role,
                            Some(&url),
                            plain
                        ))
                        .is_ok()
                    );
                }
            }
        }

        /// The service namespace of the wallet's own keys is reserved, in any
        /// ASCII case and in any `.`-separated part; the RPC namespace is not.
        #[test]
        fn provider_credentials_refuse_the_wallet_key_namespace() {
            for chain in CHAINS {
                for role in ROLES {
                    let url = format!("https://{}", role_host(role));
                    for credential in [
                        entry("stellar-agent-signer-p", "default"),
                        entry("Stellar-Agent-Signer-p", "default"),
                        entry("STELLAR-AGENT-OWNER-p", "x"),
                        entry("stellar-agent-", "x"),
                        entry("main", "GABC.stellar-agent-signer-alice"),
                        entry("x.stellar-agent-audit-q", "y"),
                        entry("x. stellar-agent-audit-q", "y"),
                    ] {
                        assert_provider_refusal(
                            &role_credential_file(
                                chain,
                                role,
                                Some(&url),
                                credential_record(
                                    role,
                                    role_host(role),
                                    credential,
                                    header("X-Key"),
                                ),
                            ),
                            &field(role, "credential"),
                            ProviderAttestationRejection::ReservedCredentialEntry,
                        );
                    }
                    for credential in [
                        entry("stellar-agent-rpc-p", "primary"),
                        entry("Stellar-Agent-RPC-p", "oracle"),
                        entry("acme-keys", "x"),
                        entry("stellar-agentx", "y"),
                    ] {
                        let file = role_credential_file(
                            chain,
                            role,
                            Some(&url),
                            credential_record(role, role_host(role), credential, header("X-Key")),
                        );
                        assert!(load_provider_file(&file).is_ok(), "{file}");
                    }
                }
            }
        }

        /// A credential with the service of a wallet key reference refuses,
        /// outside the wallet key namespace too and in any ASCII case.
        #[test]
        fn provider_credentials_refuse_a_wallet_key_service() {
            for chain in CHAINS {
                for role in ROLES {
                    let url = format!("https://{}", role_host(role));
                    for credential in [
                        entry("acme-wallet-keys", "primary"),
                        entry("ACME-Wallet-Keys", "other"),
                    ] {
                        let file = edit_file(
                            &role_credential_file(
                                chain,
                                role,
                                Some(&url),
                                credential_record(
                                    role,
                                    role_host(role),
                                    credential,
                                    header("X-Key"),
                                ),
                            ),
                            |value| {
                                value["audit_log_hash_chain_key_id"]["service"] =
                                    "acme-wallet-keys".into();
                            },
                        );
                        assert_provider_refusal(
                            &file,
                            &field(role, "credential"),
                            ProviderAttestationRejection::ReservedCredentialEntry,
                        );
                    }
                }
            }
        }

        /// A credential whose `account.service` form equals a wallet key's
        /// refuses, so a store that joins the two with a `.` cannot be
        /// pointed at the wallet key under a dotted profile name.
        #[test]
        fn provider_credentials_refuse_a_dotted_alias_of_a_wallet_key() {
            for (signer_service, alias) in [
                (
                    "stellar-agent-signer-alice.main",
                    entry("main", "GABC.stellar-agent-signer-alice"),
                ),
                ("acme-signer.main", entry("main", "GABC.acme-signer")),
                ("acme-signer.main", entry("MAIN", "gabc.ACME-signer")),
                ("acme.signer.main", entry("signer.main", "GABC.acme")),
            ] {
                for role in ROLES {
                    let url = format!("https://{}", role_host(role));
                    let file = with_signer(
                        &role_credential_file(
                            "stellar:testnet",
                            role,
                            Some(&url),
                            credential_record(
                                role,
                                role_host(role),
                                alias.clone(),
                                header("X-Key"),
                            ),
                        ),
                        signer_service,
                        "GABC",
                    );
                    let (refused, reason) = refusal(load_named("alice.main", &file));
                    assert_eq!(refused, field(role, "credential"));
                    assert_eq!(
                        reason,
                        ProviderAttestationRejection::ReservedCredentialEntry
                    );
                }
            }
        }

        /// The wallet key references are taken from the file as well as from
        /// the merged profile, so a testnet overlay of `mcp_signer_default`
        /// does not free the file's signer entry.
        #[test]
        fn provider_credentials_refuse_the_file_signer_under_an_overlay() {
            for role in ROLES {
                let url = format!("https://{}", role_host(role));
                let file = with_signer(
                    &role_credential_file(
                        "stellar:testnet",
                        role,
                        Some(&url),
                        credential_record(
                            role,
                            role_host(role),
                            entry("acme-signer", "GABC"),
                            header("X-Key"),
                        ),
                    ),
                    "acme-signer",
                    "GABC",
                );
                assert_eq!(
                    refusal(load_provider_file(&file)).1,
                    ProviderAttestationRejection::ReservedCredentialEntry
                );
                assert_eq!(
                    refusal(provider_load(
                        &file,
                        "mcp_signer_default",
                        serde_json::json!({"service": "other-signer", "account": "x"})
                    ))
                    .1,
                    ProviderAttestationRejection::ReservedCredentialEntry
                );
            }
        }

        /// Default references load under dotted profile names and profile
        /// names with a space, and all three roles may name one entry.
        #[test]
        fn provider_credentials_allow_the_default_entries() {
            for name in ["a.b", "alice.main", "my prod", "Alice.Main"] {
                let service = format!("stellar-agent-rpc-{name}");
                for chain in CHAINS {
                    let file = |accounts: [&str; 3]| {
                        let mut primary = credential_record(
                            "primary",
                            "primary.example",
                            entry(&service, accounts[0]),
                            header("X-API-Key"),
                        );
                        primary["operator"] = "Primary operator".into();
                        let secondary = credential_record(
                            "secondary",
                            "secondary.example",
                            entry(&service, accounts[1]),
                            query("apikey"),
                        );
                        let oracle = credential_record(
                            "oracle",
                            "oracle.example",
                            entry(&service, accounts[2]),
                            serde_json::json!({"kind": "path"}),
                        );
                        provider_file(
                            chain,
                            "https://primary.example",
                            Some("https://secondary.example"),
                            Some("https://oracle.example"),
                            Some(serde_json::json!({
                                "primary": primary,
                                "secondary": secondary,
                                "oracle": oracle
                            })),
                        )
                    };
                    let providers = load_named(name, &file(["primary", "secondary", "oracle"]))
                        .unwrap()
                        .providers
                        .unwrap();
                    for role in [
                        ProviderRole::Primary,
                        ProviderRole::Secondary,
                        ProviderRole::Oracle,
                    ] {
                        assert_eq!(
                            providers.credential(role).unwrap().0,
                            &KeyringEntryRef::new(service.clone(), role.as_str())
                        );
                    }
                    assert!(load_named(name, &file(["primary", "primary", "primary"])).is_ok());
                }
            }
        }

        #[test]
        fn mainnet_secondary_and_oracle_operators_differ_from_primary() {
            for role in ["secondary", "oracle"] {
                for operator in ["Primary operator", "  primary OPERATOR\t"] {
                    let mut record = provider_record("other.example", true);
                    record["operator"] = operator.into();
                    assert_provider_refusal(
                        &role_credential_file(
                            "stellar:mainnet",
                            role,
                            Some("https://other.example"),
                            record,
                        ),
                        &field(role, "operator"),
                        ProviderAttestationRejection::SharedOperator,
                    );
                }
            }
            let shared = provider_record("shared.example", true);
            let file = provider_file(
                "stellar:mainnet",
                "https://primary.example",
                Some("https://shared.example/a"),
                Some("https://shared.example/b"),
                Some(serde_json::json!({"secondary": shared, "oracle": shared})),
            );
            assert_provider_refusal(
                &file,
                "providers.primary",
                ProviderAttestationRejection::PrimaryRecordRequired,
            );
            assert!(load_provider_file(&with_primary_record(&file, "primary.example")).is_ok());
        }

        #[test]
        fn provider_operator_comparison_trims_and_folds_case() {
            for (primary, other, shared) in [
                ("  Example RPC ", "EXAMPLE rpc", true),
                ("Stra\u{df}e", "STRASSE", true),
                ("\u{fb01}ne RPC", "FINE rpc", true),
                ("Example Inc.", "Example", false),
                ("Example  RPC", "Example RPC", false),
            ] {
                let mut record = provider_record("other.example", true);
                record["operator"] = other.into();
                let file = edit_file(
                    &role_credential_file(
                        "stellar:mainnet",
                        "secondary",
                        Some("https://other.example"),
                        record,
                    ),
                    |value| value["providers"]["primary"]["operator"] = primary.into(),
                );
                if shared {
                    assert_provider_refusal(
                        &file,
                        "providers.secondary.operator",
                        ProviderAttestationRejection::SharedOperator,
                    );
                } else {
                    assert!(load_provider_file(&file).is_ok(), "{file}");
                }
            }
        }

        #[test]
        fn testnet_shared_operator_loads() {
            for role in ["secondary", "oracle"] {
                let mut record = provider_record("other.example", true);
                record["operator"] = "Primary operator".into();
                let file = role_credential_file(
                    "stellar:testnet",
                    role,
                    Some("https://other.example"),
                    record,
                );
                let providers = load_provider_file(&file).unwrap().providers.unwrap();
                assert_eq!(providers.primary.unwrap().operator, "Primary operator");
            }
        }

        /// A file with several defects reports them in the loader's order:
        /// decode, pairing, reserved entry, endpoint presence, operator, host,
        /// userinfo, insecure endpoint, repeated query name, then the mainnet
        /// rules.
        #[test]
        fn provider_credential_checks_follow_record_checks() {
            use ProviderAttestationRejection as R;
            let reserved = entry("stellar-agent-signer-p", "default");
            for chain in CHAINS {
                let mainnet = chain == "stellar:mainnet";
                for role in ROLES {
                    let host = role_host(role);
                    let mut record = credential_record(
                        role,
                        "wrong.example",
                        serde_json::json!("bad"),
                        serde_json::json!("bad"),
                    );
                    record["operator"] = "".into();
                    record["SECRET_SENTINEL"] = 1.into();
                    let bad_url = if mainnet {
                        format!("https://{host}/?apikey=1")
                    } else {
                        format!("http://user@{host}/?apikey=1")
                    };
                    let mut steps: Vec<(serde_json::Value, String, R)> = Vec::new();
                    let mut step = |record: &serde_json::Value, suffix: &str, reason: R| {
                        steps.push((record.clone(), field(role, suffix), reason));
                    };
                    step(&record, "", R::InvalidShape);
                    record.as_object_mut().unwrap().remove("SECRET_SENTINEL");
                    if role == "primary" {
                        record["independent_of_primary"] = true.into();
                        step(&record, "independent_of_primary", R::PrimaryIndependence);
                        record
                            .as_object_mut()
                            .unwrap()
                            .remove("independent_of_primary");
                    }
                    step(&record, "credential", R::InvalidCredential);
                    record.as_object_mut().unwrap().remove("placement");
                    step(&record, "credential", R::InvalidCredential);
                    record["credential"] = reserved.clone();
                    step(
                        &record,
                        "credential",
                        R::IncompleteCredential {
                            missing_field: "placement",
                        },
                    );
                    record["placement"] = serde_json::json!("bad");
                    step(&record, "placement", R::InvalidPlacement);
                    record["placement"] = header("Host");
                    step(&record, "placement.name", R::InvalidHeaderName);
                    record["placement"] = query("apikey");
                    step(&record, "credential", R::ReservedCredentialEntry);
                    record["credential"] = default_entry(role);
                    if role != "primary" {
                        let file = role_credential_file(chain, role, None, record.clone());
                        assert_provider_refusal(
                            &file,
                            &field(role, ""),
                            R::UrlRequired {
                                url_field: url_field(role),
                            },
                        );
                    }
                    step(&record, "operator", R::EmptyOperator);
                    record["operator"] = "Independent organization".into();
                    step(
                        &record,
                        "host",
                        R::HostMismatch {
                            url_field: url_field(role),
                        },
                    );
                    record["host"] = host.into();
                    for (record, field, reason) in steps {
                        assert_provider_refusal(
                            &role_credential_file(chain, role, Some(&bad_url), record),
                            &field,
                            reason,
                        );
                    }
                    let file = |url: &str, record: &serde_json::Value| {
                        role_credential_file(chain, role, Some(url), record.clone())
                    };
                    if !mainnet {
                        assert_provider_refusal(
                            &file(&format!("http://user@{host}/?apikey=1"), &record),
                            url_field(role),
                            R::UserinfoWithCredential,
                        );
                        assert_provider_refusal(
                            &file(&format!("http://{host}/?apikey=1"), &record),
                            url_field(role),
                            R::InsecureCredentialEndpoint,
                        );
                    }
                    assert_provider_refusal(
                        &file(&format!("https://{host}/?apikey=1"), &record),
                        &field(role, "placement.name"),
                        R::InvalidQueryParameterName,
                    );
                    let good_url = format!("https://{host}/?x=1");
                    if mainnet && role != "primary" {
                        record["independent_of_primary"] = false.into();
                        record["operator"] = "Primary operator".into();
                        assert_provider_refusal(
                            &file(&good_url, &record),
                            &field(role, "independent_of_primary"),
                            R::IndependenceRequired,
                        );
                        record["independent_of_primary"] = true.into();
                        assert_provider_refusal(
                            &file(&good_url, &record),
                            &field(role, "operator"),
                            R::SharedOperator,
                        );
                        record["operator"] = "Independent organization".into();
                    }
                    assert!(load_provider_file(&file(&good_url, &record)).is_ok());
                }
            }
        }

        /// No refusal echoes a value of the file: header and query names,
        /// service, account, operator, and URL parts stay out of every
        /// rendering, and the code stays the provider attestation code.
        #[test]
        fn provider_credential_errors_echo_no_file_value() {
            use ProviderAttestationRejection as R;
            for chain in CHAINS {
                for role in ROLES {
                    let host = role_host(role);
                    let url = format!("https://{host}/?SECRET_SENTINEL=1");
                    let cases = [
                        (
                            credential_record(
                                role,
                                host,
                                default_entry(role),
                                header("SECRET_SENTINEL:"),
                            ),
                            "placement.name",
                            R::InvalidHeaderName,
                        ),
                        (
                            credential_record(
                                role,
                                host,
                                default_entry(role),
                                query("SECRET_SENTINEL&"),
                            ),
                            "placement.name",
                            R::InvalidQueryParameterName,
                        ),
                        (
                            credential_record(
                                role,
                                host,
                                default_entry(role),
                                query("SECRET_SENTINEL"),
                            ),
                            "placement.name",
                            R::InvalidQueryParameterName,
                        ),
                        (
                            credential_record(
                                role,
                                host,
                                entry("\u{17f}SECRET_SENTINEL", "a"),
                                header("X-Key"),
                            ),
                            "credential",
                            R::InvalidCredential,
                        ),
                        (
                            credential_record(
                                role,
                                host,
                                entry("svc", "SECRET_SENTINEL\u{1}"),
                                header("X-Key"),
                            ),
                            "credential",
                            R::InvalidCredential,
                        ),
                        (
                            credential_record(
                                role,
                                host,
                                entry("stellar-agent-signer-SECRET_SENTINEL", "a"),
                                header("X-Key"),
                            ),
                            "credential",
                            R::ReservedCredentialEntry,
                        ),
                        (
                            credential_record(
                                role,
                                host,
                                default_entry(role),
                                serde_json::json!({"kind": "SECRET_SENTINEL"}),
                            ),
                            "placement",
                            R::InvalidPlacement,
                        ),
                    ];
                    for (record, suffix, reason) in cases {
                        assert_provider_refusal(
                            &role_credential_file(chain, role, Some(&url), record),
                            &field(role, suffix),
                            reason,
                        );
                    }
                }
                if chain == "stellar:mainnet" {
                    let mut record = provider_record("other.example", true);
                    record["operator"] = "SECRET_SENTINEL Ops".into();
                    let file = edit_file(
                        &role_credential_file(
                            chain,
                            "oracle",
                            Some("https://other.example"),
                            record,
                        ),
                        |value| {
                            value["providers"]["primary"]["operator"] =
                                " SECRET_SENTINEL OPS ".into();
                        },
                    );
                    assert_provider_refusal(&file, "providers.oracle.operator", R::SharedOperator);
                } else {
                    let record = credential_record(
                        "primary",
                        "primary.example",
                        default_entry("primary"),
                        header("X-Key"),
                    );
                    assert_provider_refusal(
                        &role_credential_file(
                            chain,
                            "primary",
                            Some(concat!(
                                "http://SECRET_SENTINEL:SECRET_SENTINEL@",
                                "primary.example/SECRET_SENTINEL"
                            )),
                            record,
                        ),
                        "rpc_url",
                        R::UserinfoWithCredential,
                    );
                }
            }
        }

        /// A testnet profile file whose oracle record has comments before
        /// and inside it, a trailing comment, uneven spacing, and tables
        /// after it. It is split into the text before the record, the
        /// record, and the text after it.
        fn oracle_record_fixture() -> (String, &'static str, String) {
            let base = endpoint_toml(
                "stellar:testnet",
                Endpoints {
                    rpc_url: Some("https://primary.example"),
                    secondary_rpc_url: None,
                    oracle_provider_url: Some("https://other.example"),
                },
            );
            let (head, tail) = base.split_at(base.find("[mcp_signer_default]").unwrap());
            let record = "# The oracle provider, attested by the operator.\n\
                          [providers.oracle]\n\
                          operator = \"Oracle operator\"\n\
                          # Reviewed with the provider's operations team.\n\
                          host   =   \"other.example\"  # the host of oracle_provider_url\n\
                          independent_of_primary = false\n";
            (head.to_owned(), record, tail.to_owned())
        }

        /// The two lines the patch adds for the default oracle reference of
        /// the profile `p` with a path placement.
        const ORACLE_PATH_RECORD_LINES: &str = concat!(
            "credential = { service = \"stellar-agent-rpc-p\", account = \"oracle\" }\n",
            "placement = { kind = \"path\" }\n",
        );

        /// The on-disk patch adds the reference and the placement after the
        /// record's last key and keeps every other byte of the file. It
        /// refuses a missing record, or one that already names either key,
        /// without touching the file.
        #[test]
        fn set_provider_credential_patches_only_the_record() {
            let (head, record, tail) = oracle_record_fixture();
            let file = format!("{head}{record}\n{tail}");
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("p.toml");
            std::fs::write(&path, &file).unwrap();
            let credential = KeyringEntryRef::default_rpc_credential("p", ProviderRole::Oracle);
            let placement = RpcCredentialPlacement::Path {};

            let missing = set_provider_credential_on_disk(
                "p",
                dir.path(),
                ProviderRole::Primary,
                &credential,
                &placement,
            )
            .unwrap_err();
            assert!(matches!(missing, ProfileSaveError::Io(_)), "{missing}");
            assert_eq!(std::fs::read_to_string(&path).unwrap(), file);

            set_provider_credential_on_disk(
                "p",
                dir.path(),
                ProviderRole::Oracle,
                &credential,
                &placement,
            )
            .unwrap();
            let written = std::fs::read_to_string(&path).unwrap();
            let expected_text = format!("{head}{record}{ORACLE_PATH_RECORD_LINES}\n{tail}");
            assert_eq!(written, expected_text);

            let patched: toml::Value = toml::from_str(&written).unwrap();
            let mut expected: toml::Value = toml::from_str(&file).unwrap();
            let oracle = expected["providers"]["oracle"].as_table_mut().unwrap();
            oracle.insert(
                "credential".into(),
                toml::Value::try_from(&credential).unwrap(),
            );
            oracle.insert(
                "placement".into(),
                toml::Value::try_from(&placement).unwrap(),
            );
            assert_eq!(patched, expected);
            let loaded = load_from_dir("p", dir.path(), None).unwrap();
            assert_eq!(
                loaded.providers.unwrap().credential(ProviderRole::Oracle),
                Some((&credential, &placement))
            );

            let before = std::fs::read_to_string(&path).unwrap();
            let again = set_provider_credential_on_disk(
                "p",
                dir.path(),
                ProviderRole::Oracle,
                &credential,
                &placement,
            )
            .unwrap_err();
            assert!(matches!(again, ProfileSaveError::Io(_)), "{again}");
            assert_eq!(std::fs::read_to_string(&path).unwrap(), before);
            assert!(matches!(
                set_provider_credential_on_disk(
                    "../p",
                    dir.path(),
                    ProviderRole::Oracle,
                    &credential,
                    &placement
                ),
                Err(ProfileSaveError::InvalidName { .. })
            ));
        }

        /// A file whose lines all end in CRLF keeps CRLF on every line: the
        /// patch yields the original text with the two record lines
        /// inserted, each ending in CRLF, and the result loads.
        #[test]
        fn set_provider_credential_keeps_crlf_line_endings() {
            let (head, record, tail) = oracle_record_fixture();
            let crlf = |text: &str| text.replace('\n', "\r\n");
            let file = crlf(&format!("{head}{record}\n{tail}"));
            assert!(!file.replace("\r\n", "").contains('\n'));
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("p.toml");
            std::fs::write(&path, &file).unwrap();
            let credential = KeyringEntryRef::default_rpc_credential("p", ProviderRole::Oracle);
            let placement = RpcCredentialPlacement::Path {};

            set_provider_credential_on_disk(
                "p",
                dir.path(),
                ProviderRole::Oracle,
                &credential,
                &placement,
            )
            .unwrap();
            let written = std::fs::read_to_string(&path).unwrap();
            let expected_text = crlf(&format!("{head}{record}{ORACLE_PATH_RECORD_LINES}\n{tail}"));
            assert_eq!(written, expected_text);
            let loaded = load_from_dir("p", dir.path(), None).unwrap();
            assert_eq!(
                loaded.providers.unwrap().credential(ProviderRole::Oracle),
                Some((&credential, &placement))
            );
        }

        /// A text uses CRLF throughout only when it holds a CRLF and every
        /// LF in it follows a CR.
        #[test]
        fn uses_crlf_throughout_requires_crlf_on_every_line() {
            assert!(uses_crlf_throughout("a\r\nb\r\n"));
            assert!(!uses_crlf_throughout("a\r\nb\n"));
            assert!(!uses_crlf_throughout("\na\r\n"));
            assert!(!uses_crlf_throughout("a\nb\n"));
            assert!(!uses_crlf_throughout(""));
        }

        /// A record written as an inline table gains the two keys inside
        /// that inline table, in the form the loader reads, and each
        /// placement kind is written in its serde form.
        #[test]
        fn set_provider_credential_patches_an_inline_record() {
            let base = endpoint_toml(
                "stellar:testnet",
                Endpoints {
                    rpc_url: Some("https://primary.example"),
                    secondary_rpc_url: None,
                    oracle_provider_url: None,
                },
            );
            let (head, tail) = base.split_at(base.find("[mcp_signer_default]").unwrap());
            let file = format!(
                "{head}[providers]\n\
                 primary = {{ operator = \"Primary operator\", host = \"primary.example\" }}\n\n\
                 {tail}"
            );
            for (placement, rendered) in [
                (
                    RpcCredentialPlacement::Header {
                        name: "X-API-Key".to_owned(),
                    },
                    "{ kind = \"header\", name = \"X-API-Key\" }",
                ),
                (
                    RpcCredentialPlacement::Query {
                        name: "apikey".to_owned(),
                    },
                    "{ kind = \"query\", name = \"apikey\" }",
                ),
                (RpcCredentialPlacement::Path {}, "{ kind = \"path\" }"),
            ] {
                let dir = tempfile::tempdir().unwrap();
                let path = dir.path().join("p.toml");
                std::fs::write(&path, &file).unwrap();
                let credential =
                    KeyringEntryRef::default_rpc_credential("p", ProviderRole::Primary);
                set_provider_credential_on_disk(
                    "p",
                    dir.path(),
                    ProviderRole::Primary,
                    &credential,
                    &placement,
                )
                .unwrap();
                let written = std::fs::read_to_string(&path).unwrap();
                let expected_text = format!(
                    "{head}[providers]\n\
                     primary = {{ operator = \"Primary operator\", host = \"primary.example\", \
                     credential = {{ service = \"stellar-agent-rpc-p\", account = \"primary\" }}, \
                     placement = {rendered} }}\n\n\
                     {tail}"
                );
                assert_eq!(written, expected_text, "{placement:?}");
                let loaded = load_from_dir("p", dir.path(), None).unwrap();
                assert_eq!(
                    loaded.providers.unwrap().credential(ProviderRole::Primary),
                    Some((&credential, &placement))
                );
            }
        }

        /// The write-side check runs the loader's credential rules against
        /// the loaded profile and the file's own wallet key references.
        #[test]
        fn write_check_applies_the_loader_rules() {
            let file = with_signer(
                &provider_file(
                    "stellar:testnet",
                    "http://primary.example/?apikey=1",
                    None,
                    None,
                    Some(serde_json::json!({"primary": {
                        "operator": "Primary operator",
                        "host": "primary.example"
                    }})),
                ),
                "acme-signer",
                "GABC",
            );
            let dir = tempfile::tempdir().unwrap();
            std::fs::write(dir.path().join("p.toml"), &file).unwrap();
            let profile = provider_load(
                &file,
                "mcp_signer_default",
                serde_json::json!({"service": "other-signer", "account": "x"}),
            )
            .unwrap();
            let check = |credential: &KeyringEntryRef, placement: &RpcCredentialPlacement| {
                match check_provider_credential_for_write_in_dir(
                    "p",
                    dir.path(),
                    &profile,
                    ProviderRole::Primary,
                    credential,
                    placement,
                ) {
                    Ok(()) => None,
                    Err(ProfileLoadError::InvalidProviderAttestation { source, .. }) => {
                        Some((source.field, source.reason))
                    }
                    Err(other) => panic!("{other:?}"),
                }
            };
            let header = RpcCredentialPlacement::Header {
                name: "X-Key".to_owned(),
            };
            let default = KeyringEntryRef::default_rpc_credential("p", ProviderRole::Primary);
            assert_eq!(
                check(&default, &header),
                Some((
                    "rpc_url",
                    ProviderAttestationRejection::InsecureCredentialEndpoint
                ))
            );
            assert_eq!(
                check(&KeyringEntryRef::new("acme-signer", "GABC"), &header),
                Some((
                    "providers.primary.credential",
                    ProviderAttestationRejection::ReservedCredentialEntry
                ))
            );
            assert_eq!(
                check(&KeyringEntryRef::new("other-signer", "x"), &header),
                Some((
                    "providers.primary.credential",
                    ProviderAttestationRejection::ReservedCredentialEntry
                ))
            );
            assert_eq!(
                check(&KeyringEntryRef::new(" svc", "a"), &header),
                Some((
                    "providers.primary.credential",
                    ProviderAttestationRejection::InvalidCredential
                ))
            );
            assert_eq!(
                check(
                    &default,
                    &RpcCredentialPlacement::Header {
                        name: "Host".to_owned()
                    }
                ),
                Some((
                    "providers.primary.placement.name",
                    ProviderAttestationRejection::InvalidHeaderName
                ))
            );
            assert_eq!(
                check_provider_credential_for_write_in_dir(
                    "p",
                    dir.path(),
                    &profile,
                    ProviderRole::Secondary,
                    &default,
                    &header,
                )
                .map_err(|error| error.to_string()),
                Err(
                    "profile 'p': profile field `providers.secondary` has no configured \
                     endpoint; set `secondary_rpc_url` or remove this provider table in the \
                     profile file"
                        .to_owned()
                )
            );
        }

        /// All three placements serialize as tables with a `kind` key and
        /// load back equal.
        #[test]
        fn provider_credentials_round_trip_through_toml() {
            let providers = Providers {
                primary: Some(
                    PrimaryProviderRecord::new("Primary RPC Ltd", "primary.example")
                        .with_credential(
                            KeyringEntryRef::new("stellar-agent-rpc-test-profile", "primary"),
                            RpcCredentialPlacement::Header {
                                name: "Authorization".to_owned(),
                            },
                        ),
                ),
                secondary: Some(
                    ProviderRecord::new("Secondary RPC Ltd", "secondary.example", true)
                        .with_credential(
                            KeyringEntryRef::new("stellar-agent-rpc-test-profile", "secondary"),
                            RpcCredentialPlacement::Query {
                                name: "apikey".to_owned(),
                            },
                        ),
                ),
                oracle: Some(
                    ProviderRecord::new("Oracle RPC Ltd", "oracle.example", true).with_credential(
                        KeyringEntryRef::new("acme-keys", "oracle"),
                        RpcCredentialPlacement::Path {},
                    ),
                ),
            };
            let serialized = toml::to_string(&serde_json::json!({"providers": providers})).unwrap();
            for line in ["kind = \"header\"", "kind = \"query\"", "kind = \"path\""] {
                assert!(serialized.contains(line), "{serialized}");
            }
            let file = provider_file(
                "stellar:mainnet",
                "https://primary.example",
                Some("https://secondary.example/v1"),
                Some("https://oracle.example/"),
                Some(serde_json::to_value(&providers).unwrap()),
            );
            assert_eq!(
                load_provider_file(&file).unwrap().providers,
                Some(providers)
            );
        }
    }
}
