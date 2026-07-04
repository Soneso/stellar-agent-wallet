//! figment-backed profile loader.
//!
//! Loads a [`Profile`] from three layered sources in priority order:
//!
//! 1. **CLI overlay** — programmatically-supplied key/value pairs (highest
//!    priority; used by `stellar-agent profile show <name>` to surface the
//!    effective resolved config).
//! 2. **Environment variables** — `STELLAR_AGENT_<FIELD>` prefixed variables.
//! 3. **TOML file** — `<profile_dir>/<name>.toml` (lowest priority).
//!
//! # Path resolution
//!
//! Profile files live at the OS-conventional state directory:
//!
//! | Platform | Path |
//! |----------|------|
//! | Linux    | `~/.local/state/stellar-agent/profiles/<name>.toml` |
//! | macOS    | `~/Library/Application Support/stellar-agent/profiles/<name>.toml` |
//! | Windows  | `%LOCALAPPDATA%\stellar-agent\profiles\<name>.toml` |
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

use super::schema::{Profile, default_audit_log_path};
pub use super::schema::{default_approval_dir, default_policy_dir, default_profile_dir};
use crate::profile::caip2::Caip2;

/// Mirror of `stellar_agent_smart_account::managers::rules::UPPER_BOUND_MAX_SCAN_ID`.
///
/// Hoisted to module level so it is declared once and consumed by both
/// profile-load entry points.  The canonical constant lives in the smart-account
/// crate; this mirror avoids a crate-dependency cycle
/// (`stellar-agent-smart-account` already depends on `stellar-agent-core`).
///
/// **Drift-protection:** an integration test in
/// `crates/stellar-agent-smart-account/tests/upper_bound_max_scan_id_parity_test.rs`
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
/// `crates/stellar-agent-smart-account/tests/horizon_bound_parity_test.rs`
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
/// E.g. `STELLAR_AGENT_RPC_URL=https://...` overrides `rpc_url`.
const ENV_PREFIX: &str = "STELLAR_AGENT_";

// ─────────────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────────────

/// Errors produced when loading a profile.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ProfileLoadError {
    /// The profile file was not found at the expected path.
    #[error("profile '{name}' not found at '{path}'")]
    NotFound {
        /// The profile name as supplied by the caller.
        name: String,
        /// The full path that was checked.
        path: PathBuf,
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

    /// The `rpc_url` field is not a valid URL.
    #[error("profile '{name}': {source}")]
    InvalidRpcUrl {
        /// The profile name as supplied by the caller.
        name: String,
        /// The inner URL-parse error.
        #[source]
        source: super::schema::RpcUrlParseError,
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
/// 3. Merge sources: TOML file → env-var overlay (priority: env wins).
/// 4. Reject `version != 2` with [`ProfileLoadError::VersionUnsupported`].
/// 5. Resolve `rpc_url` default from `chain_id` if the TOML omitted it.
/// 6. Resolve `network_passphrase` from `chain_id` (always derived; not
///    overridable from profile config).
/// 7. Resolve `audit_log_path` default if the TOML omitted it.
/// 8. Validate `rpc_url` is a well-formed URL.
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

    // ── Step 2: full extraction with env-var overlay.
    let partial: PartialProfile = Figment::new()
        .merge(Toml::file(path))
        .merge(Env::prefixed(ENV_PREFIX))
        .extract()
        .map_err(|e| ProfileLoadError::Figment {
            name: name.to_owned(),
            source: Box::new(e),
        })?;
    let policy = require_policy_section(partial.policy, path)?;

    // ── Step 3: resolve derived fields.
    let chain_id = partial.chain_id;
    let rpc_url = partial
        .rpc_url
        .unwrap_or_else(|| chain_id.default_rpc_url().to_owned());
    let network_passphrase = chain_id.network_passphrase().to_owned();
    let audit_log_path = partial
        .audit_log_path
        .unwrap_or_else(|| default_audit_log_path().unwrap_or_else(|_| PathBuf::from("audit.log")));

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

    let profile = Profile {
        version: partial.version,
        chain_id,
        rpc_url,
        network_passphrase,
        mcp_signer_default: partial.mcp_signer_default,
        mcp_nonce_key_alias: partial.mcp_nonce_key_alias,
        usd_threshold: partial.usd_threshold,
        classic_fee_per_op_stroops: partial.classic_fee_per_op_stroops,
        classic_max_fee_per_op_stroops: partial.classic_max_fee_per_op_stroops,
        submit_timeout_seconds: partial.submit_timeout_seconds,
        audit_log_path,
        mcp_disabled: partial.mcp_disabled,
        audit_log_hash_chain_key_id: partial.audit_log_hash_chain_key_id,
        policy_owner_key_id: partial.policy_owner_key_id,
        attestation_key_id: partial.attestation_key_id,
        counterparty_cache_key_id: partial.counterparty_cache_key_id,
        oracle_provider_url: partial.oracle_provider_url,
        policy,
        wallet: partial.wallet,
        smart_account_max_context_rule_scan_id: partial.smart_account_max_context_rule_scan_id,
        session_rule_max_horizon_ledgers: partial.session_rule_max_horizon_ledgers,
        secondary_rpc_url: partial.secondary_rpc_url,
        pool_master_key_id: partial.pool_master_key_id,
        pool_config: partial.pool_config,
        remote_approval: partial.remote_approval,
    };

    // ── Step 5: validate rpc_url.
    profile
        .validate_rpc_url()
        .map_err(|e| ProfileLoadError::InvalidRpcUrl {
            name: name.to_owned(),
            source: e,
        })?;

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
/// Returns [`ProfileSaveError`] on I/O failure.
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
/// Returns [`ProfileSaveError`] on I/O failure.
pub fn save_to_dir(name: &str, profile: &Profile, dir: &Path) -> Result<PathBuf, ProfileSaveError> {
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

/// Errors produced when saving a profile.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ProfileSaveError {
    /// The OS-conventional state directory could not be determined.
    #[error("could not determine profile directory: {0}")]
    NoStateDir(#[from] super::schema::StateDirError),
    /// Serialisation to TOML failed.
    #[error("failed to serialise profile to TOML: {0}")]
    Serialize(#[from] toml::ser::Error),
    /// An I/O error occurred.
    #[error("I/O error writing profile: {0}")]
    Io(std::io::Error),
}

// ─────────────────────────────────────────────────────────────────────────────
// CLI overlay support
// ─────────────────────────────────────────────────────────────────────────────

/// Loads a profile with an additional CLI-supplied overlay map (highest
/// priority source).
///
/// Useful for `stellar-agent profile show <name>` where the caller wants to
/// display the effective resolved config with any ad-hoc overrides applied.
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
    let path = profile_dir.join(format!("{name}.toml"));

    if !path.exists() {
        return Err(ProfileLoadError::NotFound {
            name: name.to_owned(),
            path,
        });
    }

    let raw: RawVersion = Figment::new()
        .merge(Toml::file(&path))
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

    let partial: PartialProfile = Figment::new()
        .merge(Toml::file(&path))
        .merge(Env::prefixed(ENV_PREFIX))
        .merge(Serialized::defaults(overlay))
        .extract()
        .map_err(|e| ProfileLoadError::Figment {
            name: name.to_owned(),
            source: Box::new(e),
        })?;
    let policy = require_policy_section(partial.policy, &path)?;

    let chain_id = partial.chain_id;
    let rpc_url = partial
        .rpc_url
        .unwrap_or_else(|| chain_id.default_rpc_url().to_owned());
    let network_passphrase = chain_id.network_passphrase().to_owned();
    let audit_log_path = partial
        .audit_log_path
        .unwrap_or_else(|| default_audit_log_path().unwrap_or_else(|_| PathBuf::from("audit.log")));

    // Validate smart_account_max_context_rule_scan_id bound.
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

    // Validate session_rule_max_horizon_ledgers bound.
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

    let profile = Profile {
        version: partial.version,
        chain_id,
        rpc_url,
        network_passphrase,
        mcp_signer_default: partial.mcp_signer_default,
        mcp_nonce_key_alias: partial.mcp_nonce_key_alias,
        usd_threshold: partial.usd_threshold,
        classic_fee_per_op_stroops: partial.classic_fee_per_op_stroops,
        classic_max_fee_per_op_stroops: partial.classic_max_fee_per_op_stroops,
        submit_timeout_seconds: partial.submit_timeout_seconds,
        audit_log_path,
        mcp_disabled: partial.mcp_disabled,
        audit_log_hash_chain_key_id: partial.audit_log_hash_chain_key_id,
        policy_owner_key_id: partial.policy_owner_key_id,
        attestation_key_id: partial.attestation_key_id,
        counterparty_cache_key_id: partial.counterparty_cache_key_id,
        oracle_provider_url: partial.oracle_provider_url,
        policy,
        wallet: partial.wallet,
        smart_account_max_context_rule_scan_id: partial.smart_account_max_context_rule_scan_id,
        session_rule_max_horizon_ledgers: partial.session_rule_max_horizon_ledgers,
        secondary_rpc_url: partial.secondary_rpc_url,
        pool_master_key_id: partial.pool_master_key_id,
        pool_config: partial.pool_config,
        remote_approval: partial.remote_approval,
    };

    profile
        .validate_rpc_url()
        .map_err(|e| ProfileLoadError::InvalidRpcUrl {
            name: name.to_owned(),
            source: e,
        })?;

    // Multicall guard — same as in `load_from_path`.
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
/// - `rpc_url = Caip2::Testnet.default_rpc_url()`
/// - `network_passphrase = Caip2::Testnet.network_passphrase()`
/// - All optional fields at their schema defaults.
///
/// # Errors
///
/// Returns an error only if the OS-conventional state directory cannot be
/// determined (i.e. `directories::ProjectDirs` fails — effectively never on
/// supported platforms), or if the profile file exists but fails to load.
pub fn load_default_or_testnet_fallback() -> Result<Profile, ProfileLoadError> {
    // Pass `None` for the multicall hook: the testnet-fallback path is a
    // pre-multicall startup convenience; no registry is available at this point.
    match load("default", None) {
        Ok(profile) => Ok(profile),
        Err(ProfileLoadError::NotFound { .. }) => Ok(synthesise_default_first_run_profile()),
        Err(e) => Err(e),
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
/// The operator opts in to `V1` via the `rotate-owner-key` +
/// `rotate-attestation-key` + `rotate-audit-key` ceremony.
///
/// # Design note
///
/// The synthesised profile is never persisted — it is in-memory only for the
/// duration of the current process.  A newly-initialised deployment creates an
/// explicit `default.toml` (with `engine = "v1"`) on first
/// `stellar-agent profile init`; from that point the fallback arm is no longer
/// taken.
fn synthesise_default_first_run_profile() -> Profile {
    Profile::builder_testnet(
        "stellar-agent-signer-default",
        "default",
        "stellar-agent-nonce-default",
        "default",
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

/// Partial profile with optional fields that have derived defaults.
///
/// `rpc_url` and `audit_log_path` are optional in the TOML; they are resolved
/// from `chain_id` / OS-conventions at load time.  `network_passphrase` is
/// NOT present in the TOML — it is always derived from `chain_id`.
///
/// The v2 fields (`audit_log_hash_chain_key_id`, `policy_owner_key_id`,
/// `attestation_key_id`, `counterparty_cache_key_id`) are required in v2
/// profiles; they are populated by `migrate_v1_to_v2` with default-derived
/// names.  `oracle_provider_url` defaults to `None`.
/// `policy` defaults to `PolicyConfig::default()` (engine `V1`).
/// `classic_fee_per_op_stroops`, `classic_max_fee_per_op_stroops`, and
/// `submit_timeout_seconds` default to `None` for pre-existing v2 profiles
/// that predate those optional fields.
#[derive(serde::Deserialize)]
struct PartialProfile {
    version: u32,
    chain_id: Caip2,
    rpc_url: Option<String>,
    mcp_signer_default: super::schema::KeyringEntryRef,
    mcp_nonce_key_alias: super::schema::KeyringEntryRef,
    #[serde(default)]
    usd_threshold: u64,
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
    oracle_provider_url: Option<url::Url>,
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
    /// Remote-approval HTTP surface configuration. Absent from profiles
    /// predating remote approval; defaults to `None` (off).
    #[serde(default)]
    remote_approval: Option<super::schema::RemoteApprovalConfig>,
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
    use crate::profile::schema::MINIMUM_FLOOR;

    /// Writes a minimal valid profile TOML to a temp directory and returns the
    /// directory handle (keeps the temp dir alive).
    fn write_profile(content: &str) -> (tempfile::TempDir, String) {
        let dir = tempfile::tempdir().unwrap();
        let name = "test-profile";
        let path = dir.path().join(format!("{name}.toml"));
        std::fs::write(&path, content).unwrap();
        (dir, name.to_owned())
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
            matches!(err, ProfileLoadError::InvalidRpcUrl { .. }),
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
        assert_eq!(loaded.usd_threshold, profile.usd_threshold);
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
    fn usd_threshold_defaults_to_minimum_floor_on_load() {
        // A profile TOML with no usd_threshold field should default to 0
        // (the serde default), and effective_usd_threshold() returns MINIMUM_FLOOR.
        let (dir, name) = write_profile(minimal_toml());
        let p = load_from_dir(&name, dir.path(), None).unwrap();
        // raw value is 0 (omitted), effective is MINIMUM_FLOOR
        assert_eq!(p.effective_usd_threshold(), MINIMUM_FLOOR);
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

    // ── usd_threshold above MINIMUM_FLOOR ────────────────────────────────────

    /// When `usd_threshold` in the TOML exceeds `MINIMUM_FLOOR`, the raw value
    /// is preserved and `effective_usd_threshold()` returns that higher value.
    #[test]
    fn usd_threshold_above_floor_preserved() {
        let dir = tempfile::tempdir().unwrap();
        let above_floor = MINIMUM_FLOOR + 1;
        let profile = Profile::builder_testnet("svc", "acct", "n-svc", "n-acct")
            .with_profile_name("usd-test")
            .audit_log_path(dir.path().join("audit.log"))
            .usd_threshold(above_floor)
            .build();

        save_to_dir("usd-test", &profile, dir.path()).unwrap();
        let loaded = load_from_dir("usd-test", dir.path(), None).unwrap();
        assert_eq!(loaded.usd_threshold, above_floor);
        assert_eq!(loaded.effective_usd_threshold(), above_floor);
    }

    // ── Mainnet profile round-trip ────────────────────────────────────────────

    /// A mainnet profile saved and reloaded has the correct `chain_id` and
    /// the mainnet network passphrase.
    #[test]
    fn mainnet_profile_round_trip() {
        use crate::profile::caip2::{Caip2, MAINNET_PASSPHRASE};
        let dir = tempfile::tempdir().unwrap();
        let profile = Profile::builder_mainnet("svc", "acct", "n-svc", "n-acct")
            .with_profile_name("mainnet-profile")
            .audit_log_path(dir.path().join("mainnet-audit.log"))
            .build();

        save_to_dir("mainnet-profile", &profile, dir.path()).unwrap();
        let loaded = load_from_dir("mainnet-profile", dir.path(), None).unwrap();
        assert_eq!(loaded.chain_id, Caip2::Mainnet);
        assert_eq!(loaded.network_passphrase, MAINNET_PASSPHRASE);
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
}
