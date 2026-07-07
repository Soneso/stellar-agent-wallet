//! Profile-config schema migration.
//!
//! The migration mechanism is invoked by `stellar-agent profile migrate <name>`.
//! It reads the profile at version N, applies the chain of migration functions to
//! reach the current supported version, then writes back atomically (temp-file +
//! rename).
//!
//! # Atomicity contract
//!
//! Atomic write uses `tempfile::NamedTempFile::persist` which resolves to
//! `rename(2)` on POSIX.  A failed migration leaves the original file in place
//! because the rename only occurs after the migration function completes
//! successfully.
//!
//! **Networked filesystem caveat:** `rename(2)` is atomic on single-host POSIX
//! filesystems (local ext4, APFS, NTFS via WSL).  NFSv3 and SMB mounts may
//! have weaker rename semantics; NFSv4 typically provides atomic rename but
//! client-cache races can still occur.  Operators using such mounts for the
//! stellar-agent state directory assume the same threat regime as the unchained
//! audit log — the keyring, not the TOML file, is the actual defence for
//! secret material.  On Windows, `tempfile::persist` uses
//! `MoveFileExW(MOVEFILE_REPLACE_EXISTING)` which is not strictly atomic
//! against a crash between write and rename; see also the identical caveat on
//! [`super::loader::save`](`crate::profile::loader::save`) which documents the
//! Windows NTFS behaviour and the secret-material mitigating note.
//!
//! # TOCTOU accepted limitation
//!
//! The migration path contains a time-of-check / time-of-use window: the
//! profile file is read at step 1 (peek version) and again at step 2 (load
//! v1), then written at step 3 (save).  A concurrent writer replacing the
//! file between steps 1 and 3 would result in the migrated output being
//! derived from the file state at step 2, not from whatever the concurrent
//! writer produced.
//!
//! **Accepted limitation:** `stellar-agent profile migrate` is an
//! operator-driven CLI command, invoked interactively or in a maintenance
//! script.  Concurrent profile writes during a deliberate, attended migration
//! are outside the operational threat model.  Adding `flock` or advisory
//! locking here is deferred; operators who run migrations against shared
//! state directories should ensure single-writer discipline at the
//! infrastructure level.
//!
//! # Supported migrations
//!
//! | From → To | Function |
//! |-----------|----------|
//! | v1 → v2   | `migrate_v1_to_v2` |

use std::path::{Path, PathBuf};

use super::loader::{ProfileLoadError, ProfileSaveError, save_to_dir};
use super::schema::{KeyringEntryRef, PolicyConfig, PolicyEngineKind, Profile};

// ─────────────────────────────────────────────────────────────────────────────
// Internal: v1-only partial loader used exclusively by migrate_v1_to_v2.
//
// The main loader rejects version != SUPPORTED_VERSION (currently 2).  To
// migrate a v1 profile we need a loader that accepts version 1 without
// requiring the v2-specific fields.  This partial struct and the associated
// figment extraction are intentionally private to this module.
// ─────────────────────────────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
struct PartialV1Profile {
    // figment accepts unknown keys; `version` is not used after deserialization
    // because `peek_version` already extracted it.  The field is retained so
    // serde round-trips cleanly without a custom Deserialize impl, but is
    // intentionally unnamed at call sites.
    #[serde(rename = "version")]
    _version: u32,
    chain_id: super::caip2::Caip2,
    rpc_url: Option<String>,
    mcp_signer_default: KeyringEntryRef,
    mcp_nonce_key_alias: KeyringEntryRef,
    #[serde(default)]
    usd_threshold: u64,
    audit_log_path: Option<std::path::PathBuf>,
    #[serde(default)]
    mcp_disabled: bool,
}

/// Loads a v1 profile from an explicit path, bypassing the v2 version check.
///
/// This is the ONLY call site that should accept version `1`; the production
/// loader requires version `2`.
///
/// # Errors
///
/// Returns [`ProfileLoadError`] on figment extraction failure.
fn load_v1_from_path(name: &str, path: &Path) -> Result<PartialV1Profile, ProfileLoadError> {
    use figment::{
        Figment,
        providers::{Format, Toml},
    };

    let raw: PartialV1Profile = Figment::new()
        .merge(Toml::file(path))
        .extract()
        .map_err(|e| ProfileLoadError::Figment {
            name: name.to_owned(),
            source: Box::new(e),
        })?;

    Ok(raw)
}

// ─────────────────────────────────────────────────────────────────────────────
// Public types
// ─────────────────────────────────────────────────────────────────────────────

/// Errors produced during profile migration.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MigrateError {
    /// The profile could not be loaded before migration.
    #[error("migration failed to load profile '{name}': {source}")]
    Load {
        /// Profile name supplied by the caller.
        name: String,
        /// The underlying load error (boxed to keep the enum variant small).
        #[source]
        source: Box<ProfileLoadError>,
    },

    /// The profile could not be saved after migration.
    #[error("migration failed to save profile '{name}': {source}")]
    Save {
        /// Profile name supplied by the caller.
        name: String,
        /// The underlying save error.
        #[source]
        source: ProfileSaveError,
    },

    /// The profile version is not known to this migration chain.
    ///
    /// The production loader's version guard fires first in normal operation;
    /// this variant is a safety net for versions the migration chain cannot
    /// handle (e.g. a future v3 profile opened by a v2 wallet).
    #[error(
        "profile '{name}' has version {found} which has no migration path \
         in this wallet version (supports up to {supported})"
    )]
    UnknownVersion {
        /// Profile name supplied by the caller.
        name: String,
        /// The version found in the TOML file.
        found: u32,
        /// The highest version this wallet can migrate.
        supported: u32,
    },
}

/// Result of a migration attempt.
#[derive(Debug)]
#[non_exhaustive]
pub enum MigrateOutcome {
    /// The profile was already at the latest version; the file was not touched.
    NoOp {
        /// The current (already-latest) schema version.
        version: u32,
    },
    /// The profile was migrated from `from_version` to `to_version`.
    Migrated {
        /// The schema version before migration.
        from_version: u32,
        /// The schema version after migration.
        to_version: u32,
        /// The path to the migrated profile file.
        path: PathBuf,
    },
}

/// Current supported schema version.
const CURRENT_VERSION: u32 = 2;

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

/// Migrates the named profile in the given directory to the current schema
/// version.
///
/// If the profile is already at the current version, returns
/// [`MigrateOutcome::NoOp`] without touching the file.
///
/// On success, the original file is atomically replaced with the migrated
/// content (temp-file + rename).  A failure during migration leaves the
/// original file in place.
///
/// # Errors
///
/// - [`MigrateError::Load`] — the profile file could not be loaded.
/// - [`MigrateError::Save`] — the migrated profile could not be saved.
/// - [`MigrateError::UnknownVersion`] — no migration path exists from the
///   profile's current version (can only happen when the profile is at a
///   version the wallet does not know how to migrate from).
pub fn migrate(name: &str, profile_dir: &Path) -> Result<MigrateOutcome, MigrateError> {
    let path = profile_dir.join(format!("{name}.toml"));

    // Peek at the version field without requiring v2-specific fields.
    let raw_version = peek_version(name, &path)?;

    if raw_version == CURRENT_VERSION {
        return Ok(MigrateOutcome::NoOp {
            version: raw_version,
        });
    }

    let from_version = raw_version;

    // Dispatch on the from-version.
    let migrated = apply_migrations(name, &path, from_version)?;

    let dest = save_to_dir(name, &migrated, profile_dir).map_err(|e| MigrateError::Save {
        name: name.to_owned(),
        source: e,
    })?;

    Ok(MigrateOutcome::Migrated {
        from_version,
        to_version: CURRENT_VERSION,
        path: dest,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Reads only the `version` field from the TOML at `path` without requiring
/// any other fields to be present.
fn peek_version(name: &str, path: &Path) -> Result<u32, MigrateError> {
    use figment::{
        Figment,
        providers::{Format, Toml},
    };

    #[derive(serde::Deserialize)]
    struct VersionOnly {
        version: u32,
    }

    Figment::new()
        .merge(Toml::file(path))
        .extract::<VersionOnly>()
        .map(|v| v.version)
        .map_err(|e| MigrateError::Load {
            name: name.to_owned(),
            source: Box::new(ProfileLoadError::Figment {
                name: name.to_owned(),
                source: Box::new(e),
            }),
        })
}

/// Applies the chain of migration functions from `from_version` to
/// [`CURRENT_VERSION`].
fn apply_migrations(name: &str, path: &Path, from_version: u32) -> Result<Profile, MigrateError> {
    match from_version {
        1 => {
            let v1 = load_v1_from_path(name, path).map_err(|e| MigrateError::Load {
                name: name.to_owned(),
                source: Box::new(e),
            })?;
            Ok(migrate_v1_to_v2(name, v1))
        }
        _ => Err(MigrateError::UnknownVersion {
            name: name.to_owned(),
            found: from_version,
            supported: CURRENT_VERSION,
        }),
    }
}

/// Migrates a v1 profile to v2.
///
/// All v1 fields are preserved unchanged.  The lazy-mint v2 fields are
/// populated with default-derived keyring entry references and unset values.
/// `classic_fee_per_op_stroops` and `classic_max_fee_per_op_stroops` are
/// initialised to `None` so migrated profiles keep using the protocol default
/// per-operation classic fee with no cap. No key material is created here;
/// actual key material is created by the rotate-key CLI commands.
///
/// # Lazy-mint semantics
///
/// | New field | Default value | Key minted by |
/// |-----------|---------------|---------------|
/// | `audit_log_hash_chain_key_id` | `stellar-agent-audit-<name>/default` | `rotate-audit-key` |
/// | `policy_owner_key_id` | `stellar-agent-owner-<name>/default` | `enroll-owner-key` |
/// | `attestation_key_id` | `stellar-agent-attestation-<name>/default` | `rotate-attestation-key` |
/// | `counterparty_cache_key_id` | `stellar-agent-counterparty-<name>/default` | `rotate-counterparty-key` |
/// | `oracle_provider_url` | `None` | operator action |
/// | `policy.engine` | `Noop` | operator action |
/// | `classic_fee_per_op_stroops` | `None` | operator action |
/// | `classic_max_fee_per_op_stroops` | `None` | operator action |
///
/// # Idempotency
///
/// The public [`migrate`] function guards on `from_version == CURRENT_VERSION`
/// before calling into [`apply_migrations`], so re-running on a v2 profile
/// returns `MigrateOutcome::NoOp` without ever reaching this function.
///
fn migrate_v1_to_v2(profile_name: &str, v1: PartialV1Profile) -> Profile {
    use super::schema::default_audit_log_path;

    let audit_log_path = v1
        .audit_log_path
        .unwrap_or_else(|| default_audit_log_path().unwrap_or_else(|_| PathBuf::from("audit.log")));

    let chain_id = v1.chain_id;
    let rpc_url = v1
        .rpc_url
        .unwrap_or_else(|| chain_id.default_rpc_url().to_owned());
    let network_passphrase = chain_id.network_passphrase().to_owned();

    Profile {
        version: 2,
        chain_id,
        rpc_url,
        network_passphrase,
        mcp_signer_default: v1.mcp_signer_default,
        mcp_nonce_key_alias: v1.mcp_nonce_key_alias,
        usd_threshold: v1.usd_threshold,
        classic_fee_per_op_stroops: None,
        classic_max_fee_per_op_stroops: None,
        submit_timeout_seconds: None,
        audit_log_path,
        mcp_disabled: v1.mcp_disabled,
        // ── Lazy-mint defaults for new v2 fields ─────────────────────────────
        audit_log_hash_chain_key_id: KeyringEntryRef::default_audit_key(profile_name),
        policy_owner_key_id: KeyringEntryRef::default_owner_key(profile_name),
        attestation_key_id: KeyringEntryRef::default_attestation_key(profile_name),
        counterparty_cache_key_id: KeyringEntryRef::default_counterparty_key(profile_name),
        oracle_provider_url: None,
        policy: PolicyConfig {
            engine: PolicyEngineKind::Noop,
        },
        wallet: crate::profile::schema::WalletConfig::default(),
        smart_account_max_context_rule_scan_id: None,
        session_rule_max_horizon_ledgers: None,
        secondary_rpc_url: None,
        // Pool not yet initialised in v1→v2 migrations.
        pool_master_key_id: None,
        pool_config: None,
        // Remote approval is off by default for migrated profiles.
        remote_approval: None,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use super::*;
    use crate::profile::loader::{load_from_dir, save_to_dir};
    use crate::profile::schema::{MINIMUM_FLOOR, Profile};

    // ── Helpers ──────────────────────────────────────────────────────────────

    /// Writes a v2 profile using the builder and returns the profile name.
    fn make_v2_profile(dir: &Path, name: &str) -> String {
        let profile = Profile::builder_testnet("svc", "acct", "nonce-svc", "nonce-acct")
            .with_profile_name(name)
            .audit_log_path(dir.join("audit.log"))
            .build();
        save_to_dir(name, &profile, dir).unwrap();
        name.to_owned()
    }

    /// Writes a minimal v1 TOML directly (bypasses the builder which emits v2).
    fn write_v1_toml(dir: &Path, name: &str) -> String {
        let toml = format!(
            r#"version = 1
chain_id = "stellar:testnet"

[mcp_signer_default]
service = "stellar-agent-signer"
account = "{name}"

[mcp_nonce_key_alias]
service = "stellar-agent-nonce"
account = "{name}"
"#
        );
        std::fs::write(dir.join(format!("{name}.toml")), toml).unwrap();
        name.to_owned()
    }

    // ── migrate_v2_is_noop ────────────────────────────────────────────────────

    /// A profile already at version 2 returns NoOp without touching the file.
    #[test]
    fn migrate_v2_is_noop() {
        let dir = tempfile::tempdir().unwrap();
        let name = make_v2_profile(dir.path(), "noop-test");

        let outcome = migrate(&name, dir.path()).unwrap();
        assert!(
            matches!(outcome, MigrateOutcome::NoOp { version: 2 }),
            "expected NoOp {{ version: 2 }}, got {outcome:?}"
        );
    }

    #[test]
    fn migrate_v2_noop_leaves_file_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let name = make_v2_profile(dir.path(), "noop-unchanged");
        let path = dir.path().join(format!("{name}.toml"));

        let before = std::fs::read_to_string(&path).unwrap();
        migrate(&name, dir.path()).unwrap();
        let after = std::fs::read_to_string(&path).unwrap();

        assert_eq!(before, after, "NoOp migration must not modify the file");
    }

    // ── migrate_v1_to_v2_round_trip ───────────────────────────────────────────

    /// A v1 TOML migrates to v2; all new fields are present at expected defaults.
    #[test]
    fn migrate_v1_to_v2_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let name = write_v1_toml(dir.path(), "round-trip");

        let outcome = migrate(&name, dir.path()).unwrap();
        assert!(
            matches!(
                outcome,
                MigrateOutcome::Migrated {
                    from_version: 1,
                    to_version: 2,
                    ..
                }
            ),
            "expected Migrated 1→2, got {outcome:?}"
        );

        // Reload through the standard loader (requires v2).
        let loaded = load_from_dir(&name, dir.path(), None).unwrap();
        assert_eq!(loaded.version, 2);
        assert_eq!(
            loaded.audit_log_hash_chain_key_id.service,
            format!("stellar-agent-audit-{name}")
        );
        assert_eq!(loaded.audit_log_hash_chain_key_id.account, "default");
        assert_eq!(
            loaded.policy_owner_key_id.service,
            format!("stellar-agent-owner-{name}")
        );
        assert_eq!(loaded.policy_owner_key_id.account, "default");
        assert_eq!(
            loaded.attestation_key_id.service,
            format!("stellar-agent-attestation-{name}")
        );
        assert_eq!(loaded.attestation_key_id.account, "default");
        assert_eq!(
            loaded.counterparty_cache_key_id.service,
            format!("stellar-agent-counterparty-{name}")
        );
        assert_eq!(loaded.counterparty_cache_key_id.account, "default");
        assert_eq!(loaded.oracle_provider_url, None);
        assert_eq!(loaded.classic_fee_per_op_stroops, None);
        assert_eq!(
            loaded.policy.engine,
            crate::profile::schema::PolicyEngineKind::Noop
        );
    }

    // ── migrate_v1_to_v2_idempotent ───────────────────────────────────────────

    /// Running migrate twice on a v1 profile: first run migrates (1→2), second
    /// run returns NoOp (already at v2).
    #[test]
    fn migrate_v1_to_v2_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let name = write_v1_toml(dir.path(), "idempotent");

        let first = migrate(&name, dir.path()).unwrap();
        assert!(
            matches!(
                first,
                MigrateOutcome::Migrated {
                    from_version: 1,
                    to_version: 2,
                    ..
                }
            ),
            "first run must migrate"
        );

        let second = migrate(&name, dir.path()).unwrap();
        assert!(
            matches!(second, MigrateOutcome::NoOp { version: 2 }),
            "second run must be NoOp, got {second:?}"
        );
    }

    // ── migrate_v1_to_v2_preserves_existing_fields ────────────────────────────

    /// All v1 fields are unchanged after migration.
    #[test]
    fn migrate_v1_to_v2_preserves_existing_fields() {
        let dir = tempfile::tempdir().unwrap();
        let name = write_v1_toml(dir.path(), "preserve-fields");

        migrate(&name, dir.path()).unwrap();

        let loaded = load_from_dir(&name, dir.path(), None).unwrap();

        // v1 field values as written by write_v1_toml.
        assert_eq!(loaded.mcp_signer_default.service, "stellar-agent-signer");
        assert_eq!(loaded.mcp_signer_default.account, name);
        assert_eq!(loaded.mcp_nonce_key_alias.service, "stellar-agent-nonce");
        assert_eq!(loaded.mcp_nonce_key_alias.account, name);
        assert_eq!(loaded.chain_id, crate::profile::caip2::Caip2::Testnet);
        // usd_threshold was not set in v1 TOML → defaults to 0 (effective = MINIMUM_FLOOR)
        assert_eq!(loaded.effective_usd_threshold(), MINIMUM_FLOOR);
        assert!(!loaded.mcp_disabled);
    }

    // ── migrate_not_found ─────────────────────────────────────────────────────

    #[test]
    fn migrate_not_found_returns_load_error() {
        let dir = tempfile::tempdir().unwrap();
        let err = migrate("nonexistent", dir.path()).unwrap_err();
        assert!(
            matches!(err, MigrateError::Load { .. }),
            "expected Load error, got {err:?}"
        );
    }

    // ── migrate_v1_to_v2_produces_noop_engine ────────────────────────────────

    /// `migrate_v1_to_v2` MUST set `policy.engine = "noop"` on migrated profiles,
    /// regardless of `PolicyEngineKind::default()` (which is `V1` for
    /// newly-minted profiles).
    ///
    /// A migrated profile must retain the mainnet gate until the operator
    /// explicitly opts in to V1.
    #[test]
    fn migrate_v1_to_v2_produces_noop_engine() {
        let dir = tempfile::tempdir().unwrap();
        let name = write_v1_toml(dir.path(), "noop-engine-asymmetry");

        migrate(&name, dir.path()).unwrap();

        let loaded = load_from_dir(&name, dir.path(), None).unwrap();
        assert_eq!(
            loaded.policy.engine,
            crate::profile::schema::PolicyEngineKind::Noop,
            "migrate_v1_to_v2 must set engine = Noop regardless of PolicyEngineKind::default()"
        );
    }

    // ── migrate_unknown_version ───────────────────────────────────────────────

    #[test]
    fn migrate_unknown_version_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        // Write a TOML with version = 99.
        let toml = r#"version = 99
chain_id = "stellar:testnet"

[mcp_signer_default]
service = "s"
account = "a"

[mcp_nonce_key_alias]
service = "n"
account = "a"
"#;
        std::fs::write(dir.path().join("future.toml"), toml).unwrap();
        let err = migrate("future", dir.path()).unwrap_err();
        assert!(
            matches!(err, MigrateError::UnknownVersion { found: 99, .. }),
            "expected UnknownVersion, got {err:?}"
        );
    }
}
