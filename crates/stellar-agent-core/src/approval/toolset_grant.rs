//! First-invoke grant store for signing-adjacent toolset capabilities.
//!
//! Persists approved (toolset, capability, destination, asset, amount_min,
//! amount_max) tuples + HMAC attestation, per profile, to a TOML file.
//!
//! # Purpose
//!
//! After the operator approves a `ToolsetFirstInvokeGate` approval via
//! `stellar-agent approve --id <nonce> --profile <name>`, the gated resolver persists a
//! `ToolsetGrant` record here.  On subsequent invocations the resolver checks
//! this store FIRST: if a current, matching grant exists, the first-invoke
//! gate is short-circuited (but the per-action `PaymentSimulated` approval
//! ALWAYS fires unconditionally — the grant only suppresses the re-prompt on
//! the first-invoke gate).
//!
//! # Grant matching
//!
//! A grant matches a payment envelope iff:
//! - `toolset_name` == toolset name from the invoke call.
//! - Its install identity, package version and package shasum equal the current pin.
//! - `capability` == capability token (e.g. `"sign-payment"`).
//! - A `sign-payment` grant for a G account covers that account and every M
//!   address of it. A grant for an M address covers only that complete M
//!   address. Other capabilities compare the destination text exactly.
//! - `asset` == canonical `code:issuer` or `"XLM"` of the envelope asset.
//! - `amount_min_stroops` ≤ envelope_amount ≤ `amount_max_stroops`.
//! - The grant is not expired (TTL check).
//! - Its version 3 HMAC verifies under the profile's key and profile/chain binding.
//! - Its lifetime is at most 30 days and its issue time meets the install cutoff.
//! - Its issue time does not lie after the current time.
//!
//! # Durability properties
//!
//! - **Bounded TTL**: verified grants expire within 30 days of issuance.
//! - **Install epoch**: grants must be issued at or after the start of the
//!   second following the current pin's install time. A reinstall requires
//!   fresh consent, including a forced install or an install after manual removal.
//!   Each install mints a random identity. A grant names the install identity,
//!   version and shasum it is approved for; a queued request for another identity
//!   yields no grant the current installation honors.
//! - An invalid install time honors no grant. Consent issued in the install
//!   second re-prompts once.
//!
//! # Tamper framing
//!
//! A forged or edited grant fails attestation verification and suppresses
//! nothing. The verified lookup binds the grant's fields, kind, lifetime,
//! profile, and chain under the profile's attestation key.
//!
//! The per-action `PaymentSimulated` approval fires on every toolset-routed
//! payment and binds the actual executed envelope.
//!
//! Coverage never rewrites a grant. The attestation binds the stored
//! destination text, so a G grant and an M grant attest different bytes.

use std::fs;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

use super::error::{ApprovalError, toml_error_position};
use crate::approval::attestation::{
    ATTESTATION_VERSION, ATTESTATION_VERSION_V2, AttestationScope, AttestedLifetime,
    compute_attestation, compute_toolset_gate_digest, verify_toolset_gate_attestation,
};
use crate::payment_accounts::PaymentAccount;

/// The kind name a grant's version 3 attestation binds.
pub const TOOLSET_GRANT_KIND: &str = "ToolsetGrant";

/// The capability whose destination is a classic payment destination.
pub(crate) const SIGN_PAYMENT_CAPABILITY: &str = "sign-payment";

/// Checks that a `sign-payment` destination is a canonical G account or M
/// address. Other capabilities keep their own destination forms, such as the
/// smart-account contract of `sign-rule-create`.
pub(crate) fn check_grant_destination(capability: &str, destination: &str) -> Result<(), String> {
    if capability == SIGN_PAYMENT_CAPABILITY && PaymentAccount::parse(destination).is_err() {
        return Err(
            "a sign-payment destination must be a canonical G account or M address".to_owned(),
        );
    }
    Ok(())
}

/// Whether a payment grant for `granted` covers a payment to `destination`.
///
/// A G grant covers its account and every M address of that account, which
/// all credit the same balance. An M grant covers only its complete M address.
fn payment_grant_covers(granted: &str, destination: &str) -> bool {
    let (Ok(granted), Ok(destination)) = (
        PaymentAccount::parse(granted),
        PaymentAccount::parse(destination),
    ) else {
        return false;
    };
    match granted.muxed_id() {
        None => destination.base_account() == granted.canonical(),
        Some(_) => destination.canonical() == granted.canonical(),
    }
}

/// The layout of a grant attestation stored before grants named theirs.
fn legacy_attestation_version() -> u32 {
    ATTESTATION_VERSION_V2
}

// ─────────────────────────────────────────────────────────────────────────────
// TTL constant
// ─────────────────────────────────────────────────────────────────────────────

/// Default TTL for a `ToolsetGrant`: 30 days in milliseconds.
///
/// After expiry the grant is removed from the store on next load and the
/// first-invoke gate fires again, prompting the operator for re-approval.
pub const TOOLSET_GRANT_DEFAULT_TTL_MS: u64 = 30 * 24 * 60 * 60 * 1_000;

// ─────────────────────────────────────────────────────────────────────────────
// ToolsetGrant
// ─────────────────────────────────────────────────────────────────────────────

/// A persisted first-invoke grant record for a toolset's signing-adjacent capability.
///
/// Created by the gated resolver after the operator approves a
/// `ToolsetFirstInvokeGate` pending approval.
///
/// The capability and destination are private, so a grant built or
/// deserialized outside the store names a destination its capability admits.
/// A stored grant loads as written, and matching checks its destination.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(try_from = "GrantRecord", into = "GrantRecord")]
#[non_exhaustive]
pub struct ToolsetGrant {
    /// Wallet-issued grant identifier (16 bytes, URL-safe base64 no-pad).
    pub grant_id: String,

    /// Name of the toolset the grant was issued to.
    pub toolset_name: String,

    /// Random installation identity, 32 lowercase hex characters.
    #[serde(default)]
    pub install_id: String,
    /// Package version the grant was approved for.
    #[serde(default)]
    pub package_version: String,
    /// SHA-256 of the package the grant was approved for, 64 lowercase hex characters.
    #[serde(default)]
    pub package_shasum: String,

    capability: String,

    destination: String,

    /// Asset identifier (`"XLM"` or `"<code>:<G-strkey>"`).
    pub asset: String,

    /// Bucket lower bound in stroops.
    pub amount_min_stroops: i64,

    /// Bucket upper bound in stroops.
    pub amount_max_stroops: i64,

    /// Unix epoch milliseconds when this grant was issued.
    pub granted_at_unix_ms: u64,

    /// Unix epoch milliseconds when this grant expires.
    pub expires_at_unix_ms: u64,

    /// HMAC-SHA256 attestation blob (URL-safe base64 no-pad, 32 bytes).
    ///
    /// The verified lookup requires a valid blob under the profile's key and
    /// binding. Version 3 binds the grant's fields, user identity, kind, and
    /// lifetime. A missing or invalid blob suppresses no first-invoke prompt.
    pub attestation_blob_b64: Option<String>,

    /// Platform-stable user identity at grant time (used to rebind HMAC).
    pub process_uid_at_grant: String,

    /// The layout `attestation_blob_b64` is computed under.
    ///
    /// Version 3 also binds the grant's kind name ([`TOOLSET_GRANT_KIND`]),
    /// its grant time, and its expiry, so a hand-edited lifetime fails
    /// verification. A grant written without the field reads as version 2.
    #[serde(default = "legacy_attestation_version")]
    pub attestation_version: u32,
}

/// The stored form of a grant, before its destination is checked.
///
/// A [`ToolsetGrant`] serializes through this record, which keeps the
/// layout of the derived form.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct GrantRecord {
    grant_id: String,
    toolset_name: String,
    #[serde(default)]
    install_id: String,
    #[serde(default)]
    package_version: String,
    #[serde(default)]
    package_shasum: String,
    capability: String,
    destination: String,
    asset: String,
    amount_min_stroops: i64,
    amount_max_stroops: i64,
    granted_at_unix_ms: u64,
    expires_at_unix_ms: u64,
    attestation_blob_b64: Option<String>,
    process_uid_at_grant: String,
    #[serde(default = "legacy_attestation_version")]
    attestation_version: u32,
}

impl TryFrom<GrantRecord> for ToolsetGrant {
    type Error = String;

    fn try_from(record: GrantRecord) -> Result<Self, String> {
        check_grant_destination(&record.capability, &record.destination)?;
        Ok(Self::stored(record))
    }
}

impl ToolsetGrant {
    /// A grant as the store holds it, without the destination check.
    fn stored(record: GrantRecord) -> Self {
        Self {
            grant_id: record.grant_id,
            toolset_name: record.toolset_name,
            install_id: record.install_id,
            package_version: record.package_version,
            package_shasum: record.package_shasum,
            capability: record.capability,
            destination: record.destination,
            asset: record.asset,
            amount_min_stroops: record.amount_min_stroops,
            amount_max_stroops: record.amount_max_stroops,
            granted_at_unix_ms: record.granted_at_unix_ms,
            expires_at_unix_ms: record.expires_at_unix_ms,
            attestation_blob_b64: record.attestation_blob_b64,
            process_uid_at_grant: record.process_uid_at_grant,
            attestation_version: record.attestation_version,
        }
    }
}

impl From<ToolsetGrant> for GrantRecord {
    fn from(grant: ToolsetGrant) -> Self {
        Self {
            grant_id: grant.grant_id,
            toolset_name: grant.toolset_name,
            install_id: grant.install_id,
            package_version: grant.package_version,
            package_shasum: grant.package_shasum,
            capability: grant.capability,
            destination: grant.destination,
            asset: grant.asset,
            amount_min_stroops: grant.amount_min_stroops,
            amount_max_stroops: grant.amount_max_stroops,
            granted_at_unix_ms: grant.granted_at_unix_ms,
            expires_at_unix_ms: grant.expires_at_unix_ms,
            attestation_blob_b64: grant.attestation_blob_b64,
            process_uid_at_grant: grant.process_uid_at_grant,
            attestation_version: grant.attestation_version,
        }
    }
}

impl ToolsetGrant {
    /// Returns the capability token, such as `"sign-payment"`.
    #[must_use]
    pub fn capability(&self) -> &str {
        &self.capability
    }

    /// Returns the destination from the authoritative envelope, as approved.
    ///
    /// A `sign-payment` grant holds a canonical G account or M address.
    #[must_use]
    pub fn destination(&self) -> &str {
        &self.destination
    }

    /// Returns `true` if this grant has expired relative to `now_unix_ms`.
    #[must_use]
    pub fn is_expired(&self, now_unix_ms: u64) -> bool {
        self.expires_at_unix_ms <= now_unix_ms
    }

    /// Compares the installation, payment fields and clock against this grant's bucket and expiry.
    ///
    /// A `sign-payment` grant for a G account covers that account and its M
    /// addresses; a grant for an M address covers only that address. Other
    /// capabilities compare the destination text exactly.
    ///
    /// This is a field and clock comparison only. Use
    /// [`ToolsetGrantStore::find_matching`] for a verified lookup.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn matches(
        &self,
        toolset_name: &str,
        install_id: &str,
        package_version: &str,
        package_shasum: &str,
        capability: &str,
        destination: &str,
        asset: &str,
        amount_stroops: i64,
        now_unix_ms: u64,
    ) -> bool {
        if self.is_expired(now_unix_ms) {
            return false;
        }
        self.toolset_name == toolset_name
            && self.install_id == install_id
            && self.package_version == package_version
            && self.package_shasum == package_shasum
            && self.capability == capability
            && self.covers_destination(destination)
            && self.asset == asset
            && amount_stroops >= self.amount_min_stroops
            && amount_stroops <= self.amount_max_stroops
    }

    fn covers_destination(&self, destination: &str) -> bool {
        if self.capability == SIGN_PAYMENT_CAPABILITY {
            payment_grant_covers(&self.destination, destination)
        } else {
            self.destination == destination
        }
    }

    /// Verifies the HMAC attestation blob against the stored grant fields.
    ///
    /// Returns `true` iff the blob was produced by the wallet's attestation key
    /// for this exact grant shape.
    ///
    /// # Errors
    ///
    /// Returns `false` (not an error) when the blob is missing or wrong.  The
    /// caller handles the refusal path.
    #[must_use]
    pub fn verify_attestation(
        &self,
        key: &[u8; 32],
        binding: &super::AttestationBinding<'_>,
    ) -> bool {
        let Some(blob_b64) = &self.attestation_blob_b64 else {
            return false;
        };
        let Ok(blob_bytes) = URL_SAFE_NO_PAD.decode(blob_b64) else {
            return false;
        };
        let Ok(blob_arr): Result<[u8; 32], _> = blob_bytes.try_into() else {
            return false;
        };
        let Some(scope) =
            AttestationScope::from_version(self.attestation_version, self.attested_lifetime())
        else {
            return false;
        };
        verify_toolset_gate_attestation(
            key,
            binding,
            &self.grant_id,
            &self.toolset_name,
            &self.install_id,
            &self.package_version,
            &self.package_shasum,
            &self.capability,
            &self.destination,
            &self.asset,
            self.amount_min_stroops,
            self.amount_max_stroops,
            &self.process_uid_at_grant,
            &scope,
            &blob_arr,
        )
    }

    /// The kind and lifetime a version 3 attestation of this grant covers.
    #[must_use]
    pub fn attested_lifetime(&self) -> AttestedLifetime<'static> {
        AttestedLifetime::new(
            TOOLSET_GRANT_KIND,
            self.granted_at_unix_ms,
            self.expires_at_unix_ms,
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// On-disk schema
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Default, Serialize, Deserialize)]
struct GrantStoreFile {
    #[serde(default)]
    grants: Vec<GrantRecord>,
}

// ─────────────────────────────────────────────────────────────────────────────
// ToolsetGrantStore
// ─────────────────────────────────────────────────────────────────────────────

/// The invocation a grant must cover to suppress the first-invoke gate.
#[derive(Debug, Clone, Copy)]
pub struct GrantQuery<'a> {
    /// Installed toolset name from the invocation.
    pub toolset_name: &'a str,
    /// Random installation identity, 32 lowercase hex characters.
    pub install_id: &'a str,
    /// Package version from the current verified pin.
    pub package_version: &'a str,
    /// SHA-256 of the package from the current verified pin, 64 lowercase hex characters.
    pub package_shasum: &'a str,
    /// Signing-adjacent capability required by the action.
    pub capability: &'a str,
    /// Canonical destination from the authoritative invocation data.
    pub destination: &'a str,
    /// Canonical asset identifier from the authoritative invocation data.
    pub asset: &'a str,
    /// Amount in stroops from the authoritative invocation data.
    pub amount_stroops: i64,
    /// Current Unix time in milliseconds for the expiry and issue-time checks.
    pub now_unix_ms: u64,
    /// Grants issued before this instant belong to an earlier installation.
    pub not_before_unix_ms: u64,
}

/// TOML-file-backed store of first-invoke grants.
///
/// Stored at `<grants_dir>/<profile>.toolset_grants.toml` with mode `0o600` on
/// Unix.  Does NOT acquire an exclusive file lock (grants are write-rarely,
/// read-often; concurrent reads are acceptable; the MCP server is single-process
/// and writes are sequentialised through the async call path).
///
/// Expired grants are pruned on each `open()` call.
///
/// A stored grant loads as written, whatever its destination. A
/// `sign-payment` grant whose destination is not a canonical G account or M
/// address is an ordinary grant that never matches an invocation.
pub struct ToolsetGrantStore {
    path: PathBuf,
    grants: Vec<ToolsetGrant>,
}

impl std::fmt::Debug for ToolsetGrantStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ToolsetGrantStore")
            .field("path", &self.path)
            .field("grant_count", &self.grants.len())
            .finish_non_exhaustive()
    }
}

impl ToolsetGrantStore {
    /// Opens the grant store at `path`.
    ///
    /// Creates the parent directory if absent.  Loads grants from the TOML
    /// file if it exists, pruning any that have already expired according to
    /// `now_unix_ms`.
    ///
    /// # Errors
    ///
    /// - [`ApprovalError::Io`] on I/O failure.
    /// - [`ApprovalError::Toml`] if the file cannot be parsed.
    pub fn open(path: PathBuf, now_unix_ms: u64) -> Result<Self, ApprovalError> {
        // Create parent directory.
        if let Some(parent) = path.parent() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt as _;
                fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(parent)
                    .map_err(ApprovalError::from_io)?;
            }
            #[cfg(not(unix))]
            {
                fs::create_dir_all(parent).map_err(ApprovalError::from_io)?;
            }
        }

        let grants = if path.exists() {
            let content = fs::read_to_string(&path).map_err(ApprovalError::from_io)?;
            let sf: GrantStoreFile = toml::from_str(&content).map_err(|e| ApprovalError::Toml {
                detail: format!(
                    "toolset grant store: {}",
                    toml_error_position(&content, e.span().map(|s| s.start))
                ),
            })?;
            // Prune expired grants on load.
            sf.grants
                .into_iter()
                .map(ToolsetGrant::stored)
                .filter(|g| !g.is_expired(now_unix_ms))
                .collect()
        } else {
            Vec::new()
        };

        Ok(Self { path, grants })
    }

    /// Returns the first verified grant covering the invocation, or `None`.
    ///
    /// The grant must use the current attestation version, verify under the
    /// supplied key and binding, and expire within the default TTL of issuance.
    /// Its issue time must meet the query's installation cutoff and must not lie
    /// after the query's current time, so a grant dated in the future never
    /// carries over to a later installation. A `sign-payment` grant whose
    /// stored destination is not a canonical G account or M address covers
    /// no destination.
    #[must_use]
    pub fn find_matching(
        &self,
        query: &GrantQuery<'_>,
        attestation_key: &[u8; 32],
        binding: &super::AttestationBinding<'_>,
    ) -> Option<&ToolsetGrant> {
        self.grants.iter().find(|g| {
            g.matches(
                query.toolset_name,
                query.install_id,
                query.package_version,
                query.package_shasum,
                query.capability,
                query.destination,
                query.asset,
                query.amount_stroops,
                query.now_unix_ms,
            ) && g.attestation_version == ATTESTATION_VERSION
                && g.verify_attestation(attestation_key, binding)
                && g.expires_at_unix_ms.saturating_sub(g.granted_at_unix_ms)
                    <= TOOLSET_GRANT_DEFAULT_TTL_MS
                && g.granted_at_unix_ms >= query.not_before_unix_ms
                && g.granted_at_unix_ms <= query.now_unix_ms
        })
    }

    /// Inserts a new `ToolsetGrant` and persists the store.
    ///
    /// Does not check for duplicate `(toolset, capability, destination, asset,
    /// bucket)` — deduplication is the caller's responsibility.  Calling
    /// `revoke_toolset` before `insert` prevents accumulation of redundant
    /// grants for the same toolset.
    ///
    /// # Errors
    ///
    /// - [`ApprovalError::InvalidEntry`] if a `sign-payment` grant names a
    ///   destination other than a canonical G account or M address.
    /// - [`ApprovalError::Io`] / [`ApprovalError::Toml`] on persistence failure.
    pub fn insert(&mut self, grant: ToolsetGrant) -> Result<(), ApprovalError> {
        check_grant_destination(&grant.capability, &grant.destination)
            .map_err(|detail| ApprovalError::InvalidEntry { detail })?;
        self.grants.push(grant);
        self.persist()
    }

    /// Removes all grants for the given `toolset_name`.
    ///
    /// Returns the number of grants removed.
    ///
    /// # Errors
    ///
    /// - [`ApprovalError::Io`] / [`ApprovalError::Toml`] on persistence failure.
    pub fn revoke_toolset(&mut self, toolset_name: &str) -> Result<usize, ApprovalError> {
        let before = self.grants.len();
        self.grants.retain(|g| g.toolset_name != toolset_name);
        let removed = before - self.grants.len();
        if removed > 0 {
            self.persist()?;
        }
        Ok(removed)
    }

    /// Removes every toolset grant and returns the number removed.
    ///
    /// # Errors
    /// Returns an approval-store error if persistence fails.
    pub fn revoke_all(&mut self) -> Result<usize, ApprovalError> {
        let removed = self.grants.len();
        if removed > 0 {
            self.grants.clear();
            self.persist()?;
        }
        Ok(removed)
    }

    /// Returns the number of grants currently in the store.
    #[must_use]
    pub fn len(&self) -> usize {
        self.grants.len()
    }

    /// Returns `true` if the store contains no grants.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.grants.is_empty()
    }

    /// Persists the grant store atomically via tempfile + rename.
    fn persist(&self) -> Result<(), ApprovalError> {
        let file_content = toml::to_string_pretty(&GrantStoreFile {
            grants: self.grants.iter().cloned().map(GrantRecord::from).collect(),
        })
        .map_err(|e| ApprovalError::Toml {
            detail: format!("toolset_grant_store: serialize error: {e}"),
        })?;

        let parent = self.path.parent().unwrap_or_else(|| Path::new("."));
        let mut tmp = tempfile::NamedTempFile::new_in(parent).map_err(ApprovalError::from_io)?;

        use std::io::Write as _;
        tmp.write_all(file_content.as_bytes())
            .map_err(ApprovalError::from_io)?;
        tmp.flush().map_err(ApprovalError::from_io)?;
        // Durable content before rename: `flush` only empties the userspace
        // buffer; the rename must never publish a file whose bytes are not
        // yet on stable storage.
        tmp.as_file().sync_data().map_err(ApprovalError::from_io)?;

        // Set file permissions to 0o600 on Unix before rename.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o600))
                .map_err(ApprovalError::from_io)?;
        }

        tmp.persist(&self.path)
            .map_err(|e| ApprovalError::from_io(e.error))?;

        // fsync parent directory to commit the directory entry. Opening a
        // directory path via `std::fs::File::open` requires
        // `FILE_FLAG_BACKUP_SEMANTICS` on Windows (which the stable API does
        // not set) and fails with `ERROR_ACCESS_DENIED`; POSIX has no such
        // restriction. Skip on non-Unix — NTFS journals directory-entry
        // metadata itself, and a crash losing the last grant write only means
        // the operator re-approves the first-invoke gate once more.
        #[cfg(unix)]
        fs::File::open(parent)
            .and_then(|f| f.sync_all())
            .map_err(ApprovalError::from_io)?;

        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Grant construction helper
// ─────────────────────────────────────────────────────────────────────────────

/// Checks that a first-invoke request names a complete installation and a
/// destination its capability admits.
///
/// # Errors
///
/// Returns `approval.entry_inconsistent` when the installation fields are absent
/// or malformed, or when a `sign-payment` destination is not a canonical G
/// account or M address. Other approval kinds pass unchanged.
pub fn verify_toolset_gate_entry_terms(
    kind: &super::ApprovalKind,
) -> Result<(), crate::error::WalletError> {
    let super::ApprovalKind::ToolsetFirstInvokeGate {
        install_id,
        package_version,
        package_shasum,
        capability,
        destination,
        ..
    } = kind
    else {
        return Ok(());
    };
    check_grant_destination(capability, destination)
        .map_err(|reason| super::inconsistent(&reason))?;
    let lower_hex = |value: &str, len: usize| {
        value.len() == len
            && value
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    };
    if !lower_hex(install_id, 32)
        || !(1..=64).contains(&package_version.len())
        || !lower_hex(package_shasum, 64)
    {
        return Err(super::inconsistent(
            "it names no installation; invoke the toolset again to request approval",
        ));
    }
    Ok(())
}

/// Constructs and HMAC-attests a new [`ToolsetGrant`] from a confirmed
/// `ToolsetFirstInvokeGate` approval.
///
/// The `attestation_key` is loaded by the caller from the platform keyring
/// (the same key used for `PaymentSimulated` attestation).  The caller wraps
/// it in `Zeroizing<[u8; 32]>` and passes `&*key`.
///
/// # Parameters
///
/// - `toolset_name`: package name of the toolset.
/// - `install_id`: random identity of the approved installation.
/// - `package_version`: approved package version.
/// - `package_shasum`: approved package SHA-256.
/// - `capability`: capability token (e.g. `"sign-payment"`).
/// - `destination`: the destination as approved; a canonical G account or M
///   address for `sign-payment`.
/// - `asset`: canonical asset identifier.
/// - `amount_min_stroops`: bucket lower bound.
/// - `amount_max_stroops`: bucket upper bound.
/// - `process_uid`: from `process_uid_for_attestation()`.
/// - `now_unix_ms`: current time from the system clock.
/// - `ttl_ms`: grant TTL (use [`TOOLSET_GRANT_DEFAULT_TTL_MS`]).
/// - `attestation_key`: 32-byte HMAC key from the platform keyring.
///
/// # Errors
///
/// Returns [`ApprovalError::InvalidEntry`] when a `sign-payment` destination
/// is not a canonical G account or M address.
#[allow(clippy::too_many_arguments)]
pub fn build_attested_grant(
    toolset_name: String,
    install_id: String,
    package_version: String,
    package_shasum: String,
    capability: String,
    destination: String,
    asset: String,
    amount_min_stroops: i64,
    amount_max_stroops: i64,
    process_uid: String,
    now_unix_ms: u64,
    ttl_ms: u64,
    attestation_key: &[u8; 32],
    binding: &super::AttestationBinding<'_>,
) -> Result<ToolsetGrant, ApprovalError> {
    check_grant_destination(&capability, &destination)
        .map_err(|detail| ApprovalError::InvalidEntry { detail })?;
    // Generate a random grant_id.
    let mut raw = [0u8; 16];
    OsRng.fill_bytes(&mut raw);
    let grant_id = URL_SAFE_NO_PAD.encode(raw);

    let expires_at_unix_ms = now_unix_ms.saturating_add(ttl_ms);

    // Compute the digest for this grant shape.
    let digest = compute_toolset_gate_digest(
        &toolset_name,
        &install_id,
        &package_version,
        &package_shasum,
        &capability,
        &destination,
        &asset,
        amount_min_stroops,
        amount_max_stroops,
    );

    // Compute the HMAC attestation blob over the grant's kind and lifetime.
    let attestation_blob = compute_attestation(
        attestation_key,
        binding,
        &grant_id,
        &digest,
        &process_uid,
        &AttestedLifetime::new(TOOLSET_GRANT_KIND, now_unix_ms, expires_at_unix_ms),
    );
    let attestation_blob_b64 = URL_SAFE_NO_PAD.encode(attestation_blob);

    Ok(ToolsetGrant {
        grant_id,
        toolset_name,
        install_id,
        package_version,
        package_shasum,
        capability,
        destination,
        asset,
        amount_min_stroops,
        amount_max_stroops,
        granted_at_unix_ms: now_unix_ms,
        expires_at_unix_ms,
        attestation_blob_b64: Some(attestation_blob_b64),
        process_uid_at_grant: process_uid,
        attestation_version: ATTESTATION_VERSION,
    })
}

/// Returns the default path for the toolset grant store.
///
/// Stored at `<grants_dir>/<profile>.toolset_grants.toml` inside the
/// profile's approval directory.
///
/// # Errors
///
/// - [`ApprovalError::Io`] if the approval directory cannot be resolved.
pub fn default_toolset_grants_path(profile_name: &str) -> Result<PathBuf, ApprovalError> {
    let dir = crate::profile::schema::default_approval_dir().map_err(|e| {
        ApprovalError::from_io_detail(
            std::io::ErrorKind::Other,
            format!("toolset_grants_path: {e}"),
        )
    })?;
    Ok(dir.join(format!("{profile_name}.toolset_grants.toml")))
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics acceptable in unit tests"
)]
mod tests {
    use super::*;
    use crate::approval::attestation::compute_toolset_gate_digest;

    /// The G account of the key `[1; 32]`.
    const DEST_G: &str = "GAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQDZ7H";
    /// M addresses of [`DEST_G`] with IDs zero, seven, and `u64::MAX`.
    const DEST_M0: &str = "MAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAAAAAAAAAAAABAXI";
    const DEST_M7: &str = "MAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAAAAAAAAAAAA6TAI";
    const DEST_MMAX: &str = "MAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQD7777777777776QNE";
    /// The G account of the key `[2; 32]` and its M address with ID `u64::MAX`.
    const OTHER_G: &str = "GABAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEJXA";
    const OTHER_MMAX: &str =
        "MABAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAF7777777777777GNW";
    const NOW_MS: u64 = 1_750_000_000_000;

    fn make_grant(
        toolset: &str,
        cap: &str,
        min: i64,
        max: i64,
        ttl: u64,
        key: &[u8; 32],
    ) -> ToolsetGrant {
        build_attested_grant(
            toolset.to_owned(),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            "1.0.0".to_owned(),
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".to_owned(),
            cap.to_owned(),
            DEST_G.to_owned(),
            "XLM".to_owned(),
            min,
            max,
            "1000".to_owned(),
            NOW_MS,
            ttl,
            key,
            &crate::approval::AttestationBinding::new("default", "stellar:testnet"),
        )
        .unwrap()
    }

    fn test_query() -> GrantQuery<'static> {
        GrantQuery {
            toolset_name: "my-toolset",
            install_id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            package_version: "1.0.0",
            package_shasum: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            capability: "sign-payment",
            destination: DEST_G,
            asset: "XLM",
            amount_stroops: 5,
            now_unix_ms: NOW_MS,
            not_before_unix_ms: 0,
        }
    }

    fn store_with_grant(dir: &tempfile::TempDir, grant: ToolsetGrant) -> ToolsetGrantStore {
        let path = dir.path().join("default.toolset_grants.toml");
        let mut store = ToolsetGrantStore::open(path, NOW_MS).unwrap();
        store.insert(grant).unwrap();
        store
    }

    /// `grant` re-attested under the version 2 layout, which binds the
    /// profile, chain, grant id, gate digest and user identity but neither the
    /// kind nor the lifetime.
    fn version_2_grant(
        grant: &ToolsetGrant,
        key: &[u8; 32],
        binding: &crate::approval::AttestationBinding<'_>,
    ) -> ToolsetGrant {
        use hmac::{Hmac, KeyInit as _, Mac as _};
        let digest = compute_toolset_gate_digest(
            &grant.toolset_name,
            &grant.install_id,
            &grant.package_version,
            &grant.package_shasum,
            &grant.capability,
            &grant.destination,
            &grant.asset,
            grant.amount_min_stroops,
            grant.amount_max_stroops,
        );
        let mut mac = Hmac::<sha2::Sha256>::new_from_slice(key).unwrap();
        mac.update(b"stellar-agent-approval-attestation:v2");
        for field in [
            binding.profile_name.as_bytes(),
            binding.chain_id.as_bytes(),
            grant.grant_id.as_bytes(),
        ] {
            mac.update(&u32::try_from(field.len()).unwrap().to_be_bytes());
            mac.update(field);
        }
        mac.update(&digest);
        let uid = grant.process_uid_at_grant.as_bytes();
        mac.update(&u32::try_from(uid.len()).unwrap().to_be_bytes());
        mac.update(uid);
        let mut legacy = grant.clone();
        legacy.attestation_blob_b64 = Some(URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()));
        legacy.attestation_version = ATTESTATION_VERSION_V2;
        legacy
    }

    #[test]
    fn find_matching_ignores_a_grant_without_a_valid_attestation() {
        let key = [0x42; 32];
        let binding = crate::approval::AttestationBinding::new("default", "stellar:testnet");
        let valid = make_grant("my-toolset", "sign-payment", 0, 10, 86_400_000, &key);
        let valid_control = valid.clone();
        let mut missing = valid.clone();
        missing.attestation_blob_b64 = None;
        let mut random = valid;
        random.attestation_blob_b64 = Some(URL_SAFE_NO_PAD.encode([0xa5; 32]));
        let wrong_key = make_grant("my-toolset", "sign-payment", 0, 10, 86_400_000, &[0x24; 32]);
        for grant in [missing, random, wrong_key] {
            let dir = tempfile::TempDir::new().unwrap();
            let store = store_with_grant(&dir, grant);
            assert!(store.find_matching(&test_query(), &key, &binding).is_none());
        }
        let dir = tempfile::TempDir::new().unwrap();
        let store = store_with_grant(&dir, valid_control);
        assert!(store.find_matching(&test_query(), &key, &binding).is_some());
    }

    #[test]
    fn find_matching_ignores_an_edited_lifetime() {
        let key = [0x42; 32];
        let binding = crate::approval::AttestationBinding::new("default", "stellar:testnet");
        let grant = make_grant("my-toolset", "sign-payment", 0, 10, 86_400_000, &key);
        let mut edited = grant.clone();
        edited.expires_at_unix_ms += 1;
        let dir = tempfile::TempDir::new().unwrap();
        let store = store_with_grant(&dir, edited);
        assert!(store.find_matching(&test_query(), &key, &binding).is_none());
        let dir = tempfile::TempDir::new().unwrap();
        let store = store_with_grant(&dir, grant);
        assert!(store.find_matching(&test_query(), &key, &binding).is_some());
    }

    #[test]
    fn find_matching_ignores_a_version_2_grant() {
        let key = [0x42; 32];
        let binding = crate::approval::AttestationBinding::new("default", "stellar:testnet");
        let grant = make_grant("my-toolset", "sign-payment", 0, 10, 86_400_000, &key);
        let legacy = version_2_grant(&grant, &key, &binding);
        assert!(legacy.verify_attestation(&key, &binding));
        let dir = tempfile::TempDir::new().unwrap();
        let store = store_with_grant(&dir, legacy);
        assert!(store.find_matching(&test_query(), &key, &binding).is_none());
        let dir = tempfile::TempDir::new().unwrap();
        let store = store_with_grant(&dir, grant);
        assert!(store.find_matching(&test_query(), &key, &binding).is_some());
    }

    #[test]
    fn find_matching_ignores_another_binding() {
        let key = [0x42; 32];
        let grant = make_grant("my-toolset", "sign-payment", 0, 10, 86_400_000, &key);
        let dir = tempfile::TempDir::new().unwrap();
        let store = store_with_grant(&dir, grant);
        for binding in [
            crate::approval::AttestationBinding::new("other", "stellar:testnet"),
            crate::approval::AttestationBinding::new("default", "stellar:pubnet"),
        ] {
            assert!(store.find_matching(&test_query(), &key, &binding).is_none());
        }
        let own = crate::approval::AttestationBinding::new("default", "stellar:testnet");
        assert!(store.find_matching(&test_query(), &key, &own).is_some());
    }

    #[test]
    fn find_matching_ignores_a_lifetime_beyond_the_default_ttl() {
        let key = [0x42; 32];
        let binding = crate::approval::AttestationBinding::new("default", "stellar:testnet");
        let grant = make_grant(
            "my-toolset",
            "sign-payment",
            0,
            10,
            TOOLSET_GRANT_DEFAULT_TTL_MS + 1,
            &key,
        );
        assert!(grant.verify_attestation(&key, &binding));
        let dir = tempfile::TempDir::new().unwrap();
        let store = store_with_grant(&dir, grant);
        assert!(store.find_matching(&test_query(), &key, &binding).is_none());
        let default_ttl = make_grant(
            "my-toolset",
            "sign-payment",
            0,
            10,
            TOOLSET_GRANT_DEFAULT_TTL_MS,
            &key,
        );
        let dir = tempfile::TempDir::new().unwrap();
        let store = store_with_grant(&dir, default_ttl);
        assert!(store.find_matching(&test_query(), &key, &binding).is_some());
    }

    #[test]
    fn find_matching_ignores_a_grant_issued_before_the_install() {
        let key = [0x42; 32];
        let binding = crate::approval::AttestationBinding::new("default", "stellar:testnet");
        let grant = make_grant("my-toolset", "sign-payment", 0, 10, 86_400_000, &key);
        let dir = tempfile::TempDir::new().unwrap();
        let store = store_with_grant(&dir, grant);
        let mut query = test_query();
        query.not_before_unix_ms = NOW_MS + 1;
        assert!(store.find_matching(&query, &key, &binding).is_none());
        query.not_before_unix_ms = NOW_MS;
        assert!(store.find_matching(&query, &key, &binding).is_some());
    }

    #[test]
    fn find_matching_ignores_a_grant_dated_in_the_future() {
        let key = [0x42; 32];
        let binding = crate::approval::AttestationBinding::new("default", "stellar:testnet");
        let grant = make_grant("my-toolset", "sign-payment", 0, 10, 86_400_000, &key);
        let dir = tempfile::TempDir::new().unwrap();
        let store = store_with_grant(&dir, grant);
        let mut query = test_query();
        query.now_unix_ms = NOW_MS - 1;
        assert!(store.find_matching(&query, &key, &binding).is_none());
        query.now_unix_ms = NOW_MS;
        assert!(store.find_matching(&query, &key, &binding).is_some());
    }

    #[test]
    fn find_matching_finds_a_valid_grant_behind_a_forged_one() {
        let key = [0x42; 32];
        let binding = crate::approval::AttestationBinding::new("default", "stellar:testnet");
        let valid = make_grant("my-toolset", "sign-payment", 0, 10, 86_400_000, &key);
        let mut forged = make_grant("my-toolset", "sign-payment", 0, 10, 86_400_000, &[0x24; 32]);
        forged.attestation_blob_b64 = None;
        let dir = tempfile::TempDir::new().unwrap();
        let mut store = store_with_grant(&dir, forged);
        store.insert(valid.clone()).unwrap();
        let found = store
            .find_matching(&test_query(), &key, &binding)
            .expect("the valid grant behind the forged one matches");
        assert_eq!(found.grant_id, valid.grant_id);
    }

    #[test]
    fn open_parse_error_names_the_position_only() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("grants.toml");
        let blob = "Q".repeat(43);
        fs::write(
            &path,
            format!("[[grants]]\ngrant_id = \"test\"\nattestation_blob_b64 = \"{blob}"),
        )
        .unwrap();
        let err = ToolsetGrantStore::open(path, NOW_MS).unwrap_err();
        assert!(matches!(err, ApprovalError::Toml { .. }));
        let rendered = err.to_string();
        assert!(
            rendered.contains("toolset grant store: TOML parse error at line 3"),
            "{rendered}"
        );
        assert!(!rendered.contains(&blob), "{rendered}");
        assert!(!rendered.contains("attestation_blob_b64"), "{rendered}");
    }

    // ── ToolsetGrant::matches ──────────────────────────────────────────────────

    #[test]
    fn grant_matches_within_bucket() {
        let key = [0x42u8; 32];
        let grant = make_grant(
            "my-toolset",
            "sign-payment",
            0,
            10_000_000,
            86_400_000,
            &key,
        );
        assert!(grant.matches(
            "my-toolset",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "1.0.0",
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "sign-payment",
            DEST_G,
            "XLM",
            5_000_000,
            NOW_MS
        ));
    }

    #[test]
    fn grant_matches_at_bucket_boundary() {
        let key = [0x42u8; 32];
        let grant = make_grant(
            "my-toolset",
            "sign-payment",
            0,
            10_000_000,
            86_400_000,
            &key,
        );
        // At min.
        assert!(grant.matches(
            "my-toolset",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "1.0.0",
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "sign-payment",
            DEST_G,
            "XLM",
            0,
            NOW_MS
        ));
        // At max.
        assert!(grant.matches(
            "my-toolset",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "1.0.0",
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "sign-payment",
            DEST_G,
            "XLM",
            10_000_000,
            NOW_MS
        ));
    }

    #[test]
    fn grant_does_not_match_amount_exceed() {
        let key = [0x42u8; 32];
        let grant = make_grant(
            "my-toolset",
            "sign-payment",
            0,
            10_000_000,
            86_400_000,
            &key,
        );
        assert!(!grant.matches(
            "my-toolset",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "1.0.0",
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "sign-payment",
            DEST_G,
            "XLM",
            10_000_001, // exceeds max
            NOW_MS
        ));
    }

    #[test]
    fn grant_does_not_match_wrong_toolset() {
        let key = [0x42u8; 32];
        let grant = make_grant(
            "my-toolset",
            "sign-payment",
            0,
            10_000_000,
            86_400_000,
            &key,
        );
        assert!(!grant.matches(
            "other-toolset",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "1.0.0",
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "sign-payment",
            DEST_G,
            "XLM",
            1_000,
            NOW_MS
        ));
    }

    #[test]
    fn grant_does_not_match_wrong_destination() {
        let key = [0x42u8; 32];
        let grant = make_grant(
            "my-toolset",
            "sign-payment",
            0,
            10_000_000,
            86_400_000,
            &key,
        );
        // Another account, one of its M addresses, and malformed text.
        for other_dest in [
            OTHER_G,
            OTHER_MMAX,
            "GBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
        ] {
            assert!(
                !grant.matches(
                    "my-toolset",
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "1.0.0",
                    "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                    "sign-payment",
                    other_dest,
                    "XLM",
                    1_000,
                    NOW_MS
                ),
                "{other_dest}"
            );
        }
    }

    #[test]
    fn grant_does_not_match_wrong_asset() {
        let key = [0x42u8; 32];
        let grant = make_grant(
            "my-toolset",
            "sign-payment",
            0,
            10_000_000,
            86_400_000,
            &key,
        );
        assert!(!grant.matches(
            "my-toolset",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "1.0.0",
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "sign-payment",
            DEST_G,
            "USDC:Gxxxx",
            1_000,
            NOW_MS
        ));
    }

    /// Asserts that a grant found by `test_query()` is not found by `query`,
    /// which differs from `test_query()` in one field.
    fn assert_grant_misses(query: &GrantQuery<'_>) {
        let key = [0x42; 32];
        let binding = crate::approval::AttestationBinding::new("default", "stellar:testnet");
        let dir = tempfile::TempDir::new().unwrap();
        let store = store_with_grant(
            &dir,
            make_grant("my-toolset", "sign-payment", 0, 10, 86_400_000, &key),
        );
        assert!(store.find_matching(&test_query(), &key, &binding).is_some());
        assert!(store.find_matching(query, &key, &binding).is_none());
    }

    #[test]
    fn grant_does_not_match_other_package_version() {
        assert_grant_misses(&GrantQuery {
            package_version: "1.0.1",
            ..test_query()
        });
    }

    #[test]
    fn grant_does_not_match_other_package_shasum() {
        assert_grant_misses(&GrantQuery {
            package_shasum: "eddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            ..test_query()
        });
    }

    // ── ToolsetGrant::is_expired ───────────────────────────────────────────────

    #[test]
    fn grant_expired_when_past_expiry() {
        let key = [0x42u8; 32];
        let grant = make_grant("my-toolset", "sign-payment", 0, 10_000_000, 1_000, &key); // 1s TTL
        let expired_now = NOW_MS + 2_000;
        assert!(grant.is_expired(expired_now));
    }

    #[test]
    fn grant_not_expired_before_expiry() {
        let key = [0x42u8; 32];
        let grant = make_grant(
            "my-toolset",
            "sign-payment",
            0,
            10_000_000,
            86_400_000,
            &key,
        );
        assert!(!grant.is_expired(NOW_MS));
    }

    // ── ToolsetGrant::verify_attestation ───────────────────────────────────────

    #[test]
    fn grant_attestation_verifies_correctly() {
        let key = [0x55u8; 32];
        let grant = make_grant(
            "my-toolset",
            "sign-payment",
            0,
            10_000_000,
            86_400_000,
            &key,
        );
        assert!(
            grant.verify_attestation(
                &key,
                &crate::approval::AttestationBinding::new("default", "stellar:testnet")
            ),
            "attestation must verify"
        );
    }

    #[test]
    fn grant_attestation_fails_with_wrong_key() {
        let key = [0x55u8; 32];
        let wrong_key = [0x66u8; 32];
        let grant = make_grant(
            "my-toolset",
            "sign-payment",
            0,
            10_000_000,
            86_400_000,
            &key,
        );
        assert!(
            !grant.verify_attestation(
                &wrong_key,
                &crate::approval::AttestationBinding::new("default", "stellar:testnet")
            ),
            "wrong key must fail"
        );
    }

    #[test]
    fn grant_attestation_fails_when_missing() {
        let key = [0x55u8; 32];
        let mut grant = make_grant(
            "my-toolset",
            "sign-payment",
            0,
            10_000_000,
            86_400_000,
            &key,
        );
        grant.attestation_blob_b64 = None;
        assert!(
            !grant.verify_attestation(
                &key,
                &crate::approval::AttestationBinding::new("default", "stellar:testnet")
            ),
            "missing attestation must fail"
        );
    }

    // ── ToolsetGrantStore: insert + find_matching ──────────────────────────────

    #[test]
    fn store_insert_and_find_matching() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("default.toolset_grants.toml");
        let mut store = ToolsetGrantStore::open(path.clone(), NOW_MS).unwrap();
        assert!(store.is_empty());

        let key = [0x42u8; 32];
        let grant = make_grant(
            "test-toolset",
            "sign-payment",
            0,
            10_000_000,
            86_400_000,
            &key,
        );
        store.insert(grant).unwrap();
        assert_eq!(store.len(), 1);

        // Should find the matching grant.
        let found = store.find_matching(
            &GrantQuery {
                toolset_name: "test-toolset",
                amount_stroops: 5_000_000,
                ..test_query()
            },
            &key,
            &crate::approval::AttestationBinding::new("default", "stellar:testnet"),
        );
        assert!(found.is_some(), "should find matching grant");
    }

    /// Windows regression: `persist()` (invoked by `insert`) must succeed
    /// across repeated rename cycles in the same process. Each call renames a
    /// fresh temp file over the store path, then (Unix-only) fsyncs the
    /// parent directory; on Windows that step is skipped entirely rather than
    /// opening the directory as a file. A regression that re-enables an
    /// unconditional directory-open would fail here on `windows-storage` CI
    /// even though it passes on every POSIX runner.
    #[test]
    fn persist_succeeds_across_repeated_inserts() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("default.toolset_grants.toml");
        let mut store = ToolsetGrantStore::open(path.clone(), NOW_MS).unwrap();
        let key = [0x42u8; 32];
        for i in 0..5u32 {
            let grant = make_grant(
                &format!("test-toolset-{i}"),
                "sign-payment",
                0,
                10_000_000,
                86_400_000,
                &key,
            );
            store.insert(grant).unwrap();
        }
        assert_eq!(store.len(), 5);
        drop(store);

        let reopened = ToolsetGrantStore::open(path, NOW_MS).unwrap();
        assert_eq!(reopened.len(), 5, "all five persisted grants must reload");
    }

    #[test]
    fn store_revoke_toolset_removes_grants() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("default.toolset_grants.toml");
        let mut store = ToolsetGrantStore::open(path.clone(), NOW_MS).unwrap();

        let key = [0x42u8; 32];
        let g1 = make_grant("toolset-a", "sign-payment", 0, 10_000_000, 86_400_000, &key);
        let g2 = make_grant("toolset-b", "sign-payment", 0, 10_000_000, 86_400_000, &key);
        store.insert(g1).unwrap();
        store.insert(g2).unwrap();
        assert_eq!(store.len(), 2);

        let removed = store.revoke_toolset("toolset-a").unwrap();
        assert_eq!(removed, 1);
        assert_eq!(store.len(), 1);

        // toolset-a is gone; toolset-b remains.
        let found_a = store.find_matching(
            &GrantQuery {
                toolset_name: "toolset-a",
                amount_stroops: 5_000_000,
                ..test_query()
            },
            &key,
            &crate::approval::AttestationBinding::new("default", "stellar:testnet"),
        );
        assert!(found_a.is_none(), "toolset-a grant must be revoked");

        let found_b = store.find_matching(
            &GrantQuery {
                toolset_name: "toolset-b",
                amount_stroops: 5_000_000,
                ..test_query()
            },
            &key,
            &crate::approval::AttestationBinding::new("default", "stellar:testnet"),
        );
        assert!(found_b.is_some(), "toolset-b grant must still exist");
    }

    // ── Grant-store-empty-after-install invariant ─────────────────────────────

    #[test]
    fn grant_store_empty_for_fresh_toolset() {
        // A fresh install has no grants; the first invoke must always hit the gate.
        // This test verifies find_matching returns None for a toolset not in the store.
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("default.toolset_grants.toml");
        let store = ToolsetGrantStore::open(path, NOW_MS).unwrap();

        let found = store.find_matching(
            &GrantQuery {
                toolset_name: "fresh-toolset",
                amount_stroops: 1_000_000,
                ..test_query()
            },
            &[0x42; 32],
            &crate::approval::AttestationBinding::new("default", "stellar:testnet"),
        );
        assert!(
            found.is_none(),
            "no grant exists for fresh-toolset — first invoke must hit the gate"
        );
    }

    // ── Adversarial bucketing: sub-bucket re-use should not bypass ───────────

    #[test]
    fn grant_does_not_match_amount_below_min() {
        let key = [0x42u8; 32];
        // Grant bucket is 1_000_000 – 10_000_000 stroops.
        let grant = make_grant(
            "my-toolset",
            "sign-payment",
            1_000_000,
            10_000_000,
            86_400_000,
            &key,
        );
        // Amount below min does NOT match.
        assert!(!grant.matches(
            "my-toolset",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "1.0.0",
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "sign-payment",
            DEST_G,
            "XLM",
            999_999,
            NOW_MS
        ));
    }

    // ── build_attested_grant KAT: same key+params → deterministic attestation ─

    #[test]
    fn build_attested_grant_attestation_is_verifiable() {
        let key = [0x99u8; 32];
        let grant = build_attested_grant(
            "my-toolset".to_owned(),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            "1.0.0".to_owned(),
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".to_owned(),
            "sign-payment".to_owned(),
            DEST_G.to_owned(),
            "XLM".to_owned(),
            0,
            5_000_000,
            "501".to_owned(),
            NOW_MS,
            TOOLSET_GRANT_DEFAULT_TTL_MS,
            &key,
            &crate::approval::AttestationBinding::new("grant-profile", "stellar:mainnet"),
        )
        .unwrap();

        // The attestation must pass with the correct key.
        assert!(grant.verify_attestation(
            &key,
            &crate::approval::AttestationBinding::new("grant-profile", "stellar:mainnet")
        ));

        assert!(!grant.verify_attestation(
            &key,
            &crate::approval::AttestationBinding::new("other", "stellar:mainnet")
        ));
        assert!(!grant.verify_attestation(
            &key,
            &crate::approval::AttestationBinding::new("grant-profile", "stellar:testnet")
        ));
        // The grant must not be expired immediately after creation.
        assert!(!grant.is_expired(NOW_MS));
        assert!(grant.is_expired(NOW_MS + TOOLSET_GRANT_DEFAULT_TTL_MS + 1));
    }

    // ── Digest KAT: compute_toolset_gate_digest in the grant path ─────────────

    #[test]
    fn build_attested_grant_digest_uses_correct_fields() {
        // The attestation binds the grant_id + digest + process_uid.
        // We can reconstruct the digest independently and verify HMAC.
        let key = [0xabu8; 32];
        let grant = build_attested_grant(
            "verified-toolset".to_owned(),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            "1.0.0".to_owned(),
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".to_owned(),
            "sign-payment".to_owned(),
            DEST_G.to_owned(),
            "XLM".to_owned(),
            0,
            2_000_000,
            "1234".to_owned(),
            NOW_MS,
            86_400_000,
            &key,
            &crate::approval::AttestationBinding::new("default", "stellar:testnet"),
        )
        .unwrap();

        // Independently compute the expected digest.
        let expected_digest = compute_toolset_gate_digest(
            "verified-toolset",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "1.0.0",
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "sign-payment",
            DEST_G,
            "XLM",
            0,
            2_000_000,
        );

        // Decode the stored attestation blob.
        let blob_b64 = grant.attestation_blob_b64.as_ref().unwrap();
        let blob_bytes: [u8; 32] = URL_SAFE_NO_PAD
            .decode(blob_b64)
            .unwrap()
            .try_into()
            .unwrap();

        // Verify the HMAC directly.
        let ok = crate::approval::attestation::verify_attestation(
            &key,
            &crate::approval::AttestationBinding::new("default", "stellar:testnet"),
            &grant.grant_id,
            &expected_digest,
            "1234",
            &AttestationScope::V3(AttestedLifetime::new(
                TOOLSET_GRANT_KIND,
                NOW_MS,
                NOW_MS + 86_400_000,
            )),
            &blob_bytes,
        );
        assert!(
            ok,
            "independently-computed digest must match stored attestation"
        );
    }

    /// A grant attests at version 3; a stretched expiry fails, and a grant
    /// stored at version 2 without the field still verifies under its own
    /// layout.
    #[test]
    fn grant_attestation_binds_its_lifetime_and_reads_version_2() {
        let key = [0x42u8; 32];
        let binding = crate::approval::AttestationBinding::new("default", "stellar:testnet");
        let grant = make_grant("my-toolset", "sign-payment", 0, 10, 86_400_000, &key);
        assert_eq!(grant.attestation_version, ATTESTATION_VERSION);
        assert!(grant.verify_attestation(&key, &binding));
        let mut stretched = grant.clone();
        stretched.expires_at_unix_ms += 1;
        assert!(!stretched.verify_attestation(&key, &binding));

        let mut legacy = version_2_grant(&grant, &key, &binding);
        assert!(legacy.verify_attestation(&key, &binding));
        let mut text = toml::to_string(&legacy).unwrap();
        text = text
            .lines()
            .filter(|line| !line.starts_with("attestation_version"))
            .collect::<Vec<_>>()
            .join("\n");
        let reread: ToolsetGrant = toml::from_str(&text).unwrap();
        assert_eq!(reread.attestation_version, ATTESTATION_VERSION_V2);
        assert!(reread.verify_attestation(&key, &binding));
        legacy.attestation_version = ATTESTATION_VERSION;
        assert!(!legacy.verify_attestation(&key, &binding));
    }

    #[test]
    fn a_grant_without_an_install_identity_never_matches() {
        let grant = make_grant("my-toolset", "sign-payment", 0, 10, 60_000, &[7; 32]);
        let mut stored = toml::Value::try_from(&grant).unwrap();
        for field in ["install_id", "package_version", "package_shasum"] {
            stored.as_table_mut().unwrap().remove(field);
        }
        let mut legacy: ToolsetGrant = stored.try_into().unwrap();
        // Retain package terms to isolate the install identity comparison.
        legacy.package_version.clone_from(&grant.package_version);
        legacy.package_shasum.clone_from(&grant.package_shasum);
        assert!(!legacy.matches(
            &grant.toolset_name,
            &grant.install_id,
            &grant.package_version,
            &grant.package_shasum,
            &grant.capability,
            &grant.destination,
            &grant.asset,
            5,
            NOW_MS
        ));
        let dir = tempfile::TempDir::new().unwrap();
        let store = store_with_grant(&dir, legacy);
        assert!(
            store
                .find_matching(
                    &test_query(),
                    &[7; 32],
                    &crate::approval::AttestationBinding::new("default", "stellar:testnet")
                )
                .is_none()
        );
    }

    const KEY: [u8; 32] = [0x42; 32];

    fn binding() -> crate::approval::AttestationBinding<'static> {
        crate::approval::AttestationBinding::new("default", "stellar:testnet")
    }

    /// A grant of the bucket `[2, 10]` to `destination` under [`KEY`].
    fn grant_to(capability: &str, destination: &str) -> Result<ToolsetGrant, ApprovalError> {
        build_attested_grant(
            "my-toolset".to_owned(),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            "1.0.0".to_owned(),
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".to_owned(),
            capability.to_owned(),
            destination.to_owned(),
            "XLM".to_owned(),
            2,
            10,
            "1000".to_owned(),
            NOW_MS,
            86_400_000,
            &KEY,
            &binding(),
        )
    }

    fn found(store: &ToolsetGrantStore, destination: &str) -> bool {
        let query = GrantQuery {
            destination,
            ..test_query()
        };
        store.find_matching(&query, &KEY, &binding()).is_some()
    }

    #[test]
    fn a_g_grant_covers_its_m_addresses() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = store_with_grant(&dir, grant_to("sign-payment", DEST_G).unwrap());
        for destination in [DEST_G, DEST_M0, DEST_M7, DEST_MMAX] {
            assert!(found(&store, destination), "{destination}");
        }
        for destination in [OTHER_G, OTHER_MMAX] {
            assert!(!found(&store, destination), "{destination}");
        }
    }

    #[test]
    fn an_m_grant_covers_only_its_complete_address() {
        for (granted, others) in [
            (DEST_M7, [DEST_G, DEST_M0, DEST_MMAX, OTHER_MMAX]),
            (DEST_M0, [DEST_G, DEST_M7, DEST_MMAX, OTHER_G]),
            (DEST_MMAX, [DEST_G, DEST_M0, DEST_M7, OTHER_MMAX]),
        ] {
            let dir = tempfile::TempDir::new().unwrap();
            let store = store_with_grant(&dir, grant_to("sign-payment", granted).unwrap());
            assert!(found(&store, granted), "{granted}");
            for other in others {
                assert!(!found(&store, other), "{granted} covers {other}");
            }
        }
    }

    /// Each query differs from a covered M payment in one non-destination
    /// term, and each misses.
    #[test]
    fn every_non_destination_constraint_refuses_a_covered_m_payment() {
        let dir = tempfile::TempDir::new().unwrap();
        let grant = grant_to("sign-payment", DEST_G).unwrap();
        let mut unattested = grant.clone();
        unattested.attestation_blob_b64 = None;
        let store = store_with_grant(&dir, grant);
        let covered = GrantQuery {
            destination: DEST_MMAX,
            ..test_query()
        };
        assert!(store.find_matching(&covered, &KEY, &binding()).is_some());
        let misses = [
            (
                "toolset",
                GrantQuery {
                    toolset_name: "other",
                    ..covered
                },
            ),
            (
                "install",
                GrantQuery {
                    install_id: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    ..covered
                },
            ),
            (
                "version",
                GrantQuery {
                    package_version: "1.0.1",
                    ..covered
                },
            ),
            (
                "shasum",
                GrantQuery {
                    package_shasum: "eddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                    ..covered
                },
            ),
            (
                "capability",
                GrantQuery {
                    capability: "sign-rule-create",
                    ..covered
                },
            ),
            (
                "asset",
                GrantQuery {
                    asset: "USDC:GAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQDZ7H",
                    ..covered
                },
            ),
            (
                "minimum",
                GrantQuery {
                    amount_stroops: 1,
                    ..covered
                },
            ),
            (
                "maximum",
                GrantQuery {
                    amount_stroops: 11,
                    ..covered
                },
            ),
            (
                "expiry",
                GrantQuery {
                    now_unix_ms: NOW_MS + 86_400_000,
                    ..covered
                },
            ),
            (
                "install cutoff",
                GrantQuery {
                    not_before_unix_ms: NOW_MS + 1,
                    ..covered
                },
            ),
            (
                "issued in the future",
                GrantQuery {
                    now_unix_ms: NOW_MS - 1,
                    ..covered
                },
            ),
        ];
        for (term, query) in misses {
            assert!(
                store.find_matching(&query, &KEY, &binding()).is_none(),
                "{term}"
            );
        }
        let dir = tempfile::TempDir::new().unwrap();
        let store = store_with_grant(&dir, unattested);
        assert!(
            store.find_matching(&covered, &KEY, &binding()).is_none(),
            "attestation"
        );
    }

    #[test]
    fn g_and_m_grants_reopen_with_their_stored_bytes() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("default.toolset_grants.toml");
        let grants = [
            grant_to("sign-payment", DEST_G).unwrap(),
            grant_to("sign-payment", DEST_MMAX).unwrap(),
        ];
        let mut store = ToolsetGrantStore::open(path.clone(), NOW_MS).unwrap();
        for grant in &grants {
            store.insert(grant.clone()).unwrap();
        }
        let written = fs::read_to_string(&path).unwrap();
        let reopened = ToolsetGrantStore::open(path.clone(), NOW_MS).unwrap();
        for (stored, original) in reopened.grants.iter().zip(&grants) {
            assert_eq!(stored.destination, original.destination);
            assert_eq!(stored.attestation_blob_b64, original.attestation_blob_b64);
            assert!(stored.verify_attestation(&KEY, &binding()));
        }
        assert_eq!(reopened.len(), 2);
        assert!(found(&reopened, DEST_MMAX));
        reopened.persist().unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), written);
    }

    #[test]
    fn an_m_grant_attests_its_exact_destination_bytes() {
        let grant = grant_to("sign-payment", DEST_MMAX).unwrap();
        assert_eq!(grant.destination, DEST_MMAX);
        let blob: [u8; 32] = URL_SAFE_NO_PAD
            .decode(grant.attestation_blob_b64.as_ref().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let verifies = |destination: &str| {
            let digest = compute_toolset_gate_digest(
                &grant.toolset_name,
                &grant.install_id,
                &grant.package_version,
                &grant.package_shasum,
                &grant.capability,
                destination,
                &grant.asset,
                grant.amount_min_stroops,
                grant.amount_max_stroops,
            );
            crate::approval::attestation::verify_attestation(
                &KEY,
                &binding(),
                &grant.grant_id,
                &digest,
                "1000",
                &AttestationScope::V3(grant.attested_lifetime()),
                &blob,
            )
        };
        assert!(verifies(DEST_MMAX));
        assert!(!verifies(DEST_G));
    }

    #[test]
    fn construction_refuses_a_malformed_payment_destination() {
        let contract = stellar_strkey::Contract([1; 32]).to_string();
        let muxed_contract = stellar_strkey::MuxedContract {
            contract_id: [1; 32],
            id: 7,
        }
        .to_string();
        let corrupted = format!("{}A", &DEST_G[..55]);
        for destination in [
            contract.as_str(),
            muxed_contract.as_str(),
            corrupted.as_str(),
            &DEST_M7.to_lowercase(),
            " GAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQDZ7H",
        ] {
            let err = grant_to("sign-payment", destination).unwrap_err();
            assert!(matches!(err, ApprovalError::InvalidEntry { .. }), "{err}");
            assert!(!err.to_string().contains(destination.trim()), "{err}");
        }
    }

    /// Replaces the stored destination text of the only grant in `path`.
    fn edit_stored_destination(path: &Path, from: &str, to: &str) {
        let text = fs::read_to_string(path).unwrap();
        assert!(text.contains(from));
        fs::write(path, text.replace(from, to)).unwrap();
    }

    #[test]
    fn loading_refuses_a_malformed_payment_destination() {
        let corrupted = format!("{}A", &DEST_M7[..68]);
        let contract = stellar_strkey::Contract([1; 32]).to_string().to_string();
        for malformed in [corrupted.as_str(), contract.as_str(), "GBBBBBBBBB"] {
            let dir = tempfile::TempDir::new().unwrap();
            let path = dir.path().join("default.toolset_grants.toml");
            let grant = grant_to("sign-payment", DEST_M7).unwrap();
            drop(store_with_grant(&dir, grant.clone()));
            assert!(found(
                &ToolsetGrantStore::open(path.clone(), NOW_MS).unwrap(),
                DEST_M7
            ));
            edit_stored_destination(&path, DEST_M7, malformed);
            let edited = fs::read_to_string(&path).unwrap();
            let store = ToolsetGrantStore::open(path.clone(), NOW_MS).unwrap();
            assert_eq!(store.len(), 1);
            assert_eq!(store.grants[0].destination(), malformed);
            for destination in [DEST_M7, DEST_G, malformed] {
                assert!(!found(&store, destination), "{destination}");
            }
            assert_eq!(fs::read_to_string(&path).unwrap(), edited);
        }
    }

    #[test]
    fn rule_create_grants_keep_their_contract_destination() {
        let contract = stellar_strkey::Contract([1; 32]).to_string().to_string();
        let other = stellar_strkey::Contract([2; 32]).to_string().to_string();
        let grant = grant_to("sign-rule-create", &contract).unwrap();
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("default.toolset_grants.toml");
        drop(store_with_grant(&dir, grant.clone()));
        let reopened = ToolsetGrantStore::open(path, NOW_MS).unwrap();
        let stored = &reopened.grants[0];
        assert_eq!(stored.destination, contract);
        assert_eq!(stored.attestation_blob_b64, grant.attestation_blob_b64);
        let query = |destination| GrantQuery {
            capability: "sign-rule-create",
            destination,
            ..test_query()
        };
        assert!(
            reopened
                .find_matching(&query(&contract), &KEY, &binding())
                .is_some()
        );
        assert!(
            reopened
                .find_matching(&query(&other), &KEY, &binding())
                .is_none()
        );
    }

    /// [`DEST_G`] with its last character changed, so its checksum fails.
    fn bad_checksum_g() -> String {
        format!("{}A", &DEST_G[..55])
    }

    /// A grant to `destination` whose attestation verifies under [`KEY`],
    /// built around the construction check.
    fn attested_to(toolset_name: &str, destination: &str) -> ToolsetGrant {
        let mut grant = grant_to("sign-payment", DEST_G).unwrap();
        grant.toolset_name = toolset_name.to_owned();
        grant.destination = destination.to_owned();
        let digest = compute_toolset_gate_digest(
            &grant.toolset_name,
            &grant.install_id,
            &grant.package_version,
            &grant.package_shasum,
            &grant.capability,
            &grant.destination,
            &grant.asset,
            grant.amount_min_stroops,
            grant.amount_max_stroops,
        );
        let blob = compute_attestation(
            &KEY,
            &binding(),
            &grant.grant_id,
            &digest,
            &grant.process_uid_at_grant,
            &grant.attested_lifetime(),
        );
        grant.attestation_blob_b64 = Some(URL_SAFE_NO_PAD.encode(blob));
        assert!(grant.verify_attestation(&KEY, &binding()));
        grant
    }

    #[test]
    fn grant_deserialize_refuses_bad_destination() {
        let grant = grant_to("sign-payment", DEST_G).unwrap();
        let text = toml::to_string(&grant).unwrap();
        assert!(toml::from_str::<ToolsetGrant>(&text).is_ok());
        let bad = bad_checksum_g();
        let err = toml::from_str::<ToolsetGrant>(&text.replace(DEST_G, &bad)).unwrap_err();
        assert!(!err.to_string().contains(&bad), "{err}");
        let json = serde_json::to_string(&grant).unwrap();
        assert!(serde_json::from_str::<ToolsetGrant>(&json.replace(DEST_G, &bad)).is_err());
    }

    #[test]
    fn grant_insert_refuses_bad_destination() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("default.toolset_grants.toml");
        let mut store = ToolsetGrantStore::open(path.clone(), NOW_MS).unwrap();
        let err = store.insert(attested_to("my-toolset", &bad_checksum_g()));
        assert!(
            matches!(err, Err(ApprovalError::InvalidEntry { .. })),
            "{err:?}"
        );
        let mut contract = grant_to("sign-rule-create", DEST_G).unwrap();
        contract.capability = SIGN_PAYMENT_CAPABILITY.to_owned();
        contract.destination = stellar_strkey::Contract([1; 32]).to_string().to_string();
        assert!(store.insert(contract).is_err());
        assert!(store.is_empty());
        assert!(!path.exists());
    }

    /// One authenticated grant with a refused destination sits between two
    /// usable grants. It is an ordinary grant: counted, kept in place on
    /// rewrite, revoked, and pruned. It matches no destination, not even its
    /// own text, and the usable grants match before and after a restart.
    #[test]
    fn a_grant_with_a_refused_destination_is_an_ordinary_grant() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("default.toolset_grants.toml");
        let bad = attested_to("old-toolset", &bad_checksum_g());
        let mut grants = vec![
            grant_to("sign-payment", DEST_G).unwrap(),
            bad.clone(),
            grant_to("sign-payment", OTHER_MMAX).unwrap(),
        ];
        let file = |grants: &[ToolsetGrant]| {
            toml::to_string_pretty(&GrantStoreFile {
                grants: grants.iter().cloned().map(GrantRecord::from).collect(),
            })
            .unwrap()
        };
        let text = file(&grants);
        fs::write(&path, &text).unwrap();
        let bad_query = GrantQuery {
            toolset_name: "old-toolset",
            destination: &bad.destination,
            ..test_query()
        };
        for _restart in 0..2 {
            let store = ToolsetGrantStore::open(path.clone(), NOW_MS).unwrap();
            assert!(found(&store, DEST_M7));
            assert!(found(&store, OTHER_MMAX));
            assert_eq!(store.len(), 3);
            assert_eq!(store.grants[1].destination(), bad.destination);
            assert!(store.grants[1].verify_attestation(&KEY, &binding()));
            assert!(store.find_matching(&bad_query, &KEY, &binding()).is_none());
            assert!(!store.grants[1].matches(
                "old-toolset",
                &bad.install_id,
                &bad.package_version,
                &bad.package_shasum,
                SIGN_PAYMENT_CAPABILITY,
                &bad.destination,
                "XLM",
                5,
                NOW_MS,
            ));
            assert_eq!(fs::read_to_string(&path).unwrap(), text);
        }
        let mut store = ToolsetGrantStore::open(path.clone(), NOW_MS).unwrap();
        let added = grant_to("sign-payment", OTHER_G).unwrap();
        store.insert(added.clone()).unwrap();
        grants.push(added);
        assert_eq!(fs::read_to_string(&path).unwrap(), file(&grants));
        let mut store = ToolsetGrantStore::open(path.clone(), NOW_MS).unwrap();
        assert!(found(&store, OTHER_G) && found(&store, DEST_MMAX));
        assert_eq!(store.revoke_toolset("old-toolset").unwrap(), 1);
        let store = ToolsetGrantStore::open(path.clone(), NOW_MS).unwrap();
        assert_eq!(store.len(), 3);
        assert!(store.grants.iter().all(|g| g.grant_id != bad.grant_id));
        fs::write(&path, &text).unwrap();
        let store = ToolsetGrantStore::open(path, bad.expires_at_unix_ms).unwrap();
        assert!(store.is_empty(), "expired grants prune on load");
    }

    /// A one-payment unsigned envelope to `destination`, as base64 XDR.
    fn payment_envelope(destination: stellar_xdr::MuxedAccount) -> String {
        use stellar_xdr::{
            Limits, Memo, MuxedAccount, Operation, OperationBody, PaymentOp, Preconditions,
            SequenceNumber, Transaction, TransactionEnvelope, TransactionExt,
            TransactionV1Envelope, Uint256, WriteXdr,
        };
        TransactionEnvelope::Tx(TransactionV1Envelope {
            tx: Transaction {
                source_account: MuxedAccount::Ed25519(Uint256([0x01; 32])),
                fee: 100,
                seq_num: SequenceNumber(9),
                cond: Preconditions::None,
                memo: Memo::None,
                operations: vec![Operation {
                    source_account: None,
                    body: OperationBody::Payment(PaymentOp {
                        destination,
                        asset: stellar_xdr::Asset::Native,
                        amount: 5,
                    }),
                }]
                .try_into()
                .unwrap(),
                ext: TransactionExt::V0,
            },
            signatures: Vec::new().try_into().unwrap(),
        })
        .to_xdr_base64(Limits::none())
        .unwrap()
    }

    /// Approvals bind the full ID. A grant, an intent digest and an
    /// approval subject for M17 cover neither M18, the G base nor another
    /// key; a grant for G covers every M on its key.
    #[test]
    fn muxed_approval_id_binding() {
        use crate::approval::intent::{
            ClassicIntent, IntentAsset, IntentBase, IntentPayload, MemoFact,
        };
        let key = [0xAC; 32];
        let other = [0xEC; 32];
        let g = |key: [u8; 32]| format!("{}", stellar_strkey::ed25519::PublicKey(key));
        let m = |key: [u8; 32], id: u64| {
            format!(
                "{}",
                stellar_strkey::ed25519::MuxedAccount { ed25519: key, id }
            )
        };
        let attestation_key = [0x42; 32];
        let binding = crate::approval::AttestationBinding::new("default", "stellar:testnet");
        let grant_for = |destination: &str| {
            build_attested_grant(
                "my-toolset".to_owned(),
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
                "1.0.0".to_owned(),
                "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".to_owned(),
                "sign-payment".to_owned(),
                destination.to_owned(),
                "XLM".to_owned(),
                0,
                10,
                "1000".to_owned(),
                NOW_MS,
                86_400_000,
                &attestation_key,
                &binding,
            )
            .unwrap()
        };
        let covers = |grant: &ToolsetGrant, destination: &str| {
            let query = GrantQuery {
                destination,
                ..test_query()
            };
            let matched = grant.matches(
                query.toolset_name,
                query.install_id,
                query.package_version,
                query.package_shasum,
                query.capability,
                destination,
                query.asset,
                query.amount_stroops,
                query.now_unix_ms,
            );
            let dir = tempfile::TempDir::new().unwrap();
            let store = store_with_grant(&dir, grant.clone());
            let verified = store
                .find_matching(&query, &attestation_key, &binding)
                .is_some();
            assert_eq!(matched, verified, "{destination}");
            matched
        };
        let m17 = grant_for(&m(key, 17));
        assert!(covers(&m17, &m(key, 17)));
        for uncovered in [m(key, 18), m(key, 0), g(key), m(other, 17)] {
            assert!(
                !covers(&m17, &uncovered),
                "the M17 grant covers {uncovered}"
            );
        }
        let base = grant_for(&g(key));
        assert!(covers(&base, &g(key)));
        for covered in [m(key, 0), m(key, 17)] {
            assert!(
                covers(&base, &covered),
                "the G grant does not cover {covered}"
            );
        }

        let intent = |destination: String| {
            ClassicIntent::new(
                IntentBase::new(
                    "stellar:testnet".to_owned(),
                    g([0x01; 32]),
                    [3; 32],
                    100,
                    MemoFact::None,
                )
                .unwrap(),
                IntentPayload::Pay {
                    destination,
                    asset: IntentAsset::Native,
                    amount_stroops: 5,
                },
            )
            .unwrap()
            .digest()
        };
        let subject = |destination: stellar_xdr::MuxedAccount| {
            crate::approval::subject::approval_subject_classic(&payment_envelope(destination))
        };
        let muxed = |key: [u8; 32], id: u64| {
            stellar_xdr::MuxedAccount::MuxedEd25519(stellar_xdr::MuxedAccountMed25519 {
                id,
                ed25519: stellar_xdr::Uint256(key),
            })
        };
        let bound_intent = intent(m(key, 17));
        let bound_subject = subject(muxed(key, 17));
        for (destination, xdr) in [
            (m(key, 18), muxed(key, 18)),
            (m(key, 0), muxed(key, 0)),
            (
                g(key),
                stellar_xdr::MuxedAccount::Ed25519(stellar_xdr::Uint256(key)),
            ),
            (m(other, 17), muxed(other, 17)),
        ] {
            assert_ne!(intent(destination.clone()), bound_intent, "{destination}");
            assert_ne!(subject(xdr), bound_subject, "{destination}");
        }
        assert_eq!(intent(m(key, 17)), bound_intent);
    }
}
