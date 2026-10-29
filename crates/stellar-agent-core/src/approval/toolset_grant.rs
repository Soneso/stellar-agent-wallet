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
//! - `capability` == capability token (e.g. `"sign-payment"`).
//! - `destination` == canonical G-strkey of the envelope destination.
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

/// The kind name a grant's version 3 attestation binds.
pub const TOOLSET_GRANT_KIND: &str = "ToolsetGrant";

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
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ToolsetGrant {
    /// Wallet-issued grant identifier (16 bytes, URL-safe base64 no-pad).
    pub grant_id: String,

    /// Name of the toolset the grant was issued to.
    pub toolset_name: String,

    /// Capability token (e.g. `"sign-payment"`).
    pub capability: String,

    /// Canonical G-strkey destination address (from authoritative envelope).
    pub destination: String,

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

impl ToolsetGrant {
    /// Returns `true` if this grant has expired relative to `now_unix_ms`.
    #[must_use]
    pub fn is_expired(&self, now_unix_ms: u64) -> bool {
        self.expires_at_unix_ms <= now_unix_ms
    }

    /// Compares the payment fields and clock against this grant's bucket and expiry.
    ///
    /// This is a field and clock comparison only. Use
    /// [`ToolsetGrantStore::find_matching`] for a verified lookup.
    #[must_use]
    pub fn matches(
        &self,
        toolset_name: &str,
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
            && self.capability == capability
            && self.destination == destination
            && self.asset == asset
            && amount_stroops >= self.amount_min_stroops
            && amount_stroops <= self.amount_max_stroops
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
    grants: Vec<ToolsetGrant>,
}

// ─────────────────────────────────────────────────────────────────────────────
// ToolsetGrantStore
// ─────────────────────────────────────────────────────────────────────────────

/// The invocation a grant must cover to suppress the first-invoke gate.
#[derive(Debug, Clone, Copy)]
pub struct GrantQuery<'a> {
    /// Installed toolset name from the invocation.
    pub toolset_name: &'a str,
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
    /// carries over to a later installation.
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
    /// - [`ApprovalError::Io`] / [`ApprovalError::Toml`] on persistence failure.
    pub fn insert(&mut self, grant: ToolsetGrant) -> Result<(), ApprovalError> {
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
            grants: self.grants.clone(),
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
/// - `capability`: capability token (e.g. `"sign-payment"`).
/// - `destination`: canonical G-strkey destination.
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
/// Returns [`ApprovalError::Io`] if the system clock returns an error.
#[allow(clippy::too_many_arguments)]
pub fn build_attested_grant(
    toolset_name: String,
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
    // Generate a random grant_id.
    let mut raw = [0u8; 16];
    OsRng.fill_bytes(&mut raw);
    let grant_id = URL_SAFE_NO_PAD.encode(raw);

    let expires_at_unix_ms = now_unix_ms.saturating_add(ttl_ms);

    // Compute the digest for this grant shape.
    let digest = compute_toolset_gate_digest(
        &toolset_name,
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

    const DEST_G: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
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
        assert!(grant.matches("my-toolset", "sign-payment", DEST_G, "XLM", 0, NOW_MS));
        // At max.
        assert!(grant.matches(
            "my-toolset",
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
        let other_dest = "GBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
        // other_dest is 58 chars, not a valid G-strkey, but the matches() fn
        // does exact string compare so any mismatch returns false.
        assert!(!grant.matches(
            "my-toolset",
            "sign-payment",
            other_dest,
            "XLM",
            1_000,
            NOW_MS
        ));
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
            "sign-payment",
            DEST_G,
            "USDC:Gxxxx",
            1_000,
            NOW_MS
        ));
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
        assert!(!grant.matches("my-toolset", "sign-payment", DEST_G, "XLM", 999_999, NOW_MS));
    }

    // ── build_attested_grant KAT: same key+params → deterministic attestation ─

    #[test]
    fn build_attested_grant_attestation_is_verifiable() {
        let key = [0x99u8; 32];
        let grant = build_attested_grant(
            "my-toolset".to_owned(),
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
}
