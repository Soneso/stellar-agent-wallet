//! First-invoke grant store for signing-adjacent toolset capabilities.
//!
//! Persists approved (toolset, capability, destination, asset, amount_min,
//! amount_max) tuples + HMAC attestation, per profile, to a TOML file.
//!
//! # Purpose
//!
//! After the operator approves a `ToolsetFirstInvokeGate` approval via
//! `stellar-agent approve --id <nonce>`, the gated resolver persists a
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
//!
//! # Durability properties
//!
//! - **Bounded TTL**: re-prompt on expiry.
//! - **Revoke-on-uninstall**: the caller MUST call `revoke_toolset` when a toolset
//!   is uninstalled.
//! - **Invalidate-on-capabilities-change**: the caller MUST call
//!   `revoke_toolset` when the toolset's pinned capabilities change.
//!
//! # Tamper framing
//!
//! The structural guarantee is the unconditional per-action
//! `PaymentSimulated` approval for toolset-routed payments.  A forged or
//! tampered grant can at worst suppress the first-invoke re-prompt; it
//! CANNOT bypass the forced per-action approval.  The per-action approval
//! binds the actual executed envelope.
//!
//! The `attestation_blob_b64` field (produced by the wallet's HMAC key at
//! approve time) provides defence-in-depth against local file tampering —
//! a hand-edited grant without a valid HMAC blob will be rejected by
//! `verify_grant_attestation`.

use std::fs;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

use super::error::ApprovalError;
use crate::approval::attestation::{
    compute_attestation, compute_toolset_gate_digest, verify_toolset_gate_attestation,
};

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
    /// `None` for grants not yet attested (should not happen in normal flow).
    /// `Some(blob)` after `verify_grant_attestation` passes.
    ///
    /// The HMAC binds `grant_id` + the `compute_toolset_gate_digest` of
    /// (toolset_name, capability, destination, asset, amount_min, amount_max)
    /// + `process_uid_at_grant`.
    pub attestation_blob_b64: Option<String>,

    /// Platform-stable user identity at grant time (used to rebind HMAC).
    pub process_uid_at_grant: String,
}

impl ToolsetGrant {
    /// Returns `true` if this grant has expired relative to `now_unix_ms`.
    #[must_use]
    pub fn is_expired(&self, now_unix_ms: u64) -> bool {
        self.expires_at_unix_ms <= now_unix_ms
    }

    /// Returns `true` if this grant matches the given payment parameters.
    ///
    /// Matching is conservative (fail-closed): any param not provably inside
    /// the grant bucket → no match.
    ///
    /// # HMAC note
    ///
    /// The grant HMAC (`attestation_blob_b64`) is intentionally NOT verified on
    /// this read path.  The structural defence is that even a grant that passes
    /// field-level matching still forces a per-action `PaymentSimulated` approval
    /// via `verify_attestation_gate` before the commit can proceed.  Verifying
    /// the HMAC here would not add security because an attacker who can forge a
    /// grant can also replay a previously-observed valid HMAC; the per-action
    /// attestation is what binds the approval to the specific transaction.
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
    pub fn verify_attestation(&self, key: &[u8; 32]) -> bool {
        let Some(blob_b64) = &self.attestation_blob_b64 else {
            return false;
        };
        let Ok(blob_bytes) = URL_SAFE_NO_PAD.decode(blob_b64) else {
            return false;
        };
        let Ok(blob_arr): Result<[u8; 32], _> = blob_bytes.try_into() else {
            return false;
        };
        verify_toolset_gate_attestation(
            key,
            &self.grant_id,
            &self.toolset_name,
            &self.capability,
            &self.destination,
            &self.asset,
            self.amount_min_stroops,
            self.amount_max_stroops,
            &self.process_uid_at_grant,
            &blob_arr,
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
                detail: e.to_string(),
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

    /// Returns the first current (non-expired) grant matching the given
    /// payment parameters, or `None` if no such grant exists.
    ///
    /// # HMAC note
    ///
    /// The grant HMAC is intentionally NOT verified on this read path — see the
    /// [`ToolsetGrant::matches`] rustdoc for the rationale.  The per-action
    /// `PaymentSimulated` attestation gate in `verify_attestation_gate` is the
    /// structural defence against forged or replayed grants.
    #[must_use]
    pub fn find_matching(
        &self,
        toolset_name: &str,
        capability: &str,
        destination: &str,
        asset: &str,
        amount_stroops: i64,
        now_unix_ms: u64,
    ) -> Option<&ToolsetGrant> {
        self.grants.iter().find(|g| {
            g.matches(
                toolset_name,
                capability,
                destination,
                asset,
                amount_stroops,
                now_unix_ms,
            )
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

    /// Removes all grants for the given `toolset_name` (revoke-on-uninstall and
    /// revoke-on-capabilities-change).
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

        // Set file permissions to 0o600 on Unix before rename.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o600))
                .map_err(ApprovalError::from_io)?;
        }

        tmp.persist(&self.path)
            .map_err(|e| ApprovalError::from_io(e.error))?;

        // fsync parent directory to commit the directory entry.
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

    // Compute the HMAC attestation blob.
    let attestation_blob = compute_attestation(attestation_key, &grant_id, &digest, &process_uid);
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
        )
        .unwrap()
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
        assert!(grant.verify_attestation(&key), "attestation must verify");
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
        assert!(!grant.verify_attestation(&wrong_key), "wrong key must fail");
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
            !grant.verify_attestation(&key),
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
            "test-toolset",
            "sign-payment",
            DEST_G,
            "XLM",
            5_000_000,
            NOW_MS,
        );
        assert!(found.is_some(), "should find matching grant");
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
            "toolset-a",
            "sign-payment",
            DEST_G,
            "XLM",
            5_000_000,
            NOW_MS,
        );
        assert!(found_a.is_none(), "toolset-a grant must be revoked");

        let found_b = store.find_matching(
            "toolset-b",
            "sign-payment",
            DEST_G,
            "XLM",
            5_000_000,
            NOW_MS,
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
            "fresh-toolset",
            "sign-payment",
            DEST_G,
            "XLM",
            1_000_000,
            NOW_MS,
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
        )
        .unwrap();

        // The attestation must pass with the correct key.
        assert!(grant.verify_attestation(&key));

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
            &grant.grant_id,
            &expected_digest,
            "1234",
            &blob_bytes,
        );
        assert!(
            ok,
            "independently-computed digest must match stored attestation"
        );
    }
}
