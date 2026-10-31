//! The audit readiness: proof that a profile's keyed audit writer, opened
//! with the profile's keyring-held tip anchor, was verified and drained, and
//! that the anchor covers its tip.
//!
//! [`audit_readiness`] is the only producer. It refuses a process on a
//! headless keyring backend through [`refuse_headless_keyring_backend`], then
//! loads the profile's audit key and anchor store through
//! [`crate::keyring::keyed_audit_access`],
//! acquires the writer from the process registry under the profile's own
//! name, and checks its keyring-backed anchor store and path under the same
//! lock as its verified facts. Provenance belongs to the writer itself.
//! Replacing the writer in the shared handle cannot preserve that provenance.
//!
//! The proof owns a strong handle to the writer, so the writer's sidecar lock
//! lasts as long as any authority built on the proof. Its facts describe the
//! active file at the moment of verification: an audit rotation resets the
//! entry count and changes the active file, so an authorization that recorded
//! the facts before a rotation does not match the log after it and is minted
//! again.
//!
//! The proof's fields are private:
//!
//! ```compile_fail,E0451
//! use stellar_agent_network::mainnet::audit_readiness::AuditReadiness;
//! fn forge(p: AuditReadiness) -> AuditReadiness { AuditReadiness { ..p } }
//! ```
//!
//! The import alone resolves:
//!
//! ```
//! use stellar_agent_network::mainnet::audit_readiness::AuditReadiness;
//! fn need(_: Option<AuditReadiness>) {}
//! need(None);
//! ```
//!
//! It implements none of `Serialize`, `Deserialize`, `Default`, or `Clone`:
//!
//! ```compile_fail,E0277
//! use stellar_agent_network::mainnet::audit_readiness::AuditReadiness;
//! fn need<T: serde::Serialize>() {}
//! need::<AuditReadiness>();
//! ```
//!
//! ```compile_fail,E0277
//! use stellar_agent_network::mainnet::audit_readiness::AuditReadiness;
//! fn need<T: serde::de::DeserializeOwned>() {}
//! need::<AuditReadiness>();
//! ```
//!
//! ```compile_fail,E0277
//! use stellar_agent_network::mainnet::audit_readiness::AuditReadiness;
//! fn need<T: Default>() {}
//! need::<AuditReadiness>();
//! ```
//!
//! ```compile_fail,E0277
//! use stellar_agent_network::mainnet::audit_readiness::AuditReadiness;
//! fn need<T: Clone>() {}
//! need::<AuditReadiness>();
//! ```

use std::sync::Arc;

use stellar_agent_core::audit_log::writer::VerifiedTipFacts;
use stellar_agent_core::audit_log::{
    AuditWriterRegistry, BindingCheck, TipAnchorStore, audit_writer_refusal,
};
use stellar_agent_core::error::{NetworkError, ValidationError, WalletError};
use stellar_agent_core::mainnet::fact::{FACT_LABEL_AUDIT, FactDigest};
use stellar_agent_core::profile::schema::Profile;

use super::refusal::{MainnetAuthorizationError, MainnetPrecondition};
use super::types::AuditFacts;
use crate::keyring::{KeyringBackend, KeyringTipAnchorStore, active_keyring_backend};
use crate::submission_record::AuditWriterHandle;

/// Proof that the profile's keyring-anchored audit writer was verified and
/// its anchor covers its tip.
///
/// See the module documentation for the producer and what the proof holds.
/// The `profile` field cannot be projected outside this crate.
///
/// ```compile_fail,E0616
/// use stellar_agent_network::mainnet::audit_readiness::AuditReadiness;
/// fn inspect(p: &AuditReadiness) { let _ = &p.profile; }
/// ```
///
/// ```
/// use stellar_agent_network::mainnet::audit_readiness::AuditReadiness;
/// fn need(_: Option<AuditReadiness>) {}
/// need(None);
/// ```
///
/// The `facts` field cannot be projected outside this crate.
///
/// ```compile_fail,E0616
/// use stellar_agent_network::mainnet::audit_readiness::AuditReadiness;
/// fn inspect(p: &AuditReadiness) { let _ = &p.facts; }
/// ```
///
/// ```
/// use stellar_agent_network::mainnet::audit_readiness::AuditReadiness;
/// fn need(_: Option<AuditReadiness>) {}
/// need(None);
/// ```
///
/// The `verified_at_ms` field cannot be projected outside this crate.
///
/// ```compile_fail,E0616
/// use stellar_agent_network::mainnet::audit_readiness::AuditReadiness;
/// fn inspect(p: &AuditReadiness) { let _ = &p.verified_at_ms; }
/// ```
///
/// ```
/// use stellar_agent_network::mainnet::audit_readiness::AuditReadiness;
/// fn need(_: Option<AuditReadiness>) {}
/// need(None);
/// ```
///
/// The `writer` field cannot be projected outside this crate.
///
/// ```compile_fail,E0616
/// use stellar_agent_network::mainnet::audit_readiness::AuditReadiness;
/// fn inspect(p: &AuditReadiness) { let _ = &p.writer; }
/// ```
///
/// ```
/// use stellar_agent_network::mainnet::audit_readiness::AuditReadiness;
/// fn need(_: Option<AuditReadiness>) {}
/// need(None);
/// ```
///
/// The `expected` field cannot be projected outside this crate.
///
/// ```compile_fail,E0616
/// use stellar_agent_network::mainnet::audit_readiness::AuditReadiness;
/// fn inspect(p: &AuditReadiness) { let _ = &p.expected; }
/// ```
///
/// ```
/// use stellar_agent_network::mainnet::audit_readiness::AuditReadiness;
/// fn need(_: Option<AuditReadiness>) {}
/// need(None);
/// ```
///
pub struct AuditReadiness {
    profile: String,
    facts: VerifiedTipFacts,
    verified_at_ms: u64,
    writer: AuditWriterHandle,
    expected: KeyringTipAnchorStore,
}

impl std::fmt::Debug for AuditReadiness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditReadiness")
            .field("profile", &self.profile)
            .field("anchored_count", &self.facts.entry_count)
            .field("verified_at_ms", &self.verified_at_ms)
            .finish_non_exhaustive()
    }
}

impl AuditReadiness {
    /// The profile whose writer was verified: the registry key the writer is
    /// cached under.
    #[must_use]
    pub fn profile(&self) -> &str {
        &self.profile
    }

    /// When the verification ran, in Unix milliseconds on the mainnet clock.
    #[must_use]
    pub fn verified_at_ms(&self) -> u64 {
        self.verified_at_ms
    }

    /// The digest of the active log path.
    #[must_use]
    pub fn log_path_digest(&self) -> [u8; 32] {
        self.facts.log_path_sha256
    }

    /// The anchored entry count of the active file at verification.
    #[must_use]
    pub fn anchored_count(&self) -> u64 {
        self.facts.entry_count
    }

    /// The hash the active segment's first entry links to.
    #[must_use]
    pub fn segment(&self) -> [u8; 32] {
        self.facts.segment_start_hash
    }

    /// Rechecks the writer's provenance, path, verified tip, anchor coverage,
    /// and entry tags in force.
    ///
    /// # Errors
    /// Refuses a poisoned writer lock and changed provenance or path with
    /// `AuditProvenance`, and an unverifiable or uncovered tip, or a log
    /// without entry tags in force, with `AuditNotAnchored`.
    pub fn fresh_facts(&self) -> Result<AuditFacts, MainnetAuthorizationError> {
        use MainnetPrecondition as P;
        let mut writer = self
            .writer
            .lock()
            .map_err(|_| MainnetAuthorizationError::Refused(P::AuditProvenance))?;
        super::refusal::require(
            writer
                .tip_anchor_store()
                .is_some_and(|store| keyring_backed_at(store.as_ref(), &self.expected)),
            P::AuditProvenance,
        )?;
        super::refusal::require(
            stellar_agent_core::audit_log::log_path_sha256(writer.path())
                == self.facts.log_path_sha256,
            P::AuditProvenance,
        )?;
        let facts = writer
            .verified_tip_facts()
            .map_err(|_| MainnetAuthorizationError::Refused(P::AuditNotAnchored))?;
        super::refusal::require(facts.anchor_covers_tip, P::AuditNotAnchored)?;
        super::refusal::require(facts.entry_tags_in_force, P::AuditNotAnchored)?;
        Ok(AuditFacts {
            log_path_digest: facts.log_path_sha256,
            anchored_count: facts.entry_count,
            segment: facts.segment_start_hash,
        })
    }

    /// The active file's tip at verification.
    #[must_use]
    pub fn tip_hash(&self) -> [u8; 32] {
        self.facts.tip_hash
    }

    /// The writer this proof keeps alive. A consumer calls [`Self::fresh_facts`]
    /// at use time and compares its facts with the recorded ones.
    #[must_use]
    pub fn writer(&self) -> &AuditWriterHandle {
        &self.writer
    }

    /// The fact digest under `stellar-agent-authz-fact:audit:v1`.
    ///
    /// Fields, in order: `lp(profile)`, the 32-byte log path digest,
    /// the 32-byte segment hash, `u64be(anchored_count)`, the 32-byte tip hash, and
    /// `u64be(verified_at_ms)`. The writer handle is not a fact.
    #[must_use]
    pub fn fact_digest(&self) -> [u8; 32] {
        let mut digest = FactDigest::new(FACT_LABEL_AUDIT);
        digest
            .bytes(self.profile.as_bytes())
            .fixed(&self.facts.log_path_sha256)
            .fixed(&self.facts.segment_start_hash)
            .u64(self.facts.entry_count)
            .fixed(&self.facts.tip_hash)
            .u64(self.verified_at_ms);
        digest.finish()
    }

    /// A proof over an arbitrary writer, for this crate's tests of the types
    /// that hold one.
    #[cfg(all(test, feature = "mainnet-write"))]
    pub(crate) fn for_crate_tests(
        profile: &str,
        facts: VerifiedTipFacts,
        verified_at_ms: u64,
        writer: AuditWriterHandle,
    ) -> Self {
        Self {
            expected: KeyringTipAnchorStore::for_path_digest(
                &stellar_agent_core::profile::schema::KeyringEntryRef::default_audit_key(profile),
                &facts.log_path_sha256,
            ),
            profile: profile.to_owned(),
            facts,
            verified_at_ms,
            writer,
        }
    }
}

fn unusable(profile_name: &str, detail: &str) -> WalletError {
    WalletError::Validation(ValidationError::AuditLogUnusable {
        profile: profile_name.to_owned(),
        detail: detail.to_owned(),
    })
}

/// Whether `recorded` is the keyring-backed anchor store at the coordinate
/// `expected` names.
fn keyring_backed_at(recorded: &dyn TipAnchorStore, expected: &KeyringTipAnchorStore) -> bool {
    let any: &dyn std::any::Any = recorded;
    any.downcast_ref::<KeyringTipAnchorStore>()
        .is_some_and(|store| store.anchor_entry_ref() == expected.anchor_entry_ref())
}

/// Refuses facts whose anchor does not cover the tip, and facts of a log
/// whose entries past the boundary row are not tag-checked.
///
/// A keyed writer appends the boundary row at its first acquisition; when
/// that append fails, the writer stays out of force and the next acquisition
/// retries it.
fn refuse_unless_covered(profile_name: &str, facts: &VerifiedTipFacts) -> Result<(), WalletError> {
    if !facts.anchor_covers_tip {
        return Err(unusable(
            profile_name,
            "audit.tip_anchor_unavailable: the tip anchor does not cover the log's last \
             entry; retry once the keyring is reachable",
        ));
    }
    if !facts.entry_tags_in_force {
        return Err(unusable(
            profile_name,
            "audit.tip_anchor_unavailable: the audit log has no entry-tag boundary; retry \
             once the audit writer can append",
        ));
    }
    Ok(())
}

/// Refuses a process whose keyring backend is not the platform keyring.
///
/// The tip anchor proves an audit log was not rolled back only while the
/// anchor cannot be rolled back with it. A headless backend keeps every entry
/// in one file on the same host with no generation or freshness witness, so
/// restoring an older copy of that file together with a truncated log makes
/// the two agree. Mainnet readiness and `profile enable-mainnet` call this;
/// testnet paths do not.
///
/// # Errors
///
/// [`NetworkError::MainnetKeyringBackendUnsupported`] naming the backend, for
/// any backend other than [`KeyringBackend::Platform`] as
/// [`active_keyring_backend`] reports it.
pub fn refuse_headless_keyring_backend() -> Result<(), WalletError> {
    match active_keyring_backend() {
        KeyringBackend::Platform => Ok(()),
        backend => Err(WalletError::Network(
            NetworkError::MainnetKeyringBackendUnsupported {
                backend: backend.label(),
            },
        )),
    }
}

/// Verifies `profile`'s keyed audit writer as `profile_name` and returns
/// the proof.
///
/// Refuses a headless keyring backend first, through
/// [`refuse_headless_keyring_backend`], before any keyring entry is read.
/// Checks the audit binding and loads the key and the keyring-backed anchor
/// store, acquires the writer from the registry under `profile_name`,
/// locks the writer, requires its anchor store to be the keyring-backed store
/// at the profile's coordinate and its path to match the profile, runs
/// [`stellar_agent_core::audit_log::AuditWriter::verified_tip_facts`], and
/// requires the anchor to cover the tip and entry tags to be in force.
///
/// # Errors
///
/// - [`NetworkError::MainnetKeyringBackendUnsupported`] on a headless keyring
///   backend.
/// - The errors of [`crate::keyring::keyed_audit_access`].
/// - The audit refusal of a writer that cannot be acquired or verified, as
///   [`audit_writer_refusal`] maps it.
/// - `audit.chain_key_unavailable` naming `audit.anchor_provenance_unverified`
///   for a cached writer opened with another anchor store or at a path other
///   than the profile's, naming `audit.io_error` for a poisoned writer lock,
///   and naming `audit.tip_anchor_unavailable` for an anchor that does not
///   cover the tip or a log without its entry-tag boundary row.
/// - `wallet.clock_error` when the clock cannot be read.
pub fn audit_readiness(
    profile: &Profile,
    profile_name: &str,
) -> Result<AuditReadiness, WalletError> {
    refuse_headless_keyring_backend()?;
    let access = crate::keyring::keyed_audit_access(profile, profile_name, BindingCheck::Enforce)?;
    let expected = KeyringTipAnchorStore::new(
        &profile.audit_log_hash_chain_key_id,
        &profile.audit_log_path,
    );
    let writer =
        AuditWriterRegistry::get_or_open_keyed(profile_name, &profile.audit_log_path, access)
            .map_err(|error| audit_writer_refusal(profile_name, &error))?;
    let facts = {
        let mut guard = writer.lock().map_err(|_| {
            unusable(
                profile_name,
                "audit.io_error: the audit writer mutex is poisoned",
            )
        })?;
        let provenance = guard
            .tip_anchor_store()
            .is_some_and(|store| keyring_backed_at(store.as_ref(), &expected));
        if !provenance {
            return Err(unusable(
                profile_name,
                "audit.anchor_provenance_unverified: the writer lacks the profile's keyring anchor",
            ));
        }
        if stellar_agent_core::audit_log::log_path_sha256(guard.path())
            != stellar_agent_core::audit_log::log_path_sha256(&profile.audit_log_path)
        {
            return Err(unusable(
                profile_name,
                "audit.anchor_provenance_unverified: the writer's path differs from the profile",
            ));
        }
        let facts = guard
            .verified_tip_facts()
            .map_err(|error| audit_writer_refusal(profile_name, &error))?;
        refuse_unless_covered(profile_name, &facts)?;
        facts
    };
    let verified_at_ms = super::clock::now_ms()?;
    Ok(AuditReadiness {
        profile: profile_name.to_owned(),
        facts,
        verified_at_ms,
        writer: Arc::clone(&writer),
        expected,
    })
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use super::*;
    use serial_test::serial;
    use stellar_agent_core::audit_log::tip_anchor::{InMemoryTipAnchorStore, KeyedAuditAccess};
    use stellar_agent_core::audit_log::{
        AuditEntry, AuditOutbox, NewToolInvocation, PolicyDecision,
    };
    use stellar_agent_test_support::keyring_mock;
    use tempfile::TempDir;

    fn profile(dir: &std::path::Path, name: &str) -> Profile {
        let mut profile =
            Profile::builder_mainnet_named(name, "https://rpc.example.invalid", "s", "a", "n", "a")
                .build();
        profile.audit_log_path = dir.join("audit").join(format!("{name}.jsonl"));
        let key = &profile.audit_log_hash_chain_key_id;
        crate::keyring::rotate_keyring_secret_32(&key.service, &key.account).unwrap();
        profile
    }

    /// A consent row, one of the operator rows the audit outbox queues.
    fn consent_row() -> AuditEntry {
        AuditEntry::new_approval_attested(
            "PaymentSimulated",
            "stellar_pay_commit",
            None,
            "ABCDEFGHIJKLMNOPQRSTUV",
            "cli",
            "00000000-0000-4000-8000-000000000000",
        )
    }

    fn row() -> AuditEntry {
        AuditEntry::new_tool_invocation(NewToolInvocation::new(
            "stellar_pay_commit",
            "stellar:mainnet",
            vec![],
            PolicyDecision::Allow,
            "00000000-0000-4000-8000-000000000000",
        ))
    }

    /// A fresh log yields the proof at count one, its entry-tag boundary row;
    /// a later row and a drained outbox row raise the count, the proof keeps
    /// the registry's writer, and its fact digest follows the documented
    /// layout.
    #[test]
    #[serial]
    fn the_keyring_backed_writer_yields_the_proof() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let name = "readiness-accept";
        let profile = profile(dir.path(), name);
        let first = audit_readiness(&profile, name).unwrap();
        assert_eq!(first.profile(), name);
        assert_eq!(
            first.anchored_count(),
            1,
            "a fresh log holds only the boundary row"
        );
        assert_eq!(
            first.log_path_digest(),
            stellar_agent_core::audit_log::log_path_sha256(&profile.audit_log_path)
        );
        first.writer().lock().unwrap().write_entry(row()).unwrap();
        AuditOutbox::for_log(
            &profile.audit_log_path,
            crate::keyring::KeyringTipAnchorStore::shared(
                &profile.audit_log_hash_chain_key_id,
                &profile.audit_log_path,
            ),
        )
        .append(&consent_row())
        .unwrap();
        let second = audit_readiness(&profile, name).unwrap();
        assert_eq!(
            second.anchored_count(),
            3,
            "the count is taken after the drain"
        );
        assert!(Arc::ptr_eq(first.writer(), second.writer()));

        let mut expected = FACT_LABEL_AUDIT.to_vec();
        expected.extend(u32::try_from(name.len()).unwrap().to_be_bytes());
        expected.extend(name.as_bytes());
        expected.extend(second.log_path_digest());
        expected.extend(second.segment());
        expected.extend(3_u64.to_be_bytes());
        expected.extend(second.tip_hash());
        expected.extend(second.verified_at_ms().to_be_bytes());
        let independent: [u8; 32] = <sha2::Sha256 as sha2::Digest>::digest(&expected).into();
        assert_eq!(second.fact_digest(), independent);
    }

    /// A process whose default keyring store is the headless file store is
    /// refused with the backend named, before the binding is read or the
    /// writer opens.
    #[test]
    #[serial]
    fn a_headless_keyring_backend_refuses_mainnet_readiness() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let name = "readiness-headless";
        let profile = profile(dir.path(), name);
        keyring_core::set_default_store(Arc::new(
            stellar_agent_headless_keyring::store::HeadlessStore::new(
                dir.path().join("store.keyring"),
                stellar_agent_headless_keyring::crypto::ProtectionMode::EnvKey(Arc::new(
                    zeroize::Zeroizing::new([0x41; 32]),
                )),
            ),
        ));

        let err = audit_readiness(&profile, name)
            .expect_err("a headless backend must refuse mainnet readiness");
        keyring_mock::install().unwrap();
        assert_eq!(err.code(), "network.mainnet_keyring_backend_unsupported");
        assert!(err.to_string().contains("headless-env"), "{err}");
        assert!(
            !profile.audit_log_path.exists(),
            "the refusal comes before the writer opens"
        );
        assert!(
            crate::keyring::read_keyring_string(
                &stellar_agent_core::profile::schema::KeyringEntryRef::default_audit_binding(name)
            )
            .unwrap()
            .is_none(),
            "the refusal comes before the binding is recorded"
        );
        let key = &profile.audit_log_hash_chain_key_id;
        crate::keyring::rotate_keyring_secret_32(&key.service, &key.account).unwrap();
        audit_readiness(&profile, name).expect("the platform keyring is accepted");
    }

    /// A writer this process first opened with an injected anchor store, at
    /// the profile's own path and with its own key, never yields the proof:
    /// the cache is primed before the authentic acquisition, which then gets
    /// the primed writer back.
    #[test]
    #[serial]
    fn a_cached_writer_with_an_injected_anchor_store_refuses() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let name = "readiness-injected";
        let profile = profile(dir.path(), name);
        let key = crate::keyring::load_hmac_key_32(&profile.audit_log_hash_chain_key_id).unwrap();
        let primed = AuditWriterRegistry::get_or_open_keyed(
            name,
            &profile.audit_log_path,
            KeyedAuditAccess::new(key, Arc::new(InMemoryTipAnchorStore::new())),
        )
        .unwrap();
        let err = audit_readiness(&profile, name).unwrap_err();
        assert_eq!(err.code(), "audit.chain_key_unavailable");
        assert!(
            err.to_string()
                .contains("audit.anchor_provenance_unverified"),
            "{err}"
        );
        drop(primed);
    }

    /// A keyring-backed store at another coordinate is not the profile's.
    #[test]
    fn provenance_requires_the_profiles_own_coordinate() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let key = stellar_agent_core::profile::schema::KeyringEntryRef::default_audit_key("a");
        let other = stellar_agent_core::profile::schema::KeyringEntryRef::default_audit_key("b");
        let expected = KeyringTipAnchorStore::new(&key, &path);
        assert!(keyring_backed_at(
            &KeyringTipAnchorStore::new(&key, &path),
            &expected
        ));
        assert!(!keyring_backed_at(
            &KeyringTipAnchorStore::new(&other, &path),
            &expected
        ));
        assert!(!keyring_backed_at(
            &KeyringTipAnchorStore::new(&key, &dir.path().join("other.jsonl")),
            &expected
        ));
        assert!(!keyring_backed_at(
            &InMemoryTipAnchorStore::new(),
            &expected
        ));
    }

    /// Facts whose anchor does not cover the tip refuse, and so do facts of a
    /// log without entry tags in force; covered facts with tags in force pass.
    #[test]
    fn uncovered_facts_refuse() {
        let mut facts = VerifiedTipFacts {
            segment_start_hash: [0; 32],
            entry_count: 3,
            tip_hash: [1; 32],
            log_path_sha256: [2; 32],
            anchor_covers_tip: true,
            entry_tags_in_force: true,
        };
        assert!(refuse_unless_covered("p", &facts).is_ok());
        facts.entry_tags_in_force = false;
        let err = refuse_unless_covered("p", &facts).unwrap_err();
        assert!(
            err.to_string()
                .contains("audit.tip_anchor_unavailable: the audit log has no entry-tag boundary"),
            "{err}"
        );
        facts.entry_tags_in_force = true;
        facts.anchor_covers_tip = false;
        let err = refuse_unless_covered("p", &facts).unwrap_err();
        assert!(
            err.to_string().contains("audit.tip_anchor_unavailable"),
            "{err}"
        );
    }

    /// The proof keeps the writer, and with it the sidecar lock, alive after
    /// every other handle is gone.
    #[test]
    #[serial]
    fn the_proof_keeps_the_writer_alive() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let name = "readiness-lease";
        let profile = profile(dir.path(), name);
        let proof = audit_readiness(&profile, name).unwrap();
        AuditWriterRegistry::remove_for_test(name);
        assert_eq!(Arc::strong_count(proof.writer()), 1);
        assert!(matches!(
            stellar_agent_core::audit_log::AuditWriter::open(profile.audit_log_path.clone(), None),
            Err(stellar_agent_core::audit_log::WriterError::FileLocked)
        ));
    }

    #[test]
    #[serial]
    fn replacing_the_writer_cannot_reuse_its_provenance() {
        use stellar_agent_core::audit_log::AuditWriter;
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let name = "readiness-replaced";
        let profile = profile(dir.path(), name);
        let proof = audit_readiness(&profile, name).unwrap();
        assert!(proof.fresh_facts().is_ok());
        let replacement = AuditWriter::open_with_tip_anchor(
            dir.path().join("injected.jsonl"),
            None,
            Arc::new(InMemoryTipAnchorStore::new()),
            stellar_agent_core::audit_log::BindingHistory::NotRecorded,
        )
        .unwrap();
        let original = std::mem::replace(&mut *proof.writer().lock().unwrap(), replacement);
        drop(original);
        let error = audit_readiness(&profile, name).unwrap_err();
        assert!(matches!(
            error,
            WalletError::Validation(ValidationError::AuditLogUnusable { .. })
        ));
        assert!(
            error
                .to_string()
                .contains("audit.anchor_provenance_unverified")
        );
        assert!(matches!(
            proof.fresh_facts(),
            Err(MainnetAuthorizationError::Refused(
                MainnetPrecondition::AuditProvenance
            ))
        ));
        // Keeping the original path, the audit key and the anchor's value in
        // another store does not restore keyring provenance.
        let copied = InMemoryTipAnchorStore::new();
        copied.set(proof.expected.load_anchor().unwrap());
        let replacement = AuditWriter::open_with_tip_anchor(
            profile.audit_log_path.clone(),
            crate::keyring::read_secret_32(&profile.audit_log_hash_chain_key_id).unwrap(),
            Arc::new(copied),
            stellar_agent_core::audit_log::BindingHistory::NotRecorded,
        )
        .unwrap();
        let old = std::mem::replace(&mut *proof.writer().lock().unwrap(), replacement);
        drop(old);
        assert!(
            audit_readiness(&profile, name)
                .unwrap_err()
                .to_string()
                .contains("audit.anchor_provenance_unverified")
        );
        assert!(matches!(
            proof.fresh_facts(),
            Err(MainnetAuthorizationError::Refused(
                MainnetPrecondition::AuditProvenance
            ))
        ));
    }

    #[test]
    #[serial]
    fn a_keyring_writer_at_another_path_refuses() {
        use stellar_agent_core::audit_log::AuditWriter;
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let name = "readiness-path";
        let profile = profile(dir.path(), name);
        let proof = audit_readiness(&profile, name).unwrap();
        // A copy of the log matches the profile's anchor at another path.
        let other = dir.path().join("other.jsonl");
        std::fs::copy(&profile.audit_log_path, &other).unwrap();
        let replacement = AuditWriter::open_with_tip_anchor(
            other,
            crate::keyring::read_secret_32(&profile.audit_log_hash_chain_key_id).unwrap(),
            Arc::new(proof.expected.clone()),
            stellar_agent_core::audit_log::BindingHistory::NotRecorded,
        )
        .unwrap();
        let old = std::mem::replace(&mut *proof.writer().lock().unwrap(), replacement);
        drop(old);
        assert!(
            audit_readiness(&profile, name)
                .unwrap_err()
                .to_string()
                .contains("audit.anchor_provenance_unverified")
        );
        assert!(matches!(
            proof.fresh_facts(),
            Err(MainnetAuthorizationError::Refused(
                MainnetPrecondition::AuditProvenance
            ))
        ));
    }

    #[test]
    #[serial]
    fn an_evicted_registry_writer_refuses_readiness() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let name = "readiness-evicted";
        let profile = profile(dir.path(), name);
        let proof = audit_readiness(&profile, name).unwrap();
        proof.writer().lock().unwrap().write_entry(row()).unwrap();
        std::fs::rename(&profile.audit_log_path, dir.path().join("replaced.jsonl")).unwrap();
        std::fs::write(&profile.audit_log_path, b"").unwrap();
        assert!(audit_readiness(&profile, name).is_err());
        let error = audit_readiness(&profile, name).unwrap_err();
        assert_eq!(error.code(), "audit.tip_anchor_mismatch");
    }

    #[test]
    #[serial]
    fn fresh_facts_refuse_an_uncovered_tip_and_accept_its_repair() {
        let dir = TempDir::new().unwrap();
        let name = "readiness-lag";
        let path = dir.path().join("audit").join(format!("{name}.jsonl"));
        let key = stellar_agent_core::profile::schema::KeyringEntryRef::default_audit_key(name);
        let expected = KeyringTipAnchorStore::new(&key, &path);
        let entry = expected.anchor_entry_ref();
        let failing =
            keyring_mock::install_with_write_failure_switch(&entry.service, &entry.account)
                .unwrap();
        let profile = profile(dir.path(), name);
        let proof = audit_readiness(&profile, name).unwrap();
        assert!(proof.fresh_facts().is_ok());
        failing.store(true, std::sync::atomic::Ordering::SeqCst);
        AuditOutbox::for_log(
            &profile.audit_log_path,
            crate::keyring::KeyringTipAnchorStore::shared(
                &profile.audit_log_hash_chain_key_id,
                &profile.audit_log_path,
            ),
        )
        .append(&consent_row())
        .unwrap();
        assert!(matches!(
            proof.fresh_facts(),
            Err(MainnetAuthorizationError::Refused(
                MainnetPrecondition::AuditNotAnchored
            ))
        ));
        failing.store(false, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(proof.fresh_facts().unwrap().anchored_count, 2);
    }

    /// A keyring-anchored writer without the audit key leaves its log
    /// without entry tags in force: its facts are covered, and `fresh_facts`
    /// still refuses them. The keyed open that follows appends the boundary
    /// row, and its proof's facts pass.
    #[test]
    #[serial]
    fn fresh_facts_refuse_a_log_without_tags_in_force() {
        use stellar_agent_core::audit_log::{AuditWriter, BindingHistory};
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let name = "readiness-untagged";
        let profile = profile(dir.path(), name);
        let mut writer = AuditWriter::open_with_tip_anchor(
            profile.audit_log_path.clone(),
            None,
            KeyringTipAnchorStore::shared(
                &profile.audit_log_hash_chain_key_id,
                &profile.audit_log_path,
            ),
            BindingHistory::NotRecorded,
        )
        .unwrap();
        writer.write_entry(row()).unwrap();
        let facts = writer.verified_tip_facts().unwrap();
        assert!(facts.anchor_covers_tip);
        assert!(!facts.entry_tags_in_force);
        let untagged = AuditReadiness {
            expected: KeyringTipAnchorStore::for_path_digest(
                &profile.audit_log_hash_chain_key_id,
                &facts.log_path_sha256,
            ),
            profile: name.to_owned(),
            facts,
            verified_at_ms: 5,
            writer: Arc::new(std::sync::Mutex::new(writer)),
        };
        assert!(matches!(
            untagged.fresh_facts(),
            Err(MainnetAuthorizationError::Refused(
                MainnetPrecondition::AuditNotAnchored
            ))
        ));
        drop(untagged);

        let proof = audit_readiness(&profile, name).unwrap();
        assert_eq!(proof.fresh_facts().unwrap().anchored_count, 2);
    }

    #[test]
    fn the_audit_fact_digest_covers_the_segment() {
        let dir = TempDir::new().unwrap();
        let writer =
            stellar_agent_core::audit_log::AuditWriter::open(dir.path().join("audit.jsonl"), None)
                .unwrap();
        let proof = AuditReadiness {
            profile: "p".to_owned(),
            verified_at_ms: 5,
            facts: VerifiedTipFacts {
                entry_count: 3,
                tip_hash: [1; 32],
                log_path_sha256: [2; 32],
                segment_start_hash: [4; 32],
                anchor_covers_tip: true,
                entry_tags_in_force: true,
            },
            writer: Arc::new(std::sync::Mutex::new(writer)),
            expected: KeyringTipAnchorStore::for_path_digest(
                &stellar_agent_core::profile::schema::KeyringEntryRef::default_audit_key("p"),
                &[2; 32],
            ),
        };
        assert_eq!(
            stellar_agent_core::hex::encode(&proof.fact_digest()),
            "4b0d9b85e088227fb53242993d919e15f854e69a9816a7c82a85eed3bab8e603"
        );
    }
}
