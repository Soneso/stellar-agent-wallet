//! The approval witness: proof that a pending approval record, attested by
//! the operator under version 4, approves one subject, is live, and was
//! given by an approver still authorized when the witness is produced.
//!
//! [`verify_approval`] is the only producer. It reads the record from the
//! pending store by nonce and the attestation key from the keyring itself,
//! derives the key coordinate and the owner context from the profile exactly
//! as the approve path does, and accepts nothing else from its caller but
//! the nonce, the presented attestation, the binding, the expectation, and
//! the time. A witness therefore records facts the producer established, and
//! its fields are private:
//!
//! ```compile_fail,E0451
//! use stellar_agent_core::approval::witness::ApprovalWitness;
//! fn forge(p: ApprovalWitness) -> ApprovalWitness { ApprovalWitness { ..p } }
//! ```
//!
//! The import alone resolves:
//!
//! ```
//! use stellar_agent_core::approval::witness::ApprovalWitness;
//! fn need(_: Option<ApprovalWitness>) {}
//! need(None);
//! ```
//!
//! The witness implements none of `Serialize`, `Deserialize`, `Default`, or
//! `Clone`:
//!
//! ```compile_fail,E0277
//! use stellar_agent_core::approval::witness::ApprovalWitness;
//! fn need<T: serde::Serialize>() {}
//! need::<ApprovalWitness>();
//! ```
//!
//! ```compile_fail,E0277
//! use stellar_agent_core::approval::witness::ApprovalWitness;
//! fn need<T: serde::de::DeserializeOwned>() {}
//! need::<ApprovalWitness>();
//! ```
//!
//! ```compile_fail,E0277
//! use stellar_agent_core::approval::witness::ApprovalWitness;
//! fn need<T: Default>() {}
//! need::<ApprovalWitness>();
//! ```
//!
//! ```compile_fail,E0277
//! use stellar_agent_core::approval::witness::ApprovalWitness;
//! fn need<T: Clone>() {}
//! need::<ApprovalWitness>();
//! ```
//!
//! # Why version 4
//!
//! The pending file is not a security boundary, and a version 2 attestation
//! covers the profile, chain, nonce, subject, and process UID only. Under
//! version 2, a record's kind and lifetime are whatever the file says. A
//! version 3 attestation also covers them, so the witness's expiry is the
//! one the operator approved. A version 4 attestation also covers who
//! approved: the local operator, or the operator credential the remote
//! listener verified. A version 3 record cannot tell the two apart, so it is
//! no proof.
//!
//! # Revocation reaches the commit
//!
//! For a remote approver, [`verify_approval`] reads the profile's current
//! `[remote_approval] allowed_credentials` list and the current
//! operator-credential store again, through
//! [`super::remote_authorization::RemoteApprovalAuthority`], after every
//! other check. A credential removed from either record after it approved
//! produces no witness, so its approvals that were not yet committed
//! refuse. The read is fresh for every call; nothing is cached across
//! commits, and the caller's [`Profile`] value is never taken as the current
//! list.

use super::attest::{decode_sha256_hex, load_attestation_key};
use super::attestation::{AttestationBinding, AttestedApprover, verify_attestation};
use super::remote_authorization::RemoteApprovalAuthority;
use super::store::{ApprovalKind, PendingApprovalStore};
use super::subject::approval_subject_classic;
use crate::error::{ApprovalFailure, WalletError};
use crate::mainnet::fact::{FACT_LABEL_APPROVAL, FactDigest};
use crate::profile::caip2::Caip2;
use crate::profile::owner_key::OwnerKeyContext;
use crate::profile::schema::Profile;

/// The approval kinds a mainnet proof accepts, each a classic transaction
/// whose subject is [`approval_subject_classic`] of the record's envelope.
///
/// Account creation shares the payment kind, as its approval record does.
/// Every other record kind refuses as mainnet proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ApprovedKind {
    /// An x402 Soroban payment intent.
    X402Payment,
    /// A `PaymentSimulated` record: payments and account creation.
    Payment,
    /// A `ClaimSimulated` record.
    Claim,
    /// A `TrustlineSimulated` record.
    Trustline,
}

impl ApprovedKind {
    /// The kind's one-byte tag in the approval fact digest.
    #[must_use]
    pub fn tag(self) -> u8 {
        match self {
            Self::Payment => 1,
            Self::Claim => 2,
            Self::Trustline => 3,
            Self::X402Payment => 4,
        }
    }
}

/// What the caller requires the approval to approve.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApprovalExpectation {
    /// The record kind the action needs.
    pub kind: ApprovedKind,
    /// The subject the caller computed from the action it is about to
    /// authorize.
    pub subject: [u8; 32],
}

/// Proof that a version 4 attestation approves `subject`, was live at the
/// time [`verify_approval`] checked it, and came from an approver authorized
/// at that time.
///
/// See the module documentation for the producer and the sealing.
/// The `profile` field cannot be projected outside this crate.
///
/// ```compile_fail,E0616
/// use stellar_agent_core::approval::witness::ApprovalWitness;
/// fn inspect(p: &ApprovalWitness) { let _ = &p.profile; }
/// ```
///
/// ```
/// use stellar_agent_core::approval::witness::ApprovalWitness;
/// fn need(_: Option<ApprovalWitness>) {}
/// need(None);
/// ```
///
/// The `chain` field cannot be projected outside this crate.
///
/// ```compile_fail,E0616
/// use stellar_agent_core::approval::witness::ApprovalWitness;
/// fn inspect(p: &ApprovalWitness) { let _ = &p.chain; }
/// ```
///
/// ```
/// use stellar_agent_core::approval::witness::ApprovalWitness;
/// fn need(_: Option<ApprovalWitness>) {}
/// need(None);
/// ```
///
/// The `nonce` field cannot be projected outside this crate.
///
/// ```compile_fail,E0616
/// use stellar_agent_core::approval::witness::ApprovalWitness;
/// fn inspect(p: &ApprovalWitness) { let _ = &p.nonce; }
/// ```
///
/// ```
/// use stellar_agent_core::approval::witness::ApprovalWitness;
/// fn need(_: Option<ApprovalWitness>) {}
/// need(None);
/// ```
///
/// The `kind` field cannot be projected outside this crate.
///
/// ```compile_fail,E0616
/// use stellar_agent_core::approval::witness::ApprovalWitness;
/// fn inspect(p: &ApprovalWitness) { let _ = &p.kind; }
/// ```
///
/// ```
/// use stellar_agent_core::approval::witness::ApprovalWitness;
/// fn need(_: Option<ApprovalWitness>) {}
/// need(None);
/// ```
///
/// The `subject` field cannot be projected outside this crate.
///
/// ```compile_fail,E0616
/// use stellar_agent_core::approval::witness::ApprovalWitness;
/// fn inspect(p: &ApprovalWitness) { let _ = &p.subject; }
/// ```
///
/// ```
/// use stellar_agent_core::approval::witness::ApprovalWitness;
/// fn need(_: Option<ApprovalWitness>) {}
/// need(None);
/// ```
///
/// The `created_at_ms` field cannot be projected outside this crate.
///
/// ```compile_fail,E0616
/// use stellar_agent_core::approval::witness::ApprovalWitness;
/// fn inspect(p: &ApprovalWitness) { let _ = &p.created_at_ms; }
/// ```
///
/// ```
/// use stellar_agent_core::approval::witness::ApprovalWitness;
/// fn need(_: Option<ApprovalWitness>) {}
/// need(None);
/// ```
///
/// The `expires_at_ms` field cannot be projected outside this crate.
///
/// ```compile_fail,E0616
/// use stellar_agent_core::approval::witness::ApprovalWitness;
/// fn inspect(p: &ApprovalWitness) { let _ = &p.expires_at_ms; }
/// ```
///
/// ```
/// use stellar_agent_core::approval::witness::ApprovalWitness;
/// fn need(_: Option<ApprovalWitness>) {}
/// need(None);
/// ```
///
pub struct ApprovalWitness {
    profile: String,
    chain: Caip2,
    nonce: String,
    kind: ApprovedKind,
    subject: [u8; 32],
    created_at_ms: u64,
    expires_at_ms: u64,
}

impl std::fmt::Debug for ApprovalWitness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApprovalWitness")
            .field("profile", &self.profile)
            .field("chain", &self.chain.caip2_str())
            .field("kind", &self.kind)
            .field("expires_at_ms", &self.expires_at_ms)
            .finish_non_exhaustive()
    }
}

impl ApprovalWitness {
    /// The profile the approval was attested for.
    #[must_use]
    pub fn profile(&self) -> &str {
        &self.profile
    }

    /// The chain the approval was attested for.
    #[must_use]
    pub fn chain(&self) -> Caip2 {
        self.chain
    }

    /// The approval nonce.
    #[must_use]
    pub fn nonce(&self) -> &str {
        &self.nonce
    }

    /// The approved record kind.
    #[must_use]
    pub fn kind(&self) -> ApprovedKind {
        self.kind
    }

    /// The approved subject.
    #[must_use]
    pub fn subject(&self) -> [u8; 32] {
        self.subject
    }

    /// When the record was created, in Unix milliseconds, as the version 4
    /// attestation covers it.
    #[must_use]
    pub fn created_at_ms(&self) -> u64 {
        self.created_at_ms
    }

    /// When the approval expires, in Unix milliseconds: the stored expiry the
    /// version 4 attestation covers.
    #[must_use]
    pub fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }

    /// The fact digest under `stellar-agent-authz-fact:approval:v1`.
    ///
    /// Fields, in order: `lp(profile)`, `lp(chain)` as its CAIP-2 text,
    /// `lp(nonce)`, the kind's one-byte tag, the 32-byte subject,
    /// `u64be(created_at_ms)`, and `u64be(expires_at_ms)`.
    #[must_use]
    pub fn fact_digest(&self) -> [u8; 32] {
        let mut digest = FactDigest::new(FACT_LABEL_APPROVAL);
        digest
            .bytes(self.profile.as_bytes())
            .bytes(self.chain.caip2_str().as_bytes())
            .bytes(self.nonce.as_bytes())
            .tag(self.kind.tag())
            .fixed(&self.subject)
            .u64(self.created_at_ms)
            .u64(self.expires_at_ms);
        digest.finish()
    }
}

fn invalid(detail: &str) -> WalletError {
    WalletError::Approval(ApprovalFailure::AttestationInvalid {
        detail: detail.to_owned(),
    })
}

/// Verifies the approval `nonce` as mainnet proof for `expected` and returns
/// its witness.
///
/// In order:
///
/// 1. `binding` must name `profile_name` and `profile`'s chain.
/// 2. The record is read from `pending` by `nonce`. A rejected or consumed
///    record refuses, and so does a kind other than the three
///    [`ApprovedKind`]s or other than `expected.kind`.
/// 3. The record must store attestation version 4 with a well-formed
///    approver.
/// 4. The subject is recomputed from the record's envelope text; it must
///    equal the stored digest and `expected.subject`.
/// 5. The attestation key is loaded from `profile.attestation_key_id`,
///    refused when it is or may be the owner public key of `profile_name`,
///    and the attestation must verify under version 4 over the record's
///    nonce, subject, process UID, kind, lifetime, and approver.
/// 6. `created_at <= now_ms < expires_at` on the stored, attested times.
/// 7. For a remote approver, the authority of `profile_name` at the wallet's
///    own locations is read again: the profile's current
///    `allowed_credentials` list must name the recorded credential ID, the
///    operator-credential store must still hold it, and remote approval must
///    still be enabled for `profile`'s chain.
///
/// The witness's expiry is the stored expiry. A caller that governs the
/// approval by a shorter lifetime compares [`ApprovalWitness::created_at_ms`]
/// and [`ApprovalWitness::expires_at_ms`] with it.
///
/// # Errors
///
/// - `approval.not_found`, `approval.rejected`, `approval.consumed`, or
///   `approval.wrong_kind` for the record.
/// - `approval.attestation_invalid` for a version other than 4, a missing
///   or malformed approver, a subject mismatch, or an attestation that does
///   not verify.
/// - `approval.expired` outside the record's lifetime.
/// - The key loader's errors, including the owner-key refusal.
/// - `approval.operator_credential_revoked` or
///   `approval.remote_authorization_unavailable` when a remote approver is
///   not authorized now or its authorization cannot be read.
#[allow(
    clippy::too_many_arguments,
    reason = "the producer takes each input it does not derive itself"
)]
pub fn verify_approval(
    pending: &PendingApprovalStore,
    profile: &Profile,
    profile_name: &str,
    nonce: &str,
    attestation: &[u8; 32],
    expected: &ApprovalExpectation,
    now_ms: u64,
) -> Result<ApprovalWitness, WalletError> {
    verify_approval_with(
        pending,
        profile,
        profile_name,
        nonce,
        attestation,
        expected,
        now_ms,
        RemoteApprovalAuthority::for_profile,
    )
}

/// [`verify_approval`] with the remote authority resolved by `authority`
/// from the profile name, so a test can point it at isolated files.
#[allow(
    clippy::too_many_arguments,
    reason = "the producer takes each input it does not derive itself"
)]
pub(crate) fn verify_approval_with(
    pending: &PendingApprovalStore,
    profile: &Profile,
    profile_name: &str,
    nonce: &str,
    attestation: &[u8; 32],
    expected: &ApprovalExpectation,
    now_ms: u64,
    authority: impl FnOnce(&str) -> Result<RemoteApprovalAuthority, WalletError>,
) -> Result<ApprovalWitness, WalletError> {
    let binding = AttestationBinding::new(profile_name, profile.chain_id.caip2_str());
    let record = pending.get(nonce).ok_or_else(|| {
        WalletError::Approval(ApprovalFailure::NotFound {
            detail: "no pending approval with that nonce".to_owned(),
        })
    })?;
    if let Some(summary) = super::attest::classic_entry_summary(&record.kind) {
        summary?;
    }
    let (kind, subject, stored_digest) = match &record.kind {
        ApprovalKind::PaymentSimulated {
            envelope_xdr_b64,
            envelope_sha256_hex,
            ..
        } => (
            ApprovedKind::Payment,
            approval_subject_classic(envelope_xdr_b64),
            decode_sha256_hex(envelope_sha256_hex)?,
        ),
        ApprovalKind::ClaimSimulated {
            envelope_xdr_b64,
            envelope_sha256_hex,
            ..
        } => (
            ApprovedKind::Claim,
            approval_subject_classic(envelope_xdr_b64),
            decode_sha256_hex(envelope_sha256_hex)?,
        ),
        ApprovalKind::TrustlineSimulated {
            envelope_xdr_b64,
            envelope_sha256_hex,
            ..
        } => (
            ApprovedKind::Trustline,
            approval_subject_classic(envelope_xdr_b64),
            decode_sha256_hex(envelope_sha256_hex)?,
        ),
        ApprovalKind::X402Payment {
            intent_digest,
            root_invocation_xdr,
            home_domain,
            ..
        } => {
            let subject = super::subject::verified_x402_subject(
                intent_digest,
                root_invocation_xdr,
                home_domain.as_deref(),
                profile.chain_id.network_passphrase(),
            )?;
            (ApprovedKind::X402Payment, subject, subject)
        }
        ApprovalKind::Rejected { .. } => {
            return Err(WalletError::Approval(ApprovalFailure::Rejected {
                detail: "the operator rejected this approval".to_owned(),
            }));
        }
        ApprovalKind::Consumed { .. } => {
            return Err(WalletError::Approval(ApprovalFailure::Consumed {
                detail: "this approval was already spent on a submission".to_owned(),
            }));
        }
        other => {
            return Err(WalletError::Approval(ApprovalFailure::WrongKind {
                detail: format!("{} approvals are no mainnet proof", other.kind_name()),
            }));
        }
    };
    if kind != expected.kind {
        return Err(WalletError::Approval(ApprovalFailure::WrongKind {
            detail: "the approval is for another kind of action".to_owned(),
        }));
    }
    let Some(scope) = record.attestation_scope() else {
        return Err(invalid(
            "the approval's attestation does not cover its kind, lifetime and approver; \
             approve the action again",
        ));
    };
    if stored_digest != subject || subject != expected.subject {
        return Err(invalid("the approval approves another transaction"));
    }
    let key = load_attestation_key(
        &profile.attestation_key_id,
        &OwnerKeyContext::for_profile(profile_name, profile),
    )?;
    let key: [u8; 32] = key.as_slice().try_into().map_err(|_| {
        WalletError::Approval(ApprovalFailure::KeyLengthError {
            detail: format!("attestation key must be 32 bytes, got {}", key.len()),
        })
    })?;
    let key = zeroize::Zeroizing::new(key);
    if !verify_attestation(
        &key,
        &binding,
        &record.approval_nonce,
        &subject,
        &record.process_uid,
        &scope,
        attestation,
    ) {
        return Err(invalid("the attestation does not verify"));
    }
    if record.created_at_unix_ms > now_ms || now_ms >= record.expires_at_unix_ms {
        return Err(WalletError::Approval(ApprovalFailure::Expired {
            detail: "the approval is outside its lifetime".to_owned(),
        }));
    }
    match &record.attested_approver {
        Some(AttestedApprover::Local) => {}
        Some(AttestedApprover::Remote {
            credential_id_b64url,
        }) => {
            authority(profile_name)?.require_credential(
                credential_id_b64url,
                profile.chain_id,
                None,
            )?;
        }
        None => return Err(invalid("the approval names no approver")),
    }
    Ok(ApprovalWitness {
        profile: profile_name.to_owned(),
        chain: profile.chain_id,
        nonce: record.approval_nonce.clone(),
        kind,
        subject,
        created_at_ms: record.created_at_unix_ms,
        expires_at_ms: record.expires_at_unix_ms,
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
    use crate::approval::attestation::{
        AttestedLifetime, PENDING_ATTESTATION_VERSION, compute_attestation, compute_attestation_v4,
    };
    use crate::approval::operator_credentials::{
        OperatorApprovalCredential, OperatorApprovalCredentialStore,
    };
    use crate::approval::store::{DEFAULT_TTL_MS, PendingApproval};
    use crate::profile::schema::{KeyringEntryRef, RemoteApprovalConfig};
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use serial_test::serial;
    use stellar_agent_test_support::keyring_mock;
    use tempfile::TempDir;

    const NAME: &str = "witness";
    static ENVELOPE: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
        let source = stellar_strkey::ed25519::PublicKey([1; 32]).to_string();
        super::super::fixtures::payment_envelope(&source, &source, "XLM", 1000, None, 100, 7)
    });
    const KEY: [u8; 32] = [0x5a; 32];
    const RP_ID: &str = "wallet.test.internal";

    struct Fixture {
        dir: TempDir,
        path: std::path::PathBuf,
        profile: Profile,
        nonce: String,
        blob: [u8; 32],
        created: u64,
        expires: u64,
    }

    fn profile() -> Profile {
        Profile::builder_mainnet_named(NAME, "https://rpc.example.invalid", "s", "a", "n", "a")
            .build()
    }

    fn put_key(entry: &KeyringEntryRef, key: &[u8; 32]) {
        keyring_core::Entry::new(&entry.service, &entry.account)
            .unwrap()
            .set_password(&URL_SAFE_NO_PAD.encode(key))
            .unwrap();
    }

    fn binding() -> AttestationBinding<'static> {
        AttestationBinding::new(NAME, "stellar:mainnet")
    }

    fn credential_id(seed: u8) -> String {
        URL_SAFE_NO_PAD.encode([seed; 16])
    }

    fn remote(seed: u8) -> AttestedApprover {
        AttestedApprover::Remote {
            credential_id_b64url: credential_id(seed),
        }
    }

    fn remote_config(enabled: bool, ids: Vec<String>) -> RemoteApprovalConfig {
        let mut config: RemoteApprovalConfig = toml::from_str(&format!(
            "enabled = {enabled}\nbind = \"127.0.0.1:8443\"\nrp_id = \"{RP_ID}\"\n"
        ))
        .unwrap();
        config.allowed_credentials = ids;
        config
    }

    fn profile_dir(dir: &std::path::Path) -> std::path::PathBuf {
        dir.join("profiles")
    }

    fn credentials_path(dir: &std::path::Path) -> std::path::PathBuf {
        dir.join("credentials").join(format!("{NAME}.toml"))
    }

    /// The authority of [`NAME`] over the files under `dir`.
    fn authority(dir: &std::path::Path) -> RemoteApprovalAuthority {
        RemoteApprovalAuthority::from_paths(
            NAME.to_owned(),
            profile_dir(dir),
            credentials_path(dir),
        )
        .unwrap()
    }

    /// Writes `profile` to disk under `dir` with remote approval enabled for
    /// `ids`, the way `approve operator allow` does.
    fn allow(dir: &std::path::Path, profile: &Profile, ids: &[String]) {
        let mut stored = profile.clone();
        stored.remote_approval = Some(remote_config(true, ids.to_vec()));
        crate::profile::loader::save_to_dir(NAME, &stored, &profile_dir(dir)).unwrap();
    }

    fn enroll(dir: &std::path::Path, credential_id_b64url: &str) {
        let mut key = vec![0x04u8; 65];
        key[1] = 7;
        OperatorApprovalCredentialStore::new(credentials_path(dir))
            .enroll(OperatorApprovalCredential {
                credential_id_b64url: credential_id_b64url.to_owned(),
                public_key_sec1_b64: URL_SAFE_NO_PAD.encode(key),
                rp_id: RP_ID.to_owned(),
                label: "device".to_owned(),
                registered_at_unix_ms: 1,
                sign_count: None,
            })
            .unwrap();
    }

    /// Inserts `entry` into the store at `path` and records a version 4
    /// attestation of `subject` by `approver`, the way the approve path
    /// attests. Returns the nonce and the blob.
    fn attest_entry(
        path: &std::path::Path,
        entry: PendingApproval,
        subject: &[u8; 32],
        approver: &AttestedApprover,
    ) -> (String, [u8; 32]) {
        assert_eq!(entry.attestation_version, PENDING_ATTESTATION_VERSION);
        let nonce = entry.approval_nonce.clone();
        let created = entry.created_at_unix_ms;
        let blob = compute_attestation_v4(
            &KEY,
            &binding(),
            &nonce,
            subject,
            "1000",
            &entry.attested_lifetime(),
            approver,
        );
        let mut store = PendingApprovalStore::open(path.to_path_buf()).unwrap();
        store.insert(entry, created).unwrap();
        store
            .record_attestation_at(&nonce, blob, approver.clone(), created)
            .unwrap();
        (nonce, blob)
    }

    fn payment_entry() -> PendingApproval {
        PendingApproval::new_payment_pending(
            ENVELOPE.to_string(),
            ENVELOPE.as_bytes(),
            stellar_strkey::ed25519::PublicKey([1; 32])
                .to_string()
                .to_string(),
            1_000,
            "XLM".to_owned(),
            None,
            100,
            7,
            "1000".to_owned(),
            DEFAULT_TTL_MS,
        )
        .unwrap()
    }

    /// A payment approval for [`ENVELOPE`] by the local operator, attested
    /// with [`KEY`] under the record's own kind and lifetime.
    fn fixture() -> Fixture {
        fixture_by(&AttestedApprover::Local)
    }

    /// A payment approval for [`ENVELOPE`] by `approver`. A remote
    /// approver's credential is enrolled and allowed on disk, and the
    /// returned profile carries the same `[remote_approval]` block, as the
    /// commit's in-memory profile does.
    fn fixture_by(approver: &AttestedApprover) -> Fixture {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(format!("{NAME}.toml"));
        let mut profile = profile();
        put_key(&profile.attestation_key_id, &KEY);
        if let AttestedApprover::Remote {
            credential_id_b64url,
        } = approver
        {
            let ids = vec![credential_id_b64url.clone()];
            allow(dir.path(), &profile, &ids);
            profile.remote_approval = Some(remote_config(true, ids));
            enroll(dir.path(), credential_id_b64url);
        }
        let entry = payment_entry();
        let created = entry.created_at_unix_ms;
        let expires = entry.expires_at_unix_ms;
        let (nonce, blob) =
            attest_entry(&path, entry, &approval_subject_classic(&ENVELOPE), approver);
        Fixture {
            dir,
            path,
            profile,
            nonce,
            blob,
            created,
            expires,
        }
    }

    fn expectation() -> ApprovalExpectation {
        ApprovalExpectation {
            kind: ApprovedKind::Payment,
            subject: approval_subject_classic(&ENVELOPE),
        }
    }

    fn verify(f: &Fixture, blob: &[u8; 32], now: u64) -> Result<ApprovalWitness, WalletError> {
        let store = PendingApprovalStore::open(f.path.clone()).unwrap();
        verify_approval_with(
            &store,
            &f.profile,
            NAME,
            &f.nonce,
            blob,
            &expectation(),
            now,
            |name| {
                assert_eq!(name, NAME);
                Ok(authority(f.dir.path()))
            },
        )
    }

    /// Applies `edit` to the first record of the pending file as a TOML
    /// table, the way anyone with write access to the file can.
    fn edit_record(path: &std::path::Path, edit: impl FnOnce(&mut toml_edit::Table)) {
        let mut doc: toml_edit::DocumentMut =
            std::fs::read_to_string(path).unwrap().parse().unwrap();
        let record = doc["pending"]
            .as_array_of_tables_mut()
            .unwrap()
            .get_mut(0)
            .unwrap();
        edit(record);
        std::fs::write(path, doc.to_string()).unwrap();
    }

    fn approver_table(kind: &str, credential_id_b64url: Option<&str>) -> toml_edit::Item {
        let mut table = toml_edit::Table::new();
        table["kind"] = toml_edit::value(kind);
        if let Some(id) = credential_id_b64url {
            table["credential_id_b64url"] = toml_edit::value(id);
        }
        toml_edit::Item::Table(table)
    }

    /// Rewrites `field = value` lines of the pending file, the way anyone
    /// with write access to it can.
    fn rewrite(path: &std::path::Path, field: &str, value: u64) {
        let text = std::fs::read_to_string(path).unwrap();
        let rewritten = text
            .lines()
            .map(|line| {
                if line.trim_start().starts_with(&format!("{field} =")) {
                    format!("{field} = {value}")
                } else {
                    line.to_owned()
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(path, rewritten).unwrap();
    }

    /// An attested, live, matching approval yields a witness of exactly the
    /// record's facts, and its fact digest follows the documented layout.
    #[test]
    #[serial]
    fn a_live_version_4_approval_yields_its_witness() {
        let f = fixture();
        let witness = verify(&f, &f.blob, f.created).unwrap();
        assert_eq!(witness.profile(), NAME);
        assert_eq!(witness.chain(), Caip2::Mainnet);
        assert_eq!(witness.nonce(), f.nonce);
        assert_eq!(witness.kind(), ApprovedKind::Payment);
        assert_eq!(witness.subject(), approval_subject_classic(&ENVELOPE));
        assert_eq!(witness.created_at_ms(), f.created);
        assert_eq!(witness.expires_at_ms(), f.expires);

        let mut expected = FACT_LABEL_APPROVAL.to_vec();
        for field in [NAME.as_bytes(), b"stellar:mainnet", f.nonce.as_bytes()] {
            expected.extend(u32::try_from(field.len()).unwrap().to_be_bytes());
            expected.extend(field);
        }
        expected.push(1);
        expected.extend(approval_subject_classic(&ENVELOPE));
        expected.extend(f.created.to_be_bytes());
        expected.extend(f.expires.to_be_bytes());
        let independent: [u8; 32] = <sha2::Sha256 as sha2::Digest>::digest(&expected).into();
        assert_eq!(witness.fact_digest(), independent);
    }

    /// The lifetime holds at its first millisecond and refuses before it and
    /// at the expiry itself.
    #[test]
    #[serial]
    fn freshness_holds_on_the_stored_boundaries() {
        let f = fixture();
        assert!(verify(&f, &f.blob, f.created).is_ok());
        assert!(verify(&f, &f.blob, f.expires - 1).is_ok());
        for now in [f.created - 1, f.expires, f.expires + 1] {
            let err = verify(&f, &f.blob, now).unwrap_err();
            assert_eq!(err.code(), "approval.expired", "{now}");
        }
    }

    /// An approval that expired unused, whose stored creation and expiry are
    /// then moved forward in the file, does not verify: version 4 covers both.
    #[test]
    #[serial]
    fn moving_an_expired_approval_forward_refuses() {
        let f = fixture();
        let later = f.expires + 10_000;
        assert_eq!(
            verify(&f, &f.blob, later).unwrap_err().code(),
            "approval.expired"
        );
        rewrite(&f.path, "created_at_unix_ms", later - 1);
        rewrite(&f.path, "expires_at_unix_ms", later + DEFAULT_TTL_MS);
        let store = PendingApprovalStore::open(f.path.clone()).unwrap();
        let moved = store.get(&f.nonce).unwrap();
        assert_eq!(moved.created_at_unix_ms, later - 1);
        drop(store);
        assert_eq!(
            verify(&f, &f.blob, later).unwrap_err().code(),
            "approval.attestation_invalid"
        );
    }

    /// A record without a stored version reads as version 2 and refuses as
    /// mainnet proof, even with the genuine blob its attestation step wrote.
    #[test]
    #[serial]
    fn a_version_2_record_refuses_as_mainnet_proof() {
        let f = fixture();
        let text = std::fs::read_to_string(&f.path).unwrap();
        let without: String = text
            .lines()
            .filter(|line| !line.trim_start().starts_with("attestation_version"))
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(&f.path, without).unwrap();
        let store = PendingApprovalStore::open(f.path.clone()).unwrap();
        assert_eq!(store.get(&f.nonce).unwrap().attestation_version, 2);
        drop(store);
        assert_eq!(
            verify(&f, &f.blob, f.created).unwrap_err().code(),
            "approval.attestation_invalid"
        );
    }

    /// An attestation computed with another key does not verify against the
    /// key the producer loads from the keyring, and the record's own blob does
    /// not verify once the keyring holds another key.
    #[test]
    #[serial]
    fn a_wrong_key_attestation_refuses_against_the_loaded_key() {
        let f = fixture();
        let store = PendingApprovalStore::open(f.path.clone()).unwrap();
        let record = store.get(&f.nonce).unwrap().clone();
        drop(store);
        let forged = compute_attestation_v4(
            &[0x11; 32],
            &binding(),
            &f.nonce,
            &approval_subject_classic(&ENVELOPE),
            "1000",
            &AttestedLifetime::new(
                record.kind.kind_name(),
                record.created_at_unix_ms,
                record.expires_at_unix_ms,
            ),
            &AttestedApprover::Local,
        );
        assert_eq!(
            verify(&f, &forged, f.created).unwrap_err().code(),
            "approval.attestation_invalid"
        );
        put_key(&f.profile.attestation_key_id, &[0x11; 32]);
        assert_eq!(
            verify(&f, &f.blob, f.created).unwrap_err().code(),
            "approval.attestation_invalid"
        );
        assert!(verify(&f, &forged, f.created).is_ok());
    }

    /// The kind, the subject, the binding, rejection, consumption, an unknown
    /// nonce, and a missing key each refuse on their own.
    #[test]
    #[serial]
    fn each_mismatch_refuses_on_its_own() {
        let f = fixture();
        let store = PendingApprovalStore::open(f.path.clone()).unwrap();
        let call = |expected: &ApprovalExpectation, profile: &Profile, name: &str, nonce: &str| {
            verify_approval(&store, profile, name, nonce, &f.blob, expected, f.created)
                .map(|_| ())
                .unwrap_err()
                .code()
        };
        assert_eq!(
            call(
                &ApprovalExpectation {
                    kind: ApprovedKind::Claim,
                    ..expectation()
                },
                &f.profile,
                NAME,
                &f.nonce
            ),
            "approval.wrong_kind"
        );
        assert_eq!(
            call(
                &ApprovalExpectation {
                    subject: [0; 32],
                    ..expectation()
                },
                &f.profile,
                NAME,
                &f.nonce
            ),
            "approval.attestation_invalid"
        );
        let mut other = f.profile.clone();
        other.chain_id = Caip2::Testnet;
        assert_eq!(
            call(&expectation(), &other, NAME, &f.nonce),
            "approval.attestation_invalid"
        );
        assert_eq!(
            call(&expectation(), &f.profile, "other", &f.nonce),
            "approval.attestation_invalid"
        );
        assert_eq!(
            call(&expectation(), &f.profile, NAME, "AAAAAAAAAAAAAAAAAAAAAA"),
            "approval.not_found"
        );
        drop(store);

        keyring_core::Entry::new(
            &f.profile.attestation_key_id.service,
            &f.profile.attestation_key_id.account,
        )
        .unwrap()
        .delete_credential()
        .unwrap();
        assert_eq!(
            verify(&f, &f.blob, f.created).unwrap_err().code(),
            "auth.keyring_not_found"
        );
        put_key(&f.profile.attestation_key_id, &KEY);

        let mut store = PendingApprovalStore::open(f.path.clone()).unwrap();
        store
            .consume(
                &f.nonce,
                &"ab".repeat(32),
                crate::approval::store::ConsumedOutcome::Unknown,
            )
            .unwrap();
        drop(store);
        assert_eq!(
            verify(&f, &f.blob, f.created).unwrap_err().code(),
            "approval.consumed"
        );

        let g = fixture();
        let mut store = PendingApprovalStore::open(g.path.clone()).unwrap();
        store.reject(&g.nonce, g.created, DEFAULT_TTL_MS).unwrap();
        drop(store);
        assert_eq!(
            verify(&g, &g.blob, g.created).unwrap_err().code(),
            "approval.rejected"
        );
    }

    #[test]
    #[serial]
    fn configured_attestation_coordinates_and_owner_context_are_used() {
        let mut f = fixture();
        f.profile.attestation_key_id = KeyringEntryRef::new("custom-attestation", "custom");
        put_key(&KeyringEntryRef::default_attestation_key(NAME), &[8; 32]);
        put_key(&f.profile.attestation_key_id, &KEY);
        assert!(verify(&f, &f.blob, f.created).is_ok());
        f.profile.policy_owner_key_id = KeyringEntryRef::new("custom-owner", "public");
        keyring_core::Entry::new("custom-owner", "public")
            .unwrap()
            .set_password(stellar_strkey::ed25519::PublicKey(KEY).to_string().as_ref())
            .unwrap();
        assert_eq!(
            verify(&f, &f.blob, f.created).unwrap_err().code(),
            "validation.key_matches_owner_public_key"
        );
        keyring_core::Entry::new("custom-owner", "public")
            .unwrap()
            .set_password(
                stellar_strkey::ed25519::PublicKey([3; 32])
                    .to_string()
                    .as_ref(),
            )
            .unwrap();
        assert!(verify(&f, &f.blob, f.created).is_ok());
    }

    #[test]
    #[serial]
    fn the_stored_subject_digest_is_compared() {
        let f = fixture();
        assert!(verify(&f, &f.blob, f.created).is_ok());
        let text = std::fs::read_to_string(&f.path).unwrap();
        let good = crate::hex::encode(&approval_subject_classic(&ENVELOPE));
        assert!(text.contains(&good));
        std::fs::write(&f.path, text.replace(&good, &"00".repeat(32))).unwrap();
        assert_eq!(
            verify(&f, &f.blob, f.created).unwrap_err().code(),
            "approval.entry_inconsistent"
        );
    }

    /// A payment, a claim and a trustline approval over real envelopes, each
    /// with the subject the commit expects.
    fn classic_entries() -> Vec<(ApprovedKind, PendingApproval, [u8; 32])> {
        let address = stellar_strkey::ed25519::PublicKey([1; 32])
            .to_string()
            .to_string();
        let balance = stellar_strkey::ClaimableBalance::V0([1; 32])
            .to_string()
            .to_string();
        let claim_xdr = super::super::fixtures::claim_envelope(&address, [1; 32], 100, 7);
        let trust_xdr = super::super::fixtures::change_trust_envelope(
            &address,
            "USD",
            &address,
            Some(100),
            100,
            7,
        );
        vec![
            (
                ApprovedKind::Payment,
                payment_entry(),
                approval_subject_classic(&ENVELOPE),
            ),
            (
                ApprovedKind::Claim,
                PendingApproval::new_claim_pending(
                    claim_xdr.clone(),
                    claim_xdr.as_bytes(),
                    format!("00000000{}", "01".repeat(32)),
                    balance,
                    "XLM".to_owned(),
                    1,
                    address.clone(),
                    100,
                    7,
                    "1000".to_owned(),
                    DEFAULT_TTL_MS,
                )
                .unwrap(),
                approval_subject_classic(&claim_xdr),
            ),
            (
                ApprovedKind::Trustline,
                PendingApproval::new_trustline_pending(
                    trust_xdr.clone(),
                    trust_xdr.as_bytes(),
                    address.clone(),
                    "USD".to_owned(),
                    address,
                    Some(100),
                    100,
                    7,
                    "1000".to_owned(),
                    DEFAULT_TTL_MS,
                )
                .unwrap(),
                approval_subject_classic(&trust_xdr),
            ),
        ]
    }

    #[test]
    #[serial]
    fn claim_and_trustline_approvals_yield_witnesses() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let profile = profile();
        put_key(&profile.attestation_key_id, &KEY);
        for (kind, entry, subject) in classic_entries() {
            let now = entry.created_at_unix_ms;
            let path = dir.path().join(format!("{kind:?}.toml"));
            let (nonce, blob) = attest_entry(&path, entry, &subject, &AttestedApprover::Local);
            let store = PendingApprovalStore::open(path).unwrap();
            let witness = verify_approval(
                &store,
                &profile,
                NAME,
                &nonce,
                &blob,
                &ApprovalExpectation { kind, subject },
                now,
            )
            .unwrap();
            assert_eq!(witness.kind(), kind);
        }
    }

    /// Version 2 and 3 records, a version 4 record whose approver was
    /// deleted, and a remote approval rewritten to another approver each
    /// refuse with the genuine blob of the layout the record claims. Version
    /// 4 approvals by the local operator and by an authorized remote
    /// credential verify.
    #[test]
    #[serial]
    fn legacy_pending_attestation_cannot_bypass_revocation() {
        for approver in [AttestedApprover::Local, remote(1)] {
            let f = fixture_by(&approver);
            let witness = verify(&f, &f.blob, f.created).unwrap();
            assert_eq!(witness.nonce(), f.nonce);
        }

        // A version 3 record with the genuine version 3 blob, with and
        // without its approver: that layout does not attest who approved.
        for keep_approver in [false, true] {
            let f = fixture_by(&remote(1));
            let lifetime = {
                let store = PendingApprovalStore::open(f.path.clone()).unwrap();
                let record = store.get(&f.nonce).unwrap();
                (
                    record.kind.kind_name(),
                    record.created_at_unix_ms,
                    record.expires_at_unix_ms,
                )
            };
            let v3_blob = compute_attestation(
                &KEY,
                &binding(),
                &f.nonce,
                &approval_subject_classic(&ENVELOPE),
                "1000",
                &AttestedLifetime::new(lifetime.0, lifetime.1, lifetime.2),
            );
            edit_record(&f.path, |record| {
                record["attestation_version"] = toml_edit::value(3);
                record["attestation_blob_b64"] = toml_edit::value(URL_SAFE_NO_PAD.encode(v3_blob));
                if !keep_approver {
                    record.remove("attested_approver");
                }
            });
            let store = PendingApprovalStore::open(f.path.clone()).unwrap();
            assert_eq!(store.get(&f.nonce).unwrap().attestation_version, 3);
            drop(store);
            assert_eq!(
                verify(&f, &v3_blob, f.created).unwrap_err().code(),
                "approval.attestation_invalid",
                "keep_approver = {keep_approver}"
            );
        }

        // A version 4 record whose approver was deleted.
        let f = fixture_by(&remote(1));
        edit_record(&f.path, |record| {
            record.remove("attested_approver").unwrap();
        });
        let store = PendingApprovalStore::open(f.path.clone()).unwrap();
        let record = store.get(&f.nonce).unwrap();
        assert!(record.attested_approver.is_none());
        assert!(record.attestation_scope().is_none());
        drop(store);
        assert_eq!(
            verify(&f, &f.blob, f.created).unwrap_err().code(),
            "approval.attestation_invalid"
        );

        // A remote approval rewritten to the local operator, or to another
        // credential that is itself allowed and enrolled.
        for rewritten in [
            approver_table("local", None),
            approver_table("remote", Some(&credential_id(2))),
        ] {
            let f = fixture_by(&remote(1));
            allow(
                f.dir.path(),
                &f.profile,
                &[credential_id(1), credential_id(2)],
            );
            enroll(f.dir.path(), &credential_id(2));
            edit_record(&f.path, |record| {
                record["attested_approver"] = rewritten;
            });
            assert_eq!(
                verify(&f, &f.blob, f.created).unwrap_err().code(),
                "approval.attestation_invalid"
            );
        }
    }

    /// A remote approval attested while its credential was authorized
    /// refuses at the commit once the profile on disk stops allowing it or
    /// disables remote approval, although the commit's in-memory profile
    /// still lists it. Payment, claim and trustline approvals alike.
    #[test]
    #[serial]
    fn witness_reloads_revocation_after_attestation() {
        keyring_mock::install().unwrap();
        for (kind, entry, subject) in classic_entries() {
            for edit in ["removed", "disabled"] {
                let dir = TempDir::new().unwrap();
                let mut profile = profile();
                put_key(&profile.attestation_key_id, &KEY);
                let ids = vec![credential_id(1), credential_id(2)];
                allow(dir.path(), &profile, &ids);
                profile.remote_approval = Some(remote_config(true, ids));
                enroll(dir.path(), &credential_id(1));
                enroll(dir.path(), &credential_id(2));
                let now = entry.created_at_unix_ms;
                let path = dir.path().join("pending.toml");
                let (nonce, blob) = attest_entry(&path, entry.clone(), &subject, &remote(1));
                let check = || {
                    let store = PendingApprovalStore::open(path.clone()).unwrap();
                    verify_approval_with(
                        &store,
                        &profile,
                        NAME,
                        &nonce,
                        &blob,
                        &ApprovalExpectation { kind, subject },
                        now,
                        |_| Ok(authority(dir.path())),
                    )
                };
                assert_eq!(check().unwrap().kind(), kind);
                let expected = match edit {
                    "removed" => {
                        allow(dir.path(), &profile, &[credential_id(2)]);
                        "approval.operator_credential_revoked"
                    }
                    _ => {
                        let mut stored = profile.clone();
                        stored.remote_approval = Some(remote_config(false, vec![credential_id(1)]));
                        crate::profile::loader::save_to_dir(
                            NAME,
                            &stored,
                            &profile_dir(dir.path()),
                        )
                        .unwrap();
                        "approval.remote_authorization_unavailable"
                    }
                };
                assert!(
                    profile
                        .remote_approval
                        .as_ref()
                        .unwrap()
                        .allowed_credentials
                        .contains(&credential_id(1))
                );
                assert_eq!(check().unwrap_err().code(), expected, "{kind:?} {edit}");
            }
        }
    }

    /// Removing a credential's enrollment while the profile still allows it
    /// refuses its outstanding approval at the commit, and leaves the
    /// approvals of another enrolled credential valid.
    #[test]
    #[serial]
    fn credential_removal_revokes_pending_approval() {
        let f = fixture_by(&remote(1));
        let other = fixture_by(&remote(2));
        verify(&f, &f.blob, f.created).unwrap();
        verify(&other, &other.blob, other.created).unwrap();
        assert!(
            OperatorApprovalCredentialStore::new(credentials_path(f.dir.path()))
                .remove(&credential_id(1))
                .unwrap()
        );
        assert!(
            authority(f.dir.path())
                .load_current()
                .unwrap()
                .allows(&credential_id(1))
        );
        assert_eq!(
            verify(&f, &f.blob, f.created).unwrap_err().code(),
            "approval.operator_credential_revoked"
        );
        verify(&other, &other.blob, other.created).unwrap();
    }

    /// The authority is resolved for the approval's profile name only when
    /// the approver is remote; a local approval never reads it.
    #[test]
    #[serial]
    fn local_approval_never_reads_remote_authority() {
        let f = fixture();
        let store = PendingApprovalStore::open(f.path.clone()).unwrap();
        verify_approval_with(
            &store,
            &f.profile,
            NAME,
            &f.nonce,
            &f.blob,
            &expectation(),
            f.created,
            |_| panic!("a local approval has no remote authority to read"),
        )
        .unwrap();
        drop(store);
        let r = fixture_by(&remote(1));
        let store = PendingApprovalStore::open(r.path.clone()).unwrap();
        let err = verify_approval_with(
            &store,
            &r.profile,
            NAME,
            &r.nonce,
            &r.blob,
            &expectation(),
            r.created,
            |name| {
                assert_eq!(name, NAME);
                Err(WalletError::Approval(
                    ApprovalFailure::RemoteAuthorizationUnavailable {
                        detail: "unreadable".to_owned(),
                    },
                ))
            },
        )
        .unwrap_err();
        assert_eq!(err.code(), "approval.remote_authorization_unavailable");
    }

    #[test]
    #[serial_test::serial]
    fn resolution_refuses_previously_attested_non_utf8_claim_memo() {
        use stellar_xdr::{Limits, Memo, ReadXdr as _, TransactionEnvelope, WriteXdr as _};
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let profile = profile();
        put_key(&profile.attestation_key_id, &KEY);
        let source = stellar_strkey::ed25519::PublicKey([1; 32]).to_string();
        let xdr = super::super::fixtures::claim_envelope(&source, [9; 32], 100, 7);
        let TransactionEnvelope::Tx(mut tx) =
            TransactionEnvelope::from_xdr_base64(&xdr, Limits::none()).unwrap()
        else {
            unreachable!()
        };
        tx.tx.memo = Memo::Text(vec![0xff, 0xfe].try_into().unwrap());
        let xdr = TransactionEnvelope::Tx(tx)
            .to_xdr_base64(Limits::none())
            .unwrap();
        let (id, strkey) = super::super::fixtures::balance_ids([9; 32]);
        let entry = PendingApproval::new_claim_pending(
            xdr.clone(),
            xdr.as_bytes(),
            id,
            strkey,
            "XLM".to_owned(),
            1,
            source.to_string(),
            100,
            7,
            "1000".to_owned(),
            DEFAULT_TTL_MS,
        )
        .unwrap();
        let subject = approval_subject_classic(&xdr);
        let now = entry.created_at_unix_ms;
        let path = dir.path().join("claim.toml");
        let (nonce, blob) = attest_entry(&path, entry, &subject, &AttestedApprover::Local);
        let store = PendingApprovalStore::open(path).unwrap();
        assert_eq!(
            verify_approval(
                &store,
                &profile,
                NAME,
                &nonce,
                &blob,
                &ApprovalExpectation {
                    kind: ApprovedKind::Claim,
                    subject
                },
                now
            )
            .unwrap_err()
            .code(),
            "approval.entry_inconsistent"
        );
    }
}
