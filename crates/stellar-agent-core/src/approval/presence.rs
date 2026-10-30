//! Mainnet consent by a WebAuthn assertion from an owner-pinned credential.
//!
//! A mainnet approval takes effect only with a fresh WebAuthn assertion, with
//! user presence (UP) and user verification (UV), from a credential the
//! owner-signed policy lists in `mainnet.approval_credentials`
//! ([`MainnetApprovalCredential`]). Terminal input, a process identity, and
//! the attestation HMAC key alone produce no mainnet consent.
//!
//! # Ceremony
//!
//! 1. [`issue_mainnet_presence`] snapshots a live, unattested pending entry
//!    with the verified policy and an expected origin, draws 32 random bytes
//!    and a consent request ID, and computes the challenge. The returned
//!    [`PendingMainnetPresence`] is single use: it has no `Clone`, and
//!    [`verify_mainnet_presence`] consumes it.
//! 2. The authenticator signs the challenge. [`MainnetPresenceOptions`] tells
//!    the page what to ask for; the verifier never reads it back.
//! 3. [`verify_mainnet_presence`] checks the assertion against the
//!    snapshot's challenge, origin and signed credential key, and returns a
//!    [`VerifiedMainnetPresence`]. That type has no other producer.
//! 4. The attester consumes the verified presence, rechecks the locked entry
//!    and the current policy, and records a version 5 attestation with the
//!    [`MainnetPresenceReceipt`].
//!
//! The commit witness verifies the stored receipt again: the raw assertion
//! under the current signed key, over the challenge recomputed from the
//! stored record.
//!
//! # Challenge
//!
//! ```text
//! SHA-256(
//!   b"stellar-agent-mainnet-presence:v1" ||
//!   random32 || lp(consent_request_id) || lp(approval_nonce) ||
//!   lp(profile_name) || lp(chain_caip2) || lp(kind_name) ||
//!   subject32 || lp(process_uid) ||
//!   u64be(entry_created_at_ms) || u64be(entry_expires_at_ms) ||
//!   i64be(policy_sequence) || policy_digest32 || policy_owner32 ||
//!   lp(b"localhost") || lp(expected_origin) ||
//!   u64be(challenge_issued_at_ms) || u64be(challenge_expires_at_ms)
//! )
//! ```
//!
//! `lp(x)` is `u32be(len(x)) || x`; a length beyond `u32::MAX` refuses.
//!
//! # Origin and relying party
//!
//! The relying-party ID is [`MAINNET_APPROVAL_RP_ID`]. The expected origin is
//! exactly `http://localhost:<port>` with a canonical decimal port in
//! `1..=65535`, chosen by the caller from its bound listener; no request
//! header selects it. `clientDataJSON.origin` must equal it, `crossOrigin`
//! must be absent or `false`, and `topOrigin` must be absent.
//!
//! # Counters
//!
//! The signature counter in authenticator bytes 33..37 is recorded and
//! audited only. A zero, repeated or decreasing counter neither waives a
//! check nor refuses an otherwise valid fresh assertion. Replay defense is
//! the random single-use challenge and the pending entry's lifecycle; the
//! wallet does not detect cloned credentials.
//!
//! # Sealing
//!
//! ```compile_fail,E0451
//! use stellar_agent_core::approval::presence::VerifiedMainnetPresence;
//! fn forge(p: VerifiedMainnetPresence) -> VerifiedMainnetPresence {
//!     VerifiedMainnetPresence { ..p }
//! }
//! ```
//!
//! The import alone resolves:
//!
//! ```
//! use stellar_agent_core::approval::presence::VerifiedMainnetPresence;
//! fn need(_: Option<VerifiedMainnetPresence>) {}
//! need(None);
//! ```
//!
//! ```compile_fail,E0277
//! use stellar_agent_core::approval::presence::VerifiedMainnetPresence;
//! fn need<T: Clone>() {}
//! need::<VerifiedMainnetPresence>();
//! ```
//!
//! ```compile_fail,E0277
//! use stellar_agent_core::approval::presence::VerifiedMainnetPresence;
//! fn need<T: serde::Serialize>() {}
//! need::<VerifiedMainnetPresence>();
//! ```
//!
//! ```compile_fail,E0277
//! use stellar_agent_core::approval::presence::VerifiedMainnetPresence;
//! fn need<T: serde::de::DeserializeOwned>() {}
//! need::<VerifiedMainnetPresence>();
//! ```
//!
//! ```compile_fail,E0277
//! use stellar_agent_core::approval::presence::VerifiedMainnetPresence;
//! fn need<T: Default>() {}
//! need::<VerifiedMainnetPresence>();
//! ```
//!
//! A pending challenge cannot be duplicated, so one challenge verifies at
//! most once:
//!
//! ```compile_fail,E0277
//! use stellar_agent_core::approval::presence::PendingMainnetPresence;
//! fn need<T: Clone>() {}
//! need::<PendingMainnetPresence>();
//! ```
//!
//! ```compile_fail,E0451
//! use stellar_agent_core::approval::presence::PendingMainnetPresence;
//! fn forge(p: PendingMainnetPresence) -> PendingMainnetPresence {
//!     PendingMainnetPresence { ..p }
//! }
//! ```

use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand_core::{OsRng, RngCore as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::AssertionInput;
use super::attestation::AttestationBinding;
use super::store::{ApprovalKind, PendingApproval};
use crate::audit_log::schema::MainnetPresenceAudit;
use crate::error::{ApprovalFailure, WalletError};
use crate::mainnet::verified_policy::VerifiedPolicy;
use crate::profile::caip2::Caip2;

/// The relying-party ID of every mainnet approval credential.
pub const MAINNET_APPROVAL_RP_ID: &str = "localhost";

/// The CAIP-2 chain of every mainnet consent.
pub const MAINNET_CHAIN_ID: &str = "stellar:mainnet";

/// The longest life of one presence challenge, in milliseconds.
pub const MAINNET_PRESENCE_CHALLENGE_TTL_MS: u64 = 120_000;

/// The fewest approval credentials a mainnet policy lists.
pub const MAINNET_APPROVAL_CREDENTIALS_MIN: usize = 1;

/// The most approval credentials a mainnet policy lists.
pub const MAINNET_APPROVAL_CREDENTIALS_MAX: usize = 16;

/// The shortest credential ID, in decoded bytes.
pub const CREDENTIAL_ID_MIN_BYTES: usize = 16;

/// The longest credential ID, in decoded bytes.
pub const CREDENTIAL_ID_MAX_BYTES: usize = 64;

/// The only authenticator-data length a mainnet consent accepts: the RP-ID
/// hash, the flags byte and the counter, with no attested credential data and
/// no extensions.
pub const MAINNET_AUTHENTICATOR_DATA_BYTES: usize = 37;

/// The longest `clientDataJSON`, in bytes.
pub const MAINNET_CLIENT_DATA_JSON_MAX_BYTES: usize = 1024;

/// The longest DER signature, in bytes.
pub const MAINNET_SIGNATURE_DER_MAX_BYTES: usize = 80;

/// The largest serialized receipt the pending-store reader accepts, in bytes.
/// Sixteen KiB covers the bounded fields as TOML byte arrays and leaves room
/// for field names and whitespace; the reader checks it before receipt decoding.
pub(crate) const MAINNET_PRESENCE_RECEIPT_MAX_BYTES: usize = 16 * 1024;

const RECEIPT_REQUEST_ID_MAX_BYTES: usize = 36;
const RECEIPT_RANDOM_MAX_BYTES: usize = 43;
const RECEIPT_HEX_MAX_BYTES: usize = 64;
const RECEIPT_ORIGIN_MAX_BYTES: usize = "http://localhost:65535".len();
const RECEIPT_SIGNATURE_BYTES: usize = 64;

/// The SEC1 uncompressed P-256 point length.
const SEC1_UNCOMPRESSED_BYTES: usize = 65;

/// The version of the receipt layout this build writes and reads.
pub const MAINNET_PRESENCE_RECEIPT_VERSION: u32 = 1;

const CHALLENGE_DOMAIN: &[u8] = b"stellar-agent-mainnet-presence:v1";
const VIEW_DOMAIN: &[u8] = b"stellar-agent-mainnet-consent-view:v1";
const RECEIPT_DOMAIN: &[u8] = b"stellar-agent-mainnet-presence-receipt:v1";
const CREDENTIAL_FINGERPRINT_DOMAIN: &[u8] = b"stellar-agent-mainnet-approval-credential:v1";

/// Authenticator flag bits a mainnet consent refuses: the reserved bits
/// 0x02 and 0x20, attested credential data (AT, 0x40) and extension data
/// (ED, 0x80). The page requests no extensions and an assertion carries no
/// credential data.
const REFUSED_FLAGS: u8 = 0x02 | 0x20 | super::webauthn::FLAG_AT | super::webauthn::FLAG_ED;

/// The fixed message of an unsupported pending kind.
pub const UNSUPPORTED_KIND_MESSAGE: &str = "This pending kind has no mainnet consent path.";

// ─────────────────────────────────────────────────────────────────────────────
// Encodings
// ─────────────────────────────────────────────────────────────────────────────

/// Decodes canonical unpadded base64url of `min..=max` bytes.
///
/// The encoded length is checked before any buffer is allocated, and the
/// decoded bytes must encode back to exactly `value`, so one byte string has
/// one accepted text form.
#[must_use]
pub fn decode_canonical_b64url(value: &str, min: usize, max: usize) -> Option<Vec<u8>> {
    let max_encoded = max.checked_mul(4)?.div_ceil(3);
    if value.is_empty() || value.len() > max_encoded {
        return None;
    }
    let bytes = URL_SAFE_NO_PAD.decode(value).ok()?;
    if bytes.len() < min || bytes.len() > max || URL_SAFE_NO_PAD.encode(&bytes) != value {
        return None;
    }
    Some(bytes)
}

/// A SHA-256 preimage builder whose length prefixes refuse rather than
/// saturate.
struct Preimage {
    hasher: Sha256,
    overflow: bool,
}

impl Preimage {
    fn new(domain: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(domain);
        Self {
            hasher,
            overflow: false,
        }
    }

    fn lp(&mut self, bytes: &[u8]) -> &mut Self {
        match u32::try_from(bytes.len()) {
            Ok(len) => {
                self.hasher.update(len.to_be_bytes());
                self.hasher.update(bytes);
            }
            Err(_) => self.overflow = true,
        }
        self
    }

    fn fixed(&mut self, bytes: &[u8]) -> &mut Self {
        self.hasher.update(bytes);
        self
    }

    fn u32(&mut self, value: u32) -> &mut Self {
        self.hasher.update(value.to_be_bytes());
        self
    }

    fn u64(&mut self, value: u64) -> &mut Self {
        self.hasher.update(value.to_be_bytes());
        self
    }

    fn i64(&mut self, value: i64) -> &mut Self {
        self.hasher.update(value.to_be_bytes());
        self
    }

    fn finish(self) -> Option<[u8; 32]> {
        (!self.overflow).then(|| self.hasher.finalize().into())
    }
}

/// Whether `origin` is exactly `http://localhost:<port>` with a canonical
/// decimal port in `1..=65535`.
#[must_use]
pub fn is_mainnet_presence_origin(origin: &str) -> bool {
    let Some(port) = origin.strip_prefix("http://localhost:") else {
        return false;
    };
    !port.is_empty()
        && port.len() <= 5
        && port.bytes().all(|b| b.is_ascii_digit())
        && !port.starts_with('0')
        && port.parse::<u16>().is_ok_and(|port| port >= 1)
}

/// The expected origin of a listener bound to `port`.
#[must_use]
pub fn mainnet_presence_origin(port: u16) -> String {
    format!("http://{MAINNET_APPROVAL_RP_ID}:{port}")
}

/// Whether `value` is the canonical lowercase hyphenated form of a version 4
/// UUID.
fn is_canonical_uuid_v4(value: &str) -> bool {
    uuid::Uuid::parse_str(value)
        .is_ok_and(|id| id.get_version_num() == 4 && id.hyphenated().to_string() == value)
}

fn is_lower_hex32(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn decode_lower_hex32(value: &str) -> Option<[u8; 32]> {
    if !is_lower_hex32(value) {
        return None;
    }
    crate::hex::decode_hex32(value).ok()
}

// ─────────────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────────────

fn presence_invalid() -> WalletError {
    WalletError::Approval(ApprovalFailure::PresenceInvalid)
}

fn presence_expired() -> WalletError {
    WalletError::Approval(ApprovalFailure::PresenceExpired)
}

fn policy_unavailable() -> WalletError {
    WalletError::Approval(ApprovalFailure::PresencePolicyUnavailable)
}

fn unsupported_kind() -> WalletError {
    WalletError::Approval(ApprovalFailure::WrongKind {
        detail: UNSUPPORTED_KIND_MESSAGE.to_owned(),
    })
}

fn binding_mismatch() -> WalletError {
    WalletError::Approval(ApprovalFailure::BindingMismatch {
        detail: "this request belongs to another profile or network".to_owned(),
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Approval credentials
// ─────────────────────────────────────────────────────────────────────────────

/// Why an approval credential's encoded form is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ApprovalCredentialError {
    /// The credential ID is not canonical unpadded base64url of 16 to 64
    /// bytes.
    CredentialId,
    /// The key is not a 65-byte SEC1 uncompressed point on P-256.
    PublicKey,
}

impl std::fmt::Display for ApprovalCredentialError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::CredentialId => "Invalid approval credential id.",
            Self::PublicKey => "Invalid approval credential P-256 public key.",
        })
    }
}

impl std::error::Error for ApprovalCredentialError {}

/// One approval credential the owner admits in the signed mainnet policy: a
/// WebAuthn credential ID and its P-256 public key.
///
/// The signed list is the whole mainnet approval authority: the remote
/// allowlist, the operator-credential store and the smart-account passkey
/// registry add none. Every constructor validates both fields, so a value
/// always holds a 16 to 64 byte ID and a valid uncompressed point.
#[derive(Clone, PartialEq, Eq)]
pub struct MainnetApprovalCredential {
    credential_id: Vec<u8>,
    public_key_sec1: [u8; 65],
}

impl std::fmt::Debug for MainnetApprovalCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MainnetApprovalCredential")
            .field("credential_id_len", &self.credential_id.len())
            .field("fingerprint", &self.fingerprint())
            .finish()
    }
}

impl MainnetApprovalCredential {
    /// Decodes the policy form: canonical unpadded base64url of the
    /// credential ID and of the SEC1 uncompressed public key.
    ///
    /// # Errors
    ///
    /// [`ApprovalCredentialError::CredentialId`] or
    /// [`ApprovalCredentialError::PublicKey`] for the first field that is not
    /// canonical or not valid.
    pub fn from_encoded(
        credential_id_b64url: &str,
        public_key_sec1_b64url: &str,
    ) -> Result<Self, ApprovalCredentialError> {
        let credential_id = decode_canonical_b64url(
            credential_id_b64url,
            CREDENTIAL_ID_MIN_BYTES,
            CREDENTIAL_ID_MAX_BYTES,
        )
        .ok_or(ApprovalCredentialError::CredentialId)?;
        let key = decode_canonical_b64url(
            public_key_sec1_b64url,
            SEC1_UNCOMPRESSED_BYTES,
            SEC1_UNCOMPRESSED_BYTES,
        )
        .ok_or(ApprovalCredentialError::PublicKey)?;
        Self::from_raw(&credential_id, &key)
    }

    /// Validates raw bytes: a 16 to 64 byte credential ID and a 65-byte SEC1
    /// uncompressed P-256 point.
    ///
    /// # Errors
    ///
    /// As [`Self::from_encoded`].
    pub fn from_raw(
        credential_id: &[u8],
        public_key_sec1: &[u8],
    ) -> Result<Self, ApprovalCredentialError> {
        if !(CREDENTIAL_ID_MIN_BYTES..=CREDENTIAL_ID_MAX_BYTES).contains(&credential_id.len()) {
            return Err(ApprovalCredentialError::CredentialId);
        }
        let key: [u8; 65] = public_key_sec1
            .try_into()
            .map_err(|_| ApprovalCredentialError::PublicKey)?;
        if key[0] != 0x04 || p256::PublicKey::from_sec1_bytes(&key).is_err() {
            return Err(ApprovalCredentialError::PublicKey);
        }
        Ok(Self {
            credential_id: credential_id.to_vec(),
            public_key_sec1: key,
        })
    }

    /// The raw credential ID.
    #[must_use]
    pub fn credential_id(&self) -> &[u8] {
        &self.credential_id
    }

    /// The SEC1 uncompressed public key `0x04 || x || y`.
    #[must_use]
    pub fn public_key_sec1(&self) -> &[u8; 65] {
        &self.public_key_sec1
    }

    /// The canonical unpadded base64url form of the credential ID.
    #[must_use]
    pub fn credential_id_b64url(&self) -> String {
        URL_SAFE_NO_PAD.encode(&self.credential_id)
    }

    /// The canonical unpadded base64url form of the public key.
    #[must_use]
    pub fn public_key_sec1_b64url(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.public_key_sec1)
    }

    /// `sha256:` followed by the lowercase hex SHA-256 of
    /// `b"stellar-agent-mainnet-approval-credential:v1" || lp(id) || key`.
    ///
    /// Audit rows and command output name a credential by this value, which
    /// reveals neither the ID nor the key.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(CREDENTIAL_FINGERPRINT_DOMAIN);
        // The ID is at most 64 bytes, so its length always fits a u32.
        hasher.update(
            u32::try_from(self.credential_id.len())
                .unwrap_or(u32::MAX)
                .to_be_bytes(),
        );
        hasher.update(&self.credential_id);
        hasher.update(self.public_key_sec1);
        format!("sha256:{}", crate::hex::encode(&hasher.finalize()))
    }

    /// The canonical inline-table entry of `mainnet.approval_credentials`.
    #[must_use]
    pub fn policy_entry_toml(&self) -> String {
        format!(
            "{{ credential_id_b64url = \"{}\", public_key_sec1_b64url = \"{}\" }}",
            self.credential_id_b64url(),
            self.public_key_sec1_b64url()
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Subject and view digest
// ─────────────────────────────────────────────────────────────────────────────

/// The subject a mainnet consent to `entry` approves.
///
/// Payment, claim and trustline entries approve SHA-256 of the exact stored
/// unsigned envelope text, after the stored digest is checked against it and
/// the envelope decodes. An x402 entry approves its verified intent subject
/// on the binding's network, authenticated or not. A trustline clawback
/// opt-in approves its `(network, code, issuer)` commitment, and its network
/// must be the binding's chain. Every other kind refuses: no zero or
/// placeholder subject exists.
///
/// # Errors
///
/// `approval.wrong_kind` for an unsupported kind,
/// `approval.entry_inconsistent` for a classic entry whose digest or envelope
/// does not check, `approval.attestation_invalid` for an x402 invocation that
/// does not match its digest, and `approval.binding_mismatch` for a chain
/// that is not a CAIP-2 chain or an opt-in for another network.
pub fn mainnet_consent_subject(
    entry: &PendingApproval,
    binding: &AttestationBinding<'_>,
) -> Result<[u8; 32], WalletError> {
    match &entry.kind {
        ApprovalKind::PaymentSimulated {
            envelope_xdr_b64, ..
        }
        | ApprovalKind::ClaimSimulated {
            envelope_xdr_b64, ..
        }
        | ApprovalKind::TrustlineSimulated {
            envelope_xdr_b64, ..
        } => {
            if let Some(summary) = super::attest::classic_entry_summary(&entry.kind) {
                summary?;
            }
            Ok(super::subject::approval_subject_classic(envelope_xdr_b64))
        }
        ApprovalKind::X402Payment {
            intent_digest,
            root_invocation_xdr,
            home_domain,
            ..
        } => {
            let chain: Caip2 = binding.chain_id.parse().map_err(|_| binding_mismatch())?;
            super::subject::verified_x402_subject(
                intent_digest,
                root_invocation_xdr,
                home_domain.as_deref(),
                chain.network_passphrase(),
            )
        }
        ApprovalKind::TrustlineClawbackOptIn {
            network,
            code,
            issuer,
        } => {
            if network != binding.chain_id {
                return Err(binding_mismatch());
            }
            Ok(super::attestation::compute_trustline_clawback_opt_in_digest(network, code, issuer))
        }
        ApprovalKind::SignWithPasskey { .. }
        | ApprovalKind::RegisterPasskey { .. }
        | ApprovalKind::ToolsetFirstInvokeGate { .. }
        | ApprovalKind::RuleProposalSimulated { .. }
        | ApprovalKind::MppChargeSimulated { .. }
        | ApprovalKind::Rejected { .. }
        | ApprovalKind::Consumed { .. } => Err(unsupported_kind()),
    }
}

/// The consent fields every challenge and view digest binds, in order.
fn consent_fields(
    preimage: &mut Preimage,
    entry: &PendingApproval,
    binding: &AttestationBinding<'_>,
    subject: &[u8; 32],
    policy: &VerifiedPolicy,
) {
    preimage
        .lp(entry.approval_nonce.as_bytes())
        .lp(binding.profile_name.as_bytes())
        .lp(binding.chain_id.as_bytes())
        .lp(entry.kind.kind_name().as_bytes())
        .fixed(subject)
        .lp(entry.process_uid.as_bytes())
        .u64(entry.created_at_unix_ms)
        .u64(entry.expires_at_unix_ms)
        .i64(policy.sequence())
        .fixed(&policy.digest())
        .fixed(&policy.owner());
}

/// The digest of the consent details a page renders, for a stale-view check.
///
/// ```text
/// SHA-256(
///   b"stellar-agent-mainnet-consent-view:v1" || lp(approval_nonce) ||
///   lp(profile_name) || lp(chain_caip2) || lp(kind_name) || subject32 ||
///   lp(process_uid) || u64be(entry_created_at_ms) ||
///   u64be(entry_expires_at_ms) || i64be(policy_sequence) ||
///   policy_digest32 || policy_owner32
/// )
/// ```
///
/// Every input is also in the challenge, so the digest adds no authority: a
/// page compares it with a freshly computed value before it asks for a
/// challenge, and a mismatch means the rendered details are stale.
///
/// # Errors
///
/// The errors of [`mainnet_consent_subject`], and
/// `approval.presence_invalid` for a field longer than `u32::MAX` bytes.
pub fn mainnet_consent_view_digest(
    entry: &PendingApproval,
    binding: &AttestationBinding<'_>,
    policy: &VerifiedPolicy,
) -> Result<[u8; 32], WalletError> {
    let subject = mainnet_consent_subject(entry, binding)?;
    let mut preimage = Preimage::new(VIEW_DOMAIN);
    consent_fields(&mut preimage, entry, binding, &subject, policy);
    preimage.finish().ok_or_else(presence_invalid)
}

/// Every input of one challenge.
pub(crate) struct ChallengeFacts<'a> {
    pub(crate) random: &'a [u8; 32],
    pub(crate) request_id: &'a str,
    pub(crate) entry: &'a PendingApproval,
    pub(crate) binding: &'a AttestationBinding<'a>,
    pub(crate) subject: &'a [u8; 32],
    pub(crate) policy: &'a VerifiedPolicy,
    pub(crate) expected_origin: &'a str,
    pub(crate) issued_at_unix_ms: u64,
    pub(crate) expires_at_unix_ms: u64,
}

/// The challenge of the module documentation; `None` for a field longer
/// than `u32::MAX` bytes.
pub(crate) fn mainnet_presence_challenge(facts: &ChallengeFacts<'_>) -> Option<[u8; 32]> {
    let mut preimage = Preimage::new(CHALLENGE_DOMAIN);
    preimage.fixed(facts.random).lp(facts.request_id.as_bytes());
    consent_fields(
        &mut preimage,
        facts.entry,
        facts.binding,
        facts.subject,
        facts.policy,
    );
    preimage
        .lp(MAINNET_APPROVAL_RP_ID.as_bytes())
        .lp(facts.expected_origin.as_bytes())
        .u64(facts.issued_at_unix_ms)
        .u64(facts.expires_at_unix_ms);
    preimage.finish()
}

// ─────────────────────────────────────────────────────────────────────────────
// Assertion checks
// ─────────────────────────────────────────────────────────────────────────────

/// Detects a member's presence, `null` included.
fn present<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<serde_json::Value>, D::Error> {
    serde_json::Value::deserialize(deserializer).map(Some)
}

/// The security members of `clientDataJSON`. A duplicate of any of them
/// refuses; other members are ignored.
#[derive(Deserialize)]
struct ClientDataSecurity {
    #[serde(rename = "type")]
    type_field: String,
    challenge: String,
    origin: String,
    #[serde(rename = "crossOrigin", default, deserialize_with = "present")]
    cross_origin: Option<serde_json::Value>,
    #[serde(rename = "topOrigin", default, deserialize_with = "present")]
    top_origin: Option<serde_json::Value>,
}

/// What a verified assertion's authenticator data says.
#[derive(Debug, Clone)]
pub(crate) struct AssertionFacts {
    pub(crate) credential: MainnetApprovalCredential,
    pub(crate) user_present: bool,
    pub(crate) user_verified: bool,
    pub(crate) sign_count: u32,
}

/// Verifies `assertion` as a mainnet consent to `challenge` at
/// `expected_origin`, under the key `policy` signs for its credential ID.
///
/// The original bytes are checked; no JSON is rebuilt before the signature
/// check. Every refusal is `approval.presence_invalid`.
pub(crate) fn check_assertion(
    policy: &VerifiedPolicy,
    challenge: &[u8; 32],
    expected_origin: &str,
    assertion: &AssertionInput,
) -> Result<AssertionFacts, WalletError> {
    if !is_mainnet_presence_origin(expected_origin) {
        return Err(presence_invalid());
    }
    if !(CREDENTIAL_ID_MIN_BYTES..=CREDENTIAL_ID_MAX_BYTES).contains(&assertion.credential_id.len())
        || assertion.authenticator_data.len() != MAINNET_AUTHENTICATOR_DATA_BYTES
        || assertion.client_data_json.is_empty()
        || assertion.client_data_json.len() > MAINNET_CLIENT_DATA_JSON_MAX_BYTES
        || super::assertion_input::validate_signature_compact(&assertion.signature_compact).is_err()
    {
        return Err(presence_invalid());
    }
    let credential = policy
        .mainnet()
        .and_then(|body| {
            body.approval_credentials
                .iter()
                .find(|credential| credential.credential_id() == assertion.credential_id.as_slice())
        })
        .cloned()
        .ok_or_else(presence_invalid)?;
    let flags = assertion.authenticator_data[32];
    if flags & REFUSED_FLAGS != 0 {
        return Err(presence_invalid());
    }
    let client: ClientDataSecurity =
        serde_json::from_slice(&assertion.client_data_json).map_err(|_| presence_invalid())?;
    let cross_origin_ok = match &client.cross_origin {
        None => true,
        Some(serde_json::Value::Bool(cross)) => !cross,
        Some(_) => false,
    };
    if client.type_field != "webauthn.get"
        || client.challenge != URL_SAFE_NO_PAD.encode(challenge)
        || client.origin != expected_origin
        || !cross_origin_ok
        || client.top_origin.is_some()
    {
        return Err(presence_invalid());
    }
    let signature: [u8; 64] = assertion
        .signature_compact
        .as_slice()
        .try_into()
        .map_err(|_| presence_invalid())?;
    let rp_id_hash: [u8; 32] = Sha256::digest(MAINNET_APPROVAL_RP_ID.as_bytes()).into();
    super::webauthn::pre_verify_assertion(
        challenge,
        credential.public_key_sec1(),
        &assertion.authenticator_data,
        &assertion.client_data_json,
        &signature,
        &rp_id_hash,
    )
    .map_err(|error| {
        tracing::debug!(reason = %error, "mainnet presence assertion refused");
        presence_invalid()
    })?;
    let mut counter = [0u8; 4];
    counter.copy_from_slice(&assertion.authenticator_data[33..37]);
    Ok(AssertionFacts {
        credential,
        user_present: flags & super::webauthn::FLAG_UP != 0,
        user_verified: flags & super::webauthn::FLAG_UV != 0,
        sign_count: u32::from_be_bytes(counter),
    })
}

/// The browser's assertion, as the page posts it: unpadded base64url of the
/// raw credential ID, authenticator data, `clientDataJSON` and DER
/// signature.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MainnetAssertionWire {
    /// The credential's raw ID.
    pub credential_id_b64url: String,
    /// The authenticator data.
    pub authenticator_data_b64url: String,
    /// The `clientDataJSON` bytes.
    pub client_data_json_b64url: String,
    /// The DER ECDSA signature.
    pub signature_der_b64url: String,
}

impl std::fmt::Debug for MainnetAssertionWire {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MainnetAssertionWire")
            .finish_non_exhaustive()
    }
}

impl MainnetAssertionWire {
    /// Decodes the fields within their bounds and normalizes the signature to
    /// its compact low-S form.
    ///
    /// Each encoded length is checked before decoding, and noncanonical or
    /// padded base64url refuses.
    ///
    /// # Errors
    ///
    /// `approval.presence_invalid` for any field out of bounds, not canonical,
    /// or a signature that is not strict DER.
    pub fn decode(&self) -> Result<AssertionInput, WalletError> {
        let field = |value: &str, min: usize, max: usize| {
            decode_canonical_b64url(value, min, max).ok_or_else(presence_invalid)
        };
        let credential_id = field(
            &self.credential_id_b64url,
            CREDENTIAL_ID_MIN_BYTES,
            CREDENTIAL_ID_MAX_BYTES,
        )?;
        let authenticator_data = field(
            &self.authenticator_data_b64url,
            MAINNET_AUTHENTICATOR_DATA_BYTES,
            MAINNET_AUTHENTICATOR_DATA_BYTES,
        )?;
        let client_data_json = field(
            &self.client_data_json_b64url,
            1,
            MAINNET_CLIENT_DATA_JSON_MAX_BYTES,
        )?;
        let der = field(
            &self.signature_der_b64url,
            8,
            MAINNET_SIGNATURE_DER_MAX_BYTES,
        )?;
        let (signature, _) = super::webauthn::normalize_der_to_compact_low_s(&der)
            .map_err(|_| presence_invalid())?;
        AssertionInput::new(
            credential_id,
            authenticator_data,
            client_data_json,
            signature.as_bytes().to_vec(),
        )
        .map_err(|_| presence_invalid())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Issue
// ─────────────────────────────────────────────────────────────────────────────

/// What a page passes to `navigator.credentials.get`.
///
/// Informational only: the verifier checks the assertion against the
/// challenge it holds and never reads these values back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct MainnetPresenceOptions {
    /// The challenge, canonical base64url.
    pub challenge: String,
    /// The consent request ID the assertion POST names.
    pub request_id: String,
    /// The relying-party ID, [`MAINNET_APPROVAL_RP_ID`].
    pub rp_id: String,
    /// The signed policy's credential IDs, canonical base64url.
    pub allow_credentials: Vec<String>,
    /// The ceremony timeout, in milliseconds.
    pub timeout_ms: u32,
    /// When the challenge expires, in Unix milliseconds.
    pub expires_at_unix_ms: u64,
}

/// One outstanding presence challenge: the consent snapshot it binds, the
/// random value, the request ID, the expected origin and both deadlines.
///
/// Only [`issue_mainnet_presence`] constructs one, and only
/// [`verify_mainnet_presence`] consumes it. It cannot be cloned or
/// serialized, so a challenge verifies at most once and cannot be recovered
/// from a browser, a disk file, or its inputs.
pub struct PendingMainnetPresence {
    entry: PendingApproval,
    profile_name: String,
    chain_id: String,
    policy: VerifiedPolicy,
    random: [u8; 32],
    request_id: String,
    expected_origin: String,
    issued_at_unix_ms: u64,
    expires_at_unix_ms: u64,
    deadline: Instant,
    challenge: [u8; 32],
}

impl std::fmt::Debug for PendingMainnetPresence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingMainnetPresence")
            .field("profile_name", &self.profile_name)
            .field("request_id", &self.request_id)
            .field("expires_at_unix_ms", &self.expires_at_unix_ms)
            .finish_non_exhaustive()
    }
}

impl PendingMainnetPresence {
    /// The options a page passes to the authenticator.
    #[must_use]
    pub fn options(&self) -> MainnetPresenceOptions {
        let credentials = self
            .policy
            .mainnet()
            .map(|body| body.approval_credentials.as_slice())
            .unwrap_or_default();
        MainnetPresenceOptions {
            challenge: URL_SAFE_NO_PAD.encode(self.challenge),
            request_id: self.request_id.clone(),
            rp_id: MAINNET_APPROVAL_RP_ID.to_owned(),
            allow_credentials: credentials
                .iter()
                .map(MainnetApprovalCredential::credential_id_b64url)
                .collect(),
            timeout_ms: u32::try_from(self.expires_at_unix_ms - self.issued_at_unix_ms)
                .unwrap_or(u32::MAX),
            expires_at_unix_ms: self.expires_at_unix_ms,
        }
    }

    /// The consent request ID.
    #[must_use]
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    /// The approval nonce of the challenged entry.
    #[must_use]
    pub fn approval_nonce(&self) -> &str {
        &self.entry.approval_nonce
    }

    /// The expected origin the challenge binds.
    #[must_use]
    pub fn expected_origin(&self) -> &str {
        &self.expected_origin
    }

    /// Whether the challenge is still live at `now_ms` on both clocks.
    #[must_use]
    pub fn is_live(&self, now_ms: u64, now: Instant) -> bool {
        now < self.deadline && self.issued_at_unix_ms <= now_ms && now_ms < self.expires_at_unix_ms
    }
}

/// Issues a presence challenge for `entry` under `policy`.
///
/// Requires a mainnet `binding`, a `policy` whose mainnet section names the
/// binding's profile and lists approval credentials, a live and unattested
/// `entry` of a supported kind, and an `expected_origin` of the form
/// `http://localhost:<port>`. The challenge lives for the shorter of 120
/// seconds and the entry's remaining life, on the monotonic and the wall
/// clock alike.
///
/// # Errors
///
/// - `approval.binding_mismatch` for another chain.
/// - `approval.presence_policy_unavailable` for a policy without a mainnet
///   section for the binding's profile or without credentials.
/// - `approval.presence_invalid` for an origin of another shape.
/// - `approval.expired`, `approval.already_attested` for the entry's state.
/// - The errors of [`mainnet_consent_subject`].
pub fn issue_mainnet_presence(
    entry: &PendingApproval,
    binding: &AttestationBinding<'_>,
    policy: &VerifiedPolicy,
    expected_origin: &str,
    now_ms: u64,
    now: Instant,
) -> Result<PendingMainnetPresence, WalletError> {
    if binding.chain_id != MAINNET_CHAIN_ID {
        return Err(binding_mismatch());
    }
    let body = policy.mainnet().ok_or_else(policy_unavailable)?;
    if body.profile != binding.profile_name || body.approval_credentials.is_empty() {
        return Err(policy_unavailable());
    }
    if !is_mainnet_presence_origin(expected_origin) {
        return Err(presence_invalid());
    }
    if entry.created_at_unix_ms > now_ms || now_ms >= entry.expires_at_unix_ms {
        return Err(WalletError::Approval(ApprovalFailure::Expired {
            detail: "this pending approval is outside its lifetime".to_owned(),
        }));
    }
    if entry.attestation_blob_b64.is_some() {
        return Err(WalletError::Approval(ApprovalFailure::AlreadyAttested {
            detail: "this pending approval has already been attested".to_owned(),
        }));
    }
    let subject = mainnet_consent_subject(entry, binding)?;
    let ttl = MAINNET_PRESENCE_CHALLENGE_TTL_MS.min(
        entry
            .expires_at_unix_ms
            .checked_sub(now_ms)
            .ok_or_else(presence_expired)?,
    );
    let expires_at_unix_ms = now_ms.checked_add(ttl).ok_or_else(presence_expired)?;
    let deadline = now
        .checked_add(Duration::from_millis(ttl))
        .ok_or_else(presence_expired)?;
    let mut random = [0u8; 32];
    OsRng.fill_bytes(&mut random);
    let request_id = uuid::Uuid::new_v4().hyphenated().to_string();
    let challenge = mainnet_presence_challenge(&ChallengeFacts {
        random: &random,
        request_id: &request_id,
        entry,
        binding,
        subject: &subject,
        policy,
        expected_origin,
        issued_at_unix_ms: now_ms,
        expires_at_unix_ms,
    })
    .ok_or_else(presence_invalid)?;
    Ok(PendingMainnetPresence {
        entry: entry.clone(),
        profile_name: binding.profile_name.to_owned(),
        chain_id: binding.chain_id.to_owned(),
        policy: policy.clone(),
        random,
        request_id,
        expected_origin: expected_origin.to_owned(),
        issued_at_unix_ms: now_ms,
        expires_at_unix_ms,
        deadline,
        challenge,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Verify
// ─────────────────────────────────────────────────────────────────────────────

/// A verified mainnet presence: an assertion with UP and UV from a signed
/// credential, over the challenge of one consent snapshot.
///
/// [`verify_mainnet_presence`] is its only producer. Surfaces read the
/// request ID and the credential fingerprint; the attester consumes it.
pub struct VerifiedMainnetPresence {
    entry: PendingApproval,
    profile_name: String,
    chain_id: String,
    policy: VerifiedPolicy,
    receipt: MainnetPresenceReceipt,
    deadline: Instant,
    credential_fingerprint: String,
}

impl std::fmt::Debug for VerifiedMainnetPresence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedMainnetPresence")
            .field("profile_name", &self.profile_name)
            .field("request_id", &self.receipt.request_id)
            .field("credential_fingerprint", &self.credential_fingerprint)
            .finish_non_exhaustive()
    }
}

/// The parts of a verified presence the attester consumes.
pub(crate) struct VerifiedPresenceParts {
    pub(crate) entry: PendingApproval,
    pub(crate) profile_name: String,
    pub(crate) chain_id: String,
    pub(crate) policy: VerifiedPolicy,
    pub(crate) receipt: MainnetPresenceReceipt,
    pub(crate) deadline: Instant,
}

impl VerifiedMainnetPresence {
    /// The consent request ID of the ceremony.
    #[must_use]
    pub fn request_id(&self) -> &str {
        &self.receipt.request_id
    }

    /// The fingerprint of the credential that signed, as
    /// [`MainnetApprovalCredential::fingerprint`] renders it.
    #[must_use]
    pub fn credential_fingerprint(&self) -> &str {
        &self.credential_fingerprint
    }

    /// The approval nonce of the consented entry.
    #[must_use]
    pub fn approval_nonce(&self) -> &str {
        &self.entry.approval_nonce
    }

    pub(crate) fn into_parts(self) -> VerifiedPresenceParts {
        VerifiedPresenceParts {
            entry: self.entry,
            profile_name: self.profile_name,
            chain_id: self.chain_id,
            policy: self.policy,
            receipt: self.receipt,
            deadline: self.deadline,
        }
    }
}

/// Verifies `assertion` against the challenge `pending` holds, consuming it.
///
/// The challenge must be live on both clocks at `now_ms` and `now`; a wall
/// clock earlier than issuance refuses. The assertion is then checked as the
/// module documents, under the key the challenged policy signs for its
/// credential ID.
///
/// # Errors
///
/// `approval.presence_expired` outside the challenge's life, and
/// `approval.presence_invalid` for every assertion defect.
pub fn verify_mainnet_presence(
    pending: PendingMainnetPresence,
    assertion: AssertionInput,
    now_ms: u64,
    now: Instant,
) -> Result<VerifiedMainnetPresence, WalletError> {
    if !pending.is_live(now_ms, now) {
        return Err(presence_expired());
    }
    let facts = check_assertion(
        &pending.policy,
        &pending.challenge,
        &pending.expected_origin,
        &assertion,
    )?;
    let receipt = MainnetPresenceReceipt {
        version: MAINNET_PRESENCE_RECEIPT_VERSION,
        request_id: pending.request_id,
        random_b64url: URL_SAFE_NO_PAD.encode(pending.random),
        policy_sequence: pending.policy.sequence(),
        policy_digest_hex: crate::hex::encode(&pending.policy.digest()),
        policy_owner_hex: crate::hex::encode(&pending.policy.owner()),
        expected_origin: pending.expected_origin,
        issued_at_unix_ms: pending.issued_at_unix_ms,
        expires_at_unix_ms: pending.expires_at_unix_ms,
        verified_at_unix_ms: now_ms,
        assertion,
    };
    Ok(VerifiedMainnetPresence {
        entry: pending.entry,
        profile_name: pending.profile_name,
        chain_id: pending.chain_id,
        policy: pending.policy,
        receipt,
        deadline: pending.deadline,
        credential_fingerprint: facts.credential.fingerprint(),
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Receipt
// ─────────────────────────────────────────────────────────────────────────────

/// The record of one verified ceremony, stored with the version 5
/// attestation it is bound into.
///
/// It keeps the raw assertion, so the commit witness verifies the signature
/// again. Counters, UP and UV are read from the signed authenticator data,
/// never from a separate field. Decoding checks every field's shape and
/// bounds; `Debug` shows no assertion bytes.
#[derive(Clone)]
pub struct MainnetPresenceReceipt {
    version: u32,
    request_id: String,
    random_b64url: String,
    policy_sequence: i64,
    policy_digest_hex: String,
    policy_owner_hex: String,
    expected_origin: String,
    issued_at_unix_ms: u64,
    expires_at_unix_ms: u64,
    verified_at_unix_ms: u64,
    assertion: AssertionInput,
}

impl PartialEq for MainnetPresenceReceipt {
    fn eq(&self, other: &Self) -> bool {
        self.version == other.version
            && self.request_id == other.request_id
            && self.random_b64url == other.random_b64url
            && self.policy_sequence == other.policy_sequence
            && self.policy_digest_hex == other.policy_digest_hex
            && self.policy_owner_hex == other.policy_owner_hex
            && self.expected_origin == other.expected_origin
            && self.issued_at_unix_ms == other.issued_at_unix_ms
            && self.expires_at_unix_ms == other.expires_at_unix_ms
            && self.verified_at_unix_ms == other.verified_at_unix_ms
            && self.assertion.credential_id == other.assertion.credential_id
            && self.assertion.authenticator_data == other.assertion.authenticator_data
            && self.assertion.client_data_json == other.assertion.client_data_json
            && self.assertion.signature_compact == other.assertion.signature_compact
    }
}

impl Eq for MainnetPresenceReceipt {}

impl std::fmt::Debug for MainnetPresenceReceipt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MainnetPresenceReceipt")
            .field("version", &self.version)
            .field("request_id", &self.request_id)
            .field("policy_sequence", &self.policy_sequence)
            .field("issued_at_unix_ms", &self.issued_at_unix_ms)
            .field("expires_at_unix_ms", &self.expires_at_unix_ms)
            .field("verified_at_unix_ms", &self.verified_at_unix_ms)
            .field("assertion", &self.assertion)
            .finish_non_exhaustive()
    }
}

impl MainnetPresenceReceipt {
    /// The consent request ID.
    #[must_use]
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    /// The signed policy sequence the ceremony bound.
    #[must_use]
    pub fn policy_sequence(&self) -> i64 {
        self.policy_sequence
    }

    /// The lowercase hex BLAKE3 digest of the policy the ceremony bound.
    #[must_use]
    pub fn policy_digest_hex(&self) -> &str {
        &self.policy_digest_hex
    }

    /// The lowercase hex owner key of the policy the ceremony bound.
    #[must_use]
    pub fn policy_owner_hex(&self) -> &str {
        &self.policy_owner_hex
    }

    /// The origin the challenge bound.
    #[must_use]
    pub fn expected_origin(&self) -> &str {
        &self.expected_origin
    }

    /// When the challenge was issued, in Unix milliseconds.
    #[must_use]
    pub fn issued_at_unix_ms(&self) -> u64 {
        self.issued_at_unix_ms
    }

    /// When the challenge expired, in Unix milliseconds.
    #[must_use]
    pub fn expires_at_unix_ms(&self) -> u64 {
        self.expires_at_unix_ms
    }

    /// When the assertion was verified, in Unix milliseconds.
    #[must_use]
    pub fn verified_at_unix_ms(&self) -> u64 {
        self.verified_at_unix_ms
    }

    /// The canonical base64url ID of the credential that signed.
    #[must_use]
    pub fn credential_id_b64url(&self) -> String {
        URL_SAFE_NO_PAD.encode(&self.assertion.credential_id)
    }

    /// Whether every field has its shape: version 1, a canonical UUIDv4
    /// request ID, a canonical 32-byte random value, a lowercase hex policy
    /// digest and owner, an expected origin of the mainnet form, and an assertion
    /// within the mainnet bounds.
    #[must_use]
    pub fn is_well_formed(&self) -> bool {
        self.version == MAINNET_PRESENCE_RECEIPT_VERSION
            && is_canonical_uuid_v4(&self.request_id)
            && decode_canonical_b64url(&self.random_b64url, 32, 32).is_some()
            && is_lower_hex32(&self.policy_digest_hex)
            && is_lower_hex32(&self.policy_owner_hex)
            && is_mainnet_presence_origin(&self.expected_origin)
            && (CREDENTIAL_ID_MIN_BYTES..=CREDENTIAL_ID_MAX_BYTES)
                .contains(&self.assertion.credential_id.len())
            && self.assertion.authenticator_data.len() == MAINNET_AUTHENTICATOR_DATA_BYTES
            && !self.assertion.client_data_json.is_empty()
            && self.assertion.client_data_json.len() <= MAINNET_CLIENT_DATA_JSON_MAX_BYTES
            && super::assertion_input::validate_signature_compact(&self.assertion.signature_compact)
                .is_ok()
    }

    fn random(&self) -> Option<[u8; 32]> {
        decode_canonical_b64url(&self.random_b64url, 32, 32)?
            .try_into()
            .ok()
    }

    fn policy_digest(&self) -> Option<[u8; 32]> {
        decode_lower_hex32(&self.policy_digest_hex)
    }

    fn policy_owner(&self) -> Option<[u8; 32]> {
        decode_lower_hex32(&self.policy_owner_hex)
    }

    /// Whether the receipt names `policy`: its sequence, digest and owner.
    #[must_use]
    pub fn names_policy(&self, policy: &VerifiedPolicy) -> bool {
        self.policy_sequence == policy.sequence()
            && self.policy_digest() == Some(policy.digest())
            && self.policy_owner() == Some(policy.owner())
    }

    /// The receipt digest a version 5 attestation binds.
    ///
    /// SHA-256 of `b"stellar-agent-mainnet-presence-receipt:v1"` followed by
    /// `u32(version)`, `lp(request_id)`, the 32 decoded random bytes,
    /// `i64(policy_sequence)`, the 32 decoded policy digest bytes, the 32
    /// decoded owner bytes,
    /// `lp(expected_origin)`, `u64(issued)`, `u64(expires)`, `u64(verified)`,
    /// then `lp` of the raw credential ID, authenticator data,
    /// `clientDataJSON` and compact signature. All integers are big endian;
    /// no TOML or JSON enters the digest.
    ///
    /// `None` for a receipt that is not well formed.
    #[must_use]
    pub fn digest(&self) -> Option<[u8; 32]> {
        if !self.is_well_formed() {
            return None;
        }
        let mut preimage = Preimage::new(RECEIPT_DOMAIN);
        preimage
            .u32(self.version)
            .lp(self.request_id.as_bytes())
            .fixed(&self.random()?)
            .i64(self.policy_sequence)
            .fixed(&self.policy_digest()?)
            .fixed(&self.policy_owner()?)
            .lp(self.expected_origin.as_bytes())
            .u64(self.issued_at_unix_ms)
            .u64(self.expires_at_unix_ms)
            .u64(self.verified_at_unix_ms)
            .lp(&self.assertion.credential_id)
            .lp(&self.assertion.authenticator_data)
            .lp(&self.assertion.client_data_json)
            .lp(&self.assertion.signature_compact);
        preimage.finish()
    }

    /// Recomputes the challenge of this receipt over `entry`, `binding` and
    /// `policy`, after checking `entry` is a supported kind.
    fn challenge(
        &self,
        entry: &PendingApproval,
        binding: &AttestationBinding<'_>,
        policy: &VerifiedPolicy,
    ) -> Result<[u8; 32], WalletError> {
        let subject = mainnet_consent_subject(entry, binding)?;
        let random = self.random().ok_or_else(presence_invalid)?;
        mainnet_presence_challenge(&ChallengeFacts {
            random: &random,
            request_id: &self.request_id,
            entry,
            binding,
            subject: &subject,
            policy,
            expected_origin: &self.expected_origin,
            issued_at_unix_ms: self.issued_at_unix_ms,
            expires_at_unix_ms: self.expires_at_unix_ms,
        })
        .ok_or_else(presence_invalid)
    }
}

/// Decodes a string without copying an overlong field into its receipt.
fn bounded_string<'de, D: serde::Deserializer<'de>, const MAX: usize>(
    deserializer: D,
) -> Result<String, D::Error> {
    struct BoundedString<const MAX: usize>;
    impl<'de, const MAX: usize> serde::de::Visitor<'de> for BoundedString<MAX> {
        type Value = String;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(formatter, "a string of at most {MAX} bytes")
        }

        fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<String, E> {
            if value.len() > MAX {
                return Err(E::custom("mainnet_presence string exceeds its byte bound"));
            }
            Ok(value.to_owned())
        }
    }
    deserializer.deserialize_str(BoundedString::<MAX>)
}

/// Decodes at most the field's byte bound, without trusting a size hint.
fn bounded_bytes<'de, D: serde::Deserializer<'de>, const MAX: usize>(
    deserializer: D,
) -> Result<Vec<u8>, D::Error> {
    struct BoundedBytes<const MAX: usize>;
    impl<'de, const MAX: usize> serde::de::Visitor<'de> for BoundedBytes<MAX> {
        type Value = Vec<u8>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(formatter, "an array of at most {MAX} bytes")
        }

        fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<u8>, A::Error> {
            use serde::de::Error as _;
            if seq.size_hint().is_some_and(|size| size > MAX) {
                return Err(A::Error::custom(
                    "mainnet_presence array exceeds its byte bound",
                ));
            }
            let mut bytes = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(MAX));
            while let Some(byte) = seq.next_element::<u8>()? {
                if bytes.len() == MAX {
                    return Err(A::Error::custom(
                        "mainnet_presence array exceeds its byte bound",
                    ));
                }
                bytes.push(byte);
            }
            Ok(bytes)
        }
    }
    deserializer.deserialize_seq(BoundedBytes::<MAX>)
}

/// The on-disk receipt. Unknown fields refuse.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiptWire {
    version: u32,
    #[serde(deserialize_with = "bounded_string::<_, RECEIPT_REQUEST_ID_MAX_BYTES>")]
    request_id: String,
    #[serde(deserialize_with = "bounded_string::<_, RECEIPT_RANDOM_MAX_BYTES>")]
    random_b64url: String,
    policy_sequence: i64,
    #[serde(deserialize_with = "bounded_string::<_, RECEIPT_HEX_MAX_BYTES>")]
    policy_digest_hex: String,
    #[serde(deserialize_with = "bounded_string::<_, RECEIPT_HEX_MAX_BYTES>")]
    policy_owner_hex: String,
    #[serde(deserialize_with = "bounded_string::<_, RECEIPT_ORIGIN_MAX_BYTES>")]
    expected_origin: String,
    issued_at_unix_ms: u64,
    expires_at_unix_ms: u64,
    verified_at_unix_ms: u64,
    assertion: AssertionWireDisk,
}

/// The on-disk assertion of a receipt. Unknown fields refuse.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AssertionWireDisk {
    #[serde(deserialize_with = "bounded_bytes::<_, CREDENTIAL_ID_MAX_BYTES>")]
    credential_id: Vec<u8>,
    #[serde(deserialize_with = "bounded_bytes::<_, MAINNET_AUTHENTICATOR_DATA_BYTES>")]
    authenticator_data: Vec<u8>,
    #[serde(deserialize_with = "bounded_bytes::<_, MAINNET_CLIENT_DATA_JSON_MAX_BYTES>")]
    client_data_json: Vec<u8>,
    #[serde(deserialize_with = "bounded_bytes::<_, RECEIPT_SIGNATURE_BYTES>")]
    signature_compact: Vec<u8>,
}

impl Serialize for MainnetPresenceReceipt {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        ReceiptWire {
            version: self.version,
            request_id: self.request_id.clone(),
            random_b64url: self.random_b64url.clone(),
            policy_sequence: self.policy_sequence,
            policy_digest_hex: self.policy_digest_hex.clone(),
            policy_owner_hex: self.policy_owner_hex.clone(),
            expected_origin: self.expected_origin.clone(),
            issued_at_unix_ms: self.issued_at_unix_ms,
            expires_at_unix_ms: self.expires_at_unix_ms,
            verified_at_unix_ms: self.verified_at_unix_ms,
            assertion: AssertionWireDisk {
                credential_id: self.assertion.credential_id.clone(),
                authenticator_data: self.assertion.authenticator_data.clone(),
                client_data_json: self.assertion.client_data_json.clone(),
                signature_compact: self.assertion.signature_compact.clone(),
            },
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for MainnetPresenceReceipt {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = ReceiptWire::deserialize(deserializer)?;
        let assertion = AssertionInput::new(
            wire.assertion.credential_id,
            wire.assertion.authenticator_data,
            wire.assertion.client_data_json,
            wire.assertion.signature_compact,
        )
        .map_err(|_| serde::de::Error::custom("mainnet_presence assertion is malformed"))?;
        let receipt = Self {
            version: wire.version,
            request_id: wire.request_id,
            random_b64url: wire.random_b64url,
            policy_sequence: wire.policy_sequence,
            policy_digest_hex: wire.policy_digest_hex,
            policy_owner_hex: wire.policy_owner_hex,
            expected_origin: wire.expected_origin,
            issued_at_unix_ms: wire.issued_at_unix_ms,
            expires_at_unix_ms: wire.expires_at_unix_ms,
            verified_at_unix_ms: wire.verified_at_unix_ms,
            assertion,
        };
        if !receipt.is_well_formed() {
            return Err(serde::de::Error::custom("mainnet_presence is malformed"));
        }
        Ok(receipt)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Stored verification
// ─────────────────────────────────────────────────────────────────────────────

/// What a stored receipt proves, for the audit row and the witness.
#[derive(Debug, Clone)]
pub(crate) struct StoredPresence {
    pub(crate) challenge: [u8; 32],
    pub(crate) receipt_digest: [u8; 32],
    pub(crate) facts: AssertionFacts,
}

/// Verifies `receipt` as the consent to `entry` under `policy`.
///
/// Recomputes the challenge from the receipt, the entry, the binding and
/// the policy, and checks the raw assertion under the key `policy` signs for
/// its credential ID. The receipt must name `policy`, its times must satisfy
/// `issued <= verified < challenge_expires`, `challenge_expires <=
/// entry_expires`, `challenge_expires - issued <= 120000` and
/// `verified <= now_ms`. Never returns a live [`VerifiedMainnetPresence`].
///
/// # Errors
///
/// `approval.presence_policy_unavailable` for a receipt bound to another
/// policy, `approval.presence_invalid` for every other defect, and the
/// subject errors of [`mainnet_consent_subject`].
pub(crate) fn verify_receipt(
    entry: &PendingApproval,
    receipt: &MainnetPresenceReceipt,
    binding: &AttestationBinding<'_>,
    policy: &VerifiedPolicy,
    now_ms: u64,
) -> Result<StoredPresence, WalletError> {
    if !receipt.is_well_formed() {
        return Err(presence_invalid());
    }
    if !receipt.names_policy(policy) {
        return Err(policy_unavailable());
    }
    let window = receipt
        .expires_at_unix_ms
        .checked_sub(receipt.issued_at_unix_ms)
        .ok_or_else(presence_invalid)?;
    if receipt.issued_at_unix_ms > receipt.verified_at_unix_ms
        || receipt.verified_at_unix_ms >= receipt.expires_at_unix_ms
        || receipt.expires_at_unix_ms > entry.expires_at_unix_ms
        || window > MAINNET_PRESENCE_CHALLENGE_TTL_MS
        || receipt.verified_at_unix_ms > now_ms
    {
        return Err(presence_invalid());
    }
    let challenge = receipt.challenge(entry, binding, policy)?;
    let facts = check_assertion(
        policy,
        &challenge,
        &receipt.expected_origin,
        &receipt.assertion,
    )?;
    Ok(StoredPresence {
        challenge,
        receipt_digest: receipt.digest().ok_or_else(presence_invalid)?,
        facts,
    })
}

/// The audit object of a verified ceremony.
pub(crate) fn presence_audit(
    stored: &StoredPresence,
    receipt: &MainnetPresenceReceipt,
) -> MainnetPresenceAudit {
    MainnetPresenceAudit {
        credential_fingerprint: stored.facts.credential.fingerprint(),
        challenge_sha256_hex: crate::hex::encode(&stored.challenge),
        receipt_sha256_hex: crate::hex::encode(&stored.receipt_digest),
        policy_digest_hex: receipt.policy_digest_hex.clone(),
        policy_sequence: receipt.policy_sequence,
        rp_id: MAINNET_APPROVAL_RP_ID.to_owned(),
        webauthn_origin: receipt.expected_origin.clone(),
        user_present: stored.facts.user_present,
        user_verified: stored.facts.user_verified,
        sign_count: stored.facts.sign_count,
        verified_at_unix_ms: receipt.verified_at_unix_ms,
    }
}

#[cfg(test)]
#[path = "presence_tests.rs"]
mod tests;
