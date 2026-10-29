//! HMAC-SHA256 attestation primitive for the wallet-owned approval spine.
//!
//! The attestation binds the profile name, CAIP-2 chain id, approval nonce,
//! envelope digest, approving process UID, and, from version 3 on, the
//! approval's kind and lifetime.
//!
//! # Canonical input layout, version 3
//!
//! [`compute_attestation`] produces this layout:
//!
//! ```text
//! mac.update(b"stellar-agent-approval-attestation:v3")
//! mac.update(u32_be(len(profile_name)))   mac.update(profile_name)
//! mac.update(u32_be(len(chain_id)))       mac.update(chain_id)
//! mac.update(u32_be(len(approval_nonce))) mac.update(approval_nonce)
//! mac.update(envelope_sha256)
//! mac.update(u32_be(len(process_uid)))    mac.update(process_uid)
//! mac.update(u32_be(len(kind)))           mac.update(kind)
//! mac.update(u64_be(created_at_unix_ms))
//! mac.update(u64_be(expires_at_unix_ms))
//! ```
//!
//! `kind` is the approval record's kind name (for example
//! `PaymentSimulated`). A record whose stored kind, creation time, or expiry
//! differs from the attested values fails verification, so an operator's
//! approval cannot be stretched to a longer lifetime or another kind by
//! editing the pending file, which is not a security boundary.
//!
//! # Version 2
//!
//! Version 2 covers the first five fields only, under the tag
//! `stellar-agent-approval-attestation:v2`. Records written before version 3
//! carry no `attestation_version` and read as version 2;
//! [`verify_attestation`] verifies each record under the layout its stored
//! version names, so an approval attested under version 2 still verifies on
//! the paths that accept it. A pending approval requires version 4 (below).
//!
//! # Version 4: pending approvals name their approver
//!
//! A pending approval's attestation also authenticates who approved it.
//! [`compute_attestation_v4`] produces the version 3 fields under the tag
//! `stellar-agent-approval-attestation:v4`, followed by the approver:
//!
//! ```text
//! (the version 3 fields, in the version 3 order)
//! mac.update([approver_tag])              0x00 local, 0x01 remote
//! mac.update(u32_be(len(credential_id)))  mac.update(credential_id)   (remote only)
//! ```
//!
//! `credential_id` is the canonical base64url form of the operator credential
//! the remote listener verified. Changing the recorded approver, turning a
//! remote approval into a local one, or deleting the approver makes the blob
//! fail verification. Every pending-approval consumer requires version 4
//! ([`PENDING_ATTESTATION_VERSION`]): a pending record stored under version 2
//! or 3 does not say whether a local operator or a remote credential
//! approved it, so it verifies nothing and the action needs fresh consent.
//! Toolset grants are versioned on their own and keep using
//! [`compute_attestation`] and [`AttestationScope::from_version`].
//!
//! # Version 5: mainnet consent
//!
//! A mainnet consent is recorded under version 5
//! ([`MAINNET_ATTESTATION_VERSION`]) with a mainnet passkey approver
//! (`0x02`, followed by the length-prefixed credential ID) and the 32-byte
//! digest of the stored WebAuthn presence receipt appended after the
//! approver. [`compute_attestation_v5`] produces it. Version 4 bytes are
//! unchanged, and a version 4 blob never verifies as version 5 or the
//! reverse, so a local or remote approval cannot stand for a mainnet
//! consent.
//!
//! Lengths count UTF-8 bytes, encoded as big-endian u32 with saturation.
//! The tags and the 32-byte digest have no prefix or NUL terminator.
//! The tag separates this HMAC from every other use of the key.
//! Binding fields make a blob unverifiable under another profile or chain.
//! A layout change bumps the tag; blobs under one tag do not verify under
//! another.
//!
//! # Key discipline
//!
//! This module accepts the key as `&[u8; 32]`.  The caller is responsible for:
//!
//! 1. Loading the key from the platform keyring into a `Zeroizing<[u8; 32]>`.
//! 2. Dereferencing into this function as `compute_attestation(&*key, ...)`.
//! 3. Dropping the `Zeroizing` guard immediately after the call.
//!
//! Callers load the key from the keyring; this module implements only the
//! HMAC primitive.

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use super::presence::MainnetPresenceReceipt;

/// Profile and chain that mint or verify an approval.
///
/// The profile name is the approval store file stem both binaries open.
/// The CAIP-2 chain id comes from the environment-merged profile.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct AttestationBinding<'a> {
    /// Approval store profile name.
    pub profile_name: &'a str,
    /// CAIP-2 chain id of the environment-merged profile.
    pub chain_id: &'a str,
}

impl<'a> AttestationBinding<'a> {
    /// Constructs the profile and chain binding.
    #[must_use]
    pub fn new(profile_name: &'a str, chain_id: &'a str) -> Self {
        Self {
            profile_name,
            chain_id,
        }
    }
}

/// HMAC-SHA256 type alias.
type HmacSha256 = Hmac<Sha256>;

/// The attestation layout version 2: profile, chain, nonce, subject, and
/// process UID.
pub const ATTESTATION_VERSION_V2: u32 = 2;

/// The attestation layout this build produces: version 2's fields plus the
/// approval's kind and lifetime.
pub const ATTESTATION_VERSION: u32 = 3;

/// HMAC domain tag of version 2.
const ATTESTATION_TAG_V2: &[u8] = b"stellar-agent-approval-attestation:v2";

/// HMAC domain tag of version 3.
const ATTESTATION_TAG_V3: &[u8] = b"stellar-agent-approval-attestation:v3";

/// The attestation layout every pending approval is recorded and verified
/// under: version 3's fields plus the authenticated approver.
pub const PENDING_ATTESTATION_VERSION: u32 = 4;

/// HMAC domain tag of version 4.
const ATTESTATION_TAG_V4: &[u8] = b"stellar-agent-approval-attestation:v4";

/// The attestation layout of a mainnet consent: version 4's fields with a
/// mainnet passkey approver, plus the digest of the retained WebAuthn
/// receipt. Testnet approvals keep [`PENDING_ATTESTATION_VERSION`].
pub const MAINNET_ATTESTATION_VERSION: u32 = 5;

/// HMAC domain tag of version 5.
const ATTESTATION_TAG_V5: &[u8] = b"stellar-agent-approval-attestation:v5";

/// The approver byte of a local approval in the version 4 layout.
const APPROVER_TAG_LOCAL: u8 = 0x00;

/// The approver byte of a remote approval in the version 4 layout.
const APPROVER_TAG_REMOTE: u8 = 0x01;

/// The approver byte of a mainnet passkey approval in the version 5 layout.
const APPROVER_TAG_MAINNET_PASSKEY: u8 = 0x02;

/// Who approved a pending approval, as its version 4 attestation
/// authenticates it.
///
/// Derived from the verified identity of the surface that approved, never
/// from request input: a loopback or CLI surface records [`Self::Local`], the
/// remote listener records [`Self::Remote`] with the credential ID its
/// WebAuthn verification matched, and a mainnet consent records
/// [`Self::MainnetPasskey`] with the credential ID of the verified assertion.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AttestedApprover {
    /// The wallet host's own operator, through the CLI or the loopback inbox.
    Local,
    /// An operator credential authenticated by the remote-approval listener.
    Remote {
        /// The canonical base64url credential ID the listener verified.
        credential_id_b64url: String,
    },
    /// An approval credential of the owner-signed mainnet policy whose
    /// assertion, with user presence and user verification, the wallet
    /// verified. Valid only in the version 5 layout.
    MainnetPasskey {
        /// The canonical base64url ID of the credential that signed.
        credential_id_b64url: String,
    },
}

impl AttestedApprover {
    /// Whether the approver is well formed: a remote approver names a
    /// non-empty, canonical base64url credential ID, and a mainnet passkey
    /// approver a canonical base64url ID of 16 to 64 bytes.
    #[must_use]
    pub fn is_well_formed(&self) -> bool {
        match self {
            Self::Local => true,
            Self::Remote {
                credential_id_b64url,
            } => is_canonical_b64url(credential_id_b64url),
            Self::MainnetPasskey {
                credential_id_b64url,
            } => super::presence::decode_canonical_b64url(
                credential_id_b64url,
                super::presence::CREDENTIAL_ID_MIN_BYTES,
                super::presence::CREDENTIAL_ID_MAX_BYTES,
            )
            .is_some(),
        }
    }
}

impl std::fmt::Debug for AttestedApprover {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Local => f.write_str("Local"),
            Self::Remote {
                credential_id_b64url,
            } => f
                .debug_struct("Remote")
                .field(
                    "credential_id_b64url",
                    &crate::redact_first5_last5(credential_id_b64url),
                )
                .finish(),
            Self::MainnetPasskey {
                credential_id_b64url,
            } => f
                .debug_struct("MainnetPasskey")
                .field(
                    "credential_id_b64url",
                    &crate::redact_first5_last5(credential_id_b64url),
                )
                .finish(),
        }
    }
}

/// Whether `value` is non-empty unpadded base64url that re-encodes to itself.
fn is_canonical_b64url(value: &str) -> bool {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    !value.is_empty()
        && URL_SAFE_NO_PAD
            .decode(value)
            .is_ok_and(|bytes| URL_SAFE_NO_PAD.encode(bytes) == value)
}

/// The approval facts a version 3 attestation covers beyond version 2's.
///
/// Every value comes from the approval record the operator approves:
/// [`super::store::PendingApproval::attested_lifetime`] builds it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct AttestedLifetime<'a> {
    /// The record's kind name, for example `PaymentSimulated`.
    pub kind: &'a str,
    /// When the record was created, in Unix milliseconds.
    pub created_at_unix_ms: u64,
    /// When the record expires, in Unix milliseconds.
    pub expires_at_unix_ms: u64,
}

impl<'a> AttestedLifetime<'a> {
    /// The kind and lifetime of an approval record.
    #[must_use]
    pub fn new(kind: &'a str, created_at_unix_ms: u64, expires_at_unix_ms: u64) -> Self {
        Self {
            kind,
            created_at_unix_ms,
            expires_at_unix_ms,
        }
    }
}

/// The layout a stored attestation was computed under, with the facts that
/// layout covers beyond version 2's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AttestationScope<'a> {
    /// Version 2: no kind and no lifetime.
    V2,
    /// Version 3: the record's kind and lifetime.
    V3(AttestedLifetime<'a>),
    /// Version 4: the record's kind and lifetime and its authenticated
    /// approver. A pending testnet approval verifies under it.
    V4(AttestedLifetime<'a>, &'a AttestedApprover),
    /// Version 5: version 4's fields with a mainnet passkey approver, plus
    /// the digest of the presence receipt. A mainnet consent verifies under
    /// it.
    V5(
        AttestedLifetime<'a>,
        &'a AttestedApprover,
        &'a MainnetPresenceReceipt,
    ),
}

impl<'a> AttestationScope<'a> {
    /// Selects a toolset grant's stored layout; unsupported versions verify
    /// nothing.
    ///
    /// Version 4 is a pending-approval layout and needs the approver, so this
    /// selector never returns it; a pending record selects its layout with
    /// [`Self::pending`].
    #[must_use]
    pub fn from_version(version: u32, lifetime: AttestedLifetime<'a>) -> Option<Self> {
        match version {
            ATTESTATION_VERSION_V2 => Some(Self::V2),
            ATTESTATION_VERSION => Some(Self::V3(lifetime)),
            _ => None,
        }
    }

    /// Selects a pending approval's layout: version 4 with a well-formed
    /// local or remote approver and no presence receipt, or version 5 with a
    /// well-formed mainnet passkey approver and a well-formed receipt whose
    /// assertion names the same credential.
    ///
    /// Every other combination verifies nothing: version 2 or 3, a missing
    /// or malformed approver, a mainnet passkey approver under version 4, a
    /// local or remote approver under version 5, a receipt under version 4,
    /// and version 5 without a receipt or with another credential's.
    #[must_use]
    pub fn pending(
        version: u32,
        lifetime: AttestedLifetime<'a>,
        approver: Option<&'a AttestedApprover>,
        receipt: Option<&'a MainnetPresenceReceipt>,
    ) -> Option<Self> {
        let approver = approver.filter(|approver| approver.is_well_formed())?;
        match (version, approver, receipt) {
            (
                PENDING_ATTESTATION_VERSION,
                AttestedApprover::Local | AttestedApprover::Remote { .. },
                None,
            ) => Some(Self::V4(lifetime, approver)),
            (
                MAINNET_ATTESTATION_VERSION,
                AttestedApprover::MainnetPasskey {
                    credential_id_b64url,
                },
                Some(receipt),
            ) if receipt.is_well_formed()
                && receipt.credential_id_b64url() == *credential_id_b64url =>
            {
                Some(Self::V5(lifetime, approver, receipt))
            }
            _ => None,
        }
    }

    /// The layout version number this scope verifies under.
    #[must_use]
    pub fn version(&self) -> u32 {
        match self {
            Self::V2 => ATTESTATION_VERSION_V2,
            Self::V3(_) => ATTESTATION_VERSION,
            Self::V4(..) => PENDING_ATTESTATION_VERSION,
            Self::V5(..) => MAINNET_ATTESTATION_VERSION,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Toolset-gate digest constants
// ─────────────────────────────────────────────────────────────────────────────

/// Domain-separation tag for the `ToolsetFirstInvokeGate` attestation digest.
///
/// A layout change bumps the tag; digests under the previous tag do not verify.
///
/// Current version: `v1`.
pub const TOOLSET_GATE_DOMAIN_TAG: &[u8] = b"stellar-agent-toolset-grant:v1";

// ─────────────────────────────────────────────────────────────────────────────
// Public helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Computes the SHA-256 hash of `envelope_xdr_bytes`.
///
/// Returns a 32-byte array.  Used to derive `envelope_sha256_hex` when
/// constructing a [`super::store::PendingApproval`].
///
/// # Examples
///
/// ```
/// use stellar_agent_core::approval::attestation::envelope_sha256;
///
/// let hash = envelope_sha256(b"fake-envelope-xdr");
/// assert_eq!(hash.len(), 32);
/// ```
#[must_use]
pub fn envelope_sha256(envelope_xdr_bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(envelope_xdr_bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Computes the 32-byte SHA-256 digest for a `ToolsetFirstInvokeGate` approval.
///
/// # Domain-separated length-prefixed preimage
///
/// ```text
/// SHA-256(
///   TOOLSET_GATE_DOMAIN_TAG
///   || u32_be(len(toolset_name))  || toolset_name
///   || u32_be(len(capability))  || capability
///   || u32_be(len(destination)) || destination   (canonical G-strkey)
///   || u32_be(len(asset))       || asset          (code:issuer or "XLM")
///   || i64_be(amount_min_stroops)
///   || i64_be(amount_max_stroops)
/// )
/// ```
///
/// Length prefixes on every variable-length field prevent boundary-collision
/// attacks (same discipline as the HMAC preimage for `PaymentSimulated`).
/// The fixed-width amount fields need no length prefix.
///
/// # Layout citation
///
/// Preimage layout is defined here (this file) and is the canonical source.
/// The `TOOLSET_GATE_DOMAIN_TAG` version tag guarantees old grants fail closed
/// if the layout is ever revised.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::approval::attestation::compute_toolset_gate_digest;
///
/// let digest = compute_toolset_gate_digest(
///     "my-toolset",
///     "sign-payment",
///     "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
///     "XLM",
///     0,
///     10_000_000,
/// );
/// assert_eq!(digest.len(), 32);
/// ```
#[must_use]
pub fn compute_toolset_gate_digest(
    toolset_name: &str,
    capability: &str,
    destination: &str,
    asset: &str,
    amount_min_stroops: i64,
    amount_max_stroops: i64,
) -> [u8; 32] {
    let mut hasher = Sha256::new();

    // Domain-separation tag (fixed-length; no length prefix needed).
    hasher.update(TOOLSET_GATE_DOMAIN_TAG);

    // Length-prefixed variable-length fields.
    let toolset_len = u32::try_from(toolset_name.len()).unwrap_or(u32::MAX);
    hasher.update(toolset_len.to_be_bytes());
    hasher.update(toolset_name.as_bytes());

    let cap_len = u32::try_from(capability.len()).unwrap_or(u32::MAX);
    hasher.update(cap_len.to_be_bytes());
    hasher.update(capability.as_bytes());

    let dest_len = u32::try_from(destination.len()).unwrap_or(u32::MAX);
    hasher.update(dest_len.to_be_bytes());
    hasher.update(destination.as_bytes());

    let asset_len = u32::try_from(asset.len()).unwrap_or(u32::MAX);
    hasher.update(asset_len.to_be_bytes());
    hasher.update(asset.as_bytes());

    // Fixed-width amount fields (no length prefix needed).
    hasher.update(amount_min_stroops.to_be_bytes());
    hasher.update(amount_max_stroops.to_be_bytes());

    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Verifies whether `attestation_blob` was produced by the HMAC-SHA256
/// attestation of a `ToolsetFirstInvokeGate` approval with the given fields.
///
/// Recomputes the toolset-gate digest from `toolset_name`, `capability`,
/// `destination`, `asset`, `amount_min_stroops`, `amount_max_stroops` via
/// [`compute_toolset_gate_digest`], then feeds the result as the
/// `envelope_sha256` slot of [`verify_attestation`].
///
/// Returns `true` iff the attestation blob matches.  Comparison is
/// constant-time via [`subtle::ConstantTimeEq`] (inherited from
/// [`verify_attestation`]).
///
/// # Key discipline
///
/// Same as [`compute_attestation`]: caller wraps the key in
/// `Zeroizing<[u8; 32]>` and passes `&*key`.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::approval::attestation::{
///     AttestationScope, AttestedLifetime, compute_attestation, compute_toolset_gate_digest,
///     verify_toolset_gate_attestation,
/// };
///
/// let key = [0x42u8; 32];
/// let digest = compute_toolset_gate_digest(
///     "my-toolset", "sign-payment",
///     "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
///     "XLM", 0, 10_000_000,
/// );
/// let lifetime = AttestedLifetime::new("ToolsetFirstInvokeGate", 0, 60_000);
/// let blob = compute_attestation(&key,
/// &stellar_agent_core::approval::AttestationBinding::new("default", "stellar:testnet"),
/// "test-nonce", &digest, "1000", &lifetime);
/// assert!(verify_toolset_gate_attestation(
///     &key, &stellar_agent_core::approval::AttestationBinding::new("default", "stellar:testnet"),
///     "test-nonce",
///     "my-toolset",
///     "sign-payment",
///     "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
///     "XLM",
///     0,
///     10_000_000,
///     "1000",
///     &AttestationScope::V3(lifetime),
///     &blob,
/// ));
/// ```
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn verify_toolset_gate_attestation(
    key: &[u8; 32],
    binding: &AttestationBinding<'_>,
    approval_nonce: &str,
    toolset_name: &str,
    capability: &str,
    destination: &str,
    asset: &str,
    amount_min_stroops: i64,
    amount_max_stroops: i64,
    process_uid: &str,
    scope: &AttestationScope<'_>,
    attestation_blob: &[u8; 32],
) -> bool {
    let digest = compute_toolset_gate_digest(
        toolset_name,
        capability,
        destination,
        asset,
        amount_min_stroops,
        amount_max_stroops,
    );
    verify_attestation(
        key,
        binding,
        approval_nonce,
        &digest,
        process_uid,
        scope,
        attestation_blob,
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// TrustlineClawbackOptIn digest
// ─────────────────────────────────────────────────────────────────────────────

/// Domain-separation tag for the `TrustlineClawbackOptIn` attestation digest.
///
/// A layout change bumps the tag; digests under the previous tag do not verify.
///
/// Current version: `v1`.
pub const TRUSTLINE_CLAWBACK_OPT_IN_DOMAIN_TAG: &[u8] =
    b"stellar-agent-trustline-clawback-opt-in:v1";

/// Computes the 32-byte SHA-256 commitment for a `TrustlineClawbackOptIn`
/// approval, binding the wallet owner's acknowledgment to a specific
/// `(network, code, issuer)` triple.
///
/// # Domain-separated length-prefixed preimage
///
/// ```text
/// SHA-256(
///   TRUSTLINE_CLAWBACK_OPT_IN_DOMAIN_TAG
///   || u32_be(len(network)) || network
///   || u32_be(len(code))    || code
///   || u32_be(len(issuer))  || issuer
/// )
/// ```
///
/// Length prefixes on every variable-length field prevent boundary-collision
/// attacks.  The domain-separation tag ensures this digest cannot
/// cross-validate against any other attestation kind.
///
/// # Layout citation
///
/// Preimage layout is defined here (this file) and is the canonical source.
/// The `TRUSTLINE_CLAWBACK_OPT_IN_DOMAIN_TAG` version tag guarantees existing
/// blobs fail closed if the layout is ever revised.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::approval::attestation::compute_trustline_clawback_opt_in_digest;
///
/// let digest = compute_trustline_clawback_opt_in_digest(
///     "Test SDF Network ; September 2015",
///     "USDC",
///     "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5",
/// );
/// assert_eq!(digest.len(), 32);
/// ```
#[must_use]
pub fn compute_trustline_clawback_opt_in_digest(
    network: &str,
    code: &str,
    issuer: &str,
) -> [u8; 32] {
    let mut hasher = Sha256::new();

    // Domain-separation tag (fixed-length; no length prefix needed).
    hasher.update(TRUSTLINE_CLAWBACK_OPT_IN_DOMAIN_TAG);

    // Length-prefixed variable-length fields.
    let network_len = u32::try_from(network.len()).unwrap_or(u32::MAX);
    hasher.update(network_len.to_be_bytes());
    hasher.update(network.as_bytes());

    let code_len = u32::try_from(code.len()).unwrap_or(u32::MAX);
    hasher.update(code_len.to_be_bytes());
    hasher.update(code.as_bytes());

    let issuer_len = u32::try_from(issuer.len()).unwrap_or(u32::MAX);
    hasher.update(issuer_len.to_be_bytes());
    hasher.update(issuer.as_bytes());

    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// RuleProposalSimulated digest
// ─────────────────────────────────────────────────────────────────────────────

/// Domain-separation tag for the `RuleProposalSimulated` attestation digest.
///
/// A layout change bumps the tag; digests under the previous tag do not verify.
///
/// Current version: `v1`.
pub const RULE_PROPOSAL_DOMAIN_TAG: &[u8] = b"stellar-agent-rule-proposal-v1";

/// Computes the 32-byte SHA-256 digest binding an agent-proposed
/// `add_context_rule` installation to its EXACT resolved arguments.
///
/// # Domain-separated length-prefixed preimage
///
/// ```text
/// SHA-256(
///   RULE_PROPOSAL_DOMAIN_TAG
///   || u32_be(len(invoke_contract_args_xdr)) || invoke_contract_args_xdr
///   || u32_be(len(smart_account_xdr))        || smart_account_xdr
///   || u32_be(len(auth_rule_ids_xdr))         || auth_rule_ids_xdr
///   || flags_byte
/// )
/// ```
///
/// Length prefixes on every variable-length field prevent boundary-collision
/// attacks (same discipline as every other digest in this module). The
/// fixed-width `flags_byte` needs no length prefix.
///
/// # Why XDR, not serde
///
/// `serde`/JSON/TOML serialization of the resolved rule definition is not
/// ordering-stable across crate versions (field order, map key order, and
/// numeric representation are all serde-implementation details). XDR is the
/// wire format the Soroban host itself consumes to execute
/// `add_context_rule`, and is stable by protocol definition — hashing the
/// SAME XDR bytes the invocation will submit is the only representation
/// guaranteed to bind EXACTLY what gets installed.
///
/// # Domain separation
///
/// The domain tag, plus hashing a distinct XDR type
/// (`InvokeContractArgs` for `add_context_rule`), makes this digest space
/// disjoint from `envelope_sha256` (`PaymentSimulated` / `ClaimSimulated`,
/// which hash a full transaction envelope) and from
/// [`compute_toolset_gate_digest`] / [`compute_trustline_clawback_opt_in_digest`]
/// (different domain tags) — an attestation minted for one kind can never
/// verify as another, even though every kind shares the same keyring HMAC key.
///
/// # Caller-side construction
///
/// `stellar-agent-core` cannot depend on `stellar-agent-smart-account` (the
/// latter depends on the former), so this function accepts pre-encoded XDR
/// byte buffers rather than typed `InvokeContractArgs` / `ScAddress` values.
/// `stellar-agent-smart-account::managers::rules::compute_context_rule_proposal_sha256`
/// builds `invoke_contract_args_xdr` from `build_add_context_rule_args`
/// wrapped in the OZ `add_context_rule` `InvokeContractArgs` (the SAME
/// builder `install_rule_inner` calls), `smart_account_xdr` from XDR-encoding
/// the smart-account contract's `ScAddress`, and `auth_rule_ids_xdr` via
/// [`super::super::smart_account::rule_id::encode_context_rule_ids`] — the
/// SAME encoder already used for the on-chain signing auth-digest preimage.
/// `flags_byte` packs `accept_mutable_verifier` (bit 0) and
/// `accept_unknown_verifier` (bit 1); all other bits are reserved and MUST
/// be zero.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::approval::attestation::compute_rule_proposal_digest;
///
/// let digest = compute_rule_proposal_digest(b"invoke-args-xdr", b"sa-xdr", b"ids-xdr", 0);
/// assert_eq!(digest.len(), 32);
/// ```
#[must_use]
pub fn compute_rule_proposal_digest(
    invoke_contract_args_xdr: &[u8],
    smart_account_xdr: &[u8],
    auth_rule_ids_xdr: &[u8],
    flags_byte: u8,
) -> [u8; 32] {
    let mut hasher = Sha256::new();

    // Domain-separation tag (fixed-length; no length prefix needed).
    hasher.update(RULE_PROPOSAL_DOMAIN_TAG);

    // Length-prefixed variable-length fields.
    let args_len = u32::try_from(invoke_contract_args_xdr.len()).unwrap_or(u32::MAX);
    hasher.update(args_len.to_be_bytes());
    hasher.update(invoke_contract_args_xdr);

    let sa_len = u32::try_from(smart_account_xdr.len()).unwrap_or(u32::MAX);
    hasher.update(sa_len.to_be_bytes());
    hasher.update(smart_account_xdr);

    let ids_len = u32::try_from(auth_rule_ids_xdr.len()).unwrap_or(u32::MAX);
    hasher.update(ids_len.to_be_bytes());
    hasher.update(auth_rule_ids_xdr);

    // Fixed-width flags byte (no length prefix needed).
    hasher.update([flags_byte]);

    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Computes the HMAC-SHA256 attestation blob, version 3.
///
/// # Input domain
///
/// ```text
/// mac.update(b"stellar-agent-approval-attestation:v3")
/// mac.update(u32_be(len(profile_name)))   mac.update(profile_name)
/// mac.update(u32_be(len(chain_id)))       mac.update(chain_id)
/// mac.update(u32_be(len(approval_nonce))) mac.update(approval_nonce)
/// mac.update(envelope_sha256)
/// mac.update(u32_be(len(process_uid)))    mac.update(process_uid)
/// mac.update(u32_be(len(kind)))           mac.update(kind)
/// mac.update(u64_be(created_at_unix_ms))
/// mac.update(u64_be(expires_at_unix_ms))
/// ```
///
/// Lengths count UTF-8 bytes, encoded as big-endian u32 with saturation.
/// The tag separates this HMAC from every other use of the key.
/// Binding fields make a blob unverifiable under another profile or chain;
/// `lifetime` makes it unverifiable for another kind or lifetime.
/// A layout change bumps the tag; blobs under one tag do not verify under
/// another.
///
/// # Key discipline
///
/// The caller MUST wrap the key in `Zeroizing<[u8; 32]>` and pass `&*key`
/// here.  This function does not allocate key bytes.
///
/// # Panics
///
/// Never panics in practice.  `HmacSha256::new_from_slice` returns `Err` only
/// for a zero-length key slice; a `&[u8; 32]` is always 32 bytes so the error
/// path is unreachable.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::approval::attestation::{AttestedLifetime, compute_attestation};
///
/// let key = [0x42u8; 32];
/// let env_hash = [0x01u8; 32];
/// let lifetime = AttestedLifetime::new("PaymentSimulated", 0, 60_000);
/// let blob = compute_attestation(&key,
/// &stellar_agent_core::approval::AttestationBinding::new("default", "stellar:testnet"),
/// "test-nonce", &env_hash, "1000", &lifetime);
/// assert_eq!(blob.len(), 32);
/// ```
#[must_use]
pub fn compute_attestation(
    key: &[u8; 32],
    binding: &AttestationBinding<'_>,
    approval_nonce: &str,
    envelope_sha256: &[u8; 32],
    process_uid: &str,
    lifetime: &AttestedLifetime<'_>,
) -> [u8; 32] {
    compute_with_scope(
        key,
        binding,
        approval_nonce,
        envelope_sha256,
        process_uid,
        &AttestationScope::V3(*lifetime),
    )
}

/// Computes the HMAC-SHA256 attestation blob of a pending approval, version 4.
///
/// Takes [`compute_attestation`]'s arguments plus the approver the approving
/// surface verified, and authenticates all of them:
///
/// ```text
/// mac.update(b"stellar-agent-approval-attestation:v4")
/// (profile_name, chain_id, approval_nonce, envelope_sha256, process_uid,
///  kind, created_at_unix_ms, expires_at_unix_ms, as version 3 lays them out)
/// mac.update([0x00])                                  local approver
/// mac.update([0x01])                                  remote approver,
/// mac.update(u32_be(len(credential_id)))              followed by its
/// mac.update(credential_id)                           credential ID
/// ```
///
/// Same key discipline as [`compute_attestation`].
///
/// # Examples
///
/// ```
/// use stellar_agent_core::approval::attestation::{
///     AttestationScope, AttestedApprover, AttestedLifetime, compute_attestation_v4,
///     verify_attestation,
/// };
///
/// let key = [0x42u8; 32];
/// let binding = stellar_agent_core::approval::AttestationBinding::new("default",
/// "stellar:testnet");
/// let lifetime = AttestedLifetime::new("PaymentSimulated", 0, 60_000);
/// let approver = AttestedApprover::Local;
/// let blob = compute_attestation_v4(&key, &binding, "n", &[1u8; 32], "1000", &lifetime,
/// &approver);
/// assert!(verify_attestation(&key, &binding, "n", &[1u8; 32], "1000",
/// &AttestationScope::V4(lifetime, &approver), &blob));
/// // The same blob does not verify as a version 3 attestation.
/// assert!(!verify_attestation(&key, &binding, "n", &[1u8; 32], "1000",
/// &AttestationScope::V3(lifetime), &blob));
/// ```
#[must_use]
pub fn compute_attestation_v4(
    key: &[u8; 32],
    binding: &AttestationBinding<'_>,
    approval_nonce: &str,
    envelope_sha256: &[u8; 32],
    process_uid: &str,
    lifetime: &AttestedLifetime<'_>,
    approver: &AttestedApprover,
) -> [u8; 32] {
    compute_with_scope(
        key,
        binding,
        approval_nonce,
        envelope_sha256,
        process_uid,
        &AttestationScope::V4(*lifetime, approver),
    )
}

/// Computes a version 5 attestation of a mainnet consent.
///
/// The preimage is version 4's with the version 5 domain tag, the mainnet
/// passkey approver, and the receipt digest appended:
///
/// ```text
/// mac.update(b"stellar-agent-approval-attestation:v5")
/// (profile_name, chain_id, approval_nonce, envelope_sha256, process_uid,
///  kind, created_at_unix_ms, expires_at_unix_ms, as version 4 lays them out)
/// mac.update([0x02])                                  mainnet passkey
/// mac.update(u32_be(len(credential_id)))              approver, with its
/// mac.update(credential_id)                           credential ID
/// mac.update(receipt_digest)                          32 bytes
/// ```
///
/// [`MainnetPresenceReceipt::digest`] defines the receipt digest. Same key
/// discipline as [`compute_attestation`].
#[must_use]
#[allow(
    clippy::too_many_arguments,
    reason = "each argument is a distinct field of the attested preimage"
)]
pub fn compute_attestation_v5(
    key: &[u8; 32],
    binding: &AttestationBinding<'_>,
    approval_nonce: &str,
    envelope_sha256: &[u8; 32],
    process_uid: &str,
    lifetime: &AttestedLifetime<'_>,
    approver: &AttestedApprover,
    receipt: &MainnetPresenceReceipt,
) -> [u8; 32] {
    compute_with_scope(
        key,
        binding,
        approval_nonce,
        envelope_sha256,
        process_uid,
        &AttestationScope::V5(*lifetime, approver, receipt),
    )
}

/// Computes the blob of `scope`'s layout. [`compute_attestation`] produces
/// version 3 for toolset grants, [`compute_attestation_v4`] version 4 for
/// pending testnet approvals and [`compute_attestation_v5`] version 5 for
/// mainnet consents; verification recomputes version 2 for grants stored
/// under it.
fn compute_with_scope(
    key: &[u8; 32],
    binding: &AttestationBinding<'_>,
    approval_nonce: &str,
    envelope_sha256: &[u8; 32],
    process_uid: &str,
    scope: &AttestationScope<'_>,
) -> [u8; 32] {
    // `new_from_slice` on a 32-byte array is always `Ok`.  The only failure
    // mode is a zero-length key slice; `&[u8; 32]` is never zero-length.
    #[allow(
        clippy::expect_used,
        reason = "new_from_slice fails only for zero-length keys; &[u8; 32] is always 32 bytes"
    )]
    let mut mac = HmacSha256::new_from_slice(key.as_ref())
        .expect("HmacSha256 key initialisation with 32-byte array is infallible");

    let length_prefixed = |mac: &mut HmacSha256, bytes: &[u8]| {
        let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
        mac.update(&len.to_be_bytes());
        mac.update(bytes);
    };

    mac.update(match scope {
        AttestationScope::V2 => ATTESTATION_TAG_V2,
        AttestationScope::V3(_) => ATTESTATION_TAG_V3,
        AttestationScope::V4(..) => ATTESTATION_TAG_V4,
        AttestationScope::V5(..) => ATTESTATION_TAG_V5,
    });
    length_prefixed(&mut mac, binding.profile_name.as_bytes());
    length_prefixed(&mut mac, binding.chain_id.as_bytes());
    length_prefixed(&mut mac, approval_nonce.as_bytes());
    // envelope_sha256 is always 32 bytes (fixed-length); no length prefix needed.
    mac.update(envelope_sha256);
    length_prefixed(&mut mac, process_uid.as_bytes());
    if let AttestationScope::V3(lifetime)
    | AttestationScope::V4(lifetime, _)
    | AttestationScope::V5(lifetime, ..) = scope
    {
        length_prefixed(&mut mac, lifetime.kind.as_bytes());
        mac.update(&lifetime.created_at_unix_ms.to_be_bytes());
        mac.update(&lifetime.expires_at_unix_ms.to_be_bytes());
    }
    if let AttestationScope::V4(_, approver) | AttestationScope::V5(_, approver, _) = scope {
        match approver {
            AttestedApprover::Local => mac.update(&[APPROVER_TAG_LOCAL]),
            AttestedApprover::Remote {
                credential_id_b64url,
            } => {
                mac.update(&[APPROVER_TAG_REMOTE]);
                length_prefixed(&mut mac, credential_id_b64url.as_bytes());
            }
            AttestedApprover::MainnetPasskey {
                credential_id_b64url,
            } => {
                mac.update(&[APPROVER_TAG_MAINNET_PASSKEY]);
                length_prefixed(&mut mac, credential_id_b64url.as_bytes());
            }
        }
    }
    if let AttestationScope::V5(_, _, receipt) = scope {
        // A receipt that is not well formed has no digest; its blob then
        // matches no recordable receipt, and `pending` never selects it.
        match receipt.digest() {
            Some(digest) => mac.update(&digest),
            None => mac.update(&[0xff]),
        }
    }

    let mut out = [0u8; 32];
    out.copy_from_slice(mac.finalize().into_bytes().as_slice());
    out
}

/// Verifies an HMAC-SHA256 attestation blob under the layout `scope` names,
/// using constant-time comparison.
///
/// Returns `true` iff `attestation_blob` matches the expected tag for the
/// given inputs.  The comparison is constant-time via
/// [`subtle::ConstantTimeEq`] to prevent timing side-channels. A caller
/// passes the scope its record stores
/// ([`super::store::PendingApproval::attestation_scope`]); a version 3 scope
/// whose kind or times differ from the attested ones does not verify.
///
/// # Key discipline
///
/// Same as [`compute_attestation`]: caller wraps the key in
/// `Zeroizing<[u8; 32]>` and passes `&*key`.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::approval::attestation::{
///     AttestationScope, AttestedLifetime, compute_attestation, verify_attestation,
/// };
///
/// let key = [0x42u8; 32];
/// let env_hash = [0x01u8; 32];
/// let binding = stellar_agent_core::approval::AttestationBinding::new("default",
/// "stellar:testnet");
/// let lifetime = AttestedLifetime::new("PaymentSimulated", 0, 60_000);
/// let blob = compute_attestation(&key, &binding, "my-nonce", &env_hash, "1000", &lifetime);
/// let scope = AttestationScope::V3(lifetime);
/// assert!(verify_attestation(&key, &binding, "my-nonce", &env_hash, "1000", &scope, &blob));
/// // Wrong key returns false.
/// let wrong_key = [0xffu8; 32];
/// assert!(!verify_attestation(&wrong_key, &binding, "my-nonce", &env_hash, "1000", &scope,
/// &blob));
/// // A longer stored lifetime returns false.
/// let stretched = AttestationScope::V3(AttestedLifetime::new("PaymentSimulated", 0, 120_000));
/// assert!(!verify_attestation(&key, &binding, "my-nonce", &env_hash, "1000", &stretched, &blob));
/// ```
#[must_use]
pub fn verify_attestation(
    key: &[u8; 32],
    binding: &AttestationBinding<'_>,
    approval_nonce: &str,
    envelope_sha256: &[u8; 32],
    process_uid: &str,
    scope: &AttestationScope<'_>,
    attestation_blob: &[u8; 32],
) -> bool {
    let expected = compute_with_scope(
        key,
        binding,
        approval_nonce,
        envelope_sha256,
        process_uid,
        scope,
    );
    // Constant-time comparison to prevent timing side-channels.
    expected.ct_eq(attestation_blob).into()
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

    /// The kind and lifetime the version 3 tests attest.
    const LIFETIME: AttestedLifetime<'static> = AttestedLifetime {
        kind: "PaymentSimulated",
        created_at_unix_ms: 1_000,
        expires_at_unix_ms: 61_000,
    };

    fn v3(
        key: &[u8; 32],
        binding: &AttestationBinding<'_>,
        nonce: &str,
        digest: &[u8; 32],
        uid: &str,
    ) -> [u8; 32] {
        compute_attestation(key, binding, nonce, digest, uid, &LIFETIME)
    }

    fn verify3(
        key: &[u8; 32],
        binding: &AttestationBinding<'_>,
        nonce: &str,
        digest: &[u8; 32],
        uid: &str,
        blob: &[u8; 32],
    ) -> bool {
        verify_attestation(
            key,
            binding,
            nonce,
            digest,
            uid,
            &AttestationScope::V3(LIFETIME),
            blob,
        )
    }

    // ── KAT (known-answer test) ──────────────────────────────────────────────

    /// The producer computes version 3, whose vector is computed
    /// independently from the documented layout.
    #[test]
    fn compute_attestation_known_answer_v3() {
        let result = v3(
            &[0x42; 32],
            &crate::approval::AttestationBinding::new("default", "stellar:testnet"),
            "test-nonce",
            &[0x01; 32],
            "1000",
        );
        let actual: String = result.iter().map(|byte| format!("{byte:02x}")).collect();
        assert_eq!(
            actual,
            "d7602ceb2823a7091ad49c9f34441eff659ee84b3dfffcbc9373e519332f8b14"
        );
    }

    /// A version 2 blob from the earlier producer still verifies under the
    /// version 2 scope, and not under version 3.
    #[test]
    fn a_version_2_blob_verifies_under_its_own_scope_only() {
        let binding = crate::approval::AttestationBinding::new("default", "stellar:testnet");
        let blob: [u8; 32] = crate::hex::decode_hex32(
            "eb90c7b47bafc0f5cc69786042755460f544f79b8c6b4e8874d5cc9fa87edabf",
        )
        .unwrap();
        assert!(verify_attestation(
            &[0x42; 32],
            &binding,
            "test-nonce",
            &[0x01; 32],
            "1000",
            &AttestationScope::V2,
            &blob,
        ));
        assert!(!verify3(
            &[0x42; 32],
            &binding,
            "test-nonce",
            &[0x01; 32],
            "1000",
            &blob,
        ));
        let current = v3(&[0x42; 32], &binding, "test-nonce", &[0x01; 32], "1000");
        assert!(!verify_attestation(
            &[0x42; 32],
            &binding,
            "test-nonce",
            &[0x01; 32],
            "1000",
            &AttestationScope::V2,
            &current,
        ));
        assert_eq!(AttestationScope::V2.version(), 2);
        assert_eq!(AttestationScope::V3(LIFETIME).version(), 3);
    }

    /// A version 3 blob fails when the stored kind, creation time, or expiry
    /// differs from the attested one.
    #[test]
    fn version_3_binds_the_kind_and_the_lifetime() {
        let binding = crate::approval::AttestationBinding::new("default", "stellar:mainnet");
        let blob = v3(&[0x42; 32], &binding, "nonce", &[0x01; 32], "1000");
        assert!(verify3(
            &[0x42; 32],
            &binding,
            "nonce",
            &[0x01; 32],
            "1000",
            &blob
        ));
        for changed in [
            AttestedLifetime::new("ClaimSimulated", 1_000, 61_000),
            AttestedLifetime::new("PaymentSimulated", 1_001, 61_000),
            AttestedLifetime::new("PaymentSimulated", 1_000, 61_001),
        ] {
            assert!(
                !verify_attestation(
                    &[0x42; 32],
                    &binding,
                    "nonce",
                    &[0x01; 32],
                    "1000",
                    &AttestationScope::V3(changed),
                    &blob,
                ),
                "{changed:?}"
            );
        }
    }

    #[test]
    fn compute_attestation_utf8_length_prefixes_count_bytes() {
        let binding = AttestationBinding::new("trésor", "stellar:網");
        let key = [0x42; 32];
        let digest = [0x01; 32];
        let mut preimage = b"stellar-agent-approval-attestation:v3".to_vec();
        preimage.extend_from_slice(&7_u32.to_be_bytes());
        preimage.extend_from_slice(binding.profile_name.as_bytes());
        preimage.extend_from_slice(&11_u32.to_be_bytes());
        preimage.extend_from_slice(binding.chain_id.as_bytes());
        preimage.extend_from_slice(&10_u32.to_be_bytes());
        preimage.extend_from_slice(b"test-nonce");
        preimage.extend_from_slice(&digest);
        preimage.extend_from_slice(&4_u32.to_be_bytes());
        preimage.extend_from_slice(b"1000");
        preimage.extend_from_slice(&16_u32.to_be_bytes());
        preimage.extend_from_slice(b"PaymentSimulated");
        preimage.extend_from_slice(&1_000_u64.to_be_bytes());
        preimage.extend_from_slice(&61_000_u64.to_be_bytes());
        assert_eq!(
            u32::from_be_bytes(preimage[37..41].try_into().unwrap()) as usize,
            binding.profile_name.len()
        );
        assert_eq!(
            u32::from_be_bytes(preimage[48..52].try_into().unwrap()) as usize,
            binding.chain_id.len()
        );
        let mut mac = Hmac::<Sha256>::new_from_slice(&key).unwrap();
        mac.update(&preimage);
        let expected: [u8; 32] = mac.finalize().into_bytes().into();
        assert_eq!(
            v3(&key, &binding, "test-nonce", &digest, "1000"),
            expected,
            "the HMAC must use UTF-8 byte-length prefixes"
        );
    }

    // ── Round-trip (compute → verify) ───────────────────────────────────────

    #[test]
    fn compute_then_verify_succeeds() {
        let key = [0x42u8; 32];
        let env_hash = [0xabu8; 32];
        let blob = v3(
            &key,
            &crate::approval::AttestationBinding::new("default", "stellar:testnet"),
            "my-approval-nonce",
            &env_hash,
            "500",
        );
        assert!(
            verify3(
                &key,
                &crate::approval::AttestationBinding::new("default", "stellar:testnet"),
                "my-approval-nonce",
                &env_hash,
                "500",
                &blob
            ),
            "round-trip verify must succeed"
        );
    }

    // ── Tamper detection ─────────────────────────────────────────────────────

    #[test]
    fn tamper_nonce_fails_verify() {
        let key = [0x42u8; 32];
        let env_hash = [0xabu8; 32];
        let blob = v3(
            &key,
            &crate::approval::AttestationBinding::new("default", "stellar:testnet"),
            "original-nonce",
            &env_hash,
            "500",
        );
        assert!(
            !verify3(
                &key,
                &crate::approval::AttestationBinding::new("default", "stellar:testnet"),
                "tampered-nonce",
                &env_hash,
                "500",
                &blob
            ),
            "tampered nonce must fail verify"
        );
    }

    #[test]
    fn tamper_envelope_hash_fails_verify() {
        let key = [0x42u8; 32];
        let env_hash = [0xabu8; 32];
        let blob = v3(
            &key,
            &crate::approval::AttestationBinding::new("default", "stellar:testnet"),
            "nonce",
            &env_hash,
            "500",
        );
        let mut tampered_hash = env_hash;
        tampered_hash[0] ^= 0xff;
        assert!(
            !verify3(
                &key,
                &crate::approval::AttestationBinding::new("default", "stellar:testnet"),
                "nonce",
                &tampered_hash,
                "500",
                &blob
            ),
            "tampered envelope hash must fail verify"
        );
    }

    #[test]
    fn tamper_user_id_fails_verify() {
        let key = [0x42u8; 32];
        let env_hash = [0xabu8; 32];
        let blob = v3(
            &key,
            &crate::approval::AttestationBinding::new("default", "stellar:testnet"),
            "nonce",
            &env_hash,
            "1000",
        );
        assert!(
            !verify3(
                &key,
                &crate::approval::AttestationBinding::new("default", "stellar:testnet"),
                "nonce",
                &env_hash,
                "9999",
                &blob
            ),
            "tampered process_uid must fail verify"
        );
    }

    #[test]
    fn tamper_blob_byte_fails_verify() {
        let key = [0x42u8; 32];
        let env_hash = [0xabu8; 32];
        let mut blob = v3(
            &key,
            &crate::approval::AttestationBinding::new("default", "stellar:testnet"),
            "nonce",
            &env_hash,
            "1000",
        );
        blob[0] ^= 0xff;
        assert!(
            !verify3(
                &key,
                &crate::approval::AttestationBinding::new("default", "stellar:testnet"),
                "nonce",
                &env_hash,
                "1000",
                &blob
            ),
            "bit-flipped blob must fail verify"
        );
    }

    // ── Cross-key isolation ──────────────────────────────────────────────────

    #[test]
    fn different_key_fails_verify() {
        let key1 = [0x11u8; 32];
        let key2 = [0x22u8; 32];
        let env_hash = [0xabu8; 32];
        let blob = v3(
            &key1,
            &crate::approval::AttestationBinding::new("default", "stellar:testnet"),
            "nonce",
            &env_hash,
            "1000",
        );
        assert!(
            !verify3(
                &key2,
                &crate::approval::AttestationBinding::new("default", "stellar:testnet"),
                "nonce",
                &env_hash,
                "1000",
                &blob
            ),
            "different key must fail verify"
        );
    }

    // ── Boundary-collision defence ───────────────────────────────────────────

    #[test]
    fn no_boundary_collision_nonce_uid() {
        let key = [0x55u8; 32];
        let env_hash = [0x00u8; 32];
        let blob1 = v3(
            &key,
            &crate::approval::AttestationBinding::new("default", "stellar:testnet"),
            "ab",
            &env_hash,
            "cd",
        );
        let blob2 = v3(
            &key,
            &crate::approval::AttestationBinding::new("default", "stellar:testnet"),
            "abc",
            &env_hash,
            "d",
        );
        assert_ne!(
            blob1, blob2,
            "length-prefix separators must prevent boundary collisions"
        );
    }

    // ── Determinism ──────────────────────────────────────────────────────────

    #[test]
    fn compute_attestation_is_deterministic() {
        let key = [0x99u8; 32];
        let env_hash = [0x77u8; 32];
        let b1 = v3(
            &key,
            &crate::approval::AttestationBinding::new("default", "stellar:testnet"),
            "same-nonce",
            &env_hash,
            "42",
        );
        let b2 = v3(
            &key,
            &crate::approval::AttestationBinding::new("default", "stellar:testnet"),
            "same-nonce",
            &env_hash,
            "42",
        );
        assert_eq!(b1, b2, "compute_attestation must be deterministic");
    }

    // ── envelope_sha256 ──────────────────────────────────────────────────────

    #[test]
    fn envelope_sha256_is_32_bytes() {
        let hash = envelope_sha256(b"fake-xdr-bytes");
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn envelope_sha256_differs_on_different_input() {
        let h1 = envelope_sha256(b"xdr1");
        let h2 = envelope_sha256(b"xdr2");
        assert_ne!(h1, h2);
    }

    #[test]
    fn envelope_sha256_is_deterministic() {
        let h1 = envelope_sha256(b"xdr");
        let h2 = envelope_sha256(b"xdr");
        assert_eq!(h1, h2);
    }

    // ── verify_attestation: constant-time path exercised ────────────────────

    #[test]
    fn verify_attestation_constant_time_path_reachable() {
        let key = [0x33u8; 32];
        let env_hash = [0xddu8; 32];
        let blob = v3(
            &key,
            &crate::approval::AttestationBinding::new("default", "stellar:testnet"),
            "n",
            &env_hash,
            "u",
        );
        assert!(verify3(
            &key,
            &crate::approval::AttestationBinding::new("default", "stellar:testnet"),
            "n",
            &env_hash,
            "u",
            &blob
        ));
        let wrong = [0u8; 32];
        assert!(!verify3(
            &key,
            &crate::approval::AttestationBinding::new("default", "stellar:testnet"),
            "n",
            &env_hash,
            "u",
            &wrong
        ));
    }

    // ── Toolset-gate digest KAT ─────────────────────────────────────────────────
    //
    // Known-answer test vector for `compute_toolset_gate_digest`.  Any accidental
    // change to the preimage layout is detected immediately.
    // The expected bytes are computed by the reference Python below:
    //
    // ```python
    // import hashlib, struct
    // DOMAIN_TAG = b"stellar-agent-toolset-grant:v1"
    // toolset_name = b"test-toolset"
    // capability = b"sign-payment"
    // destination = b"GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    // asset = b"XLM"
    // amount_min = 0
    // amount_max = 10_000_000
    //
    // msg = (
    //     DOMAIN_TAG
    //     + struct.pack(">I", len(toolset_name)) + toolset_name
    //     + struct.pack(">I", len(capability)) + capability
    //     + struct.pack(">I", len(destination)) + destination
    //     + struct.pack(">I", len(asset)) + asset
    //     + struct.pack(">q", amount_min)
    //     + struct.pack(">q", amount_max)
    // )
    // print(hashlib.sha256(msg).hexdigest())
    // ```
    //
    // Run to regenerate if preimage layout changes (REQUIRES domain tag bump).

    #[test]
    fn compute_toolset_gate_digest_known_answer() {
        const DEST_G: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

        let result = compute_toolset_gate_digest(
            "test-toolset",
            "sign-payment",
            DEST_G,
            "XLM",
            0_i64,
            10_000_000_i64,
        );

        // Reference Python gives the expected 32-byte hex digest.
        // Recompute here using the same algorithm as the function under test.
        let mut hasher = Sha256::new();
        hasher.update(TOOLSET_GATE_DOMAIN_TAG);
        let fields: &[&[u8]] = &[b"test-toolset", b"sign-payment", DEST_G.as_bytes(), b"XLM"];
        for field in fields {
            let len = u32::try_from(field.len()).unwrap().to_be_bytes();
            hasher.update(len);
            hasher.update(field);
        }
        hasher.update(0_i64.to_be_bytes());
        hasher.update(10_000_000_i64.to_be_bytes());
        let mut expected = [0u8; 32];
        expected.copy_from_slice(&hasher.finalize());

        assert_eq!(
            result, expected,
            "KAT: compute_toolset_gate_digest output mismatch — domain tag or \
             preimage layout changed; bump TOOLSET_GATE_DOMAIN_TAG version"
        );
        assert_ne!(
            result, [0u8; 32],
            "KAT: toolset gate digest must not be all-zero"
        );
    }

    // ── Toolset-gate boundary-collision defence ─────────────────────────────────

    #[test]
    fn toolset_gate_digest_no_boundary_collision_toolset_cap() {
        // toolset="ab" cap="cd" must differ from toolset="a" cap="bcd" (length prefixes).
        const DEST_G: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let d1 = compute_toolset_gate_digest("ab", "cd", DEST_G, "XLM", 0, 1_000_000);
        let d2 = compute_toolset_gate_digest("a", "bcd", DEST_G, "XLM", 0, 1_000_000);
        assert_ne!(
            d1, d2,
            "boundary collision detected in toolset_name/capability fields"
        );
    }

    // ── verify_toolset_gate_attestation round-trip ──────────────────────────────

    #[test]
    fn verify_toolset_gate_attestation_round_trip() {
        const DEST_G: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let key = [0x77u8; 32];
        let digest =
            compute_toolset_gate_digest("my-toolset", "sign-payment", DEST_G, "XLM", 0, 5_000_000);
        let blob = v3(
            &key,
            &crate::approval::AttestationBinding::new("default", "stellar:testnet"),
            "gate-nonce",
            &digest,
            "1234",
        );

        assert!(
            verify_toolset_gate_attestation(
                &key,
                &crate::approval::AttestationBinding::new("default", "stellar:testnet"),
                "gate-nonce",
                "my-toolset",
                "sign-payment",
                DEST_G,
                "XLM",
                0,
                5_000_000,
                "1234",
                &AttestationScope::V3(LIFETIME),
                &blob,
            ),
            "round-trip verify_toolset_gate_attestation must succeed"
        );
    }

    #[test]
    fn verify_toolset_gate_attestation_wrong_toolset_fails() {
        const DEST_G: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let key = [0x77u8; 32];
        let digest =
            compute_toolset_gate_digest("my-toolset", "sign-payment", DEST_G, "XLM", 0, 5_000_000);
        let blob = v3(
            &key,
            &crate::approval::AttestationBinding::new("default", "stellar:testnet"),
            "gate-nonce",
            &digest,
            "1234",
        );

        assert!(
            !verify_toolset_gate_attestation(
                &key,
                &crate::approval::AttestationBinding::new("default", "stellar:testnet"),
                "gate-nonce",
                "other-toolset", // tampered
                "sign-payment",
                DEST_G,
                "XLM",
                0,
                5_000_000,
                "1234",
                &AttestationScope::V3(LIFETIME),
                &blob,
            ),
            "tampered toolset_name must fail verification"
        );
    }

    #[test]
    fn verify_toolset_gate_attestation_wrong_amount_fails() {
        const DEST_G: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let key = [0x77u8; 32];
        let digest =
            compute_toolset_gate_digest("my-toolset", "sign-payment", DEST_G, "XLM", 0, 5_000_000);
        let blob = v3(
            &key,
            &crate::approval::AttestationBinding::new("default", "stellar:testnet"),
            "gate-nonce",
            &digest,
            "1234",
        );

        assert!(
            !verify_toolset_gate_attestation(
                &key,
                &crate::approval::AttestationBinding::new("default", "stellar:testnet"),
                "gate-nonce",
                "my-toolset",
                "sign-payment",
                DEST_G,
                "XLM",
                0,
                9_999_999, // tampered amount_max
                "1234",
                &AttestationScope::V3(LIFETIME),
                &blob,
            ),
            "tampered amount_max_stroops must fail verification"
        );
    }

    // ── RuleProposalSimulated digest KAT ─────────────────────────────────────
    //
    // Known-answer test vector for `compute_rule_proposal_digest`. Any
    // accidental change to the preimage layout is detected immediately.
    // Reference Python:
    //
    // ```python
    // import hashlib, struct
    // DOMAIN_TAG = b"stellar-agent-rule-proposal-v1"
    // args_xdr = b"fake-invoke-contract-args-xdr"
    // sa_xdr = b"fake-smart-account-xdr"
    // ids_xdr = b"fake-auth-rule-ids-xdr"
    // flags = 0
    //
    // msg = (
    //     DOMAIN_TAG
    //     + struct.pack(">I", len(args_xdr)) + args_xdr
    //     + struct.pack(">I", len(sa_xdr)) + sa_xdr
    //     + struct.pack(">I", len(ids_xdr)) + ids_xdr
    //     + bytes([flags])
    // )
    // print(hashlib.sha256(msg).hexdigest())
    // ```

    #[test]
    fn compute_rule_proposal_digest_known_answer() {
        const ARGS: &[u8] = b"fake-invoke-contract-args-xdr";
        const SA: &[u8] = b"fake-smart-account-xdr";
        const IDS: &[u8] = b"fake-auth-rule-ids-xdr";

        let result = compute_rule_proposal_digest(ARGS, SA, IDS, 0);

        let mut hasher = Sha256::new();
        hasher.update(RULE_PROPOSAL_DOMAIN_TAG);
        for field in [ARGS, SA, IDS] {
            let len = u32::try_from(field.len()).unwrap().to_be_bytes();
            hasher.update(len);
            hasher.update(field);
        }
        hasher.update([0u8]);
        let mut expected = [0u8; 32];
        expected.copy_from_slice(&hasher.finalize());

        assert_eq!(
            result, expected,
            "KAT: compute_rule_proposal_digest output mismatch — domain tag or \
             preimage layout changed; bump RULE_PROPOSAL_DOMAIN_TAG version"
        );
        assert_ne!(
            result, [0u8; 32],
            "KAT: rule proposal digest must not be all-zero"
        );
    }

    #[test]
    fn rule_proposal_digest_no_boundary_collision_across_fields() {
        // args="ab" sa="cd" must differ from args="a" sa="bcd" (length prefixes).
        let d1 = compute_rule_proposal_digest(b"ab", b"cd", b"ids", 0);
        let d2 = compute_rule_proposal_digest(b"a", b"bcd", b"ids", 0);
        assert_ne!(
            d1, d2,
            "boundary collision detected across invoke_contract_args_xdr/smart_account_xdr"
        );
    }

    #[test]
    fn rule_proposal_digest_flags_byte_changes_digest() {
        let d0 = compute_rule_proposal_digest(b"args", b"sa", b"ids", 0);
        let d1 = compute_rule_proposal_digest(b"args", b"sa", b"ids", 1);
        let d2 = compute_rule_proposal_digest(b"args", b"sa", b"ids", 2);
        let d3 = compute_rule_proposal_digest(b"args", b"sa", b"ids", 3);
        assert_ne!(d0, d1);
        assert_ne!(d0, d2);
        assert_ne!(d0, d3);
        assert_ne!(d1, d2);
    }

    #[test]
    fn rule_proposal_digest_is_deterministic() {
        let a = compute_rule_proposal_digest(b"args", b"sa", b"ids", 3);
        let b = compute_rule_proposal_digest(b"args", b"sa", b"ids", 3);
        assert_eq!(a, b);
    }

    #[test]
    fn rule_proposal_digest_differs_from_toolset_gate_digest() {
        // Same conceptual inputs must land in disjoint digest spaces because
        // of the differing domain tags — a rule-proposal attestation can
        // never verify as a toolset-gate attestation.
        const DEST_G: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let rule_digest = compute_rule_proposal_digest(b"x", b"y", b"z", 0);
        let toolset_digest = compute_toolset_gate_digest("x", "y", DEST_G, "XLM", 0, 1_000_000);
        assert_ne!(rule_digest, toolset_digest);
    }

    #[test]
    fn attestation_differs_per_profile_name() {
        let a = AttestationBinding::new("a", "stellar:testnet");
        let b = AttestationBinding::new("b", "stellar:testnet");
        let blob = v3(&[0x42; 32], &a, "nonce", &[1; 32], "1000");
        assert_ne!(blob, v3(&[0x42; 32], &b, "nonce", &[1; 32], "1000"));
        assert!(!verify3(&[0x42; 32], &b, "nonce", &[1; 32], "1000", &blob));
    }

    #[test]
    fn attestation_differs_per_chain_id() {
        let testnet = AttestationBinding::new("a", "stellar:testnet");
        let mainnet = AttestationBinding::new("a", "stellar:mainnet");
        for (mint, verify) in [(testnet, mainnet), (mainnet, testnet)] {
            let blob = v3(&[0x42; 32], &mint, "nonce", &[1; 32], "1000");
            assert_ne!(blob, v3(&[0x42; 32], &verify, "nonce", &[1; 32], "1000"));
            assert!(!verify3(
                &[0x42; 32],
                &verify,
                "nonce",
                &[1; 32],
                "1000",
                &blob
            ));
        }
    }

    #[test]
    fn v1_layout_blob_does_not_verify() {
        let mut mac = HmacSha256::new_from_slice(&[0x42; 32]).unwrap();
        mac.update(&10_u32.to_be_bytes());
        mac.update(b"test-nonce");
        mac.update(&[1; 32]);
        mac.update(&4_u32.to_be_bytes());
        mac.update(b"1000");
        let blob: [u8; 32] = mac.finalize().into_bytes().into();
        assert!(!verify3(
            &[0x42; 32],
            &AttestationBinding::new("default", "stellar:testnet"),
            "test-nonce",
            &[1; 32],
            "1000",
            &blob
        ));
    }

    /// The version 4 layout recomputed independently from the documented
    /// bytes, for a local and a remote approver.
    #[test]
    fn version_4_layout_matches_independent_hmac() {
        let binding = AttestationBinding::new("default", "stellar:testnet");
        let remote = AttestedApprover::Remote {
            credential_id_b64url: "AAECAw".to_owned(),
        };
        for approver in [AttestedApprover::Local, remote] {
            let mut mac = HmacSha256::new_from_slice(&[0x42; 32]).unwrap();
            mac.update(b"stellar-agent-approval-attestation:v4");
            for field in [&b"default"[..], b"stellar:testnet", b"nonce"] {
                mac.update(&u32::try_from(field.len()).unwrap().to_be_bytes());
                mac.update(field);
            }
            mac.update(&[1; 32]);
            mac.update(&4_u32.to_be_bytes());
            mac.update(b"1000");
            mac.update(&u32::try_from(LIFETIME.kind.len()).unwrap().to_be_bytes());
            mac.update(LIFETIME.kind.as_bytes());
            mac.update(&LIFETIME.created_at_unix_ms.to_be_bytes());
            mac.update(&LIFETIME.expires_at_unix_ms.to_be_bytes());
            match &approver {
                AttestedApprover::Local => mac.update(&[0x00]),
                AttestedApprover::Remote {
                    credential_id_b64url,
                } => {
                    mac.update(&[0x01]);
                    mac.update(&6_u32.to_be_bytes());
                    mac.update(credential_id_b64url.as_bytes());
                }
                AttestedApprover::MainnetPasskey { .. } => {
                    unreachable!("only version 4 approvers are listed")
                }
            }
            let expected: [u8; 32] = mac.finalize().into_bytes().into();
            assert_eq!(
                compute_attestation_v4(
                    &[0x42; 32],
                    &binding,
                    "nonce",
                    &[1; 32],
                    "1000",
                    &LIFETIME,
                    &approver
                ),
                expected
            );
        }
    }

    /// A version 4 blob verifies only for the approver it names: another
    /// credential ID, the local operator in place of a remote credential,
    /// and a record without its approver each refuse.
    #[test]
    fn remote_attestation_authenticates_approver() {
        let binding = AttestationBinding::new("default", "stellar:mainnet");
        let remote = |id: &str| AttestedApprover::Remote {
            credential_id_b64url: id.to_owned(),
        };
        let approver = remote("AAECAw");
        let blob = compute_attestation_v4(
            &[0x42; 32],
            &binding,
            "nonce",
            &[1; 32],
            "1000",
            &LIFETIME,
            &approver,
        );
        let verifies = |scope: Option<AttestationScope<'_>>| {
            scope.is_some_and(|scope| {
                verify_attestation(
                    &[0x42; 32],
                    &binding,
                    "nonce",
                    &[1; 32],
                    "1000",
                    &scope,
                    &blob,
                )
            })
        };
        assert!(verifies(AttestationScope::pending(
            4,
            LIFETIME,
            Some(&approver),
            None
        )));
        let other = remote("AAECBA");
        assert!(!verifies(AttestationScope::pending(
            4,
            LIFETIME,
            Some(&other),
            None
        )));
        assert!(!verifies(AttestationScope::pending(
            4,
            LIFETIME,
            Some(&AttestedApprover::Local),
            None
        )));
        assert!(AttestationScope::pending(4, LIFETIME, None, None).is_none());
        assert!(!verifies(Some(AttestationScope::V3(LIFETIME))));
        assert!(!verifies(Some(AttestationScope::V2)));

        let local = compute_attestation_v4(
            &[0x42; 32],
            &binding,
            "nonce",
            &[1; 32],
            "1000",
            &LIFETIME,
            &AttestedApprover::Local,
        );
        assert_ne!(local, blob);
    }

    /// Only version 4 with a well-formed approver selects a pending layout.
    #[test]
    fn pending_layout_is_version_4_with_a_well_formed_approver() {
        let local = AttestedApprover::Local;
        for version in [0, 1, ATTESTATION_VERSION_V2, ATTESTATION_VERSION, 5] {
            assert!(AttestationScope::pending(version, LIFETIME, Some(&local), None).is_none());
        }
        assert_eq!(
            AttestationScope::pending(4, LIFETIME, Some(&local), None)
                .unwrap()
                .version(),
            PENDING_ATTESTATION_VERSION
        );
        for id in ["", "AAECAw==", "AAECA+", "AAECAx", "A"] {
            let malformed = AttestedApprover::Remote {
                credential_id_b64url: id.to_owned(),
            };
            assert!(!malformed.is_well_formed(), "{id}");
            assert!(AttestationScope::pending(4, LIFETIME, Some(&malformed), None).is_none());
        }
        let debug = format!(
            "{:?}",
            AttestedApprover::Remote {
                credential_id_b64url: "BwcHBwcHBwcHBwcHBwcHBw".to_owned()
            }
        );
        assert!(!debug.contains("BwcHBwcHBwcHBwcHBwcHBw"), "{debug}");
        assert!(AttestationScope::from_version(4, LIFETIME).is_none());
        assert!(AttestationScope::from_version(5, LIFETIME).is_none());

        // A mainnet passkey approver never selects version 4, and the
        // well-formedness rule bounds its ID to 16 to 64 bytes.
        let passkey = AttestedApprover::MainnetPasskey {
            credential_id_b64url: "BwcHBwcHBwcHBwcHBwcHBw".to_owned(),
        };
        assert!(passkey.is_well_formed());
        assert!(AttestationScope::pending(4, LIFETIME, Some(&passkey), None).is_none());
        assert!(AttestationScope::pending(5, LIFETIME, Some(&passkey), None).is_none());
        for id in ["AAECAw", "", "BwcHBwcHBwcHBwcHBwcHBw=="] {
            assert!(
                !AttestedApprover::MainnetPasskey {
                    credential_id_b64url: id.to_owned()
                }
                .is_well_formed(),
                "{id}"
            );
        }
        let debug = format!("{passkey:?}");
        assert!(!debug.contains("BwcHBwcHBwcHBwcHBwcHBw"), "{debug}");
    }

    /// The version 4 layout of a local and a remote approval is frozen.
    #[test]
    fn version_4_known_answers_are_unchanged() {
        let binding = AttestationBinding::new("default", "stellar:testnet");
        let local = compute_attestation_v4(
            &[0x42; 32],
            &binding,
            "nonce",
            &[1; 32],
            "1000",
            &LIFETIME,
            &AttestedApprover::Local,
        );
        let remote = compute_attestation_v4(
            &[0x42; 32],
            &binding,
            "nonce",
            &[1; 32],
            "1000",
            &LIFETIME,
            &AttestedApprover::Remote {
                credential_id_b64url: "AAECAw".to_owned(),
            },
        );
        assert_eq!(
            crate::hex::encode(&local),
            "638a4456b01167ffd03cf0f474ec9e4560189c9cd2250f8a2fb1b8cc14250682"
        );
        assert_eq!(
            crate::hex::encode(&remote),
            "f92567fa7d210f4c11467319bf9d5d36d4e6b3309fb1bd55421899f877a0d223"
        );
    }
}
