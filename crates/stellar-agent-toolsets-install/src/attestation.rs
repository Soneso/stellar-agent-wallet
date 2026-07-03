//! Auditor attestation format, verification, and trust-set for the
//! install-time attestation gate.
//!
//! ## Canonical attestation preimage layout
//!
//! ```text
//! ATTESTATION_DOMAIN_TAG  (36 bytes: b"stellar-agent-toolset-attestation:v1")
//! || u32_be(len(package))       || package_bytes
//! || u32_be(len(version))       || version_bytes
//! || u32_be(len(shasum))        || shasum_bytes   (64 ASCII hex chars)
//! || u32_be(len(caps_joined))   || caps_joined_bytes  // Capability Ord order, comma-joined
//! ```
//!
//! This layout is CONSTRUCTED by the verifier from a fixed compile-time constant
//! plus the identity tuple and the capability tokens in `Capability` `Ord` order
//! — it is NEVER PARSED.
//! A signer using `:v2` as the tag would produce a different, non-validating
//! preimage (the tag is the discriminant; there is no silent absorption).
//!
//! The domain tag (`stellar-agent-toolset-attestation:v1`, 36 bytes) differs from
//! the publisher signature tag (`stellar-agent-toolset-sig:v1`, 28 bytes) in both
//! length and content.  This gives structural cross-protocol replay immunity: a
//! valid publisher signature CANNOT be a valid attestation preimage and vice
//! versa.
//!
//! Length-prefixing all four fields makes the concatenation injective on the
//! 4-tuple (mirrors `signature.rs` precedent).
//!
//! ## Algorithm
//!
//! ed25519 (`ed25519-dalek 2.2.0`, `verify_strict`).  `verify_strict` is
//! mandatory — it rejects small-order / malleable signatures.
//!
//! ## Auditor trust set
//!
//! The auditor trust set is a local file of G-strkeys at
//! `<toolsets_dir>/auditor-trust.txt` (DISTINCT from the publisher `trust.txt`).
//! Parsed by the same ALL-OR-NOTHING parser as the publisher trust set but
//! loaded from a SEPARATE file via a SEPARATE argument — no implicit
//! publisher→auditor bridge.
//!
//! An absent or empty auditor trust set → `TrustSetEmpty` → for a key-touching
//! toolset → `AttestationRequired` (fail-closed).
//!
//! ## Capability binding
//!
//! The preimage binds the capability tokens emitted in `Capability` `Ord` order
//! (enum declaration order) and comma-joined.  The auditor's signature provably
//! covers the exact capability claim:
//! "I reviewed THIS artefact WITH THESE capabilities."

use std::collections::BTreeSet;
use std::fmt;
use std::path::Path;

use ed25519_dalek::{Signature, VerifyingKey};
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use stellar_strkey::ed25519::PublicKey as StrPublicKey;

use stellar_agent_toolsets::CapabilitySet;

use crate::ToolsetInstallError;

// ── Hex serde helpers for fixed-size byte arrays ──────────────────────────────
//
// serde 1.x does not implement Serialize/Deserialize for [u8; 64].
// We use hex-encoded strings for CLI/file transport (human-readable, auditable).

/// Serialises a 32-byte array as a lowercase hex string.
fn serialize_bytes32<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&hex::encode(bytes))
}

/// Deserialises a lowercase hex string into a 32-byte array.
fn deserialize_bytes32<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
    let hex_str = String::deserialize(d)?;
    let bytes = hex::decode(&hex_str).map_err(|e| D::Error::custom(format!("invalid hex: {e}")))?;
    bytes
        .try_into()
        .map_err(|_| D::Error::custom("expected 32-byte hex string for auditor_pubkey"))
}

/// Serialises a 64-byte array as a lowercase hex string.
fn serialize_bytes64<S: Serializer>(bytes: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&hex::encode(bytes))
}

/// Deserialises a lowercase hex string into a 64-byte array.
fn deserialize_bytes64<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
    let hex_str = String::deserialize(d)?;
    let bytes = hex::decode(&hex_str).map_err(|e| D::Error::custom(format!("invalid hex: {e}")))?;
    bytes
        .try_into()
        .map_err(|_| D::Error::custom("expected 64-byte hex string for signature"))
}

/// Domain tag for the attestation preimage (exact 36-byte constant).
///
/// Distinct from the publisher domain tag (`stellar-agent-toolset-sig:v1`,
/// 28 bytes) in both length and content.  This difference is the structural
/// cross-protocol replay barrier: the SAME 64-byte ed25519 signature cannot
/// validate against BOTH preimage layouts simultaneously.
///
/// ## Byte layout
///
/// ```text
/// ATTESTATION_DOMAIN_TAG  b"stellar-agent-toolset-attestation:v1"  36 bytes
/// ```
pub const ATTESTATION_DOMAIN_TAG: &[u8] = b"stellar-agent-toolset-attestation:v1";

/// An auditor's signed attestation over a toolset artefact.
///
/// `ToolsetAttestation` binds `(package, version, shasum, capabilities)` to
/// a specific auditor public key and ed25519 signature.  The struct is the
/// carrier from the CLI/file transport layer into the install gate; the gate
/// performs its membership check and signature verification both against the
/// `auditor_pubkey` carried in THIS struct (single key source).
///
/// ## Serde encoding
///
/// `auditor_pubkey` serialises as a lowercase hex string (64 hex chars).
/// `signature` serialises as a lowercase hex string (128 hex chars).
/// This keeps the wire format human-readable and auditable.
///
/// ## Redacting `Debug`
///
/// `Debug` is manually implemented to NEVER emit the raw `auditor_pubkey` bytes
/// or the raw `signature` bytes.
/// `Display` of any error involving this struct similarly carries no key/sig bytes.
///
/// ## No `Default`
///
/// `Default` is intentionally NOT derived.  An all-zero attestation is
/// structurally invalid (all-zero pubkey is a degenerate curve point; all-zero
/// signature would never verify against a real preimage).  Allowing it silently
/// via `Default` would create a footgun in test code.
#[derive(Clone, Serialize, Deserialize)]
pub struct ToolsetAttestation {
    /// Package name this attestation covers.
    ///
    /// Must equal the install-time `package` argument after the Step-9 identity
    /// cross-check.
    pub package: String,

    /// Version string this attestation covers.
    ///
    /// Must equal the install-time `version` argument.
    pub version: String,

    /// SHA-256 hex digest (`64` lowercase hex chars) this attestation covers.
    ///
    /// Must equal the locally-recomputed `signed_shasum` from `hash.rs`.
    pub shasum: String,

    /// The set of capabilities this attestation covers.
    ///
    /// Must equal the signature-verified capability set from the parsed manifest.
    /// Binding the capabilities prevents capability-omission replay: an
    /// attestation for `sign-payment` cannot be presented for an artefact whose
    /// pin declares no key-touching capabilities, and vice versa.
    pub capabilities: CapabilitySet,

    /// Auditor ed25519 public key (raw 32 bytes; serialised as 64-char hex).
    ///
    /// This is the SINGLE authoritative auditor key — the gate checks trust-set
    /// membership AND verifies the signature against THESE SAME bytes.
    /// The CLI `--auditor` flag is used only to populate this field when
    /// constructing the struct; it does NOT introduce a second key path.
    #[serde(
        serialize_with = "serialize_bytes32",
        deserialize_with = "deserialize_bytes32"
    )]
    pub auditor_pubkey: [u8; 32],

    /// ed25519 signature over the canonical attestation preimage (64 bytes; serialised as 128-char hex).
    ///
    /// Built by the auditor over the preimage constructed by
    /// [`build_attestation_preimage`]; verified by
    /// [`verify_attestation_signature`] via `verify_strict`.
    #[serde(
        serialize_with = "serialize_bytes64",
        deserialize_with = "deserialize_bytes64"
    )]
    pub signature: [u8; 64],
}

/// Manually-implemented `Debug` that NEVER emits raw `auditor_pubkey` or
/// `signature` bytes.
///
/// Uses the redacted strkey form (first-5-last-5) for the auditor pubkey
/// and `[REDACTED]` for the signature bytes.
impl fmt::Debug for ToolsetAttestation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let key_str = StrPublicKey::from_payload(&self.auditor_pubkey)
            .map(|pk| {
                stellar_agent_core::observability::redact::redact_strkey_first5_last5(
                    &pk.to_string(),
                )
            })
            .unwrap_or_else(|_| "G...?".to_owned());

        f.debug_struct("ToolsetAttestation")
            .field("package", &self.package)
            .field("version", &self.version)
            .field(
                "shasum",
                &stellar_agent_core::hex::redact_hex_first8_last8(&self.shasum),
            )
            .field("capabilities", &self.capabilities)
            .field("auditor_pubkey", &key_str)
            .field("signature", &"[REDACTED]")
            .finish()
    }
}

/// Builds the canonical attestation preimage for the given identity tuple.
///
/// This function is `pub` so integration tests can verify the canonical byte
/// layout against `tests/vectors/toolset-attestation-v1.json`.
///
/// # Panics
///
/// Does not panic for any valid input.  All field lengths are bounded well below
/// `u32::MAX` by the upstream validation checks in [`crate::install_toolset`]
/// before this function is called.
///
/// Layout (length-prefixed, domain-separated):
/// ```text
/// ATTESTATION_DOMAIN_TAG (36 bytes)
/// || u32_be(len(package))      || package_bytes
/// || u32_be(len(version))      || version_bytes
/// || u32_be(len(shasum))       || shasum_bytes  (hex-encoded SHA-256, 64 chars)
/// || u32_be(len(caps_joined))  || caps_joined_bytes  // Capability Ord order, comma-joined
/// ```
///
/// `shasum` MUST be the locally-recomputed hex digest from `crate::hash`.
/// `caps_joined` is built from the **signature-verified** capability set in the
/// pin record — never from a re-parse of the on-disk `TOOLSET.md`
/// (capability-source invariant).
///
/// Capability tokens are emitted in `Capability` `Ord` order (enum declaration
/// order) and comma-joined.  Insertion order of the caller's `CapabilitySet` is
/// irrelevant; `CapabilitySet::iter()` always yields a canonical order.
pub fn build_attestation_preimage(
    package: &str,
    version: &str,
    shasum_hex: &str,
    capabilities: &CapabilitySet,
) -> Vec<u8> {
    let package_bytes = package.as_bytes();
    let version_bytes = version.as_bytes();
    let shasum_bytes = shasum_hex.as_bytes();

    // Emit tokens in Capability Ord order (enum declaration order), comma-joined.
    // `CapabilitySet::iter()` is backed by BTreeSet, yielding the derived Ord order.
    let caps_tokens: Vec<String> = capabilities.iter().map(|c| c.to_string()).collect();
    let caps_joined = caps_tokens.join(",");
    let caps_bytes = caps_joined.as_bytes();

    let capacity = ATTESTATION_DOMAIN_TAG.len()
        + 4
        + package_bytes.len()
        + 4
        + version_bytes.len()
        + 4
        + shasum_bytes.len()
        + 4
        + caps_bytes.len();

    let mut preimage = Vec::with_capacity(capacity);

    preimage.extend_from_slice(ATTESTATION_DOMAIN_TAG);

    // Package name is validated to ≤ 64 ASCII bytes; fits in u32.
    // Version is validated to ≤ 64 bytes; fits in u32.
    // Shasum is always 64 ASCII hex chars; fits in u32.
    // Capability tokens are bounded by the known taxonomy; fits in u32.
    // Using `as u32` is safe because all lengths are bounded well below u32::MAX
    // by the validation steps that precede this call.
    #[allow(clippy::cast_possible_truncation)]
    let pkg_len = package_bytes.len() as u32;
    preimage.extend_from_slice(&pkg_len.to_be_bytes());
    preimage.extend_from_slice(package_bytes);

    #[allow(clippy::cast_possible_truncation)]
    let ver_len = version_bytes.len() as u32;
    preimage.extend_from_slice(&ver_len.to_be_bytes());
    preimage.extend_from_slice(version_bytes);

    #[allow(clippy::cast_possible_truncation)]
    let sum_len = shasum_bytes.len() as u32;
    preimage.extend_from_slice(&sum_len.to_be_bytes());
    preimage.extend_from_slice(shasum_bytes);

    #[allow(clippy::cast_possible_truncation)]
    let caps_len = caps_bytes.len() as u32;
    preimage.extend_from_slice(&caps_len.to_be_bytes());
    preimage.extend_from_slice(caps_bytes);

    preimage
}

/// Verifies the ed25519 attestation signature inside `attestation`.
///
/// Uses `ed25519_dalek::VerifyingKey::verify_strict` (cofactor-checked,
/// no small-subgroup / malleable acceptance).  `verify_strict` is mandatory —
/// it rejects small-order / malleable signatures.
///
/// Both the membership check and the signature verify use `attestation.auditor_pubkey`
/// (single key source).
///
/// # Errors
///
/// - [`ToolsetInstallError::AttestationInvalid`] — `auditor_pubkey` is not a valid
///   compressed ed25519 point, or `verify_strict` fails.  The error is opaque
///   (no key/sig bytes).
pub fn verify_attestation_signature(
    attestation: &ToolsetAttestation,
    capabilities: &CapabilitySet,
) -> Result<(), ToolsetInstallError> {
    let key = VerifyingKey::from_bytes(&attestation.auditor_pubkey).map_err(|_| {
        ToolsetInstallError::AttestationInvalid {
            detail: "auditor public key is not a valid ed25519 point",
        }
    })?;

    let preimage = build_attestation_preimage(
        &attestation.package,
        &attestation.version,
        &attestation.shasum,
        capabilities,
    );
    let sig = Signature::from_bytes(&attestation.signature);

    // verify_strict rejects small-order / malleable signatures.
    key.verify_strict(&preimage, &sig)
        .map_err(|_| ToolsetInstallError::AttestationInvalid {
            detail: "ed25519 verify_strict failed for attestation signature",
        })
}

/// Checks that `auditor_pubkey_bytes` is present in `auditor_trust_set`.
///
/// Returns [`ToolsetInstallError::AuditorUntrusted`] with a redacted key string
/// if the key is not in the set.
///
/// # Errors
///
/// - [`ToolsetInstallError::AuditorUntrusted`] — key not in the auditor trust set.
pub fn check_auditor_trusted(
    auditor_pubkey_bytes: &[u8; 32],
    auditor_trust_set: &BTreeSet<[u8; 32]>,
) -> Result<(), ToolsetInstallError> {
    if auditor_trust_set.contains(auditor_pubkey_bytes) {
        return Ok(());
    }

    // `redact_strkey_first5_last5` already returns "G...?" for invalid inputs,
    // so no second fallback is needed here.
    let key_str = stellar_agent_core::observability::redact::redact_strkey_first5_last5(
        &StrPublicKey::from_payload(auditor_pubkey_bytes)
            .map(|pk| pk.to_string())
            .unwrap_or_default(),
    );

    Err(ToolsetInstallError::AuditorUntrusted {
        auditor_key_redacted: key_str,
    })
}

/// Loads the auditor trust set from `path`.
///
/// Uses the same shared file-read prelude as the publisher trust set
/// (`crate::signature::load_trust_set_file`) but is called with a DISTINCT
/// path — no fall-back to the publisher `trust.txt` exists.
/// An absent or empty auditor trust set fails closed (`TrustSetEmpty`).
///
/// # Errors
///
/// - [`ToolsetInstallError::Io`] — trust-set file cannot be opened or read.
/// - [`ToolsetInstallError::TrustSetEmpty`] — file absent or has no entries.
/// - [`ToolsetInstallError::TrustSetMalformed`] — any entry is malformed or duplicate.
pub fn load_auditor_trust_set(path: &Path) -> Result<BTreeSet<[u8; 32]>, ToolsetInstallError> {
    // Delegates to the shared file-read helper in signature.rs; the "auditor"
    // label is used only in the size-cap error message — it never selects a file.
    crate::signature::load_trust_set_file(path, "auditor")
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use ed25519_dalek::{Signer, SigningKey};
    use rand_core::OsRng;

    use stellar_agent_toolsets::parse_capability_value_pub;

    use super::*;
    use crate::signature::{DOMAIN_TAG, build_preimage};

    fn make_auditor_keypair() -> (SigningKey, [u8; 32]) {
        let sk = SigningKey::generate(&mut OsRng);
        let pk = sk.verifying_key().to_bytes();
        (sk, pk)
    }

    fn make_attestation(
        sk: &SigningKey,
        pk: [u8; 32],
        package: &str,
        version: &str,
        shasum: &str,
        caps: &CapabilitySet,
    ) -> ToolsetAttestation {
        let preimage = build_attestation_preimage(package, version, shasum, caps);
        let sig: [u8; 64] = sk.sign(&preimage).to_bytes();
        ToolsetAttestation {
            package: package.to_owned(),
            version: version.to_owned(),
            shasum: shasum.to_owned(),
            capabilities: caps.clone(),
            auditor_pubkey: pk,
            signature: sig,
        }
    }

    // ── Preimage construction ─────────────────────────────────────────────────

    #[test]
    fn attestation_preimage_starts_with_domain_tag() {
        let caps = CapabilitySet::empty();
        let pre = build_attestation_preimage("my-toolset", "1.0.0", &"a".repeat(64), &caps);
        assert!(
            pre.starts_with(ATTESTATION_DOMAIN_TAG),
            "attestation preimage must start with the attestation domain tag"
        );
    }

    #[test]
    fn attestation_domain_tag_is_exact_36_bytes() {
        assert_eq!(
            ATTESTATION_DOMAIN_TAG,
            b"stellar-agent-toolset-attestation:v1"
        );
        assert_eq!(ATTESTATION_DOMAIN_TAG.len(), 36);
    }

    #[test]
    fn attestation_preimage_length_prefixed_fields_are_injective() {
        // Different orderings of the same bytes should NOT produce the same preimage.
        let caps = CapabilitySet::empty();
        let p1 = build_attestation_preimage("a", "bc", &"d".repeat(64), &caps);
        let p2 = build_attestation_preimage("ab", "c", &"d".repeat(64), &caps);
        assert_ne!(
            p1, p2,
            "length-prefixed attestation preimage must be injective on the 4-tuple"
        );
    }

    #[test]
    fn attestation_preimage_capability_binding_is_injective() {
        // An empty capability set and a non-empty one must produce different preimages.
        let caps_empty = CapabilitySet::empty();
        let caps_sign = parse_capability_value_pub("sign-payment").unwrap();
        let p1 = build_attestation_preimage("my-toolset", "1.0.0", &"a".repeat(64), &caps_empty);
        let p2 = build_attestation_preimage("my-toolset", "1.0.0", &"a".repeat(64), &caps_sign);
        assert_ne!(
            p1, p2,
            "capability binding must make the preimage injective on the capability set"
        );
    }

    // ── Cross-protocol inequality ─────────────────────────────────────────────

    #[test]
    fn attestation_preimage_ne_publisher_preimage_for_same_tuple() {
        // The attestation domain tag and the publisher domain tag differ in both
        // length and content.  For any input tuple, the two preimages must differ.
        // This structural guarantee prevents cross-protocol replay.
        let caps = CapabilitySet::empty();
        let shasum = "a".repeat(64);

        let att_pre = build_attestation_preimage("my-toolset", "1.0.0", &shasum, &caps);
        let sig_pre = build_preimage("my-toolset", "1.0.0", &shasum);

        assert_ne!(
            att_pre, sig_pre,
            "attestation preimage must differ from publisher preimage for the same tuple \
             (cross-protocol replay protection)"
        );
    }

    #[test]
    fn attestation_domain_tag_ne_publisher_domain_tag() {
        // Direct constant comparison — belts-and-suspenders alongside the preimage test.
        assert_ne!(
            ATTESTATION_DOMAIN_TAG, DOMAIN_TAG,
            "attestation and publisher domain tags must differ"
        );
        assert_ne!(
            ATTESTATION_DOMAIN_TAG.len(),
            DOMAIN_TAG.len(),
            "attestation and publisher domain tags must have different lengths"
        );
    }

    // ── Signature verification ────────────────────────────────────────────────

    #[test]
    fn valid_attestation_verifies() {
        let (sk, pk) = make_auditor_keypair();
        let caps = parse_capability_value_pub("sign-payment").unwrap();
        let shasum = "a".repeat(64);
        let att = make_attestation(&sk, pk, "my-toolset", "1.0.0", &shasum, &caps);
        verify_attestation_signature(&att, &caps).unwrap();
    }

    #[test]
    fn wrong_auditor_key_rejected_as_attestation_invalid() {
        let (sk, _pk) = make_auditor_keypair();
        let (_sk2, pk2) = make_auditor_keypair();
        let caps = parse_capability_value_pub("sign-payment").unwrap();
        let shasum = "a".repeat(64);
        let mut att = make_attestation(&sk, _pk, "my-toolset", "1.0.0", &shasum, &caps);
        // Swap the pubkey — membership check passes but verify fails.
        att.auditor_pubkey = pk2;
        let err = verify_attestation_signature(&att, &caps).unwrap_err();
        assert!(
            matches!(err, ToolsetInstallError::AttestationInvalid { .. }),
            "expected AttestationInvalid, got: {err:?}"
        );
    }

    #[test]
    fn tampered_package_rejected() {
        let (sk, pk) = make_auditor_keypair();
        let caps = parse_capability_value_pub("sign-payment").unwrap();
        let shasum = "a".repeat(64);
        let mut att = make_attestation(&sk, pk, "my-toolset", "1.0.0", &shasum, &caps);
        att.package = "evil-toolset".to_owned();
        let err = verify_attestation_signature(&att, &caps).unwrap_err();
        assert!(
            matches!(err, ToolsetInstallError::AttestationInvalid { .. }),
            "expected AttestationInvalid for tampered package"
        );
    }

    #[test]
    fn tampered_version_rejected() {
        let (sk, pk) = make_auditor_keypair();
        let caps = parse_capability_value_pub("sign-payment").unwrap();
        let shasum = "a".repeat(64);
        let mut att = make_attestation(&sk, pk, "my-toolset", "1.0.0", &shasum, &caps);
        att.version = "2.0.0".to_owned();
        let err = verify_attestation_signature(&att, &caps).unwrap_err();
        assert!(
            matches!(err, ToolsetInstallError::AttestationInvalid { .. }),
            "expected AttestationInvalid for tampered version"
        );
    }

    #[test]
    fn tampered_shasum_rejected() {
        let (sk, pk) = make_auditor_keypair();
        let caps = parse_capability_value_pub("sign-payment").unwrap();
        let shasum = "a".repeat(64);
        let mut att = make_attestation(&sk, pk, "my-toolset", "1.0.0", &shasum, &caps);
        att.shasum = "b".repeat(64);
        let err = verify_attestation_signature(&att, &caps).unwrap_err();
        assert!(
            matches!(err, ToolsetInstallError::AttestationInvalid { .. }),
            "expected AttestationInvalid for tampered shasum"
        );
    }

    #[test]
    fn tampered_capabilities_in_preimage_rejected() {
        // The gate passes a different caps set (the verified one) than the
        // attestation was signed for.
        let (sk, pk) = make_auditor_keypair();
        let caps_signed = parse_capability_value_pub("sign-payment").unwrap();
        let caps_different = CapabilitySet::empty();
        let shasum = "a".repeat(64);
        let att = make_attestation(&sk, pk, "my-toolset", "1.0.0", &shasum, &caps_signed);
        // Verify with a different cap set — preimage differs → sig invalid.
        let err = verify_attestation_signature(&att, &caps_different).unwrap_err();
        assert!(
            matches!(err, ToolsetInstallError::AttestationInvalid { .. }),
            "expected AttestationInvalid for mismatched capabilities"
        );
    }

    #[test]
    fn mutated_signature_byte_rejected() {
        let (sk, pk) = make_auditor_keypair();
        let caps = parse_capability_value_pub("sign-payment").unwrap();
        let shasum = "a".repeat(64);
        let mut att = make_attestation(&sk, pk, "my-toolset", "1.0.0", &shasum, &caps);
        att.signature[0] ^= 0x01;
        let err = verify_attestation_signature(&att, &caps).unwrap_err();
        assert!(
            matches!(err, ToolsetInstallError::AttestationInvalid { .. }),
            "expected AttestationInvalid for mutated signature byte"
        );
    }

    #[test]
    fn all_zeros_pubkey_rejected_as_attestation_invalid() {
        // All-zero pubkey is a degenerate ed25519 point (small-order); verify_strict
        // must reject it.
        let (sk, pk) = make_auditor_keypair();
        let caps = parse_capability_value_pub("sign-payment").unwrap();
        let shasum = "a".repeat(64);
        let mut att = make_attestation(&sk, pk, "my-toolset", "1.0.0", &shasum, &caps);
        att.auditor_pubkey = [0u8; 32];
        let err = verify_attestation_signature(&att, &caps).unwrap_err();
        assert!(
            matches!(err, ToolsetInstallError::AttestationInvalid { .. }),
            "expected AttestationInvalid for all-zeros pubkey"
        );
    }

    #[test]
    fn publisher_sig_rejected_as_attestation() {
        // A valid PUBLISHER signature (signed over the publisher preimage) MUST
        // be rejected when presented as an ATTESTATION signature.
        // This verifies cross-protocol replay immunity.
        let (sk, pk) = make_auditor_keypair();
        let caps = parse_capability_value_pub("sign-payment").unwrap();
        let shasum = "a".repeat(64);

        // Sign over the PUBLISHER preimage.
        let publisher_preimage = build_preimage("my-toolset", "1.0.0", &shasum);
        let publisher_sig: [u8; 64] = sk.sign(&publisher_preimage).to_bytes();

        // Present the publisher sig in an attestation struct.
        let att = ToolsetAttestation {
            package: "my-toolset".to_owned(),
            version: "1.0.0".to_owned(),
            shasum: shasum.clone(),
            capabilities: caps.clone(),
            auditor_pubkey: pk,
            signature: publisher_sig,
        };

        let err = verify_attestation_signature(&att, &caps).unwrap_err();
        assert!(
            matches!(err, ToolsetInstallError::AttestationInvalid { .. }),
            "publisher signature must be rejected as an attestation signature \
             (cross-protocol replay protection)"
        );
    }

    // ── Trust set ─────────────────────────────────────────────────────────────

    #[test]
    fn auditor_in_trust_set_succeeds() {
        let (_sk, pk) = make_auditor_keypair();
        let mut set = BTreeSet::new();
        set.insert(pk);
        check_auditor_trusted(&pk, &set).unwrap();
    }

    #[test]
    fn auditor_not_in_trust_set_returns_auditor_untrusted() {
        let (_sk, pk) = make_auditor_keypair();
        let (_sk2, pk2) = make_auditor_keypair();
        let mut set = BTreeSet::new();
        set.insert(pk);
        let err = check_auditor_trusted(&pk2, &set).unwrap_err();
        assert!(
            matches!(err, ToolsetInstallError::AuditorUntrusted { .. }),
            "expected AuditorUntrusted, got: {err:?}"
        );
    }

    // ── Redacting Debug ───────────────────────────────────────────────────────

    #[test]
    fn debug_does_not_expose_auditor_pubkey_bytes() {
        let (sk, pk) = make_auditor_keypair();
        let caps = parse_capability_value_pub("sign-payment").unwrap();
        let shasum = "a".repeat(64);
        let att = make_attestation(&sk, pk, "my-toolset", "1.0.0", &shasum, &caps);

        let debug_str = format!("{att:?}");

        // The raw pubkey hex must not appear in Debug output.
        let pk_hex = hex::encode(pk);
        assert!(
            !debug_str.contains(&pk_hex),
            "Debug must not contain raw auditor pubkey hex; got: {debug_str}"
        );

        // The raw signature hex must not appear.
        let sig_hex = hex::encode(att.signature);
        assert!(
            !debug_str.contains(&sig_hex),
            "Debug must not contain raw signature hex; got: {debug_str}"
        );

        // The redaction sentinel must be present.
        assert!(
            debug_str.contains("[REDACTED]"),
            "Debug must contain [REDACTED] for signature; got: {debug_str}"
        );
    }

    // ── Capability token ordering ─────────────────────────────────────────────

    #[test]
    fn capability_tokens_are_sorted_in_preimage() {
        // Two capability sets with the same capabilities in different insertion
        // order must produce the SAME preimage (BTreeSet iteration is sorted).
        // This test verifies the sorted-join is canonical.
        let caps1 = parse_capability_value_pub("sign-payment read-balance").unwrap();
        let caps2 = parse_capability_value_pub("read-balance sign-payment").unwrap();
        let p1 = build_attestation_preimage("my-toolset", "1.0.0", &"a".repeat(64), &caps1);
        let p2 = build_attestation_preimage("my-toolset", "1.0.0", &"a".repeat(64), &caps2);
        assert_eq!(
            p1, p2,
            "capability tokens must be sorted consistently regardless of insertion order"
        );
    }
}
