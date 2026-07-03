//! Publisher signature verification for toolset packages.
//!
//! ## Canonical signed payload layout
//!
//! ```text
//! DOMAIN_TAG              (28 bytes: b"stellar-agent-toolset-sig:v1")
//! || u32_be(len(package)) || package_bytes
//! || u32_be(len(version)) || version_bytes
//! || u32_be(len(shasum))  || shasum_bytes   (64 ASCII hex chars)
//! ```
//!
//! This layout is CONSTRUCTED by the verifier from a fixed compile-time
//! constant plus the identity tuple — it is NEVER PARSED.  A signer using
//! `:v2` as the tag would produce a different, non-validating preimage
//! (the tag is the discriminant; there is no silent absorption).
//!
//! The `shasum` in the preimage is the LOCALLY-RECOMPUTED SHA-256 from
//! `crate::hash`, not a caller-supplied value — this closes the substitution
//! attack where a crafted package has a valid signature but a mismatched hash.
//!
//! Length-prefixing the three fields makes the concatenation injective on the
//! 3-tuple (a newline-delimited alternative permits `version="b\nc"` colliding
//! with `package="a\nb"` — that design is rejected).
//!
//! ## Algorithm
//!
//! ed25519 (`ed25519-dalek 2.2.0`, `verify_strict`).  `verify_strict` is
//! mandatory — it rejects small-order / malleable signatures.
//!
//! ## Trust set
//!
//! The trust set is a local file of G-strkeys (one per line, `#`-prefixed
//! comment lines and blank lines skipped).  Parsing is ALL-OR-NOTHING:
//! any malformed or duplicate entry rejects the whole file.  An absent /
//! empty trust set → `TrustSetEmpty` (fail-closed).
//!
//! ## Test vector
//!
//! The canonical payload byte layout is locked by
//! `tests/vectors/toolset-sig-v1.json` (full preimage + signature under a
//! fixed ephemeral test key).  That file is the machine-verifiable source
//! of truth for the layout specified above.

use std::collections::BTreeSet;
use std::io::Read;
use std::path::Path;

use ed25519_dalek::{Signature, VerifyingKey};
use stellar_strkey::ed25519::PublicKey as StrPublicKey;

use crate::{MAX_TRUST_SET_BYTES, MAX_TRUST_SET_ENTRIES, ToolsetInstallError};

/// Domain tag for the toolset-package signature preimage (exact 28-byte constant).
///
/// This constant is the canonical layout source for the preimage specification.
/// It is referenced by the test vector at `tests/vectors/toolset-sig-v1.json`.
/// The verifier builds the preimage from scratch; nothing is parsed from the
/// input — a `:v2` tag would be a different constant → different preimage →
/// non-validating signature.
///
/// ## Byte layout
///
/// ```text
/// DOMAIN_TAG  b"stellar-agent-toolset-sig:v1"  28 bytes
/// ```
pub const DOMAIN_TAG: &[u8] = b"stellar-agent-toolset-sig:v1";

/// Builds the canonical signed preimage for the given identity tuple.
///
/// This function is `pub` so integration tests can verify the canonical byte
/// layout against `tests/vectors/toolset-sig-v1.json`.
///
/// # Panics
///
/// Does not panic for any valid input.  All field lengths are bounded well
/// below `u32::MAX` by the upstream validation checks in
/// [`crate::install_toolset`] before this function is called.
///
/// Layout (length-prefixed, domain-separated):
/// ```text
/// DOMAIN_TAG (28 bytes)
/// || u32_be(len(package)) || package_bytes
/// || u32_be(len(version)) || version_bytes
/// || u32_be(len(shasum))  || shasum_bytes  (hex-encoded SHA-256, 64 chars)
/// ```
///
/// `shasum` MUST be the locally-recomputed hex digest from `crate::hash`,
/// not a caller-supplied string.
pub fn build_preimage(package: &str, version: &str, shasum_hex: &str) -> Vec<u8> {
    let package_bytes = package.as_bytes();
    let version_bytes = version.as_bytes();
    let shasum_bytes = shasum_hex.as_bytes();

    let capacity = DOMAIN_TAG.len()
        + 4
        + package_bytes.len()
        + 4
        + version_bytes.len()
        + 4
        + shasum_bytes.len();

    let mut preimage = Vec::with_capacity(capacity);

    preimage.extend_from_slice(DOMAIN_TAG);

    // Package name is validated to ≤ 64 ASCII bytes; fits in u32.
    // Version is validated to ≤ 64 bytes; fits in u32.
    // Shasum is always 64 ASCII hex chars; fits in u32.
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

    preimage
}

/// Verifies the ed25519 signature over the canonical preimage built from
/// `(package, version, shasum_hex)` using `publisher_pubkey_bytes`.
///
/// `shasum_hex` MUST be the locally-recomputed hex digest (lowercase, 64
/// ASCII chars) from `crate::hash`.
///
/// Uses `ed25519_dalek::VerifyingKey::verify_strict` (cofactor-checked,
/// no small-subgroup / malleable acceptance).
///
/// # Errors
///
/// - [`ToolsetInstallError::SignatureInvalid`] — signature fails `verify_strict`,
///   or `publisher_pubkey_bytes` is not a valid compressed ed25519 point.
pub fn verify_signature(
    package: &str,
    version: &str,
    shasum_hex: &str,
    signature_bytes: &[u8; 64],
    publisher_pubkey_bytes: &[u8; 32],
) -> Result<(), ToolsetInstallError> {
    let key = VerifyingKey::from_bytes(publisher_pubkey_bytes)
        .map_err(|_| ToolsetInstallError::SignatureInvalid)?;

    let preimage = build_preimage(package, version, shasum_hex);
    let sig = Signature::from_bytes(signature_bytes);

    // verify_strict rejects small-order / malleable signatures.
    key.verify_strict(&preimage, &sig)
        .map_err(|_| ToolsetInstallError::SignatureInvalid)
}

/// Shared file-read prelude for all trust-set loaders.
///
/// Opens `path`, reads at most `MAX_TRUST_SET_BYTES + 1` bytes through a capped
/// reader, rejects if the content exceeds the cap, and delegates to
/// [`parse_trust_set_content`].  Used by both [`load_trust_set`] and
/// `attestation::load_auditor_trust_set` so the size-cap and absent-file logic
/// lives in one place.
///
/// # Errors
///
/// Same contract as [`load_trust_set`].
pub(crate) fn load_trust_set_file(
    path: &Path,
    size_cap_label: &str,
) -> Result<BTreeSet<[u8; 32]>, ToolsetInstallError> {
    // Absent file → TrustSetEmpty (fail-closed).
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(ToolsetInstallError::TrustSetEmpty);
        }
        Err(e) => return Err(ToolsetInstallError::from_io(e)),
    };

    // Cap reading to prevent DoS on a huge trust-set file.
    let mut limited = file.take((MAX_TRUST_SET_BYTES as u64) + 1);
    let mut content = String::new();
    limited
        .read_to_string(&mut content)
        .map_err(ToolsetInstallError::from_io)?;

    if content.len() > MAX_TRUST_SET_BYTES {
        return Err(ToolsetInstallError::TrustSetMalformed {
            detail: format!("{size_cap_label} trust-set file exceeds size cap"),
        });
    }

    parse_trust_set_content(&content)
}

/// Loads and parses the publisher trust-set file at `path`.
///
/// Returns a `BTreeSet<[u8; 32]>` (raw ed25519 public key bytes, decoded
/// from G-strkeys) on success.
///
/// ## Parse contract (ALL-OR-NOTHING)
///
/// - File size is capped at [`MAX_TRUST_SET_BYTES`] before reading.
/// - Entry count is capped at [`MAX_TRUST_SET_ENTRIES`].
/// - Each non-blank, non-comment line must be a valid Stellar `G...` strkey
///   encoding an ed25519 public key.
/// - Duplicate keys (same 32 raw bytes, regardless of encoding) → error.
/// - Any malformed entry → `TrustSetMalformed` (whole file rejected).
/// - Absent or empty file → `TrustSetEmpty` (fail-closed).
///
/// # Errors
///
/// - [`ToolsetInstallError::Io`] — trust-set file cannot be opened or read.
/// - [`ToolsetInstallError::TrustSetEmpty`] — file absent or has no entries.
/// - [`ToolsetInstallError::TrustSetMalformed`] — any entry is malformed or
///   duplicate.
pub fn load_trust_set(path: &Path) -> Result<BTreeSet<[u8; 32]>, ToolsetInstallError> {
    load_trust_set_file(path, "publisher")
}

/// Parses trust-set content from a string (extracted for testability).
///
/// Used by [`load_trust_set`] and directly in tests.
///
/// # Errors
///
/// - [`ToolsetInstallError::TrustSetEmpty`] — content has no valid key entries.
/// - [`ToolsetInstallError::TrustSetMalformed`] — any entry is malformed,
///   duplicated, or the entry count exceeds the cap.
pub fn parse_trust_set_content(content: &str) -> Result<BTreeSet<[u8; 32]>, ToolsetInstallError> {
    let mut keys: BTreeSet<[u8; 32]> = BTreeSet::new();
    let mut count = 0usize;

    for raw_line in content.lines() {
        let line = raw_line.trim();

        // Skip blank lines and comment lines.
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Entry count cap.
        if count >= MAX_TRUST_SET_ENTRIES {
            return Err(ToolsetInstallError::TrustSetMalformed {
                detail: format!("trust-set exceeds {MAX_TRUST_SET_ENTRIES}-entry cap"),
            });
        }

        // Reject non-G-strkey inputs immediately (no panic on decode).
        let pubkey = StrPublicKey::from_string(line).map_err(|_| {
            ToolsetInstallError::TrustSetMalformed {
                detail: stellar_agent_toolsets::sanitise_display(
                    &format!("invalid G-strkey entry: '{line}'"),
                    256,
                ),
            }
        })?;

        let raw_bytes: [u8; 32] = pubkey.0;

        // Duplicate detection (canonical/non-canonical encodings of the same
        // 32 bytes are caught because we compare raw bytes, not the strkey string).
        if keys.contains(&raw_bytes) {
            return Err(ToolsetInstallError::TrustSetMalformed {
                detail: stellar_agent_toolsets::sanitise_display(
                    &format!("duplicate key: '{line}'"),
                    256,
                ),
            });
        }

        keys.insert(raw_bytes);
        count += 1;
    }

    if keys.is_empty() {
        return Err(ToolsetInstallError::TrustSetEmpty);
    }

    Ok(keys)
}

/// Checks that `signer_pubkey_bytes` is present in `trust_set`.
///
/// Returns the redacted signer key string on error (for `UntrustedPublisher`).
///
/// # Errors
///
/// - [`ToolsetInstallError::UntrustedPublisher`] — key not in trust set.
pub fn check_signer_trusted(
    signer_pubkey_bytes: &[u8; 32],
    trust_set: &BTreeSet<[u8; 32]>,
) -> Result<(), ToolsetInstallError> {
    if trust_set.contains(signer_pubkey_bytes) {
        return Ok(());
    }

    // Produce a redacted representation of the signer key.
    let key_str = if let Ok(pk) = StrPublicKey::from_payload(signer_pubkey_bytes) {
        stellar_agent_core::observability::redact::redact_strkey_first5_last5(&pk.to_string())
    } else {
        "G...?".to_owned()
    };

    Err(ToolsetInstallError::UntrustedPublisher {
        publisher_key_redacted: key_str,
    })
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

    use super::*;

    fn make_keypair() -> (SigningKey, [u8; 32]) {
        let sk = SigningKey::generate(&mut OsRng);
        let pk = sk.verifying_key().to_bytes();
        (sk, pk)
    }

    fn sign_preimage(sk: &SigningKey, preimage: &[u8]) -> [u8; 64] {
        sk.sign(preimage).to_bytes()
    }

    // ── Preimage construction ─────────────────────────────────────────────────

    #[test]
    fn preimage_starts_with_domain_tag() {
        let pre = build_preimage("my-toolset", "1.0.0", &"a".repeat(64));
        assert!(
            pre.starts_with(DOMAIN_TAG),
            "preimage must start with the domain tag"
        );
    }

    #[test]
    fn preimage_length_prefixed_fields_are_injective() {
        // Different orderings of same bytes should NOT produce the same preimage.
        let p1 = build_preimage("a", "bc", &"d".repeat(64));
        let p2 = build_preimage("ab", "c", &"d".repeat(64));
        assert_ne!(
            p1, p2,
            "length-prefixed preimage must be injective on the 3-tuple"
        );
    }

    // ── Signature verification ────────────────────────────────────────────────

    #[test]
    fn valid_signature_verifies() {
        let (sk, pk) = make_keypair();
        let shasum = "a".repeat(64);
        let preimage = build_preimage("my-toolset", "1.0.0", &shasum);
        let sig = sign_preimage(&sk, &preimage);
        verify_signature("my-toolset", "1.0.0", &shasum, &sig, &pk).unwrap();
    }

    #[test]
    fn wrong_signature_bytes_rejected() {
        let (sk, pk) = make_keypair();
        let shasum = "a".repeat(64);
        let preimage = build_preimage("my-toolset", "1.0.0", &shasum);
        let mut sig = sign_preimage(&sk, &preimage);
        sig[0] ^= 0x01; // Flip a bit.
        let err = verify_signature("my-toolset", "1.0.0", &shasum, &sig, &pk).unwrap_err();
        assert!(
            matches!(err, ToolsetInstallError::SignatureInvalid),
            "expected SignatureInvalid, got: {err:?}"
        );
    }

    #[test]
    fn wrong_pubkey_rejected() {
        let (sk, _pk) = make_keypair();
        let (_sk2, pk2) = make_keypair();
        let shasum = "a".repeat(64);
        let preimage = build_preimage("my-toolset", "1.0.0", &shasum);
        let sig = sign_preimage(&sk, &preimage);
        let err = verify_signature("my-toolset", "1.0.0", &shasum, &sig, &pk2).unwrap_err();
        assert!(
            matches!(err, ToolsetInstallError::SignatureInvalid),
            "expected SignatureInvalid, got: {err:?}"
        );
    }

    #[test]
    fn mutated_shasum_rejected() {
        let (sk, pk) = make_keypair();
        let shasum = "a".repeat(64);
        let preimage = build_preimage("my-toolset", "1.0.0", &shasum);
        let sig = sign_preimage(&sk, &preimage);
        // Verify with a different shasum → preimage differs → sig invalid.
        let different_shasum = "b".repeat(64);
        let err =
            verify_signature("my-toolset", "1.0.0", &different_shasum, &sig, &pk).unwrap_err();
        assert!(
            matches!(err, ToolsetInstallError::SignatureInvalid),
            "expected SignatureInvalid, got: {err:?}"
        );
    }

    // ── Trust set parsing ─────────────────────────────────────────────────────

    fn make_g_strkey(pk: &[u8; 32]) -> std::string::String {
        // `stellar_strkey` returns heapless::String<56>; convert to std String.
        StrPublicKey(*pk).to_string().as_str().to_owned()
    }

    #[test]
    fn single_valid_key_parsed() {
        let (_sk, pk) = make_keypair();
        let strkey = make_g_strkey(&pk);
        let content = format!("{strkey}\n");
        let set = parse_trust_set_content(&content).unwrap();
        assert_eq!(set.len(), 1);
        assert!(set.contains(&pk));
    }

    #[test]
    fn empty_content_returns_trust_set_empty() {
        let err = parse_trust_set_content("").unwrap_err();
        assert!(
            matches!(err, ToolsetInstallError::TrustSetEmpty),
            "expected TrustSetEmpty, got: {err:?}"
        );
    }

    #[test]
    fn comments_and_blanks_skipped() {
        let (_sk, pk) = make_keypair();
        let strkey = make_g_strkey(&pk);
        let content = format!("# This is a comment\n\n{strkey}\n\n");
        let set = parse_trust_set_content(&content).unwrap();
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn malformed_entry_rejects_whole_file() {
        let err = parse_trust_set_content("not-a-g-strkey").unwrap_err();
        assert!(
            matches!(err, ToolsetInstallError::TrustSetMalformed { .. }),
            "expected TrustSetMalformed, got: {err:?}"
        );
    }

    #[test]
    fn duplicate_key_rejects_whole_file() {
        let (_sk, pk) = make_keypair();
        let strkey = make_g_strkey(&pk);
        let content = format!("{strkey}\n{strkey}\n");
        let err = parse_trust_set_content(&content).unwrap_err();
        assert!(
            matches!(err, ToolsetInstallError::TrustSetMalformed { .. }),
            "expected TrustSetMalformed for duplicate, got: {err:?}"
        );
    }

    #[test]
    fn signer_in_trust_set_succeeds() {
        let (_sk, pk) = make_keypair();
        let mut set = BTreeSet::new();
        set.insert(pk);
        check_signer_trusted(&pk, &set).unwrap();
    }

    #[test]
    fn signer_not_in_trust_set_returns_untrusted_publisher() {
        let (_sk, pk) = make_keypair();
        let (_sk2, pk2) = make_keypair();
        let mut set = BTreeSet::new();
        set.insert(pk); // pk but NOT pk2
        let err = check_signer_trusted(&pk2, &set).unwrap_err();
        assert!(
            matches!(err, ToolsetInstallError::UntrustedPublisher { .. }),
            "expected UntrustedPublisher, got: {err:?}"
        );
    }
}
