//! BLAKE3 digest and ed25519 signature verification for policy documents.
//!
//! Three primitives:
//!
//! 1. [`crate::policy::v1::signature::digest`] — computes a BLAKE3 hash of the canonical policy bytes.
//! 2. [`crate::policy::v1::signature::sign`] — produces an ed25519 signature over the digest using the
//!    owner signing key.  It is the exact inverse of [`crate::policy::v1::signature::verify`].
//! 3. [`crate::policy::v1::signature::verify`] — verifies an ed25519 signature over the digest using the
//!    owner public key.
//!
//! Owner rotation uses [`build_owner_rotation`](crate::policy::v1::signature::build_owner_rotation)
//! and [`verify_owner_rotation`](crate::policy::v1::signature::verify_owner_rotation).
//! The previous owner signs a separate domain that binds both keys and the body.
//!
//! ## Dependencies
//!
//! - `ed25519-dalek` is used for signature production and verification.  No
//!   hand-rolled ed25519.
//! - `blake3` is used for hashing.  `subtle::ConstantTimeEq` is NOT needed
//!   here: `ed25519_dalek::VerifyingKey::verify_strict` is already
//!   internally constant-time on the signature comparison step.
//!
//! ## blake3 non-secret-input note
//!
//! The `canonical_bytes` input to `digest` is the canonical form of the
//! policy file — a non-secret operator-readable document.  BLAKE3's
//! compression function is NOT required to be constant-time for this input
//! (the input is not secret).  If a future change ever passes secret bytes
//! into a `blake3` call, this property must be re-evaluated.
//!
//! ## Caller contract for `verify`
//!
//! The `profile` name is not used inside `verify` itself — it is supplied by
//! the caller in [`crate::policy::v1::loader::load_signed_policy`] when constructing the
//! [`crate::policy::PolicyError::OwnerSignatureInvalid`] error variant.
//! `verify` returns a generic `()` on success or
//! [`crate::policy::PolicyError::OwnerSignatureInvalid`] with the caller-
//! supplied profile name on failure.  The split avoids coupling `signature.rs`
//! to the loader's profile-name plumbing while preserving the typed error.

use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};

use crate::policy::PolicyError;

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

/// Computes the BLAKE3 digest of `canonical_bytes`.
///
/// The output is a fixed 32-byte array suitable as the pre-image for
/// [`verify`].
///
/// The input MUST be the output of
/// [`super::canonical::canonical_bytes`] — non-secret, policy-file bytes
/// with the `[signature]` table excluded.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::policy::v1::signature::digest;
///
/// let bytes = b"version = 1\nscope = \"profile:default\"\n";
/// let d = digest(bytes);
/// assert_eq!(d.len(), 32);
///
/// // Same input always yields the same digest.
/// assert_eq!(digest(bytes), digest(bytes));
/// ```
#[must_use]
pub fn digest(canonical_bytes: &[u8]) -> [u8; 32] {
    // blake3::hash is deterministic and pure-Rust (the "pure" feature is
    // enabled in the workspace dep, see Cargo.toml comment).
    let h = blake3::hash(canonical_bytes);
    // `as_bytes()` returns `&[u8; 32]`; copy into an owned array.
    *h.as_bytes()
}

/// Verifies an ed25519 signature over `digest` using `owner_pubkey`.
///
/// Uses `ed25519_dalek::VerifyingKey::verify_strict` which is internally
/// constant-time on the signature check (cofactor-checked, no malleability
/// acceptance).
///
/// On success returns `Ok(())`.  On failure returns
/// [`PolicyError::OwnerSignatureInvalid`] with the `profile` name supplied by
/// the caller and an empty `rules_with_signed_optional_keys`.  The caller
/// (typically [`crate::policy::v1::loader::load_signed_policy`]) provides
/// `profile` so this function does not need to know the profile name itself,
/// and fills the rule indexes from the document it holds.
///
/// # Errors
///
/// Returns [`PolicyError::OwnerSignatureInvalid`] when:
///
/// - `owner_pubkey` is not a valid compressed ed25519 point.
/// - The signature does not verify against `digest` and `owner_pubkey`.
///
/// # Examples
///
/// ```
/// use ed25519_dalek::{SigningKey, Signer};
/// use rand_core::OsRng;
/// use stellar_agent_core::policy::v1::signature::{digest, verify};
///
/// let signing_key = SigningKey::generate(&mut OsRng);
/// let pubkey_bytes = signing_key.verifying_key().to_bytes();
///
/// let canonical = b"version = 1\nscope = \"profile:default\"\n";
/// let d = digest(canonical);
/// let sig_bytes: [u8; 64] = signing_key.sign(&d).to_bytes();
///
/// verify(&d, &sig_bytes, &pubkey_bytes, "alice").unwrap();
/// ```
pub fn verify(
    digest: &[u8; 32],
    signature: &[u8; 64],
    owner_pubkey: &[u8; 32],
    profile: &str,
) -> Result<(), PolicyError> {
    let key =
        VerifyingKey::from_bytes(owner_pubkey).map_err(|_| PolicyError::OwnerSignatureInvalid {
            profile: profile.to_owned(),
            rules_with_signed_optional_keys: Vec::new(),
        })?;

    let sig = Signature::from_bytes(signature);

    // `verify_strict` requires that the signature passes the cofactor check
    // and rejects the small-subgroup edge cases that `verify` accepts for
    // batch-verification compatibility.  This is the correct choice for a
    // single-signature path.
    key.verify_strict(digest, &sig)
        .map_err(|_| PolicyError::OwnerSignatureInvalid {
            profile: profile.to_owned(),
            rules_with_signed_optional_keys: Vec::new(),
        })
}

/// Produces an ed25519 signature over `digest` using `signing_key`.
///
/// This is the exact inverse of [`verify`]: for any `digest` and `signing_key`,
///
/// ```text
/// verify(digest, &sign(digest, signing_key), &signing_key.verifying_key().to_bytes(), p)
/// ```
///
/// returns `Ok(())` for every profile name `p`.
///
/// The `digest` MUST be the output of [`digest`] over the
/// [`super::canonical::canonical_bytes`] of the policy document (the
/// `[signature]` table excluded).  Signing any other pre-image produces a
/// signature the loader will reject.
///
/// The returned bytes are the raw 64-byte ed25519 signature.  Callers writing
/// the on-disk `[signature]` table hex-encode them; the loader hex-decodes and
/// passes them straight to [`verify`].
///
/// # Examples
///
/// ```
/// use ed25519_dalek::SigningKey;
/// use rand_core::OsRng;
/// use stellar_agent_core::policy::v1::signature::{digest, sign, verify};
///
/// let signing_key = SigningKey::generate(&mut OsRng);
/// let pubkey = signing_key.verifying_key().to_bytes();
///
/// let d = digest(b"version = 1\nscope = \"profile:default\"\n");
/// let sig = sign(&d, &signing_key);
///
/// verify(&d, &sig, &pubkey, "alice").unwrap();
/// ```
#[must_use]
pub fn sign(digest: &[u8; 32], signing_key: &SigningKey) -> [u8; 64] {
    // `ed25519_dalek::SigningKey::sign` is deterministic (RFC 8032 §5.1.6):
    // the nonce is derived from the key and message, so signing the same
    // digest with the same key always yields the same 64 bytes.  This matches
    // `verify_strict` on the read side — no domain separation or pre-hashing
    // is applied here because none is applied there.
    signing_key.sign(digest).to_bytes()
}

/// Builds the digest authorized by the previous owner.
///
/// The message is `stellar-agent-owner-rotation-v1`, followed by the previous
/// and new public keys, then BLAKE3 of the canonical body without either
/// signature table. Each key and digest occupies exactly 32 bytes.
///
/// # Errors
/// Refuses a body that cannot be canonicalized.
pub fn owner_rotation_digest(
    raw: &str,
    previous_owner: &[u8; 32],
    new_owner: &[u8; 32],
) -> Result<[u8; 32], PolicyError> {
    let body = super::canonical::owner_rotation_bytes(raw)?;
    let mut message = b"stellar-agent-owner-rotation-v1".to_vec();
    message.extend_from_slice(previous_owner);
    message.extend_from_slice(new_owner);
    message.extend_from_slice(&digest(&body));
    Ok(digest(&message))
}

/// Builds an `[owner_rotation]` table signed by the previous owner.
///
/// The new owner's policy signature must cover the returned table too.
///
/// # Errors
/// Refuses a body that cannot be canonicalized.
pub fn build_owner_rotation(
    raw: &str,
    previous_key: &SigningKey,
    new_owner: &[u8; 32],
) -> Result<toml_edit::Table, PolicyError> {
    let previous_owner = previous_key.verifying_key().to_bytes();
    let digest = owner_rotation_digest(raw, &previous_owner, new_owner)?;
    let mut table = toml_edit::Table::new();
    table["previous_owner"] = toml_edit::value(
        stellar_strkey::ed25519::PublicKey(previous_owner)
            .to_string()
            .to_string(),
    );
    table["new_owner"] = toml_edit::value(
        stellar_strkey::ed25519::PublicKey(*new_owner)
            .to_string()
            .to_string(),
    );
    table["sig"] = toml_edit::value(crate::hex::encode(&previous_key.sign(&digest).to_bytes()));
    Ok(table)
}

/// The fields of a well-formed `[owner_rotation]` table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwnerRotation {
    /// The owner the statement hands the policy over from.
    pub previous_owner: [u8; 32],
    /// The owner the statement authorizes.
    pub new_owner: [u8; 32],
    /// The previous owner's signature over [`owner_rotation_digest`].
    pub sig: [u8; 64],
}

/// Parses the `[owner_rotation]` table of `doc`; `None` when it is absent.
///
/// The table holds exactly `previous_owner` and `new_owner`, each a G-strkey
/// string, and `sig`, a string of 128 hex characters.
///
/// # Errors
/// Returns [`PolicyError::PolicyFileParseFailed`] naming the defect: a value
/// that is not a table, a missing or unknown key, a value that is not a
/// string, a key that is not a G-strkey, or a `sig` that is not 64 bytes of
/// hex.
pub fn parse_owner_rotation(
    doc: &toml_edit::DocumentMut,
) -> Result<Option<OwnerRotation>, PolicyError> {
    let malformed = |detail: String| PolicyError::PolicyFileParseFailed { detail };
    let Some(item) = doc.get("owner_rotation") else {
        return Ok(None);
    };
    let table = item
        .as_table_like()
        .ok_or_else(|| malformed("`owner_rotation` must be a table".into()))?;
    let keys = super::schema::OWNER_ROTATION_KEYS;
    if let Some((key, _)) = table.iter().find(|(key, _)| !keys.contains(key)) {
        return Err(malformed(format!(
            "owner_rotation: unknown key `{}`; the owner rotation table accepts {}",
            key.escape_debug(),
            keys.join(", ")
        )));
    }
    let text = |key: &str| {
        table
            .get(key)
            .ok_or_else(|| malformed(format!("`[owner_rotation].{key}` is missing")))?
            .as_str()
            .ok_or_else(|| malformed(format!("`[owner_rotation].{key}` must be a string")))
    };
    let owner = |key: &str| {
        stellar_strkey::ed25519::PublicKey::from_string(text(key)?)
            .map(|key| key.0)
            .map_err(|_| malformed(format!("`[owner_rotation].{key}` must be a G-strkey")))
    };
    let previous_owner = owner("previous_owner")?;
    let new_owner = owner("new_owner")?;
    let sig = decode_signature_hex(text("sig")?)
        .ok_or_else(|| malformed("`[owner_rotation].sig` must be 128 hex characters".into()))?;
    Ok(Some(OwnerRotation {
        previous_owner,
        new_owner,
        sig,
    }))
}

/// Decodes exactly 64 bytes of hex digits, either case. Signs, whitespace and
/// non-ASCII text are refused.
fn decode_signature_hex(hex: &str) -> Option<[u8; 64]> {
    if hex.len() != 128 || !hex.is_ascii() {
        return None;
    }
    let (first, second) = hex.split_at(64);
    let mut out = [0_u8; 64];
    out[..32].copy_from_slice(&crate::hex::decode_hex32(first).ok()?);
    out[32..].copy_from_slice(&crate::hex::decode_hex32(second).ok()?);
    Some(out)
}

/// Verifies a rotation statement against the pinned and verifying owners.
///
/// # Errors
/// Returns `OwnerRotationRequired` for an absent statement,
/// `PolicyFileParseFailed` for a malformed table, and `OwnerRotationInvalid`
/// for a statement that names other owners or whose signature does not
/// authorize this policy body.
pub fn verify_owner_rotation(
    raw: &str,
    previous_owner: &[u8; 32],
    new_owner: &[u8; 32],
) -> Result<(), PolicyError> {
    let invalid = || PolicyError::OwnerRotationInvalid;
    let doc =
        raw.parse::<toml_edit::DocumentMut>()
            .map_err(|e| PolicyError::PolicyFileParseFailed {
                detail: e.to_string(),
            })?;
    let rotation = parse_owner_rotation(&doc)?.ok_or(PolicyError::OwnerRotationRequired)?;
    if rotation.previous_owner != *previous_owner || rotation.new_owner != *new_owner {
        return Err(invalid());
    }
    let digest = owner_rotation_digest(raw, previous_owner, new_owner)?;
    let key = VerifyingKey::from_bytes(previous_owner).map_err(|_| invalid())?;
    key.verify_strict(&digest, &Signature::from_bytes(&rotation.sig))
        .map_err(|_| invalid())
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use ed25519_dalek::Signer;
    use rand_core::OsRng;

    use super::*;

    fn make_keypair() -> (ed25519_dalek::SigningKey, [u8; 32]) {
        let sk = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let pk = sk.verifying_key().to_bytes();
        (sk, pk)
    }

    const CANONICAL: &[u8] = b"version = 1\nscope = \"profile:default\"\n";

    // ── digest_deterministic ─────────────────────────────────────────────────

    #[test]
    fn digest_deterministic() {
        let d1 = digest(CANONICAL);
        let d2 = digest(CANONICAL);
        assert_eq!(d1, d2, "digest must be deterministic for the same input");
    }

    #[test]
    fn digest_different_inputs_produce_different_hashes() {
        let d1 = digest(CANONICAL);
        let d2 = digest(b"version = 2\nscope = \"profile:default\"\n");
        assert_ne!(d1, d2, "different inputs must produce different digests");
    }

    // ── verify_valid_signature ───────────────────────────────────────────────

    #[test]
    fn verify_valid_signature() {
        let (sk, pk) = make_keypair();
        let d = digest(CANONICAL);
        let sig: [u8; 64] = sk.sign(&d).to_bytes();
        verify(&d, &sig, &pk, "alice").expect("valid signature must verify successfully");
    }

    // ── verify_wrong_key_rejected ────────────────────────────────────────────

    #[test]
    fn verify_wrong_key_rejected() {
        let (sk, _pk) = make_keypair();
        let (_sk2, pk2) = make_keypair();

        let d = digest(CANONICAL);
        let sig: [u8; 64] = sk.sign(&d).to_bytes();

        let err = verify(&d, &sig, &pk2, "alice").unwrap_err();
        assert!(
            matches!(
                err,
                PolicyError::OwnerSignatureInvalid { ref profile, .. } if profile == "alice"
            ),
            "wrong key must produce OwnerSignatureInvalid for the correct profile, got: {err:?}"
        );
    }

    // ── verify_corrupted_sig_rejected ────────────────────────────────────────

    #[test]
    fn verify_corrupted_sig_rejected() {
        let (sk, pk) = make_keypair();
        let d = digest(CANONICAL);
        let mut sig: [u8; 64] = sk.sign(&d).to_bytes();

        // Flip a bit in the signature.
        sig[0] ^= 0x01;

        let err = verify(&d, &sig, &pk, "bob").unwrap_err();
        assert!(
            matches!(
                err,
                PolicyError::OwnerSignatureInvalid { ref profile, .. } if profile == "bob"
            ),
            "corrupted signature must produce OwnerSignatureInvalid, got: {err:?}"
        );
    }

    // ── verify_invalid_pubkey_rejected ───────────────────────────────────────

    #[test]
    fn verify_invalid_pubkey_rejected() {
        let (sk, _) = make_keypair();
        let d = digest(CANONICAL);
        let sig: [u8; 64] = sk.sign(&d).to_bytes();

        // All-zeros is not a valid compressed ed25519 point.
        let invalid_pk = [0u8; 32];
        let result = verify(&d, &sig, &invalid_pk, "charlie");
        // Some all-zero points are accepted as valid group elements by dalek;
        // the sig will still fail to verify since the key doesn't match.
        // Either way the result must not be Ok(()).
        if result.is_ok() {
            panic!("verification with wrong key (all-zeros) must not succeed");
        }
    }

    // ── verify_wrong_digest_rejected ─────────────────────────────────────────

    #[test]
    fn verify_wrong_digest_rejected() {
        let (sk, pk) = make_keypair();
        let d = digest(CANONICAL);
        let sig: [u8; 64] = sk.sign(&d).to_bytes();

        // Verify against a different digest.
        let mut wrong_digest = d;
        wrong_digest[0] ^= 0x01;

        let err = verify(&wrong_digest, &sig, &pk, "dave").unwrap_err();
        assert!(
            matches!(err, PolicyError::OwnerSignatureInvalid { .. }),
            "wrong digest must produce OwnerSignatureInvalid, got: {err:?}"
        );
    }

    // ── sign is the exact inverse of verify ───────────────────────────────────

    #[test]
    fn sign_then_verify_round_trip() {
        let (sk, pk) = make_keypair();
        let d = digest(CANONICAL);
        let sig = sign(&d, &sk);
        verify(&d, &sig, &pk, "alice").expect("sign output must verify under the matching key");
    }

    #[test]
    fn sign_matches_dalek_signer_trait() {
        // The free `sign` must produce byte-identical output to the trait method
        // the loader's read side implicitly relies on via `verify_strict`.
        let (sk, _pk) = make_keypair();
        let d = digest(CANONICAL);
        let via_fn = sign(&d, &sk);
        let via_trait: [u8; 64] = sk.sign(&d).to_bytes();
        assert_eq!(
            via_fn, via_trait,
            "sign must equal the raw ed25519 signature over the digest"
        );
    }

    #[test]
    fn sign_is_deterministic() {
        // RFC 8032 ed25519 is deterministic: same key + same digest → same sig.
        let (sk, _pk) = make_keypair();
        let d = digest(CANONICAL);
        assert_eq!(
            sign(&d, &sk),
            sign(&d, &sk),
            "signing the same digest with the same key must be deterministic"
        );
    }

    #[test]
    fn sign_wrong_key_is_rejected_by_verify() {
        let (sk, _pk) = make_keypair();
        let (_sk2, pk2) = make_keypair();
        let d = digest(CANONICAL);
        let sig = sign(&d, &sk);
        let err = verify(&d, &sig, &pk2, "alice").unwrap_err();
        assert!(
            matches!(err, PolicyError::OwnerSignatureInvalid { .. }),
            "a signature must not verify under a different owner key, got: {err:?}"
        );
    }

    #[test]
    fn rotation_statement_binds_the_domain_keys_and_body_and_is_signed_by_new_owner() {
        let old = SigningKey::from_bytes(&[51; 32]);
        let new = SigningKey::from_bytes(&[52; 32]);
        let raw = "version = 2\nscope = \"profile:operator\"\nsequence = 2\n";
        let old_public = old.verifying_key().to_bytes();
        let new_public = new.verifying_key().to_bytes();
        let table = build_owner_rotation(raw, &old, &new_public).unwrap();
        let sig = decode_signature_hex(table["sig"].as_str().unwrap()).unwrap();
        let mut message = b"stellar-agent-owner-rotation-v1".to_vec();
        message.extend(old_public);
        message.extend(new_public);
        message.extend(digest(
            &super::super::canonical::canonical_bytes(raw).unwrap(),
        ));
        old.verifying_key()
            .verify_strict(&digest(&message), &Signature::from_bytes(&sig))
            .unwrap();
        let mut doc = raw.parse::<toml_edit::DocumentMut>().unwrap();
        doc["owner_rotation"] = toml_edit::Item::Table(table);
        assert_eq!(
            owner_rotation_digest(&doc.to_string(), &old_public, &new_public).unwrap(),
            digest(&message)
        );
        let outer = digest(&super::super::canonical::canonical_bytes(&doc.to_string()).unwrap());
        let outer_sig = sign(&outer, &new);
        doc["owner_rotation"]["sig"] = toml_edit::value("00".repeat(64));
        let changed = digest(&super::super::canonical::canonical_bytes(&doc.to_string()).unwrap());
        assert!(verify(&changed, &outer_sig, &new_public, "operator").is_err());
    }

    /// Parsing refuses each malformed shape of the table and accepts the
    /// well-formed one.
    #[test]
    fn owner_rotation_parse_refuses_each_malformed_shape() {
        let old = SigningKey::from_bytes(&[51; 32]);
        let new = SigningKey::from_bytes(&[52; 32]);
        let raw = "version = 2\nscope = \"profile:operator\"\nsequence = 2\n";
        let table = build_owner_rotation(raw, &old, &new.verifying_key().to_bytes()).unwrap();
        let mut valid = raw.parse::<toml_edit::DocumentMut>().unwrap();
        valid["owner_rotation"] = toml_edit::Item::Table(table);
        let parsed = parse_owner_rotation(&valid).unwrap().unwrap();
        assert_eq!(parsed.previous_owner, old.verifying_key().to_bytes());
        assert_eq!(parsed.new_owner, new.verifying_key().to_bytes());
        assert_eq!(
            parse_owner_rotation(&raw.parse::<toml_edit::DocumentMut>().unwrap()).unwrap(),
            None
        );
        let upper = valid["owner_rotation"]["sig"]
            .as_str()
            .unwrap()
            .to_ascii_uppercase();
        let mut doc = valid.clone();
        doc["owner_rotation"]["sig"] = toml_edit::value(upper);
        assert_eq!(parse_owner_rotation(&doc).unwrap().unwrap(), parsed);
        for (defect, expected) in [
            ("non_table", "`owner_rotation` must be a table"),
            ("missing", "`[owner_rotation].sig` is missing"),
            ("unknown", "owner_rotation: unknown key `extra`"),
            (
                "non_string",
                "`[owner_rotation].new_owner` must be a string",
            ),
            (
                "strkey",
                "`[owner_rotation].previous_owner` must be a G-strkey",
            ),
            (
                "sig_hex",
                "`[owner_rotation].sig` must be 128 hex characters",
            ),
            (
                "sig_sign",
                "`[owner_rotation].sig` must be 128 hex characters",
            ),
            (
                "sig_non_ascii",
                "`[owner_rotation].sig` must be 128 hex characters",
            ),
            (
                "sig_length",
                "`[owner_rotation].sig` must be 128 hex characters",
            ),
        ] {
            let mut doc = valid.clone();
            match defect {
                "non_table" => doc["owner_rotation"] = toml_edit::value("statement"),
                "missing" => {
                    doc["owner_rotation"].as_table_mut().unwrap().remove("sig");
                }
                "unknown" => doc["owner_rotation"]["extra"] = toml_edit::value("x"),
                "non_string" => doc["owner_rotation"]["new_owner"] = toml_edit::value(5),
                "strkey" => doc["owner_rotation"]["previous_owner"] = toml_edit::value("GABC"),
                "sig_hex" => doc["owner_rotation"]["sig"] = toml_edit::value("zz".repeat(64)),
                "sig_sign" => doc["owner_rotation"]["sig"] = toml_edit::value("+f".repeat(64)),
                "sig_non_ascii" => {
                    doc["owner_rotation"]["sig"] =
                        toml_edit::value(format!("{0}\u{e9}{0}", "0".repeat(63)));
                }
                _ => doc["owner_rotation"]["sig"] = toml_edit::value("00".repeat(63)),
            }
            let error = parse_owner_rotation(&doc).unwrap_err();
            assert!(
                matches!(&error, PolicyError::PolicyFileParseFailed { detail } if detail.starts_with(expected)),
                "{defect}: {error:?}"
            );
        }
    }
}
