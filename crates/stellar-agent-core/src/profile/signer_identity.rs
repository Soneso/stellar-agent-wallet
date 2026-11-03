//! The identity record beside an enrolled signer seed.
//!
//! The strict v2 JSON form is
//! `{"v":2,"public_key":"G...","role":"agent","profile":"name","chain":"stellar:mainnet"}`,
//! with `owner` (a G-strkey) and `owner_sig` (64 bytes, base64url without padding)
//! once the owner signs the binding. A bound record names exactly one profile,
//! chain and owner. Its signature also covers the seed coordinate. Version 1
//! records parse as unbound identities.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::{Profile, caip2::Caip2, schema::KeyringEntryRef};
use crate::error::AuthError;

/// The identity record version this build writes.
pub const SIGNER_IDENTITY_VERSION: u32 = 2;
/// The identity record's supported signing role.
pub const SIGNER_IDENTITY_ROLE_AGENT: &str = "agent";

/// The profile and optional owner served by the enrolled signer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerBinding {
    /// The exact profile name.
    pub profile: String,
    /// The profile's chain.
    pub chain: Caip2,
    /// The owner public key and its signature of the binding digest.
    pub owner: Option<([u8; 32], [u8; 64])>,
}

/// The enrolled signer's identity record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerIdentityRecord {
    public_key: [u8; 32],
    /// The binding, absent only for a version 1 record.
    pub binding: Option<SignerBinding>,
}

/// Why a stored identity record is refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SignerIdentityRecordError {
    /// The value is not the record object.
    #[error("the signer identity record is not a supported record object")]
    Malformed,
    /// The record names a version this build does not read.
    #[error("the signer identity record has unsupported version {0}")]
    UnsupportedVersion(u32),
    /// A public key is not a G-strkey.
    #[error("the signer identity record's public key is not a G-strkey")]
    MalformedKey,
    /// The record names a role other than `agent`.
    #[error("the signer identity record names an unsupported role")]
    UnsupportedRole,
    /// Only one of the owner and its signature is present.
    #[error("the signer identity record needs both owner and owner_sig")]
    IncompleteOwner,
    /// The owner signature does not verify.
    #[error("the signer identity owner signature is invalid")]
    OwnerSignatureInvalid,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignerIdentityWire {
    v: u32,
    public_key: String,
    role: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    profile: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    chain: Option<Caip2>,
    #[serde(skip_serializing_if = "Option::is_none")]
    owner: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    owner_sig: Option<String>,
}

impl SignerIdentityRecord {
    /// An owner-free v2 agent identity for exactly this profile and chain.
    #[must_use]
    pub fn agent(public_key: [u8; 32], profile: impl Into<String>, chain: Caip2) -> Self {
        Self {
            public_key,
            binding: Some(SignerBinding {
                profile: profile.into(),
                chain,
                owner: None,
            }),
        }
    }

    /// The enrolled public key.
    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        self.public_key
    }

    /// The enrolled public key as a G-strkey.
    #[must_use]
    pub fn public_key_strkey(&self) -> String {
        stellar_strkey::ed25519::PublicKey(self.public_key)
            .to_string()
            .to_string()
    }

    /// The v2 stored form. Rendering never adopts a profile, so an unbound
    /// record has no stored form.
    ///
    /// # Errors
    /// Returns [`SignerIdentityRecordError::Malformed`] for a record without a
    /// binding.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::profile::{caip2::Caip2, signer_identity::SignerIdentityRecord};
    /// let record = SignerIdentityRecord::agent([0; 32], "v", Caip2::Mainnet);
    /// let rendered = record.render().unwrap();
    /// assert_eq!(rendered, concat!(
    ///     "{\"v\":2,\"public_key\":\"GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
    ///     "\",\"role\":\"agent\",\"profile\":\"v\",\"chain\":\"stellar:mainnet\"}"
    /// ));
    /// assert_eq!(SignerIdentityRecord::parse(&rendered), Ok(record));
    /// ```
    pub fn render(&self) -> Result<String, SignerIdentityRecordError> {
        let binding = self
            .binding
            .as_ref()
            .ok_or(SignerIdentityRecordError::Malformed)?;
        let wire = SignerIdentityWire {
            v: SIGNER_IDENTITY_VERSION,
            public_key: self.public_key_strkey(),
            role: SIGNER_IDENTITY_ROLE_AGENT.to_owned(),
            profile: Some(binding.profile.clone()),
            chain: Some(binding.chain),
            owner: binding.owner.map(|(key, _)| {
                stellar_strkey::ed25519::PublicKey(key)
                    .to_string()
                    .to_string()
            }),
            owner_sig: binding
                .owner
                .map(|(_, signature)| URL_SAFE_NO_PAD.encode(signature)),
        };
        serde_json::to_string(&wire).map_err(|_| SignerIdentityRecordError::Malformed)
    }

    /// Binds the record to `owner` and signs its binding digest over
    /// `seed_ref` with that key.
    ///
    /// # Errors
    /// Returns [`SignerIdentityRecordError::Malformed`] for a record without a
    /// binding: an owner signs a named profile and chain, never an unbound
    /// identity.
    pub fn bind_owner(
        &mut self,
        owner: &ed25519_dalek::SigningKey,
        seed_ref: &KeyringEntryRef,
    ) -> Result<(), SignerIdentityRecordError> {
        let binding = self
            .binding
            .take()
            .ok_or(SignerIdentityRecordError::Malformed)?;
        self.binding = Some(owner_signed(
            binding,
            &self.public_key_strkey(),
            owner,
            seed_ref,
        ));
        Ok(())
    }

    /// Parses a strict v1 or v2 record.
    ///
    /// # Errors
    /// Returns the first malformed or unsupported field.
    pub fn parse(raw: &str) -> Result<Self, SignerIdentityRecordError> {
        use SignerIdentityRecordError as Error;
        let wire: SignerIdentityWire =
            serde_json::from_str(raw.trim()).map_err(|_| Error::Malformed)?;
        if wire.v != 1 && wire.v != SIGNER_IDENTITY_VERSION {
            return Err(Error::UnsupportedVersion(wire.v));
        }
        let object: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(raw.trim()).map_err(|_| Error::Malformed)?;
        if (wire.v == 1 && object.len() != 3) || object.values().any(serde_json::Value::is_null) {
            return Err(Error::Malformed);
        }
        let public_key = stellar_strkey::ed25519::PublicKey::from_string(&wire.public_key)
            .map_err(|_| Error::MalformedKey)?
            .0;
        if wire.role != SIGNER_IDENTITY_ROLE_AGENT {
            return Err(Error::UnsupportedRole);
        }
        let binding = if wire.v == 1 {
            None
        } else {
            let owner = match (wire.owner, wire.owner_sig) {
                (None, None) => None,
                (Some(key), Some(sig)) => Some((
                    stellar_strkey::ed25519::PublicKey::from_string(&key)
                        .map_err(|_| Error::MalformedKey)?
                        .0,
                    URL_SAFE_NO_PAD
                        .decode(sig)
                        .map_err(|_| Error::OwnerSignatureInvalid)?
                        .try_into()
                        .map_err(|_| Error::OwnerSignatureInvalid)?,
                )),
                _ => return Err(Error::IncompleteOwner),
            };
            Some(SignerBinding {
                profile: wire.profile.ok_or(Error::Malformed)?,
                chain: wire.chain.ok_or(Error::Malformed)?,
                owner,
            })
        };
        Ok(Self {
            public_key,
            binding,
        })
    }

    /// SHA-256 over the domain and seven length-prefixed UTF-8 fields: key,
    /// role, profile, chain, owner, seed service, and seed account. Absent
    /// binding fields use empty strings.
    #[must_use]
    pub fn binding_digest(&self, seed_ref: &KeyringEntryRef) -> [u8; 32] {
        binding_digest_of(&self.public_key_strkey(), self.binding.as_ref(), seed_ref)
    }

    /// Verifies the owner's signature against this record and seed coordinate.
    ///
    /// # Errors
    /// Refuses an absent owner or an invalid Ed25519 signature.
    pub fn verify_owner_signature(
        &self,
        seed_ref: &KeyringEntryRef,
    ) -> Result<(), SignerIdentityRecordError> {
        let (owner, signature) = self
            .binding
            .as_ref()
            .and_then(|b| b.owner)
            .ok_or(SignerIdentityRecordError::IncompleteOwner)?;
        ed25519_dalek::VerifyingKey::from_bytes(&owner)
            .and_then(|key| {
                key.verify_strict(
                    &self.binding_digest(seed_ref),
                    &ed25519_dalek::Signature::from_bytes(&signature),
                )
            })
            .map_err(|_| SignerIdentityRecordError::OwnerSignatureInvalid)
    }

    /// Creates an owner-signed record for an offline fixture.
    #[cfg(any(test, feature = "test-helpers"))]
    #[must_use]
    pub fn signed_for_test(
        public_key: [u8; 32],
        name: &str,
        profile: &Profile,
        owner: &ed25519_dalek::SigningKey,
    ) -> Self {
        let public_key_strkey = stellar_strkey::ed25519::PublicKey(public_key)
            .to_string()
            .to_string();
        Self {
            public_key,
            binding: Some(owner_signed(
                SignerBinding {
                    profile: name.to_owned(),
                    chain: profile.chain_id,
                    owner: None,
                },
                &public_key_strkey,
                owner,
                &profile.mcp_signer_default,
            )),
        }
    }
}

/// `binding` with `owner` as its owner and the owner's signature of the
/// binding digest. The digest covers the owner key but not the signature.
fn owner_signed(
    mut binding: SignerBinding,
    public_key: &str,
    owner: &ed25519_dalek::SigningKey,
    seed_ref: &KeyringEntryRef,
) -> SignerBinding {
    use ed25519_dalek::Signer as _;
    let owner_key = owner.verifying_key().to_bytes();
    binding.owner = Some((owner_key, [0; 64]));
    let digest = binding_digest_of(public_key, Some(&binding), seed_ref);
    binding.owner = Some((owner_key, owner.sign(&digest).to_bytes()));
    binding
}

fn binding_digest_of(
    public_key: &str,
    binding: Option<&SignerBinding>,
    seed_ref: &KeyringEntryRef,
) -> [u8; 32] {
    let owner = binding
        .and_then(|b| b.owner)
        .map(|(key, _)| {
            stellar_strkey::ed25519::PublicKey(key)
                .to_string()
                .to_string()
        })
        .unwrap_or_default();
    binding_digest_fields(&[
        public_key,
        SIGNER_IDENTITY_ROLE_AGENT,
        binding.map_or("", |b| b.profile.as_str()),
        binding.map_or("", |b| b.chain.caip2_str()),
        &owner,
        &seed_ref.service,
        &seed_ref.account,
    ])
}

fn binding_digest_fields(fields: &[&str; 7]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"stellar-agent-signer-binding:v2");
    for field in fields {
        digest.update((field.len() as u32).to_be_bytes());
        digest.update(field.as_bytes());
    }
    digest.finalize().into()
}

/// The validated enrolled signer pin of a mainnet profile; `None` on testnet.
///
/// # Errors
/// Refuses a placeholder or malformed mainnet signer pin.
pub fn enrolled_signer_pin(
    profile_name: &str,
    profile: &Profile,
) -> Result<Option<String>, AuthError> {
    if !profile.chain_id.is_mainnet() {
        return Ok(None);
    }
    let account = &profile.mcp_signer_default.account;
    let reason = if profile.mcp_signer_default.is_signer_placeholder() {
        Some("placeholder")
    } else if stellar_strkey::ed25519::PublicKey::from_string(account).is_err() {
        Some("malformed")
    } else {
        None
    };
    if let Some(reason) = reason {
        return Err(AuthError::EnrolledSignerUnpinned {
            profile: profile_name.to_owned(),
            reason,
        });
    }
    Ok(Some(account.clone()))
}

/// Refuses a signer that is not the profile's enrolled identity on mainnet.
///
/// # Errors
/// Refuses an invalid pin or a derived key that differs from the pin.
pub fn check_enrolled_signer(
    profile_name: &str,
    profile: &Profile,
    derived_g: &str,
) -> Result<(), AuthError> {
    if let Some(enrolled) = enrolled_signer_pin(profile_name, profile)?
        && derived_g != enrolled
    {
        return Err(AuthError::EnrolledSignerMismatch {
            profile: profile_name.to_owned(),
            enrolled,
            derived: derived_g.to_owned(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test fixtures fail loudly")]
    use super::*;

    #[test]
    fn a_bound_record_round_trips() {
        let profile = profile(&key(1));
        let owner = ed25519_dalek::SigningKey::from_bytes(&[11; 32]);
        let record = SignerIdentityRecord::signed_for_test([1; 32], "identity", &profile, &owner);
        assert!(record.render().unwrap().contains("\"v\":2"));
        assert_eq!(
            SignerIdentityRecord::parse(&record.render().unwrap()),
            Ok(record.clone())
        );
        assert!(
            record
                .verify_owner_signature(&profile.mcp_signer_default)
                .is_ok()
        );
    }

    #[test]
    fn a_v1_record_parses_as_unbound() {
        let raw = format!(r#"{{"v":1,"public_key":"{}","role":"agent"}}"#, key(1));
        let record = SignerIdentityRecord::parse(&raw).unwrap();
        assert_eq!(record.binding, None);
        assert_eq!(record.public_key(), [1; 32]);
    }

    #[test]
    fn an_unbound_record_has_no_stored_form() {
        let raw = format!(r#"{{"v":1,"public_key":"{}","role":"agent"}}"#, key(1));
        let mut record = SignerIdentityRecord::parse(&raw).unwrap();
        assert_eq!(record.render(), Err(SignerIdentityRecordError::Malformed));
        let owner = ed25519_dalek::SigningKey::from_bytes(&[11; 32]);
        let seed = KeyringEntryRef::new("stellar-agent-signer-v", key(1));
        assert_eq!(
            record.bind_owner(&owner, &seed),
            Err(SignerIdentityRecordError::Malformed)
        );
        assert_eq!(record.binding, None);
    }

    #[test]
    fn binding_an_owner_signs_the_named_binding() {
        let owner = ed25519_dalek::SigningKey::from_bytes(&[11; 32]);
        let seed = KeyringEntryRef::new("stellar-agent-signer-v", key(1));
        let mut record = SignerIdentityRecord::agent([1; 32], "v", Caip2::Mainnet);
        record.bind_owner(&owner, &seed).unwrap();
        let binding = record.binding.as_ref().unwrap();
        assert_eq!(binding.profile, "v");
        assert_eq!(
            binding.owner.map(|(key, _)| key),
            Some(owner.verifying_key().to_bytes())
        );
        assert_eq!(record.verify_owner_signature(&seed), Ok(()));
        let mut moved = seed.clone();
        moved.account.push('x');
        assert_eq!(
            record.verify_owner_signature(&moved),
            Err(SignerIdentityRecordError::OwnerSignatureInvalid)
        );
    }

    #[test]
    fn a_half_owner_record_is_refused() {
        let mut raw: serde_json::Value = serde_json::from_str(
            &SignerIdentityRecord::agent([1; 32], "v", Caip2::Mainnet)
                .render()
                .unwrap(),
        )
        .unwrap();
        raw["owner"] = key(2).into();
        assert_eq!(
            SignerIdentityRecord::parse(&raw.to_string()),
            Err(SignerIdentityRecordError::IncompleteOwner)
        );
        raw.as_object_mut().unwrap().remove("owner");
        raw["owner_sig"] = URL_SAFE_NO_PAD.encode([0; 64]).into();
        assert_eq!(
            SignerIdentityRecord::parse(&raw.to_string()),
            Err(SignerIdentityRecordError::IncompleteOwner)
        );
    }

    #[test]
    fn the_binding_digest_covers_every_field() {
        let key = key(0);
        let coordinate = KeyringEntryRef::new("stellar-agent-signer-v", &key);
        let mut record = SignerIdentityRecord::agent([0; 32], "v", Caip2::Mainnet);
        record.binding.as_mut().unwrap().owner = Some(([0; 32], [0; 64]));
        let digest = record.binding_digest(&coordinate);
        assert_eq!(
            crate::hex::encode(&digest),
            "84ac10f017b6c3f164e57f83992b0246a0ba69aeb19722352858a432541c570d"
        );
        let fields = [
            key.as_str(),
            "agent",
            "v",
            "stellar:mainnet",
            key.as_str(),
            "stellar-agent-signer-v",
            key.as_str(),
        ];
        assert_eq!(binding_digest_fields(&fields), digest);
        for index in 0..fields.len() {
            let mut changed = fields;
            changed[index] = "different";
            assert_ne!(binding_digest_fields(&changed), digest, "field {index}");
        }
        let mut changed = record.clone();
        changed.public_key = [1; 32];
        assert_ne!(changed.binding_digest(&coordinate), digest);
        for index in 0..3 {
            let mut changed = record.clone();
            let binding = changed.binding.as_mut().unwrap();
            match index {
                0 => binding.profile.push('x'),
                1 => binding.chain = Caip2::Testnet,
                _ => binding.owner.as_mut().unwrap().0 = [1; 32],
            }
            assert_ne!(changed.binding_digest(&coordinate), digest);
        }
        for index in 0..2 {
            let mut changed = coordinate.clone();
            if index == 0 {
                changed.service.push('x');
            } else {
                changed.account.push('x');
            }
            assert_ne!(record.binding_digest(&changed), digest);
        }
    }

    fn profile(account: &str) -> Profile {
        Profile::builder_mainnet_named(
            "identity",
            "https://rpc.example.invalid",
            "s",
            account,
            "n",
            "a",
        )
        .build()
    }

    fn key(byte: u8) -> String {
        stellar_strkey::ed25519::PublicKey([byte; 32])
            .to_string()
            .to_string()
    }

    #[test]
    fn testnet_placeholder_has_no_pin_and_accepts_any_signer() {
        let p = Profile::builder_testnet_named("identity", "s", "default", "n", "a").build();
        assert!(matches!(enrolled_signer_pin("identity", &p), Ok(None)));
        assert!(check_enrolled_signer("identity", &p, "any key").is_ok());
    }

    #[test]
    fn mainnet_placeholder_refuses() {
        assert!(matches!(
            check_enrolled_signer("identity", &profile("default"), &key(1)),
            Err(AuthError::EnrolledSignerUnpinned {
                reason: "placeholder",
                ..
            })
        ));
    }

    #[test]
    fn mainnet_malformed_refuses() {
        assert!(matches!(
            check_enrolled_signer("identity", &profile("invalid"), &key(1)),
            Err(AuthError::EnrolledSignerUnpinned {
                reason: "malformed",
                ..
            })
        ));
    }

    #[test]
    fn mainnet_differing_key_refuses_with_both_keys() {
        let a = key(1);
        let b = key(2);
        let result = check_enrolled_signer("identity", &profile(&a), &b);
        assert!(
            matches!(&result, Err(AuthError::EnrolledSignerMismatch { enrolled, derived, .. }) if enrolled == &a && derived == &b)
        );
        if let Err(error) = result {
            assert!(error.to_string().contains(&a));
            assert!(error.to_string().contains(&b));
        }
    }

    /// The record round-trips, and each malformed shape refuses with its own
    /// error.
    #[test]
    fn identity_record_parsing_is_strict() {
        let record = SignerIdentityRecord::agent([1; 32], "identity", Caip2::Mainnet);
        assert_eq!(
            SignerIdentityRecord::parse(&record.render().unwrap()),
            Ok(record.clone())
        );
        let g = record.public_key_strkey();
        for (raw, expected) in [
            ("not json".to_owned(), SignerIdentityRecordError::Malformed),
            (
                format!("{{\"v\":1,\"public_key\":\"{g}\",\"role\":\"agent\",\"x\":1}}"),
                SignerIdentityRecordError::Malformed,
            ),
            (
                format!("{{\"v\":3,\"public_key\":\"{g}\",\"role\":\"agent\"}}"),
                SignerIdentityRecordError::UnsupportedVersion(3),
            ),
            (
                "{\"v\":1,\"public_key\":\"GBAD\",\"role\":\"agent\"}".to_owned(),
                SignerIdentityRecordError::MalformedKey,
            ),
            (
                format!("{{\"v\":1,\"public_key\":\"{g}\",\"role\":\"fee_payer\"}}"),
                SignerIdentityRecordError::UnsupportedRole,
            ),
        ] {
            assert_eq!(SignerIdentityRecord::parse(&raw), Err(expected), "{raw}");
        }
    }

    #[test]
    fn mainnet_equal_key_passes() {
        let a = key(1);
        assert!(check_enrolled_signer("identity", &profile(&a), &a).is_ok());
    }
}
