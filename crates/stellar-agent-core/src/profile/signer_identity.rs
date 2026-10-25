//! Enrolled signer identity rules for loaded profiles, and the identity
//! record enrollment writes beside the seed.
//!
//! # The identity record
//!
//! `profile enroll-signer` writes, after the seed, one strict JSON object at
//! [`super::schema::signer_identity_entry_ref`] (the signer's service, account
//! `enrolled-identity`):
//!
//! ```text
//! {"v":1,"public_key":"G...","role":"agent"}
//! ```
//!
//! It states which public key the profile enrolled and in which role, so a
//! producer of signing authority reads the enrollment without reading the
//! seed. [`SignerIdentityRecord::parse`] refuses any other shape.

use serde::{Deserialize, Serialize};

use super::Profile;
use crate::error::AuthError;

/// The only identity record version this build reads and writes.
pub const SIGNER_IDENTITY_VERSION: u32 = 1;

/// The role an identity record of version 1 names.
pub const SIGNER_IDENTITY_ROLE_AGENT: &str = "agent";

/// The enrolled signer's identity record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerIdentityRecord {
    public_key: [u8; 32],
}

/// Why a stored identity record was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SignerIdentityRecordError {
    /// The value is not the record object.
    #[error("the signer identity record is not the version 1 record object")]
    Malformed,
    /// The record names a version this build does not read.
    #[error("the signer identity record has unsupported version {0}")]
    UnsupportedVersion(u32),
    /// The public key is not a G-strkey.
    #[error("the signer identity record's public key is not a G-strkey")]
    MalformedKey,
    /// The record names a role other than `agent`.
    #[error("the signer identity record names an unsupported role")]
    UnsupportedRole,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignerIdentityWire {
    v: u32,
    public_key: String,
    role: String,
}

impl SignerIdentityRecord {
    /// The record of an agent signer whose public key is `public_key`.
    #[must_use]
    pub fn agent(public_key: [u8; 32]) -> Self {
        Self { public_key }
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

    /// The record's stored form.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::profile::signer_identity::SignerIdentityRecord;
    ///
    /// let record = SignerIdentityRecord::agent([0; 32]);
    /// assert_eq!(
    ///     record.render(),
    ///     concat!(
    ///         "{\"v\":1,\"public_key\":\"",
    ///         "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
    ///         "\",\"role\":\"agent\"}"
    ///     )
    /// );
    /// assert_eq!(SignerIdentityRecord::parse(&record.render()), Ok(record));
    /// ```
    #[must_use]
    pub fn render(&self) -> String {
        let wire = SignerIdentityWire {
            v: SIGNER_IDENTITY_VERSION,
            public_key: self.public_key_strkey(),
            role: SIGNER_IDENTITY_ROLE_AGENT.to_owned(),
        };
        // Three plain strings and an integer always serialize.
        serde_json::to_string(&wire).unwrap_or_default()
    }

    /// Parses a stored record, refusing every other shape.
    ///
    /// # Errors
    ///
    /// The [`SignerIdentityRecordError`] naming the first rule the value
    /// breaks.
    pub fn parse(raw: &str) -> Result<Self, SignerIdentityRecordError> {
        let wire: SignerIdentityWire =
            serde_json::from_str(raw.trim()).map_err(|_| SignerIdentityRecordError::Malformed)?;
        if wire.v != SIGNER_IDENTITY_VERSION {
            return Err(SignerIdentityRecordError::UnsupportedVersion(wire.v));
        }
        let public_key = stellar_strkey::ed25519::PublicKey::from_string(&wire.public_key)
            .map_err(|_| SignerIdentityRecordError::MalformedKey)?
            .0;
        if wire.role != SIGNER_IDENTITY_ROLE_AGENT {
            return Err(SignerIdentityRecordError::UnsupportedRole);
        }
        Ok(Self { public_key })
    }
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
    use super::*;

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
        let record = SignerIdentityRecord::agent([1; 32]);
        assert_eq!(
            SignerIdentityRecord::parse(&record.render()),
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
                format!("{{\"v\":2,\"public_key\":\"{g}\",\"role\":\"agent\"}}"),
                SignerIdentityRecordError::UnsupportedVersion(2),
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
