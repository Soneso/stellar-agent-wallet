//! The audit binding: which log a persisted profile writes, held in the keyring.
//!
//! A profile's audit log is bound to two things: the lexically normalized path
//! of the log file and the keyring coordinate of its audit chain-root key. The
//! tip anchor of [`super::tip_anchor`] derives its own coordinate from both, so
//! a profile whose `audit_log_path` or `audit_log_hash_chain_key_id` changes
//! has an anchor coordinate with nothing stored at it. The binding records the
//! pair the profile last wrote under, at
//! [`KeyringEntryRef::default_audit_binding`], and a keyed writer refuses a
//! profile whose pair differs from the record.
//!
//! This module is pure: it builds, renders, parses, and compares bindings. The
//! keyring store that holds them lives in `stellar-agent-network`.
//!
//! # Wire form
//!
//! ```text
//! {"version":1,"log_path_sha256":"<64 lowercase hex>","audit_key":{"service":"...","account":"..."}}
//! ```
//!
//! Parsing is strict: the version is exactly 1, the digest is 64 lowercase hex
//! characters, and no other key is accepted at either level.
//!
//! # Scope
//!
//! The binding lives in the keyring, outside the log file. Anyone who can
//! restore the keyring's own storage together with the log can restore an
//! older state. With a headless keyring backend these entries are kept in a
//! file on the same host. Anyone who can write that file can restore older
//! entries or delete one, which needs no key material. A deleted binding is
//! recorded again from the profile file at the next keyed use.

use serde::{Deserialize, Serialize};

use crate::profile::schema::{KeyringEntryRef, Profile};

use super::tip_anchor::log_path_sha256;

/// The only wire version this module writes and accepts.
const BINDING_WIRE_VERSION: u32 = 1;

/// The log a profile writes, as the keyring records it.
///
/// Two bindings are equal when the path digests and the audit-key coordinates
/// are equal.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AuditBinding {
    /// SHA-256 of the lexically normalized `audit_log_path`, the digest the tip
    /// anchor's keyring account derives from.
    pub log_path_sha256: [u8; 32],
    /// The profile's audit chain-root key coordinate.
    pub audit_key: KeyringEntryRef,
}

/// Whether a keyed writer may record an absent binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingCheck {
    /// For a persisted profile: an absent binding is recorded from the profile,
    /// an equal one continues, and any other refuses.
    Enforce,
    /// For a synthesized profile: an absent binding continues without being
    /// recorded, an equal one continues, and any other refuses.
    CheckOnly,
}

/// A stored binding that is not a well-formed version 1 record.
///
/// Carries no part of the stored value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AuditBindingParseError {
    /// The value is not the JSON object of the wire form.
    #[error("audit binding: the record is not a version 1 binding object")]
    Malformed,
    /// The record carries a version other than 1.
    #[error("audit binding: the record version is not 1")]
    Version,
    /// The path digest is not 64 lowercase hex characters.
    #[error("audit binding: the path digest is not 64 lowercase hex characters")]
    PathDigest,
}

/// How a stored record compares with the profile's binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordedBinding {
    /// Nothing is recorded.
    Absent,
    /// The record equals the profile's binding.
    Equal,
    /// The record parses and differs from the profile's binding.
    Changed(AuditBinding),
    /// The record does not parse.
    Unparseable,
}

impl RecordedBinding {
    /// Compares a raw stored record with `expected`.
    #[must_use]
    pub fn classify(raw: Option<&str>, expected: &AuditBinding) -> Self {
        match raw {
            None => Self::Absent,
            Some(raw) => match AuditBinding::parse(raw) {
                Ok(recorded) if &recorded == expected => Self::Equal,
                Ok(recorded) => Self::Changed(recorded),
                Err(_) => Self::Unparseable,
            },
        }
    }

    /// Whether a keyed writer refuses this record.
    #[must_use]
    pub fn refuses(&self) -> bool {
        matches!(self, Self::Changed(_) | Self::Unparseable)
    }

    /// The wire label an operator-facing report uses for this record.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::Equal => "equal",
            Self::Changed(_) => "changed",
            Self::Unparseable => "unreadable",
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireAuditKey {
    service: String,
    account: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireBinding {
    version: u32,
    log_path_sha256: String,
    audit_key: WireAuditKey,
}

impl AuditBinding {
    /// Builds the binding a profile's log path and audit-key coordinate imply.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::audit_log::binding::AuditBinding;
    /// use stellar_agent_core::profile::schema::Profile;
    ///
    /// let profile = Profile::builder_testnet_named("alice", "s", "a", "n", "a").build();
    /// let binding = AuditBinding::for_profile(&profile);
    /// assert_eq!(binding.audit_key, profile.audit_log_hash_chain_key_id);
    /// let parsed = AuditBinding::parse(&binding.to_keyring_value()).unwrap();
    /// assert_eq!(parsed, binding);
    /// ```
    #[must_use]
    pub fn for_profile(profile: &Profile) -> Self {
        Self {
            log_path_sha256: log_path_sha256(&profile.audit_log_path),
            audit_key: profile.audit_log_hash_chain_key_id.clone(),
        }
    }

    /// Renders the keyring value of the wire form.
    #[must_use]
    pub fn to_keyring_value(&self) -> String {
        let wire = WireBinding {
            version: BINDING_WIRE_VERSION,
            log_path_sha256: crate::hex::encode(&self.log_path_sha256),
            audit_key: WireAuditKey {
                service: self.audit_key.service.clone(),
                account: self.audit_key.account.clone(),
            },
        };
        // Serializing a struct of strings and an integer cannot fail.
        serde_json::to_string(&wire).unwrap_or_default()
    }

    /// Parses the keyring value of the wire form, strictly.
    ///
    /// # Errors
    ///
    /// [`AuditBindingParseError`] naming the malformed part, never echoing the
    /// value.
    pub fn parse(value: &str) -> Result<Self, AuditBindingParseError> {
        let wire: WireBinding =
            serde_json::from_str(value).map_err(|_| AuditBindingParseError::Malformed)?;
        if wire.version != BINDING_WIRE_VERSION {
            return Err(AuditBindingParseError::Version);
        }
        if !wire
            .log_path_sha256
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(AuditBindingParseError::PathDigest);
        }
        let log_path_sha256 = crate::hex::decode_hex32(&wire.log_path_sha256)
            .map_err(|_| AuditBindingParseError::PathDigest)?;
        Ok(Self {
            log_path_sha256,
            audit_key: KeyringEntryRef::new(wire.audit_key.service, wire.audit_key.account),
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, reason = "test-only")]

    use super::*;

    fn profile(path: &str) -> Profile {
        let mut profile = Profile::builder_testnet_named("alice", "s", "a", "n", "a").build();
        profile.audit_log_path = std::path::PathBuf::from(path);
        profile
    }

    #[test]
    fn the_wire_form_is_the_documented_json() {
        let binding = AuditBinding::for_profile(&profile("/var/log/alice.jsonl"));
        let value: serde_json::Value =
            serde_json::from_str(&binding.to_keyring_value()).expect("JSON");
        let digest = crate::hex::encode(&log_path_sha256(std::path::Path::new(
            "/var/log/alice.jsonl",
        )));
        assert_eq!(
            value,
            serde_json::json!({
                "version": 1,
                "log_path_sha256": digest,
                "audit_key": {
                    "service": "stellar-agent-audit-alice",
                    "account": "default"
                }
            })
        );
        assert!(
            binding
                .to_keyring_value()
                .starts_with("{\"version\":1,\"log_path_sha256\":\"")
        );
    }

    #[test]
    fn the_digest_follows_the_lexically_normalized_path() {
        let plain = AuditBinding::for_profile(&profile("/var/log/alice.jsonl"));
        let dotted = AuditBinding::for_profile(&profile("/var/log/./x/../alice.jsonl"));
        let other = AuditBinding::for_profile(&profile("/var/log/bob.jsonl"));
        assert_eq!(plain, dotted);
        assert_ne!(plain, other);
    }

    #[test]
    fn parsing_is_strict() {
        let good = AuditBinding::for_profile(&profile("/a.jsonl")).to_keyring_value();
        assert!(AuditBinding::parse(&good).is_ok());
        let upper = good.replace(
            &crate::hex::encode(&log_path_sha256(std::path::Path::new("/a.jsonl"))),
            &crate::hex::encode(&log_path_sha256(std::path::Path::new("/a.jsonl"))).to_uppercase(),
        );
        for (bad, expected) in [
            (String::new(), AuditBindingParseError::Malformed),
            ("not json".to_owned(), AuditBindingParseError::Malformed),
            (
                good.replace("\"version\":1", "\"version\":2"),
                AuditBindingParseError::Version,
            ),
            (
                good.replace("}}", "},\"extra\":1}"),
                AuditBindingParseError::Malformed,
            ),
            (
                good.replace("\"account\"", "\"extra\":\"x\",\"account\""),
                AuditBindingParseError::Malformed,
            ),
            (upper, AuditBindingParseError::PathDigest),
            (
                good.replace("\"log_path_sha256\":\"", "\"log_path_sha256\":\"0"),
                AuditBindingParseError::PathDigest,
            ),
        ] {
            assert_eq!(AuditBinding::parse(&bad), Err(expected), "{bad}");
        }
    }

    #[test]
    fn classification_covers_every_record() {
        let expected = AuditBinding::for_profile(&profile("/a.jsonl"));
        let other = AuditBinding::for_profile(&profile("/b.jsonl"));
        assert_eq!(
            RecordedBinding::classify(None, &expected),
            RecordedBinding::Absent
        );
        assert_eq!(
            RecordedBinding::classify(Some(&expected.to_keyring_value()), &expected),
            RecordedBinding::Equal
        );
        assert_eq!(
            RecordedBinding::classify(Some(&other.to_keyring_value()), &expected),
            RecordedBinding::Changed(other)
        );
        assert_eq!(
            RecordedBinding::classify(Some("garbage"), &expected),
            RecordedBinding::Unparseable
        );
        let mut rekeyed = profile("/a.jsonl");
        rekeyed.audit_log_hash_chain_key_id = KeyringEntryRef::new("svc", "acct");
        assert!(
            RecordedBinding::classify(
                Some(&AuditBinding::for_profile(&rekeyed).to_keyring_value()),
                &expected
            )
            .refuses()
        );
    }
}
