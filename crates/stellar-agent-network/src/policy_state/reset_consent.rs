//! The latest verified owner authorization consumed by a window reset.

use stellar_agent_core::profile::owner_key::owner_key_fingerprint;

use super::WindowStoreError;
use super::store::{ResetRecord, WIRE_VERSION_OPERATIONS, WireFile};

/// One committed reset authorization, with no retained history.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ResetConsentRecord {
    pub(super) request_id: String,
    pub(super) statement_digest: String,
    pub(super) owner_key_fingerprint: String,
    pub(super) consumed_at_ms: u64,
}

/// Consent that passes owner matching and strict signature verification.
pub(super) struct VerifiedResetConsent {
    pub(super) request_id: String,
    pub(super) statement_digest: [u8; 32],
    pub(super) owner: [u8; 32],
}

impl VerifiedResetConsent {
    pub(super) fn new(record: &ResetRecord<'_>, owner: [u8; 32]) -> Self {
        Self {
            request_id: record.request_id.to_owned(),
            statement_digest: record.statement_digest(),
            owner,
        }
    }
}

/// Registration hooks for the reset authorization section.
pub(super) struct ResetConsents;

impl ResetConsents {
    pub(super) fn validate(wire: &WireFile) -> Result<(), WindowStoreError> {
        let Some(record) = &wire.reset_consent else {
            return Ok(());
        };
        let hex = |value: &str, len: usize| {
            value.len() == len
                && value
                    .bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        };
        if wire.version < WIRE_VERSION_OPERATIONS
            || record.request_id.is_empty()
            || record.request_id.len() > 128
            || !record.request_id.bytes().all(|c| c.is_ascii_graphic())
            || !hex(&record.statement_digest, 64)
            || !record
                .owner_key_fingerprint
                .strip_prefix("sha256:")
                .is_some_and(|value| hex(value, 32))
            || record.consumed_at_ms == 0
        {
            return Err(WindowStoreError::Invalid {
                detail: "invalid reset consent record".into(),
            });
        }
        Ok(())
    }

    pub(super) fn on_reset(
        wire: Option<&WireFile>,
        verified: Option<VerifiedResetConsent>,
        now_ms: u64,
    ) -> Result<Option<ResetConsentRecord>, WindowStoreError> {
        let previous = wire.and_then(|wire| wire.reset_consent.as_ref());
        let Some(verified) = verified else {
            return Ok(previous.cloned());
        };
        if previous.is_some_and(|record| record.request_id == verified.request_id) {
            return Err(WindowStoreError::ResetConsentReplayed);
        }
        let record = ResetConsentRecord {
            request_id: verified.request_id,
            statement_digest: stellar_agent_core::hex::encode(&verified.statement_digest),
            owner_key_fingerprint: owner_key_fingerprint(&verified.owner),
            consumed_at_ms: now_ms,
        };
        let wire = WireFile {
            version: WIRE_VERSION_OPERATIONS,
            reset_consent: Some(record),
            ..WireFile::default()
        };
        Self::validate(&wire)?;
        Ok(wire.reset_consent)
    }

    pub(super) fn prune(_wire: &mut WireFile, _now_ms: u64) {}
}
