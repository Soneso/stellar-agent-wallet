//! Shared counterparty CLI error-envelope mapping.
//!
//! Converts [`stellar_agent_network::CounterpartyError`] values into the
//! `counterparty.*` wire-code namespace used by `counterparty list` and
//! `counterparty refresh`.

use stellar_agent_core::envelope::Envelope;
use stellar_agent_network::{CounterpartyError, CounterpartyKindParseError};

/// Converts a [`CounterpartyError`] into an error [`Envelope`] using the
/// wire codes defined in the `CounterpartyError` documentation.
///
/// The `error.code` field carries the stable wire code (e.g.
/// `"counterparty.fetch_failed"`); `message` is the error's `Display` output.
/// Uses [`Envelope::err_raw`] to bypass the [`stellar_agent_core::WalletError`]
/// hierarchy so the `counterparty.*` wire-code namespace is preserved in the
/// JSON output.
///
/// # Panics
///
/// Only if `Uuid::new_v4` fails to obtain OS entropy (extremely rare).
pub(crate) fn to_counterparty_envelope(err: &CounterpartyError) -> Envelope<()> {
    let code = match err {
        CounterpartyError::WriterLocked => "counterparty.writer_locked",
        CounterpartyError::CacheInvalid { .. } => "counterparty.cache_invalid",
        CounterpartyError::HmacMismatch => "counterparty.hmac_mismatch",
        CounterpartyError::FetchFailed { .. } => "counterparty.fetch_failed",
        CounterpartyError::TomlInvalid { .. } => "counterparty.toml_invalid",
        CounterpartyError::KindParseError(CounterpartyKindParseError::UnknownKind { .. }) => {
            "counterparty.kind_parse.unknown"
        }
        CounterpartyError::KindParseError(CounterpartyKindParseError::MissingField { .. }) => {
            "counterparty.kind_parse.missing_field"
        }
        CounterpartyError::KindParseError(CounterpartyKindParseError::InvalidValue { .. }) => {
            "counterparty.kind_parse.invalid_value"
        }
        CounterpartyError::HomeDomainInvalid { .. } => "counterparty.home_domain_invalid",
        CounterpartyError::KeyringUnavailable { .. } => "counterparty.keyring_unavailable",
        CounterpartyError::Io { .. } => "counterparty.io",
        // Non-exhaustive match — new variants map to the generic code.
        _ => "counterparty.unknown",
    };
    Envelope::err_raw(code, err.to_string())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test-only")]

    use super::*;

    #[test]
    fn counterparty_fetch_failed_wire_code() {
        let err = CounterpartyError::FetchFailed {
            detail: "connection refused".to_owned(),
        };
        let env = to_counterparty_envelope(&err);
        assert!(!env.ok);
        let e = env.error.as_ref().unwrap();
        assert_eq!(e.code, "counterparty.fetch_failed");
        assert!(!e.message.is_empty());
    }

    #[test]
    fn counterparty_hmac_mismatch_wire_code() {
        let err = CounterpartyError::HmacMismatch;
        let env = to_counterparty_envelope(&err);
        assert_eq!(
            env.error.as_ref().unwrap().code,
            "counterparty.hmac_mismatch"
        );
    }

    #[test]
    fn counterparty_home_domain_invalid_wire_code() {
        let err = CounterpartyError::HomeDomainInvalid {
            detail: "contains IDN characters".to_owned(),
        };
        let env = to_counterparty_envelope(&err);
        assert!(!env.ok);
        assert_eq!(
            env.error.as_ref().unwrap().code,
            "counterparty.home_domain_invalid"
        );
    }

    #[test]
    fn counterparty_kind_parse_subvariant_wire_codes() {
        let cases = [
            (
                CounterpartyError::KindParseError(CounterpartyKindParseError::UnknownKind {
                    kind: "UNKNOWN".to_owned(),
                }),
                "counterparty.kind_parse.unknown",
            ),
            (
                CounterpartyError::KindParseError(CounterpartyKindParseError::MissingField {
                    kind: "KNOWN_ISSUER".to_owned(),
                    field: "issuer".to_owned(),
                }),
                "counterparty.kind_parse.missing_field",
            ),
            (
                CounterpartyError::KindParseError(CounterpartyKindParseError::InvalidValue {
                    field: "kind".to_owned(),
                    value: "42".to_owned(),
                }),
                "counterparty.kind_parse.invalid_value",
            ),
        ];

        for (err, expected) in cases {
            let env = to_counterparty_envelope(&err);
            assert_eq!(env.error.as_ref().unwrap().code, expected);
        }
    }
}
