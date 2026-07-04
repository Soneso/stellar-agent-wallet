//! Fail-closed validation of [`stellar_agent_core::profile::schema::RemoteApprovalConfig`]
//! at `approve serve --remote` start time.
//!
//! `RemoteApprovalConfig.rp_id` and `.bind` deserialise as free-form strings —
//! the profile schema itself does not (and should not; it has no network
//! concept) validate that `rp_id` is a usable WebAuthn Relying Party ID or
//! that `bind` is a parseable socket address. This module is the single place
//! that rejects a malformed config BEFORE the process attempts to bind a
//! TLS listener or provision a certificate for it.

use std::net::SocketAddr;

/// A `RemoteApprovalConfig` value failed validation for remote-approval start.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RemoteConfigValidationError {
    /// `bind` does not parse as a `SocketAddr` (e.g. `"host:port"` form
    /// without a numeric IP, or a malformed address).
    #[error("remote_approval.bind is not a valid socket address: {bind:?}")]
    InvalidBindAddress {
        /// The offending configured value.
        bind: String,
    },

    /// `rp_id` is empty.
    #[error("remote_approval.rp_id must not be empty")]
    EmptyRpId,

    /// `rp_id` is an IP literal (IPv4 or IPv6). WebAuthn Level 2 §5.1.2
    /// forbids IP-literal Relying Party IDs: a passkey bound to an IP
    /// address cannot be verified by a browser, which requires the RP-ID to
    /// be a registrable domain suffix of the page's origin hostname.
    #[error("remote_approval.rp_id must be a DNS hostname, not an IP literal: {rp_id:?}")]
    RpIdIsIpLiteral {
        /// The offending configured value.
        rp_id: String,
    },

    /// `rp_id` contains characters that cannot appear in a DNS hostname
    /// (anything outside `a`-`z`, `A`-`Z`, `0`-`9`, `-`, and `.` as a label
    /// separator), or has a malformed label (empty, or starting/ending with
    /// `-`).
    #[error("remote_approval.rp_id is not a well-formed DNS hostname: {rp_id:?}")]
    RpIdNotAHostname {
        /// The offending configured value.
        rp_id: String,
    },
}

/// Validates `bind` and `rp_id` for remote-approval start, fail-closed.
///
/// Returns the parsed [`SocketAddr`] on success so the caller does not need
/// to re-parse `bind`.
///
/// # Errors
///
/// See [`RemoteConfigValidationError`] variants.
pub fn validate_remote_config(
    bind: &str,
    rp_id: &str,
) -> Result<SocketAddr, RemoteConfigValidationError> {
    let addr = bind.parse::<SocketAddr>().map_err(|_| {
        RemoteConfigValidationError::InvalidBindAddress {
            bind: bind.to_owned(),
        }
    })?;

    validate_rp_id(rp_id)?;

    Ok(addr)
}

/// Validates that `rp_id` is a well-formed DNS hostname and not an IP
/// literal.
///
/// # Errors
///
/// See [`RemoteConfigValidationError::EmptyRpId`],
/// [`RemoteConfigValidationError::RpIdIsIpLiteral`],
/// [`RemoteConfigValidationError::RpIdNotAHostname`].
pub fn validate_rp_id(rp_id: &str) -> Result<(), RemoteConfigValidationError> {
    if rp_id.is_empty() {
        return Err(RemoteConfigValidationError::EmptyRpId);
    }

    if rp_id.parse::<std::net::IpAddr>().is_ok() {
        return Err(RemoteConfigValidationError::RpIdIsIpLiteral {
            rp_id: rp_id.to_owned(),
        });
    }
    // Bracketed IPv6 literals (`"[::1]"`) do not parse as `IpAddr` directly;
    // reject the bracket form explicitly too.
    if rp_id.starts_with('[') && rp_id.ends_with(']') {
        return Err(RemoteConfigValidationError::RpIdIsIpLiteral {
            rp_id: rp_id.to_owned(),
        });
    }

    if rp_id.len() > 253 || !is_well_formed_hostname(rp_id) {
        return Err(RemoteConfigValidationError::RpIdNotAHostname {
            rp_id: rp_id.to_owned(),
        });
    }

    Ok(())
}

/// Returns `true` if `s` is a syntactically well-formed DNS hostname: one or
/// more dot-separated labels, each 1-63 ASCII alphanumeric-or-hyphen
/// characters, never starting or ending with a hyphen.
///
/// This is a conservative syntactic check (RFC 1123), not a resolvability
/// check — the operator is responsible for making `rp_id` actually resolve
/// from the approving device (internal DNS or a hosts-file entry).
fn is_well_formed_hostname(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    s.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, reason = "test-only")]
    use super::*;

    #[test]
    fn valid_config_parses() {
        let addr = validate_remote_config("0.0.0.0:8443", "wallet.internal").unwrap();
        assert_eq!(addr.port(), 8443);
    }

    #[test]
    fn rejects_unparseable_bind() {
        let err = validate_remote_config("not-an-address", "wallet.internal").unwrap_err();
        assert!(matches!(
            err,
            RemoteConfigValidationError::InvalidBindAddress { .. }
        ));
    }

    #[test]
    fn rejects_bind_missing_port() {
        let err = validate_remote_config("0.0.0.0", "wallet.internal").unwrap_err();
        assert!(matches!(
            err,
            RemoteConfigValidationError::InvalidBindAddress { .. }
        ));
    }

    #[test]
    fn rejects_empty_rp_id() {
        let err = validate_remote_config("0.0.0.0:8443", "").unwrap_err();
        assert!(matches!(err, RemoteConfigValidationError::EmptyRpId));
    }

    #[test]
    fn rejects_ipv4_literal_rp_id() {
        let err = validate_remote_config("0.0.0.0:8443", "203.0.113.5").unwrap_err();
        assert!(matches!(
            err,
            RemoteConfigValidationError::RpIdIsIpLiteral { .. }
        ));
    }

    #[test]
    fn rejects_ipv6_literal_rp_id() {
        let err = validate_remote_config("0.0.0.0:8443", "::1").unwrap_err();
        assert!(matches!(
            err,
            RemoteConfigValidationError::RpIdIsIpLiteral { .. }
        ));
        let err2 = validate_remote_config("0.0.0.0:8443", "[::1]").unwrap_err();
        assert!(matches!(
            err2,
            RemoteConfigValidationError::RpIdIsIpLiteral { .. }
        ));
    }

    #[test]
    fn rejects_malformed_hostname_labels() {
        for bad in [
            "-leading-hyphen.example",
            "trailing-hyphen-.example",
            "..",
            "a..b",
        ] {
            let err = validate_remote_config("0.0.0.0:8443", bad).unwrap_err();
            assert!(
                matches!(err, RemoteConfigValidationError::RpIdNotAHostname { .. }),
                "expected RpIdNotAHostname for {bad:?}, got {err:?}"
            );
        }
    }

    #[test]
    fn accepts_typical_hostnames() {
        for good in [
            "wallet.internal",
            "my-wallet-host",
            "wallet.example.com",
            "a.b.c.d",
        ] {
            assert!(
                validate_rp_id(good).is_ok(),
                "expected {good:?} to be accepted"
            );
        }
    }
}
