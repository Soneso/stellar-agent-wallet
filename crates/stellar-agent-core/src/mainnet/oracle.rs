//! The oracle a mainnet profile needs before it is enabled and before every
//! mainnet write.
//!
//! An oracle is usable when the profile sets `oracle_provider_url` and holds
//! the matching `providers.oracle` record. The profile loader checks that
//! record when it reads the file: an HTTPS endpoint, a host other than the
//! primary's, an operator other than the primary's, and the independence
//! assertion.
//! [`require_mainnet_oracle`](crate::mainnet::oracle::require_mainnet_oracle)
//! decides presence on a loaded profile, so `profile enable-mainnet`, the CLI
//! write path, and the MCP write admission refuse with the same code.

use crate::error::{MainnetOracleGap, ValidationError};
use crate::profile::schema::Profile;

/// Refuses a mainnet profile that names no usable oracle.
///
/// The check reads presence only; whether the endpoint answers is the
/// action's own concern when it reads the oracle.
///
/// # Errors
///
/// [`ValidationError::MainnetOracleRequired`] with
/// [`MainnetOracleGap::UrlMissing`] when `oracle_provider_url` is unset, and
/// with [`MainnetOracleGap::RecordMissing`] when the URL is set and the
/// profile holds no `providers.oracle` record.
pub fn require_mainnet_oracle(profile: &Profile) -> Result<(), ValidationError> {
    let refuse = |gap| Err(ValidationError::MainnetOracleRequired { gap });
    if profile.oracle_provider_url.is_none() {
        return refuse(MainnetOracleGap::UrlMissing);
    }
    if profile
        .providers
        .as_ref()
        .and_then(|providers| providers.oracle.as_ref())
        .is_none()
    {
        return refuse(MainnetOracleGap::RecordMissing);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::panic,
        reason = "test fixtures fail loudly"
    )]
    use super::*;
    use crate::profile::schema::{PrimaryProviderRecord, ProviderRecord};

    fn builder() -> crate::profile::schema::ProfileBuilder {
        Profile::builder_mainnet_named(
            "operator",
            "https://rpc.example.invalid",
            "s",
            "a",
            "n",
            "a",
        )
        .primary_provider(PrimaryProviderRecord::new(
            "Primary operator",
            "rpc.example.invalid",
        ))
    }

    fn oracle_url() -> url::Url {
        url::Url::parse("https://oracle.example.invalid").unwrap()
    }

    fn oracle_record() -> ProviderRecord {
        ProviderRecord::new("Oracle operator", "oracle.example.invalid", true)
    }

    fn gap(result: Result<(), ValidationError>) -> MainnetOracleGap {
        match result {
            Err(ValidationError::MainnetOracleRequired { gap }) => gap,
            other => panic!("expected the oracle refusal, got {other:?}"),
        }
    }

    /// A profile without `oracle_provider_url` is refused with the missing
    /// URL, even when it holds an oracle record, and the refusal carries the
    /// profile code.
    #[test]
    fn mainnet_oracle_required_refuses_a_profile_without_the_url() {
        for profile in [
            builder().build(),
            builder().oracle_provider(oracle_record()).build(),
        ] {
            let error = require_mainnet_oracle(&profile).unwrap_err();
            assert_eq!(error.code(), "profile.mainnet_oracle_required");
            assert_eq!(error.to_string(), MainnetOracleGap::UrlMissing.text());
            assert!(error.to_string().contains("sets no oracle_provider_url"));
            assert_eq!(
                gap(require_mainnet_oracle(&profile)),
                MainnetOracleGap::UrlMissing
            );
        }
    }

    /// A profile whose `oracle_provider_url` has no `providers.oracle`
    /// record is refused with the missing record, with and without other
    /// provider records.
    #[test]
    fn mainnet_oracle_required_refuses_a_url_without_its_record() {
        let bare = Profile::builder_mainnet_named(
            "operator",
            "https://rpc.example.invalid",
            "s",
            "a",
            "n",
            "a",
        )
        .oracle_provider_url(oracle_url())
        .build();
        assert!(bare.providers.is_none());
        let with_primary = builder().oracle_provider_url(oracle_url()).build();
        assert!(with_primary.providers.is_some());
        for profile in [bare, with_primary] {
            let error = require_mainnet_oracle(&profile).unwrap_err();
            assert_eq!(error.code(), "profile.mainnet_oracle_required");
            assert_eq!(error.to_string(), MainnetOracleGap::RecordMissing.text());
            assert!(
                error
                    .to_string()
                    .contains("without a providers.oracle record")
            );
            assert_eq!(
                gap(require_mainnet_oracle(&profile)),
                MainnetOracleGap::RecordMissing
            );
        }
    }

    /// A profile with the URL and its record passes.
    #[test]
    fn mainnet_oracle_required_accepts_a_complete_oracle() {
        let profile = builder()
            .oracle_provider_url(oracle_url())
            .oracle_provider(oracle_record())
            .build();
        assert!(require_mainnet_oracle(&profile).is_ok());
    }
}
