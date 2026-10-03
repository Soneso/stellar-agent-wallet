//! Network flags assert the chain of the loaded profile.
//!
//! Endpoint flags override testnet profiles and are refused on mainnet profiles.
//! The context always starts with the loaded profile's chain and endpoints.
//!
//! # Two-layer mainnet defence
//!
//! Structural refusals inspect the context's chain before signer access on pay,
//! claim, account creation and deployment, smart-account deployment, signers,
//! rules writes, execute, migration submit, timelock writes, and multicall.
//! The submit layer also checks the endpoint and passphrase.

use std::fmt;
use std::str::FromStr;

use stellar_agent_core::profile::caip2::Caip2;
pub(crate) use stellar_agent_core::profile::caip2::TESTNET_RPC_URL;

/// An optional assertion that the loaded profile uses the named network.
/// Profile creation uses the value to select the new file's chain.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetNetwork {
    /// Stellar testnet.
    Testnet,
    /// Stellar mainnet.
    Mainnet,
}

impl From<TargetNetwork> for Caip2 {
    fn from(network: TargetNetwork) -> Self {
        match network {
            TargetNetwork::Testnet => Self::Testnet,
            TargetNetwork::Mainnet => Self::Mainnet,
        }
    }
}

impl TargetNetwork {
    /// Returns the CAIP-2 chain identifier for this CLI selector.
    #[must_use]
    pub fn caip2(self) -> Caip2 {
        self.into()
    }
}

impl FromStr for TargetNetwork {
    type Err = String;

    /// Parses a network name case-insensitively.
    ///
    /// # Errors
    ///
    /// Returns a `String` error if the input is not `"testnet"` or `"mainnet"`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "testnet" => Ok(Self::Testnet),
            "mainnet" => Ok(Self::Mainnet),
            other => Err(format!(
                "unknown network '{other}'; only 'testnet' and 'mainnet' are recognized"
            )),
        }
    }
}

impl fmt::Display for TargetNetwork {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Testnet => f.write_str("testnet"),
            Self::Mainnet => f.write_str("mainnet"),
        }
    }
}

/// The endpoint flags a verb accepts; every field is optional.
#[derive(Clone, Copy)]
pub(crate) struct EndpointFlags<'a> {
    pub network: Option<TargetNetwork>,
    pub rpc_url: Option<&'a str>,
    pub secondary_rpc_url: Option<&'a str>,
}

/// The network context of a command, from the loaded profile and the flags.
pub(crate) fn network_context_for_command(
    profile: &stellar_agent_core::profile::Profile,
    profile_name: &str,
    flags: EndpointFlags<'_>,
) -> Result<stellar_agent_network::NetworkContext, stellar_agent_core::error::WalletError> {
    use stellar_agent_core::error::ValidationError;
    if let Some(network) = flags.network
        && network.caip2() != profile.chain_id
    {
        return Err(ValidationError::NetworkFlagMismatch {
            flag: network.to_string(),
            profile: profile_name.to_owned(),
            chain: profile.chain_id.caip2_str().to_owned(),
        }
        .into());
    }
    if profile.chain_id.is_mainnet() {
        for (field, value) in [
            ("rpc_url", flags.rpc_url),
            ("secondary_rpc_url", flags.secondary_rpc_url),
        ] {
            if value.is_some() {
                return Err(ValidationError::ProfileNonOverlayableField { field }.into());
            }
        }
    }
    let mut context = stellar_agent_network::NetworkContext::from_profile(profile);
    if let Some(url) = flags.rpc_url {
        context.rpc_url = url.to_owned();
    }
    Ok(context.with_secondary(
        flags
            .secondary_rpc_url
            .map(str::to_owned)
            .or_else(|| profile.secondary_rpc_url.clone()),
    ))
}

/// Parses an RPC URL flag without echoing credentials in errors.
#[derive(Clone)]
pub(crate) struct EndpointUrlFlag;

impl clap::builder::TypedValueParser for EndpointUrlFlag {
    type Value = String;
    fn parse_ref(
        &self,
        _cmd: &clap::Command,
        arg: Option<&clap::Arg>,
        value: &std::ffi::OsStr,
    ) -> Result<String, clap::Error> {
        use clap::error::ErrorKind;
        let flag = arg.and_then(clap::Arg::get_long).unwrap_or("endpoint");
        let value = value.to_str().ok_or_else(|| {
            clap::Error::raw(
                ErrorKind::ValueValidation,
                format!("`--{flag}`: invalid UTF-8"),
            )
        })?;
        let parsed = url::Url::parse(value).map_err(|error| {
            clap::Error::raw(ErrorKind::ValueValidation, format!("`--{flag}`: {error}"))
        })?;
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(clap::Error::raw(
                ErrorKind::ValueValidation,
                format!(
                    "`--{flag}` {}",
                    stellar_agent_core::redact::CREDENTIALED_URL_INPUT_REFUSAL
                ),
            ));
        }
        Ok(value.to_owned())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "test-only; panics and unwraps are acceptable in unit tests"
    )]

    use super::*;

    #[test]
    fn target_network_from_str_round_trips() {
        assert_eq!(
            TargetNetwork::from_str("testnet").unwrap(),
            TargetNetwork::Testnet
        );
        assert_eq!(
            TargetNetwork::from_str("TESTNET").unwrap(),
            TargetNetwork::Testnet
        );
        assert_eq!(
            TargetNetwork::from_str("Testnet").unwrap(),
            TargetNetwork::Testnet
        );
        assert_eq!(
            TargetNetwork::from_str("mainnet").unwrap(),
            TargetNetwork::Mainnet
        );
        assert_eq!(
            TargetNetwork::from_str("MAINNET").unwrap(),
            TargetNetwork::Mainnet
        );
    }

    #[test]
    fn target_network_from_str_unknown_is_error() {
        let err = TargetNetwork::from_str("futurenet").unwrap_err();
        assert!(
            err.contains("futurenet"),
            "error must include the unknown token"
        );
        assert!(TargetNetwork::from_str("").is_err());
    }

    #[test]
    fn target_network_display_lowercase() {
        assert_eq!(TargetNetwork::Testnet.to_string(), "testnet");
        assert_eq!(TargetNetwork::Mainnet.to_string(), "mainnet");
    }

    #[test]
    fn target_network_caip2_maps_both_variants() {
        assert_eq!(TargetNetwork::Testnet.caip2(), Caip2::Testnet);
        assert_eq!(TargetNetwork::Mainnet.caip2(), Caip2::Mainnet);
        assert_eq!(
            TargetNetwork::Mainnet.caip2().caip2_str(),
            "stellar:mainnet"
        );
    }
}

#[cfg(test)]
mod flag_rules_tests {
    #![allow(clippy::unwrap_used, reason = "test assertions")]
    use super::*;
    use stellar_agent_core::{
        error::{ValidationError, WalletError},
        profile::Profile,
    };

    fn profile(mainnet: bool) -> Profile {
        let mut p = if mainnet {
            Profile::builder_mainnet_named("flags", "s", "a", "n", "a")
        } else {
            Profile::builder_testnet_named("flags", "s", "a", "n", "a")
        }
        .rpc_url("https://primary.example")
        .build();
        p.secondary_rpc_url = Some("https://secondary.example".into());
        p
    }

    fn flags() -> EndpointFlags<'static> {
        EndpointFlags {
            network: None,
            rpc_url: None,
            secondary_rpc_url: None,
        }
    }

    #[test]
    fn absent_flags_copy_all_profile_fields() {
        let p = profile(false);
        let c = network_context_for_command(&p, "flags", flags()).unwrap();
        assert_eq!(c.chain_id, p.chain_id);
        assert_eq!(c.rpc_url, p.rpc_url);
        assert_eq!(c.secondary_rpc_url, p.secondary_rpc_url);
    }

    #[test]
    fn matching_testnet_flag_passes() {
        assert!(
            network_context_for_command(
                &profile(false),
                "flags",
                EndpointFlags {
                    network: Some(TargetNetwork::Testnet),
                    ..flags()
                }
            )
            .is_ok()
        );
    }

    #[test]
    fn testnet_profile_mainnet_flag_refuses() {
        let error = network_context_for_command(
            &profile(false),
            "flags",
            EndpointFlags {
                network: Some(TargetNetwork::Mainnet),
                ..flags()
            },
        )
        .unwrap_err();
        assert_eq!(error.code(), "profile.network_flag_mismatch");
    }

    #[test]
    fn mainnet_profile_testnet_flag_refuses() {
        let error = network_context_for_command(
            &profile(true),
            "flags",
            EndpointFlags {
                network: Some(TargetNetwork::Testnet),
                ..flags()
            },
        )
        .unwrap_err();
        assert_eq!(error.code(), "profile.network_flag_mismatch");
    }

    #[test]
    fn testnet_endpoint_flags_override_only_endpoints() {
        let p = profile(false);
        let c = network_context_for_command(
            &p,
            "flags",
            EndpointFlags {
                rpc_url: Some("https://override.example"),
                secondary_rpc_url: Some("https://override-secondary.example"),
                ..flags()
            },
        )
        .unwrap();
        assert_eq!(c.chain_id, p.chain_id);
        assert_eq!(c.rpc_url, "https://override.example");
        assert_eq!(
            c.secondary_rpc_url.as_deref(),
            Some("https://override-secondary.example")
        );
        let c = network_context_for_command(
            &p,
            "flags",
            EndpointFlags {
                rpc_url: Some("https://override.example"),
                ..flags()
            },
        )
        .unwrap();
        assert_eq!(c.secondary_rpc_url, p.secondary_rpc_url);
    }

    #[test]
    fn mainnet_equal_primary_flag_refuses() {
        assert!(matches!(
            network_context_for_command(
                &profile(true),
                "flags",
                EndpointFlags {
                    rpc_url: Some("https://primary.example"),
                    ..flags()
                }
            ),
            Err(WalletError::Validation(
                ValidationError::ProfileNonOverlayableField { field: "rpc_url" }
            ))
        ));
    }

    #[test]
    fn mainnet_equal_secondary_flag_refuses() {
        assert!(matches!(
            network_context_for_command(
                &profile(true),
                "flags",
                EndpointFlags {
                    secondary_rpc_url: Some("https://secondary.example"),
                    ..flags()
                }
            ),
            Err(WalletError::Validation(
                ValidationError::ProfileNonOverlayableField {
                    field: "secondary_rpc_url"
                }
            ))
        ));
    }

    fn rpc_url_arg() -> clap::Arg {
        clap::Arg::new("rpc_url").long("rpc-url")
    }

    #[test]
    fn endpoint_url_flag_accepts_credential_free_urls_unchanged() {
        use clap::builder::TypedValueParser;
        for value in [
            "http://127.0.0.1:8080",
            "https://soroban-testnet.stellar.org",
        ] {
            assert_eq!(
                EndpointUrlFlag
                    .parse_ref(
                        &clap::Command::new("test"),
                        Some(&rpc_url_arg()),
                        value.as_ref()
                    )
                    .unwrap(),
                value
            );
        }
    }

    #[test]
    fn endpoint_url_flag_refuses_userinfo_without_echoing_it() {
        use clap::builder::TypedValueParser;
        for value in [
            "https://user:secret@rpc.example",
            "https://user@rpc.example",
        ] {
            let error = EndpointUrlFlag
                .parse_ref(
                    &clap::Command::new("test"),
                    Some(&rpc_url_arg()),
                    value.as_ref(),
                )
                .unwrap_err()
                .to_string();
            assert!(!error.contains("user"));
            assert!(!error.contains("secret"));
            assert!(error.contains("`--rpc-url` never carries credentials"));
        }
    }
}
