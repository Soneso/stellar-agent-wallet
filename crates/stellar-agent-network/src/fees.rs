//! Stellar RPC `getFeeStats` typed wrapper for `stellar-agent-network`.
//!
//! Provides fee-stats fetching, percentile selection, and classic-fee
//! resolution for transaction construction.

use serde::{Deserialize, Serialize};
use stellar_agent_core::error::{
    DerivedFee, FeeSource, NetworkError, ValidationError, WalletError,
};
use stellar_agent_core::profile::schema::Profile;
use stellar_rpc_client::{FeeStat, GetFeeStatsResponse};

use crate::client::StellarRpcClient;

/// Operation count of the single-operation classic envelopes built by the
/// CLI and MCP handlers and accepted by the staged decoder.
pub const CLASSIC_SINGLE_OPERATION_COUNT: u32 = 1;

/// Allowed public Stellar RPC host names for explicit RPC URL overrides.
pub const ALLOWED_RPC_HOSTS: &[&str] = &[
    "soroban-testnet.stellar.org",
    "mainnet.sorobanrpc.com",
    "soroban-mainnet.stellar.org",
];

/// Errors returned by [`validate_rpc_url`].
///
/// Each variant names the rule the URL breaks and never the URL or any part
/// of it, because an RPC URL can carry a credential.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RpcUrlError {
    /// The URL could not be parsed as an absolute URL with a host.
    #[error("invalid RPC URL: it must be an absolute URL with a host")]
    InvalidUrl,
    /// The URL scheme is not HTTPS.
    #[error("non-HTTPS RPC URL not allowed: the URL must use https")]
    NonHttps,
    /// The URL contains embedded credentials.
    #[error("RPC URL must not contain embedded credentials")]
    CredentialsInUrl,
    /// The URL's host is not in the allow-list.
    #[error("the RPC host is not in the allow-list (allowed: {allowed})")]
    HostNotAllowed {
        /// Human-readable list of allowed hosts.
        allowed: String,
    },
}

/// Per-fee-class distribution returned by `getFeeStats`. Stroops are
/// per-operation, not per-transaction.
///
/// Every fee-denominated field (`max`, `min`, `mode`, `p10`..`p99`) is
/// encoded as a decimal string on the wire (`serde(with =
/// "stellar_agent_core::wire_stroops::u64")`): a JSON number backed by
/// `f64` cannot represent a `u64` stroop amount exactly once it exceeds
/// `2^53`. `transaction_count` and `ledger_count` are counts, not
/// stroop amounts, and stay plain JSON numbers. The Rust field types stay
/// `u64` throughout — `select()`/`from_rpc` arithmetic is unaffected — only
/// the wire encoding changes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeDistribution {
    /// Maximum fee observed.
    #[serde(with = "stellar_agent_core::wire_stroops::u64")]
    pub max: u64,
    /// Minimum fee observed.
    #[serde(with = "stellar_agent_core::wire_stroops::u64")]
    pub min: u64,
    /// Most frequently observed fee.
    #[serde(with = "stellar_agent_core::wire_stroops::u64")]
    pub mode: u64,
    /// 10th percentile.
    #[serde(with = "stellar_agent_core::wire_stroops::u64")]
    pub p10: u64,
    /// 20th percentile.
    #[serde(with = "stellar_agent_core::wire_stroops::u64")]
    pub p20: u64,
    /// 30th percentile.
    #[serde(with = "stellar_agent_core::wire_stroops::u64")]
    pub p30: u64,
    /// 40th percentile.
    #[serde(with = "stellar_agent_core::wire_stroops::u64")]
    pub p40: u64,
    /// 50th percentile.
    #[serde(with = "stellar_agent_core::wire_stroops::u64")]
    pub p50: u64,
    /// 60th percentile.
    #[serde(with = "stellar_agent_core::wire_stroops::u64")]
    pub p60: u64,
    /// 70th percentile.
    #[serde(with = "stellar_agent_core::wire_stroops::u64")]
    pub p70: u64,
    /// 80th percentile.
    #[serde(with = "stellar_agent_core::wire_stroops::u64")]
    pub p80: u64,
    /// 90th percentile.
    #[serde(with = "stellar_agent_core::wire_stroops::u64")]
    pub p90: u64,
    /// 95th percentile.
    #[serde(with = "stellar_agent_core::wire_stroops::u64")]
    pub p95: u64,
    /// 99th percentile.
    #[serde(with = "stellar_agent_core::wire_stroops::u64")]
    pub p99: u64,
    /// Transactions included in the distribution.
    pub transaction_count: u64,
    /// Consecutive ledgers included in the distribution.
    pub ledger_count: u64,
}

/// Resolved view of `getFeeStats`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeStatsView {
    /// Classic inclusion fee distribution.
    pub inclusion_fee: FeeDistribution,
    /// Soroban inclusion fee distribution.
    pub soroban_inclusion_fee: FeeDistribution,
    /// Latest ledger used by the RPC server.
    pub latest_ledger: u32,
}

impl FeeStatsView {
    /// Maps the upstream RPC response into the wallet view.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkError::RpcResponseMalformed`] if any string fee field
    /// fails to parse as a `u64`.
    pub fn from_rpc(response: &GetFeeStatsResponse) -> Result<Self, NetworkError> {
        Ok(Self {
            inclusion_fee: FeeDistribution::from_rpc(&response.inclusion_fee)?,
            soroban_inclusion_fee: FeeDistribution::from_rpc(&response.soroban_inclusion_fee)?,
            latest_ledger: response.latest_ledger,
        })
    }
}

impl FeeDistribution {
    fn from_rpc(stat: &FeeStat) -> Result<Self, NetworkError> {
        Ok(Self {
            max: parse_fee_field("max", &stat.max)?,
            min: parse_fee_field("min", &stat.min)?,
            mode: parse_fee_field("mode", &stat.mode)?,
            p10: parse_fee_field("p10", &stat.p10)?,
            p20: parse_fee_field("p20", &stat.p20)?,
            p30: parse_fee_field("p30", &stat.p30)?,
            p40: parse_fee_field("p40", &stat.p40)?,
            p50: parse_fee_field("p50", &stat.p50)?,
            p60: parse_fee_field("p60", &stat.p60)?,
            p70: parse_fee_field("p70", &stat.p70)?,
            p80: parse_fee_field("p80", &stat.p80)?,
            p90: parse_fee_field("p90", &stat.p90)?,
            p95: parse_fee_field("p95", &stat.p95)?,
            p99: parse_fee_field("p99", &stat.p99)?,
            transaction_count: u64::from(stat.transaction_count),
            ledger_count: u64::from(stat.ledger_count),
        })
    }
}

/// Classic fee percentile selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeePercentile {
    /// p10.
    P10,
    /// p20.
    P20,
    /// p30.
    P30,
    /// p40.
    P40,
    /// p50.
    P50,
    /// p60.
    P60,
    /// p70.
    P70,
    /// p80.
    P80,
    /// p90.
    P90,
    /// p95.
    P95,
    /// p99.
    P99,
}

impl FeePercentile {
    /// Returns the wire label.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::P10 => "p10",
            Self::P20 => "p20",
            Self::P30 => "p30",
            Self::P40 => "p40",
            Self::P50 => "p50",
            Self::P60 => "p60",
            Self::P70 => "p70",
            Self::P80 => "p80",
            Self::P90 => "p90",
            Self::P95 => "p95",
            Self::P99 => "p99",
        }
    }

    /// Selects this percentile from the classic fee distribution.
    #[must_use]
    pub fn select(self, distribution: &FeeDistribution) -> u64 {
        match self {
            Self::P10 => distribution.p10,
            Self::P20 => distribution.p20,
            Self::P30 => distribution.p30,
            Self::P40 => distribution.p40,
            Self::P50 => distribution.p50,
            Self::P60 => distribution.p60,
            Self::P70 => distribution.p70,
            Self::P80 => distribution.p80,
            Self::P90 => distribution.p90,
            Self::P95 => distribution.p95,
            Self::P99 => distribution.p99,
        }
    }
}

/// Parsed classic fee choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClassicFeeChoice {
    /// Use profile/default fee.
    ProfileDefault,
    /// Use an explicit per-op fee.
    Explicit(u32),
    /// Fetch `getFeeStats` and use a percentile.
    Auto(FeePercentile),
}

/// Resolved classic fee selection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClassicFeeSelection {
    /// Selected per-operation fee in stroops.
    ///
    /// Encoded as a decimal string on the wire (`serde(with =
    /// "stellar_agent_core::wire_stroops::u32")`). The Rust field type
    /// stays `u32` — arithmetic call sites are unaffected.
    #[serde(with = "stellar_agent_core::wire_stroops::u32")]
    pub per_op_stroops: u32,
    /// Selection label (`explicit`, `profile_default`, or percentile label).
    pub selected_fee_percentile: String,
}

/// The argument a refused fee choice names; the rejected text never appears.
const FEE_FIELD: &str = "--fee";

/// Parses `<integer>`, `auto`, `auto:pNN`, or `None`.
///
/// # Errors
///
/// Returns [`WalletError::Validation`] for unknown grammar or invalid numeric
/// values.
pub fn parse_classic_fee_choice(raw: Option<&str>) -> Result<ClassicFeeChoice, WalletError> {
    let Some(raw) = raw else {
        return Ok(ClassicFeeChoice::ProfileDefault);
    };
    let value = raw.trim();
    if value == "auto" {
        return Ok(ClassicFeeChoice::Auto(FeePercentile::P95));
    }
    if let Some(percentile) = value.strip_prefix("auto:") {
        return parse_percentile(percentile).map(ClassicFeeChoice::Auto);
    }
    value
        .parse::<u32>()
        .map(ClassicFeeChoice::Explicit)
        .map_err(|_| {
            WalletError::Validation(ValidationError::AmountMalformed {
                field: FEE_FIELD.into(),
            })
        })
}

/// Resolves a parsed fee choice.
///
/// # Errors
///
/// Returns a typed validation error when a percentile does not fit in `u32`.
pub async fn resolve_classic_fee_selection(
    client: &StellarRpcClient,
    default_per_op_stroops: u32,
    choice: ClassicFeeChoice,
) -> Result<ClassicFeeSelection, WalletError> {
    match choice {
        ClassicFeeChoice::ProfileDefault => Ok(ClassicFeeSelection {
            per_op_stroops: default_per_op_stroops,
            selected_fee_percentile: "profile_default".to_owned(),
        }),
        ClassicFeeChoice::Explicit(per_op_stroops) => Ok(ClassicFeeSelection {
            per_op_stroops,
            selected_fee_percentile: "explicit".to_owned(),
        }),
        ClassicFeeChoice::Auto(percentile) => {
            let stats = fetch_fee_stats(client).await?;
            let selected = percentile.select(&stats.inclusion_fee);
            let per_op_stroops = u32::try_from(selected).map_err(|_| {
                WalletError::Validation(ValidationError::AmountOutOfRange {
                    field: "the selected percentile fee".into(),
                })
            })?;
            Ok(ClassicFeeSelection {
                per_op_stroops,
                selected_fee_percentile: percentile.label().to_owned(),
            })
        }
    }
}

/// Names the source of the per-operation fee a parsed choice resolves to,
/// for the fee-cap refusal of [`check_classic_fee_cap`].
///
/// `default_source` is the source of the fee a [`ClassicFeeChoice::ProfileDefault`]
/// choice resolves to: [`FeeSource::ProfileDefault`] for a stage that reads
/// `classic_fee_per_op_stroops`, [`FeeSource::CommandDefault`] for a stage
/// that uses its built-in default fee.
#[must_use]
pub fn classic_fee_source(choice: ClassicFeeChoice, default_source: FeeSource) -> FeeSource {
    match choice {
        ClassicFeeChoice::ProfileDefault => default_source,
        ClassicFeeChoice::Explicit(_) => FeeSource::Explicit,
        ClassicFeeChoice::Auto(percentile) => FeeSource::Selected {
            percentile: percentile.label().to_owned(),
        },
    }
}

/// Checks a built CLI envelope's resolved fee against the profile cap.
///
/// A [`ClassicFeeChoice::ProfileDefault`] choice is reported as
/// [`FeeSource::CommandDefault`], because the CLI build uses its built-in fee
/// and does not read `classic_fee_per_op_stroops`.
///
/// # Errors
///
/// Returns the refusal of [`check_classic_fee_cap`].
pub fn check_built_fee_cap(
    per_op: u32,
    choice: ClassicFeeChoice,
    profile: &Profile,
) -> Result<(), WalletError> {
    check_classic_fee_cap(
        per_op,
        classic_fee_source(choice, FeeSource::CommandDefault),
        profile,
    )
}

/// Checks a classic per-operation fee against the profile's
/// `classic_max_fee_per_op_stroops` before a stage signs or sends.
///
/// A fee equal to the cap passes. A profile without a cap passes on testnet;
/// on mainnet the cap is required, so a fee never reaches the network
/// unbounded there.
///
/// # Errors
///
/// - [`ValidationError::MainnetFeeCapRequired`] for a mainnet profile that
///   sets no cap.
/// - [`ValidationError::FeeAboveCap`] for a fee above the cap; its text names
///   `fee_source`.
pub fn check_classic_fee_cap(
    per_op: u32,
    fee_source: FeeSource,
    profile: &Profile,
) -> Result<(), WalletError> {
    match profile.classic_max_fee_per_op_stroops {
        None if profile.chain_id.is_mainnet() => Err(WalletError::Validation(
            ValidationError::MainnetFeeCapRequired,
        )),
        Some(cap) if per_op > cap => Err(WalletError::Validation(ValidationError::FeeAboveCap {
            per_op: DerivedFee::new(per_op, &fee_source),
            cap,
            fee_source,
        })),
        _ => Ok(()),
    }
}

/// Returns the tighter stored and signed classic fee cap.
#[must_use]
pub fn effective_classic_fee_cap(profile: &Profile, signed: u32) -> u32 {
    profile
        .classic_max_fee_per_op_stroops
        .map_or(signed, |cap| cap.min(signed))
}

/// Checks the tighter of the signed and profile classic fee caps.
///
/// # Errors
/// Refuses a fee above the effective cap or a mainnet fee without any cap.
pub fn check_classic_fee_cap_signed(
    per_op: u32,
    fee_source: FeeSource,
    profile: &Profile,
    signed: Option<u32>,
) -> Result<(), WalletError> {
    let cap = match (profile.classic_max_fee_per_op_stroops, signed) {
        (Some(profile_cap), Some(signed)) => {
            if profile_cap > signed {
                tracing::warn!("profile classic fee cap exceeds signed cap; using signed cap");
            }
            Some(effective_classic_fee_cap(profile, signed))
        }
        (profile, signed) => profile.or(signed),
    };
    match cap {
        None if profile.chain_id.is_mainnet() => Err(WalletError::Validation(
            ValidationError::MainnetFeeCapRequired,
        )),
        Some(cap) if per_op > cap => Err(WalletError::Validation(ValidationError::FeeAboveCap {
            per_op: DerivedFee::new(per_op, &fee_source),
            cap,
            fee_source,
        })),
        _ => Ok(()),
    }
}

/// Fetches fee stats through a [`StellarRpcClient`].
///
/// # Errors
///
/// Returns [`NetworkError`] for RPC or parse failures.
pub async fn fetch_fee_stats(client: &StellarRpcClient) -> Result<FeeStatsView, NetworkError> {
    client.get_fee_stats().await
}

/// Validates an RPC URL override against the production allow-list.
///
/// # Errors
///
/// Returns [`RpcUrlError`] if the URL is malformed, non-HTTPS, credentialed,
/// or not allow-listed.
pub fn validate_rpc_url(url: &str) -> Result<(), RpcUrlError> {
    validate_rpc_url_inner(url, false)
}

/// Validates an RPC URL override, additionally allowing loopback addresses.
#[cfg(any(test, feature = "test-loopback"))]
#[doc(hidden)]
pub fn validate_rpc_url_allowing_loopback(url: &str) -> Result<(), RpcUrlError> {
    validate_rpc_url_inner(url, true)
}

fn parse_fee_field(field: &'static str, raw: &str) -> Result<u64, NetworkError> {
    raw.parse::<u64>()
        .map_err(|e| NetworkError::RpcResponseMalformed {
            method: "getFeeStats".to_owned(),
            detail: format!("field {field}: {e}"),
        })
}

fn parse_percentile(raw: &str) -> Result<FeePercentile, WalletError> {
    match raw {
        "p10" => Ok(FeePercentile::P10),
        "p20" => Ok(FeePercentile::P20),
        "p30" => Ok(FeePercentile::P30),
        "p40" => Ok(FeePercentile::P40),
        "p50" => Ok(FeePercentile::P50),
        "p60" => Ok(FeePercentile::P60),
        "p70" => Ok(FeePercentile::P70),
        "p80" => Ok(FeePercentile::P80),
        "p90" => Ok(FeePercentile::P90),
        "p95" => Ok(FeePercentile::P95),
        "p99" => Ok(FeePercentile::P99),
        _ => Err(WalletError::Validation(ValidationError::AmountMalformed {
            field: FEE_FIELD.into(),
        })),
    }
}

fn validate_rpc_url_inner(url: &str, allow_loopback: bool) -> Result<(), RpcUrlError> {
    let parsed = url::Url::parse(url).map_err(|_| RpcUrlError::InvalidUrl)?;
    if parsed.username() != "" || parsed.password().is_some() {
        return Err(RpcUrlError::CredentialsInUrl);
    }

    let host = parsed.host_str().ok_or(RpcUrlError::InvalidUrl)?;

    // `url::Url::host_str` returns IPv6 hosts in bracketed form (`[::1]`), so the
    // loopback set matches that form rather than a bare `::1`.
    let is_loopback = matches!(host, "127.0.0.1" | "localhost" | "[::1]");
    if allow_loopback && is_loopback {
        return Ok(());
    }

    if parsed.scheme() != "https" {
        return Err(RpcUrlError::NonHttps);
    }

    if ALLOWED_RPC_HOSTS.contains(&host) {
        Ok(())
    } else {
        Err(RpcUrlError::HostNotAllowed {
            allowed: ALLOWED_RPC_HOSTS.join(", "),
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used, reason = "test assertions")]

    use super::*;

    fn testnet(cap: Option<u32>) -> Profile {
        Profile::builder_testnet_named("fees", "signer", "fees", "nonce", "fees")
            .classic_max_fee_per_op_stroops(cap)
            .build()
    }

    fn mainnet(cap: Option<u32>) -> Profile {
        Profile::builder_mainnet_named(
            "fees",
            "https://rpc.example",
            "signer",
            "fees",
            "nonce",
            "fees",
        )
        .classic_max_fee_per_op_stroops(cap)
        .build()
    }

    fn above_cap_text(result: Result<(), WalletError>) -> String {
        match result {
            Err(WalletError::Validation(ValidationError::FeeAboveCap { cap: 500, .. })) => {
                result.unwrap_err().to_string()
            }
            other => panic!("expected FeeAboveCap for 501 over 500, got {other:?}"),
        }
    }

    #[test]
    #[serial_test::serial]
    fn mainnet_without_cap_refuses() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        let error = check_classic_fee_cap(100, FeeSource::Explicit, &mainnet(None)).unwrap_err();
        assert_eq!(error.code(), "validation.mainnet_fee_cap_required");
    }

    #[test]
    #[serial_test::serial]
    fn mainnet_with_cap_passes() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        assert!(check_classic_fee_cap(100, FeeSource::Explicit, &mainnet(Some(10_000))).is_ok());
    }

    #[test]
    #[serial_test::serial]
    fn testnet_without_cap_passes() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        assert!(check_classic_fee_cap(u32::MAX, FeeSource::Explicit, &testnet(None)).is_ok());
    }

    #[test]
    #[serial_test::serial]
    fn fee_equal_to_cap_passes() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        assert!(check_classic_fee_cap(500, FeeSource::Envelope, &testnet(Some(500))).is_ok());
        assert!(check_classic_fee_cap(500, FeeSource::Envelope, &mainnet(Some(500))).is_ok());
    }

    #[test]
    #[serial_test::serial]
    fn fee_above_cap_names_its_source() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        let profile = testnet(Some(500));
        let selected = FeeSource::Selected {
            percentile: "p95".to_owned(),
        };
        let check = |source| check_classic_fee_cap(501, source, &profile);
        assert_eq!(
            check(selected.clone()).unwrap_err().code(),
            "fees.percentile_exceeds_cap"
        );
        assert!(above_cap_text(check(selected)).starts_with("auto-selected per-operation fee 501"));
        assert_eq!(
            above_cap_text(check(FeeSource::Explicit)),
            "--fee must be a per-operation stroop amount within classic_max_fee_per_op_stroops; \
             lower --fee or raise classic_max_fee_per_op_stroops."
        );
        assert_eq!(
            above_cap_text(check(FeeSource::ProfileDefault)),
            "classic_fee_per_op_stroops must not exceed classic_max_fee_per_op_stroops; lower \
             classic_fee_per_op_stroops or raise classic_max_fee_per_op_stroops."
        );
        assert!(above_cap_text(check(FeeSource::CommandDefault)).starts_with("the default"));
        assert!(above_cap_text(check(FeeSource::Envelope)).starts_with("the envelope's"));
        let mainnet = mainnet(Some(500));
        assert!(
            above_cap_text(check_classic_fee_cap(501, FeeSource::Explicit, &mainnet))
                .starts_with("--fee must be")
        );
    }

    #[test]
    fn fee_source_follows_the_choice() {
        assert_eq!(
            classic_fee_source(ClassicFeeChoice::Explicit(5), FeeSource::CommandDefault),
            FeeSource::Explicit
        );
        assert_eq!(
            classic_fee_source(
                ClassicFeeChoice::Auto(FeePercentile::P90),
                FeeSource::ProfileDefault
            ),
            FeeSource::Selected {
                percentile: "p90".to_owned()
            }
        );
        assert_eq!(
            classic_fee_source(ClassicFeeChoice::ProfileDefault, FeeSource::CommandDefault),
            FeeSource::CommandDefault
        );
        assert_eq!(
            classic_fee_source(ClassicFeeChoice::ProfileDefault, FeeSource::ProfileDefault),
            FeeSource::ProfileDefault
        );
    }
    #[test]
    #[serial_test::serial]
    fn effective_fee_cap_is_tighter_cap() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        let mut profile = Profile::builder_mainnet_named(
            "fees",
            "https://rpc.example.invalid",
            "s",
            "a",
            "n",
            "a",
        )
        .build();
        for (configured, expected) in [(None, 500), (Some(900), 500), (Some(200), 200)] {
            profile.classic_max_fee_per_op_stroops = configured;
            assert_eq!(effective_classic_fee_cap(&profile, 500), expected);
            assert!(
                check_classic_fee_cap_signed(expected, FeeSource::Envelope, &profile, Some(500))
                    .is_ok()
            );
            assert_eq!(
                check_classic_fee_cap_signed(
                    expected + 1,
                    FeeSource::Envelope,
                    &profile,
                    Some(500)
                )
                .unwrap_err()
                .code(),
                "fees.percentile_exceeds_cap"
            );
        }
    }
}
