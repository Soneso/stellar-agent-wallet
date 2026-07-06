//! Stellar RPC `getFeeStats` typed wrapper for `stellar-agent-network`.
//!
//! Provides fee-stats fetching, percentile selection, and classic-fee
//! resolution for transaction construction.

use serde::{Deserialize, Serialize};
use stellar_agent_core::error::{NetworkError, ValidationError, WalletError};
use stellar_rpc_client::{FeeStat, GetFeeStatsResponse};

use crate::client::StellarRpcClient;

/// Allowed public Stellar RPC host names for explicit RPC URL overrides.
pub const ALLOWED_RPC_HOSTS: &[&str] = &[
    "soroban-testnet.stellar.org",
    "mainnet.sorobanrpc.com",
    "soroban-mainnet.stellar.org",
];

/// Errors returned by [`validate_rpc_url`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RpcUrlError {
    /// The URL could not be parsed.
    #[error("invalid RPC URL: {0}")]
    InvalidUrl(String),
    /// The URL scheme is not HTTPS.
    #[error("non-HTTPS RPC URL not allowed: {0}")]
    NonHttps(String),
    /// The URL contains embedded credentials.
    #[error("RPC URL must not contain embedded credentials")]
    CredentialsInUrl,
    /// The URL's host is not in the allow-list.
    #[error("RPC host '{host}' not in allow-list (allowed: {allowed})")]
    HostNotAllowed {
        /// Rejected host.
        host: String,
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
                input: value.to_owned(),
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
                    amount: selected.to_string(),
                })
            })?;
            Ok(ClassicFeeSelection {
                per_op_stroops,
                selected_fee_percentile: percentile.label().to_owned(),
            })
        }
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
            input: format!("auto:{raw}"),
        })),
    }
}

fn validate_rpc_url_inner(url: &str, allow_loopback: bool) -> Result<(), RpcUrlError> {
    let parsed = url::Url::parse(url).map_err(|e| RpcUrlError::InvalidUrl(e.to_string()))?;
    if parsed.username() != "" || parsed.password().is_some() {
        return Err(RpcUrlError::CredentialsInUrl);
    }

    let host = parsed
        .host_str()
        .ok_or_else(|| RpcUrlError::InvalidUrl("missing host".to_owned()))?;

    // `url::Url::host_str` returns IPv6 hosts in bracketed form (`[::1]`), so the
    // loopback set matches that form rather than a bare `::1`.
    let is_loopback = matches!(host, "127.0.0.1" | "localhost" | "[::1]");
    if allow_loopback && is_loopback {
        return Ok(());
    }

    if parsed.scheme() != "https" {
        return Err(RpcUrlError::NonHttps(url.to_owned()));
    }

    if ALLOWED_RPC_HOSTS.contains(&host) {
        Ok(())
    } else {
        Err(RpcUrlError::HostNotAllowed {
            host: host.to_owned(),
            allowed: ALLOWED_RPC_HOSTS.join(", "),
        })
    }
}
