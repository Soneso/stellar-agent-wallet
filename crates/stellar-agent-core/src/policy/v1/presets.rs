//! Mainnet spending presets.
//!
//! A preset names an archetype, a tolerated loss `L` over `T` unattended
//! days, a typical payment `p`, and a 1d rounding quantum `q`.
//! [`derive`](crate::policy::v1::presets::derive) turns a preset and the
//! operator's choices into
//! [`DerivedSpending`](crate::policy::v1::presets::DerivedSpending) with
//! checked `i128` stroop arithmetic (one unit is 10^7 stroops):
//!
//! - `W = L / ceil(T/7)`, `D = q·floor(min(W, 2L/T)/q)`, `P = f·D`.
//! - `A = min(max(P/2, p), P)` for shop and business, `U = D/4` for an api preset with an
//!   unlisted budget, and an unlisted payment of at most `P/2`.
//! - `1h = max(6, ceil(D/(8p)))` and `1m = min(60, max(2, ceil(1h/6)))`.
//! - `M = ceil₀.₁(reserve + (D/p)·c)`,
//!   `R = ceil₁(max(ceil₀.₁(M + T·(D/p)·c), M + 0.1))` in whole XLM, and
//!   `B = min(W·ceil(T/7), D·T)`, with `c` the fee cap per operation.
//!
//! [`policy_body`](crate::policy::v1::presets::policy_body) writes the
//! unsigned `version = 2` body of a derivation,
//! [`summarize`](crate::policy::v1::presets::summarize) reads the spending
//! bounds of any policy body, and [`plan`](crate::policy::v1::presets::plan)
//! states the funding plan of a derivation.
//!
//! ```
//! use stellar_agent_core::policy::v1::presets::{
//!     AuthorityStatus, PresetAsset, PresetInput, derive, find_preset, plan, policy_body,
//!     summarize,
//! };
//! use stellar_agent_core::policy::v1::validate_unsigned_policy;
//! use stellar_agent_core::profile::caip2::MAINNET_PASSPHRASE;
//!
//! let derived = derive(&PresetInput {
//!     preset: find_preset("api-week").unwrap(),
//!     asset: PresetAsset::Usdc { issuer: "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN".into() },
//!     tolerated_loss_stroops: None,
//!     typical_payment_stroops: None,
//!     unlisted_budget: true,
//!     total_budget: true,
//! })
//! .unwrap();
//! assert_eq!(derived.daily_cap_stroops, 50_000_000);
//! assert_eq!(derived.calls_per_hour, 63);
//!
//! let body = policy_body("agent", &derived);
//! assert!(validate_unsigned_policy(&body, "agent", MAINNET_PASSPHRASE).is_ok());
//!
//! let summary = summarize(&body.parse().unwrap(), MAINNET_PASSPHRASE, AuthorityStatus::Draft);
//! assert_eq!(summary.limits[0].per_tx_cap.as_deref(), Some("0.5"));
//! assert_eq!(summary.limits[0].period_caps[1].window, "1w");
//! assert_eq!(summary.limits[0].period_caps[1].amount.as_deref(), Some("20"));
//! assert_eq!(plan(&derived).recommended_balance_xlm, "6");
//! ```

use super::asset_equivalence::assets_equivalent;
use super::criteria::counterparty_allowlist::destination_form;
use super::criteria::per_period_cap::Window;
use super::mainnet_minimum::{
    MAINNET_CLAIM_TOOLS, MAINNET_READ_ONLY_TOOLS, MAINNET_TRUSTLINE_TOOLS, MAINNET_VALUE_OUT_TOOLS,
};
use super::value::asset_normalise;
use crate::profile::caip2::Caip2;
use serde::Serialize;
use toml_edit::{DocumentMut, InlineTable, Item, Value};

/// Stroops in one unit of an asset.
const STROOPS_PER_UNIT: i128 = 10_000_000;

/// The fee cap of a preset, in stroops per classic operation: 100 times the
/// 100-stroop minimum base fee.
pub const PRESET_FEE_PER_OPERATION_STROOPS: i128 = 10_000;

/// The protocol minimum of a USDC operating account, in stroops: the account
/// and one trustline at the 0.5 XLM base reserve.
const USDC_RESERVE_STROOPS: i128 = 15_000_000;

/// The protocol minimum of an XLM operating account, in stroops: the account
/// at the 0.5 XLM base reserve.
const NATIVE_RESERVE_STROOPS: i128 = 10_000_000;

/// The preset that applies when the operator names none: the first preset.
pub const DEFAULT_PRESET: &str = PRESETS[0].name;

const MAINNET_CHAIN: &str = "stellar:mainnet";

/// The rounding step of the floor: 0.1 XLM.
const TENTH_XLM_STROOPS: i128 = 1_000_000;

/// The rounding step of the recommended balance: 1 XLM.
const WHOLE_XLM_STROOPS: i128 = STROOPS_PER_UNIT;

const AUXILIARY_PER_MINUTE: u32 = 2;
const AUXILIARY_PER_HOUR: u32 = 6;

/// The payment tools of a generated body, in rule order.
const PAYMENT_TOOLS: [&str; 4] = [
    "stellar_pay",
    "stellar_pay_commit",
    "stellar_x402_create_payment",
    "stellar_x402_authenticated_payment",
];

/// The payment tools whose rules carry the balance floor. The x402 tools
/// evaluate without an account view, so a floor there denies every call.
const FLOOR_TOOLS: [&str; 2] = ["stellar_pay", "stellar_pay_commit"];

/// The x402 tools, which evaluate without an account view.
const X402_TOOLS: [&str; 2] = [
    "stellar_x402_create_payment",
    "stellar_x402_authenticated_payment",
];

/// The kind of agent a preset serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Archetype {
    /// Paid API and data requests.
    Api,
    /// Inference or compute.
    Compute,
    /// Shopping.
    Shop,
    /// Business workflows.
    Business,
}

impl Archetype {
    /// The fraction `f` of the 1d cap one payment may take, as numerator
    /// and denominator: 1/10, 1/4, 1/1, and 1/2.
    const fn fraction(self) -> (i128, i128) {
        match self {
            Self::Api => (1, 10),
            Self::Compute => (1, 4),
            Self::Shop => (1, 1),
            Self::Business => (1, 2),
        }
    }

    /// Whether payments above half the per-payment cap request approval.
    const fn requires_approval(self) -> bool {
        matches!(self, Self::Shop | Self::Business)
    }

    /// Whether the archetype offers a budget for unlisted recipients.
    const fn offers_unlisted_budget(self) -> bool {
        matches!(self, Self::Api)
    }
}

/// One named preset. Amounts are in stroops of USDC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PresetSpec {
    /// The preset name, such as `api-week`.
    pub name: &'static str,
    /// The archetype, which fixes `f`, the approval threshold, and the
    /// unlisted option.
    pub archetype: Archetype,
    /// The tolerated loss `L` over the unattended period.
    pub tolerated_loss_stroops: i128,
    /// The unattended days `T`.
    pub unattended_days: u32,
    /// The typical payment `p`.
    pub typical_payment_stroops: i128,
    /// The rounding quantum `q` of the 1d cap.
    pub daily_quantum_stroops: i128,
}

/// A preset whose loss, typical payment, and quantum are given in hundredths
/// of a unit.
const fn spec(
    name: &'static str,
    archetype: Archetype,
    loss_hundredths: i128,
    unattended_days: u32,
    typical_hundredths: i128,
    quantum_hundredths: i128,
) -> PresetSpec {
    const HUNDREDTH: i128 = STROOPS_PER_UNIT / 100;
    PresetSpec {
        name,
        archetype,
        tolerated_loss_stroops: loss_hundredths * HUNDREDTH,
        unattended_days,
        typical_payment_stroops: typical_hundredths * HUNDREDTH,
        daily_quantum_stroops: quantum_hundredths * HUNDREDTH,
    }
}

/// The twelve presets, in archetype order, each with a 1-day, 7-day, and
/// 14-day period.
pub const PRESETS: [PresetSpec; 12] = [
    spec("api-day", Archetype::Api, 200, 1, 1, 100),
    spec("api-week", Archetype::Api, 2_000, 7, 1, 100),
    spec("api-2weeks", Archetype::Api, 5_000, 14, 1, 100),
    spec("compute-day", Archetype::Compute, 2_000, 1, 1, 1_000),
    spec("compute-week", Archetype::Compute, 12_000, 7, 1, 1_000),
    spec("compute-2weeks", Archetype::Compute, 30_000, 14, 1, 1_000),
    spec("shop-day", Archetype::Shop, 5_000, 1, 2_500, 100),
    spec("shop-week", Archetype::Shop, 50_000, 7, 2_500, 2_000),
    spec("shop-2weeks", Archetype::Shop, 100_000, 14, 2_500, 2_000),
    spec("business-day", Archetype::Business, 40_000, 1, 10_000, 100),
    spec(
        "business-week",
        Archetype::Business,
        200_000,
        7,
        10_000,
        2_000,
    ),
    spec(
        "business-2weeks",
        Archetype::Business,
        500_000,
        14,
        10_000,
        2_000,
    ),
];

/// Returns the preset named `name`.
///
/// # Errors
/// Returns [`PresetError::Invalid`] naming the presets when no preset has
/// that name.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::policy::v1::presets::{DEFAULT_PRESET, find_preset};
///
/// assert_eq!(find_preset(DEFAULT_PRESET).unwrap().unattended_days, 1);
/// assert!(find_preset("api-month").is_err());
/// ```
pub fn find_preset(name: &str) -> Result<&'static PresetSpec, PresetError> {
    PRESETS
        .iter()
        .find(|spec| spec.name == name)
        .ok_or_else(|| {
            let names = PRESETS
                .iter()
                .map(|s| s.name)
                .collect::<Vec<_>>()
                .join(", ");
            PresetError::Invalid(format!("unknown preset {name}; presets: {names}"))
        })
}

/// Returns the preset that applies when the operator names none.
#[must_use]
pub fn default_preset() -> &'static PresetSpec {
    &PRESETS[0]
}

/// The asset a preset profile pays in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PresetAsset {
    /// USDC of the given issuer.
    Usdc {
        /// The issuer account, a G-strkey.
        issuer: String,
    },
    /// Native XLM.
    Native,
}

impl PresetAsset {
    /// The policy identity: `USDC:{issuer}` or `native`.
    fn policy_id(&self) -> String {
        match self {
            Self::Usdc { issuer } => format!("USDC:{issuer}"),
            Self::Native => "native".to_owned(),
        }
    }

    /// The code shown to the operator: `USDC` or `XLM`.
    const fn code(&self) -> &'static str {
        match self {
            Self::Usdc { .. } => "USDC",
            Self::Native => "XLM",
        }
    }

    /// The protocol minimum of the operating account, in stroops of XLM.
    const fn reserve_stroops(&self) -> i128 {
        match self {
            Self::Usdc { .. } => USDC_RESERVE_STROOPS,
            Self::Native => NATIVE_RESERVE_STROOPS,
        }
    }
}

/// The operator's preset choices.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresetInput {
    /// The chosen preset.
    pub preset: &'static PresetSpec,
    /// The payment asset.
    pub asset: PresetAsset,
    /// The tolerated loss in stroops of XLM; required for XLM and refused
    /// for USDC, whose presets fix it.
    pub tolerated_loss_stroops: Option<i128>,
    /// The typical payment in stroops of XLM; required for XLM and refused
    /// for USDC, whose presets fix it.
    pub typical_payment_stroops: Option<i128>,
    /// Whether the payment tools pay unlisted recipients from one shared
    /// budget; api presets only.
    pub unlisted_budget: bool,
    /// Whether the payment rules carry a non-renewing total budget of `L`.
    pub total_budget: bool,
}

/// A refused preset input.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PresetError {
    /// An input is malformed, out of range, or does not apply.
    #[error("{0}")]
    Invalid(String),
    /// A required input is missing.
    #[error("the {0} input is required")]
    InputRequired(&'static str),
}

impl PresetError {
    /// The wire code: `profile.preset_invalid` or
    /// `profile.preset_input_required`.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Invalid(_) => "profile.preset_invalid",
            Self::InputRequired(_) => "profile.preset_input_required",
        }
    }

    /// The process exit status of either refusal.
    #[must_use]
    pub const fn exit_code(&self) -> i32 {
        1
    }
}

/// Parses a positive decimal amount of at most seven decimals into stroops.
///
/// # Errors
/// Returns [`PresetError::Invalid`] for an empty or malformed amount, zero,
/// a sign, more than seven decimals, or more stroops than `i128` holds.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::policy::v1::presets::parse_amount;
///
/// assert_eq!(parse_amount("2.5").unwrap(), 25_000_000);
/// assert_eq!(parse_amount("0.0000001").unwrap(), 1);
/// assert!(parse_amount("0").is_err());
/// assert!(parse_amount("0.00000001").is_err());
/// ```
pub fn parse_amount(text: &str) -> Result<i128, PresetError> {
    let invalid = |why: &str| PresetError::Invalid(format!("amount {text:?} {why}"));
    let (whole, fraction) = match text.split_once('.') {
        Some((whole, fraction)) => (whole, fraction),
        None => (text, ""),
    };
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    if !digits(whole) || (text.contains('.') && !digits(fraction)) {
        return Err(invalid("must be a decimal number such as 12 or 0.5"));
    }
    if fraction.len() > 7 {
        return Err(invalid("has more than seven decimals"));
    }
    let overflow = || invalid("exceeds the largest representable amount");
    let mut stroops: i128 = 0;
    for byte in whole.bytes().chain(fraction.bytes()) {
        stroops = stroops
            .checked_mul(10)
            .and_then(|s| s.checked_add(i128::from(byte - b'0')))
            .ok_or_else(overflow)?;
    }
    for _ in fraction.len()..7 {
        stroops = stroops.checked_mul(10).ok_or_else(overflow)?;
    }
    if stroops == 0 {
        return Err(invalid("must be greater than zero"));
    }
    Ok(stroops)
}

/// The unlisted budget of an api preset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DerivedUnlisted {
    /// The largest unlisted payment, `P/2`, in stroops.
    pub per_payment_stroops: i128,
    /// The unlisted total per rolling day, `U = D/4`, in stroops.
    pub per_day_stroops: i128,
}

/// The limits a preset derivation produces. Amounts are in stroops of the
/// payment asset, except the XLM balances.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivedSpending {
    /// The preset derived from.
    pub preset: &'static PresetSpec,
    /// The payment asset.
    pub asset: PresetAsset,
    /// The tolerated loss `L`.
    pub tolerated_loss_stroops: i128,
    /// The unattended days `T`.
    pub unattended_days: u32,
    /// The typical payment `p`.
    pub typical_payment_stroops: i128,
    /// The 1w cap `W`.
    pub weekly_cap_stroops: i128,
    /// The 1d cap `D`.
    pub daily_cap_stroops: i128,
    /// The per-payment cap `P`.
    pub per_tx_cap_stroops: i128,
    /// The approval threshold `A`, for shop and business.
    pub approval_above_stroops: Option<i128>,
    /// The unlisted budget, when chosen.
    pub unlisted: Option<DerivedUnlisted>,
    /// The payment calls per rolling minute.
    pub calls_per_minute: u32,
    /// The payment calls per rolling hour.
    pub calls_per_hour: u32,
    /// The non-renewing total budget, `L` when chosen.
    pub total_budget_stroops: Option<i128>,
    /// The protocol minimum of the operating account, in stroops of XLM.
    pub reserve_stroops: i128,
    /// The fee cap `c`, in stroops of XLM per classic operation.
    pub fee_per_operation_stroops: i128,
    /// The balance floor `M`, in stroops of XLM.
    pub balance_floor_stroops: i128,
    /// The recommended balance `R`, in stroops of XLM: a whole number of XLM
    /// above `M`.
    pub recommended_balance_stroops: i128,
    /// The worst case over the period `B`, in stroops of the payment asset.
    pub worst_case_stroops: i128,
    /// The operating balance `O = L`, in stroops of the payment asset.
    pub operating_balance_stroops: i128,
}

fn overflow() -> PresetError {
    PresetError::Invalid("the preset amounts overflow the derivation".to_owned())
}

/// `ceil(numerator / denominator)` for a nonnegative numerator and a positive
/// denominator.
fn ceil_div(numerator: i128, denominator: i128) -> Result<i128, PresetError> {
    let quotient = numerator.checked_div(denominator).ok_or_else(overflow)?;
    if numerator.checked_rem(denominator).ok_or_else(overflow)? == 0 {
        Ok(quotient)
    } else {
        quotient.checked_add(1).ok_or_else(overflow)
    }
}

/// `numerator / denominator` rounded up to a multiple of 0.1 XLM.
fn ceil_tenth(numerator: i128, denominator: i128) -> Result<i128, PresetError> {
    let step = denominator
        .checked_mul(TENTH_XLM_STROOPS)
        .ok_or_else(overflow)?;
    ceil_div(numerator, step)?
        .checked_mul(TENTH_XLM_STROOPS)
        .ok_or_else(overflow)
}

fn mul(a: i128, b: i128) -> Result<i128, PresetError> {
    a.checked_mul(b).ok_or_else(overflow)
}

fn div(a: i128, b: i128) -> Result<i128, PresetError> {
    a.checked_div(b).ok_or_else(overflow)
}

fn add(a: i128, b: i128) -> Result<i128, PresetError> {
    a.checked_add(b).ok_or_else(overflow)
}

/// Refuses a derived limit of zero, naming it.
fn nonzero(value: i128, name: &str, asset: &PresetAsset) -> Result<i128, PresetError> {
    if value > 0 {
        Ok(value)
    } else {
        Err(PresetError::Invalid(format!(
            "the derived {name} is 0 {}; raise the tolerated loss",
            asset.code()
        )))
    }
}

fn calls(value: i128) -> Result<u32, PresetError> {
    u32::try_from(value).map_err(|_| overflow())
}

/// Derives the limits of a preset and the operator's choices.
///
/// USDC uses the preset's `L`, `p`, and `q`. XLM takes `L` and `p` from the
/// input, keeps the preset's `T` and `f`, and rounds caps down to one stroop.
///
/// The approval threshold of shop and business is the larger of half the
/// per-payment cap and the typical payment, and at most the per-payment cap:
/// `A = min(max(P/2, p), P)`, so a typical payment never needs approval.
///
/// # Errors
/// - [`PresetError::InputRequired`] when an XLM input lacks the tolerated
///   loss or the typical payment.
/// - [`PresetError::Invalid`] for an amount input on a USDC preset, an
///   unlisted budget on a preset other than api, a zero or negative amount,
///   an overflow, a derived `D`, `P`, `A`, `U`, or `P/2` of zero, or a
///   typical payment above `P`.
pub fn derive(input: &PresetInput) -> Result<DerivedSpending, PresetError> {
    let spec = input.preset;
    let archetype = spec.archetype;
    let asset = &input.asset;
    if input.unlisted_budget && !archetype.offers_unlisted_budget() {
        return Err(PresetError::Invalid(format!(
            "an unlisted budget applies to api presets only, not {}",
            spec.name
        )));
    }
    let (loss, typical, quantum) = match asset {
        PresetAsset::Usdc { .. } => {
            if input.tolerated_loss_stroops.is_some() || input.typical_payment_stroops.is_some() {
                return Err(PresetError::Invalid(
                    "a USDC preset fixes its tolerated loss and typical payment; \
                     these inputs apply to XLM only"
                        .to_owned(),
                ));
            }
            (
                spec.tolerated_loss_stroops,
                spec.typical_payment_stroops,
                spec.daily_quantum_stroops,
            )
        }
        PresetAsset::Native => (
            input
                .tolerated_loss_stroops
                .ok_or(PresetError::InputRequired("tolerated_loss"))?,
            input
                .typical_payment_stroops
                .ok_or(PresetError::InputRequired("typical_payment"))?,
            1,
        ),
    };
    for (value, name) in [(loss, "tolerated loss"), (typical, "typical payment")] {
        if value <= 0 {
            return Err(PresetError::Invalid(format!(
                "the {name} must be greater than zero"
            )));
        }
    }
    let days = i128::from(spec.unattended_days);
    if days == 0 || quantum <= 0 {
        return Err(PresetError::Invalid(format!(
            "preset {} has no unattended days or quantum",
            spec.name
        )));
    }
    let weeks = ceil_div(days, 7)?;
    let weekly = div(loss, weeks)?;
    // floor(min(W, 2L/T)/q) is the smaller of the two floors.
    let steps = div(weekly, quantum)?.min(div(mul(2, loss)?, mul(days, quantum)?)?);
    let daily = nonzero(mul(quantum, steps)?, "1d cap", asset)?;
    let (numerator, denominator) = archetype.fraction();
    let per_tx = nonzero(
        div(mul(daily, numerator)?, denominator)?,
        "per-payment cap",
        asset,
    )?;
    if typical > per_tx {
        return Err(PresetError::Invalid(format!(
            "the typical payment of {} {code} exceeds the per-payment cap of {} {code}",
            format_amount(typical),
            format_amount(per_tx),
            code = asset.code()
        )));
    }
    // The approval threshold is never below the typical payment, so a typical
    // payment pays unattended: A = min(max(P/2, p), P).
    let approval = if archetype.requires_approval() {
        let threshold = div(per_tx, 2)?.max(typical).min(per_tx);
        Some(nonzero(threshold, "approval threshold", asset)?)
    } else {
        None
    };
    let unlisted = if input.unlisted_budget {
        Some(DerivedUnlisted {
            per_payment_stroops: nonzero(div(per_tx, 2)?, "unlisted per-payment cap", asset)?,
            per_day_stroops: nonzero(div(daily, 4)?, "unlisted 1d budget", asset)?,
        })
    } else {
        None
    };
    let per_hour = ceil_div(daily, mul(8, typical)?)?.max(6);
    let per_minute = ceil_div(per_hour, 6)?.clamp(2, 60);
    let fee = PRESET_FEE_PER_OPERATION_STROOPS;
    let reserve = asset.reserve_stroops();
    // One day of fees is (D/p)·c; both bounds keep the denominator p exact.
    let daily_fees = mul(daily, fee)?;
    let floor = ceil_tenth(add(mul(reserve, typical)?, daily_fees)?, typical)?;
    // R starts from the rounded floor, then rounds up to whole XLM.
    let tenths = ceil_tenth(add(mul(floor, typical)?, mul(days, daily_fees)?)?, typical)?
        .max(add(floor, TENTH_XLM_STROOPS)?);
    let recommended = mul(ceil_div(tenths, WHOLE_XLM_STROOPS)?, WHOLE_XLM_STROOPS)?;
    let worst_case = mul(weekly, weeks)?.min(mul(daily, days)?);
    Ok(DerivedSpending {
        preset: spec,
        asset: asset.clone(),
        tolerated_loss_stroops: loss,
        unattended_days: spec.unattended_days,
        typical_payment_stroops: typical,
        weekly_cap_stroops: weekly,
        daily_cap_stroops: daily,
        per_tx_cap_stroops: per_tx,
        approval_above_stroops: approval,
        unlisted,
        calls_per_minute: calls(per_minute)?,
        calls_per_hour: calls(per_hour)?,
        total_budget_stroops: input.total_budget.then_some(loss),
        reserve_stroops: reserve,
        fee_per_operation_stroops: fee,
        balance_floor_stroops: floor,
        recommended_balance_stroops: recommended,
        worst_case_stroops: worst_case,
        operating_balance_stroops: loss,
    })
}

/// Formats stroops as a decimal amount without trailing zeros.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::policy::v1::presets::format_amount;
///
/// assert_eq!(format_amount(2_000_000), "0.2");
/// assert_eq!(format_amount(20_000_000), "2");
/// assert_eq!(format_amount(12_500_000), "1.25");
/// ```
#[must_use]
pub fn format_amount(stroops: i128) -> String {
    let sign = if stroops < 0 { "-" } else { "" };
    let magnitude = stroops.unsigned_abs();
    let unit = STROOPS_PER_UNIT.unsigned_abs();
    let whole = magnitude / unit;
    let fraction = magnitude % unit;
    if fraction == 0 {
        format!("{sign}{whole}")
    } else {
        let digits = format!("{fraction:07}");
        format!("{sign}{whole}.{}", digits.trim_end_matches('0'))
    }
}

fn toml_string(text: &str) -> String {
    Value::from(text).decorated("", "").to_string()
}

fn push_rule(body: &mut String, tool: &str, criteria: &[String]) {
    body.push_str("\n[[rules]]\n");
    body.push_str(&format!(
        "match = {{ tool = {}, chain = \"{MAINNET_CHAIN}\" }}\n",
        toml_string(tool)
    ));
    if criteria.is_empty() {
        body.push_str("criteria = []\n");
    } else {
        body.push_str("criteria = [\n");
        for criterion in criteria {
            body.push_str(&format!("    {criterion},\n"));
        }
        body.push_str("]\n");
    }
    body.push_str("decision = \"allow\"\nallow_opaque_signing = false\n");
}

fn rate_limits(per_minute: u32, per_hour: u32) -> [String; 2] {
    [
        format!("{{ kind = \"rate_limit\", window = \"1m\", max_calls = {per_minute} }}"),
        format!("{{ kind = \"rate_limit\", window = \"1h\", max_calls = {per_hour} }}"),
    ]
}

/// Writes the unsigned `version = 2` policy body of `derived` for the profile
/// `profile_name`.
///
/// The body holds `scope = "profile:{profile_name}"` and `sequence = 1`, no
/// `[mainnet]` table, and no comment. Every rule matches `stellar:mainnet`,
/// decides `allow`, and sets `allow_opaque_signing = false`:
///
/// - `stellar_pay`, `stellar_pay_commit`, and both x402 tools carry the asset
///   allowlist, the per-payment, 1d, and 1w caps, and the 1m and 1h rate
///   limits. Shop and business add the approval threshold when it is below
///   the per-payment cap, a chosen total budget adds `total_budget`, and the
///   two pay tools add the balance floor.
/// - Each payment rule's counterparty criterion selects `G_ACCOUNT` and
///   `C_ACCOUNT` with an empty allowlist, so G, M, and C recipients share one
///   list. No listed recipient is paid until one is added.
/// - A chosen unlisted budget writes the same `unlisted` table text on every
///   payment rule. Equal tables share one counter per asset, so one budget
///   bounds `stellar_pay`, `stellar_pay_commit`, and both x402 tools
///   together.
/// - The trustline tools of a USDC profile allow USDC alone; the claim tools
///   carry no asset allowlist. Both take 2 calls per 1m and 6 per 1h.
/// - The read-only tools carry no criterion. Native account funding, and the
///   trustline tools of an XLM profile, have no rule and deny by default.
#[must_use]
pub fn policy_body(profile_name: &str, derived: &DerivedSpending) -> String {
    let asset = toml_string(&derived.asset.policy_id());
    let amount = |stroops: i128| toml_string(&stroops.to_string());
    let mut body = format!(
        "version = 2\nscope = {}\nsequence = 1\n",
        toml_string(&format!("profile:{profile_name}"))
    );
    // One table text on every payment rule: the loader admits equal tables
    // only, and equal budget tables share one counter per asset.
    let unlisted = derived.unlisted.map_or_else(String::new, |budget| {
        format!(
            ", unlisted = {{ mode = \"budget\", asset = {asset}, window = \"1d\", \
             per_tx_stroops = {}, per_period_stroops = {} }}",
            amount(budget.per_payment_stroops),
            amount(budget.per_day_stroops)
        )
    });
    for tool in PAYMENT_TOOLS {
        let mut criteria = vec![format!(
            "{{ kind = \"asset_allowlist\", assets = [{asset}] }}"
        )];
        criteria.push(format!(
            "{{ kind = \"counterparty_allowlist\", kinds = [\"G_ACCOUNT\", \"C_ACCOUNT\"], \
             allowlist = []{unlisted} }}"
        ));
        criteria.push(format!(
            "{{ kind = \"per_tx_cap\", asset = {asset}, max_stroops = {} }}",
            amount(derived.per_tx_cap_stroops)
        ));
        // A threshold equal to the per-payment cap leaves no payment to
        // approve, and the loader takes a threshold only below the cap.
        if let Some(threshold) = derived
            .approval_above_stroops
            .filter(|a| *a < derived.per_tx_cap_stroops)
        {
            criteria.push(format!(
                "{{ kind = \"approval_above\", asset = {asset}, max_stroops = {} }}",
                amount(threshold)
            ));
        }
        for (window, cap) in [
            ("1d", derived.daily_cap_stroops),
            ("1w", derived.weekly_cap_stroops),
        ] {
            criteria.push(format!(
                "{{ kind = \"per_period_cap\", asset = {asset}, window = \"{window}\", max_stroops = {} }}",
                amount(cap)
            ));
        }
        if let Some(total) = derived.total_budget_stroops {
            criteria.push(format!(
                "{{ kind = \"total_budget\", asset = {asset}, max_stroops = {} }}",
                amount(total)
            ));
        }
        if FLOOR_TOOLS.contains(&tool) {
            criteria.push(format!(
                "{{ kind = \"balance_floor\", min_stroops = {} }}",
                amount(derived.balance_floor_stroops)
            ));
        }
        criteria.extend(rate_limits(
            derived.calls_per_minute,
            derived.calls_per_hour,
        ));
        push_rule(&mut body, tool, &criteria);
    }
    if matches!(derived.asset, PresetAsset::Usdc { .. }) {
        for tool in MAINNET_TRUSTLINE_TOOLS {
            let mut criteria = vec![format!(
                "{{ kind = \"asset_allowlist\", assets = [{asset}] }}"
            )];
            criteria.extend(rate_limits(AUXILIARY_PER_MINUTE, AUXILIARY_PER_HOUR));
            push_rule(&mut body, tool, &criteria);
        }
    }
    for tool in MAINNET_CLAIM_TOOLS {
        push_rule(
            &mut body,
            tool,
            &rate_limits(AUXILIARY_PER_MINUTE, AUXILIARY_PER_HOUR),
        );
    }
    for tool in MAINNET_READ_ONLY_TOOLS {
        push_rule(&mut body, tool, &[]);
    }
    body
}

/// Adds a recipient to lists selecting its destination kind. G and M join
/// `G_ACCOUNT` lists; C joins `C_ACCOUNT` lists. This is how the engine
/// classifies a destination. An M entry covers only its own mux id. A list that already
/// names it is unchanged. The result is an unsigned body; it takes effect
/// once the owner signs it.
///
/// # Errors
/// Returns [`PresetError::Invalid`] when `body` is not a policy body, when
/// `recipient` is not a G, M, or C address, or when no list of `body`
/// checks its kind.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::policy::v1::presets::{
///     PresetAsset, PresetInput, add_recipient, derive, find_preset, policy_body,
/// };
///
/// let issuer = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";
/// let derived = derive(&PresetInput {
///     preset: find_preset("shop-day").unwrap(),
///     asset: PresetAsset::Usdc { issuer: issuer.into() },
///     tolerated_loss_stroops: None,
///     typical_payment_stroops: None,
///     unlisted_budget: false,
///     total_budget: false,
/// })
/// .unwrap();
/// let recipient = "GAEQSCIJBEEQSCIJBEEQSCIJBEEQSCIJBEEQSCIJBEEQSCIJBEEQSH7S";
/// assert!(!policy_body("agent", &derived).contains(recipient));
/// let body = add_recipient(&policy_body("agent", &derived), recipient).unwrap();
/// assert!(body.contains(recipient));
/// ```
pub fn add_recipient(body: &str, recipient: &str) -> Result<String, PresetError> {
    let Some((kind, _)) = destination_form(recipient) else {
        return Err(PresetError::Invalid(format!(
            "recipient {recipient:?} is not a G, M, or C address"
        )));
    };
    let kind = kind.tag();
    let mut document: DocumentMut = body.parse().map_err(|error| {
        PresetError::Invalid(format!("the policy body does not parse: {error}"))
    })?;
    let mut lists = 0;
    let rules = document
        .get_mut("rules")
        .and_then(Item::as_array_of_tables_mut)
        .into_iter()
        .flat_map(|rules| rules.iter_mut());
    for rule in rules {
        let criteria = rule
            .get_mut("criteria")
            .and_then(Item::as_array_mut)
            .into_iter()
            .flat_map(|criteria| criteria.iter_mut())
            .filter_map(Value::as_inline_table_mut);
        for criterion in criteria {
            let checks = criterion.get("kind").and_then(Value::as_str)
                == Some("counterparty_allowlist")
                && criterion
                    .get("kinds")
                    .and_then(Value::as_array)
                    .is_some_and(|kinds| kinds.iter().any(|k| k.as_str() == Some(kind)));
            if !checks {
                continue;
            }
            let Some(list) = criterion.get_mut("allowlist").and_then(Value::as_array_mut) else {
                continue;
            };
            lists += 1;
            append_recipient(list, recipient);
        }
    }
    if lists == 0 {
        return Err(PresetError::Invalid(format!(
            "no counterparty list of the body checks {kind} recipients"
        )));
    }
    Ok(document.to_string())
}

fn append_recipient(list: &mut toml_edit::Array, recipient: &str) {
    if !list.iter().any(|entry| entry.as_str() == Some(recipient)) {
        list.push(recipient);
    }
}

/// The address gate and base address of a payment destination.
#[derive(Debug, PartialEq, Eq)]
pub struct RecipientForm {
    /// The address kind the destination requires.
    pub kind: &'static str,
    /// The underlying G or C address.
    pub base: String,
    /// Whether the destination is a W address.
    pub muxed_contract: bool,
}

/// Classifies G, M, C, and W payment destinations.
///
/// # Errors
/// Returns [`RecipientRefusal::Invalid`] for any other form without echoing it.
pub fn classify_recipient(recipient: &str) -> Result<RecipientForm, RecipientRefusal> {
    let (kind, base) = destination_form(recipient).ok_or(RecipientRefusal::Invalid)?;
    Ok(RecipientForm {
        kind: kind.tag(),
        base,
        muxed_contract: recipient.starts_with('W'),
    })
}

/// The effective consumers of one edited rule.
#[derive(Debug, PartialEq, Eq)]
pub struct RuleScope {
    /// The zero-based position in `rules`.
    pub rule: usize,
    /// The tools from the four mainnet lists, in list order.
    pub tools: Vec<String>,
    /// Whether the rule also matches tools outside those lists.
    pub wildcard: bool,
}

/// A recipient addition that requires an owner signature.
#[derive(Debug, PartialEq, Eq)]
pub struct RecipientAddition {
    /// The edited policy body.
    pub body: String,
    /// The destination's address kind.
    pub kind: &'static str,
    /// The sorted zero-based indexes of changed rules.
    pub updated_rules: Vec<usize>,
    /// The sorted rule indexes where the destination kind is appended.
    pub kinds_added: Vec<usize>,
    /// The sorted rule indexes where a domain criterion is split.
    pub split_rules: Vec<usize>,
    /// Every tool governed by each target rule.
    pub scope: Vec<RuleScope>,
    /// Selected tools whose effective rules have no address gate.
    pub ungated_tools: Vec<String>,
    /// Selected tools denied by their first match or without a match.
    pub denied_tools: Vec<String>,
}

/// An existing admission that needs no edit.
#[derive(Debug, PartialEq, Eq)]
pub struct RecipientListed {
    /// The destination's address kind.
    pub kind: &'static str,
    /// The exact entry, or the base when any list relies on it.
    pub covered_by: String,
    /// Every tool governed by each target rule.
    pub scope: Vec<RuleScope>,
    /// Selected tools whose effective rules have no address gate.
    pub ungated_tools: Vec<String>,
    /// Selected tools denied by their first match or without a match.
    pub denied_tools: Vec<String>,
}

/// The result of adding a payment destination.
#[derive(Debug, PartialEq, Eq)]
pub enum RecipientEdit {
    /// The owner must sign this body to admit the recipient.
    Added(RecipientAddition),
    /// Every target address list already covers the recipient.
    Listed(RecipientListed),
}

/// A refusal that leaves the body unchanged.
#[derive(Debug, PartialEq, Eq)]
pub enum RecipientRefusal {
    /// The destination is not a payment address.
    Invalid,
    /// The passphrase does not identify a known network.
    UnknownNetwork,
    /// The TOML body fails to parse at this byte position.
    Body(usize),
    /// No editable address list exists for the requested scope.
    ListMissing(String),
    /// The edit expands permissions beyond one recipient.
    Unsupported(String),
    /// The target lists or their consumers require a wider choice.
    Ambiguous(String),
    /// Appending the kind activates these other entries.
    KindConflict(String),
}

impl RecipientRefusal {
    /// The stable refusal code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Invalid => "profile.policy_recipient_invalid",
            Self::UnknownNetwork => "profile.policy_network_unknown",
            Self::Body(_) => "profile.policy_body_invalid",
            Self::ListMissing(_) => "profile.policy_recipient_list_missing",
            Self::Unsupported(_) => "profile.policy_recipient_list_unsupported",
            Self::Ambiguous(_) => "profile.policy_counterparty_ambiguous",
            Self::KindConflict(_) => "profile.policy_recipient_kind_conflict",
        }
    }
}

impl std::fmt::Display for RecipientRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid => f.write_str("the recipient must be a G, M, C, or W payment address"),
            Self::UnknownNetwork => f.write_str("the passphrase is not a known network"),
            Self::Body(position) => write!(f, "the policy body does not parse at byte {position}"),
            Self::ListMissing(detail)
            | Self::Unsupported(detail)
            | Self::Ambiguous(detail)
            | Self::KindConflict(detail) => f.write_str(detail),
        }
    }
}

fn selects(list: &InlineTable, kind: &str) -> bool {
    list.get("kinds")
        .and_then(Value::as_array)
        .is_some_and(|kinds| kinds.iter().any(|entry| entry.as_str() == Some(kind)))
}

fn recipient_entries(list: &InlineTable) -> impl Iterator<Item = &str> {
    list.get("allowlist")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
}

fn address_list(list: &InlineTable) -> bool {
    list.get("kind").and_then(Value::as_str) == Some("counterparty_allowlist")
        && (selects(list, "G_ACCOUNT") || selects(list, "C_ACCOUNT"))
}

fn listed_set(list: &InlineTable) -> std::collections::BTreeSet<&str> {
    recipient_entries(list)
        .filter(|entry| {
            destination_form(entry).is_some_and(|(kind, _)| selects(list, kind.tag()))
                || (selects(list, "KNOWN_ISSUER")
                    && stellar_strkey::ed25519::PublicKey::from_string(
                        entry.split_once(':').map_or(entry, |(_, issuer)| issuer),
                    )
                    .is_ok())
                || (selects(list, "HOME_DOMAIN") && destination_form(entry).is_none())
        })
        .collect()
}

/// Adds one recipient to every effective address list of the selected payment tools.
/// An empty selection covers all mainnet payment tools. The owner signs the resulting body.
///
/// # Errors
/// Refuses invalid input, absent lists, ambiguous scope, and permission changes beyond the named recipient.
pub fn add_payment_recipient(
    body: &str,
    network_passphrase: &str,
    recipient: &str,
    tools: &[&str],
) -> Result<RecipientEdit, RecipientRefusal> {
    let form = classify_recipient(recipient)?;
    let chain = Caip2::from_passphrase(network_passphrase)
        .ok_or(RecipientRefusal::UnknownNetwork)?
        .caip2_str();
    let document: DocumentMut = body.parse().map_err(|error: toml_edit::TomlError| {
        RecipientRefusal::Body(error.span().map_or(0, |span| span.start))
    })?;
    let rules = read_rules(&document);
    let targets = recipient_targets(&rules, chain, tools)?;
    let lists = target_recipient_lists(&rules, &targets)?;
    if let Some(covered_by) = recipient_coverage(&lists, &form, recipient) {
        return Ok(RecipientEdit::Listed(RecipientListed {
            kind: form.kind,
            covered_by,
            scope: targets.scope,
            ungated_tools: targets.ungated_tools,
            denied_tools: targets.denied_tools,
        }));
    }
    check_recipient_edit(&lists, &targets.scope, tools, &form, recipient)?;
    Ok(RecipientEdit::Added(apply_recipient_edit(
        document, targets, form.kind, recipient,
    )))
}

struct RecipientTargets {
    indexes: std::collections::BTreeSet<usize>,
    scope: Vec<RuleScope>,
    ungated_tools: Vec<String>,
    denied_tools: Vec<String>,
}

fn recipient_targets(
    rules: &[RuleView<'_>],
    chain: &str,
    tools: &[&str],
) -> Result<RecipientTargets, RecipientRefusal> {
    for tool in tools {
        if !MAINNET_VALUE_OUT_TOOLS.contains(tool) {
            return Err(RecipientRefusal::ListMissing(format!(
                "{tool} is not a payment tool"
            )));
        }
    }
    let selected: Vec<_> = MAINNET_VALUE_OUT_TOOLS
        .iter()
        .copied()
        .filter(|tool| tools.is_empty() || tools.contains(tool))
        .collect();
    let mut targets = std::collections::BTreeSet::new();
    let mut ungated_tools = Vec::new();
    let mut denied_tools = Vec::new();
    for tool in &selected {
        let editable =
            first_match(rules, tool, chain).filter(|index| rules[*index].decision != "deny");
        let Some(index) = editable else {
            if !tools.is_empty() {
                return Err(RecipientRefusal::ListMissing(format!(
                    "{tool} has no editable rule"
                )));
            }
            denied_tools.push((*tool).to_owned());
            continue;
        };
        if !rules[index].criteria.iter().any(|list| address_list(list)) {
            ungated_tools.push((*tool).to_owned());
        }
        targets.insert(index);
    }
    let scope: Vec<_> = targets
        .iter()
        .map(|index| RuleScope {
            rule: *index,
            tools: MAINNET_READ_ONLY_TOOLS
                .iter()
                .chain(MAINNET_VALUE_OUT_TOOLS)
                .chain(MAINNET_TRUSTLINE_TOOLS)
                .chain(MAINNET_CLAIM_TOOLS)
                .filter(|tool| first_match(rules, tool, chain) == Some(*index))
                .map(|tool| (*tool).to_owned())
                .collect(),
            wildcard: rules[*index].tool == "*",
        })
        .collect();
    Ok(RecipientTargets {
        indexes: targets,
        scope,
        ungated_tools,
        denied_tools,
    })
}

fn target_recipient_lists<'a>(
    rules: &[RuleView<'a>],
    targets: &RecipientTargets,
) -> Result<Vec<(usize, &'a InlineTable)>, RecipientRefusal> {
    let lists: Vec<_> = targets
        .indexes
        .iter()
        .flat_map(|index| {
            rules[*index]
                .criteria
                .iter()
                .filter(|list| address_list(list))
                .map(move |list| (*index, *list))
        })
        .collect();
    if lists.is_empty() {
        return Err(RecipientRefusal::ListMissing(
            "no target rule has an address list; a new list adds a gate for every current recipient".into(),
        ));
    }
    for (index, list) in &lists {
        if selects(list, "SEP10_IDENTITY") || selects(list, "ONE_TIME_ADDRESS") {
            return Err(RecipientRefusal::Unsupported(format!(
                "rule {index} selects a reserved kind that denies every call"
            )));
        }
    }
    Ok(lists)
}

/// Coverage and kind conflict are disjoint because coverage requires every list to select the recipient's kind.
fn recipient_coverage(
    lists: &[(usize, &InlineTable)],
    form: &RecipientForm,
    recipient: &str,
) -> Option<String> {
    if lists.iter().all(|(_, list)| {
        selects(list, form.kind)
            && recipient_entries(list).any(|entry| entry == recipient || entry == form.base)
    }) {
        let exact = lists
            .iter()
            .all(|(_, list)| recipient_entries(list).any(|entry| entry == recipient));
        Some(if exact {
            recipient.to_owned()
        } else {
            form.base.clone()
        })
    } else {
        None
    }
}

fn check_recipient_edit(
    lists: &[(usize, &InlineTable)],
    scope: &[RuleScope],
    tools: &[&str],
    form: &RecipientForm,
    recipient: &str,
) -> Result<(), RecipientRefusal> {
    if !tools.is_empty() {
        for consumer in scope {
            if consumer.wildcard
                || consumer
                    .tools
                    .iter()
                    .any(|tool| !tools.contains(&tool.as_str()))
            {
                let payment = consumer
                    .tools
                    .iter()
                    .filter(|tool| {
                        MAINNET_VALUE_OUT_TOOLS.contains(&tool.as_str())
                            && !tools.contains(&tool.as_str())
                    })
                    .map(String::as_str)
                    .collect::<Vec<_>>()
                    .join(", ");
                let payment = if payment.is_empty() {
                    String::new()
                } else {
                    format!(" Select these payment tools too: {payment}.")
                };
                return Err(RecipientRefusal::Ambiguous(format!(
                    "rule {} shares its list.{payment} {}Supply an empty selection to accept its full scope.",
                    consumer.rule,
                    if consumer.wildcard {
                        "The rule governs every tool without an earlier match, including non-payment tools. "
                    } else {
                        ""
                    },
                )));
            }
        }
    }
    let expected = listed_set(lists[0].1);
    if lists.iter().any(|(_, list)| listed_set(list) != expected) {
        let detail = lists
            .iter()
            .map(|(index, list)| {
                let tools = scope
                    .iter()
                    .find(|scope| scope.rule == *index)
                    .map(|scope| scope.tools.join(", "))
                    .unwrap_or_default();
                format!("{tools}: {:?}", listed_set(list))
            })
            .collect::<Vec<_>>()
            .join("; ");
        return Err(RecipientRefusal::Ambiguous(format!(
            "the target lists differ: {detail}. One recipient joins a list the owner keeps narrower. Supply a selection whose target lists hold the same entries."
        )));
    }
    for (index, list) in lists {
        if selects(list, "KNOWN_ISSUER")
            && recipient.starts_with('G')
            && !recipient_entries(list).any(|entry| {
                entry == recipient
                    || entry
                        .split_once(':')
                        .is_some_and(|(_, issuer)| issuer == recipient)
            })
        {
            return Err(RecipientRefusal::Unsupported(format!(
                "rule {index}: payments in assets issued by this G become allowed for every recipient the rule pays. \
                 Use a list for the recipient without KNOWN_ISSUER, or a hand edit signed with profile sign-policy."
            )));
        }
        if !selects(list, form.kind) {
            let activated: Vec<_> = recipient_entries(list)
                .filter(|entry| {
                    *entry != recipient
                        && destination_form(entry).is_some_and(|(kind, _)| kind.tag() == form.kind)
                })
                .collect();
            if !activated.is_empty() {
                return Err(RecipientRefusal::KindConflict(format!(
                    "rule {index}: appending {} also lists {}; these entries leave their unlisted budget or approval path",
                    form.kind,
                    activated.join(", ")
                )));
            }
        }
        if selects(list, "HOME_DOMAIN") && list.contains_key("unlisted") {
            return Err(RecipientRefusal::Unsupported(format!(
                "rule {index}: the unlisted mode applies to the merged address and domain outcome. \
                 After a split it applies to the address check alone."
            )));
        }
    }
    Ok(())
}

fn split_domain_list(
    list: &mut InlineTable,
    kind: &str,
    recipient: &str,
    missing_kind: bool,
) -> InlineTable {
    let mut address_kinds = toml_edit::Array::new();
    if let Some(kinds) = list.get_mut("kinds").and_then(Value::as_array_mut) {
        for kind in kinds
            .iter()
            .filter(|kind| matches!(kind.as_str(), Some("G_ACCOUNT" | "C_ACCOUNT")))
        {
            address_kinds.push(kind.clone());
        }
        kinds.retain(|kind| !matches!(kind.as_str(), Some("G_ACCOUNT" | "C_ACCOUNT")));
    }
    if missing_kind {
        address_kinds.push(kind);
    }
    let mut address = InlineTable::new();
    address.insert("kind", "counterparty_allowlist".into());
    address.insert("kinds", address_kinds.into());
    address.insert("allowlist", Value::from_iter([recipient]));
    address
}

fn apply_recipient_edit(
    mut document: DocumentMut,
    targets: RecipientTargets,
    kind: &'static str,
    recipient: &str,
) -> RecipientAddition {
    let mut updated_rules = Vec::new();
    let mut kinds_added = Vec::new();
    let mut split_rules = Vec::new();
    if let Some(rules) = document
        .get_mut("rules")
        .and_then(Item::as_array_of_tables_mut)
    {
        for index in targets.indexes {
            let Some(criteria) = rules
                .get_mut(index)
                .and_then(|rule| rule.get_mut("criteria"))
                .and_then(Item::as_array_mut)
            else {
                continue;
            };
            let mut position = 0;
            while position < criteria.len() {
                let Some(list) = criteria
                    .get_mut(position)
                    .and_then(Value::as_inline_table_mut)
                    .filter(|list| address_list(list))
                else {
                    position += 1;
                    continue;
                };
                let missing_kind = !selects(list, kind);
                let split = selects(list, "HOME_DOMAIN");
                let changed = missing_kind
                    || split
                    || !recipient_entries(list).any(|entry| entry == recipient);
                if changed && !updated_rules.contains(&index) {
                    updated_rules.push(index);
                }
                if missing_kind && !kinds_added.contains(&index) {
                    kinds_added.push(index);
                }
                if split {
                    let address = split_domain_list(list, kind, recipient, missing_kind);
                    criteria.insert(position + 1, address);
                    if !split_rules.contains(&index) {
                        split_rules.push(index);
                    }
                    position += 1;
                } else {
                    if missing_kind
                        && let Some(kinds) = list.get_mut("kinds").and_then(Value::as_array_mut)
                    {
                        kinds.push(kind);
                    }
                    if let Some(entries) = list.get_mut("allowlist").and_then(Value::as_array_mut) {
                        append_recipient(entries, recipient);
                    }
                }
                position += 1;
            }
        }
    }
    RecipientAddition {
        body: document.to_string(),
        kind,
        updated_rules,
        kinds_added,
        split_rules,
        scope: targets.scope,
        ungated_tools: targets.ungated_tools,
        denied_tools: targets.denied_tools,
    }
}

/// What the owner's signature status of a summarized body is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityStatus {
    /// A generated body that no owner has signed.
    Draft,
    /// A body that takes effect only after the owner signs it.
    RequiresSignature,
    /// A body whose owner signature verified.
    Verified,
    /// A body whose verification failed or could not run.
    Unavailable,
}

/// Where the fee cap of a summarized body comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeCapStatus {
    /// The body has no `[mainnet]` table; enablement writes the preset cap.
    Planned,
    /// The body's `[mainnet]` table holds the cap.
    Signed,
}

/// A value the summary states once for several tools.
///
/// It serializes tagged, so no value of `T` reads as the marker: an agreed
/// value as `{"uniform": value}`, an agreed absence as `{"uniform": null}`,
/// and differing values as the string `"per_tool"`; the per-tool entries
/// then state each tool's value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Agreed<T> {
    /// Every contributing tool states this value; `None` when none states one.
    Uniform(Option<T>),
    /// The contributing tools state different values.
    PerTool,
}

impl<T: PartialEq> Agreed<T> {
    /// The agreed value of `values`, one per contributing tool.
    fn of(values: impl IntoIterator<Item = Option<T>>) -> Self {
        let mut values = values.into_iter();
        let Some(first) = values.next() else {
            return Self::Uniform(None);
        };
        if values.any(|value| value != first) {
            Self::PerTool
        } else {
            Self::Uniform(first)
        }
    }

    /// The value every contributing tool states, or `None` when none states
    /// one or the tools differ.
    #[must_use]
    pub fn uniform(&self) -> Option<&T> {
        match self {
            Self::Uniform(value) => value.as_ref(),
            Self::PerTool => None,
        }
    }
}

impl Agreed<String> {
    /// [`Agreed::uniform`] as a string slice.
    #[must_use]
    pub fn as_deref(&self) -> Option<&str> {
        self.uniform().map(String::as_str)
    }
}

/// How the evaluation treats a payment to one recipient.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Treatment {
    /// Admitted within the caps and the approval threshold.
    Allowed,
    /// Admitted within the unlisted budget and its per-payment cap.
    Budgeted,
    /// Admitted after an approval, at any amount within the caps.
    Approval,
    /// Admitted after an approval and within the unlisted budget.
    ApprovalWithinBudget,
    /// Denied at any amount.
    Denied,
}

impl Treatment {
    /// The unlisted mode that names this treatment of an address in no list.
    const fn unlisted_mode(self) -> &'static str {
        match self {
            Self::Allowed => "unrestricted",
            Self::Budgeted => "budget",
            Self::Approval => "approval",
            Self::ApprovalWithinBudget => "approval_within_budget",
            Self::Denied => "deny",
        }
    }
}

/// One recipient and its treatment by one tool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RecipientTreatment {
    /// The recipient address.
    pub recipient: String,
    /// What the tool's rule does with a payment to it.
    pub treatment: Treatment,
}

/// The limits one tool's effective rule sets for one asset. Amounts are
/// decimal strings in the asset; `null` marks an absent bound.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ToolLimits {
    /// The tool.
    pub tool: String,
    /// The decision of the tool's effective rule: `allow` or
    /// `require_approval`, which requires approval for every payment.
    pub decision: &'static str,
    /// The rule's per-payment cap.
    pub per_tx_cap: Option<String>,
    /// At most the largest single payment to a listed recipient the rule
    /// pays without the unlisted budget, or to any address under a rule
    /// without a counterparty criterion: the smallest of the per-payment cap
    /// and every amount counter's limit. `0` when no such recipient exists.
    pub largest_payment: Option<String>,
    /// At most the largest single payment through the unlisted budget or to
    /// an address in no list; when every such payment goes through the
    /// budget, also its per-payment bound and window cap. `0` when the rule
    /// pays no such recipient.
    pub unlisted_largest_payment: Option<String>,
    /// Every period cap of the rule, one per window, shortest window first.
    pub period_caps: Vec<PeriodCap>,
    /// Every rate limit of the rule, shortest window first.
    pub rate_caps: Vec<RateCap>,
    /// The non-renewing total until the next signature.
    pub total_budget: Option<String>,
    /// The amount above which a payment requests approval.
    pub approval_above: Option<String>,
    /// At most what this tool alone pays without approval in each window of
    /// the asset, and in `total` until the next signature, to the recipients
    /// of `largest_payment`. When it pays one, it is also at most what it
    /// pays every recipient together. Only payments the evaluation allows
    /// count; a payment that requests approval never does. `0` when no such
    /// recipient is paid with `allow`, `null` for no bound.
    pub bounds: Vec<PeriodBound>,
    /// At most what this tool alone pays without approval through the
    /// unlisted budget and to addresses in no list, per window. `0` when the
    /// rule pays neither with `allow`.
    pub unlisted_bounds: Vec<PeriodBound>,
    /// The criterion kinds and shapes of the rule the bounds do not model;
    /// each marks the tool's bounds as not known to be reachable.
    pub unmodeled_criteria: Vec<String>,
    /// How the tool treats an address in no list: `deny`, `approval`,
    /// `budget`, `approval_within_budget`, or `unrestricted` when its rule
    /// carries no counterparty criterion and allows.
    pub unlisted_mode: &'static str,
    /// The largest payment the rule's unlisted budget admits; it bounds every
    /// recipient treated as budgeted. `null` without a budget.
    pub unlisted_per_tx_cap: Option<String>,
    /// The rule's unlisted budget per window. `null` without a budget.
    pub unlisted_period_cap: Option<PeriodCap>,
    /// `deny` when the rule carries an unlisted budget, the decision once it
    /// is spent; `unbudgeted` otherwise.
    pub unlisted_exhaustion: &'static str,
    /// Every recipient a payment rule lists, with this tool's treatment.
    pub recipients: Vec<RecipientTreatment>,
    /// Whether the tool denies every call: an x402 rule with a balance floor,
    /// since x402 tools evaluate without an account view.
    pub denies_every_call: bool,
}

/// A cap over one rolling window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PeriodCap {
    /// The window: `1m`, `5m`, `1h`, `1d`, or `1w`.
    pub window: String,
    /// The cap.
    pub amount: String,
}

/// A rate limit of a rule over one rolling window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RateCap {
    /// The window: `1m`, `5m`, `1h`, `1d`, or `1w`.
    pub window: String,
    /// The calls the window admits.
    pub calls: u32,
    /// How many of the rule's criteria count each call in this window's
    /// shared bucket.
    pub writers: u32,
}

/// At most what one tool can pay without approval in one window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PeriodBound {
    /// A rolling window, or `total` for the time until the next signature.
    pub window: String,
    /// At most this amount; `null` for no bound.
    pub amount: Option<String>,
    /// Whether a sequence of payments the evaluation allows is known to pay
    /// exactly the amount, with the operating account funded above any
    /// floor. Otherwise the amount reads as "at most".
    pub reachable: bool,
}

/// One period cap of the asset, agreed over the tools that admit it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AgreedPeriodCap {
    /// The window.
    pub window: String,
    /// The cap, agreed over the tools; a tool without a cap in this window
    /// states none.
    pub amount: Agreed<String>,
}

/// A counter the evaluation keeps for the asset, shared by every tool whose
/// rule writes it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Counter {
    /// `amount` for a period cap, `total` for a total budget, `unlisted` for
    /// an unlisted budget, or `calls` for a rate limit.
    pub kind: &'static str,
    /// The bucket the counter is keyed by: the asset identifier as written,
    /// `unlisted:<identifier>`, or `rate_limit`.
    pub identifier: String,
    /// The window, or `total` for the total budget.
    pub window: String,
    /// The tools whose payments the counter counts.
    pub tools: Vec<String>,
    /// The limit each of those tools applies to it, in the asset or in
    /// calls, agreed over them.
    pub limit: Agreed<String>,
    /// How many criteria of each tool's rule write each payment to it,
    /// agreed over the tools.
    pub writers: Agreed<u32>,
}

/// At most what the asset can lose without approval in one window through
/// every tool together.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AssetBound {
    /// A rolling window, or `total` for the time until the next signature.
    pub window: String,
    /// At most this amount; `null` when some tool pays without a bound;
    /// `per_tool` when the tools' bounds differ within one counter or their
    /// counters overlap, and the per-tool bounds apply.
    pub amount: Agreed<String>,
    /// The counters that bind it, one per independent group of tools.
    pub counters: Vec<String>,
    /// Whether the amount is the sum over several separate counters of the
    /// asset.
    pub summed_over_counters: bool,
    /// Whether a sequence of payments the evaluation allows is known to pay
    /// exactly the amount. Otherwise the amount reads as "at most".
    pub reachable: bool,
}

/// The effective limits of one asset. Each aggregate holds a value only
/// when every tool in `tools` states it; amounts are decimal strings in the
/// asset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AssetLimits {
    /// The policy identity of the asset.
    pub asset: String,
    /// The identifiers the rules count the asset under; counters keyed by
    /// different identifiers are separate.
    pub identifiers: Vec<String>,
    /// Whether the asset is counted under more than one identifier.
    pub counted_under_several_identifiers: bool,
    /// The per-payment cap.
    pub per_tx_cap: Agreed<String>,
    /// At most the largest single payment to a listed recipient; see
    /// [`ToolLimits::largest_payment`].
    pub largest_payment: Agreed<String>,
    /// At most the largest single payment through the unlisted budget or to
    /// an address in no list, agreed over the tools that pay one; see
    /// [`ToolLimits::unlisted_largest_payment`].
    pub unlisted_largest_payment: Agreed<String>,
    /// Every window any tool caps, shortest first.
    pub period_caps: Vec<AgreedPeriodCap>,
    /// The non-renewing total until the next signature.
    pub total_budget: Agreed<String>,
    /// The amount above which a payment requests approval.
    pub approval_above: Agreed<String>,
    /// How the tools treat an address in no list; see
    /// [`ToolLimits::unlisted_mode`].
    pub unlisted_mode: Agreed<&'static str>,
    /// The tools that admit an address in no list.
    pub unlisted_tools: Vec<String>,
    /// The largest unlisted payment, agreed over `unlisted_tools`.
    pub unlisted_per_tx_cap: Agreed<String>,
    /// The unlisted budget per window, agreed over `unlisted_tools`.
    pub unlisted_period_cap: Agreed<PeriodCap>,
    /// Every counter the evaluation keeps for the asset.
    pub counters: Vec<Counter>,
    /// At most what the asset loses without approval in every window of the
    /// asset, and in `total`, to the recipients of [`ToolLimits::bounds`].
    /// When every paying tool pays such a recipient, it is also at most what
    /// every payment together loses.
    pub bounds: Vec<AssetBound>,
    /// At most what the asset loses without approval through the unlisted
    /// budget and to addresses in no list, per window.
    pub unlisted_bounds: Vec<AssetBound>,
    /// The limits of each tool whose effective rule admits the asset.
    pub tools: Vec<ToolLimits>,
}

/// The call limits of one tool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ToolRate {
    /// The tool.
    pub tool: String,
    /// Every rate limit of the tool's rule, shortest window first.
    pub limits: Vec<RateCap>,
}

/// The calls one window admits, agreed over the payment tools.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AgreedRate {
    /// The window.
    pub window: String,
    /// The calls, agreed over the payment tools; a tool without a limit in
    /// this window states none.
    pub calls: Agreed<u32>,
}

/// The payment call limits. Every tool counts against the same bucket per
/// window, and each tool's rule compares that count with its own limit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RateLimits {
    /// Every window a payment rule limits, shortest first.
    pub windows: Vec<AgreedRate>,
    /// Whether every tool counts against the same buckets; always `true`.
    pub shared_across_tools: bool,
    /// The limits of each payment tool.
    pub tools: Vec<ToolRate>,
}

/// The balance floor of one payment tool's rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ToolFloor {
    /// The tool.
    pub tool: String,
    /// The floor in XLM, the highest floor of the rule; `null` without one.
    pub floor_xlm: Option<String>,
}

/// One recipient a payment rule lists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ListedRecipient {
    /// The recipient address.
    pub recipient: String,
    /// Its treatment, agreed over every tool and asset; see
    /// [`ToolLimits::recipients`] when it differs.
    pub treatment: Agreed<Treatment>,
}

/// The call limits of one trustline or claim tool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuxiliaryRateLimit {
    /// The tool.
    pub tool: String,
    /// Every rate limit of the tool's rule, shortest window first.
    pub limits: Vec<RateCap>,
}

/// The recipients the payment rules admit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Recipients {
    /// The counterparty kinds checked.
    pub kinds: Vec<String>,
    /// Every recipient a payment rule lists, with its treatment.
    pub listed: Vec<ListedRecipient>,
    /// The tools whose rule carries no counterparty criterion and so admits
    /// every recipient.
    pub unrestricted_tools: Vec<String>,
    /// The tools for which no listed recipient exists yet: their lists name
    /// no recipient they pay, so they pay listed recipients nothing, and
    /// their listed bounds and largest payment are 0 until one is added.
    pub without_listed_recipient: Vec<String>,
}

/// The mainnet tools a body admits and the ones it denies by default.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ToolCoverage {
    /// Tools with an effective `allow` or `require_approval` rule.
    pub covered: Vec<String>,
    /// Tools without one, which the engine denies.
    pub uncovered: Vec<String>,
}

/// The spending bounds of a policy body. Every bound states at most what can
/// be spent: no sequence of payments the evaluation allows exceeds it. A
/// bound marked `reachable` is also spent exactly by some sequence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SpendingSummary {
    /// The signature status supplied by the caller.
    pub authority_status: AuthorityStatus,
    /// The body's `version`.
    pub policy_version: Option<i64>,
    /// The body's `sequence`.
    pub sequence: Option<i64>,
    /// The effective limits per asset.
    pub limits: Vec<AssetLimits>,
    /// What follows an exhausted unlisted budget, agreed over the tools that
    /// admit an address in no list; see [`ToolLimits::unlisted_exhaustion`].
    pub unlisted_exhaustion: Agreed<&'static str>,
    /// The payment rate limits.
    pub rate_limits: RateLimits,
    /// The trustline and claim rate limits.
    pub auxiliary_rate_limits: Vec<AuxiliaryRateLimit>,
    /// The fee cap in stroops per classic operation.
    pub classic_max_fee_per_op_stroops: Option<i64>,
    /// Where the fee cap comes from.
    pub fee_cap_status: FeeCapStatus,
    /// The fee cap in XLM, the maximum per classic operation. Soroban
    /// resource fees are outside it.
    pub max_fee_per_classic_operation_xlm: Option<String>,
    /// The balance floor in XLM, agreed over the payment tools whose rule
    /// carries one and that pay; see `balance_floors` when it differs.
    pub balance_floor_xlm: Agreed<String>,
    /// The balance floor of each payment tool.
    pub balance_floors: Vec<ToolFloor>,
    /// The admitted recipients.
    pub recipients: Recipients,
    /// The covered and uncovered mainnet tools.
    pub tools: ToolCoverage,
    /// Statements that hold for these bounds.
    pub notes: Vec<String>,
}

struct RuleView<'a> {
    tool: &'a str,
    chain: &'a str,
    decision: &'a str,
    criteria: Vec<&'a InlineTable>,
}

impl RuleView<'_> {
    fn of_kind<'b>(&'b self, kind: &'b str) -> impl Iterator<Item = &'b InlineTable> + 'b {
        self.criteria
            .iter()
            .copied()
            .filter(move |c| c.get("kind").and_then(Value::as_str) == Some(kind))
    }
}

fn read_rules(body: &DocumentMut) -> Vec<RuleView<'_>> {
    let Some(rules) = body.get("rules").and_then(Item::as_array_of_tables) else {
        return Vec::new();
    };
    rules
        .iter()
        .map(|rule| {
            let matcher = rule.get("match").and_then(Item::as_table_like);
            let field = |key: &str| {
                matcher
                    .and_then(|m| m.get(key))
                    .and_then(Item::as_str)
                    .unwrap_or("")
            };
            RuleView {
                tool: field("tool"),
                chain: field("chain"),
                decision: rule.get("decision").and_then(Item::as_str).unwrap_or(""),
                criteria: rule
                    .get("criteria")
                    .and_then(Item::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_inline_table)
                    .collect(),
            }
        })
        .collect()
}

/// The first rule matching `tool` on `chain`, the one the engine applies,
/// when it admits calls.
fn effective<'r, 'a>(
    rules: &'r [RuleView<'a>],
    tool: &str,
    chain: &str,
) -> Option<&'r RuleView<'a>> {
    first_match(rules, tool, chain)
        .map(|index| &rules[index])
        .filter(|rule| rule.decision != "deny")
}

fn first_match(rules: &[RuleView<'_>], tool: &str, chain: &str) -> Option<usize> {
    rules.iter().position(|rule| {
        (rule.tool == "*" || rule.tool == tool) && (rule.chain == "*" || rule.chain == chain)
    })
}

fn stroops_of(value: Option<&Value>) -> Option<i128> {
    match value? {
        Value::Integer(n) => Some(i128::from(*n.value())),
        Value::String(s) => s.value().parse().ok(),
        _ => None,
    }
}

fn calls_of(value: Option<&Value>) -> Option<u32> {
    value
        .and_then(Value::as_integer)
        .and_then(|n| u32::try_from(n).ok())
}

/// Every rate limit of a rule per window, shortest first: the tightest
/// limit and the number of criteria counting each call.
fn rule_rates(rule: &RuleView<'_>) -> Vec<RateCap> {
    let mut rates: Vec<(u64, RateCap)> = Vec::new();
    for c in rule.of_kind("rate_limit") {
        let window = c
            .get("window")
            .and_then(Value::as_str)
            .and_then(|w| Window::parse(w).ok());
        let (Some(window), Some(calls)) = (window, calls_of(c.get("max_calls"))) else {
            continue;
        };
        match rates.iter_mut().find(|(s, _)| *s == window.as_secs()) {
            Some((_, rate)) => {
                rate.calls = rate.calls.min(calls);
                rate.writers += 1;
            }
            None => rates.push((
                window.as_secs(),
                RateCap {
                    window: window.label().to_owned(),
                    calls,
                    writers: 1,
                },
            )),
        }
    }
    rates.sort_by_key(|(secs, _)| *secs);
    rates.into_iter().map(|(_, rate)| rate).collect()
}

fn min_present<T: Ord + Copy>(values: impl IntoIterator<Item = Option<T>>) -> Option<T> {
    values.into_iter().flatten().min()
}

/// The display code of a policy asset identity: `XLM` for native, else the
/// code before the issuer.
fn asset_code(asset: &str) -> &str {
    if asset == "native" {
        "XLM"
    } else {
        asset.split(':').next().unwrap_or(asset)
    }
}

/// What the counterparty criteria of a rule do with one recipient. Every
/// criterion applies: one that denies denies the call, one in `approval`
/// mode escalates it, and one in `budget` mode bounds it by the budget.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Flags {
    denied: bool,
    approval: bool,
    budgeted: bool,
}

impl Flags {
    const fn treatment(self) -> Treatment {
        match (self.denied, self.approval, self.budgeted) {
            (true, _, _) => Treatment::Denied,
            (false, true, true) => Treatment::ApprovalWithinBudget,
            (false, true, false) => Treatment::Approval,
            (false, false, true) => Treatment::Budgeted,
            (false, false, false) => Treatment::Allowed,
        }
    }
}

/// The window label of the total budget's counter, which never renews.
const TOTAL: &str = "total";

/// The bucket of the rate counters, shared by every tool's `rate_limit`.
const RATE_BUCKET: &str = "rate_limit";

/// The criterion kinds the bound computation models. Every other kind of a
/// payment rule marks the tool's bounds as not known to be reachable; an
/// unmodeled criterion can only refuse more, so each bound stays an upper
/// bound.
const fn modeled_criterion_kinds() -> &'static [&'static str] {
    &[
        "asset_allowlist",
        "per_tx_cap",
        "approval_above",
        "per_period_cap",
        "rate_limit",
        "counterparty_allowlist",
        "total_budget",
        "balance_floor",
    ]
}

/// The counterparty kinds the recipient model reads. They are alternatives:
/// a criterion lists a recipient when it selects the recipient's kind and
/// its allowlist holds the recipient or, for an M address, its base G.
const MODELED_COUNTERPARTY_KINDS: [&str; 2] = ["G_ACCOUNT", "C_ACCOUNT"];

/// Whether a list entry is a payment destination: a G, M, or C address, as
/// the engine classifies a destination.
fn is_address(entry: &str) -> bool {
    destination_form(entry).is_some()
}

/// The criterion kinds that make a recipient's class depend on a verified
/// domain, which the summary does not model.
const CLASS_CONDITION_KINDS: [&str; 1] = ["home_domain_resolved"];

/// A counter key as the evaluation builds it: the bucket and the window
/// (`total` for the total budget). `per_period_cap` keys the identifier as
/// written, with the native aliases normalized; `total_budget` keys
/// `total:<identifier>`; an unlisted budget keys `unlisted:<identifier>`;
/// every `rate_limit` shares the `rate_limit` bucket of its window.
type CounterKey = (String, &'static str);

/// What a counter counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CapKind {
    /// Stroops of the asset.
    Amount,
    /// Calls.
    Calls,
}

/// One counter a rule writes for the asset: its key, its window in seconds
/// (`None` for the total budget), the tightest limit its criteria apply,
/// and how many of the rule's criteria write each payment to it.
#[derive(Debug, Clone)]
struct CapView {
    key: CounterKey,
    secs: Option<u64>,
    limit: i128,
    writers: u32,
    kind: CapKind,
    /// The unlisted budget counts only payments to an address the budget's
    /// criterion does not list.
    unlisted_only: bool,
}

/// The recipient class of a bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Class {
    /// Recipients the rule lists and pays without the unlisted budget, and
    /// every address under a rule without a counterparty criterion.
    Listed,
    /// Payments through the unlisted budget, and to addresses in no list.
    Unlisted,
}

/// One tool's effective rule, read for one asset.
struct ToolView {
    tool: String,
    decision: &'static str,
    per_tx: Option<i128>,
    approval: Option<i128>,
    /// Every counter the rule writes for the asset.
    caps: Vec<CapView>,
    /// The criterion kinds and shapes of the rule the computation does not
    /// model.
    unmodeled: Vec<String>,
    /// The budget's per-payment bound and window cap, when the rule carries
    /// one for the asset.
    budget: Option<(Option<i128>, Option<PeriodCap>)>,
    /// An x402 rule with a floor denies every call.
    blocked: bool,
    /// The treatment of an address in no list.
    unlisted: Treatment,
    /// The treatment of each recipient any payment rule lists.
    recipients: Vec<(String, Treatment)>,
    /// The rule carries no counterparty criterion and pays every address.
    open: bool,
    /// The summary models which class a recipient falls in: every
    /// counterparty criterion lists addresses only, and no verified-domain
    /// condition applies.
    classified: bool,
}

impl ToolView {
    fn amount_caps(&self) -> impl Iterator<Item = &CapView> {
        self.caps
            .iter()
            .filter(|c| c.kind == CapKind::Amount && !c.unlisted_only)
    }

    fn total(&self) -> Option<i128> {
        self.amount_caps()
            .filter(|c| c.secs.is_none())
            .map(|c| c.limit)
            .min()
    }

    /// The tightest amount cap per window, shortest window first.
    fn period_caps(&self) -> Vec<(u64, &'static str, i128)> {
        let mut caps: Vec<(u64, &'static str, i128)> = Vec::new();
        for cap in self.amount_caps() {
            let Some(secs) = cap.secs else {
                continue;
            };
            match caps.iter_mut().find(|(s, _, _)| *s == secs) {
                Some(entry) => entry.2 = entry.2.min(cap.limit),
                None => caps.push((secs, cap.key.1, cap.limit)),
            }
        }
        caps.sort_by_key(|(secs, _, _)| *secs);
        caps
    }

    /// The rate counters of the rule, shortest window first.
    fn rate_caps(&self) -> Vec<RateCap> {
        let mut caps: Vec<&CapView> = self
            .caps
            .iter()
            .filter(|c| c.kind == CapKind::Calls)
            .collect();
        caps.sort_by_key(|c| c.secs);
        caps.into_iter()
            .map(|c| RateCap {
                window: c.key.1.to_owned(),
                calls: u32::try_from(c.limit).unwrap_or(u32::MAX),
                writers: c.writers,
            })
            .collect()
    }

    /// Whether every payment of the class goes through the unlisted budget:
    /// the class has a recipient and an address in no list is budgeted or
    /// denied. Without a modeled classification no payment is known to meet
    /// the budget.
    fn budgeted(&self, class: Class) -> bool {
        self.classified
            && class == Class::Unlisted
            && self.has_recipient(class)
            && matches!(
                self.unlisted,
                Treatment::Budgeted | Treatment::ApprovalWithinBudget | Treatment::Denied
            )
    }

    /// Whether some recipient of the class exists. The listed class holds a
    /// recipient the rule lists and pays without the unlisted budget, and
    /// every address under a rule without a counterparty criterion. The
    /// unlisted class holds a listed recipient the rule pays through the
    /// budget, and an address in no list the rule admits.
    fn has_recipient(&self, class: Class) -> bool {
        let named = |treatments: &[Treatment]| {
            self.recipients
                .iter()
                .any(|(recipient, t)| is_address(recipient) && treatments.contains(t))
        };
        match class {
            Class::Listed => self.open || named(&[Treatment::Allowed, Treatment::Approval]),
            Class::Unlisted => {
                self.unlisted != Treatment::Denied
                    || named(&[Treatment::Budgeted, Treatment::ApprovalWithinBudget])
            }
        }
    }

    /// Whether the tool pays any recipient of the class. Without a modeled
    /// classification any recipient may fall in either class.
    fn admits(&self, class: Class) -> bool {
        !self.blocked && (!self.classified || self.has_recipient(class))
    }

    /// Whether the tool pays some recipient of the class with `allow`: its
    /// rule allows, and the class holds a recipient no criterion escalates.
    /// Without a modeled classification any recipient may be one.
    fn pays_unattended(&self, class: Class) -> bool {
        let named = |treatment: Treatment| {
            self.recipients
                .iter()
                .any(|(recipient, t)| is_address(recipient) && *t == treatment)
        };
        self.decision == "allow"
            && !self.blocked
            && (!self.classified
                || match class {
                    Class::Listed => self.open || named(Treatment::Allowed),
                    Class::Unlisted => {
                        matches!(self.unlisted, Treatment::Allowed | Treatment::Budgeted)
                            || named(Treatment::Budgeted)
                    }
                })
    }

    /// The largest single payment to the class the evaluation allows
    /// without approval: the largest admitted payment, at most the approval
    /// threshold. `0` when the tool pays no recipient of the class with
    /// `allow`.
    fn unattended_largest(&self, class: Class) -> Option<i128> {
        if !self.pays_unattended(class) {
            return Some(0);
        }
        min_present([self.largest(class), self.approval])
    }

    /// The counters a payment to the class writes and must fit.
    fn class_caps(&self, class: Class) -> Vec<&CapView> {
        let budgeted = self.budgeted(class);
        self.caps
            .iter()
            .filter(|c| !c.unlisted_only || budgeted)
            .collect()
    }

    /// The largest single payment to the class: the smallest of the
    /// per-payment caps and of every amount counter's limit.
    fn largest(&self, class: Class) -> Option<i128> {
        if !self.admits(class) {
            return Some(0);
        }
        let budget_per_tx = if self.budgeted(class) {
            self.budget.as_ref().and_then(|(per_tx, _)| *per_tx)
        } else {
            None
        };
        min_present(
            [self.per_tx, budget_per_tx].into_iter().chain(
                self.class_caps(class)
                    .into_iter()
                    .filter(|c| c.kind == CapKind::Amount)
                    .map(|c| Some(c.limit)),
            ),
        )
    }

    /// At most what one counter admits in a window of `window` seconds
    /// (`None` for the time until the next signature).
    ///
    /// An amount counter written `m` times per payment admits a total `S`
    /// with `m·S_before + a ≤ L` for its last payment `a ≤ amax`, so `S` is at
    /// most `⌊(L − amax)/m⌋ + amax`; `L` when `m` is one. A call counter
    /// written `m` times admits `⌈N/m⌉` calls of at most `amax` each. A
    /// counter whose window covers the bound's applies once, a shorter one
    /// once per window that fits, and a renewing one bounds nothing over an
    /// unlimited time.
    fn cap_bound(cap: &CapView, window: Option<u64>, amax: Option<i128>) -> Option<i128> {
        let writers = i128::from(cap.writers.max(1));
        let once = match cap.kind {
            CapKind::Amount if writers == 1 => cap.limit,
            CapKind::Amount => match amax {
                Some(amax) => {
                    let last = amax.min(cap.limit).max(0);
                    (cap.limit - last) / writers + last
                }
                None => cap.limit,
            },
            CapKind::Calls => {
                let calls = (cap.limit + writers - 1) / writers;
                calls.checked_mul(amax?)?
            }
        };
        match (cap.secs, window) {
            (None, _) => Some(once),
            (Some(_), None) => None,
            (Some(secs), Some(window)) if secs >= window => Some(once),
            (Some(secs), Some(window)) => i128::from(window / secs).checked_mul(once),
        }
    }

    /// At most what this tool alone can pay the class in a window without
    /// approval: the tightest counter bound over payments the evaluation
    /// allows, `None` without one. Zero when it pays no recipient of the
    /// class with `allow`. A payment that requests approval never counts.
    fn bound(&self, class: Class, window: Option<u64>) -> Option<i128> {
        if !self.pays_unattended(class) {
            return Some(0);
        }
        let amax = self.unattended_largest(class);
        min_present(
            self.class_caps(class)
                .into_iter()
                .map(|cap| Self::cap_bound(cap, window, amax)),
        )
    }

    /// The counter that gives the tool's bound in the window: a counter
    /// covering the window first, shortest first, then a shorter one.
    fn binding_cap(&self, class: Class, window: Option<u64>) -> Option<&CapView> {
        let bound = self.bound(class, window)?;
        let amax = self.unattended_largest(class);
        let mut caps = self.class_caps(class);
        caps.sort_by_key(|c| {
            let covers = match (c.secs, window) {
                (None, _) => true,
                (Some(_), None) => false,
                (Some(secs), Some(window)) => secs >= window,
            };
            (!covers, c.secs.unwrap_or(u64::MAX))
        });
        caps.into_iter()
            .find(|cap| Self::cap_bound(cap, window, amax) == Some(bound))
    }

    /// Whether a sequence of payments the evaluation allows is known to
    /// spend exactly the bound. Every criterion is modeled, the class holds
    /// a recipient paid with `allow`, and a run over the counters reaches the
    /// bound within the window. The runs are the greedy one and the staged
    /// one. The staged run first pays up to the bound less the largest
    /// payment, then pays the largest payment. It reaches the bound
    /// `⌊(L − amax)/m⌋ + amax` of an amount counter written `m` times. A
    /// bound neither run reaches is not reachable.
    fn reachable(&self, class: Class, window: Option<u64>) -> bool {
        if !self.pays_unattended(class) {
            return true;
        }
        let (Some(bound), Some(amax)) = (self.bound(class, window), self.unattended_largest(class))
        else {
            return false;
        };
        let caps = self.class_caps(class);
        self.unmodeled.is_empty()
            && self.classified
            && (greedy_reaches(&caps, amax, bound, window, 0)
                || greedy_reaches(&caps, amax, bound, window, amax))
    }

    /// The tool's bounds for the class, one per window and one for `total`.
    ///
    /// A restriction enters a bound only when the summary models the
    /// condition under which the evaluation applies it. The unlisted budget,
    /// its per-payment cap, and every other restriction that attaches to a
    /// recipient class need a modeled classification: every counterparty
    /// criterion of the rule lists addresses only (`G_ACCOUNT`, `C_ACCOUNT`)
    /// and no verified-domain condition applies. Otherwise the bounds of both
    /// classes take only the restrictions that hold for every recipient, are
    /// not reachable, and `unmodeled_criteria` names the cause. A classified
    /// class without a recipient, such as an empty list under a mode that
    /// denies or escalates, has the bound 0, reachable by paying nothing.
    fn class_bounds(&self, class: Class, windows: &[(u64, &'static str)]) -> Vec<PeriodBound> {
        windows
            .iter()
            .map(|(secs, label)| (Some(*secs), *label))
            .chain([(None, TOTAL)])
            .map(|(secs, label)| PeriodBound {
                window: label.to_owned(),
                amount: amount_string(self.bound(class, secs)),
                reachable: self.reachable(class, secs),
            })
            .collect()
    }

    fn limits(&self, windows: &[(u64, &'static str)]) -> ToolLimits {
        let budget = self.budget.clone();
        ToolLimits {
            tool: self.tool.clone(),
            decision: self.decision,
            per_tx_cap: amount_string(self.per_tx),
            largest_payment: amount_string(self.largest(Class::Listed)),
            unlisted_largest_payment: amount_string(self.largest(Class::Unlisted)),
            period_caps: self
                .period_caps()
                .into_iter()
                .map(|(_, window, limit)| PeriodCap {
                    window: window.to_owned(),
                    amount: format_amount(limit),
                })
                .collect(),
            rate_caps: self.rate_caps(),
            total_budget: amount_string(self.total()),
            approval_above: amount_string(self.approval),
            bounds: self.class_bounds(Class::Listed, windows),
            unlisted_bounds: self.class_bounds(Class::Unlisted, windows),
            unmodeled_criteria: self.unmodeled.clone(),
            unlisted_mode: self.unlisted.unlisted_mode(),
            unlisted_per_tx_cap: amount_string(budget.as_ref().and_then(|(per_tx, _)| *per_tx)),
            unlisted_period_cap: budget.as_ref().and_then(|(_, cap)| cap.clone()),
            unlisted_exhaustion: if budget.is_some() {
                "deny"
            } else {
                "unbudgeted"
            },
            recipients: self
                .recipients
                .iter()
                .map(|(recipient, treatment)| RecipientTreatment {
                    recipient: recipient.clone(),
                    treatment: *treatment,
                })
                .collect(),
            denies_every_call: self.blocked,
        }
    }
}

/// Whether paying greedily, the largest amount every counter admits at each
/// instant and waiting for the earliest counter to free otherwise, spends
/// exactly `target` within one closed `window` of seconds (`None` for no
/// limit). The run follows the evaluation's counters: an amount counter
/// written `m` times admits `a` while `m·sum + a ≤ L`, a call counter admits a
/// call while `m·calls < N`, and a window holds the payments at most its
/// length old. With a positive `reserve`, the run first pays greedily up to
/// `target − reserve` and then on to `target`; when it can pay nothing more
/// below that stage, it goes on to `target`.
fn greedy_reaches(
    caps: &[&CapView],
    amax: i128,
    target: i128,
    window: Option<u64>,
    reserve: i128,
) -> bool {
    if target == 0 {
        return true;
    }
    if amax <= 0 {
        return false;
    }
    let span = |cap: &CapView| cap.secs.map(|secs| secs.saturating_mul(1_000));
    let limit_ms = window.map(|secs| secs.saturating_mul(1_000));
    let mut payments: Vec<(u64, i128)> = Vec::new();
    let mut spent: i128 = 0;
    let mut now: u64 = 0;
    let mut stage = (target - reserve).max(0);
    for _ in 0..200_000 {
        let goal = if spent < stage { stage } else { target };
        let mut amount = (goal - spent).min(amax);
        let mut wait: Option<u64> = None;
        let mut stuck = false;
        for cap in caps {
            let cap_span = span(cap);
            let live = payments
                .iter()
                .filter(|(t, _)| cap_span.is_none_or(|s| t.saturating_add(s) >= now));
            let writers = i128::from(cap.writers.max(1));
            let room = match cap.kind {
                CapKind::Amount => cap.limit - writers * live.clone().map(|(_, a)| a).sum::<i128>(),
                CapKind::Calls => {
                    let calls = i128::try_from(live.clone().count()).unwrap_or(i128::MAX);
                    if writers.saturating_mul(calls) < cap.limit {
                        i128::MAX
                    } else {
                        0
                    }
                }
            };
            amount = amount.min(room.max(0));
            if room <= 0 {
                match (cap_span, live.map(|(t, _)| *t).min()) {
                    (Some(s), Some(first)) => {
                        let free = first.saturating_add(s).saturating_add(1);
                        wait = Some(wait.map_or(free, |w| w.min(free)));
                    }
                    _ => stuck = true,
                }
            }
        }
        if amount > 0 {
            payments.push((now, amount));
            spent += amount;
            if spent == target {
                let first = payments.first().map_or(now, |(t, _)| *t);
                return limit_ms.is_none_or(|limit| now - first <= limit);
            }
            continue;
        }
        let Some(next) = wait.filter(|_| !stuck) else {
            if goal < target {
                stage = spent;
                continue;
            }
            return false;
        };
        now = next;
        let first = payments.first().map_or(now, |(t, _)| *t);
        if limit_ms.is_some_and(|limit| now - first > limit) {
            return false;
        }
    }
    false
}

/// At most what the paying `views` together pay the class in a window
/// without approval, as the counters admit it.
///
/// A tool's payments count in every counter its rule writes, and each
/// payment must fit every one of them. Whatever the other tools pay, a tool
/// pays at most its own bound. The tools are grouped by the counter that
/// gives each its bound. The bound is stated when every group's tools agree
/// on that counter, its limit, its writers, and their largest unattended
/// payment, and no two groups share a counter. One group spends at most its
/// bound, and separate groups spend independently, so the asset spends at
/// most the sum.
/// It is reachable when every group's tool reaches its own bound. Otherwise
/// the per-tool bounds apply.
fn combined_bound(
    views: &[&ToolView],
    class: Class,
    window: Option<u64>,
    label: &str,
) -> AssetBound {
    let unbounded = AssetBound {
        window: label.to_owned(),
        amount: Agreed::Uniform(None),
        counters: Vec::new(),
        summed_over_counters: false,
        reachable: false,
    };
    let per_tool = AssetBound {
        amount: Agreed::PerTool,
        ..unbounded.clone()
    };
    let paying: Vec<&&ToolView> = views
        .iter()
        .filter(|v| v.pays_unattended(class) && v.bound(class, window) != Some(0))
        .collect();
    if paying.is_empty() {
        return AssetBound {
            amount: Agreed::Uniform(Some(format_amount(0))),
            reachable: true,
            ..unbounded
        };
    }
    type Signature = (CounterKey, i128, u32, CapKind, Option<i128>);
    let mut groups: Vec<(Signature, i128, Vec<&ToolView>)> = Vec::new();
    for view in &paying {
        let (Some(bound), Some(cap)) = (view.bound(class, window), view.binding_cap(class, window))
        else {
            return unbounded;
        };
        let signature = (
            cap.key.clone(),
            cap.limit,
            cap.writers,
            cap.kind,
            view.unattended_largest(class),
        );
        match groups.iter_mut().find(|(s, _, _)| s.0 == signature.0) {
            Some((s, group_bound, members)) if *s == signature && *group_bound == bound => {
                members.push(view);
            }
            Some(_) => return per_tool,
            None => groups.push((signature, bound, vec![view])),
        }
    }
    let keys = |members: &[&ToolView]| -> Vec<CounterKey> {
        members
            .iter()
            .flat_map(|v| v.class_caps(class).into_iter().map(|c| c.key.clone()))
            .collect()
    };
    for (i, (_, _, first)) in groups.iter().enumerate() {
        let first_keys = keys(first);
        for (_, _, second) in groups.iter().skip(i + 1) {
            if keys(second).iter().any(|k| first_keys.contains(k)) {
                return per_tool;
            }
        }
    }
    let Some(sum) = groups
        .iter()
        .try_fold(0_i128, |sum, (_, bound, _)| sum.checked_add(*bound))
    else {
        return per_tool;
    };
    AssetBound {
        amount: Agreed::Uniform(Some(format_amount(sum))),
        counters: groups
            .iter()
            .map(|(((identifier, window), ..), _, _)| format!("{identifier} {window}"))
            .collect(),
        summed_over_counters: groups.len() > 1,
        reachable: groups
            .iter()
            .all(|(_, _, members)| members[0].reachable(class, window)),
        ..unbounded
    }
}

/// The flags of `recipient` under the counterparty criteria of `rule`;
/// `None` stands for an address in no list.
///
/// A criterion lists the recipient only when three things hold. The
/// recipient is a G, M, or C address, the criterion's `kinds` select its
/// kind, and its allowlist holds the recipient or its base G. An entry of an unselected kind leaves the
/// recipient unlisted, as in the engine.
fn recipient_flags(
    rule: &RuleView<'_>,
    recipient: Option<&str>,
    asset: &str,
    passphrase: &str,
) -> Flags {
    let mut flags = Flags::default();
    let form = recipient.and_then(|recipient| {
        destination_form(recipient).map(|(kind, base)| (recipient, kind.tag(), base))
    });
    for criterion in rule.of_kind("counterparty_allowlist") {
        let listed = form.as_ref().is_some_and(|(recipient, kind, base)| {
            criterion
                .get("kinds")
                .and_then(Value::as_array)
                .is_some_and(|kinds| kinds.iter().any(|k| k.as_str() == Some(*kind)))
                && criterion
                    .get("allowlist")
                    .and_then(Value::as_array)
                    .is_some_and(|list| {
                        list.iter()
                            .filter_map(Value::as_str)
                            .any(|entry| entry == *recipient || entry == base.as_str())
                    })
        });
        if listed {
            continue;
        }
        let unlisted = criterion.get("unlisted").and_then(Value::as_inline_table);
        match unlisted.and_then(|u| u.get("mode")).and_then(Value::as_str) {
            Some("approval") => flags.approval = true,
            Some("budget")
                if assets_equivalent(
                    unlisted
                        .and_then(|u| u.get("asset"))
                        .and_then(Value::as_str)
                        .unwrap_or("native"),
                    asset,
                    passphrase,
                ) =>
            {
                flags.budgeted = true;
            }
            _ => flags.denied = true,
        }
    }
    flags
}

fn tool_view(
    tool: &str,
    rule: &RuleView<'_>,
    asset: &str,
    passphrase: &str,
    named: &[String],
) -> Option<ToolView> {
    let same = |c: &InlineTable| {
        c.get("asset")
            .and_then(Value::as_str)
            .is_some_and(|a| assets_equivalent(a, asset, passphrase))
    };
    let allowed = rule.of_kind("asset_allowlist").all(|list| {
        list.get("assets")
            .and_then(Value::as_array)
            .is_some_and(|assets| {
                assets
                    .iter()
                    .filter_map(Value::as_str)
                    .any(|a| assets_equivalent(a, asset, passphrase))
            })
    });
    if !allowed {
        return None;
    }
    let cap = |kind: &str| {
        min_present(
            rule.of_kind(kind)
                .filter(|c| same(c))
                .map(|c| stroops_of(c.get("max_stroops"))),
        )
    };
    let identifier = |c: &InlineTable| {
        asset_normalise(c.get("asset").and_then(Value::as_str).unwrap_or_default())
    };
    let window_of = |c: &InlineTable| {
        c.get("window")
            .and_then(Value::as_str)
            .and_then(|w| Window::parse(w).ok())
    };
    // Every criterion writing one key writes each payment once more; the
    // tightest of their limits applies.
    let mut caps: Vec<CapView> = Vec::new();
    let mut write = |cap: CapView| match caps.iter_mut().find(|c| c.key == cap.key) {
        Some(existing) => {
            existing.writers += 1;
            existing.limit = existing.limit.min(cap.limit);
        }
        None => caps.push(cap),
    };
    for c in rule.of_kind("per_period_cap").filter(|c| same(c)) {
        if let (Some(window), Some(limit)) = (window_of(c), stroops_of(c.get("max_stroops"))) {
            write(CapView {
                key: (identifier(c), window.label()),
                secs: Some(window.as_secs()),
                limit,
                writers: 1,
                kind: CapKind::Amount,
                unlisted_only: false,
            });
        }
    }
    for c in rule.of_kind("total_budget").filter(|c| same(c)) {
        if let Some(limit) = stroops_of(c.get("max_stroops")) {
            write(CapView {
                key: (identifier(c), TOTAL),
                secs: None,
                limit,
                writers: 1,
                kind: CapKind::Amount,
                unlisted_only: false,
            });
        }
    }
    for c in rule.of_kind("rate_limit") {
        let calls = c.get("max_calls").and_then(Value::as_integer);
        if let (Some(window), Some(calls)) = (window_of(c), calls) {
            write(CapView {
                key: (RATE_BUCKET.to_owned(), window.label()),
                secs: Some(window.as_secs()),
                limit: i128::from(calls),
                writers: 1,
                kind: CapKind::Calls,
                unlisted_only: false,
            });
        }
    }
    for u in rule
        .of_kind("counterparty_allowlist")
        .filter_map(|c| c.get("unlisted").and_then(Value::as_inline_table))
        .filter(|u| u.get("mode").and_then(Value::as_str) == Some("budget"))
    {
        let budget_asset = u.get("asset").and_then(Value::as_str).unwrap_or("native");
        if !assets_equivalent(budget_asset, asset, passphrase) {
            continue;
        }
        if let (Some(window), Some(limit)) = (window_of(u), stroops_of(u.get("per_period_stroops")))
        {
            write(CapView {
                key: (
                    format!("unlisted:{}", asset_normalise(budget_asset)),
                    window.label(),
                ),
                secs: Some(window.as_secs()),
                limit,
                writers: 1,
                kind: CapKind::Amount,
                unlisted_only: true,
            });
        }
    }
    let mut unmodeled: Vec<String> = Vec::new();
    for criterion in &rule.criteria {
        let kind = criterion.get("kind").and_then(Value::as_str).unwrap_or("");
        if !modeled_criterion_kinds().contains(&kind) && !unmodeled.iter().any(|k| k == kind) {
            unmodeled.push(kind.to_owned());
        }
    }
    let unmodeled_kinds = rule.of_kind("counterparty_allowlist").any(|c| {
        c.get("kinds")
            .and_then(Value::as_array)
            .is_some_and(|kinds| {
                kinds.iter().any(|k| {
                    !k.as_str()
                        .is_some_and(|k| MODELED_COUNTERPARTY_KINDS.contains(&k))
                })
            })
    });
    if unmodeled_kinds {
        unmodeled.push("counterparty_allowlist.kinds".to_owned());
    }
    let classified = !unmodeled_kinds
        && !rule
            .criteria
            .iter()
            .filter_map(|c| c.get("kind").and_then(Value::as_str))
            .any(|kind| CLASS_CONDITION_KINDS.contains(&kind));
    let budget = rule
        .of_kind("counterparty_allowlist")
        .filter_map(|c| c.get("unlisted").and_then(Value::as_inline_table))
        .find(|u| {
            u.get("mode").and_then(Value::as_str) == Some("budget")
                && assets_equivalent(
                    u.get("asset").and_then(Value::as_str).unwrap_or("native"),
                    asset,
                    passphrase,
                )
        })
        .map(|u| {
            let window = u
                .get("window")
                .and_then(Value::as_str)
                .and_then(|w| Window::parse(w).ok());
            let period =
                window
                    .zip(stroops_of(u.get("per_period_stroops")))
                    .map(|(window, amount)| PeriodCap {
                        window: window.label().to_owned(),
                        amount: format_amount(amount),
                    });
            (stroops_of(u.get("per_tx_stroops")), period)
        });
    let blocked = X402_TOOLS.contains(&tool) && rule.of_kind("balance_floor").next().is_some();
    // A `require_approval` rule escalates every call it does not deny.
    let decision = if rule.decision == "require_approval" {
        "require_approval"
    } else {
        "allow"
    };
    let treatment = |recipient: Option<&str>| {
        if blocked {
            Treatment::Denied
        } else {
            let mut flags = recipient_flags(rule, recipient, asset, passphrase);
            flags.approval |= decision == "require_approval";
            flags.treatment()
        }
    };
    Some(ToolView {
        tool: tool.to_owned(),
        decision,
        per_tx: cap("per_tx_cap"),
        approval: cap("approval_above"),
        caps,
        unmodeled,
        budget,
        blocked,
        unlisted: treatment(None),
        recipients: named
            .iter()
            .map(|recipient| (recipient.clone(), treatment(Some(recipient))))
            .collect(),
        open: rule.of_kind("counterparty_allowlist").next().is_none(),
        classified,
    })
}

/// Every recipient the counterparty criteria of `rules` list, in
/// first-appearance order.
fn named_recipients(rules: &[&RuleView<'_>]) -> Vec<String> {
    let mut named: Vec<String> = Vec::new();
    for entry in rules
        .iter()
        .flat_map(|rule| rule.of_kind("counterparty_allowlist"))
        .flat_map(|c| {
            c.get("allowlist")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
        })
        .filter_map(Value::as_str)
    {
        if !named.iter().any(|n| n == entry) {
            named.push(entry.to_owned());
        }
    }
    named
}

/// The assets the payment rules name, in first-appearance order.
fn named_assets(rules: &[&RuleView<'_>], passphrase: &str) -> Vec<String> {
    let mut assets: Vec<String> = Vec::new();
    for rule in rules {
        for criterion in &rule.criteria {
            let named: Vec<&str> = match criterion.get("kind").and_then(Value::as_str) {
                Some("asset_allowlist") => criterion
                    .get("assets")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .collect(),
                _ => criterion
                    .get("asset")
                    .and_then(Value::as_str)
                    .into_iter()
                    .collect(),
            };
            for asset in named {
                if !assets
                    .iter()
                    .any(|a| assets_equivalent(a, asset, passphrase))
                {
                    assets.push(asset.to_owned());
                }
            }
        }
    }
    assets
}

fn amount_string(stroops: Option<i128>) -> Option<String> {
    stroops.map(format_amount)
}

/// One note per approval threshold of the x402 tools that admit `asset`,
/// naming the tools that carry it.
///
/// Above the threshold the evaluation requires approval. What the tool then
/// does depends on the network and the build: with mainnet writes, a mainnet
/// call without an approval proof returns a pending approval; a build without
/// mainnet writes refuses every mainnet payment; on another network the tool
/// refuses a call that requires approval.
fn x402_approval_notes(views: &[ToolView], asset: &str, mainnet: bool) -> Vec<String> {
    let mut thresholds: Vec<(i128, Vec<&str>)> = Vec::new();
    let paying = |v: &&ToolView| X402_TOOLS.contains(&v.tool.as_str()) && !v.blocked;
    let every: Vec<&str> = views
        .iter()
        .filter(paying)
        .filter(|v| v.decision == "require_approval")
        .map(|v| v.tool.as_str())
        .collect();
    for view in views
        .iter()
        .filter(paying)
        .filter(|v| v.decision == "allow")
    {
        let Some(threshold) = view.approval else {
            continue;
        };
        match thresholds.iter_mut().find(|(t, _)| *t == threshold) {
            Some((_, tools)) => tools.push(&view.tool),
            None => thresholds.push((threshold, vec![&view.tool])),
        }
    }
    let clause = match (mainnet, cfg!(feature = "mainnet-write")) {
        (true, true) => "without an approval proof, a call above it returns a pending approval",
        (true, false) => "this build has no mainnet writes and refuses every mainnet payment",
        (false, _) => "on this network a call above it is refused",
    };
    let verb = |tools: &[&str]| {
        if tools.len() > 1 {
            "require"
        } else {
            "requires"
        }
    };
    let mut notes: Vec<String> = thresholds
        .into_iter()
        .map(|(threshold, tools)| {
            format!(
                "{} {} approval above {} {}: {clause}.",
                tools.join(" and "),
                verb(&tools),
                format_amount(threshold),
                asset_code(asset)
            )
        })
        .collect();
    if !every.is_empty() {
        let clause = match (mainnet, cfg!(feature = "mainnet-write")) {
            (true, true) => "without an approval proof, a call returns a pending approval",
            (true, false) => "this build has no mainnet writes and refuses every mainnet payment",
            (false, _) => "on this network such a call is refused",
        };
        notes.push(format!(
            "{} {} approval for every payment of {}: {clause}.",
            every.join(" and "),
            verb(&every),
            asset_code(asset)
        ));
    }
    notes
}

/// Summarizes the spending bounds of a policy body.
///
/// Reads only `body`. For each tool the first matching rule counts, as in
/// the engine, and a `deny` rule contributes nothing. Every statement holds
/// for the evaluation: each tool's limits, recipient treatments, and floor
/// are stated per tool, and an aggregate holds a value only when every
/// contributing tool states it, else [`Agreed::PerTool`].
///
/// Every criterion of a rule applies. A recipient is treated per
/// counterparty criterion, listed or by that criterion's unlisted mode. The
/// treatments combine: a denial denies, an `approval` mode escalates, and a
/// `budget` mode bounds the payment by the budget. As in the engine, the G
/// and C kinds are alternatives. A criterion lists a G, M, or C recipient
/// when its `kinds` select the recipient's kind. Its allowlist must also
/// hold the recipient or, for an M address, its base G. A rule without a
/// counterparty criterion admits every recipient, reported as
/// `unrestricted`. A rule's floor is its highest floor; an x402 rule with a
/// floor denies every call, since x402 tools evaluate without an account
/// view.
///
/// The evaluation keeps one counter per asset identifier as written and per
/// window, and one per identifier for the total budget. Every window a rule
/// caps is stated. A tool's bound in a window is its tightest cap: a cap
/// whose window covers it, a shorter cap times the number of its windows
/// that fit, or the total budget. The asset's bound is stated only when it
/// holds exactly: one value when the tools agree on a shared counter, the
/// sum when separate counters bind independent tools, else per tool.
#[must_use]
pub fn summarize(
    body: &DocumentMut,
    network_passphrase: &str,
    authority: AuthorityStatus,
) -> SpendingSummary {
    let network = Caip2::from_passphrase(network_passphrase);
    let chain = network.map_or("", Caip2::caip2_str);
    let mainnet_chain = network.is_some_and(Caip2::is_mainnet);
    let rules = read_rules(body);
    let payment: Vec<(&str, &RuleView<'_>)> = MAINNET_VALUE_OUT_TOOLS
        .iter()
        .filter_map(|tool| effective(&rules, tool, chain).map(|rule| (*tool, rule)))
        .collect();
    let payment_rules: Vec<&RuleView<'_>> = payment.iter().map(|(_, rule)| *rule).collect();
    let named = named_recipients(&payment_rules);

    let mut limits = Vec::new();
    let mut approval_notes = Vec::new();
    let mut notes_extra: Vec<String> = Vec::new();
    // The treatment of each listed recipient by every tool and asset.
    let mut listed_treatments: Vec<Vec<Option<Treatment>>> = vec![Vec::new(); named.len()];
    // The exhaustion behavior of every tool that admits an address in no list.
    let mut exhaustion: Vec<Option<&'static str>> = Vec::new();
    // The tools that pay no listed recipient in some asset.
    let mut without_listed: Vec<String> = Vec::new();
    for asset in named_assets(&payment_rules, network_passphrase) {
        let views: Vec<ToolView> = payment
            .iter()
            .filter_map(|(tool, rule)| tool_view(tool, rule, &asset, network_passphrase, &named))
            .collect();
        // Every window any counter of a tool keeps, shortest first.
        let mut windows: Vec<(u64, &'static str)> = Vec::new();
        for cap in views.iter().flat_map(|v| &v.caps) {
            if let Some(secs) = cap.secs
                && !windows.iter().any(|(s, _)| *s == secs)
            {
                windows.push((secs, cap.key.1));
            }
        }
        windows.sort_by_key(|(secs, _)| *secs);
        let tools: Vec<ToolLimits> = views.iter().map(|v| v.limits(&windows)).collect();
        let agreed = |field: fn(&ToolLimits) -> &Option<String>| {
            Agreed::of(tools.iter().map(|t| field(t).clone()))
        };
        let admitting: Vec<&ToolLimits> =
            tools.iter().filter(|t| t.unlisted_mode != "deny").collect();
        let mut counters: Vec<Counter> = Vec::new();
        for view in &views {
            for cap in &view.caps {
                let (identifier, window) = &cap.key;
                match counters
                    .iter_mut()
                    .find(|c| &c.identifier == identifier && c.window == *window)
                {
                    Some(counter) => {
                        if !counter.tools.contains(&view.tool) {
                            counter.tools.push(view.tool.clone());
                        }
                    }
                    None => counters.push(Counter {
                        kind: match (cap.kind, cap.unlisted_only, cap.secs) {
                            (CapKind::Calls, ..) => "calls",
                            (_, true, _) => "unlisted",
                            (_, _, None) => "total",
                            _ => "amount",
                        },
                        identifier: identifier.clone(),
                        window: (*window).to_owned(),
                        tools: vec![view.tool.clone()],
                        limit: Agreed::Uniform(None),
                        writers: Agreed::Uniform(None),
                    }),
                }
            }
        }
        for counter in &mut counters {
            let cap_of = |tool: &String| {
                views
                    .iter()
                    .find(|v| &v.tool == tool)
                    .and_then(|v| {
                        v.caps
                            .iter()
                            .find(|c| c.key.0 == counter.identifier && c.key.1 == counter.window)
                    })
                    .cloned()
            };
            let caps: Vec<Option<CapView>> = counter.tools.iter().map(cap_of).collect();
            let calls = counter.kind == "calls";
            counter.limit = Agreed::of(caps.iter().map(|c| {
                c.as_ref().map(|c| {
                    if calls {
                        c.limit.to_string()
                    } else {
                        format_amount(c.limit)
                    }
                })
            }));
            counter.writers = Agreed::of(caps.iter().map(|c| c.as_ref().map(|c| c.writers)));
        }
        let mut identifiers: Vec<String> = Vec::new();
        for counter in counters
            .iter()
            .filter(|c| matches!(c.kind, "amount" | "total"))
        {
            if !identifiers.contains(&counter.identifier) {
                identifiers.push(counter.identifier.clone());
            }
        }
        if identifiers.len() > 1 {
            notes_extra.push(format!(
                "{} is counted under more than one identifier ({}); their counters are \
                 separate, so a bound sums over them.",
                asset_code(&asset),
                identifiers.join(", ")
            ));
        }
        let view_refs: Vec<&ToolView> = views.iter().collect();
        let class_bounds = |class: Class| -> Vec<AssetBound> {
            windows
                .iter()
                .map(|(secs, label)| (Some(*secs), *label))
                .chain([(None, TOTAL)])
                .map(|(secs, label)| combined_bound(&view_refs, class, secs, label))
                .collect()
        };
        let bounds = class_bounds(Class::Listed);
        let unlisted_bounds = class_bounds(Class::Unlisted);
        for view in &views {
            for (slot, (_, treatment)) in listed_treatments.iter_mut().zip(&view.recipients) {
                slot.push(Some(*treatment));
            }
            if view.classified
                && !view.blocked
                && !view.has_recipient(Class::Listed)
                && !without_listed.contains(&view.tool)
            {
                without_listed.push(view.tool.clone());
            }
        }
        exhaustion.extend(admitting.iter().map(|t| Some(t.unlisted_exhaustion)));
        approval_notes.extend(x402_approval_notes(&views, &asset, mainnet_chain));
        // A window only a rate limit or the unlisted budget uses has bounds
        // but no period cap.
        let period_caps = windows
            .iter()
            .filter(|(_, label)| {
                tools
                    .iter()
                    .any(|t| t.period_caps.iter().any(|c| c.window == *label))
            })
            .map(|(_, label)| AgreedPeriodCap {
                window: (*label).to_owned(),
                amount: Agreed::of(tools.iter().map(|t| {
                    t.period_caps
                        .iter()
                        .find(|c| c.window == *label)
                        .map(|c| c.amount.clone())
                })),
            })
            .collect();
        limits.push(AssetLimits {
            counted_under_several_identifiers: identifiers.len() > 1,
            identifiers,
            per_tx_cap: agreed(|t| &t.per_tx_cap),
            largest_payment: agreed(|t| &t.largest_payment),
            unlisted_largest_payment: Agreed::of(
                views
                    .iter()
                    .zip(&tools)
                    .filter(|(view, _)| view.admits(Class::Unlisted))
                    .map(|(_, t)| t.unlisted_largest_payment.clone()),
            ),
            period_caps,
            total_budget: agreed(|t| &t.total_budget),
            approval_above: agreed(|t| &t.approval_above),
            unlisted_mode: Agreed::of(tools.iter().map(|t| Some(t.unlisted_mode))),
            unlisted_tools: admitting.iter().map(|t| t.tool.clone()).collect(),
            unlisted_per_tx_cap: Agreed::of(
                admitting.iter().map(|t| t.unlisted_per_tx_cap.clone()),
            ),
            unlisted_period_cap: Agreed::of(
                admitting.iter().map(|t| t.unlisted_period_cap.clone()),
            ),
            counters,
            bounds,
            unlisted_bounds,
            asset,
            tools,
        });
    }

    let rate_tools: Vec<ToolRate> = payment
        .iter()
        .map(|(tool, rule)| ToolRate {
            tool: (*tool).to_owned(),
            limits: rule_rates(rule),
        })
        .collect();
    let mut rate_windows: Vec<(u64, String)> = Vec::new();
    for limit in rate_tools.iter().flat_map(|t| &t.limits) {
        let secs = Window::parse(&limit.window).map_or(0, Window::as_secs);
        if !rate_windows.iter().any(|(_, w)| *w == limit.window) {
            rate_windows.push((secs, limit.window.clone()));
        }
    }
    rate_windows.sort_by_key(|(secs, _)| *secs);
    let rate_by_window: Vec<AgreedRate> = rate_windows
        .into_iter()
        .map(|(_, window)| AgreedRate {
            calls: Agreed::of(rate_tools.iter().map(|t| {
                t.limits
                    .iter()
                    .find(|l| l.window == window)
                    .map(|l| l.calls)
            })),
            window,
        })
        .collect();
    let auxiliary_rate_limits = MAINNET_TRUSTLINE_TOOLS
        .iter()
        .chain(MAINNET_CLAIM_TOOLS)
        .filter_map(|tool| {
            effective(&rules, tool, chain).map(|rule| AuxiliaryRateLimit {
                tool: (*tool).to_owned(),
                limits: rule_rates(rule),
            })
        })
        .collect();

    let mainnet = body.get("mainnet").and_then(Item::as_table_like);
    let (fee_cap_status, fee) = match mainnet {
        None => (
            FeeCapStatus::Planned,
            i64::try_from(PRESET_FEE_PER_OPERATION_STROOPS).ok(),
        ),
        Some(table) => (
            FeeCapStatus::Signed,
            table
                .get("classic_max_fee_per_op_stroops")
                .and_then(Item::as_integer),
        ),
    };

    // Every floor of a rule applies, so a rule's floor is its highest.
    let floors: Vec<Option<i128>> = payment_rules
        .iter()
        .map(|rule| {
            rule.of_kind("balance_floor")
                .filter_map(|c| stroops_of(c.get("min_stroops")))
                .max()
        })
        .collect();
    let balance_floors: Vec<ToolFloor> = payment
        .iter()
        .zip(&floors)
        .map(|((tool, _), floor)| ToolFloor {
            tool: (*tool).to_owned(),
            floor_xlm: amount_string(*floor),
        })
        .collect();
    let x402_floors: Vec<(&str, bool)> = payment
        .iter()
        .zip(&floors)
        .filter(|((tool, _), _)| X402_TOOLS.contains(tool))
        .map(|((tool, _), floor)| (*tool, floor.is_some()))
        .collect();

    let mut recipients = Recipients {
        kinds: Vec::new(),
        listed: named
            .iter()
            .zip(listed_treatments)
            .map(|(recipient, treatments)| ListedRecipient {
                recipient: recipient.clone(),
                treatment: Agreed::of(treatments),
            })
            .collect(),
        unrestricted_tools: Vec::new(),
        without_listed_recipient: without_listed,
    };
    for (tool, rule) in &payment {
        if rule.of_kind("counterparty_allowlist").next().is_none() {
            recipients.unrestricted_tools.push((*tool).to_owned());
        }
        for kind in rule
            .of_kind("counterparty_allowlist")
            .flat_map(|c| {
                c.get("kinds")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
            })
            .filter_map(Value::as_str)
        {
            if !recipients.kinds.iter().any(|k| k == kind) {
                recipients.kinds.push(kind.to_owned());
            }
        }
    }

    let (covered, uncovered): (Vec<&str>, Vec<&str>) = MAINNET_VALUE_OUT_TOOLS
        .iter()
        .chain(MAINNET_TRUSTLINE_TOOLS)
        .chain(MAINNET_CLAIM_TOOLS)
        .chain(MAINNET_READ_ONLY_TOOLS)
        .copied()
        .partition(|tool| effective(&rules, tool, chain).is_some());

    let unlisted_exhaustion = Agreed::of(exhaustion);
    let mut notes = vec![
        "Caps use rolling windows: 1d covers the last 86,400 seconds and 1w the last 604,800 seconds."
            .to_owned(),
        "Rate limits count every tool in one shared bucket per window.".to_owned(),
        "A payment beyond an exhausted cap, total budget, or unlisted budget is denied."
            .to_owned(),
        "A new policy signature starts a new total_budget allocation.".to_owned(),
    ];
    let floor_free: Vec<&str> = x402_floors
        .iter()
        .filter(|(_, floored)| !floored)
        .map(|(tool, _)| *tool)
        .collect();
    if floor_free.len() == x402_floors.len() && !floor_free.is_empty() {
        notes.push("The balance floor does not apply to x402 payments.".to_owned());
    } else if !floor_free.is_empty() {
        notes.push(format!(
            "The balance floor does not apply to {}.",
            floor_free.join(" and ")
        ));
    }
    for (tool, _) in x402_floors.iter().filter(|(_, floored)| *floored) {
        notes.push(format!(
            "{tool} denies every call: its rule carries a balance floor, and x402 tools \
             evaluate without an account view."
        ));
    }
    notes.extend(approval_notes);
    notes.extend(notes_extra);

    SpendingSummary {
        authority_status: authority,
        policy_version: body.get("version").and_then(Item::as_integer),
        sequence: body.get("sequence").and_then(Item::as_integer),
        limits,
        unlisted_exhaustion,
        rate_limits: RateLimits {
            windows: rate_by_window,
            shared_across_tools: true,
            tools: rate_tools,
        },
        auxiliary_rate_limits,
        classic_max_fee_per_op_stroops: fee,
        fee_cap_status,
        max_fee_per_classic_operation_xlm: fee.map(|f| format_amount(i128::from(f))),
        balance_floor_xlm: Agreed::of(
            payment
                .iter()
                .zip(&floors)
                .filter(|((tool, _), floor)| floor.is_some() && !X402_TOOLS.contains(tool))
                .map(|(_, floor)| amount_string(*floor)),
        ),
        balance_floors,
        recipients,
        tools: ToolCoverage {
            covered: covered.into_iter().map(str::to_owned).collect(),
            uncovered: uncovered.into_iter().map(str::to_owned).collect(),
        },
        notes,
    }
}

/// The funding plan of a derivation, shown at `profile init` only. Amounts
/// are decimal strings; XLM amounts carry the `_xlm` suffix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PresetPlan {
    /// The preset name.
    pub preset: &'static str,
    /// The payment asset code.
    pub asset: &'static str,
    /// The tolerated loss `L`.
    pub tolerated_loss: String,
    /// The unattended days `T`.
    pub unattended_days: u32,
    /// The typical payment `p`.
    pub typical_payment: String,
    /// `L/T`, rounded down to one stroop.
    pub even_daily_spend: String,
    /// The spend the preset fits.
    pub expected_spend_fit: String,
    /// One sentence when the typical payment exceeds the unlisted
    /// per-payment cap; the approval threshold is never below it.
    pub typical_use: Vec<String>,
    /// The operating balance `O` in the payment asset.
    pub operating_balance: String,
    /// The protocol minimum of the operating account.
    pub protocol_minimum_xlm: String,
    /// The balance floor `M`.
    pub balance_floor_xlm: String,
    /// The recommended balance `R`, a whole number of XLM.
    pub recommended_balance_xlm: String,
    /// `O + R` for an XLM profile; `null` for USDC.
    pub recommended_funding_xlm: Option<String>,
    /// `R` less the protocol minimum, the XLM that fees can consume.
    pub fee_allowance_xlm: String,
    /// The worst case `B` over the period in the payment asset.
    pub worst_case_asset: String,
    /// The condition under which the fee bound holds.
    pub funding_condition: String,
    /// The labeled starting values the derivation assumes.
    pub assumptions: Vec<String>,
}

/// States the funding plan of `derived`.
#[must_use]
pub fn plan(derived: &DerivedSpending) -> PresetPlan {
    let code = derived.asset.code();
    let typical = derived.typical_payment_stroops;
    let even_daily = derived
        .tolerated_loss_stroops
        .checked_div(i128::from(derived.unattended_days))
        .unwrap_or(derived.tolerated_loss_stroops);
    // The approval threshold is never below the typical payment, so only the
    // unlisted per-payment cap can fall short of it.
    let mut typical_use = Vec::new();
    if let Some(budget) = derived.unlisted.filter(|u| typical > u.per_payment_stroops) {
        typical_use.push(format!(
            "A typical payment of {} {code} exceeds the unlisted per-payment cap of {} {code}.",
            format_amount(typical),
            format_amount(budget.per_payment_stroops)
        ));
    }
    let recommended = derived.recommended_balance_stroops;
    let funding = match derived.asset {
        PresetAsset::Native => derived
            .operating_balance_stroops
            .checked_add(recommended)
            .map(format_amount),
        PresetAsset::Usdc { .. } => None,
    };
    let (numerator, denominator) = derived.preset.archetype.fraction();
    let reserve_note = match derived.asset {
        PresetAsset::Usdc { .. } => format!(
            "Protocol minimum {} XLM: the account and one trustline at the 0.5 XLM base reserve.",
            format_amount(derived.reserve_stroops)
        ),
        PresetAsset::Native => format!(
            "Protocol minimum {} XLM: the account at the 0.5 XLM base reserve.",
            format_amount(derived.reserve_stroops)
        ),
    };
    PresetPlan {
        preset: derived.preset.name,
        asset: code,
        tolerated_loss: format_amount(derived.tolerated_loss_stroops),
        unattended_days: derived.unattended_days,
        typical_payment: format_amount(typical),
        even_daily_spend: format_amount(even_daily),
        expected_spend_fit: format!(
            "Expected spend above {} {code} per day does not fit this preset.",
            format_amount(even_daily)
        ),
        typical_use,
        operating_balance: format_amount(derived.operating_balance_stroops),
        protocol_minimum_xlm: format_amount(derived.reserve_stroops),
        balance_floor_xlm: format_amount(derived.balance_floor_stroops),
        recommended_balance_xlm: format_amount(recommended),
        recommended_funding_xlm: funding,
        fee_allowance_xlm: format_amount(recommended - derived.reserve_stroops),
        worst_case_asset: format_amount(derived.worst_case_stroops),
        funding_condition: format!(
            "The fee bound holds while the operating account holds {} XLM.",
            format_amount(recommended)
        ),
        assumptions: vec![
            "Burst factor 2: the 1d cap is at most twice the even daily spend.".to_owned(),
            format!(
                "Per-payment fraction {numerator}/{denominator}: the per-payment cap is \
                 {numerator}/{denominator} of the 1d cap."
            ),
            "Rates assume 8 active hours per day and 10-minute bursts, with at least 6 calls \
             per hour, 2 per minute, and at most 60 per minute."
                .to_owned(),
            format!(
                "Fee cap {} stroops per classic operation, 100 times the 100-stroop minimum \
                 base fee.",
                derived.fee_per_operation_stroops
            ),
            reserve_note,
            "These constants are starting values, reviewed with canary data before alpha.15."
                .to_owned(),
        ],
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use super::*;
    use crate::asset_id::CanonicalAsset;
    use crate::policy::v1::criteria::counterparty_allowlist::RecipientClass;
    use crate::policy::v1::criteria::state_store::set_query_time_for_test;
    use crate::policy::v1::mainnet_minimum::{self, RequirementStatus};
    use crate::policy::v1::{
        AccountReserveLookupError, AccountReservesView, ActionKind, FloorInput, ObservedAccount,
        PolicyEngineV1, PolicyStateStore, ValueClass, ValueLeg, canonical::canonical_bytes,
        loader::load_signed_policy_text, signature, validate_unsigned_policy,
        value::derive_value_class,
    };
    use crate::policy::{Decision, DenyReason, PolicyEngine, ToolDescriptor, ToolValueKind};
    use crate::profile::{
        caip2::{MAINNET_PASSPHRASE, TESTNET_PASSPHRASE},
        schema::Profile,
    };

    const ISSUER: &str = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";
    const OTHER_ISSUER: &str = "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5";
    const PROFILE: &str = "preset-test";
    /// The x402 tool that creates a payment.
    const CREATE_TOOL: &str = "stellar_x402_create_payment";
    /// A policy instant far from the host clock.
    const T0: u64 = 1_800_000_000_000;
    /// The spacing of recorded payments, beyond the 1m window.
    const STEP_MS: u64 = 61_000;

    const READ_ONLY: [&str; 17] = [
        "stellar_balances",
        "stellar_fee_stats",
        "stellar_dex_quote",
        "stellar_rules_list",
        "stellar_rules_get",
        "stellar_sep43_get_address",
        "stellar_sep43_get_network",
        "stellar_sep47_discover",
        "stellar_sep48_preview_invocation",
        "stellar_sep53_verify_message",
        "stellar_sep6_deposit_info",
        "stellar_sep7_parse_uri",
        "stellar_toolset_list",
        "stellar_mpp_authorization_status",
        "stellar_x402_parse_receipt",
        "stellar_transaction_status",
        "stellar_signed_intents_list",
    ];

    fn usdc() -> PresetAsset {
        PresetAsset::Usdc {
            issuer: ISSUER.to_owned(),
        }
    }

    fn input(name: &str, unlisted_budget: bool, total_budget: bool) -> PresetInput {
        PresetInput {
            preset: find_preset(name).unwrap(),
            asset: usdc(),
            tolerated_loss_stroops: None,
            typical_payment_stroops: None,
            unlisted_budget,
            total_budget,
        }
    }

    fn xlm_input(name: &str, loss: &str, typical: &str) -> PresetInput {
        PresetInput {
            preset: find_preset(name).unwrap(),
            asset: PresetAsset::Native,
            tolerated_loss_stroops: Some(parse_amount(loss).unwrap()),
            typical_payment_stroops: Some(parse_amount(typical).unwrap()),
            unlisted_budget: false,
            total_budget: true,
        }
    }

    fn derived(name: &str, unlisted_budget: bool, total_budget: bool) -> DerivedSpending {
        derive(&input(name, unlisted_budget, total_budget)).unwrap()
    }

    fn doc(body: &str) -> DocumentMut {
        body.parse().unwrap()
    }

    /// Every input combination a preset accepts in USDC.
    fn usdc_inputs() -> Vec<PresetInput> {
        let mut inputs = Vec::new();
        for spec in &PRESETS {
            for total in [true, false] {
                inputs.push(input(spec.name, false, total));
                if spec.archetype == Archetype::Api {
                    inputs.push(input(spec.name, true, total));
                }
            }
        }
        inputs
    }

    /// Each rule's tool and criteria, in order.
    fn rules_of(doc: &DocumentMut) -> Vec<(String, Vec<InlineTable>)> {
        doc["rules"]
            .as_array_of_tables()
            .unwrap()
            .iter()
            .map(|rule| {
                (
                    rule["match"]["tool"].as_str().unwrap().to_owned(),
                    rule["criteria"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|c| c.as_inline_table().unwrap().clone())
                        .collect(),
                )
            })
            .collect()
    }

    fn kind_of(criterion: &InlineTable) -> &str {
        criterion.get("kind").and_then(Value::as_str).unwrap()
    }

    fn of_kind<'a>(criteria: &'a [InlineTable], kind: &str) -> Vec<&'a InlineTable> {
        criteria.iter().filter(|c| kind_of(c) == kind).collect()
    }

    fn text<'a>(criterion: &'a InlineTable, key: &str) -> &'a str {
        criterion.get(key).and_then(Value::as_str).unwrap()
    }

    fn rates(criteria: &[InlineTable]) -> Vec<(String, i64)> {
        of_kind(criteria, "rate_limit")
            .into_iter()
            .map(|c| {
                (
                    text(c, "window").to_owned(),
                    c.get("max_calls").and_then(Value::as_integer).unwrap(),
                )
            })
            .collect()
    }

    fn mainnet_profile() -> Profile {
        Profile::builder_mainnet(
            "https://rpc.example.invalid",
            "svc",
            "acct",
            "n-svc",
            "n-acct",
        )
        .build()
    }

    fn summary_of(body: &str) -> SpendingSummary {
        summarize(&doc(body), MAINNET_PASSPHRASE, AuthorityStatus::Draft)
    }

    /// The agreed period cap of `limits` in `window`.
    fn cap_of<'a>(limits: &'a AssetLimits, window: &str) -> Option<&'a str> {
        limits
            .period_caps
            .iter()
            .find(|c| c.window == window)
            .and_then(|c| c.amount.as_deref())
    }

    /// The combined bound of `limits` in `window`.
    fn bound_of<'a>(limits: &'a AssetLimits, window: &str) -> &'a Agreed<String> {
        &limits
            .bounds
            .iter()
            .find(|b| b.window == window)
            .unwrap()
            .amount
    }

    /// The first asset's limits of `tool`.
    fn tool_limits<'a>(summary: &'a SpendingSummary, tool: &str) -> &'a ToolLimits {
        summary.limits[0]
            .tools
            .iter()
            .find(|t| t.tool == tool)
            .unwrap()
    }

    fn account(seed: u8) -> String {
        stellar_strkey::ed25519::PublicKey([seed; 32])
            .to_string()
            .as_str()
            .to_owned()
    }

    // ── Engine fixtures ────────────────────────────────────────────────────

    /// An operating account holding the given XLM balance in stroops.
    struct Balance(i64);

    impl AccountReservesView for Balance {
        fn reserves_stroops(&self, base_reserve_stroops: i64) -> i64 {
            3 * base_reserve_stroops
        }

        fn balance_stroops(&self) -> Result<i64, AccountReserveLookupError> {
            Ok(self.0)
        }
    }

    /// The generated body with `listed` as the one listed recipient.
    fn listed_body(derived: &DerivedSpending, listed: &str) -> String {
        policy_body(PROFILE, derived)
            .replace("allowlist = []", &format!("allowlist = [\"{listed}\"]"))
    }

    /// The network a fixture evaluates on.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Net {
        Mainnet,
        Testnet,
    }

    impl Net {
        fn passphrase(self) -> &'static str {
            match self {
                Self::Mainnet => MAINNET_PASSPHRASE,
                Self::Testnet => TESTNET_PASSPHRASE,
            }
        }

        fn chain(self) -> &'static str {
            match self {
                Self::Mainnet => MAINNET_CHAIN,
                Self::Testnet => "stellar:testnet",
            }
        }

        fn profile(self) -> Profile {
            match self {
                Self::Mainnet => mainnet_profile(),
                Self::Testnet => {
                    Profile::builder_testnet("alice", "acct", "n-svc", "n-acct").build()
                }
            }
        }

        /// `body`, generated for mainnet, with its rules and its USDC
        /// contract identifier on this network.
        fn body(self, body: &str) -> String {
            body.replace(MAINNET_CHAIN, self.chain())
                .replace(&usdc_sac(Net::Mainnet), &usdc_sac(self))
        }

        fn summary(self, body: &str) -> SpendingSummary {
            summarize(&doc(body), self.passphrase(), AuthorityStatus::Draft)
        }
    }

    /// Signs `body` and loads it through the signed-policy loader, recording
    /// the digest that opens its `total_budget` allocation.
    fn verified_engine(body: &str) -> PolicyEngineV1 {
        verified_engine_on(body, Net::Mainnet)
    }

    fn verified_engine_on(body: &str, net: Net) -> PolicyEngineV1 {
        let key = ed25519_dalek::SigningKey::from_bytes(&[0x42; 32]);
        let canonical = canonical_bytes(body).unwrap();
        let sig = crate::hex::encode(&signature::sign(&signature::digest(&canonical), &key));
        let signed = format!("{body}\n[signature]\nowner_id = \"{PROFILE}\"\nsig = \"{sig}\"\n");
        let document = load_signed_policy_text(
            &signed,
            PROFILE,
            &key.verifying_key().to_bytes(),
            net.passphrase(),
        )
        .unwrap();
        PolicyEngineV1::new_verified(
            document,
            PROFILE.to_owned(),
            PolicyStateStore::new(),
            &canonical,
        )
    }

    fn tool(name: &str) -> ToolDescriptor {
        tool_on(name, Net::Mainnet)
    }

    fn tool_on(name: &str, net: Net) -> ToolDescriptor {
        ToolDescriptor {
            name: name.to_owned(),
            destructive_hint: true,
            read_only_hint: false,
            chain_id_required: true,
            chain_id: net.chain().to_owned(),
            value_kind: ToolValueKind::MovesValue,
        }
    }

    /// The decision class; a period cap or total budget denial names its
    /// bound.
    fn label(decision: &Decision) -> String {
        match decision {
            Decision::Allow => "allow".to_owned(),
            Decision::RequireApproval(_) => "approval".to_owned(),
            Decision::Deny(DenyReason::PerPeriodCapExceeded { window, .. }) => {
                format!("deny:{window}")
            }
            Decision::Deny(DenyReason::TotalBudgetExhausted { .. }) => "deny:total".to_owned(),
            Decision::Deny(_) => "deny".to_owned(),
        }
    }

    fn pay_args(to: &str, amount: i128) -> serde_json::Value {
        serde_json::json!({
            "destination": to,
            "asset": format!("USDC:{ISSUER}"),
            "amount_stroops": amount.to_string(),
        })
    }

    /// One payment a property check evaluates. `asset` is `native` or an
    /// identity of the fixture USDC.
    #[derive(Debug, Clone, Copy)]
    struct Payment<'a> {
        tool: &'a str,
        asset: &'a str,
        to: &'a str,
        amount: i128,
    }

    impl Payment<'_> {
        fn native(self) -> bool {
            self.asset == "native"
        }

        /// The arguments of the classic payment, with the envelope fee.
        fn pay_args(self, fee_stroops: i64) -> serde_json::Value {
            let asset = if self.native() {
                "native".to_owned()
            } else {
                format!("USDC:{ISSUER}")
            };
            serde_json::json!({
                "destination": self.to,
                "asset": asset,
                "amount_stroops": self.amount.to_string(),
                "total_fee_stroops": fee_stroops,
            })
        }

        /// The value of the x402 payment on `net`.
        fn x402_value(self, net: Net) -> ValueClass {
            let asset = if self.native() {
                CanonicalAsset::Native
            } else {
                CanonicalAsset::parse_threshold_key(&format!("USDC:{ISSUER}")).unwrap()
            };
            ValueClass::single(ValueLeg {
                kind: ActionKind::X402Payment,
                amount: Some(self.amount),
                asset: Some(asset.sac_contract_id(net.passphrase()).unwrap()),
                destination: Some(self.to.to_owned()),
            })
        }
    }

    /// Evaluates `payment` as its tool does: a classic payment with a fresh
    /// read of an account holding `balance` and the envelope fee `fee`, an
    /// x402 payment without an account view.
    fn evaluate_payment(
        engine: &PolicyEngineV1,
        payment: Payment<'_>,
        (now_ms, balance, fee): (u64, i64, i64),
        net: Net,
    ) -> Decision {
        let descriptor = tool_on(payment.tool, net);
        let profile = net.profile();
        if X402_TOOLS.contains(&payment.tool) {
            return engine
                .evaluate_with_value(
                    &descriptor,
                    &serde_json::json!({}),
                    &profile,
                    payment.x402_value(net),
                    None,
                    None,
                    None,
                    None,
                    None,
                    now_ms,
                )
                .unwrap();
        }
        let observed = ObservedAccount::new(Balance(balance), 1, now_ms, now_ms - 5_000);
        let floor = FloorInput {
            observed: &observed,
            effective_reservations_stroops: 0,
        };
        engine
            .evaluate(
                &descriptor,
                &payment.pay_args(fee),
                &profile,
                Some(&floor),
                None,
                None,
                None,
                None,
                now_ms,
            )
            .unwrap()
    }

    fn pay(engine: &PolicyEngineV1, to: &str, amount: i128, now_ms: u64) -> Decision {
        pay_from(engine, to, amount, now_ms, 1_000 * 10_000_000)
    }

    fn pay_from(
        engine: &PolicyEngineV1,
        to: &str,
        amount: i128,
        now_ms: u64,
        balance_stroops: i64,
    ) -> Decision {
        pay_on(
            engine,
            "stellar_pay",
            to,
            amount,
            (now_ms, balance_stroops),
            Net::Mainnet,
        )
    }

    /// Evaluates a classic payment at `now_ms` with a fresh read of an
    /// account holding `balance_stroops`, as the pay tools do.
    fn pay_on(
        engine: &PolicyEngineV1,
        name: &str,
        to: &str,
        amount: i128,
        (now_ms, balance_stroops): (u64, i64),
        net: Net,
    ) -> Decision {
        let observed = ObservedAccount::new(Balance(balance_stroops), 1, now_ms, now_ms - 5_000);
        let floor = FloorInput {
            observed: &observed,
            effective_reservations_stroops: 0,
        };
        engine
            .evaluate(
                &tool_on(name, net),
                &pay_args(to, amount),
                &net.profile(),
                Some(&floor),
                None,
                None,
                None,
                None,
                now_ms,
            )
            .unwrap()
    }

    fn x402_value(to: &str, amount: i128) -> ValueClass {
        x402_value_on(to, amount, Net::Mainnet)
    }

    fn x402_value_on(to: &str, amount: i128, net: Net) -> ValueClass {
        let sac = CanonicalAsset::parse_threshold_key(&format!("USDC:{ISSUER}"))
            .unwrap()
            .sac_contract_id(net.passphrase())
            .unwrap();
        ValueClass::single(ValueLeg {
            kind: ActionKind::X402Payment,
            amount: Some(amount),
            asset: Some(sac),
            destination: Some(to.to_owned()),
        })
    }

    /// Evaluates an x402 payment as the x402 tools do: without an account view.
    fn x402(engine: &PolicyEngineV1, name: &str, to: &str, amount: i128, now_ms: u64) -> Decision {
        x402_on(engine, name, to, amount, now_ms, Net::Mainnet)
    }

    fn x402_on(
        engine: &PolicyEngineV1,
        name: &str,
        to: &str,
        amount: i128,
        now_ms: u64,
        net: Net,
    ) -> Decision {
        engine
            .evaluate_with_value(
                &tool_on(name, net),
                &serde_json::json!({}),
                &net.profile(),
                x402_value_on(to, amount, net),
                None,
                None,
                None,
                None,
                None,
                now_ms,
            )
            .unwrap()
    }

    /// Evaluates a payment by `tool` at `now_ms` and records it as confirmed
    /// when the evaluation admits it, as the dispatch does after an approved
    /// or allowed payment.
    fn spend(
        engine: &PolicyEngineV1,
        tool: &str,
        to: &str,
        amount: i128,
        now_ms: u64,
        net: Net,
    ) -> Decision {
        let usdc = format!("USDC:{ISSUER}");
        let payment = Payment {
            tool,
            asset: &usdc,
            to,
            amount,
        };
        spend_payment(engine, payment, now_ms, net)
    }

    /// [`spend`] for any [`Payment`].
    fn spend_payment(
        engine: &PolicyEngineV1,
        payment: Payment<'_>,
        now_ms: u64,
        net: Net,
    ) -> Decision {
        let _clock = set_query_time_for_test(now_ms);
        let profile = net.profile();
        let descriptor = tool_on(payment.tool, net);
        let observed = ObservedAccount::new(Balance(i64::MAX), 1, now_ms, now_ms - 5_000);
        let floor = FloorInput {
            observed: &observed,
            effective_reservations_stroops: 0,
        };
        let evaluation = if X402_TOOLS.contains(&payment.tool) {
            engine.evaluate_with_value_full(
                &descriptor,
                &serde_json::json!({}),
                &profile,
                payment.x402_value(net),
                None,
                None,
                None,
                None,
                None,
                now_ms,
            )
        } else {
            engine.evaluate_full(
                &descriptor,
                &payment.pay_args(0),
                &profile,
                Some(&floor),
                None,
                None,
                None,
                None,
                now_ms,
            )
        }
        .unwrap();
        if !matches!(evaluation.decision, Decision::Deny(_)) {
            engine
                .record_confirmed(
                    &descriptor,
                    &profile,
                    &ValueClass::Value(evaluation.value_effects.clone().unwrap()),
                )
                .unwrap();
        }
        evaluation.decision
    }

    /// A rule for `tool` on mainnet with `criteria` after the asset
    /// allowlist of `asset`.
    fn plain_rule(tool: &str, asset: &str, criteria: &[String], decision: &str) -> String {
        let mut all = vec![format!(
            "{{ kind = \"asset_allowlist\", assets = [\"{asset}\"] }}"
        )];
        all.extend(criteria.iter().cloned());
        format!(
            "\n[[rules]]\nmatch = {{ tool = \"{tool}\", chain = \"{MAINNET_CHAIN}\" }}\n\
             criteria = [{}]\ndecision = \"{decision}\"\n",
            all.join(", ")
        )
    }

    fn plain_body(rules: &[String]) -> String {
        format!(
            "version = 2\nscope = \"profile:{PROFILE}\"\nsequence = 1\n{}",
            rules.concat()
        )
    }

    fn period_cap(asset: &str, window: &str, stroops: i128) -> String {
        format!(
            "{{ kind = \"per_period_cap\", asset = \"{asset}\", window = \"{window}\", \
             max_stroops = \"{stroops}\" }}"
        )
    }

    fn per_tx(asset: &str, stroops: i128) -> String {
        format!("{{ kind = \"per_tx_cap\", asset = \"{asset}\", max_stroops = \"{stroops}\" }}")
    }

    fn usdc_sac(net: Net) -> String {
        CanonicalAsset::parse_threshold_key(&format!("USDC:{ISSUER}"))
            .unwrap()
            .sac_contract_id(net.passphrase())
            .unwrap()
    }

    // ── Presets and derivation ─────────────────────────────────────────────

    #[test]
    fn preset_names_are_exact() {
        let names: Vec<&str> = PRESETS.iter().map(|s| s.name).collect();
        assert_eq!(
            names,
            [
                "api-day",
                "api-week",
                "api-2weeks",
                "compute-day",
                "compute-week",
                "compute-2weeks",
                "shop-day",
                "shop-week",
                "shop-2weeks",
                "business-day",
                "business-week",
                "business-2weeks",
            ]
        );
        for name in names {
            assert_eq!(find_preset(name).unwrap().name, name);
        }
        let unknown = find_preset("api-month").unwrap_err();
        assert_eq!(unknown.code(), "profile.preset_invalid");
    }

    #[test]
    fn omitted_preset_is_api_day() {
        assert_eq!(DEFAULT_PRESET, "api-day");
        let preset = default_preset();
        assert_eq!(preset.name, "api-day");
        assert_eq!(preset.archetype, Archetype::Api);
        assert_eq!(preset.unattended_days, 1);
        assert_eq!(preset.tolerated_loss_stroops, 20_000_000);
    }

    /// One row of the preset table: amounts as decimal strings.
    struct Row {
        name: &'static str,
        loss: &'static str,
        days: u32,
        typical: &'static str,
        quantum: &'static str,
        per_tx: &'static str,
        daily: &'static str,
        weekly: &'static str,
        per_minute: u32,
        per_hour: u32,
        approval: Option<&'static str>,
        unlisted_day: Option<&'static str>,
        unlisted_payment: Option<&'static str>,
        floor: &'static str,
        recommended: &'static str,
        allowance: &'static str,
    }

    #[rustfmt::skip]
    const TABLE: [Row; 12] = [
        Row { name: "api-day", loss: "2", days: 1, typical: "0.01", quantum: "1", per_tx: "0.2", daily: "2", weekly: "2", per_minute: 5, per_hour: 25, approval: None, unlisted_day: Some("0.5"), unlisted_payment: Some("0.1"), floor: "1.7", recommended: "2", allowance: "0.5" },
        Row { name: "api-week", loss: "20", days: 7, typical: "0.01", quantum: "1", per_tx: "0.5", daily: "5", weekly: "20", per_minute: 11, per_hour: 63, approval: None, unlisted_day: Some("1.25"), unlisted_payment: Some("0.25"), floor: "2", recommended: "6", allowance: "4.5" },
        Row { name: "api-2weeks", loss: "50", days: 14, typical: "0.01", quantum: "1", per_tx: "0.7", daily: "7", weekly: "25", per_minute: 15, per_hour: 88, approval: None, unlisted_day: Some("1.75"), unlisted_payment: Some("0.35"), floor: "2.2", recommended: "12", allowance: "10.5" },
        Row { name: "compute-day", loss: "20", days: 1, typical: "0.01", quantum: "10", per_tx: "5", daily: "20", weekly: "20", per_minute: 42, per_hour: 250, approval: None, unlisted_day: None, unlisted_payment: None, floor: "3.5", recommended: "6", allowance: "4.5" },
        Row { name: "compute-week", loss: "120", days: 7, typical: "0.01", quantum: "10", per_tx: "7.5", daily: "30", weekly: "120", per_minute: 60, per_hour: 375, approval: None, unlisted_day: None, unlisted_payment: None, floor: "4.5", recommended: "26", allowance: "24.5" },
        Row { name: "compute-2weeks", loss: "300", days: 14, typical: "0.01", quantum: "10", per_tx: "10", daily: "40", weekly: "150", per_minute: 60, per_hour: 500, approval: None, unlisted_day: None, unlisted_payment: None, floor: "5.5", recommended: "62", allowance: "60.5" },
        Row { name: "shop-day", loss: "50", days: 1, typical: "25", quantum: "1", per_tx: "50", daily: "50", weekly: "50", per_minute: 2, per_hour: 6, approval: Some("25"), unlisted_day: None, unlisted_payment: None, floor: "1.6", recommended: "2", allowance: "0.5" },
        Row { name: "shop-week", loss: "500", days: 7, typical: "25", quantum: "20", per_tx: "140", daily: "140", weekly: "500", per_minute: 2, per_hour: 6, approval: Some("70"), unlisted_day: None, unlisted_payment: None, floor: "1.6", recommended: "2", allowance: "0.5" },
        Row { name: "shop-2weeks", loss: "1000", days: 14, typical: "25", quantum: "20", per_tx: "140", daily: "140", weekly: "500", per_minute: 2, per_hour: 6, approval: Some("70"), unlisted_day: None, unlisted_payment: None, floor: "1.6", recommended: "2", allowance: "0.5" },
        Row { name: "business-day", loss: "400", days: 1, typical: "100", quantum: "1", per_tx: "200", daily: "400", weekly: "400", per_minute: 2, per_hour: 6, approval: Some("100"), unlisted_day: None, unlisted_payment: None, floor: "1.6", recommended: "2", allowance: "0.5" },
        Row { name: "business-week", loss: "2000", days: 7, typical: "100", quantum: "20", per_tx: "280", daily: "560", weekly: "2000", per_minute: 2, per_hour: 6, approval: Some("140"), unlisted_day: None, unlisted_payment: None, floor: "1.6", recommended: "2", allowance: "0.5" },
        Row { name: "business-2weeks", loss: "5000", days: 14, typical: "100", quantum: "20", per_tx: "350", daily: "700", weekly: "2500", per_minute: 2, per_hour: 6, approval: Some("175"), unlisted_day: None, unlisted_payment: None, floor: "1.6", recommended: "2", allowance: "0.5" },
    ];

    /// The derivation reproduces the preset table cell for cell, with the
    /// unlisted budget chosen where the archetype offers it. The expected
    /// cells are literals.
    #[test]
    #[allow(clippy::print_stdout, reason = "prints the computed preset table")]
    fn preset_rows_match_independent_constants() {
        println!(
            "| Preset | L | T | p | q | P | D | W | 1m/1h | A | U | P/2 | M | R | R - reserve | O | B |"
        );
        let off = |v: Option<i128>| v.map_or_else(|| "off".to_owned(), format_amount);
        for row in &TABLE {
            let spec = find_preset(row.name).unwrap();
            let unlisted = spec.archetype == Archetype::Api;
            let d = derived(row.name, unlisted, true);
            println!(
                "| {} | {} | {} | {} | {} | {} | {} | {} | {}/{} | {} | {} | {} | {} | {} | {} | {} | {} |",
                row.name,
                format_amount(d.tolerated_loss_stroops),
                d.unattended_days,
                format_amount(d.typical_payment_stroops),
                format_amount(spec.daily_quantum_stroops),
                format_amount(d.per_tx_cap_stroops),
                format_amount(d.daily_cap_stroops),
                format_amount(d.weekly_cap_stroops),
                d.calls_per_minute,
                d.calls_per_hour,
                off(d.approval_above_stroops),
                off(d.unlisted.map(|u| u.per_day_stroops)),
                off(d.unlisted.map(|u| u.per_payment_stroops)),
                format_amount(d.balance_floor_stroops),
                format_amount(d.recommended_balance_stroops),
                format_amount(d.recommended_balance_stroops - d.reserve_stroops),
                format_amount(d.operating_balance_stroops),
                format_amount(d.worst_case_stroops),
            );
            let amount = |v: i128| format_amount(v);
            assert_eq!(amount(d.tolerated_loss_stroops), row.loss, "{} L", row.name);
            assert_eq!(d.unattended_days, row.days, "{} T", row.name);
            assert_eq!(
                amount(d.typical_payment_stroops),
                row.typical,
                "{} p",
                row.name
            );
            assert_eq!(
                amount(spec.daily_quantum_stroops),
                row.quantum,
                "{} q",
                row.name
            );
            assert_eq!(amount(d.per_tx_cap_stroops), row.per_tx, "{} P", row.name);
            assert_eq!(amount(d.daily_cap_stroops), row.daily, "{} D", row.name);
            assert_eq!(amount(d.weekly_cap_stroops), row.weekly, "{} W", row.name);
            assert_eq!(
                (d.calls_per_minute, d.calls_per_hour),
                (row.per_minute, row.per_hour),
                "{} rates",
                row.name
            );
            assert_eq!(
                d.approval_above_stroops.map(amount).as_deref(),
                row.approval,
                "{} A",
                row.name
            );
            assert_eq!(
                d.unlisted.map(|u| amount(u.per_day_stroops)).as_deref(),
                row.unlisted_day,
                "{} U",
                row.name
            );
            assert_eq!(
                d.unlisted.map(|u| amount(u.per_payment_stroops)).as_deref(),
                row.unlisted_payment,
                "{} P/2",
                row.name
            );
            assert_eq!(amount(d.balance_floor_stroops), row.floor, "{} M", row.name);
            assert_eq!(
                amount(d.recommended_balance_stroops),
                row.recommended,
                "{} R",
                row.name
            );
            assert_eq!(
                amount(d.recommended_balance_stroops - d.reserve_stroops),
                row.allowance,
                "{} R - 1.5",
                row.name
            );
            assert_eq!(d.reserve_stroops, 15_000_000, "{} reserve", row.name);
            assert_eq!(d.fee_per_operation_stroops, 10_000, "{} fee", row.name);
            assert_eq!(
                amount(d.operating_balance_stroops),
                row.loss,
                "{} O",
                row.name
            );
            assert_eq!(amount(d.worst_case_stroops), row.loss, "{} B", row.name);
            assert_eq!(
                amount(d.total_budget_stroops.unwrap()),
                row.loss,
                "{} total",
                row.name
            );
        }
    }

    #[test]
    fn daily_rounding_uses_declared_quantum() {
        let spec = find_preset("business-week").unwrap();
        assert_eq!(spec.daily_quantum_stroops, 200_000_000);
        let d = derived("business-week", false, true);
        // min(W, 2L/T) = min(2000, 571.43); 20-USDC steps give 560, 10-USDC steps 570.
        assert_eq!(d.daily_cap_stroops, 5_600_000_000);
        assert_eq!(d.per_tx_cap_stroops, 2_800_000_000);
        assert_eq!(
            derived("shop-2weeks", false, true).daily_cap_stroops,
            1_400_000_000
        );
        assert_eq!(
            derived("compute-2weeks", false, true).daily_cap_stroops,
            400_000_000
        );
    }

    #[test]
    fn r_rounds_from_rounded_m() {
        // shop-day: M = ceil₀.₁(1.5 + 0.002) = 1.6, R = ceil₁(ceil₀.₁(1.602)) = 2.
        let d = derived("shop-day", false, true);
        assert_eq!(d.balance_floor_stroops, 16_000_000);
        assert_eq!(d.recommended_balance_stroops, 20_000_000);
        let d = derived("business-week", false, true);
        assert_eq!(d.balance_floor_stroops, 16_000_000);
        assert_eq!(d.recommended_balance_stroops, 20_000_000);
        // XLM api-week, L = 437.5, p = 1: one day of fees is 0.125 XLM, so
        // M = ceil₀.₁(1.125) = 1.2 and R = ceil₁(ceil₀.₁(1.2 + 0.875)) = 3;
        // rounding raw values independently gives ceil₁(ceil₀.₁(2.0)) = 2.
        let d = derive(&xlm_input("api-week", "437.5", "1")).unwrap();
        assert_eq!(d.balance_floor_stroops, 12_000_000);
        assert_eq!(d.recommended_balance_stroops, 30_000_000);
        // api-day: ceil₀.₁(M + T·0.2) = 1.9 rounds up to 2.
        assert_eq!(
            derived("api-day", false, true).recommended_balance_stroops,
            20_000_000
        );
    }

    /// The approval threshold is at least the typical payment and at most
    /// the per-payment cap, for every preset and three custom XLM inputs, and
    /// the evaluation of the generated body allows a typical payment to a
    /// listed recipient without approval.
    #[test]
    fn approval_threshold_admits_typical_payment() {
        let listed = account(7);
        let mut inputs: Vec<PresetInput> = PRESETS
            .iter()
            .map(|spec| input(spec.name, spec.archetype == Archetype::Api, true))
            .collect();
        // P/2 = p; p above P/2; p equal to P.
        inputs.extend([
            xlm_input("shop-day", "10", "5"),
            xlm_input("business-week", "700", "80"),
            xlm_input("shop-week", "70", "20"),
        ]);
        let mut thresholds = Vec::new();
        for input in &inputs {
            let d = derive(input).unwrap();
            let name = input.preset.name;
            if let Some(threshold) = d.approval_above_stroops {
                assert!(threshold >= d.typical_payment_stroops, "{name}");
                assert!(threshold <= d.per_tx_cap_stroops, "{name}");
            }
            thresholds.push(d.approval_above_stroops.map(format_amount));
            let engine = verified_engine(&listed_body(&d, &listed));
            let args = serde_json::json!({
                "destination": listed,
                "asset": d.asset.policy_id(),
                "amount_stroops": d.typical_payment_stroops.to_string(),
            });
            let observed = ObservedAccount::new(Balance(1_000 * 10_000_000), 1, T0, T0 - 5_000);
            let floor = FloorInput {
                observed: &observed,
                effective_reservations_stroops: 0,
            };
            let decision = engine
                .evaluate(
                    &tool("stellar_pay"),
                    &args,
                    &mainnet_profile(),
                    Some(&floor),
                    None,
                    None,
                    None,
                    None,
                    T0,
                )
                .unwrap();
            assert_eq!(decision, Decision::Allow, "{name}");
        }
        let thresholds: Vec<Option<&str>> = thresholds.iter().map(Option::as_deref).collect();
        assert_eq!(
            thresholds,
            [
                None,
                None,
                None,
                None,
                None,
                None,
                Some("25"),
                Some("70"),
                Some("70"),
                Some("100"),
                Some("140"),
                Some("175"),
                Some("5"),
                Some("80"),
                Some("20"),
            ]
        );
    }

    /// R is a whole number of XLM above M for every preset and for custom
    /// inputs, one of them an XLM profile.
    #[test]
    fn recommended_balance_is_whole_xlm_above_floor() {
        let mut inputs: Vec<PresetInput> = PRESETS
            .iter()
            .map(|spec| input(spec.name, spec.archetype == Archetype::Api, true))
            .collect();
        inputs.extend([
            xlm_input("compute-week", "100", "1"),
            xlm_input("shop-2weeks", "33.3333333", "0.7"),
            xlm_input("business-day", "1234.5678901", "0.05"),
        ]);
        let mut whole = Vec::new();
        for input in &inputs {
            let d = derive(input).unwrap();
            assert_eq!(
                d.recommended_balance_stroops % 10_000_000,
                0,
                "{}",
                input.preset.name
            );
            assert!(d.recommended_balance_stroops > d.balance_floor_stroops);
            whole.push(d.recommended_balance_stroops / 10_000_000);
        }
        assert_eq!(whole, [2, 6, 12, 6, 26, 62, 2, 2, 2, 2, 2, 2, 2, 2, 51]);
    }

    #[test]
    fn xlm_inputs_and_reserve() {
        let d = derive(&xlm_input("api-week", "100", "1")).unwrap();
        assert_eq!(d.asset, PresetAsset::Native);
        assert_eq!(d.tolerated_loss_stroops, 1_000_000_000);
        assert_eq!(d.typical_payment_stroops, 10_000_000);
        assert_eq!(d.unattended_days, 7);
        assert_eq!(d.reserve_stroops, 10_000_000);
        assert_eq!(d.weekly_cap_stroops, 1_000_000_000);
        assert_eq!(d.daily_cap_stroops, 285_714_285);
        assert_eq!(d.per_tx_cap_stroops, 28_571_428);
        assert_eq!((d.calls_per_minute, d.calls_per_hour), (2, 6));
        // M = ceil₀.₁(1.0 + 0.0285714285) = 1.1; R = ceil₁(ceil₀.₁(1.1 + 0.2)) = 2.
        assert_eq!(d.balance_floor_stroops, 11_000_000);
        assert_eq!(d.recommended_balance_stroops, 20_000_000);
        assert_eq!(d.operating_balance_stroops, 1_000_000_000);
        assert_eq!(d.worst_case_stroops, 1_000_000_000);
        assert_eq!(d.total_budget_stroops, Some(1_000_000_000));

        let mut missing = xlm_input("api-week", "100", "1");
        missing.tolerated_loss_stroops = None;
        let error = derive(&missing).unwrap_err();
        assert_eq!(error, PresetError::InputRequired("tolerated_loss"));
        assert_eq!(error.code(), "profile.preset_input_required");
        assert_eq!(error.exit_code(), 1);
        let mut missing = xlm_input("api-week", "100", "1");
        missing.typical_payment_stroops = None;
        assert_eq!(
            derive(&missing).unwrap_err(),
            PresetError::InputRequired("typical_payment")
        );
        let mut usdc_with_amounts = input("api-week", false, true);
        usdc_with_amounts.tolerated_loss_stroops = Some(1_000_000_000);
        let error = derive(&usdc_with_amounts).unwrap_err();
        assert_eq!(error.code(), "profile.preset_invalid");
        assert_eq!(error.exit_code(), 1);
    }

    #[test]
    fn xlm_caps_round_down_to_one_stroop() {
        // compute-week, L = 100 XLM: 2L/T = 28.571428571... floors to one stroop,
        // and P = D/4 = 7.142857125 floors to 7.1428571.
        let d = derive(&xlm_input("compute-week", "100", "1")).unwrap();
        assert_eq!(d.daily_cap_stroops, 285_714_285);
        assert_eq!(d.per_tx_cap_stroops, 71_428_571);
        let d = derive(&xlm_input("shop-2weeks", "33.3333333", "1")).unwrap();
        // W = L / 2 = 16.66666665 floors to 16.6666666; 2L/T = 4.76190475...
        assert_eq!(d.weekly_cap_stroops, 166_666_666);
        assert_eq!(d.daily_cap_stroops, 47_619_047);
        assert_eq!(d.approval_above_stroops, Some(23_809_523));
    }

    #[test]
    fn invalid_amount_refuses() {
        assert_eq!(parse_amount("12").unwrap(), 120_000_000);
        assert_eq!(parse_amount("0.0000001").unwrap(), 1);
        // 10^19 stroops exceeds i64; the derivation and the policy loader
        // accept it.
        let large = parse_amount("1000000000000").unwrap();
        assert_eq!(large, 10_000_000_000_000_000_000);
        let large_input = PresetInput {
            tolerated_loss_stroops: Some(large),
            typical_payment_stroops: Some(parse_amount("100000000").unwrap()),
            ..xlm_input("api-week", "1", "1")
        };
        let body = policy_body(PROFILE, &derive(&large_input).unwrap());
        validate_unsigned_policy(&body, PROFILE, MAINNET_PASSPHRASE).unwrap();
        // i128::MAX stroops parses; its derivation overflows and refuses.
        let largest = parse_amount("17014118346046923173168730371588.4105727").unwrap();
        assert_eq!(largest, i128::MAX);
        let overflowing = PresetInput {
            tolerated_loss_stroops: Some(largest),
            ..large_input
        };
        assert_eq!(
            derive(&overflowing).unwrap_err().code(),
            "profile.preset_invalid"
        );
        for text in [
            "0",
            "0.0000000",
            "-1",
            "+1",
            "0.00000001",
            "1.12345678",
            "17014118346046923173168730371588.4105728",
            "100000000000000000000000000000000000000000",
            "",
            ".5",
            "5.",
            "1e3",
            " 1",
            "1,5",
        ] {
            let error = parse_amount(text).unwrap_err();
            assert_eq!(error.code(), "profile.preset_invalid", "{text:?}");
        }
        let mut zero = xlm_input("api-week", "100", "1");
        zero.tolerated_loss_stroops = Some(0);
        assert_eq!(derive(&zero).unwrap_err().code(), "profile.preset_invalid");
        let mut negative = xlm_input("api-week", "100", "1");
        negative.typical_payment_stroops = Some(-1);
        assert_eq!(
            derive(&negative).unwrap_err().code(),
            "profile.preset_invalid"
        );
        let mut huge = xlm_input("api-week", "100", "1");
        huge.tolerated_loss_stroops = Some(i128::MAX);
        assert_eq!(derive(&huge).unwrap_err().code(), "profile.preset_invalid");
        // A loss too small for a nonzero per-payment cap: D = 1 stroop, P = 0.
        let tiny = PresetInput {
            tolerated_loss_stroops: Some(1),
            typical_payment_stroops: Some(1),
            ..xlm_input("api-day", "1", "1")
        };
        assert!(
            matches!(derive(&tiny), Err(PresetError::Invalid(detail)) if detail.contains("per-payment cap"))
        );
        let unlisted_for_compute = input("compute-week", true, true);
        assert_eq!(
            derive(&unlisted_for_compute).unwrap_err().code(),
            "profile.preset_invalid"
        );
    }

    #[test]
    fn typical_payment_above_cap_refuses() {
        // api-day, L = 1 XLM: D = 1, P = 0.1.
        let at_cap = derive(&xlm_input("api-day", "1", "0.1")).unwrap();
        assert_eq!(at_cap.per_tx_cap_stroops, 1_000_000);
        let above = derive(&xlm_input("api-day", "1", "0.1000001")).unwrap_err();
        assert_eq!(above.code(), "profile.preset_invalid");
        assert!(
            above
                .to_string()
                .contains("exceeds the per-payment cap of 0.1 XLM")
        );
    }

    #[test]
    fn rates_round_up_and_clamp() {
        // api-week: D/(8p) = 62.5 rounds up to 63; 63/6 = 10.5 rounds up to 11.
        let d = derived("api-week", false, true);
        assert_eq!((d.calls_per_minute, d.calls_per_hour), (11, 63));
        // compute-week: 375 per hour gives ceil(62.5) = 63 per minute, clamped to 60.
        let d = derived("compute-week", false, true);
        assert_eq!((d.calls_per_minute, d.calls_per_hour), (60, 375));
        // compute-day: 250 per hour, ceil(41.67) = 42 per minute.
        let d = derived("compute-day", false, true);
        assert_eq!((d.calls_per_minute, d.calls_per_hour), (42, 250));
        // shop-day: D/(8p) = 0.25 rises to the floors of 6 and 2.
        let d = derived("shop-day", false, true);
        assert_eq!((d.calls_per_minute, d.calls_per_hour), (2, 6));
    }

    // ── Generated body ─────────────────────────────────────────────────────

    #[test]
    fn unlisted_per_payment_is_half_p() {
        let body = doc(&policy_body(PROFILE, &derived("api-day", true, true)));
        let rules = rules_of(&body);
        let (_, criteria) = rules
            .iter()
            .find(|(tool, _)| tool == "stellar_x402_create_payment")
            .unwrap();
        let allowlist = of_kind(criteria, "counterparty_allowlist")[0];
        let unlisted = allowlist
            .get("unlisted")
            .and_then(Value::as_inline_table)
            .unwrap();
        assert_eq!(text(unlisted, "mode"), "budget");
        assert_eq!(text(unlisted, "asset"), format!("USDC:{ISSUER}"));
        assert_eq!(text(unlisted, "window"), "1d");
        // P = 0.2 USDC, so P/2 = 0.1 USDC; U = D/4 = 0.5 USDC.
        assert_eq!(text(unlisted, "per_tx_stroops"), "1000000");
        assert_eq!(text(unlisted, "per_period_stroops"), "5000000");
        let summary = summarize(&body, MAINNET_PASSPHRASE, AuthorityStatus::Draft);
        assert_eq!(
            summary.limits[0].unlisted_per_tx_cap.as_deref(),
            Some("0.1")
        );
        assert_eq!(
            summary.limits[0].unlisted_period_cap,
            Agreed::Uniform(Some(PeriodCap {
                window: "1d".to_owned(),
                amount: "0.5".to_owned()
            }))
        );
    }

    #[test]
    fn unlisted_no_omits_budget() {
        for spec in &PRESETS {
            let body = policy_body(PROFILE, &derived(spec.name, false, true));
            assert!(!body.contains("unlisted"), "{}", spec.name);
        }
        assert!(policy_body(PROFILE, &derived("api-week", true, true)).contains("unlisted"));
    }

    #[test]
    fn total_budget_choice_controls_criterion() {
        for spec in &PRESETS {
            let with = doc(&policy_body(PROFILE, &derived(spec.name, false, true)));
            for (tool, criteria) in rules_of(&with) {
                let totals = of_kind(&criteria, "total_budget");
                if PAYMENT_TOOLS.contains(&tool.as_str()) {
                    assert_eq!(totals.len(), 1, "{} {tool}", spec.name);
                    assert_eq!(text(totals[0], "asset"), format!("USDC:{ISSUER}"));
                    assert_eq!(
                        text(totals[0], "max_stroops"),
                        spec.tolerated_loss_stroops.to_string()
                    );
                } else {
                    assert!(totals.is_empty(), "{} {tool}", spec.name);
                }
            }
            let without = policy_body(PROFILE, &derived(spec.name, false, false));
            assert!(!without.contains("total_budget"), "{}", spec.name);
        }
    }

    #[test]
    fn approval_only_for_shop_and_business() {
        for spec in &PRESETS {
            let body = doc(&policy_body(PROFILE, &derived(spec.name, false, true)));
            let expected = match spec.archetype {
                Archetype::Api | Archetype::Compute => None,
                Archetype::Shop | Archetype::Business => {
                    Some(derived(spec.name, false, true).per_tx_cap_stroops / 2)
                }
            };
            for (tool, criteria) in rules_of(&body) {
                let approvals: Vec<i128> = of_kind(&criteria, "approval_above")
                    .into_iter()
                    .map(|c| text(c, "max_stroops").parse().unwrap())
                    .collect();
                match expected {
                    Some(threshold) if PAYMENT_TOOLS.contains(&tool.as_str()) => {
                        assert_eq!(approvals, [threshold], "{} {tool}", spec.name);
                    }
                    _ => assert!(approvals.is_empty(), "{} {tool}", spec.name),
                }
            }
        }
        assert_eq!(
            derived("shop-week", false, true).approval_above_stroops,
            Some(700_000_000)
        );
        assert_eq!(derived("api-week", true, true).approval_above_stroops, None);
        assert_eq!(
            derived("compute-day", false, true).approval_above_stroops,
            None
        );
    }

    #[test]
    fn body_has_no_comment_and_no_mainnet_table() {
        for input in usdc_inputs() {
            let body = policy_body(PROFILE, &derive(&input).unwrap());
            assert!(!body.contains('#'), "{}", input.preset.name);
            assert!(!body.contains("[mainnet]"), "{}", input.preset.name);
            assert!(
                body.starts_with("version = 2\nscope = \"profile:preset-test\"\nsequence = 1\n"),
                "{}",
                input.preset.name
            );
            let parsed = doc(&body);
            assert!(!parsed.contains_key("mainnet"));
            assert!(!parsed.contains_key("signature"));
            assert_eq!(
                parsed.iter().map(|(key, _)| key).collect::<Vec<_>>(),
                ["version", "scope", "sequence", "rules"]
            );
        }
    }

    #[test]
    fn body_uses_supplied_usdc_identity() {
        let other = PresetInput {
            asset: PresetAsset::Usdc {
                issuer: OTHER_ISSUER.to_owned(),
            },
            ..input("shop-week", false, true)
        };
        let body = policy_body(PROFILE, &derive(&other).unwrap());
        assert!(!body.contains(ISSUER));
        assert!(!body.contains("\"USDC\""));
        assert!(!body.contains("native"));
        let identity = format!("\"USDC:{OTHER_ISSUER}\"");
        // Four payment rules name the asset in the allowlist and four caps,
        // plus the approval threshold and total budget; two trustline rules.
        assert_eq!(body.matches(&identity).count(), 4 * 6 + 2);
        let native = policy_body(
            PROFILE,
            &derive(&xlm_input("api-week", "100", "1")).unwrap(),
        );
        assert!(!native.contains("USDC"));
        assert_eq!(native.matches("\"native\"").count(), 4 * 5);
    }

    #[test]
    fn generated_body_passes_authoring_validation() {
        let mut inputs = usdc_inputs();
        for spec in &PRESETS {
            inputs.push(xlm_input(spec.name, "500", "1"));
        }
        for input in &inputs {
            let body = policy_body(PROFILE, &derive(input).unwrap());
            validate_unsigned_policy(&body, PROFILE, MAINNET_PASSPHRASE).unwrap_or_else(|error| {
                panic!(
                    "{} unlisted={} total={}: {error}",
                    input.preset.name, input.unlisted_budget, input.total_budget
                )
            });
            assert!(validate_unsigned_policy(&body, "other", MAINNET_PASSPHRASE).is_err());
        }
        let body = policy_body(PROFILE, &derived("api-day", true, true));
        let unsequenced = body.replace("sequence = 1\n", "");
        assert!(validate_unsigned_policy(&unsequenced, PROFILE, MAINNET_PASSPHRASE).is_err());
    }

    #[test]
    fn generated_rules_meet_mainnet_rule_minimum() {
        let profile = mainnet_profile();
        let mut inputs = usdc_inputs();
        inputs.push(xlm_input("shop-week", "500", "10"));
        for input in &inputs {
            let body = doc(&policy_body(PROFILE, &derive(input).unwrap()));
            for outcome in mainnet_minimum::evaluate(&body, &profile, PROFILE) {
                let table = matches!(
                    outcome.requirement,
                    "mainnet_table"
                        | "fee_cap"
                        | "thresholds"
                        | "ttl"
                        | "approval_credentials"
                        | "approval.cert_pin_without_origin"
                        | "approval.origin_without_cert_pin"
                );
                if table {
                    assert_eq!(
                        outcome.status,
                        RequirementStatus::Failed {
                            rules: vec![],
                            detail: "the [mainnet] table is missing".to_owned(),
                        },
                        "{} {}",
                        input.preset.name,
                        outcome.requirement
                    );
                } else {
                    assert_eq!(
                        outcome.status,
                        RequirementStatus::Passed,
                        "{} {}",
                        input.preset.name,
                        outcome.requirement
                    );
                }
            }
        }
    }

    #[test]
    fn auxiliary_rules_have_exact_windows() {
        for asset in [usdc(), PresetAsset::Native] {
            let input = match asset {
                PresetAsset::Native => xlm_input("compute-week", "100", "1"),
                PresetAsset::Usdc { .. } => input("compute-week", false, true),
            };
            let body = doc(&policy_body(PROFILE, &derive(&input).unwrap()));
            for (tool, criteria) in rules_of(&body) {
                let auxiliary = MAINNET_TRUSTLINE_TOOLS.contains(&tool.as_str())
                    || MAINNET_CLAIM_TOOLS.contains(&tool.as_str());
                if !auxiliary {
                    continue;
                }
                assert_eq!(
                    rates(&criteria),
                    [("1m".to_owned(), 2), ("1h".to_owned(), 6)],
                    "{tool}"
                );
                let allowlists = of_kind(&criteria, "asset_allowlist");
                if MAINNET_CLAIM_TOOLS.contains(&tool.as_str()) {
                    assert!(allowlists.is_empty(), "{tool}");
                    assert_eq!(criteria.len(), 2, "{tool}");
                } else {
                    assert_eq!(allowlists.len(), 1, "{tool}");
                    let assets = allowlists[0]
                        .get("assets")
                        .and_then(Value::as_array)
                        .unwrap();
                    assert_eq!(
                        assets.iter().filter_map(Value::as_str).collect::<Vec<_>>(),
                        [format!("USDC:{ISSUER}")],
                        "{tool}"
                    );
                    assert_eq!(criteria.len(), 3, "{tool}");
                }
            }
        }
    }

    #[test]
    fn payment_rules_list_every_address_kind() {
        for input in usdc_inputs() {
            let body = doc(&policy_body(PROFILE, &derive(&input).unwrap()));
            for (tool, criteria) in rules_of(&body) {
                let lists = of_kind(&criteria, "counterparty_allowlist");
                if !PAYMENT_TOOLS.contains(&tool.as_str()) {
                    assert!(lists.is_empty(), "{tool}");
                    continue;
                }
                assert_eq!(lists.len(), 1, "{tool}");
                let strings = |key: &str| {
                    lists[0]
                        .get(key)
                        .and_then(Value::as_array)
                        .unwrap()
                        .iter()
                        .map(|v| v.as_str().unwrap().to_owned())
                        .collect::<Vec<_>>()
                };
                assert_eq!(strings("kinds"), ["G_ACCOUNT", "C_ACCOUNT"], "{tool}");
                assert!(strings("allowlist").is_empty(), "{tool}");
            }
        }
    }

    #[test]
    fn unlisted_tables_equal_on_every_payment_rule() {
        for name in ["api-day", "api-week", "api-2weeks"] {
            for total in [true, false] {
                let body = policy_body(PROFILE, &derived(name, true, total));
                validate_unsigned_policy(&body, PROFILE, MAINNET_PASSPHRASE)
                    .unwrap_or_else(|error| panic!("{name}: {error}"));
                let tables: Vec<(String, String)> = rules_of(&doc(&body))
                    .into_iter()
                    .flat_map(|(tool, criteria)| {
                        criteria
                            .iter()
                            .filter_map(|c| c.get("unlisted"))
                            .map(|table| (tool.clone(), table.to_string().trim().to_owned()))
                            .collect::<Vec<_>>()
                    })
                    .collect();
                let carriers: Vec<&str> = tables.iter().map(|(tool, _)| tool.as_str()).collect();
                assert_eq!(carriers, PAYMENT_TOOLS, "{name}");
                assert!(
                    tables.iter().all(|(_, text)| *text == tables[0].1),
                    "{name}: {tables:?}"
                );
                let summary = summary_of(&body);
                let limits = &summary.limits[0];
                assert_eq!(limits.unlisted_mode, Agreed::Uniform(Some("budget")));
                assert_eq!(limits.unlisted_tools, PAYMENT_TOOLS);
                let unlisted: Vec<&Counter> = limits
                    .counters
                    .iter()
                    .filter(|c| c.kind == "unlisted")
                    .collect();
                assert_eq!(unlisted.len(), 1, "{name}");
                assert_eq!(unlisted[0].tools, PAYMENT_TOOLS, "{name}");
            }
        }
    }

    fn muxed(seed: u8, id: u64) -> String {
        stellar_strkey::ed25519::MuxedAccount {
            ed25519: [seed; 32],
            id,
        }
        .to_string()
        .as_str()
        .to_owned()
    }

    fn contract(seed: u8) -> String {
        stellar_strkey::Contract([seed; 32])
            .to_string()
            .as_str()
            .to_owned()
    }

    /// The allowlist of every payment rule of `body`, in rule order.
    fn payment_lists(body: &str) -> Vec<(String, Vec<String>)> {
        rules_of(&doc(body))
            .into_iter()
            .filter(|(tool, _)| PAYMENT_TOOLS.contains(&tool.as_str()))
            .map(|(tool, criteria)| {
                let list = of_kind(&criteria, "counterparty_allowlist")[0]
                    .get("allowlist")
                    .and_then(Value::as_array)
                    .unwrap()
                    .iter()
                    .map(|v| v.as_str().unwrap().to_owned())
                    .collect();
                (tool, list)
            })
            .collect()
    }

    #[test]
    fn add_recipient_accepts_every_address_form() {
        let (g, m, c) = (account(7), muxed(8, 5), contract(3));
        let body = policy_body(PROFILE, &derived("api-day", false, true));
        let mut added = body.clone();
        for recipient in [&g, &m, &c] {
            added = add_recipient(&added, recipient).unwrap();
        }
        validate_unsigned_policy(&added, PROFILE, MAINNET_PASSPHRASE).unwrap();
        for (tool, list) in payment_lists(&added) {
            assert_eq!(list, [g.clone(), m.clone(), c.clone()], "{tool}");
        }
        // A list that names the recipient stays unchanged.
        assert_eq!(add_recipient(&added, &m).unwrap(), added);

        // A rule whose list selects G only takes G and M, never C.
        let mixed = edit_rules(&body, &["stellar_pay"], |criteria| {
            for value in criteria.iter_mut() {
                let table = value.as_inline_table_mut().unwrap();
                if table["kind"].as_str() == Some("counterparty_allowlist") {
                    table.insert("kinds", Value::from_iter(["G_ACCOUNT"]));
                }
            }
        });
        let mut added = mixed;
        for recipient in [&g, &m, &c] {
            added = add_recipient(&added, recipient).unwrap();
        }
        for (tool, list) in payment_lists(&added) {
            let expected = if tool == "stellar_pay" {
                vec![g.clone(), m.clone()]
            } else {
                vec![g.clone(), m.clone(), c.clone()]
            };
            assert_eq!(list, expected, "{tool}");
        }
        let g_only = body.replace(
            "kinds = [\"G_ACCOUNT\", \"C_ACCOUNT\"]",
            "kinds = [\"G_ACCOUNT\"]",
        );
        assert_eq!(
            add_recipient(&g_only, &c),
            Err(PresetError::Invalid(
                "no counterparty list of the body checks C_ACCOUNT recipients".to_owned()
            ))
        );
        assert!(add_recipient(&g_only, &m).unwrap().contains(&m));

        // Every other form refuses, with no list changed.
        let pool = stellar_strkey::Strkey::LiquidityPool(stellar_strkey::LiquidityPool([4; 32]))
            .to_string()
            .as_str()
            .to_owned();
        for other in [pool.as_str(), "not-an-address", ""] {
            assert_eq!(
                add_recipient(&body, other),
                Err(PresetError::Invalid(format!(
                    "recipient {other:?} is not a G, M, or C address"
                ))),
                "{other}"
            );
        }
    }

    /// The summary lists a recipient as the engine does. G and C kinds are
    /// alternatives, and an M address matches its exact entry or its base G.
    /// An entry of an unselected kind is unlisted.
    #[test]
    fn summary_treats_address_kinds_as_alternatives() {
        let (g, m, c) = (account(7), muxed(8, 5), contract(3));
        let body = policy_body(PROFILE, &derived("api-day", false, true));
        let mut main = body.clone();
        for recipient in [&g, &m, &c] {
            main = add_recipient(&main, recipient).unwrap();
        }
        let summary = summary_of(&main);
        assert_eq!(summary.recipients.kinds, ["G_ACCOUNT", "C_ACCOUNT"]);
        assert!(summary.recipients.without_listed_recipient.is_empty());
        let listed: Vec<(&str, &Agreed<Treatment>)> = summary
            .recipients
            .listed
            .iter()
            .map(|r| (r.recipient.as_str(), &r.treatment))
            .collect();
        let allowed = Agreed::Uniform(Some(Treatment::Allowed));
        assert_eq!(
            listed,
            [
                (g.as_str(), &allowed),
                (m.as_str(), &allowed),
                (c.as_str(), &allowed)
            ]
        );
        let engine = verified_engine(&main);
        let amount = 100_000;
        assert_eq!(pay(&engine, &g, amount, T0), Decision::Allow);
        assert_eq!(pay(&engine, &muxed(7, 9), amount, T0), Decision::Allow);
        assert_eq!(pay(&engine, &m, amount, T0), Decision::Allow);
        assert_eq!(label(&pay(&engine, &muxed(8, 6), amount, T0)), "deny");
        assert_eq!(x402(&engine, CREATE_TOOL, &c, amount, T0), Decision::Allow);

        // A list that selects G only leaves its C entry unlisted.
        let g_only = main.replace(
            "kinds = [\"G_ACCOUNT\", \"C_ACCOUNT\"]",
            "kinds = [\"G_ACCOUNT\"]",
        );
        let summary = summary_of(&g_only);
        let c_entry = summary
            .recipients
            .listed
            .iter()
            .find(|r| r.recipient == c)
            .unwrap();
        assert_eq!(c_entry.treatment, Agreed::Uniform(Some(Treatment::Denied)));
        assert_eq!(
            label(&x402(
                &verified_engine(&g_only),
                CREATE_TOOL,
                &c,
                amount,
                T0
            )),
            "deny"
        );

        // An M address alone is a recipient the pay rule pays.
        let m_only = add_recipient(&body, &m).unwrap();
        let summary = summary_of(&m_only);
        let pay_limits = tool_limits(&summary, "stellar_pay");
        assert_eq!(pay_limits.largest_payment, pay_limits.per_tx_cap);
        assert_eq!(pay_limits.largest_payment.as_deref(), Some("0.2"));
    }

    #[test]
    fn tool_coverage_matches_table() {
        let payment = [
            "stellar_pay",
            "stellar_pay_commit",
            "stellar_x402_create_payment",
            "stellar_x402_authenticated_payment",
        ];
        let trustline = ["stellar_trustline", "stellar_trustline_commit"];
        let claim = ["stellar_claim", "stellar_claim_commit"];
        let usdc_tools: Vec<&str> = payment
            .iter()
            .chain(&trustline)
            .chain(&claim)
            .chain(&READ_ONLY)
            .copied()
            .collect();
        let xlm_tools: Vec<&str> = payment
            .iter()
            .chain(&claim)
            .chain(&READ_ONLY)
            .copied()
            .collect();
        for (input, expected, uncovered) in [
            (
                input("api-week", true, true),
                &usdc_tools,
                vec!["stellar_create_account", "stellar_create_account_commit"],
            ),
            (
                xlm_input("api-week", "100", "1"),
                &xlm_tools,
                vec![
                    "stellar_create_account",
                    "stellar_create_account_commit",
                    "stellar_trustline",
                    "stellar_trustline_commit",
                ],
            ),
        ] {
            let body = policy_body(PROFILE, &derive(&input).unwrap());
            let rules = rules_of(&doc(&body));
            let tools: Vec<&str> = rules.iter().map(|(tool, _)| tool.as_str()).collect();
            assert_eq!(&tools, expected);
            for (tool, criteria) in &rules {
                if READ_ONLY.contains(&tool.as_str()) {
                    assert!(criteria.is_empty(), "{tool}");
                }
            }
            let parsed = doc(&body);
            for rule in parsed["rules"].as_array_of_tables().unwrap() {
                assert_eq!(rule["match"]["chain"].as_str(), Some("stellar:mainnet"));
                assert_eq!(rule["decision"].as_str(), Some("allow"));
                assert_eq!(rule["allow_opaque_signing"].as_bool(), Some(false));
            }
            let summary = summary_of(&body);
            assert_eq!(summary.tools.uncovered, uncovered);
            assert_eq!(summary.tools.covered.len(), expected.len());
            for tool in expected.iter() {
                assert!(summary.tools.covered.iter().any(|t| t == tool), "{tool}");
            }
        }
    }

    #[test]
    fn x402_floor_note_matches_evaluation() {
        let listed = account(7);
        let derived = derived("api-week", false, true);
        let body = listed_body(&derived, &listed);
        // The engine allows an x402 call without an account view, and the
        // note states that no floor applies to it.
        let engine = verified_engine(&body);
        for name in X402_TOOLS {
            assert_eq!(
                x402(&engine, name, &listed, 100_000, T0),
                Decision::Allow,
                "{name}"
            );
        }
        let summary = summary_of(&body);
        assert_eq!(summary.balance_floor_xlm.as_deref(), Some("2"));
        assert!(
            summary
                .notes
                .contains(&"The balance floor does not apply to x402 payments.".to_owned())
        );
        for (tool, criteria) in rules_of(&doc(&body)) {
            let floors = of_kind(&criteria, "balance_floor");
            if FLOOR_TOOLS.contains(&tool.as_str()) {
                assert_eq!(text(floors[0], "min_stroops"), "20000000", "{tool}");
            } else {
                assert!(floors.is_empty(), "{tool}");
            }
        }
    }

    /// A floor on the authenticated x402 rule only: the exemption names the
    /// floor-free tool, and the floored tool is stated as denying every call.
    #[test]
    fn x402_floor_note_names_floor_free_tools() {
        let listed = account(7);
        let body = edit_rules(
            &listed_body(&derived("compute-week", false, true), &listed),
            &["stellar_x402_authenticated_payment"],
            |criteria| {
                criteria.push(criterion(
                    "{ kind = \"balance_floor\", min_stroops = \"100000000\" }",
                ));
            },
        );
        let engine = verified_engine(&body);
        assert_eq!(
            x402(&engine, CREATE_TOOL, &listed, 100_000, T0),
            Decision::Allow
        );
        assert_eq!(
            x402(
                &engine,
                "stellar_x402_authenticated_payment",
                &listed,
                100_000,
                T0
            ),
            Decision::Deny(DenyReason::AccountUnread)
        );
        let summary = summary_of(&body);
        let floor_notes: Vec<&String> = summary
            .notes
            .iter()
            .filter(|n| n.contains("balance floor"))
            .collect();
        assert_eq!(
            floor_notes,
            [
                "The balance floor does not apply to stellar_x402_create_payment.",
                "stellar_x402_authenticated_payment denies every call: its rule carries a \
                 balance floor, and x402 tools evaluate without an account view.",
            ]
        );
        let authenticated = tool_limits(&summary, "stellar_x402_authenticated_payment");
        assert!(authenticated.denies_every_call);
        assert_eq!(authenticated.unlisted_mode, "deny");
        assert_eq!(authenticated.recipients[0].treatment, Treatment::Denied);
        assert!(!tool_limits(&summary, CREATE_TOOL).denies_every_call);
        let floors: Vec<(&str, Option<&str>)> = summary
            .balance_floors
            .iter()
            .map(|f| (f.tool.as_str(), f.floor_xlm.as_deref()))
            .collect();
        assert_eq!(
            floors,
            [
                ("stellar_pay", Some("4.5")),
                ("stellar_pay_commit", Some("4.5")),
                (CREATE_TOOL, None),
                ("stellar_x402_authenticated_payment", Some("10")),
            ]
        );
        assert_eq!(summary.balance_floor_xlm.as_deref(), Some("4.5"));
    }

    #[test]
    fn x402_approval_note_matches_evaluation() {
        let listed = account(7);
        let base = listed_body(&derived("shop-week", false, true), &listed);
        let approval_notes = |summary: &SpendingSummary| -> Vec<String> {
            summary
                .notes
                .iter()
                .filter(|n| n.contains(" approval above "))
                .cloned()
                .collect()
        };
        const CREATE: &str = "stellar_x402_create_payment";
        const AUTHENTICATED: &str = "stellar_x402_authenticated_payment";
        let without_threshold = |tool: &str| {
            edit_rules(&base, &[tool], |criteria| {
                criteria.retain(|c| {
                    c.as_inline_table().unwrap()["kind"].as_str() != Some("approval_above")
                });
            })
        };
        for (carriers, body) in [
            (vec![CREATE, AUTHENTICATED], base.clone()),
            (vec![CREATE], without_threshold(AUTHENTICATED)),
            (vec![AUTHENTICATED], without_threshold(CREATE)),
        ] {
            for net in [Net::Mainnet, Net::Testnet] {
                let body = net.body(&body);
                let engine = verified_engine_on(&body, net);
                // A = 70 USDC: equality passes, and one stroop more requests
                // approval on a tool that carries the threshold.
                for name in X402_TOOLS {
                    let above = if carriers.contains(&name) {
                        "approval"
                    } else {
                        "allow"
                    };
                    assert_eq!(
                        label(&x402_on(&engine, name, &listed, 700_000_000, T0, net)),
                        "allow"
                    );
                    assert_eq!(
                        label(&x402_on(&engine, name, &listed, 700_000_001, T0, net)),
                        above,
                        "{name} {net:?} {carriers:?}"
                    );
                }
                let verb = if carriers.len() > 1 {
                    "require"
                } else {
                    "requires"
                };
                let clause = match (net, cfg!(feature = "mainnet-write")) {
                    (Net::Mainnet, true) => {
                        "without an approval proof, a call above it returns a pending approval"
                    }
                    (Net::Mainnet, false) => {
                        "this build has no mainnet writes and refuses every mainnet payment"
                    }
                    (Net::Testnet, _) => "on this network a call above it is refused",
                };
                assert_eq!(
                    approval_notes(&net.summary(&body)),
                    [format!(
                        "{} {verb} approval above 70 USDC: {clause}.",
                        carriers.join(" and ")
                    )],
                    "{net:?} {carriers:?}"
                );
            }
        }
        let api = summary_of(&policy_body(PROFILE, &derived("api-week", false, true)));
        assert!(approval_notes(&api).is_empty());
    }

    #[test]
    fn payment_rules_carry_all_caps() {
        for input in usdc_inputs() {
            let d = derive(&input).unwrap();
            let body = doc(&policy_body(PROFILE, &d));
            let asset = format!("USDC:{ISSUER}");
            let mut payment_rules = 0;
            for (tool, criteria) in rules_of(&body) {
                if !PAYMENT_TOOLS.contains(&tool.as_str()) {
                    assert!(of_kind(&criteria, "per_tx_cap").is_empty());
                    continue;
                }
                payment_rules += 1;
                let caps = |kind: &str, window: Option<&str>| -> Vec<String> {
                    of_kind(&criteria, kind)
                        .into_iter()
                        .filter(|c| window.is_none_or(|w| text(c, "window") == w))
                        .inspect(|c| assert_eq!(text(c, "asset"), asset))
                        .map(|c| text(c, "max_stroops").to_owned())
                        .collect()
                };
                assert_eq!(
                    caps("per_tx_cap", None),
                    [d.per_tx_cap_stroops.to_string()],
                    "{tool}"
                );
                assert_eq!(
                    caps("per_period_cap", Some("1d")),
                    [d.daily_cap_stroops.to_string()],
                    "{tool}"
                );
                assert_eq!(
                    caps("per_period_cap", Some("1w")),
                    [d.weekly_cap_stroops.to_string()],
                    "{tool}"
                );
                assert_eq!(of_kind(&criteria, "per_period_cap").len(), 2, "{tool}");
                assert_eq!(
                    rates(&criteria),
                    [
                        ("1m".to_owned(), i64::from(d.calls_per_minute)),
                        ("1h".to_owned(), i64::from(d.calls_per_hour)),
                    ],
                    "{tool}"
                );
                let assets = of_kind(&criteria, "asset_allowlist");
                assert_eq!(assets.len(), 1, "{tool}");
            }
            assert_eq!(payment_rules, 4);
        }
    }

    // ── Summary ────────────────────────────────────────────────────────────

    #[test]
    fn summary_reads_actual_body() {
        let body = listed_body(&derived("api-day", false, true), &account(7));
        let generated = summary_of(&body);
        assert_eq!(cap_of(&generated.limits[0], "1d"), Some("2"));
        assert_eq!(generated.limits[0].per_tx_cap.as_deref(), Some("0.2"));
        let authored = body
            .replace(
                "window = \"1d\", max_stroops = \"20000000\"",
                "window = \"1d\", max_stroops = \"15000000\"",
            )
            .replace("max_stroops = \"2000000\"", "max_stroops = \"3000000\"");
        let summary = summary_of(&authored);
        let limits = &summary.limits[0];
        assert_eq!(limits.asset, format!("USDC:{ISSUER}"));
        assert_eq!(cap_of(limits, "1d"), Some("1.5"));
        assert_eq!(limits.per_tx_cap.as_deref(), Some("0.3"));
        assert_eq!(bound_of(limits, "1d").as_deref(), Some("1.5"));
        assert_eq!(summary.policy_version, Some(2));
        assert_eq!(summary.sequence, Some(1));
        assert_eq!(summary.authority_status, AuthorityStatus::Draft);
        let resequenced = summarize(
            &doc(&authored.replace("sequence = 1", "sequence = 9")),
            MAINNET_PASSPHRASE,
            AuthorityStatus::Verified,
        );
        assert_eq!(resequenced.sequence, Some(9));
        assert_eq!(resequenced.authority_status, AuthorityStatus::Verified);
    }

    #[test]
    fn summary_bounds_per_day_week_signature() {
        // api-2weeks: D = 7, W = 25, L = 50.
        let body = listed_body(&derived("api-2weeks", false, true), &account(7));
        let limits = summary_of(&body).limits.remove(0);
        assert_eq!(bound_of(&limits, "1d").as_deref(), Some("7"));
        assert_eq!(bound_of(&limits, "1w").as_deref(), Some("25"));
        assert_eq!(bound_of(&limits, "total").as_deref(), Some("50"));
        // A body that lists no recipient pays no listed recipient: the
        // listed bound is 0, reached by paying nothing, and the recipient
        // statement names every payment tool.
        let unlisted = summary_of(&policy_body(PROFILE, &derived("api-2weeks", false, true)));
        let day = unlisted.limits[0]
            .bounds
            .iter()
            .find(|b| b.window == "1d")
            .unwrap();
        assert_eq!((day.amount.as_deref(), day.reachable), (Some("0"), true));
        assert_eq!(
            unlisted.limits[0].largest_payment,
            Agreed::Uniform(Some("0".to_owned()))
        );
        assert_eq!(
            unlisted.recipients.without_listed_recipient,
            [
                "stellar_pay",
                "stellar_pay_commit",
                CREATE_TOOL,
                "stellar_x402_authenticated_payment"
            ]
        );
        assert!(
            summary_of(&body)
                .recipients
                .without_listed_recipient
                .is_empty()
        );
        assert!(limits.bounds.iter().all(|b| b.reachable));
        let with_total = |total: &str| {
            summary_of(&body.replace(
                "kind = \"total_budget\", asset = \"USDC:GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN\", max_stroops = \"500000000\"",
                &format!(
                    "kind = \"total_budget\", asset = \"USDC:{ISSUER}\", max_stroops = \"{total}\""
                ),
            ))
            .limits
            .remove(0)
        };
        let ten = with_total("100000000");
        assert_eq!(bound_of(&ten, "1d").as_deref(), Some("7"));
        assert_eq!(bound_of(&ten, "1w").as_deref(), Some("10"));
        assert_eq!(bound_of(&ten, "total").as_deref(), Some("10"));
        let five = with_total("50000000");
        assert_eq!(bound_of(&five, "1d").as_deref(), Some("5"));
        assert_eq!(bound_of(&five, "1w").as_deref(), Some("5"));
        // 7·cap_1d bounds the week when it is below cap_1w.
        let weekly = summary_of(&body.replace(
            "window = \"1w\", max_stroops = \"250000000\"",
            "window = \"1w\", max_stroops = \"600000000\"",
        ))
        .limits
        .remove(0);
        assert_eq!(bound_of(&weekly, "1w").as_deref(), Some("49"));
        let without_total = summary_of(&listed_body(
            &derived("api-2weeks", false, false),
            &account(7),
        ))
        .limits
        .remove(0);
        assert_eq!(without_total.total_budget, Agreed::Uniform(None));
        assert_eq!(bound_of(&without_total, "total"), &Agreed::Uniform(None));
        assert_eq!(bound_of(&without_total, "1w").as_deref(), Some("25"));
    }

    #[test]
    fn summary_uses_first_match_rules() {
        let asset = format!("\"USDC:{ISSUER}\"");
        let rule = |tool: &str, cap: &str, decision: &str| {
            format!(
                "\n[[rules]]\nmatch = {{ tool = \"{tool}\", chain = \"stellar:mainnet\" }}\n\
                 criteria = [{{ kind = \"asset_allowlist\", assets = [{asset}] }}, \
                 {{ kind = \"per_tx_cap\", asset = {asset}, max_stroops = \"{cap}\" }}]\n\
                 decision = \"{decision}\"\n"
            )
        };
        let body = format!(
            "version = 2\nscope = \"profile:{PROFILE}\"\nsequence = 1\n{}{}{}{}",
            rule("stellar_pay", "10000000", "allow"),
            rule("stellar_pay", "1000000000", "allow"),
            rule("stellar_pay_commit", "10000000", "deny"),
            rule("stellar_pay_commit", "1000000000", "allow"),
        );
        let summary = summary_of(&body);
        assert_eq!(summary.limits.len(), 1);
        assert_eq!(summary.limits[0].per_tx_cap.as_deref(), Some("1"));
        assert!(summary.tools.covered.contains(&"stellar_pay".to_owned()));
        assert!(
            summary
                .tools
                .uncovered
                .contains(&"stellar_pay_commit".to_owned())
        );
        // A rule for another chain does not match a mainnet tool.
        let testnet_first = body.replacen("stellar:mainnet", "stellar:testnet", 1);
        assert_eq!(
            summary_of(&testnet_first).limits[0].per_tx_cap.as_deref(),
            Some("100")
        );
    }

    /// `body` with each criterion of the rules of `tools` passed to `edit`,
    /// which may append to or filter the criteria.
    fn edit_rules(body: &str, tools: &[&str], edit: impl Fn(&mut toml_edit::Array)) -> String {
        let mut parsed = doc(body);
        for rule in parsed["rules"].as_array_of_tables_mut().unwrap().iter_mut() {
            if tools.contains(&rule["match"]["tool"].as_str().unwrap()) {
                edit(rule["criteria"].as_array_mut().unwrap());
            }
        }
        parsed.to_string()
    }

    fn criterion(text: &str) -> Value {
        text.parse().unwrap()
    }

    #[test]
    fn summary_recipients_intersect_within_rule() {
        let (first, second) = (account(7), account(9));
        let body = listed_body(&derived("compute-week", false, true), &first);
        let listed = |summary: &SpendingSummary| -> Vec<(String, Agreed<Treatment>)> {
            summary
                .recipients
                .listed
                .iter()
                .map(|l| (l.recipient.clone(), l.treatment.clone()))
                .collect()
        };
        assert_eq!(
            listed(&summary_of(&body)),
            [(first.clone(), Agreed::Uniform(Some(Treatment::Allowed)))]
        );
        let narrowed = edit_rules(&body, &PAYMENT_TOOLS, |criteria| {
            criteria.push(criterion(&format!(
                "{{ kind = \"counterparty_allowlist\", kinds = [\"G_ACCOUNT\"], allowlist = [\"{second}\"] }}"
            )));
        });
        let engine = verified_engine(&narrowed);
        for to in [&first, &second] {
            assert_eq!(label(&pay(&engine, to, 100_000, T0)), "deny");
            assert_eq!(label(&x402(&engine, CREATE_TOOL, to, 100_000, T0)), "deny");
        }
        let summary = summary_of(&narrowed);
        let denied = Agreed::Uniform(Some(Treatment::Denied));
        assert_eq!(
            listed(&summary),
            [(first, denied.clone()), (second, denied)]
        );
        assert!(summary.recipients.unrestricted_tools.is_empty());
        assert_eq!(
            summary.limits[0].unlisted_mode,
            Agreed::Uniform(Some("deny"))
        );
    }

    /// A budget or approval list `[A]` and a second list `[B]` on the create
    /// rule, in both criterion orders: each recipient's stated treatment is
    /// the evaluation's.
    #[test]
    fn summary_treats_each_recipient_by_every_criterion() {
        let (a, b, c) = (account(7), account(9), account(11));
        for mode in ["budget", "approval"] {
            for second_first in [false, true] {
                let mut base = listed_body(&derived("api-week", true, true), &a);
                if mode == "approval" {
                    // Every payment rule carries the same table.
                    base = edit_rules(&base, &PAYMENT_TOOLS, |criteria| {
                        for item in criteria.iter_mut() {
                            let table = item.as_inline_table_mut().unwrap();
                            if table["kind"].as_str() == Some("counterparty_allowlist") {
                                table.insert("unlisted", criterion("{ mode = \"approval\" }"));
                            }
                        }
                    });
                }
                let body = edit_rules(&base, &[CREATE_TOOL], |criteria| {
                    let restriction = criterion(&format!(
                        "{{ kind = \"counterparty_allowlist\", kinds = [\"G_ACCOUNT\"], allowlist = [\"{b}\"] }}"
                    ));
                    if second_first {
                        criteria.insert(0, restriction);
                    } else {
                        criteria.push(restriction);
                    }
                });
                let engine = verified_engine(&body);
                let create = tool_limits(&summary_of(&body), CREATE_TOOL).clone();
                let stated = |recipient: &str| {
                    create
                        .recipients
                        .iter()
                        .find(|r| r.recipient == recipient)
                        .unwrap()
                        .treatment
                };
                let (b_treatment, b_decision) = if mode == "budget" {
                    (Treatment::Budgeted, "allow")
                } else {
                    (Treatment::Approval, "approval")
                };
                assert_eq!(stated(&a), Treatment::Denied, "{mode} {second_first}");
                assert_eq!(stated(&b), b_treatment, "{mode} {second_first}");
                assert_eq!(create.unlisted_mode, "deny", "{mode} {second_first}");
                for (to, decision) in [(&a, "deny"), (&b, b_decision), (&c, "deny")] {
                    assert_eq!(
                        label(&x402(&engine, CREATE_TOOL, to, 100_000, T0)),
                        decision,
                        "{mode} {second_first}"
                    );
                }
                if mode == "budget" {
                    // B is unlisted to the budget criterion, so its cap applies.
                    assert_eq!(create.unlisted_per_tx_cap.as_deref(), Some("0.25"));
                    assert_eq!(create.unlisted_exhaustion, "deny");
                    assert_eq!(
                        label(&x402(&engine, CREATE_TOOL, &b, 2_500_000, T0)),
                        "allow"
                    );
                    assert_eq!(
                        label(&x402(&engine, CREATE_TOOL, &b, 2_500_001, T0)),
                        "deny"
                    );
                }
            }
        }
    }

    /// For every body, a tool the summary names in `unlisted_tools` admits an
    /// unlisted recipient, and every other tool denies one.
    #[test]
    fn summary_unlisted_statement_matches_evaluation() {
        let listed = account(7);
        let unlisted = account(9);
        let compute = listed_body(&derived("compute-week", false, true), &listed);
        let drop_counterparty = |criteria: &mut toml_edit::Array| {
            criteria.retain(|c| {
                c.as_inline_table().unwrap()["kind"].as_str() != Some("counterparty_allowlist")
            });
        };
        let budget = listed_body(&derived("api-week", true, true), &listed);
        let uniform = |mode| Agreed::Uniform(Some(mode));
        let per_tool = Agreed::PerTool;
        let bodies = [
            (uniform("deny"), compute.clone()),
            (uniform("budget"), budget.clone()),
            (
                uniform("deny"),
                edit_rules(&budget, &PAYMENT_TOOLS, |criteria| {
                    criteria.push(criterion(&format!(
                        "{{ kind = \"counterparty_allowlist\", kinds = [\"G_ACCOUNT\"], allowlist = [\"{listed}\"] }}"
                    )));
                }),
            ),
            (
                uniform("unrestricted"),
                edit_rules(&compute, &PAYMENT_TOOLS, drop_counterparty),
            ),
            (
                per_tool,
                edit_rules(&compute, &["stellar_pay"], drop_counterparty),
            ),
        ];
        for (mode, body) in &bodies {
            let summary = summary_of(body);
            let limits = &summary.limits[0];
            assert_eq!(limits.unlisted_mode, *mode);
            if let Some(mode) = limits.unlisted_mode.uniform() {
                assert!(limits.tools.iter().all(|t| t.unlisted_mode == *mode));
            }
            let engine = verified_engine(body);
            for name in [
                "stellar_pay",
                CREATE_TOOL,
                "stellar_x402_authenticated_payment",
            ] {
                let decision = if name == "stellar_pay" {
                    pay(&engine, &unlisted, 100_000, T0)
                } else {
                    x402(&engine, name, &unlisted, 100_000, T0)
                };
                assert_eq!(
                    decision == Decision::Allow,
                    limits.unlisted_tools.iter().any(|t| t == name),
                    "{mode:?} {name}: {decision:?}"
                );
                assert_eq!(
                    decision == Decision::Allow,
                    tool_limits(&summary, name).unlisted_mode != "deny",
                    "{mode:?} {name}"
                );
            }
        }
        let partial = summary_of(&bodies[4].1);
        assert_eq!(partial.recipients.unrestricted_tools, ["stellar_pay"]);
        assert_eq!(partial.limits[0].unlisted_tools, ["stellar_pay"]);
        assert_eq!(
            summary_of(&bodies[3].1).recipients.unrestricted_tools,
            PAYMENT_TOOLS
        );
    }

    #[test]
    fn summary_floor_is_highest_within_rule() {
        let listed = account(7);
        let body = listed_body(&derived("compute-week", false, true), &listed);
        assert_eq!(summary_of(&body).balance_floor_xlm.as_deref(), Some("4.5"));
        let raised = edit_rules(&body, &FLOOR_TOOLS, |criteria| {
            criteria.push(criterion(
                "{ kind = \"balance_floor\", min_stroops = \"100000000\" }",
            ));
        });
        let engine = verified_engine(&raised);
        assert_eq!(
            label(&pay_from(&engine, &listed, 100_000, T0, 50_000_000)),
            "deny"
        );
        assert_eq!(
            pay_from(&engine, &listed, 100_000, T0, 100_000_000),
            Decision::Allow
        );
        assert_eq!(summary_of(&raised).balance_floor_xlm.as_deref(), Some("10"));
    }

    #[test]
    fn summary_fee_is_max_per_classic_operation() {
        let body = policy_body(PROFILE, &derived("api-day", false, true));
        let planned = summary_of(&body);
        assert_eq!(planned.fee_cap_status, FeeCapStatus::Planned);
        assert_eq!(planned.classic_max_fee_per_op_stroops, Some(10_000));
        assert_eq!(
            planned.max_fee_per_classic_operation_xlm.as_deref(),
            Some("0.001")
        );
        let signed = summary_of(&format!(
            "{body}\n[mainnet]\nclassic_max_fee_per_op_stroops = 500\n"
        ));
        assert_eq!(signed.fee_cap_status, FeeCapStatus::Signed);
        assert_eq!(signed.classic_max_fee_per_op_stroops, Some(500));
        assert_eq!(
            signed.max_fee_per_classic_operation_xlm.as_deref(),
            Some("0.00005")
        );
        let json = serde_json::to_value(&planned).unwrap();
        assert_eq!(json["fee_cap_status"], "planned");
        assert_eq!(json["max_fee_per_classic_operation_xlm"], "0.001");
        assert_eq!(
            serde_json::to_value(&signed).unwrap()["fee_cap_status"],
            "signed"
        );
    }

    #[test]
    fn typical_use_flags_exceeding_payments() {
        // The threshold is never below the typical payment: business-day's
        // A = max(200/2, 100) = 100 = p passes.
        assert!(
            plan(&derived("business-day", false, true))
                .typical_use
                .is_empty()
        );
        // shop-day: p = A = 25 passes.
        assert!(
            plan(&derived("shop-day", false, true))
                .typical_use
                .is_empty()
        );
        for name in ["shop-week", "business-week", "business-2weeks", "api-week"] {
            assert!(
                plan(&derived(name, name.starts_with("api"), true))
                    .typical_use
                    .is_empty()
            );
        }
        let xlm = derive(&PresetInput {
            unlisted_budget: true,
            ..xlm_input("api-day", "10", "0.6")
        })
        .unwrap();
        // D = 10, P = 1, P/2 = 0.5 < p = 0.6.
        assert_eq!(
            plan(&xlm).typical_use,
            ["A typical payment of 0.6 XLM exceeds the unlisted per-payment cap of 0.5 XLM."]
        );
    }

    #[test]
    fn summary_states_exhaustion_deny() {
        let with = serde_json::to_value(summary_of(&policy_body(
            PROFILE,
            &derived("api-week", true, true),
        )))
        .unwrap();
        assert_eq!(
            with["unlisted_exhaustion"],
            serde_json::json!({"uniform": "deny"})
        );
        assert_eq!(
            with["limits"][0]["unlisted_mode"],
            serde_json::json!({"uniform": "budget"})
        );
        let create = &with["limits"][0]["tools"][2];
        assert_eq!(create["tool"], CREATE_TOOL);
        assert_eq!(create["unlisted_mode"], "budget");
        assert_eq!(create["unlisted_exhaustion"], "deny");
        assert_eq!(with["limits"][0]["tools"][0]["unlisted_exhaustion"], "deny");
        let without = serde_json::to_value(summary_of(&policy_body(
            PROFILE,
            &derived("api-week", false, true),
        )))
        .unwrap();
        assert_eq!(
            without["unlisted_exhaustion"],
            serde_json::json!({"uniform": null})
        );
        assert_eq!(
            without["limits"][0]["unlisted_mode"],
            serde_json::json!({"uniform": "deny"})
        );
        assert_eq!(
            without["limits"][0]["unlisted_per_tx_cap"],
            serde_json::json!({"uniform": null})
        );
        assert!(
            with["notes"]
                .as_array()
                .unwrap()
                .iter()
                .any(|n| n.as_str().unwrap().contains("unlisted budget is denied"))
        );
    }

    /// An unrestricted pay rule beside budgeted rules: the unlisted caps and
    /// the exhaustion behavior differ per tool, and the summary states each.
    #[test]
    fn summary_unlisted_caps_per_tool() {
        let (listed, unlisted) = (account(7), account(9));
        let body = edit_rules(
            &listed_body(&derived("api-week", true, true), &listed),
            &["stellar_pay"],
            |criteria| {
                criteria.retain(|c| {
                    c.as_inline_table().unwrap()["kind"].as_str() != Some("counterparty_allowlist")
                });
            },
        );
        let engine = verified_engine(&body);
        assert_eq!(pay(&engine, &unlisted, 3_000_000, T0), Decision::Allow);
        assert_eq!(
            label(&x402(&engine, CREATE_TOOL, &unlisted, 3_000_000, T0)),
            "deny"
        );
        let summary = summary_of(&body);
        let limits = &summary.limits[0];
        let per_tool = Agreed::PerTool;
        assert_eq!(limits.unlisted_tools, PAYMENT_TOOLS);
        assert_eq!(limits.unlisted_per_tx_cap, per_tool);
        assert_eq!(limits.unlisted_period_cap, Agreed::PerTool);
        assert_eq!(summary.unlisted_exhaustion, Agreed::PerTool);
        let pay_limits = tool_limits(&summary, "stellar_pay");
        assert_eq!(
            (
                pay_limits.unlisted_mode,
                pay_limits.unlisted_per_tx_cap.as_deref()
            ),
            ("unrestricted", None)
        );
        assert_eq!(pay_limits.unlisted_exhaustion, "unbudgeted");
        let create = tool_limits(&summary, CREATE_TOOL);
        assert_eq!(
            (create.unlisted_mode, create.unlisted_per_tx_cap.as_deref()),
            ("budget", Some("0.25"))
        );
        assert_eq!(
            create.unlisted_period_cap,
            Some(PeriodCap {
                window: "1d".to_owned(),
                amount: "1.25".to_owned()
            })
        );
        assert_eq!(create.unlisted_exhaustion, "deny");
    }

    #[test]
    fn summary_lists_uncovered_tools() {
        let usdc = summary_of(&policy_body(PROFILE, &derived("compute-week", false, true)));
        assert_eq!(
            usdc.tools.uncovered,
            ["stellar_create_account", "stellar_create_account_commit"]
        );
        assert_eq!(usdc.tools.covered.len(), 25);
        let native = summary_of(&policy_body(
            PROFILE,
            &derive(&xlm_input("compute-week", "100", "1")).unwrap(),
        ));
        assert_eq!(
            native.tools.uncovered,
            [
                "stellar_create_account",
                "stellar_create_account_commit",
                "stellar_trustline",
                "stellar_trustline_commit",
            ]
        );
    }

    #[test]
    fn summary_notes_shared_buckets_and_renewal() {
        let summary = summary_of(&policy_body(PROFILE, &derived("api-day", false, true)));
        for note in [
            "Rate limits count every tool in one shared bucket per window.",
            "A new policy signature starts a new total_budget allocation.",
            "Caps use rolling windows: 1d covers the last 86,400 seconds and 1w the last 604,800 seconds.",
            "A payment beyond an exhausted cap, total budget, or unlisted budget is denied.",
        ] {
            assert!(summary.notes.contains(&note.to_owned()), "{note}");
        }
        assert!(summary.rate_limits.shared_across_tools);
        assert_eq!(summary.rate_limits.tools.len(), 4);
        let json = serde_json::to_value(&summary).unwrap();
        assert_eq!(
            json["rate_limits"]["windows"],
            serde_json::json!([
                {"window": "1m", "calls": {"uniform": 5}},
                {"window": "1h", "calls": {"uniform": 25}},
            ])
        );
        assert_eq!(json["rate_limits"]["shared_across_tools"], true);
        assert_eq!(
            json["auxiliary_rate_limits"][0]["tool"],
            "stellar_trustline"
        );
        assert_eq!(
            json["auxiliary_rate_limits"][3]["limits"],
            serde_json::json!([
                {"window": "1m", "calls": 2, "writers": 1},
                {"window": "1h", "calls": 6, "writers": 1},
            ])
        );
    }

    #[test]
    fn plan_appears_only_at_init() {
        let d = derived("api-week", true, true);
        let summary = serde_json::to_value(summary_of(&policy_body(PROFILE, &d))).unwrap();
        let sorted_keys = |value: &serde_json::Value| {
            let mut keys: Vec<String> = value.as_object().unwrap().keys().cloned().collect();
            keys.sort_unstable();
            keys
        };
        let keys = sorted_keys(&summary);
        let mut expected = [
            "authority_status",
            "policy_version",
            "sequence",
            "limits",
            "unlisted_exhaustion",
            "rate_limits",
            "auxiliary_rate_limits",
            "classic_max_fee_per_op_stroops",
            "fee_cap_status",
            "max_fee_per_classic_operation_xlm",
            "balance_floor_xlm",
            "balance_floors",
            "recipients",
            "tools",
            "notes",
        ];
        expected.sort_unstable();
        assert_eq!(keys, expected);
        let limit_keys = sorted_keys(&summary["limits"][0]);
        let mut expected_limits = [
            "asset",
            "identifiers",
            "counted_under_several_identifiers",
            "per_tx_cap",
            "largest_payment",
            "period_caps",
            "total_budget",
            "approval_above",
            "unlisted_mode",
            "unlisted_tools",
            "unlisted_per_tx_cap",
            "unlisted_period_cap",
            "unlisted_largest_payment",
            "counters",
            "bounds",
            "unlisted_bounds",
            "tools",
        ];
        expected_limits.sort_unstable();
        assert_eq!(limit_keys, expected_limits);
        let text = summary.to_string();
        for plan_key in [
            "unattended_days",
            "typical_payment",
            "recommended_balance",
            "\"6\"",
        ] {
            assert!(!text.contains(plan_key), "{plan_key}");
        }
        let plan = serde_json::to_value(plan(&d)).unwrap();
        let plan_keys = sorted_keys(&plan);
        let mut expected_plan = [
            "preset",
            "asset",
            "tolerated_loss",
            "unattended_days",
            "typical_payment",
            "even_daily_spend",
            "expected_spend_fit",
            "typical_use",
            "operating_balance",
            "protocol_minimum_xlm",
            "balance_floor_xlm",
            "recommended_balance_xlm",
            "recommended_funding_xlm",
            "fee_allowance_xlm",
            "worst_case_asset",
            "funding_condition",
            "assumptions",
        ];
        expected_plan.sort_unstable();
        assert_eq!(plan_keys, expected_plan);
        assert_eq!(plan["unattended_days"], 7);
        assert_eq!(plan["typical_payment"], "0.01");
        assert_eq!(plan["recommended_balance_xlm"], "6");
        assert_eq!(plan["even_daily_spend"], "2.8571428");
        assert_eq!(
            plan["expected_spend_fit"],
            "Expected spend above 2.8571428 USDC per day does not fit this preset."
        );
        assert_eq!(
            plan["funding_condition"],
            "The fee bound holds while the operating account holds 6 XLM."
        );
        assert_eq!(plan["fee_allowance_xlm"], "4.5");
        assert_eq!(
            plan["assumptions"],
            serde_json::json!([
                "Burst factor 2: the 1d cap is at most twice the even daily spend.",
                "Per-payment fraction 1/10: the per-payment cap is 1/10 of the 1d cap.",
                "Rates assume 8 active hours per day and 10-minute bursts, with at least 6 \
                 calls per hour, 2 per minute, and at most 60 per minute.",
                "Fee cap 10000 stroops per classic operation, 100 times the 100-stroop \
                 minimum base fee.",
                "Protocol minimum 1.5 XLM: the account and one trustline at the 0.5 XLM base \
                 reserve.",
                "These constants are starting values, reviewed with canary data before alpha.15.",
            ])
        );
    }

    #[test]
    fn xlm_plan_shows_total_funding() {
        let xlm = plan(&derive(&xlm_input("api-week", "100", "1")).unwrap());
        assert_eq!(xlm.asset, "XLM");
        assert_eq!(xlm.operating_balance, "100");
        assert_eq!(xlm.protocol_minimum_xlm, "1");
        assert_eq!(xlm.balance_floor_xlm, "1.1");
        assert_eq!(xlm.recommended_balance_xlm, "2");
        assert_eq!(xlm.recommended_funding_xlm.as_deref(), Some("102"));
        assert_eq!(xlm.fee_allowance_xlm, "1");
        let usdc = plan(&derived("api-week", false, true));
        assert_eq!(usdc.recommended_funding_xlm, None);
        assert_eq!(usdc.protocol_minimum_xlm, "1.5");
        assert_eq!(usdc.operating_balance, "20");
        assert_eq!(
            serde_json::to_value(&usdc).unwrap()["recommended_funding_xlm"],
            serde_json::Value::Null
        );
    }

    /// Two rules cap the asset under its classic identifier and its contract
    /// identifier: the evaluation keeps two counters, and the 1d bound is
    /// their sum, labeled as such. Under one identifier the counter is shared.
    #[test]
    fn summary_sums_separate_counters() {
        const PAY: &str = "stellar_pay";
        const COMMIT: &str = "stellar_pay_commit";
        let listed = account(7);
        for net in [Net::Mainnet, Net::Testnet] {
            let classic = format!("USDC:{ISSUER}");
            let sac = usdc_sac(net);
            let body = net.body(&plain_body(&[
                plain_rule(
                    PAY,
                    &classic,
                    &[
                        per_tx(&classic, 10_000_000),
                        period_cap(&classic, "1d", 10_000_000),
                    ],
                    "allow",
                ),
                plain_rule(
                    COMMIT,
                    &sac,
                    &[per_tx(&sac, 20_000_000), period_cap(&sac, "1d", 20_000_000)],
                    "allow",
                ),
            ]));
            let summary = net.summary(&body);
            let limits = &summary.limits[0];
            assert!(limits.counted_under_several_identifiers);
            assert_eq!(limits.identifiers, [classic.clone(), sac.clone()]);
            assert_eq!(limits.counters.len(), 2);
            let day = limits.bounds.iter().find(|b| b.window == "1d").unwrap();
            assert_eq!(day.amount.as_deref(), Some("3"), "{net:?}");
            assert!(day.summed_over_counters);
            assert_eq!(day.counters, [format!("{classic} 1d"), format!("{sac} 1d")]);
            assert!(
                summary
                    .notes
                    .iter()
                    .any(|n| n.starts_with("USDC is counted under more than one identifier"))
            );
            // Both sides: 1 + 2 USDC pass, one stroop more is refused by each.
            let engine = verified_engine_on(&body, net);
            assert_eq!(
                spend(&engine, PAY, &listed, 10_000_000, T0, net),
                Decision::Allow
            );
            assert_eq!(
                spend(&engine, COMMIT, &listed, 20_000_000, T0, net),
                Decision::Allow
            );
            for tool in [PAY, COMMIT] {
                assert_eq!(label(&spend(&engine, tool, &listed, 1, T0, net)), "deny:1d");
            }
            // One identifier: the counter is shared; equal limits agree on 2.
            let shared = net.body(&plain_body(&[
                plain_rule(
                    PAY,
                    &classic,
                    &[period_cap(&classic, "1d", 20_000_000)],
                    "allow",
                ),
                plain_rule(
                    COMMIT,
                    &classic,
                    &[period_cap(&classic, "1d", 20_000_000)],
                    "allow",
                ),
            ]));
            let summary = net.summary(&shared);
            let day = &summary.limits[0].bounds[0];
            assert_eq!(
                (day.amount.as_deref(), day.summed_over_counters),
                (Some("2"), false)
            );
            assert!(!summary.limits[0].counted_under_several_identifiers);
            let engine = verified_engine_on(&shared, net);
            assert_eq!(
                spend(&engine, PAY, &listed, 10_000_000, T0, net),
                Decision::Allow
            );
            assert_eq!(
                spend(&engine, COMMIT, &listed, 10_000_000, T0, net),
                Decision::Allow
            );
            assert_eq!(label(&spend(&engine, PAY, &listed, 1, T0, net)), "deny:1d");
        }
    }

    /// A 5m cap below the per-payment cap: the summary states the window, the
    /// largest payment it leaves, and its bound.
    #[test]
    fn summary_states_every_window() {
        let classic = format!("USDC:{ISSUER}");
        let listed = account(7);
        let body = plain_body(&[plain_rule(
            "stellar_pay",
            &classic,
            &[
                per_tx(&classic, 100_000_000),
                period_cap(&classic, "5m", 10_000_000),
                period_cap(&classic, "1d", 2_000_000_000),
            ],
            "allow",
        )]);
        let summary = summary_of(&body);
        let limits = &summary.limits[0];
        assert_eq!(limits.per_tx_cap.as_deref(), Some("10"));
        assert_eq!(limits.largest_payment.as_deref(), Some("1"));
        assert_eq!(
            limits
                .period_caps
                .iter()
                .map(|c| (c.window.as_str(), c.amount.as_deref()))
                .collect::<Vec<_>>(),
            [("5m", Some("1")), ("1d", Some("200"))]
        );
        // 288 windows of 5m fit in a day: 288 USDC, so the 1d cap binds.
        let bounds: Vec<(&str, Option<&str>)> = limits
            .bounds
            .iter()
            .map(|b| (b.window.as_str(), b.amount.as_deref()))
            .collect();
        assert_eq!(
            bounds,
            [("5m", Some("1")), ("1d", Some("200")), ("total", None)]
        );
        let engine = verified_engine(&body);
        assert_eq!(pay(&engine, &listed, 10_000_000, T0), Decision::Allow);
        assert_eq!(label(&pay(&engine, &listed, 10_000_001, T0)), "deny:5m");
        assert_eq!(
            spend(
                &engine,
                "stellar_pay",
                &listed,
                10_000_000,
                T0,
                Net::Mainnet
            ),
            Decision::Allow
        );
        assert_eq!(
            label(&spend(&engine, "stellar_pay", &listed, 1, T0, Net::Mainnet)),
            "deny:5m"
        );
    }

    /// A `require_approval` rule requires approval for every amount; a `deny`
    /// rule leaves its tool uncovered.
    #[test]
    fn summary_reflects_rule_decision() {
        let classic = format!("USDC:{ISSUER}");
        let listed = account(7);
        let body = plain_body(&[
            plain_rule(
                "stellar_pay",
                &classic,
                &[per_tx(&classic, 100_000_000)],
                "require_approval",
            ),
            plain_rule(
                "stellar_pay_commit",
                &classic,
                &[per_tx(&classic, 100_000_000)],
                "deny",
            ),
            plain_rule(
                CREATE_TOOL,
                &classic,
                &[per_tx(&classic, 100_000_000)],
                "require_approval",
            ),
        ]);
        let summary = summary_of(&body);
        let pay_limits = tool_limits(&summary, "stellar_pay");
        assert_eq!(pay_limits.decision, "require_approval");
        assert_eq!(pay_limits.unlisted_mode, "approval");
        assert!(
            summary
                .tools
                .uncovered
                .iter()
                .any(|t| t == "stellar_pay_commit")
        );
        let engine = verified_engine(&body);
        assert_eq!(label(&pay(&engine, &listed, 1, T0)), "approval");
        assert_eq!(
            label(&x402(&engine, CREATE_TOOL, &listed, 1, T0)),
            "approval"
        );
        let clause = if cfg!(feature = "mainnet-write") {
            "without an approval proof, a call returns a pending approval"
        } else {
            "this build has no mainnet writes and refuses every mainnet payment"
        };
        assert!(summary.notes.contains(&format!(
            "stellar_x402_create_payment requires approval for every payment of USDC: {clause}."
        )));
    }

    /// Floors and bounds that differ per tool are stated per tool.
    #[test]
    fn summary_floors_and_bounds_agree_or_per_tool() {
        let classic = format!("USDC:{ISSUER}");
        let listed = account(7);
        let floor =
            |stroops: i128| format!("{{ kind = \"balance_floor\", min_stroops = \"{stroops}\" }}");
        let body = plain_body(&[
            plain_rule(
                "stellar_pay",
                &classic,
                &[period_cap(&classic, "1d", 10_000_000), floor(100_000_000)],
                "allow",
            ),
            plain_rule(
                "stellar_pay_commit",
                &classic,
                &[period_cap(&classic, "1d", 20_000_000), floor(45_000_000)],
                "allow",
            ),
            plain_rule(
                CREATE_TOOL,
                &classic,
                &[period_cap(&classic, "1d", 30_000_000)],
                "allow",
            ),
        ]);
        let summary = summary_of(&body);
        assert_eq!(summary.balance_floor_xlm, Agreed::PerTool);
        let limits = &summary.limits[0];
        assert_eq!(bound_of(limits, "1d"), &Agreed::PerTool);
        let own: Vec<Option<&str>> = limits
            .tools
            .iter()
            .map(|t| t.bounds[0].amount.as_deref())
            .collect();
        assert_eq!(own, [Some("1"), Some("2"), Some("3")]);
        let engine = verified_engine(&body);
        assert_eq!(
            label(&pay_on(
                &engine,
                "stellar_pay",
                &listed,
                1,
                (T0, 50_000_000),
                Net::Mainnet
            )),
            "deny"
        );
        assert_eq!(
            label(&pay_on(
                &engine,
                "stellar_pay_commit",
                &listed,
                1,
                (T0, 50_000_000),
                Net::Mainnet
            )),
            "allow"
        );
        // Each tool alone reaches its own bound; the counter is shared.
        for (tool, bound) in [
            ("stellar_pay", 10_000_000),
            ("stellar_pay_commit", 20_000_000),
            (CREATE_TOOL, 30_000_000),
        ] {
            let engine = verified_engine(&body);
            assert_eq!(
                label(&spend(&engine, tool, &listed, bound, T0, Net::Mainnet)),
                "allow"
            );
            assert_eq!(
                label(&spend(&engine, tool, &listed, 1, T0, Net::Mainnet)),
                "deny:1d"
            );
        }
        let agreed = plain_body(&[
            plain_rule("stellar_pay", &classic, &[floor(45_000_000)], "allow"),
            plain_rule(
                "stellar_pay_commit",
                &classic,
                &[floor(45_000_000)],
                "allow",
            ),
        ]);
        assert_eq!(
            summary_of(&agreed).balance_floor_xlm.as_deref(),
            Some("4.5")
        );
    }

    fn tool_bound<'a>(limits: &'a ToolLimits, unlisted: bool, window: &str) -> &'a PeriodBound {
        let bounds = if unlisted {
            &limits.unlisted_bounds
        } else {
            &limits.bounds
        };
        bounds.iter().find(|b| b.window == window).unwrap()
    }

    /// api-day with its unlisted budget: payments to an address in no list
    /// fit the budget's counter, at most 0.1 each and 0.5 per day. With no
    /// listed recipient the listed class pays 0; with one, 0.2 and 2.
    #[test]
    fn summary_bounds_the_unlisted_class_by_its_counter() {
        let unlisted = account(9);
        for net in [Net::Mainnet, Net::Testnet] {
            let body = net.body(&policy_body(PROFILE, &derived("api-day", true, true)));
            let summary = net.summary(&body);
            let create = tool_limits(&summary, CREATE_TOOL);
            assert_eq!(create.unlisted_largest_payment.as_deref(), Some("0.1"));
            let day = tool_bound(create, true, "1d");
            assert_eq!((day.amount.as_deref(), day.reachable), (Some("0.5"), true));
            assert_eq!(create.largest_payment.as_deref(), Some("0"));
            let listed_day = tool_bound(create, false, "1d");
            assert_eq!(
                (listed_day.amount.as_deref(), listed_day.reachable),
                (Some("0"), true)
            );
            let added = net.summary(&add_recipient(&body, &account(7)).unwrap());
            let added_create = tool_limits(&added, CREATE_TOOL);
            assert_eq!(added_create.largest_payment.as_deref(), Some("0.2"));
            let added_day = tool_bound(added_create, false, "1d");
            assert_eq!(
                (added_day.amount.as_deref(), added_day.reachable),
                (Some("2"), true)
            );
            let limits = &summary.limits[0];
            let asset_day = limits
                .unlisted_bounds
                .iter()
                .find(|b| b.window == "1d")
                .unwrap();
            assert_eq!(
                (asset_day.amount.as_deref(), asset_day.reachable),
                (Some("0.5"), true)
            );
            assert!(
                limits
                    .counters
                    .iter()
                    .any(|c| c.kind == "unlisted" && c.window == "1d")
            );
            // Both sides: five payments of 0.1 pass, one stroop more is refused.
            let engine = verified_engine_on(&body, net);
            assert_eq!(
                label(&x402_on(
                    &engine,
                    CREATE_TOOL,
                    &unlisted,
                    1_000_001,
                    T0,
                    net
                )),
                "deny"
            );
            for i in 0..5 {
                assert_eq!(
                    spend(
                        &engine,
                        CREATE_TOOL,
                        &unlisted,
                        1_000_000,
                        T0 + i * STEP_MS,
                        net
                    ),
                    Decision::Allow
                );
            }
            assert_eq!(
                label(&spend(
                    &engine,
                    CREATE_TOOL,
                    &unlisted,
                    1,
                    T0 + 5 * STEP_MS,
                    net
                )),
                "deny"
            );
        }
    }

    /// A daily rate of one call at a per-payment cap of 1: the daily bound
    /// is 1, not the amount cap of 3.
    #[test]
    fn summary_bounds_by_every_rate_window() {
        let classic = format!("USDC:{ISSUER}");
        let listed = account(7);
        for net in [Net::Mainnet, Net::Testnet] {
            let body = net.body(&plain_body(&[plain_rule(
                "stellar_pay",
                &classic,
                &[
                    per_tx(&classic, 10_000_000),
                    period_cap(&classic, "1d", 30_000_000),
                    "{ kind = \"rate_limit\", window = \"1d\", max_calls = 1 }".to_owned(),
                ],
                "allow",
            )]));
            let summary = net.summary(&body);
            let windows = &summary.rate_limits.windows;
            assert_eq!(windows.len(), 1);
            assert_eq!(
                (windows[0].window.as_str(), &windows[0].calls),
                ("1d", &Agreed::Uniform(Some(1)))
            );
            let pay_limits = tool_limits(&summary, "stellar_pay");
            let day = tool_bound(pay_limits, false, "1d");
            assert_eq!((day.amount.as_deref(), day.reachable), (Some("1"), true));
            let engine = verified_engine_on(&body, net);
            assert_eq!(
                spend(&engine, "stellar_pay", &listed, 10_000_000, T0, net),
                Decision::Allow
            );
            assert!(matches!(
                spend(&engine, "stellar_pay", &listed, 1, T0 + 86_400_000, net),
                Decision::Deny(DenyReason::RateLimitExceeded { .. })
            ));
        }
    }

    /// Two 1d caps on one identifier write each payment twice: with caps 1
    /// and 2 and a per-payment cap of 0.5, at most 0.75 passes per day, and
    /// 0.25 then 0.5 reaches it.
    #[test]
    fn summary_counts_every_writer_of_a_counter() {
        let classic = format!("USDC:{ISSUER}");
        let listed = account(7);
        for net in [Net::Mainnet, Net::Testnet] {
            let caps = vec![
                per_tx(&classic, 5_000_000),
                period_cap(&classic, "1d", 10_000_000),
                period_cap(&classic, "1d", 20_000_000),
            ];
            let body = net.body(&plain_body(&[plain_rule(
                "stellar_pay",
                &classic,
                &caps,
                "allow",
            )]));
            let single = net.body(&plain_body(&[plain_rule(
                "stellar_pay",
                &classic,
                &caps[..2],
                "allow",
            )]));
            let summary = net.summary(&body);
            assert_ne!(summary, net.summary(&single));
            let day = tool_bound(tool_limits(&summary, "stellar_pay"), false, "1d");
            assert_eq!(day.amount.as_deref(), Some("0.75"));
            assert!(day.reachable, "0.25 then 0.5 spends 0.75");
            let counter = summary.limits[0]
                .counters
                .iter()
                .find(|c| c.window == "1d")
                .unwrap();
            assert_eq!(counter.writers, Agreed::Uniform(Some(2)));
            let engine = verified_engine_on(&body, net);
            assert_eq!(
                spend(&engine, "stellar_pay", &listed, 2_500_000, T0, net),
                Decision::Allow
            );
            assert_eq!(
                spend(&engine, "stellar_pay", &listed, 5_000_000, T0, net),
                Decision::Allow
            );
            assert_eq!(
                label(&spend(&engine, "stellar_pay", &listed, 1, T0, net)),
                "deny:1d"
            );
        }
    }

    /// An issuer list beside an unlisted budget: the summary does not model
    /// which recipients the issuer list admits, so the budget stays out of
    /// the bound. Two payments of 1 to an address in no list pass, and the
    /// stated bound is not below them, in both criterion orders.
    #[test]
    fn summary_leaves_a_conditional_budget_out_of_the_bound() {
        let classic = format!("USDC:{ISSUER}");
        let outsider = account(9);
        let list = format!(
            "{{ kind = \"counterparty_allowlist\", kinds = [\"KNOWN_ISSUER\"], \
             allowlist = [\"{classic}\"], unlisted = {{ mode = \"budget\", \
             asset = \"{classic}\", window = \"1d\", per_tx_stroops = \"1000000\", \
             per_period_stroops = \"5000000\" }} }}"
        );
        let caps = [
            per_tx(&classic, 10_000_000),
            period_cap(&classic, "1d", 20_000_000),
        ];
        for net in [Net::Mainnet, Net::Testnet] {
            for first in [true, false] {
                let criteria: Vec<String> = if first {
                    [list.clone()].into_iter().chain(caps.clone()).collect()
                } else {
                    caps.iter().cloned().chain([list.clone()]).collect()
                };
                let body = net.body(&plain_body(&[plain_rule(
                    "stellar_pay",
                    &classic,
                    &criteria,
                    "allow",
                )]));
                validate_unsigned_policy(&body, PROFILE, net.passphrase()).unwrap();
                let summary = net.summary(&body);
                let pay = tool_limits(&summary, "stellar_pay");
                assert_eq!(pay.unmodeled_criteria, ["counterparty_allowlist.kinds"]);
                for unlisted in [true, false] {
                    let day = tool_bound(pay, unlisted, "1d");
                    assert_eq!((day.amount.as_deref(), day.reachable), (Some("2"), false));
                }
                assert_eq!(pay.unlisted_largest_payment.as_deref(), Some("1"));
                assert_eq!(pay.largest_payment.as_deref(), Some("1"));
                let day = summary.limits[0]
                    .unlisted_bounds
                    .iter()
                    .find(|b| b.window == "1d")
                    .unwrap();
                assert_eq!((day.amount.as_deref(), day.reachable), (Some("2"), false));
                let engine = verified_engine_on(&body, net);
                for _ in 0..2 {
                    assert_eq!(
                        spend(&engine, "stellar_pay", &outsider, 10_000_000, T0, net),
                        Decision::Allow
                    );
                }
                assert_eq!(
                    label(&spend(&engine, "stellar_pay", &outsider, 1, T0, net)),
                    "deny:1d"
                );
            }
        }
        // A verified-domain condition leaves the address list's budget out
        // of the bound as well.
        let address_list = list.replace("KNOWN_ISSUER", "G_ACCOUNT").replace(
            &format!("[\"{classic}\"], unlisted"),
            &format!("[\"{}\"], unlisted", account(7)),
        );
        let criteria: Vec<String> = caps
            .iter()
            .cloned()
            .chain([
                address_list,
                "{ kind = \"home_domain_resolved\" }".to_owned(),
            ])
            .collect();
        let body = plain_body(&[plain_rule("stellar_pay", &classic, &criteria, "allow")]);
        validate_unsigned_policy(&body, PROFILE, MAINNET_PASSPHRASE).unwrap();
        let summary = summary_of(&body);
        let pay = tool_limits(&summary, "stellar_pay");
        assert_eq!(pay.unmodeled_criteria, ["home_domain_resolved"]);
        let day = tool_bound(pay, true, "1d");
        assert_eq!((day.amount.as_deref(), day.reachable), (Some("2"), false));
        assert_eq!(pay.unlisted_largest_payment.as_deref(), Some("1"));
    }

    /// A recipient one list names and the budget's list omits pays through
    /// the budget: the unlisted class holds it, while the listed class and
    /// addresses in no list pay nothing.
    #[test]
    fn summary_counts_a_listed_recipient_paid_through_the_budget() {
        let classic = format!("USDC:{ISSUER}");
        let (named, budget_listed) = (account(9), account(7));
        let criteria = [
            per_tx(&classic, 10_000_000),
            period_cap(&classic, "1d", 20_000_000),
            format!(
                "{{ kind = \"counterparty_allowlist\", kinds = [\"G_ACCOUNT\"], \
                 allowlist = [\"{named}\"] }}"
            ),
            format!(
                "{{ kind = \"counterparty_allowlist\", kinds = [\"G_ACCOUNT\"], \
                 allowlist = [\"{budget_listed}\"], unlisted = {{ mode = \"budget\", \
                 asset = \"{classic}\", window = \"1d\", per_tx_stroops = \"5000000\", \
                 per_period_stroops = \"15000000\" }} }}"
            ),
        ];
        for net in [Net::Mainnet, Net::Testnet] {
            let body = net.body(&plain_body(&[plain_rule(
                "stellar_pay",
                &classic,
                &criteria,
                "allow",
            )]));
            validate_unsigned_policy(&body, PROFILE, net.passphrase()).unwrap();
            let summary = net.summary(&body);
            let pay = tool_limits(&summary, "stellar_pay");
            assert_eq!(pay.largest_payment.as_deref(), Some("0"));
            assert_eq!(pay.unlisted_largest_payment.as_deref(), Some("0.5"));
            let day = tool_bound(pay, true, "1d");
            assert_eq!((day.amount.as_deref(), day.reachable), (Some("1.5"), true));
            let engine = verified_engine_on(&body, net);
            for i in 0..3 {
                assert_eq!(
                    spend(&engine, "stellar_pay", &named, 5_000_000, T0 + i, net),
                    Decision::Allow
                );
            }
            assert_eq!(
                coarse(&spend(&engine, "stellar_pay", &named, 1, T0 + 3, net)),
                "deny"
            );
            assert_eq!(
                coarse(&spend(&engine, "stellar_pay", &budget_listed, 1, T0, net)),
                "deny"
            );
        }
    }

    /// Every bound of every preset, per tool and per asset, for listed and
    /// unlisted recipients, is stated and reachable: the presets are fully
    /// modeled. This holds for the generated body as written, which lists no
    /// recipient, and with one recipient added.
    #[test]
    fn preset_bounds_are_reachable() {
        let cases = PRESETS.iter().flat_map(|spec| {
            let unlisted = spec.archetype == Archetype::Api;
            let generated = policy_body(PROFILE, &derived(spec.name, unlisted, true));
            let added = add_recipient(&generated, &account(7)).unwrap();
            [(spec, generated), (spec, added)]
        });
        let mut bodies = 0;
        for (spec, body) in cases {
            bodies += 1;
            validate_unsigned_policy(&body, PROFILE, MAINNET_PASSPHRASE).unwrap();
            let summary = summary_of(&body);
            let limits = &summary.limits[0];
            for tool in &limits.tools {
                assert!(tool.unmodeled_criteria.is_empty(), "{}", spec.name);
                for bound in tool.bounds.iter().chain(&tool.unlisted_bounds) {
                    assert!(
                        bound.amount.is_some(),
                        "{} {} {}",
                        spec.name,
                        tool.tool,
                        bound.window
                    );
                    assert!(
                        bound.reachable,
                        "{} {} {}",
                        spec.name, tool.tool, bound.window
                    );
                }
            }
            for bound in limits.bounds.iter().chain(&limits.unlisted_bounds) {
                assert!(
                    bound.amount.uniform().is_some(),
                    "{} {}",
                    spec.name,
                    bound.window
                );
                assert!(bound.reachable, "{} {}", spec.name, bound.window);
            }
            // Rate windows bound the spend but are not period caps.
            let caps: Vec<&str> = limits
                .period_caps
                .iter()
                .map(|c| c.window.as_str())
                .collect();
            let rates: Vec<&str> = summary
                .rate_limits
                .windows
                .iter()
                .map(|r| r.window.as_str())
                .collect();
            assert_eq!(
                (caps, rates),
                (vec!["1d", "1w"], vec!["1m", "1h"]),
                "{}",
                spec.name
            );
        }
        assert_eq!(bodies, 24);
    }

    /// A payment that requests approval never counts toward a bound. With a
    /// threshold of 140 USDC and two calls per minute, business-week states
    /// 280 USDC per minute without approval. The evaluation pays it and
    /// never passes it. The largest admitted payment stays the per-payment cap.
    #[test]
    fn unattended_bounds_exclude_approved_payments() {
        let body = with_every_address_form(&policy_body(
            PROFILE,
            &derived("business-week", false, true),
        ));
        let summary = summary_of(&body);
        let limits = &summary.limits[0];
        for tool in &limits.tools {
            assert_eq!(
                (
                    tool.largest_payment.as_deref(),
                    tool.approval_above.as_deref()
                ),
                (Some("280"), Some("140")),
                "{}",
                tool.tool
            );
            let minute = tool_bound(tool, false, "1m");
            assert_eq!(
                (minute.amount.as_deref(), minute.reachable),
                (Some("280"), true),
                "{}",
                tool.tool
            );
        }
        assert_eq!(
            bound_of(limits, "1m"),
            &Agreed::Uniform(Some("280".to_owned()))
        );
        // Payment sequences the evaluation allows meet every stated bound.
        let counts = check_every_bound(&body, Net::Mainnet, &summary);
        assert!(counts.checked > 0);

        let engine = verified_engine(&body);
        let listed = account(7);
        assert_eq!(label(&pay(&engine, &listed, 2_800_000_000, T0)), "approval");
        for i in 0..2 {
            assert_eq!(
                spend(
                    &engine,
                    "stellar_pay",
                    &listed,
                    1_400_000_000,
                    T0 + i,
                    Net::Mainnet
                ),
                Decision::Allow
            );
        }
        assert_eq!(label(&pay(&engine, &listed, 1, T0 + 2)), "deny");
    }

    /// The criterion kinds the bounds do not model, each marking them.
    const MARKED_CRITERION_KINDS: [&str; 12] = [
        "minimum_reserve",
        "inner_invocation_count_cap",
        "bundle_aggregate_cap",
        "restrict_bundle_to_recognised_kinds",
        "bundle_per_period_cap",
        "bundle_per_tx_cap",
        "bundle_rate_limit",
        "quorum_satisfied",
        "home_domain_resolved",
        "sep10_session_active",
        "sep45_session_active",
        "memo_binding",
    ];

    /// Every criterion kind of the policy grammar is either modeled or
    /// marked, and a marked kind leaves every bound of its tool "at most".
    #[test]
    fn every_criterion_kind_is_modeled_or_marked() {
        for (kind, _) in super::super::schema::CRITERION_KEY_SETS {
            assert!(
                modeled_criterion_kinds().contains(kind) || MARKED_CRITERION_KINDS.contains(kind),
                "{kind} is neither modeled nor marked"
            );
            assert!(
                !(modeled_criterion_kinds().contains(kind)
                    && MARKED_CRITERION_KINDS.contains(kind)),
                "{kind}"
            );
        }
        let classic = format!("USDC:{ISSUER}");
        let body = plain_body(&[plain_rule(
            "stellar_pay",
            &classic,
            &[
                period_cap(&classic, "1d", 10_000_000),
                "{ kind = \"quorum_satisfied\" }".to_owned(),
            ],
            "allow",
        )]);
        validate_unsigned_policy(&body, PROFILE, MAINNET_PASSPHRASE).unwrap();
        let summary = summary_of(&body);
        let pay_limits = tool_limits(&summary, "stellar_pay");
        assert_eq!(pay_limits.unmodeled_criteria, ["quorum_satisfied"]);
        let day = tool_bound(pay_limits, false, "1d");
        assert_eq!((day.amount.as_deref(), day.reachable), (Some("1"), false));
        assert!(pay_limits.bounds.iter().all(|b| !b.reachable));
        assert!(summary.limits[0].bounds.iter().all(|b| !b.reachable));
    }

    // ── Summary property ───────────────────────────────────────────────────

    /// A counterparty criterion of a generated rule.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum ListKind {
        /// Lists A; denies every other recipient.
        Allow,
        /// Lists B; denies every other recipient.
        Deny,
        /// Lists A; pays every other recipient from the unlisted budget.
        Budget,
        /// Lists B; escalates every other recipient to approval.
        Approval,
    }

    const LIST_KINDS: [ListKind; 4] = [
        ListKind::Allow,
        ListKind::Deny,
        ListKind::Budget,
        ListKind::Approval,
    ];

    /// No list, each list alone, and each ordered pair of distinct lists.
    fn list_configs() -> Vec<Vec<ListKind>> {
        let mut configs = vec![Vec::new()];
        configs.extend(LIST_KINDS.iter().map(|kind| vec![*kind]));
        for first in LIST_KINDS {
            for second in LIST_KINDS.iter().filter(|k| **k != first) {
                configs.push(vec![first, *second]);
            }
        }
        configs
    }

    /// One generated rule for `tool`; its per-payment cap is `index + 1`
    /// USDC, so rules differ.
    /// The variations of a generated rule beyond its lists.
    #[derive(Debug, Clone, Copy)]
    struct RuleShape {
        floor: bool,
        threshold: bool,
        /// `allow`, `require_approval`, or `deny`.
        decision: &'static str,
        /// The asset as its mainnet contract identifier, a separate counter.
        contract: bool,
        /// A 5m cap below the per-payment cap.
        five_minutes: bool,
        /// A rate window and its call count.
        rate: Option<(&'static str, u32)>,
        /// A second 1d cap on the counter of the first.
        repeated: bool,
        /// The budget list classifies by issuer.
        issuer: bool,
        /// The allow list classifies by verified domain.
        domain: bool,
        /// The lists name nobody.
        empty: bool,
    }

    fn generated_rule(tool: &str, lists: &[ListKind], shape: RuleShape, index: usize) -> String {
        let RuleShape {
            floor,
            threshold,
            decision,
            contract,
            five_minutes,
            rate,
            repeated,
            issuer,
            domain,
            empty,
        } = shape;
        let asset = if contract {
            format!("\"{}\"", usdc_sac(Net::Mainnet))
        } else {
            format!("\"USDC:{ISSUER}\"")
        };
        let per_tx = 10_000_000 * (i128::try_from(index).unwrap() + 1);
        let (a, b) = (account(7), account(9));
        let mut criteria = vec![format!(
            "{{ kind = \"asset_allowlist\", assets = [{asset}] }}"
        )];
        let issuer_entry = format!("USDC:{ISSUER}");
        // The issuer kind reads a classic asset; x402 tools pay a contract.
        let issuer = issuer && !X402_TOOLS.contains(&tool);
        for kind in lists {
            let (listed, unlisted) = match kind {
                ListKind::Allow => (&a, String::new()),
                ListKind::Deny => (&b, String::new()),
                ListKind::Budget => (
                    if issuer { &issuer_entry } else { &a },
                    format!(
                        ", unlisted = {{ mode = \"budget\", asset = {asset}, window = \"1d\", \
                         per_tx_stroops = \"{}\", per_period_stroops = \"{per_tx}\" }}",
                        per_tx / 4
                    ),
                ),
                ListKind::Approval => (&b, ", unlisted = { mode = \"approval\" }".to_owned()),
            };
            let (kinds, listed) = match kind {
                ListKind::Budget if issuer => ("KNOWN_ISSUER", listed.as_str()),
                ListKind::Allow if domain => ("HOME_DOMAIN", "example.org"),
                _ => ("G_ACCOUNT", listed.as_str()),
            };
            let entries = if empty {
                String::new()
            } else {
                format!("\"{listed}\"")
            };
            criteria.push(format!(
                "{{ kind = \"counterparty_allowlist\", kinds = [\"{kinds}\"], \
                 allowlist = [{entries}]{unlisted} }}"
            ));
        }
        criteria.push(format!(
            "{{ kind = \"per_tx_cap\", asset = {asset}, max_stroops = \"{per_tx}\" }}"
        ));
        criteria.push(format!(
            "{{ kind = \"per_period_cap\", asset = {asset}, window = \"1d\", max_stroops = \"{}\" }}",
            per_tx * 10
        ));
        if threshold {
            criteria.push(format!(
                "{{ kind = \"approval_above\", asset = {asset}, max_stroops = \"{}\" }}",
                per_tx / 2
            ));
        }
        if five_minutes {
            criteria.push(format!(
                "{{ kind = \"per_period_cap\", asset = {asset}, window = \"5m\", max_stroops = \"{}\" }}",
                per_tx * 3 / 4
            ));
        }
        if repeated {
            criteria.push(format!(
                "{{ kind = \"per_period_cap\", asset = {asset}, window = \"1d\", max_stroops = \"{}\" }}",
                per_tx * 6
            ));
        }
        if let Some((window, calls)) = rate {
            criteria.push(format!(
                "{{ kind = \"rate_limit\", window = \"{window}\", max_calls = {calls} }}"
            ));
        }
        if floor {
            // Floors differ by position: 5 XLM, then 3 XLM.
            criteria.push(format!(
                "{{ kind = \"balance_floor\", min_stroops = \"{}\" }}",
                50_000_000 - 20_000_000 * i128::from(u8::from(index % 2 == 1))
            ));
        }
        format!(
            "\n[[rules]]\nmatch = {{ tool = \"{tool}\", chain = \"{MAINNET_CHAIN}\" }}\n\
             criteria = [{}]\ndecision = \"{decision}\"\n",
            criteria.join(", ")
        )
    }

    /// The generated bodies: every pair of list configurations on three tool
    /// pairs, a same-tool pair whose second rule is shadowed, and a rotation
    /// of triples on two tool orders. Floors and thresholds vary with the
    /// position. The loader refuses a body whose `unlisted` tables differ;
    /// such bodies are left out.
    fn generated_bodies() -> Vec<String> {
        const PAY: &str = "stellar_pay";
        const AUTHENTICATED: &str = "stellar_x402_authenticated_payment";
        let configs = list_configs();
        let mut specs: Vec<Vec<(&str, &[ListKind])>> = Vec::new();
        for tools in [[PAY, CREATE_TOOL], [CREATE_TOOL, AUTHENTICATED], [PAY, PAY]] {
            for first in &configs {
                for second in &configs {
                    specs.push(vec![(tools[0], first), (tools[1], second)]);
                }
            }
        }
        for tools in [
            [PAY, CREATE_TOOL, AUTHENTICATED],
            [AUTHENTICATED, PAY, CREATE_TOOL],
        ] {
            for i in 0..configs.len() {
                specs.push(
                    tools
                        .iter()
                        .enumerate()
                        .map(|(r, tool)| (*tool, configs[(i + 6 * r) % configs.len()].as_slice()))
                        .collect(),
                );
            }
        }
        let mut bodies = Vec::new();
        for (n, spec) in specs.iter().enumerate() {
            let tables = spec
                .iter()
                .flat_map(|(_, lists)| lists.iter())
                .filter(|k| matches!(k, ListKind::Budget | ListKind::Approval))
                .count();
            let mut body = format!("version = 2\nscope = \"profile:{PROFILE}\"\nsequence = 1\n");
            for (r, (tool, lists)) in spec.iter().enumerate() {
                let shape = RuleShape {
                    floor: (n + r) % 3 == 0,
                    threshold: (n / 3 + r) % 2 == 0,
                    decision: match (n + 2 * r) % 7 {
                        0 => "require_approval",
                        1 => "deny",
                        _ => "allow",
                    },
                    contract: (n + r) % 5 == 0,
                    five_minutes: (n / 2 + r) % 4 == 0,
                    rate: match (n + r) % 6 {
                        1 => Some(("1m", 3)),
                        4 => Some(("1d", 5)),
                        _ => None,
                    },
                    repeated: (n + 3 * r) % 5 == 2,
                    issuer: (n + r) % 4 == 2,
                    domain: (n + 2 * r) % 9 == 4,
                    empty: (n / 5 + r) % 6 == 3,
                };
                body.push_str(&generated_rule(tool, lists, shape, r));
            }
            if let Err(error) = validate_unsigned_policy(&body, PROFILE, MAINNET_PASSPHRASE) {
                // Equal `unlisted` tables only, and approval and budget
                // criteria only on `allow` rules.
                let detail = error.to_string();
                assert!(
                    tables > 1 || detail.contains("requires decision = \"allow\""),
                    "{detail}\n{body}"
                );
                continue;
            }
            let texts: Vec<String> = rules_of(&doc(&body))
                .iter()
                .flat_map(|(_, criteria)| criteria.iter().filter_map(|c| c.get("unlisted")))
                .map(|table| table.to_string().trim().to_owned())
                .collect();
            assert_eq!(texts.len(), tables, "{body}");
            assert!(texts.iter().all(|t| *t == texts[0]), "{body}");
            bodies.push(body);
        }
        // The generated preset bodies in USDC with the total budget on and
        // off, and in XLM, each as written and with a G, an M, and a C
        // recipient.
        for spec in &PRESETS {
            let unlisted = spec.archetype == Archetype::Api;
            let usdc = [true, false]
                .map(|total| policy_body(PROFILE, &derived(spec.name, unlisted, total)));
            let xlm = policy_body(PROFILE, &derive(&xlm_input(spec.name, "100", "1")).unwrap());
            for generated in usdc.into_iter().chain([xlm]) {
                bodies.push(with_every_address_form(&generated));
                bodies.push(generated);
            }
        }
        bodies
    }

    fn treatment_of_mode(mode: &str) -> Treatment {
        match mode {
            "unrestricted" => Treatment::Allowed,
            "budget" => Treatment::Budgeted,
            "approval" => Treatment::Approval,
            "approval_within_budget" => Treatment::ApprovalWithinBudget,
            _ => Treatment::Denied,
        }
    }

    /// The decision the summary's statements give for a payment of `amount`
    /// to a recipient of `treatment` by a tool of `limits`; `named` when a
    /// payment rule lists the recipient.
    fn stated_decision(
        limits: &ToolLimits,
        (treatment, named): (Treatment, bool),
        amount: i128,
    ) -> &'static str {
        let cap = |value: &Option<String>| {
            value.as_deref().map(|v| {
                if v == "0" {
                    0
                } else {
                    parse_amount(v).unwrap()
                }
            })
        };
        let budgeted = matches!(
            treatment,
            Treatment::Budgeted | Treatment::ApprovalWithinBudget
        );
        // A payment through the budget, or to an address in no list, is of
        // the unlisted class.
        let largest = if budgeted || !named {
            &limits.unlisted_largest_payment
        } else {
            &limits.largest_payment
        };
        if treatment == Treatment::Denied
            || cap(largest).is_some_and(|cap| amount > cap)
            || (budgeted && cap(&limits.unlisted_per_tx_cap).is_some_and(|cap| amount > cap))
        {
            "deny"
        } else if matches!(
            treatment,
            Treatment::Approval | Treatment::ApprovalWithinBudget
        ) || cap(&limits.approval_above).is_some_and(|a| amount > a)
        {
            "approval"
        } else {
            "allow"
        }
    }

    fn coarse(decision: &Decision) -> &'static str {
        match decision {
            Decision::Allow => "allow",
            Decision::RequireApproval(_) => "approval",
            Decision::Deny(_) => "deny",
        }
    }

    /// The base G of an M address.
    fn base_account(recipient: &str) -> Option<String> {
        match stellar_strkey::Strkey::from_string(recipient) {
            Ok(stellar_strkey::Strkey::MuxedAccountEd25519(muxed)) => Some(
                stellar_strkey::ed25519::PublicKey(muxed.ed25519)
                    .to_string()
                    .as_str()
                    .to_owned(),
            ),
            _ => None,
        }
    }

    /// The treatment the summary states for `recipient` by the tool of
    /// `stated`, and whether a payment rule lists it. It is the recipient's
    /// own entry, for an M address the entry of its base G, else the
    /// unlisted mode.
    fn stated_treatment(stated: &ToolLimits, recipient: &str) -> (Treatment, bool) {
        let entry = |address: &str| stated.recipients.iter().find(|r| r.recipient == address);
        entry(recipient)
            .or_else(|| base_account(recipient).and_then(|base| entry(&base)))
            .map_or_else(
                || (treatment_of_mode(stated.unlisted_mode), false),
                |r| (r.treatment, true),
            )
    }

    /// The largest payment to `recipient` the summary states the tool of
    /// `stated` admits, at most its approval threshold; `0` when unstated.
    fn largest_stated(stated: &ToolLimits, recipient: &str) -> i128 {
        let (treatment, named) = stated_treatment(stated, recipient);
        let budgeted = matches!(
            treatment,
            Treatment::Budgeted | Treatment::ApprovalWithinBudget
        );
        let largest = if budgeted || !named {
            &stated.unlisted_largest_payment
        } else {
            &stated.largest_payment
        };
        let stroops = |v: &Option<String>| v.as_deref().map(|v| parse_amount(v).unwrap_or(0));
        min_present([
            stroops(largest),
            stroops(&stated.approval_above),
            if budgeted {
                stroops(&stated.unlisted_per_tx_cap)
            } else {
                None
            },
        ])
        .unwrap_or(0)
    }

    /// The recipients a property check pays. They are G addresses the
    /// generated bodies list and one they do not. Three M addresses follow:
    /// one by its base G, one by its own entry, one in no list. A listed and
    /// an unlisted C address close the list.
    fn property_recipients() -> Vec<String> {
        vec![
            account(7),
            account(9),
            account(11),
            muxed(7, 1),
            muxed(9, 4),
            muxed(9, 5),
            contract(3),
            contract(5),
        ]
    }

    /// The listed forms [`property_recipients`] pays by entry: a G, an M,
    /// and a C address.
    fn with_every_address_form(body: &str) -> String {
        [account(7), muxed(9, 4), contract(3)]
            .iter()
            .fold(body.to_owned(), |body, recipient| {
                add_recipient(&body, recipient).unwrap()
            })
    }

    /// The payment tools a property check evaluates, each with one payment.
    const PROPERTY_TOOLS: [&str; 4] = [
        "stellar_pay",
        "stellar_pay_commit",
        CREATE_TOOL,
        "stellar_x402_authenticated_payment",
    ];

    /// Checks every statement of the summary of `body` on `net` against the
    /// evaluation, returning the number of evaluations compared.
    fn check_summary_property(body: &str, net: Net) -> usize {
        let engine = verified_engine_on(body, net);
        let summary = net.summary(body);
        let recipients = property_recipients();
        let a = &recipients[0];
        let mut cases = 0;
        let asset = summary
            .limits
            .first()
            .map_or("native", |l| l.asset.as_str())
            .to_owned();
        let evaluate = |tool: &str, to: &str, amount: i128, (balance, fee): (i64, i64)| {
            let payment = Payment {
                tool,
                asset: &asset,
                to,
                amount,
            };
            evaluate_payment(&engine, payment, (T0, balance, fee), net)
        };
        // A body whose every rule denies states no asset; every tool denies.
        if summary.limits.is_empty() {
            for tool in PROPERTY_TOOLS {
                assert!(summary.tools.uncovered.iter().any(|t| t == tool));
                assert_eq!(
                    coarse(&evaluate(tool, a, 1, (i64::MAX, 0))),
                    "deny",
                    "{body}"
                );
                cases += 1;
            }
            return cases;
        }
        let limits = &summary.limits[0];
        for tool in PROPERTY_TOOLS {
            let Some(stated) = limits.tools.iter().find(|t| t.tool == tool) else {
                assert!(summary.tools.uncovered.iter().any(|t| t == tool));
                assert_eq!(
                    coarse(&evaluate(tool, a, 1, (i64::MAX, 0))),
                    "deny",
                    "{body}"
                );
                cases += 1;
                continue;
            };
            let amounts: Vec<i128> = [
                &stated.per_tx_cap,
                &stated.largest_payment,
                &stated.approval_above,
                &stated.unlisted_per_tx_cap,
            ]
            .into_iter()
            .filter_map(|v| {
                v.as_deref()
                    .filter(|v| *v != "0")
                    .map(|v| parse_amount(v).unwrap())
            })
            .flat_map(|v| [v, v + 1])
            .chain([1])
            .collect();
            // Without a modeled classification the summary states only what
            // holds for every recipient: no admitted payment passes either
            // stated largest payment.
            if unclassified(stated) {
                let largest =
                    |v: &Option<String>| v.as_deref().map(|v| parse_amount(v).unwrap_or(0));
                for recipient in &recipients {
                    for amount in &amounts {
                        if coarse(&evaluate(tool, recipient, *amount, (i64::MAX, 0))) != "deny" {
                            for stated_largest in [
                                largest(&stated.largest_payment),
                                largest(&stated.unlisted_largest_payment),
                            ]
                            .into_iter()
                            .flatten()
                            {
                                assert!(*amount <= stated_largest, "{net:?} {tool}\n{body}");
                            }
                        }
                        cases += 1;
                    }
                }
                continue;
            }
            for recipient in &recipients {
                let (treatment, named) = stated_treatment(stated, recipient);
                for amount in &amounts {
                    assert_eq!(
                        coarse(&evaluate(tool, recipient, *amount, (i64::MAX, 0))),
                        stated_decision(stated, (treatment, named), *amount),
                        "{net:?} {tool} {recipient} {amount} {treatment:?}\n{body}"
                    );
                    cases += 1;
                }
            }
            // The stated floor holds after the payment's native debit and
            // the envelope fee: a balance leaving exactly the floor pays,
            // one stroop less denies. A payment of another asset debits
            // only the fee.
            let floor = summary
                .balance_floors
                .iter()
                .find(|f| f.tool == tool)
                .and_then(|f| f.floor_xlm.as_deref())
                .map(|f| i64::try_from(parse_amount(f).unwrap()).unwrap());
            if !X402_TOOLS.contains(&tool) {
                let payable = recipients
                    .iter()
                    .find(|r| stated_decision(stated, stated_treatment(stated, r), 1) != "deny");
                if let Some(recipient) = payable {
                    const FEE: i64 = 100;
                    let amount = largest_stated(stated, recipient).max(1);
                    let decision =
                        stated_decision(stated, stated_treatment(stated, recipient), amount);
                    let debit = if asset == "native" { amount } else { 0 };
                    let debit = i64::try_from(debit).unwrap() + FEE;
                    let balances = match floor {
                        Some(floor) => [(floor + debit, decision), (floor + debit - 1, "deny")],
                        None => [(debit, decision), (debit - 1, decision)],
                    };
                    for (balance, expected) in balances {
                        assert_eq!(
                            coarse(&evaluate(tool, recipient, amount, (balance, FEE))),
                            expected,
                            "{net:?} {tool} floor {floor:?} {balance} {amount}\n{body}"
                        );
                        cases += 1;
                    }
                }
            }
        }
        // An aggregate holds only what every tool states.
        if let Some(mode) = limits.unlisted_mode.uniform() {
            assert!(
                limits.tools.iter().all(|t| t.unlisted_mode == *mode),
                "{body}"
            );
        }
        for (aggregate, field) in [
            (
                &limits.per_tx_cap,
                (|t| &t.per_tx_cap) as fn(&ToolLimits) -> &Option<String>,
            ),
            (&limits.approval_above, |t| &t.approval_above),
        ] {
            if let Agreed::Uniform(value) = aggregate {
                assert!(limits.tools.iter().all(|t| field(t) == value), "{body}");
            }
        }
        let admitting = || {
            limits
                .tools
                .iter()
                .filter(|t| limits.unlisted_tools.contains(&t.tool))
        };
        if let Agreed::Uniform(value) = &limits.unlisted_per_tx_cap {
            assert!(
                admitting().all(|t| &t.unlisted_per_tx_cap == value),
                "{body}"
            );
        }
        if let Agreed::Uniform(Some(value)) = &summary.unlisted_exhaustion {
            assert!(
                admitting().all(|t| t.unlisted_exhaustion == *value),
                "{body}"
            );
        }
        for listed in &summary.recipients.listed {
            if let Some(treatment) = listed.treatment.uniform() {
                assert!(
                    limits.tools.iter().all(|t| t
                        .recipients
                        .iter()
                        .any(|r| r.recipient == listed.recipient && r.treatment == *treatment)),
                    "{body}"
                );
            }
        }
        // The approval notes name exactly the x402 tools that pay and carry a
        // threshold or a `require_approval` decision.
        let approval_notes: Vec<&String> = summary
            .notes
            .iter()
            .filter(|n| n.contains(" approval above ") || n.contains(" approval for every payment"))
            .collect();
        for tool in X402_TOOLS {
            let carries = limits.tools.iter().any(|t| {
                t.tool == tool
                    && !t.denies_every_call
                    && (t.decision == "require_approval" || t.approval_above.is_some())
            });
            assert_eq!(
                approval_notes.iter().any(|n| n.contains(tool)),
                carries,
                "{tool}\n{body}"
            );
        }
        cases
    }

    /// Every statement of the summary equals the evaluation, for a generated
    /// family of signed bodies, on mainnet and on a testnet subset. Every
    /// stated bound of a mainnet body holds against payment sequences.
    #[test]
    fn summary_statements_match_evaluation() {
        let bodies = generated_bodies();
        let (mut cases, mut bounds, mut sequences, mut unreachable) = (0, 0, 0, 0);
        let mut staged = 0;
        for (n, body) in bodies.iter().enumerate() {
            cases += check_summary_property(body, Net::Mainnet);
            if n % 5 == 0 {
                cases += check_summary_property(&Net::Testnet.body(body), Net::Testnet);
            }
            let summary = Net::Mainnet.summary(body);
            if let Some(limits) = summary.limits.first() {
                unreachable += limits
                    .bounds
                    .iter()
                    .chain(&limits.unlisted_bounds)
                    .filter(|b| !b.reachable)
                    .count();
            }
            let counts = check_every_bound(body, Net::Mainnet, &summary);
            sequences += counts.evaluations;
            bounds += counts.checked;
            staged += counts.staged;
        }
        assert_eq!(
            (bodies.len(), cases, bounds, sequences, unreachable, staged),
            (320, 36_650, 1_960, 550_121, 360, 60),
            "property size"
        );
        // The family holds both rate windows, a repeated counter, an
        // unlisted budget beside a listed recipient and beside an issuer
        // list, the verified-domain condition, and lists that name nobody.
        let holding = |needle: &str| bodies.iter().filter(|b| b.contains(needle)).count();
        assert_eq!(
            (
                holding("window = \"1m\", max_calls"),
                holding("window = \"1d\", max_calls"),
                bodies
                    .iter()
                    .filter(|b| Net::Mainnet.summary(b).limits.iter().any(|l| l
                        .counters
                        .iter()
                        .any(|c| c.writers == Agreed::Uniform(Some(2)))))
                    .count(),
                holding("mode = \"budget\""),
            ),
            (146, 88, 52, 98),
            "generated shapes"
        );
        assert_eq!(
            (
                holding("kinds = [\"KNOWN_ISSUER\"]"),
                holding("kinds = [\"HOME_DOMAIN\"]"),
                holding("allowlist = []"),
            ),
            (12, 33, 109),
            "generated classifications"
        );
        // The preset bodies pay XLM, and list an M and a C recipient.
        assert_eq!(
            (
                holding("assets = [\"native\"]"),
                holding(&muxed(9, 4)),
                holding(&contract(3)),
            ),
            (24, 36, 36),
            "generated assets and address forms"
        );
    }

    /// A rule for the bound family: caps over `1h`, `1d`, `1w`, and a total
    /// chosen by `bits`, under the classic or the contract identifier.
    fn bound_rule(tool: &str, n: usize, r: usize) -> String {
        let scale = i128::try_from(r).unwrap() + 1;
        let asset = if (n + r).is_multiple_of(3) {
            usdc_sac(Net::Mainnet)
        } else {
            format!("USDC:{ISSUER}")
        };
        let bits = (n + 3 * r) % 8;
        let mut criteria = vec![per_tx(
            &asset,
            if (n + r).is_multiple_of(4) {
                5_000_000
            } else {
                1_000_000_000
            },
        )];
        for (bit, window, limit) in [
            (1, "1h", 10_000_000),
            (2, "1d", 50_000_000),
            (4, "1w", 200_000_000),
        ] {
            if bits & bit != 0 {
                criteria.push(period_cap(&asset, window, limit * scale));
            }
        }
        let decision = match (n + r) % 5 {
            0 => "require_approval",
            1 => "deny",
            _ => "allow",
        };
        if (n + r).is_multiple_of(2) && decision == "allow" {
            criteria.push(format!(
                "{{ kind = \"total_budget\", asset = \"{asset}\", max_stroops = \"{}\" }}",
                300_000_000 * scale
            ));
        }
        // Rate windows of both lengths, shared by every tool.
        match (n + 2 * r) % 5 {
            1 => criteria
                .push("{ kind = \"rate_limit\", window = \"1m\", max_calls = 3 }".to_owned()),
            2 => criteria
                .push("{ kind = \"rate_limit\", window = \"1d\", max_calls = 4 }".to_owned()),
            _ => {}
        }
        // A repeated criterion writes each payment twice to one counter.
        if (n + r) % 7 == 3 {
            criteria.push(period_cap(&asset, "1d", 80_000_000 * scale));
            criteria.push(period_cap(&asset, "1d", 120_000_000 * scale));
        }
        // A repeated total budget, reached by a smaller payment first.
        if (n + r) % 7 == 5 && decision == "allow" {
            criteria.push(format!(
                "{{ kind = \"total_budget\", asset = \"{asset}\", max_stroops = \"{}\" }}",
                90_000_000 * scale
            ));
            criteria.push(format!(
                "{{ kind = \"total_budget\", asset = \"{asset}\", max_stroops = \"{}\" }}",
                150_000_000 * scale
            ));
        }
        // An unlisted budget on the first rule, beside a classification by
        // address, by issuer, or by verified domain.
        if r == 0 && n % 4 == 3 && decision == "allow" {
            // The issuer kind reads a classic asset; x402 tools pay a
            // contract.
            let (kind, listed) = match (n / 4) % 3 {
                1 if !X402_TOOLS.contains(&tool) => ("KNOWN_ISSUER", format!("USDC:{ISSUER}")),
                2 => ("HOME_DOMAIN", "example.org".to_owned()),
                _ => ("G_ACCOUNT", account(7)),
            };
            criteria.push(format!(
                "{{ kind = \"counterparty_allowlist\", kinds = [\"{kind}\"], \
                 allowlist = [\"{listed}\"], unlisted = {{ mode = \"budget\", asset = \"{asset}\", \
                 window = \"1d\", per_tx_stroops = \"2000000\", per_period_stroops = \"8000000\" }} }}"
            ));
        }
        // A list that names nobody, under the deny mode, and under the
        // approval mode on a rule of the policy without another table.
        if r == 1 && n % 6 == 1 {
            criteria.push(
                "{ kind = \"counterparty_allowlist\", kinds = [\"G_ACCOUNT\"], allowlist = [] }"
                    .to_owned(),
            );
        }
        if r == 2 && n % 4 != 3 && decision == "allow" {
            criteria.push(
                "{ kind = \"counterparty_allowlist\", kinds = [\"G_ACCOUNT\"], allowlist = [], \
                 unlisted = { mode = \"approval\" } }"
                    .to_owned(),
            );
        }
        plain_rule(tool, &asset, &criteria, decision)
    }

    fn window_ms(label: &str) -> Option<u64> {
        (label != TOTAL).then(|| Window::parse(label).unwrap().as_secs() * 1_000)
    }

    /// A payer of a bound check: the tool, the asset it pays, a recipient of
    /// the class, the class's stated largest admitted payment, and its
    /// largest payment without approval.
    struct Payer<'a> {
        tool: &'a str,
        asset: &'a str,
        recipient: String,
        admitted: Option<i128>,
        largest: Option<i128>,
        /// The tool's own bounds for the class.
        own: &'a [PeriodBound],
    }

    impl Payer<'_> {
        /// What a staged run pays through this payer before its largest
        /// payment: its own bound in `window` less the largest payment.
        fn stage(&self, window: &str) -> i128 {
            let own = self
                .own
                .iter()
                .find(|b| b.window == window)
                .and_then(|b| b.amount.as_deref())
                .map(|a| parse_amount(a).unwrap_or(0));
            match (own, self.largest) {
                (Some(own), Some(largest)) => (own - largest).max(0),
                _ => 0,
            }
        }
    }

    /// Whether the summary leaves the recipient classification of the tool
    /// unmodeled, so both classes state the bound of every recipient.
    fn unclassified(tool: &ToolLimits) -> bool {
        tool.unmodeled_criteria
            .iter()
            .any(|c| c == "counterparty_allowlist.kinds" || c == "home_domain_resolved")
    }

    /// The payers of `class` among `tools` paying `asset` without approval.
    /// The listed class pays a listed recipient the rule allows without the
    /// unlisted budget, or every address under a rule without a list. The
    /// unlisted class pays an address in no list, or a listed recipient paid
    /// through the budget, when the rule allows either. A tool without a
    /// modeled classification pays an address in no list in both classes. A `require_approval` rule pays nobody without approval,
    /// and no payer pays above the approval threshold.
    fn payers<'a>(
        tools: &[&'a ToolLimits],
        asset: &'a str,
        unlisted: bool,
        open: &[String],
    ) -> Vec<Payer<'a>> {
        let outsider = account(11);
        let stroops = |v: &Option<String>| v.as_deref().map(|v| parse_amount(v).unwrap_or(0));
        let named = |t: &ToolLimits, treatment: Treatment| {
            t.recipients
                .iter()
                .find(|r| is_address(&r.recipient) && r.treatment == treatment)
                .map(|r| r.recipient.clone())
        };
        tools
            .iter()
            .filter(|t| t.decision == "allow")
            .filter_map(|t| {
                let own = if unlisted {
                    &t.unlisted_bounds
                } else {
                    &t.bounds
                };
                let largest = if unlisted {
                    &t.unlisted_largest_payment
                } else {
                    &t.largest_payment
                };
                let recipient = if unclassified(t) {
                    Some(outsider.clone())
                } else if unlisted {
                    matches!(t.unlisted_mode, "budget" | "unrestricted")
                        .then(|| outsider.clone())
                        .or_else(|| named(t, Treatment::Budgeted))
                } else {
                    named(t, Treatment::Allowed)
                        .or_else(|| open.contains(&t.tool).then(|| outsider.clone()))
                };
                let admitted = stroops(largest);
                recipient.map(|recipient| Payer {
                    tool: t.tool.as_str(),
                    asset,
                    recipient,
                    admitted,
                    largest: min_present([admitted, stroops(&t.approval_above)]),
                    own,
                })
            })
            .collect()
    }

    /// Whether `engine` allows a payment of `amount` by `payer` without
    /// approval. A payment answered with an approval request is not
    /// admitted: the stated bounds hold what is spendable unattended.
    fn engine_admits(
        engine: &PolicyEngineV1,
        payer: &Payer<'_>,
        amount: i128,
        now: u64,
        net: Net,
    ) -> bool {
        let payment = Payment {
            tool: payer.tool,
            asset: payer.asset,
            to: &payer.recipient,
            amount,
        };
        evaluate_payment(engine, payment, (now, i64::MAX, 0), net) == Decision::Allow
    }

    /// The outcome of one payment run: evaluations, total paid, the last
    /// instant, and the engine with its recorded payments.
    struct Run {
        evaluations: usize,
        total: i128,
        now: u64,
        engine: PolicyEngineV1,
    }

    /// Pays toward `bound` from a fresh state.
    ///
    /// Every payer pays, at each instant, the largest amount the evaluation
    /// admits up to one stroop above what the bound leaves, and the run waits
    /// for the next instant a stated window frees a payment; a period bound
    /// keeps the run within one closed window. A staged run first pays
    /// through each payer exactly its stage, smaller payments before the
    /// largest, and goes on once it pays nothing more below the stages. No
    /// admitted payment of the run passes the bound.
    fn run_bound(
        body: &str,
        net: Net,
        payers: &[Payer<'_>],
        windows_ms: &[u64],
        (window, bound): (&str, i128),
        staged: bool,
    ) -> Run {
        let engine = verified_engine_on(body, net);
        let span = window_ms(window);
        let mut evaluations = 0;
        let mut admits = |payer: &Payer<'_>, amount: i128, now: u64| {
            evaluations += 1;
            engine_admits(&engine, payer, amount, now, net)
        };
        let mut times: Vec<u64> = Vec::new();
        let mut total: i128 = 0;
        let mut now = T0;
        let mut stages: Vec<i128> = payers
            .iter()
            .map(|p| if staged { p.stage(window) } else { 0 })
            .collect();
        let mut paid_by: Vec<i128> = vec![0; payers.len()];
        for _ in 0..3_000 {
            let mut paid = false;
            for (i, payer) in payers.iter().enumerate() {
                // The evaluation, not the stated threshold, decides how much
                // of the largest admitted payment it allows unattended.
                let largest = payer.admitted.unwrap_or(i128::MAX);
                let ceiling = if paid_by[i] < stages[i] {
                    (stages[i] - paid_by[i]).min(bound - total).min(largest)
                } else if stages.iter().zip(&paid_by).any(|(s, p)| p < s) {
                    // A payer at its stage waits for the others.
                    0
                } else {
                    (bound - total + 1).min(largest)
                };
                if ceiling <= 0 {
                    continue;
                }
                let amount = if admits(payer, ceiling, now) {
                    ceiling
                } else {
                    let (mut low, mut high) = (0, ceiling);
                    while high - low > 1 {
                        let mid = low + (high - low) / 2;
                        if admits(payer, mid, now) {
                            low = mid;
                        } else {
                            high = mid;
                        }
                    }
                    low
                };
                if amount == 0 {
                    continue;
                }
                assert!(
                    total + amount <= bound,
                    "{window} bound {bound} passed: {total} + {amount} by {}\n{body}",
                    payer.tool
                );
                let payment = Payment {
                    tool: payer.tool,
                    asset: payer.asset,
                    to: &payer.recipient,
                    amount,
                };
                assert_eq!(spend_payment(&engine, payment, now, net), Decision::Allow);
                total += amount;
                paid_by[i] += amount;
                times.push(now);
                paid = true;
            }
            if paid {
                continue;
            }
            let next = times
                .iter()
                .flat_map(|t| windows_ms.iter().map(move |w| t + w + 1))
                .filter(|t| *t > now)
                .min();
            let first = times.first().copied().unwrap_or(now);
            match next {
                Some(next) if span.is_none_or(|span| next - first <= span) => now = next,
                _ if stages.iter().zip(&paid_by).any(|(s, p)| p < s) => {
                    stages.clone_from(&paid_by);
                }
                _ => break,
            }
        }
        Run {
            evaluations,
            total,
            now,
            engine,
        }
    }

    /// Checks one stated bound against the evaluation from a fresh state.
    ///
    /// The greedy run, and when it stops short the staged run that keeps
    /// the largest payment for last, never pass the bound. When the bound
    /// is reachable, one of them pays it exactly and every payer is then
    /// refused one stroop more. Returns the number of evaluations and
    /// whether the staged run gave the exact sum the greedy run missed.
    fn check_bound(
        body: &str,
        net: Net,
        payers: &[Payer<'_>],
        windows_ms: &[u64],
        (window, bound): (&str, i128),
        reachable: bool,
    ) -> (usize, bool) {
        let greedy = run_bound(body, net, payers, windows_ms, (window, bound), false);
        let mut evaluations = greedy.evaluations;
        let mut staged_hit = false;
        let mut reached = greedy;
        if reached.total < bound {
            let staged = run_bound(body, net, payers, windows_ms, (window, bound), true);
            evaluations += staged.evaluations;
            if staged.total > reached.total {
                staged_hit = staged.total == bound;
                reached = staged;
            }
        }
        if reachable {
            assert_eq!(reached.total, bound, "{window} not reached\n{body}");
            for payer in payers {
                evaluations += 1;
                assert!(
                    !engine_admits(&reached.engine, payer, 1, reached.now, net),
                    "{}",
                    payer.tool
                );
            }
        }
        (evaluations, staged_hit)
    }

    /// Every window a tool's stated caps and rates keep, in milliseconds.
    fn stated_windows_ms(tools: &[&ToolLimits]) -> Vec<u64> {
        let mut windows: Vec<u64> = tools
            .iter()
            .flat_map(|t| {
                t.period_caps
                    .iter()
                    .map(|c| c.window.clone())
                    .chain(t.rate_caps.iter().map(|c| c.window.clone()))
                    .chain(t.unlisted_period_cap.iter().map(|c| c.window.clone()))
            })
            .filter_map(|w| window_ms(&w))
            .collect();
        windows.sort_unstable();
        windows.dedup();
        windows
    }

    /// The counts of a bound check: evaluations, bounds checked, and bounds
    /// a staged run reached that the greedy run missed.
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
    struct BoundCounts {
        evaluations: usize,
        checked: usize,
        staged: usize,
    }

    impl BoundCounts {
        fn add(&mut self, (evaluations, staged): (usize, bool)) {
            self.evaluations += evaluations;
            self.checked += 1;
            self.staged += usize::from(staged);
        }
    }

    /// Checks every stated bound of the first asset of `summary`, per tool
    /// and per asset, for listed recipients and addresses in no list.
    fn check_every_bound(body: &str, net: Net, summary: &SpendingSummary) -> BoundCounts {
        let mut counts = BoundCounts::default();
        let Some(limits) = summary.limits.first() else {
            return counts;
        };
        let open = &summary.recipients.unrestricted_tools;
        let all: Vec<&ToolLimits> = limits.tools.iter().collect();
        let windows = stated_windows_ms(&all);
        let asset = limits.asset.as_str();
        for unlisted in [false, true] {
            for tool in &all {
                let own = payers(&[*tool], asset, unlisted, open);
                let bounds = if unlisted {
                    &tool.unlisted_bounds
                } else {
                    &tool.bounds
                };
                for bound in bounds {
                    let Some(amount) = bound.amount.as_deref() else {
                        continue;
                    };
                    let amount = parse_amount(amount).unwrap_or(0);
                    if own.is_empty() {
                        assert!(!bound.reachable || amount == 0, "{}\n{body}", tool.tool);
                        continue;
                    }
                    counts.add(check_bound(
                        body,
                        net,
                        &own,
                        &windows,
                        (&bound.window, amount),
                        bound.reachable,
                    ));
                }
            }
            let joint = payers(&all, asset, unlisted, open);
            let asset_bounds = if unlisted {
                &limits.unlisted_bounds
            } else {
                &limits.bounds
            };
            for bound in asset_bounds {
                let Some(amount) = bound.amount.as_deref() else {
                    continue;
                };
                let amount = parse_amount(amount).unwrap_or(0);
                if joint.is_empty() {
                    assert!(!bound.reachable || amount == 0, "{body}");
                    continue;
                }
                counts.add(check_bound(
                    body,
                    net,
                    &joint,
                    &windows,
                    (&bound.window, amount),
                    bound.reachable,
                ));
            }
        }
        counts
    }

    /// No payment sequence passes a stated bound, per tool and per asset,
    /// and every bound flagged reachable is reached exactly, with one stroop
    /// more refused. The family varies windows, identifiers, totals,
    /// repeated criteria, per-payment caps, decisions, and recipient
    /// classifications, and holds the generated preset bodies.
    #[test]
    fn summary_bounds_match_payment_sequences() {
        const PAY: &str = "stellar_pay";
        const COMMIT: &str = "stellar_pay_commit";
        let mut family: Vec<(Net, String)> = Vec::new();
        for tools in [
            vec![PAY, COMMIT],
            vec![PAY, COMMIT, CREATE_TOOL],
            vec![CREATE_TOOL, PAY],
        ] {
            for n in 0..24 {
                let rules: Vec<String> = tools
                    .iter()
                    .enumerate()
                    .map(|(r, tool)| bound_rule(tool, n, r))
                    .collect();
                for net in [Net::Mainnet, Net::Testnet] {
                    if net == Net::Testnet && n % 4 != 0 {
                        continue;
                    }
                    family.push((net, net.body(&plain_body(&rules))));
                }
            }
        }
        // The generated preset bodies as written and with one recipient.
        for spec in &PRESETS {
            let unlisted = spec.archetype == Archetype::Api;
            let generated = policy_body(PROFILE, &derived(spec.name, unlisted, true));
            let added = add_recipient(&generated, &account(7)).unwrap();
            family.push((Net::Mainnet, generated));
            family.push((Net::Mainnet, added));
        }
        let mut counts = BoundCounts::default();
        let (mut summed, mut per_tool, mut unreachable) = (0, 0, 0);
        for (net, body) in &family {
            validate_unsigned_policy(body, PROFILE, net.passphrase())
                .unwrap_or_else(|error| panic!("{error}\n{body}"));
            let summary = net.summary(body);
            for bound in summary
                .limits
                .iter()
                .flat_map(|l| l.bounds.iter().chain(&l.unlisted_bounds))
            {
                summed += usize::from(bound.summed_over_counters);
                per_tool += usize::from(bound.amount == Agreed::PerTool);
                unreachable += usize::from(!bound.reachable);
            }
            let body_counts = check_every_bound(body, *net, &summary);
            counts.evaluations += body_counts.evaluations;
            counts.checked += body_counts.checked;
            counts.staged += body_counts.staged;
        }
        assert_eq!(
            (family.len(), counts, summed, per_tool, unreachable),
            (
                114,
                BoundCounts {
                    evaluations: 1_010_390,
                    checked: 1_580,
                    staged: 86,
                },
                202,
                0,
                176
            ),
            "bound property size"
        );
        // The family holds every classification beside the unlisted budget,
        // and lists that name nobody.
        let holding = |needle: &str| family.iter().filter(|(_, b)| b.contains(needle)).count();
        assert_eq!(
            (
                holding("kinds = [\"KNOWN_ISSUER\"]"),
                holding("kinds = [\"HOME_DOMAIN\"]"),
                holding("allowlist = []"),
            ),
            (4, 3, 39),
            "bound family shapes"
        );
    }

    // ── Evaluation matrix ──────────────────────────────────────────────────

    const API: &[&str] = &[
        "typical:allow",
        "per_tx:allow",
        "per_tx+1:deny",
        "x402_per_tx:allow",
        "unlisted_pay:deny",
        "unlisted_x402:deny",
    ];
    const API_UNLISTED: &[&str] = &[
        "typical:allow",
        "per_tx:allow",
        "per_tx+1:deny",
        "x402_per_tx:allow",
        "unlisted_pay:allow",
        "unlisted_half:allow",
        "unlisted_half+1:deny",
        "unlisted_authenticated:allow",
        "unlisted_within_u:allow",
        "unlisted_beyond_u:deny",
        "unlisted_pay_beyond_u:deny",
    ];
    const APPROVING: &[&str] = &[
        "typical:allow",
        "per_tx:approval",
        "per_tx+1:deny",
        "approval:allow",
        "approval+1:approval",
        "x402_above_approval:approval",
        "unlisted_pay:deny",
        "unlisted_x402:deny",
    ];
    /// Each bound alone: spent to one stroop below it, one more stroop
    /// reaches it and a second exceeds it.
    const EXHAUSTION: &[&str] = &[
        "1d_equal:allow",
        "1d+1:deny:1d",
        "1w_equal:allow",
        "1w+1:deny:1w",
        "total_equal:allow",
        "total+1:deny:total",
    ];

    /// Every preset and unlisted choice with its literal decisions; the
    /// amounts are the literals of [`TABLE`].
    const MATRIX: [(&str, bool, &[&str]); 15] = [
        ("api-day", false, API),
        ("api-day", true, API_UNLISTED),
        ("api-week", false, API),
        ("api-week", true, API_UNLISTED),
        ("api-2weeks", false, API),
        ("api-2weeks", true, API_UNLISTED),
        ("compute-day", false, API),
        ("compute-week", false, API),
        ("compute-2weeks", false, API),
        ("shop-day", false, APPROVING),
        ("shop-week", false, APPROVING),
        ("shop-2weeks", false, APPROVING),
        ("business-day", false, APPROVING),
        ("business-week", false, APPROVING),
        ("business-2weeks", false, APPROVING),
    ];

    /// Records a confirmed payment of any amount to a listed recipient. The
    /// effects carry the listed class, as the effects of a permitted
    /// evaluation do, since an unlisted budget sizes by that class.
    fn record_pay(engine: &PolicyEngineV1, to: &str, amount: i128) {
        let args = pay_args(to, amount);
        let ValueClass::Value(effects) = derive_value_class("stellar_pay", &args) else {
            panic!("a payment moves value");
        };
        engine
            .record_confirmed(
                &tool("stellar_pay"),
                &mainnet_profile(),
                &ValueClass::Value(effects.with_recipient_class(Some(RecipientClass::Listed))),
            )
            .unwrap();
    }

    /// Records a confirmed x402 payment with the effects its permitted
    /// evaluation returned, which carry the recipient class the unlisted
    /// budget counts by.
    fn record_x402(engine: &PolicyEngineV1, to: &str, amount: i128, now_ms: u64) {
        let evaluation = engine
            .evaluate_with_value_full(
                &tool(CREATE_TOOL),
                &serde_json::json!({}),
                &mainnet_profile(),
                x402_value(to, amount),
                None,
                None,
                None,
                None,
                None,
                now_ms,
            )
            .unwrap();
        assert_eq!(evaluation.decision, Decision::Allow);
        engine
            .record_confirmed(
                &tool(CREATE_TOOL),
                &mainnet_profile(),
                &ValueClass::Value(evaluation.value_effects.unwrap()),
            )
            .unwrap();
    }

    fn matrix_run(name: &str, unlisted_budget: bool) -> Vec<String> {
        let row = TABLE.iter().find(|row| row.name == name).unwrap();
        let stroops = |text: &str| parse_amount(text).unwrap();
        let (typical, per_tx) = (stroops(row.typical), stroops(row.per_tx));
        let listed = account(7);
        let unlisted = account(9);
        let body = listed_body(&derived(name, unlisted_budget, true), &listed);
        let fresh = || verified_engine(&body);
        let mut out = Vec::new();
        let mut push = |case: &str, decision: Decision| {
            out.push(format!("{case}:{}", label(&decision)));
        };
        push("typical", pay(&fresh(), &listed, typical, T0));
        push("per_tx", pay(&fresh(), &listed, per_tx, T0));
        push("per_tx+1", pay(&fresh(), &listed, per_tx + 1, T0));
        match row.approval.map(stroops) {
            Some(threshold) => {
                push("approval", pay(&fresh(), &listed, threshold, T0));
                push("approval+1", pay(&fresh(), &listed, threshold + 1, T0));
                push(
                    "x402_above_approval",
                    x402(&fresh(), CREATE_TOOL, &listed, threshold + 1, T0),
                );
            }
            None => push(
                "x402_per_tx",
                x402(&fresh(), CREATE_TOOL, &listed, per_tx, T0),
            ),
        }
        push("unlisted_pay", pay(&fresh(), &unlisted, typical, T0));
        let clock = set_query_time_for_test(T0);
        if let Some(half) = row
            .unlisted_payment
            .filter(|_| unlisted_budget)
            .map(stroops)
        {
            push(
                "unlisted_half",
                x402(&fresh(), CREATE_TOOL, &unlisted, half, T0),
            );
            push(
                "unlisted_half+1",
                x402(&fresh(), CREATE_TOOL, &unlisted, half + 1, T0),
            );
            push(
                "unlisted_authenticated",
                x402(
                    &fresh(),
                    "stellar_x402_authenticated_payment",
                    &unlisted,
                    half,
                    T0,
                ),
            );
            // U = 5·(P/2): four payments leave room for a fifth, five spend U.
            let engine = fresh();
            for k in 0..4 {
                clock.set(T0 + k * STEP_MS);
                record_x402(&engine, &unlisted, half, T0 + k * STEP_MS);
            }
            let now = T0 + 4 * STEP_MS;
            push(
                "unlisted_within_u",
                x402(&engine, CREATE_TOOL, &unlisted, half, now),
            );
            clock.set(now);
            record_x402(&engine, &unlisted, half, now);
            push(
                "unlisted_beyond_u",
                x402(&engine, CREATE_TOOL, &unlisted, 1, now + STEP_MS),
            );
            // The pay rule shares the budget the x402 payments spent.
            push(
                "unlisted_pay_beyond_u",
                pay(&engine, &unlisted, 1, now + STEP_MS),
            );
        } else {
            push(
                "unlisted_x402",
                x402(&fresh(), CREATE_TOOL, &unlisted, typical, T0),
            );
        }
        // Each bound alone: the earlier spend lies inside its window and
        // outside every shorter one.
        for (bound, spent, age_ms) in [
            ("1d", row.daily, 3_600_000),
            ("1w", row.weekly, 2 * 86_400_000),
            ("total", row.loss, 9 * 86_400_000),
        ] {
            let engine = fresh();
            clock.set(T0 - age_ms);
            record_pay(&engine, &listed, stroops(spent) - 1);
            push(&format!("{bound}_equal"), pay(&engine, &listed, 1, T0));
            push(&format!("{bound}+1"), pay(&engine, &listed, 2, T0));
        }
        out
    }

    /// Every preset and unlisted choice on a signed and verified policy with
    /// one listed G recipient. The amounts and decisions are literals.
    #[test]
    fn preset_evaluation_matrix() {
        for (name, unlisted_budget, expected) in MATRIX {
            assert_eq!(
                matrix_run(name, unlisted_budget),
                [expected, EXHAUSTION].concat(),
                "{name} unlisted={unlisted_budget}"
            );
        }
    }

    include!("presets_recipient_tests.rs");
}
