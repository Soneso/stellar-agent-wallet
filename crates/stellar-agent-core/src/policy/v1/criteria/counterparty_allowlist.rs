//! Counterparty allowlist criterion.
//!
//! `CounterpartyAllowlistCriterion` checks that the destination account or
//! asset issuer in the current tool call appears on a configured allowlist.
//!
//! # Supported kinds
//!
//! - `G_ACCOUNT` — G-strkey destination address.
//! - `C_ACCOUNT` — C-strkey (contract) destination address.
//! - `KNOWN_ISSUER` — asset issuer G-strkey for non-native payments.
//! - `HOME_DOMAIN` — the `home_domain` field of the destination's on-chain
//!   `AccountEntry`, resolved via `AccountReservesView::home_domain`.
//!
//! Unsupported kinds (`SEP10_IDENTITY`, `ONE_TIME_ADDRESS`) return
//! [`DenyReason::CounterpartyKindUnsupported`] rather than silently allowing;
//! these kinds are reserved for future wiring.
//!
//! # TOML shape
//!
//! ```toml
//! { kind = "counterparty_allowlist", kinds = ["G_ACCOUNT"], allowlist = ["GABC...", "GXYZ..."] }
//! { kind = "counterparty_allowlist", kinds = ["KNOWN_ISSUER"], allowlist = ["USDC:GA5Z..."] }
//! { kind = "counterparty_allowlist", kinds = ["HOME_DOMAIN"], allowlist = ["circle.com", "stellar.org"] }
//! ```
//!
//! `kinds` selects which counterparty dimension(s) to check; `allowlist` is
//! the approved set for all listed kinds.
//!
//! # G_ACCOUNT logic
//!
//! Extracts `args["destination"]` and validates it as a G-strkey via
//! [`stellar_strkey::ed25519::PublicKey::from_string`].  If the destination is
//! not on the allowlist, returns [`DenyReason::CounterpartyDenied`].
//!
//! # C_ACCOUNT logic
//!
//! Extracts `args["destination"]` and validates it as a C-strkey (contract
//! address) via [`stellar_strkey::Contract::from_string`].
//!
//! # KNOWN_ISSUER logic
//!
//! Extracts `args["asset"]`; for non-native assets (`"CODE:G…issuer"`) the
//! issuer G-strkey is matched against the allowlist entries of the form
//! `"CODE:Gissuer"`.  A native-asset payment passes through (no issuer to
//! check).
//!
//! # HOME_DOMAIN logic
//!
//! Reads the destination account's `home_domain` via
//! `AccountReservesView::home_domain`.  When `home_domain`
//! is `None` (the destination account has no published home domain) the criterion
//! returns [`DenyReason::CounterpartyDenied`] — an account with no home domain
//! cannot match an allowlist of trusted operators.
//!
//! The comparison is a **strict byte-equality** between the resolved domain and
//! each allowlist entry.  Both sides MUST be valid ASCII; non-ASCII bytes in the
//! resolved home domain produce [`DenyReason::CounterpartyDenied`] (not an
//! error) as the homoglyph defence: a Cyrillic or digit-substituted domain such
//! as `сircle.com` or `circ1e.com` cannot satisfy an allowlist entry of
//! `"circle.com"`.  Allowlist entries that contain non-ASCII bytes are rejected
//! at construction time in the TOML loader (see [`crate::policy::v1::loader`]).
//!
//! The comparison is case-sensitive.  Operators MUST normalise domain names to
//! lowercase in their policy files (RFC 4343 DNS case-insensitivity is explicitly
//! NOT applied here — a follow-up issue tracks whether relaxation is appropriate;
//! the safe default is strict equality).
//!

use stellar_strkey::{Contract, ed25519::PublicKey};

use crate::policy::v1::EvalContext;
use crate::policy::v1::criteria::Criterion;
use crate::policy::{DenyReason, PolicyError};

// ─────────────────────────────────────────────────────────────────────────────
// CounterpartyKind
// ─────────────────────────────────────────────────────────────────────────────

/// The dimension(s) along which a counterparty is identified.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CounterpartyKind {
    /// A classic Stellar account address (G-strkey).
    GAccount,
    /// A Soroban contract address (C-strkey).
    CAccount,
    /// The issuer of the asset being transferred (G-strkey).
    KnownIssuer,
    /// SEP-10 authenticated identity (reserved; not currently evaluated).
    Sep10Identity,
    /// Verified `home_domain` of the destination account.
    HomeDomain,
    /// Single-use or unverified address (reserved; not currently evaluated).
    OneTimeAddress,
}

impl CounterpartyKind {
    /// Parses a kind string from TOML.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::PolicyFileParseFailed`] for unrecognised strings.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::policy::v1::criteria::counterparty_allowlist::CounterpartyKind;
    ///
    /// assert_eq!(
    ///     CounterpartyKind::parse("G_ACCOUNT").unwrap(),
    ///     CounterpartyKind::GAccount,
    /// );
    /// ```
    pub fn parse(s: &str) -> Result<Self, PolicyError> {
        match s {
            "G_ACCOUNT" => Ok(Self::GAccount),
            "C_ACCOUNT" => Ok(Self::CAccount),
            "KNOWN_ISSUER" => Ok(Self::KnownIssuer),
            "SEP10_IDENTITY" => Ok(Self::Sep10Identity),
            "HOME_DOMAIN" => Ok(Self::HomeDomain),
            "ONE_TIME_ADDRESS" => Ok(Self::OneTimeAddress),
            other => Err(PolicyError::PolicyFileParseFailed {
                detail: format!(
                    "counterparty_allowlist: unknown kind '{}'; \
                     accepted: G_ACCOUNT, C_ACCOUNT, KNOWN_ISSUER, \
                     SEP10_IDENTITY, HOME_DOMAIN, ONE_TIME_ADDRESS",
                    other
                ),
            }),
        }
    }

    /// Returns the TOML tag string for this kind.
    #[must_use]
    pub fn tag(&self) -> &'static str {
        match self {
            Self::GAccount => "G_ACCOUNT",
            Self::CAccount => "C_ACCOUNT",
            Self::KnownIssuer => "KNOWN_ISSUER",
            Self::Sep10Identity => "SEP10_IDENTITY",
            Self::HomeDomain => "HOME_DOMAIN",
            Self::OneTimeAddress => "ONE_TIME_ADDRESS",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CounterpartyAllowlistCriterion
// ─────────────────────────────────────────────────────────────────────────────

/// Counterparty allowlist criterion.
///
/// Checks that the destination account or asset issuer is present in the
/// configured `allowlist` for each of the specified `kinds`.  All kinds are
/// checked; the first denial wins.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::policy::v1::criteria::counterparty_allowlist::{
///     CounterpartyAllowlistCriterion, CounterpartyKind,
/// };
/// use stellar_agent_core::policy::v1::criteria::Criterion;
///
/// let criterion = CounterpartyAllowlistCriterion::new(
///     vec![CounterpartyKind::GAccount],
///     vec!["GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN".to_owned()],
/// );
/// assert_eq!(criterion.kind(), "counterparty_allowlist");
/// ```
#[derive(Debug, Clone)]
pub struct CounterpartyAllowlistCriterion {
    /// Counterparty dimensions to check.
    kinds: Vec<CounterpartyKind>,
    /// Approved counterparty entries.  For `G_ACCOUNT`/`C_ACCOUNT` these are
    /// strkeys; for `KNOWN_ISSUER` these are `"CODE:Gissuer"` strings.
    allowlist: Vec<String>,
}

impl CounterpartyAllowlistCriterion {
    /// Constructs a new [`CounterpartyAllowlistCriterion`].
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::policy::v1::criteria::counterparty_allowlist::{
    ///     CounterpartyAllowlistCriterion, CounterpartyKind,
    /// };
    ///
    /// let criterion = CounterpartyAllowlistCriterion::new(
    ///     vec![CounterpartyKind::GAccount],
    ///     vec!["GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN".to_owned()],
    /// );
    /// ```
    #[must_use]
    pub fn new(kinds: Vec<CounterpartyKind>, allowlist: Vec<String>) -> Self {
        Self { kinds, allowlist }
    }
}

impl Criterion for CounterpartyAllowlistCriterion {
    fn kind(&self) -> &'static str {
        "counterparty_allowlist"
    }

    /// Evaluates each configured kind against the current tool call.
    ///
    /// Returns `Ok(None)` when every kind passes (destination on allowlist).
    /// Returns `Ok(Some(DenyReason::CounterpartyDenied))` when a destination
    /// is not on the allowlist.
    /// Returns `Ok(Some(DenyReason::CounterpartyKindUnsupported))` when an
    /// unsupported kind (`SEP10_IDENTITY`, `HOME_DOMAIN`, `ONE_TIME_ADDRESS`)
    /// is listed.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::CriterionEvaluationFailed`] when the destination
    /// field is missing or is not a valid strkey.
    fn evaluate(&self, ctx: &EvalContext<'_>) -> Result<Option<DenyReason>, PolicyError> {
        for kind in &self.kinds {
            if let Some(deny) = self.evaluate_kind(kind, ctx)? {
                return Ok(Some(deny));
            }
        }
        Ok(None)
    }
}

impl CounterpartyAllowlistCriterion {
    fn evaluate_kind(
        &self,
        kind: &CounterpartyKind,
        ctx: &EvalContext<'_>,
    ) -> Result<Option<DenyReason>, PolicyError> {
        match kind {
            CounterpartyKind::GAccount => self.check_g_account(ctx),
            CounterpartyKind::CAccount => self.check_c_account(ctx),
            CounterpartyKind::KnownIssuer => self.check_known_issuer(ctx),
            CounterpartyKind::HomeDomain => self.check_home_domain(ctx),
            unsupported => Ok(Some(DenyReason::CounterpartyKindUnsupported {
                kind: unsupported.tag().to_owned(),
            })),
        }
    }

    fn check_g_account(&self, ctx: &EvalContext<'_>) -> Result<Option<DenyReason>, PolicyError> {
        let destination = resolve_destination(ctx)?;

        // Validate that it is a well-formed G-strkey.
        PublicKey::from_string(&destination).map_err(|e| {
            PolicyError::CriterionEvaluationFailed {
                detail: format!(
                    "counterparty_allowlist: invalid G-strkey in 'destination' \
                     for tool '{}': {e}",
                    ctx.tool.name
                ),
            }
        })?;

        if !self.allowlist.contains(&destination) {
            return Ok(Some(DenyReason::CounterpartyDenied {
                kind: "G_ACCOUNT".to_owned(),
                value: destination,
            }));
        }

        Ok(None)
    }

    fn check_c_account(&self, ctx: &EvalContext<'_>) -> Result<Option<DenyReason>, PolicyError> {
        let destination = resolve_destination(ctx)?;

        // Validate that it is a well-formed C-strkey.
        Contract::from_string(&destination).map_err(|e| {
            PolicyError::CriterionEvaluationFailed {
                detail: format!(
                    "counterparty_allowlist: invalid C-strkey in 'destination' \
                     for tool '{}': {e}",
                    ctx.tool.name
                ),
            }
        })?;

        if !self.allowlist.contains(&destination) {
            return Ok(Some(DenyReason::CounterpartyDenied {
                kind: "C_ACCOUNT".to_owned(),
                value: destination,
            }));
        }

        Ok(None)
    }

    fn check_known_issuer(&self, ctx: &EvalContext<'_>) -> Result<Option<DenyReason>, PolicyError> {
        let asset_str = match resolve_asset(ctx) {
            None => return Ok(None), // no asset field; criterion does not apply
            Some(s) => s,
        };

        // Native asset has no issuer to check.
        if asset_str.eq_ignore_ascii_case("native") || asset_str.eq_ignore_ascii_case("xlm") {
            return Ok(None);
        }

        // Non-native: parse "CODE:Gissuer".
        let issuer = parse_asset_issuer(&asset_str, ctx)?;

        // Check the issuer against the allowlist, which stores entries as
        // "CODE:Gissuer".  We match on the issuer portion of each allowlist
        // entry and also support bare G-strkey entries.
        let on_list = self.allowlist.iter().any(|entry| {
            if let Some(list_issuer) = entry.split_once(':').map(|(_, i)| i) {
                list_issuer == issuer
            } else {
                // Bare G-strkey entry.
                entry == &issuer
            }
        });

        if !on_list {
            return Ok(Some(DenyReason::CounterpartyDenied {
                kind: "KNOWN_ISSUER".to_owned(),
                value: issuer,
            }));
        }

        Ok(None)
    }

    /// Checks the destination account's `home_domain` against the allowlist.
    ///
    /// Reads `home_domain` via [`crate::policy::v1::AccountIdentityView::home_domain`]
    /// (supplied in [`EvalContext::identity_view`]).  When `identity_view` is
    /// `None` or `home_domain()` returns `None` (destination has no published home
    /// domain), returns [`DenyReason::CounterpartyDenied`].
    ///
    /// The comparison is case-insensitive ASCII (see the `check_home_domain` body).
    /// Non-ASCII bytes in the resolved home domain produce
    /// [`DenyReason::CounterpartyDenied`] — the homoglyph defence.  Allowlist
    /// entries are guaranteed to be valid ASCII because the TOML loader rejects
    /// non-ASCII entries at parse time.
    fn check_home_domain(&self, ctx: &EvalContext<'_>) -> Result<Option<DenyReason>, PolicyError> {
        // Retrieve the home_domain from the identity view.
        // When identity_view is None or home_domain() returns None, the
        // destination has no published home domain and cannot match any allowlist
        // entry.  AccountIdentityView has no default home_domain() implementation,
        // so forgetting to implement it at the dispatch site is a compile error.
        let resolved = match ctx.identity_view.and_then(|v| v.home_domain()) {
            Some(d) => d,
            None => {
                return Ok(Some(DenyReason::CounterpartyDenied {
                    kind: "HOME_DOMAIN".to_owned(),
                    value: String::new(),
                }));
            }
        };

        // Strict-ASCII enforcement — the homoglyph defence.
        // If the resolved home_domain contains non-ASCII bytes (e.g. Cyrillic
        // lookalikes, digit substitutions encoded outside the ASCII range), the
        // domain cannot satisfy any allowlist entry and is immediately denied.
        // Non-ASCII bytes are REDACTED from the DenyReason value to avoid
        // leaking potentially sensitive data in error/audit envelopes.
        // The ASCII branch still echoes the value (all bytes are printable ASCII).
        if !resolved.bytes().all(|b| b.is_ascii()) {
            return Ok(Some(DenyReason::CounterpartyDenied {
                kind: "HOME_DOMAIN".to_owned(),
                value: "<non-ascii-redacted>".to_owned(),
            }));
        }

        // Case-insensitive ASCII comparison per RFC 4343.
        // Lowercase the resolved home_domain before comparing so that on-chain
        // entries like "Circle.com" correctly match the allowlist entry "circle.com".
        // The homoglyph defence is not relaxed: Cyrillic lookalikes have already
        // been rejected by the non-ASCII check above; only ASCII-lowercase
        // normalisation is applied here.
        let resolved_lower = resolved.to_ascii_lowercase();
        if !self.allowlist.iter().any(|entry| entry == &resolved_lower) {
            return Ok(Some(DenyReason::CounterpartyDenied {
                kind: "HOME_DOMAIN".to_owned(),
                value: resolved_lower,
            }));
        }

        Ok(None)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Returns `true` for the pay/create tool family whose value fields are now
/// sourced from the derived value leg rather than raw args.
fn is_pay_or_create(tool_name: &str) -> bool {
    matches!(
        tool_name,
        "stellar_pay"
            | "stellar_pay_commit"
            | "stellar_create_account"
            | "stellar_create_account_commit"
    )
}

/// Resolves the counterparty destination for the current call.
///
/// For the pay/create family reads `ctx.value`'s sole leg `destination`
/// (behaviour-neutral: the leg's destination is the same `args["destination"]`
/// string the gate derived); an unresolvable destination is refused exactly as
/// a missing/non-string `args` field was. Other tools keep the raw-args path.
///
/// # Errors
///
/// Returns [`PolicyError::CriterionEvaluationFailed`] when the destination is
/// unresolvable.
fn resolve_destination(ctx: &EvalContext<'_>) -> Result<String, PolicyError> {
    if is_pay_or_create(ctx.tool.name.as_str()) {
        ctx.value
            .sole_value_leg()
            .and_then(|leg| leg.destination.clone())
            .ok_or_else(|| PolicyError::CriterionEvaluationFailed {
                detail: format!(
                    "counterparty_allowlist: missing or non-string field 'destination' \
                     in value descriptor for tool '{}'",
                    ctx.tool.name
                ),
            })
    } else {
        extract_string_field(ctx, "destination")
    }
}

/// Resolves the asset for the KNOWN_ISSUER check.
///
/// For the pay/create family reads `ctx.value`'s sole leg `asset` (the
/// canonical asset id derived from `args["asset"]`); `None` means the criterion
/// does not apply, matching an absent `args["asset"]`. Other tools keep the
/// raw-args path.
fn resolve_asset(ctx: &EvalContext<'_>) -> Option<String> {
    if is_pay_or_create(ctx.tool.name.as_str()) {
        ctx.value.sole_value_leg().and_then(|leg| leg.asset.clone())
    } else {
        ctx.args
            .get("asset")
            .and_then(|v| v.as_str())
            .map(str::to_owned)
    }
}

fn extract_string_field(ctx: &EvalContext<'_>, field: &str) -> Result<String, PolicyError> {
    ctx.args
        .get(field)
        .and_then(|v| v.as_str())
        .map(str::to_owned)
        .ok_or_else(|| PolicyError::CriterionEvaluationFailed {
            detail: format!(
                "counterparty_allowlist: missing or non-string field '{}' \
                 in args for tool '{}'",
                field, ctx.tool.name
            ),
        })
}

/// Parses `"CODE:G…ISSUER"` and returns the issuer G-strkey.
fn parse_asset_issuer(asset_str: &str, ctx: &EvalContext<'_>) -> Result<String, PolicyError> {
    let issuer = asset_str.split_once(':').map(|(_, i)| i).ok_or_else(|| {
        PolicyError::CriterionEvaluationFailed {
            detail: format!(
                "counterparty_allowlist: non-native asset '{}' must be in \
                 CODE:Gissuer format for tool '{}'",
                asset_str, ctx.tool.name
            ),
        }
    })?;

    // Validate the issuer is a proper G-strkey.
    PublicKey::from_string(issuer).map_err(|e| PolicyError::CriterionEvaluationFailed {
        detail: format!(
            "counterparty_allowlist: invalid issuer G-strkey in asset '{}' \
             for tool '{}': {e}",
            asset_str, ctx.tool.name
        ),
    })?;

    Ok(issuer.to_owned())
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use serde_json::json;

    use super::*;
    use crate::policy::v1::criteria::state_store::PolicyStateStore;
    use crate::policy::{McpToolRegistration, ToolDescriptor};
    use crate::profile::schema::Profile;

    // Known-valid 56-char G-strkeys (from Stellar codebase fixtures).
    const G_ALLOWED: &str = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";
    // Another valid G-strkey not on the allowlist.
    const G_DENIED: &str = "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY";
    // Valid C-strkey fixtures. C_DENIED uses a non-trivial byte payload to
    // avoid all-constant synthetic shapes while remaining off-allowlist.
    const C_ALLOWED: &str = "CA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUWDA";
    const C_DENIED_BYTES: [u8; 32] = [
        0x10, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67,
        0x78, 0x89, 0x9A, 0xAB, 0xBC, 0xCD, 0xDE, 0xEF, 0xF0, 0x0F, 0x1E, 0x2D, 0x3C, 0x4B, 0x5A,
        0x69, 0x78,
    ];

    // A valid USDC issuer G-strkey (matches the mainnet GA5Z... issuer).
    const USDC_ISSUER: &str = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";

    /// Constructs a `ToolDescriptor` for `tool_name` with the registration
    /// attributes used by all criterion tests.
    fn make_tool(tool_name: &'static str) -> ToolDescriptor {
        let reg = McpToolRegistration {
            name: tool_name,
            destructive_hint: true,
            read_only_hint: false,
            chain_id_required: true,
            value_kind: crate::policy::ToolValueKind::ReadOnly,
        };
        ToolDescriptor::from_registration(&reg)
    }

    /// Constructs a standard testnet `Profile` for criterion tests.
    fn make_profile() -> Profile {
        Profile::builder_testnet("alice", "acct", "n-svc", "n-acct").build()
    }

    /// Constructs an [`EvalContext`] from caller-owned `tool`, `profile`,
    /// `args`, and `store`.  Lifetimes are tied to the caller's stack so
    /// no heap allocation is leaked.
    fn make_ctx<'a>(
        tool: &'a ToolDescriptor,
        profile: &'a Profile,
        args: &'a serde_json::Value,
        store: &'a PolicyStateStore,
    ) -> EvalContext<'a> {
        EvalContext {
            tool,
            args,
            profile_name: "alice",
            profile,
            // Mirror the dispatch gate: derive the value descriptor the
            // counterparty checks now read through ctx.value for pay/create.
            value: crate::policy::v1::value::derive_value_class(tool.name.as_str(), args),
            account_view: None,
            identity_view: None,
            quorum: None,
            counterparty_cache: None,
            sep10_sessions: None,
            sep45_sessions: None,
            state_store: store,
            bundle: None,
        }
    }

    #[test]
    fn g_account_in_allowlist_passes() {
        let tool = make_tool("stellar_pay");
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let criterion = CounterpartyAllowlistCriterion::new(
            vec![CounterpartyKind::GAccount],
            vec![G_ALLOWED.to_owned()],
        );
        let args = json!({ "destination": G_ALLOWED });
        let ctx = make_ctx(&tool, &profile, &args, &store);
        let result = criterion.evaluate(&ctx).unwrap();
        assert!(result.is_none(), "allowed G-account should pass");
    }

    #[test]
    fn g_account_not_in_allowlist_denies() {
        let tool = make_tool("stellar_pay");
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let criterion = CounterpartyAllowlistCriterion::new(
            vec![CounterpartyKind::GAccount],
            vec![G_ALLOWED.to_owned()],
        );
        let args = json!({ "destination": G_DENIED });
        let ctx = make_ctx(&tool, &profile, &args, &store);
        let result = criterion.evaluate(&ctx).unwrap();
        assert!(
            matches!(result, Some(DenyReason::CounterpartyDenied { kind, .. }) if kind == "G_ACCOUNT"),
            "G-account not on allowlist should be denied"
        );
    }

    #[test]
    fn c_account_in_allowlist_passes() {
        let tool = make_tool("stellar_pay");
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let criterion = CounterpartyAllowlistCriterion::new(
            vec![CounterpartyKind::CAccount],
            vec![C_ALLOWED.to_owned()],
        );
        let args = json!({ "destination": C_ALLOWED });
        let ctx = make_ctx(&tool, &profile, &args, &store);
        let result = criterion.evaluate(&ctx).unwrap();
        assert!(result.is_none(), "allowed C-account should pass");
    }

    #[test]
    fn c_account_not_in_allowlist_denies() {
        let tool = make_tool("stellar_pay");
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let c_denied = Contract(C_DENIED_BYTES).to_string();
        let criterion = CounterpartyAllowlistCriterion::new(
            vec![CounterpartyKind::CAccount],
            vec![C_ALLOWED.to_owned()],
        );
        let args = json!({ "destination": c_denied.as_str() });
        let ctx = make_ctx(&tool, &profile, &args, &store);
        let result = criterion.evaluate(&ctx).unwrap();

        assert!(
            matches!(result, Some(DenyReason::CounterpartyDenied { kind, .. }) if kind == "C_ACCOUNT"),
            "C-account not on allowlist should be denied"
        );
    }

    #[test]
    fn known_issuer_in_allowlist_passes() {
        let tool = make_tool("stellar_pay");
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let criterion = CounterpartyAllowlistCriterion::new(
            vec![CounterpartyKind::KnownIssuer],
            vec![format!("USDC:{USDC_ISSUER}")],
        );
        let args = json!({
            "asset": format!("USDC:{USDC_ISSUER}"),
            "destination": G_ALLOWED
        });
        let ctx = make_ctx(&tool, &profile, &args, &store);
        let result = criterion.evaluate(&ctx).unwrap();
        assert!(result.is_none(), "USDC issuer on allowlist should pass");
    }

    #[test]
    fn known_issuer_bare_g_strkey_allowlist_entry_passes() {
        let tool = make_tool("stellar_pay");
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let criterion = CounterpartyAllowlistCriterion::new(
            vec![CounterpartyKind::KnownIssuer],
            vec![USDC_ISSUER.to_owned()],
        );
        let args = json!({
            "asset": format!("USDC:{USDC_ISSUER}"),
            "destination": G_ALLOWED
        });
        let ctx = make_ctx(&tool, &profile, &args, &store);
        let result = criterion.evaluate(&ctx).unwrap();

        assert!(
            result.is_none(),
            "bare G-strkey issuer allowlist entry should pass"
        );
    }

    #[test]
    fn known_issuer_not_in_allowlist_denies() {
        let tool = make_tool("stellar_pay");
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let criterion = CounterpartyAllowlistCriterion::new(
            vec![CounterpartyKind::KnownIssuer],
            vec![format!("USDC:{G_DENIED}")],
        );
        // Use a well-formed G-strkey as the "unlisted" issuer.
        let asset = format!("MYTOKEN:{USDC_ISSUER}");
        let args = json!({ "asset": asset, "destination": G_ALLOWED });
        let ctx = make_ctx(&tool, &profile, &args, &store);
        let result = criterion.evaluate(&ctx).unwrap();
        assert!(
            matches!(result, Some(DenyReason::CounterpartyDenied { kind, .. }) if kind == "KNOWN_ISSUER"),
            "unlisted issuer should be denied"
        );
    }

    #[test]
    fn unsupported_kind_returns_counterparty_kind_unsupported() {
        let tool = make_tool("stellar_pay");
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let criterion =
            CounterpartyAllowlistCriterion::new(vec![CounterpartyKind::Sep10Identity], vec![]);
        let args = json!({ "destination": G_ALLOWED });
        let ctx = make_ctx(&tool, &profile, &args, &store);
        let result = criterion.evaluate(&ctx).unwrap();
        assert!(
            matches!(result, Some(DenyReason::CounterpartyKindUnsupported { kind }) if kind == "SEP10_IDENTITY"),
            "SEP10_IDENTITY should return CounterpartyKindUnsupported"
        );
    }

    #[test]
    fn invalid_g_strkey_in_args_returns_evaluation_failed() {
        let tool = make_tool("stellar_pay");
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let criterion = CounterpartyAllowlistCriterion::new(
            vec![CounterpartyKind::GAccount],
            vec![G_ALLOWED.to_owned()],
        );
        let args = json!({ "destination": "not-a-strkey" });
        let ctx = make_ctx(&tool, &profile, &args, &store);
        let result = criterion.evaluate(&ctx);
        assert!(
            matches!(result, Err(PolicyError::CriterionEvaluationFailed { .. })),
            "invalid G-strkey should return CriterionEvaluationFailed"
        );
    }

    #[test]
    fn native_asset_skips_known_issuer_check() {
        let tool = make_tool("stellar_pay");
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let criterion = CounterpartyAllowlistCriterion::new(
            vec![CounterpartyKind::KnownIssuer],
            vec![], // empty allowlist
        );
        let args = json!({ "asset": "native", "destination": G_ALLOWED });
        let ctx = make_ctx(&tool, &profile, &args, &store);
        let result = criterion.evaluate(&ctx).unwrap();
        assert!(
            result.is_none(),
            "native asset has no issuer to check; should pass"
        );
    }

    // ── HOME_DOMAIN tests ─────────────────────────────────────────────────────

    /// A minimal [`crate::policy::v1::AccountIdentityView`] implementation for
    /// HOME_DOMAIN unit tests.  Private to the test module; not part of the
    /// public API.
    struct MockIdentityView {
        /// The value returned by `home_domain()`.  `None` simulates an account
        /// whose `AccountEntry.home_domain` field is empty.
        home_domain: Option<&'static str>,
    }

    impl crate::policy::v1::AccountIdentityView for MockIdentityView {
        fn home_domain(&self) -> Option<String> {
            self.home_domain.map(str::to_owned)
        }

        fn account_id(&self) -> &str {
            "GABC123456789012345678901234567890123456789012345678901234"
        }
    }

    /// Constructs an [`EvalContext`] with a `MockIdentityView` set on
    /// `identity_view`.
    fn make_ctx_with_identity<'a>(
        tool: &'a ToolDescriptor,
        profile: &'a Profile,
        args: &'a serde_json::Value,
        store: &'a PolicyStateStore,
        view: &'a dyn crate::policy::v1::AccountIdentityView,
    ) -> EvalContext<'a> {
        EvalContext {
            tool,
            args,
            profile_name: "alice",
            profile,
            value: crate::policy::v1::value::derive_value_class(tool.name.as_str(), args),
            account_view: None,
            identity_view: Some(view),
            quorum: None,
            counterparty_cache: None,
            sep10_sessions: None,
            sep45_sessions: None,
            state_store: store,
            bundle: None,
        }
    }

    #[test]
    fn home_domain_in_allowlist_passes() {
        let tool = make_tool("stellar_pay");
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let view = MockIdentityView {
            home_domain: Some("circle.com"),
        };
        let criterion = CounterpartyAllowlistCriterion::new(
            vec![CounterpartyKind::HomeDomain],
            vec!["circle.com".to_owned()],
        );
        let args = json!({ "destination": G_ALLOWED });
        let ctx = make_ctx_with_identity(&tool, &profile, &args, &store, &view);
        let result = criterion.evaluate(&ctx).unwrap();
        assert!(
            result.is_none(),
            "home_domain on allowlist should pass; got {result:?}"
        );
    }

    #[test]
    fn home_domain_not_in_allowlist_denies() {
        let tool = make_tool("stellar_pay");
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let view = MockIdentityView {
            home_domain: Some("evil.com"),
        };
        let criterion = CounterpartyAllowlistCriterion::new(
            vec![CounterpartyKind::HomeDomain],
            vec!["circle.com".to_owned()],
        );
        let args = json!({ "destination": G_ALLOWED });
        let ctx = make_ctx_with_identity(&tool, &profile, &args, &store, &view);
        let result = criterion.evaluate(&ctx).unwrap();
        assert!(
            matches!(
                result,
                Some(DenyReason::CounterpartyDenied { ref kind, .. }) if kind == "HOME_DOMAIN"
            ),
            "home_domain not on allowlist should be denied; got {result:?}"
        );
    }

    /// Digit-1 substitution homoglyph: `circ1e.com` (ASCII, digit '1' in place
    /// of lowercase 'l').  This is a valid-ASCII string but it must NOT match
    /// the allowlist entry `"circle.com"` because byte-equality comparison
    /// distinguishes `'1'` (0x31) from `'l'` (0x6C).
    #[test]
    fn home_domain_digit_one_homoglyph_denies() {
        let tool = make_tool("stellar_pay");
        let profile = make_profile();
        let store = PolicyStateStore::new();
        // Digit '1' in position 4: "circ1e.com" vs allowlist "circle.com".
        let view = MockIdentityView {
            home_domain: Some("circ1e.com"),
        };
        let criterion = CounterpartyAllowlistCriterion::new(
            vec![CounterpartyKind::HomeDomain],
            vec!["circle.com".to_owned()],
        );
        let args = json!({ "destination": G_ALLOWED });
        let ctx = make_ctx_with_identity(&tool, &profile, &args, &store, &view);
        let result = criterion.evaluate(&ctx).unwrap();
        assert!(
            matches!(
                result,
                Some(DenyReason::CounterpartyDenied { ref kind, .. }) if kind == "HOME_DOMAIN"
            ),
            "digit-1 homoglyph 'circ1e.com' must be denied; got {result:?}"
        );
    }

    /// Cyrillic homoglyph: the resolved `home_domain` contains non-ASCII bytes
    /// (Cyrillic 'с' U+0441, encoded as 0xD1 0x81 in UTF-8).  Strict-ASCII
    /// enforcement converts this to a `CounterpartyDenied` outcome with a
    /// REDACTED value.
    #[test]
    fn home_domain_cyrillic_non_ascii_denies_with_redacted_value() {
        let tool = make_tool("stellar_pay");
        let profile = make_profile();
        let store = PolicyStateStore::new();
        // Cyrillic 'с' (U+0441) at the start: "сircle.com" — visually similar
        // to "circle.com" but encoded as two non-ASCII UTF-8 bytes.
        let view = MockIdentityView {
            home_domain: Some("\u{0441}ircle.com"),
        };
        let criterion = CounterpartyAllowlistCriterion::new(
            vec![CounterpartyKind::HomeDomain],
            vec!["circle.com".to_owned()],
        );
        let args = json!({ "destination": G_ALLOWED });
        let ctx = make_ctx_with_identity(&tool, &profile, &args, &store, &view);
        let result = criterion.evaluate(&ctx).unwrap();
        // Non-ASCII bytes → CounterpartyDenied with value redacted.
        match result {
            Some(DenyReason::CounterpartyDenied {
                ref kind,
                ref value,
            }) => {
                assert_eq!(kind, "HOME_DOMAIN");
                assert_eq!(
                    value, "<non-ascii-redacted>",
                    "Cyrillic home_domain must produce redacted value, not the raw bytes"
                );
            }
            other => panic!("expected CounterpartyDenied, got {other:?}"),
        }
    }

    /// On-chain home_domain with mixed case must match a lowercase-normalised
    /// allowlist entry (RFC 4343 DNS case-insensitivity).
    #[test]
    fn home_domain_mixed_case_matches_lowercase_allowlist_entry() {
        let tool = make_tool("stellar_pay");
        let profile = make_profile();
        let store = PolicyStateStore::new();
        // On-chain AccountEntry.home_domain = "Circle.com" (mixed case).
        // Allowlist entry = "circle.com" (lowercase, as required by loader).
        let view = MockIdentityView {
            home_domain: Some("Circle.com"),
        };
        let criterion = CounterpartyAllowlistCriterion::new(
            vec![CounterpartyKind::HomeDomain],
            vec!["circle.com".to_owned()],
        );
        let args = json!({ "destination": G_ALLOWED });
        let ctx = make_ctx_with_identity(&tool, &profile, &args, &store, &view);
        let result = criterion.evaluate(&ctx).unwrap();
        assert!(
            result.is_none(),
            "mixed-case on-chain home_domain should match lowercase allowlist entry; got {result:?}"
        );
    }

    /// When the destination account has no published `home_domain` (the
    /// `AccountEntry.home_domain` field is empty), the criterion must deny.
    /// An account with no home domain cannot be matched against an allowlist of
    /// trusted operators.
    #[test]
    fn home_domain_none_denies() {
        let tool = make_tool("stellar_pay");
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let view = MockIdentityView { home_domain: None };
        let criterion = CounterpartyAllowlistCriterion::new(
            vec![CounterpartyKind::HomeDomain],
            vec!["circle.com".to_owned()],
        );
        let args = json!({ "destination": G_ALLOWED });
        let ctx = make_ctx_with_identity(&tool, &profile, &args, &store, &view);
        let result = criterion.evaluate(&ctx).unwrap();
        assert!(
            matches!(
                result,
                Some(DenyReason::CounterpartyDenied { ref kind, .. }) if kind == "HOME_DOMAIN"
            ),
            "None home_domain must be denied; got {result:?}"
        );
    }

    /// When `identity_view` is `None` (no view plumbed by the dispatch layer),
    /// the HOME_DOMAIN criterion must deny, because the domain cannot be
    /// resolved.  `account_view` alone is not sufficient to unlock HOME_DOMAIN
    /// matching; `identity_view` must be set.
    #[test]
    fn home_domain_no_identity_view_denies() {
        let tool = make_tool("stellar_pay");
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let criterion = CounterpartyAllowlistCriterion::new(
            vec![CounterpartyKind::HomeDomain],
            vec!["circle.com".to_owned()],
        );
        let args = json!({ "destination": G_ALLOWED });
        // No identity_view — use the plain make_ctx helper which sets it to None.
        let ctx = make_ctx(&tool, &profile, &args, &store);
        let result = criterion.evaluate(&ctx).unwrap();
        assert!(
            matches!(
                result,
                Some(DenyReason::CounterpartyDenied { ref kind, .. }) if kind == "HOME_DOMAIN"
            ),
            "missing identity_view must produce CounterpartyDenied; got {result:?}"
        );
    }

    /// Mixed-kinds criterion: both `G_ACCOUNT` and `HOME_DOMAIN` are enabled.
    /// Verifies that both checks fire in order and that the first denial wins.
    #[test]
    fn mixed_kinds_g_account_and_home_domain_both_checked() {
        let tool = make_tool("stellar_pay");
        let profile = make_profile();
        let store = PolicyStateStore::new();

        // G_ACCOUNT matches but HOME_DOMAIN does not.
        let view = MockIdentityView {
            home_domain: Some("evil.com"),
        };
        let criterion = CounterpartyAllowlistCriterion::new(
            vec![CounterpartyKind::GAccount, CounterpartyKind::HomeDomain],
            vec![G_ALLOWED.to_owned(), "circle.com".to_owned()],
        );
        let args = json!({ "destination": G_ALLOWED });
        let ctx = make_ctx_with_identity(&tool, &profile, &args, &store, &view);
        let result = criterion.evaluate(&ctx).unwrap();
        // G_ACCOUNT passes (G_ALLOWED is on the allowlist), then HOME_DOMAIN
        // fires and denies because "evil.com" is not "circle.com".
        assert!(
            matches!(
                result,
                Some(DenyReason::CounterpartyDenied { ref kind, .. }) if kind == "HOME_DOMAIN"
            ),
            "HOME_DOMAIN check must fire and deny when G_ACCOUNT passes; got {result:?}"
        );
    }

    /// Mixed-kinds: G_ACCOUNT denies first — HOME_DOMAIN check is never reached.
    #[test]
    fn mixed_kinds_g_account_denies_before_home_domain() {
        let tool = make_tool("stellar_pay");
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let view = MockIdentityView {
            home_domain: Some("circle.com"),
        };
        let criterion = CounterpartyAllowlistCriterion::new(
            vec![CounterpartyKind::GAccount, CounterpartyKind::HomeDomain],
            vec![G_ALLOWED.to_owned(), "circle.com".to_owned()],
        );
        // G_DENIED is NOT on the allowlist.
        let args = json!({ "destination": G_DENIED });
        let ctx = make_ctx_with_identity(&tool, &profile, &args, &store, &view);
        let result = criterion.evaluate(&ctx).unwrap();
        // G_ACCOUNT fires first and denies.
        assert!(
            matches!(
                result,
                Some(DenyReason::CounterpartyDenied { ref kind, .. }) if kind == "G_ACCOUNT"
            ),
            "G_ACCOUNT denial must short-circuit before HOME_DOMAIN; got {result:?}"
        );
    }
}
