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
//! # HOME_DOMAIN logic — trust model
//!
//! `home_domain` on `AccountEntry` is a **self-asserted** field: any account
//! can set it to an allowlisted string via `SetOptions` at zero cost. Matching
//! the self-assertion alone (the behavior for the other kinds) lets an attacker-controlled
//! account impersonate an allowlisted operator simply by copying that
//! operator's `home_domain` string onto its own `AccountEntry` — the homoglyph
//! defence below bounds which BYTES the string may contain, not whether the
//! assertion is true.
//!
//! `HOME_DOMAIN` therefore requires a **verified, bidirectional** binding
//! before the allowlist is even consulted:
//!
//! 1. The destination account's on-chain `home_domain` resolves via
//!    [`crate::policy::v1::AccountIdentityView::home_domain`] (self-asserted;
//!    the same shape as every other kind's deny).
//! 2. Strict-ASCII homoglyph defence on the resolved value (unchanged).
//! 3. **Domain verification**: [`EvalContext::counterparty_cache`] must be
//!    populated AND report the domain as resolved
//!    ([`crate::policy::v1::CounterpartyCacheView::has_resolved`]) — proof the
//!    wallet operator has independently fetched a real `stellar.toml` at that
//!    domain (via `stellar-agent counterparty warm-up` or
//!    `stellar-agent counterparty refresh <domain>`), not merely that the
//!    on-chain field contains a plausible-looking string.
//! 4. **Account-listing verification**: the resolved domain's cached
//!    `stellar.toml` `ACCOUNTS` list must name THIS account
//!    ([`crate::policy::v1::CounterpartyCacheView::is_account_listed`]) — the
//!    bidirectional half of the proof.  Without it, step 3 alone would still
//!    let any account that copies an ALREADY-cached, legitimate operator's
//!    `home_domain` string pass, since `has_resolved` is keyed by domain only.
//! 5. Only once steps 3–4 both pass does the resolved domain get checked
//!    against the operator's `allowlist` — a verified-but-non-allowlisted
//!    domain still denies, distinctly from an unverified one (see the `value`
//!    field on each deny below).
//!
//! # Breaking change (behavior tightening)
//!
//! Existing `HOME_DOMAIN` rules now require `EvalContext::counterparty_cache`
//! to carry a resolved entry that lists the counterparty account — operators
//! MUST populate the cache (`stellar-agent counterparty warm-up` scans the
//! configured `allowlist` entries out of the policy file and refreshes each;
//! `stellar-agent counterparty refresh <domain>` refreshes one domain) before
//! any `HOME_DOMAIN` rule can pass. A rule that previously passed on a
//! self-asserted match alone will now deny until the operator populates the
//! cache. This does NOT affect `G_ACCOUNT` / `C_ACCOUNT` / `KNOWN_ISSUER`.
//!
//! # Deny detail
//!
//! All `HOME_DOMAIN` denials use [`DenyReason::CounterpartyDenied`] with
//! `kind = "HOME_DOMAIN"`; the `value` field text distinguishes the failure
//! mode for operator triage: no on-chain domain, non-ASCII homoglyph, cache
//! not populated, domain not resolved in the cache, account not listed by the
//! domain's `stellar.toml`, or (only once verified) not on the allowlist.

use stellar_strkey::{Contract, ed25519::PublicKey};

use crate::policy::v1::EvalContext;
use crate::policy::v1::criteria::Criterion;
use crate::policy::v1::value::{ValueEffects, ValueGate, classify_value};
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
    /// `HOME_DOMAIN` is evaluated against the account's on-chain home domain via
    /// the identity view. Returns
    /// `Ok(Some(DenyReason::CounterpartyKindUnsupported))` when an unsupported
    /// kind (`SEP10_IDENTITY`, `ONE_TIME_ADDRESS`) is listed.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::CriterionEvaluationFailed`] when the destination
    /// field is missing or is not a valid strkey.
    fn evaluate(&self, ctx: &EvalContext<'_>) -> Result<Option<DenyReason>, PolicyError> {
        // The shared fail-closed gate: an opaque-sign call under a matched
        // rule (without `allow_opaque_signing`) or a forgotten `MovesValue`
        // population denies here. `NotApplicable` (a genuinely read-only call,
        // or a tool the descriptor derivation has not classified) falls
        // through to the legacy per-kind path below, unchanged.
        match classify_value(ctx) {
            ValueGate::Deny(reason) => return Ok(Some(reason)),
            ValueGate::Effects(effects) => {
                for kind in &self.kinds {
                    if let Some(deny) = self.evaluate_kind_over_effects(kind, ctx, effects)? {
                        return Ok(Some(deny));
                    }
                }
                return Ok(None);
            }
            ValueGate::NotApplicable => {}
        }

        for kind in &self.kinds {
            if let Some(deny) = self.evaluate_kind(kind, ctx)? {
                return Ok(Some(deny));
            }
        }
        Ok(None)
    }
}

impl CounterpartyAllowlistCriterion {
    /// Legacy per-kind dispatch reading raw `ctx.args` — reached only when
    /// [`classify_value`] resolves `NotApplicable` for the current call (a
    /// genuinely read-only tool, or one the descriptor derivation has not yet
    /// classified).
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

    /// Descriptor-driven per-kind dispatch over the resolved value legs.
    ///
    /// `HOME_DOMAIN` stays on `identity_view` (leg-independent — the
    /// destination account's home domain, not any per-leg field), unchanged
    /// from the raw-args path.
    fn evaluate_kind_over_effects(
        &self,
        kind: &CounterpartyKind,
        ctx: &EvalContext<'_>,
        effects: &ValueEffects,
    ) -> Result<Option<DenyReason>, PolicyError> {
        match kind {
            CounterpartyKind::GAccount => self.check_g_account_legs(ctx, effects),
            CounterpartyKind::CAccount => self.check_c_account_legs(ctx, effects),
            CounterpartyKind::KnownIssuer => self.check_known_issuer_legs(ctx, effects),
            CounterpartyKind::HomeDomain => self.check_home_domain(ctx),
            unsupported => Ok(Some(DenyReason::CounterpartyKindUnsupported {
                kind: unsupported.tag().to_owned(),
            })),
        }
    }

    /// Checks each debit leg's `destination` as a G-strkey against the
    /// allowlist.
    ///
    /// A debit leg with `destination == None` denies
    /// ([`DenyReason::CounterpartyDenied`]) rather than erroring: a
    /// counterparty-bearing action with no resolvable counterparty cannot
    /// satisfy an allowlist. A single-leg pay/create call sees exactly the
    /// same check as the raw-args path, since its sole leg carries the same
    /// `args["destination"]` string the gate derived.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::CriterionEvaluationFailed`] when a present
    /// destination is not a well-formed G-strkey.
    fn check_g_account_legs(
        &self,
        ctx: &EvalContext<'_>,
        effects: &ValueEffects,
    ) -> Result<Option<DenyReason>, PolicyError> {
        for leg in effects.legs() {
            if !leg.kind.carries_debit() {
                continue;
            }
            let Some(destination) = leg.destination.as_deref() else {
                return Ok(Some(DenyReason::CounterpartyDenied {
                    kind: "G_ACCOUNT".to_owned(),
                    value: String::new(),
                }));
            };

            PublicKey::from_string(destination).map_err(|e| {
                PolicyError::CriterionEvaluationFailed {
                    detail: format!(
                        "counterparty_allowlist: invalid G-strkey in a debit leg's \
                         destination for tool '{}': {e}",
                        ctx.tool.name
                    ),
                }
            })?;

            if !self.allowlist.iter().any(|a| a == destination) {
                return Ok(Some(DenyReason::CounterpartyDenied {
                    kind: "G_ACCOUNT".to_owned(),
                    value: destination.to_owned(),
                }));
            }
        }
        Ok(None)
    }

    /// Checks each debit leg's `destination` as a C-strkey against the
    /// allowlist. See [`Self::check_g_account_legs`] for the `None`-is-deny
    /// posture.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::CriterionEvaluationFailed`] when a present
    /// destination is not a well-formed C-strkey.
    fn check_c_account_legs(
        &self,
        ctx: &EvalContext<'_>,
        effects: &ValueEffects,
    ) -> Result<Option<DenyReason>, PolicyError> {
        for leg in effects.legs() {
            if !leg.kind.carries_debit() {
                continue;
            }
            let Some(destination) = leg.destination.as_deref() else {
                return Ok(Some(DenyReason::CounterpartyDenied {
                    kind: "C_ACCOUNT".to_owned(),
                    value: String::new(),
                }));
            };

            Contract::from_string(destination).map_err(|e| {
                PolicyError::CriterionEvaluationFailed {
                    detail: format!(
                        "counterparty_allowlist: invalid C-strkey in a debit leg's \
                         destination for tool '{}': {e}",
                        ctx.tool.name
                    ),
                }
            })?;

            if !self.allowlist.iter().any(|a| a == destination) {
                return Ok(Some(DenyReason::CounterpartyDenied {
                    kind: "C_ACCOUNT".to_owned(),
                    value: destination.to_owned(),
                }));
            }
        }
        Ok(None)
    }

    /// Checks each debit leg's `asset` issuer against the allowlist.
    ///
    /// A native-asset debit leg has no issuer and is skipped. A debit leg whose
    /// asset is `None` (unresolved) denies fail-closed
    /// ([`DenyReason::CounterpartyDenied`], `kind = "KNOWN_ISSUER"`): the
    /// operator asked to bound issuers and this leg's issuer cannot be
    /// established, so it is never waved through.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::CriterionEvaluationFailed`] when a present
    /// non-native asset is not in `CODE:Gissuer` format, or the issuer is not
    /// a well-formed G-strkey.
    fn check_known_issuer_legs(
        &self,
        ctx: &EvalContext<'_>,
        effects: &ValueEffects,
    ) -> Result<Option<DenyReason>, PolicyError> {
        for leg in effects.legs() {
            if !leg.kind.carries_debit() {
                continue;
            }
            // A debit leg whose asset the dispatch site could not resolve cannot
            // be checked against the issuer allowlist, so it denies fail-closed
            // (design §2.2) — mirroring the None-destination posture in
            // `check_g_account_legs`. A `None` here is never a silent pass.
            let Some(asset_str) = leg.asset.as_deref() else {
                return Ok(Some(DenyReason::CounterpartyDenied {
                    kind: "KNOWN_ISSUER".to_owned(),
                    value: String::new(),
                }));
            };
            if asset_str.eq_ignore_ascii_case("native") || asset_str.eq_ignore_ascii_case("xlm") {
                continue;
            }

            let issuer = parse_asset_issuer(asset_str, ctx)?;

            let on_list = self.allowlist.iter().any(|entry| {
                if let Some(list_issuer) = entry.split_once(':').map(|(_, i)| i) {
                    list_issuer == issuer
                } else {
                    entry == &issuer
                }
            });

            if !on_list {
                return Ok(Some(DenyReason::CounterpartyDenied {
                    kind: "KNOWN_ISSUER".to_owned(),
                    value: issuer,
                }));
            }
        }
        Ok(None)
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

    /// Checks the destination account's `home_domain` against the allowlist,
    /// requiring a VERIFIED (not merely self-asserted) domain-account binding.
    ///
    /// See the module-level `# HOME_DOMAIN logic — trust model` section for
    /// the full 5-step rationale. Reads `home_domain` via
    /// [`crate::policy::v1::AccountIdentityView::home_domain`] (supplied in
    /// [`EvalContext::identity_view`]) and cross-checks it against
    /// [`EvalContext::counterparty_cache`]. Every failure mode returns
    /// [`DenyReason::CounterpartyDenied`] with `kind = "HOME_DOMAIN"`; the
    /// `value` field distinguishes which step failed for operator triage.
    fn check_home_domain(&self, ctx: &EvalContext<'_>) -> Result<Option<DenyReason>, PolicyError> {
        fn deny(value: impl Into<String>) -> Result<Option<DenyReason>, PolicyError> {
            Ok(Some(DenyReason::CounterpartyDenied {
                kind: "HOME_DOMAIN".to_owned(),
                value: value.into(),
            }))
        }

        // Step 1: retrieve the (self-asserted) home_domain from the identity
        // view. AccountIdentityView has no default home_domain()
        // implementation, so forgetting to implement it at the dispatch site
        // is a compile error.
        let Some(identity) = ctx.identity_view else {
            return deny(String::new());
        };
        let Some(resolved) = identity.home_domain() else {
            return deny(String::new());
        };

        // Step 2: strict-ASCII enforcement — the homoglyph defence. If the
        // resolved home_domain contains non-ASCII bytes (e.g. Cyrillic
        // lookalikes, digit substitutions encoded outside the ASCII range),
        // the domain cannot satisfy any allowlist entry and is immediately
        // denied. Non-ASCII bytes are REDACTED from the value to avoid leaking
        // potentially sensitive data in error/audit envelopes.
        if !resolved.bytes().all(|b| b.is_ascii()) {
            return deny("<non-ascii-redacted>");
        }

        // Case-insensitive ASCII comparison per RFC 4343. Lowercase the
        // resolved home_domain so that on-chain entries like "Circle.com"
        // correctly match a "circle.com" allowlist/cache entry. The homoglyph
        // defence is not relaxed: Cyrillic lookalikes were already rejected
        // above; only ASCII-lowercase normalisation is applied here.
        let resolved_lower = resolved.to_ascii_lowercase();

        // Step 3: domain verification. `has_resolved` proves the wallet
        // operator independently fetched a real stellar.toml at this domain —
        // it does NOT (by itself) prove this specific account belongs to it,
        // since the cache is keyed by domain alone.
        let cache = match ctx.counterparty_cache {
            Some(c) => c,
            None => {
                return deny(format!(
                    "{resolved_lower}: not verified (counterparty cache not populated)"
                ));
            }
        };
        if !cache.has_resolved(&resolved_lower) {
            return deny(format!(
                "{resolved_lower}: not verified (domain not resolved in counterparty cache; \
                 run `stellar-agent counterparty refresh {resolved_lower}`)"
            ));
        }

        // Step 4: account-listing verification — the bidirectional half of
        // the proof. Closes the gap step 3 alone would leave open: without
        // this, any account could self-assert an ALREADY-cached, legitimate
        // operator's home_domain and pass, since has_resolved does not
        // distinguish which account a resolved domain belongs to.
        if !cache.is_account_listed(&resolved_lower, identity.account_id()) {
            return deny(format!(
                "{resolved_lower}: not verified (account not listed by domain's stellar.toml)"
            ));
        }

        // Step 5: only a VERIFIED domain is checked against the operator's
        // allowlist. A verified-but-non-allowlisted domain still denies, with
        // a distinct value text from every unverified-domain deny above.
        if !self.allowlist.iter().any(|entry| entry == &resolved_lower) {
            return deny(resolved_lower);
        }

        Ok(None)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Resolves the counterparty destination for the current call from raw
/// `ctx.args`.
///
/// Reached only via [`CounterpartyAllowlistCriterion::evaluate_kind`], which
/// runs when [`classify_value`] resolves `NotApplicable` for the current
/// call — a tool the descriptor derivation has not classified as
/// value-moving. A value-moving tool (including the pay/create family) is
/// always routed through [`CounterpartyAllowlistCriterion::evaluate_kind_over_effects`]
/// instead, which reads the resolved value leg(s) rather than raw args.
///
/// # Errors
///
/// Returns [`PolicyError::CriterionEvaluationFailed`] when the destination is
/// missing or not a string.
fn resolve_destination(ctx: &EvalContext<'_>) -> Result<String, PolicyError> {
    extract_string_field(ctx, "destination")
}

/// Resolves the asset for the KNOWN_ISSUER check from raw `ctx.args`.
///
/// `None` means the criterion does not apply, matching an absent
/// `args["asset"]`. See [`resolve_destination`] for why this path is reached
/// only for tools not classified as value-moving.
fn resolve_asset(ctx: &EvalContext<'_>) -> Option<String> {
    ctx.args
        .get("asset")
        .and_then(|v| v.as_str())
        .map(str::to_owned)
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

    #[test]
    fn known_issuer_debit_leg_with_no_asset_denies() {
        use crate::policy::v1::value::{ActionKind, ValueClass, ValueEffects, ValueLeg};

        let tool = make_tool("stellar_blend_lend");
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let criterion = CounterpartyAllowlistCriterion::new(
            vec![CounterpartyKind::KnownIssuer],
            vec![format!("USDC:{USDC_ISSUER}")],
        );
        // A debit (outflow) leg whose asset the dispatch site could not resolve
        // must deny fail-closed under a KNOWN_ISSUER rule, not silently pass.
        let args = json!({});
        let leg = ValueLeg {
            kind: ActionKind::Lend,
            amount: Some(1),
            asset: None,
            destination: Some("CAAA".to_owned()),
        };
        let ctx = EvalContext::new(&tool, &args, "alice", &profile, &store)
            .with_value(ValueClass::Value(ValueEffects::single(leg)));
        let result = criterion.evaluate(&ctx).unwrap();
        assert!(
            matches!(&result, Some(DenyReason::CounterpartyDenied { kind, .. }) if kind.as_str() == "KNOWN_ISSUER"),
            "a debit leg with no resolvable asset must deny under a KNOWN_ISSUER rule, got {result:?}"
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
    /// `identity_view` and NO `counterparty_cache` (the attacker shape: a
    /// self-asserted `home_domain` with no independent verification).
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

    /// A minimal [`crate::policy::v1::CounterpartyCacheView`] for HOME_DOMAIN
    /// verification tests. `resolved` is `Some((domain, listed_account))` when
    /// exactly one domain is cached as resolved, with exactly one account
    /// listed in that domain's `ACCOUNTS`. `None` simulates a cache with no
    /// bindings at all — distinct from `ctx.counterparty_cache` itself being
    /// `None` (cache not populated vs. cache populated but empty).
    struct MockCacheView {
        resolved: Option<(&'static str, &'static str)>,
    }

    impl crate::policy::v1::CounterpartyCacheView for MockCacheView {
        fn has_resolved(&self, home_domain: &str) -> bool {
            self.resolved.is_some_and(|(d, _)| d == home_domain)
        }

        fn is_account_listed(&self, home_domain: &str, account_id: &str) -> bool {
            self.resolved
                .is_some_and(|(d, a)| d == home_domain && a == account_id)
        }
    }

    /// Constructs an [`EvalContext`] with a `MockIdentityView` on
    /// `identity_view` and a `MockCacheView` on `counterparty_cache`.
    fn make_ctx_with_identity_and_cache<'a>(
        tool: &'a ToolDescriptor,
        profile: &'a Profile,
        args: &'a serde_json::Value,
        store: &'a PolicyStateStore,
        identity: &'a dyn crate::policy::v1::AccountIdentityView,
        cache: &'a dyn crate::policy::v1::CounterpartyCacheView,
    ) -> EvalContext<'a> {
        EvalContext {
            tool,
            args,
            profile_name: "alice",
            profile,
            value: crate::policy::v1::value::derive_value_class(tool.name.as_str(), args),
            account_view: None,
            identity_view: Some(identity),
            quorum: None,
            counterparty_cache: Some(cache),
            sep10_sessions: None,
            sep45_sessions: None,
            state_store: store,
            bundle: None,
        }
    }

    /// The account_id `MockIdentityView::account_id()` returns; shared by
    /// every HOME_DOMAIN verification test so `MockCacheView::resolved`'s
    /// account half lines up with it.
    const IDENTITY_ACCOUNT_ID: &str = "GABC123456789012345678901234567890123456789012345678901234";

    /// Self-asserted `home_domain` with NO counterparty cache at all (the
    /// attacker shape: any account can set `home_domain` via `SetOptions`
    /// with zero independent verification). Must deny even though the
    /// asserted domain is on the operator's allowlist — matching the domain
    /// on-chain proves nothing without cache verification.
    #[test]
    fn home_domain_self_asserted_only_with_no_cache_denies() {
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
        match result {
            Some(DenyReason::CounterpartyDenied {
                ref kind,
                ref value,
            }) => {
                assert_eq!(kind, "HOME_DOMAIN");
                assert!(
                    value.contains("not verified") && value.contains("cache not populated"),
                    "a self-asserted-only domain (no cache) must deny as unverified, \
                     not as merely off-allowlist; got value: {value}"
                );
            }
            other => panic!("self-asserted home_domain with no cache must deny; got {other:?}"),
        }
    }

    /// Cache-verified AND allowlisted domain passes: the domain is resolved
    /// in the counterparty cache, the counterparty account is listed in that
    /// domain's `ACCOUNTS`, and the domain is on the operator's allowlist.
    #[test]
    fn home_domain_cache_verified_and_allowlisted_passes() {
        let tool = make_tool("stellar_pay");
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let identity = MockIdentityView {
            home_domain: Some("circle.com"),
        };
        let cache = MockCacheView {
            resolved: Some(("circle.com", IDENTITY_ACCOUNT_ID)),
        };
        let criterion = CounterpartyAllowlistCriterion::new(
            vec![CounterpartyKind::HomeDomain],
            vec!["circle.com".to_owned()],
        );
        let args = json!({ "destination": G_ALLOWED });
        let ctx =
            make_ctx_with_identity_and_cache(&tool, &profile, &args, &store, &identity, &cache);
        let result = criterion.evaluate(&ctx).unwrap();
        assert!(
            result.is_none(),
            "cache-verified, allowlisted home_domain should pass; got {result:?}"
        );
    }

    /// Cache-verified but NOT allowlisted domain denies, with a deny `value`
    /// distinguishable from an unverified-domain deny (the operator can tell
    /// "verified but not on our allowlist" from "not verified at all").
    #[test]
    fn home_domain_cache_verified_but_not_allowlisted_denies() {
        let tool = make_tool("stellar_pay");
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let identity = MockIdentityView {
            home_domain: Some("legitimate-but-unlisted.example"),
        };
        let cache = MockCacheView {
            resolved: Some(("legitimate-but-unlisted.example", IDENTITY_ACCOUNT_ID)),
        };
        let criterion = CounterpartyAllowlistCriterion::new(
            vec![CounterpartyKind::HomeDomain],
            vec!["circle.com".to_owned()], // does NOT include the resolved domain
        );
        let args = json!({ "destination": G_ALLOWED });
        let ctx =
            make_ctx_with_identity_and_cache(&tool, &profile, &args, &store, &identity, &cache);
        let result = criterion.evaluate(&ctx).unwrap();
        match result {
            Some(DenyReason::CounterpartyDenied {
                ref kind,
                ref value,
            }) => {
                assert_eq!(kind, "HOME_DOMAIN");
                assert!(
                    !value.contains("not verified"),
                    "a fully-verified-but-unlisted domain must NOT be denied as \
                     unverified; got value: {value}"
                );
                assert_eq!(
                    value, "legitimate-but-unlisted.example",
                    "not-allowlisted deny must echo the verified domain, matching the \
                     pre-existing (non-verification) deny shape"
                );
            }
            other => panic!("verified-but-unlisted domain must deny; got {other:?}"),
        }
    }

    /// Cache absent entirely (`ctx.counterparty_cache = None`) denies as
    /// unverified, distinct from a populated-but-empty/miss cache.
    #[test]
    fn home_domain_cache_absent_denies() {
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
        // make_ctx_with_identity sets counterparty_cache = None.
        let ctx = make_ctx_with_identity(&tool, &profile, &args, &store, &view);
        let result = criterion.evaluate(&ctx).unwrap();
        match result {
            Some(DenyReason::CounterpartyDenied {
                ref kind,
                ref value,
            }) => {
                assert_eq!(kind, "HOME_DOMAIN");
                assert!(
                    value.contains("cache not populated"),
                    "absent cache must deny with a cache-not-populated detail; got: {value}"
                );
            }
            other => panic!("absent counterparty_cache must deny; got {other:?}"),
        }
    }

    /// The domain is genuinely resolved in the cache (a REAL, independently
    /// fetched stellar.toml exists at that domain) but the counterparty
    /// account is NOT in that domain's `ACCOUNTS` list. This is the core
    /// anti-spoofing case #49 closes: an attacker account cannot borrow an
    /// already-cached, legitimate operator's `home_domain` string.
    #[test]
    fn home_domain_resolved_but_account_not_listed_denies() {
        let tool = make_tool("stellar_pay");
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let identity = MockIdentityView {
            home_domain: Some("circle.com"),
        };
        let cache = MockCacheView {
            // circle.com IS resolved, but its ACCOUNTS list names a DIFFERENT
            // account than the one this call's identity_view carries.
            resolved: Some((
                "circle.com",
                "GDIFFERENTACCOUNTNOTLISTEDBYTHISDOMAIN1234567890AB",
            )),
        };
        let criterion = CounterpartyAllowlistCriterion::new(
            vec![CounterpartyKind::HomeDomain],
            vec!["circle.com".to_owned()],
        );
        let args = json!({ "destination": G_ALLOWED });
        let ctx =
            make_ctx_with_identity_and_cache(&tool, &profile, &args, &store, &identity, &cache);
        let result = criterion.evaluate(&ctx).unwrap();
        match result {
            Some(DenyReason::CounterpartyDenied {
                ref kind,
                ref value,
            }) => {
                assert_eq!(kind, "HOME_DOMAIN");
                assert!(
                    value.contains("account not listed"),
                    "a resolved domain whose ACCOUNTS list omits this account must deny \
                     as account-not-listed, not silently pass on domain-resolution alone; \
                     got value: {value}"
                );
            }
            other => panic!("resolved domain with unlisted account must deny; got {other:?}"),
        }
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
        // The cache resolves and lists the lookalike domain, so evaluation
        // reaches the allowlist byte-equality comparison itself — the deny
        // must come from byte-inequality, not from an unverified-cache
        // shortcut, or this test would keep passing if the comparison were
        // ever loosened to a fuzzy match.
        let view = MockIdentityView {
            home_domain: Some("circ1e.com"),
        };
        let cache = MockCacheView {
            resolved: Some(("circ1e.com", IDENTITY_ACCOUNT_ID)),
        };
        let criterion = CounterpartyAllowlistCriterion::new(
            vec![CounterpartyKind::HomeDomain],
            vec!["circle.com".to_owned()],
        );
        let args = json!({ "destination": G_ALLOWED });
        let ctx = make_ctx_with_identity_and_cache(&tool, &profile, &args, &store, &view, &cache);
        let result = criterion.evaluate(&ctx).unwrap();
        match result {
            Some(DenyReason::CounterpartyDenied {
                ref kind,
                ref value,
            }) => {
                assert_eq!(kind, "HOME_DOMAIN");
                assert_eq!(
                    value, "circ1e.com",
                    "the deny must come from allowlist byte-inequality (bare \
                     domain value), not a cache-verification shortcut"
                );
            }
            other => panic!("digit-1 homoglyph 'circ1e.com' must be denied; got {other:?}"),
        }
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
        // The cache is keyed by the LOWERCASED form, matching what the
        // criterion queries after ASCII-lowercase normalisation.
        let identity = MockIdentityView {
            home_domain: Some("Circle.com"),
        };
        let cache = MockCacheView {
            resolved: Some(("circle.com", IDENTITY_ACCOUNT_ID)),
        };
        let criterion = CounterpartyAllowlistCriterion::new(
            vec![CounterpartyKind::HomeDomain],
            vec!["circle.com".to_owned()],
        );
        let args = json!({ "destination": G_ALLOWED });
        let ctx =
            make_ctx_with_identity_and_cache(&tool, &profile, &args, &store, &identity, &cache);
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

    // ── Fail-closed value-descriptor matrix ─────────────────────────────────

    /// Constructs a `ToolDescriptor` with an explicit `value_kind` (rather
    /// than the fixed `ReadOnly` of [`make_tool`]).
    fn make_tool_with_kind(
        tool_name: &'static str,
        value_kind: crate::policy::ToolValueKind,
    ) -> ToolDescriptor {
        let reg = McpToolRegistration {
            name: tool_name,
            destructive_hint: true,
            read_only_hint: false,
            chain_id_required: true,
            value_kind,
        };
        ToolDescriptor::from_registration(&reg)
    }

    /// A `MovesValue` tool the descriptor derivation has not classified
    /// (`derive_value_class` falls through to `ReadOnly` for any name outside
    /// its match arms) must deny fail-closed rather than passing silently.
    #[test]
    fn moves_value_tool_with_unpopulated_effects_denies_unsizable() {
        let tool = make_tool_with_kind(
            "stellar_blend_lend",
            crate::policy::ToolValueKind::MovesValue,
        );
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let criterion = CounterpartyAllowlistCriterion::new(
            vec![CounterpartyKind::GAccount],
            vec![G_ALLOWED.to_owned()],
        );
        let args = json!({});
        let ctx = make_ctx(&tool, &profile, &args, &store);
        let result = criterion.evaluate(&ctx);
        assert!(
            matches!(result, Ok(Some(DenyReason::UnsizableValueEffect { .. }))),
            "a MovesValue tool with no resolved effects must deny fail-closed, got {result:?}"
        );
    }

    /// An opaque-signing call on the single-tx path must deny fail-closed.
    #[test]
    fn opaque_sign_call_denies_unsizable_on_single_tx() {
        let tool = make_tool("stellar_sep43_sign_transaction");
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let criterion = CounterpartyAllowlistCriterion::new(
            vec![CounterpartyKind::GAccount],
            vec![G_ALLOWED.to_owned()],
        );
        let args = json!({});
        let ctx = make_ctx(&tool, &profile, &args, &store);
        let result = criterion.evaluate(&ctx);
        assert!(
            matches!(result, Ok(Some(DenyReason::UnsizableValueEffect { .. }))),
            "an opaque-signing call must deny fail-closed on the single-tx path, got {result:?}"
        );
    }

    /// A resolved `Value` effect is checked per-leg: the sole leg of a
    /// single-leg pay/create call is checked identically to the raw-args
    /// path (byte-identical outcome for the existing pay tests above).
    #[test]
    fn g_account_over_effects_single_leg_matches_raw_args_outcome() {
        let tool = make_tool("stellar_pay");
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let criterion = CounterpartyAllowlistCriterion::new(
            vec![CounterpartyKind::GAccount],
            vec![G_ALLOWED.to_owned()],
        );
        let args =
            json!({ "destination": G_DENIED, "amount_stroops": "100000000", "asset": "native" });
        let ctx = make_ctx(&tool, &profile, &args, &store);
        let result = criterion.evaluate(&ctx).unwrap();
        assert!(
            matches!(result, Some(DenyReason::CounterpartyDenied { ref kind, .. }) if kind == "G_ACCOUNT"),
            "a pay call's sole leg must be checked identically to the raw-args path, \
             got {result:?}"
        );
    }

    /// A debit leg with no resolvable destination denies
    /// (`CounterpartyDenied`) rather than erroring: a counterparty-bearing
    /// action with no resolvable counterparty cannot satisfy an allowlist.
    #[test]
    fn g_account_over_effects_missing_destination_denies() {
        use crate::policy::v1::value::{ActionKind, ValueClass, ValueEffects, ValueLeg};

        let tool = make_tool("stellar_multicall");
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let criterion = CounterpartyAllowlistCriterion::new(
            vec![CounterpartyKind::GAccount],
            vec![G_ALLOWED.to_owned()],
        );
        let leg = ValueLeg {
            kind: ActionKind::Payment,
            amount: Some(100),
            asset: Some("native".to_owned()),
            destination: None,
        };
        let args = json!({});
        let ctx = EvalContext::new(&tool, &args, "alice", &profile, &store)
            .with_value(ValueClass::Value(ValueEffects::single(leg)));
        let result = criterion.evaluate(&ctx).unwrap();
        assert!(
            matches!(result, Some(DenyReason::CounterpartyDenied { ref kind, .. }) if kind == "G_ACCOUNT"),
            "a debit leg with no destination must deny, not error: {result:?}"
        );
    }
}
