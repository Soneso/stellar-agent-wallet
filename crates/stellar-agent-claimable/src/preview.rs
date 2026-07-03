//! Typed, XDR-free claim preview and pure guard functions.
//!
//! [`ClaimPreview::build`] projects a fetched `ClaimableBalanceEntry` plus
//! the claiming account's identity and the current time into a
//! JSON-serialisable preview. Building the preview does not itself submit
//! anything on-chain; it also does not refuse on "not a claimant" or
//! "predicate not satisfied" — those are informational fields on the
//! preview. [`require_claimant`], [`require_predicate_satisfied`], and
//! [`check_trustline`] are the pure guard functions a driver (CLI/MCP verb)
//! calls to turn that informational state into the fail-closed
//! `claim.not_claimant` / `claim.predicate_not_satisfied` /
//! `claim.trustline_*` refusals documented in the crate's guard surface.
//!
//! `ClaimPreview::build` DOES fail closed on
//! [`crate::error::ClaimError::PredicateUnsupported`]: a claimant predicate
//! the evaluator refuses to interpret (see [`crate::predicate`]) is a
//! malformed-input condition, not an informational state to display.

use serde::{Deserialize, Serialize};
use stellar_xdr::{Asset, ClaimableBalanceEntry, ClaimableBalanceEntryExt, Claimant};

use crate::entry::TrustlineState;
use crate::error::ClaimError;
use crate::id::BalanceId;
use crate::predicate::{self, ClaimabilityWindow};

/// The `CLAIMABLE_BALANCE_CLAWBACK_ENABLED_FLAG` bit (`0x1`) of
/// `ClaimableBalanceEntryExtensionV1.flags`, per CAP-35 ("Asset Clawback").
/// `stellar-xdr` does not generate a named enum for this flag — the field is
/// a raw `u32` — so the bit value is asserted here directly.
const CLAWBACK_ENABLED_FLAG: u32 = 1;

/// A single claimant entry, as shown to the operator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimantView {
    /// The claimant's G-strkey.
    pub destination: String,
    /// The top-level discriminant name of the claimant's predicate (e.g.
    /// `"Unconditional"`, `"And"`, `"BeforeAbsoluteTime"`) — a display hint,
    /// not a full predicate rendering.
    pub predicate_kind: String,
}

/// A typed, JSON-serialisable, XDR-free preview of a proposed
/// `ClaimClaimableBalance` operation.
///
/// # No `sponsor` field
///
/// `getLedgerEntries` (this crate's only RPC read path — see
/// [`crate::entry`]) returns `LedgerEntryData`, which does not carry the
/// sponsorship information stored on the enclosing `LedgerEntry.ext`. This
/// preview therefore cannot report who (if anyone) sponsors the balance's
/// base reserve. This is not a gap in the claim guard surface: the claiming
/// account itself never pays or reclaims a reserve for a claimable balance
/// it claims; the crate root docs carry the "no claimant reserve check"
/// rationale.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimPreview {
    /// The canonical 72-hex-character balance id.
    pub balance_id_hex72: String,
    /// The `B...` strkey rendering of the balance id.
    pub balance_id_strkey: String,
    /// The asset code, or `None` for the native XLM asset.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asset_code: Option<String>,
    /// The asset issuer G-strkey, or `None` for the native XLM asset.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asset_issuer: Option<String>,
    /// The balance amount, in stroops.
    pub amount_stroops: i64,
    /// The balance amount, formatted as a fixed-point decimal string at the
    /// Stellar protocol's 7-decimal-place unit (e.g. `"12.5000000"`).
    pub amount_display: String,
    /// All claimants on the entry, in on-ledger order (the order that
    /// determines first-match precedence).
    pub claimants: Vec<ClaimantView>,
    /// Whether `claimant_account` (the account passed to
    /// [`ClaimPreview::build`]) is a claimant on this entry.
    ///
    /// Determined by **first-matching-claimant order**: the first claimant
    /// entry whose destination equals `claimant_account`, matching
    /// stellar-core's own claim-authorization semantics (not "any claimant
    /// entry with that destination is satisfied").
    pub is_claimant: bool,
    /// The matched claimant's predicate verdict at `now`, when
    /// `is_claimant` is `true`. `None` when `is_claimant` is `false`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub predicate_satisfied: Option<bool>,
    /// The claimability window derivable from the matched claimant's
    /// predicate structure, when `is_claimant` is `true`. Both bounds are
    /// `None` when not exactly derivable (see [`crate::predicate::derive_window`]);
    /// defaulted when `is_claimant` is `false`.
    pub window: ClaimabilityWindow,
    /// Whether the balance's `ClaimableBalanceEntryExtensionV1` clawback
    /// flag is set.
    ///
    /// Informational only — not a guard. For a non-native asset the
    /// clawback posture was already disclosed and accepted when the
    /// trustline was created (see the `trustline` verb's clawback gate);
    /// the native asset can never carry clawback.
    pub clawback_enabled: bool,
}

impl ClaimPreview {
    /// Builds a [`ClaimPreview`] from a fetched entry.
    ///
    /// `claimant_account` is the wallet's own G-strkey; `now` is a Unix
    /// timestamp (wall-clock time at preview build — see the crate-level
    /// documentation for why on-chain evaluation at apply-ledger close time
    /// can still diverge from this preview near a predicate boundary).
    ///
    /// # Errors
    ///
    /// Returns [`ClaimError::PredicateUnsupported`] when `claimant_account`
    /// is a claimant (first match) and that claimant's predicate is one of
    /// the fail-closed forms documented in [`crate::predicate`]. An
    /// unsupported predicate on a claimant OTHER than `claimant_account` does
    /// not affect this call — only the first-matching claimant's predicate
    /// is evaluated.
    pub fn build(
        entry: &ClaimableBalanceEntry,
        claimant_account: &str,
        now: u64,
    ) -> Result<Self, ClaimError> {
        let id = BalanceId::from_hash({
            let stellar_xdr::ClaimableBalanceId::ClaimableBalanceIdTypeV0(h) = &entry.balance_id;
            h.0
        });

        let (asset_code, asset_issuer) = asset_code_issuer(&entry.asset);
        let amount_display = format_stroops(entry.amount);

        let mut claimants = Vec::with_capacity(entry.claimants.len());
        let mut matched_predicate: Option<&stellar_xdr::ClaimPredicate> = None;

        for c in entry.claimants.iter() {
            let Claimant::ClaimantTypeV0(v0) = c;
            let destination = account_id_to_strkey(&v0.destination);
            let is_match = matched_predicate.is_none() && destination == claimant_account;
            if is_match {
                matched_predicate = Some(&v0.predicate);
            }
            claimants.push(ClaimantView {
                destination,
                predicate_kind: v0.predicate.name().to_owned(),
            });
        }

        let is_claimant = matched_predicate.is_some();
        let (predicate_satisfied, window) = match matched_predicate {
            Some(pred) => {
                let verdict = predicate::evaluate(pred, now)?;
                (Some(verdict.is_satisfied()), predicate::derive_window(pred))
            }
            None => (None, ClaimabilityWindow::default()),
        };

        let clawback_enabled = matches!(
            &entry.ext,
            ClaimableBalanceEntryExt::V1(v1) if v1.flags & CLAWBACK_ENABLED_FLAG != 0
        );

        Ok(Self {
            balance_id_hex72: id.to_hex72(),
            balance_id_strkey: id.to_strkey(),
            asset_code,
            asset_issuer,
            amount_stroops: entry.amount,
            amount_display,
            claimants,
            is_claimant,
            predicate_satisfied,
            window,
            clawback_enabled,
        })
    }
}

/// Refuses unless `preview.is_claimant` is `true`.
///
/// # Errors
///
/// Returns [`ClaimError::NotClaimant`] when the account is not a claimant on
/// the entry.
pub fn require_claimant(preview: &ClaimPreview, account: &str) -> Result<(), ClaimError> {
    if preview.is_claimant {
        Ok(())
    } else {
        Err(ClaimError::NotClaimant {
            account: account.to_owned(),
        })
    }
}

/// Refuses unless the matched claimant's predicate is currently satisfied.
///
/// # Errors
///
/// Returns [`ClaimError::PredicateNotSatisfied`] when
/// `preview.predicate_satisfied` is `Some(false)` or `None` (the latter
/// meaning the account is not even a claimant — callers should call
/// [`require_claimant`] first for a more specific error in that case).
pub fn require_predicate_satisfied(preview: &ClaimPreview) -> Result<(), ClaimError> {
    match preview.predicate_satisfied {
        Some(true) => Ok(()),
        Some(false) => Err(ClaimError::PredicateNotSatisfied {
            hint: window_hint(&preview.window),
        }),
        None => Err(ClaimError::PredicateNotSatisfied {
            hint: "this account is not a claimant on this balance".to_owned(),
        }),
    }
}

/// Builds a human-readable hint from a claimability window.
fn window_hint(window: &ClaimabilityWindow) -> String {
    match (window.valid_from, window.valid_until) {
        (Some(from), Some(until)) => {
            format!("claimable between unix time {from} and {until}")
        }
        (Some(from), None) => format!("claimable once unix time reaches {from}"),
        (None, Some(until)) => format!("claimable only before unix time {until}"),
        (None, None) => "this balance is not currently claimable".to_owned(),
    }
}

/// Guards a non-native claim against the claiming account's trustline state.
///
/// The native asset short-circuits `Ok(())` — a native claim never requires
/// a trustline.
///
/// # Errors
///
/// - [`ClaimError::TrustlineMissing`] when `state.exists` is `false`.
/// - [`ClaimError::TrustlineNotAuthorized`] when the trustline exists but
///   `state.authorized` is `false`.
/// - [`ClaimError::TrustlineLimit`] when `state.limit - state.balance <
///   amount_stroops`.
pub fn check_trustline(
    state: &TrustlineState,
    asset_code: Option<&str>,
    asset_issuer: Option<&str>,
    amount_stroops: i64,
) -> Result<(), ClaimError> {
    let (Some(code), Some(issuer)) = (asset_code, asset_issuer) else {
        // Native asset: no trustline is required.
        return Ok(());
    };

    if !state.exists {
        return Err(ClaimError::TrustlineMissing {
            code: code.to_owned(),
            issuer: issuer.to_owned(),
        });
    }
    if !state.authorized {
        return Err(ClaimError::TrustlineNotAuthorized {
            code: code.to_owned(),
            issuer: issuer.to_owned(),
        });
    }
    let headroom = state.limit.saturating_sub(state.balance);
    if headroom < amount_stroops {
        return Err(ClaimError::TrustlineLimit {
            code: code.to_owned(),
            issuer: issuer.to_owned(),
            amount_stroops,
            headroom_stroops: headroom,
        });
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Small local helpers (XDR → display types)
// ─────────────────────────────────────────────────────────────────────────────

/// Resolves a `stellar_xdr::AccountId` to a G-strkey.
///
/// Infallible for XDR-decoded keys (the only ed25519-keyed `PublicKey`
/// variant the protocol currently defines).
fn account_id_to_strkey(account_id: &stellar_xdr::AccountId) -> String {
    let stellar_xdr::AccountId(ref pk) = *account_id;
    match pk {
        stellar_xdr::PublicKey::PublicKeyTypeEd25519(uint256) => {
            format!("{}", stellar_strkey::ed25519::PublicKey(uint256.0))
        }
    }
}

/// Splits a `stellar_xdr::Asset` into `(code, issuer)`, `(None, None)` for
/// native.
fn asset_code_issuer(asset: &Asset) -> (Option<String>, Option<String>) {
    match asset {
        Asset::Native => (None, None),
        Asset::CreditAlphanum4(a) => (
            Some(trim_asset_code(&a.asset_code.0)),
            Some(account_id_to_strkey(&a.issuer)),
        ),
        Asset::CreditAlphanum12(a) => (
            Some(trim_asset_code(&a.asset_code.0)),
            Some(account_id_to_strkey(&a.issuer)),
        ),
    }
}

/// Trims trailing NUL padding from a fixed-length XDR asset-code byte array.
fn trim_asset_code(bytes: &[u8]) -> String {
    std::str::from_utf8(bytes)
        .unwrap_or_default()
        .trim_end_matches('\0')
        .to_owned()
}

/// Formats `stroops` as a fixed-point decimal string at the Stellar
/// protocol's 7-decimal-place unit (applies uniformly to native and
/// non-native assets — the wire type is the same `i64` unit for both).
fn format_stroops(stroops: i64) -> String {
    let negative = stroops < 0;
    let magnitude = stroops.unsigned_abs();
    let whole = magnitude / 10_000_000;
    let frac = magnitude % 10_000_000;
    format!("{}{whole}.{frac:07}", if negative { "-" } else { "" })
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only"
    )]

    use stellar_xdr::{
        AccountId as XdrAccountId, AlphaNum4, AssetCode4, ClaimPredicate,
        ClaimableBalanceEntryExtensionV1, ClaimableBalanceEntryExtensionV1Ext,
        Claimant as XdrClaimant, ClaimantV0, Hash, PublicKey as XdrPublicKey,
        Uint256 as XdrUint256, VecM,
    };

    use super::*;

    const CLAIMANT_G: &str = "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY";
    const OTHER_G: &str = "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL";
    const ISSUER_G: &str = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";

    fn g_account_id(g: &str) -> XdrAccountId {
        let pk = stellar_strkey::ed25519::PublicKey::from_string(g).unwrap();
        XdrAccountId(XdrPublicKey::PublicKeyTypeEd25519(XdrUint256(pk.0)))
    }

    fn entry_with_claimants(
        asset: Asset,
        amount: i64,
        claimants: Vec<(&str, ClaimPredicate)>,
        ext: ClaimableBalanceEntryExt,
    ) -> ClaimableBalanceEntry {
        let claimant_vec: Vec<XdrClaimant> = claimants
            .into_iter()
            .map(|(g, pred)| {
                XdrClaimant::ClaimantTypeV0(ClaimantV0 {
                    destination: g_account_id(g),
                    predicate: pred,
                })
            })
            .collect();
        ClaimableBalanceEntry {
            balance_id: stellar_xdr::ClaimableBalanceId::ClaimableBalanceIdTypeV0(Hash([7u8; 32])),
            claimants: VecM::try_from(claimant_vec).unwrap(),
            asset,
            amount,
            ext,
        }
    }

    fn usdc_asset() -> Asset {
        let mut code_bytes = [0u8; 4];
        code_bytes[..4].copy_from_slice(b"USDC");
        Asset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4(code_bytes),
            issuer: g_account_id(ISSUER_G),
        })
    }

    // ─── build: native, unconditional, claimant match ─────────────────────

    #[test]
    fn build_native_unconditional_is_claimant() {
        let entry = entry_with_claimants(
            Asset::Native,
            50_000_000,
            vec![(CLAIMANT_G, ClaimPredicate::Unconditional)],
            ClaimableBalanceEntryExt::V0,
        );
        let preview = ClaimPreview::build(&entry, CLAIMANT_G, 1_000).unwrap();

        assert!(preview.is_claimant);
        assert_eq!(preview.predicate_satisfied, Some(true));
        assert_eq!(preview.asset_code, None);
        assert_eq!(preview.asset_issuer, None);
        assert_eq!(preview.amount_stroops, 50_000_000);
        assert_eq!(preview.amount_display, "5.0000000");
        assert!(!preview.clawback_enabled);
        assert_eq!(preview.claimants.len(), 1);
        assert_eq!(preview.claimants[0].destination, CLAIMANT_G);
    }

    // ─── build: not a claimant ──────────────────────────────────────────────

    #[test]
    fn build_not_a_claimant() {
        let entry = entry_with_claimants(
            Asset::Native,
            10_000_000,
            vec![(OTHER_G, ClaimPredicate::Unconditional)],
            ClaimableBalanceEntryExt::V0,
        );
        let preview = ClaimPreview::build(&entry, CLAIMANT_G, 1_000).unwrap();
        assert!(!preview.is_claimant);
        assert_eq!(preview.predicate_satisfied, None);
        assert_eq!(preview.window, ClaimabilityWindow::default());
    }

    // ─── build: first-matching-claimant order ──────────────────────────────

    #[test]
    fn build_uses_first_matching_claimant_not_any_satisfied() {
        // Two claimant entries for the SAME destination: the first has an
        // unsatisfied predicate, the second an unconditional one. Stellar-core
        // semantics use the FIRST match, so the verdict must be "not satisfied"
        // even though a later entry for the same account would be satisfied.
        let entry = entry_with_claimants(
            Asset::Native,
            10_000_000,
            vec![
                (CLAIMANT_G, ClaimPredicate::BeforeAbsoluteTime(500)),
                (CLAIMANT_G, ClaimPredicate::Unconditional),
            ],
            ClaimableBalanceEntryExt::V0,
        );
        let preview = ClaimPreview::build(&entry, CLAIMANT_G, 1_000).unwrap();
        assert!(preview.is_claimant);
        assert_eq!(
            preview.predicate_satisfied,
            Some(false),
            "must use the FIRST matching claimant's predicate, not the second"
        );
    }

    // ─── build: predicate-expired ───────────────────────────────────────────

    #[test]
    fn build_predicate_expired() {
        let entry = entry_with_claimants(
            Asset::Native,
            10_000_000,
            vec![(CLAIMANT_G, ClaimPredicate::BeforeAbsoluteTime(500))],
            ClaimableBalanceEntryExt::V0,
        );
        let preview = ClaimPreview::build(&entry, CLAIMANT_G, 1_000).unwrap();
        assert_eq!(preview.predicate_satisfied, Some(false));
        assert_eq!(preview.window.valid_until, Some(500));
    }

    // ─── build: predicate-unsupported fails closed ─────────────────────────

    #[test]
    fn build_unsupported_predicate_on_matched_claimant_errs() {
        let entry = entry_with_claimants(
            Asset::Native,
            10_000_000,
            vec![(CLAIMANT_G, ClaimPredicate::BeforeRelativeTime(60))],
            ClaimableBalanceEntryExt::V0,
        );
        let err = ClaimPreview::build(&entry, CLAIMANT_G, 1_000)
            .expect_err("BeforeRelativeTime on the matched claimant must fail closed");
        assert_eq!(err.code(), "claim.predicate_unsupported");
    }

    #[test]
    fn build_unsupported_predicate_on_unmatched_claimant_does_not_err() {
        // The malformed predicate belongs to a DIFFERENT account; it must
        // not affect building a preview for CLAIMANT_G.
        let entry = entry_with_claimants(
            Asset::Native,
            10_000_000,
            vec![
                (OTHER_G, ClaimPredicate::BeforeRelativeTime(60)),
                (CLAIMANT_G, ClaimPredicate::Unconditional),
            ],
            ClaimableBalanceEntryExt::V0,
        );
        let preview = ClaimPreview::build(&entry, CLAIMANT_G, 1_000).unwrap();
        assert!(preview.is_claimant);
        assert_eq!(preview.predicate_satisfied, Some(true));
    }

    // ─── build: non-native asset ─────────────────────────────────────────

    #[test]
    fn build_non_native_asset_fields() {
        let entry = entry_with_claimants(
            usdc_asset(),
            1_230_000_000,
            vec![(CLAIMANT_G, ClaimPredicate::Unconditional)],
            ClaimableBalanceEntryExt::V0,
        );
        let preview = ClaimPreview::build(&entry, CLAIMANT_G, 1_000).unwrap();
        assert_eq!(preview.asset_code.as_deref(), Some("USDC"));
        assert_eq!(preview.asset_issuer.as_deref(), Some(ISSUER_G));
        assert_eq!(preview.amount_display, "123.0000000");
    }

    // ─── build: clawback flag surfacing ────────────────────────────────────

    #[test]
    fn build_clawback_flag_set() {
        let entry = entry_with_claimants(
            usdc_asset(),
            10_000_000,
            vec![(CLAIMANT_G, ClaimPredicate::Unconditional)],
            ClaimableBalanceEntryExt::V1(ClaimableBalanceEntryExtensionV1 {
                ext: ClaimableBalanceEntryExtensionV1Ext::V0,
                flags: CLAWBACK_ENABLED_FLAG,
            }),
        );
        let preview = ClaimPreview::build(&entry, CLAIMANT_G, 1_000).unwrap();
        assert!(preview.clawback_enabled);
    }

    #[test]
    fn build_clawback_flag_unset_with_v1_ext() {
        let entry = entry_with_claimants(
            usdc_asset(),
            10_000_000,
            vec![(CLAIMANT_G, ClaimPredicate::Unconditional)],
            ClaimableBalanceEntryExt::V1(ClaimableBalanceEntryExtensionV1 {
                ext: ClaimableBalanceEntryExtensionV1Ext::V0,
                flags: 0,
            }),
        );
        let preview = ClaimPreview::build(&entry, CLAIMANT_G, 1_000).unwrap();
        assert!(!preview.clawback_enabled);
    }

    // ─── require_claimant ───────────────────────────────────────────────────

    #[test]
    fn require_claimant_ok_when_claimant() {
        let entry = entry_with_claimants(
            Asset::Native,
            10_000_000,
            vec![(CLAIMANT_G, ClaimPredicate::Unconditional)],
            ClaimableBalanceEntryExt::V0,
        );
        let preview = ClaimPreview::build(&entry, CLAIMANT_G, 1_000).unwrap();
        assert!(require_claimant(&preview, CLAIMANT_G).is_ok());
    }

    #[test]
    fn require_claimant_errs_when_not_claimant() {
        let entry = entry_with_claimants(
            Asset::Native,
            10_000_000,
            vec![(OTHER_G, ClaimPredicate::Unconditional)],
            ClaimableBalanceEntryExt::V0,
        );
        let preview = ClaimPreview::build(&entry, CLAIMANT_G, 1_000).unwrap();
        let err = require_claimant(&preview, CLAIMANT_G).expect_err("must refuse");
        assert_eq!(err.code(), "claim.not_claimant");
    }

    // ─── require_predicate_satisfied ────────────────────────────────────────

    #[test]
    fn require_predicate_satisfied_ok_when_satisfied() {
        let entry = entry_with_claimants(
            Asset::Native,
            10_000_000,
            vec![(CLAIMANT_G, ClaimPredicate::Unconditional)],
            ClaimableBalanceEntryExt::V0,
        );
        let preview = ClaimPreview::build(&entry, CLAIMANT_G, 1_000).unwrap();
        assert!(require_predicate_satisfied(&preview).is_ok());
    }

    #[test]
    fn require_predicate_satisfied_errs_with_window_hint() {
        let entry = entry_with_claimants(
            Asset::Native,
            10_000_000,
            vec![(CLAIMANT_G, ClaimPredicate::BeforeAbsoluteTime(500))],
            ClaimableBalanceEntryExt::V0,
        );
        let preview = ClaimPreview::build(&entry, CLAIMANT_G, 1_000).unwrap();
        let err = require_predicate_satisfied(&preview).expect_err("must refuse");
        assert_eq!(err.code(), "claim.predicate_not_satisfied");
        assert!(format!("{err}").contains("500"));
    }

    #[test]
    fn require_predicate_satisfied_errs_when_not_claimant() {
        let entry = entry_with_claimants(
            Asset::Native,
            10_000_000,
            vec![(OTHER_G, ClaimPredicate::Unconditional)],
            ClaimableBalanceEntryExt::V0,
        );
        let preview = ClaimPreview::build(&entry, CLAIMANT_G, 1_000).unwrap();
        let err = require_predicate_satisfied(&preview).expect_err("must refuse");
        assert_eq!(err.code(), "claim.predicate_not_satisfied");
    }

    // ─── check_trustline ─────────────────────────────────────────────────

    #[test]
    fn check_trustline_native_short_circuits_ok() {
        let state = TrustlineState {
            exists: false,
            authorized: false,
            limit: 0,
            balance: 0,
        };
        assert!(check_trustline(&state, None, None, 100).is_ok());
    }

    #[test]
    fn check_trustline_missing_errs() {
        let state = TrustlineState {
            exists: false,
            authorized: false,
            limit: 0,
            balance: 0,
        };
        let err = check_trustline(&state, Some("USDC"), Some(ISSUER_G), 100)
            .expect_err("missing trustline must be refused");
        assert_eq!(err.code(), "claim.trustline_missing");
    }

    #[test]
    fn check_trustline_not_authorized_errs() {
        let state = TrustlineState {
            exists: true,
            authorized: false,
            limit: 1_000,
            balance: 0,
        };
        let err = check_trustline(&state, Some("USDC"), Some(ISSUER_G), 100)
            .expect_err("unauthorized trustline must be refused");
        assert_eq!(err.code(), "claim.trustline_not_authorized");
    }

    #[test]
    fn check_trustline_limit_exceeded_errs() {
        let state = TrustlineState {
            exists: true,
            authorized: true,
            limit: 1_000,
            balance: 950,
        };
        // headroom = 50, amount = 100 -> exceeds.
        let err = check_trustline(&state, Some("USDC"), Some(ISSUER_G), 100)
            .expect_err("amount exceeding headroom must be refused");
        assert_eq!(err.code(), "claim.trustline_limit");
    }

    #[test]
    fn check_trustline_within_headroom_ok() {
        let state = TrustlineState {
            exists: true,
            authorized: true,
            limit: 1_000,
            balance: 800,
        };
        // headroom = 200, amount = 100 -> within.
        assert!(check_trustline(&state, Some("USDC"), Some(ISSUER_G), 100).is_ok());
    }

    #[test]
    fn check_trustline_exact_headroom_boundary_ok() {
        let state = TrustlineState {
            exists: true,
            authorized: true,
            limit: 1_000,
            balance: 900,
        };
        // headroom = 100, amount = 100 -> exactly fits.
        assert!(check_trustline(&state, Some("USDC"), Some(ISSUER_G), 100).is_ok());
    }

    // ─── format_stroops ──────────────────────────────────────────────────

    #[test]
    fn format_stroops_zero() {
        assert_eq!(format_stroops(0), "0.0000000");
    }

    #[test]
    fn format_stroops_one_unit() {
        assert_eq!(format_stroops(10_000_000), "1.0000000");
    }

    #[test]
    fn format_stroops_fractional() {
        assert_eq!(format_stroops(1_500_000), "0.1500000");
    }
}
