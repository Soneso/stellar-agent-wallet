//! Denomination-explicit resolver for stablecoin asset inputs.
//!
//! `resolve_denomination` is the single entry point for all asset inputs to
//! the `trustline` verb.  Every input path — SEP-41 C-address, explicit
//! `code+issuer`, or bare code — flows through this function before any
//! trustline-building logic runs.
//!
//! # Accepted inputs
//!
//! 1. **SEP-41 C-strkey** (`C...`, 56 chars) — Stellar Asset Contract (SAC)
//!    address.  The resolver currently returns `UnresolvableSacAddress` because
//!    SAC-to-asset resolution requires an on-chain RPC call and is not yet
//!    implemented.  This path is validated structurally so the future wiring
//!    does not regress.
//!
//! 2. **Explicit `code+issuer`** — both code (1–12 alphanumeric) and issuer
//!    (G-strkey) are supplied.  Subject to refusal rules 1–3.
//!
//! 3. **Bare code** — only an asset code (no issuer) is supplied.  Allowed ONLY
//!    when the code resolves through the pin table for the active network.
//!    The pin supplies the issuer; the returned `ResolvedAsset.issuer` is the
//!    pinned canonical issuer.  Otherwise: `UnpinnedBareCode` refusal.
//!
//! # Refusal order (all five paths, strictly in order)
//!
//! 1. Code equals `USDT` (any case) → [`ResolveError::UsdtRefused`] (`USDT-on-Stellar-lookalike-risk`).
//! 2. `(code, issuer)` hits the known-lookalike denylist → [`ResolveError::LookalikeRefused`] (counterparty-lookalike; REFUSE, never warn-and-proceed).
//! 3. Code matches a pinned code but the supplied issuer differs from the pin → [`ResolveError::PinnedCodeIssuerMismatch`] (lookalike-of-pinned-asset).
//! 4. Bare code with no pin row for the active network → [`ResolveError::UnpinnedBareCode`].
//! 5. Explicit non-pinned `code+issuer` (valid G-strkey, valid 1–12 alnum code) → allowed; returns [`ResolvedAsset`].
//!
//! # Bare-code scope
//!
//! The bare-code-via-pin path is trustline-surface-only: the pin supplies the
//! issuer, so the caller need not know it.  Bare codes MUST NOT be adopted in
//! the `pay` verb's asset parser — the pin table is not a runtime-resolution
//! mechanism for general payment routing, only for the trustline verb's
//! user-ergonomics surface.

use stellar_agent_core::observability::redact_strkey_first5_last5;
use thiserror::Error;
use tracing::info;

use crate::deny::{USDT_REFUSAL_WARNING, is_usdt};
use crate::pins::{NetworkId, is_known_lookalike, pinned_issuer};

// ─────────────────────────────────────────────────────────────────────────────
// Resolver error
// ─────────────────────────────────────────────────────────────────────────────

/// Errors returned by [`resolve_denomination`].
///
/// Each variant maps to a refusal rule in the ordered-refusal sequence and
/// carries a human-readable message for the policy-engine denial log.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum ResolveError {
    /// USDT hard-refusal.
    ///
    /// The named warning [`USDT_REFUSAL_WARNING`] is included in the message.
    /// No override path exists at v1.
    #[error(
        "USDT-on-Stellar-lookalike-risk — USDT trustlines are refused on this wallet (code: {code:?})"
    )]
    UsdtRefused {
        /// The supplied asset code (may be mixed-case, e.g. `"usdt"`).
        code: String,
    },

    /// The `(code, issuer)` pair is in the known-lookalike denylist (refusal rule 2).
    ///
    /// Issuer is redacted to first-5-last-5 in the error message.
    #[error(
        "counterparty-lookalike — (code={code:?}, issuer={issuer_redacted}) \
         is a known lookalike in the denylist (home_domain={home_domain:?})"
    )]
    LookalikeRefused {
        /// Asset code.
        code: String,
        /// Issuer G-strkey, first-5-last-5 redacted.
        issuer_redacted: String,
        /// On-chain `home_domain` of the lookalike issuer.
        home_domain: &'static str,
    },

    /// Code matches a pinned code but the supplied issuer differs (refusal rule 3).
    ///
    /// Both the supplied and pinned issuers are redacted to first-5-last-5.
    #[error(
        "issuer mismatch for pinned code — code {code:?} is pinned to \
         issuer {pinned_issuer_redacted} but supplied issuer is {supplied_issuer_redacted}"
    )]
    PinnedCodeIssuerMismatch {
        /// Asset code (e.g. `"USDC"`).
        code: String,
        /// Pinned canonical issuer, first-5-last-5 redacted.
        pinned_issuer_redacted: String,
        /// Caller-supplied issuer, first-5-last-5 redacted.
        supplied_issuer_redacted: String,
    },

    /// Bare code supplied with no pin row for the active network (refusal rule 4).
    ///
    /// EURAU is an example: not pinnable because its live on-chain assets are
    /// lookalikes.
    #[error(
        "denomination-explicit required — bare code {code:?} has no issuer pin \
         for network {network:?}; supply code+issuer explicitly"
    )]
    UnpinnedBareCode {
        /// The bare asset code.
        code: String,
        /// The active network.
        network: NetworkId,
    },

    /// The supplied passphrase does not match any known network (mainnet/testnet).
    #[error("unsupported network passphrase — cannot resolve stablecoin pins for unknown network")]
    UnknownNetwork,

    /// A SEP-41 C-strkey SAC address was supplied but SAC resolution is not
    /// yet implemented (requires an on-chain RPC call).
    #[error(
        "SAC address resolution not yet available — supply code+issuer instead of \
         C-strkey {address_redacted}"
    )]
    UnresolvableSacAddress {
        /// C-strkey, first-5-last-5 redacted.
        address_redacted: String,
    },

    /// The supplied asset code is structurally invalid (not 1–12 ASCII alnum).
    #[error("invalid asset code {code:?} — must be 1–12 ASCII alphanumeric characters")]
    InvalidCode {
        /// The rejected code.
        code: String,
    },

    /// The supplied issuer is not a valid G-strkey.
    #[error("invalid issuer — must be a valid Stellar G-strkey")]
    InvalidIssuer,
}

// ─────────────────────────────────────────────────────────────────────────────
// Resolved asset
// ─────────────────────────────────────────────────────────────────────────────

/// A denomination-resolved stablecoin asset.
///
/// Returned by [`resolve_denomination`] on success.  Always carries a canonical
/// uppercase code and a verified G-strkey issuer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedAsset {
    /// The asset code, in the canonical uppercase form as found in the pin table
    /// or as supplied by the caller (already validated as ASCII alphanumeric).
    pub code: String,
    /// The issuer G-strkey.
    ///
    /// For bare-code inputs resolved through the pin table, this is the
    /// canonical pinned issuer.  For explicit `code+issuer` inputs this is the
    /// caller-supplied issuer (after G-strkey validation).
    pub issuer: String,
    /// Whether this asset was resolved through the pin table.
    ///
    /// `true` for bare-code inputs resolved via pin + for explicit
    /// `code+issuer` inputs whose issuer matches the pin.
    pub is_pinned: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// Denominator input
// ─────────────────────────────────────────────────────────────────────────────

/// The caller-supplied denomination input to [`resolve_denomination`].
#[derive(Debug, Clone)]
pub enum DenominationInput {
    /// A SEP-41 C-strkey Stellar Asset Contract address.
    SacAddress(String),
    /// An explicit code+issuer pair.
    CodeAndIssuer {
        /// Asset code (1–12 ASCII alphanumeric).
        code: String,
        /// Issuer G-strkey.
        issuer: String,
    },
    /// A bare asset code (no issuer).
    ///
    /// Allowed only when the code resolves through the pin table.
    BareCode(String),
}

// ─────────────────────────────────────────────────────────────────────────────
// Resolver
// ─────────────────────────────────────────────────────────────────────────────

/// Resolves a denomination input to a canonical `(code, issuer)` pair.
///
/// This is the single entry point for all asset inputs to the `trustline` verb.
/// Every input — SEP-41 C-address, explicit `code+issuer`, or bare code —
/// flows through this function before any trustline-building logic runs.
///
/// # Parameters
///
/// - `input`: the caller-supplied denomination input.
/// - `network_passphrase`: the active network passphrase from the wallet profile.
///
/// # Errors
///
/// Returns a [`ResolveError`] variant corresponding to the first triggered
/// refusal rule (in order):
///
/// 0. Unknown network passphrase → [`ResolveError::UnknownNetwork`].
/// 1. `USDT` (any case) → [`ResolveError::UsdtRefused`].
/// 2. `(code, issuer)` in denylist → [`ResolveError::LookalikeRefused`].
/// 3. Code pinned but issuer differs → [`ResolveError::PinnedCodeIssuerMismatch`].
/// 4. Bare code, no pin for network → [`ResolveError::UnpinnedBareCode`].
/// 5. SAC address (deferred) → [`ResolveError::UnresolvableSacAddress`].
/// 6. Invalid code/issuer → [`ResolveError::InvalidCode`] / [`ResolveError::InvalidIssuer`].
///
/// # Panics
///
/// Never panics.
///
/// # Examples
///
/// ```
/// use stellar_agent_stablecoin::resolve::{DenominationInput, resolve_denomination};
///
/// let result = resolve_denomination(
///     DenominationInput::BareCode("USDC".to_owned()),
///     "Test SDF Network ; September 2015",
/// );
/// let asset = result.unwrap();
/// assert_eq!(asset.code, "USDC");
/// assert_eq!(asset.issuer, "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5");
/// assert!(asset.is_pinned);
/// ```
///
pub fn resolve_denomination(
    input: DenominationInput,
    network_passphrase: &str,
) -> Result<ResolvedAsset, ResolveError> {
    // Resolve network — fail fast for unknown passphrases.
    let network =
        NetworkId::from_passphrase(network_passphrase).ok_or(ResolveError::UnknownNetwork)?;

    match input {
        // ── Path 1: SEP-41 C-strkey SAC address ──────────────────────────────
        DenominationInput::SacAddress(addr) => {
            // Validate using stellar_strkey — this performs the full CRC-16
            // check, not just a length/prefix heuristic (mirrors the issuer
            // path below which uses stellar_strkey::ed25519::PublicKey).
            match stellar_strkey::Contract::from_string(&addr) {
                Ok(_) => {
                    // SAC-to-asset resolution requires an on-chain RPC call.
                    // Not yet implemented; return a typed error.
                    let redacted = redact_strkey_first5_last5(&addr);
                    Err(ResolveError::UnresolvableSacAddress {
                        address_redacted: redacted,
                    })
                }
                Err(_) => {
                    // Not a valid C-strkey; treat as invalid.
                    Err(ResolveError::InvalidCode { code: addr })
                }
            }
        }

        // ── Path 2: Explicit code+issuer ─────────────────────────────────────
        DenominationInput::CodeAndIssuer { code, issuer } => {
            let code_upper = validate_and_upper_code(&code)?;
            validate_g_strkey(&issuer)?;

            resolve_with_code_and_issuer(code_upper, issuer, network)
        }

        // ── Path 3: Bare code ─────────────────────────────────────────────────
        DenominationInput::BareCode(code) => {
            let code_upper = validate_and_upper_code(&code)?;

            // Rule 1: USDT hard-deny.
            if is_usdt(&code_upper) {
                info!(
                    code = %code_upper,
                    warning = USDT_REFUSAL_WARNING,
                    "USDT trustline refused"
                );
                return Err(ResolveError::UsdtRefused { code: code_upper });
            }

            // Bare code: must resolve through the pin table.
            match pinned_issuer(&code_upper, network) {
                Some(canonical_issuer) => {
                    info!(
                        code = %code_upper,
                        issuer = %redact_strkey_first5_last5(canonical_issuer),
                        "bare code resolved via pin table"
                    );
                    Ok(ResolvedAsset {
                        code: code_upper,
                        issuer: canonical_issuer.to_owned(),
                        is_pinned: true,
                    })
                }
                None => {
                    // No pin row for this code on this network; refuses as unpinned bare code.
                    Err(ResolveError::UnpinnedBareCode {
                        code: code_upper,
                        network,
                    })
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Validates the asset code and returns the canonical uppercase version.
///
/// Accepts 1–12 ASCII alphanumeric characters; rejects empty codes, codes
/// longer than 12 chars, and codes containing non-ASCII-alphanumeric characters.
fn validate_and_upper_code(code: &str) -> Result<String, ResolveError> {
    if code.is_empty() || code.len() > 12 || !code.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err(ResolveError::InvalidCode {
            code: code.to_owned(),
        });
    }
    Ok(code.to_ascii_uppercase())
}

/// Validates the issuer is a syntactically valid G-strkey.
fn validate_g_strkey(issuer: &str) -> Result<(), ResolveError> {
    stellar_strkey::ed25519::PublicKey::from_string(issuer)
        .map_err(|_| ResolveError::InvalidIssuer)?;
    Ok(())
}

/// Core refusal-order logic for a code+issuer pair.
///
/// Called from the explicit `CodeAndIssuer` path only.  The bare-code path
/// resolves its issuer from the pin table and returns directly without going
/// through this function.
fn resolve_with_code_and_issuer(
    code_upper: String,
    issuer: String,
    network: NetworkId,
) -> Result<ResolvedAsset, ResolveError> {
    // Rule 1: USDT hard-deny — checked before issuer lookup.
    if is_usdt(&code_upper) {
        info!(
            code = %code_upper,
            warning = USDT_REFUSAL_WARNING,
            "USDT trustline refused"
        );
        return Err(ResolveError::UsdtRefused { code: code_upper });
    }

    // Rule 2: known-lookalike denylist check.
    if is_known_lookalike(&code_upper, &issuer) {
        let home_domain = crate::pins::KNOWN_LOOKALIKES
            .iter()
            .find(|e| e.code == code_upper && e.issuer == issuer)
            .map(|e| e.home_domain)
            .unwrap_or("<unknown>");
        let issuer_redacted = redact_strkey_first5_last5(&issuer);
        info!(
            code = %code_upper,
            issuer = %issuer_redacted,
            home_domain = %home_domain,
            "lookalike denylist match — refusing trustline"
        );
        return Err(ResolveError::LookalikeRefused {
            code: code_upper,
            issuer_redacted,
            home_domain,
        });
    }

    // Rule 3: code matches a pinned code but issuer differs (issuer mismatch).
    if let Some(canonical) = pinned_issuer(&code_upper, network) {
        if issuer != canonical {
            let pinned_redacted = redact_strkey_first5_last5(canonical);
            let supplied_redacted = redact_strkey_first5_last5(&issuer);
            info!(
                code = %code_upper,
                pinned_issuer = %pinned_redacted,
                supplied_issuer = %supplied_redacted,
                "pinned-code issuer mismatch — refusing trustline"
            );
            return Err(ResolveError::PinnedCodeIssuerMismatch {
                code: code_upper,
                pinned_issuer_redacted: pinned_redacted,
                supplied_issuer_redacted: supplied_redacted,
            });
        }
        // Issuer matches the pin — allowed.
        info!(
            code = %code_upper,
            issuer = %redact_strkey_first5_last5(&issuer),
            "pinned code+issuer match — allowing trustline"
        );
        return Ok(ResolvedAsset {
            code: code_upper,
            issuer,
            is_pinned: true,
        });
    }

    // Rule 5: explicit non-pinned code+issuer — allowed.
    info!(
        code = %code_upper,
        issuer = %redact_strkey_first5_last5(&issuer),
        "non-pinned explicit code+issuer — allowing trustline"
    );
    Ok(ResolvedAsset {
        code: code_upper,
        issuer,
        is_pinned: false,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests — KATs for all five refusal paths + happy paths
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only; panics and unwraps are acceptable in unit tests"
    )]

    use super::*;

    const TESTNET: &str = "Test SDF Network ; September 2015";
    const MAINNET: &str = "Public Global Stellar Network ; September 2015";

    // Pinned testnet USDC issuer.
    const USDC_TESTNET: &str = "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5";
    // Pinned mainnet USDC issuer.
    const USDC_MAINNET: &str = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";
    // Pinned testnet EURC issuer.
    const EURC_TESTNET: &str = "GB3Q6QDZYTHWT7E5PVS3W7FUT5GVAFC5KSZFFLPU25GO7VTC3NM2ZTVO";
    // A non-pinned valid G-strkey (from test fixtures, seed [2u8;32]).
    const UNPINNED_ISSUER: &str = "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY";
    // EURAU lookalike #1.
    const EURAU_LOOKALIKE_1: &str = "GCMHTNLK3N2QYQENZTJAKO34J3GGNL26BILAWPWVRB37JLV7TXDBHNFT";
    // EURAU lookalike #2.
    const EURAU_LOOKALIKE_2: &str = "GCPW5C27VOZ4T74ERBEAUW2O7TXRZ5CNMRN7CCDVI477FXRWULBACBSC";

    // ── Rule 1: USDT hard-deny ────────────────────────────────────────────────

    #[test]
    fn kat_usdt_bare_code_refused() {
        let err = resolve_denomination(DenominationInput::BareCode("USDT".to_owned()), TESTNET)
            .unwrap_err();
        assert!(
            matches!(err, ResolveError::UsdtRefused { ref code } if code == "USDT"),
            "expected UsdtRefused, got: {err:?}"
        );
    }

    #[test]
    fn kat_usdt_lowercase_refused() {
        let err = resolve_denomination(DenominationInput::BareCode("usdt".to_owned()), TESTNET)
            .unwrap_err();
        assert!(matches!(err, ResolveError::UsdtRefused { .. }));
    }

    #[test]
    fn kat_usdt_with_issuer_refused() {
        let err = resolve_denomination(
            DenominationInput::CodeAndIssuer {
                code: "USDT".to_owned(),
                issuer: UNPINNED_ISSUER.to_owned(),
            },
            TESTNET,
        )
        .unwrap_err();
        assert!(matches!(err, ResolveError::UsdtRefused { .. }));
    }

    // ── Rule 2: Lookalike denylist ────────────────────────────────────────────

    #[test]
    fn kat_eurau_lookalike_1_refused() {
        let err = resolve_denomination(
            DenominationInput::CodeAndIssuer {
                code: "EURAU".to_owned(),
                issuer: EURAU_LOOKALIKE_1.to_owned(),
            },
            TESTNET,
        )
        .unwrap_err();
        assert!(
            matches!(err, ResolveError::LookalikeRefused { .. }),
            "expected LookalikeRefused, got: {err:?}"
        );
    }

    #[test]
    fn kat_eurau_lookalike_2_refused() {
        let err = resolve_denomination(
            DenominationInput::CodeAndIssuer {
                code: "EURAU".to_owned(),
                issuer: EURAU_LOOKALIKE_2.to_owned(),
            },
            MAINNET,
        )
        .unwrap_err();
        assert!(matches!(err, ResolveError::LookalikeRefused { .. }));
    }

    // ── Rule 3: Pinned-code issuer mismatch ──────────────────────────────────

    #[test]
    fn kat_usdc_wrong_issuer_refused() {
        // USDC code + non-pinned issuer → PinnedCodeIssuerMismatch.
        let err = resolve_denomination(
            DenominationInput::CodeAndIssuer {
                code: "USDC".to_owned(),
                issuer: UNPINNED_ISSUER.to_owned(),
            },
            TESTNET,
        )
        .unwrap_err();
        assert!(
            matches!(err, ResolveError::PinnedCodeIssuerMismatch { .. }),
            "expected PinnedCodeIssuerMismatch, got: {err:?}"
        );
    }

    #[test]
    fn kat_eurc_wrong_issuer_refused() {
        let err = resolve_denomination(
            DenominationInput::CodeAndIssuer {
                code: "EURC".to_owned(),
                issuer: UNPINNED_ISSUER.to_owned(),
            },
            MAINNET,
        )
        .unwrap_err();
        assert!(matches!(err, ResolveError::PinnedCodeIssuerMismatch { .. }));
    }

    // ── Rule 4: Unpinned bare code ────────────────────────────────────────────

    #[test]
    fn kat_eurau_bare_code_refused_as_unpinned() {
        // EURAU bare code → UnpinnedBareCode (not pinnable; its live on-chain assets are lookalikes).
        let err = resolve_denomination(DenominationInput::BareCode("EURAU".to_owned()), TESTNET)
            .unwrap_err();
        assert!(
            matches!(err, ResolveError::UnpinnedBareCode { ref code, .. } if code == "EURAU"),
            "expected UnpinnedBareCode, got: {err:?}"
        );
    }

    #[test]
    fn kat_unknown_bare_code_refused() {
        let err = resolve_denomination(DenominationInput::BareCode("FOO".to_owned()), TESTNET)
            .unwrap_err();
        assert!(matches!(err, ResolveError::UnpinnedBareCode { .. }));
    }

    // ── Rule 5: Non-pinned explicit code+issuer — allowed ────────────────────

    #[test]
    fn kat_non_pinned_explicit_allowed() {
        let asset = resolve_denomination(
            DenominationInput::CodeAndIssuer {
                code: "MYTOKEN".to_owned(),
                issuer: UNPINNED_ISSUER.to_owned(),
            },
            TESTNET,
        )
        .unwrap();
        assert_eq!(asset.code, "MYTOKEN");
        assert_eq!(asset.issuer, UNPINNED_ISSUER);
        assert!(!asset.is_pinned);
    }

    // ── Happy paths ───────────────────────────────────────────────────────────

    #[test]
    fn usdc_bare_code_testnet_resolves_via_pin() {
        let asset =
            resolve_denomination(DenominationInput::BareCode("USDC".to_owned()), TESTNET).unwrap();
        assert_eq!(asset.code, "USDC");
        assert_eq!(asset.issuer, USDC_TESTNET);
        assert!(asset.is_pinned);
    }

    #[test]
    fn usdc_bare_code_mainnet_resolves_via_pin() {
        let asset =
            resolve_denomination(DenominationInput::BareCode("USDC".to_owned()), MAINNET).unwrap();
        assert_eq!(asset.code, "USDC");
        assert_eq!(asset.issuer, USDC_MAINNET);
        assert!(asset.is_pinned);
    }

    #[test]
    fn usdc_lowercase_bare_code_resolves() {
        let asset =
            resolve_denomination(DenominationInput::BareCode("usdc".to_owned()), TESTNET).unwrap();
        assert_eq!(asset.code, "USDC");
        assert_eq!(asset.issuer, USDC_TESTNET);
    }

    #[test]
    fn eurc_bare_code_testnet_resolves() {
        let asset =
            resolve_denomination(DenominationInput::BareCode("EURC".to_owned()), TESTNET).unwrap();
        assert_eq!(asset.code, "EURC");
        assert_eq!(asset.issuer, EURC_TESTNET);
        assert!(asset.is_pinned);
    }

    #[test]
    fn usdc_explicit_pinned_issuer_allowed() {
        let asset = resolve_denomination(
            DenominationInput::CodeAndIssuer {
                code: "USDC".to_owned(),
                issuer: USDC_TESTNET.to_owned(),
            },
            TESTNET,
        )
        .unwrap();
        assert_eq!(asset.code, "USDC");
        assert_eq!(asset.issuer, USDC_TESTNET);
        assert!(asset.is_pinned);
    }

    #[test]
    fn usdc_explicit_mainnet_issuer_on_mainnet_allowed() {
        let asset = resolve_denomination(
            DenominationInput::CodeAndIssuer {
                code: "USDC".to_owned(),
                issuer: USDC_MAINNET.to_owned(),
            },
            MAINNET,
        )
        .unwrap();
        assert_eq!(asset.code, "USDC");
        assert!(asset.is_pinned);
    }

    // ── Edge cases ────────────────────────────────────────────────────────────

    #[test]
    fn unknown_network_passphrase_returns_error() {
        let err = resolve_denomination(
            DenominationInput::BareCode("USDC".to_owned()),
            "Unknown Network ; January 2020",
        )
        .unwrap_err();
        assert!(matches!(err, ResolveError::UnknownNetwork));
    }

    #[test]
    fn sac_address_returns_unresolvable_error() {
        // A C-strkey (Stellar Asset Contract address).
        let sac = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM";
        let err = resolve_denomination(DenominationInput::SacAddress(sac.to_owned()), TESTNET)
            .unwrap_err();
        assert!(
            matches!(err, ResolveError::UnresolvableSacAddress { .. }),
            "expected UnresolvableSacAddress, got: {err:?}"
        );
    }

    #[test]
    fn invalid_code_too_long_returns_error() {
        let err = resolve_denomination(
            DenominationInput::CodeAndIssuer {
                code: "TOOLONGCODE123".to_owned(),
                issuer: UNPINNED_ISSUER.to_owned(),
            },
            TESTNET,
        )
        .unwrap_err();
        assert!(matches!(err, ResolveError::InvalidCode { .. }));
    }

    #[test]
    fn invalid_issuer_not_g_strkey() {
        let err = resolve_denomination(
            DenominationInput::CodeAndIssuer {
                code: "MYTOKEN".to_owned(),
                issuer: "NOTASTRKEY".to_owned(),
            },
            TESTNET,
        )
        .unwrap_err();
        assert!(matches!(err, ResolveError::InvalidIssuer));
    }

    #[test]
    fn usdt0_explicit_not_refused_by_usdt_rule() {
        // USDT0 is a real distinct asset and must NOT be caught by the USDT rule.
        // It will fail as UnpinnedBareCode when supplied as a bare code.
        let err = resolve_denomination(DenominationInput::BareCode("USDT0".to_owned()), TESTNET)
            .unwrap_err();
        assert!(
            matches!(err, ResolveError::UnpinnedBareCode { .. }),
            "USDT0 must not trigger USDT refusal; expected UnpinnedBareCode, got: {err:?}"
        );
    }

    #[test]
    fn usdt0_explicit_code_issuer_allowed() {
        // USDT0 with an explicit issuer is allowed (not USDT and not in the denylist).
        let asset = resolve_denomination(
            DenominationInput::CodeAndIssuer {
                code: "USDT0".to_owned(),
                issuer: UNPINNED_ISSUER.to_owned(),
            },
            TESTNET,
        )
        .unwrap();
        assert_eq!(asset.code, "USDT0");
        assert!(!asset.is_pinned);
    }

    // ── SAC address negative branch (malformed strkey) ────────────────────────

    #[test]
    fn sac_address_malformed_returns_invalid_code() {
        // "notacstrkey" is neither a valid C-strkey (fails CRC-16) nor 56 chars;
        // the stellar_strkey::Contract parser rejects it, producing InvalidCode.
        let err = resolve_denomination(
            DenominationInput::SacAddress("notacstrkey".to_owned()),
            TESTNET,
        )
        .unwrap_err();
        assert!(
            matches!(err, ResolveError::InvalidCode { .. }),
            "malformed SAC address must produce InvalidCode, got: {err:?}"
        );
    }
}
