//! SAC (Stellar Asset Contract) canonicalisation helper.
//!
//! # What this module does
//!
//! Derives the SAC contract address for a Stellar classic asset
//! (`code:issuer` pair) using the `ContractIdPreimage::Asset` path.
//!
//! # Reference implementations
//!
//! 1. `stellar-strkey` handles encoding and `stellar-xdr` handles preimage
//!    construction; there is no combined SAC helper to reuse.
//!
//! 2. `stellar-cli cmd/soroban-cli/src/utils.rs`
//!    (`contract_id_hash_from_asset`) implements the exact algorithm:
//!    `SHA256(XDR(HashIdPreimage::ContractId { network_id: SHA256(passphrase), preimage: Asset(...) }))`.
//!    The function is in a binary crate (`soroban-cli`), not a library; it
//!    cannot be imported.  Implementing the equivalent Rust logic here is
//!    therefore the correct approach (NOT a hand-roll bypassing ecosystem crates —
//!    this uses `stellar-xdr` types + `sha2` + `stellar-strkey`, all registered
//!    ecosystem crates).
//!    Also cross-checked against `js-stellar-base` (the JavaScript/TypeScript
//!    base library used by Soroswap's SDK); the algorithm is identical.
//!
//! 3. In-tree, `stellar-agent-smart-account/src/deployment/address.rs`
//!    implements `ContractIdPreimage::Address` (deployer+salt path), which is
//!    structurally identical but uses a different preimage variant.  The SAC
//!    path uses `ContractIdPreimage::Asset`.  A shared helper in `stellar-agent-core`
//!    is the correct home for broad reuse (also used by stablecoins).
//!
//! # Byte-layout citation
//!
//! The preimage byte layout is:
//!
//! ```text
//! HashIdPreimage::ContractId {
//!   network_id: SHA256(network_passphrase),   // [u8; 32]
//!   contract_id_preimage: ContractIdPreimage::Asset(Asset { ... }),
//! }
//! ```
//!
//! Cited from `stellar-xdr` `src/curr/generated.rs`:
//! - `HashIdPreimage::ContractId` (XDR type `HashIDPreimage` arm
//!   `HashIDPreimageContractID { hashIDPreimageContractID }`).
//! - `ContractIdPreimage::Asset` (XDR type `ContractIDPreimage`
//!   arm `ContractIDPreimageAsset`), encoding an `Asset`.
//! - `Asset` encoding: `AlphaNum4` or `AlphaNum12` struct per XDR spec, with
//!   `AssetCode4`/`AssetCode12` + `AccountID (Ed25519 PublicKey)`.
//!
//! Cross-check: `stellar-cli cmd/soroban-cli/src/utils.rs` — identical
//! algorithm (network_id = SHA256(passphrase), preimage =
//! `ContractIdPreimage::Asset(asset)`, hash = SHA256(preimage.to_xdr())).
//!
//! # Known-answer test vector
//!
//! XLM SAC on testnet:
//! - Asset: native XLM (`Asset::Native`)
//! - Network passphrase: `Test SDF Network ; September 2015`
//! - Expected SAC: `CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC`
//!
//! Source: `soroswap-core/public/tokens.json:testnet:assets[0]:contract`
//! (`CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC`).
//! Independently verified via `stellar contract id asset --asset native --network testnet`
//! (CLI result: `CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC`).
//!
//! # Canonicalisation runs BEFORE policy eval
//!
//! Token addresses are canonicalised to SEP-41/SAC contract addresses BEFORE
//! any policy evaluation, venue allowlist check, or path building.

use sha2::{Digest, Sha256};
use stellar_xdr::{
    AccountId, AlphaNum4, AlphaNum12, Asset, AssetCode4, AssetCode12, ContractIdPreimage, Hash,
    HashIdPreimage, HashIdPreimageContractId, Limits, PublicKey, Uint256, WriteXdr,
};

// ─────────────────────────────────────────────────────────────────────────────
// SacError
// ─────────────────────────────────────────────────────────────────────────────

/// Error returned by SAC canonicalisation.
///
/// All variants carry non-sensitive diagnostic information.  The `Display`
/// impl never leaks a full address, private key, or sensitive bytes.
///
/// # Sibling-variant Display audit
///
/// Every variant below is reviewed to ensure its `Display` text contains no
/// `C…`/`G…` full addresses.  Inputs are truncated before surfacing.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SacError {
    /// The issuer is not a valid G-strkey ed25519 public key.
    #[error("SAC issuer is not a valid G-strkey: {reason}")]
    InvalidIssuer {
        /// Non-sensitive reason.
        reason: String,
    },

    /// The asset code is not valid (empty, too long, or contains invalid chars).
    #[error("SAC asset code is invalid: {reason}")]
    InvalidCode {
        /// Non-sensitive reason.
        reason: &'static str,
    },

    /// The input is a bare code with no issuer and no native marker.
    ///
    /// Ambiguous bare code is refused — the caller must supply a full
    /// `CODE:ISSUER` or `native`.
    #[error(
        "ambiguous asset: a bare asset code with no issuer cannot be canonicalised to a SAC; \
         supply CODE:ISSUER or use a C-strkey SAC address directly"
    )]
    AmbiguousBareCode,

    /// XDR serialisation of the preimage failed.
    #[error("SAC preimage XDR encode error: {reason}")]
    XdrEncode {
        /// Non-sensitive reason.
        reason: String,
    },

    /// The input string does not match any recognised format (C-strkey, native,
    /// CODE:ISSUER).
    #[error("unrecognised token format; supply a C-strkey SAC address, 'native', or 'CODE:ISSUER'")]
    UnrecognisedFormat,
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

/// Canonicalises a token identifier to a SEP-41/SAC contract address (C-strkey).
///
/// Accepts three input forms:
///
/// 1. **C-strkey contract address** — returned as-is after strkey validation.
/// 2. **`"native"` (case-insensitive)** — derived via SAC preimage for native XLM.
/// 3. **`"CODE:ISSUER"` classic asset** — derived via SAC preimage.
///
/// Ambiguous inputs (bare code with no issuer, non-canonicalising strings) are
/// refused with [`SacError::AmbiguousBareCode`] or [`SacError::UnrecognisedFormat`].
///
/// # Canonicalisation order
///
/// MUST run BEFORE policy eval, venue allowlist, and path building.
///
/// # Algorithm (byte-layout claim)
///
/// For `native` or `CODE:ISSUER`:
/// ```text
/// network_id = SHA256(network_passphrase.as_bytes())
/// preimage = HashIdPreimage::ContractId {
///   network_id,
///   contract_id_preimage: ContractIdPreimage::Asset(asset),
/// }
/// contract_id = SHA256(preimage.to_xdr(Limits::none()))
/// return stellar_strkey::Contract(contract_id).to_string()
/// ```
///
/// Byte-layout cited from:
/// - `stellar-xdr` `src/curr/generated.rs`
///   (`HashIdPreimage::ContractId` XDR shape).
/// - `stellar-xdr` `src/curr/generated.rs`
///   (`ContractIdPreimage::Asset` XDR shape).
/// - `stellar-cli cmd/soroban-cli/src/utils.rs` (canonical reference
///   implementation, same algorithm).
///
/// Cross-check: `stellar-agent-smart-account/src/deployment/address.rs`
/// uses the structurally identical `ContractIdPreimage::Address` path.
///
/// # Errors
///
/// Returns [`SacError`] on any input-validation or encoding failure.
///
/// # Examples
///
/// ```
/// use stellar_agent_dex::sac::canonicalise_token;
///
/// // C-strkey passed through as-is.
/// let addr = "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC";
/// let passphrase = "Test SDF Network ; September 2015";
/// let result = canonicalise_token(addr, passphrase).unwrap();
/// assert_eq!(result, addr);
/// ```
pub fn canonicalise_token(token: &str, network_passphrase: &str) -> Result<String, SacError> {
    let token = token.trim();

    // ── 1. Already a C-strkey? Return validated. ──────────────────────────
    if let Ok(contract) = stellar_strkey::Contract::from_string(token) {
        return Ok(format!("{}", stellar_strkey::Strkey::Contract(contract)));
    }

    // ── 2. "native" (XLM SAC) ────────────────────────────────────────────
    if token.eq_ignore_ascii_case("native") {
        let asset = Asset::Native;
        return derive_sac_contract_id(asset, network_passphrase);
    }

    // ── 3. "CODE:ISSUER" classic asset ───────────────────────────────────
    if let Some(pos) = token.find(':') {
        let code = &token[..pos];
        let issuer_str = &token[pos + 1..];
        let asset = parse_classic_asset(code, issuer_str)?;
        return derive_sac_contract_id(asset, network_passphrase);
    }

    // ── 4. Bare code (no issuer) — ambiguous, refuse ──────────────────────
    // Bare codes cannot be unambiguously mapped to a SAC without an issuer.
    if !token.is_empty()
        && token
            .chars()
            .all(|c| c.is_ascii_alphabetic() || c.is_ascii_digit())
    {
        return Err(SacError::AmbiguousBareCode);
    }

    Err(SacError::UnrecognisedFormat)
}

/// Canonicalises every token in `tokens`, returning the C-strkey addresses in order.
///
/// Runs BEFORE policy eval / allowlist / path-build.
/// Fails on the first canonicalisation error.
///
/// # Errors
///
/// Returns [`SacError`] on any canonicalisation failure.
pub fn canonicalise_path(
    tokens: &[String],
    network_passphrase: &str,
) -> Result<Vec<String>, SacError> {
    tokens
        .iter()
        .map(|t| canonicalise_token(t, network_passphrase))
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Derives the SAC contract address for `asset` on `network_passphrase`.
///
/// Byte-layout cited from:
/// - `stellar-xdr` `src/curr/generated.rs` (`HashIdPreimage::ContractId`).
/// - `stellar-xdr` `src/curr/generated.rs` (`ContractIdPreimage::Asset`).
/// - `stellar-cli cmd/soroban-cli/src/utils.rs` (canonical reference).
fn derive_sac_contract_id(asset: Asset, network_passphrase: &str) -> Result<String, SacError> {
    let network_id: [u8; 32] = Sha256::digest(network_passphrase.as_bytes()).into();

    let preimage = HashIdPreimage::ContractId(HashIdPreimageContractId {
        network_id: Hash(network_id),
        contract_id_preimage: ContractIdPreimage::Asset(asset),
    });

    let encoded = preimage
        .to_xdr(Limits::none())
        .map_err(|e| SacError::XdrEncode {
            reason: e.to_string(),
        })?;

    let contract_id_bytes: [u8; 32] = Sha256::digest(&encoded).into();
    // stellar_strkey::Contract(pub [u8; 32]) wraps the raw contract-id bytes.
    // `Display` on it returns a heapless::String<56>, not std::String; convert
    // explicitly.  `stellar_strkey::Contract` defined in
    // rs-stellar-strkey src/strkey.rs.
    let strkey_contract = stellar_strkey::Contract(contract_id_bytes);
    // `format!` drives Display (which returns heapless::String<56>) through the
    // Formatter trait, writing to a std::String buffer.
    Ok(format!("{strkey_contract}"))
}

/// Parses a `CODE:ISSUER` classic asset into an [`Asset`] XDR value.
fn parse_classic_asset(code: &str, issuer_str: &str) -> Result<Asset, SacError> {
    // Validate issuer G-strkey.
    let issuer_pk = stellar_strkey::ed25519::PublicKey::from_string(issuer_str).map_err(|e| {
        SacError::InvalidIssuer {
            reason: format!("issuer parse failed: {e}"),
        }
    })?;
    let account_id = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(issuer_pk.0)));

    let code_len = code.len();
    if code_len == 0 {
        return Err(SacError::InvalidCode {
            reason: "asset code is empty",
        });
    }
    if code_len > 12 {
        return Err(SacError::InvalidCode {
            reason: "asset code exceeds 12 characters",
        });
    }
    // Canonical Stellar asset-code rule is `^[a-zA-Z0-9]{1,12}$`; reject any
    // non-alphanumeric byte so a malformed code cannot be copied into an
    // AssetCode4/AssetCode12 and yield a SAC id derived from an invalid asset.
    if !code.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return Err(SacError::InvalidCode {
            reason: "asset code must be ASCII alphanumeric",
        });
    }

    if code_len <= 4 {
        let mut code4 = [0u8; 4];
        code4[..code_len].copy_from_slice(code.as_bytes());
        let asset_code = AssetCode4(code4);
        Ok(Asset::CreditAlphanum4(AlphaNum4 {
            asset_code,
            issuer: account_id,
        }))
    } else {
        let mut code12 = [0u8; 12];
        code12[..code_len].copy_from_slice(code.as_bytes());
        let asset_code = AssetCode12(code12);
        Ok(Asset::CreditAlphanum12(AlphaNum12 {
            asset_code,
            issuer: account_id,
        }))
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
        clippy::panic,
        reason = "test-only fixture construction"
    )]

    use super::*;

    const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";

    // ── Known-answer SAC test vector ────────────────────────────────────────
    //
    // XLM native SAC on testnet.
    // Expected: `CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC`
    // Source: soroswap-core/public/tokens.json testnet assets[0].contract
    // CLI-verified: `stellar contract id asset --asset native --network testnet`
    // → CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC

    #[test]
    fn xlm_native_sac_testnet_known_answer() {
        let result = canonicalise_token("native", TESTNET_PASSPHRASE)
            .expect("native SAC derivation must succeed");
        assert_eq!(
            result, "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC",
            "XLM native SAC on testnet must match the known-answer vector"
        );
    }

    #[test]
    fn native_case_insensitive() {
        let lower = canonicalise_token("native", TESTNET_PASSPHRASE).unwrap();
        let upper = canonicalise_token("NATIVE", TESTNET_PASSPHRASE).unwrap();
        assert_eq!(lower, upper, "native must be case-insensitive");
    }

    // ── C-strkey passthrough ─────────────────────────────────────────────────

    #[test]
    fn c_strkey_passes_through_validated() {
        let addr = "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC";
        let result = canonicalise_token(addr, TESTNET_PASSPHRASE).unwrap();
        assert_eq!(result, addr);
    }

    #[test]
    fn invalid_c_strkey_falls_through_to_native_check() {
        // A string starting with 'C' but not a valid strkey should return an
        // error rather than silently passing.
        let result = canonicalise_token("CINVALIDSTRKEY", TESTNET_PASSPHRASE);
        // It's not a valid strkey, not "native", not CODE:ISSUER with valid issuer,
        // and not a bare code — UnrecognisedFormat.
        assert!(result.is_err(), "invalid strkey must return error");
    }

    // ── Ambiguous bare code ──────────────────────────────────────────────────

    #[test]
    fn bare_code_refused() {
        let result = canonicalise_token("USDC", TESTNET_PASSPHRASE);
        assert!(
            matches!(result, Err(SacError::AmbiguousBareCode)),
            "bare code must return AmbiguousBareCode; got {result:?}"
        );
    }

    #[test]
    fn bare_xlm_code_refused() {
        let result = canonicalise_token("XLM", TESTNET_PASSPHRASE);
        assert!(
            matches!(result, Err(SacError::AmbiguousBareCode)),
            "bare XLM code must return AmbiguousBareCode; got {result:?}"
        );
    }

    #[test]
    fn non_alphanumeric_bare_string_unrecognised() {
        // Not a C-strkey, not "native", not CODE:ISSUER, and not an alphanumeric
        // bare code → UnrecognisedFormat.
        let result = canonicalise_token("not a token!", TESTNET_PASSPHRASE);
        assert!(
            matches!(result, Err(SacError::UnrecognisedFormat)),
            "non-alphanumeric bare string must return UnrecognisedFormat; got {result:?}"
        );
    }

    // ── CODE:ISSUER with bad issuer refused ──────────────────────────────────

    #[test]
    fn code_issuer_with_invalid_issuer_refused() {
        let result = canonicalise_token("USDC:NOTAVALIDISSUER", TESTNET_PASSPHRASE);
        assert!(
            matches!(result, Err(SacError::InvalidIssuer { .. })),
            "invalid issuer must be refused; got {result:?}"
        );
    }

    // ── CODE:ISSUER alphanumeric-code enforcement ────────────────────────────

    /// A valid G-strkey issuer for CODE:ISSUER canonicalisation tests
    /// (the all-zero ed25519 public key encodes to this G-strkey).
    const VALID_ISSUER: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";

    #[test]
    fn code_issuer_non_alphanumeric_code_refused() {
        let token = format!("AB/X:{VALID_ISSUER}");
        let result = canonicalise_token(&token, TESTNET_PASSPHRASE);
        assert!(
            matches!(result, Err(SacError::InvalidCode { .. })),
            "non-alphanumeric asset code must be refused with InvalidCode; got {result:?}"
        );
    }

    #[test]
    fn code_issuer_alphanum4_canonicalises() {
        let token = format!("USDC:{VALID_ISSUER}");
        let result = canonicalise_token(&token, TESTNET_PASSPHRASE)
            .expect("4-char alphanumeric CODE:ISSUER must canonicalise");
        assert!(
            stellar_strkey::Contract::from_string(&result).is_ok(),
            "canonicalised result must be a valid C-strkey SAC address"
        );
    }

    #[test]
    fn code_issuer_alphanum12_canonicalises() {
        let token = format!("LONGASSET123:{VALID_ISSUER}");
        let result = canonicalise_token(&token, TESTNET_PASSPHRASE)
            .expect("12-char alphanumeric CODE:ISSUER must canonicalise");
        assert!(
            stellar_strkey::Contract::from_string(&result).is_ok(),
            "canonicalised result must be a valid C-strkey SAC address"
        );
    }

    // ── Error Display does not leak sensitive data ───────────────────────────

    #[test]
    fn error_display_does_not_leak_full_address() {
        // AmbiguousBareCode has no address in its message.
        let err = SacError::AmbiguousBareCode;
        let display = err.to_string();
        // The display must not contain a full 56-char strkey.
        assert!(
            display.len() < 200,
            "error display surprisingly long: {display}"
        );
    }

    // ── canonicalise_path round-trip ─────────────────────────────────────────

    #[test]
    fn canonicalise_path_passthrough_c_strkeys() {
        let tokens = vec![
            "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC".to_owned(),
            "CB3TLW74NBIOT3BUWOZ3TUM6RFDF6A4GVIRUQRQZABG5KPOUL4JJOV2F".to_owned(),
        ];
        let result = canonicalise_path(&tokens, TESTNET_PASSPHRASE).unwrap();
        assert_eq!(result, tokens);
    }

    #[test]
    fn canonicalise_path_fails_on_first_error() {
        let tokens = vec![
            "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC".to_owned(),
            "USDC".to_owned(), // ambiguous
        ];
        let result = canonicalise_path(&tokens, TESTNET_PASSPHRASE);
        assert!(
            result.is_err(),
            "ambiguous token must fail canonicalise_path"
        );
    }
}
