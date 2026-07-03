//! Fetching `ClaimableBalanceEntry` and trustline state from Stellar RPC.
//!
//! Both fetches go through [`stellar_agent_network::StellarRpcClient::get_ledger_entries`],
//! the wallet's single RPC read boundary — there is no dedicated
//! `getClaimableBalance` or `getTrustline` endpoint. All entry XDR returned
//! by `getLedgerEntries` is decoded with
//! [`stellar_agent_xdr_limits::untrusted_decode_limits`], bounding both
//! recursion depth and allocation size against a malformed or adversarial
//! RPC response.
//!
//! # `getLedgerEntries` returns `LedgerEntryData`, not `LedgerEntry`
//!
//! The `xdr` field of each `getLedgerEntries` result decodes to
//! `LedgerEntryData`, not the enclosing `LedgerEntry` (which additionally
//! carries `last_modified_ledger_seq` and an `ext` union). Sponsorship
//! (`LedgerEntryExtensionV1.sponsoring_id`) lives on that outer `ext`, so it
//! is not observable through this RPC call — see the crate-level
//! documentation for why [`crate::preview::ClaimPreview`] carries no
//! `sponsor` field.

use stellar_agent_core::error::{ProtocolError, ValidationError, WalletError};
use stellar_agent_network::StellarRpcClient;
use stellar_xdr::{
    AccountId, AlphaNum4, AlphaNum12, AssetCode4, AssetCode12, ClaimableBalanceEntry,
    ClaimableBalanceId, Hash, LedgerEntryData, LedgerKey, LedgerKeyClaimableBalance,
    LedgerKeyTrustLine, PublicKey, ReadXdr, TrustLineAsset, Uint256,
};

use crate::error::ClaimError;
use crate::id::BalanceId;

/// Fetches the `ClaimableBalanceEntry` for `id` via `getLedgerEntries`.
///
/// # Errors
///
/// - [`ClaimError::BalanceNotFound`] when no entry exists for `id`. This is
///   the expected outcome when the balance has already been claimed — the
///   entry is deleted from the ledger on claim, not marked claimed.
/// - [`ClaimError::Wallet`] wrapping the network error on RPC failure, or a
///   `protocol.xdr_codec_failed` error if the response XDR cannot be decoded.
pub async fn fetch_claimable_balance_entry(
    client: &StellarRpcClient,
    id: &BalanceId,
) -> Result<ClaimableBalanceEntry, ClaimError> {
    let key = LedgerKey::ClaimableBalance(LedgerKeyClaimableBalance {
        balance_id: ClaimableBalanceId::ClaimableBalanceIdTypeV0(Hash(id.hash())),
    });

    let response = client
        .get_ledger_entries(std::slice::from_ref(&key))
        .await
        .map_err(WalletError::Network)?;

    for e in response.entries.unwrap_or_default() {
        let led = LedgerEntryData::from_xdr_base64(
            &e.xdr,
            stellar_agent_xdr_limits::untrusted_decode_limits(e.xdr.len()),
        )
        .map_err(|err| {
            WalletError::Protocol(ProtocolError::XdrCodecFailed {
                detail: format!("failed to decode claimable-balance entry XDR: {err}"),
            })
        })?;
        if let LedgerEntryData::ClaimableBalance(cbe) = led {
            return Ok(cbe);
        }
    }

    Err(ClaimError::BalanceNotFound)
}

/// The claiming account's trustline state for a non-native asset, as needed
/// by [`crate::preview::check_trustline`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustlineState {
    /// Whether a trustline exists at all.
    pub exists: bool,
    /// Whether the issuer has authorized this trustline
    /// (`AUTHORIZED_FLAG`). Meaningless when `exists` is `false`.
    pub authorized: bool,
    /// The trustline's limit, in stroops. Meaningless when `exists` is
    /// `false`.
    pub limit: i64,
    /// The trustline's current balance, in stroops. Meaningless when
    /// `exists` is `false`.
    pub balance: i64,
}

impl TrustlineState {
    /// The state representing no trustline at all.
    const ABSENT: Self = Self {
        exists: false,
        authorized: false,
        limit: 0,
        balance: 0,
    };
}

/// The `AUTHORIZED_FLAG` bit (`1`) of the `TrustLineFlags` XDR enum, applied
/// to `TrustLineEntry.flags`.
const AUTHORIZED_FLAG: u32 = 1;

/// Fetches the trustline state for `(code, issuer)` on `account` via
/// `getLedgerEntries`.
///
/// Returns a [`TrustlineState`] with `exists: false` (not an error) when no
/// trustline exists — callers combine this with
/// [`crate::preview::check_trustline`] to produce the specific
/// `claim.trustline_*` refusal.
///
/// # Errors
///
/// - [`ClaimError::Wallet`] wrapping [`ValidationError::AddressInvalid`] if
///   `account` or `issuer` is not a valid G-strkey, or
///   [`ValidationError::AssetInvalid`] if `code` is empty or exceeds 12
///   bytes.
/// - [`ClaimError::Wallet`] wrapping the network error on RPC failure, or a
///   `protocol.xdr_codec_failed` error if the response XDR cannot be decoded.
pub async fn fetch_trustline_state(
    client: &StellarRpcClient,
    account: &str,
    code: &str,
    issuer: &str,
) -> Result<TrustlineState, ClaimError> {
    let account_pk = stellar_strkey::ed25519::PublicKey::from_string(account).map_err(|_| {
        WalletError::Validation(ValidationError::AddressInvalid {
            input: account.to_owned(),
        })
    })?;
    let account_id = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(account_pk.0)));

    let asset = code_issuer_to_trust_line_asset(code, issuer)?;

    let key = LedgerKey::Trustline(LedgerKeyTrustLine { account_id, asset });

    let response = client
        .get_ledger_entries(std::slice::from_ref(&key))
        .await
        .map_err(WalletError::Network)?;

    for e in response.entries.unwrap_or_default() {
        let led = LedgerEntryData::from_xdr_base64(
            &e.xdr,
            stellar_agent_xdr_limits::untrusted_decode_limits(e.xdr.len()),
        )
        .map_err(|err| {
            WalletError::Protocol(ProtocolError::XdrCodecFailed {
                detail: format!("failed to decode trustline entry XDR: {err}"),
            })
        })?;
        if let LedgerEntryData::Trustline(tl) = led {
            return Ok(TrustlineState {
                exists: true,
                authorized: tl.flags & AUTHORIZED_FLAG != 0,
                limit: tl.limit,
                balance: tl.balance,
            });
        }
    }

    Ok(TrustlineState::ABSENT)
}

/// Converts a `(code, issuer)` pair to a `stellar_xdr::TrustLineAsset` for
/// `LedgerKey::Trustline` construction.
///
/// Duplicates the code-length-based `AlphaNum4` / `AlphaNum12` discrimination
/// that `stellar_agent_network::builder::Asset::to_xdr_trust_line_asset`
/// applies; that method is `pub(crate)` to the network crate and not
/// reusable here, so this crate constructs the XDR asset directly rather
/// than adding a cross-crate dependency for one small conversion.
fn code_issuer_to_trust_line_asset(code: &str, issuer: &str) -> Result<TrustLineAsset, ClaimError> {
    let pk = stellar_strkey::ed25519::PublicKey::from_string(issuer).map_err(|_| {
        WalletError::Validation(ValidationError::AddressInvalid {
            input: issuer.to_owned(),
        })
    })?;
    let xdr_issuer = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(pk.0)));

    let code_bytes = code.as_bytes();
    if code_bytes.is_empty() || code_bytes.len() > 12 {
        return Err(ClaimError::Wallet(WalletError::Validation(
            ValidationError::AssetInvalid {
                input: code.to_owned(),
            },
        )));
    }

    if code_bytes.len() <= 4 {
        let mut arr = [0u8; 4];
        arr[..code_bytes.len()].copy_from_slice(code_bytes);
        Ok(TrustLineAsset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4(arr),
            issuer: xdr_issuer,
        }))
    } else {
        let mut arr = [0u8; 12];
        arr[..code_bytes.len()].copy_from_slice(code_bytes);
        Ok(TrustLineAsset::CreditAlphanum12(AlphaNum12 {
            asset_code: AssetCode12(arr),
            issuer: xdr_issuer,
        }))
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only"
    )]

    use serde_json::json;
    use stellar_agent_test_support::EchoIdResponder;
    use stellar_xdr::{
        AccountId as XdrAccountId, Asset, ClaimPredicate,
        ClaimableBalanceEntry as XdrClaimableBalanceEntry, ClaimableBalanceEntryExt, Claimant,
        ClaimantV0, Limits, PublicKey as XdrPublicKey, TrustLineEntry, TrustLineEntryExt,
        Uint256 as XdrUint256, VecM, WriteXdr,
    };
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer};

    use super::*;

    const CLAIMANT_G: &str = "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY";
    const ISSUER_G: &str = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";

    fn g_account_id(g: &str) -> XdrAccountId {
        let pk = stellar_strkey::ed25519::PublicKey::from_string(g).unwrap();
        XdrAccountId(XdrPublicKey::PublicKeyTypeEd25519(XdrUint256(pk.0)))
    }

    fn ledger_key_xdr(key: &LedgerKey) -> String {
        key.to_xdr_base64(Limits::none()).unwrap()
    }

    fn claimable_balance_key_xdr(id: &BalanceId) -> String {
        let key = LedgerKey::ClaimableBalance(LedgerKeyClaimableBalance {
            balance_id: ClaimableBalanceId::ClaimableBalanceIdTypeV0(Hash(id.hash())),
        });
        ledger_key_xdr(&key)
    }

    // ─── fetch_claimable_balance_entry: hit ───────────────────────────────

    #[tokio::test]
    async fn fetch_entry_hit_returns_entry() {
        let id = BalanceId::parse(&"ab".repeat(32)).unwrap();
        let key_xdr = claimable_balance_key_xdr(&id);

        let entry = XdrClaimableBalanceEntry {
            balance_id: ClaimableBalanceId::ClaimableBalanceIdTypeV0(Hash(id.hash())),
            claimants: VecM::try_from(vec![Claimant::ClaimantTypeV0(ClaimantV0 {
                destination: g_account_id(CLAIMANT_G),
                predicate: ClaimPredicate::Unconditional,
            })])
            .unwrap(),
            asset: Asset::Native,
            amount: 100_000_000,
            ext: ClaimableBalanceEntryExt::V0,
        };
        let entry_xdr = LedgerEntryData::ClaimableBalance(entry.clone())
            .to_xdr_base64(Limits::none())
            .unwrap();

        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(EchoIdResponder::new(json!({
                "entries": [
                    {"key": key_xdr, "xdr": entry_xdr, "lastModifiedLedgerSeq": 1}
                ],
                "latestLedger": 1
            })))
            .mount(&mock_server)
            .await;

        let client = StellarRpcClient::new(&mock_server.uri()).unwrap();
        let fetched = fetch_claimable_balance_entry(&client, &id).await.unwrap();
        assert_eq!(fetched.amount, 100_000_000);
        assert_eq!(fetched.claimants.len(), 1);
    }

    // ─── fetch_claimable_balance_entry: miss ──────────────────────────────

    #[tokio::test]
    async fn fetch_entry_miss_returns_balance_not_found() {
        let id = BalanceId::parse(&"cd".repeat(32)).unwrap();

        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(EchoIdResponder::new(json!({
                "entries": [],
                "latestLedger": 1
            })))
            .mount(&mock_server)
            .await;

        let client = StellarRpcClient::new(&mock_server.uri()).unwrap();
        let err = fetch_claimable_balance_entry(&client, &id)
            .await
            .expect_err("empty entries must be BalanceNotFound");
        assert_eq!(err.code(), "claim.balance_not_found");
    }

    // ─── fetch_claimable_balance_entry: garbage XDR ───────────────────────

    #[tokio::test]
    async fn fetch_entry_garbage_xdr_returns_wallet_error() {
        let id = BalanceId::parse(&"ef".repeat(32)).unwrap();
        let key_xdr = claimable_balance_key_xdr(&id);

        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(EchoIdResponder::new(json!({
                "entries": [
                    {"key": key_xdr, "xdr": "AAAA_NOT_VALID_XDR====", "lastModifiedLedgerSeq": 1}
                ],
                "latestLedger": 1
            })))
            .mount(&mock_server)
            .await;

        let client = StellarRpcClient::new(&mock_server.uri()).unwrap();
        let err = fetch_claimable_balance_entry(&client, &id)
            .await
            .expect_err("garbage XDR must be an error");
        assert_eq!(err.code(), "protocol.xdr_codec_failed");
    }

    // ─── fetch_trustline_state: hit ────────────────────────────────────────

    #[tokio::test]
    async fn fetch_trustline_hit_authorized() {
        let asset = code_issuer_to_trust_line_asset("USDC", ISSUER_G).unwrap();
        let key = LedgerKey::Trustline(LedgerKeyTrustLine {
            account_id: g_account_id(CLAIMANT_G),
            asset: asset.clone(),
        });
        let key_xdr = ledger_key_xdr(&key);

        let tl = TrustLineEntry {
            account_id: g_account_id(CLAIMANT_G),
            asset,
            balance: 10_000_000,
            limit: 100_000_000,
            flags: AUTHORIZED_FLAG,
            ext: TrustLineEntryExt::V0,
        };
        let tl_xdr = LedgerEntryData::Trustline(tl)
            .to_xdr_base64(Limits::none())
            .unwrap();

        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(EchoIdResponder::new(json!({
                "entries": [
                    {"key": key_xdr, "xdr": tl_xdr, "lastModifiedLedgerSeq": 1}
                ],
                "latestLedger": 1
            })))
            .mount(&mock_server)
            .await;

        let client = StellarRpcClient::new(&mock_server.uri()).unwrap();
        let state = fetch_trustline_state(&client, CLAIMANT_G, "USDC", ISSUER_G)
            .await
            .unwrap();
        assert!(state.exists);
        assert!(state.authorized);
        assert_eq!(state.limit, 100_000_000);
        assert_eq!(state.balance, 10_000_000);
    }

    #[tokio::test]
    async fn fetch_trustline_hit_not_authorized() {
        let asset = code_issuer_to_trust_line_asset("USDC", ISSUER_G).unwrap();
        let key = LedgerKey::Trustline(LedgerKeyTrustLine {
            account_id: g_account_id(CLAIMANT_G),
            asset: asset.clone(),
        });
        let key_xdr = ledger_key_xdr(&key);

        let tl = TrustLineEntry {
            account_id: g_account_id(CLAIMANT_G),
            asset,
            balance: 0,
            limit: 100_000_000,
            flags: 0,
            ext: TrustLineEntryExt::V0,
        };
        let tl_xdr = LedgerEntryData::Trustline(tl)
            .to_xdr_base64(Limits::none())
            .unwrap();

        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(EchoIdResponder::new(json!({
                "entries": [
                    {"key": key_xdr, "xdr": tl_xdr, "lastModifiedLedgerSeq": 1}
                ],
                "latestLedger": 1
            })))
            .mount(&mock_server)
            .await;

        let client = StellarRpcClient::new(&mock_server.uri()).unwrap();
        let state = fetch_trustline_state(&client, CLAIMANT_G, "USDC", ISSUER_G)
            .await
            .unwrap();
        assert!(state.exists);
        assert!(!state.authorized);
    }

    // ─── fetch_trustline_state: miss ───────────────────────────────────────

    #[tokio::test]
    async fn fetch_trustline_miss_returns_absent_state() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(EchoIdResponder::new(json!({
                "entries": [],
                "latestLedger": 1
            })))
            .mount(&mock_server)
            .await;

        let client = StellarRpcClient::new(&mock_server.uri()).unwrap();
        let state = fetch_trustline_state(&client, CLAIMANT_G, "USDC", ISSUER_G)
            .await
            .unwrap();
        assert!(!state.exists);
        assert!(!state.authorized);
        assert_eq!(state.limit, 0);
        assert_eq!(state.balance, 0);
    }

    // ─── fetch_trustline_state: invalid inputs ─────────────────────────────

    #[tokio::test]
    async fn fetch_trustline_invalid_account_returns_wallet_error() {
        let mock_server = MockServer::start().await;
        let client = StellarRpcClient::new(&mock_server.uri()).unwrap();
        let err = fetch_trustline_state(&client, "not-a-g-address", "USDC", ISSUER_G)
            .await
            .expect_err("invalid account must be rejected");
        assert_eq!(err.code(), "validation.address_invalid");
    }

    #[tokio::test]
    async fn fetch_trustline_empty_code_returns_wallet_error() {
        let mock_server = MockServer::start().await;
        let client = StellarRpcClient::new(&mock_server.uri()).unwrap();
        let err = fetch_trustline_state(&client, CLAIMANT_G, "", ISSUER_G)
            .await
            .expect_err("empty code must be rejected");
        assert_eq!(err.code(), "validation.asset_invalid");
    }

    #[tokio::test]
    async fn fetch_trustline_code_too_long_returns_wallet_error() {
        let mock_server = MockServer::start().await;
        let client = StellarRpcClient::new(&mock_server.uri()).unwrap();
        let err = fetch_trustline_state(&client, CLAIMANT_G, "TOOLONGASSETCODE", ISSUER_G)
            .await
            .expect_err("13-char code must be rejected");
        assert_eq!(err.code(), "validation.asset_invalid");
    }
}
