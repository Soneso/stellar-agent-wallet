//! Memo parsing from optional structured fields to [`stellar_xdr::Memo`].
//!
//! This module provides [`parse_memo_fields`], the single canonical parser
//! for the four Stellar memo variants as they are expressed in user-facing
//! interfaces (CLI arguments, MCP tool arguments).  It is the shared
//! implementation used by the `stellar_pay` MCP tool and the CLI pay command.
//!
//! # Memo field mutual exclusivity
//!
//! At most ONE of the four memo fields may be `Some` at a time.  The CLI
//! enforces this via a `clap` `ArgGroup`; the MCP handler validates it
//! programmatically using this helper's `MemoMutuallyExclusive` error variant.
//!
//! # Unit label scope
//!
//! Memo parsing is asset-agnostic: callers validate asset / amount unit labels
//! before invoking this module and pass only the selected memo fields here.
//! A non-native payment may carry `amount = "10 USDC"` in the surrounding
//! command context while still using `memo_text = "invoice-42"` or a
//! 64-character memo hash parsed by this helper.
//!
//! Memo construction is a prerequisite for the `memo_present` flag passed to
//! [`crate::sep29::check_memo_required`].

use stellar_agent_core::error::{ValidationError, WalletError};
use stellar_xdr::{Hash, Memo, StringM};

/// Parses up to four optional memo fields into a single [`Memo`].
///
/// At most one of the four arguments may be `Some`; providing more than one
/// returns [`WalletError::Validation`] wrapping
/// [`ValidationError::MemoMutuallyExclusive`].  When all are `None`, returns
/// [`Memo::None`].  `memo_text = Some("")` is treated the same as `None`:
/// an empty text memo represents operator omission and must not make the
/// SEP-29 `memo_present` check pass.
///
/// # Errors
///
/// - [`WalletError::Validation`] wrapping [`ValidationError::MemoMutuallyExclusive`]
///   if more than one memo variant is supplied.
/// - [`WalletError::Validation`] wrapping [`ValidationError::MemoInvalidType`]
///   when:
///   - `memo_text` exceeds 28 bytes.
///   - `memo_text` cannot be converted to the XDR `StringM<28>` type.
///   - `memo_hash_hex` or `memo_return_hex` is not exactly 64 hex characters.
///
/// # Examples
///
/// ```
/// use stellar_agent_network::memo::parse_memo_fields;
/// use stellar_xdr::Memo;
///
/// let memo = parse_memo_fields(Some("hello"), None, None, None).unwrap();
/// assert!(matches!(memo, Memo::Text(_)));
///
/// let memo = parse_memo_fields(None, Some(42u64), None, None).unwrap();
/// assert!(matches!(memo, Memo::Id(42)));
///
/// let memo = parse_memo_fields(None, None, None, None).unwrap();
/// assert!(matches!(memo, Memo::None));
/// ```
pub fn parse_memo_fields(
    memo_text: Option<&str>,
    memo_id: Option<u64>,
    memo_hash_hex: Option<&str>,
    memo_return_hex: Option<&str>,
) -> Result<Memo, WalletError> {
    let memo_text = memo_text.filter(|text| !text.is_empty());

    // Count how many variants are set; reject anything > 1.
    let set_count = [
        memo_text.is_some(),
        memo_id.is_some(),
        memo_hash_hex.is_some(),
        memo_return_hex.is_some(),
    ]
    .iter()
    .filter(|&&b| b)
    .count();

    if set_count > 1 {
        return Err(WalletError::Validation(
            ValidationError::MemoMutuallyExclusive,
        ));
    }

    if let Some(text) = memo_text {
        let bytes = text.as_bytes();
        if bytes.len() > 28 {
            return Err(WalletError::Validation(ValidationError::MemoInvalidType {
                memo_type: format!("TEXT (length {} exceeds 28-byte maximum)", bytes.len()),
            }));
        }
        let string_m: StringM<28> = bytes.to_vec().try_into().map_err(|_| {
            WalletError::Validation(ValidationError::MemoInvalidType {
                memo_type: "TEXT (XDR StringM<28> conversion failed)".to_owned(),
            })
        })?;
        return Ok(Memo::Text(string_m));
    }

    if let Some(id) = memo_id {
        return Ok(Memo::Id(id));
    }

    if let Some(hex_str) = memo_hash_hex {
        let bytes = decode_32_hex_bytes(hex_str, "HASH")?;
        return Ok(Memo::Hash(Hash(bytes)));
    }

    if let Some(hex_str) = memo_return_hex {
        let bytes = decode_32_hex_bytes(hex_str, "RETURN")?;
        return Ok(Memo::Return(Hash(bytes)));
    }

    Ok(Memo::None)
}

/// Decodes a 64-hex-character string to a 32-byte array.
///
/// Returns [`WalletError::Validation`] wrapping [`ValidationError::MemoInvalidType`]
/// if `hex_str` is not exactly 64 ASCII hex characters.
///
/// This is a crate-internal helper; callers outside this module use
/// [`parse_memo_fields`] instead.
///
/// # Errors
///
/// - [`WalletError::Validation`] if the input length is not 64 or contains
///   non-hex characters.
pub(crate) fn decode_32_hex_bytes(hex_str: &str, memo_type: &str) -> Result<[u8; 32], WalletError> {
    if hex_str.len() != 64 || !hex_str.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(WalletError::Validation(ValidationError::MemoInvalidType {
            memo_type: format!("{memo_type} (must be exactly 64 hex characters)"),
        }));
    }

    let mut bytes = [0u8; 32];
    for (i, chunk) in hex_str.as_bytes().chunks(2).enumerate() {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        bytes[i] = (hi << 4) | lo;
    }
    Ok(bytes)
}

fn hex_nibble(b: u8) -> Result<u8, WalletError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => {
            // Redaction invariant: this field MUST NOT contain raw key/seed/signature
            // bytes; do not echo attacker-supplied memo bytes into the error
            // envelope — the raw byte value of an invalid hex character could
            // be an encoding of sensitive input.
            Err(WalletError::Validation(ValidationError::MemoInvalidType {
                memo_type: "invalid hex character (non-hex byte present)".to_owned(),
            }))
        }
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

    use serde_json::json;
    use stellar_agent_test_support::EchoIdResponder;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer};

    use super::*;
    use crate::StellarRpcClient;
    use stellar_xdr::{Limits, WriteXdr};

    const SEP29_TEST_ACCOUNT: &str = "GBZXN7PIRZGNMHGA7MUUUF4GWPY5AYPV6LY4UV2GL6VJGIQRXFDNMADI";

    fn data_ledger_key_xdr(account_address: &str, data_key: &str) -> String {
        use stellar_xdr::{
            AccountId, LedgerKey, LedgerKeyData, PublicKey, String64, StringM, Uint256,
        };

        let pk_bytes = stellar_strkey::ed25519::PublicKey::from_string(account_address)
            .expect("valid address")
            .0;
        let xdr_account_id = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(pk_bytes)));
        let data_name = String64::from(
            StringM::<64>::try_from(data_key.as_bytes().to_vec()).expect("key fits in 64 bytes"),
        );
        LedgerKey::Data(LedgerKeyData {
            account_id: xdr_account_id,
            data_name,
        })
        .to_xdr_base64(Limits::none())
        .expect("valid XDR")
    }

    fn data_entry_xdr(account_address: &str, data_key: &str, value: &[u8]) -> String {
        use stellar_xdr::{
            AccountId, BytesM, DataEntry, DataEntryExt, DataValue, LedgerEntryData, PublicKey,
            String64, StringM, Uint256,
        };

        let pk_bytes = stellar_strkey::ed25519::PublicKey::from_string(account_address)
            .expect("valid address")
            .0;
        let xdr_account_id = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(pk_bytes)));
        let data_name = String64::from(
            StringM::<64>::try_from(data_key.as_bytes().to_vec()).expect("key fits in 64 bytes"),
        );
        let data_value = DataValue(BytesM::<64>::try_from(value.to_vec()).expect("value fits"));
        let entry = DataEntry {
            account_id: xdr_account_id,
            data_name,
            data_value,
            ext: DataEntryExt::V0,
        };
        LedgerEntryData::Data(entry)
            .to_xdr_base64(Limits::none())
            .expect("valid XDR")
    }

    #[test]
    fn memo_none_when_all_none() {
        let m = parse_memo_fields(None, None, None, None).unwrap();
        assert!(matches!(m, Memo::None));
    }

    #[test]
    fn memo_text_empty_coerces_to_none_with_identical_xdr() {
        let empty = parse_memo_fields(Some(""), None, None, None).unwrap();
        let none = parse_memo_fields(None, None, None, None).unwrap();

        assert!(matches!(empty, Memo::None));
        assert_eq!(
            empty.to_xdr(Limits::none()).unwrap(),
            none.to_xdr(Limits::none()).unwrap()
        );
    }

    #[tokio::test]
    async fn memo_text_empty_does_not_satisfy_sep29_memo_present() {
        let mock_server = MockServer::start().await;
        let key_xdr = data_ledger_key_xdr(SEP29_TEST_ACCOUNT, "config.memo_required");
        let entry_xdr = data_entry_xdr(SEP29_TEST_ACCOUNT, "config.memo_required", b"1");
        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(EchoIdResponder::new(json!({
                "entries": [{
                    "key": key_xdr,
                    "xdr": entry_xdr,
                    "lastModifiedLedgerSeq": 12345
                }],
                "latestLedger": 99999
            })))
            .mount(&mock_server)
            .await;
        let client = StellarRpcClient::new(&mock_server.uri()).expect("mock URL must be valid");

        let empty = parse_memo_fields(Some(""), None, None, None).unwrap();
        let none = parse_memo_fields(None, None, None, None).unwrap();

        for memo in [empty, none] {
            let memo_present = !matches!(memo, Memo::None);
            assert!(!memo_present);

            let err =
                crate::sep29::check_memo_required(&client, None, SEP29_TEST_ACCOUNT, memo_present)
                    .await
                    .expect_err("memo-required account must reject absent memo");
            assert!(
                matches!(
                    err,
                    WalletError::Validation(ValidationError::MemoRequired { .. })
                ),
                "empty memo_text must fail the real SEP-29 memo-present gate as None: {err:?}"
            );
            assert_eq!(err.code(), "validation.memo_required");
        }
    }

    #[test]
    fn memo_text_valid() {
        let m = parse_memo_fields(Some("hello"), None, None, None).unwrap();
        assert!(matches!(m, Memo::Text(_)));
    }

    #[test]
    fn memo_text_exactly_28_bytes() {
        let s = "a".repeat(28);
        let m = parse_memo_fields(Some(&s), None, None, None).unwrap();
        assert!(matches!(m, Memo::Text(_)));
    }

    #[test]
    fn memo_text_29_bytes_fails() {
        let s = "a".repeat(29);
        let result = parse_memo_fields(Some(&s), None, None, None);
        assert!(result.is_err());
        let code = result.unwrap_err().code().to_owned();
        assert_eq!(code, "validation.memo_invalid_type");
    }

    #[test]
    fn memo_text_multibyte_at_28_byte_boundary() {
        let exactly_28_bytes = "É".repeat(14);
        assert_eq!(exactly_28_bytes.len(), 28);
        let m = parse_memo_fields(Some(&exactly_28_bytes), None, None, None).unwrap();
        assert!(matches!(m, Memo::Text(_)));

        let too_long = format!("{exactly_28_bytes}a");
        assert_eq!(too_long.len(), 29);
        let result = parse_memo_fields(Some(&too_long), None, None, None);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), "validation.memo_invalid_type");
    }

    #[test]
    fn memo_id() {
        let m = parse_memo_fields(None, Some(42), None, None).unwrap();
        assert!(matches!(m, Memo::Id(42)));
    }

    #[test]
    fn memo_hash_valid() {
        let hex = "0011223344556677889900aabbccddeeff0011223344556677889900aabbccdd";
        let m = parse_memo_fields(None, None, Some(hex), None).unwrap();
        assert!(matches!(m, Memo::Hash(_)));
    }

    #[test]
    fn memo_return_valid() {
        let hex = "0011223344556677889900aabbccddeeff0011223344556677889900aabbccdd";
        let m = parse_memo_fields(None, None, None, Some(hex)).unwrap();
        assert!(matches!(m, Memo::Return(_)));
    }

    #[test]
    fn memo_hash_wrong_length_fails() {
        let result = parse_memo_fields(None, None, Some("0011"), None);
        assert!(result.is_err());
    }

    #[test]
    fn memo_hash_non_hex_fails() {
        let hex = "GG11223344556677889900aabbccddeeff0011223344556677889900aabbccdd";
        let result = parse_memo_fields(None, None, Some(hex), None);
        assert!(result.is_err());
    }

    #[test]
    fn memo_two_variants_fails_with_mutually_exclusive() {
        let result = parse_memo_fields(Some("hello"), Some(42), None, None);
        assert!(result.is_err());
        let code = result.unwrap_err().code().to_owned();
        assert_eq!(code, "validation.memo_mutually_exclusive");
    }

    #[test]
    fn memo_three_variants_fails() {
        let hex = "0011223344556677889900aabbccddeeff0011223344556677889900aabbccdd";
        let result = parse_memo_fields(Some("text"), Some(1), Some(hex), None);
        assert!(result.is_err());
    }

    #[test]
    fn parse_memo_fields_rejects_all_four_set() {
        let hex = "0011223344556677889900aabbccddeeff0011223344556677889900aabbccdd";
        let result = parse_memo_fields(Some("text"), Some(1), Some(hex), Some(hex));
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().code(),
            "validation.memo_mutually_exclusive"
        );
    }

    #[test]
    fn decode_32_hex_valid_round_trip() {
        let hex = "0011223344556677889900aabbccddeeff0011223344556677889900aabbccdd";
        let bytes = decode_32_hex_bytes(hex, "HASH").unwrap();
        assert_eq!(bytes[0], 0x00);
        assert_eq!(bytes[1], 0x11);
        assert_eq!(bytes[31], 0xdd);
    }

    #[test]
    fn decode_32_hex_uppercase_lowercase_byte_equality() {
        let lower = "0011223344556677889900aabbccddeeff0011223344556677889900aabbccdd";
        let upper = lower.to_ascii_uppercase();

        assert_eq!(
            decode_32_hex_bytes(lower, "HASH").unwrap(),
            decode_32_hex_bytes(&upper, "RETURN").unwrap()
        );
    }

    #[test]
    fn decode_32_hex_too_short_fails() {
        assert!(decode_32_hex_bytes("0011", "HASH").is_err());
    }

    #[test]
    fn decode_32_hex_too_long_fails() {
        let hex = "0".repeat(66);
        assert!(decode_32_hex_bytes(&hex, "HASH").is_err());
    }
}
