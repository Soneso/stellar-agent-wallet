//! Canonical classic payment destinations.
//!
//! A classic `Payment`, `PathPaymentStrictReceive`, or `PathPaymentStrictSend`
//! operation pays a `MuxedAccount`: a G account, or an M address that names a
//! G account and a 64-bit ID.
//! [`PaymentAccount`](crate::payment_accounts::PaymentAccount) accepts exactly
//! those two forms in their canonical spelling, so equal destinations compare
//! as equal text.

use stellar_strkey::{Strkey, ed25519};

use crate::error::{ValidationError, WalletError};

/// A checksum-valid G account or M address in canonical spelling.
///
/// An M address keeps its complete text and its ID, including ID zero, so it
/// stays distinct from its base G account.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::payment_accounts::PaymentAccount;
///
/// let base = "GAAACAQDAQCQMBYIBEFAWDANBYHRAEISCMKBKFQXDAMRUGY4DUPB7JZX";
/// let muxed = "MAAACAQDAQCQMBYIBEFAWDANBYHRAEISCMKBKFQXDAMRUGY4DUPB6AAAAAAAAAAAABEJ6";
/// let account = PaymentAccount::parse(muxed)?;
/// assert_eq!(account.canonical(), muxed);
/// assert_eq!(account.base_account(), base);
/// assert_eq!(account.muxed_id(), Some(0));
/// assert!(PaymentAccount::parse(base)?.muxed_id().is_none());
/// # Ok::<(), stellar_agent_core::WalletError>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentAccount {
    canonical: String,
    base_account: String,
    ed25519: [u8; 32],
    muxed_id: Option<u64>,
}

impl PaymentAccount {
    /// Parses a canonical, checksum-valid G account or M address.
    ///
    /// # Errors
    ///
    /// Returns `validation.address_invalid` for any other text: a C or W
    /// address, another strkey type, a bad checksum, surrounding whitespace,
    /// or a spelling that re-encodes differently. The error never contains
    /// the rejected text.
    pub fn parse(address: &str) -> Result<Self, WalletError> {
        let invalid =
            || WalletError::from(ValidationError::address_argument("payment destination"));
        let strkey = Strkey::from_string(address).map_err(|_| invalid())?;
        let (ed25519, muxed_id) = match &strkey {
            Strkey::PublicKeyEd25519(key) => (key.0, None),
            Strkey::MuxedAccountEd25519(muxed) => (muxed.ed25519, Some(muxed.id)),
            Strkey::PreAuthTx(_)
            | Strkey::HashX(_)
            | Strkey::SignedPayloadEd25519(_)
            | Strkey::Contract(_)
            | Strkey::LiquidityPool(_)
            | Strkey::ClaimableBalance(_)
            | Strkey::MuxedContract(_) => return Err(invalid()),
        };
        // This check is defense in depth: the strkey decoder refuses other
        // spellings, and re-encoding keeps one spelling if a decoder admits more.
        if strkey.to_string().as_str() != address {
            return Err(invalid());
        }
        Ok(Self {
            canonical: address.to_owned(),
            base_account: ed25519::PublicKey(ed25519).to_string().as_str().to_owned(),
            ed25519,
            muxed_id,
        })
    }

    /// Returns the complete destination: the G account or the M address.
    #[must_use]
    pub fn canonical(&self) -> &str {
        &self.canonical
    }

    /// Returns the canonical G account that holds the destination's balance.
    #[must_use]
    pub fn base_account(&self) -> &str {
        &self.base_account
    }

    /// Returns the M address's ID, or `None` for a G account.
    ///
    /// An M address with ID zero returns `Some(0)`.
    #[must_use]
    pub fn muxed_id(&self) -> Option<u64> {
        self.muxed_id
    }

    /// Returns the destination as the XDR `MuxedAccount` a payment carries.
    #[must_use]
    pub fn to_muxed_account(&self) -> stellar_xdr::MuxedAccount {
        let ed25519 = stellar_xdr::Uint256(self.ed25519);
        match self.muxed_id {
            None => stellar_xdr::MuxedAccount::Ed25519(ed25519),
            Some(id) => {
                stellar_xdr::MuxedAccount::MuxedEd25519(stellar_xdr::MuxedAccountMed25519 {
                    id,
                    ed25519,
                })
            }
        }
    }

    /// Returns the base G account as the XDR `AccountId` a plain account
    /// field carries.
    #[must_use]
    pub fn base_account_id(&self) -> stellar_xdr::AccountId {
        stellar_xdr::AccountId(stellar_xdr::PublicKey::PublicKeyTypeEd25519(
            stellar_xdr::Uint256(self.ed25519),
        ))
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test-only; panics acceptable in unit tests"
)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [7; 32];

    fn g() -> String {
        ed25519::PublicKey(KEY).to_string().as_str().to_owned()
    }

    fn m(id: u64) -> String {
        ed25519::MuxedAccount { ed25519: KEY, id }
            .to_string()
            .as_str()
            .to_owned()
    }

    #[test]
    fn g_and_m_round_trip_through_parsing_and_xdr() {
        for (text, id) in [(g(), None), (m(0), Some(0)), (m(u64::MAX), Some(u64::MAX))] {
            let account = PaymentAccount::parse(&text).unwrap();
            assert_eq!(account.canonical(), text);
            assert_eq!(account.base_account(), g());
            assert_eq!(account.muxed_id(), id, "{text}");
            let xdr = account.to_muxed_account();
            let expected = match id {
                None => stellar_xdr::MuxedAccount::Ed25519(stellar_xdr::Uint256(KEY)),
                Some(id) => {
                    stellar_xdr::MuxedAccount::MuxedEd25519(stellar_xdr::MuxedAccountMed25519 {
                        id,
                        ed25519: stellar_xdr::Uint256(KEY),
                    })
                }
            };
            assert_eq!(xdr, expected, "{text}");
            // The XDR display renders the complete destination again.
            assert_eq!(xdr.to_string(), text);
        }
    }

    #[test]
    fn base_account_id_is_the_base_key_for_g_and_m() {
        let expected = stellar_xdr::AccountId(stellar_xdr::PublicKey::PublicKeyTypeEd25519(
            stellar_xdr::Uint256(KEY),
        ));
        for text in [g(), m(0), m(17), m(u64::MAX)] {
            let account = PaymentAccount::parse(&text).unwrap();
            assert_eq!(account.base_account_id(), expected, "{text}");
            assert_eq!(account.base_account_id().to_string(), g(), "{text}");
        }
    }

    #[test]
    fn m_with_id_zero_stays_distinct_from_its_base_account() {
        let base = PaymentAccount::parse(&g()).unwrap();
        let zero = PaymentAccount::parse(&m(0)).unwrap();
        assert_ne!(base, zero);
        assert_eq!(zero.muxed_id(), Some(0));
        assert_ne!(base.to_muxed_account(), zero.to_muxed_account());
    }

    /// Replaces the character at `index` with another base32 character.
    fn corrupt(text: &str, index: usize) -> String {
        let mut bytes = text.as_bytes().to_vec();
        bytes[index] = if bytes[index] == b'A' { b'B' } else { b'A' };
        String::from_utf8(bytes).unwrap()
    }

    #[test]
    fn corrupt_checksums_refuse() {
        for text in [g(), m(0), m(u64::MAX)] {
            for index in [1, 20, text.len() - 2] {
                let corrupted = corrupt(&text, index);
                let err = PaymentAccount::parse(&corrupted).unwrap_err();
                assert_eq!(err.code(), "validation.address_invalid", "{corrupted}");
                assert!(!err.to_string().contains(&corrupted), "{err}");
            }
        }
    }

    #[test]
    fn noncanonical_spellings_refuse() {
        let muxed = m(u64::MAX);
        let mut padded_bit = muxed.clone().into_bytes();
        // The last base32 character of an M address carries one unused bit.
        let last = padded_bit.len() - 1;
        padded_bit[last] = flip_low_bit(padded_bit[last]);
        let padded_bit = String::from_utf8(padded_bit).unwrap();
        for text in [
            format!(" {}", g()),
            format!("{} ", g()),
            format!("{}\n", muxed),
            g().to_lowercase(),
            muxed.to_lowercase(),
            format!("{}=", g()),
            padded_bit,
            String::new(),
        ] {
            assert!(PaymentAccount::parse(&text).is_err(), "{text:?}");
        }
    }

    /// Flips the low bit of a base32 character's value.
    fn flip_low_bit(c: u8) -> u8 {
        const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        let value = ALPHABET.iter().position(|&a| a == c).unwrap();
        ALPHABET[value ^ 1]
    }

    #[test]
    fn other_address_kinds_refuse() {
        let contract = stellar_strkey::Contract(KEY)
            .to_string()
            .as_str()
            .to_owned();
        let muxed_contract = stellar_strkey::MuxedContract {
            contract_id: KEY,
            id: 1,
        }
        .to_string()
        .as_str()
        .to_owned();
        let pre_auth = stellar_strkey::PreAuthTx(KEY)
            .to_string()
            .as_str()
            .to_owned();
        let hash_x = stellar_strkey::HashX(KEY).to_string().as_str().to_owned();
        for text in [contract, muxed_contract, pre_auth, hash_x] {
            let err = PaymentAccount::parse(&text).unwrap_err();
            assert_eq!(err.code(), "validation.address_invalid", "{text}");
        }
    }
}
