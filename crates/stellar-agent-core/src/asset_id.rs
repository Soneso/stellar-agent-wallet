//! Canonical identities for cross-check thresholds and ledger observations.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use stellar_xdr::{
    AccountId, AlphaNum4, AlphaNum12, Asset, AssetCode4, AssetCode12, ContractIdPreimage, Hash,
    HashIdPreimage, HashIdPreimageContractId, Limits, PublicKey, Uint256, WriteXdr,
};

use crate::amount::StellarAmount;
use crate::error::ValidationError;

/// A native asset, classic asset, or token contract, preserving asset-code case.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CanonicalAsset {
    /// Native XLM.
    Native,
    /// An issued classic asset.
    Classic {
        /// Case-sensitive asset code.
        code: String,
        /// Canonical issuer account address.
        issuer: String,
    },
    /// Canonical contract address.
    Contract(String),
}

/// A safe explanation of an invalid asset identity, without the rejected input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AssetIdError {
    /// Native thresholds belong in their dedicated field.
    #[error(
        "is the native asset, whose threshold is cross_check_threshold_stroops; remove the entry"
    )]
    Native,
    /// The key has no recognized identity form.
    #[error("is not CODE:ISSUER or a contract address (C...)")]
    Form,
    /// The code violates the classic asset alphabet or length.
    #[error("has an asset code that is not 1 to 12 ASCII letters and digits")]
    Code,
    /// The issuer is not a canonical G-strkey.
    #[error("has an issuer that is not a valid account address (G...)")]
    Issuer,
    /// The contract is not a canonical C-strkey.
    #[error("is not a valid contract address (C...)")]
    Contract,
}

impl CanonicalAsset {
    /// Parses a human amount using this asset's unit.
    ///
    /// Native `XLM` labels are case-insensitive for compatibility. Issued asset
    /// codes match exactly because Stellar asset codes are case-sensitive.
    ///
    /// # Errors
    /// Returns the amount parser's validation error, or
    /// [`ValidationError::AssetInvalid`] for a contract without a classic unit.
    pub fn parse_amount(&self, input: &str) -> Result<StellarAmount, ValidationError> {
        match self {
            Self::Native => StellarAmount::parse_with_unit(input),
            Self::Classic { code, .. } => StellarAmount::parse_with_unit_for(input, code),
            Self::Contract(_) => Err(ValidationError::AssetInvalid {
                input: self.to_string(),
            }),
        }
    }

    /// Parses a classic identity without trimming or changing code case.
    ///
    /// # Errors
    /// Returns a safe code or issuer defect.
    pub fn classic(code: &str, issuer: &str) -> Result<Self, AssetIdError> {
        if code.is_empty() || code.len() > 12 || !code.bytes().all(|b| b.is_ascii_alphanumeric()) {
            return Err(AssetIdError::Code);
        }
        let key = stellar_strkey::ed25519::PublicKey::from_string(issuer)
            .map_err(|_| AssetIdError::Issuer)?;
        if key.to_string() != issuer {
            return Err(AssetIdError::Issuer);
        }
        Ok(Self::Classic {
            code: code.to_owned(),
            issuer: issuer.to_owned(),
        })
    }

    /// Parses a canonical contract address.
    ///
    /// # Errors
    /// Returns a contract defect without the rejected address.
    pub fn contract(id: &str) -> Result<Self, AssetIdError> {
        let key = stellar_strkey::Contract::from_string(id).map_err(|_| AssetIdError::Contract)?;
        if key.to_string() != id {
            return Err(AssetIdError::Contract);
        }
        Ok(Self::Contract(id.to_owned()))
    }

    /// Parses a threshold key. Native aliases belong in the native threshold field.
    ///
    /// # Errors
    /// Returns the first identity defect without the rejected input.
    pub fn parse_threshold_key(key: &str) -> Result<Self, AssetIdError> {
        if key.eq_ignore_ascii_case("native") || key.eq_ignore_ascii_case("xlm") {
            return Err(AssetIdError::Native);
        }
        if let Some((code, issuer)) = key.split_once(':') {
            return Self::classic(code, issuer);
        }
        if key.starts_with('C') {
            return Self::contract(key);
        }
        Err(AssetIdError::Form)
    }

    /// Derives the Stellar Asset Contract address on the supplied network.
    /// Returns `None` for a contract identity or an invalid directly constructed asset.
    #[must_use]
    pub fn sac_contract_id(&self, network_passphrase: &str) -> Option<String> {
        let asset = match self {
            Self::Native => Asset::Native,
            Self::Contract(_) => return None,
            Self::Classic { code, issuer } => {
                Self::classic(code, issuer).ok()?;
                let key = stellar_strkey::ed25519::PublicKey::from_string(issuer).ok()?;
                let issuer = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(key.0)));
                if code.len() <= 4 {
                    let mut bytes = [0; 4];
                    bytes[..code.len()].copy_from_slice(code.as_bytes());
                    Asset::CreditAlphanum4(AlphaNum4 {
                        asset_code: AssetCode4(bytes),
                        issuer,
                    })
                } else {
                    let mut bytes = [0; 12];
                    bytes[..code.len()].copy_from_slice(code.as_bytes());
                    Asset::CreditAlphanum12(AlphaNum12 {
                        asset_code: AssetCode12(bytes),
                        issuer,
                    })
                }
            }
        };
        let preimage = HashIdPreimage::ContractId(HashIdPreimageContractId {
            network_id: Hash(Sha256::digest(network_passphrase.as_bytes()).into()),
            contract_id_preimage: ContractIdPreimage::Asset(asset),
        });
        let bytes = preimage.to_xdr(Limits::none()).ok()?;
        Some(
            stellar_strkey::Contract(Sha256::digest(bytes).into())
                .to_string()
                .to_string(),
        )
    }
}

impl fmt::Display for CanonicalAsset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Native => f.write_str("native"),
            Self::Classic { code, issuer } => write!(f, "{code}:{issuer}"),
            Self::Contract(id) => f.write_str(id),
        }
    }
}

impl Serialize for CanonicalAsset {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for CanonicalAsset {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        if text == "native" {
            return Ok(Self::Native);
        }
        Self::parse_threshold_key(&text).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test assertions")]
    use super::*;
    use crate::profile::caip2::{MAINNET_PASSPHRASE, TESTNET_PASSPHRASE};

    #[test]
    fn amount_units_follow_canonical_asset() {
        for unit in ["XLM", "xlm", "Xlm"] {
            assert_eq!(
                CanonicalAsset::Native
                    .parse_amount(&format!("100 {unit}"))
                    .unwrap()
                    .as_stroops(),
                1_000_000_000
            );
        }
        let issuer = stellar_strkey::ed25519::PublicKey([7; 32]).to_string();
        for code in ["TST", "tst", "XLM"] {
            let asset = CanonicalAsset::classic(code, &issuer).unwrap();
            assert_eq!(
                asset
                    .parse_amount(&format!("100 {code}"))
                    .unwrap()
                    .as_stroops(),
                1_000_000_000
            );
            let supplied = if code == "tst" { "TST" } else { "xlm" };
            let error = asset.parse_amount(&format!("100 {supplied}")).unwrap_err();
            assert_eq!(error.code(), "validation.amount_malformed");
            assert_eq!(
                error.to_string(),
                format!("amount '100 {supplied}' has unit '{supplied}'; expected unit '{code}'")
            );
        }
        let contract = stellar_strkey::Contract([7; 32]).to_string();
        assert!(matches!(
            CanonicalAsset::contract(&contract)
                .unwrap()
                .parse_amount("100 XLM"),
            Err(ValidationError::AssetInvalid { .. })
        ));
    }

    #[test]
    fn native_sac_known_answer() {
        assert_eq!(
            CanonicalAsset::Native
                .sac_contract_id(TESTNET_PASSPHRASE)
                .unwrap(),
            "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC"
        );
    }

    #[test]
    fn classic_sac_known_answer() {
        let asset = CanonicalAsset::classic(
            "USDC",
            "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN",
        )
        .unwrap();
        assert_eq!(
            asset.sac_contract_id(MAINNET_PASSPHRASE).unwrap(),
            "CCW67TSZV3SSS2HXMBQ5JFGCKJNXKZM7UQUWUZPUTHXSTZLEO7SJMI75"
        );
    }

    #[test]
    fn asset_identity_preserves_case_and_refuses_noncanonical_forms() {
        let issuer = stellar_strkey::ed25519::PublicKey([7; 32]).to_string();
        assert_ne!(
            CanonicalAsset::classic("usd", &issuer).unwrap(),
            CanonicalAsset::classic("USD", &issuer).unwrap()
        );
        for code in ["", " USD", "USD ", "USD_", "abcdefghijklmn", "é"] {
            assert_eq!(
                CanonicalAsset::classic(code, &issuer),
                Err(AssetIdError::Code)
            );
        }
        for key in ["native", "NATIVE", "XlM", "xlm"] {
            assert_eq!(
                CanonicalAsset::parse_threshold_key(key),
                Err(AssetIdError::Native)
            );
        }
        assert!(CanonicalAsset::contract("Cinvalid").is_err());
        assert!(CanonicalAsset::classic("USD", "Ginvalid").is_err());
    }
}
