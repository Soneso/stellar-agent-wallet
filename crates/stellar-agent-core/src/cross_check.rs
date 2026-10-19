//! Pure cross-check requirements and stable witness labels.

use crate::{
    asset_id::CanonicalAsset,
    error::{NetworkError, WitnessUnavailableReason},
    profile::{caip2::Caip2, schema::Profile},
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fmt};

/// Per-asset thresholds in the asset's base units.
///
/// Every key is a non-native asset and every value is non-negative. The map
/// is private so that [`CrossCheckThresholds::new`] and deserialization, which
/// both check the two rules, are the only ways to build a table; the native
/// threshold is `cross_check_threshold_stroops` with its floor.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    try_from = "BTreeMap<CanonicalAsset, WireThreshold>",
    into = "BTreeMap<CanonicalAsset, WireThreshold>"
)]
pub struct CrossCheckThresholds(BTreeMap<CanonicalAsset, i128>);

/// A threshold table that names the native asset or holds a negative value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("holds the native asset or a negative threshold")]
pub struct InvalidCrossCheckThresholds;

#[derive(Serialize, Deserialize)]
struct WireThreshold(#[serde(with = "crate::wire_stroops::i128")] i128);

impl TryFrom<BTreeMap<CanonicalAsset, WireThreshold>> for CrossCheckThresholds {
    type Error = InvalidCrossCheckThresholds;
    fn try_from(values: BTreeMap<CanonicalAsset, WireThreshold>) -> Result<Self, Self::Error> {
        Self::new(
            values
                .into_iter()
                .map(|(key, value)| (key, value.0))
                .collect(),
        )
    }
}

impl From<CrossCheckThresholds> for BTreeMap<CanonicalAsset, WireThreshold> {
    fn from(values: CrossCheckThresholds) -> Self {
        values
            .0
            .into_iter()
            .map(|(key, value)| (key, WireThreshold(value)))
            .collect()
    }
}

impl CrossCheckThresholds {
    /// Builds a table from validated entries.
    ///
    /// The profile loader calls this after it has parsed every key and value
    /// and checked the SAC rules, which need the profile's network.
    ///
    /// # Errors
    /// Refuses a native key or a negative value.
    pub fn new(
        entries: BTreeMap<CanonicalAsset, i128>,
    ) -> Result<Self, InvalidCrossCheckThresholds> {
        if entries
            .iter()
            .any(|(key, value)| *key == CanonicalAsset::Native || *value < 0)
        {
            return Err(InvalidCrossCheckThresholds);
        }
        Ok(Self(entries))
    }

    /// The threshold set directly for this identity, without SAC lookups.
    #[must_use]
    pub fn get(&self, asset: &CanonicalAsset) -> Option<i128> {
        self.0.get(asset).copied()
    }

    /// The entries in canonical key order.
    pub fn iter(&self) -> impl Iterator<Item = (&CanonicalAsset, i128)> + '_ {
        self.0.iter().map(|(key, value)| (key, *value))
    }

    /// Whether the profile has no per-asset thresholds.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Value used to decide whether an independent witness is required.
#[derive(Debug, Clone, Copy)]
pub enum CrossCheckValue<'a> {
    /// An amount denominated in the asset's base units.
    Amount {
        /// Canonical asset identity.
        asset: &'a CanonicalAsset,
        /// Amount in base units.
        base_units: i128,
    },
    /// An action whose stage has no reliable amount.
    Unvalued,
}

/// Why a testnet action continues without an oracle comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CrossCheckSkip {
    /// The profile has no oracle endpoint.
    OracleNotConfigured,
    /// The profile has no threshold for this asset.
    NoThresholdForAsset,
}

/// The required treatment of a transaction's ledger observations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrossCheckRequirement {
    /// Obtain the witness before signing.
    Required,
    /// Continue on testnet with the specified warning.
    Skipped(CrossCheckSkip),
    /// The amount is below its threshold and no memo observation requires comparison.
    NotRequired,
}

/// Borrowed thresholds with the native floor already applied.
pub struct ThresholdSet<'a> {
    /// Effective native threshold, in stroops.
    pub native_stroops: u64,
    /// Per-asset thresholds.
    pub table: &'a CrossCheckThresholds,
    /// Network used to derive SAC identities.
    pub network_passphrase: &'a str,
}

impl<'a> ThresholdSet<'a> {
    /// Resolves the native floor and the profile's network.
    #[must_use]
    pub fn from_profile(profile: &'a Profile) -> Self {
        Self {
            native_stroops: profile.effective_cross_check_threshold_stroops(),
            table: &profile.cross_check_thresholds,
            network_passphrase: &profile.network_passphrase,
        }
    }

    /// Looks up direct identities, classic SAC equivalents, then the native SAC.
    #[must_use]
    pub fn threshold_for(&self, asset: &CanonicalAsset) -> Option<i128> {
        if *asset == CanonicalAsset::Native {
            return Some(i128::from(self.native_stroops));
        }
        if let Some(value) = self.table.get(asset) {
            return Some(value);
        }
        if let CanonicalAsset::Contract(id) = asset {
            for (key, value) in self.table.iter() {
                if matches!(key, CanonicalAsset::Classic { .. })
                    && key.sac_contract_id(self.network_passphrase).as_ref() == Some(id)
                {
                    return Some(value);
                }
            }
            if CanonicalAsset::Native
                .sac_contract_id(self.network_passphrase)
                .as_ref()
                == Some(id)
            {
                return Some(i128::from(self.native_stroops));
            }
        }
        None
    }
}

/// Determines the witness requirement without constructing a client.
/// Mainnet missing thresholds take precedence over memo observations.
/// Testnet memo observations require a configured oracle even without a threshold.
///
/// # Errors
/// Refuses missing thresholds or required missing oracles on mainnet.
pub fn cross_check_requirement(
    chain: Caip2,
    value: CrossCheckValue<'_>,
    thresholds: &ThresholdSet<'_>,
    oracle_configured: bool,
    memo_check: bool,
) -> Result<CrossCheckRequirement, NetworkError> {
    let threshold = match value {
        CrossCheckValue::Amount { asset, .. } => thresholds.threshold_for(asset),
        CrossCheckValue::Unvalued => None,
    };
    let missing_asset = match value {
        CrossCheckValue::Amount { asset, .. } if threshold.is_none() => Some(asset),
        _ => None,
    };
    match chain {
        Caip2::Mainnet => {
            if let Some(asset) = missing_asset {
                return Err(NetworkError::WitnessUnavailable {
                    reason: WitnessUnavailableReason::NoThresholdForAsset {
                        asset: asset.clone(),
                    },
                });
            }
        }
        Caip2::Testnet => {
            if missing_asset.is_some() && !memo_check {
                return Ok(CrossCheckRequirement::Skipped(
                    CrossCheckSkip::NoThresholdForAsset,
                ));
            }
        }
    }
    let required = memo_check
        || match value {
            CrossCheckValue::Unvalued => true,
            CrossCheckValue::Amount { base_units, .. } => {
                threshold.is_some_and(|t| base_units >= t)
            }
        };
    if !required {
        return Ok(CrossCheckRequirement::NotRequired);
    }
    if oracle_configured {
        return Ok(CrossCheckRequirement::Required);
    }
    match chain {
        Caip2::Mainnet => Err(NetworkError::WitnessUnavailable {
            reason: WitnessUnavailableReason::OracleNotConfigured,
        }),
        Caip2::Testnet => Ok(CrossCheckRequirement::Skipped(
            CrossCheckSkip::OracleNotConfigured,
        )),
    }
}

/// Witness observation kinds: the classic ledger entries and the Soroban
/// simulation. Discriminants are digest tags and remain stable.
///
/// The derived `Ord` follows the declaration order, and the digest orders its
/// observations by it; the variants are therefore declared in ascending tag
/// order, so the ordering and the tags agree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum WitnessEntry {
    /// Source account.
    SourceAccount = 1,
    /// Source trustline.
    SourceTrustline = 2,
    /// Destination account.
    DestinationAccount = 3,
    /// Issuer account.
    IssuerAccount = 4,
    /// Claimable balance.
    ClaimableBalance = 5,
    /// SEP-29 memo requirement.
    MemoRequirement = 6,
    /// Pool channel account.
    PoolChannelAccount = 7,
    /// Pool funder account.
    FunderAccount = 8,
    /// The simulation of an unsigned Soroban transaction.
    SorobanSimulation = 9,
}

impl fmt::Display for WitnessEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::SourceAccount => "source account",
            Self::SourceTrustline => "source trustline",
            Self::DestinationAccount => "destination account",
            Self::IssuerAccount => "issuer account",
            Self::ClaimableBalance => "claimable balance",
            Self::MemoRequirement => "memo requirement",
            Self::PoolChannelAccount => "pool channel account",
            Self::FunderAccount => "funder account",
            Self::SorobanSimulation => "soroban simulation",
        })
    }
}

/// A compared field, with stable wire names and operator-facing labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WitnessField {
    /// Entry presence.
    Existence,
    /// Account sequence.
    Sequence,
    /// Native balance.
    NativeBalance,
    /// Account subentry count.
    SubentryCount,
    /// Account or trustline flags.
    Flags,
    /// Trustline balance.
    Balance,
    /// Trustline limit.
    Limit,
    /// Projected home domain.
    HomeDomain,
    /// Entire claimable-balance entry.
    Record,
    /// Normalized memo requirement.
    Value,
    /// Simulation outcome: an error or a restore preamble.
    SimulationResult,
    /// Number of results and of authorization entries in a simulation.
    AuthorizationCount,
    /// Credential kind of a simulated authorization entry.
    Credentials,
    /// Address of a simulated authorization entry.
    Address,
    /// Signature of a simulated authorization entry.
    Signature,
    /// Root invocation of a simulated authorization entry.
    Invocation,
    /// Minimum resource fee of a simulation against the wallet's ceiling.
    ResourceFee,
    /// Distance between the simulation ledgers of the two endpoints.
    LedgerSkew,
    /// Simulation ledger against the signature expiration ledger.
    Expiration,
}

impl fmt::Display for WitnessField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Existence => "existence",
            Self::Sequence => "sequence",
            Self::NativeBalance => "native balance",
            Self::SubentryCount => "subentry count",
            Self::Flags => "flags",
            Self::Balance => "balance",
            Self::Limit => "limit",
            Self::HomeDomain => "home domain",
            Self::Record => "record",
            Self::Value => "value",
            Self::SimulationResult => "result",
            Self::AuthorizationCount => "authorization count",
            Self::Credentials => "credentials",
            Self::Address => "address",
            Self::Signature => "signature",
            Self::Invocation => "invocation",
            Self::ResourceFee => "resource fee ceiling",
            Self::LedgerSkew => "ledger skew",
            Self::Expiration => "expiration",
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test assertions")]
    use super::*;
    use crate::profile::caip2::TESTNET_PASSPHRASE;

    fn requirement(
        chain: Caip2,
        amount: Option<i128>,
        oracle: bool,
        memo: bool,
    ) -> Result<CrossCheckRequirement, NetworkError> {
        let table = CrossCheckThresholds::default();
        let thresholds = ThresholdSet {
            native_stroops: 100,
            table: &table,
            network_passphrase: TESTNET_PASSPHRASE,
        };
        cross_check_requirement(
            chain,
            amount.map_or(CrossCheckValue::Unvalued, |base_units| {
                CrossCheckValue::Amount {
                    asset: &CanonicalAsset::Native,
                    base_units,
                }
            }),
            &thresholds,
            oracle,
            memo,
        )
    }

    #[test]
    fn requirement_mainnet_without_oracle_refuses_witness_unavailable() {
        let error = requirement(Caip2::Mainnet, Some(100), false, false).unwrap_err();
        assert_eq!(error.code(), "network.witness_unavailable");
        assert!(matches!(
            error,
            NetworkError::WitnessUnavailable {
                reason: WitnessUnavailableReason::OracleNotConfigured
            }
        ));
    }

    #[test]
    fn requirement_mainnet_at_threshold_with_oracle_is_required() {
        assert_eq!(
            requirement(Caip2::Mainnet, Some(100), true, false).unwrap(),
            CrossCheckRequirement::Required
        );
    }

    #[test]
    fn requirement_mainnet_unvalued_is_required_regardless() {
        assert_eq!(
            requirement(Caip2::Mainnet, None, true, false).unwrap(),
            CrossCheckRequirement::Required
        );
        assert!(requirement(Caip2::Mainnet, None, false, false).is_err());
    }

    #[test]
    fn requirement_truth_table_native_and_unvalued() {
        for chain in [Caip2::Testnet, Caip2::Mainnet] {
            for oracle in [false, true] {
                for value in [Some(0), Some(99), Some(100), Some(101), None] {
                    let result = requirement(chain, value, oracle, false);
                    if value.is_some_and(|v| v < 100) {
                        assert_eq!(result.unwrap(), CrossCheckRequirement::NotRequired);
                    } else if oracle {
                        assert_eq!(result.unwrap(), CrossCheckRequirement::Required);
                    } else if chain == Caip2::Mainnet {
                        assert!(matches!(
                            result,
                            Err(NetworkError::WitnessUnavailable {
                                reason: WitnessUnavailableReason::OracleNotConfigured
                            })
                        ));
                    } else {
                        assert_eq!(
                            result.unwrap(),
                            CrossCheckRequirement::Skipped(CrossCheckSkip::OracleNotConfigured)
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn requirement_memo_check_with_oracle_is_required_below_threshold() {
        for chain in [Caip2::Testnet, Caip2::Mainnet] {
            assert_eq!(
                requirement(chain, Some(1), true, true).unwrap(),
                CrossCheckRequirement::Required
            );
        }
        assert!(requirement(Caip2::Mainnet, Some(1), false, true).is_err());
        assert_eq!(
            requirement(Caip2::Testnet, Some(1), false, true).unwrap(),
            CrossCheckRequirement::Skipped(CrossCheckSkip::OracleNotConfigured)
        );
    }

    fn classic() -> CanonicalAsset {
        CanonicalAsset::classic(
            "USD",
            &stellar_strkey::ed25519::PublicKey([7; 32]).to_string(),
        )
        .unwrap()
    }

    #[test]
    fn requirement_testnet_asset_without_threshold_skips() {
        let table = CrossCheckThresholds::default();
        let thresholds = ThresholdSet {
            native_stroops: 100,
            table: &table,
            network_passphrase: TESTNET_PASSPHRASE,
        };
        for oracle in [false, true] {
            for base_units in [0, 100, i128::MAX] {
                let value = CrossCheckValue::Amount {
                    asset: &classic(),
                    base_units,
                };
                assert_eq!(
                    cross_check_requirement(Caip2::Testnet, value, &thresholds, oracle, false)
                        .unwrap(),
                    CrossCheckRequirement::Skipped(CrossCheckSkip::NoThresholdForAsset)
                );
                for memo in [false, true] {
                    assert!(matches!(
                        cross_check_requirement(Caip2::Mainnet, value, &thresholds, oracle, memo),
                        Err(NetworkError::WitnessUnavailable {
                            reason: WitnessUnavailableReason::NoThresholdForAsset { .. }
                        })
                    ));
                }
                assert_eq!(
                    cross_check_requirement(Caip2::Testnet, value, &thresholds, oracle, true)
                        .unwrap(),
                    if oracle {
                        CrossCheckRequirement::Required
                    } else {
                        CrossCheckRequirement::Skipped(CrossCheckSkip::OracleNotConfigured)
                    }
                );
            }
        }
    }

    #[test]
    fn requirement_contract_matches_sac_equivalent_classic_key() {
        let asset = classic();
        let contract =
            CanonicalAsset::contract(&asset.sac_contract_id(TESTNET_PASSPHRASE).unwrap()).unwrap();
        let table = CrossCheckThresholds::new(BTreeMap::from([(asset, 200)])).unwrap();
        let thresholds = ThresholdSet {
            native_stroops: 100,
            table: &table,
            network_passphrase: TESTNET_PASSPHRASE,
        };
        assert_eq!(thresholds.threshold_for(&contract), Some(200));
        assert_eq!(
            cross_check_requirement(
                Caip2::Mainnet,
                CrossCheckValue::Amount {
                    asset: &contract,
                    base_units: 200
                },
                &thresholds,
                true,
                false
            )
            .unwrap(),
            CrossCheckRequirement::Required
        );
    }

    #[test]
    fn requirement_direct_contract_and_native_sac_use_their_thresholds() {
        let asset =
            CanonicalAsset::contract(&stellar_strkey::Contract([9; 32]).to_string()).unwrap();
        let mut profile = Profile::builder_testnet("signer", "witness", "nonce", "witness").build();
        profile.cross_check_threshold_stroops = 0;
        profile.cross_check_thresholds =
            CrossCheckThresholds::new(BTreeMap::from([(asset.clone(), 500)])).unwrap();
        let thresholds = ThresholdSet::from_profile(&profile);
        assert_eq!(thresholds.threshold_for(&asset), Some(500));
        let native_sac = CanonicalAsset::contract(
            &CanonicalAsset::Native
                .sac_contract_id(TESTNET_PASSPHRASE)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            thresholds.threshold_for(&native_sac),
            Some(i128::from(crate::profile::schema::MINIMUM_FLOOR))
        );
    }
    #[test]
    fn thresholds_constructor_refuses_native_and_negative_entries() {
        let table = CrossCheckThresholds::new(BTreeMap::from([(classic(), 0)])).unwrap();
        assert_eq!(table.get(&classic()), Some(0));
        assert_eq!(table.iter().collect::<Vec<_>>(), [(&classic(), 0)]);
        assert!(!table.is_empty());
        for entries in [
            BTreeMap::from([(CanonicalAsset::Native, 1)]),
            BTreeMap::from([(classic(), -1)]),
        ] {
            assert_eq!(
                CrossCheckThresholds::new(entries),
                Err(InvalidCrossCheckThresholds)
            );
        }
        let key = classic().to_string();
        let parsed: CrossCheckThresholds =
            serde_json::from_value(serde_json::json!({ key.clone(): "7" })).unwrap();
        assert_eq!(parsed.get(&classic()), Some(7));
        for wire in [
            serde_json::json!({ "native": "1" }),
            serde_json::json!({ key: "-1" }),
        ] {
            let error = serde_json::from_value::<CrossCheckThresholds>(wire).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("holds the native asset or a negative threshold"),
                "{error}"
            );
        }
    }

    #[test]
    fn soroban_simulation_kind_has_its_wire_name_tag_and_label() {
        assert_eq!(
            serde_json::to_value(WitnessEntry::SorobanSimulation).unwrap(),
            serde_json::json!("soroban_simulation")
        );
        assert_eq!(
            serde_json::from_value::<WitnessEntry>(serde_json::json!("soroban_simulation"))
                .unwrap(),
            WitnessEntry::SorobanSimulation
        );
        assert_eq!(WitnessEntry::SorobanSimulation as u8, 9);
        assert!(WitnessEntry::FunderAccount < WitnessEntry::SorobanSimulation);
        assert_eq!(
            WitnessEntry::SorobanSimulation.to_string(),
            "soroban simulation"
        );
    }

    #[test]
    fn soroban_simulation_fields_have_their_labels() {
        for (field, label) in [
            (WitnessField::SimulationResult, "result"),
            (WitnessField::AuthorizationCount, "authorization count"),
            (WitnessField::Credentials, "credentials"),
            (WitnessField::Address, "address"),
            (WitnessField::Signature, "signature"),
            (WitnessField::Invocation, "invocation"),
            (WitnessField::ResourceFee, "resource fee ceiling"),
            (WitnessField::LedgerSkew, "ledger skew"),
            (WitnessField::Expiration, "expiration"),
        ] {
            assert_eq!(field.to_string(), label);
        }
    }

    #[test]
    fn soroban_divergence_names_the_simulation_and_the_field() {
        let error = NetworkError::WitnessDivergence {
            entry: WitnessEntry::SorobanSimulation,
            field: WitnessField::AuthorizationCount,
            sequence_delta: None,
        };
        assert_eq!(
            error.to_string(),
            "cross-check refused: the primary RPC and the oracle disagree on the soroban \
             simulation authorization count; the wallet did not sign or send. Retry the \
             action; if the disagreement persists, investigate both endpoints"
        );
        assert_eq!(
            crate::error::WalletError::from(error).code(),
            "simulation.divergence"
        );
    }
}
