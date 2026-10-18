//! Batched, keyed oracle projection and exact classic field comparisons.

use super::{inputs::*, unavailable};
use crate::{account::project_account_entry, builder::Asset, sep29::normalise_memo_required};
use std::collections::BTreeMap;
use stellar_agent_core::{
    cross_check::{WitnessEntry, WitnessField},
    error::{NetworkError, WalletError},
};
use stellar_rpc_client::GetLedgerEntriesResponse;
use stellar_xdr::{
    AccountId, ClaimableBalanceId, Hash, LedgerEntryData, LedgerKey, LedgerKeyAccount,
    LedgerKeyClaimableBalance, LedgerKeyData, LedgerKeyTrustLine, PublicKey, ReadXdr, Uint256,
};

#[derive(Clone)]
pub(super) struct Observation {
    pub kind: WitnessEntry,
    pub key: LedgerKey,
    pub value: Observed,
}

#[derive(Clone)]
pub(super) enum Observed {
    Account(AccountObservation),
    Trustline(TrustlineObservation),
    Destination(DestinationObservation),
    Issuer(IssuerObservation),
    Claimable(ClaimableBalanceObservation),
    Memo(bool),
    Absent,
}

fn account_id(id: &str) -> Result<AccountId, WalletError> {
    let pk =
        stellar_strkey::ed25519::PublicKey::from_string(id).map_err(|_| invalid_observation())?;
    Ok(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(pk.0))))
}

fn account_key(id: &str) -> Result<LedgerKey, WalletError> {
    Ok(LedgerKey::Account(LedgerKeyAccount {
        account_id: account_id(id)?,
    }))
}

fn trustline_observation(t: &TrustlineObservation) -> Result<Observation, WalletError> {
    let asset = Asset::parse(&t.asset.to_string())?.to_xdr_trust_line_asset()?;
    Ok(Observation {
        kind: WitnessEntry::SourceTrustline,
        key: LedgerKey::Trustline(LedgerKeyTrustLine {
            account_id: account_id(&t.account_id)?,
            asset,
        }),
        value: Observed::Trustline(t.clone()),
    })
}

impl ClassicInputs {
    pub(super) fn observations(&self) -> Result<Vec<Observation>, WalletError> {
        use WitnessEntry as K;
        let mut out = Vec::new();
        let source = match self {
            Self::Pay(v) => &v.source,
            Self::CreateAccount(v) => &v.source,
            Self::Trustline(v) => &v.source,
            Self::Claim(v) => &v.source,
            Self::PoolInit(v) => &v.funder,
        };
        out.push(Observation {
            kind: if matches!(self, Self::PoolInit(_)) {
                K::FunderAccount
            } else {
                K::SourceAccount
            },
            key: account_key(&source.account_id)?,
            value: Observed::Account(source.clone()),
        });
        match self {
            Self::Pay(v) => {
                out.push(Observation {
                    kind: K::DestinationAccount,
                    key: account_key(&v.destination.account_id)?,
                    value: Observed::Destination(v.destination.clone()),
                });
                if let MemoObservation::Read(required) = v.memo {
                    let name = b"config.memo_required"
                        .to_vec()
                        .try_into()
                        .map_err(|_| invalid_observation())?;
                    out.push(Observation {
                        kind: K::MemoRequirement,
                        key: LedgerKey::Data(LedgerKeyData {
                            account_id: account_id(&v.destination.account_id)?,
                            data_name: name,
                        }),
                        value: Observed::Memo(required),
                    });
                }
                if let Some(t) = &v.trustline {
                    out.push(trustline_observation(t)?);
                }
            }
            Self::CreateAccount(_) => {}
            Self::Trustline(v) => out.push(Observation {
                kind: K::IssuerAccount,
                key: account_key(&v.issuer.account_id)?,
                value: Observed::Issuer(v.issuer.clone()),
            }),
            Self::Claim(v) => {
                if let Some(t) = &v.trustline {
                    out.push(trustline_observation(t)?);
                }
                if let Some(b) = &v.balance {
                    out.push(Observation {
                        kind: K::ClaimableBalance,
                        key: LedgerKey::ClaimableBalance(LedgerKeyClaimableBalance {
                            balance_id: ClaimableBalanceId::ClaimableBalanceIdTypeV0(Hash(
                                b.balance_id,
                            )),
                        }),
                        value: Observed::Claimable(b.clone()),
                    });
                }
            }
            Self::PoolInit(v) => {
                for id in &v.absent_channels {
                    out.push(Observation {
                        kind: K::PoolChannelAccount,
                        key: account_key(id)?,
                        value: Observed::Absent,
                    });
                }
            }
        }
        out.sort_by_key(|observation| observation.kind);
        Ok(out)
    }
}

pub(super) fn keys(observations: &[Observation]) -> Vec<LedgerKey> {
    let mut keys = Vec::new();
    for observation in observations {
        if !keys.contains(&observation.key) {
            keys.push(observation.key.clone());
        }
    }
    keys
}

fn data_matches_key(key: &LedgerKey, data: &LedgerEntryData) -> bool {
    match (key, data) {
        (LedgerKey::Account(k), LedgerEntryData::Account(v)) => k.account_id == v.account_id,
        (LedgerKey::Trustline(k), LedgerEntryData::Trustline(v)) => {
            k.account_id == v.account_id && k.asset == v.asset
        }
        (LedgerKey::Data(k), LedgerEntryData::Data(v)) => {
            k.account_id == v.account_id && k.data_name == v.data_name
        }
        (LedgerKey::ClaimableBalance(k), LedgerEntryData::ClaimableBalance(v)) => {
            k.balance_id == v.balance_id
        }
        _ => false,
    }
}

pub(super) fn compare_answer(
    observations: &[Observation],
    requested: &[LedgerKey],
    response: GetLedgerEntriesResponse,
    authority: &str,
) -> Result<u32, WalletError> {
    let invalid = || {
        unavailable(super::Reason::InvalidAnswer {
            authority: authority.to_owned(),
        })
    };
    let ledger = u32::try_from(response.latest_ledger)
        .ok()
        .filter(|n| *n != 0)
        .ok_or_else(invalid)?;
    let mut entries = BTreeMap::new();
    for entry in response.entries.unwrap_or_default() {
        let key = LedgerKey::from_xdr_base64(
            &entry.key,
            stellar_agent_xdr_limits::untrusted_decode_limits(entry.key.len()),
        )
        .map_err(|_| invalid())?;
        let data = LedgerEntryData::from_xdr_base64(
            &entry.xdr,
            stellar_agent_xdr_limits::untrusted_decode_limits(entry.xdr.len()),
        )
        .map_err(|_| invalid())?;
        if !requested.contains(&key) || entries.contains_key(&key) || !data_matches_key(&key, &data)
        {
            return Err(invalid());
        }
        entries.insert(key, data);
    }
    for observation in observations {
        compare(observation, entries.get(&observation.key), authority)?;
    }
    Ok(ledger)
}

fn disagreement(kind: WitnessEntry, field: WitnessField, delta: Option<u64>) -> WalletError {
    NetworkError::WitnessDivergence {
        entry: kind,
        field,
        sequence_delta: delta,
    }
    .into()
}

fn compare(
    observation: &Observation,
    data: Option<&LedgerEntryData>,
    authority: &str,
) -> Result<(), WalletError> {
    use WitnessField as F;
    let kind = observation.kind;
    let invalid = || {
        unavailable(super::Reason::InvalidAnswer {
            authority: authority.to_owned(),
        })
    };
    macro_rules! check {
        ($field:ident, $a:expr, $b:expr) => {
            if $a != $b {
                return Err(disagreement(kind, F::$field, None));
            }
        };
    }
    match &observation.value {
        Observed::Account(primary) => {
            let Some(LedgerEntryData::Account(raw)) = data else {
                return Err(disagreement(kind, F::Existence, None));
            };
            let view = project_account_entry(&primary.account_id, raw).map_err(|_| invalid())?;
            let oracle = AccountObservation::from_view(&view).map_err(|_| invalid())?;
            if primary.sequence != oracle.sequence {
                return Err(disagreement(
                    kind,
                    F::Sequence,
                    Some(primary.sequence.abs_diff(oracle.sequence)),
                ));
            }
            check!(NativeBalance, primary.native_balance, oracle.native_balance);
            check!(SubentryCount, primary.subentry_count, oracle.subentry_count);
            check!(Flags, primary.flags, oracle.flags);
        }
        Observed::Trustline(primary) => {
            let raw = match data {
                Some(LedgerEntryData::Trustline(raw)) => Some(raw),
                None => None,
                _ => return Err(invalid()),
            };
            let oracle =
                TrustlineObservation::from_entry(&primary.account_id, primary.asset.clone(), raw)
                    .map_err(|_| invalid())?;
            check!(Existence, primary.state.is_some(), oracle.state.is_some());
            if let (Some(a), Some(b)) = (primary.state, oracle.state) {
                check!(Balance, a.0, b.0);
                check!(Limit, a.1, b.1);
                check!(Flags, a.2, b.2);
            }
        }
        Observed::Destination(primary) => {
            let oracle = match data {
                Some(LedgerEntryData::Account(raw)) => {
                    Some(project_account_entry(&primary.account_id, raw).map_err(|_| invalid())?)
                }
                None => None,
                _ => return Err(invalid()),
            };
            let oracle = DestinationObservation::from_view(&primary.account_id, oracle.as_ref());
            check!(
                Existence,
                primary.present.is_some(),
                oracle.present.is_some()
            );
            if let (Some(a), Some(b)) = (&primary.present, &oracle.present) {
                check!(HomeDomain, a.0, b.0);
                check!(Flags, a.1, b.1);
            }
        }
        Observed::Issuer(primary) => {
            let oracle = match data {
                Some(LedgerEntryData::Account(raw)) => {
                    Some(project_account_entry(&primary.account_id, raw).map_err(|_| invalid())?)
                }
                None => None,
                _ => return Err(invalid()),
            };
            let oracle = IssuerObservation::from_view(&primary.account_id, oracle.as_ref());
            check!(Existence, primary.flags.is_some(), oracle.flags.is_some());
            check!(Flags, primary.flags, oracle.flags);
        }
        Observed::Claimable(primary) => {
            let oracle = match data {
                Some(LedgerEntryData::ClaimableBalance(raw)) => Some(raw),
                None => None,
                _ => return Err(invalid()),
            };
            check!(Existence, primary.entry.is_some(), oracle.is_some());
            check!(Record, primary.entry.as_ref(), oracle);
        }
        Observed::Memo(primary) => {
            let raw = match data {
                Some(LedgerEntryData::Data(raw)) => Some(raw.data_value.to_vec()),
                None => None,
                _ => return Err(invalid()),
            };
            if *primary != normalise_memo_required(&raw) {
                return Err(NetworkError::RpcDivergence {
                    context: "SEP-29 config.memo_required".to_owned(),
                }
                .into());
            }
        }
        Observed::Absent => {
            check!(Existence, false, data.is_some());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test assertions"
    )]
    use super::super::*;
    use super::*;
    use crate::builder::Asset as ClassicAsset;
    use serde_json::json;
    use std::time::Duration;
    use stellar_agent_core::{asset_id::CanonicalAsset, profile::caip2::TESTNET_PASSPHRASE};
    use stellar_agent_test_support::EchoIdResponder;
    use stellar_xdr::*;
    use wiremock::matchers::{body_partial_json, method};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn account(n: u8) -> AccountEntry {
        AccountEntry {
            account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([n; 32]))),
            balance: 100_000_000_000,
            seq_num: SequenceNumber(42),
            num_sub_entries: 2,
            inflation_dest: None,
            flags: 0,
            home_domain: b"example.org".to_vec().try_into().unwrap(),
            thresholds: Thresholds([1, 1, 1, 1]),
            signers: vec![].try_into().unwrap(),
            ext: AccountEntryExt::V0,
        }
    }
    fn address(n: u8) -> String {
        stellar_strkey::ed25519::PublicKey([n; 32])
            .to_string()
            .to_string()
    }
    fn source(n: u8) -> AccountObservation {
        AccountObservation::from_view(&project_account_entry(&address(n), &account(n)).unwrap())
            .unwrap()
    }
    fn pay() -> ClassicInputs {
        PayWitnessInputs {
            source: source(7),
            destination: DestinationObservation::from_view(
                &address(8),
                Some(&project_account_entry(&address(8), &account(8)).unwrap()),
            ),
            memo: MemoObservation::Read(false),
            trustline: None,
        }
        .into()
    }
    #[allow(
        clippy::needless_pass_by_value,
        reason = "fixtures own their constructed XDR"
    )]
    fn entry(key: &LedgerKey, data: LedgerEntryData) -> serde_json::Value {
        json!({"key": key.to_xdr_base64(Limits::none()).unwrap(),
            "xdr": data.to_xdr_base64(Limits::none()).unwrap(), "lastModifiedLedgerSeq": 100})
    }
    fn account_answer(n: u8) -> serde_json::Value {
        entry(
            &account_key(&address(n)).unwrap(),
            LedgerEntryData::Account(account(n)),
        )
    }
    #[allow(
        clippy::needless_pass_by_value,
        reason = "fixtures own their constructed entries"
    )]
    fn answer(entries: Vec<serde_json::Value>) -> serde_json::Value {
        json!({"entries": entries, "latestLedger": 100})
    }
    fn pay_answer() -> serde_json::Value {
        answer(vec![account_answer(7), account_answer(8)])
    }
    fn profile(server: &MockServer) -> Profile {
        Profile::builder_testnet("signer", "witness", "nonce", "witness")
            .rpc_url(format!("{}/primary", server.uri()))
            .oracle_provider_url(url::Url::parse(&format!("{}/oracle", server.uri())).unwrap())
            .build()
    }
    async fn oracle(identity: serde_json::Value) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(body_partial_json(json!({"method": "getNetwork"})))
            .respond_with(EchoIdResponder::new(identity))
            .mount(&server)
            .await;
        server
    }
    fn network() -> serde_json::Value {
        stellar_agent_test_support::signed_envelope::get_network_result(TESTNET_PASSPHRASE)
    }
    async fn read_mock(server: &MockServer, body: serde_json::Value) {
        Mock::given(method("POST"))
            .and(body_partial_json(json!({"method": "getLedgerEntries"})))
            .respond_with(EchoIdResponder::new(body))
            .mount(server)
            .await;
    }
    async fn run(
        server: &MockServer,
        inputs: ClassicInputs,
    ) -> Result<CrossCheckOutcome, WalletError> {
        let profile = profile(server);
        obtain_classic_witness_with_timing(
            &profile,
            &NetworkContext::from_profile(&profile),
            CrossCheckValue::Unvalued,
            inputs,
            "test_witness",
            WitnessTiming {
                attempt_budget: Duration::from_millis(300),
                retry_backoff: Duration::from_millis(1),
            },
        )
        .await
    }
    async fn methods(server: &MockServer) -> Vec<String> {
        server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .map(|request| {
                serde_json::from_slice::<serde_json::Value>(&request.body).unwrap()["method"]
                    .as_str()
                    .unwrap()
                    .to_owned()
            })
            .collect()
    }
    async fn disagrees(
        inputs: ClassicInputs,
        body: serde_json::Value,
        expected_entry: WitnessEntry,
        expected_field: WitnessField,
    ) {
        let server = oracle(network()).await;
        read_mock(&server, body).await;
        let error = run(&server, inputs).await.unwrap_err();
        assert_eq!(error.code(), "simulation.divergence");
        assert!(
            matches!(error, WalletError::Network(NetworkError::WitnessDivergence {
            entry, field, .. }) if entry == expected_entry && field == expected_field),
            "{error}"
        );
        if expected_field == WitnessField::Sequence {
            assert!(matches!(
                error,
                WalletError::Network(NetworkError::WitnessDivergence {
                    sequence_delta: Some(1),
                    ..
                })
            ));
            assert!(error.to_string().contains("sequence delta 1"));
        }
        assert_eq!(methods(&server).await, ["getNetwork", "getLedgerEntries"]);
    }
    async fn account_disagrees(kind: WitnessEntry, field: WitnessField) {
        let (inputs, n) = match kind {
            WitnessEntry::SourceAccount => {
                (CreateAccountWitnessInputs { source: source(7) }.into(), 7)
            }
            WitnessEntry::FunderAccount => (
                PoolInitWitnessInputs {
                    funder: source(7),
                    absent_channels: vec![],
                }
                .into(),
                7,
            ),
            WitnessEntry::DestinationAccount => (pay(), 8),
            WitnessEntry::IssuerAccount => (
                TrustlineWitnessInputs {
                    source: source(7),
                    issuer: IssuerObservation::from_view(
                        &address(8),
                        Some(&project_account_entry(&address(8), &account(8)).unwrap()),
                    ),
                }
                .into(),
                8,
            ),
            _ => panic!("account kind"),
        };
        let mut raw = account(n);
        match field {
            WitnessField::Sequence => raw.seq_num.0 += 1,
            WitnessField::NativeBalance => raw.balance += 1,
            WitnessField::SubentryCount => raw.num_sub_entries += 1,
            WitnessField::Flags => raw.flags ^= 8,
            WitnessField::HomeDomain => {
                raw.home_domain = b"other.example".to_vec().try_into().unwrap()
            }
            WitnessField::Existence => {}
            _ => panic!("account field"),
        }
        let mut entries = if n == 8 {
            vec![account_answer(7)]
        } else {
            vec![]
        };
        if field != WitnessField::Existence {
            entries.push(entry(
                &account_key(&address(n)).unwrap(),
                LedgerEntryData::Account(raw),
            ));
        }
        disagrees(inputs, answer(entries), kind, field).await;
    }

    #[tokio::test]
    async fn classic_disagreement_source_existence() {
        account_disagrees(WitnessEntry::SourceAccount, WitnessField::Existence).await;
    }

    #[tokio::test]
    async fn classic_disagreement_source_sequence() {
        account_disagrees(WitnessEntry::SourceAccount, WitnessField::Sequence).await;
    }

    #[tokio::test]
    async fn classic_disagreement_source_native_balance() {
        account_disagrees(WitnessEntry::SourceAccount, WitnessField::NativeBalance).await;
    }

    #[tokio::test]
    async fn classic_disagreement_source_subentry_count() {
        account_disagrees(WitnessEntry::SourceAccount, WitnessField::SubentryCount).await;
    }

    #[tokio::test]
    async fn classic_disagreement_source_flags() {
        account_disagrees(WitnessEntry::SourceAccount, WitnessField::Flags).await;
    }

    #[tokio::test]
    async fn classic_disagreement_destination_existence() {
        account_disagrees(WitnessEntry::DestinationAccount, WitnessField::Existence).await;
    }

    #[tokio::test]
    async fn classic_disagreement_destination_home_domain() {
        account_disagrees(WitnessEntry::DestinationAccount, WitnessField::HomeDomain).await;
    }

    #[tokio::test]
    async fn classic_disagreement_destination_flags() {
        account_disagrees(WitnessEntry::DestinationAccount, WitnessField::Flags).await;
    }

    #[tokio::test]
    async fn classic_disagreement_issuer_existence() {
        account_disagrees(WitnessEntry::IssuerAccount, WitnessField::Existence).await;
    }

    #[tokio::test]
    async fn classic_disagreement_issuer_flags() {
        account_disagrees(WitnessEntry::IssuerAccount, WitnessField::Flags).await;
    }

    #[tokio::test]
    async fn classic_disagreement_funder_sequence() {
        account_disagrees(WitnessEntry::FunderAccount, WitnessField::Sequence).await;
    }

    #[tokio::test]
    async fn classic_disagreement_funder_native_balance() {
        account_disagrees(WitnessEntry::FunderAccount, WitnessField::NativeBalance).await;
    }

    #[tokio::test]
    async fn classic_disagreement_funder_subentry_count() {
        account_disagrees(WitnessEntry::FunderAccount, WitnessField::SubentryCount).await;
    }

    #[tokio::test]
    async fn classic_disagreement_funder_flags() {
        account_disagrees(WitnessEntry::FunderAccount, WitnessField::Flags).await;
    }

    fn claim() -> (ClassicInputs, TrustLineEntry, ClaimableBalanceEntry) {
        let asset = CanonicalAsset::classic("USD", &address(9)).unwrap();
        let trustline = TrustLineEntry {
            account_id: account_id(&address(7)).unwrap(),
            asset: ClassicAsset::parse(&asset.to_string())
                .unwrap()
                .to_xdr_trust_line_asset()
                .unwrap(),
            balance: 1_000,
            limit: 10_000,
            flags: 1,
            ext: TrustLineEntryExt::V0,
        };
        let balance = ClaimableBalanceEntry {
            balance_id: ClaimableBalanceId::ClaimableBalanceIdTypeV0(Hash([3; 32])),
            claimants: vec![].try_into().unwrap(),
            asset: stellar_xdr::Asset::Native,
            amount: 10,
            ext: ClaimableBalanceEntryExt::V0,
        };
        let inputs = ClaimWitnessInputs {
            source: source(7),
            trustline: Some(
                TrustlineObservation::from_entry(&address(7), asset, Some(&trustline)).unwrap(),
            ),
            balance: Some(ClaimableBalanceObservation {
                balance_id: [3; 32],
                entry: Some(balance.clone()),
            }),
        }
        .into();
        (inputs, trustline, balance)
    }
    fn claim_answer(
        inputs: &ClassicInputs,
        trustline: Option<TrustLineEntry>,
        balance: Option<ClaimableBalanceEntry>,
    ) -> serde_json::Value {
        let observations = inputs.observations().unwrap();
        let mut entries = vec![account_answer(7)];
        if let Some(t) = trustline {
            entries.push(entry(&observations[1].key, LedgerEntryData::Trustline(t)));
        }
        if let Some(b) = balance {
            entries.push(entry(
                &observations[2].key,
                LedgerEntryData::ClaimableBalance(b),
            ));
        }
        answer(entries)
    }
    async fn trustline_disagrees(field: WitnessField) {
        let (inputs, mut trustline, balance) = claim();
        match field {
            WitnessField::Balance => trustline.balance += 1,
            WitnessField::Limit => trustline.limit += 1,
            WitnessField::Flags => trustline.flags ^= 2,
            _ => {}
        }
        let trustline = (field != WitnessField::Existence).then_some(trustline);
        let body = claim_answer(&inputs, trustline, Some(balance));
        disagrees(inputs, body, WitnessEntry::SourceTrustline, field).await;
    }
    #[tokio::test]
    async fn classic_disagreement_trustline_existence() {
        trustline_disagrees(WitnessField::Existence).await;
    }
    #[tokio::test]
    async fn classic_disagreement_trustline_balance() {
        trustline_disagrees(WitnessField::Balance).await;
    }
    #[tokio::test]
    async fn classic_disagreement_trustline_limit() {
        trustline_disagrees(WitnessField::Limit).await;
    }
    #[tokio::test]
    async fn classic_disagreement_trustline_flags() {
        trustline_disagrees(WitnessField::Flags).await;
    }
    fn pay_with_trustline() -> (ClassicInputs, TrustLineEntry) {
        let (claim_inputs, trustline, _) = claim();
        let ClassicInputs::Claim(ClaimWitnessInputs {
            trustline: Some(observation),
            ..
        }) = claim_inputs
        else {
            panic!("claim fixture carries a trustline");
        };
        let inputs = PayWitnessInputs {
            source: source(7),
            destination: DestinationObservation::from_view(
                &address(8),
                Some(&project_account_entry(&address(8), &account(8)).unwrap()),
            ),
            memo: MemoObservation::NotRead,
            trustline: Some(observation),
        }
        .into();
        (inputs, trustline)
    }
    fn pay_trustline_answer(
        inputs: &ClassicInputs,
        trustline: Option<TrustLineEntry>,
    ) -> serde_json::Value {
        let observations = inputs.observations().unwrap();
        let mut entries = vec![account_answer(7), account_answer(8)];
        if let Some(t) = trustline {
            let key = &observations
                .iter()
                .find(|o| o.kind == WitnessEntry::SourceTrustline)
                .unwrap()
                .key;
            entries.push(entry(key, LedgerEntryData::Trustline(t)));
        }
        answer(entries)
    }
    async fn pay_trustline_disagrees(field: WitnessField) {
        let (inputs, mut trustline) = pay_with_trustline();
        match field {
            WitnessField::Balance => trustline.balance += 1,
            WitnessField::Limit => trustline.limit += 1,
            WitnessField::Flags => trustline.flags ^= 2,
            _ => {}
        }
        let trustline = (field != WitnessField::Existence).then_some(trustline);
        let body = pay_trustline_answer(&inputs, trustline);
        disagrees(inputs, body, WitnessEntry::SourceTrustline, field).await;
    }
    #[tokio::test]
    async fn classic_pay_trustline_match_covers_the_trustline() {
        let (inputs, trustline) = pay_with_trustline();
        let server = oracle(network()).await;
        read_mock(&server, pay_trustline_answer(&inputs, Some(trustline))).await;
        let outcome = run(&server, inputs).await.unwrap();
        assert_eq!(
            outcome.witness().unwrap().kinds(),
            [
                WitnessEntry::SourceAccount,
                WitnessEntry::SourceTrustline,
                WitnessEntry::DestinationAccount
            ]
        );
    }
    #[tokio::test]
    async fn classic_pay_trustline_disagreement_existence() {
        pay_trustline_disagrees(WitnessField::Existence).await;
    }
    #[tokio::test]
    async fn classic_pay_trustline_disagreement_balance() {
        pay_trustline_disagrees(WitnessField::Balance).await;
    }
    #[tokio::test]
    async fn classic_pay_trustline_disagreement_limit() {
        pay_trustline_disagrees(WitnessField::Limit).await;
    }
    #[tokio::test]
    async fn classic_pay_trustline_disagreement_flags() {
        pay_trustline_disagrees(WitnessField::Flags).await;
    }
    #[tokio::test]
    async fn classic_disagreement_claimable_record() {
        let (inputs, trustline, mut balance) = claim();
        balance.amount += 1;
        let body = claim_answer(&inputs, Some(trustline), Some(balance));
        disagrees(
            inputs,
            body,
            WitnessEntry::ClaimableBalance,
            WitnessField::Record,
        )
        .await;
    }
    #[tokio::test]
    async fn classic_disagreement_claimable_absence() {
        let (inputs, trustline, _) = claim();
        let body = claim_answer(&inputs, Some(trustline), None);
        disagrees(
            inputs,
            body,
            WitnessEntry::ClaimableBalance,
            WitnessField::Existence,
        )
        .await;
    }
    #[tokio::test]
    async fn classic_disagreement_pool_channel_existence() {
        let inputs = PoolInitWitnessInputs {
            funder: source(7),
            absent_channels: vec![address(8)],
        };
        disagrees(
            inputs.into(),
            pay_answer(),
            WitnessEntry::PoolChannelAccount,
            WitnessField::Existence,
        )
        .await;
    }
    #[tokio::test]
    async fn classic_memo_flag_disagreement_is_rpc_divergence() {
        let server = oracle(network()).await;
        let inputs = pay();
        let key = inputs.observations().unwrap()[2].key.clone();
        let LedgerKey::Data(k) = &key else {
            panic!("data key")
        };
        let memo = LedgerEntryData::Data(DataEntry {
            account_id: k.account_id.clone(),
            data_name: k.data_name.clone(),
            data_value: b"1".to_vec().try_into().unwrap(),
            ext: DataEntryExt::V0,
        });
        read_mock(
            &server,
            answer(vec![
                account_answer(7),
                account_answer(8),
                entry(&key, memo),
            ]),
        )
        .await;
        let error = run(&server, inputs).await.unwrap_err();
        assert_eq!(error.code(), "network.rpc_divergence");
        assert_eq!(
            error.to_string(),
            "SEP-29 config.memo_required differs between primary and secondary RPC; re-simulate"
        );
        assert_eq!(methods(&server).await, ["getNetwork", "getLedgerEntries"]);
    }
    #[tokio::test]
    async fn classic_answer_out_of_order_associates_by_key() {
        // The two accounts differ in every compared field, so an answer
        // associated by position fails a field comparison.
        let mut destination = account(8);
        destination.seq_num.0 = 7_000;
        destination.balance = 5_000_000;
        destination.num_sub_entries = 9;
        destination.flags = 1;
        destination.home_domain = b"destination.example".to_vec().try_into().unwrap();
        let inputs: ClassicInputs = PayWitnessInputs {
            source: source(7),
            destination: DestinationObservation::from_view(
                &address(8),
                Some(&project_account_entry(&address(8), &destination).unwrap()),
            ),
            memo: MemoObservation::Read(false),
            trustline: None,
        }
        .into();
        let server = oracle(network()).await;
        read_mock(
            &server,
            answer(vec![
                entry(
                    &account_key(&address(8)).unwrap(),
                    LedgerEntryData::Account(destination),
                ),
                account_answer(7),
            ]),
        )
        .await;
        let outcome = run(&server, inputs.clone()).await.unwrap();
        let witness = outcome.witness().unwrap();
        assert_eq!(witness.oracle_ledger(), 100);
        assert_eq!(
            witness.kinds(),
            [
                WitnessEntry::SourceAccount,
                WitnessEntry::DestinationAccount,
                WitnessEntry::MemoRequirement
            ]
        );
        let requests = server.received_requests().await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&requests[1].body).unwrap();
        let requested: Vec<_> = keys(&inputs.observations().unwrap())
            .iter()
            .map(|key| key.to_xdr_base64(Limits::none()).unwrap())
            .collect();
        assert_eq!(body["params"]["keys"], json!(requested));
    }
    #[tokio::test]
    async fn self_payment_requests_the_source_key_once() {
        let server = oracle(network()).await;
        read_mock(&server, answer(vec![account_answer(7)])).await;
        let inputs = PayWitnessInputs {
            source: source(7),
            destination: DestinationObservation::from_view(
                &address(7),
                Some(&project_account_entry(&address(7), &account(7)).unwrap()),
            ),
            memo: MemoObservation::NotRead,
            trustline: None,
        };
        assert!(
            run(&server, inputs.into())
                .await
                .unwrap()
                .witness()
                .is_some()
        );
        let requests = server.received_requests().await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&requests[1].body).unwrap();
        assert_eq!(body["params"]["keys"].as_array().unwrap().len(), 1);
    }
    async fn invalid_answer(body: serde_json::Value) {
        invalid_answer_for(pay(), body).await;
    }
    async fn invalid_answer_for(inputs: ClassicInputs, body: serde_json::Value) {
        let server = oracle(network()).await;
        read_mock(&server, body).await;
        let error = run(&server, inputs).await.unwrap_err();
        assert!(
            matches!(
                error,
                WalletError::Network(NetworkError::WitnessUnavailable {
                    reason: Reason::InvalidAnswer { .. }
                })
            ),
            "{error}"
        );
        assert_eq!(methods(&server).await, ["getNetwork", "getLedgerEntries"]);
    }
    #[tokio::test]
    async fn invalid_answer_duplicate_key_is_witness_unavailable() {
        invalid_answer(answer(vec![
            account_answer(7),
            account_answer(8),
            account_answer(7),
        ]))
        .await;
    }
    #[tokio::test]
    async fn invalid_answer_unrequested_key_is_witness_unavailable() {
        invalid_answer(answer(vec![
            account_answer(7),
            account_answer(8),
            account_answer(9),
        ]))
        .await;
    }
    #[tokio::test]
    async fn invalid_answer_mismatched_data_is_witness_unavailable() {
        let (_, t, _) = claim();
        invalid_answer(answer(vec![entry(
            &account_key(&address(7)).unwrap(),
            LedgerEntryData::Trustline(t),
        )]))
        .await;
    }
    #[tokio::test]
    async fn invalid_answer_undecodable_entry_is_witness_unavailable() {
        let mut body = pay_answer();
        body["entries"][0]["xdr"] = json!("invalid-XDR");
        invalid_answer(body).await;
    }
    #[tokio::test]
    async fn invalid_answer_ledger_out_of_range_is_witness_unavailable() {
        for ledger in [-1_i64, 0, i64::from(u32::MAX) + 1] {
            let mut body = pay_answer();
            body["latestLedger"] = json!(ledger);
            invalid_answer(body).await;
        }
    }
    #[tokio::test]
    async fn invalid_answer_mismatched_identity_is_witness_unavailable_without_retry() {
        invalid_answer(answer(vec![
            entry(
                &account_key(&address(7)).unwrap(),
                LedgerEntryData::Account(account(9)),
            ),
            account_answer(8),
        ]))
        .await;
        for field in 0..3 {
            let (inputs, mut trustline, mut balance) = claim();
            match field {
                0 => trustline.account_id = account_id(&address(10)).unwrap(),
                1 => {
                    trustline.asset = stellar_xdr::TrustLineAsset::CreditAlphanum4(AlphaNum4 {
                        asset_code: AssetCode4(*b"EUR\0"),
                        issuer: account_id(&address(9)).unwrap(),
                    })
                }
                _ => {
                    balance.balance_id = ClaimableBalanceId::ClaimableBalanceIdTypeV0(Hash([4; 32]))
                }
            }
            let body = claim_answer(&inputs, Some(trustline), Some(balance));
            invalid_answer_for(inputs, body).await;
        }
        for wrong_account in [false, true] {
            let observations = pay().observations().unwrap();
            let data = DataEntry {
                account_id: account_id(&address(if wrong_account { 9 } else { 8 })).unwrap(),
                data_name: if wrong_account {
                    b"config.memo_required".to_vec()
                } else {
                    b"other".to_vec()
                }
                .try_into()
                .unwrap(),
                data_value: DataValue(vec![0].try_into().unwrap()),
                ext: DataEntryExt::V0,
            };
            invalid_answer(answer(vec![
                account_answer(7),
                account_answer(8),
                entry(&observations[2].key, LedgerEntryData::Data(data)),
            ]))
            .await;
        }
    }
    #[tokio::test]
    async fn classic_mismatch_never_retries() {
        // The first read disagrees and every later read agrees, so a retry
        // after a disagreement would pass.
        let server = oracle(network()).await;
        let mut moved = account(7);
        moved.seq_num.0 += 1;
        Mock::given(method("POST"))
            .and(body_partial_json(json!({"method": "getLedgerEntries"})))
            .respond_with(EchoIdResponder::new(answer(vec![entry(
                &account_key(&address(7)).unwrap(),
                LedgerEntryData::Account(moved),
            )])))
            .up_to_n_times(1)
            .with_priority(1)
            .mount(&server)
            .await;
        read_mock(&server, answer(vec![account_answer(7)])).await;
        let error = run(
            &server,
            CreateAccountWitnessInputs { source: source(7) }.into(),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(
                error,
                WalletError::Network(NetworkError::WitnessDivergence {
                    entry: WitnessEntry::SourceAccount,
                    field: WitnessField::Sequence,
                    sequence_delta: Some(1),
                })
            ),
            "{error}"
        );
        let reads = methods(&server)
            .await
            .iter()
            .filter(|method| *method == "getLedgerEntries")
            .count();
        assert_eq!(reads, 1);
    }
    #[tokio::test(flavor = "current_thread")]
    async fn classic_transport_retries_three_times_then_witness_unavailable() {
        let server = oracle(network()).await;
        Mock::given(method("POST"))
            .and(body_partial_json(json!({"method": "getLedgerEntries"})))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;
        #[cfg(feature = "test-hooks")]
        let before = crate::client::constructions_on_this_thread();
        let error = run(&server, pay()).await.unwrap_err();
        #[cfg(feature = "test-hooks")]
        assert_eq!(crate::client::constructions_on_this_thread() - before, 1);
        assert!(
            matches!(
                error,
                WalletError::Network(NetworkError::WitnessUnavailable {
                    reason: Reason::Transport { attempts: 3, .. }
                })
            ),
            "{error}"
        );
        assert_eq!(
            methods(&server).await,
            [
                "getNetwork",
                "getLedgerEntries",
                "getLedgerEntries",
                "getLedgerEntries"
            ]
        );
    }
    #[tokio::test]
    async fn classic_read_401_keeps_credential_code_without_retry() {
        for status in [401, 403] {
            let server = oracle(network()).await;
            Mock::given(method("POST"))
                .and(body_partial_json(json!({"method": "getLedgerEntries"})))
                .respond_with(ResponseTemplate::new(status))
                .mount(&server)
                .await;
            let error = run(&server, pay()).await.unwrap_err();
            assert_eq!(error.code(), "network.rpc_credential_refused");
            assert_eq!(
                error.to_string(),
                format!(
                    "RPC endpoint '{}' answered a request with HTTP {status}; \
                 check the credential the profile configures for this endpoint",
                    server.uri()
                )
            );
            assert_eq!(methods(&server).await, ["getNetwork", "getLedgerEntries"]);
        }
    }
    #[tokio::test]
    async fn classic_unparseable_read_body_is_invalid_answer() {
        let server = oracle(network()).await;
        Mock::given(method("POST"))
            .and(body_partial_json(json!({"method": "getLedgerEntries"})))
            .respond_with(ResponseTemplate::new(200).set_body_string("hostile-body"))
            .mount(&server)
            .await;
        let error = run(&server, pay()).await.unwrap_err();
        assert!(matches!(
            error,
            WalletError::Network(NetworkError::WitnessUnavailable {
                reason: Reason::InvalidAnswer { .. }
            })
        ));
        assert!(!error.to_string().contains("hostile-body"));
        assert_eq!(methods(&server).await, ["getNetwork", "getLedgerEntries"]);
    }
    #[tokio::test]
    async fn invalid_answer_jsonrpc_error_object_is_witness_unavailable_without_retry() {
        let server = oracle(network()).await;
        Mock::given(method("POST"))
            .and(body_partial_json(json!({"method": "getLedgerEntries"})))
            .respond_with(|request: &wiremock::Request| {
                let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
                ResponseTemplate::new(200).set_body_json(json!({"jsonrpc": "2.0", "id": body["id"],
                    "error": {"code": -32601, "message": "hostile-server-text"}}))
            })
            .mount(&server)
            .await;
        let error = run(&server, pay()).await.unwrap_err();
        assert!(matches!(
            error,
            WalletError::Network(NetworkError::WitnessUnavailable {
                reason: Reason::InvalidAnswer { .. }
            })
        ));
        assert_eq!(methods(&server).await, ["getNetwork", "getLedgerEntries"]);
    }
    #[tokio::test]
    async fn classic_oracle_on_mainnet_from_testnet_profile_is_identity_mismatch() {
        let server = oracle(
            stellar_agent_test_support::signed_envelope::get_network_result(
                stellar_agent_core::profile::caip2::MAINNET_PASSPHRASE,
            ),
        )
        .await;
        let error = run(&server, pay()).await.unwrap_err();
        assert!(matches!(
            error,
            WalletError::Network(NetworkError::WitnessUnavailable {
                reason: Reason::IdentityNetworkMismatch { .. }
            })
        ));
        assert_eq!(methods(&server).await, ["getNetwork"]);
    }
    #[tokio::test(flavor = "current_thread")]
    async fn read_error_traces_carry_no_server_text() {
        let server = oracle(network()).await;
        Mock::given(method("POST"))
            .and(body_partial_json(json!({"method": "getLedgerEntries"})))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                "https://user:credential-marker@example.invalid/private-path?token=secret-marker",
            ))
            .mount(&server)
            .await;
        let (result, logs) =
            super::super::log_capture::capture_logs(tracing::Level::TRACE, run(&server, pay()))
                .await;
        assert!(result.is_err());
        for forbidden in [
            "credential-marker",
            "secret-marker",
            "private-path",
            "user:",
        ] {
            assert!(!logs.contains(forbidden), "{logs}");
        }
        assert!(logs.contains("invalid_answer"), "{logs}");
    }
    #[test]
    fn witness_digest_known_answer() {
        let inputs: ClassicInputs = CreateAccountWitnessInputs { source: source(7) }.into();
        let digest = digest::inputs_digest(&inputs.observations().unwrap()).unwrap();
        assert_eq!(
            crate::submit::bytes_to_hex(&digest),
            "4599cc6feafbb83a1786f61d603f4e2d5358f4ecf8b4fbe9d74e20de3fc17f91"
        );
    }

    /// The payment path digests the source account, the destination, and the
    /// memo flag. The expected value follows from the layout in the digest
    /// module documentation, computed outside the crate.
    #[test]
    fn witness_digest_payment_known_answer() {
        let digest = digest::inputs_digest(&pay().observations().unwrap()).unwrap();
        assert_eq!(
            crate::submit::bytes_to_hex(&digest),
            "208b05ecf07b830903869e9bb6d77acf0d9d241d02284a9bae131b415432d06f"
        );
    }

    #[test]
    fn witness_digest_changes_for_each_account_field() {
        let inputs: ClassicInputs = CreateAccountWitnessInputs { source: source(7) }.into();
        let observations = inputs.observations().unwrap();
        let base = digest::inputs_digest(&observations).unwrap();
        for field in 0..9 {
            let mut changed = observations.clone();
            let Observed::Account(value) = &mut changed[0].value else {
                panic!("account")
            };
            match field {
                0 => value.sequence += 1,
                1 => value.native_balance += 1,
                2 => value.subentry_count += 1,
                3 => value.flags = None,
                4 => value.flags.as_mut().unwrap().auth_required = true,
                5 => value.flags.as_mut().unwrap().auth_revocable = true,
                6 => value.flags.as_mut().unwrap().auth_immutable = true,
                7 => value.flags.as_mut().unwrap().auth_clawback_enabled = true,
                _ => changed[0].key = account_key(&address(8)).unwrap(),
            }
            assert_ne!(
                base,
                digest::inputs_digest(&changed).unwrap(),
                "field {field}"
            );
        }
    }
    async fn run_profile(profile: &Profile) -> Result<CrossCheckOutcome, WalletError> {
        obtain_classic_witness_with_timing(
            profile,
            &NetworkContext::from_profile(profile),
            CrossCheckValue::Unvalued,
            pay(),
            "test_witness",
            WitnessTiming {
                attempt_budget: Duration::from_millis(300),
                retry_backoff: Duration::from_millis(1),
            },
        )
        .await
    }

    #[tokio::test]
    async fn classic_match_returns_witness_and_reads_in_one_batched_request() {
        let server = oracle(network()).await;
        read_mock(&server, pay_answer()).await;
        let outcome = run(&server, pay()).await.unwrap();
        let witness = outcome.witness().unwrap();
        assert_eq!(witness.authority(), server.uri());
        assert_eq!(witness.oracle_ledger(), 100);
        assert_eq!(witness.inputs_digest_hex().len(), 64);
        assert_eq!(
            witness.kinds(),
            &[
                WitnessEntry::SourceAccount,
                WitnessEntry::DestinationAccount,
                WitnessEntry::MemoRequirement,
            ]
        );
        assert_eq!(outcome.view().status, "passed");
        let requests = server.received_requests().await.unwrap();
        assert_eq!(methods(&server).await, ["getNetwork", "getLedgerEntries"]);
        let body: serde_json::Value = serde_json::from_slice(&requests[1].body).unwrap();
        let expected: Vec<_> = keys(&pay().observations().unwrap())
            .iter()
            .map(|key| key.to_xdr_base64(Limits::none()).unwrap())
            .collect();
        assert_eq!(body["params"]["keys"], json!(expected));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn classic_skip_and_not_required_make_no_oracle_request() {
        let server = oracle(network()).await;
        let mut profile = profile(&server);
        let native = CanonicalAsset::Native;
        let credit = CanonicalAsset::classic("USD", &address(9)).unwrap();
        for (asset, amount, missing, expected) in [
            (&native, 1, false, "not_required"),
            (&credit, i128::MAX, false, "skipped"),
            (&native, i128::MAX, true, "skipped"),
        ] {
            if missing {
                profile.oracle_provider_url = None;
            }
            #[cfg(feature = "test-hooks")]
            let before = crate::client::constructions_on_this_thread();
            let outcome = obtain_classic_witness(
                &profile,
                &NetworkContext::from_profile(&profile),
                CrossCheckValue::Amount {
                    asset,
                    base_units: amount,
                },
                CreateAccountWitnessInputs { source: source(7) },
                "test_witness",
            )
            .await
            .unwrap();
            assert_eq!(outcome.view().status, expected);
            #[cfg(feature = "test-hooks")]
            assert_eq!(crate::client::constructions_on_this_thread(), before);
        }
        assert!(methods(&server).await.is_empty());
    }

    #[tokio::test]
    async fn classic_transport_failure_recovers_without_repeating_identity() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        let server = oracle(network()).await;
        let attempts = Arc::new(AtomicUsize::new(0));
        let count = attempts.clone();
        Mock::given(method("POST"))
            .and(body_partial_json(json!({"method": "getLedgerEntries"})))
            .respond_with(move |request: &wiremock::Request| {
                if count.fetch_add(1, Ordering::SeqCst) == 0 {
                    ResponseTemplate::new(503)
                } else {
                    wiremock::Respond::respond(&EchoIdResponder::new(pay_answer()), request)
                }
            })
            .mount(&server)
            .await;
        assert!(run(&server, pay()).await.unwrap().witness().is_some());
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
        assert_eq!(
            methods(&server).await,
            ["getNetwork", "getLedgerEntries", "getLedgerEntries"]
        );
    }

    async fn deadline_case(identity_delay: Duration, read_delay: Duration) {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(body_partial_json(json!({"method": "getNetwork"})))
            .respond_with(move |request: &wiremock::Request| {
                wiremock::Respond::respond(&EchoIdResponder::new(network()), request)
                    .set_delay(identity_delay)
            })
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(body_partial_json(json!({"method": "getLedgerEntries"})))
            .respond_with(move |request: &wiremock::Request| {
                wiremock::Respond::respond(&EchoIdResponder::new(pay_answer()), request)
                    .set_delay(read_delay)
            })
            .mount(&server)
            .await;
        let error = run(&server, pay()).await.unwrap_err();
        assert!(
            matches!(
                error,
                WalletError::Network(NetworkError::WitnessUnavailable {
                    reason: Reason::DeadlineExhausted { .. }
                })
            ),
            "{error}"
        );
        assert_eq!(methods(&server).await, ["getNetwork", "getLedgerEntries"]);
    }

    #[tokio::test]
    async fn classic_deadline_is_witness_unavailable() {
        deadline_case(Duration::ZERO, Duration::from_millis(600)).await;
    }

    #[tokio::test]
    async fn classic_identity_and_reads_share_attempt_deadline() {
        deadline_case(Duration::from_millis(200), Duration::from_millis(200)).await;
    }

    #[tokio::test]
    async fn classic_identity_failure_never_retries() {
        let server = oracle(
            stellar_agent_test_support::signed_envelope::get_network_result("private-network"),
        )
        .await;
        let error = run(&server, pay()).await.unwrap_err();
        assert!(
            matches!(
                error,
                WalletError::Network(NetworkError::WitnessUnavailable {
                    reason: Reason::IdentityNetworkMismatch { .. }
                })
            ),
            "{error}"
        );
        assert_eq!(methods(&server).await, ["getNetwork"]);
    }

    fn bind_oracle_credential(profile: &mut Profile, value: Option<&str>) {
        use stellar_agent_core::profile::schema::{
            KeyringEntryRef, ProviderRecord, Providers, RpcCredentialPlacement,
        };
        let entry = KeyringEntryRef::new("stellar-agent-witness-test", "oracle");
        profile
            .providers
            .get_or_insert_with(Providers::default)
            .oracle = Some(
            ProviderRecord::new("Oracle RPC", "127.0.0.1", true).with_credential(
                entry.clone(),
                RpcCredentialPlacement::Header {
                    name: "X-API-Key".into(),
                },
            ),
        );
        if let Some(value) = value {
            keyring_core::Entry::new(&entry.service, &entry.account)
                .unwrap()
                .set_password(value)
                .unwrap();
        }
    }

    #[tokio::test(flavor = "current_thread")]
    #[serial_test::serial(keyring)]
    async fn classic_sends_oracle_credential() {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let server = oracle(network()).await;
        read_mock(&server, pay_answer()).await;
        let mut profile = profile(&server);
        bind_oracle_credential(&mut profile, Some("synthetic-oracle-credential"));
        assert!(run_profile(&profile).await.unwrap().witness().is_some());
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 2);
        for request in requests {
            assert_eq!(
                request.headers.get("X-API-Key").unwrap(),
                "synthetic-oracle-credential"
            );
        }
    }

    #[tokio::test(flavor = "current_thread")]
    #[serial_test::serial(keyring)]
    async fn classic_missing_oracle_credential_reports_keyring_not_found() {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let server = oracle(network()).await;
        let mut profile = profile(&server);
        bind_oracle_credential(&mut profile, None);
        let error = run_profile(&profile).await.unwrap_err();
        assert_eq!(error.code(), "auth.keyring_not_found");
        assert!(
            error
                .to_string()
                .contains("stellar-agent-witness-test/oracle")
        );
        assert!(methods(&server).await.is_empty());
    }

    #[tokio::test]
    async fn classic_credential_rejection_keeps_credential_code() {
        for status in [401, 403] {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .respond_with(ResponseTemplate::new(status))
                .mount(&server)
                .await;
            let error = run(&server, pay()).await.unwrap_err();
            assert_eq!(error.code(), "network.rpc_credential_refused");
            assert_eq!(
                error.to_string(),
                format!(
                    "RPC endpoint '{}' answered a request with HTTP {status}; \
                 check the credential the profile configures for this endpoint",
                    server.uri()
                )
            );
            assert_eq!(methods(&server).await, ["getNetwork"]);
        }
    }

    async fn warning_case(shared_operator: bool) {
        use super::super::log_capture::capture_logs;
        use stellar_agent_core::profile::schema::{
            PrimaryProviderRecord, ProviderRecord, Providers,
        };
        let server = oracle(network()).await;
        read_mock(&server, pay_answer()).await;
        let mut profile = profile(&server);
        if shared_operator {
            let providers = profile.providers.get_or_insert_with(Providers::default);
            providers.primary = Some(PrimaryProviderRecord::new(" Shared RPC ", "127.0.0.1"));
            providers.oracle = Some(ProviderRecord::new("shared rpc", "127.0.0.1", true));
        }
        let (outcome, captured) = capture_logs(tracing::Level::WARN, run_profile(&profile)).await;
        assert!(outcome.unwrap().witness().is_some());
        assert!(captured.contains("policy.cross_check"), "{captured}");
        let text = if shared_operator {
            "oracle provider record names the primary's operator; cross-check is degraded \
             to single-RPC verification"
        } else {
            "oracle_provider_url shares the provider host of rpc_url; \
             cross-check is degraded to single-RPC verification"
        };
        assert!(captured.contains(text), "{captured}");
        if shared_operator {
            profile.providers.as_mut().unwrap().oracle =
                Some(ProviderRecord::new("Other RPC", "127.0.0.1", true));
            let (outcome, captured) =
                capture_logs(tracing::Level::WARN, run_profile(&profile)).await;
            assert!(outcome.unwrap().witness().is_some());
            assert!(
                !captured.contains("names the primary's operator"),
                "{captured}"
            );
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn classic_same_host_warns_on_testnet() {
        warning_case(false).await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn classic_shared_operator_warns_on_testnet() {
        warning_case(true).await;
    }

    #[tokio::test]
    async fn witness_errors_echo_no_secret() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;
        let mut profile = profile(&server);
        let hostile = format!("{}/private-path?token=credential-marker", server.uri());
        profile.oracle_provider_url = Some(url::Url::parse(&hostile).unwrap());
        let error = run_profile(&profile).await.unwrap_err();
        assert_eq!(error.code(), "network.rpc_credential_refused");
        for forbidden in ["private-path", "credential-marker", "token="] {
            assert!(!error.to_string().contains(forbidden));
        }
        profile.oracle_provider_url = Some(
            url::Url::parse(
                "ftp://user:credential-marker@example.invalid/private-path?token=secret",
            )
            .unwrap(),
        );
        let error = run_profile(&profile).await.unwrap_err();
        assert!(
            matches!(
                error,
                WalletError::Network(NetworkError::WitnessUnavailable {
                    reason: Reason::ClientConstruction { .. }
                })
            ),
            "{error}"
        );
        assert_eq!(
            error.to_string(),
            "cross-check unavailable: the client for oracle 'ftp://example.invalid' \
             could not be built; correct oracle_provider_url in the profile file"
        );
    }

    #[tokio::test]
    async fn invalid_answer_response_id_is_witness_unavailable_without_retry() {
        let server = oracle(network()).await;
        Mock::given(method("POST"))
            .and(body_partial_json(json!({"method": "getLedgerEntries"})))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "jsonrpc": "2.0", "id": "unexpected", "result": pay_answer()
            })))
            .mount(&server)
            .await;
        let error = run(&server, pay()).await.unwrap_err();
        assert!(
            matches!(
                error,
                WalletError::Network(NetworkError::WitnessUnavailable {
                    reason: Reason::InvalidAnswer { .. }
                })
            ),
            "{error}"
        );
        assert_eq!(methods(&server).await, ["getNetwork", "getLedgerEntries"]);
    }

    #[test]
    fn witness_digest_changes_for_each_compared_field() {
        let (claim_inputs, _, _) = claim();
        let mut observations = claim_inputs.observations().unwrap();
        observations.extend(pay().observations().unwrap().into_iter().skip(1));
        let issuer_inputs: ClassicInputs = TrustlineWitnessInputs {
            source: source(7),
            issuer: IssuerObservation::from_view(
                &address(9),
                Some(&project_account_entry(&address(9), &account(9)).unwrap()),
            ),
        }
        .into();
        observations.extend(issuer_inputs.observations().unwrap().into_iter().skip(1));
        let pool_inputs: ClassicInputs = PoolInitWitnessInputs {
            funder: source(7),
            absent_channels: vec![address(10), address(11)],
        }
        .into();
        observations.extend(pool_inputs.observations().unwrap());
        observations.sort_by_key(|o| o.kind);
        let base = digest::inputs_digest(&observations).unwrap();
        let mut changes = Vec::new();
        for (index, observation) in observations.iter().enumerate() {
            let mut changed = observations.clone();
            changed[index].key = account_key(&address(12)).unwrap();
            changes.push(changed);
            let variants: Vec<Observed> = match &observation.value {
                Observed::Account(_) => continue,
                Observed::Trustline(v) => (0..4)
                    .map(|field| {
                        let mut v = v.clone();
                        match field {
                            0 => v.state = None,
                            1 => v.state.as_mut().unwrap().0 += 1,
                            2 => v.state.as_mut().unwrap().1 += 1,
                            _ => v.state.as_mut().unwrap().2 ^= 2,
                        }
                        Observed::Trustline(v)
                    })
                    .collect(),
                Observed::Destination(v) => (0..8)
                    .map(|field| {
                        let mut v = v.clone();
                        match field {
                            0 => v.present = None,
                            1 => v.present.as_mut().unwrap().0 = None,
                            2 => v.present.as_mut().unwrap().0 = Some("other.example".into()),
                            3 => v.present.as_mut().unwrap().1 = None,
                            n => {
                                let f = v.present.as_mut().unwrap().1.as_mut().unwrap();
                                match n {
                                    4 => f.auth_required = true,
                                    5 => f.auth_revocable = true,
                                    6 => f.auth_immutable = true,
                                    _ => f.auth_clawback_enabled = true,
                                }
                            }
                        }
                        Observed::Destination(v)
                    })
                    .collect(),
                Observed::Issuer(v) => (0..6)
                    .map(|field| {
                        let mut v = v.clone();
                        match field {
                            0 => v.flags = None,
                            1 => v.flags = Some(None),
                            n => {
                                let f = v.flags.as_mut().unwrap().as_mut().unwrap();
                                match n {
                                    2 => f.auth_required = true,
                                    3 => f.auth_revocable = true,
                                    4 => f.auth_immutable = true,
                                    _ => f.auth_clawback_enabled = true,
                                }
                            }
                        }
                        Observed::Issuer(v)
                    })
                    .collect(),
                Observed::Claimable(v) => (0..2)
                    .map(|field| {
                        let mut v = v.clone();
                        if field == 0 {
                            v.entry = None;
                        } else {
                            v.entry.as_mut().unwrap().amount += 1;
                        }
                        Observed::Claimable(v)
                    })
                    .collect(),
                Observed::Memo(value) => vec![Observed::Memo(!value)],
                Observed::Absent => vec![],
            };
            for variant in variants {
                let mut changed = observations.clone();
                changed[index].value = variant;
                changes.push(changed);
            }
        }
        let mut changed = observations.clone();
        let channels: Vec<_> = observations
            .iter()
            .enumerate()
            .filter_map(|(i, o)| (o.kind == WitnessEntry::PoolChannelAccount).then_some(i))
            .collect();
        changed.swap(channels[0], channels[1]);
        changes.push(changed);
        let mut changed = observations.clone();
        changed[0].kind = WitnessEntry::FunderAccount;
        changes.push(changed);
        for (i, changed) in changes.iter().enumerate() {
            assert_ne!(
                base,
                digest::inputs_digest(changed).unwrap(),
                "mutation {i}"
            );
        }
    }
}
