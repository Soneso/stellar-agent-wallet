//! Public toolset payments under signed mainnet policies and local RPC fixtures.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test assertions"
)]

use super::common::tests::mainnet::{
    Fixture, RpcControl, Tool, authorizations, classic_policy, mount_rpc, wire,
};
use super::toolsets::StellarToolsetInvokeArgs;
use serde_json::Value;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use stellar_agent_core::approval::{
    AttestationBinding, PendingApprovalStore, process_uid_for_attestation,
};
use stellar_agent_core::timefmt::now_unix_ms;
use stellar_agent_toolsets_runtime::{PinKey, record_first_invoke_grant};

#[path = "toolsets_payment_process_tests.rs"]
mod process;

const TOOLSET: &str = "unattended-payments";
const INSTALL: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn policy(raw: &str, outer: &str, routed: &str, ttl: i64) -> String {
    let mut doc = classic_policy(raw)
        .parse::<toml_edit::DocumentMut>()
        .unwrap();
    let rules = doc["rules"].as_array_of_tables_mut().unwrap();
    let mut invocation = rules.get(0).unwrap().clone();
    invocation["match"]["tool"] = toml_edit::value("stellar_toolset_invoke");
    for (rule, decision, reason) in rules
        .iter_mut()
        .filter(|rule| {
            matches!(
                rule["match"]["tool"].as_str(),
                Some("stellar_pay" | "stellar_pay_commit")
            )
        })
        .map(|rule| (rule, routed, "routed consent"))
        .chain(std::iter::once((&mut invocation, outer, "outer consent")))
    {
        rule["decision"] = toml_edit::value(decision);
        rule.remove("reason");
        rule.remove("ttl_secs");
        if decision == "require_approval" {
            rule["reason"] = toml_edit::value(reason);
            rule["ttl_secs"] = toml_edit::value(ttl);
        }
    }
    rules.push(invocation);
    doc.to_string()
}

struct Run {
    f: Fixture,
    control: Arc<RpcControl>,
    oracle_control: Arc<RpcControl>,
    _primary: wiremock::MockServer,
    _oracle: wiremock::MockServer,
    root: tempfile::TempDir,
    grants: std::path::PathBuf,
    /// Opt-outs that keep the legacy-attested run unenforced for every
    /// kind; a test's later enforcement guard overrides them.
    _unenforced: Vec<stellar_agent_network::policy_state::approvals::ConsentEvidenceDisableGuard>,
}

impl Run {
    async fn new(outer: &str, routed: &str, caps: &[&str]) -> Self {
        Self::with_policy(outer, routed, caps, |raw| raw).await
    }

    async fn with_policy(
        outer: &str,
        routed: &str,
        caps: &[&str],
        edit: impl FnOnce(String) -> String,
    ) -> Self {
        Self::with_recording(outer, routed, caps, edit, false).await
    }

    async fn with_recording(
        outer: &str,
        routed: &str,
        caps: &[&str],
        edit: impl FnOnce(String) -> String,
        record_keys: bool,
    ) -> Self {
        let primary = wiremock::MockServer::start().await;
        let oracle = wiremock::MockServer::start().await;
        let mut f = super::common::tests::mainnet::route_fixture(
            Fixture::build(
                |raw| edit(policy(&raw, outer, routed, 60)),
                |profile| profile.submit_timeout_seconds = Some(1),
                record_keys,
            ),
            &primary,
            &oracle,
        );
        let control = mount_rpc(&f, &primary).await;
        let oracle_control = mount_rpc(&f, &oracle).await;
        let root = tempfile::tempdir().unwrap();
        let pin = PinKey::from_bytes(zeroize::Zeroizing::new([0x63; 32]));
        stellar_agent_toolsets_install::write_toolset_for_test(
            root.path(),
            TOOLSET,
            caps,
            &[],
            "2020-01-01T00:00:00Z",
            INSTALL,
            &pin,
        )
        .unwrap();
        let grants = root.path().join("grants.toml");
        f.server
            .set_toolsets_root_for_test(root.path().to_path_buf());
        f.server.set_toolset_pin_key_for_test(pin);
        f.server.set_grant_store_path_for_test(grants.clone());
        let unenforced = super::common::tests::mainnet::unenforced(&f);
        Self {
            _unenforced: unenforced,
            f,
            control,
            oracle_control,
            _primary: primary,
            _oracle: oracle,
            root,
            grants,
        }
    }

    fn grant(&self, destination: &str) -> stellar_agent_core::approval::ToolsetGrant {
        self.grant_asset(destination, "XLM")
    }

    fn grant_asset(
        &self,
        destination: &str,
        asset: &str,
    ) -> stellar_agent_core::approval::ToolsetGrant {
        let key = super::common::load_attestation_key(self.f.server.security_profile()).unwrap();
        record_first_invoke_grant(
            "operator",
            TOOLSET,
            INSTALL,
            "1.0.0",
            &"0".repeat(64),
            "sign-payment",
            destination,
            asset,
            1,
            i64::MAX,
            &process_uid_for_attestation().unwrap(),
            now_unix_ms().unwrap(),
            &key,
            &AttestationBinding::new("operator", "stellar:mainnet"),
            Some(self.grants.clone()),
        )
        .unwrap()
    }

    fn issued_entries(&self) {
        use stellar_agent_test_support::xdr_fixtures::{
            account_ledger_key_xdr, trustline_entry_xdr, trustline_ledger_key_xdr,
        };
        use stellar_xdr::{LedgerEntryData, Limits, ReadXdr, WriteXdr};
        let mut entries = super::common::tests::mainnet::fixture_entries(&self.f);
        let source_key = account_ledger_key_xdr(self.f.envelope.source());
        for entry in &mut entries {
            if entry["key"] == source_key {
                let mut data = LedgerEntryData::from_xdr_base64(
                    entry["xdr"].as_str().unwrap(),
                    Limits::none(),
                )
                .unwrap();
                let LedgerEntryData::Account(account) = &mut data else {
                    panic!("the source key must hold an account");
                };
                account.num_sub_entries += 1;
                entry["xdr"] = data.to_xdr_base64(Limits::none()).unwrap().into();
            }
        }
        let issuer = stellar_agent_test_support::signed_envelope::account_id_for_seed([7; 32]);
        entries.push(serde_json::json!({
            "key": trustline_ledger_key_xdr(self.f.envelope.source(), "USD", &issuer),
            "xdr": trustline_entry_xdr(self.f.envelope.source(), "USD", &issuer, 1_000_000),
            "lastModifiedLedgerSeq": 100
        }));
        *self.control.entries.lock().unwrap() = Some(entries.clone());
        *self.oracle_control.entries.lock().unwrap() = Some(entries);
    }

    fn source_sequence(&self, sequence: i64) {
        use stellar_agent_test_support::xdr_fixtures::account_ledger_key_xdr;
        use stellar_xdr::{LedgerEntryData, Limits, ReadXdr, SequenceNumber, WriteXdr};
        let key = account_ledger_key_xdr(self.f.envelope.source());
        let mut entries = self
            .control
            .entries
            .lock()
            .unwrap()
            .clone()
            .unwrap_or_else(|| super::common::tests::mainnet::fixture_entries(&self.f));
        for entry in &mut entries {
            if entry["key"] == key {
                let mut data = LedgerEntryData::from_xdr_base64(
                    entry["xdr"].as_str().unwrap(),
                    Limits::none(),
                )
                .unwrap();
                let LedgerEntryData::Account(account) = &mut data else {
                    panic!("the source key must hold an account");
                };
                account.seq_num = SequenceNumber(sequence);
                entry["xdr"] = data.to_xdr_base64(Limits::none()).unwrap().into();
            }
        }
        *self.control.entries.lock().unwrap() = Some(entries.clone());
        *self.oracle_control.entries.lock().unwrap() = Some(entries);
    }

    async fn invoke(&self, action: &str, args: Value) -> Value {
        wire(
            &self
                .f
                .server
                .call_stellar_toolset_invoke(StellarToolsetInvokeArgs {
                    toolset: TOOLSET.to_owned(),
                    action: action.to_owned(),
                    chain_id: Some("stellar:mainnet".to_owned()),
                    args,
                })
                .await
                .unwrap(),
        )
    }

    fn pending(&self) -> Vec<stellar_agent_core::approval::PendingApproval> {
        let path = self
            .f
            .server
            .resolve_approval_dir()
            .unwrap()
            .join("operator.toml");
        if !path.exists() {
            return Vec::new();
        }
        let store = PendingApprovalStore::open(path).unwrap();
        store
            .snapshot(now_unix_ms().unwrap())
            .iter()
            .map(|entry| store.get(&entry.approval_nonce).unwrap().clone())
            .collect()
    }

    fn commit_args(&self, mut args: Value, prepared: &Value) -> Value {
        for field in ["envelope_xdr", "nonce", "expires_at_unix_ms"] {
            args[field] = prepared["data"][field].clone();
        }
        args
    }

    fn restart(&mut self) {
        let profile = (*self.f.server.profile).clone();
        let primary = url::Url::parse(&profile.rpc_url).unwrap();
        let oracle = profile.oracle_provider_url.as_ref().unwrap();
        self.f.server = crate::server::WalletServer::new_with_selection_and_routes_for_test(
            profile.clone(),
            stellar_agent_core::profile::name::ProfileNameSource::Flag,
            self.f.server.profiles_dir.as_ref().unwrap(),
            &[
                (primary.host_str().unwrap(), self._primary.uri().as_str()),
                (oracle.host_str().unwrap(), self._oracle.uri().as_str()),
            ],
        )
        .unwrap();
        self.f
            .server
            .set_toolsets_root_for_test(self.root.path().to_owned());
        self.f
            .server
            .set_grant_store_path_for_test(self.grants.clone());
        self.f
            .server
            .set_toolset_pin_key_for_test(PinKey::from_bytes(zeroize::Zeroizing::new([0x63; 32])));
    }

    async fn prepare_route(&self, args: &Value, toolset: bool) -> Value {
        if toolset {
            self.invoke("stellar_pay", args.clone()).await
        } else {
            wire(&Tool::Pay.prepare(&self.f.server, args).await)
        }
    }

    async fn commit_route(&self, args: Value, toolset: bool) -> Value {
        if toolset {
            self.invoke("stellar_pay_commit", args).await
        } else {
            wire(&Tool::Pay.commit(&self.f.server, args).await.unwrap())
        }
    }
}

#[tokio::test]
#[serial_test::serial(keyring, mainnet_clock)]
#[serial_test::serial]
async fn toolset_preparation_composes_before_exposure() {
    for outer in ["allow", "require_approval", "deny"] {
        let run = Run::new(outer, "allow", &["propose-transaction"]).await;
        let args = Tool::Pay.prepare_args(&run.f);
        let result = run
            .f
            .server
            .call_stellar_toolset_invoke(StellarToolsetInvokeArgs {
                toolset: TOOLSET.to_owned(),
                action: "stellar_pay".to_owned(),
                chain_id: Some("stellar:mainnet".to_owned()),
                args,
            })
            .await;
        assert!(
            result.is_ok(),
            "a propose-only installation reaches shared preparation without a grant: {result:?}"
        );
        let result = wire(&result.unwrap());
        match outer {
            "allow" => {
                assert_eq!(result["ok"], true, "{result}");
                assert!(result["data"]["nonce"].is_string());
                assert!(result["data"]["approval"].is_null());
                assert!(run.pending().is_empty());
            }
            "require_approval" => {
                assert_eq!(result["ok"], true, "{result}");
                let entries = run.pending();
                assert_eq!(entries.len(), 1);
                assert_eq!(
                    result["data"]["approval"]["approval_nonce"],
                    entries[0].approval_nonce
                );
                assert_eq!(entries[0].reason.as_deref(), Some("outer consent"));
                assert_eq!(
                    entries[0].expires_at_unix_ms - entries[0].created_at_unix_ms,
                    60_000
                );
            }
            _ => {
                assert_eq!(
                    result["error"]["code"], "policy.deny.explicit_rule_deny",
                    "{result}"
                );
                assert!(result.get("data").is_none());
                assert!(run.pending().is_empty());
            }
        }
        assert!(!run.grants.exists(), "a proposal needs no signing grant");
        assert!(run.control.sent().is_empty());
        assert!(authorizations(&run.f).is_empty());
        assert_eq!(run.f.seed_reads.load(Ordering::SeqCst), 0);
    }
}

/// On an admitted mainnet profile both toolset payment actions refuse a C
/// recipient after admission and before the outer gate, any approval, record,
/// nonce read, or send.
#[tokio::test]
#[serial_test::serial(keyring, mainnet_clock)]
#[serial_test::serial]
async fn public_contract_payment_refuses_after_mainnet_admission() {
    use stellar_xdr::WriteXdr as _;
    let run = Run::new("allow", "allow", &["propose-transaction", "sign-payment"]).await;
    let mut args = Tool::Pay.prepare_args(&run.f);
    args["destination"] = format!("{}", stellar_strkey::Contract([2; 32])).into();
    let context = stellar_agent_core::sac_payment::SacPaymentContext::new(
        stellar_agent_core::profile::caip2::Caip2::Mainnet,
        stellar_agent_core::approval::IntentAsset::Native,
    )
    .unwrap();
    let mut commit = args.clone();
    commit["envelope_xdr"] = stellar_xdr::TransactionEnvelope::Tx(
        stellar_agent_core::approval::fixtures::sac_transfer(&context),
    )
    .to_xdr_base64(stellar_xdr::Limits::none())
    .unwrap()
    .into();
    commit["nonce"] = "A".repeat(64).into();
    commit["expires_at_unix_ms"] = 9_999_999_999_u64.into();
    let nonce_reads = run.f.nonce_reads.load(Ordering::SeqCst);
    for (action, presented) in [("stellar_pay", args), ("stellar_pay_commit", commit)] {
        let code = match run
            .f
            .server
            .call_stellar_toolset_invoke(StellarToolsetInvokeArgs {
                toolset: TOOLSET.to_owned(),
                action: action.to_owned(),
                chain_id: Some("stellar:mainnet".to_owned()),
                args: presented,
            })
            .await
        {
            Ok(result) => wire(&result)["error"]["code"].to_string(),
            Err(error) => format!("protocol error: {}", error.message),
        };
        assert_eq!(
            code, "\"validation.contract_payment_unavailable\"",
            "{action}"
        );
    }
    assert!(run.pending().is_empty(), "nothing is queued");
    assert!(run.control.sent().is_empty(), "nothing is sent");
    assert!(authorizations(&run.f).is_empty(), "no authorization");
    assert_eq!(run.f.nonce_reads.load(Ordering::SeqCst), nonce_reads);
}

/// A mainnet server that is not admitted, or whose admission is stale,
/// answers a C recipient with its mainnet refusal, not the contract code, on
/// the toolset route and on direct commit.
#[tokio::test]
#[serial_test::serial(keyring, mainnet_clock)]
#[serial_test::serial]
async fn mainnet_refusals_precede_the_contract_payment_refusal() {
    use stellar_xdr::WriteXdr as _;
    let context = stellar_agent_core::sac_payment::SacPaymentContext::new(
        stellar_agent_core::profile::caip2::Caip2::Mainnet,
        stellar_agent_core::approval::IntentAsset::Native,
    )
    .unwrap();
    let envelope = stellar_xdr::TransactionEnvelope::Tx(
        stellar_agent_core::approval::fixtures::sac_transfer(&context),
    )
    .to_xdr_base64(stellar_xdr::Limits::none())
    .unwrap();
    for (case, expected) in [
        (
            "not admitted",
            "network.mainnet_write_forbidden: mainnet writes require verified enablement",
        ),
        ("stale", "enablement or policy changed, restart the server"),
    ] {
        let mut run = Run::new("allow", "allow", &["propose-transaction", "sign-payment"]).await;
        if case == "not admitted" {
            run.f.server.enablement = None;
        } else {
            super::common::tests::mainnet::put(
                &stellar_agent_core::profile::schema::mainnet_enablement_entry_ref(
                    &run.f.server.profile.policy_window_state_key_id,
                ),
                "rotated-installation",
            );
        }
        let mut commit = Tool::Pay.prepare_args(&run.f);
        commit["destination"] = format!("{}", stellar_strkey::Contract([2; 32])).into();
        commit["envelope_xdr"] = envelope.clone().into();
        commit["nonce"] = "A".repeat(64).into();
        commit["expires_at_unix_ms"] = 9_999_999_999_u64.into();
        let toolset = run
            .f
            .server
            .call_stellar_toolset_invoke(StellarToolsetInvokeArgs {
                toolset: TOOLSET.to_owned(),
                action: "stellar_pay_commit".to_owned(),
                chain_id: Some("stellar:mainnet".to_owned()),
                args: commit.clone(),
            })
            .await;
        commit["chain_id"] = "stellar:mainnet".into();
        let direct = run
            .f
            .server
            .call_stellar_pay_commit(serde_json::from_value(commit).unwrap())
            .await;
        for (route, result) in [("toolset", toolset), ("direct commit", direct)] {
            let refusal = match result {
                Ok(result) => {
                    let body = wire(&result);
                    format!("{} {}", body["error"]["code"], body["error"]["message"])
                }
                Err(error) => format!("protocol error: {}", error.message),
            };
            assert_eq!(
                refusal,
                format!("\"network.mainnet_write_forbidden\" \"{expected}\""),
                "{case}, {route}"
            );
        }
        assert!(run.control.sent().is_empty(), "{case}: nothing is sent");
    }
}

/// A toolset payment commit on mainnet keeps the commit floor rule: a floor
/// on `stellar_pay` alone refuses the commit with `account.unread`, nothing
/// is sent or minted; equal floors on both names commit and submit once.
#[tokio::test]
#[serial_test::serial(keyring, mainnet_clock)]
#[serial_test::serial]
async fn toolset_commit_keeps_the_commit_floor_rule() {
    use super::common::tests::mainnet::{cover_native_history, with_floor};
    for (names, ok) in [
        (&["stellar_pay"][..], false),
        (&["stellar_pay", "stellar_pay_commit"][..], true),
    ] {
        let run = Run::with_policy(
            "allow",
            "allow",
            &["propose-transaction", "sign-payment"],
            |raw| {
                names
                    .iter()
                    .fold(raw, |raw, name| with_floor(&raw, name, 1))
            },
        )
        .await;
        cover_native_history(&run.f);
        let args = Tool::Pay.prepare_args(&run.f);
        let prepared = wire(&Tool::Pay.prepare(&run.f.server, &args).await);
        assert_eq!(prepared["ok"], true, "{names:?}: {prepared}");
        run.grant(args["destination"].as_str().unwrap());
        let commit = run.commit_args(args, &prepared);
        let result = run.invoke("stellar_pay_commit", commit).await;
        if ok {
            assert_eq!(result["ok"], true, "{names:?}: {result}");
            assert_eq!(run.control.sent().len(), 1, "{names:?}: submitted once");
            assert_eq!(authorizations(&run.f).len(), 1, "{names:?}");
        } else {
            assert_eq!(
                result["error"]["code"], "account.unread",
                "{names:?}: {result}"
            );
            assert!(run.control.sent().is_empty(), "{names:?}: nothing sent");
            assert!(
                authorizations(&run.f).is_empty(),
                "{names:?}: nothing minted"
            );
        }
    }
}

#[tokio::test]
#[serial_test::serial(keyring, mainnet_clock)]
#[serial_test::serial]
async fn public_commit_is_unattended_or_queues_before_nonce_use() {
    for outer in ["allow", "require_approval", "deny"] {
        let run = Run::with_policy(
            outer,
            "allow",
            &["propose-transaction", "sign-payment"],
            |raw| outer_lifetime(&raw, 120),
        )
        .await;
        let args = Tool::Pay.prepare_args(&run.f);
        let prepared = wire(&Tool::Pay.prepare(&run.f.server, &args).await);
        assert_eq!(prepared["ok"], true, "{prepared}");
        assert!(prepared["data"]["approval"].is_null());
        run.grant(args["destination"].as_str().unwrap());
        let mut commit = run.commit_args(args.clone(), &prepared);
        let other = if outer == "require_approval" {
            let mut other = Tool::Pay.prepare_args(&run.f);
            other["amount_in_stroops"] = "9".into();
            let prepared = wire(&Tool::Pay.prepare(&run.f.server, &other).await);
            assert_eq!(prepared["ok"], true, "{prepared}");
            Some(run.commit_args(other, &prepared))
        } else {
            None
        };
        let nonce_reads = run.f.nonce_reads.load(Ordering::SeqCst);
        if let Some(other) = other.clone() {
            let mut invented = commit.clone();
            invented["nonce"] = "A".repeat(64).into();
            let mut other_envelope = other.clone();
            for field in ["nonce", "expires_at_unix_ms"] {
                other_envelope[field] = commit[field].clone();
            }
            let mut other_expiry = commit.clone();
            other_expiry["expires_at_unix_ms"] =
                (commit["expires_at_unix_ms"].as_u64().unwrap() + 1).into();
            for (case, presented) in [
                ("unknown nonce", invented),
                ("known nonce, other envelope", other_envelope),
                ("known nonce, other expiry", other_expiry),
            ] {
                let result = run.invoke("stellar_pay_commit", presented).await;
                assert_eq!(result["error"]["code"], "nonce.expired", "{case}: {result}");
                assert_eq!(
                    result["error"]["message"],
                    "nonce expired or invalid; re-simulate to obtain a fresh nonce",
                    "{case}: queue lookup keeps the ordinary commit refusal"
                );
                assert!(run.pending().is_empty(), "{case}: nothing is queued");
            }
        }
        let result = run.invoke("stellar_pay_commit", commit.clone()).await;
        if outer == "deny" {
            assert_eq!(
                result["error"]["code"], "policy.deny.explicit_rule_deny",
                "{result}"
            );
            assert!(run.pending().is_empty());
            assert!(run.control.sent().is_empty());
            assert!(authorizations(&run.f).is_empty());
            continue;
        }
        if outer == "require_approval" {
            assert_eq!(
                result["error"]["code"], "policy.approval_required",
                "{result}"
            );
            let first = run.pending();
            assert_eq!(first.len(), 1);
            assert_eq!(first[0].reason.as_deref(), Some("outer consent"));
            let operation = stellar_agent_network::policy_state::OperationStatus::new(
                &run.f.server.window_store,
                run.f.server.security_profile(),
            )
            .view(
                &stellar_agent_network::policy_state::BusinessId::parse(
                    commit["business_id"].as_str().unwrap(),
                )
                .unwrap(),
            )
            .unwrap()
            .unwrap();
            let waiting_end = operation.waiting_expires_at_ms.unwrap();
            assert_eq!(
                first[0].expires_at_unix_ms,
                (first[0].created_at_unix_ms + 120_000).min(waiting_end),
                "the queued end is the earlier of the outer 120 s consent and the operation's \
                 waiting end {waiting_end}"
            );
            let repeated = run.invoke("stellar_pay_commit", commit.clone()).await;
            assert_eq!(repeated["error"]["code"], "policy.approval_required");
            let retained = run.pending();
            assert_eq!(retained[0].approval_nonce, first[0].approval_nonce);
            assert_eq!(retained[0].expires_at_unix_ms, first[0].expires_at_unix_ms);
            assert!(run.f.server.replay_window.lock().await.is_empty());
            assert_eq!(
                run.f.nonce_reads.load(Ordering::SeqCst),
                nonce_reads,
                "queue lookup reads no nonce key"
            );
            assert!(authorizations(&run.f).is_empty());
            assert_eq!(run.f.seed_reads.load(Ordering::SeqCst), 0);
            assert!(run.control.sent().is_empty());
            commit["approval_nonce"] = first[0].approval_nonce.clone().into();
            let attestation = run.f.attest(&first[0]);
            commit["approval_attestation"] = "A".repeat(43).into();
            assert_eq!(
                run.invoke("stellar_pay_commit", commit.clone()).await["error"]["code"],
                "policy.approval_required"
            );
            commit["approval_attestation"] = attestation.into();
            let sent = run.invoke("stellar_pay_commit", commit.clone()).await;
            assert_eq!(sent["ok"], true, "{sent}");
        } else {
            assert_eq!(result["ok"], true, "{result}");
            assert!(run.pending().is_empty(), "Allow queues no payment consent");
        }
        assert_eq!(run.control.sent().len(), 1);
        assert_eq!(authorizations(&run.f).len(), 1);
        let replay = run.invoke("stellar_pay_commit", commit).await;
        assert_eq!(replay["data"]["status"], "replayed", "{replay}");
        assert_eq!(run.control.sent().len(), 1);
        if let Some(other) = other {
            // At its end the other preparation's entry is expired: the
            // commit refuses before queueing, after the first one completed.
            let end = other["expires_at_unix_ms"].as_u64().unwrap();
            let pending: Vec<_> = run
                .pending()
                .into_iter()
                .map(|entry| entry.approval_nonce)
                .collect();
            let clock = stellar_agent_core::timefmt::test_clock::install(Arc::new(
                stellar_agent_core::timefmt::MockClock::new(move || Ok(end)),
            ));
            let result = run.invoke("stellar_pay_commit", other).await;
            drop(clock);
            assert_eq!(
                result["error"]["code"], "nonce.expired",
                "expired entry: {result}"
            );
            assert_eq!(
                run.pending()
                    .into_iter()
                    .map(|entry| entry.approval_nonce)
                    .collect::<Vec<_>>(),
                pending,
                "expired entry: nothing is queued"
            );
            assert_eq!(run.control.sent().len(), 1);
        }
        drop(stellar_agent_toolsets_install::lock_toolsets(run.root.path()).unwrap());
    }
}

/// The policy `raw` with the lifetime of its outer `stellar_toolset_invoke`
/// approval rule set to `secs`. A toolset commit of a direct-first payment
/// signs only while the consent it queues outlasts the stored deadline, so
/// these runs give that rule the 120-second classic deadline.
fn outer_lifetime(raw: &str, secs: i64) -> String {
    let mut doc = raw.parse::<toml_edit::DocumentMut>().unwrap();
    for rule in doc["rules"].as_array_of_tables_mut().unwrap().iter_mut() {
        if rule["match"]["tool"].as_str() == Some("stellar_toolset_invoke")
            && rule.contains_key("ttl_secs")
        {
            rule["ttl_secs"] = toml_edit::value(secs);
        }
    }
    doc.to_string()
}

/// The operation a mainnet payment preparation opened under `args`'s
/// business id.
fn prepared_operation(run: &Run, args: &Value) -> stellar_agent_network::policy_state::OperationId {
    stellar_agent_network::policy_state::OperationStatus::new(
        &run.f.server.window_store,
        run.f.server.security_profile(),
    )
    .view(
        &stellar_agent_network::policy_state::BusinessId::parse(
            args["business_id"].as_str().unwrap(),
        )
        .unwrap(),
    )
    .unwrap()
    .expect("the preparation opens the operation record")
    .operation_id
}

/// A mainnet toolset commit that queues its consent opens one durable
/// approval record for the prepared operation, and proof delivery reads
/// that record while consent evidence is enforced.
#[tokio::test]
#[serial_test::serial(keyring, mainnet_clock)]
#[serial_test::serial]
async fn public_commit_queue_opens_the_durable_record_proof_delivery_reads() {
    use stellar_agent_core::approval::witness::ApprovedKind;
    use stellar_agent_network::policy_state::approvals::{
        ConsentDeliveryV1, ConsentEvidenceEnforcementGuard, VerifiedConsentDelivery,
        seed_existing_consent_delivery_for_test,
    };
    use stellar_agent_network::policy_state::{ApprovalState, ApprovalStatus};
    let run = Run::with_policy(
        "require_approval",
        "allow",
        &["propose-transaction", "sign-payment"],
        |raw| outer_lifetime(&raw, 120),
    )
    .await;
    let name = run.f.server.profile_name_for_approval();
    let enforced = ConsentEvidenceEnforcementGuard::new(&name, ApprovedKind::Payment);
    let args = Tool::Pay.prepare_args(&run.f);
    let prepared = wire(&Tool::Pay.prepare(&run.f.server, &args).await);
    assert_eq!(prepared["ok"], true, "{prepared}");
    assert!(prepared["data"]["approval"].is_null());
    let operation = prepared_operation(&run, &args);
    run.grant(args["destination"].as_str().unwrap());
    let mut commit = run.commit_args(args.clone(), &prepared);
    let queued = run.invoke("stellar_pay_commit", commit.clone()).await;
    assert_eq!(
        queued["error"]["code"], "policy.approval_required",
        "{queued}"
    );
    let entries = run.pending();
    assert_eq!(entries.len(), 1);
    let status =
        || ApprovalStatus::new(&run.f.server.window_store, run.f.server.security_profile());
    let record = status()
        .find_by_nonce(&entries[0].approval_nonce)
        .unwrap()
        .map(|view| view.record);
    assert!(
        record.is_some(),
        "the commit-time queue opens the durable approval record"
    );
    let record = record.unwrap();
    assert_eq!(
        record.operation_id, operation,
        "the record names the prepared operation"
    );
    assert_eq!(record.kind, ApprovedKind::Payment);
    assert_eq!(record.state, ApprovalState::Pending);
    assert_eq!(
        (record.created_at_ms, record.waiting_expires_at_ms),
        (entries[0].created_at_unix_ms, entries[0].expires_at_unix_ms)
    );
    assert_eq!(
        status()
            .find_by_operation(operation)
            .unwrap()
            .map(|view| view.record.nonce),
        Some(entries[0].approval_nonce.clone()),
        "one durable record per queued approval"
    );
    let repeated = run.invoke("stellar_pay_commit", commit.clone()).await;
    assert_eq!(repeated["error"]["code"], "policy.approval_required");
    assert_eq!(run.pending().len(), 1);
    assert_eq!(
        run.pending()[0].approval_nonce,
        entries[0].approval_nonce,
        "the repeat reuses the linked entry"
    );
    assert!(run.control.sent().is_empty());
    assert!(authorizations(&run.f).is_empty());

    commit["approval_nonce"] = entries[0].approval_nonce.clone().into();
    commit["approval_attestation"] = run.f.attest(&entries[0]).into();
    assert!(
        status()
            .find_by_nonce(&entries[0].approval_nonce)
            .unwrap()
            .unwrap()
            .record
            .consent
            .is_some(),
        "the operator's consent completes the durable record"
    );
    let witness = {
        use base64::Engine as _;
        let inbox = PendingApprovalStore::open(
            run.f
                .server
                .resolve_approval_dir()
                .unwrap()
                .join("operator.toml"),
        )
        .unwrap();
        // A direct preparation opens a canonical record, so the approval is
        // the consent to its stored intent (business_entry.rs:509-514), which
        // the commit verifies with the intent and its decision
        // (canonical_commit.rs:249-262).
        let policy = run.f.server.current_mainnet_policy().unwrap();
        let id = stellar_agent_network::policy_state::BusinessId::parse(
            args["business_id"].as_str().unwrap(),
        )
        .unwrap();
        let stored = stellar_agent_network::policy_state::OperationStatus::new(
            &run.f.server.window_store,
            run.f.server.security_profile(),
        )
        .view(&id)
        .unwrap()
        .unwrap();
        assert_eq!(
            stored.slot_kind,
            stellar_agent_network::policy_state::SlotKind::Canonical
        );
        let intent = run
            .f
            .server
            .canonical_commit_target(policy, id, args["source"].as_str().unwrap(), |_| true)
            .unwrap_or_else(|_| panic!("the canonical record resumes"))
            .intent;
        assert_eq!(*intent.digest().as_bytes(), stored.intent_digest);
        let decision = stellar_agent_core::mainnet::decision::MainnetDecision::for_test(
            stellar_agent_core::policy::Decision::RequireApproval(
                stellar_agent_core::policy::ApprovalRequest::new(String::new(), 0),
            ),
            None,
            policy.digest(),
            0,
            0,
            &name,
            run.f.server.security_profile().chain_id.caip2_str(),
            now_unix_ms().unwrap(),
            entries[0].expires_at_unix_ms - entries[0].created_at_unix_ms,
            stellar_agent_core::mainnet::decision::AuthorityScope::Classic,
        );
        stellar_agent_core::approval::witness::verify_intent_approval(
            &inbox,
            run.f.server.security_profile(),
            &name,
            &entries[0].approval_nonce,
            &base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(commit["approval_attestation"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap(),
            &intent,
            &decision,
            policy,
            now_unix_ms().unwrap(),
        )
        .unwrap()
    };
    // The fixture's legacy attestation records no delivery, so the fixture
    // seeds the record's direct-anchored delivery facts.
    run.f
        .server
        .approval_step(|recorder| {
            seed_existing_consent_delivery_for_test(
                recorder,
                record.id,
                None,
                ConsentDeliveryV1::direct_anchored(record.id),
            )
            .map_err(stellar_agent_network::operation_entry::operation_refusal)
        })
        .unwrap();
    let delivery = status().consent_delivery(&witness);
    assert!(
        matches!(
            delivery,
            Ok(VerifiedConsentDelivery::DirectAnchored { identity }) if identity == record.id
        ),
        "proof delivery reads the durable record: {delivery:?}"
    );
    drop(enforced);
    let sent = run.invoke("stellar_pay_commit", commit).await;
    assert_eq!(sent["ok"], true, "{sent}");
    assert_eq!(run.control.sent().len(), 1);
    assert_eq!(authorizations(&run.f).len(), 1);
}

/// A store failure while the mainnet toolset commit queues its consent
/// refuses with the direct preparation's store refusal and queues nothing.
#[tokio::test]
#[serial_test::serial(keyring, mainnet_clock)]
#[serial_test::serial]
async fn public_commit_queue_store_failure_refuses_without_queueing() {
    let run = Run::new(
        "require_approval",
        "allow",
        &["propose-transaction", "sign-payment"],
    )
    .await;
    let args = Tool::Pay.prepare_args(&run.f);
    let prepared = wire(&Tool::Pay.prepare(&run.f.server, &args).await);
    assert_eq!(prepared["ok"], true, "{prepared}");
    let operation = prepared_operation(&run, &args);
    run.grant(args["destination"].as_str().unwrap());
    let commit = run.commit_args(args.clone(), &prepared);
    // Another payment's toolset preparation supplies the entry the store
    // is filled with, so every one of the 4,096 entries is live.
    let mut other = Tool::Pay.prepare_args(&run.f);
    other["amount_in_stroops"] = "9".into();
    let other = run.invoke("stellar_pay", other).await;
    assert_eq!(other["ok"], true, "{other}");
    let path = run
        .f
        .server
        .resolve_approval_dir()
        .unwrap()
        .join("operator.toml");
    let mut file: toml_edit::DocumentMut = std::fs::read_to_string(&path).unwrap().parse().unwrap();
    let template = file["pending"][0].as_table().unwrap().clone();
    let entries = file["pending"].as_array_of_tables_mut().unwrap();
    while entries.len() < 4096 {
        let mut entry = template.clone();
        entry["approval_nonce"] = toml_edit::value(format!("capacity{:014}", entries.len()));
        entries.push(entry);
    }
    let bytes = file.to_string();
    std::fs::write(&path, &bytes).unwrap();

    let refused = run
        .f
        .server
        .call_stellar_toolset_invoke(StellarToolsetInvokeArgs {
            toolset: TOOLSET.into(),
            action: "stellar_pay_commit".into(),
            chain_id: Some("stellar:mainnet".into()),
            args: commit,
        })
        .await
        .map(|result| wire(&result))
        .map_err(|error| error.message.to_string());
    assert_eq!(
        refused,
        Err(
            "approval.store_error: pending approval store full: maximum 4096 entries reached; \
             retained payment bindings occupy capacity until their retention ends, and \
             `stellar-agent approve gc --profile operator` frees them afterward"
                .to_owned()
        ),
        "the commit-time queue refuses with the store refusal"
    );
    assert_eq!(std::fs::read_to_string(&path).unwrap(), bytes);
    assert_eq!(PendingApprovalStore::open(path).unwrap().len(), 4096);
    assert!(
        stellar_agent_network::policy_state::ApprovalStatus::new(
            &run.f.server.window_store,
            run.f.server.security_profile(),
        )
        .find_by_operation(operation)
        .unwrap()
        .is_none(),
        "no durable record opens"
    );
    assert!(run.f.server.replay_window.lock().await.is_empty());
    assert!(authorizations(&run.f).is_empty());
    assert!(run.control.sent().is_empty());
}

/// A mainnet toolset commit hands its grant lease to submission: during the
/// send, grant revocation and the install lock refuse busy with the grant
/// bytes unchanged, and both succeed once the commit returns.
#[tokio::test]
#[serial_test::serial(keyring, mainnet_clock)]
#[serial_test::serial]
async fn public_mainnet_commit_holds_the_lease_through_submission() {
    let run = Run::new("allow", "allow", &["propose-transaction", "sign-payment"]).await;
    let args = Tool::Pay.prepare_args(&run.f);
    let prepared = wire(&Tool::Pay.prepare(&run.f.server, &args).await);
    assert_eq!(prepared["ok"], true, "{prepared}");
    run.grant(args["destination"].as_str().unwrap());
    let commit = run.commit_args(args, &prepared);
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let observed = Arc::clone(&seen);
    let root = run.root.path().to_owned();
    let grants = run.grants.clone();
    *run.control.on_request.lock().unwrap() = Some(Arc::new(move |method: &str| {
        if method != "sendTransaction" {
            return;
        }
        let before = std::fs::read(&grants).unwrap();
        let revoke = stellar_agent_core::approval::ToolsetGrantStore::open(
            grants.clone(),
            now_unix_ms().unwrap(),
        )
        .and_then(|mut store| store.revoke_toolset(TOOLSET));
        let install = stellar_agent_toolsets_install::lock_toolsets(&root);
        observed.lock().unwrap().push([
            matches!(
                revoke,
                Err(stellar_agent_core::approval::ApprovalError::WriterLocked)
            ),
            install.is_err(),
            std::fs::read(&grants).unwrap() == before,
        ]);
    }));
    let result = run.invoke("stellar_pay_commit", commit).await;
    *run.control.on_request.lock().unwrap() = None;
    assert_eq!(result["ok"], true, "{result}");
    assert_eq!(run.control.sent().len(), 1);
    assert_eq!(
        *seen.lock().unwrap(),
        vec![[true, true, true]],
        "the lease holds off revocation and install, with unchanged grant bytes, during the send"
    );
    let mut store = stellar_agent_core::approval::ToolsetGrantStore::open(
        run.grants.clone(),
        now_unix_ms().unwrap(),
    )
    .unwrap();
    assert_eq!(store.revoke_toolset(TOOLSET).unwrap(), 1);
    drop(stellar_agent_toolsets_install::lock_toolsets(run.root.path()).unwrap());
}

#[tokio::test]
#[serial_test::serial(keyring, mainnet_clock)]
#[serial_test::serial]
async fn exact_payment_actions_require_complete_mainnet_context() {
    for missing in [
        "engine",
        "policy",
        "enablement",
        "context",
        "profiles",
        "oracle",
        "profile selection",
        "rotated enablement",
        "stale policy",
        "unsigned policy",
    ] {
        let mut run = Run::new(
            "allow",
            "allow",
            &["propose-transaction", "sign-payment", "sign-rule-create"],
        )
        .await;
        let args = Tool::Pay.prepare_args(&run.f);
        let prepared = wire(&Tool::Pay.prepare(&run.f.server, &args).await);
        assert_eq!(prepared["ok"], true, "{prepared}");
        let commit = run.commit_args(args.clone(), &prepared);
        match missing {
            "engine" => {
                let mut profile = (*run.f.server.profile).clone();
                profile.policy.engine = stellar_agent_core::profile::schema::PolicyEngineKind::Noop;
                run.f.server.profile = Arc::new(profile);
            }
            "policy" => run.f.server.verified_policy = None,
            "enablement" => run.f.server.enablement = None,
            "context" => run.f.server.mainnet_context = None,
            "profiles" => run.f.server.profiles_dir = None,
            "oracle" => {
                let mut profile = (*run.f.server.profile).clone();
                profile.oracle_provider_url = None;
                profile.providers.as_mut().unwrap().oracle = None;
                let profiles = run.f.server.profiles_dir.as_ref().unwrap();
                stellar_agent_core::profile::loader::save_to_dir("operator", &profile, profiles)
                    .unwrap();
                let context = stellar_agent_network::NetworkContext::mainnet_write(
                    &profile,
                    run.f.server.selection.as_ref().unwrap(),
                    profiles,
                    stellar_agent_network::MainnetEndpointFlags {
                        network: None,
                        rpc_url: false,
                        secondary_rpc_url: false,
                    },
                )
                .unwrap();
                run.f.server.mainnet_context = Some(Arc::new(context));
            }
            "profile selection" => {
                run.f.server.selection.as_mut().unwrap().name = "different-profile".to_owned();
            }
            "rotated enablement" => super::common::tests::mainnet::put(
                &stellar_agent_core::profile::schema::mainnet_enablement_entry_ref(
                    &run.f.server.profile.policy_window_state_key_id,
                ),
                "rotated-installation",
            ),
            "stale policy" => {
                Fixture::write_policy(&run.f.raw.replace("sequence = 7", "sequence = 8"));
            }
            "unsigned policy" => {
                let path = run.f.server.policy_path.as_ref().unwrap();
                let raw = std::fs::read_to_string(path).unwrap();
                let mut doc = raw.parse::<toml_edit::DocumentMut>().unwrap();
                doc.remove("signature");
                std::fs::write(path, doc.to_string()).unwrap();
            }
            _ => unreachable!(),
        }
        let reads = run.control.methods().len() + run.oracle_control.methods().len();
        let nonces = run.f.nonce_reads.load(Ordering::SeqCst);
        for action in ["stellar_pay_commit", "stellar_pay"] {
            let payload = if action == "stellar_pay" {
                args.clone()
            } else {
                commit.clone()
            };
            let result = run
                .f
                .server
                .call_stellar_toolset_invoke(StellarToolsetInvokeArgs {
                    toolset: TOOLSET.to_owned(),
                    action: action.to_owned(),
                    chain_id: Some("stellar:mainnet".to_owned()),
                    args: payload,
                })
                .await;
            assert!(
                result.is_ok(),
                "{missing}/{action}: admission refuses before grant resolution: {result:?}"
            );
            let result = wire(&result.unwrap());
            assert_eq!(
                result["error"]["code"],
                if missing == "oracle" {
                    "profile.mainnet_oracle_required"
                } else {
                    "network.mainnet_write_forbidden"
                },
                "{missing}/{action}: {result}"
            );
        }
        assert!(run.pending().is_empty());
        assert!(!run.grants.exists());
        assert!(run.control.sent().is_empty());
        assert_eq!(run.f.seed_reads.load(Ordering::SeqCst), 0);
        assert!(authorizations(&run.f).is_empty());
        assert_eq!(run.f.nonce_reads.load(Ordering::SeqCst), nonces);
        assert_eq!(
            run.control.methods().len() + run.oracle_control.methods().len(),
            reads,
            "{missing}: admission performs no action reads"
        );
    }
    let mut run = Run::new(
        "allow",
        "allow",
        &[
            "propose-transaction",
            "read-balance",
            "sign-payment",
            "sign-rule-create",
        ],
    )
    .await;
    // The mainnet loader requires a destination allowlist on the outer rule,
    // which the raw names alone cannot satisfy. A signed criteria-free outer
    // Allow rule is therefore substituted below the validator, so the outer
    // gate allows and the mainnet action check decides.
    let loaded = run.f.server.verified_policy.clone();
    {
        use ed25519_dalek::Signer as _;
        let verified = loaded.clone().unwrap();
        let body = "version = 2\nscope = \"profile:operator\"\nsequence = 7\n\
                    [[rules]]\nmatch = { tool = \"stellar_toolset_invoke\", chain = \"stellar:mainnet\" }\n\
                    criteria = []\ndecision = \"allow\"\n";
        let owner = ed25519_dalek::SigningKey::from_bytes(&[11; 32]);
        let signature = owner.sign(&stellar_agent_core::policy::v1::signature::digest(
            &stellar_agent_core::policy::v1::canonical::canonical_bytes(body).unwrap(),
        ));
        let signed = format!(
            "{body}\n[signature]\nowner_id = \"{}\"\nsig = \"{}\"\n",
            stellar_strkey::ed25519::PublicKey(owner.verifying_key().to_bytes()),
            stellar_agent_core::hex::encode(&signature.to_bytes())
        );
        let document = stellar_agent_core::policy::v1::loader::load_signed_policy_text(
            &signed,
            "operator",
            &owner.verifying_key().to_bytes(),
            stellar_agent_core::profile::caip2::MAINNET_PASSPHRASE,
        )
        .unwrap();
        run.f.server.verified_policy = Some(Arc::new(
            verified.with_engine_for_test(Arc::new(
                stellar_agent_core::policy::v1::PolicyEngineV1::new(
                    document,
                    "operator".to_owned(),
                )
                .with_policy_digest_for_test(verified.digest()),
            )),
        ));
    }
    let reads = run.control.methods().len() + run.oracle_control.methods().len();
    let read_only = run
        .f
        .server
        .call_stellar_toolset_invoke(StellarToolsetInvokeArgs {
            toolset: TOOLSET.to_owned(),
            action: "stellar_balances".to_owned(),
            chain_id: Some("stellar:mainnet".to_owned()),
            args: serde_json::json!({
                "chain_id": "stellar:mainnet",
                "account_id": run.f.envelope.source(),
            }),
        })
        .await
        .map(|result| wire(&result))
        .map_err(|error| error.message.to_string());
    assert_eq!(
        read_only.as_ref().map(|body| &body["error"]["code"]),
        Ok(&serde_json::json!("network.mainnet_write_forbidden")),
        "a signed outer Allow rule opens no installed nonsigning mainnet action: {read_only:?}"
    );
    assert_eq!(
        run.control.methods().len() + run.oracle_control.methods().len(),
        reads,
        "the refused nonsigning action reads nothing"
    );
    run.f.server.verified_policy = loaded;
    let args = Tool::Pay.prepare_args(&run.f);
    let result = run
        .f
        .server
        .call_stellar_toolset_invoke(StellarToolsetInvokeArgs {
            toolset: TOOLSET.to_owned(),
            action: "stellar_rule_create_commit".to_owned(),
            chain_id: Some("stellar:mainnet".to_owned()),
            args: args.clone(),
        })
        .await;
    assert!(
        result.is_ok(),
        "a nonpayment signing action returns the entry refusal before resolving arguments: {result:?}"
    );
    let result = wire(&result.unwrap());
    assert_eq!(
        result["error"]["code"], "network.mainnet_write_forbidden",
        "{result}"
    );
    for action in [
        "stellar_pay ",
        "STELLAR_PAY",
        "stellar_pay_commit\u{1b}[0m",
        " stellar_pay_commit",
    ] {
        let result = run
            .f
            .server
            .call_stellar_toolset_invoke(StellarToolsetInvokeArgs {
                toolset: TOOLSET.to_owned(),
                action: action.to_owned(),
                chain_id: Some("stellar:mainnet".to_owned()),
                args: args.clone(),
            })
            .await;
        assert!(
            result.is_err() || result.as_ref().unwrap().is_error == Some(true),
            "raw alias {action:?} refuses"
        );
    }
    let wrong_chain = run
        .f
        .server
        .call_stellar_toolset_invoke(StellarToolsetInvokeArgs {
            toolset: TOOLSET.to_owned(),
            action: "stellar_pay_commit".to_owned(),
            chain_id: Some("stellar:testnet".to_owned()),
            args,
        })
        .await
        .unwrap_err();
    assert!(wrong_chain.message.starts_with("chain_id mismatch:"));
    assert!(run.pending().is_empty());
    assert!(!run.grants.exists());
    assert!(run.control.sent().is_empty());
}

const DESTINATIONS: [(&str, &str, &str); 3] = [
    (
        "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL",
        "8419e4131cc68b0c89dc835394a978dc8cf090e5118e60af862c515c5b787483",
        "GBPXX...MWIVL",
    ),
    (
        "MBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWAAAAAAAAAAAACKJY",
        "64e93b350686c45c3c01d84623636a6f40323d247be272b220d98744292907b4",
        "MBPXX...ACKJY",
    ),
    (
        "MBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMX77777777777752TU",
        "ce738b37887ec1ae76a1c81c5140596d400dc64a883fccc4f13605822726b99b",
        "MBPXX...752TU",
    ),
];

fn recorded_amount(run: &Run, bucket: &str) -> (i128, usize) {
    let state = super::common::tests::mainnet::ledger(&run.f).unwrap();
    let records = state["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["bucket"] == bucket)
        .unwrap()["records"]
        .as_array()
        .unwrap();
    (
        records
            .iter()
            .map(|record| record["amount"].as_str().unwrap().parse::<i128>().unwrap())
            .sum(),
        records.len(),
    )
}

#[tokio::test]
#[serial_test::serial(keyring, mainnet_clock)]
#[serial_test::serial]
async fn public_composed_cap_debits_once_and_preserves_exact_headroom() {
    use stellar_agent_core::policy::v1::criteria::state_store::{
        StateKey, WindowEntry, WindowLimit,
    };
    let run = Run::with_policy(
        "allow",
        "allow",
        &["propose-transaction", "sign-payment"],
        |raw| {
            let mut doc = raw.parse::<toml_edit::DocumentMut>().unwrap();
            for rule in doc["rules"].as_array_of_tables_mut().unwrap().iter_mut() {
                if rule["match"]["tool"].as_str() == Some("stellar_toolset_invoke") {
                    for criterion in rule["criteria"].as_array_mut().unwrap().iter_mut() {
                        let criterion = criterion.as_inline_table_mut().unwrap();
                        if criterion["kind"].as_str() == Some("per_period_cap") {
                            criterion.insert("max_stroops", toml_edit::Value::from("100"));
                        }
                    }
                }
            }
            doc.to_string()
        },
    )
    .await;
    run.f
        .server
        .window_store
        .record_authorized(
            run.f.server.security_profile(),
            &[WindowEntry::new(
                StateKey::new("operator", 1, "native", 86_400),
                now_unix_ms().unwrap(),
                40,
                WindowLimit::Amount {
                    asset: "native".into(),
                    window: "1d".into(),
                    max_stroops: 200,
                },
            )],
        )
        .unwrap();
    assert_eq!(recorded_amount(&run, "native"), (40, 1));
    run.grant(DESTINATIONS[0].0);
    for (amount, admitted) in [(50, true), (11, false), (10, true)] {
        let mut args = Tool::Pay.prepare_args(&run.f);
        args["amount_in_stroops"] = amount.to_string().into();
        let prepared = run.invoke("stellar_pay", args.clone()).await;
        if !admitted {
            assert_eq!(
                prepared["error"]["code"], "policy.deny.per_period_cap_exceeded",
                "{prepared}"
            );
            assert_eq!(recorded_amount(&run, "native"), (90, 2));
            assert_eq!(run.control.sent().len(), 1);
            continue;
        }
        assert_eq!(prepared["ok"], true, "{prepared}");
        let result = run
            .invoke("stellar_pay_commit", run.commit_args(args, &prepared))
            .await;
        assert_eq!(result["ok"], true, "{result}");
        assert_eq!(
            recorded_amount(&run, "native"),
            if amount == 50 { (90, 2) } else { (100, 3) }
        );
        run.source_sequence(if amount == 50 { 2 } else { 3 });
    }
    assert_eq!(run.control.sent().len(), 2);
    assert_eq!(authorizations(&run.f).len(), 2);
    assert!(run.pending().is_empty());
}

#[tokio::test]
#[serial_test::serial(keyring, mainnet_clock)]
#[serial_test::serial]
async fn public_outer_unlisted_classification_controls_threshold_and_holds() {
    use super::common::tests::mainnet::{ledger, observe};
    let threshold = stellar_agent_core::profile::schema::MINIMUM_FLOOR;
    for amount in [threshold - 1, threshold, threshold + 1] {
        let run = Run::with_policy(
            "allow",
            "allow",
            &["propose-transaction", "sign-payment"],
            |raw| {
                let raw = raw
                    .replace("max_stroops = \"100\"", "max_stroops = \"20000000000\"")
                    .replace("max_stroops = \"200\"", "max_stroops = \"40000000000\"");
                let mut doc = raw.parse::<toml_edit::DocumentMut>().unwrap();
                for rule in doc["rules"].as_array_of_tables_mut().unwrap().iter_mut() {
                    if rule["match"]["tool"].as_str() == Some("stellar_toolset_invoke") {
                        for criterion in rule["criteria"].as_array_mut().unwrap().iter_mut() {
                            let criterion = criterion.as_inline_table_mut().unwrap();
                            if criterion["kind"].as_str() == Some("counterparty_allowlist") {
                                criterion.insert(
                                    "allowlist",
                                    toml_edit::Value::Array(toml_edit::Array::new()),
                                );
                                let mut budget = toml_edit::InlineTable::new();
                                for (key, value) in
                                    [("mode", "budget"), ("asset", "native"), ("window", "1d")]
                                {
                                    budget.insert(key, value.into());
                                }
                                budget.insert("per_tx_stroops", 15_000_000_000_i64.into());
                                budget.insert("per_period_stroops", 30_000_000_000_i64.into());
                                criterion.insert("unlisted", budget.into());
                            }
                        }
                    }
                }
                doc.to_string()
            },
        )
        .await;
        let mut args = Tool::Pay.prepare_args(&run.f);
        args["amount_in_stroops"] = amount.to_string().into();
        args["memo_text"] = "invoice".into();
        let prepared = run.invoke("stellar_pay", args.clone()).await;
        assert_eq!(prepared["ok"], true, "{prepared}");
        assert!(run.pending().is_empty());
        let grant = run.grant(args["destination"].as_str().unwrap());
        let commit = run.commit_args(args, &prepared);
        let at_seed = Arc::new(std::sync::Mutex::new(Vec::<Value>::new()));
        let captured = Arc::clone(&at_seed);
        let path = run.f.server.window_store.path().to_path_buf();
        observe(&run.f.on_seed_read, move || {
            let bytes = std::fs::read(&path).unwrap();
            captured
                .lock()
                .unwrap()
                .push(serde_json::from_slice(&bytes[32..]).unwrap());
        });
        let result = run.invoke("stellar_pay_commit", commit).await;
        *run.f.on_seed_read.lock().unwrap() = None;
        assert_eq!(result["ok"], true, "{result}");
        if amount >= threshold {
            assert_eq!(
                result["data"]["cross_check"]["status"], "passed",
                "{result}"
            );
            assert!(run.oracle_control.count("getLedgerEntries") > 0);
        }
        let captures = at_seed.lock().unwrap();
        assert_eq!(captures.len(), 1);
        let holds = captures[0]["holds"].as_array().unwrap();
        let amount_text = amount.to_string();
        assert_eq!(
            holds.len(),
            3,
            "one native debit, one call, and the outer unlisted debit: {holds:?}"
        );
        assert_eq!(
            holds
                .iter()
                .filter(|hold| hold["bucket"] == "unlisted:native"
                    && hold["amount"].as_str() == Some(amount_text.as_str()))
                .count(),
            1,
            "the outer rule's own classification sizes its hold"
        );
        assert_eq!(recorded_amount(&run, "native"), (i128::from(amount), 1));
        assert_eq!(
            recorded_amount(&run, "unlisted:native"),
            (i128::from(amount), 1)
        );
        let records = authorizations(&run.f);
        assert_eq!(records.len(), 1);
        assert!(records[0]["expires_ms"].as_u64().unwrap() <= grant.expires_at_unix_ms);
        assert!(records[0]["policy_authority"].is_object());
        assert!(records[0]["approval_nonce"].is_null());
        assert!(
            ledger(&run.f).unwrap()["holds"]
                .as_array()
                .is_none_or(Vec::is_empty)
        );
        let audit =
            std::fs::read_to_string(&run.f.server.security_profile().audit_log_path).unwrap();
        let rows: Vec<Value> = audit
            .lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .filter(|row: &Value| row["kind"] == "value_action_pending")
            .collect();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["policy_decision"], "allow");
        assert_eq!(run.control.sent().len(), 1);
    }
}

#[tokio::test]
#[serial_test::serial(keyring, mainnet_clock)]
#[serial_test::serial]
async fn exact_muxed_mainnet_grant_preserves_its_id() {
    for (granted, wrong) in [
        (DESTINATIONS[1].0, DESTINATIONS[2].0),
        (DESTINATIONS[2].0, DESTINATIONS[1].0),
    ] {
        let run = Run::new("allow", "allow", &["propose-transaction", "sign-payment"]).await;
        let original = run.grant(granted);
        let mut args = Tool::Pay.prepare_args(&run.f);
        args["destination"] = wrong.into();
        let prepared = run.invoke("stellar_pay", args.clone()).await;
        assert_eq!(prepared["ok"], true, "{prepared}");
        let error = run
            .f
            .server
            .call_stellar_toolset_invoke(StellarToolsetInvokeArgs {
                toolset: TOOLSET.to_owned(),
                action: "stellar_pay_commit".to_owned(),
                chain_id: Some("stellar:mainnet".to_owned()),
                args: run.commit_args(args, &prepared),
            })
            .await
            .expect_err("a different M ID requires its own first-invoke consent");
        assert!(
            error
                .message
                .starts_with("toolset.first_invoke_approval_required"),
            "{error}"
        );
        let pending = run.pending();
        assert_eq!(pending.len(), 1);
        assert!(
            matches!(&pending[0].kind, stellar_agent_core::approval::ApprovalKind::ToolsetFirstInvokeGate { destination, .. } if destination == wrong)
        );
        assert!(run.control.sent().is_empty());
        assert!(authorizations(&run.f).is_empty());
        let mut args = Tool::Pay.prepare_args(&run.f);
        args["destination"] = granted.into();
        let prepared = run.invoke("stellar_pay", args.clone()).await;
        assert_eq!(prepared["ok"], true, "{prepared}");
        let result = run
            .invoke("stellar_pay_commit", run.commit_args(args, &prepared))
            .await;
        assert_eq!(result["ok"], true, "{result}");
        assert_eq!(result["data"]["destination"], granted);
        assert_eq!(run.control.sent().len(), 1);
        assert!(
            authorizations(&run.f)[0]["expires_ms"].as_u64().unwrap()
                <= original.expires_at_unix_ms
        );
    }
}

#[tokio::test]
#[serial_test::serial(keyring, mainnet_clock)]
#[serial_test::serial]
async fn simultaneous_public_proofs_have_one_payment_effect() {
    let mut run = Run::new(
        "require_approval",
        "require_approval",
        &["propose-transaction", "sign-payment"],
    )
    .await;
    let args = Tool::Pay.prepare_args(&run.f);
    let first = run.invoke("stellar_pay", args.clone()).await;
    let second = wire(&Tool::Pay.prepare(&run.f.server, &args).await);
    assert_eq!(first["ok"], true, "{first}");
    assert_eq!(second["ok"], true, "{second}");
    assert_eq!(
        first["data"]["envelope_xdr"],
        second["data"]["envelope_xdr"]
    );
    assert_ne!(first["data"]["nonce"], second["data"]["nonce"]);
    assert_eq!(
        first["data"]["approval"]["approval_nonce"],
        second["data"]["approval"]["approval_nonce"]
    );
    run.grant(args["destination"].as_str().unwrap());
    let entry = run.pending().pop().unwrap();
    let attestation = run.f.attest(&entry);
    let mut first_args = run.commit_args(args.clone(), &first);
    let mut second_args = run.commit_args(args, &second);
    for commit in [&mut first_args, &mut second_args] {
        commit["approval_nonce"] = entry.approval_nonce.clone().into();
        commit["approval_attestation"] = attestation.clone().into();
    }
    let arrivals = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    run.f.server.payment_proof_barrier = Some((
        Arc::new(tokio::sync::Barrier::new(2)),
        Arc::clone(&arrivals),
    ));
    let (toolset, direct) = tokio::join!(
        run.invoke("stellar_pay_commit", first_args),
        Tool::Pay.commit(&run.f.server, second_args)
    );
    run.f.server.payment_proof_barrier = None;
    let direct = wire(&direct.unwrap());
    assert_eq!(
        arrivals.load(Ordering::SeqCst),
        2,
        "both calls verified the same live proof before either could mint"
    );
    let results = [toolset, direct];
    assert_eq!(
        results.iter().filter(|result| result["ok"] == true).count(),
        1,
        "{results:?}"
    );
    let loser = results.iter().find(|result| result["ok"] == false).unwrap();
    assert_eq!(
        loser["error"]["code"], "network.mainnet_authorization_refused",
        "{loser}"
    );
    assert_eq!(run.control.sent().len(), 1);
    assert_eq!(authorizations(&run.f).len(), 1);
    assert_eq!(recorded_amount(&run, "native"), (10, 1));
}

#[tokio::test]
#[serial_test::serial(keyring, mainnet_clock)]
#[serial_test::serial]
async fn public_outer_cap_uses_payment_value_at_both_boundaries() {
    for cap in [9, 10] {
        let run = Run::with_policy(
            "allow",
            "allow",
            &["propose-transaction", "sign-payment"],
            |raw| {
                let mut doc = raw.parse::<toml_edit::DocumentMut>().unwrap();
                for rule in doc["rules"].as_array_of_tables_mut().unwrap().iter_mut() {
                    if rule["match"]["tool"].as_str() == Some("stellar_toolset_invoke") {
                        for criterion in rule["criteria"].as_array_mut().unwrap().iter_mut() {
                            let criterion = criterion.as_inline_table_mut().unwrap();
                            if criterion["kind"].as_str() == Some("per_tx_cap") {
                                criterion
                                    .insert("max_stroops", toml_edit::Value::from(cap.to_string()));
                            }
                        }
                    }
                }
                doc.to_string()
            },
        )
        .await;
        let args = Tool::Pay.prepare_args(&run.f);
        let toolset_prepared = run.invoke("stellar_pay", args.clone()).await;
        if cap == 9 {
            assert_eq!(
                toolset_prepared["error"]["code"], "policy.deny.per_tx_cap_exceeded",
                "preparation must evaluate the payment value: {toolset_prepared}"
            );
            assert!(toolset_prepared["data"].is_null());
        } else {
            assert_eq!(toolset_prepared["ok"], true, "{toolset_prepared}");
        }
        let direct_prepared = wire(&Tool::Pay.prepare(&run.f.server, &args).await);
        assert_eq!(direct_prepared["ok"], true, "{direct_prepared}");
        run.grant(args["destination"].as_str().unwrap());
        let result = run
            .invoke(
                "stellar_pay_commit",
                run.commit_args(args, &direct_prepared),
            )
            .await;
        if cap == 9 {
            assert_eq!(
                result["error"]["code"], "policy.deny.per_tx_cap_exceeded",
                "commit must evaluate the payment value: {result}"
            );
            assert!(authorizations(&run.f).is_empty());
            assert_eq!(run.f.seed_reads.load(Ordering::SeqCst), 0);
            assert!(run.control.sent().is_empty());
        } else {
            assert_eq!(result["ok"], true, "{result}");
            assert_eq!(run.control.sent().len(), 1);
        }
        assert!(run.pending().is_empty());
    }
}

#[tokio::test]
#[serial_test::serial(keyring, mainnet_clock)]
#[serial_test::serial]
async fn signed_policy_composition_reuses_consent_across_public_routes() {
    for (outer, routed, outer_ttl, routed_ttl, reason, ttl) in [
        ("allow", "require_approval", 120, 60, "routed consent", 60),
        ("require_approval", "allow", 15, 120, "outer consent", 15),
        (
            "require_approval",
            "require_approval",
            60,
            120,
            "routed consent",
            60,
        ),
        (
            "require_approval",
            "require_approval",
            120,
            60,
            "routed consent",
            60,
        ),
        (
            "require_approval",
            "require_approval",
            60,
            60,
            "routed consent",
            60,
        ),
    ] {
        let run = Run::with_policy(
            outer,
            routed,
            &["propose-transaction", "sign-payment"],
            |raw| {
                let mut doc = raw.parse::<toml_edit::DocumentMut>().unwrap();
                for rule in doc["rules"].as_array_of_tables_mut().unwrap().iter_mut() {
                    if rule["decision"].as_str() == Some("require_approval") {
                        rule["ttl_secs"] = toml_edit::value(
                            if rule["match"]["tool"].as_str() == Some("stellar_toolset_invoke") {
                                outer_ttl
                            } else {
                                routed_ttl
                            },
                        );
                    }
                }
                doc.to_string()
            },
        )
        .await;
        let now = now_unix_ms().unwrap();
        let _policy_clock =
            stellar_agent_core::policy::v1::criteria::state_store::set_query_time_for_test(now);
        let args = Tool::Pay.prepare_args(&run.f);
        let prepared = run.invoke("stellar_pay", args.clone()).await;
        assert_eq!(prepared["ok"], true, "{prepared}");
        let first = run.pending();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].reason.as_deref(), Some(reason));
        assert_eq!(
            first[0].expires_at_unix_ms - first[0].created_at_unix_ms,
            ttl * 1000
        );
        let repeated = run.invoke("stellar_pay", args.clone()).await;
        assert_eq!(repeated["data"]["approval"], prepared["data"]["approval"]);
        let direct = wire(&Tool::Pay.prepare(&run.f.server, &args).await);
        assert_eq!(direct["ok"], true, "{direct}");
        assert_eq!(
            direct["data"]["envelope_xdr"],
            prepared["data"]["envelope_xdr"]
        );
        if routed == "require_approval" {
            assert_eq!(
                direct["data"]["approval"]["approval_nonce"],
                first[0].approval_nonce
            );
        }
        let grant = run.grant(args["destination"].as_str().unwrap());
        let mut commit = run.commit_args(args, &direct);
        assert_eq!(
            run.invoke("stellar_pay_commit", commit.clone()).await["error"]["code"],
            "policy.approval_required"
        );
        let retained = run.pending();
        assert_eq!(retained.len(), 1);
        assert_eq!(retained[0].approval_nonce, first[0].approval_nonce);
        assert_eq!(retained[0].expires_at_unix_ms, first[0].expires_at_unix_ms);
        commit["approval_nonce"] = first[0].approval_nonce.clone().into();
        commit["approval_attestation"] = run.f.attest(&first[0]).into();
        let sent = run.invoke("stellar_pay_commit", commit.clone()).await;
        assert_eq!(sent["ok"], true, "{sent}");
        let records = authorizations(&run.f);
        assert_eq!(records.len(), 1);
        let log = std::fs::read_to_string(&run.f.server.security_profile().audit_log_path).unwrap();
        let rows: Vec<Value> = log
            .lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .filter(|row: &Value| row["kind"] == "value_action_pending")
            .collect();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["policy_decision"], "require_approval");
        let policy = run.f.server.verified_policy.as_deref().unwrap();
        assert_eq!(
            rows[0]["policy_digest"],
            stellar_agent_core::hex::encode(&policy.digest()),
            "the payment audit retains the governing signed policy"
        );
        assert_eq!(
            rows[0]["rule_index"],
            if routed == "allow" { 1 } else { 4 },
            "outer-only approval selects the outer rule; a tie selects the routed commit"
        );
        assert_eq!(rows[0]["approval_nonce"], first[0].approval_nonce);
        assert_eq!(rows[0]["legs"].as_array().unwrap().len(), 1);
        assert_eq!(rows[0]["legs"][0]["amount"], "10");
        assert_eq!(rows[0]["legs"][0]["asset"], "native");
        assert!(grant.expires_at_unix_ms > first[0].expires_at_unix_ms);
        assert_eq!(
            records[0]["expires_ms"], first[0].expires_at_unix_ms,
            "the original composed consent end is the shortest authority bound"
        );
        assert!(
            records[0]["approval_nonce"].is_string(),
            "consent authority: {}",
            records[0]
        );
        assert_eq!(run.control.sent().len(), 1);
        let replay = wire(&Tool::Pay.commit(&run.f.server, commit).await.unwrap());
        assert_eq!(replay["data"]["status"], "replayed", "{replay}");
        assert_eq!(replay["data"]["destination"], sent["data"]["destination"]);
        assert_eq!(run.control.sent().len(), 1);
    }
}

#[tokio::test]
#[serial_test::serial(keyring, mainnet_clock)]
#[serial_test::serial]
async fn granted_mainnet_payment_preserves_six_complete_destinations() {
    for (outer, routed) in [
        ("allow", "allow"),
        ("require_approval", "allow"),
        ("allow", "require_approval"),
        ("deny", "allow"),
        ("allow", "deny"),
    ] {
        granted_mainnet_destination_matrix(outer, routed).await;
    }
}

async fn granted_mainnet_destination_matrix(outer: &str, routed: &str) {
    use stellar_agent_core::envelope_decode::{
        ClassicOperation, ClassicTransactionKind, classic_summary,
    };
    use stellar_agent_core::profile::receipt::{PaymentDestinations, ReceiptStore};
    for issued in [false, true] {
        for (destination, hash, redaction) in DESTINATIONS {
            let issuer = stellar_agent_test_support::signed_envelope::account_id_for_seed([7; 32]);
            let asset = if issued {
                format!("USD:{issuer}")
            } else {
                "native".to_owned()
            };
            let run = Run::with_policy(
                outer,
                routed,
                &["propose-transaction", "sign-payment"],
                |raw| {
                    if !issued {
                        return raw;
                    }
                    let mut doc = raw
                        .replace("\"native\"", &format!("\"{asset}\""))
                        .parse::<toml_edit::DocumentMut>()
                        .unwrap();
                    doc["mainnet"]["cross_check_thresholds"][&asset] = toml_edit::value("100");
                    doc.to_string()
                },
            )
            .await;
            if issued {
                run.issued_entries();
            }
            let grant = run.grant_asset(DESTINATIONS[0].0, if issued { &asset } else { "XLM" });
            let grant_bytes = std::fs::read(&run.grants).unwrap();
            let mut args = Tool::Pay.prepare_args(&run.f);
            args["destination"] = destination.into();
            args["asset"] = asset.clone().into();
            let prepared = run.invoke("stellar_pay", args.clone()).await;
            if outer == "deny" || routed == "deny" {
                assert_eq!(prepared["error"]["code"], "policy.deny.explicit_rule_deny");
                if routed == "allow" {
                    let direct = wire(&Tool::Pay.prepare(&run.f.server, &args).await);
                    assert_eq!(direct["ok"], true, "{direct}");
                    let denied = run
                        .invoke("stellar_pay_commit", run.commit_args(args, &direct))
                        .await;
                    assert_eq!(denied["error"]["code"], "policy.deny.explicit_rule_deny");
                }
                assert!(run.pending().is_empty());
                assert!(run.control.sent().is_empty());
                assert!(authorizations(&run.f).is_empty());
                assert_eq!(run.f.seed_reads.load(Ordering::SeqCst), 0);
                assert_eq!(std::fs::read(&run.grants).unwrap(), grant_bytes);
                continue;
            }
            assert_eq!(prepared["ok"], true, "{asset}/{destination}: {prepared}");
            let requires = outer == "require_approval" || routed == "require_approval";
            assert_eq!(prepared["data"]["approval"].is_null(), !requires);
            let mut commit = run.commit_args(args, &prepared);
            if requires {
                let pending = run.pending();
                assert_eq!(pending.len(), 1);
                let refused = run.invoke("stellar_pay_commit", commit.clone()).await;
                assert_eq!(refused["error"]["code"], "policy.approval_required");
                assert_eq!(run.pending()[0].approval_nonce, pending[0].approval_nonce);
                assert!(run.control.sent().is_empty());
                assert!(authorizations(&run.f).is_empty());
                assert_eq!(run.f.seed_reads.load(Ordering::SeqCst), 0);
                commit["approval_nonce"] = pending[0].approval_nonce.clone().into();
                commit["approval_attestation"] = run.f.attest(&pending[0]).into();
            }
            let result = run
                .f
                .server
                .call_stellar_toolset_invoke(StellarToolsetInvokeArgs {
                    toolset: TOOLSET.to_owned(),
                    action: "stellar_pay_commit".to_owned(),
                    chain_id: Some("stellar:mainnet".to_owned()),
                    args: commit,
                })
                .await;
            assert!(result.is_ok(), "a G grant covers {destination}: {result:?}");
            let result = wire(&result.unwrap());
            assert_eq!(result["ok"], true, "{asset}/{destination}: {result}");
            assert_eq!(result["data"]["destination"], destination);
            let pending = run.pending();
            assert_eq!(pending.len(), usize::from(requires));
            assert!(
                pending
                    .iter()
                    .all(super::common::tests::mainnet::is_consumed)
            );
            let sent = run.control.sent();
            assert_eq!(sent.len(), 1);
            assert_eq!(
                classic_summary(&sent[0], ClassicTransactionKind::Payment)
                    .unwrap()
                    .operation,
                ClassicOperation::Payment {
                    destination: destination.to_owned(),
                    asset: if issued {
                        asset.clone()
                    } else {
                        "XLM".to_owned()
                    },
                    amount_stroops: 10
                }
            );
            let authorizations = authorizations(&run.f);
            assert_eq!(authorizations.len(), 1);
            assert!(authorizations[0]["expires_ms"].as_u64().unwrap() <= grant.expires_at_unix_ms);
            assert_eq!(
                std::fs::read(&run.grants).unwrap(),
                grant_bytes,
                "the original grant identity and interval stay unchanged"
            );
            let log =
                std::fs::read_to_string(&run.f.server.security_profile().audit_log_path).unwrap();
            let rows: Vec<Value> = log
                .lines()
                .filter_map(|line| serde_json::from_str(line).ok())
                .filter(|row: &Value| row["kind"] == "value_action_pending")
                .collect();
            assert_eq!(rows.len(), 1, "{log}");
            assert_eq!(
                rows[0]["policy_decision"],
                if requires {
                    "require_approval"
                } else {
                    "allow"
                }
            );
            let leg = &rows[0]["legs"][0];
            assert_eq!(leg["destination_sha256"], hash);
            assert_eq!(leg["destination_redacted"], redaction);
            assert_eq!(leg["amount"], "10");
            assert_eq!(leg["asset"], asset);
            assert!(!log.contains(destination));
            let receipts = ReceiptStore::open("operator").unwrap().all().unwrap();
            assert_eq!(receipts.len(), 1);
            let expected = if destination.starts_with('M') {
                PaymentDestinations::Single(destination.to_owned())
            } else {
                PaymentDestinations::None
            };
            assert_eq!(receipts[0].destinations, expected);
        }
    }
}

#[tokio::test]
#[serial_test::serial(keyring, mainnet_clock)]
#[serial_test::serial]
async fn public_payment_recovery_refuses_malformed_store_and_isolates_broken_links() {
    for case in ["duplicate", "missing", "unknown", "broken link"] {
        let run = Run::new(
            "require_approval",
            "allow",
            &["propose-transaction", "sign-payment"],
        )
        .await;
        let args = Tool::Pay.prepare_args(&run.f);
        let prepared = run.invoke("stellar_pay", args.clone()).await;
        assert_eq!(prepared["ok"], true);
        let path = run
            .f
            .server
            .resolve_approval_dir()
            .unwrap()
            .join("operator.toml");
        let original = std::fs::read_to_string(&path).unwrap();
        let mut file: toml_edit::DocumentMut = original.parse().unwrap();
        match case {
            "duplicate" => {}
            "missing" => {
                file["payment_recovery"][0]
                    .as_table_mut()
                    .unwrap()
                    .remove("expires");
            }
            "unknown" => {
                file["payment_recovery"][0]["unrecognized"] = toml_edit::value(true);
            }
            "broken link" => {
                let created = file["payment_recovery"][0]["created"].as_integer().unwrap();
                file["payment_recovery"][0]["created"] = toml_edit::value(created + 1);
            }
            _ => unreachable!(),
        }
        let bytes = if case == "duplicate" {
            let start = original.find("[[payment_recovery]]").unwrap();
            format!("{original}\n{}", &original[start..])
        } else {
            file.to_string()
        };
        let _: toml_edit::DocumentMut = bytes.parse().unwrap();
        std::fs::write(&path, &bytes).unwrap();
        let result = run
            .f
            .server
            .call_stellar_toolset_invoke(StellarToolsetInvokeArgs {
                toolset: TOOLSET.into(),
                action: "stellar_pay".into(),
                chain_id: Some("stellar:mainnet".into()),
                args: args.clone(),
            })
            .await;
        if case == "broken link" {
            let body = wire(&result.unwrap());
            assert_eq!(
                body["error"]["code"], "approval.entry_inconsistent",
                "the broken link refuses only its use"
            );
            let mut store = PendingApprovalStore::open(path.clone()).unwrap();
            assert_eq!(
                store.snapshot(now_unix_ms().unwrap()).len(),
                1,
                "the malformed-use record remains listable"
            );
            let nonce = prepared["data"]["approval"]["approval_nonce"]
                .as_str()
                .unwrap();
            store
                .reject(nonce, now_unix_ms().unwrap(), 300_000)
                .unwrap();
            drop(store);
            let mut independent = args;
            independent["business_id"] = uuid::Uuid::new_v4().to_string().into();
            independent["memo_id"] = 7.into();
            let next = run.invoke("stellar_pay", independent.clone()).await;
            assert_eq!(
                next["ok"], true,
                "an unrelated payment still prepares: {next}"
            );
            let entry = run
                .pending()
                .into_iter()
                .find(|entry| {
                    entry.approval_nonce
                        == next["data"]["approval"]["approval_nonce"].as_str().unwrap()
                })
                .unwrap();
            run.grant(independent["destination"].as_str().unwrap());
            let mut commit = run.commit_args(independent, &next);
            commit["approval_nonce"] = entry.approval_nonce.clone().into();
            commit["approval_attestation"] = run.f.attest(&entry).into();
            assert_eq!(
                run.invoke("stellar_pay_commit", commit).await["ok"],
                true,
                "an unrelated payment still submits"
            );
            assert_eq!(run.control.sent().len(), 1);
        } else {
            // The initial inbox open refuses the whole file on the protocol
            // error channel.
            let error = result.expect_err(
                "a malformed recovery section must refuse the public preparation typed",
            );
            assert_eq!(
                (error.code, &*error.message, error.data),
                (
                    rmcp::model::ErrorCode::INTERNAL_ERROR,
                    "approval.store_error: approval I/O error: Other",
                    None
                ),
                "{case}"
            );
            assert_eq!(
                std::fs::read_to_string(&path).unwrap(),
                bytes,
                "a malformed file is never rewritten"
            );
            assert!(authorizations(&run.f).is_empty());
            assert!(run.control.sent().is_empty());
        }
    }
}

#[tokio::test]
#[serial_test::serial(keyring, mainnet_clock)]
#[serial_test::serial]
async fn public_payment_reuses_consent_at_approval_capacity() {
    let run = Run::new("require_approval", "allow", &["propose-transaction"]).await;
    let args = Tool::Pay.prepare_args(&run.f);
    let prepared = run.invoke("stellar_pay", args.clone()).await;
    assert_eq!(prepared["ok"], true);
    let path = run
        .f
        .server
        .resolve_approval_dir()
        .unwrap()
        .join("operator.toml");
    let mut file: toml_edit::DocumentMut = std::fs::read_to_string(&path).unwrap().parse().unwrap();
    let template = file["pending"][0].as_table().unwrap().clone();
    let entries = file["pending"].as_array_of_tables_mut().unwrap();
    while entries.len() < 4096 {
        let mut entry = template.clone();
        entry["approval_nonce"] = toml_edit::value(format!("capacity{:014}", entries.len()));
        entries.push(entry);
    }
    let bytes = file.to_string();
    std::fs::write(&path, &bytes).unwrap();
    assert_eq!(
        PendingApprovalStore::open(path.clone()).unwrap().len(),
        4096
    );
    let result = run
        .f
        .server
        .call_stellar_toolset_invoke(StellarToolsetInvokeArgs {
            toolset: TOOLSET.into(),
            action: "stellar_pay".into(),
            chain_id: Some("stellar:mainnet".into()),
            args,
        })
        .await;
    assert!(
        result.is_ok(),
        "an existing recovery key is reused before checking capacity: {result:?}"
    );
    assert_eq!(
        wire(&result.unwrap())["data"]["approval"],
        prepared["data"]["approval"]
    );
    assert_eq!(std::fs::read_to_string(&path).unwrap(), bytes);

    // A new key at genuine capacity: every entry is live, so nothing is
    // collected and the payment refuses typed without a write.
    let mut new_key = Tool::Pay.prepare_args(&run.f);
    new_key["amount_in_stroops"] = "9".into();
    let refused = run
        .f
        .server
        .call_stellar_toolset_invoke(StellarToolsetInvokeArgs {
            toolset: TOOLSET.into(),
            action: "stellar_pay".into(),
            chain_id: Some("stellar:mainnet".into()),
            args: new_key,
        })
        .await
        .map(|result| wire(&result))
        .map_err(|error| error.message.to_string());
    assert_eq!(
        refused,
        Err(
            "approval.store_error: pending approval store full: maximum 4096 entries reached; \
             retained payment bindings occupy capacity until their retention ends, and \
             `stellar-agent approve gc --profile operator` frees them afterward"
                .to_owned()
        ),
        "a new key at genuine capacity refuses with the store's capacity error"
    );
    assert_eq!(std::fs::read_to_string(&path).unwrap(), bytes);
    assert_eq!(PendingApprovalStore::open(path).unwrap().len(), 4096);
    assert!(authorizations(&run.f).is_empty());
    assert!(run.control.sent().is_empty());
}

#[tokio::test]
#[serial_test::serial(keyring, mainnet_clock)]
#[serial_test::serial]
async fn public_muxed_business_conflict_keeps_the_original_payment() {
    let run = Run::new("allow", "allow", &["propose-transaction", "sign-payment"]).await;
    let mut args = Tool::Pay.prepare_args(&run.f);
    args["destination"] = DESTINATIONS[1].0.into();
    run.grant(DESTINATIONS[0].0);
    let prepared = run.invoke("stellar_pay", args.clone()).await;
    assert_eq!(prepared["ok"], true);
    let mut conflicting = args.clone();
    conflicting["destination"] = DESTINATIONS[2].0.into();
    for sent in [false, true] {
        let direct = wire(&Tool::Pay.prepare(&run.f.server, &conflicting).await);
        assert_eq!(
            direct["error"]["code"], "operation.business_id_conflict",
            "a different full M ID cannot replace the retained intent"
        );
        assert_eq!(run.control.sent().len(), usize::from(sent));
        if !sent {
            let retry = run.invoke("stellar_pay", args.clone()).await;
            assert_eq!(
                retry["data"]["envelope_xdr"],
                prepared["data"]["envelope_xdr"]
            );
            let result = run
                .invoke("stellar_pay_commit", run.commit_args(args.clone(), &retry))
                .await;
            assert_eq!(result["ok"], true, "{result}");
            assert_eq!(result["data"]["destination"], DESTINATIONS[1].0);
        }
    }
    let replay = run
        .invoke("stellar_pay_commit", run.commit_args(args, &prepared))
        .await;
    assert_eq!(replay["ok"], true);
    assert_eq!(replay["data"]["destination"], DESTINATIONS[1].0);
    assert_eq!(run.control.sent().len(), 1);
    assert_eq!(authorizations(&run.f).len(), 1);
}

#[tokio::test]
#[serial_test::serial(keyring, mainnet_clock)]
#[serial_test::serial]
async fn public_classic_payments_share_contract_named_accounting_in_both_route_orders() {
    use stellar_agent_core::policy::v1::criteria::state_store::{
        StateKey, WindowEntry, WindowLimit,
    };
    for issued in [false, true] {
        for first_toolset in [true, false] {
            let issuer = stellar_agent_test_support::signed_envelope::account_id_for_seed([7; 32]);
            let classic = if issued {
                format!("USD:{issuer}")
            } else {
                "native".to_owned()
            };
            let contract =
                stellar_agent_core::asset_id::CanonicalAsset::parse_payment_asset(&classic)
                    .unwrap()
                    .sac_contract_id(stellar_agent_core::profile::caip2::MAINNET_PASSPHRASE)
                    .unwrap();
            let run = Run::with_policy(
                "allow",
                "allow",
                &["propose-transaction", "sign-payment"],
                |raw| {
                    let mut doc = raw
                        .replace("\"native\"", &format!("\"{contract}\""))
                        .parse::<toml_edit::DocumentMut>()
                        .unwrap();
                    if issued {
                        doc["mainnet"]["cross_check_thresholds"][&contract] =
                            toml_edit::value("100");
                    }
                    for rule in doc["rules"].as_array_of_tables_mut().unwrap().iter_mut() {
                        for criterion in rule["criteria"].as_array_mut().unwrap().iter_mut() {
                            let criterion = criterion.as_inline_table_mut().unwrap();
                            if criterion["kind"].as_str() == Some("per_period_cap") {
                                criterion.insert("max_stroops", "100".into());
                            }
                        }
                    }
                    doc.to_string()
                },
            )
            .await;
            if issued {
                run.issued_entries();
            }
            run.f
                .server
                .window_store
                .record_authorized(
                    run.f.server.security_profile(),
                    &[WindowEntry::new(
                        StateKey::new("operator", 1, &contract, 86_400),
                        now_unix_ms().unwrap(),
                        40,
                        WindowLimit::Amount {
                            asset: contract.clone(),
                            window: "1d".to_owned(),
                            max_stroops: 100,
                        },
                    )],
                )
                .unwrap();
            assert_eq!(recorded_amount(&run, &contract), (40, 1));
            run.grant_asset(DESTINATIONS[0].0, if issued { &classic } else { "XLM" });
            for (amount, admitted) in [(50, true), (11, false), (10, true)] {
                let toolset = if amount == 50 {
                    first_toolset
                } else {
                    !first_toolset
                };
                let mut args = Tool::Pay.prepare_args(&run.f);
                args["asset"] = if !issued && toolset {
                    "XLM".into()
                } else {
                    classic.clone().into()
                };
                args["amount_in_stroops"] = amount.to_string().into();
                let prepared = if toolset {
                    run.invoke("stellar_pay", args.clone()).await
                } else {
                    wire(&Tool::Pay.prepare(&run.f.server, &args).await)
                };
                if !admitted {
                    assert_eq!(
                        prepared["error"]["code"],
                        "policy.deny.per_period_cap_exceeded"
                    );
                    assert_eq!(recorded_amount(&run, &contract), (90, 2));
                    assert_eq!(run.control.sent().len(), 1);
                    continue;
                }
                assert_eq!(
                    prepared["ok"], true,
                    "an equivalent contract policy admits the classic payment: {prepared}"
                );
                let commit = run.commit_args(args, &prepared);
                let result = if toolset {
                    run.invoke("stellar_pay_commit", commit).await
                } else {
                    wire(&Tool::Pay.commit(&run.f.server, commit).await.unwrap())
                };
                assert_eq!(result["ok"], true, "{result}");
                assert_eq!(
                    recorded_amount(&run, &contract),
                    if amount == 50 { (90, 2) } else { (100, 3) },
                    "both spellings and routes use the same policy counter"
                );
                run.source_sequence(if amount == 50 { 2 } else { 3 });
            }
            assert_eq!(run.control.sent().len(), 2);
            assert_eq!(authorizations(&run.f).len(), 2);
            assert!(run.pending().is_empty());
        }
    }
}

#[tokio::test]
#[serial_test::serial(keyring, mainnet_clock)]
#[serial_test::serial]
async fn public_outer_reserve_uses_authoritative_fee_for_native_and_issued() {
    use stellar_agent_test_support::xdr_fixtures::{
        account_entry_xdr_with_seq, account_ledger_key_xdr,
    };
    for issued in [false, true] {
        for allowed in [false, true] {
            let issuer = stellar_agent_test_support::signed_envelope::account_id_for_seed([7; 32]);
            let asset = if issued {
                format!("USD:{issuer}")
            } else {
                "native".to_owned()
            };
            let run = Run::with_policy(
                "allow",
                "allow",
                &["propose-transaction", "sign-payment"],
                |raw| {
                    let mut doc = raw
                        .replace("\"native\"", &format!("\"{asset}\""))
                        .parse::<toml_edit::DocumentMut>()
                        .unwrap();
                    if issued {
                        doc["mainnet"]["cross_check_thresholds"][&asset] = toml_edit::value("100");
                    }
                    for rule in doc["rules"].as_array_of_tables_mut().unwrap().iter_mut() {
                        if rule["match"]["tool"].as_str() == Some("stellar_toolset_invoke") {
                            let mut reserve = toml_edit::InlineTable::new();
                            reserve.insert("kind", "minimum_reserve".into());
                            reserve.insert("margin_stroops", 1_000_i64.into());
                            rule["criteria"].as_array_mut().unwrap().push(reserve);
                        }
                    }
                    doc.to_string()
                },
            )
            .await;
            if issued {
                run.issued_entries();
            }
            let mut entries = run
                .control
                .entries
                .lock()
                .unwrap()
                .clone()
                .unwrap_or_else(|| super::common::tests::mainnet::fixture_entries(&run.f));
            let source = run.f.envelope.source();
            let source_key = account_ledger_key_xdr(source);
            let native_debit = if issued { 0 } else { 10 };
            let subentries = u32::from(issued);
            let minimum_balance = (2 + i64::from(subentries)) * 5_000_000;
            let balance = minimum_balance + 1_000 + native_debit + 177 - i64::from(!allowed);
            for entry in &mut entries {
                if entry["key"] == source_key {
                    entry["xdr"] =
                        account_entry_xdr_with_seq(source, balance, subentries, 1).into();
                }
            }
            *run.control.entries.lock().unwrap() = Some(entries.clone());
            *run.oracle_control.entries.lock().unwrap() = Some(entries);
            let mut args = Tool::Pay.prepare_args(&run.f);
            args["asset"] = asset.clone().into();
            args["fee"] = "177".into();
            args["memo_text"] = "fee-sensitive".into();
            let prepared = run.invoke("stellar_pay", args.clone()).await;
            if allowed {
                assert_eq!(
                    prepared["ok"], true,
                    "the exact reserve boundary admits: {prepared}"
                );
            } else {
                assert_eq!(
                    prepared["error"]["code"], "policy.deny.minimum_reserve_breached",
                    "preparation includes the decoded native fee for {asset}: {prepared}"
                );
                assert!(prepared["data"].is_null());
            }
            assert!(run.pending().is_empty());
            assert!(run.control.sent().is_empty());
            assert!(authorizations(&run.f).is_empty());
            assert_eq!(run.f.seed_reads.load(Ordering::SeqCst), 0);
            let direct = wire(&Tool::Pay.prepare(&run.f.server, &args).await);
            assert_eq!(
                direct["ok"], true,
                "the routed policy permits the control: {direct}"
            );
            let facts = stellar_agent_core::envelope_decode::decode_authoritative_args(
                direct["data"]["envelope_xdr"].as_str().unwrap(),
                "stellar_pay_commit",
            )
            .unwrap();
            assert_eq!(facts["total_fee_stroops"], 177);
            assert_eq!(facts["sequence_number"], 2);
            run.grant_asset(DESTINATIONS[0].0, if issued { &asset } else { "XLM" });
            let nonce_reads = run.f.nonce_reads.load(Ordering::SeqCst);
            let committed = run
                .invoke("stellar_pay_commit", run.commit_args(args, &direct))
                .await;
            if allowed {
                assert_eq!(committed["ok"], true, "{committed}");
                assert_eq!(run.control.sent().len(), 1);
                assert_eq!(authorizations(&run.f).len(), 1);
            } else {
                assert_eq!(
                    committed["error"]["code"], "policy.deny.minimum_reserve_breached",
                    "commit includes the decoded native fee for {asset}: {committed}"
                );
                assert_eq!(
                    run.f.nonce_reads.load(Ordering::SeqCst),
                    nonce_reads,
                    "the outer reserve refuses before nonce HMAC"
                );
                assert!(run.f.server.replay_window.lock().await.is_empty());
                assert!(run.control.sent().is_empty());
                assert!(authorizations(&run.f).is_empty());
                assert_eq!(run.f.seed_reads.load(Ordering::SeqCst), 0);
            }
            assert!(run.pending().is_empty());
        }
    }
}

#[tokio::test]
#[serial_test::serial(keyring, mainnet_clock)]
#[serial_test::serial]
async fn public_toolset_pairs_share_one_frame_and_leave_direct_calls_independent() {
    async fn account_reads(rpc: &wiremock::MockServer, account: &str) -> usize {
        let key = stellar_agent_test_support::xdr_fixtures::account_ledger_key_xdr(account);
        rpc.received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|request| {
                let body: Value = serde_json::from_slice(&request.body).unwrap();
                body["method"] == "getLedgerEntries"
                    && body["params"]["keys"]
                        .as_array()
                        .is_some_and(|keys| keys.iter().any(|candidate| candidate == &key))
            })
            .count()
    }
    let mut run = Run::new("allow", "allow", &["propose-transaction", "sign-payment"]).await;
    let cache = Arc::new(super::common::tests::ChangingCounterpartyResolver(
        std::sync::atomic::AtomicUsize::new(0),
    ));
    run.f.server.counterparty_resolver = cache.clone();
    let args = Tool::Pay.prepare_args(&run.f);
    let prepared = run.invoke("stellar_pay", args.clone()).await;
    assert_eq!(prepared["ok"], true, "{prepared}");
    assert_eq!(cache.0.load(Ordering::SeqCst), 1, "one preparation frame");
    assert_eq!(
        account_reads(&run._primary, run.f.envelope.source()).await,
        1
    );
    assert_eq!(account_reads(&run._primary, DESTINATIONS[0].0).await, 1);
    let facts = stellar_agent_core::envelope_decode::decode_authoritative_args(
        prepared["data"]["envelope_xdr"].as_str().unwrap(),
        "stellar_pay_commit",
    )
    .unwrap();
    assert_eq!(
        facts,
        serde_json::json!({
            "source": run.f.envelope.source(), "destination": DESTINATIONS[0].0,
            "amount_stroops": "10", "asset": "XLM", "total_fee_stroops": 100,
            "sequence_number": 2, "memo_kind": "none", "memo": null,
        })
    );
    run.grant(DESTINATIONS[0].0);
    let result = run
        .invoke("stellar_pay_commit", run.commit_args(args, &prepared))
        .await;
    assert_eq!(result["ok"], true, "{result}");
    assert_eq!(
        cache.0.load(Ordering::SeqCst),
        2,
        "one frame per handler pair"
    );
    assert_eq!(
        account_reads(&run._primary, run.f.envelope.source()).await,
        4
    );
    assert_eq!(account_reads(&run._primary, DESTINATIONS[0].0).await, 2);
    assert_eq!(run.control.sent().len(), 1);
    assert_eq!(recorded_amount(&run, "native"), (10, 1));
    run.source_sequence(2);
    let direct = wire(
        &Tool::Pay
            .prepare(&run.f.server, &Tool::Pay.prepare_args(&run.f))
            .await,
    );
    assert_eq!(
        direct["ok"], true,
        "the next direct call has its own frame: {direct}"
    );
    assert_eq!(cache.0.load(Ordering::SeqCst), 3);
    assert_eq!(
        account_reads(&run._primary, run.f.envelope.source()).await,
        5
    );
    assert_eq!(account_reads(&run._primary, DESTINATIONS[0].0).await, 3);
    assert!(run.pending().is_empty());
    assert_eq!(run.control.sent().len(), 1);
}

#[tokio::test]
#[serial_test::serial(keyring, mainnet_clock)]
#[serial_test::serial]
async fn public_toolset_commit_refreshes_reset_history_and_protects_open_operations() {
    use stellar_agent_core::policy::v1::criteria::state_store::{
        StateKey, WindowEntry, WindowLimit,
    };
    use stellar_agent_network::policy_state::{
        OwnerResetSignature, ResetConsent, ResetError, WindowStoreError,
    };
    let mut run = Run::new(
        "require_approval",
        "allow",
        &["propose-transaction", "sign-payment"],
    )
    .await;
    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    let arrivals = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    run.f.server.payment_proof_barrier = Some((barrier.clone(), arrivals.clone()));
    let server = &run.f.server;
    let profile = server.security_profile();
    let now = now_unix_ms().unwrap();
    let key = StateKey::new("operator", 1, "rate_limit", 86_400);
    let history = WindowEntry::new(
        key.clone(),
        now,
        1,
        WindowLimit::Count {
            window: "1d".to_owned(),
            max_calls: 10,
        },
    );
    let shared = server.policy_engine.window_state_store().unwrap();
    server
        .window_store
        .record_and_persist(profile, &vec![history.clone(); 10])
        .unwrap();
    server
        .window_store
        .load_into_at("operator", profile, shared, now)
        .unwrap();
    assert_eq!(shared.query_window(&key, now).unwrap(), (10, 10));
    let writer = server.window_store.clone();
    let reset = |request_id| {
        writer.reset(
            profile,
            "operator",
            now,
            "reset window history",
            request_id,
            |row| {
                let owner = ed25519_dalek::SigningKey::from_bytes(&[11; 32]);
                Ok::<_, ()>(ResetConsent {
                    owner_signature: Some(OwnerResetSignature {
                        owner: owner.verifying_key().to_bytes(),
                        signature: stellar_agent_core::policy::v1::signature::sign(
                            &row.statement_digest(),
                            &owner,
                        ),
                    }),
                })
            },
            |_, _| Ok(()),
        )
    };
    reset("before-public-gate").unwrap();
    assert_eq!(shared.query_window(&key, now).unwrap(), (10, 10));
    let args = Tool::Pay.prepare_args(&run.f);
    let prepared = run.invoke("stellar_pay", args.clone()).await;
    assert_eq!(prepared["ok"], true, "{prepared}");
    run.grant(DESTINATIONS[0].0);
    let entry = run.pending().pop().unwrap();
    let mut commit = run.commit_args(args, &prepared);
    commit["approval_nonce"] = entry.approval_nonce.clone().into();
    commit["approval_attestation"] = run.f.attest(&entry).into();
    let reset_after_gate = async {
        while arrivals.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
        let before = std::fs::read(writer.path()).unwrap();
        let refused = reset("after-public-gate");
        assert!(
            matches!(
                refused,
                Err(ResetError::Store {
                    error: WindowStoreError::OperationsOpen { open: 1 },
                    ..
                })
            ),
            "reset protects the live public operation: {refused:?}"
        );
        assert_eq!(std::fs::read(writer.path()).unwrap(), before);
        barrier.wait().await;
    };
    let payment = run.invoke("stellar_pay_commit", commit);
    tokio::pin!(payment);
    let result = tokio::select! {
        result = &mut payment => result,
        () = reset_after_gate => payment.await,
    };
    assert_eq!(
        result["ok"], true,
        "the public commit refreshes stale shared history before final resolution: {result}"
    );
    assert_eq!(arrivals.load(Ordering::SeqCst), 1);
    assert_eq!(run.control.sent().len(), 1);
    assert_eq!(authorizations(&run.f).len(), 1);
    assert_eq!(recorded_amount(&run, "native"), (10, 1));
    assert_eq!(recorded_amount(&run, "rate_limit"), (1, 1));
    run.source_sequence(2);
    let mut direct_args = Tool::Pay.prepare_args(&run.f);
    direct_args["memo_text"] = "direct-after-reset".into();
    let direct = wire(&Tool::Pay.prepare(&run.f.server, &direct_args).await);
    assert_eq!(direct["ok"], true, "{direct}");
    let sent = wire(
        &Tool::Pay
            .commit(&run.f.server, run.commit_args(direct_args, &direct))
            .await
            .unwrap(),
    );
    assert_eq!(
        sent["ok"], true,
        "a direct payment after reset sees refreshed history: {sent}"
    );
    assert_eq!(run.control.sent().len(), 2);
    assert_eq!(recorded_amount(&run, "native"), (20, 2));
    assert_eq!(recorded_amount(&run, "rate_limit"), (2, 2));
}

#[tokio::test]
#[serial_test::serial(keyring, mainnet_clock)]
#[serial_test::serial]
async fn public_mainnet_terminal_consent_survives_restart_and_clock_rollback() {
    use stellar_agent_core::policy::v1::criteria::state_store::set_query_time_for_test;
    for first_toolset in [true, false] {
        for (mode, code) in [
            ("expired", None),
            ("rejected", Some("policy.approval_rejected")),
            ("consumed", Some("policy.approval_consumed")),
        ] {
            // The operation's waiting window ends with its consent, so at
            // that end the retained operation answers with its stored state.
            let refuses = |body: &Value| match code {
                None => {
                    body["data"]["status"] == "replayed"
                        && body["data"]["operation"]["state"] == "expired"
                        && body["data"]["operation"]["tx_hash"].is_null()
                }
                Some(code) => body["error"]["code"] == code,
            };
            let mut run = Run::new(
                "require_approval",
                "require_approval",
                &["propose-transaction", "sign-payment"],
            )
            .await;
            let args = Tool::Pay.prepare_args(&run.f);
            let prepared = run.prepare_route(&args, first_toolset).await;
            assert_eq!(prepared["ok"], true, "{prepared}");
            run.grant(DESTINATIONS[0].0);
            let entry = run.pending().pop().unwrap();
            let mut commit = run.commit_args(args.clone(), &prepared);
            commit["approval_nonce"] = entry.approval_nonce.clone().into();
            commit["approval_attestation"] = run.f.attest(&entry).into();
            let path = run
                .f
                .server
                .resolve_approval_dir()
                .unwrap()
                .join("operator.toml");
            let mut store = PendingApprovalStore::open(path.clone()).unwrap();
            match mode {
                "rejected" => {
                    store
                        .reject(&entry.approval_nonce, entry.created_at_unix_ms, 600_000)
                        .unwrap();
                }
                "consumed" => {
                    store
                        .consume(
                            &entry.approval_nonce,
                            &"ab".repeat(32),
                            stellar_agent_core::approval::ConsumedOutcome::Unknown,
                        )
                        .unwrap();
                }
                _ => {}
            }
            drop(store);
            // An envelope record's waiting window ends with its consent. A
            // canonical record's granted intent consent keeps it waiting until
            // the consent's execution end (approvals.rs:1791-1806, swept at
            // operations.rs:2166-2178), so that row advances to that end.
            let end = if !first_toolset && mode == "expired" {
                let consent = stellar_agent_network::policy_state::ApprovalStatus::new(
                    &run.f.server.window_store,
                    run.f.server.security_profile(),
                )
                .find_by_nonce(&entry.approval_nonce)
                .unwrap()
                .unwrap()
                .record
                .consent;
                assert!(
                    consent.is_some(),
                    "the attested canonical consent is granted"
                );
                consent.unwrap().execution_expires_at_ms
            } else {
                entry.expires_at_unix_ms
            };
            let policy_clock = set_query_time_for_test(end);
            let network_clock = stellar_agent_network::mainnet::clock::set_now_ms_for_test(end);
            run.f.server.clock =
                Arc::new(stellar_agent_core::timefmt::MockClock::new(move || Ok(end)));
            if mode == "expired" {
                let inbox = std::fs::read(&path).unwrap();
                let expired = run.prepare_route(&args, !first_toolset).await;
                assert!(refuses(&expired), "{expired}");
                assert_eq!(
                    std::fs::read(&path).unwrap(),
                    inbox,
                    "the stored answer writes no inbox entry"
                );
                let stored = stellar_agent_network::policy_state::OperationStatus::new(
                    &run.f.server.window_store,
                    run.f.server.security_profile(),
                )
                .view(
                    &stellar_agent_network::policy_state::BusinessId::parse(
                        args["business_id"].as_str().unwrap(),
                    )
                    .unwrap(),
                )
                .unwrap()
                .unwrap();
                assert_eq!(
                    stored.state.wire_name(),
                    "expired",
                    "the window retains the expired operation"
                );
            }
            run.restart();
            let earlier = entry.created_at_unix_ms + 1;
            policy_clock.set(earlier);
            network_clock.set(earlier);
            run.f.server.clock = Arc::new(stellar_agent_core::timefmt::MockClock::new(move || {
                Ok(earlier)
            }));
            let before = std::fs::read(&path).unwrap();
            let reads = run.f.nonce_reads.load(Ordering::SeqCst);
            let stored = || {
                stellar_agent_network::policy_state::OperationStatus::new(
                    &run.f.server.window_store,
                    run.f.server.security_profile(),
                )
                .view(
                    &stellar_agent_network::policy_state::BusinessId::parse(
                        args["business_id"].as_str().unwrap(),
                    )
                    .unwrap(),
                )
                .unwrap()
            };
            let retried = run.prepare_route(&args, !first_toolset).await;
            assert!(
                refuses(&retried),
                "{mode}: retained consent refuses after rollback: {retried}"
            );
            let state_before = stored();
            let window_before = std::fs::read(run.f.server.window_store.path()).unwrap();
            let refused = run.commit_route(commit, !first_toolset).await;
            if mode == "consumed" {
                // The inbox tombstone is inbox material and decides nothing
                // on mainnet, so the commit meets the uniform refusal of a
                // proof that does not verify against the durable record.
                assert_eq!(
                    refused["error"],
                    wire(&super::common::approval_required_indistinguishable(
                        "operator"
                    ))["error"],
                    "{mode}: public commit refuses uniformly: {refused}"
                );
                assert_eq!(
                    stored(),
                    state_before,
                    "{mode}: the stored operation is unchanged"
                );
                assert_eq!(
                    std::fs::read(run.f.server.window_store.path()).unwrap(),
                    window_before,
                    "{mode}: the commit writes no window state"
                );
            } else {
                assert!(
                    refuses(&refused),
                    "{mode}: public commit preserves the terminal refusal: {refused}"
                );
            }
            assert_eq!(std::fs::read(&path).unwrap(), before);
            assert_eq!(run.f.nonce_reads.load(Ordering::SeqCst), reads);
            assert_eq!(run.f.seed_reads.load(Ordering::SeqCst), 0);
            assert!(authorizations(&run.f).is_empty());
            assert!(run.control.sent().is_empty());

            let current = now_unix_ms().unwrap();
            policy_clock.set(current);
            network_clock.set(current);
            run.f.server.clock = Arc::new(stellar_agent_core::timefmt::MockClock::new(move || {
                Ok(current)
            }));
            let mut independent = Tool::Pay.prepare_args(&run.f);
            independent["memo_text"] = "independent".into();
            let prepared = run.prepare_route(&independent, !first_toolset).await;
            assert_eq!(
                prepared["ok"], true,
                "{mode}: an unrelated payment can prepare: {prepared}"
            );
            let nonce = prepared["data"]["approval"]["approval_nonce"]
                .as_str()
                .unwrap();
            let entry = run
                .pending()
                .into_iter()
                .find(|entry| entry.approval_nonce == nonce)
                .unwrap();
            let mut commit = run.commit_args(independent, &prepared);
            commit["approval_nonce"] = nonce.into();
            commit["approval_attestation"] = run.f.attest(&entry).into();
            let proof_now = now_unix_ms().unwrap();
            policy_clock.set(proof_now);
            network_clock.set(proof_now);
            run.f.server.clock = Arc::new(stellar_agent_core::timefmt::MockClock::new(move || {
                Ok(proof_now)
            }));
            let sent = run.commit_route(commit, first_toolset).await;
            assert_eq!(
                sent["ok"], true,
                "{mode}: independent consent can pay: {sent}"
            );
            assert_eq!(run.control.sent().len(), 1);
            assert_eq!(authorizations(&run.f).len(), 1);
            assert_eq!(recorded_amount(&run, "native"), (10, 1));
        }
    }
}

#[tokio::test]
#[serial_test::serial(keyring, mainnet_clock)]
#[serial_test::serial]
async fn public_direct_and_toolset_payment_audit_bodies_match() {
    let now = now_unix_ms().unwrap();
    let _network_clock = stellar_agent_network::mainnet::clock::set_now_ms_for_test(now);
    let _policy_clock =
        stellar_agent_core::policy::v1::criteria::state_store::set_query_time_for_test(now);
    let mut bodies = Vec::new();
    for toolset in [false, true] {
        let mut run = Run::new("allow", "allow", &["propose-transaction", "sign-payment"]).await;
        run.f.server.clock = Arc::new(stellar_agent_core::timefmt::MockClock::new(move || Ok(now)));
        let mut args = Tool::Pay.prepare_args(&run.f);
        args["destination"] = DESTINATIONS[2].0.into();
        args["fee"] = "177".into();
        args["memo_text"] = "parity".into();
        run.grant(DESTINATIONS[0].0);
        let prepared = run.prepare_route(&args, toolset).await;
        assert_eq!(prepared["ok"], true, "{prepared}");
        let result = run
            .commit_route(run.commit_args(args, &prepared), toolset)
            .await;
        assert_eq!(result["ok"], true, "{result}");
        let path = &run.f.server.security_profile().audit_log_path;
        stellar_agent_core::audit_log::verify_log(path, None).unwrap();
        let rows: Vec<stellar_agent_core::audit_log::entry::AuditEntry> =
            std::fs::read_to_string(path)
                .unwrap()
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .filter(|entry: &stellar_agent_core::audit_log::entry::AuditEntry| {
                    matches!(
                        entry.event_kind,
                        stellar_agent_core::audit_log::schema::EventKind::ValueActionPending { .. }
                    )
                })
                .collect();
        assert_eq!(rows.len(), 1);
        let mut body: Value =
            serde_json::from_slice(&rows[0].canonical_json_body().unwrap()).unwrap();
        // Canonical hash-input bodies exclude chain authentication fields.
        // Only these random identifiers and the wall timestamp are normalized.
        for key in ["ts", "request_id"] {
            assert!(body.as_object_mut().unwrap().remove(key).is_some(), "{key}");
        }
        // The toolset commit takes the envelope route and names its protocol
        // nonce (pay.rs:2539); the direct commit of the canonical record names
        // none (canonical_commit.rs:342). Every other field is compared below.
        let nonce_id = body.as_object_mut().unwrap().remove("nonce_id");
        assert_eq!(
            nonce_id.is_some_and(|value| !value.is_null()),
            toolset,
            "nonce_id names the toolset commit's protocol nonce only"
        );
        assert_eq!(body["legs"][0]["destination_sha256"], DESTINATIONS[2].1);
        assert_eq!(body["legs"][0]["amount"], "10");
        assert_eq!(body["policy_decision"], "allow");
        assert_eq!(run.control.sent().len(), 1);
        assert_eq!(recorded_amount(&run, "native"), (10, 1));
        assert!(run.pending().is_empty());
        bodies.push(body);
    }
    assert_eq!(
        bodies[0], bodies[1],
        "the canonical payment audit body is independent of the public route"
    );
}

#[tokio::test]
#[serial_test::serial(keyring, mainnet_clock)]
#[serial_test::serial]
async fn public_composed_rate_counts_once_across_routes_and_restart() {
    for first_toolset in [false, true] {
        let mut run = Run::with_policy(
            "allow",
            "allow",
            &["propose-transaction", "sign-payment"],
            |raw| {
                let mut doc = raw.parse::<toml_edit::DocumentMut>().unwrap();
                for rule in doc["rules"].as_array_of_tables_mut().unwrap().iter_mut() {
                    let outer = rule["match"]["tool"].as_str() == Some("stellar_toolset_invoke");
                    for criterion in rule["criteria"].as_array_mut().unwrap().iter_mut() {
                        let criterion = criterion.as_inline_table_mut().unwrap();
                        if criterion["kind"].as_str() == Some("rate_limit") {
                            criterion.insert("max_calls", if outer { 2_i64 } else { 3_i64 }.into());
                        }
                    }
                }
                doc.to_string()
            },
        )
        .await;
        run.grant(DESTINATIONS[0].0);
        for (index, toolset) in [first_toolset, !first_toolset].into_iter().enumerate() {
            let mut args = Tool::Pay.prepare_args(&run.f);
            args["memo_text"] = format!("rate-{index}").into();
            let prepared = run.prepare_route(&args, toolset).await;
            assert_eq!(prepared["ok"], true, "{prepared}");
            let result = run
                .commit_route(run.commit_args(args, &prepared), toolset)
                .await;
            assert_eq!(result["ok"], true, "{result}");
            assert_eq!(
                recorded_amount(&run, "rate_limit"),
                (i128::try_from(index + 1).unwrap(), index + 1),
                "one shared rate debit per payment"
            );
            run.source_sequence(i64::try_from(index + 2).unwrap());
        }
        run.restart();
        let args = Tool::Pay.prepare_args(&run.f);
        let refused = run.invoke("stellar_pay", args).await;
        assert_eq!(
            refused["error"]["code"], "policy.deny.rate_limit_exceeded",
            "the tighter outer rate survives restart: {refused}"
        );
        assert_eq!(recorded_amount(&run, "rate_limit"), (2, 2));
        assert_eq!(run.control.sent().len(), 2);
        assert_eq!(authorizations(&run.f).len(), 2);
        assert!(run.pending().is_empty());
    }
}

#[tokio::test]
#[serial_test::serial(keyring, mainnet_clock)]
#[serial_test::serial]
async fn public_amount_boundaries_refuse_before_consent_or_nonce_use() {
    use stellar_xdr::{Limits, OperationBody, ReadXdr, TransactionEnvelope, WriteXdr};
    let run = Run::new("allow", "allow", &["propose-transaction", "sign-payment"]).await;
    let args = Tool::Pay.prepare_args(&run.f);
    let prepared = run.invoke("stellar_pay", args.clone()).await;
    assert_eq!(prepared["ok"], true, "{prepared}");
    let valid_commit = run.commit_args(args.clone(), &prepared);
    let reads = run.f.nonce_reads.load(Ordering::SeqCst);
    for (amount, message) in [
        ("0", "amount_in_stroops must be positive"),
        (
            "-1",
            "amount_in_stroops: not a valid non-negative decimal u64 (stroops)",
        ),
        ("9223372036854775808", "amount_in_stroops exceeds i64 max"),
    ] {
        for action in ["stellar_pay", "stellar_pay_commit"] {
            let mut invalid = if action == "stellar_pay" {
                args.clone()
            } else {
                valid_commit.clone()
            };
            invalid["amount_in_stroops"] = amount.into();
            let result = run
                .f
                .server
                .call_stellar_toolset_invoke(StellarToolsetInvokeArgs {
                    toolset: TOOLSET.into(),
                    action: action.into(),
                    chain_id: Some("stellar:mainnet".into()),
                    args: invalid,
                })
                .await;
            assert!(
                result.is_err(),
                "{action}/{amount}: invalid amount refuses at the public argument boundary: {result:?}"
            );
            let error = result.unwrap_err();
            assert_eq!(error.code, rmcp::model::ErrorCode::INVALID_PARAMS);
            assert_eq!(
                error.message, message,
                "the public amount parser preserves its boundary message"
            );
        }
    }
    for amount in [0, -1] {
        let mut invalid = valid_commit.clone();
        let mut envelope = TransactionEnvelope::from_xdr_base64(
            invalid["envelope_xdr"].as_str().unwrap(),
            Limits::none(),
        )
        .unwrap();
        let TransactionEnvelope::Tx(v1) = &mut envelope else {
            panic!("classic v1 envelope");
        };
        let mut operations = v1.tx.operations.to_vec();
        let OperationBody::Payment(payment) = &mut operations[0].body else {
            panic!("payment");
        };
        payment.amount = amount;
        v1.tx.operations = operations.try_into().unwrap();
        invalid["envelope_xdr"] = envelope.to_xdr_base64(Limits::none()).unwrap().into();
        let result = run
            .f
            .server
            .call_stellar_toolset_invoke(StellarToolsetInvokeArgs {
                toolset: TOOLSET.into(),
                action: "stellar_pay_commit".into(),
                chain_id: Some("stellar:mainnet".into()),
                args: invalid,
            })
            .await;
        assert!(
            result.is_err(),
            "a nonpositive authoritative amount refuses before first-invoke consent: {result:?}"
        );
        let error = result.unwrap_err();
        assert_eq!(error.code, rmcp::model::ErrorCode::INTERNAL_ERROR);
        assert_eq!(
            error.message,
            "toolset.enforcement_error: toolset.invalid_authoritative_amount: authoritative_amount_stroops must be > 0"
        );
    }
    assert!(run.pending().is_empty());
    assert!(!run.grants.exists());
    assert_eq!(run.f.nonce_reads.load(Ordering::SeqCst), reads);
    assert!(authorizations(&run.f).is_empty());
    assert_eq!(run.f.seed_reads.load(Ordering::SeqCst), 0);
    assert!(run.control.sent().is_empty());
    run.grant(DESTINATIONS[0].0);
    let result = run.invoke("stellar_pay_commit", valid_commit).await;
    assert_eq!(
        result["ok"], true,
        "the original valid payment remains usable: {result}"
    );
    assert_eq!(run.control.sent().len(), 1);
    assert_eq!(recorded_amount(&run, "native"), (10, 1));
}

#[tokio::test]
#[serial_test::serial(keyring, mainnet_clock)]
#[serial_test::serial]
async fn public_grant_schema_and_legacy_lifecycle_preserve_other_payments() {
    use stellar_agent_core::approval::ToolsetGrantStore;
    for case in [
        "unknown",
        "duplicate",
        "missing required",
        "legacy",
        "bad destination",
        "bad attestation",
        "expired",
    ] {
        let run = Run::new("allow", "allow", &["propose-transaction", "sign-payment"]).await;
        let mut args = Tool::Pay.prepare_args(&run.f);
        args["memo_text"] = case.into();
        let prepared = run.invoke("stellar_pay", args.clone()).await;
        assert_eq!(prepared["ok"], true, "{case}: {prepared}");
        let grant = run.grant(run.f.envelope.destination());
        let original = std::fs::read_to_string(&run.grants).unwrap();
        let mut file: toml_edit::DocumentMut = original.parse().unwrap();
        let row = file["grants"][0].as_table_mut().unwrap();
        match case {
            "unknown" => {
                row["future_field"] = toml_edit::value("kept readable");
            }
            "duplicate" => {}
            "missing required" => {
                row.remove("grant_id");
            }
            "legacy" => {
                for field in [
                    "install_id",
                    "package_version",
                    "package_shasum",
                    "attestation_version",
                ] {
                    row.remove(field);
                }
            }
            "bad destination" => {
                row["destination"] = toml_edit::value("not\n\\a\"payment-雪");
            }
            "bad attestation" => {
                row["attestation_blob_b64"] = toml_edit::value("invalid");
            }
            "expired" => {
                row["granted_at_unix_ms"] = toml_edit::value(0);
                row["expires_at_unix_ms"] = toml_edit::value(1);
            }
            _ => unreachable!(),
        }
        let bytes = if case == "duplicate" {
            format!("{original}\n{original}")
        } else {
            file.to_string()
        };
        std::fs::write(&run.grants, &bytes).unwrap();
        let nonce_reads = run.f.nonce_reads.load(Ordering::SeqCst);
        let outcome = run
            .f
            .server
            .call_stellar_toolset_invoke(StellarToolsetInvokeArgs {
                toolset: TOOLSET.into(),
                action: "stellar_pay_commit".into(),
                chain_id: Some("stellar:mainnet".into()),
                args: run.commit_args(args.clone(), &prepared),
            })
            .await;
        if matches!(case, "unknown" | "duplicate") {
            assert!(
                outcome.is_ok(),
                "compatible grant schema reaches the payment handler: {case}: {outcome:?}"
            );
            let result = wire(&outcome.unwrap());
            assert_eq!(
                result["ok"], true,
                "compatible grant schema: {case}: {result}"
            );
            assert_eq!(run.control.sent().len(), 1);
            let mut store =
                ToolsetGrantStore::open(run.grants.clone(), now_unix_ms().unwrap()).unwrap();
            let count = if case == "duplicate" { 2 } else { 1 };
            assert_eq!(
                store.len(),
                count,
                "all stored grant records remain addressable"
            );
            assert_eq!(
                store.revoke_toolset(TOOLSET).unwrap(),
                count,
                "revocation removes every matching record"
            );
            assert!(store.is_empty());
        } else {
            let error = outcome.expect_err("an unusable grant cannot authorize payment");
            assert!(
                error.message.starts_with(if case == "missing required" {
                    "toolset.enforcement_error: toolset.grant_store_error:"
                } else {
                    "toolset.first_invoke_approval_required:"
                }),
                "{case}: {}",
                error.message
            );
            assert_eq!(run.f.nonce_reads.load(Ordering::SeqCst), nonce_reads);
            assert!(run.control.sent().is_empty());
            assert!(authorizations(&run.f).is_empty());
            assert_eq!(run.f.seed_reads.load(Ordering::SeqCst), 0);
            assert_eq!(std::fs::read_to_string(&run.grants).unwrap(), bytes);
            if case == "missing required" {
                assert!(matches!(
                    ToolsetGrantStore::open(run.grants.clone(), now_unix_ms().unwrap()),
                    Err(stellar_agent_core::approval::ApprovalError::Toml { .. })
                ));
            } else {
                let mut store =
                    ToolsetGrantStore::open(run.grants.clone(), now_unix_ms().unwrap()).unwrap();
                let count = usize::from(case != "expired");
                assert_eq!(
                    store.len(),
                    count,
                    "invalid-use records remain readable; expiry is collected"
                );
                assert_eq!(store.revoke_toolset(TOOLSET).unwrap(), count);
                // Insertion persists the expiry collection without rewriting any grant term.
                store.insert(grant.clone()).unwrap();
            }
            if case != "missing required" {
                let result = run
                    .invoke(
                        "stellar_pay_commit",
                        run.commit_args(args.clone(), &prepared),
                    )
                    .await;
                assert_eq!(
                    result["ok"], true,
                    "fresh authenticated consent permits the original nonce: {case}: {result}"
                );
                assert_eq!(run.control.sent().len(), 1);
            }
        }
        run.source_sequence(2);
        args["memo_text"] = format!("independent-{case}").into();
        args["business_id"] = uuid::Uuid::new_v4().to_string().into();
        let next = run.prepare_route(&args, false).await;
        assert_eq!(next["ok"], true, "{case}: {next}");
        let sent = run.commit_route(run.commit_args(args, &next), false).await;
        assert_eq!(
            sent["ok"], true,
            "independent direct payment after grant disturbance: {case}: {sent}"
        );
        let effects = if case == "missing required" { 1 } else { 2 };
        assert_eq!(run.control.sent().len(), effects);
        assert_eq!(authorizations(&run.f).len(), effects);
        if case == "missing required" {
            assert_eq!(
                std::fs::read_to_string(&run.grants).unwrap(),
                bytes,
                "unverifiable grant state stays untouched"
            );
        }
    }
}

#[tokio::test]
#[serial_test::serial(keyring, mainnet_clock)]
#[serial_test::serial]
async fn public_composed_total_epoch_survives_aging_reset_and_restart() {
    use stellar_agent_core::policy::v1::criteria::state_store::{
        PolicyStateStore, StateKey, WindowEntry, WindowLimit,
    };
    use stellar_agent_network::policy_state::{OwnerResetSignature, ResetConsent};
    for first_toolset in [false, true] {
        let mut run = Run::with_policy("allow", "allow", &["propose-transaction", "sign-payment"], |raw| {
            let mut doc = raw.parse::<toml_edit::DocumentMut>().unwrap();
            doc["version"] = toml_edit::value(2);
            for rule in doc["rules"].as_array_of_tables_mut().unwrap().iter_mut() {
                let tool = rule["match"]["tool"].as_str().unwrap();
                if matches!(tool, "stellar_pay" | "stellar_pay_commit" | "stellar_toolset_invoke") {
                    let limit = if tool == "stellar_toolset_invoke" { 100 } else { 200 };
                    rule["criteria"].as_array_mut().unwrap().push(
                        format!("{{ kind = \"total_budget\", asset = \"native\", max_stroops = {limit} }}")
                            .parse::<toml_edit::Value>().unwrap()
                    );
                }
            }
            doc.to_string()
        }).await;
        let now = now_unix_ms().unwrap();
        let digest = run.f.server.verified_policy.as_ref().unwrap().digest();
        let key = StateKey::new("operator", 1, "total:native", 0);
        let old = WindowEntry::new(
            key.clone(),
            now - 100 * 86_400_000,
            40,
            WindowLimit::Total {
                asset: "native".into(),
                max_stroops: 200,
            },
        )
        .with_epoch(Some(digest));
        let window = run.f.server.window_store.clone();
        let profile = run.f.server.security_profile().clone();
        window.record_authorized(&profile, &[old]).unwrap();
        window
            .reset(
                &profile,
                "operator",
                now,
                "reset rolling history",
                "public-total-reset",
                |row| {
                    let owner = ed25519_dalek::SigningKey::from_bytes(&[11; 32]);
                    Ok::<_, ()>(ResetConsent {
                        owner_signature: Some(OwnerResetSignature {
                            owner: owner.verifying_key().to_bytes(),
                            signature: stellar_agent_core::policy::v1::signature::sign(
                                &row.statement_digest(),
                                &owner,
                            ),
                        }),
                    })
                },
                |_, _| Ok(()),
            )
            .unwrap();
        let totals = || {
            let state = PolicyStateStore::new();
            window
                .load_into_at("operator", &profile, &state, now_unix_ms().unwrap())
                .unwrap();
            state.query_epoch(&key, digest).unwrap()
        };
        assert_eq!(totals(), (40, 1), "old total spend survives reset and age");
        run.grant(DESTINATIONS[0].0);
        for (index, amount) in [50, 11, 10].into_iter().enumerate() {
            run.source_sequence(if index == 0 { 1 } else { 2 });
            let mut args = Tool::Pay.prepare_args(&run.f);
            args["amount_in_stroops"] = amount.to_string().into();
            args["memo_id"] = (index as u64).into();
            let route = if index == 0 { first_toolset } else { true };
            let prepared = run.prepare_route(&args, route).await;
            if amount == 11 {
                assert_eq!(
                    prepared["error"]["code"], "policy.deny.total_budget_exhausted",
                    "{prepared}"
                );
                assert_eq!(totals(), (90, 2));
                assert_eq!(run.control.sent().len(), 1);
                continue;
            }
            assert_eq!(prepared["ok"], true, "{prepared}");
            let result = run
                .commit_route(run.commit_args(args, &prepared), route)
                .await;
            assert_eq!(result["ok"], true, "{result}");
            assert_eq!(
                totals(),
                if index == 0 { (90, 2) } else { (100, 3) },
                "one debit in the original policy epoch"
            );
            run.restart();
            assert_eq!(
                run.f.server.verified_policy.as_ref().unwrap().digest(),
                digest
            );
        }
        assert_eq!(run.control.sent().len(), 2);
        assert_eq!(authorizations(&run.f).len(), 2);
        assert!(run.pending().is_empty());
    }
}

#[tokio::test]
#[serial_test::serial(keyring, mainnet_clock)]
#[serial_test::serial]
async fn public_operation_capacity_expires_waiting_without_releasing_uncertainty() {
    use stellar_agent_network::policy_state::{BusinessId, OperationStatus};
    let mut run = Run::new("allow", "allow", &["propose-transaction", "sign-payment"]).await;
    run.grant(DESTINATIONS[0].0);
    let original = Tool::Pay.prepare_args(&run.f);
    let prepared = run.invoke("stellar_pay", original.clone()).await;
    assert_eq!(prepared["ok"], true);
    let sent = run
        .invoke(
            "stellar_pay_commit",
            run.commit_args(original.clone(), &prepared),
        )
        .await;
    assert_eq!(sent["ok"], true, "{sent}");
    let profile = run.f.server.security_profile().clone();
    let window = run.f.server.window_store.clone();
    let status = OperationStatus::new(&window, &profile);
    let original_id = BusinessId::parse(original["business_id"].as_str().unwrap()).unwrap();
    let protected = status.view(&original_id).unwrap().unwrap();
    assert_eq!(protected.state.wire_name(), "sent_outcome_unknown");
    run.source_sequence(2);
    let mut waiting_end = 0;
    for index in 0..16 {
        let mut args = Tool::Pay.prepare_args(&run.f);
        args["memo_id"] = (index + 1).into();
        let next = run.prepare_route(&args, index % 2 == 0).await;
        assert_eq!(next["ok"], true, "waiting slot {index}: {next}");
        let view = status
            .view(&BusinessId::parse(args["business_id"].as_str().unwrap()).unwrap())
            .unwrap()
            .unwrap();
        waiting_end = waiting_end.max(view.waiting_expires_at_ms.unwrap());
    }
    let mut independent = Tool::Pay.prepare_args(&run.f);
    independent["memo_text"] = "after-capacity".into();
    let refused = run.invoke("stellar_pay", independent.clone()).await;
    assert_eq!(refused["error"]["code"], "operation.capacity", "{refused}");
    assert_eq!(run.control.sent().len(), 1);
    assert_eq!(recorded_amount(&run, "native"), (10, 1));
    assert_eq!(status.view(&original_id).unwrap().unwrap(), protected);
    let later = waiting_end + 1;
    let _clock = stellar_agent_network::mainnet::clock::set_now_ms_for_test(later);
    let _policy =
        stellar_agent_core::policy::v1::criteria::state_store::set_query_time_for_test(later);
    run.f.server.clock = Arc::new(stellar_agent_core::timefmt::MockClock::new(move || {
        Ok(later)
    }));
    run.source_sequence(2);
    let next = run.invoke("stellar_pay", independent.clone()).await;
    assert_eq!(
        next["ok"], true,
        "expired waiting entries free capacity: {next}"
    );
    assert_eq!(
        status.view(&original_id).unwrap().unwrap(),
        protected,
        "uncertain exposure remains protected"
    );
    assert_eq!(recorded_amount(&run, "native"), (10, 1));
    let result = run
        .invoke("stellar_pay_commit", run.commit_args(independent, &next))
        .await;
    assert_eq!(
        result["ok"], true,
        "independent payment proceeds after capacity recovery: {result}"
    );
    assert_eq!(run.control.sent().len(), 2);
    assert_eq!(authorizations(&run.f).len(), 2);
    assert_eq!(recorded_amount(&run, "native"), (20, 2));
}

#[tokio::test]
#[serial_test::serial(keyring, mainnet_clock)]
#[serial_test::serial]
async fn public_grant_replacement_after_proof_requires_fresh_resolution() {
    use stellar_agent_core::approval::ToolsetGrantStore;
    for replace in [false, true] {
        let mut run = Run::new(
            "require_approval",
            "allow",
            &["propose-transaction", "sign-payment"],
        )
        .await;
        let original = run.grant(DESTINATIONS[0].0);
        let args = Tool::Pay.prepare_args(&run.f);
        let prepared = run.invoke("stellar_pay", args.clone()).await;
        assert_eq!(prepared["ok"], true, "{prepared}");
        let entry = run.pending().pop().unwrap();
        let mut commit = run.commit_args(args, &prepared);
        commit["approval_nonce"] = entry.approval_nonce.clone().into();
        commit["approval_attestation"] = run.f.attest(&entry).into();
        let reads = run.f.nonce_reads.load(Ordering::SeqCst);
        let barrier = Arc::new(tokio::sync::Barrier::new(2));
        let arrivals = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        run.f.server.payment_proof_barrier = Some((barrier.clone(), arrivals.clone()));
        let writer = async {
            while arrivals.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
            assert_eq!(
                ToolsetGrantStore::open(run.grants.clone(), now_unix_ms().unwrap())
                    .unwrap()
                    .revoke_toolset(TOOLSET)
                    .unwrap(),
                1
            );
            if replace {
                let replacement = run.grant(DESTINATIONS[0].0);
                assert_ne!(
                    replacement.grant_id, original.grant_id,
                    "equal coverage does not preserve the resolved grant identity"
                );
            }
            barrier.wait().await;
        };
        let (result, ()) = tokio::join!(run.invoke("stellar_pay_commit", commit.clone()), writer);
        assert_eq!(
            result["error"]["code"], "toolset.grant_changed",
            "the public commit refuses a grant removed after proof verification: {result}"
        );
        assert_eq!(
            run.f.nonce_reads.load(Ordering::SeqCst),
            reads,
            "late grant invalidation precedes protocol nonce access"
        );
        assert!(authorizations(&run.f).is_empty());
        assert!(run.control.sent().is_empty());
        run.f.server.payment_proof_barrier = None;
        if !replace {
            run.grant(DESTINATIONS[0].0);
        }
        let result = run.invoke("stellar_pay_commit", commit).await;
        assert_eq!(
            result["ok"], true,
            "fresh resolution retains the original payment consent and nonce: {result}"
        );
        assert_eq!(authorizations(&run.f).len(), 1);
        assert_eq!(run.control.sent().len(), 1);
        assert_eq!(recorded_amount(&run, "native"), (10, 1));
    }
}

#[tokio::test]
#[serial_test::serial(keyring, mainnet_clock)]
#[serial_test::serial]
async fn public_toolset_memo_policy_applies_to_every_destination_and_asset() {
    for issued in [false, true] {
        for (destination, _, _) in DESTINATIONS {
            let issuer = stellar_agent_test_support::signed_envelope::account_id_for_seed([7; 32]);
            let asset = if issued {
                format!("USD:{issuer}")
            } else {
                "native".to_owned()
            };
            let run = Run::with_policy("allow", "allow", &["propose-transaction", "sign-payment"], |raw| {
                let mut doc = if issued { raw.replace("\"native\"", &format!("\"{asset}\"")) } else { raw }
                    .parse::<toml_edit::DocumentMut>().unwrap();
                if issued { doc["mainnet"]["cross_check_thresholds"][&asset] = toml_edit::value("100"); }
                let binding = format!("{{ kind = \"memo_binding\", bindings = [{{ destination = \"{}\", kind = \"id\", value = \"7\" }}] }}", DESTINATIONS[0].0)
                    .parse::<toml_edit::Value>().unwrap();
                for rule in doc["rules"].as_array_of_tables_mut().unwrap().iter_mut() {
                    if rule["match"]["tool"].as_str() == Some("stellar_toolset_invoke") {
                        rule["criteria"].as_array_mut().unwrap().push(binding.clone());
                    }
                }
                doc.to_string()
            }).await;
            if issued {
                run.issued_entries();
            }
            run.grant_asset(DESTINATIONS[0].0, if issued { &asset } else { "XLM" });
            let mut args = Tool::Pay.prepare_args(&run.f);
            args["destination"] = destination.into();
            args["asset"] = asset.clone().into();
            for memo in [None, Some(8)] {
                args["business_id"] = uuid::Uuid::new_v4().to_string().into();
                args.as_object_mut().unwrap().remove("memo_id");
                if let Some(memo) = memo {
                    args["memo_id"] = memo.into();
                }
                let prepared = run.invoke("stellar_pay", args.clone()).await;
                assert_eq!(
                    prepared["error"]["code"], "policy.deny.memo_binding_mismatch",
                    "the outer preparation policy requires the exact memo, including M accounts: {prepared}"
                );
                let direct = wire(&Tool::Pay.prepare(&run.f.server, &args).await);
                assert_eq!(direct["ok"], true, "{direct}");
                let result = run
                    .invoke("stellar_pay_commit", run.commit_args(args.clone(), &direct))
                    .await;
                assert_eq!(
                    result["error"]["code"], "policy.deny.memo_binding_mismatch",
                    "the outer commit policy requires the exact authoritative memo: {result}"
                );
                assert!(run.pending().is_empty());
                assert!(authorizations(&run.f).is_empty());
                assert!(run.control.sent().is_empty());
            }
            args["business_id"] = uuid::Uuid::new_v4().to_string().into();
            args["memo_id"] = 7.into();
            let prepared = run.invoke("stellar_pay", args.clone()).await;
            assert_eq!(prepared["ok"], true, "{prepared}");
            let result = run
                .invoke("stellar_pay_commit", run.commit_args(args, &prepared))
                .await;
            assert_eq!(
                result["ok"], true,
                "the matching memo permits one independent payment: {result}"
            );
            assert_eq!(run.control.sent().len(), 1);
            assert_eq!(authorizations(&run.f).len(), 1);
        }
    }
}

#[tokio::test]
#[serial_test::serial(keyring, mainnet_clock)]
#[serial_test::serial]
async fn public_toolset_tombstone_replay_is_status_only() {
    use stellar_agent_network::policy_state::{BusinessId, OperationStatus};
    for first_toolset in [false, true] {
        let run = Run::new("allow", "allow", &["propose-transaction", "sign-payment"]).await;
        run.grant(DESTINATIONS[0].0);
        let mut args = Tool::Pay.prepare_args(&run.f);
        args["destination"] = DESTINATIONS[2].0.into();
        let prepared = run.prepare_route(&args, first_toolset).await;
        assert_eq!(prepared["ok"], true, "{prepared}");
        let commit = run.commit_args(args.clone(), &prepared);
        let key = &run.f.server.security_profile().mcp_signer_default;
        let seed = keyring_core::Entry::new(&key.service, &key.account).unwrap();
        let stored = seed.get_password().unwrap();
        seed.delete_credential().unwrap();
        let refused = run.commit_route(commit.clone(), first_toolset).await;
        seed.set_password(&stored).unwrap();
        assert_eq!(
            refused["error"]["code"], "auth.keyring_not_found",
            "{refused}"
        );
        let id = BusinessId::parse(args["business_id"].as_str().unwrap()).unwrap();
        let status =
            OperationStatus::new(&run.f.server.window_store, run.f.server.security_profile());
        assert_eq!(
            status.view(&id).unwrap().unwrap().state.wire_name(),
            "not_sent"
        );
        let clock = stellar_agent_network::mainnet::clock::set_now_ms_for_test(
            now_unix_ms().unwrap()
                + stellar_agent_network::policy_state::operations::TERMINAL_RETENTION_MS
                + 60_000,
        );
        assert!(status.view(&id).unwrap().unwrap().compacted);
        let before = std::fs::read(run.f.server.window_store.path()).unwrap();
        for route in [!first_toolset, first_toolset] {
            let result = run.commit_route(commit.clone(), route).await;
            assert_eq!(result["ok"], true, "{result}");
            assert_eq!(result["data"]["status"], "replayed", "{result}");
            assert_eq!(result["data"]["operation"]["state"], "not_sent", "{result}");
            assert_eq!(result["data"]["next"], "none", "{result}");
            assert!(
                result["data"].get("destination").is_none(),
                "a compacted payment replay exposes status without retained destination: {result}"
            );
            assert!(result["data"].get("envelope_xdr").is_none());
            assert!(run.control.sent().is_empty());
            assert_eq!(
                std::fs::read(run.f.server.window_store.path()).unwrap(),
                before
            );
        }
        drop(clock);
        let mut independent = Tool::Pay.prepare_args(&run.f);
        independent["memo_id"] = 7.into();
        let prepared = run.invoke("stellar_pay", independent.clone()).await;
        assert_eq!(prepared["ok"], true, "{prepared}");
        let result = run
            .invoke(
                "stellar_pay_commit",
                run.commit_args(independent, &prepared),
            )
            .await;
        assert_eq!(
            result["ok"], true,
            "an independent payment continues after a retained terminal refusal: {result}"
        );
        assert_eq!(run.control.sent().len(), 1);
    }
}

/// On a canonical record a toolset commit signs only an envelope of the
/// stored intent: an envelope this server prepared for another intent, under
/// another id, refuses the conflict with either commit arguments and sends
/// nothing.
#[tokio::test]
#[serial_test::serial(keyring, mainnet_clock)]
#[serial_test::serial]
async fn public_toolset_commit_of_another_intent_under_a_canonical_id_refuses() {
    use stellar_agent_network::policy_state::{BusinessId, OperationStatus, SlotKind};
    for other in ["memo", "amount", "fee"] {
        let run = Run::new("allow", "allow", &["propose-transaction", "sign-payment"]).await;
        run.grant(DESTINATIONS[0].0);
        let args = Tool::Pay.prepare_args(&run.f);
        let prepared = run.prepare_route(&args, false).await;
        assert_eq!(prepared["ok"], true, "{prepared}");
        let id = BusinessId::parse(args["business_id"].as_str().unwrap()).unwrap();
        let status =
            OperationStatus::new(&run.f.server.window_store, run.f.server.security_profile());
        let stored = status.view(&id).unwrap().unwrap();
        assert_eq!(stored.slot_kind, SlotKind::Canonical);
        let mut foreign = Tool::Pay.prepare_args(&run.f);
        match other {
            "memo" => foreign["memo_text"] = "another".into(),
            "amount" => foreign["amount_in_stroops"] = "11".into(),
            _ => foreign["fee"] = "200".into(),
        }
        let envelope = run.prepare_route(&foreign, true).await;
        assert_eq!(envelope["ok"], true, "{other}: {envelope}");
        let foreign_id = BusinessId::parse(foreign["business_id"].as_str().unwrap()).unwrap();
        let foreign_view = status.view(&foreign_id).unwrap().unwrap();
        let window = std::fs::read(run.f.server.window_store.path()).unwrap();
        let mut under_canonical = foreign.clone();
        under_canonical["business_id"] = args["business_id"].clone();
        for commit in [
            run.commit_args(under_canonical, &envelope),
            run.commit_args(args.clone(), &envelope),
        ] {
            let refused = run.commit_route(commit, true).await;
            assert_eq!(
                refused["error"]["code"], "operation.business_id_conflict",
                "{other}: {refused}"
            );
            assert!(run.control.sent().is_empty(), "{other}");
            assert!(authorizations(&run.f).is_empty(), "{other}");
            assert_eq!(status.view(&id).unwrap().unwrap(), stored, "{other}");
            assert_eq!(
                status.view(&foreign_id).unwrap().unwrap(),
                foreign_view,
                "{other}"
            );
            assert_eq!(
                std::fs::read(run.f.server.window_store.path()).unwrap(),
                window,
                "{other}: the refusal writes no record"
            );
        }
    }
}

/// One payment keeps one open attempt across both routes: after a commit on
/// either route sends and leaves its outcome unknown, a commit of the same id
/// on the other route sends nothing and keeps the one attempt.
#[tokio::test]
#[serial_test::serial(keyring, mainnet_clock)]
#[serial_test::serial]
async fn public_open_attempt_is_one_across_routes() {
    use stellar_agent_network::policy_state::{BusinessId, OperationStatus};
    for first_toolset in [false, true] {
        let run = Run::new("allow", "allow", &["propose-transaction", "sign-payment"]).await;
        run.grant(DESTINATIONS[0].0);
        let args = Tool::Pay.prepare_args(&run.f);
        let prepared = run.prepare_route(&args, first_toolset).await;
        assert_eq!(prepared["ok"], true, "{prepared}");
        let commit = run.commit_args(args.clone(), &prepared);
        let sent = run.commit_route(commit.clone(), first_toolset).await;
        assert_eq!(sent["ok"], true, "{sent}");
        let id = BusinessId::parse(args["business_id"].as_str().unwrap()).unwrap();
        let status =
            OperationStatus::new(&run.f.server.window_store, run.f.server.security_profile());
        let open = status.view(&id).unwrap().unwrap();
        assert_eq!(open.state.wire_name(), "sent_outcome_unknown");
        assert_eq!(open.attempts, 1);
        assert_eq!(run.control.sent().len(), 1);
        let again = run.commit_route(commit, !first_toolset).await;
        assert_ne!(
            again["data"]["status"], "submitted",
            "first_toolset={first_toolset}: {again}"
        );
        assert_eq!(
            run.control.sent().len(),
            1,
            "first_toolset={first_toolset}: {again}"
        );
        assert_eq!(authorizations(&run.f).len(), 1);
        let kept = status.view(&id).unwrap().unwrap();
        assert_eq!(kept.attempts, 1, "first_toolset={first_toolset}: {again}");
        assert_eq!(kept.state.wire_name(), "sent_outcome_unknown");
    }
}

/// Fills the inbox with live copies of its first entry up to the 4,096-entry
/// capacity, so the next entry write refuses, and returns the bytes before.
fn fill_inbox(run: &Run) -> (std::path::PathBuf, String) {
    let path = run
        .f
        .server
        .resolve_approval_dir()
        .unwrap()
        .join("operator.toml");
    let before = std::fs::read_to_string(&path).unwrap();
    let mut file: toml_edit::DocumentMut = before.parse().unwrap();
    let template = file["pending"][0].as_table().unwrap().clone();
    let entries = file["pending"].as_array_of_tables_mut().unwrap();
    while entries.len() < 4096 {
        let mut entry = template.clone();
        entry["approval_nonce"] = toml_edit::value(format!("capacity{:014}", entries.len()));
        entries.push(entry);
    }
    std::fs::write(&path, file.to_string()).unwrap();
    (path, before)
}

/// A first preparation whose record opens and whose inbox entry write then
/// refuses leaves the record without an entry, as a crash between the two
/// writes does. The retry on either route queues a new entry.
///
/// On a canonical record the entry spans the decision's whole lifetime and
/// ends with the record's waiting window, so the consent to the stored intent
/// admits the commit. On an envelope record the entry starts at the retry and
/// ends with the window.
#[tokio::test]
#[serial_test::serial(keyring, mainnet_clock)]
#[serial_test::serial]
async fn public_retry_after_a_lost_first_entry_completes() {
    use stellar_agent_network::policy_state::{
        ApprovalStatus, BusinessId, OperationStatus, SlotKind,
    };
    for (first_toolset, retry_toolset) in
        [(false, false), (false, true), (true, true), (true, false)]
    {
        let label = format!("first_toolset={first_toolset} retry_toolset={retry_toolset}");
        let run = Run::new(
            "allow",
            "require_approval",
            &["propose-transaction", "sign-payment"],
        )
        .await;
        run.grant(DESTINATIONS[0].0);
        let mut other = Tool::Pay.prepare_args(&run.f);
        other["amount_in_stroops"] = "9".into();
        let other = run.prepare_route(&other, false).await;
        assert_eq!(other["ok"], true, "{label}: {other}");
        let (path, before) = fill_inbox(&run);
        let args = Tool::Pay.prepare_args(&run.f);
        // An envelope record's window ends with its envelope's deadline, about
        // 120 seconds after a preparation 75 seconds earlier, inside the
        // retry's 60-second decision and past the commit's 30-second margin.
        let opened_at = now_unix_ms().unwrap() - if first_toolset { 75_000 } else { 0 };
        let network = stellar_agent_network::mainnet::clock::set_now_ms_for_test(opened_at);
        let policy = stellar_agent_core::policy::v1::criteria::state_store::set_query_time_for_test(
            opened_at,
        );
        let lost = if first_toolset {
            run.f
                .server
                .call_stellar_toolset_invoke(StellarToolsetInvokeArgs {
                    toolset: TOOLSET.into(),
                    action: "stellar_pay".into(),
                    chain_id: Some("stellar:mainnet".into()),
                    args: args.clone(),
                })
                .await
        } else {
            Tool::Pay.prepare_result(&run.f.server, &args).await
        };
        drop((network, policy));
        assert!(
            !lost
                .as_ref()
                .is_ok_and(|result| result.is_error != Some(true)),
            "{label}: the first entry write refuses"
        );
        let id = BusinessId::parse(args["business_id"].as_str().unwrap()).unwrap();
        let status =
            OperationStatus::new(&run.f.server.window_store, run.f.server.security_profile());
        let opened = status.view(&id).unwrap().unwrap();
        assert_eq!(
            opened.slot_kind,
            if first_toolset {
                SlotKind::Envelope
            } else {
                SlotKind::Canonical
            },
            "{label}"
        );
        let approvals =
            ApprovalStatus::new(&run.f.server.window_store, run.f.server.security_profile());
        assert!(
            approvals
                .find_by_operation(opened.operation_id)
                .unwrap()
                .is_none(),
            "{label}: no approval record opened"
        );
        std::fs::write(&path, before).unwrap();
        let retried = if retry_toolset {
            run.f
                .server
                .call_stellar_toolset_invoke(StellarToolsetInvokeArgs {
                    toolset: TOOLSET.into(),
                    action: "stellar_pay".into(),
                    chain_id: Some("stellar:mainnet".into()),
                    args: args.clone(),
                })
                .await
        } else {
            Tool::Pay.prepare_result(&run.f.server, &args).await
        }
        .map(|result| wire(&result))
        .map_err(|error| error.message.to_string());
        assert!(
            retried.as_ref().is_ok_and(|body| body["ok"] == true),
            "{label}: the retry queues a new entry: {retried:?}"
        );
        let prepared = retried.unwrap();
        let nonce = prepared["data"]["approval"]["approval_nonce"]
            .as_str()
            .unwrap()
            .to_owned();
        let entry = run
            .pending()
            .into_iter()
            .find(|entry| entry.approval_nonce == nonce)
            .unwrap();
        let (created, waiting_end) = (
            opened.created_at_ms.unwrap(),
            opened.waiting_expires_at_ms.unwrap(),
        );
        assert_eq!(entry.expires_at_unix_ms, waiting_end, "{label}");
        if first_toolset {
            assert!(
                entry.created_at_unix_ms > created
                    && entry.expires_at_unix_ms < entry.created_at_unix_ms + 60_000,
                "{label}: an envelope record's entry starts at its retry and ends with the window"
            );
        } else {
            assert_eq!(
                (entry.created_at_unix_ms, waiting_end - created),
                (created, 60_000),
                "{label}: a canonical record's entry spans the decision's lifetime"
            );
        }
        let mut commit = run.commit_args(args.clone(), &prepared);
        commit["approval_nonce"] = nonce.clone().into();
        commit["approval_attestation"] = run.f.attest(&entry).into();
        let sent = run.commit_route(commit, retry_toolset).await;
        assert_eq!(sent["ok"], true, "{label}: {sent}");
        assert_eq!(run.control.sent().len(), 1, "{label}");
        assert_eq!(
            approvals
                .find_by_operation(opened.operation_id)
                .unwrap()
                .unwrap()
                .record
                .nonce,
            nonce,
            "{label}"
        );
    }
}

/// The on-chain deadline, in Unix seconds, of the unsigned or signed
/// envelope `xdr`.
fn envelope_deadline(xdr: &str) -> u64 {
    use stellar_xdr::{Limits, Preconditions, ReadXdr as _, TransactionEnvelope};
    let TransactionEnvelope::Tx(envelope) =
        TransactionEnvelope::from_xdr_base64(xdr, Limits::none()).unwrap()
    else {
        panic!("a classic envelope")
    };
    let Preconditions::Time(bounds) = envelope.tx.cond else {
        panic!("a deadline")
    };
    bounds.max_time.0
}

/// A canonical payment prepared under an approval of a 60-second rule
/// stores a deadline strictly before that decision's end, the last whole
/// second before it, which every authority its commit resolves outlasts. The
/// toolset commit of that envelope under the consent signs it unchanged.
#[tokio::test]
#[serial_test::serial(keyring, mainnet_clock)]
#[serial_test::serial]
async fn public_canonical_preparation_stores_a_deadline_its_toolset_commit_signs() {
    let run = Run::new(
        "allow",
        "require_approval",
        &["propose-transaction", "sign-payment"],
    )
    .await;
    run.grant(DESTINATIONS[0].0);
    let args = Tool::Pay.prepare_args(&run.f);
    let prepared = run.prepare_route(&args, false).await;
    assert_eq!(prepared["ok"], true, "{prepared}");
    let entry = run.pending().pop().unwrap();
    let end_ms = entry.created_at_unix_ms + 60_000;
    assert_eq!(entry.expires_at_unix_ms, end_ms, "the decision's 60 s end");
    let deadline = envelope_deadline(prepared["data"]["envelope_xdr"].as_str().unwrap());
    assert_eq!(
        deadline,
        (end_ms - 1) / 1_000,
        "the stored deadline is the last whole second before the decision's end"
    );
    assert!(deadline * 1_000 < end_ms);
    let mut commit = run.commit_args(args, &prepared);
    commit["approval_nonce"] = entry.approval_nonce.clone().into();
    commit["approval_attestation"] = run.f.attest(&entry).into();
    let sent = run.commit_route(commit, true).await;
    assert_eq!(sent["ok"], true, "{sent}");
    let sent = run.control.sent();
    assert_eq!(sent.len(), 1);
    assert_eq!(
        envelope_deadline(&sent[0]),
        deadline,
        "the toolset commit signs the stored envelope"
    );
}

/// An authority a toolset commit resolves after the preparation, here the
/// outer consent of a 60-second rule queued at the commit, can end before
/// the deadline a direct preparation under `Allow` stored. The toolset
/// commit then refuses before signing with the resolver's code and sends
/// nothing, and the direct commit of the same record sends.
#[tokio::test]
#[serial_test::serial(keyring, mainnet_clock)]
#[serial_test::serial]
async fn public_toolset_commit_under_a_shorter_later_authority_refuses_and_direct_sends() {
    let run = Run::new(
        "require_approval",
        "allow",
        &["propose-transaction", "sign-payment"],
    )
    .await;
    run.grant(DESTINATIONS[0].0);
    let args = Tool::Pay.prepare_args(&run.f);
    let prepared = run.prepare_route(&args, false).await;
    assert_eq!(prepared["ok"], true, "{prepared}");
    let deadline = envelope_deadline(prepared["data"]["envelope_xdr"].as_str().unwrap());
    let proofless = run.commit_args(args.clone(), &prepared);
    let queued = run.commit_route(proofless.clone(), true).await;
    assert_eq!(
        queued["error"]["code"], "policy.approval_required",
        "{queued}"
    );
    let entry = run.pending().pop().unwrap();
    assert!(
        entry.expires_at_unix_ms <= deadline * 1_000,
        "the outer consent ends before the stored deadline"
    );
    let mut commit = proofless.clone();
    commit["approval_nonce"] = entry.approval_nonce.clone().into();
    commit["approval_attestation"] = run.f.attest(&entry).into();
    let refused = run.commit_route(commit, true).await;
    assert_eq!(
        refused["error"]["code"], "network.mainnet_authorization_refused",
        "{refused}"
    );
    assert!(run.control.sent().is_empty());
    let sent = run.commit_route(proofless, false).await;
    assert_eq!(sent["ok"], true, "{sent}");
    assert_eq!(run.control.sent().len(), 1);
}
