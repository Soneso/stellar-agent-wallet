//! Confirmed toolset payments with first-invoke grants and policy-driven consent.
//! The local fixture exercises the same assertions without live requests.

#![cfg(feature = "testnet-acceptance")]
#![allow(
    dead_code,
    reason = "shared fixture is compiled by multiple acceptance targets"
)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics and unwraps are acceptable in testnet acceptance tests"
)]

use base64::Engine as _;
use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use stellar_agent_core::{
    approval::{
        PendingApprovalStore, TOOLSET_GRANT_DEFAULT_TTL_MS, build_attested_grant,
        process_uid_for_attestation,
    },
    profile::schema::Profile,
    timefmt::now_unix_ms,
};
use stellar_agent_mcp::server::{StellarToolsetInvokeArgs, WalletServer};
use stellar_agent_test_support::keyring_mock;
use tempfile::TempDir;
use zeroize::Zeroizing;

use crate::common;

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

const TESTNET_RPC_URL: &str = "https://soroban-testnet.stellar.org";
const TESTNET_FRIENDBOT_URL: &str = "https://friendbot.stellar.org";
const TESTNET_CHAIN_ID: &str = "stellar:testnet";
const FEE_STROOPS: u32 = 100_000;

// 1 XLM = 10_000_000 stroops
const SELF_PAYMENT_STROOPS: i64 = 10_000_000;

const TOOLSET_NAME: &str = "gated-testnet-toolset";
const CAPABILITY: &str = "sign-payment";
const ASSET_XLM: &str = "XLM";

// Syntactically valid 48-byte base64 nonce (HMAC will fail, which is expected
// before attestation is verified).
const FAKE_VALID_NONCE: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn fresh_keypair() -> (String, Zeroizing<[u8; 32]>) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let g_strkey: String = stellar_strkey::ed25519::PublicKey(verifying_key.to_bytes())
        .to_string()
        .as_str()
        .to_owned();
    let seed = Zeroizing::new(signing_key.to_bytes());
    (g_strkey, seed)
}

async fn fund_via_friendbot(g_strkey: &str) {
    let url = format!("{TESTNET_FRIENDBOT_URL}?addr={g_strkey}");
    stellar_agent_test_support::testnet_helpers::friendbot_fund(&url)
        .await
        .expect("Friendbot funds the account");
}

fn build_test_server(
    g_strkey: &str,
    seed: &Zeroizing<[u8; 32]>,
    attestation_key: &[u8; 32],
    approval_dir: &std::path::Path,
    grant_store_path: &std::path::Path,
    toolsets_root: &std::path::Path,
    rpc_url: &str,
) -> (WalletServer, Profile) {
    keyring_mock::install().expect("mock keyring store init");

    let mut profile =
        Profile::builder_testnet("stellar-agent", g_strkey, "stellar-agent-nonce", g_strkey)
            .with_noop_engine()
            .build();
    profile.rpc_url = rpc_url.to_owned();
    profile.audit_log_path = approval_dir.join("audit.jsonl");
    keyring_core::Entry::new(
        &profile.audit_log_hash_chain_key_id.service,
        &profile.audit_log_hash_chain_key_id.account,
    )
    .unwrap()
    .set_password(&base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x33; 32]))
    .unwrap();

    // Store signing key in mock keyring.
    let signer_ref = &profile.mcp_signer_default;
    let entry =
        keyring_core::Entry::new(&signer_ref.service, &signer_ref.account).expect("keyring entry");
    let s_strkey = stellar_strkey::ed25519::PrivateKey::from_payload(seed.as_ref())
        .expect("32-byte seed must encode as S-strkey")
        .as_unredacted()
        .to_string();
    entry.set_password(&s_strkey).expect("set signing key");
    // The identity record an enrollment stores beside the seed.
    stellar_agent_network::keyring::write_keyring_string(
        &stellar_agent_core::profile::schema::signer_identity_entry_ref(signer_ref),
        &stellar_agent_core::profile::signer_identity::SignerIdentityRecord::agent(
            ed25519_dalek::SigningKey::from_bytes(seed)
                .verifying_key()
                .to_bytes(),
            stellar_agent_core::profile::name::profile_name_for_approval(&profile),
            profile.chain_id,
        )
        .render()
        .expect("an agent record renders"),
    )
    .expect("set identity record");

    // Store nonce key in mock keyring.
    let nonce_ref = &profile.mcp_nonce_key_alias;
    let nonce_entry = keyring_core::Entry::new(&nonce_ref.service, &nonce_ref.account)
        .expect("nonce keyring entry");
    let nonce_key_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x42u8; 32]);
    nonce_entry
        .set_password(&nonce_key_b64)
        .expect("set nonce key");

    // Store attestation key in mock keyring.
    let attest_ref = &profile.attestation_key_id;
    let attest_entry = keyring_core::Entry::new(&attest_ref.service, &attest_ref.account)
        .expect("attestation keyring entry");
    let attest_key_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(attestation_key);
    attest_entry
        .set_password(&attest_key_b64)
        .expect("set attestation key");

    let mut server = WalletServer::new(profile.clone()).expect("WalletServer::new");
    server.set_approval_dir_for_test(approval_dir.to_path_buf());
    server.set_grant_store_path_for_test(grant_store_path.to_path_buf());
    server.set_toolsets_root_for_test(toolsets_root.to_path_buf());
    server.set_toolset_pin_key_for_test(toolset_pin_key());
    (server, profile)
}

/// The pin key the suite tags its install record under and hands the server.
fn toolset_pin_key() -> stellar_agent_toolsets_runtime::PinKey {
    stellar_agent_toolsets_runtime::PinKey::from_bytes(Zeroizing::new([0x5a; 32]))
}

/// Writes `toolset_name` declaring `sign-payment` as an install leaves it,
/// with its record tagged under [`toolset_pin_key`].
fn write_toolset_pin(toolsets_root: &std::path::Path, toolset_name: &str) {
    stellar_agent_toolsets_install::write_toolset_for_test(
        toolsets_root,
        toolset_name,
        &["sign-payment", "propose-transaction"],
        &[],
        "2026-06-02T00:00:00Z",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        &toolset_pin_key(),
    )
    .expect("write toolset");
}

/// Builds a minimal payment XDR envelope for testing (no live RPC needed).
fn build_payment_xdr(source: &str, dest: &str, amount_stroops: i64) -> String {
    use stellar_xdr::{
        Asset, Limits, Memo, MuxedAccount, Operation, OperationBody, PaymentOp, Preconditions,
        SequenceNumber, Transaction, TransactionEnvelope, TransactionExt, TransactionV1Envelope,
        Uint256, VecM, WriteXdr,
    };
    fn g_bytes(g: &str) -> [u8; 32] {
        stellar_strkey::ed25519::PublicKey::from_string(g)
            .expect("valid G-strkey")
            .0
    }
    let tx = Transaction {
        source_account: MuxedAccount::Ed25519(Uint256(g_bytes(source))),
        fee: FEE_STROOPS,
        seq_num: SequenceNumber(101),
        cond: Preconditions::None,
        memo: Memo::None,
        operations: vec![Operation {
            source_account: None,
            body: OperationBody::Payment(PaymentOp {
                destination: MuxedAccount::Ed25519(Uint256(g_bytes(dest))),
                asset: Asset::Native,
                amount: amount_stroops,
            }),
        }]
        .try_into()
        .expect("single-op vec"),
        ext: TransactionExt::V0,
    };
    TransactionEnvelope::Tx(TransactionV1Envelope {
        tx,
        signatures: VecM::default(),
    })
    .to_xdr_base64(Limits::none())
    .expect("XDR encode")
}

// ─────────────────────────────────────────────────────────────────────────────
// First-invoke grant and policy-controlled payment consent
// ─────────────────────────────────────────────────────────────────────────────

/// Chooses the public commit adapter for each payment.
#[derive(Clone, Copy)]
pub enum Route {
    Toolset,
    Direct,
    Alternating,
}

async fn commit(
    server: &WalletServer,
    args: serde_json::Value,
    toolset: bool,
) -> rmcp::model::CallToolResult {
    if toolset {
        server
            .call_stellar_toolset_invoke(StellarToolsetInvokeArgs {
                toolset: TOOLSET_NAME.to_owned(),
                action: "stellar_pay_commit".to_owned(),
                chain_id: Some(TESTNET_CHAIN_ID.to_owned()),
                args,
            })
            .await
            .unwrap()
    } else {
        server
            .call_stellar_pay_commit(serde_json::from_value(args).unwrap())
            .await
            .unwrap()
    }
}

/// Executes all six destination/asset cases under both policy decisions.
/// The caller holds the process-global keyring and state-directory serial lock.
///
/// # Panics
/// Panics when setup, a payment assertion or evidence persistence fails.
pub async fn run(route: Route, evidence_test: &str, local: bool) {
    let storage_sandbox =
        stellar_agent_test_support::sandbox::StateSandbox::new().expect("storage sandbox");
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let (g_strkey, seed) = fresh_keypair();
    let (issuer, issuer_seed) = fresh_keypair();
    let mock = if local {
        use wiremock::Respond as _;
        let mock = wiremock::MockServer::start().await;
        let sequence = std::sync::Arc::new(std::sync::atomic::AtomicI64::new(100));
        let account = g_strkey.clone();
        let issuer = issuer.clone();
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .respond_with(move |request: &wiremock::Request| {
                let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
                let seq = sequence.load(std::sync::atomic::Ordering::SeqCst);
                if body["method"] == "getTransaction" {
                    sequence.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
                common::TimeoutRpc::new(vec![
                    (
                        stellar_agent_test_support::xdr_fixtures::account_ledger_key_xdr(&account),
                        stellar_agent_test_support::xdr_fixtures::account_entry_xdr_with_seq(
                            &account,
                            100_000_000_000,
                            0,
                            seq,
                        ),
                    ),
                    (
                        stellar_agent_test_support::xdr_fixtures::account_ledger_key_xdr(&issuer),
                        stellar_agent_test_support::xdr_fixtures::account_entry_xdr_with_seq(
                            &issuer,
                            100_000_000_000,
                            0,
                            seq,
                        ),
                    ),
                    (
                        stellar_agent_test_support::xdr_fixtures::trustline_ledger_key_xdr(
                            &account, "USD", &issuer,
                        ),
                        stellar_agent_test_support::xdr_fixtures::trustline_entry_xdr(
                            &account,
                            "USD",
                            &issuer,
                            1_000_000_000,
                        ),
                    ),
                ])
                .confirming_in(1001)
                .respond(request)
            })
            .mount(&mock)
            .await;
        Some(mock)
    } else {
        fund_via_friendbot(&g_strkey).await;
        fund_via_friendbot(&issuer).await;
        None
    };
    let rpc_url = mock
        .as_ref()
        .map_or_else(|| TESTNET_RPC_URL.to_owned(), wiremock::MockServer::uri);

    let client = stellar_agent_network::StellarRpcClient::new(&rpc_url).unwrap();
    for account in [&g_strkey, &issuer] {
        let mut visible = false;
        for _ in 0..60 {
            if stellar_agent_network::fetch_account(&client, account, &[])
                .await
                .is_ok()
            {
                visible = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
        assert!(visible, "the funded account must become RPC-queryable");
    }
    let issuer_account = stellar_agent_network::fetch_account(&client, &issuer, &[])
        .await
        .unwrap();
    let (issued_asset, setup) =
        stellar_agent_test_support::signed_envelope::funded_issued_payment_envelope(
            *seed,
            *issuer_seed,
            issuer_account.sequence_number.checked_add(1).unwrap(),
        );
    stellar_agent_network::submit_transaction_and_wait(
        &client,
        &setup,
        std::time::Duration::from_secs(120),
        stellar_agent_test_support::signed_envelope::TESTNET_PASSPHRASE,
        None,
        None,
    )
    .await
    .unwrap();

    let attestation_key = [0x42u8; 32];

    let approval_dir = TempDir::new().unwrap();
    let grant_file = approval_dir.path().join("grants.toml");
    let toolsets_dir = TempDir::new().unwrap();

    write_toolset_pin(toolsets_dir.path(), TOOLSET_NAME);

    let (mut server, profile) = build_test_server(
        &g_strkey,
        &seed,
        &attestation_key,
        approval_dir.path(),
        &grant_file,
        toolsets_dir.path(),
        &rpc_url,
    );

    // Use the funded account as source AND destination (self-payment).
    let envelope_xdr = build_payment_xdr(&g_strkey, &g_strkey, SELF_PAYMENT_STROOPS);
    let profile_name = server.profile_name_for_approval();

    // ── First invoke (no grant) → gate fires ──────────────────────────────
    let args = StellarToolsetInvokeArgs {
        toolset: TOOLSET_NAME.to_owned(),
        action: "stellar_pay_commit".to_owned(),
        chain_id: Some(TESTNET_CHAIN_ID.to_owned()),
        args: serde_json::json!({
            "envelope_xdr": &envelope_xdr,
            "source": &g_strkey,
            "destination": &g_strkey,
            "nonce": FAKE_VALID_NONCE,
            "expires_at_unix_ms": 9_999_999_999_u64,
            "asset": "native",
            "amount": "1 XLM",
            "chain_id": TESTNET_CHAIN_ID
        }),
    };

    let result1 = server.call_stellar_toolset_invoke(args).await;
    assert!(result1.is_err(), "first invoke must fail with gate error");
    let err1 = result1.unwrap_err();
    assert!(
        err1.message.contains("first_invoke_approval_required"),
        "expected first_invoke_approval_required on testnet; got: {}",
        err1.message
    );

    // Extract the approval nonce from the payload.
    let payload = err1
        .data
        .as_ref()
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();
    let gate_nonce = payload
        .get("approval_nonce")
        .and_then(|v| v.as_str())
        .expect("approval_nonce must be present in first-invoke gate error payload");

    // ── Simulate approve: build grant, persist to grant store ─────────────
    // (mirrors the operator running `stellar-agent approve --id <nonce> --profile <name>`.)
    let process_uid = process_uid_for_attestation().expect("process uid");
    let now_ms = now_unix_ms().expect("now_unix_ms");
    let grant = build_attested_grant(
        TOOLSET_NAME.to_owned(),
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
        "1.0.0".to_owned(),
        "0000000000000000000000000000000000000000000000000000000000000000".to_owned(),
        CAPABILITY.to_owned(),
        g_strkey.clone(),
        ASSET_XLM.to_owned(),
        0_i64,
        SELF_PAYMENT_STROOPS,
        process_uid.clone(),
        now_ms,
        TOOLSET_GRANT_DEFAULT_TTL_MS,
        &attestation_key,
        &stellar_agent_core::approval::AttestationBinding::new(&profile_name, TESTNET_CHAIN_ID),
    )
    .expect("build_attested_grant");

    {
        let mut grant_store =
            stellar_agent_core::approval::ToolsetGrantStore::open(grant_file.clone(), now_ms)
                .expect("open grant store");
        grant_store.insert(grant).expect("insert grant");
    }

    // Mirror the real CLI approve step: after persisting the grant, consume the
    // first-invoke gate pending approval queued by the first invoke. The CLI
    // approve path removes the entry via `store.remove(&entry.approval_nonce)`
    // after recording the first-invoke grant; simulating approval by writing the
    // grant directly would otherwise leave the `ToolsetFirstInvokeGate` entry
    // behind, so the store-count assertion below would observe two entries.
    {
        let store_path = approval_dir.path().join(format!("{profile_name}.toml"));
        let mut approval_store =
            PendingApprovalStore::open(store_path).expect("open approval store for gate consume");
        let removed = approval_store
            .remove(gate_nonce)
            .expect("remove first-invoke gate pending entry");
        assert!(
            removed,
            "first-invoke gate pending approval must exist to be consumed"
        );
    }

    let issued_grant = build_attested_grant(
        TOOLSET_NAME.to_owned(),
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
        "1.0.0".to_owned(),
        "0".repeat(64),
        CAPABILITY.to_owned(),
        g_strkey.clone(),
        issued_asset.clone(),
        1,
        SELF_PAYMENT_STROOPS,
        process_uid_for_attestation().unwrap(),
        now_ms,
        TOOLSET_GRANT_DEFAULT_TTL_MS,
        &attestation_key,
        &stellar_agent_core::approval::AttestationBinding::new(&profile_name, TESTNET_CHAIN_ID),
    )
    .unwrap();
    stellar_agent_core::approval::ToolsetGrantStore::open(grant_file.clone(), now_ms)
        .unwrap()
        .insert(issued_grant)
        .unwrap();

    let set_decision = |server: &mut WalletServer, required: bool, asset: &str| {
        use stellar_agent_core::policy::v1::{
            PolicyDocument, PolicyEngineV1, PolicyRule, RuleMatch, ScopeId,
        };
        use stellar_agent_core::policy::{ApprovalRequest, Decision};
        let rules = [
            "stellar_pay",
            "stellar_pay_commit",
            "stellar_toolset_invoke",
        ]
        .into_iter()
        .map(|tool| PolicyRule {
            r#match: RuleMatch {
                tool: tool.to_owned(),
                chain: TESTNET_CHAIN_ID.to_owned(),
            },
            criteria: vec![
                Box::new(
                    stellar_agent_core::policy::v1::criteria::PerTxCapCriterion::new(
                        asset.to_owned(),
                        100_000_000,
                    ),
                ),
                Box::new(
                    stellar_agent_core::policy::v1::criteria::PerPeriodCapCriterion::new(
                        asset.to_owned(),
                        stellar_agent_core::policy::v1::criteria::per_period_cap::Window::parse(
                            "1d",
                        )
                        .unwrap(),
                        1_000_000_000,
                    ),
                ),
            ],
            decision: if required {
                Decision::RequireApproval(
                    ApprovalRequest::new(String::new(), 600)
                        .with_reason("payment consent".to_owned()),
                )
            } else {
                Decision::Allow
            },
            allow_opaque_signing: false,
        })
        .collect();
        server.set_policy_engine_for_test(std::sync::Arc::new(PolicyEngineV1::new(
            PolicyDocument {
                version: 1,
                scope: ScopeId::AllProfiles,
                rules,
                signature: None,
            },
            profile_name.clone(),
        )));
    };
    let wire = |result: &rmcp::model::CallToolResult| -> serde_json::Value {
        serde_json::from_str(&result.content[0].as_text().unwrap().text).unwrap()
    };
    let public_key = stellar_strkey::ed25519::PublicKey::from_string(&g_strkey)
        .unwrap()
        .0;
    let evidence_dir = std::env::var_os("STELLAR_AGENT_PAYMENT_EVIDENCE_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../target/tmp/payment-evidence")
        });
    let evidence_dir = if local {
        evidence_dir.join("local")
    } else {
        evidence_dir
    };
    std::fs::create_dir_all(&evidence_dir).unwrap();
    let revision = std::process::Command::new("git")
        .args(["--no-optional-locks", "rev-parse", "HEAD"])
        .output()
        .unwrap();
    assert!(revision.status.success());
    let revision = String::from_utf8(revision.stdout).unwrap();
    let feature_state = if cfg!(feature = "mainnet-write") {
        "on"
    } else {
        "off"
    };
    let evidence_path = evidence_dir.join(format!(
        "toolset-{feature_state}-{}.jsonl",
        uuid::Uuid::new_v4()
    ));
    let mut completed = 0;
    for asset in ["native", issued_asset.as_str()] {
        let mut asset_cases = 0;
        for id in [None, Some(0), Some(u64::MAX)] {
            let destination = id.map_or_else(
                || g_strkey.clone(),
                |id| {
                    stellar_strkey::ed25519::MuxedAccount {
                        ed25519: public_key,
                        id,
                    }
                    .to_string()
                    .as_str()
                    .to_owned()
                },
            );
            for required in [false, true] {
                let amount = if asset == "native" { "1 XLM" } else { "1 USD" };
                let toolset = matches!(route, Route::Toolset)
                    || matches!(route, Route::Alternating) && completed % 2 == 0;
                set_decision(&mut server, required && !toolset, asset);
                if required && !toolset {
                    let provenance = common::payment_recovery_policy(&server);
                    server.set_payment_recovery_policy_for_test(provenance);
                }
                let prepare_args = stellar_agent_mcp::server::StellarPayArgs {
                    chain_id: TESTNET_CHAIN_ID.to_owned(),
                    source: g_strkey.clone(),
                    destination: destination.clone(),
                    asset: asset.to_owned(),
                    amount: Some(amount.to_owned()),
                    amount_in_stroops: None,
                    memo_text: Some(
                        serde_json::from_value(serde_json::json!(format!("consent-{required}")))
                            .unwrap(),
                    ),
                    memo_id: None,
                    memo_hash_hex: None,
                    memo_return_hex: None,
                    classic_base: Some(FEE_STROOPS.to_string()),
                    business_id: None,
                };
                let prepared = if matches!(route, Route::Alternating) && !toolset {
                    wire(&server.call_stellar_toolset_invoke(StellarToolsetInvokeArgs { toolset: TOOLSET_NAME.to_owned(), action: "stellar_pay".to_owned(), chain_id: Some(TESTNET_CHAIN_ID.to_owned()), args: serde_json::json!({
                "chain_id": TESTNET_CHAIN_ID, "source": g_strkey, "destination": destination,
                "asset": asset, "amount": amount, "memo_text": format!("consent-{required}"),
                "classic_base": FEE_STROOPS.to_string(),
            }) }).await.unwrap())
                } else {
                    wire(&server.call_stellar_pay(prepare_args).await.unwrap())
                };
                assert_eq!(prepared["ok"], true, "{prepared}");
                let mut args = serde_json::json!({
                    "chain_id": TESTNET_CHAIN_ID, "source": g_strkey, "destination": destination,
                    "asset": asset, "amount": amount, "memo_text": format!("consent-{required}"),
                    "envelope_xdr": prepared["data"]["envelope_xdr"], "nonce": prepared["data"]["nonce"],
                    "expires_at_unix_ms": prepared["data"]["expires_at_unix_ms"],
                });
                set_decision(&mut server, required, asset);
                if required && !toolset {
                    let provenance = common::payment_recovery_policy(&server);
                    server.set_payment_recovery_policy_for_test(provenance);
                }
                let approvals_before = PendingApprovalStore::open(
                    approval_dir.path().join(format!("{profile_name}.toml")),
                )
                .unwrap()
                .len();
                let sends_before = stellar_agent_network::client::send_attempts_on_this_thread();
                let first = wire(&commit(&server, args.clone(), toolset).await);
                let committed = if required {
                    assert_eq!(
                        first["error"]["code"], "policy.approval_required",
                        "{first}"
                    );
                    assert_eq!(
                        stellar_agent_network::client::send_attempts_on_this_thread(),
                        sends_before
                    );
                    let path = approval_dir.path().join(format!("{profile_name}.toml"));
                    let entry = {
                        let store = PendingApprovalStore::open(path.clone()).unwrap();
                        let entries = store.snapshot(now_unix_ms().unwrap());
                        assert_eq!(store.len(), approvals_before + usize::from(toolset));
                        let matching: Vec<_> = entries.iter().filter_map(|view| store.get(&view.approval_nonce)).filter(|entry| matches!(&entry.kind, stellar_agent_core::approval::ApprovalKind::PaymentSimulated { envelope_xdr_b64, .. } if envelope_xdr_b64 == args["envelope_xdr"].as_str().unwrap())).collect();
                        assert_eq!(
                            matching.len(),
                            1,
                            "one genuine policy requirement queues one consent"
                        );
                        matching[0].clone()
                    };
                    use stellar_agent_core::approval::{
                        AttestationBinding, AttestedApprover, compute_attestation_v4,
                        envelope_sha256,
                    };
                    let blob = compute_attestation_v4(
                        &attestation_key,
                        &AttestationBinding::new(&profile_name, TESTNET_CHAIN_ID),
                        &entry.approval_nonce,
                        &envelope_sha256(args["envelope_xdr"].as_str().unwrap().as_bytes()),
                        &process_uid_for_attestation().unwrap(),
                        &entry.attested_lifetime(),
                        &AttestedApprover::Local,
                    );
                    PendingApprovalStore::open(path)
                        .unwrap()
                        .record_attestation(&entry.approval_nonce, blob, AttestedApprover::Local)
                        .unwrap();
                    args["approval_nonce"] = entry.approval_nonce.into();
                    args["approval_attestation"] = base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .encode(blob)
                        .into();
                    wire(&commit(&server, args.clone(), toolset).await)
                } else {
                    let store = PendingApprovalStore::open(
                        approval_dir.path().join(format!("{profile_name}.toml")),
                    )
                    .unwrap();
                    assert_eq!(
                        store.len(),
                        approvals_before,
                        "granted Allow must not queue payment consent"
                    );
                    first
                };
                assert_eq!(
                    committed["ok"], true,
                    "granted policy-controlled payment must submit: {committed}"
                );
                assert_eq!(committed["data"]["tx_hash"].as_str().unwrap().len(), 64);
                assert!(
                    committed["data"]["ledger"].as_u64().unwrap() > 0,
                    "confirmed ledger: {committed}"
                );
                use sha2::{Digest as _, Sha256};
                use stellar_agent_core::envelope_decode::{
                    ClassicOperation, ClassicTransactionKind, classic_summary,
                };
                assert_eq!(
                    classic_summary(
                        prepared["data"]["envelope_xdr"].as_str().unwrap(),
                        ClassicTransactionKind::Payment
                    )
                    .unwrap()
                    .operation,
                    ClassicOperation::Payment {
                        destination: destination.clone(),
                        asset: if asset == "native" {
                            "XLM".to_owned()
                        } else {
                            asset.to_owned()
                        },
                        amount_stroops: SELF_PAYMENT_STROOPS
                    }
                );
                completed += 1;
                asset_cases += 1;
                let window = stellar_agent_network::policy_state::PersistedWindowStore::for_profile(
                    &profile_name,
                );
                let memory = stellar_agent_core::policy::v1::PolicyStateStore::new();
                window.load_into(&profile_name, &profile, &memory).unwrap();
                let observed = memory
                    .query_window(
                        &stellar_agent_core::policy::v1::criteria::state_store::StateKey::new(
                            &profile_name,
                            1,
                            asset,
                            86_400,
                        ),
                        now_unix_ms().unwrap(),
                    )
                    .unwrap();
                assert_eq!(
                    observed,
                    (
                        i128::from(asset_cases) * i128::from(SELF_PAYMENT_STROOPS),
                        asset_cases
                    ),
                    "one debit per payment"
                );
                let audit = std::fs::read_to_string(&profile.audit_log_path).unwrap();
                let rows: Vec<serde_json::Value> = audit
                    .lines()
                    .map(|line| serde_json::from_str(line).unwrap())
                    .filter(|row: &serde_json::Value| row["kind"] == "value_action_pending")
                    .collect();
                assert_eq!(rows.len(), completed);
                let row = rows.last().unwrap();
                assert_eq!(
                    row["policy_decision"],
                    if required {
                        "require_approval"
                    } else {
                        "allow"
                    }
                );
                let hash = stellar_agent_core::hex::encode(&Sha256::digest(destination.as_bytes()));
                assert_eq!(row["legs"][0]["destination_sha256"], hash);
                assert_eq!(
                    row["legs"][0]["destination_redacted"],
                    stellar_agent_core::observability::redact_strkey_first5_last5(&destination)
                );
                assert_eq!(row["legs"][0]["amount"], SELF_PAYMENT_STROOPS.to_string());
                assert_eq!(row["legs"][0]["asset"], asset);
                let receipt =
                    stellar_agent_core::profile::receipt::ReceiptStore::open(&profile_name)
                        .unwrap()
                        .find_by_tx_hash(committed["data"]["tx_hash"].as_str().unwrap())
                        .unwrap()
                        .unwrap();
                let expected_destination = id.map_or(
                    stellar_agent_core::profile::receipt::PaymentDestinations::None,
                    |_| {
                        stellar_agent_core::profile::receipt::PaymentDestinations::Single(
                            destination.clone(),
                        )
                    },
                );
                assert_eq!(receipt.destinations, expected_destination);
                let repeated = wire(&commit(&server, args, toolset).await);
                assert_eq!(
                    repeated["ok"], false,
                    "a repeated nonce must not submit again: {repeated}"
                );
                let send_count =
                    stellar_agent_network::client::send_attempts_on_this_thread() - sends_before;
                assert_eq!(send_count, 1, "one send including refused replay");
                use std::io::Write as _;
                let evidence = serde_json::json!({
                    "schema": 1, "revision": revision.trim(), "feature_state": feature_state,
                    "execution": if local { "local-fixture" } else { "live-testnet" },
                    "test": evidence_test, "route": if toolset { "toolset" } else { "direct" },
                    "case": format!("{}/{}/{}", if asset == "native" { "native" } else { "issued" }, id.map_or("G", |id| if id == 0 { "M0" } else { "Mmax" }), if required { "approval" } else { "allow" }),
                    "envelope_hash": stellar_agent_network::submit::envelope_hash_hex(prepared["data"]["envelope_xdr"].as_str().unwrap()),
                    "destination": destination, "asset": asset, "amount_stroops": SELF_PAYMENT_STROOPS.to_string(),
                    "transaction_hash": committed["data"]["tx_hash"], "ledger": committed["data"]["ledger"],
                    "send_count": send_count, "debit_count": observed.1 - (asset_cases - 1), "audit_destination_sha256": hash,
                    "receipt": { "envelope_hash": receipt.envelope_hash, "transaction_hash": receipt.tx_hash, "destination": id.map(|_| destination.clone()) },
                });
                let mut file = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&evidence_path)
                    .unwrap();
                writeln!(file, "{evidence}").unwrap();
            }
        }
    }
    assert_eq!(
        completed, 12,
        "every native/issued, G/M0/Mmax and policy-decision case executes"
    );
    if let Some(mock) = mock {
        let requests = mock.received_requests().await.unwrap();
        let sends = requests
            .iter()
            .filter(|request| {
                serde_json::from_slice::<serde_json::Value>(&request.body).unwrap()["method"]
                    == "sendTransaction"
            })
            .count();
        assert_eq!(
            sends, 13,
            "one setup and twelve payments: native/issued, G/M0/Mmax, Allow/required consent"
        );
    }
}
