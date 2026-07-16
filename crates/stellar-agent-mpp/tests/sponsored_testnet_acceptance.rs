//! Live released-SDK acceptance for sponsored Stellar MPP charge.
//!
//! The test funds fresh payer, server, and recipient accounts; runs the exact
//! frozen `@stellar/mpp@0.7.1` server harness; sends a credential produced by
//! the production Rust path; records its receipt; and independently reconciles
//! the final ledger envelope. Network or runtime unavailability is a failure,
//! not a self-skip.

#![cfg(feature = "testnet-acceptance")]
#![allow(
    clippy::expect_used,
    clippy::panic,
    reason = "acceptance failures must stop with their violated invariant"
)]

use std::{
    io::{BufRead as _, BufReader},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicUsize, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use serial_test::serial;
use sha2::{Digest as _, Sha256};
use stellar_agent_core::{
    WalletError,
    audit_log::{AuditEntry, AuditWriter, PolicyDecision, ValueLegRecord},
    observability::RedactedStrkey,
    policy::v1::ValueClass,
    policy::{
        Decision, McpToolRegistration, NoopPolicyEngine, PolicyEngine, ToolDescriptor,
        ToolValueKind,
    },
    profile::caip2::TESTNET_PASSPHRASE,
    profile::schema::Profile,
};
use stellar_agent_mpp::{
    ApprovalDisposition, AuthorizationStatus, ChallengeInput, CredentialOutput, HttpRequestContext,
    LedgerOutcome, MppAuthorizationStore, MppError, MppErrorCode, ReceiptInput,
    StellarReconciliationRpc, StellarSponsoredRpc, commit_authorization, mpp_value_effects,
    parse_receipt, persist_prepared_authorization, prepare_sponsored, reconcile_transaction,
    select_and_validate,
};
use stellar_agent_network::{
    SoftwareSigningKey, StellarRpcClient, fetch_account, fund_with_friendbot,
    policy_state::record_authorized_window_state,
    signing::{Signer, WebAuthnAssertion},
};
use tempfile::TempDir;
use zeroize::Zeroizing;

const RPC_URL: &str = "https://soroban-testnet.stellar.org";
const FRIENDBOT_URL: &str = "https://friendbot.stellar.org";
const NATIVE_SAC_TESTNET: &str = "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC";
const AMOUNT_STROOPS: i64 = 1_000;

struct ServerProcess(Child);

impl Drop for ServerProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn now_unix() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock after epoch")
            .as_secs(),
    )
    .expect("Unix time fits i64")
}

fn fresh_keypair() -> (String, [u8; 32]) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let public_key = stellar_strkey::ed25519::PublicKey(signing_key.verifying_key().to_bytes())
        .to_string()
        .as_str()
        .to_owned();
    (public_key, signing_key.to_bytes())
}

fn secret_strkey(seed: &[u8; 32]) -> String {
    stellar_strkey::ed25519::PrivateKey::from_payload(seed)
        .expect("32-byte seed")
        .as_unredacted()
        .to_string()
        .as_str()
        .to_owned()
}

fn harness_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../interop/stellar-mpp-js")
        .canonicalize()
        .expect("interop harness directory")
}

fn prepare_harness(directory: &Path) {
    let node = Command::new("node")
        .args(["-p", "process.versions.node"])
        .output()
        .expect("Node 24.5.0 is installed");
    assert!(node.status.success(), "Node version probe failed");
    assert_eq!(
        String::from_utf8(node.stdout)
            .expect("Node version output")
            .trim(),
        "24.5.0",
        "acceptance must run on the frozen Node version"
    );
    let install = Command::new("corepack")
        .args(["pnpm", "install", "--frozen-lockfile", "--ignore-scripts"])
        .current_dir(directory)
        .status()
        .expect("frozen pnpm install starts");
    assert!(install.success(), "frozen MPP SDK install failed");
}

fn start_server(
    directory: &Path,
    envelope_secret: &str,
    recipient: &str,
) -> (ServerProcess, String) {
    let mut child = Command::new("node")
        .arg("live-server.mjs")
        .current_dir(directory)
        .env("MPP_ENVELOPE_SIGNER_SECRET", envelope_secret)
        .env("MPP_RECIPIENT", recipient)
        .env("MPP_CURRENCY", NATIVE_SAC_TESTNET)
        .env("MPP_RPC_URL", RPC_URL)
        .env("MPP_CHALLENGE_SECRET", "stellar-agent-live-acceptance")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("released SDK server starts");
    let stdout = child.stdout.take().expect("server stdout");
    let mut reader = BufReader::new(stdout);
    let mut ready = String::new();
    reader.read_line(&mut ready).expect("server ready line");
    let ready: serde_json::Value = serde_json::from_str(&ready).expect("server ready JSON");
    let port = ready["port"].as_u64().expect("server port");
    (
        ServerProcess(child),
        format!("http://127.0.0.1:{port}/paid"),
    )
}

/// Delegating signer that counts every signature request, so the live suite
/// can prove refusal paths make zero signer calls.
struct CountingSigner {
    inner: SoftwareSigningKey,
    signatures: AtomicUsize,
}

impl CountingSigner {
    fn new(inner: SoftwareSigningKey) -> Self {
        Self {
            inner,
            signatures: AtomicUsize::new(0),
        }
    }

    fn signature_count(&self) -> usize {
        self.signatures.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl Signer for CountingSigner {
    async fn sign_tx_payload(&self, payload: &[u8; 32]) -> Result<[u8; 64], WalletError> {
        self.signatures.fetch_add(1, Ordering::SeqCst);
        self.inner.sign_tx_payload(payload).await
    }

    async fn sign_auth_digest(&self, digest: &[u8; 32]) -> Result<[u8; 64], WalletError> {
        self.signatures.fetch_add(1, Ordering::SeqCst);
        self.inner.sign_auth_digest(digest).await
    }

    async fn sign_soroban_address_auth_payload(
        &self,
        payload: &[u8; 32],
    ) -> Result<[u8; 64], WalletError> {
        self.signatures.fetch_add(1, Ordering::SeqCst);
        self.inner.sign_soroban_address_auth_payload(payload).await
    }

    async fn sign_webauthn_assertion(
        &self,
        auth_digest: &[u8; 32],
        credential_id: &[u8],
    ) -> Result<WebAuthnAssertion, WalletError> {
        self.signatures.fetch_add(1, Ordering::SeqCst);
        self.inner
            .sign_webauthn_assertion(auth_digest, credential_id)
            .await
    }

    async fn public_key(&self) -> Result<stellar_strkey::ed25519::PublicKey, WalletError> {
        self.inner.public_key().await
    }
}

fn commit_descriptor() -> ToolDescriptor {
    // Mirrors the binaries' policy descriptor for the commit tool.
    let registration = McpToolRegistration {
        name: "stellar_mpp_charge_commit",
        destructive_hint: true,
        read_only_hint: false,
        chain_id_required: true,
        value_kind: ToolValueKind::MovesValue,
    };
    let mut descriptor = ToolDescriptor::from_registration(&registration);
    descriptor.chain_id = "stellar:testnet".to_owned();
    descriptor
}

fn state_error() -> MppError {
    MppError::new(
        MppErrorCode::StateUnavailable,
        "acceptance accounting failed",
    )
}

async fn fetch_challenge_input(http: &reqwest::Client, endpoint: &str) -> ChallengeInput {
    let required = http
        .get(endpoint)
        .send()
        .await
        .expect("released server challenge");
    assert_eq!(required.status(), reqwest::StatusCode::PAYMENT_REQUIRED);
    let challenge_header = required
        .headers()
        .get(reqwest::header::WWW_AUTHENTICATE)
        .expect("WWW-Authenticate")
        .to_str()
        .expect("ASCII challenge")
        .to_owned();
    ChallengeInput::Http {
        www_authenticate: vec![challenge_header],
        selected_challenge_id: None,
        context: HttpRequestContext::new(
            "https://merchant.example",
            "GET",
            "https://merchant.example/paid",
            None,
            None,
        )
        .expect("bound HTTPS request context"),
    }
}

async fn native_balance(rpc: &StellarRpcClient, account: &str) -> i64 {
    fetch_account(rpc, account, &[])
        .await
        .expect("account query")
        .balances
        .first()
        .expect("native balance")
        .balance_stroops()
        .expect("canonical native balance")
}

#[tokio::test]
#[serial]
async fn released_server_accepts_wallet_credential_and_settles_exact_transfer() {
    let harness = harness_dir();
    prepare_harness(&harness);

    let (payer, payer_seed) = fresh_keypair();
    let (server_account, server_seed) = fresh_keypair();
    let (recipient, _recipient_seed) = fresh_keypair();
    for account in [&payer, &server_account, &recipient] {
        fund_with_friendbot(FRIENDBOT_URL, account, TESTNET_PASSPHRASE, RPC_URL)
            .await
            .expect("Friendbot funding reaches RPC");
    }

    let rpc_client = StellarRpcClient::new(RPC_URL).expect("RPC client");
    let recipient_before = native_balance(&rpc_client, &recipient).await;
    let server_secret = Zeroizing::new(secret_strkey(&server_seed));
    let (_server, endpoint) = start_server(&harness, &server_secret, &recipient);

    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(180))
        .build()
        .expect("HTTP client");
    let input = fetch_challenge_input(&http, &endpoint).await;

    let now = now_unix();
    let selected = select_and_validate(&input, now).expect("released sponsored challenge");
    assert_eq!(selected.request().amount(), i128::from(AMOUNT_STROOPS));
    assert_eq!(selected.request().currency(), NATIVE_SAC_TESTNET);
    assert_eq!(selected.request().recipient(), recipient);

    // Item 10: mainnet is refused before any signer involvement. The zero
    // RPC/keyring side-effect ordering is proven with counting doubles in the
    // offline suite; require_testnet precedes every other statement.
    let mainnet_refusal = prepare_sponsored(
        selected.clone(),
        &payer,
        "Public Global Stellar Network ; September 2015",
        &StellarSponsoredRpc::new(RPC_URL).expect("sponsored RPC"),
    )
    .await
    .expect_err("mainnet must be refused");
    assert_eq!(mainnet_refusal.code(), "mpp.network_forbidden");

    let sponsored_rpc = StellarSponsoredRpc::new(RPC_URL).expect("sponsored RPC");
    let prepared = prepare_sponsored(selected, &payer, TESTNET_PASSPHRASE, &sponsored_rpc)
        .await
        .expect("production sponsored prepare");
    let state_directory = TempDir::new().expect("state tempdir");
    let state = MppAuthorizationStore::at_path(state_directory.path().join("state"), [9; 32]);

    // Production policy/audit wiring: the same evaluate -> persist ->
    // account -> audit -> deliver sequence the binaries run, with a real
    // policy engine and a real hash-chained audit writer.
    let profile = Profile::builder_testnet("svc", "acct", "nonce-svc", "nonce-acct")
        .with_noop_engine()
        .build();
    let engine = NoopPolicyEngine;
    let descriptor = commit_descriptor();
    let evaluation = engine
        .evaluate_with_value_full(
            &descriptor,
            &serde_json::json!({}),
            &profile,
            ValueClass::Value(mpp_value_effects(prepared.selected())),
            None,
            None,
            None,
            None,
            None,
        )
        .expect("policy evaluation");
    assert!(matches!(evaluation.decision, Decision::Allow));

    let preview = persist_prepared_authorization(
        "mpp-live-acceptance",
        TESTNET_PASSPHRASE,
        &prepared,
        ApprovalDisposition::Allow,
        "acceptance",
        now,
        &state,
        None,
    )
    .expect("durable authorization");
    let signer = CountingSigner::new(SoftwareSigningKey::new_from_zeroizing(Zeroizing::new(
        payer_seed,
    )));
    let audit_path = state_directory.path().join("audit.jsonl");
    let mut audit_writer =
        AuditWriter::open(audit_path.clone(), None).expect("acceptance audit writer");
    let credential = commit_authorization(
        &state,
        None,
        None,
        &preview.authorization_id,
        now_unix(),
        TESTNET_PASSPHRASE,
        &signer,
        &sponsored_rpc,
        |_record, _prepared, effects| {
            record_authorized_window_state(
                &engine,
                &descriptor,
                &profile,
                "mpp-live-acceptance",
                &ValueClass::Value(effects.clone()),
            )
            .map_err(|_| state_error())
        },
        |authorized| {
            let entry = AuditEntry::new_mpp_charge_authorized(
                "stellar_mpp_charge_commit",
                "stellar:testnet",
                hex::encode(Sha256::digest(
                    authorized.record.authorization_id().as_bytes(),
                )),
                hex::encode(authorized.record.fingerprint()),
                authorized
                    .value_effects
                    .legs()
                    .iter()
                    .map(ValueLegRecord::from)
                    .collect(),
                RedactedStrkey::from_full(authorized.payer),
                authorized.record.approval_nonce().is_some(),
                PolicyDecision::Allow,
                "mpp-live-acceptance-commit",
            );
            audit_writer.write_entry(entry).map_err(|_| state_error())
        },
        |_withheld| {},
    )
    .await
    .expect("production sponsored commit");
    assert_eq!(signer.signature_count(), 1, "exactly one signature");
    let audit_log = std::fs::read_to_string(&audit_path).expect("audit log");
    assert!(
        audit_log.contains("mpp_charge_authorized"),
        "authorization audit row must precede delivery"
    );
    let CredentialOutput::Http { authorization } = credential else {
        panic!("HTTP challenge must return HTTP authorization")
    };

    let paid = http
        .get(&endpoint)
        .header(reqwest::header::AUTHORIZATION, authorization)
        .send()
        .await
        .expect("released server settlement response");
    assert_eq!(paid.status(), reqwest::StatusCode::OK);
    let receipt_header = paid
        .headers()
        .get("payment-receipt")
        .expect("Payment-Receipt")
        .to_str()
        .expect("ASCII receipt")
        .to_owned();
    let receipt = parse_receipt(&ReceiptInput::Http {
        value: receipt_header,
    })
    .expect("released receipt");
    let observed = state
        .record_receipt(&preview.authorization_id, &receipt, now_unix())
        .expect("receipt observation");
    assert_eq!(observed.status(), AuthorizationStatus::ReceiptObserved);
    assert!(matches!(observed.ledger_outcome(), LedgerOutcome::Unknown));

    let reconciliation_rpc = StellarReconciliationRpc::new(RPC_URL).expect("reconciliation RPC");
    let reconciled = reconcile_transaction(
        &state,
        &preview.authorization_id,
        receipt.reference(),
        now_unix(),
        &reconciliation_rpc,
    )
    .await
    .expect("independent ledger reconciliation");
    assert_eq!(reconciled.outcome, "settled");

    // Item 9: a policy denial at commit makes zero signer calls and leaves a
    // diagnosable conservative state. (The full V1 over-cap engine is
    // exercised in the offline policy suites; the live property under test is
    // deny-before-sign with the real durable store.)
    let deny_input = fetch_challenge_input(&http, &endpoint).await;
    let deny_selected = select_and_validate(&deny_input, now_unix()).expect("second challenge");
    let deny_prepared =
        prepare_sponsored(deny_selected, &payer, TESTNET_PASSPHRASE, &sponsored_rpc)
            .await
            .expect("second prepare");
    let deny_preview = persist_prepared_authorization(
        "mpp-live-acceptance",
        TESTNET_PASSPHRASE,
        &deny_prepared,
        ApprovalDisposition::Allow,
        "acceptance",
        now_unix(),
        &state,
        None,
    )
    .expect("second authorization");
    let signatures_before_deny = signer.signature_count();
    let denied = commit_authorization(
        &state,
        None,
        None,
        &deny_preview.authorization_id,
        now_unix(),
        TESTNET_PASSPHRASE,
        &signer,
        &sponsored_rpc,
        |_record, _prepared, _effects| {
            Err(MppError::new(
                MppErrorCode::ApprovalInvalid,
                "over-cap policy denial",
            ))
        },
        |_authorized| Ok(()),
        |_withheld| {},
    )
    .await
    .expect_err("policy denial must refuse");
    assert_eq!(denied.code(), "mpp.approval_invalid");
    assert_eq!(
        signer.signature_count(),
        signatures_before_deny,
        "policy denial must make zero signer calls"
    );
    let denied_record = state
        .load(&deny_preview.authorization_id)
        .expect("denied record");
    assert_eq!(denied_record.status(), AuthorizationStatus::Indeterminate);

    // Item 7: the released server must reject a credential whose transaction
    // was altered after signing.
    let tamper_input = fetch_challenge_input(&http, &endpoint).await;
    let tamper_selected = select_and_validate(&tamper_input, now_unix()).expect("third challenge");
    let tamper_prepared =
        prepare_sponsored(tamper_selected, &payer, TESTNET_PASSPHRASE, &sponsored_rpc)
            .await
            .expect("third prepare");
    let tamper_preview = persist_prepared_authorization(
        "mpp-live-acceptance",
        TESTNET_PASSPHRASE,
        &tamper_prepared,
        ApprovalDisposition::Allow,
        "acceptance",
        now_unix(),
        &state,
        None,
    )
    .expect("third authorization");
    let tampered_credential = commit_authorization(
        &state,
        None,
        None,
        &tamper_preview.authorization_id,
        now_unix(),
        TESTNET_PASSPHRASE,
        &signer,
        &sponsored_rpc,
        |_record, _prepared, _effects| Ok(()),
        |_authorized| Ok(()),
        |_withheld| {},
    )
    .await
    .expect("third commit");
    let CredentialOutput::Http {
        authorization: tamper_authorization,
    } = tampered_credential
    else {
        panic!("HTTP challenge must return HTTP authorization")
    };
    let token = tamper_authorization
        .strip_prefix("Payment ")
        .expect("Payment scheme");
    let mut wire: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(token).expect("credential decodes"))
            .expect("credential JSON");
    let transaction = wire["payload"]["transaction"]
        .as_str()
        .expect("transaction XDR")
        .to_owned();
    let mut raw = base64::engine::general_purpose::STANDARD
        .decode(&transaction)
        .expect("XDR bytes");
    let flip = raw.len() / 2;
    raw[flip] ^= 0x01;
    wire["payload"]["transaction"] =
        serde_json::Value::String(base64::engine::general_purpose::STANDARD.encode(raw));
    let tampered = format!(
        "Payment {}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&wire).expect("re-encode"))
    );
    let rejected = http
        .get(&endpoint)
        .header(reqwest::header::AUTHORIZATION, tampered)
        .send()
        .await
        .expect("tamper response");
    assert_ne!(
        rejected.status(),
        reqwest::StatusCode::OK,
        "server must reject an altered credential"
    );
    assert!(
        rejected.headers().get("payment-receipt").is_none(),
        "no receipt may accompany a rejected credential"
    );

    let recipient_after = native_balance(&rpc_client, &recipient).await;
    assert_eq!(
        recipient_after - recipient_before,
        AMOUNT_STROOPS,
        "recipient must receive exactly one challenged amount; the denied and \
         tampered attempts must move nothing"
    );
}
