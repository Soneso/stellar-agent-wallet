//! `mpp charge authorize` previews the authorization the mpp library prepares.
//!
//! The binary reads, decodes, and prepares its input in `commands/mpp.rs`,
//! which no other crate can call. This suite runs that code in a child process
//! and compares the preview it prints with one the library computes in-process
//! from the typed input, so a transformation of the input on the CLI path
//! changes the printed preview and fails the comparison.
//!
//! # Hermetic fixtures
//!
//! `STELLAR_AGENT_HOME` redirects the profile, policy, approval, MPP state,
//! audit, and headless keyring paths, and is set on the child only. The child
//! uses the headless keyring backend over a store file this test seeds. The
//! profile's `rpc_url` points at a wiremock responder that answers
//! `simulateTransaction` with the payer's authorization entry.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    reason = "test-only; the parity contract is asserted via panic-on-violation"
)]

use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::{Value, json};
use serial_test::serial;
use stellar_agent_core::{
    approval::PendingApprovalStore,
    approval::user_id::process_uid_for_attestation,
    policy::v1::{canonical::canonical_bytes, signature::digest},
    profile::{
        loader::save_new_to_dir,
        schema::{KeyringEntryRef, PolicyEngineKind, Profile},
    },
    timefmt::{format_rfc3339_utc, now_unix_ms},
};
use stellar_agent_mpp::{
    ApprovalDisposition, ChallengeInput, McpOperationKind, McpRequestContext,
    MppAuthorizationStore, StellarSponsoredRpc, persist_prepared_authorization, prepare_sponsored,
    select_and_validate,
};
use stellar_xdr::{
    AccountId, HostFunction, Limits, OperationBody, PublicKey, ReadXdr as _, ScAddress, ScVal,
    SorobanAddressCredentials, SorobanAuthorizationEntry, SorobanAuthorizedFunction,
    SorobanAuthorizedInvocation, SorobanCredentials, TransactionEnvelope, Uint256, VecM,
    WriteXdr as _,
};
use wiremock::matchers::{body_partial_json, method};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

/// The profile the child and the in-process preparation both serve under.
const PROFILE: &str = "mpp-preview-cli";

/// SEP-41 token contract the challenge charges against.
const CONTRACT: &str = "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA";

/// Charge recipient.
const RECIPIENT: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";

/// A `SorobanTransactionData` body the preparation decodes and bounds. Its
/// footprint names another contract, which nothing on the prepare path reads.
const TRANSACTION_DATA: &str = "AAAAAAAAAAIAAAAGAAAAAcwD/nT9D7Dc2LxRdab+2vEUF8B+XoN7mQW21oxPT8ALAAAAFAAAAAEAAAAHy8vNUZ8vyZ2ybPHW0XbSrRtP7gEWsJ6zDzcfY9P8z88AAAABAAAABgAAAAHMA/50/Q+w3Ni8UXWm/trxFBfAfl6De5kFttaMT0/ACwAAABAAAAABAAAAAgAAAA8AAAAHQ291bnRlcgAAAAASAAAAAAAAAAAg4dbAxsGAGICfBG3iT2cKGYQ6hK4sJWzZ6or1C5v6GAAAAAEAHfKyAAAFiAAAAIgAAAAAAAAAAw==";

/// Protection key of the headless keyring store the child reads.
const KEYRING_PROTECTION_KEY: [u8; 32] = [0x5a; 32];

fn g_strkey(key: &SigningKey) -> String {
    stellar_strkey::ed25519::PublicKey(key.verifying_key().to_bytes())
        .to_string()
        .to_string()
}

fn payer_sc_address(payer: &str) -> ScAddress {
    let key = stellar_strkey::ed25519::PublicKey::from_string(payer).expect("payer G-strkey");
    ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(key.0))))
}

/// Answers the unsigned sponsored simulation with the payer's authorization
/// entry for the contract call in the request envelope.
fn simulate_response(payer: &ScAddress, request: &Request) -> ResponseTemplate {
    let body: Value = serde_json::from_slice(&request.body).expect("JSON-RPC body");
    let envelope = TransactionEnvelope::from_xdr_base64(
        body["params"]["transaction"].as_str().expect("envelope"),
        Limits::none(),
    )
    .expect("decodable envelope");
    let TransactionEnvelope::Tx(transaction) = envelope else {
        panic!("the sponsored flow builds a v1 envelope");
    };
    let OperationBody::InvokeHostFunction(host) = transaction.tx.operations[0].body.clone() else {
        panic!("the sponsored flow builds an InvokeHostFunction operation");
    };
    let HostFunction::InvokeContract(invoke) = host.host_function else {
        panic!("the sponsored flow invokes a contract");
    };
    let entry = SorobanAuthorizationEntry {
        credentials: SorobanCredentials::Address(SorobanAddressCredentials {
            address: payer.clone(),
            nonce: 7,
            signature_expiration_ledger: 0,
            signature: ScVal::Void,
        }),
        root_invocation: SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::ContractFn(invoke),
            sub_invocations: VecM::default(),
        },
    };
    ResponseTemplate::new(200).set_body_json(json!({
        "jsonrpc": "2.0",
        "id": body["id"],
        "result": {
            "transactionData": TRANSACTION_DATA,
            "minResourceFee": "1000",
            "results": [{
                "auth": [entry.to_xdr_base64(Limits::none()).expect("auth entry encodes")],
                "xdr": ScVal::Void.to_xdr_base64(Limits::none()).expect("void encodes"),
            }],
            "latestLedger": 1000,
        },
    }))
}

/// Writes a V1 policy for [`PROFILE`] that requires approval for every tool,
/// signed by `owner`.
fn write_signed_policy(home: &Path, owner: &SigningKey) {
    let body = format!(
        r#"version = 1
scope = "profile:{PROFILE}"
[[rules]]
match = {{ tool = "*", chain = "*" }}
criteria = []
decision = "require_approval"
ttl_secs = 600
reason = "Operator review"
"#
    );
    let signature = hex::encode(
        owner
            .sign(&digest(&canonical_bytes(&body).expect("canonical policy")))
            .to_bytes(),
    );
    let policy_dir = home.join("policies");
    std::fs::create_dir_all(&policy_dir).expect("policy directory");
    std::fs::write(
        policy_dir.join(format!("{PROFILE}.toml")),
        format!(
            "{body}\n[signature]\nowner_id = \"{}\"\nsig = \"{signature}\"\n",
            g_strkey(owner)
        ),
    )
    .expect("write policy");
}

/// A tagged MCP challenge whose realm, operation, and arguments carry case
/// and whitespace, so a CLI path that rewrites them prints a different
/// preview. The explicit expiry fixes the effective expiry across both runs.
fn challenge_input() -> ChallengeInput {
    let now_seconds = now_unix_ms().expect("clock") / 1_000;
    ChallengeInput::Mcp {
        challenges: vec![json!({
            "id": "Challenge-Cli-Parity",
            "realm": " Merchant.Example ",
            "method": "stellar",
            "intent": "charge",
            "expires": format_rfc3339_utc(UNIX_EPOCH + Duration::from_secs(now_seconds + 120)),
            "request": {
                "amount": "10000000",
                "currency": CONTRACT,
                "recipient": RECIPIENT,
                "methodDetails": {"feePayer": true, "network": "stellar:testnet"},
            },
        })],
        selected_challenge_id: Some("Challenge-Cli-Parity".into()),
        context: McpRequestContext::from_params(
            " Merchant.Example ",
            McpOperationKind::Tool,
            " Checkout ",
            Some(&json!({"quantity": 1, "sku": "Item-A"})),
        )
        .expect("MCP context"),
    }
}

/// Removes the approval identifier, a random nonce minted per preparation, and
/// returns it.
fn take_approval_id(preview: &mut Value) -> String {
    preview
        .as_object_mut()
        .expect("preview object")
        .remove("approval_id")
        .and_then(|id| id.as_str().map(str::to_owned))
        .unwrap_or_else(|| panic!("a preview that requires approval carries an approval_id"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn cli_authorize_preview_matches_the_library_preview() {
    let home = tempfile::tempdir().expect("temp home");
    let keyring: Arc<keyring_core::CredentialStore> =
        Arc::new(stellar_agent_headless_keyring::store::HeadlessStore::new(
            home.path().join("headless-keyring").join("store.keyring"),
            stellar_agent_headless_keyring::crypto::ProtectionMode::EnvKey(Arc::new(
                zeroize::Zeroizing::new(KEYRING_PROTECTION_KEY),
            )),
        ));
    keyring_core::set_default_store(keyring);

    let payer = g_strkey(&SigningKey::from_bytes(&[0xa1; 32]));
    let owner = SigningKey::from_bytes(&[0xb2; 32]);
    let rpc = MockServer::start().await;
    let payer_address = payer_sc_address(&payer);
    Mock::given(method("POST"))
        .and(body_partial_json(json!({"method": "simulateTransaction"})))
        .respond_with(move |request: &Request| simulate_response(&payer_address, request))
        .expect(2)
        .mount(&rpc)
        .await;

    let mut profile =
        Profile::builder_testnet_named(PROFILE, "mpp-preview-signer", &payer, "n-svc", "n-acct")
            .rpc_url(rpc.uri())
            .audit_log_path(home.path().join("audit").join(format!("{PROFILE}.jsonl")))
            .build();
    profile.policy.engine = PolicyEngineKind::V1;
    save_new_to_dir(PROFILE, &profile, &home.path().join("profiles")).expect("save profile");
    for (coordinate, value) in [
        (
            &profile.audit_log_hash_chain_key_id,
            URL_SAFE_NO_PAD.encode([0x24; 32]),
        ),
        (&profile.policy_owner_key_id, g_strkey(&owner)),
    ] {
        keyring_core::Entry::new(&coordinate.service, &coordinate.account)
            .expect("keyring entry")
            .set_password(&value)
            .expect("seed keyring entry");
    }
    write_signed_policy(home.path(), &owner);

    let input = challenge_input();
    let input_path = home.path().join("challenge.json");
    std::fs::write(
        &input_path,
        serde_json::to_vec(&input).expect("tagged challenge JSON"),
    )
    .expect("write challenge input");

    let output = Command::new(env!("CARGO_BIN_EXE_stellar-agent"))
        .args(["mpp", "charge", "authorize", "--input-file"])
        .arg(&input_path)
        .args(["--profile", PROFILE])
        .env("STELLAR_AGENT_HOME", home.path())
        .env_remove("STELLAR_AGENT_PROFILE")
        .env(
            stellar_agent_headless_keyring::BACKEND_ENV_VAR,
            "headless-env",
        )
        .env(
            stellar_agent_headless_keyring::ENV_KEY_VAR,
            URL_SAFE_NO_PAD.encode(KEYRING_PROTECTION_KEY),
        )
        .stdin(Stdio::null())
        .output()
        .expect("stellar-agent binary must run");
    let stdout = String::from_utf8(output.stdout).expect("stdout must be UTF-8");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(1),
        "a charge that requires approval exits 1; stdout={stdout} stderr={stderr}"
    );
    let envelope: Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("stdout must be one JSON envelope ({e}); stdout={stdout}"));
    assert_eq!(
        envelope["error"]["code"], "mpp.approval_required",
        "stdout={stdout} stderr={stderr}"
    );
    let mut cli_preview = envelope["data"]["preview"].clone();
    let cli_approval_id = take_approval_id(&mut cli_preview);
    assert_eq!(envelope["data"]["approval_id"], cli_approval_id.as_str());
    assert_eq!(
        envelope["data"]["authorization_id"],
        cli_preview["authorization_id"]
    );

    let now_unix = i64::try_from(now_unix_ms().expect("clock") / 1_000).expect("Unix seconds");
    let selected = select_and_validate(&input, now_unix).expect("library selection");
    let prepared = prepare_sponsored(
        selected,
        &profile.mcp_signer_default.account,
        &profile.network_passphrase,
        &StellarSponsoredRpc::new(&profile.rpc_url).expect("library RPC"),
    )
    .await
    .expect("library preparation");
    let generation = KeyringEntryRef::new("mpp-preview-cli-library", "generation");
    keyring_core::Entry::new(&generation.service, &generation.account)
        .expect("generation entry")
        .set_password("0")
        .expect("initial generation");
    let library_state =
        MppAuthorizationStore::at_path(home.path().join("library.state"), [0x71; 32], generation);
    let mut library_approvals =
        PendingApprovalStore::open(home.path().join("library-approvals.toml"))
            .expect("library approval store");
    let library_preview = persist_prepared_authorization(
        PROFILE,
        &profile.network_passphrase,
        &prepared,
        ApprovalDisposition::RequireApproval,
        &process_uid_for_attestation().expect("process UID"),
        now_unix,
        &library_state,
        Some(&mut library_approvals),
    )
    .expect("library preview");
    let mut library_preview = serde_json::to_value(&library_preview).expect("library preview JSON");
    take_approval_id(&mut library_preview);

    assert_eq!(
        cli_preview["authorization_fingerprint"], library_preview["authorization_fingerprint"],
        "the CLI and the library must bind the same authorization"
    );
    assert_eq!(
        cli_preview, library_preview,
        "the CLI preview must match the library preview on every field but the approval nonce"
    );
}
