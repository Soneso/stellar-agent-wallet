//! Testnet acceptance tests for `stellar_x402_create_payment` MCP tool.
//!
//! These tests require a live testnet RPC endpoint and Friendbot access. They
//! are gated behind the `testnet-acceptance` feature flag:
//!
//! ```text
//! cargo test -p stellar-agent-mcp --features testnet-acceptance \
//!   --test x402_create_payment_testnet_acceptance
//! ```
//!
//! Under default `cargo test` (no `--features testnet-acceptance`), this file
//! compiles but all tests are compiled-out via `#[cfg(feature = "testnet-acceptance")]`.
//!
//! # Acceptance criteria
//!
//! - `stellar_x402_create_payment` with a native-SAC `PaymentRequirements`
//!   paying a distinct funded recipient succeeds and returns, under `data`,
//!   `{ paymentSignature, payer, asset, amount, payTo, network }`.
//! - The `paymentSignature` decodes to a `PaymentPayload` with
//!   `x402Version == 2`. Its transaction carries exactly the payer's signed
//!   authorization of `transfer(payer, recipient, amount)`. The signature
//!   verifies, and the expiration lies sixty ledgers after the simulation's.
//! - The leg records the endpoint protocol and the ledgers `L`, `H`, and
//!   `R` the payment checked. A build failure fails the leg; it never skips.
//! - Negative: invalid scheme in `payment_required` returns `isError = true`.
//! - Negative: `chain_id` mismatch returns `rmcp::ErrorData`.
//!
//! # Test isolation
//!
//! A fresh ed25519 keypair is generated per test run using `rand_core::OsRng`.
//! The keypair is funded via Friendbot before use.  No pre-committed secret
//! key material appears in source.
//!
//! # Process-global keyring
//!
//! All keyring-touching tests call `keyring_mock::install` before constructing
//! `WalletServer` and are serialised via `#[serial]` because the mock keyring
//! is process-global state.

#![cfg(feature = "testnet-acceptance")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    reason = "test-only; panics, unwraps, and eprintln are acceptable in testnet acceptance tests"
)]

use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use serial_test::serial;
use stellar_agent_core::profile::schema::Profile;
use stellar_agent_mcp::server::{WalletServer, X402CreatePaymentArgs};
use stellar_agent_test_support::keyring_mock;
use stellar_agent_x402::wire::PaymentPayload;
use zeroize::Zeroizing;

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

const TESTNET_RPC_URL: &str = "https://soroban-testnet.stellar.org";
const TESTNET_FRIENDBOT_URL: &str = "https://friendbot.stellar.org";
const TESTNET_CHAIN_ID: &str = "stellar:testnet";
/// USDC SAC on testnet.
const USDC_TESTNET_SAC: &str = "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA";
/// Atomic amount: 0.1 USDC = 1_000_000 atomic units (7 decimals).
const USDC_AMOUNT_ATOMIC: &str = "1000000";

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Generates a fresh ed25519 keypair using OS entropy.
///
/// Returns `(g_strkey, seed_bytes)`. Seed bytes are `Zeroizing`-wrapped so
/// they are cleared on drop.
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

/// Funds a testnet account via Friendbot.
///
/// Panics if the HTTP request fails or returns a non-2xx status.
async fn fund_via_friendbot(g_strkey: &str) {
    let url = format!("{TESTNET_FRIENDBOT_URL}?addr={g_strkey}");
    let resp = stellar_agent_test_support::testnet_helpers::friendbot_funding_request(&url)
        .await
        .expect("Friendbot HTTP GET must succeed");
    assert!(
        resp.status().is_success(),
        "Friendbot must return 2xx for {g_strkey}; got {}",
        resp.status()
    );
    eprintln!("funded {g_strkey} via Friendbot");
}

/// Builds a `PaymentRequirements` JSON string for the given payer, with
/// `areFeesSponsored: true` and the USDC testnet SAC.
fn usdc_testnet_requirements(payer: &str) -> String {
    serde_json::json!({
        "scheme": "exact",
        "network": "stellar:testnet",
        "asset": USDC_TESTNET_SAC,
        "amount": USDC_AMOUNT_ATOMIC,
        "payTo": payer,
        "maxTimeoutSeconds": 300,
        "extra": { "areFeesSponsored": true }
    })
    .to_string()
}

/// Installs the keyring mock and registers `seed` under the given service.
///
/// Returns a built `WalletServer` using the registered signer with the testnet
/// RPC URL.
fn build_test_server(
    g_strkey: &str,
    seed: &Zeroizing<[u8; 32]>,
    signer_service: &str,
) -> WalletServer {
    keyring_mock::install().expect("mock keyring store init");

    let mut profile =
        Profile::builder_testnet(signer_service, g_strkey, "x402-nonce-svc", "default")
            .with_noop_engine()
            .build();
    profile.rpc_url = TESTNET_RPC_URL.to_owned();

    // Store the signing key in the mock keyring under the profile's signer entry.
    let signer_ref = &profile.mcp_signer_default;
    let entry = keyring_core::Entry::new(&signer_ref.service, &signer_ref.account)
        .expect("keyring mock entry construction must succeed");
    let s_strkey = stellar_strkey::ed25519::PrivateKey::from_payload(seed.as_ref())
        .expect("32-byte seed must encode as S-strkey")
        .as_unredacted()
        .to_string();
    entry
        .set_password(&s_strkey)
        .expect("keyring mock set_password must succeed");

    // Audit chain-root key. Signing verbs prove the keyed audit writer
    // acquirable before any signing (audit.chain_key_unavailable otherwise),
    // so every profile that signs or submits in these scenarios needs the
    // key minted. Each test uses a unique per-account profile name, so a
    // fixed key cannot collide across the process-lifetime writer registry.
    use base64::Engine as _;
    let audit_ref = &profile.audit_log_hash_chain_key_id;
    let audit_key_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x37u8; 32]);
    keyring_core::Entry::new(&audit_ref.service, &audit_ref.account)
        .expect("audit chain-root keyring entry")
        .set_password(&audit_key_b64)
        .expect("set audit chain-root key");

    WalletServer::new(profile).expect("WalletServer::new must succeed with mock keyring")
}

/// Extracts the first text item from a `CallToolResult`.
fn extract_text(result: rmcp::model::CallToolResult) -> String {
    result
        .content
        .into_iter()
        .find_map(|c| {
            if let rmcp::model::RawContent::Text(t) = c.raw {
                Some(t.text)
            } else {
                None
            }
        })
        .expect("result must contain a text content item")
}

// ─────────────────────────────────────────────────────────────────────────────
// Native-SAC payments
// ─────────────────────────────────────────────────────────────────────────────

/// Native-asset Stellar Asset Contract address on testnet. A Friendbot-funded
/// account always holds native balance here, so a payment needs no trustline.
const NATIVE_SAC_TESTNET: &str = "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC";

/// Atomic amount of the native payment: 0.1 XLM.
const NATIVE_AMOUNT_STROOPS: u64 = 1_000_000;

/// Signature window of a 300-second requirement, in ledgers.
const WINDOW_LEDGERS: u64 = 60;

/// `PaymentRequirements` JSON for a native-SAC payment to `pay_to`.
fn native_requirements(pay_to: &str) -> String {
    serde_json::json!({
        "scheme": "exact",
        "network": "stellar:testnet",
        "asset": NATIVE_SAC_TESTNET,
        "amount": NATIVE_AMOUNT_STROOPS.to_string(),
        "payTo": pay_to,
        "maxTimeoutSeconds": 300,
        "extra": { "areFeesSponsored": true }
    })
    .to_string()
}

/// Waits until the endpoint shows `account`; fails when it never does.
async fn wait_until_visible(account: &str) {
    let rpc = stellar_agent_network::StellarRpcClient::new(TESTNET_RPC_URL)
        .expect("RPC client construction");
    for _ in 0..20 {
        if stellar_agent_network::fetch_account(&rpc, account, &[])
            .await
            .is_ok()
        {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    panic!("[UNAVAILABLE] account {account} is not visible on the endpoint");
}

/// The numeric fields of every `create_payment` event that names the
/// re-simulation ledger.
#[derive(Clone, Default)]
struct LedgerCapture(
    std::sync::Arc<std::sync::Mutex<Vec<std::collections::BTreeMap<String, u64>>>>,
);

struct NumericFields(std::collections::BTreeMap<String, u64>);

impl tracing::field::Visit for NumericFields {
    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        self.0.insert(field.name().to_owned(), value);
    }

    fn record_debug(&mut self, _field: &tracing::field::Field, _value: &dyn std::fmt::Debug) {}
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for LedgerCapture {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        if event.metadata().target() != "stellar_agent_x402::exact" {
            return;
        }
        let mut fields = NumericFields(std::collections::BTreeMap::new());
        event.record(&mut fields);
        if fields.0.contains_key("resimulation_ledger") {
            self.0.lock().unwrap().push(fields.0);
        }
    }
}

impl LedgerCapture {
    /// Captures `create_payment` events on this thread until the guard drops.
    fn install() -> (Self, tracing::subscriber::DefaultGuard) {
        use tracing_subscriber::layer::SubscriberExt as _;
        let capture = Self::default();
        let guard =
            tracing::subscriber::set_default(tracing_subscriber::registry().with(capture.clone()));
        tracing::callsite::rebuild_interest_cache();
        (capture, guard)
    }

    /// Checks and records the endpoint protocol and the ledgers of the one
    /// payment captured, and returns its signature expiration ledger.
    fn check_and_record(&self, leg: &str) -> u64 {
        let events = self.0.lock().unwrap();
        let [fields] = events.as_slice() else {
            panic!("[{leg}] one payment event, got {}", events.len());
        };
        let field = |name: &str| *fields.get(name).unwrap_or_else(|| panic!("{name}"));
        let (protocol, simulation, health, resimulation, expiration) = (
            field("protocol_version"),
            field("simulation_ledger"),
            field("health_ledger"),
            field("resimulation_ledger"),
            field("signature_expiration_ledger"),
        );
        eprintln!(
            "[{leg}] protocol {protocol} L={simulation} H={health} R={resimulation} E={expiration}"
        );
        assert!(
            stellar_agent_network::SUPPORTED_PROTOCOL_VERSIONS
                .contains(&u32::try_from(protocol).unwrap()),
            "[{leg}] acceptance evidence needs a supported protocol, got {protocol}"
        );
        assert_eq!(expiration, simulation + WINDOW_LEDGERS, "[{leg}]");
        assert!(simulation > 0 && simulation <= health + 1, "[{leg}]");
        assert!(health < expiration, "[{leg}]");
        assert!(
            health <= resimulation + 1 && resimulation < expiration,
            "[{leg}]"
        );
        expiration
    }
}

/// The `PaymentPayload` behind a `paymentSignature` value and the
/// authorization entries of its transaction.
fn decode_payment(
    payment_signature_b64: &str,
) -> (PaymentPayload, Vec<stellar_xdr::SorobanAuthorizationEntry>) {
    use base64::Engine as _;
    let payload_bytes = base64::engine::general_purpose::STANDARD
        .decode(payment_signature_b64)
        .expect("paymentSignature must be valid standard base64");
    let payload: PaymentPayload = serde_json::from_slice(&payload_bytes)
        .expect("paymentSignature must decode to PaymentPayload JSON");
    let envelope = <stellar_xdr::TransactionEnvelope as stellar_xdr::ReadXdr>::from_xdr_base64(
        &payload.payload.transaction,
        stellar_xdr::Limits::none(),
    )
    .expect("payload.transaction must decode to a TransactionEnvelope XDR");
    let stellar_xdr::TransactionEnvelope::Tx(transaction) = envelope else {
        panic!("TransactionEnvelope must be Tx (V1)");
    };
    let [operation] = transaction.tx.operations.as_slice() else {
        panic!("the payment carries one operation");
    };
    let stellar_xdr::OperationBody::InvokeHostFunction(host) = &operation.body else {
        panic!("tx operation must be InvokeHostFunction");
    };
    (payload, host.auth.to_vec())
}

/// The `ScAddress` of a G-strkey account.
fn account_sc_address(account: &str) -> stellar_xdr::ScAddress {
    let key = stellar_strkey::ed25519::PublicKey::from_string(account).expect("a G-strkey");
    stellar_xdr::ScAddress::Account(stellar_xdr::AccountId(
        stellar_xdr::PublicKey::PublicKeyTypeEd25519(stellar_xdr::Uint256(key.0)),
    ))
}

/// Asserts that `entries` is exactly the payer's signed authorization of
/// `transfer(payer, recipient, amount)` on the native SAC, expiring at
/// `expiration`, with a signature that verifies; and that a corrupted copy
/// does not verify.
fn assert_payer_authorization(
    leg: &str,
    entries: &[stellar_xdr::SorobanAuthorizationEntry],
    payer: &str,
    recipient: &str,
    expiration: u64,
) {
    use stellar_xdr::{
        ContractId, Hash, Int128Parts, InvokeContractArgs, ScSymbol, ScVal,
        SorobanAuthorizedFunction, SorobanCredentials,
    };
    let [entry] = entries else {
        panic!("[{leg}] one authorization entry, got {}", entries.len());
    };
    let SorobanCredentials::Address(credentials) = &entry.credentials else {
        panic!("[{leg}] the entry carries Address credentials");
    };
    assert_eq!(credentials.address, account_sc_address(payer), "[{leg}]");
    assert_eq!(
        u64::from(credentials.signature_expiration_ledger),
        expiration,
        "[{leg}]"
    );
    let contract = stellar_strkey::Contract::from_string(NATIVE_SAC_TESTNET).unwrap();
    let transfer = InvokeContractArgs {
        contract_address: stellar_xdr::ScAddress::Contract(ContractId(Hash(contract.0))),
        function_name: ScSymbol("transfer".try_into().unwrap()),
        args: vec![
            ScVal::Address(account_sc_address(payer)),
            ScVal::Address(account_sc_address(recipient)),
            ScVal::I128(Int128Parts {
                hi: 0,
                lo: NATIVE_AMOUNT_STROOPS,
            }),
        ]
        .try_into()
        .unwrap(),
    };
    assert_eq!(
        entry.root_invocation.function,
        SorobanAuthorizedFunction::ContractFn(transfer),
        "[{leg}] the payer signs the expected transfer"
    );
    assert!(entry.root_invocation.sub_invocations.is_empty(), "[{leg}]");
    let payer_key = stellar_strkey::ed25519::PublicKey::from_string(payer)
        .unwrap()
        .0;
    assert!(
        verify_auth_entry_signature(entry, &payer_key),
        "[{leg}] the payer's signature verifies"
    );
    let mut corrupted = entry.clone();
    if let SorobanCredentials::Address(credentials) = &mut corrupted.credentials {
        credentials.signature_expiration_ledger += 1;
    }
    assert!(
        !verify_auth_entry_signature(&corrupted, &payer_key),
        "[{leg}] a corrupted entry must not verify"
    );
}

/// Verifies an `Address`-credentialled entry's ed25519 signature over its
/// reconstructed `HashIdPreimage::SorobanAuthorization` on testnet.
fn verify_auth_entry_signature(
    entry: &stellar_xdr::SorobanAuthorizationEntry,
    payer_key: &[u8; 32],
) -> bool {
    use sha2::{Digest as _, Sha256};
    use stellar_xdr::{
        Hash, HashIdPreimage, HashIdPreimageSorobanAuthorization, Limits, ScVal,
        SorobanCredentials, WriteXdr as _,
    };
    const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";
    let SorobanCredentials::Address(credentials) = &entry.credentials else {
        return false;
    };
    let preimage = HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
        network_id: Hash(Sha256::digest(TESTNET_PASSPHRASE.as_bytes()).into()),
        nonce: credentials.nonce,
        signature_expiration_ledger: credentials.signature_expiration_ledger,
        invocation: entry.root_invocation.clone(),
    });
    let Ok(preimage_bytes) = preimage.to_xdr(Limits::none()) else {
        return false;
    };
    let digest: [u8; 32] = Sha256::digest(&preimage_bytes).into();
    let ScVal::Vec(Some(outer)) = &credentials.signature else {
        return false;
    };
    let Some(ScVal::Map(Some(map))) = outer.first() else {
        return false;
    };
    let signature = map.iter().find_map(|item| match (&item.key, &item.val) {
        (ScVal::Symbol(key), ScVal::Bytes(bytes)) if key.0.as_slice() == b"signature" => {
            <[u8; 64]>::try_from(bytes.0.as_slice()).ok()
        }
        _ => None,
    });
    let Some(signature) = signature else {
        return false;
    };
    let Ok(key) = ed25519_dalek::VerifyingKey::from_bytes(payer_key) else {
        return false;
    };
    key.verify_strict(&digest, &ed25519_dalek::Signature::from_bytes(&signature))
        .is_ok()
}

// ─────────────────────────────────────────────────────────────────────────────
// create_payment happy path
// ─────────────────────────────────────────────────────────────────────────────

/// create_payment happy path.
///
/// `stellar_x402_create_payment` builds a native-SAC payment from a funded
/// payer to a distinct funded recipient. The leg reads the response under
/// `data`, checks the signed authorization against the expected transfer, and
/// records the ledgers the payment checked. Any error fails the leg.
#[tokio::test]
#[serial]
async fn a6_create_payment_returns_signed_payload() {
    let (g_strkey, seed) = fresh_keypair();
    let (recipient, _recipient_seed) = fresh_keypair();
    fund_via_friendbot(&g_strkey).await;
    fund_via_friendbot(&recipient).await;
    wait_until_visible(&g_strkey).await;
    wait_until_visible(&recipient).await;
    let server = build_test_server(&g_strkey, &seed, "x402-test-signer-mcp");

    let (capture, _guard) = LedgerCapture::install();
    let result = server
        .call_stellar_x402_create_payment(X402CreatePaymentArgs {
            payment_required: native_requirements(&recipient),
            chain_id: TESTNET_CHAIN_ID.to_owned(),
            address: None,
        })
        .await
        .expect("dispatch_gate must not return ErrorData for a valid chain_id");

    let is_err = result.is_error == Some(true);
    let text = extract_text(result);
    assert!(!is_err, "[FAIL] create_payment errored: {text}");
    let value: serde_json::Value = serde_json::from_str(&text).expect("result must be valid JSON");
    assert_eq!(value["ok"], true, "{value}");
    let data = &value["data"];
    assert_eq!(data["payer"], g_strkey.as_str(), "{value}");
    assert_eq!(data["asset"], NATIVE_SAC_TESTNET, "{value}");
    assert_eq!(data["amount"], NATIVE_AMOUNT_STROOPS.to_string(), "{value}");
    assert_eq!(data["payTo"], recipient.as_str(), "{value}");
    assert_eq!(data["network"], "stellar:testnet", "{value}");
    let payment_signature = data["paymentSignature"]
        .as_str()
        .unwrap_or_else(|| panic!("paymentSignature must be a string: {value}"));

    let (payload, entries) = decode_payment(payment_signature);
    assert_eq!(payload.x402_version, 2, "x402Version must be 2");
    assert_eq!(payload.accepted.scheme, "exact");
    let expiration = capture.check_and_record("a6 create_payment");
    assert_payer_authorization(
        "a6 create_payment",
        &entries,
        &g_strkey,
        &recipient,
        expiration,
    );
    eprintln!("PASS: create_payment returned the payer's verified authorization");
}

// ─────────────────────────────────────────────────────────────────────────────
// invalid scheme returns isError
// ─────────────────────────────────────────────────────────────────────────────

/// Negative: bad scheme returns a tool-level error.
#[tokio::test]
#[serial]
async fn a6_invalid_scheme_returns_error() {
    let (g_strkey, seed) = fresh_keypair();
    fund_via_friendbot(&g_strkey).await;
    let server = build_test_server(&g_strkey, &seed, "x402-test-signer-scheme");

    let bad_requirements = serde_json::json!({
        "scheme": "upto",
        "network": "stellar:testnet",
        "asset": USDC_TESTNET_SAC,
        "amount": USDC_AMOUNT_ATOMIC,
        "payTo": g_strkey,
        "maxTimeoutSeconds": 300,
        "extra": { "areFeesSponsored": true }
    })
    .to_string();

    let result = server
        .call_stellar_x402_create_payment(X402CreatePaymentArgs {
            payment_required: bad_requirements,
            chain_id: TESTNET_CHAIN_ID.to_owned(),
            address: None,
        })
        .await
        .expect("dispatch_gate must not raise ErrorData");

    assert_eq!(
        result.is_error,
        Some(true),
        "unsupported scheme must return isError = true"
    );

    let text = extract_text(result);
    assert!(
        text.contains("scheme") || text.contains("exact") || text.contains("upto"),
        "error message must mention scheme; got {text}"
    );

    eprintln!("PASS: invalid scheme rejected with isError=true");
}

// ─────────────────────────────────────────────────────────────────────────────
// chain_id mismatch returns ErrorData (dispatch_gate level)
// ─────────────────────────────────────────────────────────────────────────────

/// Negative: chain_id mismatch returns ErrorData.
#[tokio::test]
#[serial]
async fn a6_chain_id_mismatch_returns_error_data() {
    let (g_strkey, seed) = fresh_keypair();
    fund_via_friendbot(&g_strkey).await;
    let server = build_test_server(&g_strkey, &seed, "x402-test-signer-chain");

    let requirements_json = usdc_testnet_requirements(&g_strkey);

    let error = server
        .call_stellar_x402_create_payment(X402CreatePaymentArgs {
            payment_required: requirements_json,
            chain_id: "stellar:pubnet".to_owned(), // mismatch: profile is testnet
            address: None,
        })
        .await
        .expect_err("chain_id mismatch must return Err(ErrorData) from dispatch_gate");

    assert_eq!(
        error.code,
        rmcp::model::ErrorCode::INVALID_PARAMS,
        "dispatch_gate chain_id mismatch must use INVALID_PARAMS error code"
    );

    eprintln!(
        "PASS: chain_id mismatch returns ErrorData code={:?}",
        error.code
    );
}
