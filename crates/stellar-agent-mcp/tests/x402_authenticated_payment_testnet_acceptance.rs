//! Testnet acceptance tests for `stellar_x402_authenticated_payment` MCP tool.
//!
//! # Feature gate
//!
//! These tests are gated behind `testnet-acceptance` (mirrors the pattern in
//! `x402_create_payment_testnet_acceptance.rs`).  Under default `cargo test`
//! (no `--features testnet-acceptance`) the file compiles but all tests are
//! compiled-out.
//!
//! ```text
//! cargo test -p stellar-agent-mcp --features testnet-acceptance \
//!   --test x402_authenticated_payment_testnet_acceptance -- --nocapture
//! ```
//!
//! # Acceptance criteria
//!
//! ## Positive leg (testnet, feature-gated)
//!
//! - `stellar_x402_authenticated_payment` with `home_domain =
//!   "testanchor.stellar.org"` and a native-SAC `PaymentRequirements` paying
//!   a distinct funded recipient succeeds and returns, under `data`,
//!   `{ paymentSignature, authorization, payer, home_domain, payTo }`.
//! - `paymentSignature` decodes to a `PaymentPayload` with
//!   `x402Version == 2` whose transaction carries exactly the payer's signed
//!   authorization of `transfer(payer, recipient, amount)`, with a signature
//!   that verifies.
//! - `authorization` is a non-empty Bearer token (`Bearer ` prefix +
//!   3 dot-separated JWT segments).
//! - `home_domain` in the response equals `"testanchor.stellar.org"`.
//! - `payTo` matches the `PaymentRequirements.payTo` from the input.
//! - The leg records the endpoint protocol and the ledgers the payment
//!   checked. A SEP-10 or payment failure fails the leg; it never skips.
//!
//! ## Negative leg (no live-anchor dependency; compiled under `testnet-acceptance`)
//!
//! These negatives have NO live-anchor / funding dependency (they abort
//! before any successful fetch), but — like the whole file — they are compiled
//! only under `--features testnet-acceptance`. The gate-level abort-before-payment
//! contract is ALSO covered always-on by the gate integration tests.
//!
//! - `home_domain = "unreachable.stellar.invalid"` (LDH-valid,
//!   not listening) returns `isError = true` with `error ==
//!   "identity.home_domain_unresolvable"` AND NO `paymentSignature` field.
//! - `home_domain = "UPPERCASE.COM"` (LDH-invalid) returns
//!   `isError = true` with `error == "identity.home_domain_invalid"` AND NO
//!   `paymentSignature` field.
//!
//! Abort-before-payment: neither negative case produces a `paymentSignature`
//! or `authorization` field; the gate aborts before `create_payment` is
//! called.
//!
//! # No skips (positive leg)
//!
//! The positive leg needs a live SEP-10 session with testanchor and a live
//! testnet RPC. An outage fails it: acceptance is then unavailable, and an
//! unavailable leg never counts as a passing one.
//!
//! # Key discipline
//!
//! Fresh ed25519 keypair generated per test via `rand_core::OsRng`.  The keypair
//! is Friendbot-funded before use.  No committed `S...` seeds appear in source.

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
use stellar_agent_mcp::server::{WalletServer, X402AuthenticatedPaymentArgs};
use stellar_agent_test_support::keyring_mock;
use stellar_agent_x402::wire::PaymentPayload;
use zeroize::Zeroizing;

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

const TESTNET_RPC_URL: &str = "https://soroban-testnet.stellar.org";
const TESTNET_FRIENDBOT_URL: &str = "https://friendbot.stellar.org";
const TESTNET_CHAIN_ID: &str = "stellar:testnet";

/// SDF reference anchor with SEP-10 endpoint.
///
/// Confirmed to have `WEB_AUTH_ENDPOINT` + `SIGNING_KEY` in its `stellar.toml`.
/// This is the only live testnet anchor whose SEP-10 endpoint is a stable
/// CI-safe target.
const TESTANCHOR_HOME_DOMAIN: &str = "testanchor.stellar.org";

/// USDC SAC on testnet.
const USDC_TESTNET_SAC: &str = "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA";

/// Atomic amount: 0.0001 USDC = 1_000 atomic units (7 decimals).
///
/// Chosen to be small and unlikely to exceed any allowable range;
/// the test needs build→simulate but NOT on-chain submit.
const USDC_AMOUNT_ATOMIC: &str = "1000";

// ─────────────────────────────────────────────────────────────────────────────
// Helpers (mirrored from x402_create_payment_testnet_acceptance.rs)
// ─────────────────────────────────────────────────────────────────────────────

/// Generates a fresh ed25519 keypair using OS entropy.
///
/// Returns `(g_strkey, seed_bytes)`. Seed bytes are `Zeroizing`-wrapped so
/// they are zeroed on drop.
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
/// Returns `Ok(())` if funding succeeded (2xx from Friendbot).
/// Returns `Err(reason)` if the HTTP request failed or returned non-2xx.
/// Does NOT panic — callers decide whether to skip or fail.
async fn try_fund_via_friendbot(g_strkey: &str) -> Result<(), String> {
    let url = format!("{TESTNET_FRIENDBOT_URL}?addr={g_strkey}");
    let resp = stellar_agent_test_support::testnet_helpers::friendbot_funding_request(&url)
        .await
        .map_err(|e| format!("Friendbot GET failed: {e}"))?;
    if resp.status().is_success() {
        Ok(())
    } else {
        Err(format!(
            "Friendbot returned {} for {g_strkey}",
            resp.status()
        ))
    }
}

/// Builds a `PaymentRequirements` JSON string for the given `pay_to` address.
///
/// Uses `areFeesSponsored: true` (matches the create_payment test pattern).
fn usdc_testnet_requirements(pay_to: &str) -> String {
    serde_json::json!({
        "scheme": "exact",
        "network": "stellar:testnet",
        "asset": USDC_TESTNET_SAC,
        "amount": USDC_AMOUNT_ATOMIC,
        "payTo": pay_to,
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
        Profile::builder_testnet(signer_service, g_strkey, "x402-auth-nonce-svc", "default")
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
// NEGATIVE leg (always-runs, offline)
// Runs without testnet network (aborts before any successful fetch).
// ─────────────────────────────────────────────────────────────────────────────

/// Negative: unreachable domain aborts before payment.
///
/// `home_domain = "unreachable.stellar.invalid"` (LDH-valid, not listening)
/// must return `isError = true` with `error ==
/// "identity.home_domain_unresolvable"` and NO `paymentSignature`.
///
/// The gate aborts BEFORE `create_payment` is called — no transaction is
/// built/signed on failure (abort-before-payment contract).
///
/// This test has NO live-anchor / funding dependency: the domain is
/// unreachable by design (RFC 6761 `.invalid` → NXDOMAIN) and the identity
/// gate aborts immediately on the `stellar.toml` GET failing. (It is still
/// compiled under the file-level `testnet-acceptance` gate.)
#[tokio::test]
#[serial]
async fn a6f_neg1_unreachable_domain_aborts_before_payment() {
    let (g_strkey, seed) = fresh_keypair();
    // NOTE: No Friendbot funding — the gate aborts before any RPC call.
    let server = build_test_server(&g_strkey, &seed, "x402-auth-test-neg1");

    let requirements_json = usdc_testnet_requirements(&g_strkey);

    let result = server
        .call_stellar_x402_authenticated_payment(X402AuthenticatedPaymentArgs {
            payment_required: requirements_json,
            chain_id: TESTNET_CHAIN_ID.to_owned(),
            home_domain: "unreachable.stellar.invalid".to_owned(),
            address: None,
            approval_nonce: None,
            approval_attestation: None,
        })
        .await
        .expect("dispatch_gate must not raise ErrorData for a valid chain_id");

    // Must be an error result.
    assert_eq!(
        result.is_error,
        Some(true),
        "unreachable domain must return isError = true; got is_error = {:?}",
        result.is_error
    );

    let text = extract_text(result);
    let value: serde_json::Value =
        serde_json::from_str(&text).expect("error result must be valid JSON");

    // Error code must be the identity gate abort code — NOT an x402 error.
    // The business-error envelope nests the code at `error.code`.
    let error_code = value["error"]["code"]
        .as_str()
        .expect("error.code must be present and a string");
    assert_eq!(
        error_code, "identity.home_domain_unresolvable",
        "unreachable domain must abort with identity.home_domain_unresolvable; got: {value}"
    );

    // Abort-before-payment — no paymentSignature or authorization.
    assert!(
        value.get("paymentSignature").is_none(),
        "abort-before-payment: paymentSignature must NOT be present in the error response; got: {value:?}"
    );
    assert!(
        value.get("authorization").is_none(),
        "abort-before-payment: authorization must NOT be present in the error response; got: {value:?}"
    );

    eprintln!("PASS: unreachable domain aborts with error={error_code}, no paymentSignature");
}

/// Negative: invalid home_domain aborts before payment.
///
/// `home_domain = "UPPERCASE.COM"` (LDH-invalid — uppercase not permitted) must
/// return `isError = true` with `error == "identity.home_domain_invalid"` and
/// NO `paymentSignature`.
///
/// The gate aborts BEFORE any network I/O — `HomeDomainInvalid` is a caller-
/// input error (distinct from `HomeDomainUnresolvable`).
///
/// This test makes NO network contact (the LDH validator fires synchronously
/// before any HTTPS GET). It is still compiled under the file-level
/// `testnet-acceptance` gate.
#[tokio::test]
#[serial]
async fn a6f_neg2_invalid_home_domain_aborts_before_payment() {
    let (g_strkey, seed) = fresh_keypair();
    // NOTE: No Friendbot funding — the gate aborts before any network I/O.
    let server = build_test_server(&g_strkey, &seed, "x402-auth-test-neg2");

    let requirements_json = usdc_testnet_requirements(&g_strkey);

    let result = server
        .call_stellar_x402_authenticated_payment(X402AuthenticatedPaymentArgs {
            payment_required: requirements_json,
            chain_id: TESTNET_CHAIN_ID.to_owned(),
            home_domain: "UPPERCASE.COM".to_owned(), // uppercase LDH violation
            address: None,
            approval_nonce: None,
            approval_attestation: None,
        })
        .await
        .expect("dispatch_gate must not raise ErrorData for a valid chain_id");

    // Must be an error result.
    assert_eq!(
        result.is_error,
        Some(true),
        "invalid home_domain must return isError = true; got is_error = {:?}",
        result.is_error
    );

    let text = extract_text(result);
    let value: serde_json::Value =
        serde_json::from_str(&text).expect("error result must be valid JSON");

    // Error code must be the DISTINCT input-validation abort code.
    // The business-error envelope nests the code at `error.code`.
    let error_code = value["error"]["code"]
        .as_str()
        .expect("error.code must be present and a string");
    assert_eq!(
        error_code, "identity.home_domain_invalid",
        "invalid home_domain must abort with identity.home_domain_invalid (distinct from unresolvable); got: {value}"
    );

    // Abort-before-payment — no paymentSignature or authorization.
    assert!(
        value.get("paymentSignature").is_none(),
        "abort-before-payment: paymentSignature must NOT be present in the error response; got: {value:?}"
    );
    assert!(
        value.get("authorization").is_none(),
        "abort-before-payment: authorization must NOT be present in the error response; got: {value:?}"
    );

    // Also verify error codes are DISTINGUISHABLE from the unreachable-domain case.
    assert_ne!(
        error_code, "identity.home_domain_unresolvable",
        "invalid-domain error must be DISTINCT from unreachable-domain error"
    );

    eprintln!(
        "PASS: invalid home_domain aborts with error={error_code} (distinct from unresolvable), no paymentSignature"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// POSITIVE leg (testnet, gated)
// Requires live testanchor.stellar.org SEP-10 + live testnet RPC.
// ─────────────────────────────────────────────────────────────────────────────

/// Positive: full SEP-10 authenticated payment against testanchor.
///
/// Calls `stellar_x402_authenticated_payment` with `home_domain =
/// "testanchor.stellar.org"` and a native-SAC payment from a funded payer to
/// a distinct funded recipient. The production gate runs a real SEP-10
/// ephemeral challenge/response against testanchor, then `create_payment`
/// builds the payment against testnet RPC. The leg reads the response under
/// `data` and fails on any error.
#[tokio::test]
#[serial]
async fn a6f_positive_testanchor_sep10_authenticated_payment() {
    let (g_strkey, seed) = fresh_keypair();
    let (recipient, _recipient_seed) = fresh_keypair();
    try_fund_via_friendbot(&g_strkey)
        .await
        .unwrap_or_else(|reason| panic!("[UNAVAILABLE] payer funding: {reason}"));
    try_fund_via_friendbot(&recipient)
        .await
        .unwrap_or_else(|reason| panic!("[UNAVAILABLE] recipient funding: {reason}"));
    wait_until_visible(&g_strkey).await;
    wait_until_visible(&recipient).await;

    let server = build_test_server(&g_strkey, &seed, "x402-auth-test-positive");

    let (capture, _guard) = LedgerCapture::install();
    let result = server
        .call_stellar_x402_authenticated_payment(X402AuthenticatedPaymentArgs {
            payment_required: native_requirements(&recipient),
            chain_id: TESTNET_CHAIN_ID.to_owned(),
            home_domain: TESTANCHOR_HOME_DOMAIN.to_owned(),
            address: None,
            approval_nonce: None,
            approval_attestation: None,
        })
        .await
        .expect("dispatch_gate must not raise ErrorData for a valid chain_id");

    let is_err = result.is_error == Some(true);
    let text = extract_text(result);
    assert!(!is_err, "[FAIL] authenticated_payment errored: {text}");
    let value: serde_json::Value = serde_json::from_str(&text).expect("result must be valid JSON");
    assert_eq!(value["ok"], true, "{value}");
    let data = &value["data"];
    assert_eq!(data["payer"], g_strkey.as_str(), "{value}");
    assert_eq!(data["home_domain"], TESTANCHOR_HOME_DOMAIN, "{value}");
    assert_eq!(data["payTo"], recipient.as_str(), "{value}");
    assert_eq!(data["asset"], NATIVE_SAC_TESTNET, "{value}");
    assert_eq!(data["network"], "stellar:testnet", "{value}");
    assert!(data["payto_anchored"].is_string(), "{value}");

    let authorization = data["authorization"]
        .as_str()
        .unwrap_or_else(|| panic!("authorization must be a string: {value}"));
    let jwt_part = authorization
        .strip_prefix("Bearer ")
        .unwrap_or_else(|| panic!("authorization must start with 'Bearer ': {authorization}"));
    let segments: Vec<&str> = jwt_part.split('.').collect();
    assert_eq!(
        segments.len(),
        3,
        "JWT must have exactly 3 dot-separated segments"
    );
    for segment in &segments {
        assert!(
            !segment.is_empty()
                && segment
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
            "every JWT segment must be non-empty base64url: {jwt_part}"
        );
    }

    let payment_signature = data["paymentSignature"]
        .as_str()
        .unwrap_or_else(|| panic!("paymentSignature must be a string: {value}"));
    let (payload, entries) = decode_payment(payment_signature);
    assert_eq!(payload.x402_version, 2, "x402Version must be 2");
    assert_eq!(payload.accepted.scheme, "exact");
    let expiration = capture.check_and_record("a6f authenticated_payment");
    assert_payer_authorization(
        "a6f authenticated_payment",
        &entries,
        &g_strkey,
        &recipient,
        expiration,
    );
    eprintln!(
        "PASS: SEP-10 session with {TESTANCHOR_HOME_DOMAIN} and the payer's verified authorization"
    );
}
