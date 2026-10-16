//! Testnet acceptance tests for the x402 Exact Stellar scheme.
//!
//! These tests require a live testnet RPC endpoint and Friendbot access. They
//! are gated behind the `testnet-acceptance` feature flag:
//!
//! ```text
//! cargo test -p stellar-agent-x402 --features testnet-acceptance \
//!   --test x402_exact_testnet_acceptance -- --test-threads=1 --nocapture
//! ```
//!
//! Under default `cargo test` (no `--features testnet-acceptance`), this file
//! compiles but all tests are compiled-out via `#[cfg(feature = "testnet-acceptance")]`.
//! Offline request-validation cases (bad scheme/network/asset/amount/fees) live
//! in `tests/exact_validation.rs` and run without the network.
//!
//! # Asset choice
//!
//! The legs here transfer the native asset through its Stellar Asset Contract
//! (SAC). A Friendbot-funded account always holds native balance, so every leg
//! reaches a signed payment, and the submit leg reaches ledger inclusion,
//! without a trustline. The construct/sign path is asset-agnostic; the same
//! flow applies to any SEP-41 token (e.g. a USDC SAC) once the payer holds it.
//!
//! # Acceptance criteria
//!
//! - **Construct + sign.** `create_payment` returns a `PaymentPayload` whose
//!   transaction carries exactly one authorization entry, the payer's, for
//!   `transfer(payer, recipient, amount)` on the native SAC. Its signature
//!   verifies, and it expires sixty ledgers after the simulation's ledger.
//! - **Submit + confirm.** A facilitator account distinct from the payer and
//!   the recipient re-sources the payment, refreshes its resource data, and
//!   submits it. It reaches ledger inclusion, and the payer and the recipient
//!   balances change by exactly the amount.
//!
//! Every leg records the endpoint's protocol version and the ledgers the
//! payment checked: the simulation's `L`, the health read's `H`, and the
//! re-simulation's `R`. They come from the payment's own debug event.
//!
//! # No skips
//!
//! A leg that cannot reach testnet fails. An outage makes acceptance
//! unavailable; it never counts as a passing leg.
//!
//! # Test isolation
//!
//! Fresh ed25519 keypairs are generated per test run using `rand_core::OsRng`
//! and funded via Friendbot before use. No pre-committed secret key material
//! appears in source.
//!
//! # Serial execution
//!
//! Tests are serialised via `#[serial]` so concurrent runs do not contend on
//! shared process-global state.

#![cfg(feature = "testnet-acceptance")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    reason = "test-only; panics, unwraps, and eprintln are acceptable in testnet acceptance tests"
)]

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use serial_test::serial;
use stellar_agent_network::signing::SoftwareSigningKey;
use stellar_agent_network::signing::envelope_signing::attach_signature;
use stellar_agent_network::{
    SUPPORTED_PROTOCOL_VERSIONS, StellarRpcClient, fetch_account, redact_tx_hash,
    submit_transaction_and_wait,
};
use stellar_agent_x402::constants::X402_STELLAR_TESTNET;
use stellar_agent_x402::exact::create_payment;
use stellar_agent_x402::wire::{PaymentPayload, PaymentRequirements};
use stellar_xdr::{
    AccountId, ContractId, Hash, Int128Parts, InvokeContractArgs, Limits, MuxedAccount,
    OperationBody, PublicKey, ReadXdr, ScAddress, ScSymbol, ScVal, SequenceNumber,
    SorobanAuthorizationEntry, SorobanAuthorizedFunction, SorobanCredentials, TransactionEnvelope,
    TransactionExt, Uint256, WriteXdr,
};
use tracing_subscriber::layer::SubscriberExt as _;
use zeroize::Zeroizing;

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

const TESTNET_RPC_URL: &str = "https://soroban-testnet.stellar.org";
const TESTNET_FRIENDBOT_URL: &str = "https://friendbot.stellar.org";
const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";

/// Native-asset Stellar Asset Contract address on testnet.
///
/// Derived from the testnet network passphrase via the native-asset SAC ID
/// scheme; a Friendbot-funded account always holds native balance here, so a
/// SAC `transfer` of native is submittable without a trustline.
const NATIVE_SAC_TESTNET: &str = "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC";

/// Atomic transfer amount: 0.1 native units (1 unit = 10_000_000 stroops).
const TRANSFER_AMOUNT_STROOPS: i64 = 1_000_000;

/// Signature window of a 300-second requirement, in ledgers.
const WINDOW_LEDGERS: u64 = 60;

/// Deadline of the endpoint identity check and the health read.
const IDENTITY_TIMEOUT: Duration = Duration::from_secs(60);

/// Base fee of the facilitator's settlement envelope, in stroops.
const SETTLEMENT_BASE_FEE: u32 = 100;

// ─────────────────────────────────────────────────────────────────────────────
// Accounts
// ─────────────────────────────────────────────────────────────────────────────

/// A funded testnet account.
struct Funded {
    address: String,
    seed: Zeroizing<[u8; 32]>,
}

impl Funded {
    /// Generates a fresh keypair from OS entropy and funds it via Friendbot.
    ///
    /// Panics when Friendbot does not fund it: acceptance is then unavailable.
    async fn new(role: &str) -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let address: String =
            stellar_strkey::ed25519::PublicKey(signing_key.verifying_key().to_bytes())
                .to_string()
                .as_str()
                .to_owned();
        let url = format!("{TESTNET_FRIENDBOT_URL}?addr={address}");
        let resp = stellar_agent_test_support::testnet_helpers::friendbot_funding_request(&url)
            .await
            .unwrap_or_else(|e| panic!("[UNAVAILABLE] Friendbot unreachable for the {role}: {e}"));
        assert!(
            resp.status().is_success(),
            "[UNAVAILABLE] Friendbot returned {} for the {role}",
            resp.status()
        );
        Self {
            address,
            seed: Zeroizing::new(signing_key.to_bytes()),
        }
    }

    fn signer(&self) -> SoftwareSigningKey {
        SoftwareSigningKey::new_from_zeroizing(self.seed.clone())
    }

    fn public_key(&self) -> [u8; 32] {
        stellar_strkey::ed25519::PublicKey::from_string(&self.address)
            .expect("a G-strkey")
            .0
    }

    fn sc_address(&self) -> ScAddress {
        ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(
            self.public_key(),
        ))))
    }
}

/// The native balance of `account` in stroops, once the account is visible.
async fn native_balance(rpc: &StellarRpcClient, account: &str) -> i64 {
    for _ in 0..20 {
        if let Ok(view) = fetch_account(rpc, account, &[]).await {
            let native = view
                .balances
                .iter()
                .find(|balance| balance.asset.asset_type == "native")
                .expect("every account holds native balance");
            return native
                .balance
                .replace('.', "")
                .parse()
                .expect("a 7-decimal balance");
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    panic!("[UNAVAILABLE] account {account} is not visible on the endpoint");
}

/// Native-SAC transfer requirements paying `pay_to`.
fn native_testnet_requirements(pay_to: &str) -> PaymentRequirements {
    PaymentRequirements {
        scheme: "exact".to_owned(),
        network: X402_STELLAR_TESTNET.to_owned(),
        asset: NATIVE_SAC_TESTNET.to_owned(),
        amount: TRANSFER_AMOUNT_STROOPS.to_string(),
        pay_to: pay_to.to_owned(),
        max_timeout_seconds: 300,
        extra: serde_json::json!({ "areFeesSponsored": true }),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Ledger capture
// ─────────────────────────────────────────────────────────────────────────────

/// The numeric fields of every `create_payment` event that names the
/// re-simulation ledger.
#[derive(Clone, Default)]
struct LedgerCapture(Arc<Mutex<Vec<BTreeMap<String, u64>>>>);

struct NumericFields(BTreeMap<String, u64>);

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
        let mut fields = NumericFields(BTreeMap::new());
        event.record(&mut fields);
        if fields.0.contains_key("resimulation_ledger") {
            self.0.lock().unwrap().push(fields.0);
        }
    }
}

/// The endpoint protocol and the ledgers one payment checked.
#[derive(Debug)]
struct PaymentLedgers {
    protocol_version: u64,
    simulation: u64,
    health: u64,
    resimulation: u64,
    expiration: u64,
}

impl LedgerCapture {
    /// Captures `create_payment` events on this thread until the guard drops.
    fn install() -> (Self, tracing::subscriber::DefaultGuard) {
        let capture = Self::default();
        let guard =
            tracing::subscriber::set_default(tracing_subscriber::registry().with(capture.clone()));
        tracing::callsite::rebuild_interest_cache();
        (capture, guard)
    }

    /// The ledgers of the one payment captured.
    fn single(&self) -> PaymentLedgers {
        let events = self.0.lock().unwrap();
        let [fields] = events.as_slice() else {
            panic!("one payment event, got {}", events.len());
        };
        let field = |name: &str| *fields.get(name).unwrap_or_else(|| panic!("{name}"));
        PaymentLedgers {
            protocol_version: field("protocol_version"),
            simulation: field("simulation_ledger"),
            health: field("health_ledger"),
            resimulation: field("resimulation_ledger"),
            expiration: field("signature_expiration_ledger"),
        }
    }
}

/// Asserts the ledger bounds of `ledgers` and records them.
fn check_and_record(leg: &str, ledgers: &PaymentLedgers) {
    eprintln!(
        "[{leg}] protocol {} L={} H={} R={} E={}",
        ledgers.protocol_version,
        ledgers.simulation,
        ledgers.health,
        ledgers.resimulation,
        ledgers.expiration
    );
    assert!(
        SUPPORTED_PROTOCOL_VERSIONS.contains(&u32::try_from(ledgers.protocol_version).unwrap()),
        "[{leg}] acceptance evidence needs a supported protocol, got {}",
        ledgers.protocol_version
    );
    assert_eq!(
        ledgers.expiration,
        ledgers.simulation + WINDOW_LEDGERS,
        "[{leg}] the window is sixty ledgers"
    );
    assert!(ledgers.simulation > 0, "[{leg}]");
    assert!(ledgers.simulation <= ledgers.health + 1, "[{leg}]");
    assert!(ledgers.health < ledgers.expiration, "[{leg}]");
    assert!(ledgers.health <= ledgers.resimulation + 1, "[{leg}]");
    assert!(ledgers.resimulation < ledgers.expiration, "[{leg}]");
}

// ─────────────────────────────────────────────────────────────────────────────
// Payload inspection
// ─────────────────────────────────────────────────────────────────────────────

/// The decoded envelope of a payment payload.
fn payment_envelope(payload: &PaymentPayload) -> TransactionEnvelope {
    TransactionEnvelope::from_xdr_base64(&payload.payload.transaction, Limits::none())
        .expect("the payment transaction decodes to a TransactionEnvelope")
}

/// The authorization entries of the envelope's one `InvokeHostFunction`.
fn auth_entries(envelope: &TransactionEnvelope) -> Vec<SorobanAuthorizationEntry> {
    let TransactionEnvelope::Tx(transaction) = envelope else {
        panic!("the payment is a v1 envelope");
    };
    let [operation] = transaction.tx.operations.as_slice() else {
        panic!("the payment carries one operation");
    };
    let OperationBody::InvokeHostFunction(host) = &operation.body else {
        panic!("the payment operation is InvokeHostFunction");
    };
    host.auth.to_vec()
}

/// `transfer(payer, recipient, amount)` on the native SAC.
fn expected_transfer(payer: &Funded, recipient: &Funded) -> InvokeContractArgs {
    let contract = stellar_strkey::Contract::from_string(NATIVE_SAC_TESTNET).unwrap();
    InvokeContractArgs {
        contract_address: ScAddress::Contract(ContractId(Hash(contract.0))),
        function_name: ScSymbol("transfer".try_into().unwrap()),
        args: vec![
            ScVal::Address(payer.sc_address()),
            ScVal::Address(recipient.sc_address()),
            ScVal::I128(Int128Parts {
                hi: 0,
                lo: u64::try_from(TRANSFER_AMOUNT_STROOPS).unwrap(),
            }),
        ]
        .try_into()
        .unwrap(),
    }
}

/// Asserts that `entries` is exactly the payer's signed authorization of the
/// expected transfer, expiring at `expiration`, with a signature that
/// verifies; and that a corrupted copy does not verify.
fn assert_payer_authorization(
    leg: &str,
    entries: &[SorobanAuthorizationEntry],
    payer: &Funded,
    recipient: &Funded,
    expiration: u64,
) {
    let [entry] = entries else {
        panic!("[{leg}] one authorization entry, got {}", entries.len());
    };
    let SorobanCredentials::Address(credentials) = &entry.credentials else {
        panic!("[{leg}] the entry carries Address credentials");
    };
    assert_eq!(credentials.address, payer.sc_address(), "[{leg}]");
    assert_eq!(
        u64::from(credentials.signature_expiration_ledger),
        expiration,
        "[{leg}]"
    );
    assert_eq!(
        entry.root_invocation.function,
        SorobanAuthorizedFunction::ContractFn(expected_transfer(payer, recipient)),
        "[{leg}] the payer signs the expected transfer"
    );
    assert!(
        entry.root_invocation.sub_invocations.is_empty(),
        "[{leg}] no nested calls"
    );
    assert!(
        verify_auth_entry_signature(entry, &payer.public_key(), TESTNET_PASSPHRASE),
        "[{leg}] the payer's signature verifies"
    );
    let mut corrupted = entry.clone();
    if let SorobanCredentials::Address(credentials) = &mut corrupted.credentials {
        credentials.signature_expiration_ledger += 1;
    }
    assert!(
        !verify_auth_entry_signature(&corrupted, &payer.public_key(), TESTNET_PASSPHRASE),
        "[{leg}] a corrupted entry must not verify"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Construct + sign + re-simulate
// ─────────────────────────────────────────────────────────────────────────────

/// Construct + sign: `create_payment` returns the payer's signed authorization
/// of exactly the native-SAC transfer to a distinct recipient, within the
/// ledger bounds.
#[tokio::test]
#[serial]
async fn construct_sign_resimulate_happy_path() {
    let payer = Funded::new("payer").await;
    let recipient = Funded::new("recipient").await;
    let rpc = StellarRpcClient::new(TESTNET_RPC_URL).expect("RPC client construction");
    native_balance(&rpc, &payer.address).await;
    native_balance(&rpc, &recipient.address).await;

    // The payment gets a client of its own: its first request is the
    // endpoint identity check, as on every host path.
    let payment_client = StellarRpcClient::new(TESTNET_RPC_URL).expect("RPC client construction");
    let (capture, _guard) = LedgerCapture::install();
    let payload = create_payment(
        &native_testnet_requirements(&recipient.address),
        &payer.signer(),
        &payment_client,
        TESTNET_PASSPHRASE,
        tokio::time::Instant::now() + IDENTITY_TIMEOUT,
        |_| Ok(()),
    )
    .await
    .unwrap_or_else(|e| panic!("[construct/sign FAIL] create_payment: {e}"));

    assert_eq!(payload.x402_version, 2, "x402Version must be 2");
    assert_eq!(payload.accepted.scheme, "exact");
    assert_eq!(payload.accepted.network, X402_STELLAR_TESTNET);
    let ledgers = capture.single();
    check_and_record("construct/sign", &ledgers);
    assert_payer_authorization(
        "construct/sign",
        &auth_entries(&payment_envelope(&payload)),
        &payer,
        &recipient,
        ledgers.expiration,
    );
    eprintln!("[construct/sign PASS] one verified payer authorization");
}

// ─────────────────────────────────────────────────────────────────────────────
// Submit + confirm
// ─────────────────────────────────────────────────────────────────────────────

/// Submit + confirm: a facilitator settles the payment, and the payer and the
/// recipient balances change by exactly the amount.
///
/// `create_payment` produces a payload whose transaction carries a placeholder
/// source. The facilitator re-sources it to its own account, refreshes the
/// resource data and fee with a simulation of the re-sourced envelope, signs
/// the envelope, and submits. The payer's `Address` authorization is signed
/// over a preimage that excludes the transaction source, so it stays valid.
#[tokio::test]
#[serial]
async fn submit_to_testnet_reaches_ledger() {
    let payer = Funded::new("payer").await;
    let recipient = Funded::new("recipient").await;
    let facilitator = Funded::new("facilitator").await;
    assert_ne!(
        payer.address, recipient.address,
        "distinct payer and recipient"
    );
    assert_ne!(
        payer.address, facilitator.address,
        "distinct payer and facilitator"
    );
    assert_ne!(
        recipient.address, facilitator.address,
        "distinct recipient and facilitator"
    );
    let rpc = StellarRpcClient::new(TESTNET_RPC_URL).expect("RPC client construction");
    let payer_before = native_balance(&rpc, &payer.address).await;
    let recipient_before = native_balance(&rpc, &recipient.address).await;
    let facilitator_before = native_balance(&rpc, &facilitator.address).await;

    // The payment gets a client of its own: its first request is the
    // endpoint identity check, as on every host path. The setup reads and the
    // settlement use the harness client.
    let payment_client = StellarRpcClient::new(TESTNET_RPC_URL).expect("RPC client construction");
    let (capture, _guard) = LedgerCapture::install();
    let payload = create_payment(
        &native_testnet_requirements(&recipient.address),
        &payer.signer(),
        &payment_client,
        TESTNET_PASSPHRASE,
        tokio::time::Instant::now() + IDENTITY_TIMEOUT,
        |_| Ok(()),
    )
    .await
    .unwrap_or_else(|e| panic!("[submit/confirm FAIL] create_payment: {e}"));
    let ledgers = capture.single();
    check_and_record("submit/confirm", &ledgers);
    let signed_entries = auth_entries(&payment_envelope(&payload));
    assert_payer_authorization(
        "submit/confirm",
        &signed_entries,
        &payer,
        &recipient,
        ledgers.expiration,
    );

    // The facilitator re-sources the transaction to its own account.
    let mut envelope = payment_envelope(&payload);
    let facilitator_view = fetch_account(&rpc, &facilitator.address, &[])
        .await
        .expect("facilitator account fetch");
    let TransactionEnvelope::Tx(transaction) = &mut envelope else {
        panic!("[submit/confirm FAIL] expected a V1 transaction envelope");
    };
    transaction.tx.source_account = MuxedAccount::Ed25519(Uint256(facilitator.public_key()));
    transaction.tx.seq_num = SequenceNumber(facilitator_view.sequence_number + 1);

    // It refreshes the resource data and the fee for the re-sourced envelope.
    let refreshed = rpc
        .simulate_transaction_envelope(&envelope)
        .await
        .expect("[submit/confirm FAIL] the settlement simulation request");
    assert!(
        refreshed.error.is_none(),
        "[submit/confirm FAIL] the settlement simulation: {:?}",
        refreshed.error
    );
    assert!(
        refreshed.restore_preamble.is_none(),
        "[submit/confirm FAIL] the settlement needs no restoration"
    );
    let data = refreshed
        .transaction_data()
        .expect("[submit/confirm FAIL] the settlement transaction data decodes");
    let resource_fee = u32::try_from(refreshed.min_resource_fee).expect("a u32 resource fee");
    let TransactionEnvelope::Tx(transaction) = &mut envelope else {
        panic!("[submit/confirm FAIL] expected a V1 transaction envelope");
    };
    transaction.tx.ext = TransactionExt::V1(data);
    transaction.tx.fee = SETTLEMENT_BASE_FEE + resource_fee;
    assert_eq!(
        auth_entries(&envelope),
        signed_entries,
        "the settlement keeps the payer's authorization unchanged"
    );

    let unsigned_xdr = envelope
        .to_xdr_base64(Limits::none())
        .expect("re-sourced envelope encodes");
    let signed_xdr = attach_signature(&unsigned_xdr, &facilitator.signer(), TESTNET_PASSPHRASE)
        .await
        .expect("[submit/confirm FAIL] facilitator signing");
    let submission = submit_transaction_and_wait(
        &rpc,
        &signed_xdr,
        Duration::from_secs(60),
        TESTNET_PASSPHRASE,
        None,
        None,
    )
    .await
    .expect("[submit/confirm FAIL] submit-and-confirm must reach ledger inclusion");
    assert!(submission.ledger > 0, "submission.ledger must be > 0");

    let payer_after = native_balance(&rpc, &payer.address).await;
    let recipient_after = native_balance(&rpc, &recipient.address).await;
    let facilitator_after = native_balance(&rpc, &facilitator.address).await;
    assert_eq!(
        payer_before - payer_after,
        TRANSFER_AMOUNT_STROOPS,
        "the payer pays exactly the amount and no fee"
    );
    assert_eq!(
        recipient_after - recipient_before,
        TRANSFER_AMOUNT_STROOPS,
        "the recipient receives exactly the amount"
    );
    assert!(
        facilitator_after < facilitator_before,
        "the facilitator pays the transaction fee"
    );
    eprintln!(
        "[submit/confirm PASS] settled in ledger {}; tx_hash prefix = {}",
        submission.ledger,
        redact_tx_hash(&submission.tx_hash),
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Signature verification
// ─────────────────────────────────────────────────────────────────────────────

/// Verifies that an `Address`-credentialled auth entry carries a valid ed25519
/// signature over its reconstructed `HashIdPreimage::SorobanAuthorization`.
fn verify_auth_entry_signature(
    entry: &SorobanAuthorizationEntry,
    payer_pubkey: &[u8; 32],
    passphrase: &str,
) -> bool {
    use sha2::{Digest, Sha256};
    use stellar_xdr::{HashIdPreimage, HashIdPreimageSorobanAuthorization};

    let SorobanCredentials::Address(creds) = &entry.credentials else {
        return false;
    };
    let network_id = Hash(Sha256::digest(passphrase.as_bytes()).into());
    let preimage = HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
        network_id,
        nonce: creds.nonce,
        signature_expiration_ledger: creds.signature_expiration_ledger,
        invocation: entry.root_invocation.clone(),
    });
    let Ok(preimage_bytes) = preimage.to_xdr(Limits::none()) else {
        return false;
    };
    let digest: [u8; 32] = Sha256::digest(&preimage_bytes).into();

    let Some(sig_bytes) = extract_signature_bytes(&creds.signature) else {
        return false;
    };
    let Ok(verifying_key) = ed25519_dalek::VerifyingKey::from_bytes(payer_pubkey) else {
        return false;
    };
    let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    verifying_key.verify_strict(&digest, &signature).is_ok()
}

/// Extracts the 64-byte ed25519 signature from the classic-account signature
/// ScVal `Vec([Map{public_key, signature}])`.
fn extract_signature_bytes(sig: &ScVal) -> Option<[u8; 64]> {
    let ScVal::Vec(Some(outer)) = sig else {
        return None;
    };
    let ScVal::Map(Some(map)) = outer.first()? else {
        return None;
    };
    for entry in map.iter() {
        if let ScVal::Symbol(key) = &entry.key
            && key.0.to_utf8_string_lossy() == "signature"
            && let ScVal::Bytes(bytes) = &entry.val
        {
            return bytes.0.as_slice().try_into().ok();
        }
    }
    None
}
