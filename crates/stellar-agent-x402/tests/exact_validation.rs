//! Offline validation tests for `create_payment`.
//!
//! These exercise the request validation that `create_payment` performs before
//! any RPC contact: scheme, network, mainnet refusal, asset, fee-sponsorship,
//! amount, recipient, and timeout checks all reject their input before the
//! first request on the caller's client. They run under the default
//! `cargo test` with no network access and no feature flag; the mainnet cases
//! count connections on a loopback listener. Every case passes a transmit gate
//! that records a call and refuses, and asserts the gate never ran: no
//! signature exists on these paths.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; unwraps and panics acceptable in unit tests"
)]

use std::sync::atomic::{AtomicBool, Ordering};

use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use stellar_agent_network::StellarRpcClient;
use stellar_agent_network::cross_check::SorobanCrossCheck;
use stellar_agent_network::signing::SoftwareSigningKey;
use stellar_agent_x402::X402Error;
use stellar_agent_x402::constants::X402_STELLAR_TESTNET;
use stellar_agent_x402::exact::{AuthorizationToTransmit, create_payment, validate_requirements};
use stellar_agent_x402::wire::{PaymentPayload, PaymentRequirements};
use zeroize::Zeroizing;

const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";

/// Loopback address that is never contacted: every case here returns in
/// validation before the first request on the client.
const UNUSED_RPC_URL: &str = "http://127.0.0.1:1";

/// Native-asset SAC on testnet (a structurally valid C-strkey; never reached).
const NATIVE_SAC_TESTNET: &str = "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC";

/// Structurally valid G-strkey for the `pay_to` field (not validated here).
const PAYER: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";

const AMOUNT: &str = "1000000";

/// Builds an ephemeral signer; never used by these tests because validation
/// returns before the signer is queried, but `create_payment` requires one.
fn dummy_signer() -> SoftwareSigningKey {
    let sk = SigningKey::generate(&mut OsRng);
    SoftwareSigningKey::new_from_zeroizing(Zeroizing::new(sk.to_bytes()))
}

/// A transmit gate that records being called and refuses. Validation returns
/// before any signature exists, so a case that sees `called` set has failed.
fn gate_that_must_not_run(
    called: &AtomicBool,
) -> impl FnOnce(&AuthorizationToTransmit<'_>) -> Result<(), X402Error> + '_ {
    move |_| {
        called.store(true, Ordering::SeqCst);
        Err(X402Error::TransmitGateRefused {
            detail: "the transmit gate must not run on a validation refusal".to_owned(),
        })
    }
}

/// Runs `create_payment` on a fresh client for `rpc_url` under
/// `profile_passphrase`, with a gate that must not run.
async fn pay(
    requirements: &PaymentRequirements,
    rpc_url: &str,
    profile_passphrase: &str,
    called: &AtomicBool,
) -> Result<PaymentPayload, X402Error> {
    let client = StellarRpcClient::new(rpc_url).unwrap();
    create_payment(
        requirements,
        &dummy_signer(),
        &client,
        &SorobanCrossCheck::NotRequired,
        profile_passphrase,
        tokio::time::Instant::now() + std::time::Duration::from_secs(60),
        gate_that_must_not_run(called),
    )
    .await
    .map(|created| created.payload)
}

fn assert_gate_never_ran(called: &AtomicBool) {
    assert!(
        !called.load(Ordering::SeqCst),
        "the transmit gate ran on a path that returns before signing"
    );
}

fn requirements_with(
    scheme: &str,
    network: &str,
    amount: &str,
    fees_sponsored: serde_json::Value,
) -> PaymentRequirements {
    let mut extra = serde_json::Map::new();
    extra.insert("areFeesSponsored".to_owned(), fees_sponsored);
    PaymentRequirements {
        scheme: scheme.to_owned(),
        network: network.to_owned(),
        asset: NATIVE_SAC_TESTNET.to_owned(),
        amount: amount.to_owned(),
        pay_to: PAYER.to_owned(),
        max_timeout_seconds: 300,
        extra: serde_json::Value::Object(extra),
    }
}

/// Invalid scheme is rejected with `UnsupportedScheme`.
#[tokio::test]
async fn invalid_scheme_rejected() {
    let req = requirements_with("upto", X402_STELLAR_TESTNET, AMOUNT, true.into());
    let called = AtomicBool::new(false);
    let r = pay(&req, UNUSED_RPC_URL, TESTNET_PASSPHRASE, &called).await;
    assert_gate_never_ran(&called);
    assert!(
        matches!(r, Err(X402Error::UnsupportedScheme { .. })),
        "expected UnsupportedScheme, got {r:?}"
    );
}

/// `"stellar:mainnet"` is the internal CAIP-2 string, not a valid x402 wire
/// network (the x402 wire uses `"stellar:pubnet"`).
#[tokio::test]
async fn stellar_mainnet_rejected_as_invalid_x402_network() {
    let req = requirements_with("exact", "stellar:mainnet", AMOUNT, true.into());
    let called = AtomicBool::new(false);
    let r = pay(&req, UNUSED_RPC_URL, TESTNET_PASSPHRASE, &called).await;
    assert_gate_never_ran(&called);
    assert!(
        matches!(r, Err(X402Error::UnsupportedNetwork { .. })),
        "expected UnsupportedNetwork, got {r:?}"
    );
}

/// A network passphrase that disagrees with the wire network is rejected.
#[tokio::test]
async fn wrong_network_passphrase_rejected() {
    let req = requirements_with("exact", X402_STELLAR_TESTNET, AMOUNT, true.into());
    let called = AtomicBool::new(false);
    // The mainnet passphrase as the profile's.
    let r = pay(
        &req,
        UNUSED_RPC_URL,
        "Public Global Stellar Network ; September 2015",
        &called,
    )
    .await;
    assert_gate_never_ran(&called);
    assert!(
        matches!(r, Err(X402Error::NetworkPassphraseMismatch { .. })),
        "expected NetworkPassphraseMismatch, got {r:?}"
    );
}

/// An asset that is not a C-strkey is rejected with `InvalidAssetAddress`.
#[tokio::test]
async fn invalid_asset_address_rejected() {
    let mut req = requirements_with("exact", X402_STELLAR_TESTNET, AMOUNT, true.into());
    req.asset = "not-a-strkey".to_owned();
    let called = AtomicBool::new(false);
    let r = pay(&req, UNUSED_RPC_URL, TESTNET_PASSPHRASE, &called).await;
    assert_gate_never_ran(&called);
    assert!(
        matches!(r, Err(X402Error::InvalidAssetAddress { .. })),
        "expected InvalidAssetAddress, got {r:?}"
    );
}

/// `areFeesSponsored != true` is rejected with `FeesNotSponsored`.
#[tokio::test]
async fn fees_not_sponsored_rejected() {
    let req = requirements_with("exact", X402_STELLAR_TESTNET, AMOUNT, false.into());
    let called = AtomicBool::new(false);
    let r = pay(&req, UNUSED_RPC_URL, TESTNET_PASSPHRASE, &called).await;
    assert_gate_never_ran(&called);
    assert!(
        matches!(r, Err(X402Error::FeesNotSponsored)),
        "expected FeesNotSponsored, got {r:?}"
    );
}

/// A non-strict `areFeesSponsored` (the JSON string `"true"`) is rejected: the
/// scheme requires the strict JSON boolean `true`.
#[tokio::test]
async fn fees_sponsored_string_true_rejected() {
    let req = requirements_with("exact", X402_STELLAR_TESTNET, AMOUNT, "true".into());
    let called = AtomicBool::new(false);
    let r = pay(&req, UNUSED_RPC_URL, TESTNET_PASSPHRASE, &called).await;
    assert_gate_never_ran(&called);
    assert!(
        matches!(r, Err(X402Error::FeesNotSponsored)),
        "expected FeesNotSponsored for string \"true\", got {r:?}"
    );
}

/// `amount = 0` is rejected (zero is not a positive integer).
#[tokio::test]
async fn amount_zero_rejected() {
    let req = requirements_with("exact", X402_STELLAR_TESTNET, "0", true.into());
    let called = AtomicBool::new(false);
    let r = pay(&req, UNUSED_RPC_URL, TESTNET_PASSPHRASE, &called).await;
    assert_gate_never_ran(&called);
    assert!(
        matches!(r, Err(X402Error::AmountConversion { .. })),
        "expected AmountConversion for amount=0, got {r:?}"
    );
}

/// A negative amount is rejected.
#[tokio::test]
async fn negative_amount_rejected() {
    let req = requirements_with("exact", X402_STELLAR_TESTNET, "-1000000", true.into());
    let called = AtomicBool::new(false);
    let r = pay(&req, UNUSED_RPC_URL, TESTNET_PASSPHRASE, &called).await;
    assert_gate_never_ran(&called);
    assert!(
        matches!(r, Err(X402Error::AmountConversion { .. })),
        "expected AmountConversion for negative amount, got {r:?}"
    );
}

/// A non-integer amount string is rejected.
#[tokio::test]
async fn non_integer_amount_rejected() {
    let req = requirements_with("exact", X402_STELLAR_TESTNET, "1.5", true.into());
    let called = AtomicBool::new(false);
    let r = pay(&req, UNUSED_RPC_URL, TESTNET_PASSPHRASE, &called).await;
    assert_gate_never_ran(&called);
    assert!(
        matches!(r, Err(X402Error::AmountConversion { .. })),
        "expected AmountConversion for non-integer amount, got {r:?}"
    );
}

/// A `payTo` that is not a G-, C-, or M-strkey is rejected with
/// `InvalidRecipientAddress`.
#[tokio::test]
async fn invalid_recipient_rejected() {
    let mut req = requirements_with("exact", X402_STELLAR_TESTNET, AMOUNT, true.into());
    req.pay_to = "not-a-strkey".to_owned();
    let called = AtomicBool::new(false);
    let r = pay(&req, UNUSED_RPC_URL, TESTNET_PASSPHRASE, &called).await;
    assert_gate_never_ran(&called);
    assert!(
        matches!(r, Err(X402Error::InvalidRecipientAddress { .. })),
        "expected InvalidRecipientAddress, got {r:?}"
    );
}

/// `maxTimeoutSeconds` of zero is rejected with `InvalidPaymentRequired`.
#[tokio::test]
async fn zero_max_timeout_rejected() {
    let mut req = requirements_with("exact", X402_STELLAR_TESTNET, AMOUNT, true.into());
    req.max_timeout_seconds = 0;
    let called = AtomicBool::new(false);
    let r = pay(&req, UNUSED_RPC_URL, TESTNET_PASSPHRASE, &called).await;
    assert_gate_never_ran(&called);
    assert!(
        matches!(&r, Err(X402Error::InvalidPaymentRequired { detail })
            if detail == "maxTimeoutSeconds must be at least 1"),
        "expected InvalidPaymentRequired, got {r:?}"
    );
}

/// `validate_requirements` returns the atomic amount of valid requirements,
/// accepts every recipient form and a timeout above 300 seconds, and refuses
/// each invalid field with the variant `create_payment` returns for it.
#[test]
fn validate_requirements_returns_the_amount_and_names_each_refusal() {
    let valid = requirements_with("exact", X402_STELLAR_TESTNET, AMOUNT, true.into());
    assert_eq!(
        validate_requirements(&valid, TESTNET_PASSPHRASE, UNUSED_RPC_URL).unwrap(),
        1_000_000
    );
    let muxed =
        stellar_strkey::Strkey::MuxedAccountEd25519(stellar_strkey::ed25519::MuxedAccount {
            ed25519: [0u8; 32],
            id: 7,
        })
        .to_string();
    for pay_to in [PAYER, NATIVE_SAC_TESTNET, muxed.as_str()] {
        let mut req = valid.clone();
        req.pay_to = pay_to.to_owned();
        assert!(
            validate_requirements(&req, TESTNET_PASSPHRASE, UNUSED_RPC_URL).is_ok(),
            "{pay_to}"
        );
    }
    let mut long = valid.clone();
    long.max_timeout_seconds = u32::MAX;
    assert!(validate_requirements(&long, TESTNET_PASSPHRASE, UNUSED_RPC_URL).is_ok());

    let wire_code = |edit: &dyn Fn(&mut PaymentRequirements)| {
        let mut req = valid.clone();
        edit(&mut req);
        validate_requirements(&req, TESTNET_PASSPHRASE, UNUSED_RPC_URL)
            .unwrap_err()
            .wire_code()
    };
    assert_eq!(
        wire_code(&|r| r.scheme = "upto".to_owned()),
        "x402.unsupported_scheme"
    );
    assert_eq!(
        wire_code(&|r| r.network = "stellar:mainnet".to_owned()),
        "x402.unsupported_network"
    );
    assert_eq!(
        wire_code(&|r| r.network = "stellar:pubnet".to_owned()),
        "x402.network_passphrase_mismatch"
    );
    assert_eq!(
        wire_code(&|r| r.asset = PAYER.to_owned()),
        "x402.invalid_asset_address"
    );
    assert_eq!(
        wire_code(&|r| r.extra = serde_json::json!({ "areFeesSponsored": "true" })),
        "x402.fees_not_sponsored"
    );
    assert_eq!(
        wire_code(&|r| r.amount = "0".to_owned()),
        "x402.amount_conversion"
    );
    assert_eq!(
        wire_code(&|r| r.pay_to = "not-a-strkey".to_owned()),
        "x402.invalid_recipient_address"
    );
    assert_eq!(
        wire_code(&|r| r.max_timeout_seconds = 0),
        "x402.invalid_payment_required"
    );
    let mainnet_url =
        validate_requirements(&valid, TESTNET_PASSPHRASE, "https://rpc.pubnet.example.org")
            .unwrap_err();
    assert_eq!(mainnet_url.wire_code(), "network.mainnet_write_forbidden");
}

// ── Mainnet refusal ──────────────────────────────────────────────────────────
//
// The endpoint is a loopback listener that counts and closes every
// connection, so a call that passed the refusal would connect at once and
// fail with another variant.

const MAINNET_PASSPHRASE: &str = "Public Global Stellar Network ; September 2015";

/// `stellar:pubnet` requirements under the mainnet profile passphrase are
/// refused with `MainnetSigningForbidden` before any signing call and any
/// connection.
#[tokio::test]
async fn pubnet_requirements_refused_before_signing_and_any_connection() {
    let counter = stellar_agent_test_support::ConnectionCounter::start().unwrap();
    let req = requirements_with(
        "exact",
        stellar_agent_x402::constants::X402_STELLAR_PUBNET,
        AMOUNT,
        true.into(),
    );
    let called = AtomicBool::new(false);
    let r = pay(&req, &counter.https_uri(), MAINNET_PASSPHRASE, &called).await;
    assert_gate_never_ran(&called);
    assert!(
        matches!(&r, Err(X402Error::MainnetSigningForbidden { detail })
            if detail.contains("network.mainnet_write_forbidden")),
        "expected MainnetSigningForbidden carrying the canonical code, got {r:?}"
    );
    assert_eq!(
        r.unwrap_err().wire_code(),
        "network.mainnet_write_forbidden"
    );
    assert_eq!(
        counter.accepted().unwrap(),
        0,
        "a refused mainnet payment must open no connection"
    );
}

/// Testnet requirements under the testnet passphrase, with a mainnet-pattern
/// RPC URL on the same listener, are refused the same way.
#[tokio::test]
async fn mainnet_pattern_rpc_url_refused_before_signing_and_any_connection() {
    let counter = stellar_agent_test_support::ConnectionCounter::start().unwrap();
    let req = requirements_with("exact", X402_STELLAR_TESTNET, AMOUNT, true.into());
    let rpc_url = format!("{}/pubnet", counter.https_uri());
    let called = AtomicBool::new(false);
    let r = pay(&req, &rpc_url, TESTNET_PASSPHRASE, &called).await;
    assert_gate_never_ran(&called);
    assert!(
        matches!(r, Err(X402Error::MainnetSigningForbidden { .. })),
        "expected MainnetSigningForbidden, got {r:?}"
    );
    assert_eq!(
        counter.accepted().unwrap(),
        0,
        "a refused mainnet payment must open no connection"
    );
}

// ── Network spellings ────────────────────────────────────────────────────────

/// The wallet's CAIP-2 `chain_id` and the x402 requirement `network` keep
/// their own spellings: `stellar:mainnet` is the wallet's mainnet and
/// `stellar:pubnet` the x402 one, and neither parser accepts the other's.
#[test]
fn wallet_chain_and_x402_network_spellings_stay_distinct() {
    use std::str::FromStr as _;

    use stellar_agent_core::profile::caip2::Caip2;
    use stellar_agent_x402::constants::x402_network_to_caip2;

    assert_eq!(Caip2::from_str("stellar:testnet").unwrap(), Caip2::Testnet);
    assert_eq!(Caip2::from_str("stellar:mainnet").unwrap(), Caip2::Mainnet);
    assert!(Caip2::from_str("stellar:pubnet").is_err());

    assert_eq!(
        x402_network_to_caip2("stellar:testnet").unwrap(),
        Caip2::Testnet
    );
    assert_eq!(
        x402_network_to_caip2("stellar:pubnet").unwrap(),
        Caip2::Mainnet
    );
    assert!(x402_network_to_caip2("stellar:mainnet").is_err());
}

/// A 402 value a hostile server could send: control and bidi characters, a
/// credential-bearing URL, quotes, and a thousand characters.
fn hostile_value() -> String {
    format!(
        "x\u{1b}[2J\u{202e} https://user:PWSECRET@leak.example/p?k=QSECRET \"q\" {}",
        "v".repeat(1000)
    )
}

/// Asserts that `text` holds `value` only in its quoted, escaped, bounded
/// form, and none of its raw characters or URL parts.
fn assert_holds_the_quoted_value(text: &str, value: &str) {
    let quoted = stellar_agent_network::quote_server_text(value);
    assert!(quoted.ends_with("\"..."), "the fixture exceeds the bound");
    assert!(
        quoted.starts_with(r#""x\u{001b}[2J\u{202e} leak.example \"q\" vvv"#),
        "{quoted}"
    );
    assert!(text.contains(&quoted), "{text}");
    for leaked in ["\u{1b}", "\u{202e}", "PWSECRET", "QSECRET", "https:", "/p?"] {
        assert!(!text.contains(leaked), "{leaked:?} survived: {text}");
    }
    assert!(!text.contains(&"v".repeat(300)), "{text}");
}

/// The rejected `scheme` and `network` values are stored quoted, escaped, and
/// bounded, and the error texts print them that way.
#[test]
fn scheme_and_network_values_are_quoted_and_bounded() {
    let value = hostile_value();

    let req = requirements_with(&value, X402_STELLAR_TESTNET, AMOUNT, true.into());
    let err = validate_requirements(&req, TESTNET_PASSPHRASE, UNUSED_RPC_URL).unwrap_err();
    let X402Error::UnsupportedScheme { scheme } = &err else {
        panic!("expected UnsupportedScheme, got {err:?}");
    };
    assert_eq!(scheme, &stellar_agent_network::quote_server_text(&value));
    assert_holds_the_quoted_value(&err.to_string(), &value);
    let debug = format!("{err:?}");
    for leaked in ["\u{1b}", "\u{202e}", "PWSECRET", "QSECRET"] {
        assert!(!debug.contains(leaked), "{leaked:?} survived: {debug}");
    }

    let req = requirements_with("exact", &value, AMOUNT, true.into());
    let err = validate_requirements(&req, TESTNET_PASSPHRASE, UNUSED_RPC_URL).unwrap_err();
    let X402Error::UnsupportedNetwork { network } = &err else {
        panic!("expected UnsupportedNetwork, got {err:?}");
    };
    assert_eq!(network, &stellar_agent_network::quote_server_text(&value));
    assert_holds_the_quoted_value(&err.to_string(), &value);
}

/// The `amount`, `asset`, and `payTo` values an error names appear quoted,
/// escaped, and bounded, without the decoded strkey's `Debug` form.
#[test]
fn amount_asset_and_pay_to_values_are_quoted_and_bounded() {
    let value = hostile_value();

    let req = requirements_with("exact", X402_STELLAR_TESTNET, &value, true.into());
    let err = validate_requirements(&req, TESTNET_PASSPHRASE, UNUSED_RPC_URL).unwrap_err();
    assert!(
        matches!(err, X402Error::AmountConversion { .. }),
        "expected AmountConversion, got {err:?}"
    );
    assert_holds_the_quoted_value(&err.to_string(), &value);

    let mut req = requirements_with("exact", X402_STELLAR_TESTNET, AMOUNT, true.into());
    req.asset = value.clone();
    let err = validate_requirements(&req, TESTNET_PASSPHRASE, UNUSED_RPC_URL).unwrap_err();
    assert!(
        matches!(err, X402Error::InvalidAssetAddress { .. }),
        "expected InvalidAssetAddress, got {err:?}"
    );
    assert_holds_the_quoted_value(&err.to_string(), &value);

    // A well-formed strkey of another type is named quoted, without the
    // decoded value's `Debug` form.
    let mut req = requirements_with("exact", X402_STELLAR_TESTNET, AMOUNT, true.into());
    req.asset = PAYER.to_owned();
    let err = validate_requirements(&req, TESTNET_PASSPHRASE, UNUSED_RPC_URL).unwrap_err();
    assert_eq!(
        err.to_string(),
        format!(
            "invalid SAC asset address: expected C-strkey (contract), got non-contract \
             strkey: \"{PAYER}\""
        )
    );

    let mut req = requirements_with("exact", X402_STELLAR_TESTNET, AMOUNT, true.into());
    req.pay_to = value.clone();
    let err = validate_requirements(&req, TESTNET_PASSPHRASE, UNUSED_RPC_URL).unwrap_err();
    assert!(
        matches!(err, X402Error::InvalidRecipientAddress { .. }),
        "expected InvalidRecipientAddress, got {err:?}"
    );
    assert_holds_the_quoted_value(&err.to_string(), &value);

    let pre_auth = stellar_strkey::Strkey::PreAuthTx(stellar_strkey::PreAuthTx([7u8; 32]))
        .to_string()
        .as_str()
        .to_owned();
    let mut req = requirements_with("exact", X402_STELLAR_TESTNET, AMOUNT, true.into());
    req.pay_to = pre_auth.clone();
    let err = validate_requirements(&req, TESTNET_PASSPHRASE, UNUSED_RPC_URL).unwrap_err();
    assert_eq!(
        err.to_string(),
        format!(
            "invalid recipient address: recipient strkey \"{pre_auth}\" is not a G-, C-, \
             or M-strkey"
        )
    );
}
