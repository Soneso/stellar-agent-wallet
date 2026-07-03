//! Offline validation tests for `create_payment`.
//!
//! These exercise the request validation that `create_payment` performs before
//! any RPC contact: scheme, network, asset, fee-sponsorship, and amount checks
//! all reject malformed input before the RPC client is constructed. They run
//! under the default `cargo test` with no network access and no feature flag.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test-only; unwraps acceptable in unit tests"
)]

use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use stellar_agent_network::signing::SoftwareSigningKey;
use stellar_agent_x402::X402Error;
use stellar_agent_x402::constants::X402_STELLAR_TESTNET;
use stellar_agent_x402::exact::create_payment;
use stellar_agent_x402::wire::PaymentRequirements;
use zeroize::Zeroizing;

const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";

/// Loopback address that is never contacted: every case here returns in step-1
/// validation before the RPC client is built.
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
    let r = create_payment(&req, &dummy_signer(), UNUSED_RPC_URL, TESTNET_PASSPHRASE).await;
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
    let r = create_payment(&req, &dummy_signer(), UNUSED_RPC_URL, TESTNET_PASSPHRASE).await;
    assert!(
        matches!(r, Err(X402Error::UnsupportedNetwork { .. })),
        "expected UnsupportedNetwork, got {r:?}"
    );
}

/// A network passphrase that disagrees with the wire network is rejected.
#[tokio::test]
async fn wrong_network_passphrase_rejected() {
    let req = requirements_with("exact", X402_STELLAR_TESTNET, AMOUNT, true.into());
    let r = create_payment(
        &req,
        &dummy_signer(),
        UNUSED_RPC_URL,
        "Public Global Stellar Network ; September 2015", // mainnet passphrase
    )
    .await;
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
    let r = create_payment(&req, &dummy_signer(), UNUSED_RPC_URL, TESTNET_PASSPHRASE).await;
    assert!(
        matches!(r, Err(X402Error::InvalidAssetAddress { .. })),
        "expected InvalidAssetAddress, got {r:?}"
    );
}

/// `areFeesSponsored != true` is rejected with `FeesNotSponsored`.
#[tokio::test]
async fn fees_not_sponsored_rejected() {
    let req = requirements_with("exact", X402_STELLAR_TESTNET, AMOUNT, false.into());
    let r = create_payment(&req, &dummy_signer(), UNUSED_RPC_URL, TESTNET_PASSPHRASE).await;
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
    let r = create_payment(&req, &dummy_signer(), UNUSED_RPC_URL, TESTNET_PASSPHRASE).await;
    assert!(
        matches!(r, Err(X402Error::FeesNotSponsored)),
        "expected FeesNotSponsored for string \"true\", got {r:?}"
    );
}

/// `amount = 0` is rejected (zero is not a positive integer).
#[tokio::test]
async fn amount_zero_rejected() {
    let req = requirements_with("exact", X402_STELLAR_TESTNET, "0", true.into());
    let r = create_payment(&req, &dummy_signer(), UNUSED_RPC_URL, TESTNET_PASSPHRASE).await;
    assert!(
        matches!(r, Err(X402Error::AmountConversion { .. })),
        "expected AmountConversion for amount=0, got {r:?}"
    );
}

/// A negative amount is rejected.
#[tokio::test]
async fn negative_amount_rejected() {
    let req = requirements_with("exact", X402_STELLAR_TESTNET, "-1000000", true.into());
    let r = create_payment(&req, &dummy_signer(), UNUSED_RPC_URL, TESTNET_PASSPHRASE).await;
    assert!(
        matches!(r, Err(X402Error::AmountConversion { .. })),
        "expected AmountConversion for negative amount, got {r:?}"
    );
}

/// A non-integer amount string is rejected.
#[tokio::test]
async fn non_integer_amount_rejected() {
    let req = requirements_with("exact", X402_STELLAR_TESTNET, "1.5", true.into());
    let r = create_payment(&req, &dummy_signer(), UNUSED_RPC_URL, TESTNET_PASSPHRASE).await;
    assert!(
        matches!(r, Err(X402Error::AmountConversion { .. })),
        "expected AmountConversion for non-integer amount, got {r:?}"
    );
}
