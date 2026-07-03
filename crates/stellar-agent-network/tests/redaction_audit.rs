//! CaptureWriter-based redaction audit for the network stack.
//!
//! Wires [`stellar_agent_test_support::CaptureWriter`] to a subscriber using
//! [`stellar_agent_core::observability::RedactingJsonFormatter`] and exercises
//! the transaction-build path (drives `stellar-baselib`), the signing path
//! (drives `stellar_agent_network::signing`), and the RPC `fetch_account` path
//! (drives `stellar-rpc-client`).  After each operation, the captured output
//! is checked with [`stellar_agent_test_support::assert_no_secret_bytes`].
//!
//! # What this guards
//!
//! - Upstream `stellar-baselib` `tracing::*` events must not carry raw S-strkey
//!   seeds or BIP-39 mnemonic phrases.
//! - Network-layer `tracing::*` events at `info!` and `warn!` levels must not
//!   expose the secret key used for signing.
//! - The `stellar-rpc-client` RPC path (`getLedgerEntries`) must not echo any
//!   secret-pattern present in the canned RPC envelope JSON through any
//!   `tracing::*` event — defence-in-depth against upstream `reqwest` or
//!   `jsonrpsee` logging the raw response body.
//!
//! # Filter level
//!
//! The subscriber uses `info` as the base level.  `debug!` and `trace!` from
//! upstream crates are excluded by default to reduce noise; the security-
//! relevant paths for secrets are at `info!` / `warn!` / `error!`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "integration test; panics/unwraps acceptable"
)]

use serde_json::json;
use stellar_agent_core::StellarAmount;
use stellar_agent_core::observability::RedactingJsonFormatter;
use stellar_agent_network::builder::{Asset, ClassicOpBuilder};
use stellar_agent_network::signing::SoftwareSigningKey;
use stellar_agent_network::signing::envelope_signing::attach_signature;
use stellar_agent_network::{StellarRpcClient, fetch_account};
use stellar_agent_test_support::testnet_strkeys::{
    TESTNET_FIXTURE_SEED, VERSION_PRIVATE_KEY, strkey_from_seed,
};
use stellar_agent_test_support::{CaptureWriter, EchoIdResponder, assert_no_secret_bytes};
use tracing_subscriber::{EnvFilter, Layer, fmt, layer::SubscriberExt};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer};

// ── Fixtures ──────────────────────────────────────────────────────────────────

const SRC_ACCOUNT: &str = "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY";
const DST_ACCOUNT: &str = "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL";
const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";

// ── Helper: subscriber with CaptureWriter ─────────────────────────────────────

/// Build a `tracing_subscriber` registry wired to `writer` with the
/// `RedactingJsonFormatter` and an `info`-level filter.
fn make_capture_subscriber(writer: CaptureWriter) -> impl tracing::Subscriber + Send + Sync {
    let filter = EnvFilter::builder().parse_lossy("info");
    tracing_subscriber::registry().with(
        fmt::layer()
            .event_format(RedactingJsonFormatter::new())
            .with_writer(writer)
            .with_filter(filter),
    )
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// Building a transaction via `ClassicOpBuilder` must not leak the secret key.
///
/// The `build` path drives `stellar-baselib` internally.  Any `tracing::*`
/// events emitted by baselib must not contain S-strkey seeds.
#[test]
fn build_path_does_not_leak_secret_key() {
    let s_strkey = strkey_from_seed(VERSION_PRIVATE_KEY, &TESTNET_FIXTURE_SEED);
    let writer = CaptureWriter::new();
    let subscriber = make_capture_subscriber(writer.clone());

    tracing::subscriber::with_default(subscriber, || {
        let mut builder = ClassicOpBuilder::new(SRC_ACCOUNT, 101, TESTNET_PASSPHRASE, 100);
        builder
            .payment(
                DST_ACCOUNT,
                StellarAmount::from_stroops(10_000_000),
                &Asset::Native,
            )
            .expect("payment op must succeed");
        let _xdr = builder.build().expect("build must succeed");

        // Inject the secret key as a tracing event field to verify the
        // subscriber redacts it (belt-and-braces check on the capture path).
        tracing::info!(note = %s_strkey, "redaction test marker");
    });

    let captured = writer.captured();
    // The injected S-strkey must be redacted.
    assert_no_secret_bytes(&captured);
}

/// The signing path (`attach_signature`) must not leak the raw secret key bytes
/// to any tracing subscriber.
///
/// Uses `SoftwareSigningKey::new_from_bytes` with `TESTNET_FIXTURE_SEED` to
/// create a signing key, then calls `attach_signature` to sign a test envelope.
/// The captured subscriber output must not contain the S-strkey representation
/// of the signing seed.
///
/// # Design note
///
/// `tracing::subscriber::with_default` only sets a thread-local override; it
/// cannot span an `async fn` boundary.  We therefore run the async work in a
/// `tokio::task::spawn_blocking` wrapper, which runs on a blocking thread where
/// we can safely use `with_default` + `block_on`.
#[tokio::test]
async fn signing_path_does_not_leak_secret_key() {
    let s_strkey = strkey_from_seed(VERSION_PRIVATE_KEY, &TESTNET_FIXTURE_SEED);

    // Build an unsigned envelope (synchronous; no secret-key involved).
    let mut builder = ClassicOpBuilder::new(SRC_ACCOUNT, 101, TESTNET_PASSPHRASE, 100);
    builder
        .payment(
            DST_ACCOUNT,
            StellarAmount::from_stroops(10_000_000),
            &Asset::Native,
        )
        .expect("payment op");
    let unsigned_xdr = builder.build().expect("build");

    // Run signing on a blocking thread to allow block_on inside with_default.
    let captured = tokio::task::spawn_blocking(move || {
        let writer = CaptureWriter::new();
        let subscriber = make_capture_subscriber(writer.clone());
        let key = SoftwareSigningKey::new_from_bytes(TESTNET_FIXTURE_SEED);

        tracing::subscriber::with_default(subscriber, || {
            // Inject the S-strkey to verify the subscriber intercepts it.
            tracing::info!(note = %s_strkey, "redaction test marker pre-sign");

            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("build single-thread runtime");
            let _ = rt.block_on(attach_signature(&unsigned_xdr, &key, TESTNET_PASSPHRASE));

            tracing::info!(note = %s_strkey, "redaction test marker post-sign");
        });

        writer.captured()
    })
    .await
    .expect("blocking task must not panic");

    assert_no_secret_bytes(&captured);
}

/// BIP-39 mnemonic phrases must not appear in the captured subscriber output.
///
/// Injects a 12-word BIP-39 mnemonic (the redaction layer's mnemonic detection
/// test) and asserts `assert_no_secret_bytes` catches it.
#[test]
fn bip39_mnemonic_is_redacted_in_captured_output() {
    // Use the same 12-word mnemonic from the observability unit tests.
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let writer = CaptureWriter::new();
    let subscriber = make_capture_subscriber(writer.clone());

    tracing::subscriber::with_default(subscriber, || {
        // Emit the mnemonic as a field value; the subscriber must redact it.
        tracing::info!(phrase = mnemonic, "bip39 redaction test");
    });

    let captured = writer.captured();
    assert_no_secret_bytes(&captured);
}

/// An event with no secret-shaped content must pass `assert_no_secret_bytes`
/// without triggering a false positive.
#[test]
fn benign_event_passes_redaction_audit() {
    let writer = CaptureWriter::new();
    let subscriber = make_capture_subscriber(writer.clone());

    tracing::subscriber::with_default(subscriber, || {
        tracing::info!(
            operation = "stellar_pay_build",
            source = SRC_ACCOUNT,
            destination = DST_ACCOUNT,
            amount = "10 XLM",
            "payment build request"
        );
    });

    let captured = writer.captured();
    // Must not panic — no secret bytes in this event.
    assert_no_secret_bytes(&captured);
}

// ── RPC path redaction tests ───────────────────────────────────────────────────

/// Constructs the XDR-base64 `LedgerKey::Account` for an account address.
fn account_ledger_key_xdr(address: &str) -> String {
    use stellar_xdr::{
        AccountId, LedgerKey, LedgerKeyAccount, Limits, PublicKey, Uint256, WriteXdr,
    };
    let pk_bytes = stellar_strkey::ed25519::PublicKey::from_string(address)
        .expect("valid address")
        .0;
    let key = LedgerKey::Account(LedgerKeyAccount {
        account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(pk_bytes))),
    });
    key.to_xdr_base64(Limits::none()).expect("valid XDR")
}

/// A real XDR-base64 `LedgerEntryData::Account` blob for a funded testnet
/// account.  Reused from `balances_integration.rs` — the same fixture XDR
/// works here because the goal is to exercise the `fetch_account` deserialization
/// path, not the account balance values.
const FUNDED_ACCOUNT_XDR: &str = "AAAAAAAAAABzdv3ojkzWHMD7KUoXhrPx0GH18vHKV0ZfqpMiEblG1gAAAFwVZH3YAAABdgAAAQgAAAAFAAAA\
     AAAAAAAAAAAAAQAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAIAAAAAAAAAAAAAAAAAAAADAAAAAAAOZYQAAAAAaJsIJQ==";

/// The account address matching `FUNDED_ACCOUNT_XDR`.
const FUNDED_ACCOUNT_ADDRESS: &str = "GBZXN7PIRZGNMHGA7MUUUF4GWPY5AYPV6LY4UV2GL6VJGIQRXFDNMADI";

/// `fetch_account` must not emit the fixture S-strkey through any
/// `tracing::*` event at `info`/`warn`/`error` level, even when the RPC
/// response envelope contains the S-strkey as a field value.
///
/// # Defence-in-depth probe
///
/// The wiremock response JSON embeds the fixture S-strkey in a hypothetical
/// `_debug_hint` field.  In the real Stellar RPC protocol this field does not
/// exist; it is injected here as a paranoid probe to verify that if any
/// upstream crate (reqwest, jsonrpsee, stellar-rpc-client) were to log the
/// raw response body at `info!` or above, the subscriber's redaction layer
/// catches and strips the S-strkey before it reaches any persistent destination.
///
/// # Design note
///
/// `tracing::subscriber::with_default` is thread-local.  The test drives the
/// async work on a single blocking thread using `spawn_blocking` + `block_on`,
/// the same pattern used by `signing_path_does_not_leak_secret_key`.
#[tokio::test]
async fn fetch_account_rpc_path_does_not_leak_secret_key() {
    // ── Build the fixture S-strkey (derived at runtime; never hardcoded in source).
    let s_strkey = strkey_from_seed(VERSION_PRIVATE_KEY, &TESTNET_FIXTURE_SEED);
    let s_strkey_clone = s_strkey.clone();

    // ── Start the wiremock server.
    let mock_server = MockServer::start().await;
    let key_xdr = account_ledger_key_xdr(FUNDED_ACCOUNT_ADDRESS);

    // Embed the fixture S-strkey in the response envelope as a defence-in-depth
    // probe — the real Stellar RPC does not return this field.
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(EchoIdResponder::new(json!({
            "entries": [
                {
                    "key": key_xdr,
                    "xdr": FUNDED_ACCOUNT_XDR,
                    "lastModifiedLedgerSeq": 2552504,
                    // Probe: S-strkey injected into the RPC envelope.  Any
                    // upstream crate that logs the raw JSON must be caught by
                    // the redaction subscriber.
                    "_debug_hint": s_strkey_clone,
                }
            ],
            "latestLedger": 2552990
        })))
        .mount(&mock_server)
        .await;

    let mock_uri = mock_server.uri();

    // ── Run fetch_account on a blocking thread under a CaptureWriter subscriber.
    let captured = tokio::task::spawn_blocking(move || {
        let writer = CaptureWriter::new();
        let subscriber = make_capture_subscriber(writer.clone());

        tracing::subscriber::with_default(subscriber, || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("build single-thread runtime");

            // The fetch succeeds (or fails — either way, tracing output must
            // not contain the injected S-strkey).
            let client = StellarRpcClient::new(&mock_uri).expect("mock URI must be valid");
            let _ = rt.block_on(fetch_account(&client, FUNDED_ACCOUNT_ADDRESS, &[]));

            // Belt-and-braces: also inject the S-strkey directly into a
            // tracing event to confirm the subscriber intercepts it on this
            // thread.
            tracing::info!(note = %s_strkey, "redaction probe via direct event");
        });

        writer.captured()
    })
    .await
    .expect("blocking task must not panic");

    // ── Assert: no S-strkey in any captured tracing output.
    assert_no_secret_bytes(&captured);
}

// ── Counterparty-substrate redaction tests ────────────────────────────────────

/// A failed counterparty fetch must not leak the home_domain string in
/// error- or warn-level tracing events.
///
/// The home_domain itself is not necessarily secret, but emitting it in error
/// logs can leak information about payment recipients to local log observers.
/// Error messages must remain short and non-sensitive.
#[tokio::test]
async fn counterparty_fetch_failed_does_not_leak_home_domain_in_log() {
    use stellar_agent_network::counterparty::{
        CounterpartyResolver as _, NoopCounterpartyResolver,
    };

    // Use a domain name that would stand out if leaked.
    let unique_home_domain = "secret-counterparty-test-target.example.com";

    let writer = CaptureWriter::new();
    // Use error+warn level only (per the finding: acceptable at debug).
    let filter = tracing_subscriber::EnvFilter::builder().parse_lossy("warn");
    let subscriber = tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .event_format(RedactingJsonFormatter::new())
            .with_writer(writer.clone())
            .with_filter(filter),
    );

    let captured = tokio::task::spawn_blocking(move || {
        tracing::subscriber::with_default(subscriber, || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("build runtime");
            // NoopCounterpartyResolver always returns FetchFailed; we want to
            // exercise the error path where the domain might be logged.
            let resolver = NoopCounterpartyResolver;
            let _ = rt.block_on(resolver.refresh(unique_home_domain));
        });
        writer.captured_str()
    })
    .await
    .expect("blocking task must not panic");

    // The home_domain must not appear in error/warn-level log output.
    assert!(
        !captured.contains("secret-counterparty-test-target"),
        "home_domain must not appear in error/warn logs; found in: {}",
        &captured[..captured.len().min(500)]
    );
}

/// Positive control: the capture subscriber used by these tests has the
/// redaction layer active, so a secret strkey passed into a tracing event is
/// scrubbed before reaching the writer.
///
/// (The counterparty HMAC key itself is held in `Zeroizing<[u8; 32]>` and is
/// never passed to a tracing macro on any production path; this test guards the
/// redaction wiring that would catch an accidental strkey leak.)
#[tokio::test]
async fn counterparty_redaction_subscriber_scrubs_secret_strkey() {
    let writer = CaptureWriter::new();
    let subscriber = make_capture_subscriber(writer.clone());

    // A CRC-valid S-strkey (secret seed) — a known-secret pattern the redaction
    // layer must scrub. If it survived verbatim, the redaction wiring is broken.
    let secret_strkey = strkey_from_seed(VERSION_PRIVATE_KEY, &TESTNET_FIXTURE_SEED);

    tracing::subscriber::with_default(subscriber, || {
        tracing::info!(value = %secret_strkey, "counterparty redaction probe");
    });

    let captured = writer.captured_str();
    assert!(
        !captured.contains(&secret_strkey),
        "the redaction layer must scrub the S-strkey before it reaches the writer; got: {captured}"
    );
    assert_no_secret_bytes(&writer.captured());
}

/// An I/O error from the cache layer must not expose the full cache directory
/// path in the error envelope.
///
/// `CounterpartyError::Io` carries only `kind` (an `io::ErrorKind`), not the
/// full path.  This test verifies that invariant holds at the
/// display/formatting layer.
#[test]
fn counterparty_cache_io_error_does_not_expose_full_path() {
    use stellar_agent_network::CounterpartyError;

    // Construct an Io error directly.
    let err = CounterpartyError::Io {
        kind: std::io::ErrorKind::PermissionDenied,
    };
    let display = format!("{err}");

    // The display must mention the kind but not any path component.
    assert!(
        display.contains("PermissionDenied") || display.contains("permission denied"),
        "Io error display must mention the kind"
    );
    // Must not contain HOME directory path components.
    let home = std::env::var("HOME").unwrap_or_else(|_| "/home/user".to_owned());
    assert!(
        !display.contains(&home),
        "Io error must not contain HOME path; display = {display:?}"
    );
}
