//! Offline integration tests for the x402 counterparty-identity gate.
//!
//! All full-gate tests drive the REAL `resolve_and_verify_counterparty_at`
//! production path through every step (stellar.toml fetch → parse → field
//! extraction → SSRF same-domain bind → SEP-10 challenge/response → JWT) against
//! wiremock HTTP servers.  Mocks are at the wire/HTTP level only.
//!
//! # Test seam
//!
//! The production `resolve_and_verify_counterparty` validates the home_domain
//! as a valid LDH FQDN before any network I/O; this precludes `127.0.0.1:PORT`
//! (wiremock default).  Tests use the `resolve_and_verify_counterparty_at`
//! test seam which accepts an explicit `toml_base_url` and bypasses LDH
//! validation, driving the full gate through every downstream step unchanged.
//!
//! # Key discipline
//!
//! All keypairs are generated at runtime via `OsRng`.  No `S...` seeds are
//! committed.
//!
//! Gated on `feature = "test-helpers"` because the full-gate tests call the
//! `resolve_and_verify_counterparty_at` test seam (exposed only under
//! `#[cfg(any(test, feature = "test-helpers"))]`). Without the feature this
//! file compiles to nothing, so `cargo test -p stellar-agent-x402-identity`
//! succeeds (CI runs `--all-features`, which enables it).

#![cfg(feature = "test-helpers")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics acceptable in integration tests"
)]
#![allow(
    clippy::print_stderr,
    reason = "test-only; eprintln! used for skip notifications"
)]

use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use stellar_xdr::{
    BytesM, DataValue, DecoratedSignature, Hash, Limits, ManageDataOp, Memo, MuxedAccount,
    Operation, OperationBody, Preconditions, SequenceNumber, Signature, SignatureHint, StringM,
    TimeBounds, TimePoint, Transaction, TransactionEnvelope, TransactionExt,
    TransactionSignaturePayload, TransactionSignaturePayloadTaggedTransaction,
    TransactionV1Envelope, VecM, WriteXdr,
};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

use stellar_agent_x402_identity::{
    IdentityError, resolve_and_verify_counterparty, resolve_and_verify_counterparty_at,
};

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";
const SEP10_AUTH_PATH: &str = "/sep10/auth";

// ─────────────────────────────────────────────────────────────────────────────
// Key generation helpers (all ephemeral, runtime-generated)
// ─────────────────────────────────────────────────────────────────────────────

fn gen_keypair() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

fn pubkey_to_gstrkey(sk: &SigningKey) -> String {
    let pk = stellar_strkey::ed25519::PublicKey(sk.verifying_key().to_bytes());
    format!("{pk}")
}

// ─────────────────────────────────────────────────────────────────────────────
// SEP-10 challenge builder
// ─────────────────────────────────────────────────────────────────────────────

fn str_to_string64(s: &str) -> stellar_xdr::String64 {
    StringM::<64>::try_from(s.as_bytes().to_vec())
        .expect("string must fit in StringM<64>")
        .into()
}

fn bytes_to_data_value(b: &[u8]) -> DataValue {
    DataValue(BytesM::<64>::try_from(b.to_vec()).expect("bytes must fit in BytesM<64>"))
}

fn sign_tx_to_xdr_base64(tx: Transaction, signing_key: &SigningKey, passphrase: &str) -> String {
    let vk = signing_key.verifying_key();
    let pk = stellar_strkey::ed25519::PublicKey(vk.to_bytes());
    let hint: [u8; 4] = pk.0[28..32].try_into().expect("pubkey hint");

    let network_id_hash = Hash(Sha256::digest(passphrase.as_bytes()).into());
    let tagged_tx = TransactionSignaturePayloadTaggedTransaction::Tx(tx.clone());
    let sig_payload = TransactionSignaturePayload {
        network_id: network_id_hash,
        tagged_transaction: tagged_tx,
    };
    let payload_bytes = sig_payload.to_xdr(Limits::none()).expect("sig payload XDR");
    let tx_hash: [u8; 32] = Sha256::digest(&payload_bytes).into();
    let sig = signing_key.sign(&tx_hash);
    let sig_bytes: Vec<u8> = sig.to_bytes().to_vec();

    let dec_sig = DecoratedSignature {
        hint: SignatureHint(hint),
        signature: Signature(sig_bytes.try_into().expect("sig VecM")),
    };
    let sigs_vec: VecM<DecoratedSignature, 20> = vec![dec_sig].try_into().expect("VecM<20>");
    TransactionEnvelope::Tx(TransactionV1Envelope {
        tx,
        signatures: sigs_vec,
    })
    .to_xdr_base64(Limits::none())
    .expect("envelope base64")
}

/// Build a SEP-10 challenge for `client_gkey` signed by `server_key`.
///
/// The `web_auth_domain` ManageData value is set to `web_auth_domain_value`
/// (NOT home_domain) — the real sep10 client validates `web_auth_domain`
/// against the WEB_AUTH_ENDPOINT host, not home_domain.  Using the endpoint
/// host here avoids accidentally masking a contract drift via coincidence.
fn build_challenge_xdr(
    server_key: &SigningKey,
    client_gkey: &str,
    home_domain: &str,
    web_auth_domain_value: &str,
    network_passphrase: &str,
    nonce: &[u8; 48],
) -> String {
    let server_pk = stellar_strkey::ed25519::PublicKey(server_key.verifying_key().to_bytes());
    let server_muxed = MuxedAccount::Ed25519(stellar_xdr::Uint256(server_pk.0));

    let client_pk =
        stellar_strkey::ed25519::PublicKey::from_string(client_gkey).expect("valid G-strkey");
    let client_muxed = MuxedAccount::Ed25519(stellar_xdr::Uint256(client_pk.0));

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_secs();
    let nonce_b64 = base64::engine::general_purpose::STANDARD.encode(nonce);

    let first_op = Operation {
        source_account: Some(client_muxed),
        body: OperationBody::ManageData(ManageDataOp {
            data_name: str_to_string64(&format!("{home_domain} auth")),
            data_value: Some(bytes_to_data_value(nonce_b64.as_bytes())),
        }),
    };

    // web_auth_domain op — value is the WEB_AUTH_ENDPOINT host (not home_domain).
    // The sep10 client validates web_auth_domain against the expected_web_auth_domain
    // (the endpoint host), so setting it to the endpoint host avoids masking
    // a contract drift via coincidence.
    let web_auth_op = Operation {
        source_account: Some(server_muxed.clone()),
        body: OperationBody::ManageData(ManageDataOp {
            data_name: str_to_string64("web_auth_domain"),
            data_value: Some(bytes_to_data_value(web_auth_domain_value.as_bytes())),
        }),
    };

    let ops: VecM<Operation, 100> = vec![first_op, web_auth_op]
        .try_into()
        .expect("ops VecM<100>");

    let tx = Transaction {
        source_account: server_muxed,
        fee: 100,
        seq_num: SequenceNumber(0),
        cond: Preconditions::Time(TimeBounds {
            min_time: TimePoint(now.saturating_sub(10)),
            max_time: TimePoint(now + 300),
        }),
        memo: Memo::None,
        operations: ops,
        ext: TransactionExt::V0,
    };

    sign_tx_to_xdr_base64(tx, server_key, network_passphrase)
}

// ─────────────────────────────────────────────────────────────────────────────
// Dynamic wiremock responder — reads `account` query param + serves challenge
// ─────────────────────────────────────────────────────────────────────────────

/// A wiremock `Respond` implementation that reads the `account` query parameter
/// from the incoming GET request and returns a SEP-10 challenge XDR signed for
/// that specific client account.
///
/// The ephemeral G-key sent by the gate in the `account` query param is captured
/// into `captured_account` so the paired `Sep10JwtResponder` can echo it as the
/// JWT `sub` claim. The sep10 client asserts `sub == ephemeral_gkey`
/// (`Sep10Error::SessionAccountMismatch`), so the POST response must use the
/// exact G-key from this GET.
///
/// The `web_auth_domain_value` is set to the endpoint host (NOT home_domain),
/// because the sep10 client validates `web_auth_domain` against the endpoint's
/// `expected_web_auth_domain` — using the endpoint host is explicit to avoid
/// masking a contract drift via coincidence.
struct Sep10ChallengeResponder {
    server_key: SigningKey,
    home_domain: String,
    web_auth_domain_value: String,
    network_passphrase: String,
    /// Shared with `Sep10JwtResponder` — stores the ephemeral G-key from
    /// the GET `account` param so the POST response can echo it as `sub`.
    captured_account: Arc<Mutex<String>>,
}

impl Respond for Sep10ChallengeResponder {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        // Parse the `account` query param from the GET request URL.
        let url = &request.url;
        let account = url
            .query_pairs()
            .find(|(k, _)| k == "account")
            .map(|(_, v)| v.into_owned())
            .unwrap_or_default();

        if account.is_empty() {
            return ResponseTemplate::new(400).set_body_string("missing account param");
        }

        // Store the ephemeral G-key so the POST responder can use it as JWT sub.
        *self.captured_account.lock().unwrap() = account.clone();

        let nonce = [0xABu8; 48];
        let challenge_xdr = build_challenge_xdr(
            &self.server_key,
            &account,
            &self.home_domain,
            &self.web_auth_domain_value,
            &self.network_passphrase,
            &nonce,
        );

        ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "transaction": challenge_xdr,
            "network_passphrase": self.network_passphrase,
        }))
    }
}

/// A wiremock `Respond` implementation for POST `/sep10/auth` that returns a
/// JWT whose `sub` equals the ephemeral account G-key captured by the paired
/// `Sep10ChallengeResponder`.
///
/// The sep10 client asserts `jwt.sub == ephemeral_gkey`. A static placeholder
/// would cause `Sep10Error::SessionAccountMismatch`, so the `sub` must be
/// read from `captured_account` which is populated by the GET responder.
struct Sep10JwtResponder {
    /// Same `Arc<Mutex<String>>` as `Sep10ChallengeResponder::captured_account`.
    captured_account: Arc<Mutex<String>>,
}

impl Respond for Sep10JwtResponder {
    fn respond(&self, _request: &Request) -> ResponseTemplate {
        let sub = self.captured_account.lock().unwrap().clone();
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
            serde_json::json!({
                "sub": sub,
                "iss": "test",
                "iat": 0,
                "exp": 9_999_999_999_u64,
            })
            .to_string()
            .as_bytes(),
        );
        let jwt = format!("header.{payload}.sig");
        ResponseTemplate::new(200).set_body_json(serde_json::json!({ "token": jwt }))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// stellar.toml builder
// ─────────────────────────────────────────────────────────────────────────────

fn build_stellar_toml(signing_key_gstrkey: &str, web_auth_endpoint: &str) -> String {
    format!(
        "SIGNING_KEY = \"{signing_key_gstrkey}\"\nWEB_AUTH_ENDPOINT = \"{web_auth_endpoint}\"\n"
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// HTTP client helper (allows plain HTTP for wiremock)
// ─────────────────────────────────────────────────────────────────────────────

fn test_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .expect("test reqwest::Client build")
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: wiremock server's host:port
// ─────────────────────────────────────────────────────────────────────────────

fn server_host_port(mock_server: &MockServer) -> String {
    mock_server.uri().trim_start_matches("http://").to_owned()
}

/// The wiremock server's bare host (no port). The SEP-10 client derives the
/// expected `web_auth_domain` from the endpoint URL's host (port stripped), so a
/// challenge mimicking a real anchor declares the bare host here.
fn server_host(mock_server: &MockServer) -> String {
    let host_port = server_host_port(mock_server);
    host_port
        .rsplit_once(':')
        .map_or(host_port.clone(), |(host, _port)| host.to_owned())
}

// ═════════════════════════════════════════════════════════════════════════════
// HAPPY-PATH FULL-GATE TEST
// ═════════════════════════════════════════════════════════════════════════════

/// Happy gate: drives the COMPLETE gate through all five steps against a
/// wiremock server:
///
/// 1. GET `/.well-known/stellar.toml` → SIGNING_KEY + WEB_AUTH_ENDPOINT.
/// 2. SSRF same-domain bind accepted (endpoint on same mock host as toml).
/// 3. GET `/sep10/auth?account=<ephemeral_gkey>` → challenge signed for
///    the ephemeral G-key (dynamic responder reads the `account` param).
/// 4. POST `/sep10/auth` → `{"token": "<jwt>"}`.
/// 5. Returns `VerifiedCounterpartySession { jwt, sub, home_domain }`.
///
/// Asserts: `Ok(session)` with non-empty `jwt`, non-empty `sub` (the ephemeral
/// G-strkey echoed back from the JWT claim), and `home_domain` echoed back
/// from the input.
///
/// Uses `resolve_and_verify_counterparty_at` test seam.
#[tokio::test]
async fn happy_gate_full_end_to_end_via_seam() {
    let mock_server = MockServer::start().await;
    let server_key = gen_keypair();
    let signing_key_gstrkey = pubkey_to_gstrkey(&server_key);

    // The home_domain for SSRF bind purposes.  In the test seam, home_domain
    // does NOT have to be an LDH FQDN — it is the logical identity label used
    // for the SSRF bind and the SEP-10 `home_domain` parameter.
    // We use the mock server's host:port so the SSRF bind (endpoint host ==
    // home_domain) accepts the mock WEB_AUTH_ENDPOINT.
    let mock_host = server_host_port(&mock_server);

    // TOML WEB_AUTH_ENDPOINT must be `https://` to pass the SEP-1 parser's
    // HTTPS-only validation.  The test seam overrides the actual Sep10 call to
    // use the mock server's plain-HTTP URL via `web_auth_override`.
    let toml_web_auth_endpoint = format!("https://{mock_host}{SEP10_AUTH_PATH}");
    // The actual HTTP URL used for the Sep10 challenge/response calls.
    let http_web_auth_endpoint = format!("http://{mock_host}{SEP10_AUTH_PATH}");

    // 1. stellar.toml mock
    let toml_body = build_stellar_toml(&signing_key_gstrkey, &toml_web_auth_endpoint);
    Mock::given(method("GET"))
        .and(path("/.well-known/stellar.toml"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/plain")
                .set_body_string(toml_body),
        )
        .mount(&mock_server)
        .await;

    // 2. SEP-10 GET challenge — dynamic responder builds the challenge for the
    //    ephemeral G-key sent in the `account` query param.
    //
    //    The `web_auth_domain_value` in the challenge is the endpoint's bare
    //    host (no port). The sep10 client derives the expected `web_auth_domain`
    //    from the endpoint URL's host, so a challenge mimicking a real anchor
    //    declares the bare host. Set explicitly to avoid masking a contract
    //    drift by coincidence.
    //
    //    The captured_account Arc is shared with the POST responder so the JWT
    //    `sub` can equal the ephemeral G-key that the gate generated. The sep10
    //    client asserts `sub == ephemeral_gkey` (SessionAccountMismatch), so
    //    the POST sub must match exactly.
    let captured_account: Arc<Mutex<String>> = Arc::new(Mutex::new(String::new()));
    let challenge_responder = Sep10ChallengeResponder {
        server_key: SigningKey::from_bytes(&server_key.to_bytes()),
        home_domain: mock_host.clone(),
        web_auth_domain_value: server_host(&mock_server), // endpoint bare host
        network_passphrase: TESTNET_PASSPHRASE.to_owned(),
        captured_account: Arc::clone(&captured_account),
    };
    Mock::given(method("GET"))
        .and(path(SEP10_AUTH_PATH))
        .respond_with(challenge_responder)
        .mount(&mock_server)
        .await;

    // 3. SEP-10 POST submit — dynamic responder reads the ephemeral G-key
    //    captured by the GET responder and echoes it as the JWT `sub` claim.
    //    Sep10Session::parse splits on '.' and base64url-decodes the payload;
    //    the sep10 client then asserts sub == ephemeral_gkey.
    let jwt_responder = Sep10JwtResponder {
        captured_account: Arc::clone(&captured_account),
    };
    Mock::given(method("POST"))
        .and(path(SEP10_AUTH_PATH))
        .respond_with(jwt_responder)
        .mount(&mock_server)
        .await;

    let http = test_http_client();
    // Test seam: TOML WEB_AUTH_ENDPOINT is `https://mock_host/...` (parser-valid),
    // override the Sep10 call to `http://mock_host/...` (plain-HTTP wiremock).
    let result = resolve_and_verify_counterparty_at(
        &mock_host,
        TESTNET_PASSPHRASE,
        &mock_server.uri(),
        &http,
        Some(&http_web_auth_endpoint),
    )
    .await;

    assert!(result.is_ok(), "happy gate must succeed; got: {result:?}");
    let session = result.unwrap();

    // jwt is non-empty (the gate parsed it).
    assert!(
        !session.jwt.is_empty(),
        "VerifiedCounterpartySession.jwt must be non-empty"
    );

    // sub is from the JWT's `sub` claim — the dynamic POST responder echoes the
    // ephemeral G-key that the gate sent in the GET `account` param.  The sep10
    // client asserts sub == ephemeral_gkey before returning the session, so a
    // non-empty sub here confirms the full SEP-10 round-trip completed correctly.
    assert!(
        !session.sub.is_empty(),
        "VerifiedCounterpartySession.sub must be non-empty; got: '{}'",
        session.sub
    );

    // home_domain is echoed back.
    assert_eq!(
        session.home_domain, mock_host,
        "VerifiedCounterpartySession.home_domain must be echoed from input"
    );

    // Ephemeral-key hygiene: sub is the ephemeral G-key, NOT the server key.
    assert_ne!(
        session.sub, signing_key_gstrkey,
        "session.sub must be the EPHEMERAL key, not the server SIGNING_KEY"
    );
}

// ═════════════════════════════════════════════════════════════════════════════
// ABORT-BEFORE-PAYMENT FULL-GATE TESTS (using the seam)
// ═════════════════════════════════════════════════════════════════════════════

/// Gate abort (full-gate via seam): stellar.toml has SIGNING_KEY but no
/// WEB_AUTH_ENDPOINT → `WebAuthEndpointMissing`.
///
/// Drives the complete gate through stellar.toml fetch + parse steps.
#[tokio::test]
async fn gate_abort_missing_web_auth_endpoint() {
    let mock_server = MockServer::start().await;
    let server_key = gen_keypair();
    let signing_key_gstrkey = pubkey_to_gstrkey(&server_key);

    // stellar.toml: SIGNING_KEY only, NO WEB_AUTH_ENDPOINT.
    let toml_body = format!("SIGNING_KEY = \"{signing_key_gstrkey}\"\n");
    Mock::given(method("GET"))
        .and(path("/.well-known/stellar.toml"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/plain")
                .set_body_string(toml_body),
        )
        .mount(&mock_server)
        .await;

    let mock_host = server_host_port(&mock_server);
    let http = test_http_client();
    let result = resolve_and_verify_counterparty_at(
        &mock_host,
        TESTNET_PASSPHRASE,
        &mock_server.uri(),
        &http,
        None,
    )
    .await;

    assert!(
        matches!(result, Err(IdentityError::WebAuthEndpointMissing { .. })),
        "missing WEB_AUTH_ENDPOINT must return WebAuthEndpointMissing (full gate); got: {result:?}"
    );
}

/// Gate abort (full-gate via seam): stellar.toml has WEB_AUTH_ENDPOINT but
/// no SIGNING_KEY → `SigningKeyMissing`.
#[tokio::test]
async fn gate_abort_missing_signing_key() {
    let mock_server = MockServer::start().await;
    let mock_host = server_host_port(&mock_server);
    // TOML WEB_AUTH_ENDPOINT must be `https://` for the parser.
    let toml_web_auth = format!("https://{mock_host}{SEP10_AUTH_PATH}");

    // stellar.toml: WEB_AUTH_ENDPOINT only, NO SIGNING_KEY.
    let toml_body = format!("WEB_AUTH_ENDPOINT = \"{toml_web_auth}\"\n");
    Mock::given(method("GET"))
        .and(path("/.well-known/stellar.toml"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/plain")
                .set_body_string(toml_body),
        )
        .mount(&mock_server)
        .await;

    let http = test_http_client();
    let result = resolve_and_verify_counterparty_at(
        &mock_host,
        TESTNET_PASSPHRASE,
        &mock_server.uri(),
        &http,
        None,
    )
    .await;

    assert!(
        matches!(result, Err(IdentityError::SigningKeyMissing { .. })),
        "missing SIGNING_KEY must return SigningKeyMissing (full gate); got: {result:?}"
    );
}

/// Gate abort (full-gate via seam): stellar.toml `WEB_AUTH_ENDPOINT` host
/// differs from home_domain → `WebAuthEndpointHostMismatch` (SSRF same-domain bind).
///
/// The SSRF bind checks the TOML's WEB_AUTH_ENDPOINT (not the web_auth_override)
/// so a mismatch in the TOML is always caught even when an override is present.
#[tokio::test]
async fn gate_abort_ssrf_different_host() {
    let mock_server = MockServer::start().await;
    let server_key = gen_keypair();
    let signing_key_gstrkey = pubkey_to_gstrkey(&server_key);
    let mock_host = server_host_port(&mock_server);

    // WEB_AUTH_ENDPOINT is on attacker.example.com — different from mock_host.
    // The SSRF bind checks the TOML's WEB_AUTH_ENDPOINT vs home_domain.
    let toml_body = format!(
        "SIGNING_KEY = \"{signing_key_gstrkey}\"\nWEB_AUTH_ENDPOINT = \"https://attacker.example.com/auth\"\n"
    );
    Mock::given(method("GET"))
        .and(path("/.well-known/stellar.toml"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/plain")
                .set_body_string(toml_body),
        )
        .mount(&mock_server)
        .await;

    let http = test_http_client();
    let result = resolve_and_verify_counterparty_at(
        &mock_host,
        TESTNET_PASSPHRASE,
        &mock_server.uri(),
        &http,
        None,
    )
    .await;

    assert!(
        matches!(
            result,
            Err(IdentityError::WebAuthEndpointHostMismatch { .. })
        ),
        "SSRF bind: different WEB_AUTH_ENDPOINT host must return WebAuthEndpointHostMismatch (full gate); got: {result:?}"
    );
}

/// SSRF bind adversarial (full-gate via seam): a host that contains the home_domain
/// as a suffix but is not a subdomain of it.
///
/// With `home_domain = 127.0.0.1:PORT`, `strip_port` yields the IP `127.0.0.1`,
/// which fails `is_public_fqdn` — the bind takes the exact-match-only branch.
/// The WEB_AUTH_ENDPOINT host (`evil-mock.example.com`) does not equal
/// `127.0.0.1`, so the gate rejects it via plain host-inequality.
/// The leading-dot suffix check (rejecting `evil-example.com` vs `example.com`
/// for LDH-valid domains) is exercised by the unit test
/// `ssrf_bind_evil_prefix_domain_rejected`.
#[tokio::test]
async fn gate_abort_ssrf_prefix_suffix_confusion() {
    let mock_server = MockServer::start().await;
    let server_key = gen_keypair();
    let signing_key_gstrkey = pubkey_to_gstrkey(&server_key);
    let mock_host = server_host_port(&mock_server);

    // Use a hostname-style evil domain — NOT evil-127.0.0.1 (url crate may reject
    // that as a malformed IP).  The home_domain IS mock_host (127.0.0.1:PORT);
    // the WEB_AUTH_ENDPOINT host is "evil-mock.example.com" — clearly different.
    // This still exercises the SSRF bind's host-mismatch rejection.
    let evil_endpoint = "https://evil-mock.example.com/auth";
    let toml_body = format!(
        "SIGNING_KEY = \"{signing_key_gstrkey}\"\nWEB_AUTH_ENDPOINT = \"{evil_endpoint}\"\n"
    );
    Mock::given(method("GET"))
        .and(path("/.well-known/stellar.toml"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/plain")
                .set_body_string(toml_body),
        )
        .mount(&mock_server)
        .await;

    let http = test_http_client();
    let result = resolve_and_verify_counterparty_at(
        &mock_host,
        TESTNET_PASSPHRASE,
        &mock_server.uri(),
        &http,
        None,
    )
    .await;

    assert!(
        matches!(
            result,
            Err(IdentityError::WebAuthEndpointHostMismatch { .. })
        ),
        "SSRF bind evil-prefix suffix-confusion must return WebAuthEndpointHostMismatch (full gate); got: {result:?}"
    );
}

/// Gate abort (full-gate via seam): SEP-10 challenge signed by wrong key →
/// `Sep10AuthFailed`.
///
/// stellar.toml advertises `server_key`; challenge is signed by `wrong_key`.
/// `fetch_challenge_verified` rejects the server signature.
/// Asserts `Sep10AuthFailed` specifically (not just "any error").
#[tokio::test]
async fn gate_abort_challenge_not_signed_by_signing_key() {
    let mock_server = MockServer::start().await;
    let server_key = gen_keypair(); // advertised in stellar.toml
    let wrong_key = gen_keypair(); // used to sign the challenge (wrong)
    let signing_key_gstrkey = pubkey_to_gstrkey(&server_key);
    let mock_host = server_host_port(&mock_server);

    // TOML: https:// endpoint for parser; real Sep10 goes to http:// mock.
    let toml_web_auth = format!("https://{mock_host}{SEP10_AUTH_PATH}");
    let http_web_auth = format!("http://{mock_host}{SEP10_AUTH_PATH}");

    Mock::given(method("GET"))
        .and(path("/.well-known/stellar.toml"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/plain")
                .set_body_string(build_stellar_toml(&signing_key_gstrkey, &toml_web_auth)),
        )
        .mount(&mock_server)
        .await;

    // SEP-10 GET: challenge signed by `wrong_key` (NOT `server_key`).
    // The sep10 client verifies the server signature against the SIGNING_KEY
    // from stellar.toml → rejects.  The gate aborts before the POST step, so
    // the captured_account Arc is unused here but required by the struct.
    let challenge_responder = Sep10ChallengeResponder {
        server_key: SigningKey::from_bytes(&wrong_key.to_bytes()), // ← wrong key
        home_domain: mock_host.clone(),
        web_auth_domain_value: server_host(&mock_server),
        network_passphrase: TESTNET_PASSPHRASE.to_owned(),
        captured_account: Arc::new(Mutex::new(String::new())),
    };
    Mock::given(method("GET"))
        .and(path(SEP10_AUTH_PATH))
        .respond_with(challenge_responder)
        .mount(&mock_server)
        .await;

    let http = test_http_client();
    let result = resolve_and_verify_counterparty_at(
        &mock_host,
        TESTNET_PASSPHRASE,
        &mock_server.uri(),
        &http,
        Some(&http_web_auth),
    )
    .await;

    assert!(
        matches!(result, Err(IdentityError::Sep10AuthFailed { .. })),
        "challenge not signed by SIGNING_KEY must return Sep10AuthFailed (full gate); got: {result:?}"
    );
}

// ═════════════════════════════════════════════════════════════════════════════
// 302 REDIRECT ABORT TEST
// ═════════════════════════════════════════════════════════════════════════════

/// Redirect abort: stellar.toml endpoint returns 302 → gate aborts.
///
/// Drives the test SEAM with an explicit no-redirect client and asserts a 302
/// on stellar.toml aborts the gate (and that the redirect TARGET server
/// receives zero requests). NOTE: this does NOT itself drive the production
/// `resolve_and_verify_counterparty`, which cannot be wiremock'd (it synthesises
/// `https://{home_domain}/` + LDH-validates). The PRODUCTION no-redirect
/// guarantee holds by composition: `fetch_stellar_toml` (owned + asserted in
/// `stellar-agent-network`) builds a `redirect::Policy::none()` client and
/// additionally rejects any 3xx at the status layer regardless of client policy.
#[tokio::test]
async fn gate_abort_toml_redirect_not_followed() {
    let redirect_server = MockServer::start().await;
    let target_server = MockServer::start().await;

    // Mount a 302 on the redirect server pointing to the target server.
    let target_toml_url = format!("{}/redirected-toml", target_server.uri());
    Mock::given(method("GET"))
        .and(path("/.well-known/stellar.toml"))
        .respond_with(
            ResponseTemplate::new(302).insert_header("location", target_toml_url.as_str()),
        )
        .mount(&redirect_server)
        .await;

    // The target server serves a valid stellar.toml (must NOT be reached).
    let server_key = gen_keypair();
    let signing_key_gstrkey = pubkey_to_gstrkey(&server_key);
    let toml_body = format!("SIGNING_KEY = \"{signing_key_gstrkey}\"\n");
    Mock::given(method("GET"))
        .and(path("/redirected-toml"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/plain")
                .set_body_string(toml_body),
        )
        .mount(&target_server)
        .await;

    // Production path: `resolve_and_verify_counterparty` fetches via
    // `fetch_stellar_toml`, which uses `redirect::Policy::none()` internally.
    // We can't easily drive the production path with a wiremock server because
    // it requires an LDH domain + HTTPS.
    //
    // Test seam path: use resolve_and_verify_counterparty_at with a test HTTP
    // client configured with NO redirect following (mirroring the production
    // fetch's no-redirect policy). This verifies the gate uses a no-redirect
    // client.
    let no_redirect_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .expect("no-redirect client");

    let mock_host = server_host_port(&redirect_server);
    let result = resolve_and_verify_counterparty_at(
        &mock_host,
        TESTNET_PASSPHRASE,
        &redirect_server.uri(),
        &no_redirect_client,
        None,
    )
    .await;

    // With no-redirect, the 302 must abort the gate.
    assert!(
        result.is_err(),
        "302 redirect must abort the gate (no-redirect policy); got Ok"
    );
    assert!(
        matches!(
            result,
            Err(IdentityError::HomeDomainUnresolvable { .. })
                | Err(IdentityError::TomlFetchFailed { .. })
        ),
        "302 abort must return HomeDomainUnresolvable or TomlFetchFailed; got: {result:?}"
    );

    // The target server must NOT have been hit (redirect was not followed).
    let target_reqs = target_server.received_requests().await.unwrap_or_default();
    assert_eq!(
        target_reqs.len(),
        0,
        "target server must NOT be hit when redirect is not followed; got {} requests",
        target_reqs.len()
    );
}

// ═════════════════════════════════════════════════════════════════════════════
// PRODUCTION PATH TESTS (no seam)
// ═════════════════════════════════════════════════════════════════════════════

/// Gate abort (production path): invalid home_domain → `HomeDomainInvalid`.
///
/// An invalid `home_domain` returns a DISTINCT `HomeDomainInvalid` error
/// (caller-input error), not the network-reachability `HomeDomainUnresolvable`.
/// No network I/O is attempted.
#[tokio::test]
async fn gate_abort_invalid_home_domain_returns_home_domain_invalid() {
    // "UPPERCASE.COM" fails is_valid_ldh_home_domain (uppercase not allowed).
    let result = resolve_and_verify_counterparty("UPPERCASE.COM", TESTNET_PASSPHRASE).await;
    assert!(
        matches!(result, Err(IdentityError::HomeDomainInvalid { .. })),
        "invalid home_domain must return HomeDomainInvalid (not HomeDomainUnresolvable); got: {result:?}"
    );

    // Verify the wire_code is distinct from unresolvable.
    let err = result.unwrap_err();
    assert_eq!(err.wire_code(), "identity.home_domain_invalid");
}

/// Gate abort (production path): LDH-valid but unreachable domain →
/// `HomeDomainUnresolvable` (distinct from `HomeDomainInvalid`).
#[tokio::test]
async fn gate_abort_unreachable_domain_returns_home_domain_unresolvable() {
    // A valid LDH domain that is not listening.
    let result =
        resolve_and_verify_counterparty("unreachable.stellar.invalid", TESTNET_PASSPHRASE).await;

    assert!(
        result.is_err(),
        "unreachable domain must return Err; got Ok"
    );
    let err = result.unwrap_err();
    assert!(
        matches!(err, IdentityError::HomeDomainUnresolvable { .. }),
        "unreachable domain must return HomeDomainUnresolvable; got: {err:?}"
    );
    assert_eq!(err.wire_code(), "identity.home_domain_unresolvable");
}

// ═════════════════════════════════════════════════════════════════════════════
// REDACTION TESTS
// ═════════════════════════════════════════════════════════════════════════════

/// Redaction: `HomeDomainUnresolvable` Display is authority-only.
#[test]
fn redaction_home_domain_unresolvable_authority_only() {
    let err = IdentityError::HomeDomainUnresolvable {
        authority: "example.com".to_owned(),
    };
    let display = err.to_string();
    assert!(
        display.contains("example.com"),
        "must include authority: {display}"
    );
    assert!(
        !display.contains("/.well-known/stellar.toml"),
        "must NOT include URL path: {display}"
    );
}

/// Redaction: `HomeDomainInvalid` Display is sanitised detail only.
#[test]
fn redaction_home_domain_invalid_no_full_domain() {
    let err = IdentityError::HomeDomainInvalid {
        detail: "domain contains uppercase characters".to_owned(),
    };
    let display = err.to_string();
    assert!(
        display.contains("uppercase"),
        "must include detail: {display}"
    );
    assert!(
        !display.contains("/.well-known"),
        "must NOT include URL path: {display}"
    );
}

/// Redaction: `TomlFetchFailed` Display is authority-only.
#[test]
fn redaction_toml_fetch_failed_authority_only() {
    let err = IdentityError::TomlFetchFailed {
        authority: "example.com:8443".to_owned(),
        reason: "TOML parse error: invalid syntax".to_owned(),
    };
    let display = err.to_string();
    assert!(
        display.contains("example.com:8443"),
        "must include authority with port: {display}"
    );
    assert!(
        !display.contains("/.well-known"),
        "must NOT include URL path: {display}"
    );
}

/// Redaction: `Sep10AuthFailed` Display never includes JWT.
#[test]
fn redaction_sep10_auth_failed_no_jwt() {
    let fake_jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJHQUJDIn0.SIG";
    let err = IdentityError::Sep10AuthFailed {
        reason: "challenge window expired".to_owned(),
    };
    let display = err.to_string();
    assert!(
        !display.contains(fake_jwt),
        "must NOT contain JWT: {display}"
    );
}

// ═════════════════════════════════════════════════════════════════════════════
// EPHEMERAL-KEY HYGIENE TESTS
// ═════════════════════════════════════════════════════════════════════════════

/// Ephemeral-key hygiene: per-request key uniqueness (via sep10 test helpers).
#[test]
fn ephemeral_key_hygiene_per_request_uniqueness() {
    use stellar_agent_sep10::ephemeral::{generate_ephemeral_seed, signing_key_from_seed};
    let seed1 = generate_ephemeral_seed();
    let seed2 = generate_ephemeral_seed();
    assert_ne!(*seed1, *seed2, "two OsRng seeds must differ");
    let key1 = signing_key_from_seed(&seed1);
    let key2 = signing_key_from_seed(&seed2);
    assert_ne!(
        pubkey_to_gstrkey(&key1),
        pubkey_to_gstrkey(&key2),
        "two ephemeral sessions must produce distinct G-strkeys"
    );
}

// ═════════════════════════════════════════════════════════════════════════════
// WIRE_CODE COVERAGE
// ═════════════════════════════════════════════════════════════════════════════

/// All `IdentityError` variants return a stable non-empty `wire_code()`.
#[test]
fn all_identity_error_variants_have_stable_wire_codes() {
    let variants: &[IdentityError] = &[
        IdentityError::HomeDomainInvalid {
            detail: "uppercase".to_owned(),
        },
        IdentityError::HomeDomainUnresolvable {
            authority: "x.com".to_owned(),
        },
        IdentityError::TomlFetchFailed {
            authority: "x.com".to_owned(),
            reason: "parse error".to_owned(),
        },
        IdentityError::WebAuthEndpointMissing {
            home_domain: "x.com".to_owned(),
        },
        IdentityError::SigningKeyMissing {
            home_domain: "x.com".to_owned(),
        },
        IdentityError::WebAuthEndpointHostMismatch {
            endpoint_host: "evil.org".to_owned(),
            home_domain: "x.com".to_owned(),
        },
        IdentityError::Sep10AuthFailed {
            reason: "expired".to_owned(),
        },
    ];
    for err in variants {
        let code = err.wire_code();
        assert!(!code.is_empty(), "wire_code must be non-empty: {err:?}");
        assert!(
            code.starts_with("identity."),
            "wire_code must start with 'identity.': {code}"
        );
        let _ = err.to_string(); // Display must not panic.
    }
}
