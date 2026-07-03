//! SEP-45 end-to-end round-trip acceptance tests.
//!
//! Exercises the full `auth_with_ephemeral_key` flow using a wiremock-backed
//! mock HTTP server (`new_for_unit_test` bypasses HTTPS-only enforcement).
//! All tests use the mock server; no live-anchor network I/O is performed.
//!
//! # Feature gate
//!
//! Gated behind `--features test-helpers`. Run with:
//! ```sh
//! cargo test -p stellar-agent-sep45 --features test-helpers \
//!     --test sep45_round_trip_acceptance
//! ```
//!
//! The `testnet-integration` feature is reserved for future live-anchor tests
//! once a SEP-45 `WEB_AUTH_FOR_CONTRACTS_ENDPOINT` is confirmed on
//! `testanchor.stellar.org`. All tests here use a `wiremock` mock server only.
//!
//! # Serial execution
//!
//! Tests run under `#[serial]` because they share process-global HTTP and
//! mock-server state; concurrent execution would race.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics acceptable in acceptance tests"
)]
#![allow(
    clippy::print_stderr,
    reason = "test-only; eprintln! used for skip notifications to the test runner"
)]

#[cfg(feature = "test-helpers")]
mod tests {
    use serial_test::serial;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use stellar_agent_sep45::{
        ChallengeRequest, Sep45Client, Sep45Session, ephemeral::auth_with_ephemeral_key,
    };

    // ── Test constants ────────────────────────────────────────────────────────

    const NETWORK_PASSPHRASE: &str = "Test SDF Network ; September 2015";

    /// C-strkey contract address used as the web auth contract in all tests.
    /// This is the `WEB_AUTH_CONTRACT_ID` the mock server claims to operate.
    const WEB_AUTH_CONTRACT: &str = "CALI6JC3MSNDGFRP7Z2OKUEPREHOJRRXKMJEWQDEFZPFGXALA45RAUTH";

    /// The mock anchor's home domain.
    const HOME_DOMAIN: &str = "mock-anchor.example.com";

    /// The mock anchor's web auth domain.
    const WEB_AUTH_DOMAIN: &str = "auth.mock-anchor.example.com";

    /// The server signing key seed (fixed for deterministic test fixtures).
    const SERVER_SEED: [u8; 32] = [1u8; 32];

    /// The client contract address used in all test challenges.
    const CLIENT_ACCOUNT: &str = "CABAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAFNSZ";

    /// A 32-byte ASCII nonce string — matches the entries.rs test fixture nonce.
    const NONCE: &str = "A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6";

    // ── Shared fixture builder ────────────────────────────────────────────────

    /// Derives the G-strkey server signing key from a seed.
    fn server_signing_key_str(seed: &[u8; 32]) -> String {
        use ed25519_dalek::SigningKey;
        let sk = SigningKey::from_bytes(seed);
        format!(
            "{}",
            stellar_strkey::ed25519::PublicKey(sk.verifying_key().to_bytes())
        )
    }

    /// Builds a valid two-entry `SorobanAuthorizationEntries` XDR base64 string
    /// in the standard challenge format expected by `parse_and_validate`.
    ///
    /// The server entry carries a real ed25519 signature. The client entry has
    /// a `Void` signature (awaiting client signing by `auth_with_ephemeral_key`).
    fn build_challenge_xdr(server_seed: &[u8; 32], client_account: &str, nonce: &str) -> String {
        use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
        use ed25519_dalek::{Signer, SigningKey};
        use sha2::{Digest, Sha256};
        use stellar_xdr::{
            AccountId, ContractId, Hash, HashIdPreimage, HashIdPreimageSorobanAuthorization,
            InvokeContractArgs, Limits, PublicKey as XdrPublicKey, ScAddress, ScBytes, ScMap,
            ScMapEntry, ScString, ScSymbol, ScVal, ScVec, SorobanAddressCredentials,
            SorobanAuthorizationEntries, SorobanAuthorizationEntry, SorobanAuthorizedFunction,
            SorobanAuthorizedInvocation, SorobanCredentials, Uint256, VecM, WriteXdr,
        };

        let contract_bytes = stellar_strkey::Contract::from_string(WEB_AUTH_CONTRACT)
            .unwrap()
            .0;
        let contract_address = ScAddress::Contract(ContractId(Hash(contract_bytes)));

        let server_key = SigningKey::from_bytes(server_seed);
        let server_pubkey = server_key.verifying_key().to_bytes();
        let server_g_str = format!("{}", stellar_strkey::ed25519::PublicKey(server_pubkey));

        // Build args map (shared by both entries — same nonce required by step 9).
        let make_args_map = |web_auth_domain: &str| -> ScVal {
            let entries = vec![
                ScMapEntry {
                    key: ScVal::Symbol(ScSymbol("account".try_into().unwrap())),
                    val: ScVal::String(ScString(client_account.try_into().unwrap())),
                },
                ScMapEntry {
                    key: ScVal::Symbol(ScSymbol("home_domain".try_into().unwrap())),
                    val: ScVal::String(ScString(HOME_DOMAIN.try_into().unwrap())),
                },
                ScMapEntry {
                    key: ScVal::Symbol(ScSymbol("nonce".try_into().unwrap())),
                    val: ScVal::String(ScString(nonce.try_into().unwrap())),
                },
                ScMapEntry {
                    key: ScVal::Symbol(ScSymbol("web_auth_domain".try_into().unwrap())),
                    val: ScVal::String(ScString(web_auth_domain.try_into().unwrap())),
                },
                ScMapEntry {
                    key: ScVal::Symbol(ScSymbol("web_auth_domain_account".try_into().unwrap())),
                    val: ScVal::String(ScString(server_g_str.as_str().try_into().unwrap())),
                },
            ];
            ScVal::Map(Some(ScMap(entries.try_into().unwrap())))
        };

        let fn_args = InvokeContractArgs {
            contract_address: contract_address.clone(),
            function_name: ScSymbol("web_auth_verify".try_into().unwrap()),
            args: vec![make_args_map(WEB_AUTH_DOMAIN)].try_into().unwrap(),
        };

        let invocation = SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::ContractFn(fn_args),
            sub_invocations: VecM::default(),
        };

        // Server entry: compute and attach real signature.
        let nonce_i64: i64 = 12_345_678;
        let expiry: u32 = 9_999_999;

        let network_id = {
            let mut h = Sha256::new();
            h.update(NETWORK_PASSPHRASE.as_bytes());
            Hash(h.finalize().into())
        };
        let preimage = HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
            network_id,
            nonce: nonce_i64,
            signature_expiration_ledger: expiry,
            invocation: invocation.clone(),
        });
        let mut preimage_bytes = Vec::new();
        preimage
            .write_xdr(&mut stellar_xdr::Limited::new(
                &mut preimage_bytes,
                Limits::none(),
            ))
            .unwrap();
        let payload: [u8; 32] = {
            let mut h = Sha256::new();
            h.update(&preimage_bytes);
            h.finalize().into()
        };
        let sig_bytes = server_key.sign(&payload).to_bytes();

        let server_sig_val = ScVal::Vec(Some(ScVec(
            vec![ScVal::Map(Some(ScMap(
                vec![
                    ScMapEntry {
                        key: ScVal::Symbol(ScSymbol("public_key".try_into().unwrap())),
                        val: ScVal::Bytes(ScBytes(server_pubkey.to_vec().try_into().unwrap())),
                    },
                    ScMapEntry {
                        key: ScVal::Symbol(ScSymbol("signature".try_into().unwrap())),
                        val: ScVal::Bytes(ScBytes(sig_bytes.to_vec().try_into().unwrap())),
                    },
                ]
                .try_into()
                .unwrap(),
            )))]
            .try_into()
            .unwrap(),
        )));

        let server_entry = SorobanAuthorizationEntry {
            credentials: SorobanCredentials::Address(SorobanAddressCredentials {
                address: ScAddress::Account(AccountId(XdrPublicKey::PublicKeyTypeEd25519(
                    Uint256(server_pubkey),
                ))),
                nonce: nonce_i64,
                signature_expiration_ledger: expiry,
                signature: server_sig_val,
            }),
            root_invocation: invocation.clone(),
        };

        // Client entry: unsigned (Void signature).
        let client_bytes = stellar_strkey::Contract::from_string(client_account)
            .unwrap()
            .0;
        let client_entry = SorobanAuthorizationEntry {
            credentials: SorobanCredentials::Address(SorobanAddressCredentials {
                address: ScAddress::Contract(ContractId(Hash(client_bytes))),
                nonce: 87_654_321i64,
                signature_expiration_ledger: 0,
                signature: ScVal::Void,
            }),
            root_invocation: invocation,
        };

        let entries_xdr =
            SorobanAuthorizationEntries(vec![server_entry, client_entry].try_into().unwrap());
        let mut out = Vec::new();
        entries_xdr
            .write_xdr(&mut stellar_xdr::Limited::new(&mut out, Limits::none()))
            .unwrap();
        BASE64_STANDARD.encode(&out)
    }

    /// Builds a well-formed JWT string for a C-strkey sub.
    fn build_mock_jwt(sub: &str) -> String {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256","typ":"JWT"}"#);
        let payload = serde_json::json!({
            "sub": sub,
            "iss": "https://mock-anchor.example.com",
            "iat": 1_700_000_000u64,
            "exp": 9_999_999_999u64,
        })
        .to_string();
        let payload_b64 = URL_SAFE_NO_PAD.encode(&payload);
        format!("{header}.{payload_b64}.mocksignature")
    }

    // ── Happy path: full round-trip via auth_with_ephemeral_key ──────────────

    /// Happy path — full round-trip via `auth_with_ephemeral_key`.
    ///
    /// Exercises:
    /// 1. Challenge fetch (GET mock) + 13-point SEP-45 validation.
    /// 2. Ephemeral key generation + client entry signing.
    /// 3. Signed entries submission (POST mock).
    /// 4. JWT session extraction + expiry check.
    ///
    /// The mock server:
    /// - GET `/sep45/auth` responds with the challenge XDR + network passphrase.
    /// - POST `/sep45/auth` responds with a JWT token string.
    ///
    /// Assertions:
    /// - Session `sub` is a C-strkey (starts with "C").
    /// - Session is not expired at receipt.
    /// - JWT raw string has exactly 3 segments.
    #[tokio::test]
    #[serial]
    async fn full_round_trip_produces_valid_session() {
        let mock_server = MockServer::start().await;
        let server_key_str = server_signing_key_str(&SERVER_SEED);

        // Build the challenge XDR the mock server will return.
        let challenge_xdr = build_challenge_xdr(&SERVER_SEED, CLIENT_ACCOUNT, NONCE);

        // Mock GET: return challenge JSON.
        Mock::given(method("GET"))
            .and(path("/sep45/auth"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "authorization_entries": challenge_xdr,
                "network_passphrase": NETWORK_PASSPHRASE,
            })))
            .mount(&mock_server)
            .await;

        // Mock POST: return JWT token JSON.
        // The mock accepts ANY signed XDR body (ephemeral key is random).
        let mock_jwt = build_mock_jwt(CLIENT_ACCOUNT);
        Mock::given(method("POST"))
            .and(path("/sep45/auth"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "token": mock_jwt,
            })))
            .mount(&mock_server)
            .await;

        let client =
            Sep45Client::new_for_unit_test(NETWORK_PASSPHRASE).expect("client must construct");
        let endpoint = format!("{}/sep45/auth", mock_server.uri());

        let session = auth_with_ephemeral_key(
            &client,
            ChallengeRequest {
                web_auth_endpoint: &endpoint,
                contract_id: CLIENT_ACCOUNT,
                home_domain: HOME_DOMAIN,
                expected_web_auth_contract: WEB_AUTH_CONTRACT,
                expected_server_signing_key: &server_key_str,
                client_domain: None,
                web_auth_domain: Some(WEB_AUTH_DOMAIN),
                signature_expiration_ledger: 9_999_999,
            },
        )
        .await
        .expect("auth_with_ephemeral_key must succeed against mock server");

        // sub must be a C-prefix contract strkey.
        assert!(
            session.contract_id().starts_with('C'),
            "session sub must be a C-strkey; sub='{}'",
            session.sub
        );

        // Session must not be expired at receipt.
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(
            !session.is_expired(now_unix),
            "freshly-obtained session must not be expired; exp={}, now={}",
            session.exp,
            now_unix
        );

        // JWT must have exactly 3 segments.
        let segments: Vec<&str> = session.jwt.split('.').collect();
        assert_eq!(
            segments.len(),
            3,
            "JWT must have exactly 3 dot-separated segments; got {}",
            segments.len()
        );

        // contract_id() must equal sub.
        assert_eq!(
            session.contract_id(),
            session.sub.as_str(),
            "contract_id() must return the full sub claim"
        );
    }

    /// Session `is_expired()` correctly identifies a non-expired session at
    /// receipt time, and marks the same session expired at u64::MAX.
    #[tokio::test]
    #[serial]
    async fn session_is_not_expired_at_receipt_is_expired_at_max() {
        let mock_server = MockServer::start().await;
        let server_key_str = server_signing_key_str(&SERVER_SEED);
        let challenge_xdr = build_challenge_xdr(&SERVER_SEED, CLIENT_ACCOUNT, NONCE);

        Mock::given(method("GET"))
            .and(path("/sep45/auth"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "authorization_entries": challenge_xdr,
                "network_passphrase": NETWORK_PASSPHRASE,
            })))
            .mount(&mock_server)
            .await;

        let mock_jwt = build_mock_jwt(CLIENT_ACCOUNT);
        Mock::given(method("POST"))
            .and(path("/sep45/auth"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "token": mock_jwt,
            })))
            .mount(&mock_server)
            .await;

        let client =
            Sep45Client::new_for_unit_test(NETWORK_PASSPHRASE).expect("client must construct");
        let endpoint = format!("{}/sep45/auth", mock_server.uri());

        let session = auth_with_ephemeral_key(
            &client,
            ChallengeRequest {
                web_auth_endpoint: &endpoint,
                contract_id: CLIENT_ACCOUNT,
                home_domain: HOME_DOMAIN,
                expected_web_auth_contract: WEB_AUTH_CONTRACT,
                expected_server_signing_key: &server_key_str,
                client_domain: None,
                web_auth_domain: Some(WEB_AUTH_DOMAIN),
                signature_expiration_ledger: 9_999_999,
            },
        )
        .await
        .expect("auth_with_ephemeral_key must succeed");

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        assert!(
            !session.is_expired(now),
            "freshly-obtained session must not be expired; exp={} now={now}",
            session.exp
        );
        assert!(
            session.is_expired(u64::MAX),
            "session must be expired at u64::MAX"
        );
    }

    /// `Sep45Session::parse` round-trips through the JWT correctly.
    ///
    /// After a successful auth round-trip, parsing the raw `jwt` field again
    /// produces the same `sub`, `iss`, and `exp` values.
    #[tokio::test]
    #[serial]
    async fn session_jwt_round_trips_through_parse() {
        let mock_server = MockServer::start().await;
        let server_key_str = server_signing_key_str(&SERVER_SEED);
        let challenge_xdr = build_challenge_xdr(&SERVER_SEED, CLIENT_ACCOUNT, NONCE);

        Mock::given(method("GET"))
            .and(path("/sep45/auth"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "authorization_entries": challenge_xdr,
                "network_passphrase": NETWORK_PASSPHRASE,
            })))
            .mount(&mock_server)
            .await;

        let mock_jwt = build_mock_jwt(CLIENT_ACCOUNT);
        Mock::given(method("POST"))
            .and(path("/sep45/auth"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "token": mock_jwt,
            })))
            .mount(&mock_server)
            .await;

        let client =
            Sep45Client::new_for_unit_test(NETWORK_PASSPHRASE).expect("client must construct");
        let endpoint = format!("{}/sep45/auth", mock_server.uri());

        let session = auth_with_ephemeral_key(
            &client,
            ChallengeRequest {
                web_auth_endpoint: &endpoint,
                contract_id: CLIENT_ACCOUNT,
                home_domain: HOME_DOMAIN,
                expected_web_auth_contract: WEB_AUTH_CONTRACT,
                expected_server_signing_key: &server_key_str,
                client_domain: None,
                web_auth_domain: Some(WEB_AUTH_DOMAIN),
                signature_expiration_ledger: 9_999_999,
            },
        )
        .await
        .expect("auth_with_ephemeral_key must succeed");

        let re_parsed = Sep45Session::parse(&session.jwt)
            .expect("Sep45Session::parse must succeed on mock JWT");

        assert_eq!(re_parsed.sub, session.sub, "re-parsed sub must match");
        assert_eq!(re_parsed.iss, session.iss, "re-parsed iss must match");
        assert_eq!(re_parsed.exp, session.exp, "re-parsed exp must match");
        assert_eq!(re_parsed.iat, session.iat, "re-parsed iat must match");
    }

    // ── Fail path: bad server signature in challenge is rejected ─────────────

    /// Fail path — challenge with invalid server signature is rejected.
    ///
    /// The mock server returns a challenge XDR whose server entry was signed
    /// with SERVER_SEED but the caller passes a DIFFERENT key as
    /// `expected_server_signing_key`. `auth_with_ephemeral_key` must reject
    /// the challenge during validation (before any signing or POST).
    ///
    /// This validates that `Sep45Client::fetch_challenge` propagates the
    /// `InvalidServerSignature` error (or `MissingServerEntry`) correctly
    /// from `parse_and_validate` step 10/12.
    #[tokio::test]
    #[serial]
    async fn bad_server_signing_key_returns_validation_error() {
        let mock_server = MockServer::start().await;
        let challenge_xdr = build_challenge_xdr(&SERVER_SEED, CLIENT_ACCOUNT, NONCE);

        Mock::given(method("GET"))
            .and(path("/sep45/auth"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "authorization_entries": challenge_xdr,
                "network_passphrase": NETWORK_PASSPHRASE,
            })))
            .mount(&mock_server)
            .await;

        let client =
            Sep45Client::new_for_unit_test(NETWORK_PASSPHRASE).expect("client must construct");
        let endpoint = format!("{}/sep45/auth", mock_server.uri());

        // Pass a DIFFERENT server signing key (seed [2u8;32] ≠ SERVER_SEED [1u8;32]).
        let wrong_seed = [2u8; 32];
        let wrong_key_str = server_signing_key_str(&wrong_seed);

        let result = auth_with_ephemeral_key(
            &client,
            ChallengeRequest {
                web_auth_endpoint: &endpoint,
                contract_id: CLIENT_ACCOUNT,
                home_domain: HOME_DOMAIN,
                expected_web_auth_contract: WEB_AUTH_CONTRACT,
                expected_server_signing_key: &wrong_key_str,
                client_domain: None,
                web_auth_domain: Some(WEB_AUTH_DOMAIN),
                signature_expiration_ledger: 9_999_999,
            },
        )
        .await;

        assert!(
            result.is_err(),
            "wrong expected_server_signing_key must produce an error; got Ok(_)"
        );

        let err = result.unwrap_err();
        // `parse_and_validate` step 7 checks `web_auth_domain_account` (which
        // contains the actual server key A) against the caller-supplied expected
        // key B BEFORE reaching the entry-credentials walk at step 10.
        // `WebAuthDomainAccountMismatch` is therefore the first rejection
        // triggered when a wrong server signing key is supplied.  All three
        // variants indicate fail-closed rejection of the wrong key.
        assert!(
            matches!(
                err,
                stellar_agent_sep45::Sep45Error::MissingServerEntry
                    | stellar_agent_sep45::Sep45Error::InvalidServerSignature { .. }
                    | stellar_agent_sep45::Sep45Error::WebAuthDomainAccountMismatch { .. }
            ),
            "expected MissingServerEntry, InvalidServerSignature, or WebAuthDomainAccountMismatch; got {err:?}"
        );
    }

    /// Fail path — POST returns HTTP 400 (bad signature from server perspective).
    ///
    /// Simulates a server that returns a 400 error on the POST, which maps to
    /// `Sep45Error::HttpError`.
    ///
    /// This validates that `Sep45Client::submit_signed_challenge` correctly
    /// propagates the server's error response as a typed `Sep45Error`.
    #[tokio::test]
    #[serial]
    async fn bad_signature_on_post_returns_http_error() {
        let mock_server = MockServer::start().await;
        let server_key_str = server_signing_key_str(&SERVER_SEED);
        let challenge_xdr = build_challenge_xdr(&SERVER_SEED, CLIENT_ACCOUNT, NONCE);

        Mock::given(method("GET"))
            .and(path("/sep45/auth"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "authorization_entries": challenge_xdr,
                "network_passphrase": NETWORK_PASSPHRASE,
            })))
            .mount(&mock_server)
            .await;

        // POST returns HTTP 400 — server rejects the submitted signed entries.
        Mock::given(method("POST"))
            .and(path("/sep45/auth"))
            .respond_with(
                ResponseTemplate::new(400).set_body_string(r#"{"error":"invalid signature"}"#),
            )
            .mount(&mock_server)
            .await;

        let client =
            Sep45Client::new_for_unit_test(NETWORK_PASSPHRASE).expect("client must construct");
        let endpoint = format!("{}/sep45/auth", mock_server.uri());

        let result = auth_with_ephemeral_key(
            &client,
            ChallengeRequest {
                web_auth_endpoint: &endpoint,
                contract_id: CLIENT_ACCOUNT,
                home_domain: HOME_DOMAIN,
                expected_web_auth_contract: WEB_AUTH_CONTRACT,
                expected_server_signing_key: &server_key_str,
                client_domain: None,
                web_auth_domain: Some(WEB_AUTH_DOMAIN),
                signature_expiration_ledger: 9_999_999,
            },
        )
        .await;

        assert!(result.is_err(), "POST 400 must produce an error; got Ok(_)");
        let err = result.unwrap_err();
        assert!(
            matches!(err, stellar_agent_sep45::Sep45Error::HttpError { .. }),
            "POST 400 must produce HttpError; got {err:?}"
        );
    }

    /// Fail path — server returns a JWT whose `sub` does not match the
    /// `contract_id` passed to `auth_with_ephemeral_key`.
    ///
    /// `auth_with_ephemeral_key` must return `SessionAccountMismatch` when
    /// `session.sub != contract_id`.
    #[tokio::test]
    #[serial]
    async fn mismatched_jwt_sub_rejected_with_session_account_mismatch() {
        let mock_server = MockServer::start().await;
        let server_key_str = server_signing_key_str(&SERVER_SEED);
        let challenge_xdr = build_challenge_xdr(&SERVER_SEED, CLIENT_ACCOUNT, NONCE);

        Mock::given(method("GET"))
            .and(path("/sep45/auth"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "authorization_entries": challenge_xdr,
                "network_passphrase": NETWORK_PASSPHRASE,
            })))
            .mount(&mock_server)
            .await;

        // The JWT `sub` is a DIFFERENT contract account, not CLIENT_ACCOUNT.
        // Must be a valid C-strkey (stellar_strkey::Contract validation in Sep45Session::parse).
        let different_account = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM";
        let mock_jwt = build_mock_jwt(different_account);
        Mock::given(method("POST"))
            .and(path("/sep45/auth"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "token": mock_jwt,
            })))
            .mount(&mock_server)
            .await;

        let client =
            Sep45Client::new_for_unit_test(NETWORK_PASSPHRASE).expect("client must construct");
        let endpoint = format!("{}/sep45/auth", mock_server.uri());

        let result = auth_with_ephemeral_key(
            &client,
            ChallengeRequest {
                web_auth_endpoint: &endpoint,
                contract_id: CLIENT_ACCOUNT,
                home_domain: HOME_DOMAIN,
                expected_web_auth_contract: WEB_AUTH_CONTRACT,
                expected_server_signing_key: &server_key_str,
                client_domain: None,
                web_auth_domain: Some(WEB_AUTH_DOMAIN),
                signature_expiration_ledger: 9_999_999,
            },
        )
        .await;

        assert!(
            result.is_err(),
            "mismatched JWT sub must produce an error; got Ok(_)"
        );
        let err = result.unwrap_err();
        assert!(
            matches!(
                err,
                stellar_agent_sep45::Sep45Error::SessionAccountMismatch { .. }
            ),
            "expected SessionAccountMismatch; got {err:?}"
        );
    }
}
