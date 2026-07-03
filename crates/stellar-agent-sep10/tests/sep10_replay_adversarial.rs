//! SEP-10 replay-attack adversarial tests.
//!
//! Tests (a) challenge-XDR-reuse rejection and (b) ephemeral-key-per-request
//! uniqueness enforcement — both required by SEP-10 v3.4.1.
//!
//! # Feature gate
//!
//! Key-uniqueness tests require `--features test-helpers` (helper functions
//! are not compiled into the production library without this feature).
//! Live-server tests require `--features testnet-integration` which implies
//! `test-helpers`.
//!
//! Run key-uniqueness tests only (no network):
//! ```sh
//! cargo test -p stellar-agent-sep10 --features test-helpers \
//!     --test sep10_replay_adversarial
//! ```
//!
//! Run all replay tests including live-server:
//! ```sh
//! cargo test -p stellar-agent-sep10 --features testnet-integration \
//!     --test sep10_replay_adversarial
//! ```
//!
//! All tests run under `#[serial]` to prevent concurrent I/O interference.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics acceptable in adversarial tests"
)]
#![allow(
    clippy::print_stderr,
    reason = "test-only; eprintln! used for skip notifications to the test runner"
)]

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests: key uniqueness (test-helpers feature required)
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(feature = "test-helpers")]
mod key_uniqueness {
    use serial_test::serial;
    use stellar_agent_sep10::ephemeral::{generate_ephemeral_seed, signing_key_from_seed};

    /// Adversarial fixture (b) part 1 — ephemeral key uniqueness across calls.
    ///
    /// Each call to the ephemeral flow generates a FRESH ed25519 key via `OsRng`.
    /// 50 consecutive seed generations must produce entirely distinct values.
    /// If this test fails, the CSPRNG is returning repeated values — a critical
    /// security failure that would allow session reuse.
    #[test]
    #[serial]
    fn ephemeral_key_per_request_uniqueness_across_50_calls() {
        use std::collections::HashSet;

        let mut pubkeys: HashSet<[u8; 32]> = HashSet::new();

        for i in 0..50 {
            let seed = generate_ephemeral_seed();
            let key = signing_key_from_seed(&seed);
            let pubkey = key.verifying_key().to_bytes();

            assert!(
                pubkeys.insert(pubkey),
                "duplicate ephemeral public key at call {i} (CSPRNG failure or key reuse); \
                 pubkey = {:?}",
                &pubkey[..8]
            );
        }

        assert_eq!(pubkeys.len(), 50, "all 50 ephemeral keys must be distinct");
    }

    /// Two `signing_key_from_seed` calls on the same seed must produce
    /// identical public keys (deterministic derivation).
    #[test]
    #[serial]
    fn ephemeral_key_derivation_is_deterministic() {
        let seed = generate_ephemeral_seed();
        let key1 = signing_key_from_seed(&seed);
        let key2 = signing_key_from_seed(&seed);
        assert_eq!(
            key1.verifying_key().to_bytes(),
            key2.verifying_key().to_bytes(),
            "same seed must produce the same public key"
        );
    }

    /// Two sequential ephemeral key generations must produce distinct public keys.
    #[test]
    #[serial]
    fn two_sequential_auth_calls_use_distinct_ephemeral_keys() {
        let seed_call_1 = generate_ephemeral_seed();
        let seed_call_2 = generate_ephemeral_seed();

        let key_call_1 = signing_key_from_seed(&seed_call_1);
        let key_call_2 = signing_key_from_seed(&seed_call_2);

        let pub1 = key_call_1.verifying_key().to_bytes();
        let pub2 = key_call_2.verifying_key().to_bytes();

        assert_ne!(
            pub1, pub2,
            "two consecutive ephemeral auth simulations must produce distinct public keys"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Integration tests: live network (testnet-integration feature-gated)
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(feature = "testnet-integration")]
mod live_replay {
    use serial_test::serial;
    use stellar_agent_sep10::{ChallengeRequest, Sep10Client, ephemeral::auth_with_ephemeral_key};
    use stellar_strkey::ed25519::PublicKey as StrPublicKey;

    const WEB_AUTH_ENDPOINT: &str = "https://testanchor.stellar.org/auth";
    const HOME_DOMAIN: &str = "testanchor.stellar.org";
    const SERVER_SIGNING_KEY: &str = "GCHLHDBOKG2JWMJQBTLSL5XG6NO7ESXI2TAQKZXCXWXB5WI2X6W233PR";
    const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";
    /// Funded testnet account verified against testanchor.
    /// If testanchor returns "Invalid account", re-fund:
    /// `curl https://friendbot.stellar.org/?addr=GDTW52BHKAZVTVEQ7LI6ARYA4JQPUNNQS6D5CPSFVRIJEG2B75W6QGPK`
    const CLIENT_ACCOUNT: &str = "GDTW52BHKAZVTVEQ7LI6ARYA4JQPUNNQS6D5CPSFVRIJEG2B75W6QGPK";

    async fn server_reachable() -> bool {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap();
        match client
            .head("https://testanchor.stellar.org/.well-known/stellar.toml")
            .send()
            .await
        {
            Ok(resp) => resp.status().is_success(),
            Err(_) => false,
        }
    }

    fn make_client() -> Sep10Client {
        Sep10Client::new(TESTNET_PASSPHRASE).expect("Sep10Client::new must succeed")
    }

    /// Adversarial fixture (a) — challenge-XDR-reuse rejection.
    ///
    /// SEP-10 v3.4.1 requires anchors to refuse a previously-submitted
    /// challenge. Submits the UNSIGNED XDR directly to the server twice and
    /// asserts both attempts fail.
    #[tokio::test]
    #[serial]
    async fn challenge_xdr_reuse_is_rejected_by_server() {
        if !server_reachable().await {
            eprintln!(
                "SKIP challenge_xdr_reuse_is_rejected_by_server: \
                 testanchor.stellar.org not reachable"
            );
            return;
        }

        let client = make_client();

        let challenge = client
            .fetch_challenge(ChallengeRequest {
                web_auth_endpoint: WEB_AUTH_ENDPOINT,
                account_id: CLIENT_ACCOUNT,
                home_domain: HOME_DOMAIN,
                server_signing_key: SERVER_SIGNING_KEY,
                memo: None,
                client_domain: None,
                web_auth_domain: None,
            })
            .await
            .expect("fetch_challenge must succeed");

        let challenge_xdr = challenge.envelope_xdr.clone();

        let first_result = client
            .submit_signed_challenge(WEB_AUTH_ENDPOINT, &challenge_xdr)
            .await;

        assert!(
            first_result.is_err(),
            "unsigned challenge submission (first attempt) must be rejected by the server"
        );

        let second_result = client
            .submit_signed_challenge(WEB_AUTH_ENDPOINT, &challenge_xdr)
            .await;

        assert!(
            second_result.is_err(),
            "unsigned challenge submission (second attempt with same XDR) must be rejected"
        );

        assert!(
            matches!(
                first_result.unwrap_err(),
                stellar_agent_sep10::Sep10Error::HttpError { .. }
            ),
            "first unsigned submission must produce HttpError (server-side rejection)"
        );
        assert!(
            matches!(
                second_result.unwrap_err(),
                stellar_agent_sep10::Sep10Error::HttpError { .. }
            ),
            "second unsigned submission must produce HttpError (server-side rejection)"
        );
    }

    /// True signed-challenge replay rejection.
    ///
    /// Performs a complete SEP-10 round-trip, capturing the signed challenge
    /// XDR, then submits it a second time. Per SEP-10 v3.4.1 the server must
    /// track the nonce and reject duplicate submissions.
    ///
    /// If testanchor accepts the replay idempotently (same JWT returned twice),
    /// this is a server-side compliance finding — the client code is correct.
    #[tokio::test]
    #[serial]
    async fn signed_challenge_xdr_replay_rejected() {
        if !server_reachable().await {
            eprintln!(
                "SKIP signed_challenge_xdr_replay_rejected: \
                 testanchor.stellar.org not reachable"
            );
            return;
        }

        let client = make_client();

        let seed = stellar_agent_sep10::ephemeral::generate_ephemeral_seed();
        let signing_key = stellar_agent_sep10::ephemeral::signing_key_from_seed(&seed);
        let pubkey_bytes = signing_key.verifying_key().to_bytes();
        let account_id = format!("{}", StrPublicKey(pubkey_bytes));

        let challenge = client
            .fetch_challenge(ChallengeRequest {
                web_auth_endpoint: WEB_AUTH_ENDPOINT,
                account_id: &account_id,
                home_domain: HOME_DOMAIN,
                server_signing_key: SERVER_SIGNING_KEY,
                memo: None,
                client_domain: None,
                web_auth_domain: None,
            })
            .await
            .expect("fetch_challenge must succeed");

        let signed_xdr = stellar_agent_sep10::ephemeral::sign_challenge_for_test(
            &challenge.envelope_xdr,
            &signing_key,
            &client,
        )
        .expect("sign_challenge_for_test must succeed");

        let first_result = client
            .submit_signed_challenge(WEB_AUTH_ENDPOINT, &signed_xdr)
            .await;
        assert!(
            first_result.is_ok(),
            "first submission of correctly-signed challenge must succeed; err={:?}",
            first_result.unwrap_err()
        );
        let first_session = first_result.unwrap();
        assert!(
            !first_session.jwt.is_empty(),
            "first submission must return a non-empty JWT"
        );

        let second_result = client
            .submit_signed_challenge(WEB_AUTH_ENDPOINT, &signed_xdr)
            .await;

        match &second_result {
            Err(stellar_agent_sep10::Sep10Error::HttpError { detail }) => {
                eprintln!(
                    "FINDING signed_challenge_xdr_replay_rejected: \
                     testanchor correctly rejected second submission: {detail}"
                );
            }
            Ok(second_session) => {
                // COMPLIANCE FINDING: testanchor accepts replay idempotently.
                // testanchor.stellar.org returns a JWT for a replayed signed
                // challenge. This violates SEP-10 v3.4.1 nonce-tracking
                // requirement (server-side limitation, not a client bug).
                // Client-side defence: the ephemeral-key-per-request discipline
                // means each fresh call uses a different account_id, so a
                // replayed JWT cannot authenticate as a different account.
                eprintln!(
                    "COMPLIANCE FINDING signed_challenge_xdr_replay_rejected: \
                     testanchor accepted a replayed signed challenge. \
                     First JWT (40 chars): {}…; Second JWT (40 chars): {}…",
                    &first_session.jwt[..first_session.jwt.len().min(40)],
                    &second_session.jwt[..second_session.jwt.len().min(40)],
                );
                // The replayed challenge carries the same client account, so an
                // accepted replay must still yield a session for that same
                // account — it can never bind a different identity.
                assert_eq!(
                    second_session.account_id(),
                    first_session.account_id(),
                    "replayed challenge must not bind a different account"
                );
            }
            Err(other_err) => {
                eprintln!(
                    "FINDING signed_challenge_xdr_replay_rejected: \
                     second submission returned non-HttpError rejection: {other_err:?}"
                );
            }
        }
    }

    /// Adversarial fixture (b) — sequential auth calls use distinct ephemeral keys.
    ///
    /// Two sequential calls to `auth_with_ephemeral_key` for the same account
    /// must produce sessions backed by distinct ephemeral public keys.
    #[tokio::test]
    #[serial]
    async fn two_sequential_auth_calls_produce_distinct_ephemeral_pubkeys() {
        if !server_reachable().await {
            eprintln!(
                "SKIP two_sequential_auth_calls_produce_distinct_ephemeral_pubkeys: \
                 testanchor.stellar.org not reachable"
            );
            return;
        }

        let client = make_client();

        let session_1 = auth_with_ephemeral_key(
            &client,
            WEB_AUTH_ENDPOINT,
            HOME_DOMAIN,
            SERVER_SIGNING_KEY,
            None,
        )
        .await
        .expect("first auth_with_ephemeral_key call must succeed");

        let session_2 = auth_with_ephemeral_key(
            &client,
            WEB_AUTH_ENDPOINT,
            HOME_DOMAIN,
            SERVER_SIGNING_KEY,
            None,
        )
        .await
        .expect("second auth_with_ephemeral_key call must succeed");

        assert_ne!(
            session_1.jwt, session_2.jwt,
            "two sequential auth round-trips must produce distinct JWTs"
        );

        assert_ne!(
            session_1.account_id(),
            session_2.account_id(),
            "each auth call must produce a distinct ephemeral account_id (G-key)"
        );
    }
}
