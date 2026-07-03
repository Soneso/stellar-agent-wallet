//! SEP-10 testnet end-to-end round-trip acceptance tests.
//!
//! Exercises the full `auth_with_ephemeral_key` flow against the SDF testnet
//! anchor (`testanchor.stellar.org`) over a live network connection.
//!
//! # Feature gate
//!
//! Gated behind `--features testnet-integration`. Run with:
//! ```sh
//! cargo test -p stellar-agent-sep10 --features testnet-integration \
//!     --test sep10_round_trip_testnet_acceptance
//! ```
//!
//! # Reachability check
//!
//! Tests perform a reachability probe via the server's TOML endpoint before
//! running the full flow. If the server is unreachable, tests are skipped
//! with an informational message (no false-negative CI failure).
//!
//! All tests run under `#[serial]` to prevent concurrent I/O interference.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics acceptable in integration tests"
)]
#![allow(
    clippy::print_stderr,
    reason = "test-only; eprintln! used for skip notifications to the test runner"
)]

#[cfg(feature = "testnet-integration")]
mod tests {
    use serial_test::serial;
    use stellar_agent_sep10::{
        ChallengeRequest, Sep10Client, Sep10Session, ephemeral::auth_with_ephemeral_key,
    };

    /// SDF testnet anchor web-auth endpoint.
    const WEB_AUTH_ENDPOINT: &str = "https://testanchor.stellar.org/auth";

    /// SDF testnet anchor home domain.
    const HOME_DOMAIN: &str = "testanchor.stellar.org";

    /// SDF testanchor server signing key (published in its stellar.toml).
    ///
    /// Source: <https://testanchor.stellar.org/.well-known/stellar.toml>
    /// Verified 2026-06-19 against live testanchor TOML.
    const SERVER_SIGNING_KEY: &str = "GCHLHDBOKG2JWMJQBTLSL5XG6NO7ESXI2TAQKZXCXWXB5WI2X6W233PR";

    /// Stellar testnet passphrase.
    const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";

    /// A funded testnet account used as the client account for SEP-10 auth.
    ///
    /// The private key is NOT used for signing here — the ephemeral flow
    /// generates a fresh one-shot key per call.
    ///
    /// If testanchor returns "Invalid account" in future, re-fund via:
    /// `curl https://friendbot.stellar.org/?addr=GDTW52BHKAZVTVEQ7LI6ARYA4JQPUNNQS6D5CPSFVRIJEG2B75W6QGPK`
    const CLIENT_ACCOUNT: &str = "GDTW52BHKAZVTVEQ7LI6ARYA4JQPUNNQS6D5CPSFVRIJEG2B75W6QGPK";

    /// Returns `true` if the testanchor server is reachable.
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

    /// Happy path: full round-trip via `auth_with_ephemeral_key`.
    ///
    /// Exercises:
    /// 1. Challenge fetch + 13-point SEP-10 validation.
    /// 2. Ephemeral key generation + challenge signing.
    /// 3. Signed challenge submission.
    /// 4. JWT session extraction + expiry check.
    #[tokio::test]
    #[serial]
    async fn full_round_trip_produces_valid_session() {
        if !server_reachable().await {
            eprintln!(
                "SKIP full_round_trip_produces_valid_session: \
                 testanchor.stellar.org not reachable"
            );
            return;
        }

        let client = make_client();
        let session = auth_with_ephemeral_key(
            &client,
            WEB_AUTH_ENDPOINT,
            HOME_DOMAIN,
            SERVER_SIGNING_KEY,
            None,
        )
        .await
        .expect("auth_with_ephemeral_key must succeed against live testanchor");

        // Session sub is the ephemeral G-key (non-existent account).
        assert!(
            session.account_id().starts_with('G') && session.account_id().len() == 56,
            "session sub must be a valid G-strkey; sub='{}'",
            session.sub
        );

        assert!(
            session.iss.contains("testanchor.stellar.org"),
            "session iss must reference the anchor; iss='{}'",
            session.iss
        );

        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(
            !session.is_expired(now_unix),
            "session must not be expired at receipt time; exp={}, now={}",
            session.exp,
            now_unix
        );

        assert!(!session.jwt.is_empty(), "jwt must not be empty");
        let segments: Vec<&str> = session.jwt.split('.').collect();
        assert_eq!(
            segments.len(),
            3,
            "JWT must have exactly 3 dot-separated segments; got {}",
            segments.len()
        );
    }

    /// Submitting a challenge with an invalid signature must be rejected.
    ///
    /// Fetches a challenge and submits the unsigned XDR directly. The anchor
    /// must reject it with a non-200 response, surfaced as
    /// `Sep10Error::HttpError`.
    #[tokio::test]
    #[serial]
    async fn bad_signature_submission_returns_http_error() {
        if !server_reachable().await {
            eprintln!(
                "SKIP bad_signature_submission_returns_http_error: \
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

        // Submit the UNSIGNED challenge XDR directly — no client signature.
        let result = client
            .submit_signed_challenge(WEB_AUTH_ENDPOINT, &challenge.envelope_xdr)
            .await;

        assert!(
            result.is_err(),
            "unsigned challenge submission must fail; got Ok(_)"
        );
        let err = result.unwrap_err();
        assert!(
            matches!(err, stellar_agent_sep10::Sep10Error::HttpError { .. }),
            "unsigned submission must produce HttpError; got {err:?}"
        );
    }

    /// `is_expired()` correctly identifies a non-expired session at receipt time.
    #[tokio::test]
    #[serial]
    async fn session_is_not_expired_at_receipt() {
        if !server_reachable().await {
            eprintln!(
                "SKIP session_is_not_expired_at_receipt: \
                 testanchor.stellar.org not reachable"
            );
            return;
        }

        let client = make_client();
        let session = auth_with_ephemeral_key(
            &client,
            WEB_AUTH_ENDPOINT,
            HOME_DOMAIN,
            SERVER_SIGNING_KEY,
            None,
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

    /// After a successful auth round-trip, the parsed session's `jwt` field
    /// round-trips through `Sep10Session::parse` to the same sub/iss/exp.
    #[tokio::test]
    #[serial]
    async fn session_jwt_round_trips_through_parse() {
        if !server_reachable().await {
            eprintln!(
                "SKIP session_jwt_round_trips_through_parse: \
                 testanchor.stellar.org not reachable"
            );
            return;
        }

        let client = make_client();
        let session = auth_with_ephemeral_key(
            &client,
            WEB_AUTH_ENDPOINT,
            HOME_DOMAIN,
            SERVER_SIGNING_KEY,
            None,
        )
        .await
        .expect("auth_with_ephemeral_key must succeed");

        let re_parsed = Sep10Session::parse(&session.jwt)
            .expect("Sep10Session::parse must succeed on a live JWT");

        assert_eq!(re_parsed.sub, session.sub, "re-parsed sub must match");
        assert_eq!(re_parsed.iss, session.iss, "re-parsed iss must match");
        assert_eq!(re_parsed.exp, session.exp, "re-parsed exp must match");
        assert_eq!(re_parsed.iat, session.iat, "re-parsed iat must match");
    }
}
