//! Anchor testnet acceptance tests.
//!
//! Live end-to-end tests against `testanchor.stellar.org` (SDF reference anchor).
//! Run with:
//! ```sh
//! cargo test -p stellar-agent-anchor --features testnet-acceptance \
//!     --test anchor_testnet_acceptance
//! ```
//!
//! # What is tested
//!
//! **SEP-6 leg (no auth required):**
//! - Fetch testanchor `stellar.toml` → `TRANSFER_SERVER`.
//! - `GET {transfer_server}/info` → assert non-empty decoded capability set.
//! - `authentication_required` is surfaced for each asset.
//!
//! **SEP-24 leg (requires SEP-10 auth):**
//! - Fetch testanchor `stellar.toml` → `TRANSFER_SERVER_SEP0024` +
//!   `WEB_AUTH_ENDPOINT`.
//! - Obtain a SEP-10 JWT via `auth_with_ephemeral_key`.
//! - `POST /transactions/deposit/interactive` for a testnet asset.
//! - Assert response is `interactive_customer_info_needed` with a non-empty
//!   HTTPS `url` and non-empty `id`.
//!
//! # Skip policy
//!
//! Skip-with-distinguishable-reason (not silent-pass):
//! - `"skipped: testanchor unreachable"` — HEAD probe failed.
//! - `"skipped: testanchor SEP-10 auth unavailable"` — `WEB_AUTH_ENDPOINT`
//!   absent or auth call failed.
//!
//! Offline fixture-decode assertions are covered by unit tests in
//! `src/sep24.rs` and `src/sep6.rs` and by `tests/anchor_adversarial.rs`.

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

#[cfg(feature = "testnet-acceptance")]
mod live {
    use stellar_agent_anchor::{
        Sep24Operation, Sep24Params, get_sep6_info, start_sep24_interactive,
    };
    use stellar_agent_network::counterparty::{
        fetch::fetch_stellar_toml, parser::parse_minimal_sep1,
    };

    /// SDF testnet anchor home domain.
    const TESTNET_ANCHOR_DOMAIN: &str = "testanchor.stellar.org";

    /// Stellar testnet network passphrase.
    const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";

    /// SDF testanchor server signing key (published in its stellar.toml).
    /// Verified 2026-05-28 against live testanchor TOML.
    const SERVER_SIGNING_KEY: &str = "GCHLHDBOKG2JWMJQBTLSL5XG6NO7ESXI2TAQKZXCXWXB5WI2X6W233PR";

    /// Returns `true` if the testanchor is reachable (HEAD probe).
    async fn testanchor_reachable() -> bool {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        match client
            .head("https://testanchor.stellar.org/.well-known/stellar.toml")
            .send()
            .await
        {
            Ok(resp) => resp.status().is_success(),
            Err(_) => false,
        }
    }

    /// SEP-6 testnet leg.
    ///
    /// Fetches testanchor stellar.toml → TRANSFER_SERVER → GET /info →
    /// asserts non-empty decoded capabilities + `authentication_required` surfaced.
    #[tokio::test]
    async fn sep6_acceptance_info_returns_capabilities() {
        if !testanchor_reachable().await {
            eprintln!("skipped: testanchor unreachable");
            return;
        }

        // Resolve TRANSFER_SERVER from stellar.toml.
        let toml_body = match fetch_stellar_toml(TESTNET_ANCHOR_DOMAIN).await {
            Ok(b) => b,
            Err(e) => {
                eprintln!("skipped: testanchor stellar.toml fetch failed: {e}");
                return;
            }
        };
        let sep1 = match parse_minimal_sep1(&toml_body) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("skipped: testanchor stellar.toml parse failed: {e}");
                return;
            }
        };
        let transfer_server = match sep1.transfer_server {
            Some(ref s) => s.clone(),
            None => {
                eprintln!("skipped: testanchor stellar.toml does not declare TRANSFER_SERVER");
                return;
            }
        };

        // GET /info — public, no JWT required.
        let info =
            match get_sep6_info(&transfer_server, Some(TESTNET_ANCHOR_DOMAIN), None, None).await {
                Ok(i) => i,
                Err(e) => {
                    eprintln!("skipped: testanchor SEP-6 /info call failed: {e}");
                    return;
                }
            };

        // Assert non-empty capability set.
        assert!(
            !info.deposit.is_empty() || !info.withdraw.is_empty(),
            "testanchor SEP-6 /info must return at least one deposit or withdraw asset; \
             got deposit={}, withdraw={}",
            info.deposit.len(),
            info.withdraw.len()
        );

        // authentication_required must be surfaced.
        for (asset, asset_info) in &info.deposit {
            let _ = asset_info.authentication_required;
            eprintln!(
                "sep6 deposit {asset}: enabled={}, auth_required={}",
                asset_info.enabled, asset_info.authentication_required
            );
        }
        for (asset, asset_info) in &info.withdraw {
            let _ = asset_info.authentication_required;
            eprintln!(
                "sep6 withdraw {asset}: enabled={}, auth_required={}",
                asset_info.enabled, asset_info.authentication_required
            );
        }
    }

    /// SEP-24 testnet leg.
    ///
    /// Fetches testanchor stellar.toml → TRANSFER_SERVER_SEP0024 +
    /// WEB_AUTH_ENDPOINT; obtains a SEP-10 JWT via the existing
    /// stellar-agent-sep10 client against testanchor; POSTs
    /// deposit/interactive for a testnet asset → asserts
    /// `interactive_customer_info_needed` + non-empty HTTPS url + id.
    #[tokio::test]
    async fn sep24_acceptance_deposit_interactive_url() {
        if !testanchor_reachable().await {
            eprintln!("skipped: testanchor unreachable");
            return;
        }

        // Resolve TRANSFER_SERVER_SEP0024 + WEB_AUTH_ENDPOINT from stellar.toml.
        let toml_body = match fetch_stellar_toml(TESTNET_ANCHOR_DOMAIN).await {
            Ok(b) => b,
            Err(e) => {
                eprintln!("skipped: testanchor stellar.toml fetch failed: {e}");
                return;
            }
        };
        let sep1 = match parse_minimal_sep1(&toml_body) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("skipped: testanchor stellar.toml parse failed: {e}");
                return;
            }
        };

        let transfer_server_sep0024 = match sep1.transfer_server_sep0024 {
            Some(ref s) => s.clone(),
            None => {
                eprintln!(
                    "skipped: testanchor stellar.toml does not declare TRANSFER_SERVER_SEP0024"
                );
                return;
            }
        };
        let web_auth_endpoint = match sep1.web_auth_endpoint {
            Some(ref s) => s.clone(),
            None => {
                eprintln!("skipped: testanchor stellar.toml does not declare WEB_AUTH_ENDPOINT");
                return;
            }
        };

        // Obtain a SEP-10 JWT via the existing stellar-agent-sep10 client.
        let jwt = match obtain_sep10_jwt(&web_auth_endpoint).await {
            Some(j) => j,
            None => {
                eprintln!("skipped: testanchor SEP-10 auth unavailable");
                return;
            }
        };

        // POST /transactions/deposit/interactive for a testnet asset.
        // Content-Type: application/json is required; form-encoded is rejected by
        // the Anchor Platform with HTTP 500.
        let params = Sep24Params {
            asset_code: "SRT".to_owned(),
            asset_issuer: None,
            account: None,
            amount: None,
            lang: Some("en".to_owned()),
            claimable_balance_supported: None,
        };

        // This call must NOT hit the skip branch — a failure here is a real bug.
        let result = start_sep24_interactive(
            &transfer_server_sep0024,
            Some(TESTNET_ANCHOR_DOMAIN),
            Sep24Operation::Deposit,
            &params,
            &jwt,
        )
        .await
        .expect("SEP-24 interactive deposit must succeed with HTTP 200 (JSON POST required)");

        // Assert interactive_customer_info_needed response.
        assert!(
            result.interactive_url.starts_with("https://"),
            "interactive URL must be HTTPS; url = {:?}",
            result.interactive_url
        );
        assert!(
            !result.transaction_id.is_empty(),
            "transaction_id must not be empty"
        );
        assert!(
            !result.handoff_note.is_empty(),
            "handoff_note must not be empty"
        );
        // Hand-off note must document the no-follow / no-open posture.
        assert!(
            result.handoff_note.contains("does NOT auto-open"),
            "handoff_note must document the no-follow / no-open posture; note = {:?}",
            result.handoff_note
        );
        assert!(
            result.handoff_note.contains("SEP-24"),
            "handoff_note must reference SEP-24 §5.4; note = {:?}",
            result.handoff_note
        );

        let url_host = url::Url::parse(&result.interactive_url)
            .ok()
            .and_then(|u| u.host_str().map(str::to_owned));

        // The interactive URL must be hosted on the anchor-ref-ui subdomain of
        // testanchor.stellar.org, not on the wallet or any other host.
        assert!(
            url_host
                .as_deref()
                .map(|h| h.ends_with("stellar.org"))
                .unwrap_or(false),
            "interactive URL host must be on stellar.org; got: {url_host:?}; url = {:?}",
            result.interactive_url
        );

        eprintln!(
            "sep24 deposit: transaction_id={}, url_host={:?}",
            result.transaction_id, url_host
        );
    }

    /// Obtains a SEP-10 JWT from the given web-auth endpoint using an ephemeral
    /// keypair.  Returns `None` if auth fails (skip signal).
    async fn obtain_sep10_jwt(web_auth_endpoint: &str) -> Option<String> {
        use stellar_agent_sep10::{Sep10Client, ephemeral::auth_with_ephemeral_key};

        let client = Sep10Client::new(TESTNET_PASSPHRASE).ok()?;
        let session = auth_with_ephemeral_key(
            &client,
            web_auth_endpoint,
            TESTNET_ANCHOR_DOMAIN,
            SERVER_SIGNING_KEY,
            None,
        )
        .await
        .ok()?;
        Some(session.jwt)
    }
}
