//! `deploy_smart_account` collective wall-clock budget (#46).
//!
//! `deploy_smart_account_body` shares ONE `SequentialRpcBudget` (derived from
//! `args.timeout`) across every RPC stage (account fetch, WASM pre-flight,
//! simulate, submit-and-wait, post-deploy verification). This test proves the
//! wiring is live: an RPC stage that hangs well past `args.timeout` is cut off
//! AT the shared deadline — surfacing as `SaError::DeploymentFailed { phase:
//! "build" }` naming the collective budget — rather than running to the mock's
//! full (much longer) response latency. The other five deploy flows
//! (`deploy_ed25519_verifier`, `deploy_webauthn_verifier`, `deploy_policy`,
//! `deploy_spending_limit_policy`, `deploy_timelock_controller`) wire the
//! identical `SequentialRpcBudget`/`bound_stage` pattern at the same call
//! sites; this is the representative test for all six.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "test-only")]

use std::time::{Duration, Instant};

use stellar_agent_smart_account::deployment::{DeploymentArgs, ResolvedFeePerOp, interop_deployer};
use stellar_agent_smart_account::error::SaError;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";
const INITIAL_SIGNER_G: &str = "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL";

/// An RPC endpoint that hangs far longer than the manager's `timeout` is cut
/// off AT the shared collective budget, not at the mock's own (much longer)
/// response latency. The mock never actually needs to resolve for this test —
/// `bound_stage`'s `timeout_at` races the shared deadline against the
/// in-flight request and wins long before the mock would respond.
#[tokio::test]
async fn deploy_smart_account_fetch_stage_is_cut_off_at_collective_budget() {
    let server = MockServer::start().await;
    // Delayed far past the deadline below; the test must not wait for this.
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(30)))
        .mount(&server)
        .await;

    let args = DeploymentArgs {
        deployer: interop_deployer(),
        initial_signer: INITIAL_SIGNER_G.to_owned(),
        salt: [0x77u8; 32],
        network_passphrase: TESTNET_PASSPHRASE.to_owned(),
        rpc_url: server.uri(),
        // The collective budget for the WHOLE flow — the first RPC stage
        // (account fetch) alone will exceed it, given the 30s mock delay.
        timeout: Duration::from_millis(150),
        fee: ResolvedFeePerOp {
            stroops: 100,
            percentile_label: "profile_default".to_owned(),
        },
        dry_run: false,
        genesis_signer_scval_override: None,
    };

    let started = Instant::now();
    let result = stellar_agent_smart_account::deployment::deploy_smart_account(args, None).await;
    let elapsed = started.elapsed();

    let err = result.expect_err(
        "a hung account-fetch stage must be refused by the collective budget, not silently \
         wait for the mock's full (30s) response latency",
    );
    assert!(
        matches!(err, SaError::DeploymentFailed { phase: "build", .. }),
        "expected DeploymentFailed{{phase: \"build\"}} (collective budget elapsed), got {err:?}"
    );
    let msg = err.to_string();
    assert!(
        msg.contains("collective deployment budget") && msg.contains("fetch_deployer_account"),
        "error must name the collective budget and the stage it elapsed during; got: {msg}"
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "the call must return promptly once the shared budget elapses, not after waiting \
         out the mock's 30s delay; took {elapsed:?}"
    );
}
