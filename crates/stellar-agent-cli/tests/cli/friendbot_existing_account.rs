//! Friendbot refusals retain their public code on both CLI funding surfaces.

#![allow(clippy::expect_used, reason = "test fixtures and assertions")]

use serde_json::{Value, json};
use stellar_agent_test_support::{cli_child::cli_command, sandbox::StateSandbox};
use wiremock::matchers::{method, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ACCOUNT: &str = "GBZXN7PIRZGNMHGA7MUUUF4GWPY5AYPV6LY4UV2GL6VJGIQRXFDNMADI";

async fn assert_existing_account(args: &[&str]) {
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(query_param("addr", ACCOUNT))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "type": "https://stellar.org/horizon-errors/bad_request",
            "title": "Bad Request",
            "status": 400,
            "detail": "createAccountAlreadyExist (AAAAAAAAAGT/////AAAAAQAAAAAAAAAA/////AAAAAA==)",
        })))
        .expect(1)
        .mount(&mock)
        .await;

    let home = StateSandbox::new().expect("isolated home");
    let mut command =
        cli_command(env!("CARGO_BIN_EXE_stellar-agent"), home.path()).expect("isolated CLI child");
    command.args(args).args(["--friendbot-url", &mock.uri()]);
    let output = tokio::task::spawn_blocking(move || command.output().expect("CLI runs"))
        .await
        .expect("CLI task");
    let envelope: Value = serde_json::from_slice(&output.stdout).expect("JSON envelope");
    assert_eq!(output.status.code(), Some(1), "{envelope}");
    assert_eq!(envelope["ok"], false, "{envelope}");
    assert_eq!(
        envelope["error"]["code"],
        "network.friendbot_account_already_funded"
    );
    assert!(
        envelope["error"]["message"]
            .as_str()
            .expect("message")
            .contains(ACCOUNT)
    );
    mock.verify().await;
}

#[tokio::test]
async fn friendbot_reports_an_account_created_by_an_earlier_attempt() {
    assert_existing_account(&[
        "friendbot",
        "--account",
        ACCOUNT,
        "--friendbot-url-unchecked",
    ])
    .await;
}

#[tokio::test]
async fn accounts_create_reports_an_account_created_by_an_earlier_attempt() {
    assert_existing_account(&["accounts", "create", ACCOUNT, "--fund-with-friendbot"]).await;
}
