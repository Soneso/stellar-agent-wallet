//! Released TypeScript SDK wire-vector interoperability.

#![allow(
    clippy::expect_used,
    clippy::panic,
    reason = "committed interop fixtures use expect for concise assertions"
)]

use serde_json::Value;
use stellar_agent_mpp::{
    ChallengeInput, CredentialOutput, HttpRequestContext, MPP_TYPESCRIPT_SDK_PIN, ReceiptInput,
    build_credential, parse_receipt, select_and_validate,
};

const FIXTURE: &str =
    include_str!("../../../interop/stellar-mpp-js/fixtures/sponsored-charge.json");
const NOW: i64 = 1_784_203_200;
const PAYER: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";

#[test]
fn released_typescript_vectors_round_trip_through_rust() {
    let fixture: Value = serde_json::from_str(FIXTURE).expect("committed fixture JSON");
    assert_eq!(fixture["provenance"]["package"], MPP_TYPESCRIPT_SDK_PIN);

    let header = fixture["challengeHeader"]
        .as_str()
        .expect("challenge header");
    let input = ChallengeInput::Http {
        www_authenticate: vec![header.to_owned()],
        selected_challenge_id: None,
        context: HttpRequestContext::new(
            "https://merchant.example",
            "GET",
            "https://merchant.example/paid",
            None,
            None,
        )
        .expect("HTTP context"),
    };
    let selected = select_and_validate(&input, NOW).expect("released challenge");
    assert_eq!(selected.echo().id(), Some("challenge-interop-1"));
    assert_eq!(selected.request().amount_decimal(), "10000000");

    let transaction = fixture["credential"]["transaction"]
        .as_str()
        .expect("transaction XDR");
    let credential = build_credential(&selected, PAYER, transaction).expect("credential");
    let CredentialOutput::Http { authorization } = credential else {
        panic!("HTTP challenge must produce an HTTP credential")
    };
    assert_eq!(
        authorization,
        fixture["credential"]["authorization"]
            .as_str()
            .expect("released authorization")
    );

    let receipt = parse_receipt(&ReceiptInput::Http {
        value: fixture["receipt"]["paymentReceipt"]
            .as_str()
            .expect("released receipt")
            .to_owned(),
    })
    .expect("released receipt parses");
    assert_eq!(
        receipt.reference(),
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );
    assert_eq!(receipt.timestamp(), "2026-07-16T12:06:00Z");
}
