//! Confirmed toolset payments with first-invoke grants and policy-driven consent.
#![cfg(feature = "testnet-acceptance")]

#[allow(
    clippy::expect_used,
    reason = "shared test fixtures assert their setup"
)]
mod common;

#[tokio::test]
#[serial_test::serial]
async fn gated_toolset_first_invoke_and_policy_consent_testnet() {
    common::payment_matrix::run(
        common::payment_matrix::Route::Toolset,
        "gated_toolset_first_invoke_and_policy_consent_testnet",
        std::env::var_os("TOOLSET_ACCEPTANCE_LOCAL").is_some(),
    )
    .await;
}

#[tokio::test]
#[serial_test::serial]
async fn direct_and_cross_route_payment_matrix_with_local_rpc() {
    for route in [
        common::payment_matrix::Route::Direct,
        common::payment_matrix::Route::Alternating,
    ] {
        common::payment_matrix::run(
            route,
            "direct_and_cross_route_payment_matrix_with_local_rpc",
            true,
        )
        .await;
    }
}
