//! The loaded v1 policy receives one advisory before engine construction.

#![allow(clippy::expect_used, reason = "source-scan assertions")]

#[test]
fn the_server_advises_once_after_a_successful_policy_load() {
    let source = include_str!("../src/server.rs");
    let production = source
        .split("#[cfg(test)]")
        .next()
        .expect("production source");
    let call =
        "crate::policy_advisory::warn_if_transaction_status_unmatched(&document, &profile_name);";
    assert_eq!(
        production.matches(call).count(),
        1,
        "one startup advisory call is required"
    );
    let load = production
        .find("let document = stellar_agent_core::policy::v1::loader::load_signed_policy(")
        .expect("policy load");
    let load_end = load
        + production[load..]
            .find("})?;")
            .expect("successful load boundary")
        + "})?;".len();
    let advisory = production.find(call).expect("advisory call");
    let engine = production[load_end..]
        .find("PolicyEngineV1::new_with_store(")
        .expect("engine construction")
        + load_end;
    assert!(
        load_end < advisory && advisory < engine,
        "advisory must use the successfully loaded document before it enters the engine"
    );
}
