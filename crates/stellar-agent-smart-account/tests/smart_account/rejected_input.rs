//! Multicall symbol refusals retain their code without rendering input.
#![allow(clippy::expect_used, reason = "test assertions")]

use stellar_agent_test_support::rejected_value::{assert_refusal_text, capture_refusal};

#[test]
fn rejected_input_multicall_symbol() {
    use stellar_agent_smart_account::multicall::{MulticallInvocation, build_exec_invocations};
    capture_refusal(|| {
        let target_contract = stellar_strkey::Contract([1; 32])
            .to_string()
            .as_str()
            .to_owned();
        for (fn_name, expected) in [
            (
                "CREDMARKER7!".to_owned(),
                "multicall bundle failed at phase 'build': inner[0]: invalid fn_name symbol: symbol contains an invalid character at byte offset 11; expected [A-Za-z0-9_]".to_owned(),
            ),
            (
                format!("CREDMARKER7{}é", "a".repeat(20)),
                "multicall bundle failed at phase 'build': inner[0]: invalid fn_name symbol: symbol must contain at most 32 bytes; got 33".to_owned(),
            ),
        ] {
            let error = build_exec_invocations(&[MulticallInvocation {
                target_contract: target_contract.clone(),
                fn_name,
                args_json: serde_json::json!([]),
            }]).expect_err("invalid symbol");
            assert_eq!(error.wire_code(), "sa.multicall_failed");
            assert_refusal_text(&error, &expected);
        }
        assert!(
            build_exec_invocations(&[MulticallInvocation {
                target_contract,
                fn_name: "valid_symbol7".to_owned(),
                args_json: serde_json::json!([]),
            }])
            .is_ok()
        );
    });
}
