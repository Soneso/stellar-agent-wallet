//! Address refusal diagnostics keep caller input out of every surface.
#![allow(clippy::expect_used, reason = "test assertions")]

use stellar_agent_test_support::rejected_value::{assert_refusal_text, capture_refusal};
use stellar_agent_x402::sac_transfer::build_sac_transfer_invoke;

#[test]
fn rejected_input_transfer_addresses() {
    capture_refusal(|| {
        let contract = stellar_strkey::Contract([1; 32]).to_string().to_string();
        let account = stellar_strkey::ed25519::PublicKey([2; 32])
            .to_string()
            .to_string();
        let unsupported = stellar_strkey::Strkey::PreAuthTx(stellar_strkey::PreAuthTx([3; 32]))
            .to_string()
            .to_string();
        for (sac, from, to, code, message) in [
            (
                "CREDMARKER7",
                account.as_str(),
                account.as_str(),
                "x402.invalid_asset_address",
                "invalid SAC asset address: sac_contract must be a C-strkey",
            ),
            (
                contract.as_str(),
                "CREDMARKER7",
                account.as_str(),
                "x402.invalid_payer_address",
                "invalid payer address: payer must be a G-strkey",
            ),
            (
                contract.as_str(),
                account.as_str(),
                "CREDMARKER7",
                "x402.invalid_recipient_address",
                "invalid recipient address: pay_to must be a G-, C-, M-, or W-strkey",
            ),
            (
                unsupported.as_str(),
                account.as_str(),
                account.as_str(),
                "x402.invalid_asset_address",
                "invalid SAC asset address: sac_contract must be a C-strkey",
            ),
            (
                account.as_str(),
                account.as_str(),
                account.as_str(),
                "x402.invalid_asset_address",
                "invalid SAC asset address: sac_contract must be a C-strkey",
            ),
            (
                contract.as_str(),
                contract.as_str(),
                account.as_str(),
                "x402.invalid_payer_address",
                "invalid payer address: payer must be a G-strkey",
            ),
            (
                contract.as_str(),
                account.as_str(),
                unsupported.as_str(),
                "x402.invalid_recipient_address",
                "invalid recipient address: pay_to must be a G-, C-, M-, or W-strkey",
            ),
        ] {
            let error = build_sac_transfer_invoke(sac, from, to, 1).expect_err("invalid address");
            assert_eq!(error.wire_code(), code);
            assert_refusal_text(&error, message);
            assert!(!format!("{error:?}").contains(&unsupported));
        }
        assert!(build_sac_transfer_invoke(&contract, &account, &account, 1).is_ok());
    });
}
