//! `trustline` reads the trustline it names on testnet, so `minimum_reserve`
//! adds no base reserve for a trustline the account holds, through the
//! `stellar-agent` binary in every feature state.
//!
//! The test provisions an isolated data root with the signed V1 policy
//! ceremony on testnet. The mock ledger serves the signer with one USDC
//! trustline and 1.6 XLM, against a reserve of 1.5 XLM.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test assertions"
)]

use stellar_agent_test_support::xdr_fixtures::{
    account_entry_xdr, account_ledger_key_xdr, trustline_entry_xdr, trustline_ledger_key_xdr,
};

use crate::classic_ledger::ClassicLedger;
use crate::v1_ceremony::{IsolatedHome, Keypair, policy_document, policy_rule};

const SIGNER_SEED: [u8; 32] = [0x14; 32];
const OWNER_SEED: [u8; 32] = [0x24; 32];

/// The testnet issuer the wallet pins for USDC.
const TESTNET_ISSUER: &str = "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5";

/// The signer's native balance: 1.6 XLM.
const BALANCE: i64 = 16_000_000;

/// Removing the held USDC trustline at margin 0 needs the account's reserve
/// of 1.5 XLM and the fee only, so it signs and sends once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn removing_a_held_trustline_adds_no_reserve() {
    let signer = Keypair::from_seed(SIGNER_SEED);
    let ledger = ClassicLedger::new(
        &[TESTNET_ISSUER],
        &[
            (
                account_ledger_key_xdr(signer.public()),
                account_entry_xdr(signer.public(), BALANCE, 1),
            ),
            (
                trustline_ledger_key_xdr(signer.public(), "USDC", TESTNET_ISSUER),
                trustline_entry_xdr(signer.public(), "USDC", TESTNET_ISSUER, 0),
            ),
        ],
    );
    let rpc = ledger.serve().await;
    let home = IsolatedHome::new();
    let profile = "held-trustline-reserve";
    home.provision_v1_profile(
        profile,
        &["--rpc-url", &rpc.uri()],
        &signer,
        &Keypair::from_seed(OWNER_SEED),
        &policy_document(
            profile,
            &[policy_rule(
                "stellar_trustline",
                "stellar:testnet",
                "[{ kind = \"minimum_reserve\", margin_stroops = 0 }]",
                "allow",
            )],
        ),
    );

    let run = home.run(
        &[
            "trustline",
            "--from",
            signer.public(),
            "--asset",
            &format!("USDC:{TESTNET_ISSUER}"),
            "--limit-stroops",
            "0",
            "--profile",
            profile,
        ],
        &[],
    );

    assert_eq!(run.code, 0, "{} stderr={}", run.envelope, run.stderr);
    assert_eq!(ledger.sends(), 1, "the removal is sent once");
}
