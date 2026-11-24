//! Exact JSON wire text of the four value verbs on testnet, run through the
//! `stellar-agent` binary without a business id.
//!
//! Each case provisions an isolated data root with the signed V1 policy
//! ceremony on testnet and reads and sends through a [`ClassicLedger`]. It
//! compares the whole stdout, key order included, with its expected file.
//! [`normalize`] masks the only value that varies between invocations.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test assertions"
)]

use serde_json::Value;
use stellar_xdr::{
    AccountId, Asset, ClaimPredicate, ClaimableBalanceEntry, ClaimableBalanceEntryExt,
    ClaimableBalanceId, Claimant, ClaimantV0, Hash, LedgerEntryData, LedgerKey,
    LedgerKeyClaimableBalance, Limits, PublicKey, Uint256, WriteXdr as _,
};

use crate::classic_ledger::ClassicLedger;
use crate::v1_ceremony::{IsolatedHome, Keypair, policy_document, policy_rule};

const SIGNER_SEED: [u8; 32] = [0x14; 32];
const OWNER_SEED: [u8; 32] = [0x24; 32];
const ISSUER_SEED: [u8; 32] = [0x34; 32];

/// The variable the value verbs read the signer secret from.
const SIGNER_ENV: &str = "VALUE_VERB_GUARD_SIGNER_SECRET";

/// The payment destination, funded on the mock ledger.
const DESTINATION: &str = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";

/// The account `accounts create` opens; the mock ledger does not hold it.
const NEW_ACCOUNT: &str = "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY";

/// The hash of the claimable balance the mock holds.
const BALANCE_ID_HEX64: &str = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";

const PROFILE: &str = "value-verb-guard";

/// A value verb the guard pins.
#[derive(Clone, Copy)]
enum Verb {
    Pay,
    Claim,
    Trustline,
    Create,
}

impl Verb {
    fn tool(self) -> &'static str {
        match self {
            Self::Pay => "stellar_pay",
            Self::Claim => "stellar_claim",
            Self::Trustline => "stellar_trustline",
            Self::Create => "stellar_create_account",
        }
    }

    fn expected(self) -> &'static str {
        match self {
            Self::Pay => include_str!("value_verb_wire_guard/pay.json"),
            Self::Claim => include_str!("value_verb_wire_guard/claim.json"),
            Self::Trustline => include_str!("value_verb_wire_guard/trustline.json"),
            Self::Create => include_str!("value_verb_wire_guard/create.json"),
        }
    }

    /// The verb's arguments before the profile and output flags.
    fn args(self, signer: &str, issuer: &str) -> Vec<String> {
        let owned = |items: &[&str]| items.iter().map(|item| (*item).to_owned()).collect();
        match self {
            Self::Pay => owned(&[
                "pay",
                DESTINATION,
                "1 XLM",
                "--source",
                signer,
                "--secret-env",
                SIGNER_ENV,
                "--output",
                "json",
            ]),
            Self::Claim => owned(&[
                "claim",
                BALANCE_ID_HEX64,
                "--source",
                signer,
                "--secret-env",
                SIGNER_ENV,
                "--output",
                "json",
            ]),
            Self::Trustline => vec![
                "trustline".to_owned(),
                "--from".to_owned(),
                signer.to_owned(),
                "--asset".to_owned(),
                format!("USD:{issuer}"),
            ],
            Self::Create => owned(&[
                "accounts",
                "create",
                NEW_ACCOUNT,
                "--sponsor",
                signer,
                "--starting-balance",
                "2 XLM",
                "--secret-env",
                SIGNER_ENV,
                "--output",
                "json",
            ]),
        }
    }
}

/// The ledger key and entry of an unconditional 10 XLM native claimable
/// balance with id [`BALANCE_ID_HEX64`] whose one claimant is `claimant`.
fn claimable_entry(claimant: &str) -> (String, String) {
    let balance_id = ClaimableBalanceId::ClaimableBalanceIdTypeV0(Hash([0xcd; 32]));
    let key = LedgerKey::ClaimableBalance(LedgerKeyClaimableBalance {
        balance_id: balance_id.clone(),
    })
    .to_xdr_base64(Limits::none())
    .unwrap();
    let destination = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(
        stellar_strkey::ed25519::PublicKey::from_string(claimant)
            .unwrap()
            .0,
    )));
    let entry = LedgerEntryData::ClaimableBalance(ClaimableBalanceEntry {
        balance_id,
        claimants: vec![Claimant::ClaimantTypeV0(ClaimantV0 {
            destination,
            predicate: ClaimPredicate::Unconditional,
        })]
        .try_into()
        .unwrap(),
        asset: Asset::Native,
        amount: 100_000_000,
        ext: ClaimableBalanceEntryExt::V0,
    })
    .to_xdr_base64(Limits::none())
    .unwrap();
    (key, entry)
}

/// Masks the one value that varies between invocations: the generated
/// correlation id. The signer keys are fixed and a testnet envelope carries
/// no time bound, so the envelope and its hash are stable.
fn normalize(text: &str) -> String {
    let value: Value = serde_json::from_str(text.trim_end()).unwrap();
    let id = value["request_id"].as_str().unwrap();
    assert_eq!(uuid::Uuid::parse_str(id).unwrap().get_version_num(), 4);
    text.replace(id, "REQUEST_ID")
}

async fn check(verb: Verb) {
    let signer = Keypair::from_seed(SIGNER_SEED);
    let owner = Keypair::from_seed(OWNER_SEED);
    let issuer = Keypair::from_seed(ISSUER_SEED);
    let ledger = ClassicLedger::new(
        &[signer.public(), DESTINATION, issuer.public()],
        &[claimable_entry(signer.public())],
    );
    let rpc = ledger.serve().await;
    let home = IsolatedHome::new();
    home.provision_v1_profile(
        PROFILE,
        &["--rpc-url", &rpc.uri()],
        &signer,
        &owner,
        &policy_document(
            PROFILE,
            &[policy_rule(verb.tool(), "stellar:testnet", "[]", "allow")],
        ),
    );
    let mut args = verb.args(signer.public(), issuer.public());
    args.extend(["--profile".to_owned(), PROFILE.to_owned()]);
    let argv: Vec<&str> = args.iter().map(String::as_str).collect();
    let run = home.run(&argv, &[(SIGNER_ENV, signer.secret())]);
    assert_eq!(run.code, 0, "{} stderr={}", run.stdout, run.stderr);
    assert_eq!(ledger.sends(), 1, "the transaction is sent once");
    let actual = normalize(&run.stdout);
    assert_eq!(actual, verb.expected(), "{actual}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pay_wire_text() {
    check(Verb::Pay).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn claim_wire_text() {
    check(Verb::Claim).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn trustline_wire_text() {
    check(Verb::Trustline).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn create_account_wire_text() {
    check(Verb::Create).await;
}
