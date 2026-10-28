//! `pay` and `claim` count the built envelope's fee in `minimum_reserve`, in
//! the full pipeline and under `--build-only`, through the `stellar-agent`
//! binary.
//!
//! Each test provisions an isolated data root with the signed V1 policy
//! ceremony on testnet. The profile's primary is a [`ClassicLedger`] that
//! funds every account with the same native balance, quotes a 250-stroop
//! inclusion fee, holds one native claimable balance for the signer, and
//! counts every send. Every run passes `--fee auto`, so each envelope pays
//! the quoted fee for its one operation, a fee neither the 100-stroop
//! default nor the base fee matches.
//!
//! Each verb and mode meets three margins: the crossing margin, where the
//! debit alone passes the reserve and the debit plus the fee crosses it; the
//! margin lower by exactly the envelope fee, which admits the envelope; and
//! the margin one stroop above that, which refuses it.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test assertions"
)]

use stellar_xdr::{
    AccountId, Asset, ClaimPredicate, ClaimableBalanceEntry, ClaimableBalanceEntryExt,
    ClaimableBalanceId, Claimant, ClaimantV0, Hash, LedgerEntryData, LedgerKey,
    LedgerKeyClaimableBalance, Limits, PublicKey, ReadXdr as _, TransactionEnvelope, Uint256,
    WriteXdr as _,
};
use wiremock::MockServer;

use crate::classic_ledger::{ACCOUNT_BALANCE, ClassicLedger};
use crate::v1_ceremony::{CliRun, IsolatedHome, Keypair, policy_document, policy_rule};

const SIGNER_SEED: [u8; 32] = [0x13; 32];
const OWNER_SEED: [u8; 32] = [0x23; 32];

/// The variable the value verbs read the signer secret from.
const SIGNER_ENV: &str = "FEE_RESERVE_SIGNER_SECRET";

/// The payment destination.
const DESTINATION: &str = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";

/// The native balance the mock reports for every account.
const BALANCE: i64 = ACCOUNT_BALANCE;
/// The protocol reserve of an account without subentries.
const RESERVE: i64 = 10_000_000;
/// The payment amount: 1 XLM.
const AMOUNT: i64 = 10_000_000;
/// The total fee of every envelope built against the mock: one operation at
/// the quoted 250-stroop inclusion fee.
const ENVELOPE_FEE: i64 = 250;

/// The margin at which the 1 XLM payment alone passes the reserve and the
/// payment plus any fee crosses it.
const PAY_FEE_CROSSING_MARGIN: i64 = BALANCE - AMOUNT - RESERVE;
/// The margin at which the claim, which debits nothing, passes the reserve
/// alone and crosses it with any fee.
const CLAIM_FEE_CROSSING_MARGIN: i64 = BALANCE - RESERVE;

/// The hash of the claimable balance the mock holds.
const BALANCE_ID_HEX64: &str = "abababababababababababababababababababababababababababababababab";

fn signer() -> Keypair {
    Keypair::from_seed(SIGNER_SEED)
}

fn owner() -> Keypair {
    Keypair::from_seed(OWNER_SEED)
}

/// The ledger key and entry of an unconditional 10 XLM native claimable
/// balance with id [`BALANCE_ID_HEX64`] whose one claimant is `claimant`.
fn claimable_entry(claimant: &str) -> (String, String) {
    let balance_id = ClaimableBalanceId::ClaimableBalanceIdTypeV0(Hash([0xab; 32]));
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

// ─────────────────────────────────────────────────────────────────────────────
// Harness
// ─────────────────────────────────────────────────────────────────────────────

/// A provisioned V1 profile reading through a mock ledger.
struct Fixture {
    home: IsolatedHome,
    ledger: ClassicLedger,
    _rpc: MockServer,
    profile: &'static str,
}

impl Fixture {
    /// Provisions `profile` on testnet with one `tool` rule whose only
    /// criterion is `minimum_reserve` with `margin_stroops`.
    async fn new(profile: &'static str, tool: &str, margin_stroops: i64) -> Self {
        let signer = signer();
        let ledger = ClassicLedger::new(
            &[signer.public(), DESTINATION],
            &[claimable_entry(signer.public())],
        )
        .with_inclusion_fee(u32::try_from(ENVELOPE_FEE).unwrap());
        let rpc = ledger.serve().await;
        let home = IsolatedHome::new();
        let criteria =
            format!("[{{ kind = \"minimum_reserve\", margin_stroops = {margin_stroops} }}]");
        home.provision_v1_profile(
            profile,
            &["--rpc-url", &rpc.uri()],
            &signer,
            &owner(),
            &policy_document(
                profile,
                &[policy_rule(tool, "stellar:testnet", &criteria, "allow")],
            ),
        );
        Self {
            home,
            ledger,
            _rpc: rpc,
            profile,
        }
    }

    /// Runs `verb` with `extra`, the profile, the quoted fee, JSON output,
    /// and the signer's secret.
    fn run(&self, verb: &[&str], extra: &[&str]) -> CliRun {
        let signer = signer();
        let mut args: Vec<&str> = verb.to_vec();
        args.extend_from_slice(&[
            "--source",
            signer.public(),
            "--profile",
            self.profile,
            "--fee",
            "auto",
            "--output",
            "json",
        ]);
        args.extend_from_slice(extra);
        self.home.run(&args, &[(SIGNER_ENV, signer.secret())])
    }

    /// `pay` of 1 XLM to [`DESTINATION`] with `extra` flags.
    fn pay(&self, extra: &[&str]) -> CliRun {
        self.run(&["pay", DESTINATION, "1 XLM"], extra)
    }

    /// `claim` of the signer's claimable balance with `extra` flags.
    fn claim(&self, extra: &[&str]) -> CliRun {
        self.run(&["claim", BALANCE_ID_HEX64], extra)
    }

    /// Asserts a `minimum_reserve` refusal that returned no envelope and
    /// sent nothing.
    fn assert_reserve_refusal(&self, run: &CliRun) {
        assert_eq!(run.code, 1, "{} stderr={}", run.envelope, run.stderr);
        assert_eq!(
            run.error_code(),
            "policy.deny.minimum_reserve_breached",
            "{}",
            run.envelope
        );
        assert!(
            run.envelope["data"].get("envelope_xdr").is_none(),
            "{}",
            run.envelope
        );
        assert_eq!(self.ledger.sends(), 0, "nothing is sent");
    }

    /// Asserts a full pipeline that the policy admitted and that sent its
    /// transaction once.
    fn assert_sent_once(&self, run: &CliRun) {
        assert_eq!(run.code, 0, "{} stderr={}", run.envelope, run.stderr);
        assert_eq!(self.ledger.sends(), 1, "the transaction is sent once");
    }

    /// Asserts a `--build-only` run that the policy admitted, that returned
    /// an envelope paying [`ENVELOPE_FEE`], and that sent nothing.
    fn assert_built_with_the_fee(&self, run: &CliRun) {
        assert_eq!(run.code, 0, "{} stderr={}", run.envelope, run.stderr);
        let xdr = run.envelope["data"]["envelope_xdr"]
            .as_str()
            .unwrap_or_else(|| panic!("{}", run.envelope));
        assert_eq!(
            envelope_fee(xdr),
            ENVELOPE_FEE,
            "the returned envelope carries the fee the margin leaves room for"
        );
        assert_eq!(self.ledger.sends(), 0, "nothing is sent");
    }
}

/// The total fee of the unsigned version 1 envelope `xdr`.
fn envelope_fee(xdr: &str) -> i64 {
    match TransactionEnvelope::from_xdr_base64(xdr, Limits::none()).unwrap() {
        TransactionEnvelope::Tx(tx) => i64::from(tx.tx.fee),
        other => panic!("not a version 1 envelope: {other:?}"),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

/// The full `pay` pipeline counts the fee, so the margin the payment alone
/// meets denies it before the send.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pay_counts_the_fee_toward_the_reserve() {
    let fixture = Fixture::new("fee-reserve-pay", "stellar_pay", PAY_FEE_CROSSING_MARGIN).await;

    let run = fixture.pay(&["--secret-env", SIGNER_ENV]);

    fixture.assert_reserve_refusal(&run);
}

/// The full `pay` pipeline under a margin lower by exactly the envelope fee
/// sends the payment.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pay_admits_the_margin_that_leaves_room_for_the_fee() {
    let fixture = Fixture::new(
        "fee-reserve-pay-exact",
        "stellar_pay",
        PAY_FEE_CROSSING_MARGIN - ENVELOPE_FEE,
    )
    .await;

    let run = fixture.pay(&["--secret-env", SIGNER_ENV]);

    fixture.assert_sent_once(&run);
}

/// The full `pay` pipeline under a margin that leaves room for one stroop
/// less than the envelope fee denies it before the send.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pay_refuses_the_margin_one_stroop_short_of_the_fee() {
    let fixture = Fixture::new(
        "fee-reserve-pay-deficit",
        "stellar_pay",
        PAY_FEE_CROSSING_MARGIN - (ENVELOPE_FEE - 1),
    )
    .await;

    let run = fixture.pay(&["--secret-env", SIGNER_ENV]);

    fixture.assert_reserve_refusal(&run);
}

/// `pay --build-only` counts the fee of the envelope it would return, so the
/// same margin denies it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pay_build_only_counts_the_fee_toward_the_reserve() {
    let fixture = Fixture::new(
        "fee-reserve-pay-build",
        "stellar_pay",
        PAY_FEE_CROSSING_MARGIN,
    )
    .await;

    let run = fixture.pay(&["--build-only"]);

    fixture.assert_reserve_refusal(&run);
}

/// `pay --build-only` under a margin lower by exactly the envelope fee
/// returns the envelope, so the refusal above comes from the fee.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pay_build_only_admits_the_margin_that_leaves_room_for_the_fee() {
    let fixture = Fixture::new(
        "fee-reserve-pay-build-exact",
        "stellar_pay",
        PAY_FEE_CROSSING_MARGIN - ENVELOPE_FEE,
    )
    .await;

    let run = fixture.pay(&["--build-only"]);

    fixture.assert_built_with_the_fee(&run);
}

/// `pay --build-only` under a margin that leaves room for one stroop less
/// than the envelope fee denies it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pay_build_only_refuses_the_margin_one_stroop_short_of_the_fee() {
    let fixture = Fixture::new(
        "fee-reserve-pay-build-deficit",
        "stellar_pay",
        PAY_FEE_CROSSING_MARGIN - (ENVELOPE_FEE - 1),
    )
    .await;

    let run = fixture.pay(&["--build-only"]);

    fixture.assert_reserve_refusal(&run);
}

/// The full `claim` pipeline counts the fee, so the margin the claim alone
/// meets denies it before the send.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn claim_counts_the_fee_toward_the_reserve() {
    let fixture = Fixture::new(
        "fee-reserve-claim",
        "stellar_claim",
        CLAIM_FEE_CROSSING_MARGIN,
    )
    .await;

    let run = fixture.claim(&["--secret-env", SIGNER_ENV]);

    fixture.assert_reserve_refusal(&run);
}

/// The full `claim` pipeline under a margin lower by exactly the envelope
/// fee sends the claim.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn claim_admits_the_margin_that_leaves_room_for_the_fee() {
    let fixture = Fixture::new(
        "fee-reserve-claim-exact",
        "stellar_claim",
        CLAIM_FEE_CROSSING_MARGIN - ENVELOPE_FEE,
    )
    .await;

    let run = fixture.claim(&["--secret-env", SIGNER_ENV]);

    fixture.assert_sent_once(&run);
}

/// The full `claim` pipeline under a margin that leaves room for one stroop
/// less than the envelope fee denies it before the send.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn claim_refuses_the_margin_one_stroop_short_of_the_fee() {
    let fixture = Fixture::new(
        "fee-reserve-claim-deficit",
        "stellar_claim",
        CLAIM_FEE_CROSSING_MARGIN - (ENVELOPE_FEE - 1),
    )
    .await;

    let run = fixture.claim(&["--secret-env", SIGNER_ENV]);

    fixture.assert_reserve_refusal(&run);
}

/// `claim --build-only` counts the fee of the envelope it would return, so
/// the same margin denies it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn claim_build_only_counts_the_fee_toward_the_reserve() {
    let fixture = Fixture::new(
        "fee-reserve-claim-build",
        "stellar_claim",
        CLAIM_FEE_CROSSING_MARGIN,
    )
    .await;

    let run = fixture.claim(&["--build-only"]);

    fixture.assert_reserve_refusal(&run);
}

/// `claim --build-only` under a margin lower by exactly the envelope fee
/// returns the envelope, so the refusal above comes from the fee.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn claim_build_only_admits_the_margin_that_leaves_room_for_the_fee() {
    let fixture = Fixture::new(
        "fee-reserve-claim-build-exact",
        "stellar_claim",
        CLAIM_FEE_CROSSING_MARGIN - ENVELOPE_FEE,
    )
    .await;

    let run = fixture.claim(&["--build-only"]);

    fixture.assert_built_with_the_fee(&run);
}

/// `claim --build-only` under a margin that leaves room for one stroop less
/// than the envelope fee denies it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn claim_build_only_refuses_the_margin_one_stroop_short_of_the_fee() {
    let fixture = Fixture::new(
        "fee-reserve-claim-build-deficit",
        "stellar_claim",
        CLAIM_FEE_CROSSING_MARGIN - (ENVELOPE_FEE - 1),
    )
    .await;

    let run = fixture.claim(&["--build-only"]);

    fixture.assert_reserve_refusal(&run);
}
