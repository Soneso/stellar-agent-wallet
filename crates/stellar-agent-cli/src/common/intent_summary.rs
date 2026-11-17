//! Terminal rendering of the same lasting facts shown by the consent page.

use std::io::Write;
use stellar_agent_core::approval::{
    ClassicIntent,
    view::{IntentPayloadView, IntentView},
};

pub(crate) fn write(intent: &ClassicIntent, output: &mut impl Write) -> std::io::Result<()> {
    use super::render::escape_for_terminal as esc;
    let view = IntentView::new(intent);
    writeln!(
        output,
        "Chain: {}\nSource: {}\nPolicy: {}\nMemo: {}\nFee at most: {} stroops",
        esc(view.chain_id()),
        esc(view.source()),
        esc(view.policy_digest_short()),
        esc(&view.memo().display()),
        view.fee_at_most_stroops(),
    )?;
    match view.payload() {
        IntentPayloadView::Pay {
            destination,
            asset,
            amount_stroops,
        } => writeln!(
            output,
            "Action: Pay\nDestination: {}\nAsset: {}\nAmount: {amount_stroops} stroops",
            esc(destination),
            esc(asset),
        ),
        IntentPayloadView::CreateAccount {
            destination,
            asset,
            starting_balance_stroops,
        } => writeln!(
            output,
            "Action: Create account\nDestination: {}\nAsset: {}\nStarting balance: {starting_balance_stroops} stroops",
            esc(destination),
            esc(asset),
        ),
        IntentPayloadView::Trustline {
            issuer,
            code,
            limit,
            ..
        } => writeln!(
            output,
            "Action: Trustline\nIssuer: {}\nCode: {}\nLimit: {}",
            esc(issuer),
            esc(code),
            esc(limit),
        ),
        IntentPayloadView::Claim {
            balance_id_strkey,
            asset,
            amount_stroops,
            claimant,
        } => writeln!(
            output,
            "Action: Claim\nBalance ID: {}\nAsset: {}\nAmount: {amount_stroops} stroops\nClaimant: {}",
            esc(balance_id_strkey),
            esc(asset),
            esc(claimant),
        ),
        IntentPayloadView::ContractPay {
            destination,
            asset,
            amount_stroops,
            explicit_inclusion_bid_stroops,
        } => writeln!(
            output,
            "Action: Contract payment\nDestination: {}\nAsset: {}\nAmount: {amount_stroops} stroops\nInclusion bid: {}",
            esc(destination),
            esc(asset),
            explicit_inclusion_bid_stroops.map_or_else(
                || "chosen by the wallet".to_owned(),
                |bid| format!("{bid} stroops")
            ),
        ),
    }
}
