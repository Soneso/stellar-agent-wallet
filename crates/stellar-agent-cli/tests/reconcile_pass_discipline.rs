//! Every value verb settles what stands open before its own policy gate.
//!
//! A submission whose outcome never came back holds a spending-window
//! reservation, and that reservation counts against the operator's caps until
//! something settles it. The bounded pass is what settles it without the
//! operator asking, so a value verb that skips it lets a stale hold shrink
//! every later action's headroom. Two public documents state the rule for
//! every value verb, so the scan is what keeps the statement true.
//!
//! What it proves is that each verb's source carries the call, at least as
//! many times as the verb has submitting pipelines. It proves neither where in
//! the body the call sits nor that the path reaches it; the behavioural pins
//! for the pass live in `window_reconcile.rs` and the commit integration
//! tests.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics acceptable in a source scan"
)]

/// The value verbs and the source that has to call the pass.
///
/// `pay` and `claim` carry two pipelines each (the full one and
/// `--submit-only`), which the occurrence count covers.
const VALUE_VERB_SOURCES: &[(&str, &str, usize)] = &[
    ("pay", include_str!("../src/commands/pay.rs"), 2),
    ("claim", include_str!("../src/commands/claim.rs"), 2),
    ("trustline", include_str!("../src/commands/trustline.rs"), 1),
    (
        "accounts create",
        include_str!("../src/commands/accounts/create.rs"),
        1,
    ),
    ("trade", include_str!("../src/commands/trade.rs"), 1),
    ("vault", include_str!("../src/commands/vault.rs"), 2),
    (
        "smart-account execute",
        include_str!("../src/commands/smart_account/execute.rs"),
        1,
    ),
    (
        "smart-account multicall",
        include_str!("../src/commands/smart_account/multicall.rs"),
        1,
    ),
];

/// The call every value verb makes.
const PASS_CALL: &str = "reconcile_open_reservations(";

#[test]
fn every_value_verb_runs_the_bounded_reconciliation_pass() {
    let mut missing: Vec<String> = Vec::new();
    for (verb, source, expected) in VALUE_VERB_SOURCES {
        // The Windows checkout is CRLF; the scan counts occurrences, so the
        // normalisation only keeps the reported source readable.
        let normalised = source.replace("\r\n", "\n");
        let found = normalised.matches(PASS_CALL).count();
        if found < *expected {
            missing.push(format!(
                "{verb}: found {found} call(s) to {PASS_CALL}, expected at least {expected}"
            ));
        }
    }
    assert!(
        missing.is_empty(),
        "every value verb's source must call the bounded reconciliation pass; \
         the scan counts call sites and proves neither ordering nor \
         reachability:\n{}",
        missing.join("\n")
    );
}
