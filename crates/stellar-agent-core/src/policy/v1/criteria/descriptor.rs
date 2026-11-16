//! Read-only descriptions of the limits a signed rule configures.
//!
//! A descriptor repeats a criterion's signed fields and the accounting key
//! the criterion charges. Reading it changes no evaluation.

use crate::policy::v1::criteria::state_store::StateKey;

/// What a configured limit bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum BucketKind {
    /// One call's debit, from `per_tx_cap`.
    Transaction,
    /// The debits within a rolling window, from `per_period_cap`.
    Period,
    /// The debits of one policy epoch, from `total_budget`. The bucket never
    /// rolls; only a re-signed policy starts another epoch.
    Total,
    /// One call's debit to an unlisted recipient, from the `budget` mode of
    /// `counterparty_allowlist`.
    UnlistedTransaction,
    /// The debits to unlisted recipients within a rolling window, from the
    /// same mode.
    UnlistedPeriod,
}

/// One limit of a rule's criterion, as the signed policy states it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BucketDescriptor {
    /// What the limit bounds.
    pub kind: BucketKind,
    /// The asset identifier as signed.
    pub asset: String,
    /// The rolling window in seconds; `None` for a per-call limit and for a
    /// total, which have no window.
    pub window_secs: Option<u64>,
    /// The configured limit in stroops.
    pub cap_stroops: i128,
    /// The scope specificity and bucket the criterion charges; `None` for a
    /// per-call limit, which accumulates nothing.
    accounting: Option<(u8, String)>,
}

impl BucketDescriptor {
    /// A per-call limit of `cap_stroops` in `asset`.
    pub(crate) fn per_call(kind: BucketKind, asset: &str, cap_stroops: i128) -> Self {
        Self {
            kind,
            asset: asset.to_owned(),
            window_secs: None,
            cap_stroops,
            accounting: None,
        }
    }

    /// An accumulating limit of `cap_stroops` in `asset` that charges `key`.
    /// A zero key window is a total's.
    pub(crate) fn accumulating(
        kind: BucketKind,
        asset: &str,
        cap_stroops: i128,
        key: &StateKey,
    ) -> Self {
        Self {
            kind,
            asset: asset.to_owned(),
            window_secs: (key.window_secs() != 0).then_some(key.window_secs()),
            cap_stroops,
            accounting: Some((key.scope_specificity(), key.bucket().to_owned())),
        }
    }

    /// The key the criterion charges under `profile_name`, or `None` for a
    /// per-call limit. A total's bucket names the signed asset; the window
    /// store reads every spelling of one asset as one total bucket.
    #[must_use]
    pub fn state_key(&self, profile_name: &str) -> Option<StateKey> {
        self.accounting.as_ref().map(|(scope, bucket)| {
            StateKey::new(profile_name, *scope, bucket, self.window_secs.unwrap_or(0))
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test-only")]

    use super::*;
    use crate::policy::v1::criteria::Criterion;
    use crate::policy::v1::criteria::counterparty_allowlist::{
        CounterpartyAllowlistCriterion, CounterpartyKind, UnlistedBudget, UnlistedMode,
    };
    use crate::policy::v1::criteria::per_period_cap::{PerPeriodCapCriterion, Window};
    use crate::policy::v1::criteria::per_tx_cap::PerTxCapCriterion;
    use crate::policy::v1::criteria::total_budget::TotalBudgetCriterion;
    use crate::policy::v1::criteria::{BalanceFloorCriterion, RateLimitCriterion};
    use crate::policy::v1::loader::{PolicyRule, RuleMatch};

    fn rule(criteria: Vec<Box<dyn Criterion>>) -> PolicyRule {
        PolicyRule {
            r#match: RuleMatch {
                tool: "stellar_pay".to_owned(),
                chain: "*".to_owned(),
            },
            criteria,
            decision: crate::policy::Decision::Allow,
            allow_opaque_signing: false,
        }
    }

    fn keyed(descriptor: &BucketDescriptor) -> Option<(u8, String, u64)> {
        descriptor.state_key("p").map(|key| {
            (
                key.scope_specificity(),
                key.bucket().to_owned(),
                key.window_secs(),
            )
        })
    }

    fn unlisted(mode: UnlistedMode) -> Box<dyn Criterion> {
        Box::new(
            CounterpartyAllowlistCriterion::new(vec![CounterpartyKind::GAccount], Vec::new())
                .with_unlisted(mode),
        )
    }

    /// Each rule describes its own caps in criterion order: the transaction
    /// cap with no window or key, both supported rolling windows with their
    /// own keys, and a total with no window and the total key of its asset.
    /// Two rules keep their own caps. A rate limit and a floor describe no
    /// bucket. Every key is the one the criterion charges.
    #[test]
    fn budget_descriptors_match_signed_rules() {
        let first = rule(vec![
            Box::new(PerTxCapCriterion::new("native".to_owned(), 7)),
            Box::new(PerPeriodCapCriterion::new(
                "XLM".to_owned(),
                Window::parse("1d").unwrap(),
                70,
            )),
            Box::new(PerPeriodCapCriterion::new(
                "native".to_owned(),
                Window::parse("1w").unwrap(),
                300,
            )),
            Box::new(TotalBudgetCriterion::new("native".to_owned(), 900)),
            Box::new(RateLimitCriterion::new(Window::parse("1h").unwrap(), 3)),
            Box::new(BalanceFloorCriterion::new(50)),
        ]);
        let second = rule(vec![
            Box::new(PerTxCapCriterion::new("native".to_owned(), 9)),
            Box::new(PerPeriodCapCriterion::new(
                "native".to_owned(),
                Window::parse("5m").unwrap(),
                20,
            )),
        ]);
        let described: Vec<_> = first
            .descriptors()
            .iter()
            .map(|d| {
                (
                    d.kind,
                    d.asset.clone(),
                    d.window_secs,
                    d.cap_stroops,
                    keyed(d),
                )
            })
            .collect();
        assert_eq!(
            described,
            vec![
                (BucketKind::Transaction, "native".to_owned(), None, 7, None),
                (
                    BucketKind::Period,
                    "XLM".to_owned(),
                    Some(86_400),
                    70,
                    Some((1, "native".to_owned(), 86_400))
                ),
                (
                    BucketKind::Period,
                    "native".to_owned(),
                    Some(604_800),
                    300,
                    Some((1, "native".to_owned(), 604_800))
                ),
                (
                    BucketKind::Total,
                    "native".to_owned(),
                    None,
                    900,
                    Some((1, "total:native".to_owned(), 0))
                ),
            ]
        );
        let caps: Vec<_> = second
            .descriptors()
            .iter()
            .map(|d| (d.kind, d.window_secs, d.cap_stroops))
            .collect();
        assert_eq!(
            caps,
            vec![
                (BucketKind::Transaction, None, 9),
                (BucketKind::Period, Some(300), 20)
            ]
        );
    }

    /// The `budget` mode describes its per-call bound without a key and its
    /// rolling bound under the shared `unlisted:` key; the `deny` and
    /// `approval` modes and a criterion without a mode describe nothing.
    #[test]
    fn unlisted_modes_describe_only_budget_bounds() {
        let budget = UnlistedBudget::new("XLM".to_owned(), 4, 12, Window::parse("1d").unwrap());
        let described: Vec<_> = rule(vec![unlisted(UnlistedMode::Budget(budget))])
            .descriptors()
            .iter()
            .map(|d| (d.kind, d.window_secs, d.cap_stroops, keyed(d)))
            .collect();
        assert_eq!(
            described,
            vec![
                (BucketKind::UnlistedTransaction, None, 4, None),
                (
                    BucketKind::UnlistedPeriod,
                    Some(86_400),
                    12,
                    Some((1, "unlisted:native".to_owned(), 86_400))
                ),
            ]
        );
        for mode in [UnlistedMode::Deny, UnlistedMode::Approval] {
            assert!(rule(vec![unlisted(mode)]).descriptors().is_empty());
        }
        let listed: Box<dyn Criterion> = Box::new(CounterpartyAllowlistCriterion::new(
            vec![CounterpartyKind::GAccount],
            Vec::new(),
        ));
        assert!(rule(vec![listed]).descriptors().is_empty());
    }
}
