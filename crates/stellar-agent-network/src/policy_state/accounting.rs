//! Unlisted-recipient accounting in the durable window: the bucket every
//! spelling of one asset counts in, checked sums, and how admission treats
//! the unattended allowance.
//!
//! Stored rows keep the bucket text the writing build gave them. Comparison,
//! hydration and admission map that text to the bucket the evaluation keys,
//! so no stored byte changes.

use std::borrow::Cow;

use stellar_agent_core::policy::v1::asset_equivalence::total_budget_identity;

use super::WindowStoreError;
use super::store::ChainScope;

const UNLISTED: &str = "unlisted:";

/// The bucket a row stored under `bucket` counts in on the network of
/// `scope`.
///
/// An `unlisted:` bucket names its asset by [`total_budget_identity`], as
/// the evaluation keys it, so a classic asset and its asset contract share
/// one bucket. Every other bucket, and a file without a scope, keeps its
/// text.
pub(super) fn counted_bucket(bucket: &str, scope: Option<ChainScope>) -> Cow<'_, str> {
    match (bucket.strip_prefix(UNLISTED), scope) {
        (Some(asset), Some(scope)) => Cow::Owned(format!(
            "{UNLISTED}{}",
            total_budget_identity(asset, scope.chain().network_passphrase())
        )),
        _ => Cow::Borrowed(bucket),
    }
}

/// Whether `bucket` is an unlisted-recipient bucket.
fn is_unlisted(bucket: &str) -> bool {
    bucket.starts_with(UNLISTED)
}

/// A window sum and call count.
///
/// The sum of an unlisted bucket is checked: a negative amount refuses with
/// [`WindowStoreError::AccountingInvalid`] and an overflow with
/// [`WindowStoreError::AccountingOverflow`]. Other sums also check overflow;
/// admission maps that failure to the entry's governing limit.
#[derive(Debug, Clone, Copy, Default)]
pub(super) struct Tally {
    pub(super) sum: i128,
    pub(super) count: u32,
    checked: bool,
}

impl Tally {
    /// An empty tally for `bucket`.
    pub(super) fn for_bucket(bucket: &str) -> Self {
        Self {
            checked: is_unlisted(bucket),
            ..Self::default()
        }
    }

    /// Adds one entry of `amount`.
    pub(super) fn add(&mut self, amount: i128) -> Result<(), WindowStoreError> {
        self.add_all(amount, 1)
    }

    /// Adds `count` entries summing to `amount`.
    pub(super) fn add_all(&mut self, amount: i128, count: u32) -> Result<(), WindowStoreError> {
        self.sum = if self.checked {
            if amount < 0 {
                return Err(WindowStoreError::AccountingInvalid);
            }
            self.sum
                .checked_add(amount)
                .ok_or(WindowStoreError::AccountingOverflow)?
        } else {
            self.sum
                .checked_add(amount)
                .ok_or(WindowStoreError::AccountingOverflow)?
        };
        self.count = self.count.saturating_add(count);
        Ok(())
    }
}

/// How durable admission treats the unattended allowance of an unlisted
/// entry. Every other limit, the entry's own unlisted sum included, applies
/// in every mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Admission {
    /// A write outside a mainnet mint: an exceeded allowance refuses with
    /// the policy denial.
    Restrictive,
    /// A mint under policy authority: an exceeded allowance refuses with
    /// [`WindowStoreError::UnlistedApprovalRequired`].
    Policy,
    /// A mint whose own authority is a verified per-payment approval: the
    /// allowance admits the full debit, which still counts.
    Approved,
}
