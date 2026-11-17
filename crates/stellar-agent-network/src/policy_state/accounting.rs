//! Durable unlisted-recipient and native floor accounting: canonical buckets,
//! checked sums, allowance admission and observed native exposure.
//!
//! Stored rows keep the bucket text the writing build gave them. Comparison,
//! hydration and admission map that text to the bucket the evaluation keys,
//! so no stored byte changes.

use std::borrow::Cow;

use stellar_agent_core::policy::v1::asset_equivalence::total_budget_identity;

use super::WindowStoreError;
use super::store::ChainScope;
use super::{ledger, operations};
use stellar_agent_core::policy::DenyReason;

fn unread() -> WindowStoreError {
    WindowStoreError::PolicyDenied {
        reason: Box::new(DenyReason::AccountUnread),
    }
}

/// Counts retained native obligations at the balance read's observation.
/// Release evidence is applied before requiring amounts. Neither a used
/// disposition nor a later reconciliation observation releases this balance.
pub(super) fn floor_reserved(
    wire: &super::store::WireFile,
    observation: &operations::WindowObservation,
) -> Result<u64, WindowStoreError> {
    if wire
        .admissible_floor_ledger
        .is_some_and(|floor| observation.ledger < floor)
        || wire
            .admissible_floor_close_time_ms
            .is_some_and(|floor| observation.close_time_floor_ms < floor)
    {
        return Err(unread());
    }
    let mut sum = 0_i128;
    for auth in &wire.authorizations {
        if auth
            .native_release
            .is_some_and(|row| operations::row_releases(&row, Some(observation)))
            || auth.domain.hold_owner() == crate::mainnet::HoldOwner::NoHolds
        {
            continue;
        }
        let amounts = auth.native_reservation.ok_or_else(unread)?;
        if amounts.debit_stroops < 0 || amounts.fee_stroops < 0 {
            return Err(WindowStoreError::AccountingInvalid);
        }
        if auth.domain == crate::mainnet::AuthorizationDomain::Soroban
            && amounts.debit_stroops == 0
            && !proved_non_native(wire, auth)
        {
            return Err(unread());
        }
        sum = sum
            .checked_add(amounts.total_stroops())
            .ok_or(WindowStoreError::AccountingOverflow)?;
    }
    u64::try_from(sum).map_err(|_| WindowStoreError::AccountingOverflow)
}

/// An old zero-valued Soroban record needs its bound payment facts: the
/// producer could also have written zero for a native asset transfer.
fn proved_non_native(wire: &super::store::WireFile, auth: &ledger::WireAuthorization) -> bool {
    let Some(link) = auth.operation else {
        return false;
    };
    operations::records(wire).iter().any(|record| {
        let operations::IntentSlot::X402 {
            intent_digest,
            intent,
        } = &record.intent
        else {
            return false;
        };
        record.id == link.operation_id
            && record.chain_id == auth.chain
            && intent.network
                == if auth.chain.is_mainnet() {
                    "stellar:pubnet"
                } else {
                    "stellar:testnet"
                }
            && auth.binding
                == ledger::DomainBinding::Soroban {
                    intent_digest: *intent_digest,
                }
            && stellar_strkey::ed25519::PublicKey::from_string(&intent.payer).is_ok()
            && intent
                .amount
                .parse::<i128>()
                .is_ok_and(|amount| amount >= 0)
            && stellar_strkey::Contract::from_string(&intent.asset).is_ok()
            && total_budget_identity(&intent.asset, auth.chain.network_passphrase()) != "native"
    })
}

/// A signed floor and the observed, action-bound facts used at locked mint.
///
/// Construct this after authoritative action decoding and an observed account
/// read. The store computes reservations from its locked successor. No amount
/// from this input is persisted as a second counter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckedFloor {
    minimum: i128,
    balance: i64,
    observation: operations::WindowObservation,
    chain: stellar_agent_core::profile::caip2::Caip2,
    consumer: crate::mainnet::MainnetConsumer,
    profile: String,
    policy_digest: [u8; 32],
    policy_sequence: i64,
    signer: [u8; 32],
    content: [u8; 32],
    amounts: ledger::NativeReservation,
}

impl CheckedFloor {
    #[cfg(test)]
    #[allow(
        clippy::unwrap_used,
        reason = "test fixture requires explicit native amounts"
    )]
    pub(super) fn for_test(
        request: &ledger::MintRequest,
        profile: &str,
        now: u64,
        balance: i64,
    ) -> Self {
        Self {
            minimum: 20,
            balance,
            observation: operations::WindowObservation {
                ledger: 100,
                close_time_floor_ms: now - 5_000,
                observed_at_ms: now,
            },
            chain: request.chain,
            consumer: request.consumer,
            profile: profile.to_owned(),
            policy_digest: request.policy_digest,
            policy_sequence: request.policy_sequence,
            signer: request.bindings.signer,
            content: request.binding.content_digest(),
            amounts: request.native_reservation.unwrap(),
        }
    }

    /// Binds the first matching verified rule's strongest floor to this mint.
    /// The observed account must be the enrolled operating signer, and cover
    /// the readiness ledger and close-time floor of the same endpoint read.
    /// `request.native_reservation` must come from authenticated action facts.
    /// A rule without a floor returns `None`.
    ///
    /// # Errors
    ///
    /// `account.unread` for mismatched policy, source, rule, chain or coverage,
    /// absent amounts or an unreadable balance. Invalid amounts refuse with
    /// `policy.accounting_invalid`.
    #[allow(
        clippy::too_many_arguments,
        reason = "binds independent checked proofs"
    )]
    pub fn for_mint(
        context: &crate::MainnetWriteContext,
        policy: &stellar_agent_core::mainnet::verified_policy::VerifiedPolicy,
        tool: &stellar_agent_core::policy::ToolDescriptor,
        evaluation: &stellar_agent_core::policy::Evaluation,
        signer: &crate::keyring::EnrolledSigner,
        observed: &stellar_agent_core::policy::v1::ObservedAccount<crate::account::AccountView>,
        readiness: &crate::operational::OperationalReport,
        request: &ledger::MintRequest,
    ) -> Result<Option<Self>, WindowStoreError> {
        use stellar_agent_core::policy::v1::AccountReservesView;
        use stellar_agent_core::policy::v1::criteria::balance_floor::BalanceFloorCriterion;
        let expected_tool = crate::mainnet::resolve::classic_consumer_tools(request.consumer)
            .map(|tools| tools.policy_tool)
            .or(match request.consumer {
                crate::mainnet::MainnetConsumer::X402Create => Some("stellar_x402_create_payment"),
                crate::mainnet::MainnetConsumer::X402Authenticated => {
                    Some("stellar_x402_authenticated_payment")
                }
                _ => None,
            });
        if expected_tool != Some(tool.name.as_str()) || tool.chain_id != context.chain().caip2_str()
        {
            return Err(unread());
        }
        let engine = policy.engine();
        let rules = engine.effective_rules();
        let (ordinal, rule) = rules
            .iter()
            .enumerate()
            .find(|(_, rule)| rule.matches_tool(tool))
            .ok_or_else(unread)?;
        if evaluation.provisional
            || evaluation.rule_ordinal != Some(ordinal)
            || matches!(
                evaluation.decision,
                stellar_agent_core::policy::Decision::Deny(_)
            )
        {
            return Err(unread());
        }
        let Some(minimum) = rule
            .criteria
            .iter()
            .filter_map(|criterion| {
                (criterion.as_ref() as &dyn std::any::Any)
                    .downcast_ref::<BalanceFloorCriterion>()
                    .map(BalanceFloorCriterion::min_stroops)
            })
            .max()
        else {
            return Ok(None);
        };
        let observation = observed.observation().ok_or_else(unread)?;
        if request.chain != context.chain()
            || request.policy_digest != policy.digest()
            || request.policy_sequence != policy.sequence()
            || request.bindings.signer != signer.fact_digest()
            || observed.view().account_id
                != stellar_strkey::ed25519::PublicKey(signer.public_key())
                    .to_string()
                    .as_str()
            || observation.ledger_sequence < readiness.latest_ledger
            || observation.close_time_floor_ms
                < readiness
                    .close_time_unix
                    .checked_mul(1_000)
                    .ok_or_else(unread)?
        {
            return Err(unread());
        }
        let amounts = request.native_reservation.ok_or_else(unread)?;
        if amounts.debit_stroops < 0 || amounts.fee_stroops < 0 {
            return Err(WindowStoreError::AccountingInvalid);
        }
        Ok(Some(Self {
            minimum,
            balance: observed.balance_stroops().map_err(|_| unread())?,
            observation: operations::WindowObservation {
                ledger: observation.ledger_sequence,
                close_time_floor_ms: observation.close_time_floor_ms,
                observed_at_ms: observation.observed_at_ms,
            },
            chain: request.chain,
            consumer: request.consumer,
            profile: context.profile_name().to_owned(),
            policy_digest: policy.digest(),
            policy_sequence: policy.sequence(),
            signer: signer.fact_digest(),
            content: request.binding.content_digest(),
            amounts,
        }))
    }

    pub(super) fn check(
        &self,
        wire: &super::store::WireFile,
        profile: &stellar_agent_core::profile::schema::Profile,
        request: &ledger::MintRequest,
        now: u64,
    ) -> Result<(), WindowStoreError> {
        if self.chain != request.chain
            || self.consumer != request.consumer
            || self.profile != stellar_agent_core::profile::name::profile_name_for_approval(profile)
            || self.policy_digest != request.policy_digest
            || self.policy_sequence != request.policy_sequence
            || self.signer != request.bindings.signer
            || self.content != request.binding.content_digest()
            || Some(self.amounts) != request.native_reservation
        {
            return Err(unread());
        }
        let age_ms = now
            .checked_sub(self.observation.observed_at_ms)
            .ok_or_else(unread)?;
        if age_ms > stellar_agent_core::policy::v1::criteria::balance_floor::MAX_OBSERVATION_AGE_MS
        {
            return Err(WindowStoreError::PolicyDenied {
                reason: Box::new(DenyReason::AccountStale { age_ms }),
            });
        }
        let reservations = floor_reserved(wire, &self.observation)?;
        let after = i128::from(self.balance)
            .checked_sub(i128::from(reservations))
            .and_then(|after| after.checked_sub(self.amounts.total_stroops()))
            .ok_or(WindowStoreError::AccountingOverflow)?;
        if after < self.minimum {
            return Err(WindowStoreError::PolicyDenied {
                reason: Box::new(DenyReason::AccountFloorRefused {
                    min_stroops: self.minimum,
                    balance_after_stroops: after,
                }),
            });
        }
        Ok(())
    }
}

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

#[cfg(all(test, feature = "mainnet-write"))]
#[path = "accounting_floor_tests.rs"]
mod floor_tests;
