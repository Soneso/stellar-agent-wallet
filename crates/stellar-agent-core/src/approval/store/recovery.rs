//! Bounded retry metadata written with the approval payloads.

use super::{ApprovalError, ApprovalKind, PendingApproval, PendingApprovalStore};
use crate::mainnet::verified_policy::VerifiedPolicy;
use crate::profile::caip2::Caip2;
use serde::{Deserialize, Serialize};

/// Verified policy and retained operation facts for payment approval recovery.
#[derive(Clone, Copy)]
pub struct PaymentRecoveryContext<'a> {
    /// Canonical profile name.
    pub profile: &'a str,
    /// The profile's chain.
    pub chain: Caip2,
    /// The policy verified for this preparation.
    pub policy: &'a VerifiedPolicy,
    /// Winning operation ID and waiting end; absent off mainnet.
    pub operation: Option<([u8; 16], u64)>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RecoveryKey {
    profile: String,
    chain: Caip2,
    operation: Option<[u8; 16]>,
    subject: [u8; 32],
    policy_digest: [u8; 32],
    policy_sequence: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Disposition {
    Active,
    Expired,
    Rejected,
    Consumed,
    Collected,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Recovery {
    key: RecoveryKey,
    #[serde(deserialize_with = "super::deserialize_approval_nonce")]
    nonce: String,
    created: u64,
    expires: u64,
    retain_until: u64,
    disposition: Disposition,
}

impl RecoveryKey {
    fn new(context: &PaymentRecoveryContext<'_>, envelope: &str) -> Self {
        Self {
            profile: context.profile.to_owned(),
            chain: context.chain,
            operation: context.operation.map(|(id, _)| id),
            subject: super::super::subject::approval_subject_classic(envelope),
            policy_digest: context.policy.digest(),
            policy_sequence: context.policy.sequence(),
        }
    }
}

fn malformed() -> ApprovalError {
    ApprovalError::InvalidEntry {
        detail: "the payment recovery section is malformed".to_owned(),
    }
}

impl Recovery {
    /// Checks the binding's own fields; a failure refuses the whole file.
    fn check_shape(&self) -> Result<(), ApprovalError> {
        if crate::profile::name::validate_path_component_ascii_safe(&self.key.profile).is_err()
            || self.key.policy_sequence < 0
            || self.key.chain.is_mainnet() != self.key.operation.is_some()
            || self.created >= self.expires
            || self.expires > self.retain_until
            || (self.key.operation.is_none() && self.expires != self.retain_until)
        {
            return Err(malformed());
        }
        Ok(())
    }

    /// Checks the binding against its stored payload; a failure refuses only this payment.
    fn check_link(&self, entries: &[PendingApproval]) -> Result<(), ApprovalError> {
        let inconsistent = || ApprovalError::RecoveryInconsistent;
        let mut linked = entries.iter().filter(|e| e.approval_nonce == self.nonce);
        let Some(entry) = linked.next() else {
            return if self.disposition == Disposition::Active {
                Err(inconsistent())
            } else {
                Ok(())
            };
        };
        if linked.next().is_some() {
            return Err(inconsistent());
        }
        match &entry.kind {
            ApprovalKind::Rejected { .. } if self.disposition == Disposition::Rejected => {
                return Ok(());
            }
            ApprovalKind::Consumed { .. } if self.disposition == Disposition::Consumed => {}
            ApprovalKind::PaymentSimulated {
                envelope_xdr_b64,
                envelope_sha256_hex,
                ..
            } if matches!(self.disposition, Disposition::Active | Disposition::Expired) => {
                if super::super::subject::approval_subject_classic(envelope_xdr_b64)
                    != self.key.subject
                    || *envelope_sha256_hex != crate::hex::encode(&self.key.subject)
                {
                    return Err(inconsistent());
                }
            }
            _ => return Err(inconsistent()),
        }
        if (entry.created_at_unix_ms, entry.expires_at_unix_ms) != (self.created, self.expires) {
            return Err(inconsistent());
        }
        Ok(())
    }

    fn status(&self) -> Result<(), ApprovalError> {
        match self.disposition {
            Disposition::Active => Ok(()),
            Disposition::Rejected => Err(ApprovalError::Rejected),
            Disposition::Consumed => Err(ApprovalError::Consumed),
            Disposition::Expired | Disposition::Collected => Err(ApprovalError::Expired),
        }
    }
}

impl PendingApprovalStore {
    pub(super) fn validate_recovery(&self) -> Result<(), ApprovalError> {
        for (i, binding) in self.payment_recovery.iter().enumerate() {
            binding.check_shape()?;
            if self.payment_recovery[..i]
                .iter()
                .any(|other| other.key == binding.key || other.nonce == binding.nonce)
            {
                return Err(malformed());
            }
        }
        if !self.payment_recovery.is_empty() && self.retained_count() > super::MAX_PENDING_APPROVALS
        {
            return Err(malformed());
        }
        Ok(())
    }

    /// Refuses a recorded terminal recovery binding; unindexed legacy entries stay unchanged.
    ///
    /// This read does not observe or persist clock expiry. Callers still check the stored interval.
    ///
    /// # Errors
    /// Returns the recorded expiry, rejection, or consumption, or
    /// [`ApprovalError::RecoveryInconsistent`] when the binding does not match its payload.
    pub fn check_payment_recovery(&self, nonce: &str) -> Result<(), ApprovalError> {
        if let Some(binding) = self.payment_recovery.iter().find(|b| b.nonce == nonce) {
            binding.check_link(&self.entries)?;
            binding.status()?;
        }
        Ok(())
    }

    /// Checks a recovery binding at `now`, persisting its expiry when `now`
    /// reaches the signed end; unindexed legacy entries stay unchanged.
    ///
    /// # Errors
    /// Returns [`ApprovalError::RecoveryInconsistent`] when the binding does
    /// not match its payload, before any write. Otherwise returns the recorded
    /// or newly observed expiry, rejection, consumption, or a persistence error.
    pub fn check_payment_recovery_at(
        &mut self,
        nonce: &str,
        now: u64,
    ) -> Result<(), ApprovalError> {
        let Some(index) = self.payment_recovery.iter().position(|b| b.nonce == nonce) else {
            return Ok(());
        };
        self.payment_recovery[index].check_link(&self.entries)?;
        self.observe_recovery_expiry(nonce, now)?;
        self.payment_recovery[index].status()
    }

    pub(super) fn binds_nonce(&self, nonce: &str) -> bool {
        self.payment_recovery.iter().any(|b| b.nonce == nonce)
    }

    pub(super) fn close_recovery(&mut self, nonce: &str, disposition: Disposition) {
        if let Some(binding) = self.payment_recovery.iter_mut().find(|b| b.nonce == nonce)
            && (binding.disposition == Disposition::Active || disposition != Disposition::Collected)
        {
            binding.disposition = disposition;
        }
    }

    pub(super) fn observe_recovery_expiry(
        &mut self,
        nonce: &str,
        now: u64,
    ) -> Result<(), ApprovalError> {
        if let Some(binding) = self.payment_recovery.iter_mut().find(|b| b.nonce == nonce)
            && binding.disposition == Disposition::Active
            && now >= binding.expires
        {
            binding.disposition = Disposition::Expired;
            self.persist()?;
        }
        Ok(())
    }

    pub(super) fn prune_recovery(&mut self, now: u64) -> bool {
        let mut changed = false;
        for binding in &mut self.payment_recovery {
            if binding.disposition == Disposition::Active && now >= binding.expires {
                binding.disposition = Disposition::Expired;
                changed = true;
            }
        }
        let before = self.payment_recovery.len();
        self.payment_recovery.retain(|b| now < b.retain_until);
        changed || before != self.payment_recovery.len()
    }

    pub(super) fn retained_count(&self) -> usize {
        self.entries
            .iter()
            .map(|e| &e.approval_nonce)
            .chain(self.payment_recovery.iter().map(|b| &b.nonce))
            .collect::<std::collections::BTreeSet<_>>()
            .len()
    }

    /// Counts the nonces that a write at `now` keeps after pruning expired
    /// payloads and bindings past their retention.
    fn retained_count_at(&self, now: u64) -> usize {
        self.entries
            .iter()
            .filter(|e| !e.is_expired(now))
            .map(|e| &e.approval_nonce)
            .chain(
                self.payment_recovery
                    .iter()
                    .filter(|b| now < b.retain_until)
                    .map(|b| &b.nonce),
            )
            .collect::<std::collections::BTreeSet<_>>()
            .len()
    }

    /// Reuses the original payment consent or inserts its payload and recovery binding atomically.
    /// The store lock covers lookup, nonce allocation, and persistence.
    ///
    /// # Errors
    /// Returns a terminal binding's status, inconsistent facts, an elapsed interval,
    /// capacity refusal, or a persistence error. No legacy entry is adopted.
    #[allow(
        clippy::too_many_arguments,
        reason = "captured interval and persistence time are distinct"
    )]
    pub fn recover_payment(
        &mut self,
        context: PaymentRecoveryContext<'_>,
        envelope: &str,
        uid: String,
        created: u64,
        expires: u64,
        now: u64,
        request: &crate::policy::ApprovalRequest,
    ) -> Result<PendingApproval, ApprovalError> {
        let key = RecoveryKey::new(&context, envelope);
        // A binding whose retention has ended is absent; the insertion below
        // prunes it and its expired payload in the same write.
        if let Some(index) = self
            .payment_recovery
            .iter()
            .position(|b| b.key == key && now < b.retain_until)
        {
            self.payment_recovery[index].check_link(&self.entries)?;
            let binding = &mut self.payment_recovery[index];
            if binding.disposition == Disposition::Active && now >= binding.expires {
                binding.disposition = Disposition::Expired;
                self.persist()?;
            }
            let binding = &self.payment_recovery[index];
            binding.status()?;
            if now < binding.created || now < created || now >= expires {
                return Err(ApprovalError::Expired);
            }
            return self
                .get(&binding.nonce)
                .cloned()
                .ok_or(ApprovalError::RecoveryInconsistent);
        }
        let entry = PendingApproval::new_payment_pending_until(
            envelope.to_owned(),
            uid,
            created,
            expires,
            now,
            request.reason.clone(),
        )?;
        self.insert_bound(key, context, entry, (created, expires), now)
    }

    /// Stores the payment `entry`, built for `context` and not yet stored,
    /// with a new active recovery binding, atomically. A retained binding of
    /// the same key refuses: its entry is recoverable work of an earlier
    /// write, which this entry never replaces.
    ///
    /// The MCP payment producer calls this after the entry's durable record
    /// reserves its consent evidence; other callers use
    /// [`Self::recover_payment`].
    ///
    /// # Errors
    /// [`ApprovalError::RecoveryInconsistent`] for a retained binding of the
    /// key or an entry of another kind, [`ApprovalError::Expired`] when `now`
    /// lies outside the entry's signed interval, then the capacity, nonce and
    /// persistence refusals of [`Self::recover_payment`].
    #[doc(hidden)]
    pub fn bind_payment(
        &mut self,
        context: PaymentRecoveryContext<'_>,
        entry: PendingApproval,
        now: u64,
    ) -> Result<PendingApproval, ApprovalError> {
        let ApprovalKind::PaymentSimulated {
            envelope_xdr_b64, ..
        } = &entry.kind
        else {
            return Err(ApprovalError::RecoveryInconsistent);
        };
        let key = RecoveryKey::new(&context, envelope_xdr_b64);
        if self
            .payment_recovery
            .iter()
            .any(|b| b.key == key && now < b.retain_until)
        {
            return Err(ApprovalError::RecoveryInconsistent);
        }
        let interval = (entry.created_at_unix_ms, entry.expires_at_unix_ms);
        if now < interval.0 || now >= interval.1 {
            return Err(ApprovalError::Expired);
        }
        self.insert_bound(key, context, entry, interval, now)
    }

    /// Stores `entry` with a new active binding of `key` over the signed
    /// `(created, expires)` interval, under the capacity and nonce checks.
    fn insert_bound(
        &mut self,
        key: RecoveryKey,
        context: PaymentRecoveryContext<'_>,
        entry: PendingApproval,
        (created, expires): (u64, u64),
        now: u64,
    ) -> Result<PendingApproval, ApprovalError> {
        let binding = Recovery {
            key,
            nonce: entry.approval_nonce.clone(),
            created,
            expires,
            retain_until: context.operation.map_or(expires, |(_, end)| end),
            disposition: Disposition::Active,
        };
        binding.check_shape()?;
        binding.check_link(std::slice::from_ref(&entry))?;
        // A refusal leaves memory and disk unchanged, so a binding past its
        // retention stays until a write that also stores the fresh consent.
        if self.retained_count_at(now) >= super::MAX_PENDING_APPROVALS {
            return Err(ApprovalError::pending_store_full(
                super::MAX_PENDING_APPROVALS,
            ));
        }
        self.prune_recovery(now);
        self.entries.retain(|e| !e.is_expired(now));
        if self.get(&entry.approval_nonce).is_some() || self.binds_nonce(&entry.approval_nonce) {
            return Err(ApprovalError::duplicate_nonce(&entry.approval_nonce));
        }
        self.entries.push(entry.clone());
        self.payment_recovery.push(binding);
        self.persist()?;
        Ok(entry)
    }
}

#[cfg(test)]
mod tests;
