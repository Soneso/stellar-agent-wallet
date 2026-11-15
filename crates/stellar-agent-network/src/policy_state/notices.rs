//! Committed operation transitions and the watcher's classification read.
//!
//! A [`CommittedTransition`] names one state edge whose generation commit
//! returned success. Recorders collect them in a [`CommittedBatch`] that the
//! caller drains after the step returns. [`OperationStatus::watch_classes`]
//! classifies the operations a verified read selects.

use super::WindowStoreError;
use super::operations::{
    BusinessId, OperationId, OperationState, OperationStatus, WireOperation, records,
    retained_since, tombstones,
};

/// The disagreement count of an operation's last attempt from which the
/// watcher reports it as needing attention.
const ATTENTION_DISAGREEMENTS: u8 = 3;

/// One committed state edge of an operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommittedTransition {
    operation_id: OperationId,
    business_id: BusinessId,
    state: OperationState,
    attempt_index: Option<u32>,
    at_ms: u64,
    approval_record_id: Option<[u8; 32]>,
}

impl CommittedTransition {
    /// The edge to `state` that `record` holds as its latest history entry,
    /// audited under `attempt_index`.
    pub(super) fn from_record(
        record: &WireOperation,
        attempt_index: Option<u32>,
        state: OperationState,
    ) -> Self {
        Self {
            operation_id: record.id,
            business_id: record.business_id.clone(),
            state,
            attempt_index,
            at_ms: record
                .history
                .last()
                .map_or(record.updated_at_ms, |entry| entry.at_ms),
            approval_record_id: record.approval_record_id,
        }
    }

    /// A transition with these fields, for tests outside this crate.
    #[cfg(any(test, feature = "test-helpers"))]
    #[must_use]
    pub fn for_test(
        operation_id: OperationId,
        business_id: BusinessId,
        state: OperationState,
        attempt_index: Option<u32>,
        at_ms: u64,
        approval_record_id: Option<[u8; 32]>,
    ) -> Self {
        Self {
            operation_id,
            business_id,
            state,
            attempt_index,
            at_ms,
            approval_record_id,
        }
    }

    /// The operation's identity.
    #[must_use]
    pub fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    /// The caller's business id, verbatim.
    #[must_use]
    pub fn business_id(&self) -> &BusinessId {
        &self.business_id
    }

    /// The state the edge reaches.
    #[must_use]
    pub fn state(&self) -> OperationState {
        self.state
    }

    /// The attempt the edge's audit row names; `None` before the first
    /// attempt.
    #[must_use]
    pub fn attempt_index(&self) -> Option<u32> {
        self.attempt_index
    }

    /// The edge's history time, in Unix milliseconds.
    #[must_use]
    pub fn at_ms(&self) -> u64 {
        self.at_ms
    }

    /// The durable approval record the operation links, when it links one.
    #[must_use]
    pub fn approval_record_id(&self) -> Option<[u8; 32]> {
        self.approval_record_id
    }
}

/// The committed transitions of one or more steps, in commit order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CommittedBatch {
    entries: Vec<CommittedTransition>,
}

impl CommittedBatch {
    /// Whether the batch holds no transition.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The number of transitions.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Moves every transition of `other` to the end of this batch.
    pub fn append(&mut self, mut other: CommittedBatch) {
        self.entries.append(&mut other.entries);
    }

    pub(super) fn push(&mut self, transition: CommittedTransition) {
        self.entries.push(transition);
    }
}

impl IntoIterator for CommittedBatch {
    type Item = CommittedTransition;
    type IntoIter = std::vec::IntoIter<CommittedTransition>;

    fn into_iter(self) -> Self::IntoIter {
        self.entries.into_iter()
    }
}

/// How the watcher counts one operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchClass {
    /// The operation succeeded.
    Settled,
    /// The operation failed, was not included or was cancelled, or its last
    /// attempt holds at least three endpoint disagreements.
    Attention,
    /// Every other operation.
    Pending,
}

/// One operation the watcher counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WatchedOperation {
    /// The operation's identity.
    pub operation_id: OperationId,
    /// The operation's class.
    pub class: WatchClass,
}

/// The class of an operation in `state` whose last attempt holds
/// `disagreements`. Success settles before any disagreement counts.
fn classify(state: OperationState, disagreements: u8) -> WatchClass {
    use OperationState as S;
    match state {
        S::Succeeded => WatchClass::Settled,
        S::Failed | S::NotIncluded | S::Cancelled => WatchClass::Attention,
        _ if disagreements >= ATTENTION_DISAGREEMENTS => WatchClass::Attention,
        _ => WatchClass::Pending,
    }
}

impl OperationStatus<'_> {
    /// Classifies every open record and every record or tombstone closed at
    /// or after `since_ms`, the selection of [`Self::list_since`], from one
    /// verified read.
    ///
    /// # Errors
    ///
    /// Every integrity, keyring and I/O error of the verified window read.
    pub fn watch_classes(&self, since_ms: u64) -> Result<Vec<WatchedOperation>, WindowStoreError> {
        let Some(wire) = self.read()? else {
            return Ok(Vec::new());
        };
        let mut watched: Vec<WatchedOperation> = records(&wire)
            .iter()
            .filter(|record| retained_since(record.closed_at_ms, since_ms))
            .map(|record| {
                let disagreements = record
                    .attempts
                    .last()
                    .and_then(|attempt| attempt.recovery.as_ref())
                    .map_or(0, |recovery| recovery.disagreements);
                WatchedOperation {
                    operation_id: record.id,
                    class: classify(record.state, disagreements),
                }
            })
            .collect();
        watched.extend(
            tombstones(&wire)
                .iter()
                .filter(|tombstone| retained_since(Some(tombstone.closed_at_ms), since_ms))
                .map(|tombstone| WatchedOperation {
                    operation_id: tombstone.id,
                    class: classify(tombstone.state, 0),
                }),
        );
        Ok(watched)
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::panic,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use serial_test::serial;

    use super::super::operations::tests::{Fx, agreed, decide, decided_attempt, unknown_named};
    use super::super::operations::{SlotKind, WireTombstone};
    use super::super::recovery::DecidedTransition;
    use super::*;

    /// The fixture's store clock.
    fn now() -> u64 {
        crate::mainnet::clock::now_ms().unwrap()
    }

    /// Stores the last-attempt disagreement count `count` on `id`.
    fn set_disagreements(fx: &Fx, id: OperationId, count: u8) {
        fx.rewrite(|wire| {
            let record = wire
                .operations
                .as_mut()
                .unwrap()
                .records
                .iter_mut()
                .find(|record| record.id == id)
                .unwrap();
            record
                .attempts
                .last_mut()
                .unwrap()
                .recovery
                .get_or_insert_default()
                .disagreements = count;
        });
    }

    /// Stores a tombstone of `n` in `state`, closed at `closed_at_ms`.
    fn add_tombstone(fx: &Fx, n: u8, state: OperationState, closed_at_ms: u64) -> OperationId {
        let id = OperationId::from_bytes([n; 16]);
        fx.rewrite(|wire| {
            wire.operations
                .get_or_insert_default()
                .tombstones
                .push(WireTombstone {
                    id,
                    business_id: BusinessId::parse(&format!("gone-{n}")).unwrap(),
                    state,
                    result: None,
                    intent_digest: [n; 32],
                    slot_kind: SlotKind::Canonical,
                    closed_at_ms,
                });
        });
        id
    }

    fn sorted(mut watched: Vec<WatchedOperation>) -> Vec<WatchedOperation> {
        watched.sort_by_key(|watched| watched.operation_id.to_hex());
        watched
    }

    /// Every state classifies by its own table row at 0, 2 and 3
    /// disagreements, success first; records and tombstones read through
    /// one verified read that leaves the authenticated bytes as they are.
    #[test]
    #[serial]
    fn watch_classes_follow_state_and_disagreements() {
        use OperationState as S;
        for state in S::ALL {
            let expected = match state {
                S::Succeeded => [WatchClass::Settled; 3],
                S::Failed | S::NotIncluded | S::Cancelled => [WatchClass::Attention; 3],
                _ => [
                    WatchClass::Pending,
                    WatchClass::Pending,
                    WatchClass::Attention,
                ],
            };
            assert_eq!(
                [classify(state, 0), classify(state, 2), classify(state, 3)],
                expected,
                "{state:?}"
            );
        }

        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        let mut fx = Fx::new();
        let status = OperationStatus::new(&fx.store, &fx.profile);
        assert_eq!(status.watch_classes(0).unwrap(), vec![]);

        let unknown = unknown_named(&mut fx, 1);
        let (settled, attempt) = decided_attempt(&mut fx, 2);
        fx.recorder()
            .commit_decision(&decide(
                &attempt,
                DecidedTransition::Succeeded(agreed(2, "SUCCESS")),
            ))
            .unwrap();
        set_disagreements(&fx, settled.id(), 3);
        set_disagreements(&fx, unknown.id(), 2);
        let closed = now();
        let failed = add_tombstone(&fx, 0x31, S::Failed, closed);
        let expired = add_tombstone(&fx, 0x32, S::Expired, closed);
        let status = OperationStatus::new(&fx.store, &fx.profile);
        let bytes = std::fs::read(fx.store.path()).unwrap();
        let expected = |unknown_class| {
            sorted(vec![
                WatchedOperation {
                    operation_id: unknown.id(),
                    class: unknown_class,
                },
                WatchedOperation {
                    operation_id: settled.id(),
                    class: WatchClass::Settled,
                },
                WatchedOperation {
                    operation_id: failed,
                    class: WatchClass::Attention,
                },
                WatchedOperation {
                    operation_id: expired,
                    class: WatchClass::Pending,
                },
            ])
        };
        assert_eq!(
            sorted(status.watch_classes(0).unwrap()),
            expected(WatchClass::Pending)
        );
        assert_eq!(std::fs::read(fx.store.path()).unwrap(), bytes);
        set_disagreements(&fx, unknown.id(), 3);
        assert_eq!(
            sorted(status.watch_classes(0).unwrap()),
            expected(WatchClass::Attention)
        );
    }

    /// Open records always count; a record or tombstone counts when it
    /// closed at or after the boundary.
    #[test]
    #[serial]
    fn watch_classes_keep_the_since_boundary() {
        use OperationState as S;
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        let mut fx = Fx::new();
        let open = unknown_named(&mut fx, 1);
        let boundary = now();
        let (closed, attempt) = decided_attempt(&mut fx, 2);
        fx.recorder()
            .commit_decision(&decide(
                &attempt,
                DecidedTransition::Succeeded(agreed(2, "SUCCESS")),
            ))
            .unwrap();
        let before = add_tombstone(&fx, 0x41, S::Cancelled, boundary - 1);
        let at = add_tombstone(&fx, 0x42, S::Cancelled, boundary);
        let status = OperationStatus::new(&fx.store, &fx.profile);
        let ids = |since: u64| -> Vec<OperationId> {
            sorted(status.watch_classes(since).unwrap())
                .into_iter()
                .map(|watched| watched.operation_id)
                .collect()
        };
        let all = |mut ids: Vec<OperationId>| {
            ids.sort_by_key(OperationId::to_hex);
            ids
        };
        assert_eq!(ids(boundary), all(vec![open.id(), closed.id(), at]));
        assert_eq!(
            ids(boundary - 1),
            all(vec![open.id(), closed.id(), at, before])
        );
        assert_eq!(ids(boundary + 1), all(vec![open.id()]));
    }
}
