//! What the spending-window store admits when it takes a reservation.
//!
//! The policy gate evaluates a call against the window state it reads before
//! the transaction is built and signed. Two callers on one profile — a CLI
//! invocation and the MCP server, or two MCP dispatches — can each read the
//! same state, each be admissible against it, and only then reserve. The
//! reservation write is where that is caught: it holds the store's exclusive
//! lock, re-reads the file, and re-applies the governing criterion's own
//! comparison before it inserts anything.
//!
//! These tests hold two store handles on one file, as two processes would,
//! and pin what the second one is told.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics acceptable in integration tests"
)]

use serial_test::serial;
use stellar_agent_core::policy::DenyReason;
use stellar_agent_core::policy::v1::criteria::state_store::{
    CLOCK_SKEW_TOLERANCE_MS, PolicyStateStore, StateKey, StateStoreError, WindowEntry, WindowLimit,
};
use stellar_agent_core::profile::schema::{KeyringEntryRef, Profile};
use stellar_agent_network::policy_state::{
    PersistedWindowStore, WindowReservation, WindowStoreError,
};
use stellar_agent_test_support::keyring_mock;
use tempfile::TempDir;

/// The amount cap both amount-bucket tests reserve against.
const MAX_STROOPS: i128 = 1_000;

/// Each caller's own spend: admissible against an empty window on its own,
/// over the cap once the other one is holding a reservation.
const HALF_PLUS: i128 = 600;

fn test_profile(name: &str) -> Profile {
    let mut p = Profile::builder_testnet(name, "acct", "n-svc", "n-acct").build();
    p.policy_window_state_key_id = KeyringEntryRef::default_policy_window_state_key(name);
    p
}

fn now_ms() -> u64 {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("the system clock must be after the unix epoch")
            .as_millis(),
    )
    .expect("the current time must fit in u64 milliseconds")
}

fn amount_key(profile_name: &str) -> StateKey {
    StateKey::new(profile_name, 1, "native", 86_400)
}

fn count_key(profile_name: &str) -> StateKey {
    StateKey::new(profile_name, 1, "rate_limit", 60)
}

/// One amount entry under the shared cap, as `per_period_cap` records it.
fn amount_entry(profile_name: &str, ts_ms: u64, amount: i128) -> WindowEntry {
    WindowEntry::new(
        amount_key(profile_name),
        ts_ms,
        amount,
        WindowLimit::Amount {
            asset: "native".to_owned(),
            window: "1d".to_owned(),
            max_stroops: MAX_STROOPS,
        },
    )
}

/// One call-count entry under a limit of `max_calls`, as `rate_limit` records it.
fn count_entry(profile_name: &str, ts_ms: u64, max_calls: u32) -> WindowEntry {
    WindowEntry::new(
        count_key(profile_name),
        ts_ms,
        1,
        WindowLimit::Count {
            window: "1m".to_owned(),
            max_calls,
        },
    )
}

fn reservation(id: &str, sequence: i64, now: u64) -> WindowReservation {
    WindowReservation {
        id: id.to_owned(),
        tx_hash: id.to_owned(),
        source: "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY".to_owned(),
        sequence,
        max_time: 0,
        pending_since_ms: now,
        submission_ledger: 1_000,
        operator_required: false,
    }
}

/// Two handles on one file, as two processes hold them.
struct Fixture {
    _dir: TempDir,
    profile: Profile,
    profile_name: String,
    first: PersistedWindowStore,
    second: PersistedWindowStore,
}

fn fixture(name: &str) -> Fixture {
    keyring_mock::install().unwrap();
    let dir = TempDir::new().unwrap();
    let path = dir.path().join(format!("{name}.window"));
    Fixture {
        profile: test_profile(name),
        profile_name: name.to_owned(),
        first: PersistedWindowStore::at_path(path.clone()),
        second: PersistedWindowStore::at_path(path),
        _dir: dir,
    }
}

impl Fixture {
    /// The window the file holds for `key`, read back the way the gate reads it.
    fn window(&self, key: &StateKey, now: u64) -> (i128, u32) {
        let dest = PolicyStateStore::new();
        self.first
            .load_into(&self.profile_name, &self.profile, &dest)
            .unwrap();
        dest.query_window(key, now).unwrap()
    }

    fn open_reservation_ids(&self) -> Vec<String> {
        self.first
            .pending_reservations(&self.profile)
            .unwrap()
            .into_iter()
            .map(|r| r.id)
            .collect()
    }
}

/// The second caller of two that each passed the gate against the same state
/// is refused, and the file keeps only the first one's reservation.
#[test]
#[serial]
fn a_second_reservation_over_the_amount_cap_is_refused_and_writes_nothing() {
    let fx = fixture("admit-amount");
    let now = now_ms();
    let first_id = "a".repeat(64);
    let second_id = "b".repeat(64);

    fx.first
        .record_pending(
            &fx.profile,
            &[amount_entry(&fx.profile_name, now, HALF_PLUS)],
            &reservation(&first_id, 7, now),
        )
        .expect("the first reservation fits the cap on its own");

    let refused = fx
        .second
        .record_pending(
            &fx.profile,
            &[amount_entry(&fx.profile_name, now, HALF_PLUS)],
            &reservation(&second_id, 8, now),
        )
        .expect_err("the second reservation takes the bucket past its cap");

    match refused {
        WindowStoreError::PolicyDenied { reason } => match *reason {
            DenyReason::PerPeriodCapExceeded {
                asset,
                window,
                max_stroops,
                attempted_stroops,
                period_used_stroops,
            } => {
                assert_eq!(asset, "native");
                assert_eq!(window, "1d");
                assert_eq!(max_stroops, MAX_STROOPS);
                assert_eq!(attempted_stroops, HALF_PLUS);
                assert_eq!(
                    period_used_stroops, HALF_PLUS,
                    "the refusal reports the reservation already standing"
                );
            }
            other => panic!("expected PerPeriodCapExceeded, got {other:?}"),
        },
        other => panic!("expected PolicyDenied, got {other:?}"),
    }

    assert_eq!(
        fx.open_reservation_ids(),
        vec![first_id],
        "only the admitted reservation stands"
    );
    assert_eq!(
        fx.window(&amount_key(&fx.profile_name), now + 1_000),
        (HALF_PLUS, 1),
        "the refused reservation contributed nothing to the window"
    );
}

/// The same holds for a call-count bucket, which the rate-limit criteria fill
/// one entry at a time.
#[test]
#[serial]
fn a_second_reservation_over_the_call_limit_is_refused_and_writes_nothing() {
    let fx = fixture("admit-count");
    let now = now_ms();
    let first_id = "c".repeat(64);
    let second_id = "d".repeat(64);

    fx.first
        .record_pending(
            &fx.profile,
            &[count_entry(&fx.profile_name, now, 1)],
            &reservation(&first_id, 7, now),
        )
        .expect("the first call fits the limit on its own");

    let refused = fx
        .second
        .record_pending(
            &fx.profile,
            &[count_entry(&fx.profile_name, now, 1)],
            &reservation(&second_id, 8, now),
        )
        .expect_err("the second call takes the bucket past its limit");

    match refused {
        WindowStoreError::PolicyDenied { reason } => match *reason {
            DenyReason::RateLimitExceeded {
                window,
                max_calls,
                calls_in_window,
            } => {
                assert_eq!(window, "1m");
                assert_eq!(max_calls, 1);
                assert_eq!(
                    calls_in_window, 1,
                    "the refusal reports the call already standing"
                );
            }
            other => panic!("expected RateLimitExceeded, got {other:?}"),
        },
        other => panic!("expected PolicyDenied, got {other:?}"),
    }

    assert_eq!(
        fx.open_reservation_ids(),
        vec![first_id],
        "only the admitted call stands"
    );
    assert_eq!(
        fx.window(&count_key(&fx.profile_name), now + 1_000),
        (1, 1),
        "the refused call contributed nothing to the window"
    );
}

/// One batch whose own entries jointly exceed the cap is refused whole.
///
/// Each entry fits the empty bucket on its own, so a check that looked at them
/// one at a time against the file alone would admit both.
#[test]
#[serial]
fn a_batch_whose_entries_jointly_exceed_the_cap_writes_none_of_them() {
    let fx = fixture("admit-batch");
    let now = now_ms();
    let id = "e".repeat(64);

    let refused = fx
        .first
        .record_pending(
            &fx.profile,
            &[
                amount_entry(&fx.profile_name, now, HALF_PLUS),
                amount_entry(&fx.profile_name, now, HALF_PLUS),
            ],
            &reservation(&id, 7, now),
        )
        .expect_err("two entries on one key are measured against each other");

    match refused {
        WindowStoreError::PolicyDenied { reason } => match *reason {
            DenyReason::PerPeriodCapExceeded {
                attempted_stroops,
                period_used_stroops,
                ..
            } => {
                assert_eq!(attempted_stroops, HALF_PLUS);
                assert_eq!(
                    period_used_stroops, HALF_PLUS,
                    "the entry ahead of it in the batch counts against it"
                );
            }
            other => panic!("expected PerPeriodCapExceeded, got {other:?}"),
        },
        other => panic!("expected PolicyDenied, got {other:?}"),
    }

    assert!(
        fx.open_reservation_ids().is_empty(),
        "a refused batch leaves no reservation behind"
    );
    assert_eq!(
        fx.window(&amount_key(&fx.profile_name), now + 1_000),
        (0, 0),
        "not one entry of a refused batch reaches the file"
    );
}

/// A batch the bucket admits is written whole, so admission refuses without
/// narrowing what an admitted reservation records.
#[test]
#[serial]
fn a_batch_the_bucket_admits_is_written_whole() {
    let fx = fixture("admit-whole");
    let now = now_ms();
    let id = "f".repeat(64);

    fx.first
        .record_pending(
            &fx.profile,
            &[
                amount_entry(&fx.profile_name, now, 400),
                amount_entry(&fx.profile_name, now, 400),
            ],
            &reservation(&id, 7, now),
        )
        .expect("800 stroops fit a 1000-stroop cap");

    assert_eq!(
        fx.window(&amount_key(&fx.profile_name), now + 1_000),
        (800, 2),
        "both entries of an admitted batch reach the file"
    );
}

/// An open reservation holds the cap however old it is, so a caller cannot
/// wait out a submission whose outcome is still unknown.
#[test]
#[serial]
fn a_reservation_older_than_the_window_still_holds_the_cap() {
    let fx = fixture("admit-aged");
    let now = now_ms();
    let first_id = "1".repeat(64);
    let second_id = "2".repeat(64);
    // Two days back, past the one-day window the entries are keyed to.
    let aged = now - 2 * 24 * 60 * 60 * 1_000;

    fx.first
        .record_pending(
            &fx.profile,
            &[amount_entry(&fx.profile_name, aged, HALF_PLUS)],
            &reservation(&first_id, 7, aged),
        )
        .expect("the first reservation fits the cap on its own");

    let refused = fx
        .second
        .record_pending(
            &fx.profile,
            &[amount_entry(&fx.profile_name, now, HALF_PLUS)],
            &reservation(&second_id, 8, now),
        )
        .expect_err("a pending reservation counts whatever its age");

    assert!(
        matches!(refused, WindowStoreError::PolicyDenied { .. }),
        "expected PolicyDenied, got {refused:?}"
    );
    assert_eq!(
        fx.open_reservation_ids(),
        vec![first_id],
        "only the admitted reservation stands"
    );
}

/// Confirmed spend that has aged out of its window no longer holds the cap.
///
/// The recheck reads the file the way the gate reads it, so a window that has
/// genuinely rolled forward admits the next call.
#[test]
#[serial]
fn spend_that_has_aged_out_of_the_window_admits_the_next_reservation() {
    let fx = fixture("admit-rolled");
    let now = now_ms();
    let first_id = "3".repeat(64);
    let second_id = "4".repeat(64);
    let aged = now - 2 * 24 * 60 * 60 * 1_000;

    fx.first
        .record_pending(
            &fx.profile,
            &[amount_entry(&fx.profile_name, aged, HALF_PLUS)],
            &reservation(&first_id, 7, aged),
        )
        .unwrap();
    // The chain applied it two days ago, so it is confirmed spend dated then.
    fx.first
        .confirm(
            &fx.profile,
            &first_id,
            Some(i64::try_from(aged / 1_000).unwrap()),
        )
        .unwrap();

    fx.second
        .record_pending(
            &fx.profile,
            &[amount_entry(&fx.profile_name, now, HALF_PLUS)],
            &reservation(&second_id, 8, now),
        )
        .expect("spend older than the window no longer counts against it");

    assert_eq!(
        fx.open_reservation_ids(),
        vec![second_id],
        "the new reservation stands and the settled one is closed"
    );
}

/// A same-key record dated past the clock-skew tolerance is a clock the gate
/// does not trust: its query fails closed on it, and so does admission.
#[test]
#[serial]
fn a_record_past_the_clock_skew_tolerance_refuses_admission() {
    let fx = fixture("admit-skew");
    let now = now_ms();
    let skewed_id = "a".repeat(64);
    let second_id = "b".repeat(64);

    fx.first
        .record_pending(
            &fx.profile,
            &[count_entry(
                &fx.profile_name,
                now + CLOCK_SKEW_TOLERANCE_MS + 1,
                3,
            )],
            &reservation(&skewed_id, 7, now),
        )
        .expect("an empty bucket admits its first entry at that entry's own clock");

    let refused = fx
        .second
        .record_pending(
            &fx.profile,
            &[count_entry(&fx.profile_name, now, 3)],
            &reservation(&second_id, 8, now),
        )
        .expect_err("a record past the tolerance fails admission closed");
    match refused {
        WindowStoreError::PolicyDenied { reason } => {
            assert_eq!(reason.wire_code(), "policy.deny.evaluation_error");
            assert!(
                matches!(*reason, DenyReason::EvaluationError { .. }),
                "{reason:?}"
            );
        }
        other => panic!("expected PolicyDenied, got {other:?}"),
    }
    assert_eq!(
        fx.open_reservation_ids(),
        vec![skewed_id],
        "the refused reservation wrote nothing"
    );

    let gate = PolicyStateStore::new();
    fx.first
        .load_into(&fx.profile_name, &fx.profile, &gate)
        .unwrap();
    assert!(
        matches!(
            gate.query_window(&count_key(&fx.profile_name), now),
            Err(StateStoreError::ClockSkewExceeded { .. })
        ),
        "the gate's own query of the same file fails closed"
    );
}

/// A record dated exactly at the tolerance is within the gate's clock and
/// counts toward the limit like any other.
#[test]
#[serial]
fn a_record_at_the_clock_skew_tolerance_counts_toward_the_limit() {
    let fx = fixture("admit-skew-edge");
    let now = now_ms();
    let first_id = "a".repeat(64);
    let second_id = "b".repeat(64);
    let third_id = "c".repeat(64);

    fx.first
        .record_pending(
            &fx.profile,
            &[count_entry(
                &fx.profile_name,
                now + CLOCK_SKEW_TOLERANCE_MS,
                2,
            )],
            &reservation(&first_id, 7, now),
        )
        .expect("the first call fits");
    fx.second
        .record_pending(
            &fx.profile,
            &[count_entry(&fx.profile_name, now, 2)],
            &reservation(&second_id, 8, now),
        )
        .expect("one record within the tolerance leaves one call of headroom");
    let refused = fx
        .first
        .record_pending(
            &fx.profile,
            &[count_entry(&fx.profile_name, now, 2)],
            &reservation(&third_id, 9, now),
        )
        .expect_err("the limit counts the record at the tolerance");
    match refused {
        WindowStoreError::PolicyDenied { reason } => assert!(
            matches!(
                *reason,
                DenyReason::RateLimitExceeded {
                    max_calls: 2,
                    calls_in_window: 2,
                    ..
                }
            ),
            "{reason:?}"
        ),
        other => panic!("expected PolicyDenied, got {other:?}"),
    }
    assert_eq!(fx.open_reservation_ids(), vec![first_id, second_id]);
}
