#![allow(
    clippy::unwrap_used,
    reason = "test assertions require successful fixture construction"
)]

use super::*;

fn limit(kind: usize, cap: i128, label: &str) -> WindowLimit {
    match kind {
        0 => WindowLimit::Amount {
            asset: label.to_owned(),
            window: "1m".to_owned(),
            max_stroops: cap,
        },
        1 => WindowLimit::Count {
            window: label.to_owned(),
            max_calls: u32::try_from(cap).unwrap(),
        },
        2 => WindowLimit::Unlisted {
            asset: label.to_owned(),
            window: "1m".to_owned(),
            max_stroops: cap,
        },
        _ => WindowLimit::Total {
            asset: label.to_owned(),
            max_stroops: cap,
        },
    }
}

fn entry(kind: usize, cap: i128, label: &str) -> WindowEntry {
    WindowEntry::new(
        StateKey::new("union", 1, "native", 60),
        100_000,
        if kind == 1 { 1 } else { 50 },
        limit(kind, cap, label),
    )
}

#[test]
fn composed_entries_keep_complete_keys_limits_and_singleton() {
    for kind in 0..4 {
        let routed = entry(kind, 200, "native");
        let outer = entry(kind, 100, "XLM");
        assert_eq!(
            compose_window_entries(&[routed.clone(), routed.clone()], None).unwrap(),
            vec![routed.clone(), routed.clone()],
            "singleton keeps repeated criteria: {kind}"
        );
        assert_eq!(
            compose_window_entries(&[routed.clone(), routed.clone()], Some(&[])).unwrap(),
            vec![routed.clone(), routed.clone()],
            "an empty outer vector keeps the routed multiplicity: {kind}"
        );
        assert_eq!(
            compose_window_entries(
                &[routed.clone(), routed.clone()],
                Some(std::slice::from_ref(&outer))
            )
            .unwrap(),
            vec![outer.clone(), routed.clone()],
            "the shared occurrence takes the tighter limit and its labels: {kind}"
        );
        assert_eq!(
            compose_window_entries(
                std::slice::from_ref(&outer),
                Some(std::slice::from_ref(&routed))
            )
            .unwrap(),
            vec![outer.clone()],
            "a looser outer cap cannot raise the routed cap: {kind}"
        );
        let tie = entry(kind, 100, "equivalent-label");
        assert_eq!(
            compose_window_entries(std::slice::from_ref(&outer), Some(&[tie])).unwrap(),
            vec![outer],
            "cap ties keep routed labels: {kind}"
        );
        let mut distinct = Vec::new();
        for key in [
            StateKey::new("other", 1, "native", 60),
            StateKey::new("union", 2, "native", 60),
            StateKey::new("union", 1, "other", 60),
            StateKey::new("union", 1, "native", 61),
        ] {
            let mut unique = routed.clone();
            unique.key = key;
            distinct.push(unique);
        }
        distinct.push(routed.clone().with_epoch(Some([1; 32])));
        distinct.push(routed.clone().with_epoch(Some([2; 32])));
        let mut expected = vec![routed.clone()];
        expected.extend(distinct.clone());
        assert_eq!(
            compose_window_entries(&[routed], Some(&distinct)).unwrap(),
            expected,
            "every key field and epoch keeps its entry in order: {kind}"
        );
        assert_eq!(
            compose_window_entries(&[], Some(&distinct)).unwrap(),
            distinct,
            "outer-only entries keep their order: {kind}"
        );
    }
    assert_eq!(compose_window_entries(&[], None).unwrap(), vec![]);
    assert_eq!(compose_window_entries(&[], Some(&[])).unwrap(), vec![]);
    for amount in [i128::MAX, 0, -1] {
        let mut large = entry(0, i128::MAX, "native");
        large.amount = amount;
        assert_eq!(
            compose_window_entries(
                std::slice::from_ref(&large),
                Some(std::slice::from_ref(&large))
            )
            .unwrap(),
            vec![large],
            "composition never sums, clamps, or changes a debit"
        );
    }
}

/// Occurrences pair across the two vectors only: each input keeps its own
/// multiplicity, the composed count is the larger one, and a paired
/// occurrence carries the tighter cap.
#[test]
fn composition_keeps_the_larger_multiplicity_of_each_input() {
    for kind in 0..4 {
        for (routed_cap, outer_cap) in [(200, 100), (100, 200)] {
            let routed = entry(kind, routed_cap, "native");
            let outer = entry(kind, outer_cap, "XLM");
            let tighter = if outer_cap < routed_cap {
                &outer
            } else {
                &routed
            };
            for routed_count in 0..4 {
                for outer_count in 0..4 {
                    let shared = routed_count.min(outer_count);
                    let mut expected = vec![tighter.clone(); shared];
                    expected.extend(vec![routed.clone(); routed_count - shared]);
                    expected.extend(vec![outer.clone(); outer_count - shared]);
                    assert_eq!(
                        compose_window_entries(
                            &vec![routed.clone(); routed_count],
                            Some(&vec![outer.clone(); outer_count]),
                        )
                        .unwrap(),
                        expected,
                        "multiplicity {routed_count}/{outer_count}, caps \
                         {routed_cap}/{outer_cap}: {kind}"
                    );
                }
            }
        }
    }
}

#[test]
fn composition_refuses_inconsistent_entries() {
    let routed = entry(0, 200, "native");
    for field in ["amount", "timestamp"] {
        let mut outer = routed.clone();
        if field == "amount" {
            outer.amount += 1;
        } else {
            outer.timestamp_ms += 1;
        }
        assert!(
            matches!(
                compose_window_entries(std::slice::from_ref(&routed), Some(&[outer])),
                Err(PolicyError::Internal { detail }) if detail == "inconsistent holds for one payment"
            ),
            "inconsistent {field} refuses"
        );
    }
    for first in 0..4 {
        for second in 0..4 {
            if first == second {
                continue;
            }
            let mut a = entry(first, 100, "native");
            let mut b = entry(second, 100, "native");
            a.amount = 1;
            b.amount = 1;
            assert!(
                matches!(
                    compose_window_entries(&[a], Some(&[b])),
                    Err(PolicyError::Internal { .. })
                ),
                "incompatible limits refuse: {first}/{second}"
            );
        }
    }
    for amount in [0, 2] {
        let mut count = entry(1, 10, "1m");
        count.amount = amount;
        assert!(
            matches!(
                compose_window_entries(&[], Some(&[count])),
                Err(PolicyError::Internal { .. })
            ),
            "a count entry represents one call"
        );
    }
}
