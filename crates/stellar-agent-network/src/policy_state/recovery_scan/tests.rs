#![allow(clippy::unwrap_used)]

use super::*;
use serde_json::json;

fn page(sequence: u32, close: u64, oldest: u32, latest: u32) -> GetLedgersResponse {
    serde_json::from_value(json!({
        "latestLedger":latest, "latestLedgerCloseTime":close.to_string(),
        "oldestLedger":oldest, "oldestLedgerCloseTime":1, "cursor":sequence.to_string(),
        "ledgers":[{"sequence":sequence,"ledgerCloseTime":close.to_string(),
            "hash":"00".repeat(32),"headerXdr":"","metadataXdr":""}]
    }))
    .unwrap()
}

#[test]
fn scan_engine_contiguity_seam_and_strict_end() {
    let mut scan = RecoveryScan::new("11".repeat(32), &"22".repeat(32), 10);
    assert_eq!(
        scan.digest,
        "022fb121dcc2bf2cf342659fe1b28f2e59a0ceb4b2c34099f80a2ade6b7e8614"
    );
    for (index, close) in [20, 21, 21, 23].into_iter().enumerate() {
        let n = 10 + u32::try_from(index).unwrap();
        let value = ledger(&page(n, close, 1, 20), scan.next_unread, 20).unwrap();
        scan.accept([value, value], 21).unwrap();
        assert_eq!(scan.end, (index == 3).then_some((13, 23)));
        scan = serde_json::from_str(&serde_json::to_string(&scan).unwrap()).unwrap();
        if index == 2 {
            let saved = scan.clone();
            assert_eq!(scan.accept([20, 20], 21), Err(Reason::MissingField));
            assert_eq!(scan, saved, "a decreasing seam cannot change the prefix");
            assert_eq!(scan.accept([24, 25], 21), Err(Reason::Disagreement));
            assert_eq!(scan.accept([0, 0], 21), Err(Reason::MissingField));
        }
    }
    assert_eq!(scan.next_unread, 14);
    assert_eq!(
        ledger(&page(15, 24, 1, 20), 14, 20),
        Err(Reason::MissingField)
    );
    assert_eq!(ledger(&page(14, 24, 1, 19), 14, 20), Err(Reason::Lagging));
    let mut maximum = RecoveryScan::new("11".repeat(32), &"22".repeat(32), u32::MAX);
    let saved = maximum.clone();
    assert_eq!(maximum.accept([23, 23], 21), Err(Reason::MissingField));
    assert_eq!(maximum, saved);
    for defect in 0..5 {
        let mut answer = page(14, 24, 1, 20);
        match defect {
            0 => answer.ledgers.clear(),
            1 => answer.ledgers.push(answer.ledgers[0].clone()),
            2 => answer.ledgers[0].ledger_close_time = "0".into(),
            3 => answer.ledgers[0].ledger_close_time = "bad".into(),
            _ => answer.oldest_ledger = 0,
        }
        assert_eq!(ledger(&answer, 14, 20), Err(Reason::MissingField));
    }
}

#[test]
fn scan_unread_pruning_is_history_lost() {
    for oldest in [11, 20] {
        assert_eq!(
            ledger(&page(oldest, 23, oldest, 20), 10, 20),
            Err(Reason::HistoryLost)
        );
    }
}

#[test]
fn scan_matched_prefix_survives_pruning() {
    let mut scan = RecoveryScan::new("11".repeat(32), &"22".repeat(32), 10);
    scan.accept([20, 20], 21).unwrap();
    let digest = scan.digest.clone();
    assert_eq!(ledger(&page(11, 23, 11, 20), scan.next_unread, 20), Ok(23));
    let close = ledger(&page(11, 23, 11, 20), scan.next_unread, 20).unwrap();
    scan.accept([close, close], 21).unwrap();
    assert_eq!(scan.end, Some((11, 23)));
    assert_ne!(scan.digest, digest);
    assert!(scan.valid(Some(10), Some(20), 21));
}
