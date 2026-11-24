fn destination_muxed(id: u64) -> String {
    stellar_strkey::ed25519::MuxedAccount {
        ed25519: [7; 32],
        id,
    }
    .to_string()
    .as_str()
    .to_owned()
}

fn destination_list() -> PaymentDestinations {
    PaymentDestinations::PerOperation(vec![
        OperationDestination {
            operation: 0,
            destination: SOURCE_A.to_owned(),
        },
        OperationDestination {
            operation: 2,
            destination: destination_muxed(u64::MAX),
        },
    ])
}

#[test]
fn payment_destinations_validate_their_shape() {
    use serde_json::json;
    assert!(PaymentDestinations::None.is_valid());
    assert!(PaymentDestinations::Single(destination_muxed(0)).is_valid());
    assert!(PaymentDestinations::Single(destination_muxed(u64::MAX)).is_valid());
    assert!(!PaymentDestinations::Single(destination_muxed(0).to_lowercase()).is_valid());
    assert!(!PaymentDestinations::Single(SOURCE_A.to_owned()).is_valid());
    let PaymentDestinations::PerOperation(mut entries) = destination_list() else {
        unreachable!()
    };
    assert!(PaymentDestinations::PerOperation(entries.clone()).is_valid());
    entries[1].operation = 99;
    assert!(PaymentDestinations::PerOperation(entries.clone()).is_valid());
    entries[1].operation = 100;
    assert!(!PaymentDestinations::PerOperation(entries.clone()).is_valid());
    entries[1].operation = 0;
    assert!(!PaymentDestinations::PerOperation(entries.clone()).is_valid());
    entries[1].operation = 2;
    entries[1].destination = SOURCE_B.to_owned();
    assert!(!PaymentDestinations::PerOperation(entries.clone()).is_valid());
    entries[0].destination = destination_muxed(0);
    entries[1].destination = destination_muxed(0);
    assert!(!PaymentDestinations::PerOperation(entries).is_valid());
    let entries: Vec<_> = (0..100)
        .map(|operation| OperationDestination {
            operation,
            destination: destination_muxed(u64::from(operation)),
        })
        .collect();
    assert!(PaymentDestinations::PerOperation(entries.clone()).is_valid());
    let mut too_many = entries;
    too_many.push(OperationDestination {
        operation: 100,
        destination: destination_muxed(100),
    });
    assert!(!PaymentDestinations::PerOperation(too_many).is_valid());
    for value in [
        json!(3),
        json!({}),
        json!(SOURCE_A),
        json!([]),
        json!([{"operation": 0, "destination": destination_muxed(0)}]),
        json!([{"operation": -1, "destination": SOURCE_A}, {"operation": 2, "destination": destination_muxed(0)}]),
        json!([{"operation": 4294967296_u64, "destination": SOURCE_A}, {"operation": 2, "destination": destination_muxed(0)}]),
    ] {
        assert_eq!(
            PaymentDestinations::from_stored(&value),
            PaymentDestinations::None
        );
    }
}

#[test]
fn receipt_destinations_round_trip() {
    use serde_json::json;
    const GOLDEN: &str = r#"{"envelope_hash":"a","tx_hash":"b","source":"","sequence":1,"status":{"state":"pending"},"recorded_at_ledger":7,"max_time":0,"submitted":false,"approval_consumed":false,"recovered_from_reservation":false}"#;
    let (_dir, store) = open_temp_store();
    store.try_begin("a", "b", "", 1, 0, 7).unwrap();
    let mut receipt = store.get("a").unwrap().unwrap();
    assert_eq!(serde_json::to_string(&receipt).unwrap(), GOLDEN);
    let legacy: SubmissionReceipt = serde_json::from_str(GOLDEN).unwrap();
    assert_eq!(legacy.destinations, PaymentDestinations::None);
    receipt.destinations = PaymentDestinations::Single(destination_muxed(0));
    let golden_muxed = format!(
        "{},\"destination\":\"{}\"}}",
        &GOLDEN[..GOLDEN.len() - 1],
        destination_muxed(0)
    );
    assert_eq!(serde_json::to_string(&receipt).unwrap(), golden_muxed);
    let reread: SubmissionReceipt = serde_json::from_str(&golden_muxed).unwrap();
    assert_eq!(
        reread.destinations,
        PaymentDestinations::Single(destination_muxed(0))
    );
    receipt.destinations = destination_list();
    let list = json!([
        {"operation": 0, "destination": SOURCE_A},
        {"operation": 2, "destination": destination_muxed(u64::MAX)}
    ]);
    assert_eq!(
        serde_json::to_value(&receipt).unwrap()["destinations"],
        list
    );
    let mut wire = serde_json::to_value(&receipt).unwrap();
    for case in 0..5 {
        let mut candidate = wire.clone();
        let expected = match case {
            0 => {
                candidate["destination"] = json!(destination_muxed(0));
                PaymentDestinations::None
            }
            1 => {
                candidate["destinations"][0]["extra"] = json!("ignored");
                destination_list()
            }
            2 => {
                candidate["destinations"][0]["operation"] = json!("zero");
                PaymentDestinations::None
            }
            3 => {
                candidate["destinations"] = json!(4);
                PaymentDestinations::None
            }
            _ => {
                candidate["destinations"] = json!(null);
                PaymentDestinations::None
            }
        };
        std::fs::write(
            store.file_path().unwrap(),
            serde_json::to_vec(&json!({"a": candidate, "other": legacy})).unwrap(),
        )
        .unwrap();
        let read = ReceiptStore::open_at(_dir.path(), "test").unwrap();
        assert_eq!(read.get("a").unwrap().unwrap().destinations, expected);
        assert_eq!(read.get("other").unwrap().unwrap(), legacy);
    }
    wire.as_object_mut().unwrap().remove("destinations");
    wire["destination"] = json!(SOURCE_A);
    let read: SubmissionReceipt = serde_json::from_value(wire).unwrap();
    assert_eq!(read.destinations, PaymentDestinations::None);
}

#[test]
fn every_rebuilt_receipt_keeps_its_destination() {
    let value = destination_list();
    let (_dir, store) = open_temp_store();
    let projection = checked(ReceiptStatus::Success, Some(120)).with_destinations(value.clone());
    for _ in 0..2 {
        store.replace_checked(&projection).unwrap();
        assert_eq!(store.get(HASH_A).unwrap().unwrap().destinations, value);
    }
    let (_dir, store) = open_temp_store();
    store
        .try_begin(HASH_A, TX_HASH_A, SOURCE_A, SEQ_A, 1700, 90)
        .unwrap();
    for _ in 0..2 {
        store.replace_checked(&projection).unwrap();
        let receipt = store.get(HASH_A).unwrap().unwrap();
        assert_eq!(receipt.destinations, value);
        assert_eq!(receipt.status, ReceiptStatus::Success);
    }
    let before = std::fs::read(store.file_path().unwrap()).unwrap();
    let other = checked(ReceiptStatus::Success, Some(120))
        .with_destinations(PaymentDestinations::Single(destination_muxed(0)));
    for _ in 0..2 {
        let error = store.replace_checked(&other).unwrap_err();
        assert!(error.to_string().contains("conflicting identity"));
        assert_eq!(std::fs::read(store.file_path().unwrap()).unwrap(), before);
    }
    let (_dir, store) = open_temp_store();
    for _ in 0..2 {
        store
            .finalize_to(HASH_A, ReceiptStatus::Success, Some(120), &value)
            .unwrap();
        assert_eq!(store.get(HASH_A).unwrap().unwrap().destinations, value);
    }
    let (_dir, store) = open_temp_store();
    let expiry = AccountingExpiryProjection {
        envelope_hash: HASH_A,
        tx_hash: TX_HASH_A,
        source: SOURCE_A,
        sequence: SEQ_A,
        max_time: 1700,
        recorded_at_ledger: 90,
        decision_id: HASH_B,
        destinations: value.clone(),
    };
    for _ in 0..2 {
        store.project_accounting_expiry(&expiry).unwrap();
        assert_eq!(store.get(HASH_A).unwrap().unwrap().destinations, value);
    }
    let (_dir, store) = open_temp_store();
    store
        .try_begin_to(HASH_A, TX_HASH_A, SOURCE_A, SEQ_A, 1700, 90, &value)
        .unwrap();
    for _ in 0..2 {
        let restored = store
            .recover_from_reservation(
                HASH_A,
                TX_HASH_A,
                SOURCE_A,
                SEQ_A,
                1700,
                90,
                &PaymentDestinations::Single(destination_muxed(0)),
            )
            .unwrap();
        assert_eq!(restored.destinations, value);
        store
            .finalize_to(
                HASH_A,
                ReceiptStatus::Success,
                Some(120),
                &PaymentDestinations::Single(destination_muxed(0)),
            )
            .unwrap();
        let receipt = store.get(HASH_A).unwrap().unwrap();
        assert_eq!(receipt.destinations, value);
        assert_eq!(receipt.status, ReceiptStatus::Success);
    }
}

#[test]
fn a_stale_receipt_handle_keeps_the_stored_destination() {
    let (dir, first) = open_temp_store();
    let stale = ReceiptStore::open_at(dir.path(), "test").unwrap();
    assert!(stale.get(HASH_A).unwrap().is_none());
    first
        .try_begin_to(
            HASH_A,
            TX_HASH_A,
            SOURCE_A,
            SEQ_A,
            1700,
            90,
            &destination_list(),
        )
        .unwrap();
    let stored = first.get(HASH_A).unwrap().unwrap();
    let bytes = std::fs::read(first.file_path().unwrap()).unwrap();
    for _ in 0..2 {
        let receipt = stale
            .recover_from_reservation(
                HASH_A,
                TX_HASH_A,
                SOURCE_A,
                SEQ_A,
                1700,
                90,
                &PaymentDestinations::Single(destination_muxed(0)),
            )
            .unwrap();
        assert_eq!(receipt, stored);
        assert_eq!(std::fs::read(first.file_path().unwrap()).unwrap(), bytes);
    }
}

#[test]
fn a_stale_second_process_keeps_the_destination() {
    use std::io::{BufRead as _, Write as _};
    const CHILD: &str = "STELLAR_AGENT_DESTINATION_RECEIPT_CHILD";
    if let Some(dir) = std::env::var_os(CHILD) {
        let store = ReceiptStore::open_at(std::path::Path::new(&dir), "test").unwrap();
        assert!(store.get(HASH_A).unwrap().is_none());
        writeln!(std::io::stdout(), "DESTINATION_READY").unwrap();
        std::io::stdout().flush().unwrap();
        let mut signal = String::new();
        std::io::stdin().read_line(&mut signal).unwrap();
        let other = PaymentDestinations::Single(destination_muxed(0));
        let outcome = store
            .try_begin_to(HASH_A, TX_HASH_A, SOURCE_A, SEQ_A, 1700, 90, &other)
            .unwrap();
        let BeginOutcome::AlreadyPresent(receipt) = outcome else {
            panic!("one claim wins")
        };
        assert_eq!(receipt.destinations, destination_list());
        let restored = store
            .recover_from_reservation(HASH_A, TX_HASH_A, SOURCE_A, SEQ_A, 1700, 90, &other)
            .unwrap();
        assert_eq!(restored, receipt);
        return;
    }
    let (dir, store) = open_temp_store();
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "profile::receipt::tests::a_stale_second_process_keeps_the_destination",
            "--nocapture",
        ])
        .env(CHILD, dir.path())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut output = std::io::BufReader::new(child.stdout.take().unwrap());
    loop {
        let mut line = String::new();
        assert_ne!(
            output.read_line(&mut line).unwrap(),
            0,
            "child reaches its stale read"
        );
        if line.contains("DESTINATION_READY") {
            break;
        }
    }
    assert!(matches!(
        store
            .try_begin_to(
                HASH_A,
                TX_HASH_A,
                SOURCE_A,
                SEQ_A,
                1700,
                90,
                &destination_list()
            )
            .unwrap(),
        BeginOutcome::Winner
    ));
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"continue\n")
        .unwrap();
    assert!(child.wait().unwrap().success());
    assert_eq!(
        store.get(HASH_A).unwrap().unwrap().destinations,
        destination_list()
    );
}
