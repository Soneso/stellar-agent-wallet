#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test assertions"
)]

use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serial_test::serial;

use super::*;
use crate::approval::attest::{
    ConsentAudit, ConsentAuthorization, Surface, attest_and_persist, attest_and_persist_with_row,
};
use crate::approval::mainnet_fixtures::{ATTESTATION_KEY, MainnetConsentFixture};
use crate::approval::presence::{MAINNET_CHAIN_ID, mainnet_consent_subject};
use crate::approval::store::{DEFAULT_TTL_MS, PendingApprovalStore};

const PROFILE: &str = "main";

/// One independent change to a stored entry.
type Edit<'a> = dyn Fn(&mut PendingApproval) + 'a;

fn now_ms() -> u64 {
    crate::timefmt::now_unix_ms().unwrap()
}

/// A strict mainnet consent to `entry` through the direct writer or the
/// keyed outbox, its attested entry as reopened from disk, and the returned
/// queued reference.
fn strict_consent(
    fixture: &MainnetConsentFixture,
    entry: &PendingApproval,
    queued: bool,
) -> (PendingApproval, Option<OutboxRowRef>) {
    use crate::audit_log::{
        AuditOutbox, AuditWriter, BindingHistory, tip_anchor::InMemoryTipAnchorStore,
    };
    let policy = fixture.current_policy();
    let anchors = Arc::new(InMemoryTipAnchorStore::new());
    let mut writer = AuditWriter::open_with_tip_anchor(
        fixture.audit_path(),
        Some(zeroize::Zeroizing::new([0x5a; 32])),
        anchors.clone(),
        BindingHistory::NotRecorded,
    )
    .unwrap();
    let outbox = AuditOutbox::for_log_keyed(
        &fixture.audit_path(),
        anchors,
        zeroize::Zeroizing::new([0x5a; 32]),
    );
    let mut store = PendingApprovalStore::open(fixture.store_path()).unwrap();
    store.insert(entry.clone(), now_ms()).unwrap();
    let (_, reference) = attest_and_persist_with_row(
        &mut store,
        entry,
        &ATTESTATION_KEY,
        &fixture.binding(),
        Surface::Cli,
        if queued {
            ConsentAudit::Outbox(&outbox)
        } else {
            ConsentAudit::Writer(&mut writer)
        },
        ConsentAuthorization::Mainnet {
            presence: fixture.presence(entry, &policy),
            policy: &policy,
        },
        |_, _| panic!("no grant"),
    )
    .unwrap();
    drop(store);
    let reopened = PendingApprovalStore::open(fixture.store_path()).unwrap();
    (
        reopened.get(&entry.approval_nonce).unwrap().clone(),
        reference,
    )
}

/// `entry` with its stored handoff table changed by `edit`, decoded again.
fn edited(
    entry: &PendingApproval,
    edit: impl FnOnce(&mut toml::Table),
) -> Result<PendingApproval, String> {
    let mut value = toml::Value::try_from(entry).unwrap();
    edit(
        value
            .get_mut("consent_publication")
            .and_then(toml::Value::as_table_mut)
            .unwrap(),
    );
    value
        .try_into()
        .map_err(|error: toml::de::Error| error.to_string())
}

fn verdict(entry: &PendingApproval, binding: &AttestationBinding<'_>) -> Result<(), &'static str> {
    verify_consent_publication(entry, &ATTESTATION_KEY, binding)
        .map(|_| ())
        .map_err(|error| error.code())
}

/// A strict consent stores a handoff that verifies over its reopened entry.
/// Each independent edit of a bound field or of the sink, a handoff or
/// receipt of another consent, and another profile or chain refuse.
#[test]
#[serial]
fn publication_handoff_is_authenticated_and_atomic() {
    let refused = Err("approval.attestation_invalid");
    for queued in [false, true] {
        let fixture = MainnetConsentFixture::new(PROFILE);
        let entry = fixture.payment(DEFAULT_TTL_MS);
        let (stored, reference) = strict_consent(&fixture, &entry, queued);
        let binding = fixture.binding();
        assert_eq!(reference.is_some(), queued);
        let verified = verify_consent_publication(&stored, &ATTESTATION_KEY, &binding).unwrap();
        assert_eq!(verified.outbox_row(), reference.as_ref());
        assert_eq!(verified.is_direct_anchored(), !queued);
        assert_eq!(
            verified.subject(),
            mainnet_consent_subject(&stored, &binding).unwrap()
        );

        let sibling_fixture = MainnetConsentFixture::new(PROFILE);
        let other = sibling_fixture.payment(DEFAULT_TTL_MS);
        let (sibling, _) = strict_consent(&sibling_fixture, &other, queued);
        let edits: [(&str, Box<Edit<'_>>); 8] = [
            (
                "nonce",
                Box::new(|e| e.approval_nonce.clone_from(&other.approval_nonce)),
            ),
            ("uid", Box::new(|e| e.process_uid.push('0'))),
            ("created", Box::new(|e| e.created_at_unix_ms += 1)),
            ("expires", Box::new(|e| e.expires_at_unix_ms += 1)),
            (
                "convention",
                Box::new(|e| e.subject_kind = SubjectKind::IntentDigest),
            ),
            (
                "attestation",
                Box::new(|e| {
                    e.attestation_blob_b64 = Some(URL_SAFE_NO_PAD.encode([9; 32]));
                }),
            ),
            (
                "receipt",
                Box::new(|e| e.mainnet_presence.clone_from(&sibling.mainnet_presence)),
            ),
            (
                "replay",
                Box::new(|e| {
                    e.consent_publication
                        .clone_from(&sibling.consent_publication)
                }),
            ),
        ];
        for (name, edit) in edits {
            let mut candidate = stored.clone();
            edit(&mut candidate);
            assert_eq!(
                verdict(&candidate, &binding),
                refused,
                "{name}, queued {queued}"
            );
        }
        let mut absent = stored.clone();
        absent.consent_publication = None;
        assert_eq!(verdict(&absent, &binding), refused, "absent");
        assert_eq!(
            verdict(&stored, &AttestationBinding::new("other", MAINNET_CHAIN_ID)),
            refused
        );
        assert_eq!(
            verdict(
                &stored,
                &AttestationBinding::new(PROFILE, "stellar:testnet")
            ),
            refused
        );

        let sink = edited(&stored, |table| {
            if queued {
                table.insert("sink".to_owned(), "direct_anchored".into());
                table.remove("outbox_row");
            } else {
                let mut row = toml::Table::new();
                row.insert("g".to_owned(), 0.into());
                row.insert("s".to_owned(), 1.into());
                row.insert(
                    "digest".to_owned(),
                    format!("sha256:{}", "ab".repeat(32)).into(),
                );
                table.insert("sink".to_owned(), "queued".into());
                table.insert("outbox_row".to_owned(), row.into());
            }
        })
        .unwrap();
        assert_eq!(verdict(&sink, &binding), refused, "sink, queued {queued}");
        if queued {
            for (field, value) in [
                ("g", toml::Value::from(1)),
                ("s", toml::Value::from(2)),
                ("digest", format!("sha256:{}", "cd".repeat(32)).into()),
            ] {
                let moved = edited(&stored, |table| {
                    table["outbox_row"]
                        .as_table_mut()
                        .unwrap()
                        .insert(field.to_owned(), value);
                })
                .unwrap();
                assert_eq!(verdict(&moved, &binding), refused, "{field}");
            }
        }
        let subject = edited(&stored, |table| {
            table.insert("subject".to_owned(), "11".repeat(32).into());
        })
        .unwrap();
        assert_eq!(verdict(&subject, &binding), refused, "subject");
    }
}

/// The tag is HMAC-SHA256 under the attestation key over bytes written out
/// here independently of the encoder. Version 2, unknown or missing members,
/// a non-canonical digest and an unpaired sink refuse; reordered members
/// verify. A compatibility consent stores no handoff and no field.
#[test]
#[serial]
fn publication_handoff_canonical_vectors() {
    use hmac::Mac as _;
    use sha2::Digest as _;
    for queued in [false, true] {
        let fixture = MainnetConsentFixture::new(PROFILE);
        let entry = fixture.payment(DEFAULT_TTL_MS);
        let (stored, reference) = strict_consent(&fixture, &entry, queued);
        let binding = fixture.binding();
        let mut expected = b"stellar-agent-consent-publication:v1".to_vec();
        expected.push(1);
        let prefixed = |out: &mut Vec<u8>, text: &str| {
            out.extend_from_slice(&u32::try_from(text.len()).unwrap().to_be_bytes());
            out.extend_from_slice(text.as_bytes());
        };
        prefixed(&mut expected, PROFILE);
        prefixed(&mut expected, MAINNET_CHAIN_ID);
        prefixed(&mut expected, &stored.approval_nonce);
        prefixed(&mut expected, "PaymentSimulated");
        expected.push(1);
        expected.extend_from_slice(&mainnet_consent_subject(&stored, &binding).unwrap());
        expected.extend_from_slice(&stored.created_at_unix_ms.to_be_bytes());
        expected.extend_from_slice(&stored.expires_at_unix_ms.to_be_bytes());
        prefixed(&mut expected, &stored.process_uid);
        let blob = URL_SAFE_NO_PAD
            .decode(stored.attestation_blob_b64.as_ref().unwrap())
            .unwrap();
        expected.extend_from_slice(&Sha256::digest(&blob));
        expected.extend_from_slice(&stored.mainnet_presence.as_ref().unwrap().digest().unwrap());
        if let Some(reference) = reference {
            expected.push(2);
            expected.extend_from_slice(&reference.generation().to_be_bytes());
            expected.extend_from_slice(&reference.sequence().to_be_bytes());
            expected.extend_from_slice(reference.digest());
        } else {
            expected.push(1);
        }
        let mut mac =
            <Hmac<Sha256> as hmac::digest::KeyInit>::new_from_slice(&ATTESTATION_KEY).unwrap();
        mac.update(&expected);
        let tag = crate::hex::encode(&mac.finalize().into_bytes());
        let wire = toml::Value::try_from(&stored).unwrap();
        let publication = wire["consent_publication"].as_table().unwrap();
        assert_eq!(publication["tag"].as_str(), Some(tag.as_str()));
        assert_eq!(publication["v"].as_integer(), Some(1));
        assert_eq!(
            publication["sink"].as_str(),
            Some(if queued { "queued" } else { "direct_anchored" })
        );

        let decodes = |edit: &dyn Fn(&mut toml::Table)| edited(&stored, edit).is_ok();
        assert!(!decodes(&|t| {
            t.insert("v".to_owned(), 2.into());
        }));
        assert!(!decodes(&|t| {
            t.insert("extra".to_owned(), 1.into());
        }));
        assert!(!decodes(&|t| {
            t.insert("subject".to_owned(), "AB".repeat(32).into());
        }));
        for member in ["v", "sink", "subject", "tag"] {
            assert!(
                !decodes(&|t| {
                    t.remove(member);
                }),
                "{member}"
            );
        }
        let reordered = edited(&stored, |table| {
            let members: Vec<_> = std::mem::take(table).into_iter().rev().collect();
            table.extend(members);
        })
        .unwrap();
        assert_eq!(verdict(&reordered, &binding), Ok(()));
        let unpaired = edited(&stored, |table| {
            if queued {
                table.remove("outbox_row");
            } else {
                table.insert("sink".to_owned(), "queued".into());
            }
        })
        .unwrap();
        assert_eq!(
            verdict(&unpaired, &binding),
            Err("approval.attestation_invalid")
        );
    }

    let fixture = MainnetConsentFixture::new(PROFILE);
    let policy = fixture.current_policy();
    let entry = fixture.payment(DEFAULT_TTL_MS);
    let mut store = PendingApprovalStore::open(fixture.store_path()).unwrap();
    store.insert(entry.clone(), now_ms()).unwrap();
    let mut writer = fixture.audit_writer();
    attest_and_persist(
        &mut store,
        &entry,
        &ATTESTATION_KEY,
        &fixture.binding(),
        Surface::Cli,
        ConsentAudit::Writer(&mut writer),
        ConsentAuthorization::Mainnet {
            presence: fixture.presence(&entry, &policy),
            policy: &policy,
        },
        |_, _| panic!("no grant"),
    )
    .unwrap();
    let compatible = store.get(&entry.approval_nonce).unwrap();
    assert!(compatible.mainnet_presence.is_some());
    assert!(compatible.consent_publication.is_none());
    let text = std::fs::read_to_string(fixture.store_path()).unwrap();
    assert!(!text.contains("consent_publication"));
}
