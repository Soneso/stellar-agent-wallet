//! The `mainnet.approval_credentials` array of a signed mainnet policy.
//!
//! ```toml
//! approval_credentials = [
//!   { credential_id_b64url = "<id>", public_key_sec1_b64url = "<key>" },
//! ]
//! ```
//!
//! The array holds 1 to 16 inline tables with exactly the two keys
//! `credential_id_b64url` and `public_key_sec1_b64url`. Both values are canonical unpadded base64url:
//! an ID of 16 to 64 bytes and a 65-byte SEC1 uncompressed P-256 point. The
//! IDs are unique; two entries may share a key. The loader, the minimum
//! evaluator, the profile-body validator and the canonicalizer all read the
//! array through [`parse_approval_credentials`], so they agree on what is
//! accepted.

use toml_edit::{InlineTable, Item, Value};

use crate::approval::presence::{
    MAINNET_APPROVAL_CREDENTIALS_MAX, MAINNET_APPROVAL_CREDENTIALS_MIN, MainnetApprovalCredential,
};
use crate::policy::PolicyError;

/// The keys of one credential entry, in canonical order.
pub(crate) const APPROVAL_CREDENTIAL_KEYS: &[&str] =
    &["credential_id_b64url", "public_key_sec1_b64url"];

/// The minimum requirement name of the array.
pub(crate) const REQUIREMENT: &str = "approval_credentials";

/// The parse details, fixed so an error never reflects policy content.
pub(crate) const DETAIL_SHAPE: &str =
    "mainnet.approval_credentials must be an array of 1 to 16 inline tables";
pub(crate) const DETAIL_UNKNOWN_FIELD: &str =
    "mainnet.approval_credentials contains an unknown field";
pub(crate) const DETAIL_DUPLICATE_ID: &str =
    "mainnet.approval_credentials contains a duplicate credential id";
pub(crate) const DETAIL_INVALID_ID: &str =
    "mainnet.approval_credentials contains an invalid credential id";
pub(crate) const DETAIL_INVALID_KEY: &str =
    "mainnet.approval_credentials contains an invalid P-256 public key";

/// The minimum report's detail for an absent or empty array.
pub(crate) const DETAIL_MISSING: &str =
    "mainnet.approval_credentials must contain at least one approval credential";

fn parse_error(detail: &str) -> PolicyError {
    PolicyError::PolicyFileParseFailed {
        detail: detail.to_owned(),
    }
}

/// The array's inline tables, or the shape error. `Ok(None)` for an absent
/// item.
fn entries(item: Option<&Item>) -> Result<Option<Vec<&InlineTable>>, PolicyError> {
    let Some(item) = item else {
        return Ok(None);
    };
    let Some(array) = item.as_value().and_then(Value::as_array) else {
        return Err(parse_error(DETAIL_SHAPE));
    };
    array
        .iter()
        .map(|value| {
            value
                .as_inline_table()
                .ok_or_else(|| parse_error(DETAIL_SHAPE))
        })
        .collect::<Result<Vec<_>, _>>()
        .map(Some)
}

/// Refuses an entry key outside [`APPROVAL_CREDENTIAL_KEYS`].
///
/// # Errors
///
/// `policy.policy_file_parse_failed` with the fixed unknown-field detail.
pub(crate) fn reject_unknown_fields(item: Option<&Item>) -> Result<(), PolicyError> {
    let Some(Value::Array(array)) = item.and_then(Item::as_value) else {
        return Ok(());
    };
    for entry in array.iter().filter_map(Value::as_inline_table) {
        if entry
            .iter()
            .any(|(key, _)| !APPROVAL_CREDENTIAL_KEYS.contains(&key))
        {
            return Err(parse_error(DETAIL_UNKNOWN_FIELD));
        }
    }
    Ok(())
}

/// Parses `mainnet.approval_credentials` into credentials sorted by their
/// raw IDs.
///
/// # Errors
///
/// - `policy.mainnet_minimum_unmet` with requirement `approval_credentials`
///   for an absent or empty array.
/// - `policy.policy_file_parse_failed` with one of the fixed details for an
///   array of another shape or of more than 16 entries, an unknown field, a
///   missing or invalid ID, a missing or invalid key, or a duplicate ID.
pub fn parse_approval_credentials(
    item: Option<&Item>,
) -> Result<Vec<MainnetApprovalCredential>, PolicyError> {
    let entries = entries(item)?.unwrap_or_default();
    if entries.len() < MAINNET_APPROVAL_CREDENTIALS_MIN {
        return Err(PolicyError::MainnetMinimumUnmet {
            requirement: REQUIREMENT,
            rule: None,
        });
    }
    if entries.len() > MAINNET_APPROVAL_CREDENTIALS_MAX {
        return Err(parse_error(DETAIL_SHAPE));
    }
    let mut credentials = Vec::with_capacity(entries.len());
    for entry in entries {
        if entry
            .iter()
            .any(|(key, _)| !APPROVAL_CREDENTIAL_KEYS.contains(&key))
        {
            return Err(parse_error(DETAIL_UNKNOWN_FIELD));
        }
        let id = entry
            .get("credential_id_b64url")
            .and_then(Value::as_str)
            .ok_or_else(|| parse_error(DETAIL_INVALID_ID))?;
        let key = entry
            .get("public_key_sec1_b64url")
            .and_then(Value::as_str)
            .ok_or_else(|| parse_error(DETAIL_INVALID_KEY))?;
        let credential = MainnetApprovalCredential::from_encoded(id, key).map_err(|error| {
            parse_error(match error {
                crate::approval::presence::ApprovalCredentialError::CredentialId => {
                    DETAIL_INVALID_ID
                }
                _ => DETAIL_INVALID_KEY,
            })
        })?;
        credentials.push(credential);
    }
    credentials.sort_by(|a, b| a.credential_id().cmp(b.credential_id()));
    if credentials
        .windows(2)
        .any(|pair| pair[0].credential_id() == pair[1].credential_id())
    {
        return Err(parse_error(DETAIL_DUPLICATE_ID));
    }
    Ok(credentials)
}

/// The canonical array: entries sorted by raw ID, each an inline table with
/// the two keys in [`APPROVAL_CREDENTIAL_KEYS`] order and canonical
/// encodings, without decoration.
///
/// # Errors
///
/// The errors of [`parse_approval_credentials`].
pub(crate) fn canonical_approval_credentials(item: &Item) -> Result<Value, PolicyError> {
    let credentials = parse_approval_credentials(Some(item))?;
    let mut array = toml_edit::Array::new();
    for credential in &credentials {
        let mut table = InlineTable::new();
        table.insert(
            "credential_id_b64url",
            Value::from(credential.credential_id_b64url()),
        );
        table.insert(
            "public_key_sec1_b64url",
            Value::from(credential.public_key_sec1_b64url()),
        );
        array.push(Value::InlineTable(table));
    }
    Ok(Value::Array(array))
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use stellar_agent_test_support::webauthn::TestAuthenticator;
    use toml_edit::DocumentMut;

    use super::*;

    fn authenticator(seed: u8, id: Vec<u8>) -> TestAuthenticator {
        TestAuthenticator::from_seed([seed; 32], id)
    }

    fn entry(id: &str, key: &str) -> String {
        format!("{{ credential_id_b64url = \"{id}\", public_key_sec1_b64url = \"{key}\" }}")
    }

    fn parse(array: &str) -> Result<Vec<MainnetApprovalCredential>, PolicyError> {
        let doc: DocumentMut = format!("approval_credentials = {array}\n")
            .parse()
            .expect("test TOML parses");
        parse_approval_credentials(doc.get("approval_credentials"))
    }

    fn detail(result: Result<Vec<MainnetApprovalCredential>, PolicyError>) -> String {
        match result {
            Err(PolicyError::PolicyFileParseFailed { detail }) => detail,
            other => panic!("expected a parse failure, got {other:?}"),
        }
    }

    #[test]
    fn approval_credentials_reject_malformed_or_ambiguous_entries() {
        let auth = authenticator(0x31, vec![1; 16]);
        let key = auth.public_key_sec1_b64url();
        let id16 = URL_SAFE_NO_PAD.encode([1u8; 16]);
        let id64 = URL_SAFE_NO_PAD.encode([2u8; 64]);

        // Both ID bounds pass.
        let ok = parse(&format!("[{}, {}]", entry(&id16, &key), entry(&id64, &key)))
            .expect("bounds parse");
        assert_eq!(ok.len(), 2);

        // Absent and empty arrays are a minimum failure.
        let doc: DocumentMut = "other = 1\n".parse().expect("toml");
        assert!(matches!(
            parse_approval_credentials(doc.get("approval_credentials")),
            Err(PolicyError::MainnetMinimumUnmet {
                requirement: "approval_credentials",
                rule: None
            })
        ));
        assert!(matches!(
            parse("[]"),
            Err(PolicyError::MainnetMinimumUnmet {
                requirement: "approval_credentials",
                rule: None
            })
        ));

        // Wrong shapes.
        assert_eq!(detail(parse("\"text\"")), DETAIL_SHAPE);
        assert_eq!(detail(parse("[\"text\"]")), DETAIL_SHAPE);
        let doc: DocumentMut = format!(
            "[[approval_credentials]]\ncredential_id_b64url = \"{id16}\"\npublic_key_sec1_b64url = \"{key}\"\n"
        )
        .parse()
        .expect("toml");
        assert_eq!(
            detail(parse_approval_credentials(doc.get("approval_credentials"))),
            DETAIL_SHAPE
        );
        let seventeen: Vec<String> = (0u8..17)
            .map(|i| entry(&URL_SAFE_NO_PAD.encode([i; 16]), &key))
            .collect();
        assert_eq!(
            detail(parse(&format!("[{}]", seventeen.join(", ")))),
            DETAIL_SHAPE
        );
        let sixteen: Vec<String> = (0u8..16)
            .map(|i| entry(&URL_SAFE_NO_PAD.encode([i; 16]), &key))
            .collect();
        assert_eq!(
            parse(&format!("[{}]", sixteen.join(", ")))
                .expect("16")
                .len(),
            16
        );

        // Unknown and missing fields.
        assert_eq!(
            detail(parse(&format!(
                "[{{ credential_id_b64url = \"{id16}\", public_key_sec1_b64url = \"{key}\", label = \"x\" }}]"
            ))),
            DETAIL_UNKNOWN_FIELD
        );
        assert_eq!(
            detail(parse(&format!(
                "[{{ public_key_sec1_b64url = \"{key}\" }}]"
            ))),
            DETAIL_INVALID_ID
        );
        assert_eq!(
            detail(parse(&format!("[{{ credential_id_b64url = \"{id16}\" }}]"))),
            DETAIL_INVALID_KEY
        );

        // Noncanonical base64url and ID lengths outside 16..=64.
        let padded = base64::engine::general_purpose::URL_SAFE.encode([1u8; 16]);
        assert!(padded.ends_with('='));
        assert_eq!(
            detail(parse(&format!("[{}]", entry(&padded, &key)))),
            DETAIL_INVALID_ID
        );
        let standard_alphabet = base64::engine::general_purpose::STANDARD_NO_PAD.encode([0xfb; 16]);
        assert_ne!(standard_alphabet, URL_SAFE_NO_PAD.encode([0xfb; 16]));
        assert_eq!(
            detail(parse(&format!("[{}]", entry(&standard_alphabet, &key)))),
            DETAIL_INVALID_ID
        );
        // A trailing character whose unused bits are set decodes to the same
        // bytes under a lenient decoder but is not the canonical text.
        let mut alias = URL_SAFE_NO_PAD.encode([1u8; 16]);
        let last = alias.pop().expect("nonempty");
        alias.push(if last == 'Q' { 'R' } else { 'Q' });
        assert_eq!(
            detail(parse(&format!("[{}]", entry(&alias, &key)))),
            DETAIL_INVALID_ID
        );
        for len in [15usize, 65] {
            let id = URL_SAFE_NO_PAD.encode(vec![3u8; len]);
            assert_eq!(
                detail(parse(&format!("[{}]", entry(&id, &key)))),
                DETAIL_INVALID_ID
            );
        }

        // Duplicate IDs refuse, also when the keys differ.
        let other = authenticator(0x32, vec![1; 16]).public_key_sec1_b64url();
        assert_eq!(
            detail(parse(&format!(
                "[{}, {}]",
                entry(&id16, &key),
                entry(&id16, &other)
            ))),
            DETAIL_DUPLICATE_ID
        );

        // Keys: 64 and 66 bytes, a wrong SEC1 prefix, an off-curve point.
        let raw = auth.public_key_sec1();
        for bad in [
            raw[..64].to_vec(),
            [raw.as_slice(), &[0]].concat(),
            {
                let mut compressed_prefix = raw.to_vec();
                compressed_prefix[0] = 0x02;
                compressed_prefix
            },
            {
                let mut off_curve = raw.to_vec();
                off_curve[64] ^= 1;
                off_curve
            },
        ] {
            assert_eq!(
                detail(parse(&format!(
                    "[{}]",
                    entry(&id16, &URL_SAFE_NO_PAD.encode(&bad))
                ))),
                DETAIL_INVALID_KEY
            );
        }
    }

    #[test]
    fn credentials_sort_by_raw_id_and_may_share_a_key() {
        let key = authenticator(0x33, vec![1; 16]).public_key_sec1_b64url();
        let high = URL_SAFE_NO_PAD.encode([0xf0u8; 16]);
        let low = URL_SAFE_NO_PAD.encode([0x01u8; 20]);
        let parsed =
            parse(&format!("[{}, {}]", entry(&high, &key), entry(&low, &key))).expect("parse");
        assert_eq!(parsed[0].credential_id(), &[0x01u8; 20]);
        assert_eq!(parsed[1].credential_id(), &[0xf0u8; 16]);
    }
}
