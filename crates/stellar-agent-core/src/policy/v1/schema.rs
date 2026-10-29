//! Closed key sets of the V1 policy file.
//!
//! The loader accepts a key only where this module lists it. Every listed key
//! outside the `[signature]` envelope is part of the signed canonical form
//! ([`crate::policy::v1::canonical`]), so no key the loader reads can change
//! without breaking the owner signature. The canonical form copies criterion
//! tables whole, unknown members included, so it does not define the accepted
//! keys; these sets do.
//!
//! The loader runs [`validate_policy_keys`] to refuse keys outside the policy
//! schema before it decodes and verifies the signature. An unknown key is
//! reported by name even when the signature also fails.

use toml_edit::{DocumentMut, Item, TableLike, Value};

use crate::policy::PolicyError;

/// Top-level keys of a policy file. `signature` is the envelope, which the
/// canonical form excludes.
const ROOT_KEYS: &[&str] = &["version", "scope", "rules", "signature", "owner_rotation"];

/// Keys of the signed mainnet installation binding, in canonical order.
pub(crate) const MAINNET_KEYS: &[&str] = &[
    "profile",
    "endpoint_host",
    "installation_nonce_sha256",
    "classic_max_fee_per_op_stroops",
    "authorization_ttl_seconds",
    "cross_check_thresholds",
];

/// Keys of the previous owner's rotation statement, in canonical order.
pub(crate) const OWNER_ROTATION_KEYS: &[&str] = &["previous_owner", "new_owner", "sig"];

/// Keys of the `[signature]` envelope.
const SIGNATURE_KEYS: &[&str] = &["owner_id", "sig"];

/// Keys of a rule.
const RULE_KEYS: &[&str] = &[
    "match",
    "criteria",
    "decision",
    "reason",
    "ttl_secs",
    "allow_opaque_signing",
];

/// Keys of a rule's `match` table.
const MATCH_KEYS: &[&str] = &["tool", "chain"];

/// Criterion kinds the loader supports, each with its closed key set, `kind`
/// included.
///
/// Each kind has its own set; a key valid for one kind is unknown for another.
/// The loader refuses a kind absent from this table, so a kind cannot be
/// parsed without a closed key set.
pub(crate) const CRITERION_KEY_SETS: &[(&str, &[&str])] = &[
    ("asset_allowlist", &["kind", "assets"]),
    ("per_tx_cap", &["kind", "asset", "max_stroops"]),
    (
        "per_period_cap",
        &["kind", "asset", "window", "max_stroops"],
    ),
    ("rate_limit", &["kind", "window", "max_calls"]),
    (
        "counterparty_allowlist",
        &["kind", "kinds", "allowlist", "gate_inflows"],
    ),
    ("minimum_reserve", &["kind", "margin_stroops"]),
    ("inner_invocation_count_cap", &["kind", "max_count"]),
    ("bundle_aggregate_cap", &["kind", "asset", "max_amount"]),
    ("restrict_bundle_to_recognised_kinds", &["kind", "enabled"]),
    (
        "bundle_per_period_cap",
        &["kind", "asset", "window", "max_stroops"],
    ),
    ("bundle_per_tx_cap", &["kind", "asset", "max_stroops"]),
    ("bundle_rate_limit", &["kind", "window", "max_calls"]),
    ("quorum_satisfied", &["kind"]),
    ("home_domain_resolved", &["kind"]),
    ("sep10_session_active", &["kind"]),
    ("sep45_session_active", &["kind"]),
];

/// Returns the closed key set of the criterion kind `kind`, or `None` when the
/// loader does not support the kind.
pub(crate) fn criterion_keys(kind: &str) -> Option<&'static [&'static str]> {
    CRITERION_KEY_SETS
        .iter()
        .find(|(name, _)| *name == kind)
        .map(|(_, keys)| *keys)
}

/// Refuses a policy document that holds a key outside the policy schema for
/// versions 1 and 2.
///
/// Checks these containers in order:
///
/// 1. The top level, against the key set of the document's `version`: a
///    version 2 document also accepts `sequence` and `mainnet`.
/// 2. The `[mainnet]` table, then its `cross_check_thresholds` table, whose
///    keys must be `native` or a pinned asset identity.
/// 3. The `[signature]` and `[owner_rotation]` tables.
/// 4. Each rule of a `[[rules]]` array or an inline `rules = [...]` array in
///    order, with its `match` table and its criteria. Each criterion is checked
///    against the key set of its `kind`.
///
/// A container of another shape, and a criterion whose `kind` is absent, not
/// a string, or not a supported kind, is left to the loader's own diagnostics.
///
/// The first unknown key is reported with the loader's location form:
/// ``rule[2].criteria[0]: unknown key `foo` ``,
/// `rule[1]`, `rule[0].match`, `mainnet`, `mainnet.cross_check_thresholds`,
/// `signature`, and no location for a top-level key.
///
/// [`crate::policy::v1::loader::load_signed_policy`] runs this check before it
/// verifies the owner signature.
///
/// # Errors
///
/// Returns [`PolicyError::PolicyFileParseFailed`] naming the first unknown key
/// and its location.
///
/// # Examples
///
/// ```
/// use std::str::FromStr as _;
///
/// use stellar_agent_core::policy::PolicyError;
/// use stellar_agent_core::policy::v1::validate_policy_keys;
/// use toml_edit::DocumentMut;
///
/// let doc = DocumentMut::from_str(
///     "version = 1\nscope = \"profile:alice\"\n\n[[rules]]\n\
///      match = { tool = \"*\", chain = \"*\" }\ncriteria = []\n\
///      decision = \"require_approval\"\nttl = 600\n",
/// )
/// .unwrap();
/// let err = validate_policy_keys(&doc).unwrap_err();
/// assert!(matches!(
///     err,
///     PolicyError::PolicyFileParseFailed { ref detail }
///         if detail.starts_with("rule[0]: unknown key `ttl`")
/// ));
/// ```
pub fn validate_policy_keys(doc: &DocumentMut) -> Result<(), PolicyError> {
    let v2 = doc.get("version").and_then(Item::as_integer) == Some(2);
    let root = if v2 {
        &[
            "version",
            "scope",
            "sequence",
            "mainnet",
            "rules",
            "signature",
            "owner_rotation",
        ][..]
    } else {
        ROOT_KEYS
    };
    reject_unknown_keys(doc.as_table(), root, None, "the policy file")?;
    if let Some(mainnet) = doc.get("mainnet").and_then(Item::as_table_like) {
        reject_unknown_keys(mainnet, MAINNET_KEYS, Some("mainnet"), "the mainnet table")?;
        if let Some(thresholds) = mainnet
            .get("cross_check_thresholds")
            .and_then(Item::as_table_like)
        {
            for (key, _) in thresholds.iter() {
                if key != "native"
                    && crate::asset_id::CanonicalAsset::parse_threshold_key(key).is_err()
                {
                    return Err(PolicyError::PolicyFileParseFailed {
                        detail: format!(
                            "mainnet.cross_check_thresholds: unknown key `{}`; the \
                             thresholds table accepts native and asset identities",
                            key.escape_debug()
                        ),
                    });
                }
            }
        }
    }

    if let Some(Item::Table(signature)) = doc.get("signature") {
        reject_unknown_keys(
            signature,
            SIGNATURE_KEYS,
            Some("signature"),
            "the signature table",
        )?;
    }

    if let Some(rotation) = doc.get("owner_rotation").and_then(Item::as_table_like) {
        reject_unknown_keys(
            rotation,
            OWNER_ROTATION_KEYS,
            Some("owner_rotation"),
            "the owner rotation table",
        )?;
    }

    match doc.get("rules") {
        Some(Item::ArrayOfTables(rules)) => {
            for (idx, rule) in rules.iter().enumerate() {
                validate_rule_keys(rule, idx)?;
            }
        }
        Some(Item::Value(Value::Array(rules))) => {
            for (idx, rule) in rules.iter().enumerate() {
                if let Some(rule) = rule.as_inline_table() {
                    validate_rule_keys(rule, idx)?;
                }
            }
        }
        _ => {}
    }

    Ok(())
}

/// Checks the keys of the rule at index `idx`, its `match` table, and its
/// criteria.
fn validate_rule_keys(rule: &dyn TableLike, idx: usize) -> Result<(), PolicyError> {
    let loc = format!("rule[{idx}]");
    reject_unknown_keys(rule, RULE_KEYS, Some(&loc), "a rule")?;

    if let Some(rule_match) = rule.get("match").and_then(Item::as_table_like) {
        reject_unknown_keys(
            rule_match,
            MATCH_KEYS,
            Some(&format!("{loc}.match")),
            "match",
        )?;
    }

    if let Some(Item::Value(Value::Array(criteria))) = rule.get("criteria") {
        for (criterion_idx, criterion) in criteria.iter().enumerate() {
            let Some(criterion) = criterion.as_inline_table() else {
                continue;
            };
            let Some((kind, keys)) = criterion
                .get("kind")
                .and_then(Value::as_str)
                .and_then(|kind| criterion_keys(kind).map(|keys| (kind, keys)))
            else {
                continue;
            };
            reject_unknown_keys(
                criterion,
                keys,
                Some(&format!("{loc}.criteria[{criterion_idx}]")),
                &format!("a `{kind}` criterion"),
            )?;
        }
    }

    Ok(())
}

/// Refuses the first key of `table` that `accepted` does not list.
///
/// `location` prefixes the detail in the loader's form; `owner` names the
/// container in the list of accepted keys. The key is escaped so a control
/// character in a quoted key cannot break the diagnostic.
fn reject_unknown_keys(
    table: &dyn TableLike,
    accepted: &[&str],
    location: Option<&str>,
    owner: &str,
) -> Result<(), PolicyError> {
    let Some((key, _)) = table.iter().find(|(key, _)| !accepted.contains(key)) else {
        return Ok(());
    };
    let prefix = location.map(|loc| format!("{loc}: ")).unwrap_or_default();
    Err(PolicyError::PolicyFileParseFailed {
        detail: format!(
            "{prefix}unknown key `{}`; {owner} accepts {}",
            key.escape_debug(),
            accepted.join(", ")
        ),
    })
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use std::str::FromStr as _;

    use super::*;
    use crate::policy::v1::canonical::{OPTIONAL_RULE_KEYS, REQUIRED_RULE_KEYS};

    /// Every rule key the loader accepts is in the signed canonical form: the
    /// keys the canonical form requires, then its optional keys.
    #[test]
    fn every_accepted_rule_key_is_signed() {
        let signed: Vec<&str> = REQUIRED_RULE_KEYS
            .into_iter()
            .chain(OPTIONAL_RULE_KEYS)
            .collect();
        assert_eq!(RULE_KEYS, signed.as_slice());
    }

    /// A quoted key with a control character is escaped in the diagnostic.
    #[test]
    fn unknown_key_with_a_control_character_is_escaped() {
        let doc = DocumentMut::from_str("version = 1\nscope = \"profile:alice\"\n\"a\\nb\" = 1\n")
            .unwrap();
        let err = validate_policy_keys(&doc).unwrap_err();
        assert!(
            matches!(
                err,
                PolicyError::PolicyFileParseFailed { ref detail }
                    if detail.starts_with("unknown key `a\\nb`;") && !detail.contains('\n')
            ),
            "{err:?}"
        );
    }

    /// An unknown key inside `[owner_rotation]` is refused with its location,
    /// in either version.
    #[test]
    fn unknown_owner_rotation_key_is_refused() {
        for head in [
            "version = 1\nscope = \"profile:alice\"\n",
            "version = 2\nscope = \"profile:alice\"\nsequence = 1\n",
        ] {
            let doc = DocumentMut::from_str(&format!(
                "{head}[owner_rotation]\nprevious_owner = \"G\"\nnew_owner = \"G\"\n\
                 sig = \"00\"\nextra = 1\n"
            ))
            .unwrap();
            let err = validate_policy_keys(&doc).unwrap_err();
            assert!(
                matches!(
                    err,
                    PolicyError::PolicyFileParseFailed { ref detail }
                        if detail.starts_with("owner_rotation: unknown key `extra`;")
                ),
                "{head}: {err:?}"
            );
        }
    }

    /// A container of another shape is left to the loader's diagnostics: a
    /// non-table `match`, a non-array `criteria`, a non-table criterion, and
    /// criteria whose `kind` is absent, not a string, or unsupported.
    #[test]
    fn containers_of_other_shapes_are_left_to_the_loader() {
        let doc = DocumentMut::from_str(
            r#"version = 1
scope = "profile:alice"

[[rules]]
match = "stellar_pay"
criteria = 5
decision = "allow"

[[rules]]
match = { tool = "*", chain = "*" }
criteria = ["per_tx_cap", { foo = 1 }, { kind = 7, foo = 1 }, { kind = "made_up_thing", foo = 1 }]
decision = "allow"
"#,
        )
        .unwrap();
        validate_policy_keys(&doc).unwrap();
    }
}
