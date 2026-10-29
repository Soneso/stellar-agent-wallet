//! Canonical-form serializer for owner-signature computation.
//!
//! Produces a deterministic UTF-8 byte sequence from a policy TOML document
//! suitable as the pre-image for the owner signature:
//! `blake3(canonical_bytes(policy_toml))`.
//!
//! ## Canonical form rules
//!
//! 1. The `[signature]` table is **excluded** from the output.
//! 2. Included keys: `version` (top-level integer), `scope` (top-level string),
//!    `[[rules]]` array (in original declaration order). Version 2 also signs
//!    `sequence` and the optional mainnet binding before the rules. A present
//!    `owner_rotation` table is signed in either version.
//! 3. Field order within each rule is fixed: `match`, `criteria`, `decision`,
//!    then `reason`, `ttl_secs` and `allow_opaque_signing`. The last three are
//!    emitted only when the rule carries them, so the canonical bytes of a rule
//!    without them depend on `match`, `criteria` and `decision` alone. A
//!    present empty `reason` and a present `allow_opaque_signing = false` are
//!    emitted.
//! 4. Other rule keys are not emitted. Criterion tables are copied whole,
//!    unknown members included. The loader refuses every key outside the
//!    policy schema before it verifies the signature (see
//!    [`crate::policy::v1::schema::validate_policy_keys`]), so every key the
//!    loader reads, the `[signature]` table excepted, is in the signed bytes.
//! 5. All comments stripped.
//! 6. Whitespace normalised; no trailing whitespace; no BOM.
//!
//! ## Determinism guarantee
//!
//! `toml_edit::DocumentMut::to_string()` is deterministic for a given parsed
//! document: keys are emitted in stable parsed-position order. The wallet-side
//! normalisation pass below adds comment-stripping and whitespace normalisation
//! on top of that, so two documents with the same logical content but different
//! formatting always yield the same bytes.
//!
//! ## blake3 non-secret-input note
//!
//! The `canonical_bytes` output is the canonical form of the policy file — a
//! non-secret operator-readable document. BLAKE3's compression function is NOT
//! required to be constant-time for this input (the input is not secret).
//! **If a future change ever passes secret bytes into a `blake3` call, this
//! property must be re-evaluated and a constant-time digest path adopted.**

use std::str::FromStr;

use toml_edit::{Array, DocumentMut, InlineTable, Item, Table, Value};

use crate::policy::PolicyError;

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

/// Produces the canonical UTF-8 bytes of a policy TOML document.
///
/// The canonical form is the pre-image for the owner signature:
/// `blake3(canonical_bytes(policy_toml))`.
///
/// The `[signature]` table is excluded and a present `[owner_rotation]`
/// table is included. Version 1 signs `version`, `scope`, and `[[rules]]` in
/// declaration order. Version 2 also signs `sequence` and `[mainnet]`, and
/// sorts keys in match and criterion tables.  Each rule
/// carries `match`, `criteria` and `decision`, then whichever of `reason`,
/// `ttl_secs` and `allow_opaque_signing` it holds, in that order.  All
/// comments are stripped and whitespace is normalised.
///
/// # Errors
///
/// Returns [`PolicyError::PolicyFileParseFailed`] when `toml_text` is not valid
/// TOML or is missing the required `version` or `scope` keys.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::policy::v1::canonical::canonical_bytes;
///
/// let toml = r#"
/// version = 1
/// scope = "profile:default"
///
/// [signature]
/// owner_id = "GABCDE"
/// sig = "deadbeef"
/// "#;
///
/// let bytes = canonical_bytes(toml).unwrap();
/// let text = String::from_utf8(bytes).unwrap();
/// assert!(text.contains("version = 1"));
/// assert!(text.contains("scope = \"profile:default\""));
/// assert!(!text.contains("signature"));
/// assert!(!text.contains("owner_id"));
/// ```
pub fn canonical_bytes(toml_text: &str) -> Result<Vec<u8>, PolicyError> {
    let doc = DocumentMut::from_str(toml_text).map_err(|e| PolicyError::PolicyFileParseFailed {
        detail: e.to_string(),
    })?;

    let output = build_canonical_document(&doc)?;
    Ok(output.into_bytes())
}

/// Canonical bytes bound by the previous owner's rotation statement.
///
/// Both `[signature]` and `[owner_rotation]` are excluded. Every other
/// canonical field, including scope, sequence, and rules, remains signed.
///
/// # Errors
/// Returns the same parsing errors as [`canonical_bytes`].
pub fn owner_rotation_bytes(toml_text: &str) -> Result<Vec<u8>, PolicyError> {
    let mut doc =
        DocumentMut::from_str(toml_text).map_err(|e| PolicyError::PolicyFileParseFailed {
            detail: e.to_string(),
        })?;
    doc.remove("signature");
    doc.remove("owner_rotation");
    Ok(build_canonical_document(&doc)?.into_bytes())
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Rule keys every canonical rule carries, in emission order.
pub(crate) const REQUIRED_RULE_KEYS: [&str; 3] = ["match", "criteria", "decision"];

/// Optional rule keys the canonical form signs, in emission order after
/// [`REQUIRED_RULE_KEYS`].
///
/// Each is emitted only when the rule carries it, with no default inserted, so
/// the canonical bytes of a rule without them do not depend on this list.
pub(crate) const OPTIONAL_RULE_KEYS: [&str; 3] = ["reason", "ttl_secs", "allow_opaque_signing"];

/// Builds the canonical TOML string from the parsed document.
///
/// Constructs a new `DocumentMut` containing only the canonicalised fields in
/// their fixed order, then emits via `to_string()`.
fn build_canonical_document(doc: &DocumentMut) -> Result<String, PolicyError> {
    let mut out = DocumentMut::new();

    // ── version ──────────────────────────────────────────────────────────────
    let version_item = doc
        .get("version")
        .ok_or_else(|| PolicyError::PolicyFileParseFailed {
            detail: "policy file missing required key `version`".into(),
        })?;
    let version_val = canonical_scalar(version_item)?;
    out.insert("version", Item::Value(version_val));

    // ── scope ─────────────────────────────────────────────────────────────────
    let scope_item = doc
        .get("scope")
        .ok_or_else(|| PolicyError::PolicyFileParseFailed {
            detail: "policy file missing required key `scope`".into(),
        })?;
    let scope_val = canonical_scalar(scope_item)?;
    out.insert("scope", Item::Value(scope_val));

    let v2 = version_item.as_integer() == Some(2);
    if v2 {
        let sequence = doc
            .get("sequence")
            .ok_or_else(|| PolicyError::PolicyFileParseFailed {
                detail: "policy v2 requires `sequence`".into(),
            })?;
        out.insert("sequence", Item::Value(canonical_scalar(sequence)?));
        if let Some(mainnet) = doc.get("mainnet") {
            // The canonical form requires `mainnet` to be a table.
            let mainnet =
                mainnet
                    .as_table_like()
                    .ok_or_else(|| PolicyError::PolicyFileParseFailed {
                        detail: "mainnet must be a table".into(),
                    })?;
            let mut table = Table::new();
            for key in super::schema::MAINNET_KEYS {
                if let Some(item) = mainnet.get(key) {
                    if *key == "cross_check_thresholds" {
                        let values = item.as_table_like().ok_or_else(|| {
                            PolicyError::PolicyFileParseFailed {
                                detail: "mainnet.cross_check_thresholds must be a table".into(),
                            }
                        })?;
                        let mut thresholds = Table::new();
                        let mut entries: Vec<_> = values.iter().collect();
                        entries.sort_by_key(|(key, _)| *key);
                        for (key, value) in entries {
                            thresholds.insert(key, Item::Value(canonical_scalar(value)?));
                        }
                        table.insert(key, Item::Table(thresholds));
                    } else {
                        table.insert(key, Item::Value(canonical_scalar(item)?));
                    }
                }
            }
            out.insert("mainnet", Item::Table(table));
        }
    }

    if let Some(rotation) = doc.get("owner_rotation") {
        let rotation =
            rotation
                .as_table_like()
                .ok_or_else(|| PolicyError::PolicyFileParseFailed {
                    detail: "`owner_rotation` must be a table".into(),
                })?;
        let mut table = Table::new();
        for key in super::schema::OWNER_ROTATION_KEYS {
            if let Some(item) = rotation.get(key) {
                table.insert(key, Item::Value(canonical_scalar(item)?));
            }
        }
        out.insert("owner_rotation", Item::Table(table));
    }

    // ── [[rules]] ─────────────────────────────────────────────────────────────
    // Walk the document's array-of-tables and reconstruct without decor.
    if let Some(rules_item) = doc.get("rules") {
        match rules_item {
            Item::ArrayOfTables(aot) => {
                use toml_edit::ArrayOfTables;
                let mut canonical_aot = ArrayOfTables::new();
                for table in aot.iter() {
                    canonical_aot.push(canonical_rule_table(table, v2)?);
                }
                out.insert("rules", Item::ArrayOfTables(canonical_aot));
            }
            // `rules` may also appear as an inline array in edge cases.
            // Canonical form collapses it to the same `[[rules]]` shape as
            // array-of-tables so semantically identical policies sign the same
            // byte pre-image.
            Item::Value(Value::Array(arr)) => {
                use toml_edit::ArrayOfTables;
                let mut canonical_aot = ArrayOfTables::new();
                for val in arr.iter() {
                    let inline = val.as_inline_table().ok_or_else(|| {
                        PolicyError::PolicyFileParseFailed {
                            detail: "rules array element is not a table".into(),
                        }
                    })?;
                    canonical_aot.push(canonical_table_from_inline_rule(inline, v2)?);
                }
                out.insert("rules", Item::ArrayOfTables(canonical_aot));
            }
            _ => {
                // `rules` is present but is neither an array-of-tables nor an
                // inline array of tables. Fail closed rather than silently
                // signing a policy with zero rules.
                return Err(PolicyError::PolicyFileParseFailed {
                    detail: "`rules` must be an array of tables".into(),
                });
            }
        }
    }

    // toml_edit::DocumentMut::to_string() is deterministic for a given
    // document structure (keys emitted in stable parsed-position order).
    // Normalise the emitted text: strip any residual leading/trailing blank
    // lines and trailing whitespace from each line.
    let raw = out.to_string();
    Ok(normalise_whitespace(&raw))
}

/// Returns a canonical (decor-stripped) copy of a scalar [`Item`].
///
/// Only `Item::Value` scalars (integers, strings, booleans, floats) are
/// accepted; tables and arrays produce `PolicyFileParseFailed`.
fn canonical_scalar(item: &Item) -> Result<Value, PolicyError> {
    match item {
        Item::Value(v) => Ok(strip_value_decor(v)),
        _ => Err(PolicyError::PolicyFileParseFailed {
            detail: "expected a scalar value (integer, string, boolean)".into(),
        }),
    }
}

/// Strips all decorations (comments, leading/trailing whitespace) from a
/// [`Value`] recursively.
fn strip_value_decor(val: &Value) -> Value {
    match val {
        Value::String(s) => {
            let mut out = toml_edit::Formatted::new(s.value().to_owned());
            // Ensure the TOML emitter uses basic double-quoted form.
            out.decor_mut().clear();
            Value::String(out)
        }
        Value::Integer(i) => {
            // Normalise integer representations: parse the underlying i64 and
            // re-emit as a plain decimal string.  This handles alternative
            // representations like `1000_0000000` vs `10_000_000_000` —
            // both produce the same canonical decimal representation.
            let mut out = toml_edit::Formatted::new(*i.value());
            out.decor_mut().clear();
            Value::Integer(out)
        }
        Value::Float(f) => {
            let mut out = toml_edit::Formatted::new(*f.value());
            out.decor_mut().clear();
            Value::Float(out)
        }
        Value::Boolean(b) => {
            let mut out = toml_edit::Formatted::new(*b.value());
            out.decor_mut().clear();
            Value::Boolean(out)
        }
        Value::Datetime(dt) => {
            let mut out = toml_edit::Formatted::new(*dt.value());
            out.decor_mut().clear();
            Value::Datetime(out)
        }
        Value::Array(arr) => {
            let mut out = Array::new();
            for v in arr.iter() {
                out.push(strip_value_decor(v));
            }
            // Strip trailing comma and internal decor so the array emits compactly.
            out.set_trailing_comma(false);
            out.set_trailing("");
            Value::Array(out)
        }
        Value::InlineTable(t) => {
            let mut out = InlineTable::new();
            for (k, v) in t.iter() {
                out.insert(k, strip_value_decor(v));
            }
            out.decor_mut().clear();
            Value::InlineTable(out)
        }
    }
}

/// Builds a canonical [`Table`] for a `[[rules]]` entry.
///
/// Field order is fixed: `match`, `criteria`, `decision` (each required),
/// then `reason`, `ttl_secs` and `allow_opaque_signing`, each emitted only
/// when the rule carries it. Values are emitted without decoration; an
/// integer is re-emitted as plain decimal. Other rule keys are not emitted.
fn canonical_rule_table(src: &Table, sorted: bool) -> Result<Table, PolicyError> {
    let mut out = Table::new();

    for key in REQUIRED_RULE_KEYS {
        let item = src
            .get(key)
            .ok_or_else(|| PolicyError::PolicyFileParseFailed {
                detail: format!("rule missing required `{key}` key"),
            })?;
        out.insert(
            key,
            Item::Value(sort_value(canonical_item_as_value(item)?, sorted)),
        );
    }

    for key in OPTIONAL_RULE_KEYS {
        if let Some(item) = src.get(key) {
            out.insert(
                key,
                Item::Value(sort_value(canonical_item_as_value(item)?, sorted)),
            );
        }
    }

    // Remove all table-level decor (comments, extra whitespace).
    out.decor_mut().clear();
    Ok(out)
}

/// Builds a canonical [`InlineTable`] for a rule expressed as an inline table.
///
/// Copies the required and optional rule keys the rule carries, in canonical
/// order; other keys are not copied.
fn canonical_inline_rule(src: &InlineTable) -> Result<InlineTable, PolicyError> {
    let mut out = InlineTable::new();

    for key in REQUIRED_RULE_KEYS.into_iter().chain(OPTIONAL_RULE_KEYS) {
        if let Some(v) = src.get(key) {
            out.insert(key, strip_value_decor(v));
        }
    }

    out.decor_mut().clear();
    Ok(out)
}

/// Builds a canonical [`Table`] for an inline-array rule.
///
/// The same field order as [`canonical_rule_table`]: a missing required key
/// fails, a missing optional key emits nothing.
fn canonical_table_from_inline_rule(src: &InlineTable, sorted: bool) -> Result<Table, PolicyError> {
    let inline = canonical_inline_rule(src)?;
    let mut out = Table::new();
    for key in REQUIRED_RULE_KEYS {
        if let Some(v) = inline.get(key) {
            out.insert(key, Item::Value(sort_value(strip_value_decor(v), sorted)));
        } else {
            return Err(PolicyError::PolicyFileParseFailed {
                detail: format!("rule missing required `{key}` key"),
            });
        }
    }
    for key in OPTIONAL_RULE_KEYS {
        if let Some(v) = inline.get(key) {
            out.insert(key, Item::Value(sort_value(strip_value_decor(v), sorted)));
        }
    }
    out.decor_mut().clear();
    Ok(out)
}

/// Sorts nested tables in the v2 signature preimage.
fn sort_value(value: Value, sorted: bool) -> Value {
    if !sorted {
        return value;
    }
    match value {
        Value::InlineTable(table) => {
            let mut entries: Vec<_> = table.iter().collect();
            entries.sort_by_key(|(key, _)| *key);
            let mut out = InlineTable::new();
            for (key, value) in entries {
                out.insert(key, sort_value(value.clone(), true));
            }
            Value::InlineTable(out)
        }
        Value::Array(array) => {
            let mut out = Array::new();
            for value in &array {
                out.push(sort_value(value.clone(), true));
            }
            Value::Array(out)
        }
        other => other,
    }
}

/// Extracts a canonical [`Value`] from an [`Item`], converting inline tables
/// and arrays as needed.
fn canonical_item_as_value(item: &Item) -> Result<Value, PolicyError> {
    match item {
        Item::Value(v) => Ok(strip_value_decor(v)),
        Item::Table(t) => {
            // Convert a standard table sub-key to an inline table.
            let mut out = InlineTable::new();
            for (k, v) in t.iter() {
                let cv = canonical_item_as_value(v)?;
                out.insert(k, cv);
            }
            out.decor_mut().clear();
            Ok(Value::InlineTable(out))
        }
        Item::ArrayOfTables(_) => Err(PolicyError::PolicyFileParseFailed {
            detail: "unexpected array-of-tables within rule field".into(),
        }),
        Item::None => Err(PolicyError::PolicyFileParseFailed {
            detail: "unexpected None item in rule field".into(),
        }),
    }
}

/// Normalises whitespace in the emitted TOML string.
///
/// Strips trailing whitespace from each line, removes the leading blank line
/// that `toml_edit` may emit before the first key, and ensures the output ends
/// with exactly one newline.
///
/// CARGO-MUTANTS: the `==` in the leading-blank-strip predicate below has a
/// known timeout mutant (`==` -> `!=`) because it produces a non-terminating
/// loop over a non-blank first line. The timeout is the expected signal for
/// this non-terminating mutation; no behavioural assertion can observe a
/// return value from that mutant.
fn normalise_whitespace(s: &str) -> String {
    let lines: Vec<&str> = s.lines().collect();
    let mut result: Vec<&str> = Vec::with_capacity(lines.len());

    for line in &lines {
        // Trim trailing whitespace; leading whitespace is intentional (TOML
        // array-of-tables entries use 2-space indentation).
        result.push(line.trim_end());
    }

    // Remove leading blank lines.
    while result.first() == Some(&"") {
        result.remove(0);
    }

    // Remove trailing blank lines.
    while result.last() == Some(&"") {
        result.pop();
    }

    let mut out = result.join("\n");
    // Ensure exactly one trailing newline.
    out.push('\n');
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only"
    )]

    use proptest::prelude::*;

    use super::*;

    #[test]
    fn canonical_bytes_rejects_non_array_rules() {
        // `rules` present but neither an array-of-tables nor an inline array of
        // tables must fail closed, never sign as a zero-rule policy.
        let toml = "version = 1\nscope = \"profile:default\"\nrules = 5\n";
        let err = canonical_bytes(toml).unwrap_err();
        assert!(
            matches!(err, PolicyError::PolicyFileParseFailed { .. }),
            "non-array `rules` must be rejected, got {err:?}"
        );
    }

    /// A version 2 `mainnet` value that is not a table is refused, never left
    /// out of the signed bytes.
    #[test]
    fn canonical_bytes_rejects_non_table_mainnet() {
        let toml = "version = 2\nscope = \"profile:default\"\nsequence = 1\nmainnet = 5\n";
        let err = canonical_bytes(toml).unwrap_err();
        assert!(
            matches!(
                &err,
                PolicyError::PolicyFileParseFailed { detail } if detail == "mainnet must be a table"
            ),
            "a non-table mainnet value must be refused, got {err:?}"
        );
    }

    /// An `owner_rotation` value that is not a table is refused in either
    /// version, never left out of the signed bytes.
    #[test]
    fn canonical_bytes_rejects_non_table_owner_rotation() {
        for toml in [
            "version = 1\nscope = \"profile:default\"\nowner_rotation = 5\n",
            "version = 2\nscope = \"profile:default\"\nsequence = 1\nowner_rotation = \"G\"\n",
        ] {
            let err = canonical_bytes(toml).unwrap_err();
            assert!(
                matches!(
                    &err,
                    PolicyError::PolicyFileParseFailed { detail }
                        if detail == "`owner_rotation` must be a table"
                ),
                "a non-table owner_rotation value must be refused, got {err:?}"
            );
        }
    }

    // ── canonical_bytes_strips_signature_table ────────────────────────────────

    #[test]
    fn canonical_bytes_strips_signature_table() {
        let toml = r#"
version = 1
scope = "profile:default"

[signature]
owner_id = "GABCDE"
sig = "deadbeef"
"#;
        let bytes = canonical_bytes(toml).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(
            !text.contains("signature"),
            "signature table must be excluded"
        );
        assert!(!text.contains("owner_id"), "owner_id must be excluded");
        assert!(!text.contains("deadbeef"), "sig must be excluded");
    }

    // ── canonical_bytes_preserves_rule_order ──────────────────────────────────

    #[test]
    fn canonical_bytes_preserves_rule_order() {
        let toml = r#"
version = 1
scope = "profile:default"

[[rules]]
match = { tool = "stellar_pay", chain = "*" }
criteria = []
decision = "allow"

[[rules]]
match = { tool = "stellar_create_account", chain = "*" }
criteria = []
decision = "deny"

[signature]
owner_id = "G"
sig = "x"
"#;
        let bytes = canonical_bytes(toml).unwrap();
        let text = String::from_utf8(bytes).unwrap();

        // First rule must appear before second.
        let pos_pay = text
            .find("stellar_pay")
            .expect("stellar_pay must appear in canonical output");
        let pos_create = text
            .find("stellar_create_account")
            .expect("stellar_create_account must appear in canonical output");
        assert!(
            pos_pay < pos_create,
            "stellar_pay rule must precede stellar_create_account rule"
        );
    }

    // ── canonical_bytes_strips_comments ───────────────────────────────────────

    #[test]
    fn canonical_bytes_strips_comments() {
        let toml = r#"
# This is a top-level comment
version = 1 # inline comment
scope = "profile:default" # another comment

# Rule comment
[[rules]]
# match comment
match = { tool = "stellar_pay", chain = "*" }
criteria = []
decision = "allow"

[signature]
owner_id = "G"
sig = "x"
"#;
        let bytes = canonical_bytes(toml).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(
            !text.contains('#'),
            "canonical output must not contain comments"
        );
    }

    // ── canonical_bytes_normalises_whitespace ─────────────────────────────────

    #[test]
    fn canonical_bytes_normalises_whitespace() {
        let toml = "version = 1\nscope = \"profile:default\"\n\n[signature]\nowner_id = \"G\"\nsig = \"x\"\n";
        let bytes = canonical_bytes(toml).unwrap();
        let text = String::from_utf8(bytes).unwrap();

        // No trailing whitespace on any line.
        for line in text.lines() {
            assert_eq!(
                line,
                line.trim_end(),
                "canonical output must not have trailing whitespace on any line"
            );
        }

        // Output ends with exactly one newline.
        assert!(
            text.ends_with('\n'),
            "canonical output must end with a newline"
        );
        assert!(
            !text.ends_with("\n\n"),
            "canonical output must not end with double newline"
        );
    }

    // ── canonical_bytes_no_bom ────────────────────────────────────────────────

    #[test]
    fn canonical_bytes_no_bom() {
        let toml = "version = 1\nscope = \"profile:default\"\n";
        let bytes = canonical_bytes(toml).unwrap();
        // UTF-8 BOM is EF BB BF.
        assert!(
            !bytes.starts_with(&[0xEF, 0xBB, 0xBF]),
            "canonical output must not start with a UTF-8 BOM"
        );
    }

    // ── canonical_bytes_idempotent ────────────────────────────────────────────

    #[test]
    fn canonical_bytes_idempotent() {
        let toml = r#"
version = 1
scope = "profile:default"

[[rules]]
match = { tool = "stellar_pay", chain = "stellar:mainnet" }
criteria = []
decision = "allow"

[signature]
owner_id = "GABCDE"
sig = "sig"
"#;
        let first = canonical_bytes(toml).unwrap();
        let first_str = String::from_utf8(first.clone()).unwrap();
        let second = canonical_bytes(&first_str).unwrap();
        assert_eq!(
            first, second,
            "canonical_bytes must be idempotent: applying it twice must yield the same result"
        );
    }

    // ── canonical_bytes_zero_rules_accepted ───────────────────────────────────

    #[test]
    fn canonical_bytes_zero_rules_accepted() {
        let toml = r#"
version = 1
scope = "profile:default"
"#;
        let bytes = canonical_bytes(toml).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("version = 1"));
        assert!(text.contains("profile:default"));
        assert!(!text.contains("rules"));
    }

    #[test]
    fn canonical_bytes_canonicalises_inline_rules_array() {
        let toml = r#"
version = 1
scope = "profile:default"
rules = [
  { match = { tool = "stellar_pay", chain = "*" }, criteria = [{ kind = "per_tx_cap", asset = "native", max_stroops = 100 }], decision = "allow" },
]
"#;
        let bytes = canonical_bytes(toml).unwrap();
        let text = String::from_utf8(bytes).unwrap();

        assert!(
            text.contains("[[rules]]"),
            "inline rules array must canonicalise to array-of-tables output: {text}"
        );
        assert!(
            text.contains("stellar_pay") && text.contains("per_tx_cap"),
            "inline rule content must be preserved in canonical output: {text}"
        );
    }

    #[test]
    fn canonical_inline_rule_preserves_rule_keys() {
        let doc = DocumentMut::from_str(
            r#"
rule = { match = { tool = "stellar_pay", chain = "*" }, criteria = [{ kind = "per_tx_cap", asset = "native", max_stroops = 100 }], decision = "allow" }
"#,
        )
        .unwrap();
        let inline = doc
            .get("rule")
            .and_then(Item::as_value)
            .and_then(Value::as_inline_table)
            .unwrap();

        let canonical = canonical_inline_rule(inline).unwrap();

        let keys: Vec<&str> = canonical.iter().map(|(k, _)| k).collect();
        assert_eq!(
            keys,
            vec!["match", "criteria", "decision"],
            "canonical inline rule must retain match, criteria, decision in that order"
        );
    }

    #[test]
    fn canonical_inline_rule_strips_unknown_keys() {
        let doc = DocumentMut::from_str(
            r#"
rule = { match = { tool = "stellar_pay", chain = "*" }, criteria = [{ kind = "per_tx_cap", asset = "native", max_stroops = 100 }], decision = "allow", decision_override = "deny" }
"#,
        )
        .unwrap();
        let inline = doc
            .get("rule")
            .and_then(Item::as_value)
            .and_then(Value::as_inline_table)
            .unwrap();

        let canonical = canonical_inline_rule(inline).unwrap();

        assert!(
            !canonical.contains_key("decision_override"),
            "canonical inline rule must strip unknown rule keys"
        );
    }

    // ── canonical_bytes_missing_version_fails ─────────────────────────────────

    #[test]
    fn canonical_bytes_missing_version_fails() {
        let toml = "scope = \"profile:default\"\n";
        let err = canonical_bytes(toml).unwrap_err();
        assert!(
            matches!(err, PolicyError::PolicyFileParseFailed { .. }),
            "missing version must produce PolicyFileParseFailed"
        );
    }

    // ── canonical_bytes_missing_scope_fails ───────────────────────────────────

    #[test]
    fn canonical_bytes_missing_scope_fails() {
        let toml = "version = 1\n";
        let err = canonical_bytes(toml).unwrap_err();
        assert!(
            matches!(err, PolicyError::PolicyFileParseFailed { .. }),
            "missing scope must produce PolicyFileParseFailed"
        );
    }

    // ── canonical_bytes_invalid_toml_fails ────────────────────────────────────

    #[test]
    fn canonical_bytes_invalid_toml_fails() {
        let toml = "this is not valid toml [[[";
        let err = canonical_bytes(toml).unwrap_err();
        assert!(
            matches!(err, PolicyError::PolicyFileParseFailed { .. }),
            "invalid TOML must produce PolicyFileParseFailed"
        );
    }

    // ── proptest: formatting-invariance ───────────────────────────────────────
    //
    // The same logical policy emitted with different formatting must produce
    // identical canonical bytes.

    // ── canonical_scalar rejects non-scalar version/scope ─────────────────────

    /// When the TOML `version` key is a standard table section rather than an
    /// integer scalar, `canonical_scalar` must reject it with `PolicyFileParseFailed`.
    /// `[version]` parses as `Item::Table`, which does not match the `Item::Value`
    /// arm in `canonical_scalar`.
    #[test]
    fn canonical_bytes_version_as_table_section_fails() {
        // `[version]` makes `version` a table (Item::Table), not a scalar.
        let toml = "[version]\nmajor = 1\n\n[scope]\nname = \"profile:default\"\n";
        let err = canonical_bytes(toml).unwrap_err();
        assert!(
            matches!(err, PolicyError::PolicyFileParseFailed { .. }),
            "version as table section must produce PolicyFileParseFailed"
        );
    }

    /// An inline table `version = {{ x = 1 }}` is `Item::Value(Value::InlineTable)`.
    /// `canonical_scalar` accepts `Item::Value(...)` but `strip_value_decor` on an
    /// `InlineTable` produces `Value::InlineTable` which is serialised back out.
    /// The canonical form does not reject inline-table scalars; the test verifies
    /// it does not panic.
    #[test]
    fn canonical_bytes_version_as_inline_table_does_not_panic() {
        let toml = "version = { x = 1 }\nscope = \"profile:default\"\n";
        // An inline-table `version` is semantically invalid but the serialiser
        // does not perform semantic validation — it strips decor only.
        // Must not panic; success or parse failure are both acceptable.
        let result = canonical_bytes(toml);
        match result {
            Ok(_) | Err(PolicyError::PolicyFileParseFailed { .. }) => {}
            Err(other) => panic!("unexpected error: {other:?}"),
        }
    }

    // ── strip_value_decor handles Float and Boolean value types ───────────────

    /// A TOML document containing a boolean `scope` value should be normalised
    /// without error — the `strip_value_decor` Boolean arm must be reachable.
    /// We use a float version to reach the Float arm.
    #[test]
    fn canonical_bytes_float_version_normalised() {
        // TOML float; the float arm of strip_value_decor must handle it without panic.
        let toml = "version = 1.5\nscope = \"profile:default\"\n";
        let result = canonical_bytes(toml);
        // A float version is semantically wrong but the canonical serialiser
        // does not validate version semantics — it just strips decor.
        // The only requirement is that it does NOT panic.
        match result {
            Ok(bytes) => {
                let text = String::from_utf8(bytes).unwrap();
                assert!(text.contains("1.5"), "float value must survive round-trip");
            }
            Err(PolicyError::PolicyFileParseFailed { .. }) => {
                // Also acceptable if a future validation step rejects float version.
            }
            Err(other) => panic!("unexpected error variant: {other:?}"),
        }
    }

    /// A policy file whose rules contain a boolean decision field exercises the
    /// Boolean arm of `strip_value_decor`.  A non-string `decision` is semantically
    /// wrong but the canonical serialiser only strips decor, not validates semantics.
    #[test]
    fn canonical_bytes_boolean_in_rule_field_does_not_panic() {
        // Boolean decision in a rule: exercices strip_value_decor Boolean arm.
        let toml = "version = 1\nscope = \"profile:default\"\n\n[[rules]]\nmatch = { tool = \"stellar_pay\", chain = \"*\" }\ncriteria = []\ndecision = true\n";
        let result = canonical_bytes(toml);
        // Must not panic; whether it succeeds or produces a parse error is acceptable.
        match result {
            Ok(bytes) => {
                let text = String::from_utf8(bytes).unwrap();
                // The boolean must be preserved verbatim in the canonical output.
                assert!(
                    text.contains("true"),
                    "boolean decision must appear in output: {text}"
                );
            }
            Err(PolicyError::PolicyFileParseFailed { .. }) => {}
            Err(other) => panic!("unexpected error: {other:?}"),
        }
    }

    // ── rules array element that is not a table ────────────────────────────────

    /// An inline `rules = [...]` array whose elements are strings (not tables)
    /// must fail with `PolicyFileParseFailed`.
    #[test]
    fn canonical_bytes_rules_inline_array_non_table_element_fails() {
        let toml = "version = 1\nscope = \"profile:default\"\nrules = [\"not-a-table\"]\n";
        let err = canonical_bytes(toml).unwrap_err();
        assert!(
            matches!(err, PolicyError::PolicyFileParseFailed { .. }),
            "non-table element in inline rules array must produce PolicyFileParseFailed"
        );
    }

    // ── canonical_rule_table: missing match key ───────────────────────────────

    /// A `[[rules]]` entry that is missing the `match` key must cause
    /// `PolicyFileParseFailed`.
    #[test]
    fn canonical_bytes_rule_missing_match_key_fails() {
        let toml = "version = 1\nscope = \"profile:default\"\n\n[[rules]]\ncriteria = []\ndecision = \"allow\"\n";
        let err = canonical_bytes(toml).unwrap_err();
        assert!(
            matches!(err, PolicyError::PolicyFileParseFailed { .. }),
            "rule with no `match` key must produce PolicyFileParseFailed"
        );
    }

    /// A `[[rules]]` entry that is missing the `criteria` key must cause
    /// `PolicyFileParseFailed`.
    #[test]
    fn canonical_bytes_rule_missing_criteria_key_fails() {
        let toml = "version = 1\nscope = \"profile:default\"\n\n[[rules]]\nmatch = { tool = \"stellar_pay\", chain = \"*\" }\ndecision = \"allow\"\n";
        let err = canonical_bytes(toml).unwrap_err();
        assert!(
            matches!(err, PolicyError::PolicyFileParseFailed { .. }),
            "rule with no `criteria` key must produce PolicyFileParseFailed"
        );
    }

    /// A `[[rules]]` entry that is missing the `decision` key must cause
    /// `PolicyFileParseFailed`.
    #[test]
    fn canonical_bytes_rule_missing_decision_key_fails() {
        let toml = "version = 1\nscope = \"profile:default\"\n\n[[rules]]\nmatch = { tool = \"stellar_pay\", chain = \"*\" }\ncriteria = []\n";
        let err = canonical_bytes(toml).unwrap_err();
        assert!(
            matches!(err, PolicyError::PolicyFileParseFailed { .. }),
            "rule with no `decision` key must produce PolicyFileParseFailed"
        );
    }

    // ── normalise_whitespace: multiple leading/trailing blank lines ────────────

    #[test]
    fn normalise_whitespace_strips_multiple_leading_blank_lines() {
        let input = "\n\n\nversion = 1\nscope = \"x\"\n";
        let result = normalise_whitespace(input);
        assert!(
            !result.starts_with('\n'),
            "normalised output must not start with a blank line"
        );
        assert!(
            result.starts_with("version"),
            "normalised output must start with version key: {result:?}"
        );
    }

    #[test]
    fn normalise_whitespace_strips_multiple_trailing_blank_lines() {
        let input = "version = 1\nscope = \"x\"\n\n\n\n";
        let result = normalise_whitespace(input);
        assert!(
            result.ends_with('\n'),
            "normalised output must end with exactly one newline"
        );
        assert!(
            !result.ends_with("\n\n"),
            "normalised output must not end with double newline: {result:?}"
        );
    }

    #[test]
    fn normalise_whitespace_strips_trailing_spaces_per_line() {
        let input = "version = 1   \nscope = \"x\"   \n";
        let result = normalise_whitespace(input);
        for line in result.lines() {
            assert_eq!(
                line,
                line.trim_end(),
                "every line must have trailing whitespace stripped: {line:?}"
            );
        }
    }

    // ── canonical_item_as_value: Item::Table path ─────────────────────────────

    /// A rule where `match` is a standard TOML table (not an inline table)
    /// exercises the `Item::Table` branch in `canonical_item_as_value`.
    /// The canonical form must convert it to an inline table transparently.
    #[test]
    fn canonical_bytes_rule_with_standard_table_match_converts_to_inline() {
        // Use `[rules.match]` style (standard sub-table) rather than inline.
        // Note: TOML does not allow `[rules.match]` under `[[rules]]`; instead,
        // the sub-table approach would use `[rules.0.match]` which is not valid.
        // The `Item::Table` path is reached when the item was a dotted-key table
        // that toml_edit represents as Table rather than InlineTable.
        // We use the dotted-key sub-table form to exercise this path.
        let toml = "version = 1\nscope = \"profile:default\"\n\n[[rules]]\nmatch.tool = \"stellar_pay\"\nmatch.chain = \"*\"\ncriteria = []\ndecision = \"allow\"\n";
        let result = canonical_bytes(toml);
        // Must succeed and produce output containing the rule fields.
        match result {
            Ok(bytes) => {
                let text = String::from_utf8(bytes).unwrap();
                assert!(
                    text.contains("stellar_pay"),
                    "dotted-key match sub-table must be preserved in canonical output: {text}"
                );
                assert!(text.contains("allow"), "decision must be preserved: {text}");
            }
            Err(PolicyError::PolicyFileParseFailed { .. }) => {
                // If toml_edit represents dotted keys differently and rejects them,
                // that is also acceptable — the parse error path is exercised.
            }
            Err(other) => panic!("unexpected error: {other:?}"),
        }
    }

    // ── canonical_table_from_inline_rule: missing required key ────────────────

    /// An inline-array rule element that lacks the `match` key must produce
    /// `PolicyFileParseFailed`.  This exercises the error branch in
    /// `canonical_table_from_inline_rule`.
    #[test]
    fn canonical_bytes_inline_rule_missing_match_fails() {
        let toml = "version = 1\nscope = \"profile:default\"\nrules = [{ criteria = [], decision = \"allow\" }]\n";
        let err = canonical_bytes(toml).unwrap_err();
        assert!(
            matches!(err, PolicyError::PolicyFileParseFailed { .. }),
            "inline rule missing `match` must produce PolicyFileParseFailed"
        );
    }

    // ── canonical_bytes: two rules with identical content produce stable bytes ─

    #[test]
    fn canonical_bytes_two_rules_stable_output() {
        let toml = r#"
version = 1
scope = "profile:default"

[[rules]]
match = { tool = "stellar_pay", chain = "*" }
criteria = []
decision = "allow"

[[rules]]
match = { tool = "stellar_pay", chain = "*" }
criteria = []
decision = "deny"
"#;
        // Call twice; output must be identical (determinism).
        let b1 = canonical_bytes(toml).unwrap();
        let b2 = canonical_bytes(toml).unwrap();
        assert_eq!(
            b1, b2,
            "canonical_bytes must be deterministic for the same input"
        );

        // The two rules must appear in order (first allow, then deny).
        let text = String::from_utf8(b1).unwrap();
        let pos_allow = text.find("\"allow\"").expect("allow must appear");
        let pos_deny = text.find("\"deny\"").expect("deny must appear");
        assert!(
            pos_allow < pos_deny,
            "allow rule must precede deny rule in canonical output"
        );
    }

    // ── canonical_bytes: signature-only document (no rules) ───────────────────

    #[test]
    fn canonical_bytes_signature_only_document_preserves_version_and_scope() {
        let toml = "version = 42\nscope = \"profile:production\"\n\n[signature]\nowner_id = \"GABCDE\"\nsig = \"cafebabe\"\n";
        let bytes = canonical_bytes(toml).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("42"), "version must be preserved: {text}");
        assert!(
            text.contains("production"),
            "scope must be preserved: {text}"
        );
        assert!(
            !text.contains("cafebabe"),
            "signature must be excluded: {text}"
        );
    }

    // ── golden canonical bytes for rules without optional keys ────────────────

    /// Array-of-tables golden fixture: three rules, a dotted-key `match`, a
    /// standard sub-table `match`, a rule whose keys are out of canonical
    /// order, criteria with nested arrays and underscore integers, and comments.
    const GOLDEN_ARRAY_OF_TABLES_FIXTURE: &str = r#"# Owner policy for alice.
version = 1 # schema version
scope = "profile:alice"

[[rules]]
# Dotted-key match.
match.tool = "stellar_pay"
match.chain = "stellar:testnet"
criteria = [
  # Per-transaction cap of 100 XLM.
  { kind = "per_tx_cap", asset = "native", max_stroops = 1_000_000_000 },
  { kind = "counterparty_allowlist", kinds = [ "G_ACCOUNT", "C_ACCOUNT" ], allowlist = ["GAAAA", "CBBBB"], gate_inflows = false },
]
decision = "allow"

[[rules]]
decision = "require_approval"
criteria = [{ kind = "rate_limit", window = "1h", max_calls = 1_0 }]   # hourly
match = { tool = "*", chain = "*" }

[[rules]]
criteria = []
decision = "deny"

[rules.match]
tool = "stellar_create_account"
chain = "*"

[signature]
owner_id = "GOWNER"
sig = "00"
"#;

    /// Inline `rules = [...]` golden fixture: two rules, one with its keys
    /// out of canonical order, an underscore integer, and comments inside the
    /// array.
    const GOLDEN_INLINE_RULES_FIXTURE: &str = r#"# Inline rules.
version = 1
scope = "profile:*"
rules = [
  # Daily cap.
  { match = { tool = "stellar_pay", chain = "*" }, criteria = [{ kind = "per_period_cap", asset = "native", window = "1d", max_stroops = 50_000_000 }], decision = "allow" },
  { decision = "require_approval", criteria = [], match = { chain = "*", tool = "*" } }, # catch-all
]
"#;

    /// The canonical bytes of a policy whose rules carry none of `reason`,
    /// `ttl_secs` and `allow_opaque_signing` are the signature pre-image of
    /// every such policy already signed. A canonicalizer change must not alter
    /// these bytes, or those signatures stop verifying. The expected literal is
    /// the oracle; it is never regenerated through the canonicalizer.
    #[test]
    fn golden_canonical_bytes_of_array_of_tables_rules_without_optional_keys() {
        const EXPECTED: &str = r#"version = 1
scope = "profile:alice"

[[rules]]
match = { tool = "stellar_pay", chain = "stellar:testnet" }
criteria = [{ kind = "per_tx_cap", asset = "native", max_stroops = 1000000000 }, { kind = "counterparty_allowlist", kinds = ["G_ACCOUNT", "C_ACCOUNT"], allowlist = ["GAAAA", "CBBBB"], gate_inflows = false }]
decision = "allow"

[[rules]]
match = { tool = "*", chain = "*" }
criteria = [{ kind = "rate_limit", window = "1h", max_calls = 10 }]
decision = "require_approval"

[[rules]]
match = { tool = "stellar_create_account", chain = "*" }
criteria = []
decision = "deny"
"#;
        let bytes = canonical_bytes(GOLDEN_ARRAY_OF_TABLES_FIXTURE).unwrap();
        assert_eq!(String::from_utf8(bytes).unwrap(), EXPECTED);
    }

    /// The inline `rules = [...]` counterpart of
    /// [`golden_canonical_bytes_of_array_of_tables_rules_without_optional_keys`]:
    /// the same invariant for rules the canonical form collapses to
    /// `[[rules]]`.
    #[test]
    fn golden_canonical_bytes_of_inline_rules_without_optional_keys() {
        const EXPECTED: &str = r#"version = 1
scope = "profile:*"

[[rules]]
match = { tool = "stellar_pay", chain = "*" }
criteria = [{ kind = "per_period_cap", asset = "native", window = "1d", max_stroops = 50000000 }]
decision = "allow"

[[rules]]
match = { chain = "*", tool = "*" }
criteria = []
decision = "require_approval"
"#;
        let bytes = canonical_bytes(GOLDEN_INLINE_RULES_FIXTURE).unwrap();
        assert_eq!(String::from_utf8(bytes).unwrap(), EXPECTED);
    }

    // ── optional rule keys in the canonical bytes ─────────────────────────────

    /// The canonical bytes of [`OPTIONAL_KEYS_ARRAY_OF_TABLES`] and
    /// [`OPTIONAL_KEYS_INLINE_RULES`], written by hand from the canonical form
    /// rules. The keys `reason`, `ttl_secs` and `allow_opaque_signing` follow
    /// `decision` in that order, each only when present. An integer is plain
    /// decimal, and a string is basic-quoted. A present empty `reason`, a present
    /// default TTL and a present `false` are emitted. An absent key emits nothing.
    const EXPECTED_WITH_OPTIONAL_KEYS: &str = r#"version = 1
scope = "profile:alice"

[[rules]]
match = { tool = "stellar_sep43_sign_transaction", chain = "*" }
criteria = []
decision = "require_approval"
reason = "manual review"
ttl_secs = 3600
allow_opaque_signing = true

[[rules]]
match = { tool = "stellar_pay", chain = "*" }
criteria = []
decision = "require_approval"
reason = ""
allow_opaque_signing = false

[[rules]]
match = { tool = "*", chain = "*" }
criteria = []
decision = "require_approval"
ttl_secs = 86400

[[rules]]
match = { tool = "*", chain = "*" }
criteria = []
decision = "deny"
"#;

    /// Array-of-tables rules carrying the optional keys out of canonical order,
    /// with an underscore integer and a present `false`.
    const OPTIONAL_KEYS_ARRAY_OF_TABLES: &str = r#"version = 1
scope = "profile:alice"

[[rules]]
allow_opaque_signing = true
ttl_secs = 3_600 # one hour
reason = "manual review"
decision = "require_approval"
criteria = []
match = { tool = "stellar_sep43_sign_transaction", chain = "*" }

[[rules]]
match = { tool = "stellar_pay", chain = "*" }
criteria = []
decision = "require_approval"
allow_opaque_signing = false
reason = ""

[[rules]]
match = { tool = "*", chain = "*" }
criteria = []
decision = "require_approval"
ttl_secs = 86400

[[rules]]
match = { tool = "*", chain = "*" }
criteria = []
decision = "deny"
"#;

    /// The rules of [`OPTIONAL_KEYS_ARRAY_OF_TABLES`] as an inline array, with a
    /// hexadecimal integer and literal-quoted strings.
    const OPTIONAL_KEYS_INLINE_RULES: &str = r#"version = 1
scope = "profile:alice"
rules = [
  { allow_opaque_signing = true, ttl_secs = 0xe10, reason = 'manual review', decision = "require_approval", criteria = [], match = { tool = "stellar_sep43_sign_transaction", chain = "*" } },
  { match = { tool = "stellar_pay", chain = "*" }, criteria = [], decision = "require_approval", allow_opaque_signing = false, reason = '' },
  { match = { tool = "*", chain = "*" }, criteria = [], decision = "require_approval", ttl_secs = 86400 },
  { match = { tool = "*", chain = "*" }, criteria = [], decision = "deny" },
]
"#;

    #[test]
    fn canonical_bytes_sign_optional_rule_keys_of_array_of_tables_rules() {
        let bytes = canonical_bytes(OPTIONAL_KEYS_ARRAY_OF_TABLES).unwrap();
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            EXPECTED_WITH_OPTIONAL_KEYS
        );
    }

    #[test]
    fn canonical_bytes_sign_optional_rule_keys_of_inline_rules() {
        let bytes = canonical_bytes(OPTIONAL_KEYS_INLINE_RULES).unwrap();
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            EXPECTED_WITH_OPTIONAL_KEYS
        );
    }

    proptest! {
        /// (a) Tab vs space indentation around `=` signs.
        ///
        /// The canonical form strips decor; any whitespace around `=` signs is
        /// normalised.  Both representations must produce the same bytes.
        #[test]
        fn prop_canonical_invariant_under_whitespace_around_equals(
            decision in "(allow|deny)"
        ) {
            // Space-padded form (standard TOML style).
            let space_toml = format!(
                "version = 1\nscope = \"profile:default\"\n\n[[rules]]\nmatch = {{ tool = \"stellar_pay\", chain = \"*\" }}\ncriteria = []\ndecision = \"{decision}\"\n"
            );
            // Tab-padded form: insert tabs around =.
            let tab_toml = format!(
                "version\t=\t1\nscope\t=\t\"profile:default\"\n\n[[rules]]\nmatch = {{ tool = \"stellar_pay\", chain = \"*\" }}\ncriteria = []\ndecision = \"{decision}\"\n"
            );
            let b1 = canonical_bytes(&space_toml).unwrap();
            let b2 = canonical_bytes(&tab_toml).unwrap();
            prop_assert_eq!(b1, b2, "canonical form must be invariant under whitespace around = signs");
        }

        /// (c) Different-but-equivalent integer literals.
        ///
        /// TOML allows underscores in integer literals for readability.
        /// `1000_0000000` and `10_000_000_000` are the same value; the
        /// canonical form must normalise to the same decimal representation.
        #[test]
        fn prop_canonical_invariant_under_integer_representation(
            // Pick a random integer in a range that has multiple underscore forms.
            v in 0i64..1_000_000_000i64
        ) {
            // Plain decimal form.
            let plain = format!(
                "version = {v}\nscope = \"profile:default\"\n"
            );
            // Underscore-separated form: split at thousands boundary if >= 1000.
            let underscore = if v >= 1000 {
                let hi = v / 1000;
                let lo = v % 1000;
                format!("version = {hi}_{lo:03}\nscope = \"profile:default\"\n")
            } else {
                plain.clone()
            };
            let b1 = canonical_bytes(&plain).unwrap();
            let b2 = canonical_bytes(&underscore).unwrap();
            prop_assert_eq!(b1, b2, "canonical form must be invariant under integer underscore notation");
        }

        /// (d) Reordered fields within a rule.
        ///
        /// The canonical form fixes field order as `match`, `criteria`, `decision`.
        /// Two rules that differ only in field order must produce the same bytes.
        #[test]
        fn prop_canonical_invariant_under_rule_field_order(
            decision in "(allow|deny)",
            tool in "[a-z_]{3,20}"
        ) {
            // Standard order: match, criteria, decision.
            let standard = format!(
                "version = 1\nscope = \"profile:default\"\n\n[[rules]]\nmatch = {{ tool = \"{tool}\", chain = \"*\" }}\ncriteria = []\ndecision = \"{decision}\"\n"
            );
            // Reversed order: decision, criteria, match.
            let reversed = format!(
                "version = 1\nscope = \"profile:default\"\n\n[[rules]]\ndecision = \"{decision}\"\ncriteria = []\nmatch = {{ tool = \"{tool}\", chain = \"*\" }}\n"
            );
            let b1 = canonical_bytes(&standard).unwrap();
            let b2 = canonical_bytes(&reversed).unwrap();
            prop_assert_eq!(b1, b2, "canonical form must be invariant under rule field order");
        }

        /// Inline `rules = [...]` and `[[rules]]` array-of-tables syntax with
        /// identical semantic content must have the same signature pre-image,
        /// with any subset of the optional rule keys present. The two forms
        /// list the optional keys in opposite orders.
        #[test]
        fn prop_canonical_inline_rules_array_matches_array_of_tables(
            decision in "(allow|deny|require_approval)",
            tool in "[a-z_]{3,20}",
            max_stroops in 0i64..1_000_000_000i64,
            reason in proptest::option::of("[a-z ]{0,24}"),
            ttl_secs in proptest::option::of(1i64..=604_800i64),
            allow_opaque_signing in proptest::option::of(any::<bool>())
        ) {
            let reason = reason.map(|r| format!("reason = \"{r}\""));
            let ttl_secs = ttl_secs.map(|t| format!("ttl_secs = {t}"));
            let allow_opaque_signing =
                allow_opaque_signing.map(|b| format!("allow_opaque_signing = {b}"));
            let inline_optional: String = [&reason, &ttl_secs, &allow_opaque_signing]
                .into_iter()
                .flatten()
                .map(|kv| format!(", {kv}"))
                .collect();
            let table_optional: String = [&allow_opaque_signing, &ttl_secs, &reason]
                .into_iter()
                .flatten()
                .map(|kv| format!("{kv}\n"))
                .collect();
            let inline = format!(
                "version = 1\nscope = \"profile:default\"\n\
                 rules = [{{ match = {{ tool = \"{tool}\", \
                 chain = \"*\" }}, criteria = [{{ kind = \"per_tx_cap\", \
                 asset = \"native\", max_stroops = {max_stroops} }}], \
                 decision = \"{decision}\"{inline_optional} }}]\n"
            );
            let array_of_tables = format!(
                "version = 1\nscope = \"profile:default\"\n\n[[rules]]\n\
                 {table_optional}match = {{ tool = \"{tool}\", chain = \"*\" }}\n\
                 criteria = [{{ kind = \"per_tx_cap\", asset = \"native\", \
                 max_stroops = {max_stroops} }}]\n\
                 decision = \"{decision}\"\n"
            );
            let b1 = canonical_bytes(&inline).unwrap();
            let b2 = canonical_bytes(&array_of_tables).unwrap();
            prop_assert_eq!(b1, b2, "canonical form must collapse inline and array-of-tables rule syntax");
        }
    }
}
