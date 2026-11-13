//! The spending preview a command writes to stderr before its first write.
//!
//! `profile init` previews the bounds of the policy body it is about to write,
//! and `profile enable-mainnet` the bounds of the body it is about to bind.
//! `profile policy add-counterparty` previews the body it is about to sign or
//! write, with the scope of its edit beside the summary.
//! The preview is one JSON line by default, or a flattened table:
//!
//! ```text
//! phase: before_write
//! Spending summary
//! authority_status: draft
//! limits[USDC:G...].per_tx_cap: 0.2
//! Plan
//! Floor M: 1.7 XLM
//! ```
//!
//! A preview that cannot be written stops the command before it writes
//! anything, so no bound takes effect unseen. A shown preview is kept, so a
//! later refusal can carry it at `error.details.preview`.

use std::io::Write;

use serde_json::{Map, Value};
use stellar_agent_core::envelope::{Envelope, OutputFormat};
use stellar_agent_core::policy::v1::presets::{PresetPlan, SpendingSummary};

use super::render;

/// The refusal code of a preview that could not be written.
pub(crate) const SPENDING_PREVIEW_UNWRITABLE: &str = "profile.spending_preview_unwritable";

/// The top-level keys of [`SpendingSummary`], in declaration order.
const SUMMARY_KEYS: [&str; 15] = [
    "authority_status",
    "policy_version",
    "sequence",
    "limits",
    "unlisted_exhaustion",
    "rate_limits",
    "auxiliary_rate_limits",
    "classic_max_fee_per_op_stroops",
    "fee_cap_status",
    "max_fee_per_classic_operation_xlm",
    "balance_floor_xlm",
    "balance_floors",
    "recipients",
    "tools",
    "notes",
];

/// The top-level keys of [`PresetPlan`], in declaration order.
const PLAN_KEYS: [&str; 17] = [
    "preset",
    "asset",
    "tolerated_loss",
    "unattended_days",
    "typical_payment",
    "even_daily_spend",
    "expected_spend_fit",
    "typical_use",
    "operating_balance",
    "protocol_minimum_xlm",
    "balance_floor_xlm",
    "recommended_balance_xlm",
    "recommended_funding_xlm",
    "fee_allowance_xlm",
    "worst_case_asset",
    "funding_condition",
    "assumptions",
];

/// The fields that name an array element in a table path, in precedence
/// order.
const ELEMENT_NAMES: [&str; 3] = ["tool", "recipient", "asset"];

/// `refusal` with `shown`, the preview a command wrote, at
/// `error.details.preview`. Before a preview is shown the refusal is
/// unchanged.
#[must_use]
pub(crate) fn with_shown_preview(refusal: Envelope<()>, shown: Option<&Value>) -> Envelope<()> {
    match shown {
        Some(shown) => render::with_preview_detail(refusal, shown.clone()),
        None => refusal,
    }
}

/// Writes one spending preview and keeps the value it wrote.
pub(crate) struct SpendingPreview<'a> {
    out: &'a mut dyn Write,
    shown: Option<Value>,
}

impl<'a> SpendingPreview<'a> {
    /// A preview that writes to `out`, normally stderr.
    pub(crate) fn new(out: &'a mut dyn Write) -> Self {
        Self { out, shown: None }
    }

    /// The preview written, or `None` before a write succeeds.
    pub(crate) fn shown(&self) -> Option<&Value> {
        self.shown.as_ref()
    }

    /// Writes `{"phase":"before_write","spending_summary":...}`, with `plan`
    /// beside the summary when one is given, and flushes.
    ///
    /// `Table` writes the flattened layout; JSON and every other format write
    /// one compact JSON line.
    ///
    /// # Errors
    ///
    /// Returns [`SPENDING_PREVIEW_UNWRITABLE`] with the I/O error when the
    /// write or the flush fails; nothing is recorded then.
    pub(crate) fn show(
        &mut self,
        summary: Option<&SpendingSummary>,
        plan: Option<&PresetPlan>,
        format: OutputFormat,
    ) -> Result<(), (&'static str, String)> {
        self.show_with(summary, plan, &[], format)
    }

    /// [`Self::show`] with each `extra` pair inserted after the summary and
    /// the plan. The table layout states no `extra` pair.
    ///
    /// # Errors
    ///
    /// Returns [`SPENDING_PREVIEW_UNWRITABLE`] with the I/O error when the
    /// write or the flush fails; nothing is recorded then.
    pub(crate) fn show_with(
        &mut self,
        summary: Option<&SpendingSummary>,
        plan: Option<&PresetPlan>,
        extra: &[(&'static str, Value)],
        format: OutputFormat,
    ) -> Result<(), (&'static str, String)> {
        let unwritable = |error: &dyn std::fmt::Display| {
            (
                SPENDING_PREVIEW_UNWRITABLE,
                format!(
                    "the spending preview could not be written to stderr: {error}; nothing was \
                     written"
                ),
            )
        };
        let mut value = Map::new();
        value.insert("phase".to_owned(), Value::from("before_write"));
        value.insert(
            "spending_summary".to_owned(),
            serde_json::to_value(summary).map_err(|e| unwritable(&e))?,
        );
        if let Some(plan) = plan {
            value.insert(
                "plan".to_owned(),
                serde_json::to_value(plan).map_err(|e| unwritable(&e))?,
            );
        }
        for (key, extra) in extra {
            value.insert((*key).to_owned(), extra.clone());
        }
        let value = Value::Object(value);
        let text = match format {
            OutputFormat::Table => table(&value),
            _ => {
                let json = serde_json::to_string(&value).map_err(|e| unwritable(&e))?;
                format!("{}\n", render::escape_json_format_characters(&json))
            }
        };
        self.out
            .write_all(text.as_bytes())
            .and_then(|()| self.out.flush())
            .map_err(|e| unwritable(&e))?;
        self.shown = Some(value);
        Ok(())
    }
}

/// The table layout of a preview value: the phase, the summary under
/// `Spending summary`, and the plan under `Plan` when present.
fn table(preview: &Value) -> String {
    let mut lines = vec!["phase: before_write".to_owned()];
    lines.push("Spending summary".to_owned());
    flatten_top(
        preview.get("spending_summary").unwrap_or(&Value::Null),
        &SUMMARY_KEYS,
        &mut lines,
    );
    if let Some(plan) = preview.get("plan") {
        lines.push("Plan".to_owned());
        let asset = plan.get("asset").and_then(Value::as_str).unwrap_or("");
        for (key, value) in ordered(plan, &PLAN_KEYS) {
            match key {
                "operating_balance" => {
                    lines.push(format!("Operating balance: {} {asset}", leaf(value)));
                }
                "balance_floor_xlm" => lines.push(format!("Floor M: {} XLM", leaf(value))),
                "recommended_balance_xlm" => {
                    lines.push(format!("Recommended balance R: {} XLM", leaf(value)));
                }
                _ => flatten(key, value, &mut lines),
            }
        }
    }
    let mut text = String::new();
    for line in lines {
        text.push_str(&render::sanitize_for_table(&line));
        text.push('\n');
    }
    text
}

/// Flattens an object's top-level keys in `order`, or the value itself at
/// the empty path when it is not an object.
fn flatten_top(value: &Value, order: &[&'static str], lines: &mut Vec<String>) {
    if value.is_object() {
        for (key, child) in ordered(value, order) {
            flatten(key, child, lines);
        }
    } else {
        lines.push(leaf(value));
    }
}

/// The entries of an object: the keys of `order` first, in that order, then
/// every other key in map order.
fn ordered<'v>(value: &'v Value, order: &[&'static str]) -> Vec<(&'v str, &'v Value)> {
    let Some(map) = value.as_object() else {
        return Vec::new();
    };
    let mut entries: Vec<(&str, &Value)> = order
        .iter()
        .filter_map(|key| map.get(*key).map(|child| (*key, child)))
        .collect();
    entries.extend(
        map.iter()
            .filter(|(key, _)| !order.contains(&key.as_str()))
            .map(|(key, child)| (key.as_str(), child)),
    );
    entries
}

/// Appends one `{path}: {value}` line per leaf of `value` under `path`.
fn flatten(path: &str, value: &Value, lines: &mut Vec<String>) {
    match value {
        Value::Object(map) if map.len() == 1 && map.contains_key("uniform") => {
            flatten(path, &map["uniform"], lines);
        }
        Value::Object(map) if !map.is_empty() => {
            for (key, child) in map {
                flatten(&format!("{path}.{key}"), child, lines);
            }
        }
        Value::Array(items) if !items.is_empty() => {
            for (index, item) in items.iter().enumerate() {
                flatten(
                    &format!("{path}[{}]", element_name(item, index)),
                    item,
                    lines,
                );
            }
        }
        _ => lines.push(format!("{path}: {}", leaf(value))),
    }
}

/// The path segment of an array element: its first string field among
/// `tool`, `recipient`, and `asset`; else its `window` when it has no
/// `identifier`; else its zero-based index.
fn element_name(item: &Value, index: usize) -> String {
    let field = |key: &str| item.get(key).and_then(Value::as_str);
    ELEMENT_NAMES
        .iter()
        .find_map(|key| field(key))
        .or_else(|| {
            item.get("identifier")
                .is_none()
                .then(|| field("window"))
                .flatten()
        })
        .map_or_else(|| index.to_string(), str::to_owned)
}

/// The printed form of a leaf: `none` for null and for an empty array or
/// object, `yes` or `no` for a boolean, and strings unquoted.
fn leaf(value: &Value) -> String {
    match value {
        Value::Null => "none".to_owned(),
        Value::Bool(true) => "yes".to_owned(),
        Value::Bool(false) => "no".to_owned(),
        Value::String(text) => text.clone(),
        Value::Number(number) => number.to_string(),
        Value::Array(items) if items.is_empty() => "none".to_owned(),
        Value::Object(map) if map.is_empty() => "none".to_owned(),
        Value::Array(_) | Value::Object(_) => value.to_string(),
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use super::*;
    use crate::common::render::FailingWriter;
    use stellar_agent_core::policy::v1::presets::{
        AuthorityStatus, DerivedSpending, PresetAsset, PresetInput, derive, find_preset, plan,
        policy_body, summarize,
    };
    use stellar_agent_core::profile::caip2::MAINNET_PASSPHRASE;

    const ISSUER: &str = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";

    fn derived(name: &str, unlisted_budget: bool) -> DerivedSpending {
        derive(&PresetInput {
            preset: find_preset(name).unwrap(),
            asset: PresetAsset::Usdc {
                issuer: ISSUER.to_owned(),
            },
            tolerated_loss_stroops: None,
            typical_payment_stroops: None,
            unlisted_budget,
            total_budget: true,
        })
        .unwrap()
    }

    fn summary_and_plan(name: &str, unlisted_budget: bool) -> (SpendingSummary, PresetPlan) {
        let derived = derived(name, unlisted_budget);
        let body = policy_body("agent", &derived).parse().unwrap();
        (
            summarize(&body, MAINNET_PASSPHRASE, AuthorityStatus::Draft),
            plan(&derived),
        )
    }

    /// The leaves of `value`, counted as the table prints them: an empty
    /// array or object is one leaf.
    fn leaves(value: &Value) -> usize {
        match value {
            Value::Object(map) if !map.is_empty() => map.values().map(leaves).sum(),
            Value::Array(items) if !items.is_empty() => items.iter().map(leaves).sum(),
            _ => 1,
        }
    }

    fn shown(format: OutputFormat, plan: Option<&PresetPlan>) -> (String, Value) {
        let (summary, _) = summary_and_plan("api-day", true);
        let mut out = Vec::new();
        let mut preview = SpendingPreview::new(&mut out);
        preview.show(Some(&summary), plan, format).unwrap();
        let value = preview.shown().unwrap().clone();
        (String::from_utf8(out).unwrap(), value)
    }

    /// The table states every leaf the JSON line states, at its path, with
    /// the summary's keys in declaration order and the three plan balances
    /// as labeled lines.
    #[test]
    fn human_and_json_summaries_agree() {
        let (summary, plan) = summary_and_plan("api-day", true);
        let (json, value) = shown(OutputFormat::Json, Some(&plan));
        assert_eq!(json.lines().count(), 1);
        let parsed: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, value);
        assert_eq!(parsed["phase"], "before_write");
        assert_eq!(
            parsed["spending_summary"],
            serde_json::to_value(&summary).unwrap()
        );
        assert_eq!(parsed["plan"], serde_json::to_value(&plan).unwrap());

        let (table, table_value) = shown(OutputFormat::Table, Some(&plan));
        assert_eq!(table_value, value);
        let lines: Vec<&str> = table.lines().collect();
        assert_eq!(lines[0], "phase: before_write");
        assert_eq!(lines[1], "Spending summary");
        let plan_header = lines.iter().position(|l| *l == "Plan").unwrap();
        assert_eq!(
            lines.len(),
            3 + leaves(&parsed["spending_summary"]) + leaves(&parsed["plan"]),
            "{table}"
        );

        // The summary's top-level keys follow the declaration order.
        let mut tops: Vec<&str> = Vec::new();
        for line in &lines[2..plan_header] {
            let top = line.split(['.', '[', ':']).next().unwrap();
            if tops.last() != Some(&top) {
                tops.push(top);
            }
        }
        assert_eq!(tops, SUMMARY_KEYS);

        let asset = format!("USDC:{ISSUER}");
        for expected in [
            "authority_status: draft".to_owned(),
            "policy_version: 2".to_owned(),
            format!("limits[{asset}].per_tx_cap: 0.2"),
            format!("limits[{asset}].unlisted_mode: budget"),
            format!("limits[{asset}].unlisted_period_cap.window: 1d"),
            format!("limits[{asset}].unlisted_period_cap.amount: 0.5"),
            format!("limits[{asset}].period_caps[1d].amount: 2"),
            format!("limits[{asset}].tools[stellar_pay].unlisted_period_cap.amount: 0.5"),
            format!("limits[{asset}].tools[stellar_pay].bounds[total].reachable: yes"),
            format!("limits[{asset}].tools[stellar_pay].recipients: none"),
            format!("limits[{asset}].counters[0].identifier: {asset}"),
            "rate_limits.shared_across_tools: yes".to_owned(),
            "balance_floor_xlm: 1.7".to_owned(),
            "recipients.listed: none".to_owned(),
            "notes[0]: Caps use rolling windows: 1d covers the last 86,400 seconds and 1w the \
             last 604,800 seconds."
                .to_owned(),
        ] {
            assert!(
                lines[2..plan_header].contains(&expected.as_str()),
                "{expected}\n{table}"
            );
        }

        let plan_lines = &lines[plan_header + 1..];
        assert_eq!(plan_lines[0], "preset: api-day");
        for expected in [
            format!("Operating balance: {} USDC", plan.operating_balance),
            format!("Floor M: {} XLM", plan.balance_floor_xlm),
            format!(
                "Recommended balance R: {} XLM",
                plan.recommended_balance_xlm
            ),
            "recommended_funding_xlm: none".to_owned(),
            "assumptions[0]: Burst factor 2: the 1d cap is at most twice the even daily spend."
                .to_owned(),
        ] {
            assert!(
                plan_lines.contains(&expected.as_str()),
                "{expected}\n{table}"
            );
        }
        assert_eq!(
            (
                plan.balance_floor_xlm.as_str(),
                plan.recommended_balance_xlm.as_str()
            ),
            ("1.7", "2")
        );
        for key in [
            "operating_balance",
            "balance_floor_xlm",
            "recommended_balance_xlm",
        ] {
            assert!(
                !plan_lines.iter().any(|l| l.starts_with(&format!("{key}:"))),
                "{key}\n{table}"
            );
        }
    }

    /// Without a plan, neither form carries one, and a summary of `None`
    /// reads as `null` and `none`.
    #[test]
    fn preview_without_plan_or_summary() {
        let (json, value) = shown(OutputFormat::Json, None);
        assert!(value.get("plan").is_none());
        assert!(!json.contains("\"plan\""));
        let mut out = Vec::new();
        let mut preview = SpendingPreview::new(&mut out);
        preview.show(None, None, OutputFormat::Table).unwrap();
        assert_eq!(
            preview.shown(),
            Some(&serde_json::json!({"phase": "before_write", "spending_summary": null}))
        );
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "phase: before_write\nSpending summary\nnone\n"
        );
    }

    /// A failed write or flush refuses with the preview code and records
    /// nothing.
    #[test]
    fn preview_write_failure_is_reported() {
        let (summary, plan) = summary_and_plan("api-day", false);
        for format in [OutputFormat::Json, OutputFormat::Table] {
            for writer in [FailingWriter::Write, FailingWriter::Flush] {
                let mut out = writer;
                let mut preview = SpendingPreview::new(&mut out);
                let (code, message) = preview
                    .show(Some(&summary), Some(&plan), format)
                    .unwrap_err();
                assert_eq!(code, SPENDING_PREVIEW_UNWRITABLE);
                assert_eq!(code, "profile.spending_preview_unwritable");
                assert!(
                    message.starts_with("the spending preview could not be written to stderr: ")
                        && message.ends_with("; nothing was written"),
                    "{message}"
                );
                assert!(preview.shown().is_none(), "{writer:?}");
            }
        }
    }

    /// `show` writes the line of `show_with` without extra pairs, and an
    /// extra pair joins the JSON line only.
    #[test]
    fn show_keeps_its_output() {
        let (summary, plan) = summary_and_plan("api-day", false);
        let expected = format!(
            "{}\n",
            render::escape_json_format_characters(
                &serde_json::to_string(&serde_json::json!({
                    "phase": "before_write",
                    "spending_summary": summary,
                    "plan": plan,
                }))
                .unwrap()
            )
        );
        let mut out = Vec::new();
        SpendingPreview::new(&mut out)
            .show(Some(&summary), Some(&plan), OutputFormat::Json)
            .unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), expected);

        let extra = [("edit_scope", serde_json::json!([{"rule": 0}]))];
        let mut out = Vec::new();
        let mut preview = SpendingPreview::new(&mut out);
        preview
            .show_with(Some(&summary), None, &extra, OutputFormat::Json)
            .unwrap();
        assert_eq!(preview.shown().unwrap()["edit_scope"], extra[0].1);
        let mut table = Vec::new();
        SpendingPreview::new(&mut table)
            .show_with(Some(&summary), None, &extra, OutputFormat::Table)
            .unwrap();
        let mut plain = Vec::new();
        SpendingPreview::new(&mut plain)
            .show(Some(&summary), None, OutputFormat::Table)
            .unwrap();
        assert_eq!(table, plain);
    }

    /// Every table line is printable ASCII, whatever the values hold.
    #[test]
    fn table_lines_are_sanitized() {
        let preview = serde_json::json!({
            "phase": "before_write",
            "spending_summary": {"notes": ["a\u{1b}[2Jb\u{202e}c"]},
        });
        assert_eq!(
            table(&preview),
            "phase: before_write\nSpending summary\nnotes[0]: a[2Jbc\n"
        );
    }
}
