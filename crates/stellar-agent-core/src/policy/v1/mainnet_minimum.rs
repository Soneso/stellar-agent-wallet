//! Minimum restrictions required by an enabled mainnet policy.

use super::asset_equivalence::{assets_equivalent, pinned_asset};
use crate::{policy::PolicyError, profile::schema::Profile};
use toml_edit::{DocumentMut, InlineTable, Item, TableLike, Value};

/// Registry tools whose value behavior is read-only, plus local reconciliation.
pub const MAINNET_READ_ONLY_TOOLS: &[&str] = &[
    "stellar_balances",
    "stellar_fee_stats",
    "stellar_dex_quote",
    "stellar_rules_list",
    "stellar_rules_get",
    "stellar_sep43_get_address",
    "stellar_sep43_get_network",
    "stellar_sep47_discover",
    "stellar_sep48_preview_invocation",
    "stellar_sep53_verify_message",
    "stellar_sep6_deposit_info",
    "stellar_sep7_parse_uri",
    "stellar_toolset_list",
    "stellar_toolset_invoke",
    "stellar_mpp_authorization_status",
    "stellar_x402_parse_receipt",
    "stellar_transaction_status",
];
const VALUE_OUT: &[&str] = &[
    "stellar_pay",
    "stellar_pay_commit",
    "stellar_create_account",
    "stellar_create_account_commit",
    "stellar_x402_create_payment",
    "stellar_x402_authenticated_payment",
];
const TRUSTLINE: &[&str] = &["stellar_trustline", "stellar_trustline_commit"];
const CLAIM: &[&str] = &["stellar_claim", "stellar_claim_commit"];

/// Declares the requirement enum and the public name list from one table, so
/// a requirement's discriminant is its index in [`REQUIREMENTS`].
macro_rules! requirements {
    ($($variant:ident => $name:literal),* $(,)?) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        enum Requirement {
            $($variant),*
        }

        /// The minimum requirements, in report order: the body requirements,
        /// then the per-rule requirements, then the `[mainnet]` table's.
        pub const REQUIREMENTS: &[&str] = &[$($name),*];
    };
}

requirements! {
    BodyVersion => "body_version",
    MainnetTable => "mainnet_table",
    RulesEmpty => "rules_empty",
    Scope => "scope",
    Chain => "chain",
    Tool => "tool",
    Opaque => "opaque",
    RuleTtl => "rule_ttl",
    AssetAllowlist => "asset_allowlist",
    Destination => "destination",
    HomeDomain => "home_domain",
    PerTxCap => "per_tx_cap",
    PerPeriodCap => "per_period_cap",
    RateLimit => "rate_limit",
    FeeCap => "fee_cap",
    Thresholds => "thresholds",
    Ttl => "ttl",
}

/// The detail of every `[mainnet]` table requirement when the table is absent.
const MISSING_TABLE: &str = "the [mainnet] table is missing";

/// How a policy body fares against one requirement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequirementStatus {
    /// The body meets the requirement.
    Passed,
    /// The body fails the requirement.
    Failed {
        /// Zero-based indexes of the failing rules, in order; empty for a
        /// requirement of the body or of the `[mainnet]` table.
        rules: Vec<usize>,
        /// What the body lacks.
        detail: String,
    },
    /// The body holds nothing the requirement applies to, such as a rule
    /// requirement in a body without rules.
    NotEvaluated {
        /// Why nothing was evaluated.
        detail: &'static str,
    },
}

/// One requirement's outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequirementOutcome {
    /// The requirement name, one of [`REQUIREMENTS`].
    pub requirement: &'static str,
    /// How the body fared.
    pub status: RequirementStatus,
}

/// What the evaluation found for one requirement.
#[derive(Default)]
struct Finding {
    /// Whether the body held a subject the requirement applies to.
    examined: bool,
    /// Failing rule indexes.
    rules: Vec<usize>,
    /// The failure of a body or table requirement.
    detail: Option<String>,
}

/// The findings of every requirement, indexed by [`Requirement`].
struct Findings(Vec<Finding>);

impl Findings {
    fn new() -> Self {
        Self(REQUIREMENTS.iter().map(|_| Finding::default()).collect())
    }

    fn finding(&mut self, requirement: Requirement) -> Option<&mut Finding> {
        self.0.get_mut(requirement as usize)
    }

    /// Records a body or table requirement, failing with `failure` when set.
    fn body(&mut self, requirement: Requirement, failure: Option<String>) {
        if let Some(finding) = self.finding(requirement) {
            finding.examined = true;
            finding.detail = failure;
        }
    }

    /// Records the requirement for the rule at `index`.
    fn rule(&mut self, requirement: Requirement, index: usize, ok: bool) {
        if let Some(finding) = self.finding(requirement) {
            finding.examined = true;
            if !ok {
                finding.rules.push(index);
            }
        }
    }

    fn into_outcomes(self, has_rules: bool) -> Vec<RequirementOutcome> {
        REQUIREMENTS
            .iter()
            .zip(self.0)
            .map(|(requirement, finding)| {
                let status = if let Some(detail) = finding.detail {
                    RequirementStatus::Failed {
                        rules: finding.rules,
                        detail,
                    }
                } else if !finding.rules.is_empty() {
                    let indexes = finding
                        .rules
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(", ");
                    let noun = if finding.rules.len() == 1 {
                        "rule"
                    } else {
                        "rules"
                    };
                    RequirementStatus::Failed {
                        rules: finding.rules,
                        detail: format!("{noun} {indexes}"),
                    }
                } else if finding.examined {
                    RequirementStatus::Passed
                } else if has_rules {
                    RequirementStatus::NotEvaluated {
                        detail: "no rule this requirement applies to",
                    }
                } else {
                    RequirementStatus::NotEvaluated {
                        detail: "the policy has no rules",
                    }
                };
                RequirementOutcome {
                    requirement,
                    status,
                }
            })
            .collect()
    }
}

/// Whether loading and signing must enforce mainnet restrictions in this build.
#[must_use]
pub fn required(doc: &DocumentMut, profile: &Profile) -> bool {
    cfg!(feature = "mainnet-write")
        && profile.chain_id.is_mainnet()
        && doc.get("version").and_then(Item::as_integer) == Some(2)
        && doc.contains_key("mainnet")
}

/// Evaluates every requirement, returning one outcome per entry of
/// [`REQUIREMENTS`], in that order.
///
/// The evaluation runs independently of the build feature, so an inspection
/// reports every requirement. Without a `[mainnet]` table each table
/// requirement fails with a detail naming the missing table.
#[must_use]
pub fn evaluate(
    doc: &DocumentMut,
    profile: &Profile,
    profile_name: &str,
) -> Vec<RequirementOutcome> {
    let mut findings = Findings::new();
    let version_ok = doc.get("version").and_then(Item::as_integer) == Some(2)
        && super::verified::sequence(doc).is_ok();
    findings.body(
        Requirement::BodyVersion,
        (!version_ok).then(|| "version must be 2 with a positive integer sequence".to_owned()),
    );
    let mainnet = doc.get("mainnet").and_then(Item::as_table_like);
    let table_failure = if doc.contains_key("mainnet") {
        "mainnet is not a table"
    } else {
        MISSING_TABLE
    };
    findings.body(
        Requirement::MainnetTable,
        mainnet.is_none().then(|| table_failure.to_owned()),
    );
    let scope = doc.get("scope").and_then(Item::as_str).unwrap_or("");
    let expected = format!("profile:{profile_name}");
    let scope_ok = scope == expected
        || scope
            .strip_prefix(&format!("{expected},project:"))
            .is_some_and(|id| !id.is_empty());
    findings.body(
        Requirement::Scope,
        (!scope_ok)
            .then(|| format!("scope must be {expected}, optionally followed by ,project:<id>")),
    );
    match mainnet {
        Some(mainnet) => {
            let fee_ok = mainnet
                .get("classic_max_fee_per_op_stroops")
                .and_then(Item::as_integer)
                .is_some_and(|fee| u32::try_from(fee).is_ok());
            findings.body(
                Requirement::FeeCap,
                (!fee_ok).then(|| {
                    "classic_max_fee_per_op_stroops must be an integer in the u32 range".to_owned()
                }),
            );
            findings.body(
                Requirement::Thresholds,
                super::verified::parse_thresholds(
                    mainnet.get("cross_check_thresholds"),
                    &profile.network_passphrase,
                )
                .err()
                .map(|error| match error {
                    PolicyError::PolicyFileParseFailed { detail } => detail,
                    other => other.to_string(),
                }),
            );
            let ttl_ok = mainnet
                .get("authorization_ttl_seconds")
                .is_none_or(|ttl| ttl.as_integer().is_some_and(|ttl| (1..=120).contains(&ttl)));
            findings.body(
                Requirement::Ttl,
                (!ttl_ok).then(|| "authorization_ttl_seconds must be between 1 and 120".to_owned()),
            );
        }
        None => {
            for requirement in [
                Requirement::FeeCap,
                Requirement::Thresholds,
                Requirement::Ttl,
            ] {
                findings.body(requirement, Some(table_failure.to_owned()));
            }
        }
    }
    let rules: Vec<&dyn TableLike> = match doc.get("rules") {
        Some(Item::ArrayOfTables(rules)) => rules.iter().map(|r| r as &dyn TableLike).collect(),
        Some(Item::Value(Value::Array(rules))) => rules
            .iter()
            .filter_map(Value::as_inline_table)
            .map(|r| r as &dyn TableLike)
            .collect(),
        _ => Vec::new(),
    };
    findings.body(
        Requirement::RulesEmpty,
        rules
            .is_empty()
            .then(|| "the policy has no rules".to_owned()),
    );
    for (index, rule) in rules.iter().enumerate() {
        evaluate_rule(&mut findings, index, *rule, profile);
    }
    findings.into_outcomes(!rules.is_empty())
}

/// Records the per-rule requirements of the rule at `index`.
fn evaluate_rule(findings: &mut Findings, index: usize, rule: &dyn TableLike, profile: &Profile) {
    let matcher = rule.get("match").and_then(Item::as_table_like);
    let tool = matcher
        .and_then(|m| m.get("tool"))
        .and_then(Item::as_str)
        .unwrap_or("");
    findings.rule(
        Requirement::Chain,
        index,
        matcher.and_then(|m| m.get("chain")).and_then(Item::as_str) == Some("stellar:mainnet"),
    );
    findings.rule(
        Requirement::Tool,
        index,
        VALUE_OUT.contains(&tool)
            || TRUSTLINE.contains(&tool)
            || CLAIM.contains(&tool)
            || MAINNET_READ_ONLY_TOOLS.contains(&tool),
    );
    findings.rule(
        Requirement::Opaque,
        index,
        rule.get("allow_opaque_signing")
            .is_none_or(|opaque| opaque.as_bool() == Some(false)),
    );
    let decision = rule.get("decision").and_then(Item::as_str);
    findings.rule(
        Requirement::RuleTtl,
        index,
        decision != Some("require_approval")
            || rule
                .get("ttl_secs")
                .and_then(Item::as_integer)
                .is_some_and(|ttl| (1..=3600).contains(&ttl)),
    );
    let criteria: Vec<&InlineTable> = rule
        .get("criteria")
        .and_then(Item::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_inline_table)
        .collect();
    fn kind<'a>(c: &&'a InlineTable) -> &'a str {
        c.get("kind").and_then(Value::as_str).unwrap_or("")
    }
    findings.rule(
        Requirement::HomeDomain,
        index,
        !criteria.iter().any(|c| {
            kind(c) == "home_domain_resolved"
                || (kind(c) == "counterparty_allowlist"
                    && c.get("kinds")
                        .and_then(Value::as_array)
                        .is_some_and(|kinds| {
                            kinds.iter().any(|k| k.as_str() == Some("HOME_DOMAIN"))
                        }))
        }),
    );
    let allowlists: Vec<_> = criteria
        .iter()
        .filter(|c| kind(c) == "asset_allowlist")
        .collect();
    if CLAIM.contains(&tool) {
        findings.rule(Requirement::AssetAllowlist, index, allowlists.is_empty());
    }
    if decision == Some("deny") {
        return;
    }
    if !(VALUE_OUT.contains(&tool) || TRUSTLINE.contains(&tool)) {
        return;
    }
    let assets: Vec<_> = allowlists
        .first()
        .and_then(|c| c.get("assets"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    findings.rule(
        Requirement::AssetAllowlist,
        index,
        allowlists.len() == 1
            && !assets.is_empty()
            && assets.iter().all(|asset| pinned_asset(asset).is_ok()),
    );
    if !VALUE_OUT.contains(&tool) {
        return;
    }
    findings.rule(
        Requirement::Destination,
        index,
        criteria.iter().any(|c| {
            kind(c) == "counterparty_allowlist"
                && c.get("kinds")
                    .and_then(Value::as_array)
                    .is_some_and(|kinds| {
                        kinds
                            .iter()
                            .any(|k| matches!(k.as_str(), Some("G_ACCOUNT" | "C_ACCOUNT")))
                            && kinds.iter().all(|k| {
                                matches!(
                                    k.as_str(),
                                    Some("G_ACCOUNT" | "C_ACCOUNT" | "KNOWN_ISSUER")
                                )
                            })
                    })
        }),
    );
    for (requirement, name) in [
        (Requirement::PerTxCap, "per_tx_cap"),
        (Requirement::PerPeriodCap, "per_period_cap"),
    ] {
        findings.rule(
            requirement,
            index,
            criteria.iter().any(|c| kind(c) == name)
                && assets.iter().all(|asset| {
                    criteria.iter().any(|c| {
                        kind(c) == name
                            && c.get("asset").and_then(Value::as_str).is_some_and(|cap| {
                                assets_equivalent(asset, cap, &profile.network_passphrase)
                            })
                    })
                }),
        );
    }
    findings.rule(
        Requirement::RateLimit,
        index,
        criteria.iter().any(|c| kind(c) == "rate_limit"),
    );
}

/// Returns every unmet requirement as a `policy.mainnet_minimum_unmet` error,
/// in [`REQUIREMENTS`] order with rule indexes ascending: one error per
/// failing rule, and one without a rule index for a body or table requirement.
#[must_use]
pub fn failures(doc: &DocumentMut, profile: &Profile, profile_name: &str) -> Vec<PolicyError> {
    evaluate(doc, profile, profile_name)
        .into_iter()
        .flat_map(|outcome| match outcome.status {
            RequirementStatus::Failed { rules, .. } if rules.is_empty() => {
                vec![PolicyError::MainnetMinimumUnmet {
                    requirement: outcome.requirement,
                    rule: None,
                }]
            }
            RequirementStatus::Failed { rules, .. } => rules
                .into_iter()
                .map(|rule| PolicyError::MainnetMinimumUnmet {
                    requirement: outcome.requirement,
                    rule: Some(rule),
                })
                .collect(),
            RequirementStatus::Passed | RequirementStatus::NotEvaluated { .. } => Vec::new(),
        })
        .collect()
}

/// Refuses the first unmet minimum requirement in the order of [`failures`].
///
/// # Errors
/// Returns `policy.mainnet_minimum_unmet` with a requirement and optional rule index.
pub fn validate(
    doc: &DocumentMut,
    profile: &Profile,
    profile_name: &str,
) -> Result<(), PolicyError> {
    match failures(doc, profile, profile_name).into_iter().next() {
        Some(error) => Err(error),
        None => Ok(()),
    }
}
