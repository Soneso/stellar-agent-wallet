//! `stellar-agent counterparty warm-up [--profile <name>]` — refresh all
//! HOME_DOMAIN entries from the profile's counterparty allowlist.
//!
//! The command reads the owner-signed policy TOML from the conventional policy
//! directory and extracts `counterparty_allowlist` criteria that include
//! `HOME_DOMAIN`. It skips strkeys and `CODE:ISSUER` values, refreshes the
//! remaining domain candidates, and emits a JSON summary.
//!
//! A binding is evidence for one hour from its fetch, so operators schedule
//! warm-up more often than hourly. Warm-up covers only the domains named in
//! `counterparty_allowlist` criteria that contain `HOME_DOMAIN`. A policy that
//! uses `home_domain_resolved` keeps each domain it relies on live with a
//! scheduled `stellar-agent counterparty refresh <domain>`.

use std::collections::BTreeSet;

use clap::Args;
use serde::Serialize;
use stellar_agent_core::envelope::Envelope;
use stellar_agent_core::error::{InternalError, WalletError};
use stellar_agent_core::profile::schema::default_policy_dir;
use stellar_agent_network::StellarTomlResolver;
use stellar_agent_network::counterparty::CounterpartyResolver as _;
use stellar_agent_network::counterparty::cache::DEFAULT_TTL;
use toml_edit::{DocumentMut, Item, Value};

use crate::commands::counterparty::envelope::to_counterparty_envelope;
use crate::commands::counterparty::list::{counterparty_cache_dir, format_system_time};
use crate::common::profile_access::{load_profile_reconciled, profile_access_envelope};
use crate::common::{render, resolve_profile_name};

/// Arguments for `stellar-agent counterparty warm-up`.
#[derive(Debug, Args)]
#[non_exhaustive]
pub(crate) struct WarmUpArgs {
    /// Profile name whose counterparty allowlist should be refreshed.
    ///
    /// Defaults to the `STELLAR_AGENT_PROFILE` env var, then `"default"`.
    #[arg(long = "profile", value_name = "NAME")]
    pub(crate) profile: Option<String>,
}

#[derive(Debug, Serialize)]
struct WarmUpEntry {
    home_domain: String,
    ok: bool,
    fetched_at: Option<String>,
    expires_at: Option<String>,
    error_code: Option<String>,
}

#[derive(Debug, Serialize)]
struct WarmUpData {
    profile: String,
    total: usize,
    refreshed: usize,
    failed: usize,
    entries: Vec<WarmUpEntry>,
}

fn warm_up_envelope(profile: &str, entries: Vec<WarmUpEntry>) -> Envelope<WarmUpData> {
    let refreshed = entries.iter().filter(|entry| entry.ok).count();
    let failed = entries.len().saturating_sub(refreshed);
    Envelope::ok(WarmUpData {
        profile: profile.to_owned(),
        total: entries.len(),
        refreshed,
        failed,
        entries,
    })
}

// The typed `load_signed_policy` + `CounterpartyAllowlistCriterion` path is
// not reusable here: `CounterpartyAllowlistCriterion::kinds` and
// `CounterpartyAllowlistCriterion::allowlist` are private fields with no public
// accessor. Using `toml_edit` structural extraction avoids duplicating the
// deserialization logic or adding an accessor that would widen the criterion's
// public API.
//
// Warm-up obtains evidence from the domain through the resolver's fetch and
// validation path. Authorization still uses the signed policy at evaluation,
// so this extraction needs no separate signature verification.
/// Extracts domain candidates from criteria containing `HOME_DOMAIN`.
/// Stellar strkeys and values containing `:` belong to other allowlist kinds.
/// All other values remain candidates so malformed domains fail during refresh.
fn extract_home_domain_allowlist_from_policy_toml(body: &str) -> Result<Vec<String>, WalletError> {
    let doc: DocumentMut = body.parse().map_err(|e: toml_edit::TomlError| {
        WalletError::Internal(InternalError::UnexpectedState {
            detail: format!("policy TOML parse failed: {e}"),
        })
    })?;
    let mut domains = BTreeSet::new();
    let Some(rules) = doc.get("rules").and_then(Item::as_array_of_tables) else {
        return Ok(Vec::new());
    };

    for rule in rules.iter() {
        let Some(criteria) = rule.get("criteria").and_then(Item::as_array) else {
            continue;
        };
        for criterion in criteria.iter() {
            let Some(table) = criterion.as_inline_table() else {
                continue;
            };
            if table.get("kind").and_then(Value::as_str) != Some("counterparty_allowlist") {
                continue;
            }
            let has_home_domain =
                table
                    .get("kinds")
                    .and_then(Value::as_array)
                    .is_some_and(|kinds| {
                        kinds
                            .iter()
                            .any(|kind| kind.as_str() == Some("HOME_DOMAIN"))
                    });
            if !has_home_domain {
                continue;
            }
            if let Some(allowlist) = table.get("allowlist").and_then(Value::as_array) {
                for value in allowlist.iter() {
                    if let Some(domain) = value.as_str() {
                        if stellar_strkey::Strkey::from_string(domain).is_ok()
                            || domain.contains(':')
                        {
                            tracing::debug!("skipping non-domain counterparty allowlist value");
                            continue;
                        }
                        domains.insert(domain.to_owned());
                    }
                }
            }
        }
    }

    Ok(domains.into_iter().collect())
}

/// Runs `stellar-agent counterparty warm-up [--profile <name>]`.
///
/// Returns `0` when all discovered domains refresh successfully, `1` when
/// profile loading, policy parsing, resolver construction, or any refresh fails.
pub async fn run(args: &WarmUpArgs) -> i32 {
    // `--profile`, then `STELLAR_AGENT_PROFILE`, then `"default"`.
    let resolved_profile = resolve_profile_name(args.profile.as_deref());
    let profile_name = resolved_profile.name.clone();

    // Reconciled: a profile file whose owner-key coordinate names a
    // different profile is refused rather than used under this name.
    let profile = match load_profile_reconciled(&resolved_profile) {
        Ok(p) => p,
        Err(e) => {
            tracing::debug!(profile = %profile_name, error = %e, "profile access refused");
            render::render_json(&profile_access_envelope(&e, &profile_name));
            return 1;
        }
    };

    let policy_dir = match default_policy_dir() {
        Ok(dir) => dir,
        Err(e) => {
            render::render_json(&Envelope::err(&WalletError::Internal(
                InternalError::UnexpectedState {
                    detail: e.to_string(),
                },
            )));
            return 1;
        }
    };
    let policy_path = policy_dir.join(format!("{profile_name}.toml"));
    let domains = if policy_path.exists() {
        match std::fs::read_to_string(&policy_path)
            .map_err(|e| {
                WalletError::Internal(InternalError::UnexpectedState {
                    detail: format!("could not read policy file: {}", e.kind()),
                })
            })
            .and_then(|body| extract_home_domain_allowlist_from_policy_toml(&body))
        {
            Ok(domains) => domains,
            Err(e) => {
                render::render_json(&Envelope::err(&e));
                return 1;
            }
        }
    } else {
        Vec::new()
    };

    let cache_dir = match counterparty_cache_dir(&profile_name) {
        Ok(d) => d,
        Err(e) => {
            render::render_json(&Envelope::err(&e));
            return 1;
        }
    };
    if let Err(e) = std::fs::create_dir_all(&cache_dir) {
        tracing::debug!(error = %e, "failed to create counterparty cache directory");
        render::render_json(&Envelope::<()>::err_raw(
            "counterparty.io",
            "could not create cache directory".to_owned(),
        ));
        return 1;
    }

    let resolver = match StellarTomlResolver::new(
        &profile_name,
        profile.counterparty_cache_key_id.clone(),
        &cache_dir,
        DEFAULT_TTL,
    ) {
        Ok(r) => r,
        Err(e) => {
            render::render_json(&to_counterparty_envelope(&e));
            return 1;
        }
    };

    let mut entries = Vec::with_capacity(domains.len());
    for domain in domains {
        match resolver.refresh(&domain).await {
            Ok(binding) => entries.push(WarmUpEntry {
                home_domain: binding.home_domain,
                ok: true,
                fetched_at: Some(format_system_time(binding.fetched_at)),
                expires_at: Some(format_system_time(binding.expires_at)),
                error_code: None,
            }),
            Err(e) => {
                let env = to_counterparty_envelope(&e);
                entries.push(WarmUpEntry {
                    home_domain: domain,
                    ok: false,
                    fetched_at: None,
                    expires_at: None,
                    error_code: env.error.map(|err| err.code),
                });
            }
        }
    }
    let failed = entries.iter().any(|entry| !entry.ok);
    render::render_json(&warm_up_envelope(&profile_name, entries));
    if failed { 1 } else { 0 }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test-only")]

    use super::*;
    use clap::Parser;

    #[derive(Debug, Parser)]
    struct WarmUpArgsHarness {
        #[command(flatten)]
        args: WarmUpArgs,
    }

    #[test]
    fn parse_warm_up_args() {
        let parsed = WarmUpArgsHarness::parse_from(["test", "--profile", "alice"]);
        assert_eq!(parsed.args.profile.as_deref(), Some("alice"));
    }

    #[test]
    fn extracts_home_domain_allowlist_entries() {
        let body = r#"
[[rules]]
criteria = [
  { kind = "counterparty_allowlist", kinds = ["HOME_DOMAIN"], allowlist = ["circle.com", "stellar.org"] },
  { kind = "counterparty_allowlist", kinds = ["G_ACCOUNT"], allowlist = ["GA5Z"] }
]
"#;
        let domains = extract_home_domain_allowlist_from_policy_toml(body).unwrap();
        assert_eq!(domains, vec!["circle.com", "stellar.org"]);
    }

    #[test]
    fn warm_up_envelope_shape() {
        let env = warm_up_envelope(
            "alice",
            vec![WarmUpEntry {
                home_domain: "circle.com".to_owned(),
                ok: true,
                fetched_at: Some("2026-04-30T12:34:56Z".to_owned()),
                expires_at: Some("2026-04-30T13:34:56Z".to_owned()),
                error_code: None,
            }],
        );
        assert!(env.ok);
        let data = env.data.unwrap();
        assert_eq!(data.profile, "alice");
        assert_eq!(data.total, 1);
        assert_eq!(data.refreshed, 1);
        assert_eq!(data.failed, 0);
    }

    #[test]
    fn mixed_allowlist_skips_other_kinds_by_shape() {
        let account = stellar_strkey::ed25519::PublicKey([0; 32]).to_string();
        let muxed = stellar_strkey::ed25519::MuxedAccount {
            ed25519: [0; 32],
            id: 7,
        }
        .to_string();
        let contract = stellar_strkey::Contract([0; 32]).to_string();
        let body = format!(
            r#"
[[rules]]
criteria = [
  {{ kind = "counterparty_allowlist",
     kinds = ["HOME_DOMAIN", "G_ACCOUNT", "C_ACCOUNT", "KNOWN_ISSUER"],
     allowlist = ["anchor.example", "{account}", "{muxed}", "{contract}", "USD:{account}"] }}
]
"#
        )
        .replace("\n     ", " ");
        let domains = extract_home_domain_allowlist_from_policy_toml(&body).unwrap();
        assert_eq!(domains, vec!["anchor.example"]);
    }

    #[test]
    fn allowlist_without_home_domain_yields_nothing() {
        let body = r#"
[[rules]]
criteria = [
  { kind = "counterparty_allowlist", kinds = ["G_ACCOUNT"], allowlist = ["anchor.example"] }
]
"#;
        assert!(
            extract_home_domain_allowlist_from_policy_toml(body)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn malformed_domain_remains_a_warm_up_candidate() {
        let body = r#"
[[rules]]
criteria = [
  { kind = "counterparty_allowlist", kinds = ["HOME_DOMAIN"], allowlist = ["INVALID.example"] }
]
"#;
        assert_eq!(
            extract_home_domain_allowlist_from_policy_toml(body).unwrap(),
            vec!["INVALID.example"],
        );
    }
}
