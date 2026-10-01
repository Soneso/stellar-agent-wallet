//! Manager builders for tests and live acceptance suites.
//!
//! A [`ContextRuleManager`] under test shares one audit writer with its
//! [`SignersManager`], as production does: the CLI and MCP builders wire the
//! same `Arc<Mutex<AuditWriter>>` into both. A rule's install rows, its
//! override and pin rows and its signer-set state rows therefore land in one
//! log, and a later signer verb reads the baseline the install recorded.
//!
//! The builders target the Stellar testnet passphrase and the
//! `stellar:testnet` chain id under the profile label `test-profile`.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use stellar_agent_core::audit_log::writer::AuditWriter;
use stellar_agent_core::profile::caip2::TESTNET_PASSPHRASE;
use tempfile::TempDir;

use crate::SaError;
use crate::managers::auth_entry::PreSubmitBudget;
use crate::managers::rules::{ContextRuleManager, ContextRuleManagerConfig};
use crate::managers::signers::{RuleLockGuard, SignersManager, SignersManagerConfig};

/// The chain id the builders configure.
const TEST_CHAIN_ID: &str = "stellar:testnet";

/// The profile label the builders configure.
const TEST_PROFILE: &str = "test-profile";

/// Builds a [`SignersManager`] over `primary_rpc_url` and `secondary_rpc_url`
/// that writes to `audit_writer`, whose log file is `audit_log_path`.
///
/// # Panics
///
/// Panics when [`SignersManager::new`] refuses the configuration, which only
/// happens for an RPC URL the test supplied that does not parse.
#[must_use]
#[allow(
    clippy::expect_used,
    reason = "a test builder: a URL the test supplies that does not parse is a test bug"
)]
pub fn signers_manager_for_tests(
    primary_rpc_url: &str,
    secondary_rpc_url: &str,
    audit_writer: Arc<Mutex<AuditWriter>>,
    audit_log_path: PathBuf,
    timeout: Duration,
) -> Arc<SignersManager> {
    let config = SignersManagerConfig::new(
        primary_rpc_url.to_owned(),
        secondary_rpc_url.to_owned(),
        audit_writer,
        audit_log_path,
        TESTNET_PASSPHRASE.to_owned(),
        TEST_PROFILE.to_owned(),
        timeout,
        TEST_CHAIN_ID.to_owned(),
    );
    Arc::new(SignersManager::new(config).expect("SignersManager::new accepts the test URLs"))
}

/// Builds the [`ContextRuleManagerConfig`] of a rule manager over
/// `primary_rpc_url` (and `secondary_rpc_url` when given) with
/// `signers_manager` and `audit_writer`.
///
/// Pass the writer `signers_manager` writes to. A suite that needs another
/// setting, such as a session-rule horizon cap, adds it to the returned
/// config before building the manager.
#[must_use]
pub fn rule_manager_config_for_tests(
    primary_rpc_url: &str,
    secondary_rpc_url: Option<&str>,
    signers_manager: Arc<SignersManager>,
    audit_writer: Arc<Mutex<AuditWriter>>,
    timeout: Duration,
) -> ContextRuleManagerConfig {
    let config = ContextRuleManagerConfig::new(
        primary_rpc_url.to_owned(),
        TESTNET_PASSPHRASE.to_owned(),
        timeout,
        TEST_CHAIN_ID.to_owned(),
    )
    .with_signers_manager(signers_manager)
    .with_audit_writer(audit_writer);
    match secondary_rpc_url {
        Some(url) => config.with_secondary_rpc_url(url.to_owned()),
        None => config,
    }
}

/// Builds a [`ContextRuleManager`] and its [`SignersManager`] over one new
/// audit log in a temporary directory, as production wires them.
///
/// The signers manager reads through `primary_rpc_url` and
/// `secondary_rpc_url`; the rule manager submits through `primary_rpc_url`
/// with no secondary simulation check. Returns the two managers, the audit
/// log's path and the directory that holds it, which the caller keeps for as
/// long as it uses the managers.
///
/// # Panics
///
/// Panics when the temporary directory or the audit log cannot be created,
/// or when a manager refuses an RPC URL the test supplied.
#[must_use]
#[allow(
    clippy::expect_used,
    reason = "a test builder: a temporary audit log that cannot be created is an environment \
              failure the test cannot recover from"
)]
pub fn managers_for_tests(
    primary_rpc_url: &str,
    secondary_rpc_url: &str,
    timeout: Duration,
) -> (ContextRuleManager, Arc<SignersManager>, PathBuf, TempDir) {
    let dir = tempfile::tempdir().expect("a temporary directory for the audit log");
    let audit_log_path = dir.path().join("audit.jsonl");
    let audit_writer = Arc::new(Mutex::new(
        AuditWriter::open(audit_log_path.clone(), None).expect("the temporary audit log opens"),
    ));
    let signers_manager = signers_manager_for_tests(
        primary_rpc_url,
        secondary_rpc_url,
        Arc::clone(&audit_writer),
        audit_log_path.clone(),
        timeout,
    );
    let rule_manager = rule_manager_for_tests(
        primary_rpc_url,
        None,
        Arc::clone(&signers_manager),
        audit_writer,
        timeout,
    );
    (rule_manager, signers_manager, audit_log_path, dir)
}

/// Builds a [`ContextRuleManager`] from [`rule_manager_config_for_tests`].
///
/// # Panics
///
/// Panics when [`ContextRuleManager::new`] refuses the configuration, which
/// only happens for an RPC URL the test supplied that does not parse.
#[must_use]
#[allow(
    clippy::expect_used,
    reason = "a test builder: a URL the test supplies that does not parse is a test bug"
)]
pub fn rule_manager_for_tests(
    primary_rpc_url: &str,
    secondary_rpc_url: Option<&str>,
    signers_manager: Arc<SignersManager>,
    audit_writer: Arc<Mutex<AuditWriter>>,
    timeout: Duration,
) -> ContextRuleManager {
    ContextRuleManager::new(rule_manager_config_for_tests(
        primary_rpc_url,
        secondary_rpc_url,
        signers_manager,
        audit_writer,
        timeout,
    ))
    .expect("ContextRuleManager::new accepts the test URLs")
}

/// A held lock on one rule of one smart account, from [`hold_rule_lock`].
///
/// The lock is held until the value is dropped, so a test can hold a rule's
/// lock without a verb in flight.
pub struct HeldRuleLock(RuleLockGuard);

impl std::fmt::Debug for HeldRuleLock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HeldRuleLock")
            .field("rule_id", &self.0.rule_id())
            .field("smart_account", &self.0.smart_account_redacted())
            .finish()
    }
}

/// Acquires the lock `manager` takes for rule `rule_id` of the smart account
/// `smart_account_strkey`, waiting at most `budget`, and holds it in the
/// returned value.
///
/// # Errors
///
/// [`SaError::AuthEntryConstructionFailed`] at stage `rule_lock` when the
/// lock is not acquired within `budget`.
pub async fn hold_rule_lock(
    manager: &SignersManager,
    smart_account_strkey: &str,
    rule_id: u32,
    budget: Duration,
) -> Result<HeldRuleLock, SaError> {
    manager
        .acquire_rule_lock(
            smart_account_strkey,
            rule_id,
            PreSubmitBudget {
                deadline: tokio::time::Instant::now() + budget,
                total: budget,
            },
        )
        .await
        .map(HeldRuleLock)
}
