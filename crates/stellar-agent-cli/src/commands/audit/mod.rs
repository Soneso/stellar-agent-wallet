//! `stellar-agent audit` subcommand group.
//!
//! Parent module for audit-log management subcommands.  Provides:
//!
//! - [`verify`] — walk a hash-chained audit log file and verify the chain
//!   integrity from the oldest rotated file to the current active file.
//! - [`reanchor`] — move the log's keyring-held tip anchor to its current tip
//!   after an operator-acknowledged rollback or audit binding change.
//! - `acknowledge-outbox-loss`: remove the profile's decided approvals from
//!   its approval inbox and revoke its toolset grants, then record the loss
//!   of queued operator rows.
//! - `bind-carriers`: record the identities of the audit lock files and start
//!   a new outbox generation, with every wallet process stopped.
//!
//! # Dispatch
//!
//! [`AuditArgs`] is a `clap` [`Args`] struct with a nested [`AuditSubcommand`]
//! enum.  The top-level [`crate::main`] function routes `Commands::Audit(args)`
//! to [`run`], which delegates to the appropriate subcommand handler.

pub mod acknowledge_outbox_loss;
mod bind_carriers;
pub mod reanchor;
pub mod verify;

use clap::{Args, Subcommand};
use stellar_agent_core::audit_log::WriterError;
use stellar_agent_core::error::{InternalError, ValidationError, WalletError};

/// Returns `true` when `text` already starts with an `audit.<subcode>:` wire
/// code.
fn starts_with_audit_wire_code(text: &str) -> bool {
    let Some(rest) = text.strip_prefix("audit.") else {
        return false;
    };
    let Some((subcode, _)) = rest.split_once(':') else {
        return false;
    };
    !subcode.is_empty()
        && subcode
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// Maps an audit-writer failure onto the CLI envelope model.
///
/// Operator-actionable conditions carry their documented `audit.*` codes rather
/// than being flattened into the caller's generic failure code:
///
/// - A held writer lock is `audit.writer_locked`. The audit writer is
///   process-exclusive. While an MCP server holds that profile's writer,
///   commands that need exclusive writer access refuse. The operator stops
///   the server and retries.
///   `approve --id` holds it only to write one consent row, and beside a
///   draining server it queues that row in the audit outbox instead. The
///   skill's troubleshooting table keys on codes, so an agent can only
///   recognize this if the code reaches the envelope.
/// - A tip-anchor mismatch is `audit.tip_anchor_mismatch`, and an absent anchor
///   with prior anchoring evidence is `audit.tip_anchor_missing`. Both name
///   `audit reanchor` as the remedy.
/// - Outbox loss and carrier refusals emit their own `audit.*` envelope codes:
///   `audit.outbox_rows_missing`, `audit.outbox_loss_not_found`,
///   `audit.carrier_replaced`, `audit.carriers_unbound`,
///   `audit.carrier_identity_unavailable`, `audit.carriers_busy`, and
///   `audit.carrier_binding_incomplete`.
/// - A keyed log opened without its audit key is `audit.chain_key_unavailable`,
///   and unusable consent evidence is `audit.outbox_evidence_unusable`, via
///   [`stellar_agent_core::audit_log::audit_writer_refusal`].
///
/// Everything else carries `fallback_code`, unless its own text already starts
/// with an `audit.*` code. `fallback_code` is the caller's own label for "this
/// verb could not use the audit writer".
///
/// Detail strings follow the CLI's sub-code convention: the detail begins with
/// the code, and the `WriterError` `Display` is appended only where it does not
/// already repeat it.
pub(crate) fn audit_writer_error(
    e: &WriterError,
    fallback_code: &str,
    profile_name: &str,
) -> WalletError {
    match e {
        WriterError::FileLocked => WalletError::Internal(InternalError::UnexpectedState {
            detail: "audit.writer_locked: the audit log's writer lock is held by another \
                     process; stop the running stellar-agent-mcp server and retry"
                .to_owned(),
        }),
        WriterError::TipAnchorMismatch { reason, .. } => {
            WalletError::Validation(ValidationError::AuditTipAnchorMismatch {
                profile: profile_name.to_owned(),
                reason: (*reason).to_owned(),
            })
        }
        WriterError::TipAnchorMissing { evidence, .. } => {
            WalletError::Validation(ValidationError::AuditTipAnchorMissing {
                profile: profile_name.to_owned(),
                evidence: evidence.describe().to_owned(),
            })
        }
        WriterError::OutboxRowsMissing { .. } | WriterError::RetiredOutboxChanged { .. } => {
            WalletError::Validation(ValidationError::AuditOutboxRowsMissing {
                detail: e.to_string(),
            })
        }
        WriterError::OutboxLossNotFound => {
            WalletError::Validation(ValidationError::AuditOutboxLossNotFound {
                detail: e.to_string(),
            })
        }
        WriterError::CarrierReplaced { .. } | WriterError::CarrierGenerationChanged { .. } => {
            WalletError::Validation(ValidationError::AuditCarrierReplaced {
                detail: e.to_string(),
            })
        }
        WriterError::CarriersUnbound => {
            WalletError::Validation(ValidationError::AuditCarriersUnbound {
                detail: e.to_string(),
            })
        }
        WriterError::CarrierIdentityUnavailable => {
            WalletError::Validation(ValidationError::AuditCarrierIdentityUnavailable {
                detail: e.to_string(),
            })
        }
        WriterError::CarriersBusy => WalletError::Validation(ValidationError::AuditCarriersBusy {
            detail: e.to_string(),
        }),
        WriterError::CarrierBindingIncomplete => {
            WalletError::Validation(ValidationError::AuditCarrierBindingIncomplete {
                detail: e.to_string(),
            })
        }
        // A keyed log opened without its key is the condition every other
        // audited verb reports as an unusable log; one condition, one code.
        // An evidence refusal keeps its own code the same way.
        WriterError::KeyedLogNeedsKey { .. } | WriterError::OutboxEvidenceUnusable { .. } => {
            stellar_agent_core::audit_log::audit_writer_refusal(profile_name, e)
        }
        // Variants whose own Display already leads with an `audit.*` wire code
        // carry it through unchanged; prefixing the caller's fallback would put
        // two codes in one detail and an agent matching on the first would read
        // the wrong one.
        _ => {
            let text = e.to_string();
            let detail = if starts_with_audit_wire_code(&text) {
                text
            } else {
                format!("{fallback_code}: {text}")
            };
            WalletError::Internal(InternalError::UnexpectedState { detail })
        }
    }
}

/// Arguments for the `audit` subcommand group.
#[derive(Debug, Args)]
#[non_exhaustive]
pub struct AuditArgs {
    /// The audit subcommand to run.
    #[command(subcommand)]
    pub subcommand: AuditSubcommand,
}

/// Subcommands of `stellar-agent audit`.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum AuditSubcommand {
    /// Verify the integrity of a hash-chained audit log file.
    ///
    /// Walks the log at `<log-path>` and verifies that every entry's
    /// `previous_entry_hash` matches the SHA-256 of the prior entry's
    /// canonical body.  Follows rotation manifests (cross-file chain bridges)
    /// automatically.
    ///
    /// Exits 0 on success; exits 1 on any integrity violation or I/O error.
    Verify(verify::VerifyArgs),

    /// Move the audit log's keyring-held tip anchor to the log's current tip.
    ///
    /// The way out of an `audit.tip_anchor_mismatch` refusal, which fires when
    /// the active log no longer contains the anchored chain tip, and of an
    /// `audit.log_binding_changed` refusal, which fires when the profile names
    /// a log path or audit key other than its recorded binding. A rollback
    /// needs `--acknowledge-rollback` and a binding change needs
    /// `--acknowledge-binding-change`; a binding change over a disagreeing
    /// anchor needs both. The verb cannot tell a restored backup or an edited
    /// profile from tampering.
    ///
    /// Exits 0 on success; exits 1 without a required acknowledgement and on
    /// any failure.
    Reanchor(reanchor::ReanchorArgs),
    /// Acknowledge lost queued rows after removing decided inbox approvals and toolset grants.
    AcknowledgeOutboxLoss(acknowledge_outbox_loss::AcknowledgeOutboxLossArgs),
    /// Record the carrier identities with every wallet process stopped.
    BindCarriers(bind_carriers::BindCarriersArgs),
}

/// Runs the `audit` subcommand group.
///
/// Dispatches to the appropriate subcommand handler.
///
/// Returns an exit code: `0` on success, `1` on any error.
///
/// # Errors
///
/// Never returns `Err` — errors are captured into the exit code.
///
/// # Panics
///
/// Never panics.
pub async fn run(args: &AuditArgs) -> i32 {
    match &args.subcommand {
        AuditSubcommand::Verify(a) => verify::run(a).await,
        AuditSubcommand::BindCarriers(a) => bind_carriers::run(a).await,
        AuditSubcommand::Reanchor(a) => reanchor::run(a).await,
        AuditSubcommand::AcknowledgeOutboxLoss(a) => acknowledge_outbox_loss::run(a).await,
    }
}

impl AuditArgs {
    /// The profile name this invocation operates on, as the selected subcommand
    /// resolves it.
    ///
    /// `None` means the subcommand supplied no name, so
    /// [`resolve_profile_name`](crate::common::resolve_profile_name) falls through
    /// to `STELLAR_AGENT_PROFILE` and then `"default"` — the same fall-through the
    /// subcommand itself performs. The startup advisory consumes this so it scans
    /// the audit log of the profile the command uses.
    pub(crate) fn profile_flag(&self) -> Option<&str> {
        match &self.subcommand {
            AuditSubcommand::Verify(a) => a.profile.as_deref(),
            AuditSubcommand::Reanchor(a) => Some(a.profile.as_str()),
            AuditSubcommand::BindCarriers(a) => Some(a.profile.as_str()),
            AuditSubcommand::AcknowledgeOutboxLoss(a) => Some(a.profile.as_str()),
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, reason = "test-only")]
    use super::*;

    #[test]
    fn a_held_writer_lock_carries_the_documented_code() {
        let err = audit_writer_error(&WriterError::FileLocked, "audit.reanchor_failed", "default");
        assert!(
            err.message().contains("audit.writer_locked"),
            "a held lock must name the code the docs and the skill key on: {}",
            err.message()
        );
        assert!(
            !err.message().contains("audit.reanchor_failed"),
            "the generic fallback must not mask it: {}",
            err.message()
        );
    }

    #[test]
    fn a_tip_anchor_mismatch_keeps_the_pre_flight_wire_code() {
        let err = audit_writer_error(
            &WriterError::TipAnchorMismatch {
                expected_count: 12,
                expected_offset: 3400,
                actual_len: 2600,
                reason: "test",
            },
            "audit.reanchor_failed",
            "acme",
        );
        assert_eq!(err.code(), "audit.tip_anchor_mismatch");
    }

    #[test]
    fn a_missing_tip_anchor_keeps_its_wire_code_and_names_the_evidence() {
        let err = audit_writer_error(
            &WriterError::TipAnchorMissing {
                evidence: stellar_agent_core::audit_log::PriorAnchoring::ChainRootSidecar,
                entry_count: 9,
                actual_len: 2600,
            },
            "audit.writer_unavailable",
            "acme",
        );
        assert_eq!(err.code(), "audit.tip_anchor_missing");
        let message = err.to_string();
        assert!(message.contains("chain-root sidecar"), "{message}");
        assert!(
            message.contains("audit reanchor --profile acme --acknowledge-rollback"),
            "{message}"
        );
    }

    #[test]
    fn a_variant_with_its_own_code_does_not_get_a_second_one() {
        let cases = [
            (
                WriterError::OutboxRowsMissing {
                    recorded: 2,
                    found: 1,
                },
                "audit.outbox_rows_missing",
            ),
            (
                WriterError::RetainedHistoryUnverified(
                    stellar_agent_core::audit_log::VerifyError::HmacMismatch {
                        file: "audit.jsonl.pruned".to_owned(),
                    },
                ),
                "audit.history_unverified",
            ),
            (
                WriterError::RetiredOutboxChanged { generation: 1 },
                "audit.outbox_rows_missing",
            ),
            (
                WriterError::CarrierGenerationChanged {
                    held: 1,
                    current: 2,
                },
                "audit.carrier_replaced",
            ),
            (
                WriterError::OutboxLossNotFound,
                "audit.outbox_loss_not_found",
            ),
            (
                WriterError::RotationBridgeUnusable {
                    archive_name: "audit.jsonl.20260913T120000000".to_owned(),
                    reason: "test",
                },
                "audit.rotation_bridge_unusable",
            ),
            (
                WriterError::RowTooLarge {
                    bytes: 2_000_000,
                    cap: 1_048_576,
                },
                "audit.row_too_large",
            ),
        ];
        for (writer_error, own_code) in &cases {
            let err = audit_writer_error(writer_error, "audit.reanchor_failed", "default");
            if matches!(
                writer_error,
                WriterError::OutboxRowsMissing { .. }
                    | WriterError::RetiredOutboxChanged { .. }
                    | WriterError::OutboxLossNotFound
                    | WriterError::CarrierGenerationChanged { .. }
            ) {
                assert_eq!(err.code(), *own_code);
            }
            assert!(
                err.message().contains(own_code),
                "message: {}",
                err.message()
            );
            assert!(
                !err.message().contains("audit.reanchor_failed"),
                "two codes in one detail: {}",
                err.message()
            );
        }
    }

    #[test]
    fn other_failures_carry_the_callers_fallback_code() {
        let err = audit_writer_error(
            &WriterError::TipAnchorUnavailable,
            "audit.writer_unavailable",
            "default",
        );
        assert!(
            err.message().contains("audit.writer_unavailable"),
            "message: {}",
            err.message()
        );
    }

    #[test]
    fn carrier_refusals_report_their_own_audit_codes() {
        use stellar_agent_core::audit_log::{Carrier, audit_writer_refusal};

        let cases = [
            (
                WriterError::CarrierReplaced {
                    carrier: Carrier::Writer,
                },
                "audit.carrier_replaced",
            ),
            (
                WriterError::CarrierGenerationChanged {
                    held: 1,
                    current: 2,
                },
                "audit.carrier_replaced",
            ),
            (WriterError::CarriersUnbound, "audit.carriers_unbound"),
            (
                WriterError::CarrierIdentityUnavailable,
                "audit.carrier_identity_unavailable",
            ),
            (WriterError::CarriersBusy, "audit.carriers_busy"),
            (
                WriterError::CarrierBindingIncomplete,
                "audit.carrier_binding_incomplete",
            ),
        ];
        for (writer_error, expected_code) in &cases {
            let err = audit_writer_error(writer_error, "audit.carrier_binding_failed", "default");
            assert_eq!(
                err.code(),
                *expected_code,
                "audit verb envelope code must be {expected_code}, got {} ({})",
                err.code(),
                err.message()
            );
            assert!(
                !err.code().starts_with("internal."),
                "carrier refusal must never use internal.*: {}",
                err.code()
            );
            assert!(
                err.message().starts_with(expected_code),
                "message must start with {expected_code}: {}",
                err.message()
            );
            assert!(
                !err.message().contains("audit.carrier_binding_failed"),
                "fallback code must not appear: {}",
                err.message()
            );

            // Value verbs keep `audit.chain_key_unavailable` with the carrier
            // code at the head of the detail.
            let value_err = audit_writer_refusal("default", writer_error);
            assert_eq!(value_err.code(), "audit.chain_key_unavailable");
            assert!(
                value_err
                    .message()
                    .contains(&format!("cannot be audited: {expected_code}:")),
                "value verb detail must lead with {expected_code}: {}",
                value_err.message()
            );
        }
    }

    #[test]
    fn tip_anchor_store_and_outbox_cap_errors_keep_single_code() {
        use stellar_agent_core::audit_log::TipAnchorStoreError;

        let cases = [
            (
                WriterError::TipAnchorStore(TipAnchorStoreError::new("keyring locked")),
                "audit.tip_anchor_unavailable",
            ),
            (
                WriterError::OutboxFull {
                    queued: 64,
                    cap: 64,
                },
                "audit.outbox_full",
            ),
            (
                WriterError::OutboxRowTooLarge {
                    bytes: 2_000_000,
                    cap: 1_048_576,
                },
                "audit.outbox_row_too_large",
            ),
        ];
        for (writer_error, own_code) in &cases {
            let err = audit_writer_error(writer_error, "audit.reanchor_failed", "default");
            let message = err.message();
            assert!(
                message.contains(&format!("{own_code}: ")),
                "expected {own_code}: {message}"
            );
            assert_eq!(
                message.matches(own_code).count(),
                1,
                "wire code must appear once: {message}"
            );
            assert!(
                !message.contains("audit.reanchor_failed"),
                "fallback code must not prefix self-coded error: {message}"
            );
        }
    }

    #[test]
    fn starts_with_audit_wire_code_checks_code_grammar() {
        assert!(starts_with_audit_wire_code("audit.outbox_full: cap"));
        assert!(starts_with_audit_wire_code("audit.code_2: detail"));
        assert!(!starts_with_audit_wire_code("other: detail"));
        assert!(!starts_with_audit_wire_code("policy.pin_absent: detail"));
        assert!(!starts_with_audit_wire_code("audit.outbox_full"));
        assert!(!starts_with_audit_wire_code("audit.: detail"));
        assert!(!starts_with_audit_wire_code("audit.BadCode: detail"));
        assert!(!starts_with_audit_wire_code("audit.has space: detail"));
    }
}
