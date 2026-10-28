//! `stellar-agent approve --id <nonce> --profile <name>`: interactive y/n for a pending approval.
//!
//! Fetches the pending approval entry from the on-disk store, renders a
//! wallet-controlled summary to stderr (NOT the agent's rendering, and NOT
//! stdout — stdout is reserved for the single terminal JSON envelope), reads
//! y/n from stdin, and on approval:
//!
//! - For `PaymentSimulated`, `ClaimSimulated`, `TrustlineSimulated`, and
//!   `MppChargeSimulated`: computes the HMAC-SHA256 attestation blob and
//!   persists it via `PendingApprovalStore::record_attestation`.
//! - For `ToolsetFirstInvokeGate`: builds a `ToolsetGrant`, persists it to the
//!   grant store, and CONSUMES (removes) the pending entry.
//!
//! # Security properties
//!
//! 1. **Wallet-controlled rendering** — the summary is produced by this
//!    command, not forwarded from agent output. A payment, claim, or trustline
//!    summary is decoded from the envelope whose digest the attestation binds,
//!    so the operator sees the transaction an approval signs; an entry whose
//!    digest does not name its envelope is refused before the prompt. Every
//!    untrusted value is rendered with control characters escaped.
//!
//! 2. **Cross-account-on-host non-replay** — `process_uid_for_attestation()`
//!    is re-derived at CLI time and compared to `entry.process_uid` stored at
//!    simulate time.  A different local user cannot produce a valid attestation.
//!
//! 3. **Indistinguishability for the MCP commit path** — the MCP `_commit`
//!    verifier collapses absent/expired/forged errors to the same
//!    `policy.approval_required` code.  This CLI layer surfaces
//!    distinguishable errors to the user (UX clarity is not a security leak
//!    here — the user is the wallet owner).
//!
//! # Output (JSON envelope)
//!
//! On success:
//!
//! ```json
//! {
//!   "ok": true,
//!   "data": {
//!     "approval_nonce": "ABCxyzNonce",
//!     "attested": true,
//!     "process_uid": "501",
//!     "expires_at_unix_ms": 1717000000000,
//!     "approval_attestation": "Base64UrlNoPadBlob"
//!   },
//!   "request_id": "..."
//! }
//! ```
//!
//! `approval_attestation` is present only for payment-style approvals, where the
//! commit step verifies a caller-presented attestation; it is omitted for toolset
//! first-invoke grants and trustline clawback opt-ins.
//!
//! # Exit codes
//!
//! - `0` — approved and attested.
//! - `1` — denied, expired, not found, user mismatch, or I/O error.
//!
//! This is the `approve --id <nonce> --profile <name>` CLI path of the wallet-owned approval spine.

use std::io::{BufRead as _, Write};
use std::path::PathBuf;
use std::time::{Duration, UNIX_EPOCH};

use clap::Args;
use serde::Serialize;

use stellar_agent_core::amount::StellarAmount;
use stellar_agent_core::approval::view::format_trustline_limit;
use stellar_agent_core::approval::{
    ApprovalKind, ApproverIdentity, ConsentAudit, ContextRuleProposalSnapshot,
    DEFAULT_RETRY_ATTEMPTS, DEFAULT_RETRY_BACKOFF, PendingApproval, PendingApprovalStore,
    RuleProposalContextType, RuleProposalSignerKind, Surface, ToolsetGrantRequest,
    attest_and_persist, classic_entry_summary, load_and_validate_entry, load_attestation_key,
    open_with_retry, process_uid_for_attestation, try_decode_spending_limit_params,
};
use stellar_agent_core::envelope::Envelope;
use stellar_agent_core::envelope_decode::ClassicOperation;
use stellar_agent_core::error::{ApprovalFailure, ValidationError, WalletError};
use stellar_agent_core::profile::schema::Profile;
use stellar_agent_core::timefmt;
use stellar_agent_network::keyring::init_platform_keyring_store;

use crate::common::consent::{ConsentSink, acquire_consent_sink};
use crate::common::profile_access::{load_profile_reconciled, profile_access_envelope};
use crate::common::{render, resolve_profile_name};

/// Arguments for `stellar-agent approve --id <nonce> --profile <name>`.
///
/// # Examples
///
/// ```text
/// stellar-agent approve --id ABCxyzNonce --profile <name>
/// stellar-agent approve --id ABCxyzNonce --profile myprofile --yes
/// ```
#[derive(Debug, Args)]
#[non_exhaustive]
pub struct RunArgs {
    /// Approval nonce as printed in the MCP simulate response.
    #[arg(long = "id", value_name = "NONCE", allow_hyphen_values = true)]
    pub id: Option<String>,

    /// Profile name (default: `"default"` or `STELLAR_AGENT_PROFILE` env var).
    #[arg(long = "profile", value_name = "NAME")]
    pub profile: Option<String>,

    /// Non-interactive auto-approve (for scripting and tests).
    ///
    /// Bypasses the tty prompt.  Use only in trusted automation flows.
    /// In production, prefer the interactive form to get wallet-controlled
    /// rendering before attesting.
    ///
    /// # Security implication
    ///
    /// With `--yes`, the command immediately approves without reading from
    /// stdin.  The wallet-controlled summary is still printed to stderr so
    /// there is a visible record (stdout stays reserved for the JSON envelope),
    /// but no human confirmation is required.
    /// This mode is intended for integration tests and CI pipelines operating
    /// in a controlled, trusted environment.
    #[arg(long = "yes")]
    pub yes: bool,
}

/// Success payload for the `approve --id <nonce> --profile <name>` JSON envelope.
#[derive(Debug, Serialize)]
struct ApproveRunData {
    /// The approval nonce that was attested.
    approval_nonce: String,
    /// Always `true` on success (the approval was attested).
    attested: bool,
    /// Platform-stable user identity that was bound into the attestation.
    ///
    /// Numeric UID on Unix (e.g. `"501"`); `"non-unix-stub"` on non-Unix.
    process_uid: String,
    /// Unix epoch timestamp (milliseconds) when the approval expires.
    expires_at_unix_ms: u64,
    /// The HMAC-SHA256 attestation blob (URL-safe base64, no padding) that the
    /// agent surface must present as `approval_attestation` when it calls the
    /// matching `*_commit` tool for this approval.
    ///
    /// Present only for payment-style approvals whose commit step verifies a
    /// caller-presented attestation. Absent for toolset first-invoke grants and
    /// trustline clawback opt-ins, whose gates read the recorded consent from
    /// the store directly and take no attestation argument.
    #[serde(skip_serializing_if = "Option::is_none")]
    approval_attestation: Option<String>,
    /// Where the consent row went: `"written"` to the audit log, or `"queued"`
    /// in the audit outbox for the draining writer of a running MCP server or
    /// approval inbox.
    audit: ConsentRowOutcome,
}

/// Runs `stellar-agent approve --id <nonce> --profile <name>`.
///
/// Returns `0` on approval and attestation, `1` on any error or denial.
///
/// # Errors
///
/// Never returns `Err` — errors are captured into the exit code and JSON
/// envelope.
///
/// # Panics
///
/// Never panics.
pub async fn run(args: RunArgs) -> i32 {
    // ── 1. Require --id ───────────────────────────────────────────────────────
    let nonce = match &args.id {
        Some(n) if !n.is_empty() => n.clone(),
        _ => {
            let err = WalletError::Validation(ValidationError::ProfileNotFound {
                name: "--id <NONCE> is required for `stellar-agent approve`".to_owned(),
            });
            render::render_json(&Envelope::<()>::err(&err));
            return 1;
        }
    };

    // ── 2. Resolve profile name ───────────────────────────────────────────────
    let resolved_profile = resolve_profile_name(args.profile.as_deref());
    let profile_name = resolved_profile.name.clone();

    // ── 3. Load the profile for keyring entry ref ─────────────────────────────
    // Reconciled: the attestation and approval-store coordinates below come
    // from this file, so a file that names another profile is refused here
    // rather than used to attest under a name it does not own.
    let profile = match load_profile_reconciled(&resolved_profile) {
        Ok(p) => p,
        Err(e) => {
            tracing::debug!(profile = %profile_name, error = %e, "profile access refused");
            render::render_json(&profile_access_envelope(&e, &profile_name));
            return 1;
        }
    };

    // ── 3a. The mainnet rule: no --yes, and a terminal for the y/n prompt ───
    // Before the store opens, so a refused approval leaves it untouched.
    if let Err(envelope) = mainnet_approve_rule(&profile, args.yes) {
        render::render_json(&envelope);
        return 1;
    }

    let context =
        stellar_agent_core::approval::ApprovalContext::from_profile(&profile_name, &profile);

    // ── 4. Open the pending-approval store ───────────────────────────────────
    let store_path = match build_store_path(&profile_name) {
        Ok(p) => p,
        Err(e) => {
            render::render_json(&Envelope::<()>::err(&e));
            return 1;
        }
    };

    let mut store =
        match open_with_retry(&store_path, DEFAULT_RETRY_ATTEMPTS, DEFAULT_RETRY_BACKOFF) {
            Ok(s) => s,
            Err(e) => {
                let err = super::common::approval_store_open_error(&e);
                render::render_json(&Envelope::<()>::err(&err));
                return 1;
            }
        };

    // ── 5. Derive process_uid and validate the stored entry ──────────────────
    let our_uid = match process_uid_for_attestation() {
        Ok(uid) => uid,
        Err(e) => {
            let err = WalletError::Approval(ApprovalFailure::UidUnavailable {
                detail: format!("process UID derivation failed: {e}"),
            });
            render::render_json(&Envelope::<()>::err(&err));
            return 1;
        }
    };

    let identity = ApproverIdentity::OsUid(our_uid.clone());
    // The CLI only ever constructs an `OsUid` identity, so the allowlist is
    // never consulted; pass an empty slice.
    let entry = match load_and_validate_entry(&store, &nonce, &identity, &[]) {
        Ok(entry) => entry,
        Err(e) => {
            render::render_json(&Envelope::<()>::err(&e));
            return 1;
        }
    };

    // ── 6. Render wallet-controlled summary and read y/n ─────────────────────
    match prompt_approval(&entry, &context, args.yes) {
        Ok(true) => {}
        Ok(false) => {
            let err = WalletError::Approval(ApprovalFailure::Denied {
                detail: "user declined the pending approval".to_owned(),
            });
            render::render_json(&Envelope::<()>::err(&err));
            return 1;
        }
        Err(e) => {
            render::render_json(&Envelope::<()>::err(&e));
            return 1;
        }
    }

    // ── 7. Load attestation key from keyring ──────────────────────────────────
    if let Err(e) = init_platform_keyring_store() {
        render::render_json(&Envelope::<()>::err(&e));
        return 1;
    }

    let entry_ref = &profile.attestation_key_id;
    let owner = stellar_agent_core::profile::owner_key::OwnerKeyContext::for_profile(
        &profile_name,
        &profile,
    );
    let key_bytes = match load_attestation_key(entry_ref, &owner) {
        Ok(k) => k,
        Err(e) => {
            render::render_json(&Envelope::<()>::err(&e));
            return 1;
        }
    };

    // ── 8. Write the consent row, then persist the attestation ──────────────
    // The row is written through this process's writer, or queued for the
    // draining writer of another process, before anything is persisted. Any
    // audit refusal refuses the approval with nothing persisted.
    let (approval_attestation, audit) =
        match approve_with_consent_row(&mut store, &entry, &key_bytes, &context, &profile) {
            Ok(approved) => approved,
            Err(e) => {
                render::render_json(&Envelope::<()>::err(&e));
                return 1;
            }
        };

    // key_bytes is Zeroizing; erased on drop after this point.

    // ── 9. Emit success envelope ──────────────────────────────────────────────
    render::render_json(&Envelope::ok(ApproveRunData {
        approval_nonce: nonce,
        attested: true,
        process_uid: our_uid,
        expires_at_unix_ms: entry.expires_at_unix_ms,
        approval_attestation,
        audit,
    }));
    0
}

/// Where `approve --id` wrote its consent row, reported as the success
/// envelope's `audit` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ConsentRowOutcome {
    /// Appended to the audit log through this process's writer.
    Written,
    /// Queued in the audit outbox for the draining writer of another process,
    /// which appends it before any process loads a signing key for the
    /// approved action.
    Queued,
}

/// Writes the consent row and persists the approval, in that order.
///
/// # Errors
///
/// The acquisition refusal of [`acquire_consent_sink`], a poisoned writer
/// mutex, or any error of `attest_and_persist`. Nothing is persisted when the
/// row is refused.
fn approve_with_consent_row(
    store: &mut PendingApprovalStore,
    entry: &PendingApproval,
    key_bytes: &[u8],
    context: &stellar_agent_core::approval::ApprovalContext,
    profile: &Profile,
) -> Result<(Option<String>, ConsentRowOutcome), WalletError> {
    let profile_name = context.profile_name.as_str();
    let persist_grant = |req: &ToolsetGrantRequest<'_>, key: &[u8; 32]| {
        stellar_agent_toolsets_runtime::record_first_invoke_grant(
            profile_name,
            req.toolset_name,
            req.capability,
            req.destination,
            req.asset,
            req.amount_min_stroops,
            req.amount_max_stroops,
            req.process_uid,
            req.now_unix_ms,
            key,
            req.binding,
            None, // No grant-store-path override in the production CLI approve path.
        )
        .map(|_grant| ())
        .map_err(|e| e.to_string())
    };
    match acquire_consent_sink(profile, profile_name)? {
        ConsentSink::Writer(writer) => {
            let mut guard = writer.lock().map_err(|_| {
                tracing::error!(
                    event_kind = "approval_attested",
                    "approve: audit writer mutex poisoned; refusing the approval"
                );
                WalletError::Validation(ValidationError::AuditWriterOpenFailed {
                    profile: profile_name.to_owned(),
                })
            })?;
            let attestation = attest_and_persist(
                store,
                entry,
                key_bytes,
                &context.binding(),
                Surface::Cli,
                ConsentAudit::Writer(&mut guard),
                None,
                persist_grant,
            )?;
            Ok((attestation, ConsentRowOutcome::Written))
        }
        ConsentSink::Outbox(outbox) => {
            let attestation = attest_and_persist(
                store,
                entry,
                key_bytes,
                &context.binding(),
                Surface::Cli,
                ConsentAudit::Outbox(&outbox),
                None,
                persist_grant,
            )?;
            Ok((attestation, ConsentRowOutcome::Queued))
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Private helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Refuses an approval of a pending entry on a mainnet profile that the
/// operator cannot answer at a terminal.
///
/// `--yes` is refused first, then a missing terminal on stdin or stderr. A
/// testnet profile passes without a terminal check, `--yes` included.
///
/// # Errors
///
/// `approve.yes_refused_on_mainnet` for `--yes` on a mainnet profile, and
/// `confirm.tty_required` on a mainnet profile without a terminal.
fn mainnet_approve_rule(profile: &Profile, yes: bool) -> Result<(), Envelope<()>> {
    if !profile.chain_id.is_mainnet() {
        return Ok(());
    }
    if yes {
        return Err(Envelope::<()>::err_raw(
            "approve.yes_refused_on_mainnet",
            "approve --yes is refused on a mainnet profile; run approve on a terminal and \
             answer the prompt",
        ));
    }
    crate::common::tty::require_tty_for_mainnet().map_err(|e| Envelope::<()>::err(&e))
}

/// Builds the store path for `<profile>` as `<approval_dir>/<profile>.toml`.
fn build_store_path(profile_name: &str) -> Result<PathBuf, WalletError> {
    let dir = super::common::approval_store_dir()?;
    Ok(dir.join(format!("{profile_name}.toml")))
}

/// Renders the summary, then asks for consent.
///
/// A classic entry that fails [`classic_entry_summary`] is refused with
/// `approval.entry_inconsistent` after its summary, before any prompt and
/// whatever `auto_approve` says.
fn prompt_approval(
    entry: &PendingApproval,
    context: &stellar_agent_core::approval::ApprovalContext,
    auto_approve: bool,
) -> Result<bool, WalletError> {
    render_summary(entry, context);
    stellar_agent_core::approval::mpp::verify_mpp_entry_terms(&entry.kind)?;
    if let Some(Err(error)) = classic_entry_summary(&entry.kind) {
        return Err(error);
    }
    if auto_approve {
        return Ok(true);
    }
    Ok(prompt_yn())
}

/// Renders the FULL resolved rule definition of a `RuleProposalSimulated`
/// entry: context type (with a prominent account-wide-authority callout for
/// `Default`), name, expiry, every signer (kind, address/verifier, the FULL
/// pubkey hex — not a prefix, so it is meaningfully verifiable against the
/// digest bound into `proposal_sha256` — and a PROPOSER tag), every policy
/// (typed params where recognized, else the raw base64 XDR params string),
/// `auth_rule_ids`, and the two override warning lines when set. Shared by
/// every approval surface's textual rendering (CLI `run.rs`; the
/// loopback/remote HTML templates render the same fields via their own
/// markup, not this fn).
fn render_rule_proposal_definition(definition: &ContextRuleProposalSnapshot) -> String {
    use render::escape_for_terminal as esc;
    let mut lines = Vec::new();

    match &definition.context_type {
        RuleProposalContextType::Default => {
            lines.push(
                "  Context:           Default\n  \
                 WARNING: Default context grants ACCOUNT-WIDE AUTHORITY — \
                 this rule authorizes ANY contract invocation, not a scoped \
                 subset."
                    .to_owned(),
            );
        }
        RuleProposalContextType::CallContract { contract } => {
            lines.push(format!(
                "  Context:           CallContract {}",
                esc(contract)
            ));
        }
        RuleProposalContextType::CreateContract { wasm_hash_hex } => {
            lines.push(format!(
                "  Context:           CreateContract (wasm hash) {}",
                esc(wasm_hash_hex)
            ));
        }
        // RuleProposalContextType is #[non_exhaustive]; a future variant
        // renders with a minimal fallback rather than aborting the approval
        // flow — the operator still sees every other field.
        other => {
            lines.push(format!(
                "  Context:           (unrecognized: {})",
                esc(&format!("{other:?}"))
            ));
        }
    }

    lines.push(format!("  Rule name:         {}", esc(&definition.name)));
    let expiry = match definition.valid_until {
        Some(ledger) => format!("expires at ledger {ledger}"),
        None => "permanent (no expiry)".to_owned(),
    };
    lines.push(format!("  Expiry:            {expiry}"));

    lines.push(format!("  Signers ({}):", definition.signers.len()));
    for (idx, signer) in definition.signers.iter().enumerate() {
        let proposer_tag = if signer.is_proposer {
            "  [PROPOSER]"
        } else {
            ""
        };
        let detail = match signer.kind {
            RuleProposalSignerKind::Delegated => {
                let address = signer.address.as_deref().unwrap_or("<missing address>");
                format!("Delegated  {}", esc(address))
            }
            RuleProposalSignerKind::External => {
                let verifier = signer.verifier.as_deref().unwrap_or("<missing verifier>");
                // WYSIWYS: the FULL pubkey is rendered — not a prefix — so
                // the operator can meaningfully verify it against the
                // signer bytes bound into proposal_sha256.
                let pubkey_hex = signer
                    .pubkey_data
                    .as_deref()
                    .map(|bytes| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>())
                    .unwrap_or_else(|| "<none>".to_owned());
                format!("External   verifier={} pubkey={pubkey_hex}", esc(verifier))
            }
        };
        lines.push(format!("    [{idx}] {detail}{proposer_tag}"));
    }

    if definition.policies.is_empty() {
        lines.push("  Policies:          (none)".to_owned());
    } else {
        lines.push(format!("  Policies ({}):", definition.policies.len()));
        for (idx, policy) in definition.policies.iter().enumerate() {
            let detail = match try_decode_spending_limit_params(&policy.params_xdr_b64) {
                Some(decoded) => {
                    // limit_stroops is i128 on-chain; StellarAmount::from_stroops
                    // takes i64. A limit outside i64 range (astronomically
                    // larger than total XLM supply) falls back to a bare
                    // stroops figure rather than panicking or truncating.
                    let limit_display = match i64::try_from(decoded.limit_stroops) {
                        Ok(stroops_i64) => format!(
                            "{} XLM ({} stroops)",
                            StellarAmount::from_stroops(stroops_i64).as_xlm_decimal_string(),
                            decoded.limit_stroops
                        ),
                        Err(_) => format!("{} stroops", decoded.limit_stroops),
                    };
                    format!(
                        "spending-limit: {limit_display} / {} ledgers",
                        decoded.period_ledgers
                    )
                }
                // WYSIWYS: an unrecognized policy still must show what the
                // operator is actually attesting to, not just its byte
                // count. The base64 XDR string is size-bounded (OZ policy
                // install params) so truncation is not a concern here.
                None => format!("(raw XDR params) {}", esc(&policy.params_xdr_b64)),
            };
            lines.push(format!(
                "    [{idx}] {policy_address}  {detail}",
                policy_address = esc(&policy.policy_address)
            ));
        }
    }

    lines.push(format!(
        "  Auth rule IDs:     {:?}",
        definition.auth_rule_ids
    ));

    if definition.accept_mutable_verifier {
        lines.push(
            "  WARNING: accept_mutable_verifier is set — a mutable verifier/policy \
             contract will NOT block install."
                .to_owned(),
        );
    }
    if definition.accept_unknown_verifier {
        lines.push(
            "  WARNING: accept_unknown_verifier is set — an unrecognized \
             verifier/policy wasm hash will NOT block install."
                .to_owned(),
        );
    }

    lines.join("\n")
}

/// Writes the wallet-controlled approval summary to `out`.
///
/// Formats the pending approval details in a human-readable block. Production
/// wires `out` to stderr (see [`render_summary`]) so stdout carries only the
/// single terminal JSON envelope; factored out so the block formatting is
/// unit-testable against an in-memory sink.
///
/// Every kind opens with the context's profile, network, endpoint, and signer
/// rows. A payment, claim, or trustline entry is rendered from its envelope
/// through [`classic_entry_summary`]: the effective source, every amount,
/// asset, destination, memo, fee and sequence number are the envelope's, and
/// the entry's stored `summary_*` fields are not read. An entry that fails
/// that check renders as inconsistent and is never prompted for. Every value
/// that does not come from this command passes through
/// [`render::escape_for_terminal`], so a control or direction-override
/// character shows as an escape instead of acting on the terminal.
#[allow(
    clippy::too_many_lines,
    reason = "one arm per approval kind, each rendering every field it consents to"
)]
fn write_summary(
    entry: &PendingApproval,
    context: &stellar_agent_core::approval::ApprovalContext,
    out: &mut dyn Write,
) -> std::io::Result<()> {
    use render::escape_for_terminal as esc;

    writeln!(out, "  Profile:           {}", esc(&context.profile_name))?;
    writeln!(out, "  Network:           {}", esc(&context.chain_id))?;
    writeln!(out, "  Endpoint:          {}", esc(&context.endpoint_host))?;
    writeln!(
        out,
        "  Signer:            {}",
        esc(context
            .signer_account
            .as_deref()
            .unwrap_or("(not enrolled)"))
    )?;
    let classic = match stellar_agent_core::approval::mpp::verify_mpp_entry_terms(&entry.kind) {
        Ok(()) => classic_entry_summary(&entry.kind),
        Err(error) => Some(Err(error)),
    };
    if let Some(Ok(summary)) = &classic {
        writeln!(out, "  Source:            {}", esc(&summary.source))?;
    }
    if let Some(reason) = &entry.reason {
        writeln!(out, "Reason: {}", esc(reason))?;
    }
    let created = unix_ms_to_rfc3339(entry.created_at_unix_ms);
    let expires = unix_ms_to_rfc3339(entry.expires_at_unix_ms);

    let body = match (&entry.kind, classic) {
        (_, Some(Err(error))) => format!(
            "  Kind:              {}\n  \
             INCONSISTENT:      {}\n  \
             {}",
            entry.kind.kind_name(),
            esc(&error.message()),
            stellar_agent_approval_ui::INCONSISTENT_MESSAGE,
        ),
        (_, Some(Ok(summary))) => {
            let fee = summary.fee_stroops;
            let seq = summary.seq_num;
            let memo = esc(&summary.memo.display());
            match &summary.operation {
                ClassicOperation::Payment {
                    destination,
                    asset,
                    amount_stroops,
                } => {
                    let memo = esc(&summary.memo.display());
                    format!(
                        "  To:                {to}\n  \
                         Amount:            {amount}\n  \
                         Asset:             {asset}\n  \
                         Memo:              {memo}\n  \
                         Simulated fee:     {fee} stroops\n  \
                         Simulated seq num: {seq}",
                        to = esc(destination),
                        amount = stroop_amount(*amount_stroops, asset),
                        asset = esc(asset),
                    )
                }
                ClassicOperation::PathPayment {
                    destination,
                    send_asset,
                    send_amount_stroops,
                    dest_asset,
                    dest_amount_stroops,
                } => {
                    let memo = esc(&summary.memo.display());
                    format!(
                        "  Kind:              path payment\n  \
                         To:                {to}\n  \
                         Amount:            {amount} at most\n  \
                         Asset:             {asset}\n  \
                         Receives:          {receives} at least\n  \
                         Receives asset:    {receives_asset}\n  \
                         Memo:              {memo}\n  \
                         Simulated fee:     {fee} stroops\n  \
                         Simulated seq num: {seq}",
                        to = esc(destination),
                        amount = stroop_amount(*send_amount_stroops, send_asset),
                        asset = esc(send_asset),
                        receives = stroop_amount(*dest_amount_stroops, dest_asset),
                        receives_asset = esc(dest_asset),
                    )
                }
                ClassicOperation::CreateAccount {
                    destination,
                    starting_balance_stroops,
                } => {
                    let memo = esc(&summary.memo.display());
                    format!(
                        "  To:                {to}\n  \
                         Amount:            {amount}\n  \
                         Asset:             XLM\n  \
                         Memo:              {memo}\n  \
                         Simulated fee:     {fee} stroops\n  \
                         Simulated seq num: {seq}",
                        to = esc(destination),
                        amount = stroop_amount(*starting_balance_stroops, "XLM"),
                    )
                }
                ClassicOperation::ChangeTrust {
                    asset_code,
                    asset_issuer,
                    limit_stroops,
                } => {
                    let mut limit = format_trustline_limit(*limit_stroops);
                    if let Some(n) = limit_stroops.filter(|n| *n != 0) {
                        limit.push_str(&format!(
                            " ({} {})",
                            StellarAmount::from_stroops(n).as_xlm_decimal_string(),
                            esc(asset_code)
                        ));
                    }
                    format!(
                        "  Kind:              trustline change (ChangeTrust)\n  \
                         Account:           {holder}\n  \
                         Asset:             {code}:{issuer}\n  \
                         Limit:             {limit}\n  \
                         Memo:              {memo}\n  \
                         Simulated fee:     {fee} stroops\n  \
                         Simulated seq num: {seq}",
                        holder = esc(&summary.source),
                        code = esc(asset_code),
                        issuer = esc(asset_issuer),
                    )
                }
                ClassicOperation::ClaimClaimableBalance {
                    balance_id_hex72,
                    balance_id_strkey,
                } => format!(
                    "  Kind:              ClaimSimulated\n  \
                     Balance ID:        {strkey}\n  \
                     Balance ID (hex):  {hex}\n  \
                     Asset:             {CLAIM_VALUE_NOTE}\n  \
                     Amount:            {CLAIM_VALUE_NOTE}\n  \
                     Memo:              {memo}\n  \
                     Simulated fee:     {fee} stroops\n  \
                     Simulated seq num: {seq}",
                    strkey = esc(balance_id_strkey),
                    hex = esc(balance_id_hex72),
                ),
                other => format!(
                    "  Kind:              {}\n  \
                     Terms:             this build cannot show this operation ({other:?})",
                    entry.kind.kind_name()
                ),
            }
        }
        (
            ApprovalKind::SignWithPasskey {
                smart_account_redacted,
                rule_ids,
                ..
            },
            None,
        ) => {
            format!(
                "  Kind:              SignWithPasskey\n  \
                 Smart account:     {}\n  \
                 Rule IDs:          {rule_ids:?}",
                esc(smart_account_redacted)
            )
        }
        (
            ApprovalKind::RegisterPasskey {
                smart_account_redacted,
                rule_ids,
                ..
            },
            None,
        ) => format!(
            "  Kind:              RegisterPasskey\n  \
             Smart account:     {}\n  \
             Rule IDs:          {rule_ids:?}",
            esc(smart_account_redacted)
        ),
        (ApprovalKind::Rejected { original_kind_name }, None) => format!(
            "  Kind:              Rejected ({})",
            esc(original_kind_name)
        ),
        (
            ApprovalKind::Consumed {
                original_kind_name, ..
            },
            None,
        ) => format!(
            "  Kind:              Consumed ({})",
            esc(original_kind_name)
        ),
        (
            ApprovalKind::ToolsetFirstInvokeGate {
                toolset_name,
                capability,
                destination,
                asset,
                amount_min_stroops,
                amount_max_stroops,
            },
            None,
        ) => {
            // Redact destination to first-5-last-5.
            // Fields are rendered from VALIDATED STORED values — never from
            // agent-relayed content (wallet-owned rendering).
            let dest_redacted = if destination.len() >= 10 {
                format!(
                    "{}...{}",
                    &destination[..5],
                    &destination[destination.len() - 5..]
                )
            } else {
                "<redacted>".to_owned()
            };
            format!(
                "  Kind:              ToolsetFirstInvokeGate\n  \
                 Toolset:           {toolset}\n  \
                 Capability:        {capability}\n  \
                 Destination:       {dest}\n  \
                 Asset:             {asset_text}\n  \
                 Amount max:        {amount_max}\n  \
                 Amount min:        {amount_min_stroops} stroops",
                toolset = esc(toolset_name),
                capability = esc(capability),
                dest = esc(&dest_redacted),
                asset_text = esc(asset),
                amount_max = stroop_amount(*amount_max_stroops, asset),
            )
        }
        (
            ApprovalKind::TrustlineClawbackOptIn {
                network,
                code,
                issuer,
            },
            None,
        ) => {
            // Redact issuer G-strkey to first-5-last-5.
            let issuer_redacted = if issuer.len() >= 10 {
                format!("{}...{}", &issuer[..5], &issuer[issuer.len() - 5..])
            } else {
                "<redacted>".to_owned()
            };
            format!(
                "  Kind:              TrustlineClawbackOptIn\n  \
                 Network:           {}\n  \
                 Asset code:        {}\n  \
                 Issuer:            {}\n  \
                 WARNING: This issuer has AUTH_CLAWBACK_ENABLED set.\n    \
                 The issuer may reclaim tokens from this trustline.",
                esc(network),
                esc(code),
                esc(&issuer_redacted)
            )
        }
        (
            ApprovalKind::RuleProposalSimulated {
                smart_account_redacted,
                chain_id,
                definition,
                proposal_sha256,
                ..
            },
            None,
        ) => {
            let digest_hex: String = proposal_sha256.iter().map(|b| format!("{b:02x}")).collect();
            format!(
                "  Kind:              RuleProposalSimulated\n  \
                 Smart account:     {}\n  \
                 Chain ID:          {}\n\
                 {body}\n  \
                 Proposal digest:   {digest_hex}",
                esc(smart_account_redacted),
                esc(chain_id),
                body = render_rule_proposal_definition(definition),
            )
        }
        (
            ApprovalKind::MppChargeSimulated {
                profile,
                chain_id,
                payer,
                transport,
                authority,
                target,
                amount,
                currency,
                recipient,
                challenge_expires_at_unix,
                simulated_fee_stroops,
                ..
            },
            None,
        ) => format!(
            "  Kind:              MppChargeSimulated\n  \
             Profile:           {}\n  \
             Network:           {}\n  \
             Payer:             {}\n  \
             Transport:         {}\n  \
             Authority:         {}\n  \
             Target:            {}\n  \
             Amount:            {} base units of the token contract\n  \
             Token contract:    {}\n  \
             Recipient:         {}\n  \
             Challenge expires: {challenge_expires_at_unix} (Unix seconds)\n  \
             Simulated fee:     {simulated_fee_stroops} stroops ({})",
            esc(profile),
            esc(chain_id),
            esc(payer),
            esc(transport),
            esc(authority),
            esc(target),
            esc(amount),
            esc(currency),
            esc(recipient),
            stellar_agent_approval_ui::SIMULATED_FEE_NOTE,
        ),
        (
            ApprovalKind::X402Payment {
                root_invocation_xdr,
                home_domain,
                ..
            },
            None,
        ) => {
            use stellar_xdr::{
                ReadXdr as _, ScVal, SorobanAuthorizedFunction, SorobanAuthorizedInvocation,
            };
            let decoded = SorobanAuthorizedInvocation::from_xdr_base64(
                root_invocation_xdr,
                stellar_agent_xdr_limits::untrusted_decode_limits(root_invocation_xdr.len()),
            );
            let details = decoded
                .ok()
                .and_then(|root| {
                    let SorobanAuthorizedFunction::ContractFn(function) = root.function else {
                        return None;
                    };
                    if function.function_name.0.as_slice() != b"transfer" {
                        return None;
                    }
                    let [
                        ScVal::Address(_),
                        ScVal::Address(payee),
                        ScVal::I128(amount),
                    ] = function.args.as_slice()
                    else {
                        return None;
                    };
                    let amount = (i128::from(amount.hi) << 64) | i128::from(amount.lo);
                    Some(format!(
                        "  Payee: {payee}\n  Amount: {amount}\n  Asset: {}",
                        function.contract_address
                    ))
                })
                .unwrap_or_else(|| "  Invocation cannot be decoded".to_owned());
            format!(
                "  Kind: X402Payment\n{details}\n  Home domain: {}",
                esc(home_domain.as_deref().unwrap_or("none"))
            )
        }
        (other, _) => {
            // ApprovalKind is #[non_exhaustive]; a future variant renders its
            // kind name and says that its terms cannot be shown. The CLI never
            // attests an unknown kind (attest_and_persist's match also catches
            // unknown variants and returns wrong-kind).
            format!(
                "  Kind:              {}\n  \
                 Terms:             this build cannot show the terms of this kind",
                other.kind_name()
            )
        }
    };

    let summary = format!(
        "\nPending approval\n\
         \n\
         {indent}Approval nonce:    {nonce}\n\
         {body}\n\
         {indent}Created at:        {created}\n\
         {indent}Expires at:        {expires}\n",
        indent = "  ",
        nonce = esc(&entry.approval_nonce),
        body = body,
        created = created,
        expires = expires,
    );

    write!(out, "{summary}")
}

/// What a claim summary shows for the balance's asset and amount: the claim
/// transaction names the balance by id only.
const CLAIM_VALUE_NOTE: &str = "not part of the signed claim transaction";

/// An amount in stroops: `"<decimal> XLM (<n> stroops)"` for XLM, else
/// `"<n> stroops"`.
fn stroop_amount(amount_stroops: i64, asset: &str) -> String {
    if asset == "XLM" {
        format!(
            "{} XLM ({amount_stroops} stroops)",
            StellarAmount::from_stroops(amount_stroops).as_xlm_decimal_string()
        )
    } else {
        format!("{amount_stroops} stroops")
    }
}

/// Renders the wallet-controlled approval summary to stderr.
///
/// Thin production wrapper over [`write_summary`]: routes the human-readable
/// block to STDERR so STDOUT carries only the single terminal JSON envelope
/// (the documented programmatic contract — `approve ... > out.json` must yield
/// exactly one parseable envelope). Always called regardless of `--yes` so
/// there is a visible record.
fn render_summary(
    entry: &PendingApproval,
    context: &stellar_agent_core::approval::ApprovalContext,
) {
    let mut err = std::io::stderr();
    // The summary is advisory; the JSON envelope on stdout is the authoritative
    // result, so a stderr write failure must not abort the approval.
    let _ = write_summary(entry, context, &mut err);
    // Flush stderr so the summary is visible before the prompt blocks on read.
    let _ = err.flush();
}

/// Prompts `Approve? [y/N]: ` on stderr and reads a line from stdin.
///
/// Accepts `y`, `Y`, or `yes` (case-insensitive prefix of `"yes"`).
/// Everything else (including empty input, `n`, `N`, EOF) is treated as denial.
/// No external prompt crate; uses `std::io::stdin().lock().read_line`.
fn prompt_yn() -> bool {
    #[allow(
        clippy::print_stderr,
        reason = "CLI binary intentional user output — y/n prompt on stderr"
    )]
    {
        eprint!("Approve? [y/N]: ");
    }
    // Flush stderr so the prompt appears before blocking on read.
    let _ = std::io::stderr().flush();

    let mut line = String::new();
    match std::io::stdin().lock().read_line(&mut line) {
        Ok(0) => false, // EOF
        Ok(_) => {
            let trimmed = line.trim().to_ascii_lowercase();
            trimmed == "y" || trimmed == "yes"
        }
        Err(_) => false, // I/O error → deny
    }
}

/// Formats a Unix-epoch-millisecond timestamp as an RFC 3339 date-time string.
///
/// Falls back to `"<timestamp> ms"` if the system time conversion overflows.
fn unix_ms_to_rfc3339(unix_ms: u64) -> String {
    // Saturating conversion: very large values clamp to u64::MAX seconds.
    let secs = unix_ms / 1_000;
    let nanos = ((unix_ms % 1_000) * 1_000_000) as u32;

    let Some(dt) = UNIX_EPOCH.checked_add(Duration::new(secs, nanos)) else {
        return format!("{unix_ms} ms");
    };
    timefmt::format_rfc3339_utc(dt)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use clap::Parser;
    use keyring_core::Entry as KeyringEntry;
    use serial_test::serial;
    use stellar_agent_core::approval::{
        ApprovalError, ApprovalKind, DEFAULT_TTL_MS, PendingApproval, PendingApprovalStore,
        attestation::compute_attestation, decode_sha256_hex, fixtures, process_uid_for_attestation,
    };
    use stellar_agent_core::error::AuthError;
    use stellar_agent_core::profile::schema::KeyringEntryRef;
    use stellar_agent_test_support::{StellarAgentHomeGuard, keyring_mock};
    use tempfile::TempDir;

    #[derive(Parser)]
    struct Harness {
        #[command(flatten)]
        approve: crate::commands::approve::ApproveArgs,
    }

    #[test]
    fn parses_hyphen_prefixed_approval_nonce() {
        let nonce = "-AbCdEfGhIjKlMnOpQrStU";
        let parsed = Harness::try_parse_from(["approve", "--id", nonce, "--profile", "p"])
            .expect("hyphen-prefixed nonce parses");
        assert_eq!(parsed.approve.run.id.as_deref(), Some(nonce));
        assert_eq!(parsed.approve.run.profile.as_deref(), Some("p"));
        assert!(parsed.approve.subcommand.is_none());

        let parsed = Harness::try_parse_from(["approve", "--id", "--yes"])
            .expect("the next token is the nonce");
        assert_eq!(parsed.approve.run.id.as_deref(), Some("--yes"));
        assert!(!parsed.approve.run.yes);
    }

    fn test_context() -> stellar_agent_core::approval::ApprovalContext {
        let profile = stellar_agent_core::profile::schema::Profile::builder_testnet(
            "svc", "default", "nonce", "default",
        )
        .build();
        stellar_agent_core::approval::ApprovalContext::from_profile("render-test", &profile)
    }
    use super::*;
    use crate::commands::value_audit::KeyedAcquireError;
    use crate::common::consent::is_sidecar_contention;
    use stellar_agent_core::audit_log::writer::{AuditWriter, WriterError};
    use stellar_agent_core::audit_log::{AuditOutbox, drain_lock_is_held};
    use stellar_agent_core::profile::schema::default_approval_dir;

    // ── Helper: seed an attestation key into the mock keyring ────────────────

    fn seed_key_32(service: &str, account: &str) -> [u8; 32] {
        let key = [0xABu8; 32];
        let encoded = URL_SAFE_NO_PAD.encode(key);
        let entry = KeyringEntry::new(service, account).unwrap();
        entry.set_password(&encoded).unwrap();
        key
    }

    // ── Helper: build a store at a tmp path ──────────────────────────────────

    fn open_store_at(dir: &TempDir, profile: &str) -> PendingApprovalStore {
        let path = dir.path().join(format!("{profile}.toml"));
        PendingApprovalStore::open(path).unwrap()
    }

    // ── Helper: build a valid PendingApproval entry ──────────────────────────

    const SOURCE_G: &str = "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY";
    const DEST_G: &str = "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL";
    const OTHER_G: &str = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";
    const USDC_ISSUER_G: &str = "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5";

    fn make_entry(ttl_ms: u64) -> PendingApproval {
        fixtures::payment_pending(
            SOURCE_G,
            DEST_G,
            "XLM",
            2_500_000,
            None,
            100,
            1_234_567,
            process_uid_for_attestation().expect("UID available on test host"),
            ttl_ms,
        )
    }

    // ── Decode sha256 hex ────────────────────────────────────────────────────

    #[test]
    fn decode_sha256_hex_valid() {
        let hex = "a".repeat(64);
        let result = decode_sha256_hex(&hex);
        assert!(
            result.is_ok(),
            "valid 64-char hex should decode: {result:?}"
        );
    }

    #[test]
    fn decode_sha256_hex_wrong_length_fails() {
        let err = decode_sha256_hex("abcd").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("64") || msg.contains("unexpected"), "{msg}");
    }

    #[test]
    fn decode_sha256_hex_invalid_chars_fails() {
        let hex = "zz".repeat(32); // invalid hex
        let err = decode_sha256_hex(&hex).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("unexpected") || msg.contains("hex"), "{msg}");
    }

    // ── load_attestation_key ─────────────────────────────────────────────────

    #[test]
    #[serial]
    fn load_attestation_key_success() {
        keyring_mock::install().unwrap();
        let svc = "stellar-agent-attestation-run-test-load";
        seed_key_32(svc, "default");
        let entry_ref = KeyringEntryRef::new(svc, "default");
        let key = load_attestation_key(
            &entry_ref,
            &stellar_agent_core::profile::owner_key::OwnerKeyContext::for_profile_name("run-test"),
        )
        .unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    #[serial]
    fn load_attestation_key_missing_entry_fails() {
        keyring_mock::install().unwrap();
        let entry_ref =
            KeyringEntryRef::new("stellar-agent-attestation-run-test-missing", "default");
        let err = load_attestation_key(
            &entry_ref,
            &stellar_agent_core::profile::owner_key::OwnerKeyContext::for_profile_name("run-test"),
        )
        .unwrap_err();
        assert!(
            matches!(err, WalletError::Auth(AuthError::KeyringNotFound { .. })),
            "expected KeyringNotFound, got {err:?}"
        );
    }

    // ── run: no pending entry (not_found) ────────────────────────────────────

    #[tokio::test]
    #[serial]
    async fn run_with_no_pending_returns_exit_1() {
        let home = TempDir::new().unwrap();
        let _home_guard = StellarAgentHomeGuard::new(home.path());
        assert_eq!(
            default_approval_dir().unwrap(),
            home.path().join("approvals")
        );
        keyring_mock::install().unwrap();
        let args = RunArgs {
            id: Some("__stellar_agent_approve_test_not_found_nonce123".to_owned()),
            profile: Some("__stellar_agent_approve_test_no_pending".to_owned()),
            yes: true,
        };
        // Profile doesn't exist → profile load failure → exit 1
        let code = run(args).await;
        assert_eq!(code, 1, "absent store/profile must exit 1");
    }

    #[test]
    fn unix_ms_to_rfc3339_known_date() {
        // 2026-04-30T00:00:00Z = 1777507200000 ms
        let result = unix_ms_to_rfc3339(1_777_507_200_000);
        assert_eq!(result, "2026-04-30T00:00:00Z");
    }

    #[test]
    fn unix_ms_to_rfc3339_matches_timefmt_helper() {
        use std::time::{Duration, UNIX_EPOCH};
        let unix_ms = 1_777_552_496_000;
        let expected = timefmt::format_rfc3339_utc(UNIX_EPOCH + Duration::from_secs(1_777_552_496));
        assert_eq!(unix_ms_to_rfc3339(unix_ms), expected);
    }

    // `approval_store_open_error` now lives in `common.rs` and is tested there.

    // ── Full run with mock profile+store (--yes path) ─────────────────────────
    // Command tests resolve profiles and approvals under a temporary home.

    #[tokio::test]
    #[serial]
    async fn run_missing_id_arg_returns_exit_1() {
        let home = TempDir::new().unwrap();
        let _home_guard = StellarAgentHomeGuard::new(home.path());
        keyring_mock::install().unwrap();
        let args = RunArgs {
            id: None,
            profile: None,
            yes: true,
        };
        let code = run(args).await;
        assert_eq!(code, 1, "missing --id must exit 1");
    }

    #[tokio::test]
    #[serial]
    async fn run_empty_id_arg_returns_exit_1() {
        let home = TempDir::new().unwrap();
        let _home_guard = StellarAgentHomeGuard::new(home.path());
        keyring_mock::install().unwrap();
        let args = RunArgs {
            id: Some(String::new()),
            profile: None,
            yes: true,
        };
        let code = run(args).await;
        assert_eq!(code, 1, "empty --id must exit 1");
    }

    // ── Store-level tests for the approval flow ───────────────────────────────
    // These tests operate at the store layer (not via run()) to validate the
    // core approval contract independent of the full CLI plumbing.

    #[test]
    #[serial]
    fn store_entry_with_short_ttl_is_expired_after_ttl() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let mut store = open_store_at(&dir, "__stellar_agent_approve_test_expired");
        let entry = make_entry(1); // TTL=1ms → expires immediately
        let nonce = entry.approval_nonce.clone();
        store
            .insert(entry, timefmt::now_unix_ms().expect("clock"))
            .unwrap();

        std::thread::sleep(std::time::Duration::from_millis(5));

        // Verify the entry is expired at the store level.
        let now = timefmt::now_unix_ms().unwrap();
        let found = store.get(&nonce).unwrap();
        assert!(found.is_expired(now), "entry should be expired");
    }

    #[test]
    #[serial]
    fn store_entry_second_attestation_returns_already_attested_error() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let mut store = open_store_at(&dir, "__stellar_agent_approve_test_attested");
        let entry = make_entry(DEFAULT_TTL_MS);
        let nonce = entry.approval_nonce.clone();
        store
            .insert(entry, timefmt::now_unix_ms().expect("clock"))
            .unwrap();
        store.record_attestation(&nonce, [0x42u8; 32]).unwrap();

        // Second record_attestation must fail with AlreadyAttested.
        let err = store.record_attestation(&nonce, [0x42u8; 32]).unwrap_err();
        assert!(matches!(err, ApprovalError::AlreadyAttested));
    }

    #[test]
    #[serial]
    fn store_entry_with_mismatched_process_uid_is_detectable() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let path = dir
            .path()
            .join("__stellar_agent_approve_test_uid_mismatch.toml");
        let mut store = PendingApprovalStore::open(path).unwrap();

        // Insert an entry with a different process_uid.
        let mut entry = make_entry(DEFAULT_TTL_MS);
        entry.process_uid = "99999999".to_owned(); // will never match real UID
        let nonce = entry.approval_nonce.clone();
        store
            .insert(entry, timefmt::now_unix_ms().expect("clock"))
            .unwrap();

        // Verify UID mismatch is detectable.
        let stored = store.get(&nonce).unwrap();
        let our_uid = process_uid_for_attestation().expect("UID available on test host");
        assert_ne!(
            stored.process_uid, our_uid,
            "test entry must have a mismatched process_uid"
        );
    }

    #[test]
    #[serial]
    fn run_yes_with_valid_pending_records_attestation_store_level() {
        keyring_mock::install().unwrap();
        let svc = "stellar-agent-attestation-run-test-valid";
        let raw_key = seed_key_32(svc, "default");

        let profile = stellar_agent_core::profile::schema::Profile::builder_mainnet_named(
            "mainnet-store",
            "https://mainnet-store.example",
            "svc",
            "default",
            "nonce",
            "default",
        )
        .build();
        let context =
            stellar_agent_core::approval::ApprovalContext::from_profile("mainnet-store", &profile);
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("__stellar_agent_approve_test_valid.toml");
        let mut store = PendingApprovalStore::open(path.clone()).unwrap();
        let entry = make_entry(DEFAULT_TTL_MS);
        let nonce = entry.approval_nonce.clone();
        let process_uid = entry.process_uid.clone();

        // Extract the envelope SHA-256 hex from the entry for later
        // independent recomputation of the expected attestation blob.
        let envelope_sha256_hex = if let ApprovalKind::PaymentSimulated {
            envelope_sha256_hex,
            ..
        } = &entry.kind
        {
            envelope_sha256_hex.clone()
        } else {
            unreachable!("make_entry always produces PaymentSimulated")
        };

        store
            .insert(entry, timefmt::now_unix_ms().expect("clock"))
            .unwrap();
        drop(store); // release lock

        // Load key and compute + record attestation via the extracted helper.
        let entry_ref = KeyringEntryRef::new(svc, "default");
        let key = load_attestation_key(
            &entry_ref,
            &stellar_agent_core::profile::owner_key::OwnerKeyContext::for_profile_name("run-test"),
        )
        .unwrap();

        let mut store2 = PendingApprovalStore::open(path.clone()).unwrap();
        let entry2 = store2.get(&nonce).unwrap().clone();
        let mut audit_writer =
            AuditWriter::open(dir.path().join("audit").join("audit.jsonl"), None).unwrap();
        let surfaced = stellar_agent_core::approval::attest_and_persist(
            &mut store2,
            &entry2,
            &key,
            &context.binding(),
            Surface::Cli,
            ConsentAudit::Writer(&mut audit_writer),
            None,
            |_req, _key| Err("must not be called for PaymentSimulated".to_owned()),
        )
        .unwrap();
        let surfaced_blob = surfaced
            .expect("PaymentSimulated approval must surface its attestation blob for the agent");
        drop(store2);

        // Re-open and verify attestation blob was set AND matches the expected
        // HMAC.  Independently recompute the expected blob using the same key,
        // nonce, SHA-256, and process_uid that `attest_and_persist` used.
        let store3 = PendingApprovalStore::open(path).unwrap();
        let final_entry = store3.get(&nonce).unwrap();
        let blob_b64 = final_entry
            .attestation_blob_b64
            .as_ref()
            .expect("attestation_blob_b64 must be set after record_attestation");

        // Decode persisted blob.
        let persisted_bytes: [u8; 32] = URL_SAFE_NO_PAD
            .decode(blob_b64)
            .expect("attestation_blob_b64 must be valid base64")
            .try_into()
            .expect("attestation_blob_b64 must be exactly 32 bytes");

        // Recompute expected HMAC using the same inputs the production path used.
        let sha256_bytes: [u8; 32] = hex::decode(&envelope_sha256_hex)
            .expect("envelope_sha256_hex must be valid hex")
            .try_into()
            .expect("SHA-256 must be exactly 32 bytes");
        let expected = compute_attestation(
            &raw_key,
            &context.binding(),
            &nonce,
            &sha256_bytes,
            &process_uid,
            &entry2.attested_lifetime(),
        );

        assert_eq!(
            persisted_bytes, expected,
            "persisted attestation blob must equal independently-computed HMAC"
        );

        // The blob surfaced to the caller MUST be exactly the one the commit
        // gate verifies: identical to the persisted blob and to the expected
        // HMAC. This is the value the agent presents as `approval_attestation`.
        assert_eq!(
            surfaced_blob, *blob_b64,
            "surfaced attestation must equal the persisted blob"
        );
        let surfaced_bytes: [u8; 32] = URL_SAFE_NO_PAD
            .decode(&surfaced_blob)
            .expect("surfaced attestation must be valid base64")
            .try_into()
            .expect("surfaced attestation must be exactly 32 bytes");
        assert_eq!(
            surfaced_bytes, expected,
            "surfaced attestation must equal the independently-computed HMAC the gate checks"
        );
    }

    #[test]
    #[serial]
    fn load_and_validate_entry_success() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let mut store = open_store_at(&dir, "__stellar_agent_approve_test_validate");
        let entry = make_entry(DEFAULT_TTL_MS);
        let nonce = entry.approval_nonce.clone();
        let uid = entry.process_uid.clone();
        store
            .insert(entry, timefmt::now_unix_ms().expect("clock"))
            .unwrap();

        let validated =
            load_and_validate_entry(&store, &nonce, &ApproverIdentity::OsUid(uid), &[]).unwrap();
        assert_eq!(validated.approval_nonce, nonce);
    }

    #[test]
    fn load_and_validate_entry_not_found_fails() {
        let dir = TempDir::new().unwrap();
        let store = open_store_at(&dir, "__stellar_agent_approve_test_not_found");
        assert!(matches!(
            load_and_validate_entry(
                &store,
                "--yes",
                &ApproverIdentity::OsUid("test".to_owned()),
                &[],
            ),
            Err(ref error) if error.code() == "approval.not_found"
        ));
    }

    #[test]
    #[serial]
    fn load_and_validate_entry_user_mismatch_fails() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let mut store = open_store_at(&dir, "__stellar_agent_approve_test_validate_uid");
        let entry = make_entry(DEFAULT_TTL_MS);
        let nonce = entry.approval_nonce.clone();
        store
            .insert(entry, timefmt::now_unix_ms().expect("clock"))
            .unwrap();

        let err = load_and_validate_entry(
            &store,
            &nonce,
            &ApproverIdentity::OsUid("different-uid".to_owned()),
            &[],
        )
        .unwrap_err();
        assert_eq!(
            err.code(),
            "approval.user_mismatch",
            "unexpected error: {err}"
        );
    }

    #[test]
    fn prompt_approval_auto_approve_returns_true() {
        let entry = make_entry(DEFAULT_TTL_MS);
        let approved = prompt_approval(&entry, &test_context(), true).unwrap();
        assert!(approved);
    }

    // ── render_rule_proposal_definition (Package D, GH issue #8, Leg 3) ───────

    use stellar_agent_core::approval::{RuleProposalPolicy, RuleProposalSigner};

    const RULE_TEST_G_ADDR: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const RULE_TEST_C_ADDR: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    // ── #32: summary stream routing + block indentation ──────────────────────

    /// The human-readable summary is written to the injected sink — the
    /// production wrapper wires this to stderr so stdout carries only the JSON
    /// envelope. Guards the sink seam and the block formatting; the stderr
    /// wiring itself lives in `render_summary` and is verified structurally
    /// (`render_json` is the sole stdout writer in `run()`).
    #[test]
    fn write_summary_payment_writes_block_to_sink() {
        let entry = make_entry(DEFAULT_TTL_MS);
        let mut sink: Vec<u8> = Vec::new();
        write_summary(&entry, &test_context(), &mut sink).expect("write to in-memory sink");
        let s = String::from_utf8(sink).expect("summary is utf-8");
        for row in [
            "  Profile:           render-test",
            "  Network:           stellar:testnet",
            "  Endpoint:          https://",
            "  Signer:            (not enrolled)",
            "  Source:            GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY",
        ] {
            assert!(s.contains(row), "missing {row}: {s}");
        }
        assert!(
            s.contains("Pending approval"),
            "must render the header: {s}"
        );
        assert!(
            s.contains(&format!("Approval nonce:    {}", entry.approval_nonce)),
            "must render the approval nonce: {s}"
        );
        // Every payment field keeps its 2-space indent through the multi-line
        // `format!` continuation (the `\n\` must not strip it).
        for field in [
            "\n  To:",
            "\n  Amount:",
            "\n  Asset:",
            "\n  Memo:",
            "\n  Simulated fee:",
            "\n  Simulated seq num:",
        ] {
            assert!(
                s.contains(field),
                "payment field {field:?} must keep its 2-space indent: {s}"
            );
        }
    }

    /// The Default-context WARNING line must keep its 2-space indent: the
    /// `\n\` line-continuation strips the next source line's leading spaces, so
    /// the indent must be embedded explicitly after the `\n`.
    #[test]
    fn render_rule_proposal_default_context_warning_is_indented() {
        let definition = ContextRuleProposalSnapshot::new(
            RuleProposalContextType::Default,
            "spend-daily".to_owned(),
            None,
            vec![RuleProposalSigner::delegated(
                RULE_TEST_G_ADDR.to_owned(),
                true,
            )],
            vec![],
            vec![0],
            false,
            false,
        );
        let rendered = render_rule_proposal_definition(&definition);
        assert!(
            rendered.contains("\n  WARNING: Default context grants ACCOUNT-WIDE AUTHORITY"),
            "the Default-context WARNING line must keep its 2-space indent: {rendered:?}"
        );
    }

    /// `RuleProposalSimulated` header fields (Smart account / Chain ID / Proposal
    /// digest) must each keep their 2-space indent through the multi-line
    /// `format!` continuation.
    #[test]
    fn write_summary_rule_proposal_fields_are_indented() {
        let definition = ContextRuleProposalSnapshot::new(
            RuleProposalContextType::CallContract {
                contract: RULE_TEST_C_ADDR.to_owned(),
            },
            "spend-daily".to_owned(),
            None,
            vec![RuleProposalSigner::delegated(
                RULE_TEST_G_ADDR.to_owned(),
                true,
            )],
            vec![],
            vec![0],
            false,
            false,
        );
        let entry = PendingApproval::new_rule_proposal_pending(
            RULE_TEST_C_ADDR.to_owned(),
            "Test SDF Network ; September 2015".to_owned(),
            "stellar:testnet".to_owned(),
            definition,
            [0x99u8; 32],
            "CallContract rule \"spend-daily\"".to_owned(),
            process_uid_for_attestation().expect("UID available on test host"),
            DEFAULT_TTL_MS,
        )
        .expect("build RuleProposalSimulated pending entry");
        let mut sink: Vec<u8> = Vec::new();
        write_summary(&entry, &test_context(), &mut sink).expect("write to in-memory sink");
        let s = String::from_utf8(sink).expect("summary is utf-8");
        for field in [
            "\n  Smart account:",
            "\n  Chain ID:",
            "\n  Proposal digest:",
        ] {
            assert!(
                s.contains(field),
                "RuleProposalSimulated field {field:?} must keep its 2-space indent: {s}"
            );
        }
    }

    #[test]
    fn render_rule_proposal_default_context_shows_account_wide_authority_callout() {
        let definition = ContextRuleProposalSnapshot::new(
            RuleProposalContextType::Default,
            "spend-daily".to_owned(),
            None,
            vec![RuleProposalSigner::delegated(
                RULE_TEST_G_ADDR.to_owned(),
                true,
            )],
            vec![],
            vec![0],
            false,
            false,
        );
        let rendered = render_rule_proposal_definition(&definition);
        assert!(
            rendered.contains("ACCOUNT-WIDE AUTHORITY"),
            "Default context type must render a prominent account-wide-authority \
             callout: {rendered}"
        );
    }

    #[test]
    fn render_rule_proposal_call_contract_context_has_no_authority_callout() {
        let definition = ContextRuleProposalSnapshot::new(
            RuleProposalContextType::CallContract {
                contract: RULE_TEST_C_ADDR.to_owned(),
            },
            "spend-daily".to_owned(),
            None,
            vec![RuleProposalSigner::delegated(
                RULE_TEST_G_ADDR.to_owned(),
                true,
            )],
            vec![],
            vec![0],
            false,
            false,
        );
        let rendered = render_rule_proposal_definition(&definition);
        assert!(
            !rendered.contains("ACCOUNT-WIDE AUTHORITY"),
            "CallContract context type must NOT render the Default callout: {rendered}"
        );
        assert!(rendered.contains(RULE_TEST_C_ADDR));
    }

    #[test]
    fn render_rule_proposal_tags_proposer_signer() {
        let definition = ContextRuleProposalSnapshot::new(
            RuleProposalContextType::Default,
            "spend-daily".to_owned(),
            None,
            vec![
                RuleProposalSigner::delegated(RULE_TEST_G_ADDR.to_owned(), true),
                RuleProposalSigner::external(RULE_TEST_C_ADDR.to_owned(), vec![0xABu8; 65], false),
            ],
            vec![],
            vec![0],
            false,
            false,
        );
        let rendered = render_rule_proposal_definition(&definition);
        let proposer_line = rendered
            .lines()
            .find(|l| l.contains(RULE_TEST_G_ADDR))
            .expect("delegated signer line must be present");
        assert!(
            proposer_line.contains("[PROPOSER]"),
            "the proposing agent's own signer must be tagged PROPOSER: {proposer_line}"
        );
        let external_line = rendered
            .lines()
            .find(|l| l.contains("External"))
            .expect("external signer line must be present");
        assert!(
            !external_line.contains("[PROPOSER]"),
            "a non-proposer signer must NOT be tagged PROPOSER: {external_line}"
        );
        // WYSIWYS: the fixture's external signer pubkey is 65 bytes of
        // 0xAB — the FULL hex encoding (130 chars), not a truncated prefix,
        // must appear so the rendered value is verifiable against the
        // digest bound into proposal_sha256.
        let full_pubkey_hex = "ab".repeat(65);
        assert!(
            external_line.contains(&full_pubkey_hex),
            "external signer's FULL pubkey must render as hex, not a prefix: {external_line}"
        );
    }

    #[test]
    fn render_rule_proposal_renders_typed_spending_limit_policy() {
        use stellar_agent_core::approval::try_decode_spending_limit_params;
        // Build the exact params_xdr_b64 the smart-account crate's
        // build_spending_limit_install_param produces, via its own decode
        // symmetric round-trip (already asserted correct in
        // stellar-agent-core::approval::rule_proposal's own tests) — here we
        // just need ANY correctly-shaped params blob, so we construct it via
        // the raw ScVal shape directly.
        use base64::Engine as _;
        use stellar_xdr::{Int128Parts, ScMap, ScMapEntry, ScSymbol, ScVal, WriteXdr};

        let entries: Vec<ScMapEntry> = vec![
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("period_ledgers").unwrap()),
                val: ScVal::U32(17_280),
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("spending_limit").unwrap()),
                val: ScVal::I128(Int128Parts {
                    hi: 0,
                    lo: 10_000_000,
                }),
            },
        ];
        let scval = ScVal::Map(Some(ScMap(entries.try_into().unwrap())));
        let bytes = scval.to_xdr(stellar_xdr::Limits::none()).unwrap();
        let params_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
        // Sanity: this blob really does decode as a spending-limit policy.
        assert!(try_decode_spending_limit_params(&params_b64).is_some());

        let definition = ContextRuleProposalSnapshot::new(
            RuleProposalContextType::CallContract {
                contract: RULE_TEST_C_ADDR.to_owned(),
            },
            "spend-daily".to_owned(),
            None,
            vec![RuleProposalSigner::delegated(
                RULE_TEST_G_ADDR.to_owned(),
                true,
            )],
            vec![RuleProposalPolicy::new(
                RULE_TEST_C_ADDR.to_owned(),
                params_b64,
            )],
            vec![0],
            false,
            false,
        );
        let rendered = render_rule_proposal_definition(&definition);
        assert!(
            rendered.contains("spending-limit:"),
            "recognized spending-limit params must render typed, not raw: {rendered}"
        );
        assert!(rendered.contains("10000000 stroops"));
        assert!(rendered.contains("17280 ledgers"));
    }

    #[test]
    fn render_rule_proposal_falls_back_to_raw_for_unrecognized_policy_params() {
        use base64::Engine as _;
        let raw_params =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"not a spending limit");
        let definition = ContextRuleProposalSnapshot::new(
            RuleProposalContextType::CallContract {
                contract: RULE_TEST_C_ADDR.to_owned(),
            },
            "spend-daily".to_owned(),
            None,
            vec![RuleProposalSigner::delegated(
                RULE_TEST_G_ADDR.to_owned(),
                true,
            )],
            vec![RuleProposalPolicy::new(
                RULE_TEST_C_ADDR.to_owned(),
                raw_params.clone(),
            )],
            vec![0],
            false,
            false,
        );
        let rendered = render_rule_proposal_definition(&definition);
        assert!(
            rendered.contains("raw XDR params"),
            "unrecognized policy params must fall back to a raw-bytes rendering: {rendered}"
        );
        assert!(!rendered.contains("spending-limit:"));
        // WYSIWYS: the fallback must show the ACTUAL params content, not
        // merely a byte count — a count is not verifiable against what
        // gets bound into proposal_sha256.
        assert!(
            rendered.contains(&raw_params),
            "raw fallback must render the actual base64 XDR string, not just a byte count: \
             {rendered}"
        );
    }

    #[test]
    fn render_rule_proposal_same_policy_address_different_params_render_differently() {
        use base64::Engine as _;
        let params_a =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"unrecognized params A");
        let params_b =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"unrecognized params B");
        let build = |params: String| {
            ContextRuleProposalSnapshot::new(
                RuleProposalContextType::CallContract {
                    contract: RULE_TEST_C_ADDR.to_owned(),
                },
                "spend-daily".to_owned(),
                None,
                vec![RuleProposalSigner::delegated(
                    RULE_TEST_G_ADDR.to_owned(),
                    true,
                )],
                // Same policy_address in both — only params_xdr_b64 differs.
                vec![RuleProposalPolicy::new(RULE_TEST_C_ADDR.to_owned(), params)],
                vec![0],
                false,
                false,
            )
        };
        let rendered_a = render_rule_proposal_definition(&build(params_a));
        let rendered_b = render_rule_proposal_definition(&build(params_b));
        assert_ne!(
            rendered_a, rendered_b,
            "two proposals sharing a policy_address but with different params_xdr_b64 must \
             render differently, proving CONTENT (not just address) is displayed"
        );
    }

    #[test]
    fn render_rule_proposal_renders_override_warnings_only_when_set() {
        let with_overrides = ContextRuleProposalSnapshot::new(
            RuleProposalContextType::Default,
            "spend-daily".to_owned(),
            None,
            vec![RuleProposalSigner::delegated(
                RULE_TEST_G_ADDR.to_owned(),
                true,
            )],
            vec![],
            vec![0],
            true,
            true,
        );
        let rendered = render_rule_proposal_definition(&with_overrides);
        assert!(rendered.contains("accept_mutable_verifier is set"));
        assert!(rendered.contains("accept_unknown_verifier is set"));

        let without_overrides = ContextRuleProposalSnapshot::new(
            RuleProposalContextType::Default,
            "spend-daily".to_owned(),
            None,
            vec![RuleProposalSigner::delegated(
                RULE_TEST_G_ADDR.to_owned(),
                true,
            )],
            vec![],
            vec![0],
            false,
            false,
        );
        let rendered_no_warn = render_rule_proposal_definition(&without_overrides);
        assert!(!rendered_no_warn.contains("accept_mutable_verifier is set"));
        assert!(!rendered_no_warn.contains("accept_unknown_verifier is set"));
    }
    #[test]
    fn approval_prompt_shows_rule_reason_and_expiry() {
        let request = stellar_agent_core::policy::ApprovalRequest::new(String::new(), 617)
            .with_reason("Treasury review\nconfirm".to_owned());
        let entry = make_entry(DEFAULT_TTL_MS).with_policy_request(&request);
        let mut sink = Vec::new();
        write_summary(&entry, &test_context(), &mut sink).unwrap();
        let text = String::from_utf8(sink).unwrap();
        assert!(text.contains("Reason: Treasury review"), "{text}");
        assert!(!text.contains("review\nconfirm"), "{text}");
        assert!(
            text.contains(&unix_ms_to_rfc3339(entry.created_at_unix_ms + 617_000)),
            "{text}"
        );
    }

    /// A claim shows the envelope's source and balance id; the stored summary
    /// source and balance id are not shown.
    #[test]
    fn write_summary_claim_shows_the_envelope_source_only() {
        let mut entry = fixtures::claim_pending(
            SOURCE_G,
            [0x0a; 32],
            Some(("XLM", 1_000_000)),
            100,
            1,
            "1000".to_owned(),
            DEFAULT_TTL_MS,
        );
        let ApprovalKind::ClaimSimulated {
            summary_source,
            summary_balance_id_strkey,
            ..
        } = &mut entry.kind
        else {
            unreachable!()
        };
        OTHER_G.clone_into(summary_source);
        *summary_balance_id_strkey = fixtures::balance_ids([0x0b; 32]).1;
        let mut sink = Vec::new();
        write_summary(&entry, &test_context(), &mut sink).unwrap();
        let text = String::from_utf8(sink).unwrap();
        assert!(
            text.contains(&format!("  Source:            {SOURCE_G}")),
            "{text}"
        );
        assert!(
            text.contains(&format!(
                "  Balance ID:        {}",
                fixtures::balance_ids([0x0a; 32]).1
            )),
            "{text}"
        );
        assert!(!text.contains(OTHER_G), "{text}");
        assert!(
            !text.contains(&fixtures::balance_ids([0x0b; 32]).1),
            "{text}"
        );
    }

    // ── The consent row: written, queued, or refused ─────────────────────────

    use stellar_agent_core::audit_log::{AuditWriterRegistry, inspect_outbox};
    use stellar_agent_core::profile::schema::Profile;

    const TEST_G: &str = "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY";

    /// A testnet profile whose audit log lives in `dir`, with its audit key
    /// seeded unless `audit_key` is false.
    fn consent_profile(name: &str, dir: &TempDir, audit_key: bool) -> Profile {
        let mut profile = Profile::builder_testnet_named(name, "svc", TEST_G, "n-svc", "n-acct")
            .with_noop_engine()
            .build();
        profile.audit_log_path = dir.path().join("audit").join(format!("{name}.jsonl"));
        if audit_key {
            seed_key_32(
                &profile.audit_log_hash_chain_key_id.service,
                &profile.audit_log_hash_chain_key_id.account,
            );
        }
        profile
    }

    /// A store holding one pending payment entry, and that entry.
    fn pending_store(dir: &TempDir) -> (PendingApprovalStore, PendingApproval) {
        let mut store = PendingApprovalStore::open(dir.path().join("approvals.toml")).unwrap();
        let entry = make_entry(DEFAULT_TTL_MS);
        store
            .insert(entry.clone(), timefmt::now_unix_ms().unwrap())
            .unwrap();
        (store, entry)
    }

    fn consent_rows(profile: &Profile) -> Vec<serde_json::Value> {
        std::fs::read_to_string(&profile.audit_log_path)
            .unwrap_or_default()
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .filter(|row| row["kind"] == "approval_attested")
            .collect()
    }

    fn assert_nothing_persisted(store: &PendingApprovalStore, nonce: &str) {
        let entry = store.get(nonce).expect("the entry stays");
        assert!(
            entry.attestation_blob_b64.is_none(),
            "a refused approval persists nothing"
        );
    }

    fn approve_in_process(
        name: &str,
        profile: &Profile,
        store: &mut PendingApprovalStore,
        entry: &PendingApproval,
    ) -> Result<(Option<String>, ConsentRowOutcome), WalletError> {
        let context = stellar_agent_core::approval::ApprovalContext::from_profile(name, profile);
        approve_with_consent_row(store, entry, &[0x42; 32], &context, profile)
    }

    /// The acquisition is classified by the typed writer error: only sidecar
    /// contention is retried and resolved through the drain lock.
    #[test]
    fn only_sidecar_contention_is_resolved_through_the_drain_lock() {
        assert!(is_sidecar_contention(&KeyedAcquireError::Writer(
            WriterError::FileLocked
        )));
        for refused in [
            KeyedAcquireError::KeyUnavailable,
            KeyedAcquireError::BindingChanged(WalletError::Validation(
                stellar_agent_core::error::ValidationError::AuditLogBindingChanged {
                    profile: "p".to_owned(),
                },
            )),
            KeyedAcquireError::Writer(WriterError::OutboxBusy),
            KeyedAcquireError::Writer(WriterError::OutboxUnusable {
                line: 1,
                column: 1,
                reason: "invalid JSON",
            }),
            KeyedAcquireError::Writer(WriterError::TipAnchorMismatch {
                expected_count: 2,
                expected_offset: 10,
                actual_len: 0,
                reason: "file is shorter than the anchor",
            }),
            KeyedAcquireError::Writer(WriterError::Io(std::io::Error::other("disk"))),
            KeyedAcquireError::Writer(WriterError::TipAnchorUnavailable),
            KeyedAcquireError::Writer(WriterError::HmacKeyMismatch {
                profile_name: "p".to_owned(),
            }),
        ] {
            assert!(!is_sidecar_contention(&refused), "{refused:?}");
        }
    }

    #[test]
    fn the_success_envelope_names_where_the_row_went() {
        for (outcome, wire) in [
            (ConsentRowOutcome::Written, "written"),
            (ConsentRowOutcome::Queued, "queued"),
        ] {
            let data = ApproveRunData {
                approval_nonce: "n".to_owned(),
                attested: true,
                process_uid: "501".to_owned(),
                expires_at_unix_ms: 1,
                approval_attestation: None,
                audit: outcome,
            };
            assert_eq!(serde_json::to_value(&data).unwrap()["audit"], wire);
        }
    }

    #[test]
    #[serial]
    fn with_a_free_writer_the_row_is_written_then_the_approval_persisted() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let profile = consent_profile("approve-free", &dir, true);
        let (mut store, entry) = pending_store(&dir);
        let (attestation, audit) =
            approve_in_process("approve-free", &profile, &mut store, &entry).unwrap();
        assert_eq!(audit, ConsentRowOutcome::Written);
        assert!(attestation.is_some());
        assert_eq!(consent_rows(&profile).len(), 1);
        assert!(
            store
                .get(&entry.approval_nonce)
                .unwrap()
                .attestation_blob_b64
                .is_some()
        );
        assert_eq!(
            stellar_agent_network::keyring::KeyringAuditBindingStore::for_profile("approve-free")
                .load_raw()
                .unwrap(),
            Some(
                stellar_agent_core::audit_log::AuditBinding::for_profile(&profile)
                    .to_keyring_value()
            ),
            "the approval records an absent binding"
        );
    }

    #[test]
    #[serial]
    fn beside_a_draining_writer_the_row_is_queued_and_its_next_acquisition_logs_it() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let profile = consent_profile("approve-queued", &dir, true);
        // Another process's draining writer: same log, its own registry entry.
        let holder = || {
            AuditWriterRegistry::get_or_open_keyed(
                "approve-queued-server",
                &profile.audit_log_path,
                stellar_agent_network::keyring::keyed_audit_access(
                    &profile,
                    "approve-queued",
                    stellar_agent_core::audit_log::BindingCheck::Enforce,
                )
                .unwrap(),
            )
            .unwrap()
        };
        let _server = holder();
        assert!(drain_lock_is_held(&profile.audit_log_path).unwrap());

        let (mut store, entry) = pending_store(&dir);
        let (attestation, audit) =
            approve_in_process("approve-queued", &profile, &mut store, &entry).unwrap();
        assert_eq!(audit, ConsentRowOutcome::Queued);
        assert!(attestation.is_some(), "the approval is persisted");
        assert_eq!(inspect_outbox(&profile.audit_log_path).unwrap().pending, 1);
        assert!(consent_rows(&profile).is_empty(), "queued, not yet logged");
        assert!(
            drain_lock_is_held(&profile.audit_log_path).unwrap(),
            "the draining writer still holds the drain lock"
        );

        let _again = holder();
        assert_eq!(
            consent_rows(&profile).len(),
            1,
            "the next acquisition logs it"
        );
        assert_eq!(inspect_outbox(&profile.audit_log_path).unwrap().pending, 0);
    }

    #[test]
    #[serial]
    fn beside_a_writer_that_does_not_drain_the_approval_is_refused() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let profile = consent_profile("approve-locked", &dir, true);
        std::fs::create_dir_all(profile.audit_log_path.parent().unwrap()).unwrap();
        let _older = AuditWriter::open(profile.audit_log_path.clone(), None).unwrap();

        let (mut store, entry) = pending_store(&dir);
        let err = approve_in_process("approve-locked", &profile, &mut store, &entry).unwrap_err();
        assert_eq!(err.code(), "audit.chain_key_unavailable");
        assert!(err.to_string().contains("audit.writer_locked"), "{err}");
        assert_nothing_persisted(&store, &entry.approval_nonce);
        assert_eq!(inspect_outbox(&profile.audit_log_path).unwrap().pending, 0);
        assert!(
            !drain_lock_is_held(&profile.audit_log_path).unwrap(),
            "the drain lock is left free: a try_lock on it succeeds"
        );
    }

    /// A writer that holds the sidecar lock briefly, as a CLI command's startup
    /// advisory does, is waited out within the approval store's retry bound,
    /// and the row is written.
    #[test]
    #[serial]
    fn a_sidecar_lock_held_briefly_is_waited_out_and_the_row_written() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let profile = consent_profile("approve-brief", &dir, true);
        std::fs::create_dir_all(profile.audit_log_path.parent().unwrap()).unwrap();
        let (mut store, entry) = pending_store(&dir);

        let (held_tx, held_rx) = std::sync::mpsc::channel();
        let path = profile.audit_log_path.clone();
        let holder = std::thread::spawn(move || {
            let brief = AuditWriter::open(path, None).unwrap();
            held_tx.send(()).unwrap();
            std::thread::sleep(DEFAULT_RETRY_BACKOFF);
            drop(brief);
        });
        held_rx.recv().unwrap();
        let result = approve_in_process("approve-brief", &profile, &mut store, &entry);
        holder.join().unwrap();

        let (attestation, audit) = result.unwrap();
        assert_eq!(audit, ConsentRowOutcome::Written);
        assert!(attestation.is_some());
        assert_eq!(consent_rows(&profile).len(), 1);
    }

    #[test]
    #[serial]
    fn without_an_audit_key_the_approval_is_refused() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let profile = consent_profile("approve-no-key", &dir, false);
        let (mut store, entry) = pending_store(&dir);
        let err = approve_in_process("approve-no-key", &profile, &mut store, &entry).unwrap_err();
        assert_eq!(err.code(), "audit.chain_key_unavailable");
        assert_nothing_persisted(&store, &entry.approval_nonce);
        assert!(consent_rows(&profile).is_empty());
    }

    #[test]
    #[serial]
    fn on_a_rolled_back_log_the_approval_is_refused() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let profile = consent_profile("approve-rolled-back", &dir, true);
        {
            let writer = AuditWriterRegistry::get_or_open_keyed(
                "approve-rolled-back",
                &profile.audit_log_path,
                stellar_agent_network::keyring::keyed_audit_access(
                    &profile,
                    "approve-rolled-back",
                    stellar_agent_core::audit_log::BindingCheck::Enforce,
                )
                .unwrap(),
            )
            .unwrap();
            let mut writer = writer.lock().unwrap();
            for id in ["one", "two"] {
                writer
                    .write_entry(
                        stellar_agent_core::audit_log::AuditEntry::new_tool_invocation(
                            stellar_agent_core::audit_log::NewToolInvocation::new(
                                "test",
                                "stellar:testnet",
                                vec![],
                                stellar_agent_core::audit_log::PolicyDecision::Allow,
                                id,
                            ),
                        ),
                    )
                    .unwrap();
            }
        }
        std::fs::write(&profile.audit_log_path, b"").unwrap();

        let (mut store, entry) = pending_store(&dir);
        let err =
            approve_in_process("approve-rolled-back", &profile, &mut store, &entry).unwrap_err();
        assert_eq!(err.code(), "audit.tip_anchor_mismatch");
        assert_nothing_persisted(&store, &entry.approval_nonce);
    }

    #[test]
    #[serial]
    fn on_a_changed_binding_the_approval_is_refused() {
        use stellar_agent_core::audit_log::AuditBinding;
        use stellar_agent_network::keyring::KeyringAuditBindingStore;

        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let name = "approve-binding-changed";
        let mut profile = consent_profile(name, &dir, true);
        let binding_store = KeyringAuditBindingStore::for_profile(name);
        binding_store
            .store(&AuditBinding::for_profile(&profile))
            .unwrap();
        let binding_before = binding_store.load_raw().unwrap();
        let new_directory = dir.path().join("repointed");
        profile.audit_log_path = new_directory.join("audit.jsonl");

        let (mut store, entry) = pending_store(&dir);
        let err = approve_in_process(name, &profile, &mut store, &entry).unwrap_err();
        assert_eq!(err.code(), "audit.log_binding_changed");
        assert_nothing_persisted(&store, &entry.approval_nonce);
        drop(store);
        let reread = PendingApprovalStore::open(dir.path().join("approvals.toml")).unwrap();
        assert_nothing_persisted(&reread, &entry.approval_nonce);
        assert!(
            !new_directory.exists(),
            "nothing is created at the new path"
        );
        assert_eq!(binding_store.load_raw().unwrap(), binding_before);
    }

    #[test]
    #[serial]
    fn a_failing_outbox_append_refuses_and_the_entry_stays_pending() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let profile = consent_profile("approve-outbox-fails", &dir, true);
        let _server = AuditWriterRegistry::get_or_open_keyed(
            "approve-outbox-fails-server",
            &profile.audit_log_path,
            stellar_agent_network::keyring::keyed_audit_access(
                &profile,
                "approve-outbox-fails",
                stellar_agent_core::audit_log::BindingCheck::Enforce,
            )
            .unwrap(),
        )
        .unwrap();

        let (mut store, entry) = pending_store(&dir);
        let outbox = AuditOutbox::for_log(&profile.audit_log_path);
        stellar_agent_core::audit_log::outbox::test_seam::arm_partial_write(outbox.path(), 5);
        let result = approve_in_process("approve-outbox-fails", &profile, &mut store, &entry);
        stellar_agent_core::audit_log::outbox::test_seam::disarm(outbox.path());
        let err = result.unwrap_err();
        assert_eq!(err.code(), "audit.chain_key_unavailable", "{err}");
        assert_nothing_persisted(&store, &entry.approval_nonce);
        drop(store);
        let reread = PendingApprovalStore::open(dir.path().join("approvals.toml")).unwrap();
        assert_nothing_persisted(&reread, &entry.approval_nonce);
        assert_eq!(inspect_outbox(&profile.audit_log_path).unwrap().pending, 0);
    }

    #[test]
    fn write_summary_trustline_writes_block_to_sink() {
        for (limit, shown) in [
            (None, "unlimited"),
            (Some(0), "0 stroops (removes the trustline)"),
            (Some(123456789), "123456789 stroops (12.3456789 USDC)"),
        ] {
            let entry = fixtures::trustline_pending(
                SOURCE_G,
                "USDC",
                USDC_ISSUER_G,
                limit,
                100,
                42,
                "1000".to_owned(),
                DEFAULT_TTL_MS,
            );
            let mut sink = Vec::new();
            write_summary(&entry, &test_context(), &mut sink).unwrap();
            let text = String::from_utf8(sink).unwrap();
            for row in [
                format!("  Source:            {SOURCE_G}"),
                "  Kind:              trustline change (ChangeTrust)".to_owned(),
                format!("  Account:           {SOURCE_G}"),
                format!(
                    "  Asset:             {}",
                    "USDC:GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5"
                ),
                format!("  Limit:             {shown}"),
                "  Simulated fee:     100 stroops".to_owned(),
                "  Simulated seq num: 42".to_owned(),
            ] {
                assert!(
                    text.lines().any(|line| line == row),
                    "missing {row}: {text}"
                );
            }
            assert!(!text.contains("To:"));
            assert!(!text.contains("Amount:"));
        }
    }
    /// The claim transaction names the balance by id only, so the summary
    /// says that its asset and amount are not part of it, whatever the
    /// stored summary holds.
    #[test]
    fn claim_summary_says_asset_and_amount_are_not_signed() {
        for value in [None, Some(("XLM", 1_000_000))] {
            let entry = fixtures::claim_pending(
                SOURCE_G,
                [0x0a; 32],
                value,
                100,
                1,
                "1000".into(),
                DEFAULT_TTL_MS,
            );
            let mut output = Vec::new();
            write_summary(&entry, &test_context(), &mut output).unwrap();
            let text = String::from_utf8(output).unwrap();
            assert_eq!(
                text.matches("not part of the signed claim transaction")
                    .count(),
                2,
                "{text}"
            );
            assert!(!text.contains("1000000"), "{text}");
        }
    }

    /// Sets the stored summary of a payment entry to name another payment
    /// than its envelope holds; the stored digest still names the envelope.
    fn edit_stored_payment(entry: &mut PendingApproval) {
        let ApprovalKind::PaymentSimulated {
            summary_to,
            summary_amount_stroops,
            summary_asset,
            summary_memo,
            summary_simulated_fee_stroops,
            summary_simulated_seq_num,
            ..
        } = &mut entry.kind
        else {
            unreachable!()
        };
        OTHER_G.clone_into(summary_to);
        *summary_amount_stroops = 10_000;
        "XLM".clone_into(summary_asset);
        *summary_memo = Some("refund".to_owned());
        *summary_simulated_fee_stroops = 7;
        *summary_simulated_seq_num = 8;
    }

    /// The `approve` summary shows the envelope's destination, amount, asset
    /// and memo when the stored summary fields name another payment.
    #[test]
    fn approve_summary_shows_the_envelope_payment_not_the_stored_summary() {
        let mut entry = fixtures::payment_pending(
            SOURCE_G,
            DEST_G,
            &format!("USDC:{USDC_ISSUER_G}"),
            500_000_000,
            Some("invoice 9"),
            300,
            61,
            "1000".to_owned(),
            DEFAULT_TTL_MS,
        );
        edit_stored_payment(&mut entry);
        let mut sink = Vec::new();
        write_summary(&entry, &test_context(), &mut sink).unwrap();
        let text = String::from_utf8(sink).unwrap();
        for row in [
            format!("  To:                {DEST_G}"),
            "  Amount:            500000000 stroops".to_owned(),
            format!("  Asset:             USDC:{USDC_ISSUER_G}"),
            "  Memo:              text \"invoice 9\"".to_owned(),
            "  Simulated fee:     300 stroops".to_owned(),
            "  Simulated seq num: 61".to_owned(),
        ] {
            assert!(
                text.lines().any(|line| line == row),
                "missing {row}: {text}"
            );
        }
        assert!(!text.contains(OTHER_G), "{text}");
        assert!(!text.contains("10000"), "{text}");
        assert!(!text.contains("refund"), "{text}");
    }

    /// A memo holding cursor-up and erase-line sequences renders as escaped
    /// text on its own line, and the only Amount line is the envelope's.
    #[test]
    fn approve_escapes_control_sequences_in_a_memo() {
        let memo = "\u{1b}[1A\u{1b}[2KAmount: 0.1 XLM";
        let envelope =
            fixtures::payment_envelope(SOURCE_G, DEST_G, "XLM", 5_000_000_000, Some(memo), 100, 2);
        let entry = PendingApproval::new_payment_pending(
            envelope.clone(),
            envelope.as_bytes(),
            DEST_G.to_owned(),
            1_000_000,
            "XLM".to_owned(),
            None,
            100,
            2,
            "1000".to_owned(),
            DEFAULT_TTL_MS,
        )
        .unwrap();
        let mut sink = Vec::new();
        write_summary(&entry, &test_context(), &mut sink).unwrap();
        let text = String::from_utf8(sink).unwrap();
        assert!(!text.contains('\u{1b}'), "{text:?}");
        assert!(
            text.lines()
                .any(|line| line
                    == "  Memo:              text \"\\u{1b}[1A\\u{1b}[2KAmount: 0.1 XLM\""),
            "{text}"
        );
        let amount_lines: Vec<&str> = text
            .lines()
            .filter(|line| line.trim_start().starts_with("Amount:"))
            .collect();
        assert_eq!(
            amount_lines,
            ["  Amount:            500.0000000 XLM (5000000000 stroops)"],
            "{text}"
        );
    }

    /// An entry whose stored digest is not its envelope's renders as
    /// inconsistent, shows neither transaction's terms, and is refused before
    /// any prompt, `--yes` included.
    #[test]
    fn an_inconsistent_entry_renders_as_such_and_is_never_prompted() {
        let mut entry = make_entry(DEFAULT_TTL_MS);
        let other = fixtures::payment_envelope(SOURCE_G, OTHER_G, "XLM", 9, None, 100, 1);
        let ApprovalKind::PaymentSimulated {
            envelope_xdr_b64, ..
        } = &mut entry.kind
        else {
            unreachable!()
        };
        *envelope_xdr_b64 = other;
        let mut sink = Vec::new();
        write_summary(&entry, &test_context(), &mut sink).unwrap();
        let text = String::from_utf8(sink).unwrap();
        assert!(text.contains("  INCONSISTENT:      "), "{text}");
        assert!(
            text.contains(stellar_agent_approval_ui::INCONSISTENT_MESSAGE),
            "{text}"
        );
        assert!(!text.contains(OTHER_G), "{text}");
        assert!(!text.contains(DEST_G), "{text}");
        assert!(!text.contains("  Source:"), "{text}");
        let err = prompt_approval(&entry, &test_context(), true).unwrap_err();
        assert_eq!(err.code(), "approval.entry_inconsistent");
    }

    /// An unedited payment renders its envelope terms.
    #[test]
    fn an_unedited_payment_renders_its_stored_values() {
        let entry = fixtures::payment_pending(
            SOURCE_G,
            DEST_G,
            "XLM",
            25_000_000,
            Some("rent"),
            100,
            9,
            "1000".to_owned(),
            DEFAULT_TTL_MS,
        );
        let mut sink = Vec::new();
        write_summary(&entry, &test_context(), &mut sink).unwrap();
        let text = String::from_utf8(sink).unwrap();
        let expected = format!(
            "  Approval nonce:    {}\n  \
             To:                {DEST_G}\n  \
             Amount:            2.5000000 XLM (25000000 stroops)\n  \
             Asset:             XLM\n  \
             Memo:              text \"rent\"\n  \
             Simulated fee:     100 stroops\n  \
             Simulated seq num: 9\n",
            entry.approval_nonce
        );
        assert!(text.contains(&expected), "{text}");
        assert!(prompt_approval(&entry, &test_context(), true).unwrap());
    }

    /// The MPP charge prompt names every charge term, escaped.
    #[test]
    fn mpp_charge_summary_renders_its_terms() {
        let now = stellar_agent_core::timefmt::now_unix_ms().unwrap();
        let recipient = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM";
        let entry = stellar_agent_core::approval::fixtures::bind_mpp_entry(
            PendingApproval::new_mpp_charge_pending(
                [0x11; 32],
                [0x22; 32],
                "render-test".to_owned(),
                "stellar:testnet".to_owned(),
                SOURCE_G.to_owned(),
                "http".to_owned(),
                "merchant.example".to_owned(),
                "/checkout".to_owned(),
                "1000000".to_owned(),
                recipient.to_owned(),
                recipient.to_owned(),
                now / 1_000 + 3_600,
                1_100,
                "1000".to_owned(),
                DEFAULT_TTL_MS,
            )
            .unwrap(),
        );
        let mut sink = Vec::new();
        write_summary(&entry, &test_context(), &mut sink).unwrap();
        let text = String::from_utf8(sink).unwrap();
        for row in [
            "  Kind:              MppChargeSimulated".to_owned(),
            format!("  Payer:             {SOURCE_G}"),
            "  Transport:         http".to_owned(),
            "  Authority:         merchant.example".to_owned(),
            "  Target:            /checkout".to_owned(),
            "  Amount:            1000000 base units of the token contract".to_owned(),
            format!("  Token contract:    {recipient}"),
            format!("  Recipient:         {recipient}"),
            format!(
                "  Simulated fee:     1100 stroops ({})",
                stellar_agent_approval_ui::SIMULATED_FEE_NOTE
            ),
        ] {
            assert!(
                text.lines().any(|line| line == row),
                "missing {row}: {text}"
            );
        }
    }

    #[test]
    fn approve_renders_x402_payee_and_amount() {
        use stellar_xdr::{
            AccountId, ContractId, Hash, InvokeContractArgs, PublicKey, ScAddress, ScVal,
            SorobanAuthorizedFunction, SorobanAuthorizedInvocation, Uint256,
        };
        let root = SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
                contract_address: ScAddress::Contract(ContractId(Hash([3; 32]))),
                function_name: "transfer".try_into().unwrap(),
                args: vec![
                    ScVal::Address(ScAddress::Account(AccountId(
                        PublicKey::PublicKeyTypeEd25519(Uint256([4; 32])),
                    ))),
                    ScVal::Address(ScAddress::Account(AccountId(
                        PublicKey::PublicKeyTypeEd25519(Uint256([5; 32])),
                    ))),
                    ScVal::from(123i128),
                ]
                .try_into()
                .unwrap(),
            }),
            sub_invocations: vec![].try_into().unwrap(),
        };
        let mut entry = PendingApproval::new_x402_pending(
            &[0; 32],
            &root,
            Some("merchant.example.invalid\u{1b}[2J\u{7}".into()),
            "1000".into(),
            DEFAULT_TTL_MS,
        )
        .unwrap();
        let ApprovalKind::X402Payment {
            payee,
            amount,
            asset,
            ..
        } = &mut entry.kind
        else {
            unreachable!()
        };
        "untrusted-payee".clone_into(payee);
        "999".clone_into(amount);
        "untrusted-asset".clone_into(asset);
        let mut output = Vec::new();
        write_summary(&entry, &test_context(), &mut output).unwrap();
        let text = String::from_utf8(output).unwrap();
        assert!(
            text.contains(
                &stellar_strkey::ed25519::PublicKey([5; 32])
                    .to_string()
                    .to_string()
            )
        );
        assert!(text.contains("123"));
        assert!(text.contains("merchant.example.invalid"));
        assert!(!text.contains('\u{1b}'));
        assert!(!text.contains('\u{7}'));
        assert!(!text.contains("untrusted-payee"));
        assert!(!text.contains("999"));
        assert!(text.contains(&stellar_strkey::Contract([3; 32]).to_string().to_string()));
        assert!(!text.contains("untrusted-asset"));
    }

    /// The outcome of the mainnet rule for a mainnet profile when `mainnet`
    /// is true and a testnet one otherwise, with `--yes` as given and stdin
    /// and stderr reported as `terminal`.
    fn approve_rule(mainnet: bool, yes: bool, terminal: (bool, bool)) -> Result<(), String> {
        let profile = if mainnet {
            Profile::builder_mainnet_named(
                "operator",
                "https://rpc.example.invalid",
                "s",
                "a",
                "n",
                "b",
            )
            .build()
        } else {
            Profile::builder_testnet_named("operator", "s", "a", "n", "b").build()
        };
        let previous = crate::common::tty::tests::TEST_TTY.replace(Some(terminal));
        let outcome = mainnet_approve_rule(&profile, yes);
        crate::common::tty::tests::TEST_TTY.set(previous);
        outcome.map_err(|envelope| envelope.error.unwrap().code)
    }

    /// Mainnet with `--yes` refuses whatever the terminal.
    #[test]
    fn mainnet_refuses_yes_on_a_terminal() {
        assert_eq!(
            approve_rule(true, true, (true, true)),
            Err("approve.yes_refused_on_mainnet".to_owned())
        );
    }

    /// Mainnet without `--yes` requires stdin and stderr to be terminals.
    #[test]
    fn mainnet_without_yes_requires_a_terminal() {
        for terminal in [(false, true), (true, false), (false, false)] {
            assert_eq!(
                approve_rule(true, false, terminal),
                Err("confirm.tty_required".to_owned()),
                "{terminal:?}"
            );
        }
    }

    /// Mainnet without `--yes` on a terminal proceeds to the prompt.
    #[test]
    fn mainnet_without_yes_on_a_terminal_proceeds() {
        assert_eq!(approve_rule(true, false, (true, true)), Ok(()));
    }

    /// Testnet keeps `--yes` and checks no terminal.
    #[test]
    fn testnet_keeps_yes_without_a_terminal() {
        assert_eq!(approve_rule(false, true, (false, false)), Ok(()));
        assert_eq!(approve_rule(false, false, (false, false)), Ok(()));
    }

    /// Mainnet checks `--yes` before the terminal.
    #[test]
    fn mainnet_checks_yes_before_the_terminal() {
        assert_eq!(
            approve_rule(true, true, (false, false)),
            Err("approve.yes_refused_on_mainnet".to_owned())
        );
    }
    fn assert_edited_mpp_inconsistent(edit_amount: bool) {
        let mut entry = fixtures::mpp_pending();
        if let ApprovalKind::MppChargeSimulated {
            amount, recipient, ..
        } = &mut entry.kind
        {
            if edit_amount {
                *amount = "7".to_owned();
            } else {
                *recipient = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM".to_owned();
            }
        }
        let mut output = Vec::new();
        write_summary(&entry, &test_context(), &mut output).unwrap();
        let text = String::from_utf8(output).unwrap();
        assert!(text.contains("INCONSISTENT"), "{text}");
        assert!(
            text.contains(stellar_agent_approval_ui::INCONSISTENT_MESSAGE),
            "{text}"
        );
        assert!(!text.contains("Token contract:"), "{text}");
        assert_eq!(
            prompt_approval(&entry, &test_context(), true)
                .unwrap_err()
                .code(),
            "approval.entry_inconsistent"
        );
    }
    #[test]
    fn edited_mpp_amount_renders_inconsistent() {
        assert_edited_mpp_inconsistent(true);
    }
    #[test]
    fn edited_mpp_recipient_renders_inconsistent() {
        assert_edited_mpp_inconsistent(false);
    }
}
