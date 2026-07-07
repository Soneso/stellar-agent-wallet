//! `stellar-agent approve --id <nonce>` — interactive y/n for a pending approval.
//!
//! Fetches the pending approval entry from the on-disk store, renders a
//! wallet-controlled summary to stderr (NOT the agent's rendering, and NOT
//! stdout — stdout is reserved for the single terminal JSON envelope), reads
//! y/n from stdin, and on approval:
//!
//! - For `PaymentSimulated`: computes the HMAC-SHA256 attestation blob and
//!   persists it via `PendingApprovalStore::record_attestation`.
//! - For `ToolsetFirstInvokeGate`: builds a `ToolsetGrant`, persists it to the
//!   grant store, and CONSUMES (removes) the pending entry.
//!   Does NOT call `record_attestation` — that function is `PaymentSimulated`-only.
//!
//! # Security properties
//!
//! 1. **Wallet-controlled rendering** — the summary is produced by this
//!    command from the stored [`PendingApproval`] fields, not forwarded from
//!    agent output.  The agent cannot influence what the user sees.
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
//! This is the `approve --id` CLI path of the wallet-owned approval spine.

use std::io::{BufRead as _, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, UNIX_EPOCH};

use clap::Args;
use serde::Serialize;

use stellar_agent_core::amount::StellarAmount;
use stellar_agent_core::approval::{
    ApprovalKind, ApproverIdentity, ContextRuleProposalSnapshot, DEFAULT_RETRY_ATTEMPTS,
    DEFAULT_RETRY_BACKOFF, PendingApproval, RuleProposalContextType, RuleProposalSignerKind,
    Surface, load_and_validate_entry, load_attestation_key, open_with_retry,
    process_uid_for_attestation, try_decode_spending_limit_params,
};
use stellar_agent_core::audit_log::writer::AuditWriter;
use stellar_agent_core::envelope::Envelope;
use stellar_agent_core::error::{InternalError, ValidationError, WalletError};
use stellar_agent_core::profile::loader;
use stellar_agent_core::profile::schema::default_approval_dir;
use stellar_agent_core::timefmt;
use stellar_agent_network::keyring::init_platform_keyring_store;

use crate::commands::smart_account::common::open_audit_writer;
use crate::common::render;

/// Arguments for `stellar-agent approve --id <nonce>`.
///
/// # Examples
///
/// ```text
/// stellar-agent approve --id ABCxyzNonce
/// stellar-agent approve --id ABCxyzNonce --profile myprofile --yes
/// ```
#[derive(Debug, Args)]
#[non_exhaustive]
pub struct RunArgs {
    /// Approval nonce as printed in the MCP simulate response.
    #[arg(long = "id", value_name = "NONCE")]
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

/// Success payload for the `approve --id` JSON envelope.
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
}

/// Runs `stellar-agent approve --id <nonce>`.
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
    let profile_name = resolve_profile_name(args.profile.as_deref());

    // ── 3. Load the profile for keyring entry ref ─────────────────────────────
    let profile = match loader::load(&profile_name, None) {
        Ok(p) => p,
        Err(loader::ProfileLoadError::NotFound { name, .. }) => {
            let err = WalletError::Validation(ValidationError::ProfileNotFound { name });
            render::render_json(&Envelope::<()>::err(&err));
            return 1;
        }
        Err(e) => {
            tracing::debug!(profile = %profile_name, error = %e, "profile load failed");
            let err = WalletError::Validation(ValidationError::ProfileNotFound {
                name: profile_name.clone(),
            });
            render::render_json(&Envelope::<()>::err(&err));
            return 1;
        }
    };

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
            let err = WalletError::Internal(InternalError::UnexpectedState {
                detail: format!("approval.uid_unavailable: process UID derivation failed: {e}"),
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
    match prompt_approval(&entry, args.yes) {
        Ok(true) => {}
        Ok(false) => {
            let err = WalletError::Internal(InternalError::UnexpectedState {
                detail: "approval.denied: user declined the pending approval".to_owned(),
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
    let key_bytes = match load_attestation_key(entry_ref) {
        Ok(k) => k,
        Err(e) => {
            render::render_json(&Envelope::<()>::err(&e));
            return 1;
        }
    };

    // ── 7b. Open the audit log (non-fatal: proceed without emission on failure) ──
    let audit_writer_arc: Option<Arc<Mutex<AuditWriter>>> = match open_audit_writer(&profile_name) {
        Ok((writer, _path)) => Some(writer),
        Err(e) => {
            tracing::warn!(
                error = %e,
                "approve: audit writer open failed; continuing without audit emission"
            );
            None
        }
    };
    let mut audit_guard = audit_writer_arc.as_ref().map(|arc| arc.lock());
    let audit_writer_ref: Option<&mut AuditWriter> = match audit_guard.as_mut() {
        Some(Ok(g)) => Some(&mut **g),
        Some(Err(_poison)) => {
            tracing::warn!("approve: audit writer mutex poisoned; audit entry will be skipped");
            None
        }
        None => None,
    };

    // ── 8. Compute and persist HMAC attestation blob ─────────────────────────
    let approval_attestation = match stellar_agent_core::approval::attest_and_persist(
        &mut store,
        &entry,
        &key_bytes,
        Surface::Cli,
        audit_writer_ref,
        None,
        |req, key| {
            stellar_agent_toolsets_runtime::record_first_invoke_grant(
                &profile_name,
                req.toolset_name,
                req.capability,
                req.destination,
                req.asset,
                req.amount_min_stroops,
                req.amount_max_stroops,
                req.process_uid,
                req.now_unix_ms,
                key,
                None, // No grant-store-path override in the production CLI approve path.
            )
            .map(|_grant| ())
            .map_err(|e| e.to_string())
        },
    ) {
        Ok(a) => a,
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
    }));
    0
}

// ─────────────────────────────────────────────────────────────────────────────
// Private helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Resolves the effective profile name from the CLI arg or `STELLAR_AGENT_PROFILE`.
fn resolve_profile_name(arg: Option<&str>) -> String {
    if let Some(name) = arg {
        return name.to_owned();
    }
    std::env::var("STELLAR_AGENT_PROFILE").unwrap_or_else(|_| "default".to_owned())
}

/// Builds the store path for `<profile>` as `<approval_dir>/<profile>.toml`.
fn build_store_path(profile_name: &str) -> Result<PathBuf, WalletError> {
    let dir = default_approval_dir().map_err(|_| {
        WalletError::Internal(InternalError::UnexpectedState {
            detail: "approval.store_dir_error: could not determine approval store directory"
                .to_owned(),
        })
    })?;
    Ok(dir.join(format!("{profile_name}.toml")))
}

fn prompt_approval(entry: &PendingApproval, auto_approve: bool) -> Result<bool, WalletError> {
    render_summary(entry);
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
            lines.push(format!("  Context:           CallContract {contract}"));
        }
        RuleProposalContextType::CreateContract { wasm_hash_hex } => {
            lines.push(format!(
                "  Context:           CreateContract (wasm hash) {wasm_hash_hex}"
            ));
        }
        // RuleProposalContextType is #[non_exhaustive]; a future variant
        // renders with a minimal fallback rather than aborting the approval
        // flow — the operator still sees every other field.
        other => {
            lines.push(format!("  Context:           (unrecognized: {other:?})"));
        }
    }

    lines.push(format!("  Rule name:         {}", definition.name));
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
                format!("Delegated  {address}")
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
                format!("External   verifier={verifier} pubkey={pubkey_hex}")
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
                None => format!("(raw XDR params) {}", policy.params_xdr_b64),
            };
            lines.push(format!(
                "    [{idx}] {policy_address}  {detail}",
                policy_address = policy.policy_address
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
/// For `PaymentSimulated` entries, displays payment-summary fields.
/// For `SignWithPasskey` entries, displays the smart-account redacted address
/// and rule IDs (no amount — this is a passkey signing request, not a payment).
fn write_summary(entry: &PendingApproval, out: &mut dyn Write) -> std::io::Result<()> {
    let created = unix_ms_to_rfc3339(entry.created_at_unix_ms);
    let expires = unix_ms_to_rfc3339(entry.expires_at_unix_ms);

    let body = match &entry.kind {
        ApprovalKind::PaymentSimulated {
            summary_to,
            summary_amount_stroops,
            summary_asset,
            summary_memo,
            summary_simulated_fee_stroops,
            summary_simulated_seq_num,
            ..
        } => {
            let memo = summary_memo
                .as_deref()
                .map(|m| format!("  Memo:              {m}"))
                .unwrap_or_else(|| "  Memo:              (none)".to_owned());
            let amount_xlm = if summary_asset == "XLM" {
                format!(
                    "{} XLM ({} stroops)",
                    StellarAmount::from_stroops(*summary_amount_stroops).as_xlm_decimal_string(),
                    summary_amount_stroops
                )
            } else {
                format!("{} stroops", summary_amount_stroops)
            };
            format!(
                "  To:                {to}\n  \
                 Amount:            {amount}\n  \
                 Asset:             {asset}\n\
                 {memo}\n  \
                 Simulated fee:     {fee} stroops\n  \
                 Simulated seq num: {seq}",
                to = summary_to,
                amount = amount_xlm,
                asset = summary_asset,
                memo = memo,
                fee = summary_simulated_fee_stroops,
                seq = summary_simulated_seq_num,
            )
        }
        ApprovalKind::SignWithPasskey {
            smart_account_redacted,
            rule_ids,
            ..
        } => {
            format!(
                "  Kind:              SignWithPasskey\n  \
                 Smart account:     {smart_account_redacted}\n  \
                 Rule IDs:          {rule_ids:?}"
            )
        }
        ApprovalKind::ToolsetFirstInvokeGate {
            toolset_name,
            capability,
            destination,
            asset,
            amount_min_stroops,
            amount_max_stroops,
        } => {
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
            let amount_max_xlm = if asset == "XLM" {
                format!(
                    "{} XLM ({amount_max_stroops} stroops)",
                    StellarAmount::from_stroops(*amount_max_stroops).as_xlm_decimal_string(),
                )
            } else {
                format!("{amount_max_stroops} stroops")
            };
            format!(
                "  Kind:              ToolsetFirstInvokeGate\n  \
                 Toolset:           {toolset_name}\n  \
                 Capability:        {capability}\n  \
                 Destination:       {dest_redacted}\n  \
                 Asset:             {asset}\n  \
                 Amount max:        {amount_max_xlm}\n  \
                 Amount min:        {amount_min_stroops} stroops"
            )
        }
        ApprovalKind::TrustlineClawbackOptIn {
            network,
            code,
            issuer,
        } => {
            // Redact issuer G-strkey to first-5-last-5.
            let issuer_redacted = if issuer.len() >= 10 {
                format!("{}...{}", &issuer[..5], &issuer[issuer.len() - 5..])
            } else {
                "<redacted>".to_owned()
            };
            format!(
                "  Kind:              TrustlineClawbackOptIn\n  \
                 Network:           {network}\n  \
                 Asset code:        {code}\n  \
                 Issuer:            {issuer_redacted}\n  \
                 WARNING: This issuer has AUTH_CLAWBACK_ENABLED set.\n    \
                 The issuer may reclaim tokens from this trustline."
            )
        }
        ApprovalKind::ClaimSimulated {
            summary_balance_id_hex72,
            summary_balance_id_strkey,
            summary_asset,
            summary_amount_stroops,
            summary_source,
            summary_simulated_fee_stroops,
            summary_simulated_seq_num,
            ..
        } => {
            // All fields are public claim data (balance ids, amounts, source
            // account) rendered from VALIDATED STORED values — same posture as
            // PaymentSimulated's summary_to.
            let amount = if summary_asset == "XLM" {
                format!(
                    "{} XLM ({} stroops)",
                    StellarAmount::from_stroops(*summary_amount_stroops).as_xlm_decimal_string(),
                    summary_amount_stroops
                )
            } else {
                format!("{summary_amount_stroops} stroops")
            };
            format!(
                "  Kind:              ClaimSimulated\n  \
                 Balance ID:        {summary_balance_id_strkey}\n  \
                 Balance ID (hex):  {summary_balance_id_hex72}\n  \
                 Asset:             {summary_asset}\n  \
                 Amount:            {amount}\n  \
                 Source:            {summary_source}\n  \
                 Simulated fee:     {summary_simulated_fee_stroops} stroops\n  \
                 Simulated seq num: {summary_simulated_seq_num}"
            )
        }
        ApprovalKind::RuleProposalSimulated {
            smart_account_redacted,
            chain_id,
            definition,
            proposal_sha256,
            ..
        } => {
            let digest_hex: String = proposal_sha256.iter().map(|b| format!("{b:02x}")).collect();
            format!(
                "  Kind:              RuleProposalSimulated\n  \
                 Smart account:     {smart_account_redacted}\n  \
                 Chain ID:          {chain_id}\n\
                 {body}\n  \
                 Proposal digest:   {digest_hex}",
                body = render_rule_proposal_definition(definition),
            )
        }
        other => {
            // ApprovalKind is #[non_exhaustive]; future variants render with a
            // minimal kind-name fallback rather than aborting. The CLI never
            // attests an unknown kind (attest_and_persist's match also catches
            // unknown variants and returns wrong-kind).
            format!("  Kind:              {}", other.kind_name())
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
        nonce = entry.approval_nonce,
        body = body,
        created = created,
        expires = expires,
    );

    write!(out, "{summary}")
}

/// Renders the wallet-controlled approval summary to stderr.
///
/// Thin production wrapper over [`write_summary`]: routes the human-readable
/// block to STDERR so STDOUT carries only the single terminal JSON envelope
/// (the documented programmatic contract — `approve ... > out.json` must yield
/// exactly one parseable envelope). Always called regardless of `--yes` so
/// there is a visible record.
fn render_summary(entry: &PendingApproval) {
    let mut err = std::io::stderr();
    // The summary is advisory; the JSON envelope on stdout is the authoritative
    // result, so a stderr write failure must not abort the approval.
    let _ = write_summary(entry, &mut err);
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
    use keyring_core::Entry as KeyringEntry;
    use serial_test::serial;
    use stellar_agent_core::approval::{
        ApprovalError, ApprovalKind, DEFAULT_TTL_MS, PendingApproval, PendingApprovalStore,
        attestation::compute_attestation, decode_sha256_hex, process_uid_for_attestation,
    };
    use stellar_agent_core::error::AuthError;
    use stellar_agent_core::profile::schema::KeyringEntryRef;
    use stellar_agent_test_support::keyring_mock;
    use tempfile::TempDir;

    use super::*;

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

    fn make_entry(ttl_ms: u64) -> PendingApproval {
        PendingApproval::new_payment_pending(
            "b64xdr".to_owned(),
            b"fake-xdr-bytes",
            "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            2_500_000,
            "XLM".to_owned(),
            None,
            100,
            1_234_567,
            process_uid_for_attestation().expect("UID available on test host"),
            ttl_ms,
        )
        .unwrap()
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
        let key = load_attestation_key(&entry_ref).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    #[serial]
    fn load_attestation_key_missing_entry_fails() {
        keyring_mock::install().unwrap();
        let entry_ref =
            KeyringEntryRef::new("stellar-agent-attestation-run-test-missing", "default");
        let err = load_attestation_key(&entry_ref).unwrap_err();
        assert!(
            matches!(err, WalletError::Auth(AuthError::KeyringNotFound { .. })),
            "expected KeyringNotFound, got {err:?}"
        );
    }

    // ── run: no pending entry (not_found) ────────────────────────────────────

    #[tokio::test]
    #[serial]
    async fn run_with_no_pending_returns_exit_1() {
        // Uses the real approval dir; the nonce is unique so the entry
        // is absent by design.  Exit code must be 1.
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

    // ── resolve_profile_name ─────────────────────────────────────────────────

    #[test]
    fn resolve_profile_name_from_arg() {
        let name = resolve_profile_name(Some("myprofile"));
        assert_eq!(name, "myprofile");
    }

    #[test]
    fn resolve_profile_name_no_env_or_arg() {
        // When the arg is present, it always wins regardless of env.
        let name = resolve_profile_name(Some("explicit"));
        assert_eq!(name, "explicit");
    }

    // ── Full run with mock profile+store (--yes path) ─────────────────────────
    // These tests exercise the run() function end-to-end against a real temp
    // store directory.  Because run() calls default_approval_dir() we need to
    // test via a profile that's non-existent (to exercise the error paths) or
    // via direct store helper tests.

    #[tokio::test]
    #[serial]
    async fn run_missing_id_arg_returns_exit_1() {
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
        let key = load_attestation_key(&entry_ref).unwrap();

        let mut store2 = PendingApprovalStore::open(path.clone()).unwrap();
        let entry2 = store2.get(&nonce).unwrap().clone();
        let surfaced = stellar_agent_core::approval::attest_and_persist(
            &mut store2,
            &entry2,
            &key,
            Surface::Cli,
            None,
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
        let expected = compute_attestation(&raw_key, &nonce, &sha256_bytes, &process_uid);

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
        assert!(
            err.to_string().contains("approval.user_mismatch"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn prompt_approval_auto_approve_returns_true() {
        let entry = make_entry(DEFAULT_TTL_MS);
        let approved = prompt_approval(&entry, true).unwrap();
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
        write_summary(&entry, &mut sink).expect("write to in-memory sink");
        let s = String::from_utf8(sink).expect("summary is utf-8");
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
        write_summary(&entry, &mut sink).expect("write to in-memory sink");
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
}
