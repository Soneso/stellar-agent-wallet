//! Server-rendered HTML for the approval-inbox pages.
//!
//! Two pages are rendered server-side: the inbox shell (`GET /inbox`) and the
//! per-approval detail page (`GET /approval/{nonce}`). Both embed dynamic
//! values only through a `<script type="application/json">` data island (never
//! inline JS); the browser does not execute `application/json` content, so the
//! embedded values cannot escalate to script execution. All logic lives in the
//! same-origin `/static/app.js`, keeping the CSP at `script-src 'self'` with no
//! `'unsafe-inline'`.
//!
//! Free-text fields that reach the HTML body directly (asset codes, memos,
//! redacted addresses) are HTML-escaped via [`html_escape`]; the data-island
//! JSON is escaped via [`json_data_island`].

use stellar_agent_core::amount::StellarAmount;
use stellar_agent_core::approval::{
    ApprovalSummaryView, ContextRuleProposalSnapshot, PendingApprovalView, RuleProposalContextType,
    RuleProposalSignerKind, try_decode_spending_limit_params,
};

/// Serialise `value` to JSON safe to embed inside a
/// `<script type="application/json">` element.
///
/// `serde_json` performs JSON-string escaping; `<`, `>`, and `&` are then
/// replaced with their `\uXXXX` forms so the text can never contain a literal
/// `</script>` sequence, while remaining valid JSON for `JSON.parse`.
fn json_data_island(value: &serde_json::Value) -> String {
    value
        .to_string()
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026")
}

/// HTML-escapes a string for safe interpolation into element text or an
/// attribute value.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

/// Returns `true` when a kind can be approved (attested / consented) from this
/// UI. Passkey kinds and rejected tombstones are informational here.
#[must_use]
pub(crate) fn kind_is_approvable(summary: &ApprovalSummaryView) -> bool {
    matches!(
        summary,
        ApprovalSummaryView::Payment { .. }
            | ApprovalSummaryView::Claim { .. }
            | ApprovalSummaryView::ToolsetFirstInvokeGate { .. }
            | ApprovalSummaryView::TrustlineClawbackOptIn { .. }
            | ApprovalSummaryView::RuleProposal { .. }
    )
}

/// Render the inbox shell page.
///
/// Seeds the current snapshot into `#pending-data`; `/static/app.js` re-fetches
/// `/pending.json` every two seconds and updates the rows and the title badge.
#[must_use]
pub(crate) fn render_inbox_page(
    pending: &[PendingApprovalView],
    expired_count: usize,
    include_expired: bool,
) -> String {
    let data_island = json_data_island(&serde_json::json!({
        "pending": pending,
        "expired_count": expired_count,
        "include_expired": include_expired,
    }));

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Stellar Agent Wallet — Approvals</title>
  <style>
    body {{ font-family: system-ui, sans-serif; margin: 2rem; }}
    .row {{ padding: 0.5rem 0; border-bottom: 1px solid #ddd; }}
    .row a {{ text-decoration: none; }}
    .muted {{ color: #666; }}
  </style>
</head>
<body>
  <h1>Pending approvals</h1>
  <p class="muted" id="status">Loading…</p>
  <div id="inbox"></div>
  <script type="application/json" id="pending-data">{data_island}</script>
  <script src="/static/app.js"></script>
</body>
</html>"#
    )
}

/// Render a clean "not found in queue" page (HTTP 200, authenticated UX case).
#[must_use]
pub(crate) fn render_not_found_page(nonce: &str) -> String {
    let nonce = html_escape(nonce);
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Approval not found — Stellar Agent Wallet</title>
  <style>body {{ font-family: system-ui, sans-serif; margin: 2rem; }}</style>
</head>
<body>
  <h1>Approval not found</h1>
  <p>No pending approval with nonce <code>{nonce}</code> is in the queue. It may
     have been approved, rejected, or expired already.</p>
  <p><a href="/inbox">Back to inbox</a></p>
</body>
</html>"#
    )
}

/// Render the per-approval detail page.
///
/// Every field of the entry's redacted view is rendered server-side. The CSRF
/// value and the nonce ride in the `#approval-data` island so `/static/app.js`
/// can wire the Approve / Reject buttons; the response JSON (including any
/// surfaced attestation blob) is rendered into the result container by the JS.
#[must_use]
pub(crate) fn render_detail_page(
    view: &PendingApprovalView,
    csrf_hex: &str,
    attestation_blob: Option<&str>,
) -> String {
    let approvable = kind_is_approvable(&view.summary) && !view.expired && !view.attested;
    let summary_html = render_summary_html(&view.summary);
    // The full rule definition (context callout, signer table, policy table,
    // override warnings) is not dt/dd-shaped, so it renders as its own block
    // AFTER the `<dl>` closes rather than inside `summary_html`.
    let rule_proposal_extra_html = match &view.summary {
        ApprovalSummaryView::RuleProposal { definition, .. } => {
            render_rule_proposal_definition_html(definition)
        }
        _ => String::new(),
    };

    let status_line = if view.attested {
        "<strong>Status:</strong> already resolved (consent recorded)".to_owned()
    } else if view.expired {
        "<strong>Status:</strong> expired".to_owned()
    } else {
        "<strong>Status:</strong> pending".to_owned()
    };

    let attested_block = match (view.attested, attestation_blob) {
        (true, Some(blob)) => format!(
            "<h2>Recorded attestation</h2>\n\
             <p>This approval was already recorded. Present this attestation to \
             the matching commit tool:</p>\n\
             <textarea readonly rows=\"3\" style=\"width:100%\">{}</textarea>",
            html_escape(blob)
        ),
        _ => String::new(),
    };

    let actions = if approvable {
        r#"<div id="actions">
    <button id="approve-btn" type="button">Approve</button>
    <button id="reject-btn" type="button">Reject</button>
  </div>"#
            .to_owned()
    } else if view.attested || matches!(view.summary, ApprovalSummaryView::Rejected { .. }) {
        String::new()
    } else if view.expired {
        // Expired but not yet attested/rejected: allow a reject to tombstone it.
        r#"<div id="actions">
    <button id="reject-btn" type="button">Reject</button>
  </div>"#
            .to_owned()
    } else {
        // Informational kinds (passkey): no interactive approve here.
        r#"<div id="actions">
    <button id="reject-btn" type="button">Reject</button>
  </div>"#
            .to_owned()
    };

    let data_island = json_data_island(&serde_json::json!({
        "nonce": view.approval_nonce,
        "csrf": csrf_hex,
        "approvable": approvable,
    }));

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Approval detail — Stellar Agent Wallet</title>
  <style>
    body {{ font-family: system-ui, sans-serif; margin: 2rem; }}
    dt {{ font-weight: 600; margin-top: 0.5rem; }}
    button {{ margin-right: 0.5rem; padding: 0.4rem 0.9rem; }}
    .muted {{ color: #666; }}
  </style>
</head>
<body>
  <p><a href="/inbox">&larr; Back to inbox</a></p>
  <h1>Approval detail</h1>
  <p>{status_line}</p>
  <dl>
    <dt>Nonce</dt><dd><code>{nonce}</code></dd>
    <dt>Kind</dt><dd>{kind}</dd>
    <dt>Created at (unix ms)</dt><dd>{created}</dd>
    <dt>Expires at (unix ms)</dt><dd>{expires}</dd>
{summary_html}
  </dl>
  {rule_proposal_extra_html}
  {attested_block}
  {actions}
  <div id="result" class="muted"></div>
  <script type="application/json" id="approval-data">{data_island}</script>
  <script src="/static/app.js"></script>
</body>
</html>"#,
        status_line = status_line,
        nonce = html_escape(&view.approval_nonce),
        kind = html_escape(view.kind_name),
        created = view.created_at_unix_ms,
        expires = view.expires_at_unix_ms,
        summary_html = summary_html,
        rule_proposal_extra_html = rule_proposal_extra_html,
        attested_block = attested_block,
        actions = actions,
        data_island = data_island,
    )
}

/// Renders the kind-specific summary rows as `<dt>/<dd>` pairs.
fn render_summary_html(summary: &ApprovalSummaryView) -> String {
    fn row(label: &str, value: &str) -> String {
        format!(
            "    <dt>{}</dt><dd>{}</dd>\n",
            html_escape(label),
            html_escape(value)
        )
    }

    match summary {
        ApprovalSummaryView::Payment {
            to,
            amount_stroops,
            asset,
            memo,
            fee_stroops,
            seq_num,
        } => {
            let mut s = String::new();
            s.push_str(&row("Destination", to));
            s.push_str(&row("Amount (stroops)", &amount_stroops.to_string()));
            s.push_str(&row("Asset", asset));
            s.push_str(&row("Memo", memo.as_deref().unwrap_or("(none)")));
            s.push_str(&row("Simulated fee (stroops)", &fee_stroops.to_string()));
            s.push_str(&row("Simulated seq num", &seq_num.to_string()));
            s
        }
        ApprovalSummaryView::Claim {
            balance_id_strkey,
            asset,
            amount_stroops,
            source,
            fee_stroops,
            seq_num,
        } => {
            let mut s = String::new();
            s.push_str(&row("Balance id", balance_id_strkey));
            s.push_str(&row("Asset", asset));
            s.push_str(&row("Amount (stroops)", &amount_stroops.to_string()));
            s.push_str(&row("Source", source));
            s.push_str(&row("Simulated fee (stroops)", &fee_stroops.to_string()));
            s.push_str(&row("Simulated seq num", &seq_num.to_string()));
            s
        }
        ApprovalSummaryView::SignWithPasskey {
            smart_account_redacted,
            rule_ids,
            rp_id,
        } => {
            let mut s = String::new();
            s.push_str(&row("Smart account", smart_account_redacted));
            s.push_str(&row("Rule ids", &format!("{rule_ids:?}")));
            s.push_str(&row("RP id", rp_id));
            s
        }
        ApprovalSummaryView::RegisterPasskey {
            smart_account_redacted,
            rule_ids,
            rp_id,
        } => {
            let mut s = String::new();
            s.push_str(&row("Smart account", smart_account_redacted));
            s.push_str(&row("Rule ids", &format!("{rule_ids:?}")));
            s.push_str(&row("RP id", rp_id));
            s
        }
        ApprovalSummaryView::ToolsetFirstInvokeGate {
            toolset_name,
            capability,
            destination_redacted,
            asset,
            amount_min_stroops,
            amount_max_stroops,
        } => {
            let mut s = String::new();
            s.push_str(&row("Toolset", toolset_name));
            s.push_str(&row("Capability", capability));
            s.push_str(&row("Destination", destination_redacted));
            s.push_str(&row("Asset", asset));
            s.push_str(&row(
                "Amount min (stroops)",
                &amount_min_stroops.to_string(),
            ));
            s.push_str(&row(
                "Amount max (stroops)",
                &amount_max_stroops.to_string(),
            ));
            s
        }
        ApprovalSummaryView::TrustlineClawbackOptIn {
            network,
            code,
            issuer_redacted,
        } => {
            let mut s = String::new();
            s.push_str(&row("Network", network));
            s.push_str(&row("Asset code", code));
            s.push_str(&row("Issuer", issuer_redacted));
            s
        }
        ApprovalSummaryView::RuleProposal {
            smart_account_redacted,
            chain_id,
            proposal_sha256_hex,
            ..
        } => {
            // The full rule definition (context, signers, policies, warnings)
            // is NOT dt/dd-shaped (it needs tables and callout paragraphs), so
            // it is rendered separately by `render_rule_proposal_extra_html`
            // and inserted by the caller AFTER this `<dl>` closes, keeping
            // the HTML validly nested.
            let mut s = String::new();
            s.push_str(&row("Smart account", smart_account_redacted));
            s.push_str(&row("Chain ID", chain_id));
            s.push_str(&row("Proposal digest", proposal_sha256_hex));
            s
        }
        ApprovalSummaryView::Rejected { original_kind_name } => {
            row("Rejected kind", original_kind_name)
        }
        // `ApprovalSummaryView` is `#[non_exhaustive]`; a future variant renders
        // a minimal placeholder rather than failing to build.
        _ => "    <dt>Summary</dt><dd>(unrecognised kind)</dd>\n".to_owned(),
    }
}

/// Renders the full resolved rule definition of a `RuleProposalSimulated`
/// entry: context type (with a prominent account-wide-authority callout for
/// `Default`), name, expiry, a signer table (kind, verifier/address, the
/// FULL pubkey hex — not a prefix, so it is meaningfully verifiable against
/// `proposal_sha256` — and a PROPOSER tag), a policy table (typed params
/// where recognized, else the raw base64 XDR params string), `auth_rule_ids`,
/// and the two override warning lines when set.
///
/// Every snapshot-derived string is passed through `html_escape`. No
/// inline `<script>` or event-handler attribute is produced — this fn emits
/// static markup only, consistent with the page's `script-src 'self'` CSP.
///
/// `pub` (re-exported at the crate root) so `stellar-agent-approval-remote`
/// renders the identical markup for the SAME entry kind on the remote
/// approval surface, rather than duplicating this rendering logic.
#[must_use]
pub fn render_rule_proposal_definition_html(definition: &ContextRuleProposalSnapshot) -> String {
    let mut s = String::new();

    match &definition.context_type {
        RuleProposalContextType::Default => {
            s.push_str(
                "  <p class=\"warning\"><strong>WARNING:</strong> Default context grants \
                 ACCOUNT-WIDE AUTHORITY — this rule authorizes ANY contract invocation, \
                 not a scoped subset.</p>\n",
            );
        }
        RuleProposalContextType::CallContract { contract } => {
            s.push_str(&format!(
                "  <p>Context: CallContract {}</p>\n",
                html_escape(contract)
            ));
        }
        RuleProposalContextType::CreateContract { wasm_hash_hex } => {
            s.push_str(&format!(
                "  <p>Context: CreateContract (wasm hash) {}</p>\n",
                html_escape(wasm_hash_hex)
            ));
        }
        // RuleProposalContextType is #[non_exhaustive]; a future variant
        // renders with a minimal fallback rather than aborting the page.
        other => {
            s.push_str(&format!(
                "  <p>Context: (unrecognized: {})</p>\n",
                html_escape(&format!("{other:?}"))
            ));
        }
    }

    s.push_str(&format!(
        "  <p>Rule name: {}</p>\n",
        html_escape(&definition.name)
    ));
    let expiry = match definition.valid_until {
        Some(ledger) => format!("expires at ledger {ledger}"),
        None => "permanent (no expiry)".to_owned(),
    };
    s.push_str(&format!("  <p>Expiry: {}</p>\n", html_escape(&expiry)));

    s.push_str("  <h3>Signers</h3>\n  <table>\n");
    s.push_str(
        "    <tr><th>#</th><th>Kind</th><th>Address / verifier</th><th>Pubkey (hex)</th><th></th></tr>\n",
    );
    for (idx, signer) in definition.signers.iter().enumerate() {
        let (kind_label, address_cell, pubkey_cell) = match signer.kind {
            RuleProposalSignerKind::Delegated => (
                "Delegated",
                signer.address.as_deref().unwrap_or("<missing>").to_owned(),
                "—".to_owned(),
            ),
            RuleProposalSignerKind::External => (
                "External",
                signer.verifier.as_deref().unwrap_or("<missing>").to_owned(),
                // WYSIWYS: the FULL pubkey is rendered — not a prefix — so
                // the operator can meaningfully verify it against the
                // signer bytes bound into `proposal_sha256`. A truncated
                // prefix cannot be verified against the digest.
                signer
                    .pubkey_data
                    .as_deref()
                    .map(|bytes| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>())
                    .unwrap_or_else(|| "<none>".to_owned()),
            ),
        };
        let proposer_tag = if signer.is_proposer {
            "<strong>PROPOSER</strong>"
        } else {
            ""
        };
        s.push_str(&format!(
            "    <tr><td>{idx}</td><td>{}</td><td>{}</td><td>{}</td><td>{proposer_tag}</td></tr>\n",
            html_escape(kind_label),
            html_escape(&address_cell),
            html_escape(&pubkey_cell),
        ));
    }
    s.push_str("  </table>\n");

    if definition.policies.is_empty() {
        s.push_str("  <p>Policies: (none)</p>\n");
    } else {
        s.push_str("  <h3>Policies</h3>\n  <table>\n");
        s.push_str("    <tr><th>#</th><th>Policy contract</th><th>Params</th></tr>\n");
        for (idx, policy) in definition.policies.iter().enumerate() {
            let detail = match try_decode_spending_limit_params(&policy.params_xdr_b64) {
                Some(decoded) => match i64::try_from(decoded.limit_stroops) {
                    Ok(stroops_i64) => format!(
                        "spending-limit: {} XLM ({} stroops) / {} ledgers",
                        StellarAmount::from_stroops(stroops_i64).as_xlm_decimal_string(),
                        decoded.limit_stroops,
                        decoded.period_ledgers
                    ),
                    Err(_) => format!(
                        "spending-limit: {} stroops / {} ledgers",
                        decoded.limit_stroops, decoded.period_ledgers
                    ),
                },
                // WYSIWYS: an unrecognized policy still must show what the
                // operator is actually attesting to, not just its byte
                // count. The base64 XDR string is size-bounded (OZ policy
                // install params) so truncation is not a concern here.
                None => format!("(raw XDR params) {}", policy.params_xdr_b64),
            };
            s.push_str(&format!(
                "    <tr><td>{idx}</td><td>{}</td><td>{}</td></tr>\n",
                html_escape(&policy.policy_address),
                html_escape(&detail),
            ));
        }
        s.push_str("  </table>\n");
    }

    s.push_str(&format!(
        "  <p>Auth rule IDs: {}</p>\n",
        html_escape(&format!("{:?}", definition.auth_rule_ids))
    ));

    if definition.accept_mutable_verifier {
        s.push_str(
            "  <p class=\"warning\"><strong>WARNING:</strong> accept_mutable_verifier is \
             set — a mutable verifier/policy contract will NOT block install.</p>\n",
        );
    }
    if definition.accept_unknown_verifier {
        s.push_str(
            "  <p class=\"warning\"><strong>WARNING:</strong> accept_unknown_verifier is \
             set — an unrecognized verifier/policy wasm hash will NOT block install.</p>\n",
        );
    }

    s
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only; panics acceptable in unit tests"
    )]
    use super::*;
    use stellar_agent_core::approval::{
        DEFAULT_TTL_MS, PendingApproval, PendingApprovalStore, process_uid_for_attestation,
    };
    use tempfile::TempDir;

    const NOW_MS: u64 = 1_700_000_000_000;

    /// Build a payment view via a real store snapshot, with a memo carrying a
    /// `<script>` breakout attempt to exercise HTML escaping.
    fn payment_view(dir: &TempDir, attested: bool, snapshot_at: u64) -> PendingApprovalView {
        let mut store = PendingApprovalStore::open(dir.path().join("default.toml")).unwrap();
        let entry = PendingApproval::new_payment_pending(
            "b64xdr".to_owned(),
            b"fake-xdr",
            "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            2_500_000,
            "XLM".to_owned(),
            Some("<script>alert(1)</script>".to_owned()),
            100,
            7,
            process_uid_for_attestation().unwrap(),
            DEFAULT_TTL_MS,
        )
        .unwrap();
        let nonce = entry.approval_nonce.clone();
        store.insert(entry, NOW_MS).unwrap();
        if attested {
            store.record_attestation(&nonce, [0x11u8; 32]).unwrap();
        }
        store.snapshot(snapshot_at).into_iter().next().unwrap()
    }

    #[test]
    fn json_data_island_neutralises_script_breakout() {
        let out = json_data_island(&serde_json::json!({ "k": "a</script><b>&c" }));
        assert!(!out.contains("</script>"));
        let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(parsed["k"], "a</script><b>&c");
    }

    #[test]
    fn html_escape_neutralises_tags() {
        assert_eq!(html_escape("a<b>&\"'"), "a&lt;b&gt;&amp;&quot;&#x27;");
    }

    #[test]
    fn inbox_page_has_data_island_and_app_js() {
        let dir = TempDir::new().unwrap();
        let html = render_inbox_page(&[payment_view(&dir, false, NOW_MS)], 0, false);
        assert!(html.contains(r#"id="pending-data""#));
        assert!(html.contains(r#"src="/static/app.js""#));
    }

    #[test]
    fn detail_page_escapes_summary_and_offers_approve() {
        let dir = TempDir::new().unwrap();
        let view = payment_view(&dir, false, NOW_MS);
        let html = render_detail_page(&view, &"c".repeat(64), None);
        assert!(html.contains("Approve"));
        assert!(html.contains("Reject"));
        // The raw `<script>` memo must be escaped, never literal.
        assert!(!html.contains("<script>alert(1)</script>"));
        assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(html.contains(r#"id="approval-data""#));
    }

    #[test]
    fn detail_page_expired_hides_approve() {
        let dir = TempDir::new().unwrap();
        // Snapshot at the far future so the entry reports expired regardless of
        // the real creation clock stamped by `new_payment_pending`.
        let view = payment_view(&dir, false, u64::MAX);
        assert!(view.expired);
        let html = render_detail_page(&view, &"c".repeat(64), None);
        assert!(html.contains("expired"));
        assert!(!html.contains("id=\"approve-btn\""));
    }

    #[test]
    fn detail_page_attested_shows_blob() {
        let dir = TempDir::new().unwrap();
        let view = payment_view(&dir, true, NOW_MS);
        assert!(view.attested);
        let html = render_detail_page(&view, &"c".repeat(64), Some("BLOB123"));
        assert!(html.contains("BLOB123"));
        assert!(!html.contains("id=\"approve-btn\""));
    }

    // ── render_summary_html: every ApprovalKind variant ─────────────────────

    fn claim_view(dir: &TempDir) -> PendingApprovalView {
        let mut store = PendingApprovalStore::open(dir.path().join("default.toml")).unwrap();
        let entry = PendingApproval::new_claim_pending(
            "b64xdr".to_owned(),
            b"fake-xdr",
            "a".repeat(72),
            "B".to_owned() + &"A".repeat(57),
            "XLM".to_owned(),
            500,
            "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            100,
            1,
            process_uid_for_attestation().unwrap(),
            DEFAULT_TTL_MS,
        )
        .unwrap();
        store.insert(entry, NOW_MS).unwrap();
        store.snapshot(NOW_MS).into_iter().next().unwrap()
    }

    fn sign_with_passkey_view(dir: &TempDir) -> PendingApprovalView {
        let mut store = PendingApprovalStore::open(dir.path().join("default.toml")).unwrap();
        let entry = PendingApproval::new_passkey_pending(
            [0x01u8; 32],
            vec![0u8; 32],
            "CAAAA...BBBBB".to_owned(),
            vec![0],
            [0x02u8; 32],
            "localhost".to_owned(),
            process_uid_for_attestation().unwrap(),
            DEFAULT_TTL_MS,
        )
        .unwrap();
        store.insert(entry, NOW_MS).unwrap();
        store.snapshot(NOW_MS).into_iter().next().unwrap()
    }

    fn register_passkey_view(dir: &TempDir) -> PendingApprovalView {
        let mut store = PendingApprovalStore::open(dir.path().join("default.toml")).unwrap();
        let entry = PendingApproval::new_register_passkey_pending(
            "CAAAA...BBBBB".to_owned(),
            vec![0],
            [0x03u8; 32],
            "localhost".to_owned(),
            [0x04u8; 32],
            process_uid_for_attestation().unwrap(),
            DEFAULT_TTL_MS,
        )
        .unwrap();
        store.insert(entry, NOW_MS).unwrap();
        store.snapshot(NOW_MS).into_iter().next().unwrap()
    }

    fn toolset_first_invoke_gate_view(dir: &TempDir) -> PendingApprovalView {
        let mut store = PendingApprovalStore::open(dir.path().join("default.toml")).unwrap();
        let entry = PendingApproval::new_toolset_first_invoke_gate_pending(
            "my-toolset".to_owned(),
            "sign-payment".to_owned(),
            "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            "XLM".to_owned(),
            0,
            1_000_000,
            process_uid_for_attestation().unwrap(),
            DEFAULT_TTL_MS,
        )
        .unwrap();
        store.insert(entry, NOW_MS).unwrap();
        store.snapshot(NOW_MS).into_iter().next().unwrap()
    }

    fn trustline_clawback_opt_in_view(dir: &TempDir) -> PendingApprovalView {
        let mut store = PendingApprovalStore::open(dir.path().join("default.toml")).unwrap();
        let entry = PendingApproval::new_trustline_clawback_opt_in_pending(
            "Test SDF Network ; September 2015".to_owned(),
            "USDC".to_owned(),
            "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5".to_owned(),
            process_uid_for_attestation().unwrap(),
            DEFAULT_TTL_MS,
        )
        .unwrap();
        store.insert(entry, NOW_MS).unwrap();
        store.snapshot(NOW_MS).into_iter().next().unwrap()
    }

    /// Builds a `RuleProposalSimulated` view with a `Default` context (the
    /// account-wide-authority callout case), one `Delegated` proposer
    /// signer, one `External` (WebAuthn-shaped) non-proposer signer, one
    /// recognized spending-limit policy, and both override flags set — this
    /// single fixture exercises every renderer branch at once.
    fn rule_proposal_view(dir: &TempDir) -> PendingApprovalView {
        use base64::Engine as _;
        use stellar_agent_core::approval::{
            ContextRuleProposalSnapshot, RuleProposalContextType, RuleProposalPolicy,
            RuleProposalSigner,
        };
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

        let definition = ContextRuleProposalSnapshot::new(
            RuleProposalContextType::Default,
            "spend-daily".to_owned(),
            None,
            vec![
                RuleProposalSigner::delegated(
                    "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
                    true,
                ),
                RuleProposalSigner::external(
                    "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
                    vec![0xABu8; 65],
                    false,
                ),
            ],
            vec![RuleProposalPolicy::new(
                "CBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".to_owned(),
                params_b64,
            )],
            vec![0],
            true,
            true,
        );

        let mut store = PendingApprovalStore::open(dir.path().join("default.toml")).unwrap();
        let entry = PendingApproval::new_rule_proposal_pending(
            "CDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD".to_owned(),
            "Test SDF Network ; September 2015".to_owned(),
            "stellar:testnet".to_owned(),
            definition,
            [0x11u8; 32],
            "Default rule \"spend-daily\"".to_owned(),
            process_uid_for_attestation().unwrap(),
            DEFAULT_TTL_MS,
        )
        .unwrap();
        store.insert(entry, NOW_MS).unwrap();
        store.snapshot(NOW_MS).into_iter().next().unwrap()
    }

    fn rejected_view(dir: &TempDir) -> PendingApprovalView {
        let mut store = PendingApprovalStore::open(dir.path().join("default.toml")).unwrap();
        let entry = PendingApproval::new_payment_pending(
            "b64xdr".to_owned(),
            b"fake-xdr",
            "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            1_000,
            "XLM".to_owned(),
            None,
            100,
            1,
            process_uid_for_attestation().unwrap(),
            DEFAULT_TTL_MS,
        )
        .unwrap();
        let nonce = entry.approval_nonce.clone();
        store.insert(entry, NOW_MS).unwrap();
        store.reject(&nonce, NOW_MS, DEFAULT_TTL_MS).unwrap();
        store.snapshot(NOW_MS).into_iter().next().unwrap()
    }

    #[test]
    fn render_summary_html_covers_claim() {
        let dir = TempDir::new().unwrap();
        let html = render_summary_html(&claim_view(&dir).summary);
        assert!(html.contains("Balance id"));
        assert!(html.contains("Source"));
    }

    #[test]
    fn render_summary_html_covers_sign_with_passkey() {
        let dir = TempDir::new().unwrap();
        let html = render_summary_html(&sign_with_passkey_view(&dir).summary);
        assert!(html.contains("Smart account"));
        assert!(html.contains("RP id"));
    }

    #[test]
    fn render_summary_html_covers_register_passkey() {
        let dir = TempDir::new().unwrap();
        let html = render_summary_html(&register_passkey_view(&dir).summary);
        assert!(html.contains("Smart account"));
        assert!(html.contains("Rule ids"));
    }

    #[test]
    fn render_summary_html_covers_toolset_first_invoke_gate() {
        let dir = TempDir::new().unwrap();
        let html = render_summary_html(&toolset_first_invoke_gate_view(&dir).summary);
        assert!(html.contains("Toolset"));
        assert!(html.contains("Capability"));
        assert!(html.contains("Amount min"));
        assert!(html.contains("Amount max"));
    }

    #[test]
    fn render_summary_html_covers_trustline_clawback_opt_in() {
        let dir = TempDir::new().unwrap();
        let html = render_summary_html(&trustline_clawback_opt_in_view(&dir).summary);
        assert!(html.contains("Network"));
        assert!(html.contains("Issuer"));
    }

    #[test]
    fn render_summary_html_covers_rejected() {
        let dir = TempDir::new().unwrap();
        let html = render_summary_html(&rejected_view(&dir).summary);
        assert!(html.contains("Rejected kind"));
        assert!(html.contains("PaymentSimulated"));
    }

    #[test]
    fn render_summary_html_covers_rule_proposal() {
        let dir = TempDir::new().unwrap();
        let html = render_summary_html(&rule_proposal_view(&dir).summary);
        assert!(html.contains("Smart account"));
        assert!(html.contains("Proposal digest"));
    }

    #[test]
    fn kind_is_approvable_true_for_rule_proposal() {
        let dir = TempDir::new().unwrap();
        assert!(kind_is_approvable(&rule_proposal_view(&dir).summary));
    }

    #[test]
    fn render_rule_proposal_definition_html_shows_account_wide_authority_callout() {
        let dir = TempDir::new().unwrap();
        let view = rule_proposal_view(&dir);
        let ApprovalSummaryView::RuleProposal { definition, .. } = &view.summary else {
            panic!("expected RuleProposal summary");
        };
        let html = render_rule_proposal_definition_html(definition);
        assert!(
            html.contains("ACCOUNT-WIDE AUTHORITY"),
            "Default context must render the callout: {html}"
        );
    }

    #[test]
    fn render_rule_proposal_definition_html_tags_proposer_and_shows_full_pubkey() {
        let dir = TempDir::new().unwrap();
        let view = rule_proposal_view(&dir);
        let ApprovalSummaryView::RuleProposal { definition, .. } = &view.summary else {
            panic!("expected RuleProposal summary");
        };
        let html = render_rule_proposal_definition_html(definition);
        assert!(
            html.contains("<strong>PROPOSER</strong>"),
            "the delegated proposer signer must be tagged: {html}"
        );
        // WYSIWYS: the fixture's external signer pubkey is 65 bytes of
        // 0xAB — the FULL hex encoding (130 chars), not a truncated prefix,
        // must appear so the rendered value is verifiable against the
        // digest bound into proposal_sha256.
        let full_pubkey_hex = "ab".repeat(65);
        assert!(
            html.contains(&full_pubkey_hex),
            "external signer's FULL pubkey must render as hex, not a prefix: {html}"
        );
    }

    #[test]
    fn render_rule_proposal_definition_html_renders_typed_spending_limit() {
        let dir = TempDir::new().unwrap();
        let view = rule_proposal_view(&dir);
        let ApprovalSummaryView::RuleProposal { definition, .. } = &view.summary else {
            panic!("expected RuleProposal summary");
        };
        let html = render_rule_proposal_definition_html(definition);
        assert!(html.contains("spending-limit:"));
        assert!(html.contains("10000000 stroops"));
        assert!(html.contains("17280 ledgers"));
    }

    #[test]
    fn render_rule_proposal_definition_html_falls_back_to_raw_for_unrecognized_policy_params() {
        use base64::Engine as _;
        use stellar_agent_core::approval::{
            ContextRuleProposalSnapshot, RuleProposalContextType, RuleProposalPolicy,
            RuleProposalSigner,
        };
        let raw_params =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"not a spending limit");
        let definition = ContextRuleProposalSnapshot::new(
            RuleProposalContextType::CallContract {
                contract: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            },
            "spend-daily".to_owned(),
            None,
            vec![RuleProposalSigner::delegated(
                "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
                true,
            )],
            vec![RuleProposalPolicy::new(
                "CBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".to_owned(),
                raw_params.clone(),
            )],
            vec![0],
            false,
            false,
        );
        let html = render_rule_proposal_definition_html(&definition);
        assert!(!html.contains("spending-limit:"));
        // WYSIWYS: the fallback must show the ACTUAL params content, not
        // merely a byte count — a count is not verifiable against what
        // gets bound into proposal_sha256.
        assert!(
            html.contains(&raw_params),
            "raw fallback must render the actual base64 XDR string, not just a byte count: {html}"
        );
    }

    #[test]
    fn render_rule_proposal_definition_html_same_policy_address_different_params_render_differently()
     {
        use base64::Engine as _;
        use stellar_agent_core::approval::{
            ContextRuleProposalSnapshot, RuleProposalContextType, RuleProposalPolicy,
            RuleProposalSigner,
        };
        let params_a =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"unrecognized params A");
        let params_b =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"unrecognized params B");
        let build = |params: String| {
            ContextRuleProposalSnapshot::new(
                RuleProposalContextType::CallContract {
                    contract: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
                },
                "spend-daily".to_owned(),
                None,
                vec![RuleProposalSigner::delegated(
                    "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
                    true,
                )],
                // Same policy_address in both — only params_xdr_b64 differs.
                vec![RuleProposalPolicy::new(
                    "CBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".to_owned(),
                    params,
                )],
                vec![0],
                false,
                false,
            )
        };
        let html_a = render_rule_proposal_definition_html(&build(params_a));
        let html_b = render_rule_proposal_definition_html(&build(params_b));
        assert_ne!(
            html_a, html_b,
            "two proposals sharing a policy_address but with different params_xdr_b64 must \
             render differently, proving CONTENT (not just address) is displayed"
        );
    }

    #[test]
    fn render_rule_proposal_definition_html_shows_both_override_warnings() {
        let dir = TempDir::new().unwrap();
        let view = rule_proposal_view(&dir);
        let ApprovalSummaryView::RuleProposal { definition, .. } = &view.summary else {
            panic!("expected RuleProposal summary");
        };
        let html = render_rule_proposal_definition_html(definition);
        assert!(html.contains("accept_mutable_verifier is"));
        assert!(html.contains("accept_unknown_verifier is"));
    }

    #[test]
    fn render_rule_proposal_definition_html_escapes_malicious_rule_name() {
        use stellar_agent_core::approval::{
            ContextRuleProposalSnapshot, RuleProposalContextType, RuleProposalSigner,
        };
        let definition = ContextRuleProposalSnapshot::new(
            RuleProposalContextType::CallContract {
                contract: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            },
            "</script><script>alert(1)</script>".to_owned(),
            None,
            vec![RuleProposalSigner::delegated(
                "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
                false,
            )],
            vec![],
            vec![0],
            false,
            false,
        );
        let html = render_rule_proposal_definition_html(&definition);
        assert!(
            !html.contains("<script>alert(1)</script>"),
            "rule name must be HTML-escaped, not passed through raw: {html}"
        );
        assert!(html.contains("&lt;script&gt;"));
    }

    /// The detail page's "informational kind" actions branch (no interactive
    /// approve, reject only) fires for a kind that is not approvable
    /// (`kind_is_approvable` excludes passkey kinds), not expired, and not yet
    /// attested — distinct from the expired branch, which renders identical
    /// markup but is reached via a different condition.
    #[test]
    fn detail_page_informational_kind_offers_reject_only() {
        let dir = TempDir::new().unwrap();
        let view = sign_with_passkey_view(&dir);
        assert!(!view.expired);
        assert!(!view.attested);
        assert!(!kind_is_approvable(&view.summary));
        let html = render_detail_page(&view, &"c".repeat(64), None);
        assert!(html.contains(r#"id="reject-btn""#));
        assert!(!html.contains(r#"id="approve-btn""#));
    }

    /// A `Rejected` tombstone view offers neither Approve nor Reject.
    #[test]
    fn detail_page_rejected_tombstone_offers_no_actions() {
        let dir = TempDir::new().unwrap();
        let view = rejected_view(&dir);
        assert!(matches!(view.summary, ApprovalSummaryView::Rejected { .. }));
        let html = render_detail_page(&view, &"c".repeat(64), None);
        assert!(!html.contains(r#"id="approve-btn""#));
        assert!(!html.contains(r#"id="reject-btn""#));
    }

    #[test]
    fn render_not_found_page_escapes_nonce_and_links_inbox() {
        let html = render_not_found_page("<script>x</script>");
        assert!(!html.contains("<script>x</script>"));
        assert!(html.contains("&lt;script&gt;"));
        assert!(html.contains(r#"href="/inbox""#));
        assert!(html.contains("Approval not found"));
    }
}
