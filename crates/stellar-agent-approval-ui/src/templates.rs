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
//!
//! # Presentation
//!
//! Both pages render the shared identity from
//! [`stellar_agent_loopback_http::brand`] — inline stylesheet, inline mark,
//! no fetched asset — plus the page-local rules in [`INBOX_STYLE`] and
//! [`DETAIL_STYLE`].
//!
//! # What is server-rendered and what is not
//!
//! Everything the operator consents to is server-rendered: the amount in both
//! denominations, the untruncated destination, and every remaining summary
//! field. The client formats only the two absolute unix-millisecond timestamps
//! into readable text, reading them from `data-` attributes; if its script
//! never runs, the raw values stay on the page rather than the field vanishing.

use stellar_agent_core::amount::StellarAmount;
use stellar_agent_core::approval::{
    ApprovalSummaryView, ContextRuleProposalSnapshot, PendingApprovalView, RuleProposalContextType,
    RuleProposalSignerKind, try_decode_spending_limit_params,
};
use stellar_agent_loopback_http::brand::{
    BRAND_STYLE, BUDDY_MARK_SVG, CARD_BRAND_HEADER, TRUST_LINE_LOOPBACK,
};

// ─────────────────────────────────────────────────────────────────────────────
// Page-local styling
// ─────────────────────────────────────────────────────────────────────────────

/// The approval inbox's own rules: the rows and the empty state.
///
/// Public because `stellar-agent-approval-remote` renders the same inbox from
/// the same [`APP_SHARED_JS`](crate::APP_SHARED_JS) row markup; a second copy
/// of these rules would let the two surfaces drift.
pub const INBOX_STYLE: &str = r"
.approval {
  display: flex;
  align-items: center;
  gap: 14px;
  background: #ffffff;
  border: 2px solid var(--field-border);
  border-radius: 12px;
  padding: 14px 18px;
  margin-bottom: 12px;
  text-decoration: none;
  color: inherit;
}
.ap-main { flex: 1; min-width: 0; }
.ap-title { font-size: 15px; font-weight: 700; color: var(--ink-navy); }
.ap-meta {
  font-size: 12px;
  color: var(--muted-blue);
  margin-top: 2px;
  font-family: var(--font-mono);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.ap-exp { font-size: 11.5px; color: var(--body-blue); white-space: nowrap; text-align: right; }
.ap-exp b { font-weight: 700; }
.ap-exp b.soon { color: var(--danger-ink); }
.chev { color: var(--detail-blue-1); font-size: 18px; }
.empty { text-align: center; padding: 28px 0 6px; }
.empty .buddy { width: 64px; margin: 0 auto; }
.empty p { font-size: 13px; color: var(--muted-blue); margin-top: 8px; }
";

/// The approval detail page's own rules: the decision card, its amount
/// treatment, and the post-decision result panel.
///
/// Public for the same reason as [`INBOX_STYLE`]: both approval surfaces
/// render the same decision card.
pub const DETAIL_STYLE: &str = r"
.decision {
  background: #ffffff;
  border: 2px solid var(--field-border);
  border-radius: 14px;
  padding: 22px 24px;
}
.d-kind { display: flex; align-items: center; gap: 10px; margin-bottom: 14px; flex-wrap: wrap; }
.d-origin { font-size: 12px; color: var(--muted-blue); }
.d-amount {
  font-size: 32px;
  font-weight: 800;
  color: var(--ink-navy);
  letter-spacing: -.5px;
  word-break: break-word;
}
.d-amount small {
  font-size: 13px;
  font-weight: 600;
  color: var(--muted-blue);
  margin-left: 8px;
  white-space: nowrap;
}
.expiry { margin-top: 14px; font-size: 12.5px; color: var(--body-blue); line-height: 1.5; }
.expiry b { color: var(--ink-navy); }
.attested { margin-top: 18px; }
.attested h2 {
  font-size: 11px;
  font-weight: 700;
  letter-spacing: .8px;
  text-transform: uppercase;
  color: var(--muted-blue);
  margin-bottom: 6px;
}
.attested p { font-size: 12.5px; color: var(--body-blue); margin-bottom: 8px; line-height: 1.5; }
.result { margin-top: 16px; font-size: 13px; color: var(--body-blue); }
.result p { margin-bottom: 8px; }
.copy-btn {
  margin-top: 8px;
  border-radius: 8px;
  padding: 8px 14px;
  font-size: 13px;
  font-weight: 600;
  border: 2px solid var(--field-border);
  background: #ffffff;
  color: var(--face-navy);
  cursor: pointer;
  font-family: inherit;
}
";

// ─────────────────────────────────────────────────────────────────────────────
// Shared page furniture
// ─────────────────────────────────────────────────────────────────────────────

/// Renders the header bar carried by the inbox and detail pages.
fn topbar_html(right_label: &str) -> String {
    format!(
        r#"  <header class="topbar">
    {BUDDY_MARK_SVG}
    <div><div class="tb-over">STELLAR</div><div class="tb-word">Agent Wallet</div></div>
    <div class="tb-right">{right}</div>
  </header>"#,
        right = html_escape(right_label)
    )
}

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

/// `true` for a bidirectional-override or invisible-format code point.
///
/// U+061C (Arabic letter mark), U+200B..U+200F (zero-width space, joiners, and
/// the LTR/RTL marks), U+202A..U+202E (the embedding and override controls,
/// including U+202E RIGHT-TO-LEFT OVERRIDE), U+2066..U+2069 (the isolates),
/// and U+FEFF (zero-width no-break space).
const fn is_bidi_or_format_control(c: char) -> bool {
    matches!(
        c,
        '\u{061C}' | '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{FEFF}'
    )
}

/// HTML-escapes a string for safe interpolation into element text or an
/// attribute value, and neutralises bidirectional and invisible-format
/// controls.
///
/// The five-character escaping stops a value from becoming markup. The control
/// substitution stops a value from lying about itself while staying valid text:
/// a memo or asset code carrying U+202E reverses the rendering of everything
/// after it, so an operator reading a destination or an amount on the decision
/// surface can see a different string than the one being signed. Every such
/// code point is replaced with U+FFFD, which is visible, so the tampering shows
/// rather than takes effect.
///
/// One pass covers both: the control set and the five escaped ASCII characters
/// are disjoint, so ordering between them cannot matter.
///
/// Public so `stellar-agent-approval-remote` escapes through the same
/// definition; a second copy would drift.
#[must_use]
pub fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            c if is_bidi_or_format_control(c) => out.push('\u{FFFD}'),
            c => out.push(c),
        }
    }
    out
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
            | ApprovalSummaryView::MppCharge { .. }
    )
}

/// Render the inbox shell page.
///
/// Seeds the current snapshot into `#pending-data`; `/static/app.js` re-fetches
/// `/pending.json` every two seconds and updates the rows and the title badge.
///
/// The empty state is always present in the markup, because `/static/app.js`
/// composes rows through `createElement` and cannot introduce the brand mark
/// itself. It carries the `hidden` attribute when the seeded snapshot has
/// entries; the script toggles that attribute on every refresh.
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
    let topbar = topbar_html("Approvals");
    let empty_hidden = if pending.is_empty() { "" } else { " hidden" };

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Stellar Agent Wallet — Approvals</title>
  <style>{BRAND_STYLE}{INBOX_STYLE}</style>
</head>
<body>
{topbar}
  <main class="content">
    <h1>Pending approvals</h1>
    <p class="sub" id="status">Loading&hellip;</p>
    <div id="inbox"></div>
    <div class="empty" id="empty-state"{empty_hidden}>
      <span class="buddy-face" data-state="ok">{BUDDY_MARK_SVG}</span>
      <p>All caught up &mdash; no approvals waiting.</p>
    </div>
  </main>
  <script type="application/json" id="pending-data">{data_island}</script>
  <script src="/static/app-shared.js"></script>
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
  <style>{BRAND_STYLE}</style>
</head>
<body>
  <main class="page">
    <div class="card">
      {BUDDY_MARK_SVG}
{CARD_BRAND_HEADER}
      <h1>Approval not found</h1>
      <p class="lead">No pending approval with nonce <code class="chip">{nonce}</code>
         is in the queue. It may have been approved, rejected, or expired
         already.</p>
      <p class="help"><a class="back" href="/inbox">&larr; Back to inbox</a></p>
{TRUST_LINE_LOOPBACK}
    </div>
  </main>
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
///
/// The two absolute unix-millisecond timestamps are rendered as text AND as
/// `data-created-ms` / `data-expires-ms` attributes, from which
/// `/static/app.js` derives the readable wording. The raw values are what
/// survives if the script does not run.
#[must_use]
pub(crate) fn render_detail_page(
    view: &PendingApprovalView,
    csrf_hex: &str,
    attestation_blob: Option<&str>,
) -> String {
    let approvable = kind_is_approvable(&view.summary) && !view.expired && !view.attested;
    let summary_html = render_summary_html(view);
    // The full rule definition (context callout, signer table, policy table,
    // override warnings) is not dt/dd-shaped, so it renders as its own block
    // AFTER the `<dl>` closes rather than inside `summary_html`.
    let rule_proposal_extra_html = match &view.summary {
        ApprovalSummaryView::RuleProposal { definition, .. } => format!(
            "<div class=\"ruledef\">\n{}</div>",
            render_rule_proposal_definition_html(definition)
        ),
        _ => String::new(),
    };

    let (kind_label, kind_is_passkey) = kind_pill(view);
    let kind_class = if kind_is_passkey { "kind warn" } else { "kind" };

    // The neutral (pending) state carries no notice: the expiry line already
    // states where the request stands. A notice appears only when the entry
    // can no longer be approved, so it never competes with the decision.
    let status_notice = if view.attested {
        r#"<div class="notice">Already resolved &mdash; consent for this request is recorded.</div>"#
    } else if matches!(view.summary, ApprovalSummaryView::Rejected { .. }) {
        r#"<div class="notice">This request was rejected. Nothing was signed.</div>"#
    } else if view.expired {
        r#"<div class="notice warn">This request has expired. It can only be rejected now.</div>"#
    } else {
        ""
    };

    let attested_block = match (view.attested, attestation_blob) {
        (true, Some(blob)) => format!(
            "<div class=\"attested\">\n\
             <h2>Recorded attestation</h2>\n\
             <p>This approval was already recorded. Present this attestation to \
             the matching commit tool:</p>\n\
             <textarea class=\"output\" readonly rows=\"3\">{}</textarea>\n\
             </div>",
            html_escape(blob)
        ),
        _ => String::new(),
    };

    let actions = if approvable {
        format!(
            r#"<div class="actions" id="actions">
        <button class="btn approve" id="approve-btn" type="button">{}</button>
        <button class="btn reject" id="reject-btn" type="button">Reject</button>
      </div>
      <p class="caution">Approve only if you expected this request. Nothing is signed until you decide.</p>"#,
            html_escape(approve_button_label(&view.summary))
        )
    } else if view.attested || matches!(view.summary, ApprovalSummaryView::Rejected { .. }) {
        String::new()
    } else {
        // Expired-but-unresolved and informational (passkey) kinds: a reject
        // still tombstones the entry, so the destructive action stays.
        r#"<div class="actions" id="actions">
        <button class="btn reject" id="reject-btn" type="button">Reject</button>
      </div>"#
            .to_owned()
    };

    // The sentence around the two timestamps is chosen server-side, because
    // only the server knows whether a decision is still available. A live
    // request gets the remaining-time form and the clause naming what happens
    // at expiry; one that can no longer be approved gets the plain form, with
    // no action clause to contradict a page that offers no approve button.
    // `data-expiry-form` tells `/static/app-shared.js` which slot filling the
    // sentence expects.
    let expiry_line = if view.expired
        || view.attested
        || matches!(view.summary, ApprovalSummaryView::Rejected { .. })
    {
        format!(
            r#"<p class="expiry" id="expiry-line" data-created-ms="{created}" data-expires-ms="{expires}" data-expiry-form="absolute">
        Created <b id="created-text">{created} (unix ms)</b>. Expiry:
        <b id="expires-text">{expires} (unix ms)</b>.</p>"#,
            created = view.created_at_unix_ms,
            expires = view.expires_at_unix_ms,
        )
    } else {
        format!(
            r#"<p class="expiry" id="expiry-line" data-created-ms="{created}" data-expires-ms="{expires}" data-expiry-form="remaining">
        Created <b id="created-text">{created} (unix ms)</b>, expires
        <b id="expires-text">{expires} (unix ms)</b>. After that this request can
        only be rejected.</p>"#,
            created = view.created_at_unix_ms,
            expires = view.expires_at_unix_ms,
        )
    };

    let data_island = json_data_island(&serde_json::json!({
        "nonce": view.approval_nonce,
        "csrf": csrf_hex,
        "approvable": approvable,
    }));
    let topbar = topbar_html("Approvals");

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Approval detail — Stellar Agent Wallet</title>
  <style>{BRAND_STYLE}{DETAIL_STYLE}</style>
</head>
<body>
{topbar}
  <main class="content">
    <a class="back" href="/inbox">&larr; Back to inbox</a>
    <div class="decision">
      <div class="d-kind">
        <span class="{kind_class}">{kind_label}</span>
        <span class="d-origin">requested by your wallet agent</span>
      </div>
      {status_notice}
{summary_html}
      {rule_proposal_extra_html}
      {expiry_line}
      {actions}
      {attested_block}
      <div class="result" id="result"></div>
    </div>
  </main>
  <script type="application/json" id="approval-data">{data_island}</script>
  <script src="/static/app-shared.js"></script>
  <script src="/static/app.js"></script>
</body>
</html>"#,
        kind_class = kind_class,
        kind_label = html_escape(&kind_label),
        status_notice = status_notice,
        expiry_line = expiry_line,
        summary_html = summary_html,
        rule_proposal_extra_html = rule_proposal_extra_html,
        attested_block = attested_block,
        actions = actions,
        data_island = data_island,
    )
}

/// The kind pill's label, and whether it takes the amber `.warn` variant.
///
/// Passkey kinds take `.warn`: they are the two kinds this UI cannot approve
/// (the ceremony happens in the browser bridge), so the pill has to read
/// differently from the kinds that carry a decision here.
///
/// Falls back to the entry's `kind_name` for a future
/// [`ApprovalSummaryView`] variant, which is `#[non_exhaustive]`.
pub fn kind_pill(view: &PendingApprovalView) -> (String, bool) {
    match &view.summary {
        ApprovalSummaryView::Payment { .. } => ("PAYMENT".to_owned(), false),
        ApprovalSummaryView::Claim { .. } => ("CLAIM".to_owned(), false),
        ApprovalSummaryView::MppCharge { .. } => ("CHARGE".to_owned(), false),
        ApprovalSummaryView::RuleProposal { .. } => ("RULE PROPOSAL".to_owned(), false),
        ApprovalSummaryView::SignWithPasskey { .. }
        | ApprovalSummaryView::RegisterPasskey { .. } => ("PASSKEY".to_owned(), true),
        ApprovalSummaryView::ToolsetFirstInvokeGate { .. } => ("TOOLSET GATE".to_owned(), false),
        ApprovalSummaryView::TrustlineClawbackOptIn { .. } => ("CLAWBACK OPT-IN".to_owned(), false),
        ApprovalSummaryView::Rejected { .. } => ("REJECTED".to_owned(), false),
        _ => (view.kind_name.to_uppercase(), false),
    }
}

/// The approve button's label, naming what is being approved.
///
/// Only reached for the kinds this UI can approve; the passkey kinds and the
/// rejected tombstone never render an approve button.
pub fn approve_button_label(summary: &ApprovalSummaryView) -> &'static str {
    match summary {
        ApprovalSummaryView::Payment { .. } => "Approve payment",
        ApprovalSummaryView::Claim { .. } => "Approve claim",
        ApprovalSummaryView::MppCharge { .. } => "Approve charge",
        ApprovalSummaryView::RuleProposal { .. } => "Approve rule proposal",
        ApprovalSummaryView::ToolsetFirstInvokeGate { .. } => "Approve toolset access",
        ApprovalSummaryView::TrustlineClawbackOptIn { .. } => "Approve opt-in",
        _ => "Approve",
    }
}

/// Renders the amount headline, the untruncated primary address, and the
/// remaining summary fields for an entry.
///
/// The amount is shown in both denominations — the human one for reading, the
/// stroop count for matching against the CLI and the audit record — and the
/// primary address is never truncated, so what the operator verifies is the
/// whole value rather than a prefix of it. The nonce leads the field grid on
/// every kind: it is the handle the CLI prints and the audit record keys on.
pub fn render_summary_html(view: &PendingApprovalView) -> String {
    fn row(label: &str, value: &str) -> String {
        format!(
            "        <dt>{}</dt><dd>{}</dd>\n",
            html_escape(label),
            html_escape(value)
        )
    }

    /// The amount headline for a stroop-denominated (classic Stellar) amount.
    ///
    /// `StellarAmount` owns the stroop-to-decimal conversion, including the
    /// protocol's seven-decimal quantisation; the asset code is only ever
    /// appended to it, never used to rescale it.
    fn amount_headline(amount_stroops: i64, asset: &str) -> String {
        format!(
            "      <div class=\"d-amount\">{} {} <small>{} stroops</small></div>\n",
            html_escape(&StellarAmount::from_stroops(amount_stroops).as_xlm_decimal_string()),
            html_escape(asset_code(asset)),
            amount_stroops
        )
    }

    fn address_block(label: &str, value: &str) -> String {
        format!(
            "      <div class=\"addr-label\">{}</div>\n      <div class=\"addr\">{}</div>\n",
            html_escape(label),
            html_escape(value)
        )
    }

    let facts = |rows: &str| {
        format!(
            "      <dl class=\"facts\">\n{}{rows}      </dl>\n",
            row("Nonce", &view.approval_nonce)
        )
    };

    match &view.summary {
        ApprovalSummaryView::Payment {
            to,
            amount_stroops,
            asset,
            memo,
            fee_stroops,
            seq_num,
        } => {
            let mut rows = String::new();
            rows.push_str(&row("Asset", asset));
            rows.push_str(&row("Memo", memo.as_deref().unwrap_or("(none)")));
            rows.push_str(&row("Simulated fee (stroops)", &fee_stroops.to_string()));
            rows.push_str(&row("Simulated seq num", &seq_num.to_string()));
            format!(
                "{}{}{}",
                amount_headline(*amount_stroops, asset),
                address_block("Destination", to),
                facts(&rows)
            )
        }
        ApprovalSummaryView::Claim {
            balance_id_strkey,
            asset,
            amount_stroops,
            source,
            fee_stroops,
            seq_num,
        } => {
            let mut rows = String::new();
            rows.push_str(&row("Asset", asset));
            rows.push_str(&row("Source", source));
            rows.push_str(&row("Simulated fee (stroops)", &fee_stroops.to_string()));
            rows.push_str(&row("Simulated seq num", &seq_num.to_string()));
            format!(
                "{}{}{}",
                amount_headline(*amount_stroops, asset),
                address_block("Balance id", balance_id_strkey),
                facts(&rows)
            )
        }
        ApprovalSummaryView::SignWithPasskey {
            smart_account_redacted,
            rule_ids,
            rp_id,
        } => {
            let mut rows = String::new();
            rows.push_str(&row("Rule ids", &format!("{rule_ids:?}")));
            rows.push_str(&row("RP id", rp_id));
            format!(
                "{}{}",
                address_block("Smart account", smart_account_redacted),
                facts(&rows)
            )
        }
        ApprovalSummaryView::RegisterPasskey {
            smart_account_redacted,
            rule_ids,
            rp_id,
        } => {
            let mut rows = String::new();
            rows.push_str(&row("Rule ids", &format!("{rule_ids:?}")));
            rows.push_str(&row("RP id", rp_id));
            format!(
                "{}{}",
                address_block("Smart account", smart_account_redacted),
                facts(&rows)
            )
        }
        ApprovalSummaryView::ToolsetFirstInvokeGate {
            toolset_name,
            capability,
            destination_redacted,
            asset,
            amount_min_stroops,
            amount_max_stroops,
        } => {
            let mut rows = String::new();
            rows.push_str(&row("Toolset", toolset_name));
            rows.push_str(&row("Capability", capability));
            rows.push_str(&row("Asset", asset));
            rows.push_str(&row(
                "Amount min (stroops)",
                &amount_min_stroops.to_string(),
            ));
            rows.push_str(&row(
                "Amount max (stroops)",
                &amount_max_stroops.to_string(),
            ));
            format!(
                "{}{}",
                address_block("Destination", destination_redacted),
                facts(&rows)
            )
        }
        ApprovalSummaryView::TrustlineClawbackOptIn {
            network,
            code,
            issuer_redacted,
        } => {
            let mut rows = String::new();
            rows.push_str(&row("Network", network));
            rows.push_str(&row("Asset code", code));
            format!(
                "{}{}",
                address_block("Issuer", issuer_redacted),
                facts(&rows)
            )
        }
        ApprovalSummaryView::RuleProposal {
            smart_account_redacted,
            chain_id,
            proposal_sha256_hex,
            ..
        } => {
            // The full rule definition (context, signers, policies, warnings)
            // is NOT dt/dd-shaped (it needs tables and callout paragraphs), so
            // it is rendered separately by `render_rule_proposal_definition_html`
            // and inserted by the caller AFTER this block, keeping the HTML
            // validly nested.
            let mut rows = String::new();
            rows.push_str(&row("Chain ID", chain_id));
            rows.push_str(&row("Proposal digest", proposal_sha256_hex));
            format!(
                "{}{}",
                address_block("Smart account", smart_account_redacted),
                facts(&rows)
            )
        }
        ApprovalSummaryView::MppCharge {
            profile,
            chain_id,
            payer_redacted,
            transport,
            authority,
            target,
            amount,
            currency,
            recipient_redacted,
            challenge_expires_at_unix,
            simulated_fee_stroops,
        } => {
            // The amount stays in the token contract's own base units: this
            // charge is denominated in an arbitrary token whose decimal scale
            // the wallet does not have here, and a seven-decimal reading of it
            // would state a value the operator is not actually authorising.
            let mut rows = String::new();
            rows.push_str(&row("Profile", profile));
            rows.push_str(&row("Network", chain_id));
            rows.push_str(&row("Payer", payer_redacted));
            rows.push_str(&row("Transport", transport));
            rows.push_str(&row("Authority", authority));
            rows.push_str(&row("Target", target));
            rows.push_str(&row("Token contract", currency));
            rows.push_str(&row(
                "Challenge expires (Unix)",
                &challenge_expires_at_unix.to_string(),
            ));
            rows.push_str(&row(
                "Simulated fee (stroops)",
                &simulated_fee_stroops.to_string(),
            ));
            format!(
                "      <div class=\"d-amount\">{} <small>base units of the token contract</small></div>\n{}{}",
                html_escape(amount),
                address_block("Recipient", recipient_redacted),
                facts(&rows)
            )
        }
        ApprovalSummaryView::Rejected { original_kind_name } => {
            facts(&row("Rejected kind", original_kind_name))
        }
        // `ApprovalSummaryView` is `#[non_exhaustive]`; a future variant renders
        // a minimal placeholder rather than failing to build.
        _ => facts("        <dt>Summary</dt><dd>(unrecognised kind)</dd>\n"),
    }
}

/// The displayable code of an asset identifier (`"XLM"` or `"<code>:<issuer>"`).
///
/// Only the headline uses the short form; the untouched identifier, issuer
/// included, is always rendered as its own field.
pub fn asset_code(asset: &str) -> &str {
    asset.split(':').next().unwrap_or(asset)
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

    /// A bidirectional override inside a rendered value is neutralised.
    ///
    /// U+202E reverses the rendering of everything after it: a memo or asset
    /// code carrying one makes the operator read a different destination or
    /// amount than the one being signed, while the page's HTML stays perfectly
    /// well-formed. Every such code point becomes U+FFFD, which is visible.
    #[test]
    fn html_escape_neutralises_bidi_and_invisible_format_controls() {
        for control in [
            '\u{061C}', '\u{200B}', '\u{200E}', '\u{200F}', '\u{202A}', '\u{202E}', '\u{2066}',
            '\u{2069}', '\u{FEFF}',
        ] {
            let escaped = html_escape(&format!("a{control}b"));
            assert_eq!(
                escaped, "a\u{FFFD}b",
                "U+{:04X} must be replaced with U+FFFD",
                control as u32
            );
        }
        // Ordinary text, including non-ASCII, is untouched.
        assert_eq!(html_escape("a\u{00E9}\u{4E2D}b"), "a\u{00E9}\u{4E2D}b");
    }

    /// The neutralisation reaches a real page: a memo carrying U+202E renders
    /// as U+FFFD with no raw override byte anywhere in the response.
    #[test]
    fn detail_page_neutralises_a_bidi_override_in_a_memo() {
        let dir = TempDir::new().unwrap();
        let mut store = PendingApprovalStore::open(dir.path().join("default.toml")).unwrap();
        let entry = PendingApproval::new_payment_pending(
            "b64xdr".to_owned(),
            b"fake-xdr",
            "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            1_000,
            "XLM".to_owned(),
            Some("pay \u{202E}MLX 000001\u{202C} now".to_owned()),
            100,
            1,
            process_uid_for_attestation().unwrap(),
            DEFAULT_TTL_MS,
        )
        .unwrap();
        store.insert(entry, NOW_MS).unwrap();
        let view = store.snapshot(NOW_MS).into_iter().next().unwrap();

        let html = render_detail_page(&view, &"c".repeat(64), None);
        assert!(
            !html.contains('\u{202E}'),
            "no raw right-to-left override may reach the page"
        );
        assert!(
            html.contains('\u{FFFD}'),
            "the override must render as the replacement character: {html}"
        );
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

    fn mpp_charge_view(dir: &TempDir) -> PendingApprovalView {
        let mut store = PendingApprovalStore::open(dir.path().join("default.toml")).unwrap();
        let now = stellar_agent_core::timefmt::now_unix_ms().unwrap();
        let recipient = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM";
        let entry = PendingApproval::new_mpp_charge_pending(
            [0x11; 32],
            [0x22; 32],
            "default".to_owned(),
            "stellar:testnet".to_owned(),
            "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            "http".to_owned(),
            "merchant.example".to_owned(),
            "/checkout".to_owned(),
            "1000000".to_owned(),
            recipient.to_owned(),
            recipient.to_owned(),
            now / 1_000 + 3_600,
            1_100,
            process_uid_for_attestation().unwrap(),
            DEFAULT_TTL_MS,
        )
        .unwrap();
        store.insert(entry, now).unwrap();
        store.snapshot(now).into_iter().next().unwrap()
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
        let html = render_summary_html(&claim_view(&dir));
        assert!(html.contains("Balance id"));
        assert!(html.contains("Source"));
    }

    #[test]
    fn render_summary_html_covers_sign_with_passkey() {
        let dir = TempDir::new().unwrap();
        let html = render_summary_html(&sign_with_passkey_view(&dir));
        assert!(html.contains("Smart account"));
        assert!(html.contains("RP id"));
    }

    #[test]
    fn render_summary_html_covers_register_passkey() {
        let dir = TempDir::new().unwrap();
        let html = render_summary_html(&register_passkey_view(&dir));
        assert!(html.contains("Smart account"));
        assert!(html.contains("Rule ids"));
    }

    #[test]
    fn render_summary_html_covers_toolset_first_invoke_gate() {
        let dir = TempDir::new().unwrap();
        let html = render_summary_html(&toolset_first_invoke_gate_view(&dir));
        assert!(html.contains("Toolset"));
        assert!(html.contains("Capability"));
        assert!(html.contains("Amount min"));
        assert!(html.contains("Amount max"));
    }

    #[test]
    fn render_summary_html_covers_trustline_clawback_opt_in() {
        let dir = TempDir::new().unwrap();
        let html = render_summary_html(&trustline_clawback_opt_in_view(&dir));
        assert!(html.contains("Network"));
        assert!(html.contains("Issuer"));
    }

    #[test]
    fn render_summary_html_covers_rejected() {
        let dir = TempDir::new().unwrap();
        let html = render_summary_html(&rejected_view(&dir));
        assert!(html.contains("Rejected kind"));
        assert!(html.contains("PaymentSimulated"));
    }

    #[test]
    fn render_summary_html_covers_rule_proposal() {
        let dir = TempDir::new().unwrap();
        let html = render_summary_html(&rule_proposal_view(&dir));
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

    // ── Brand surface ────────────────────────────────────────────────────

    fn every_page(dir: &TempDir) -> Vec<String> {
        let view = payment_view(dir, false, NOW_MS);
        vec![
            render_inbox_page(std::slice::from_ref(&view), 0, false),
            render_inbox_page(&[], 0, false),
            render_detail_page(&view, &"c".repeat(64), None),
            render_not_found_page("nonce"),
        ]
    }

    /// A duplicated stylesheet would silently double every rule; a missing one
    /// would render the page unstyled.
    #[test]
    fn every_page_embeds_the_brand_style_exactly_once() {
        let dir = TempDir::new().unwrap();
        for html in every_page(&dir) {
            assert_eq!(
                html.matches(BRAND_STYLE).count(),
                1,
                "the brand style must appear exactly once per page"
            );
        }
    }

    #[test]
    fn every_page_embeds_the_brand_mark() {
        let dir = TempDir::new().unwrap();
        for html in every_page(&dir) {
            assert!(
                html.contains(BUDDY_MARK_SVG),
                "the brand mark must be present on the page"
            );
        }
    }

    /// `img-src 'self'` blocks every remote origin, so a page referencing one
    /// would render a hole rather than fail loudly.
    #[test]
    fn every_page_references_no_external_origin() {
        let dir = TempDir::new().unwrap();
        for html in every_page(&dir) {
            assert!(!html.contains("http://"));
            assert!(!html.contains("https://"));
        }
    }

    // ── Detail page: what the operator consents to ───────────────────────

    /// The amount appears in both denominations and the destination in full:
    /// the human form is what gets read, the stroop count is what matches the
    /// CLI and the audit record, and a truncated address cannot be verified.
    #[test]
    fn detail_page_renders_payment_amount_in_both_denominations_and_the_full_destination() {
        let dir = TempDir::new().unwrap();
        let view = payment_view(&dir, false, NOW_MS);
        let html = render_detail_page(&view, &"c".repeat(64), None);

        // The fixture is 2_500_000 stroops of XLM.
        assert!(
            html.contains("0.2500000 XLM"),
            "the human denomination must be rendered: {html}"
        );
        assert!(
            html.contains("2500000 stroops"),
            "the stroop count must be rendered alongside it: {html}"
        );
        let destination = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        assert!(
            html.contains(&format!(r#"<div class="addr">{destination}</div>"#)),
            "the destination must render whole, in the address block: {html}"
        );
    }

    /// The conversion is `StellarAmount`'s, so the seven-decimal quantisation
    /// holds at a magnitude a float would already have rounded.
    #[test]
    fn detail_page_payment_amount_survives_the_f64_precision_boundary() {
        let dir = TempDir::new().unwrap();
        let mut store = PendingApprovalStore::open(dir.path().join("default.toml")).unwrap();
        let entry = PendingApproval::new_payment_pending(
            "b64xdr".to_owned(),
            b"fake-xdr",
            "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            9_007_199_254_740_993, // 2^53 + 1
            "XLM".to_owned(),
            None,
            100,
            7,
            process_uid_for_attestation().unwrap(),
            DEFAULT_TTL_MS,
        )
        .unwrap();
        store.insert(entry, NOW_MS).unwrap();
        let view = store.snapshot(NOW_MS).into_iter().next().unwrap();

        let html = render_detail_page(&view, &"c".repeat(64), None);
        assert!(html.contains("900719925.4740993 XLM"), "{html}");
        assert!(html.contains("9007199254740993 stroops"), "{html}");
    }

    /// A non-XLM classic asset keeps the protocol's seven-decimal scale and
    /// carries its own code; the issuer stays on the untouched `Asset` field.
    #[test]
    fn detail_page_renders_a_non_xlm_asset_with_its_own_code() {
        let dir = TempDir::new().unwrap();
        let mut store = PendingApprovalStore::open(dir.path().join("default.toml")).unwrap();
        let issuer = "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5";
        let entry = PendingApproval::new_payment_pending(
            "b64xdr".to_owned(),
            b"fake-xdr",
            "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            12_500_000,
            format!("USDC:{issuer}"),
            None,
            100,
            7,
            process_uid_for_attestation().unwrap(),
            DEFAULT_TTL_MS,
        )
        .unwrap();
        store.insert(entry, NOW_MS).unwrap();
        let view = store.snapshot(NOW_MS).into_iter().next().unwrap();

        let html = render_detail_page(&view, &"c".repeat(64), None);
        assert!(html.contains("1.2500000 USDC"), "{html}");
        assert!(
            html.contains(&format!("USDC:{issuer}")),
            "the full asset identifier, issuer included, must still render: {html}"
        );
    }

    /// The button names what is being approved, so a mis-navigated tab cannot
    /// be confirmed on muscle memory alone.
    #[test]
    fn detail_page_approve_button_names_the_kind() {
        let dir = TempDir::new().unwrap();
        let html = render_detail_page(&payment_view(&dir, false, NOW_MS), &"c".repeat(64), None);
        assert!(html.contains(">Approve payment</button>"), "{html}");
        assert!(html.contains(r#"class="btn reject""#), "{html}");
        assert!(
            html.contains("Nothing is signed until you decide."),
            "{html}"
        );
    }

    /// The kind pill is total over every summary variant, and the two passkey
    /// kinds take the amber variant.
    #[test]
    fn detail_page_kind_pill_covers_every_kind() {
        // A store file holds one entry per fixture, so each fixture gets its
        // own directory rather than reading back the first entry written.
        type Fixture = fn(&TempDir) -> PendingApprovalView;
        let fixtures: [(Fixture, &str, bool); 8] = [
            (claim_view, "CLAIM", false),
            (mpp_charge_view, "CHARGE", false),
            (sign_with_passkey_view, "PASSKEY", true),
            (register_passkey_view, "PASSKEY", true),
            (toolset_first_invoke_gate_view, "TOOLSET GATE", false),
            (trustline_clawback_opt_in_view, "CLAWBACK OPT-IN", false),
            (rule_proposal_view, "RULE PROPOSAL", false),
            (rejected_view, "REJECTED", false),
        ];
        for (build, expected, warn) in fixtures {
            let dir = TempDir::new().unwrap();
            let view = build(&dir);
            let (label, is_warn) = kind_pill(&view);
            assert_eq!(label, expected, "kind pill for {}", view.kind_name);
            assert_eq!(is_warn, warn, "warn variant for {}", view.kind_name);
        }

        let dir = TempDir::new().unwrap();
        let payment = payment_view(&dir, false, NOW_MS);
        assert_eq!(kind_pill(&payment), ("PAYMENT".to_owned(), false));
    }

    /// The sentence around the timestamps is chosen by state. A live request
    /// says what happens at expiry; one that can no longer be approved must
    /// not, because the page it sits on offers no approve button — and an
    /// expired one must not read "expires expired (...)".
    #[test]
    fn detail_page_expiry_sentence_is_selected_by_state() {
        let dir = TempDir::new().unwrap();
        let live = render_detail_page(&payment_view(&dir, false, NOW_MS), &"c".repeat(64), None);
        assert!(live.contains(r#"data-expiry-form="remaining""#), "{live}");
        assert!(live.contains("After that this request can"), "{live}");

        let dir = TempDir::new().unwrap();
        let expired =
            render_detail_page(&payment_view(&dir, false, u64::MAX), &"c".repeat(64), None);
        assert!(
            expired.contains(r#"data-expiry-form="absolute""#),
            "{expired}"
        );
        assert!(
            !expired.contains("After that this request can"),
            "an expired request has no 'after that': {expired}"
        );

        let dir = TempDir::new().unwrap();
        let attested = render_detail_page(
            &payment_view(&dir, true, NOW_MS),
            &"c".repeat(64),
            Some("BLOB123"),
        );
        assert!(
            attested.contains(r#"data-expiry-form="absolute""#),
            "{attested}"
        );
        assert!(
            !attested.contains("can\n        only be rejected"),
            "a resolved request offers no actions, so it cannot promise one: {attested}"
        );

        let dir = TempDir::new().unwrap();
        let rejected = render_detail_page(&rejected_view(&dir), &"c".repeat(64), None);
        assert!(
            rejected.contains(r#"data-expiry-form="absolute""#),
            "{rejected}"
        );
        assert!(
            !rejected.contains("only be rejected"),
            "a rejected request cannot be rejected again: {rejected}"
        );
    }

    /// The nonce is what the operator matches against the CLI and the audit
    /// record, so it is rendered as a visible field, not only in the island.
    #[test]
    fn detail_page_renders_the_nonce_as_a_visible_field() {
        let dir = TempDir::new().unwrap();
        let view = payment_view(&dir, false, NOW_MS);
        let html = render_detail_page(&view, &"c".repeat(64), None);
        assert!(
            html.contains(&format!(
                "<dt>Nonce</dt><dd>{}</dd>",
                html_escape(&view.approval_nonce)
            )),
            "{html}"
        );
    }

    /// The timestamps stay machine-readable on the element the client formats,
    /// so a page whose script never runs still shows the real values.
    #[test]
    fn detail_page_carries_absolute_timestamps_in_data_attributes() {
        let dir = TempDir::new().unwrap();
        let view = payment_view(&dir, false, NOW_MS);
        let html = render_detail_page(&view, &"c".repeat(64), None);
        assert!(
            html.contains(&format!(
                r#"data-created-ms="{}" data-expires-ms="{}""#,
                view.created_at_unix_ms, view.expires_at_unix_ms
            )),
            "{html}"
        );
        assert!(html.contains(r#"<b id="created-text">"#), "{html}");
        assert!(html.contains(r#"<b id="expires-text">"#), "{html}");
    }

    /// An expired entry says so in the warning treatment and offers only the
    /// destructive action.
    #[test]
    fn detail_page_expired_states_the_reason_as_a_warning() {
        let dir = TempDir::new().unwrap();
        let view = payment_view(&dir, false, u64::MAX);
        let html = render_detail_page(&view, &"c".repeat(64), None);
        assert!(html.contains(r#"<div class="notice warn">"#), "{html}");
        assert!(html.contains("This request has expired"), "{html}");
        assert!(!html.contains(r#"id="approve-btn""#), "{html}");
    }

    /// An MPP charge is denominated in a token contract's own base units and
    /// stays in them: the wallet does not know that token's decimal scale
    /// here, so a seven-decimal reading would misstate the amount.
    #[test]
    fn detail_page_mpp_charge_keeps_the_amount_in_base_units() {
        let dir = TempDir::new().unwrap();
        let view = mpp_charge_view(&dir);
        let html = render_detail_page(&view, &"c".repeat(64), None);
        assert!(
            html.contains("1000000 <small>base units of the token contract</small>"),
            "the charge must stay in the token's own base units: {html}"
        );
        assert!(
            !html.contains("0.1000000"),
            "a seven-decimal reading would state a value the charge does not carry: {html}"
        );
        assert!(html.contains(">Approve charge</button>"), "{html}");
    }

    // ── Inbox page ───────────────────────────────────────────────────────

    /// The empty state carries the brand mark, which `/static/app.js` cannot
    /// build through `createElement`; it ships in the markup and is revealed
    /// exactly when the snapshot has no entries.
    #[test]
    fn inbox_empty_state_is_visible_only_when_the_island_is_empty() {
        let dir = TempDir::new().unwrap();

        let empty = render_inbox_page(&[], 0, false);
        assert!(
            empty.contains(r#"<div class="empty" id="empty-state">"#),
            "{empty}"
        );
        assert!(empty.contains("All caught up &mdash; no approvals waiting."));

        let seeded = render_inbox_page(&[payment_view(&dir, false, NOW_MS)], 0, false);
        assert!(
            seeded.contains(r#"<div class="empty" id="empty-state" hidden>"#),
            "{seeded}"
        );
    }

    /// The empty state's mark wears the winking face regardless of the page's
    /// own state.
    #[test]
    fn inbox_empty_state_mark_carries_its_own_state() {
        let html = render_inbox_page(&[], 0, false);
        assert!(
            html.contains(r#"<span class="buddy-face" data-state="ok">"#),
            "{html}"
        );
    }

    #[test]
    fn inbox_page_has_the_header_bar_and_the_row_container() {
        let dir = TempDir::new().unwrap();
        let html = render_inbox_page(&[payment_view(&dir, false, NOW_MS)], 0, false);
        assert!(html.contains(r#"<header class="topbar">"#), "{html}");
        assert!(
            html.contains(r#"<div class="tb-word">Agent Wallet</div>"#),
            "{html}"
        );
        assert!(html.contains(r#"<div id="inbox"></div>"#), "{html}");
    }
}
