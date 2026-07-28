//! Server-rendered HTML for the remote-approval pages.
//!
//! Four pages are rendered server-side: the login page (`GET /`), the
//! enrollment helper page (`GET /enroll`), the inbox shell (`GET /inbox`),
//! and the per-approval detail page (`GET /approval/{nonce}`). Mirrors the
//! loopback approval-inbox server's
//! `stellar-agent-approval-ui::templates` convention: dynamic values are
//! embedded only through a `<script type="application/json">` data island,
//! never inline JS — the browser does not execute `application/json`
//! content, so the embedded values cannot escalate to script execution. All
//! executable logic lives in the same-origin `/static/login.js` or
//! `/static/app.js`, keeping the CSP at `script-src 'self'` with no
//! `'unsafe-inline'`.
//!
//! The detail page's summary rows render the SAME entry data
//! (`crate::routes::entry_envelope_sha256`'s source, `PendingApprovalView`)
//! that the per-action challenge binds server-side — what the operator reads
//! here is what the challenge is over, which is what makes the ceremony
//! what-you-see-is-what-you-sign in practice, not merely in the byte-level
//! binding.
//!
//! Free-text fields that reach the HTML body directly (asset codes, memos,
//! redacted addresses) are HTML-escaped via [`html_escape`]; the data-island
//! JSON is escaped via [`json_data_island`].
//!
//! # Presentation
//!
//! The shared identity from [`stellar_agent_loopback_http::brand`] — inline
//! stylesheet, inline mark, no fetched asset — so this surface looks like the
//! loopback one rather than like a third-party site. The trust line differs:
//! this listener is reachable over a private network, so it states
//! self-hosting rather than loopback.

use stellar_agent_core::approval::{ApprovalSummaryView, PendingApprovalView};
// The approval rendering is `stellar-agent-approval-ui`'s: one definition of
// the decision card, the kind pill, the button label, and the escaping, so the
// two approval surfaces cannot present the same entry differently.
use stellar_agent_approval_ui::{
    DETAIL_STYLE, INBOX_STYLE, approve_button_label, html_escape, kind_pill,
    render_rule_proposal_definition_html, render_summary_html,
};
use stellar_agent_loopback_http::brand::{
    BRAND_STYLE, BUDDY_MARK_SVG, CARD_BRAND_HEADER, TRUST_LINE_SELF_HOSTED,
};

// ─────────────────────────────────────────────────────────────────────────────
// Page-local styling and shared fragments
// ─────────────────────────────────────────────────────────────────────────────

/// Card-only rules: the pre-authentication pages' single wide action button.
const CARD_STYLE: &str = r"
.card-btn {
  width: 100%;
  border-radius: 10px;
  padding: 13px 0;
  font-size: 15px;
  font-weight: 700;
  border: none;
  cursor: pointer;
  font-family: inherit;
  background: var(--ink-navy);
  color: #ffffff;
  margin-top: 16px;
}
.outputs { margin-top: 18px; text-align: left; }
.outputs p { font-size: 11px; font-weight: 700; letter-spacing: .8px; text-transform: uppercase; color: var(--muted-blue); margin: 12px 0 4px; }
.outputs textarea { width: 100%; }
";

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

/// Returns `true` when a kind can be approved (attested / consented) from
/// this UI. Passkey kinds and rejected tombstones are informational here.
#[must_use]
fn kind_is_approvable(summary: &ApprovalSummaryView) -> bool {
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

/// Renders the login page (`GET /`) — no session required; this IS the
/// pre-authentication surface. Loads the ungated `/static/login.js`.
#[must_use]
pub(crate) fn render_login_page(rp_id: &str) -> String {
    let rp_id = html_escape(rp_id);
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Stellar Agent Wallet — Remote Approval</title>
  <style>{BRAND_STYLE}{CARD_STYLE}</style>
</head>
<body>
  <main class="page">
    <div class="card">
      {BUDDY_MARK_SVG}
{CARD_BRAND_HEADER}
      <h1>Sign in to approve</h1>
      <p class="lead">Connecting to <code class="chip">{rp_id}</code>. Confirm with
         the passkey you enrolled for this wallet to see the requests waiting for
         your decision.</p>
      <div class="status" id="status">Sign in with your registered passkey to view pending approvals.</div>
      <button class="card-btn" id="login-btn" type="button">Sign in with passkey</button>
      <p class="help">Only a passkey this wallet already allows can sign in. A
         failed attempt reveals nothing about what is pending.</p>
{TRUST_LINE_SELF_HOSTED}
    </div>
  </main>
  <script src="/static/login.js"></script>
</body>
</html>"#
    )
}

/// Renders the passkey-enrollment helper page (`GET /enroll`). No session
/// required — enrollment must happen BEFORE any session exists, so this is
/// pre-authentication by necessity, like the login page.
///
/// A WebAuthn credential is bound to its `rp.id` at creation time: the
/// caller origin's effective domain must be a registrable-suffix match for
/// `rp.id` (WebAuthn Level 2 §5.1.3), and a `file://` page has no effective
/// domain at all. Only a page served from `https://<rp_id>` can create a
/// credential later usable against this listener — the reason this page has
/// to be served here rather than run from a local file.
///
/// The rendered page never persists anything: `/static/enroll.js` runs
/// `navigator.credentials.create()` client-side and displays the resulting
/// credential id and public key for the operator to copy into the
/// loopback-only `approve operator enroll` CLI command (see the crate-level
/// "Enrollment stays loopback-only" note). There is no corresponding write
/// endpoint on this surface.
#[must_use]
pub(crate) fn render_enroll_page(rp_id: &str) -> String {
    let rp_id_escaped = html_escape(rp_id);
    let data_island = json_data_island(&serde_json::json!({ "rp_id": rp_id }));

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Enroll a passkey — Stellar Agent Wallet</title>
  <style>{BRAND_STYLE}{CARD_STYLE}</style>
</head>
<body>
  <main class="page">
    <div class="card">
      {BUDDY_MARK_SVG}
{CARD_BRAND_HEADER}
      <h1>Enroll a passkey</h1>
      <p class="lead">Registering against <code class="chip">{rp_id_escaped}</code>.
         This page creates a new passkey and shows the values needed to enroll
         it.</p>
      <div class="status" id="status">Click below and complete your platform's passkey prompt.</div>
      <button class="card-btn" id="enroll-btn" type="button">Create passkey</button>
      <div class="outputs" id="result"></div>
      <p class="help">This page saves nothing itself &mdash; run the printed
         <code>approve operator enroll</code> command on the wallet host to
         finish enrollment.</p>
{TRUST_LINE_SELF_HOSTED}
    </div>
  </main>
  <script type="application/json" id="enroll-data">{data_island}</script>
  <script src="/static/enroll.js"></script>
</body>
</html>"#
    )
}

/// Renders a minimal, uniform message page for a pre-auth refusal (e.g. the
/// enrollment page's rate limiter) — the same styling and no-inline-script
/// discipline as every other server-rendered page in this crate, so a
/// refusal never looks different from a normal page to the operator.
#[must_use]
pub(crate) fn render_message_page(title: &str, message: &str) -> String {
    let title_escaped = html_escape(title);
    let message_escaped = html_escape(message);
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{title_escaped} — Stellar Agent Wallet</title>
  <style>{BRAND_STYLE}</style>
</head>
<body>
  <main class="page">
    <div class="card">
      {BUDDY_MARK_SVG}
{CARD_BRAND_HEADER}
      <h1>{title_escaped}</h1>
      <p class="lead">{message_escaped}</p>
{TRUST_LINE_SELF_HOSTED}
    </div>
  </main>
</body>
</html>"#
    )
}

/// Renders the inbox shell page (`GET /inbox`, session-gated).
///
/// Seeds the current snapshot into `#pending-data`; `/static/app.js`
/// re-fetches `/pending.json` every two seconds and updates the rows and the
/// title badge.
///
/// The empty state is always present in the markup, because `/static/app.js`
/// composes rows through `createElement` and cannot introduce the brand mark
/// itself. It carries the `hidden` attribute when the seeded snapshot has
/// entries; the script toggles that attribute on every refresh.
#[must_use]
pub(crate) fn render_inbox_page(pending: &[PendingApprovalView]) -> String {
    let data_island = json_data_island(&serde_json::json!({ "pending": pending }));
    let topbar = topbar_html("Approvals");
    let empty_hidden = if pending.is_empty() { "" } else { " hidden" };

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Stellar Agent Wallet — Remote Approval</title>
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

/// Renders a clean "not found in queue" page (HTTP 200, authenticated UX
/// case).
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
{TRUST_LINE_SELF_HOSTED}
    </div>
  </main>
</body>
</html>"#
    )
}

/// Renders the per-approval detail page (`GET /approval/{{nonce}}`,
/// session-gated).
///
/// Every field of the entry's redacted view is rendered server-side — the
/// same fields `crate::routes::entry_envelope_sha256` reads to derive the
/// per-action challenge's envelope hash. The CSRF value and the nonce ride
/// in the `#approval-data` island so `/static/app.js` can drive the full
/// ceremony (mint the action challenge, run `navigator.credentials.get`,
/// POST the decision); the response JSON (including any surfaced
/// attestation blob) is rendered into the result container by the JS.
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
    // The full rule definition (context callout, signer table, policy
    // table, override warnings) is not dt/dd-shaped, so it renders as its
    // own block AFTER the `<dl>` closes rather than inside `summary_html`.
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
        // Expired-not-yet-resolved and informational (e.g. passkey) kinds:
        // still allow a reject to tombstone the entry, matching the loopback
        // approval-inbox server's identical posture.
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

    /// Build a payment view via a real store snapshot, with a memo carrying
    /// a `<script>` breakout attempt to exercise HTML escaping.
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
    fn login_page_has_rp_id_and_login_js() {
        let html = render_login_page("wallet.internal");
        assert!(html.contains("wallet.internal"));
        assert!(html.contains(r#"src="/static/login.js""#));
        assert!(!html.contains("<script>"), "no inline script allowed");
    }

    #[test]
    fn login_page_escapes_rp_id() {
        let html = render_login_page("<script>x</script>");
        assert!(!html.contains("<script>x</script>"));
        assert!(html.contains("&lt;script&gt;"));
    }

    #[test]
    fn enroll_page_has_rp_id_and_enroll_js() {
        let html = render_enroll_page("wallet.internal");
        assert!(html.contains("wallet.internal"));
        assert!(html.contains(r#""rp_id":"wallet.internal""#));
        assert!(html.contains(r#"src="/static/enroll.js""#));
        assert!(html.contains(r#"id="enroll-data""#));
        assert!(!html.contains("<script>"), "no inline script allowed");
    }

    #[test]
    fn enroll_page_escapes_rp_id_in_html_and_neutralises_it_in_json_island() {
        let html = render_enroll_page("<script>x</script>");
        // The visible <code>{rp_id}</code> text must be HTML-escaped.
        assert!(html.contains("&lt;script&gt;x&lt;/script&gt;"));
        // The JSON data island independently neutralises `<` and `>` via
        // `json_data_island`'s substitution, so no literal `<script>`
        // breakout is reachable through either rendering path.
        assert!(!html.contains("<script>x</script>"));
        assert!(html.contains("\\u003cscript\\u003ex\\u003c/script\\u003e"));
    }

    #[test]
    fn message_page_escapes_title_and_message() {
        let html = render_message_page("Too <b>many</b>", "Wait & retry");
        assert!(html.contains("Too &lt;b&gt;many&lt;/b&gt;"));
        assert!(html.contains("Wait &amp; retry"));
        assert!(!html.contains("<b>many</b>"));
    }

    #[test]
    fn inbox_page_has_data_island_and_app_js() {
        let dir = TempDir::new().unwrap();
        let html = render_inbox_page(&[payment_view(&dir, false, NOW_MS)]);
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
    fn detail_page_expired_offers_reject_only() {
        let dir = TempDir::new().unwrap();
        let view = payment_view(&dir, false, u64::MAX);
        assert!(view.expired);
        let html = render_detail_page(&view, &"c".repeat(64), None);
        assert!(html.contains("expired"));
        assert!(!html.contains("id=\"approve-btn\""));
        assert!(html.contains("id=\"reject-btn\""));
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

    // ── Fixture builders ─────────────────────────────────────────────────
    //
    // One entry per approval kind, so the pins below cover every variant the
    // hoisted renderer handles rather than the three this surface happened to
    // exercise first.

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

    /// Builds a `RuleProposalSimulated` view.
    ///
    /// Carries no policy entry, unlike the loopback crate's fixture: the
    /// policy-table rendering lives in the shared
    /// `render_rule_proposal_definition_html`, which that crate pins across
    /// every branch. What this surface needs from a fixture is the kind and
    /// the decision-card wiring around it.
    fn rule_proposal_view(dir: &TempDir) -> PendingApprovalView {
        use stellar_agent_core::approval::{
            ContextRuleProposalSnapshot, RuleProposalContextType, RuleProposalSigner,
        };

        let definition = ContextRuleProposalSnapshot::new(
            RuleProposalContextType::Default,
            "spend-daily".to_owned(),
            None,
            vec![RuleProposalSigner::delegated(
                "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
                true,
            )],
            vec![],
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
            render_login_page("wallet.internal"),
            render_enroll_page("wallet.internal"),
            render_message_page("Too many requests", "Wait and retry."),
            render_inbox_page(std::slice::from_ref(&view)),
            render_inbox_page(&[]),
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

    /// This listener is reachable over a private network, not loopback, so no
    /// page on it may claim that nothing leaves the machine.
    #[test]
    fn card_pages_claim_self_hosting_and_never_loopback() {
        for html in [
            render_login_page("wallet.internal"),
            render_enroll_page("wallet.internal"),
            render_message_page("Too many requests", "Wait and retry."),
            render_not_found_page("nonce"),
        ] {
            assert!(
                html.contains(
                    "Served by your own wallet &mdash; self-hosted, no third-party service."
                ),
                "the self-hosting trust line must be present: {html}"
            );
            assert!(
                !html.contains("127.0.0.1"),
                "a non-loopback surface must not claim loopback: {html}"
            );
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
        assert!(html.contains("0.2500000 XLM"), "{html}");
        assert!(html.contains("2500000 stroops"), "{html}");
        let destination = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        assert!(
            html.contains(&format!(r#"<div class="addr">{destination}</div>"#)),
            "the destination must render whole, in the address block: {html}"
        );
    }

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
    }

    /// The kind pill is total over all nine summary variants, and the two
    /// passkey kinds take the amber variant.
    ///
    /// The pill itself is `stellar-agent-approval-ui`'s, pinned there too;
    /// what this copy guards is that THIS surface routes every kind through
    /// it rather than growing a local fallback.
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

    // ── Wiring pins ──────────────────────────────────────────────────────
    //
    // The renderings below are `stellar-agent-approval-ui`'s and are pinned
    // there against their own inputs. These copies guard the WIRING: that this
    // surface calls the shared renderer for the same entry rather than
    // presenting it some other way. They fail if this crate ever grows a local
    // rendering path.

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

    /// The empty state carries the brand mark, which `/static/app.js` cannot
    /// build through `createElement`; it ships in the markup and is revealed
    /// exactly when the snapshot has no entries.
    #[test]
    fn inbox_empty_state_is_visible_only_when_the_island_is_empty() {
        let dir = TempDir::new().unwrap();

        let empty = render_inbox_page(&[]);
        assert!(
            empty.contains(r#"<div class="empty" id="empty-state">"#),
            "{empty}"
        );
        assert!(empty.contains("All caught up &mdash; no approvals waiting."));

        let seeded = render_inbox_page(&[payment_view(&dir, false, NOW_MS)]);
        assert!(
            seeded.contains(r#"<div class="empty" id="empty-state" hidden>"#),
            "{seeded}"
        );
    }
}
