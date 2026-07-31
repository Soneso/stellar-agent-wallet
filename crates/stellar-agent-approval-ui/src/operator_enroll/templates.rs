//! Server-rendered HTML for the interactive operator-enrollment page.
//!
//! One page is rendered server-side: `GET /enroll`. Dynamic values are
//! embedded only through a `<script type="application/json">` data island,
//! never inline JS, matching the convention documented at
//! `crate::templates` — the browser does not execute `application/json`
//! content, so the embedded values cannot escalate to script execution. All
//! executable logic lives in the same-origin `/static/operator-enroll.js`,
//! keeping the CSP at `script-src 'self'` with no `'unsafe-inline'`.
//!
//! # Presentation
//!
//! The centred-card layout from [`stellar_agent_loopback_http::brand`], the
//! same one the WebAuthn bridge's ceremony pages use — this page is also a
//! single one-shot ceremony the operator either completes or abandons.

use stellar_agent_loopback_http::brand::{BRAND_STYLE, PageIdentity, TRUST_LINE_LOOPBACK};
use stellar_agent_loopback_http::escape::html_escape;

/// Enrollment-only rules: the label field and its caption.
const ENROLL_STYLE: &str = r"
.field { text-align: left; margin-bottom: 18px; }
.field label {
  display: block;
  font-size: 11px;
  font-weight: 700;
  letter-spacing: .8px;
  text-transform: uppercase;
  color: var(--muted-blue);
  margin-bottom: 6px;
}
.field input[type='text'] {
  width: 100%;
  font-family: inherit;
  font-size: 15px;
  color: var(--ink-navy);
  background: #ffffff;
  border: 2px solid var(--field-border);
  border-radius: 10px;
  padding: 11px 13px;
}
.enroll-btn {
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
";

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

/// Renders the interactive operator-enrollment page (`GET /enroll`).
///
/// # Parameters
///
/// - `profile`: the wallet profile this credential is being enrolled for,
///   shown for operator orientation only — it plays no role in the
///   credential itself (which is always recorded with `rp_id: "localhost"`).
/// - `csrf_hex`: the 64-character hex-encoded single-use CSRF token the page
///   must echo back in the `X-Stellar-Approval-CSRF` header on
///   `POST /enroll/credential`.
/// - `label_prefill`: an optional label to pre-populate the label input
///   with (from `approve operator enroll --interactive --label <L>`). The
///   operator can still edit it before submitting; `None` leaves the field
///   empty.
///
/// # rp-id binding
///
/// A WebAuthn credential is bound to its `rp.id` at creation time, and a
/// loopback HTTP origin can only claim `"localhost"` as an effective domain
/// (WebAuthn Level 2 §5.1.3) — this server therefore always registers
/// against `"localhost"`; there is no rp-id override.
#[must_use]
pub(super) fn render_enroll_page(
    profile: &str,
    csrf_hex: &str,
    label_prefill: Option<&str>,
    identity: &PageIdentity,
) -> String {
    let profile_escaped = html_escape(profile);
    let title = identity.page_title("Enroll operator passkey");
    let card_header = identity.card_header_html();
    let label_prefill_attr = label_prefill
        .map(|l| format!(r#" value="{}""#, html_escape(l)))
        .unwrap_or_default();
    let data_island = json_data_island(&serde_json::json!({
        "rpId": "localhost",
        "profile": profile,
        "csrfToken": csrf_hex,
    }));

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{title}</title>
  <style>{BRAND_STYLE}{ENROLL_STYLE}</style>
</head>
<body>
  <main class="page">
    <div class="card">
{card_header}
      <h1>Enroll operator passkey</h1>
      <p class="lead">Profile <code class="chip">{profile_escaped}</code>, registering
         against <code class="chip">localhost</code>. Name this device, then
         confirm with Touch&nbsp;ID, Windows&nbsp;Hello, or your security key.</p>
      <div class="field">
        <label for="label-input">Label (e.g. "laptop")</label>
        <input type="text" id="label-input" maxlength="64" autocomplete="off"{label_prefill_attr}>
      </div>
      <div class="status" id="status">Enter a label and create the passkey.</div>
      <button class="enroll-btn" id="enroll-btn" type="button">Create passkey</button>
      <p class="help">This credential will be able to consent to remote-approval
         requests for this profile only after its id is added to this profile's
         <code>[remote_approval] allowed_credentials</code> list. Enrolling here
         does not grant that by itself.</p>
{TRUST_LINE_LOOPBACK}
    </div>
  </main>
  <script type="application/json" id="enroll-data">{data_island}</script>
  <script src="/static/operator-enroll.js"></script>
</body>
</html>"#
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only; panics acceptable in unit tests"
    )]
    use super::*;

    /// The identity a deployment that configured nothing serves.
    fn neutral() -> PageIdentity {
        PageIdentity::neutral()
    }

    /// The mark's neutral-mouth path data, which appears in no other markup on
    /// the page.
    const MARK_PATH_DATA: &str = r##"d="M40 84 Q60 100 80 84""##;

    fn data_island(html: &str) -> &str {
        let open = r#"<script type="application/json" id="enroll-data">"#;
        let start = html.find(open).expect("data island opening tag") + open.len();
        let rest = &html[start..];
        let end = rest.find("</script>").expect("data island closing tag");
        &rest[..end]
    }

    fn parse_island(html: &str) -> serde_json::Value {
        serde_json::from_str(data_island(html)).expect("data island must be valid JSON")
    }

    #[test]
    fn page_data_island_carries_localhost_rp_id_profile_and_csrf() {
        let html = render_enroll_page("default", &"a".repeat(64), None, &neutral());
        let parsed = parse_island(&html);
        assert_eq!(parsed["rpId"], "localhost");
        assert_eq!(parsed["profile"], "default");
        assert_eq!(parsed["csrfToken"], "a".repeat(64));
    }

    #[test]
    fn page_has_no_inline_event_handler_attributes() {
        let html = render_enroll_page("default", &"b".repeat(64), None, &neutral());
        assert!(
            !html.to_lowercase().contains("onclick="),
            "page must not use inline event handler attributes"
        );
    }

    #[test]
    fn page_loads_only_the_same_origin_script() {
        let html = render_enroll_page("default", &"c".repeat(64), None, &neutral());
        assert!(html.contains(r#"src="/static/operator-enroll.js""#));
        // No other <script src=...> beyond the one same-origin file and the
        // JSON data island (which carries no `src` attribute).
        let script_src_count = html.matches("<script src=").count();
        assert_eq!(script_src_count, 1);
    }

    #[test]
    fn page_neutralises_angle_brackets_in_profile() {
        let html = render_enroll_page("<script>x</script>", &"d".repeat(64), None, &neutral());
        assert!(!html.contains("<script>x</script>"));
        assert_eq!(parse_island(&html)["profile"], "<script>x</script>");
    }

    #[test]
    fn page_contains_label_input_and_button() {
        let html = render_enroll_page("default", &"e".repeat(64), None, &neutral());
        assert!(html.contains(r#"id="label-input""#));
        assert!(html.contains(r#"id="enroll-btn""#));
    }

    #[test]
    fn page_without_prefill_has_no_value_attribute() {
        let html = render_enroll_page("default", &"f".repeat(64), None, &neutral());
        assert!(!html.contains(r#"id="label-input" maxlength="64" autocomplete="off" value"#));
    }

    #[test]
    fn page_with_prefill_populates_label_input_value() {
        let html = render_enroll_page("default", &"g".repeat(64), Some("my-laptop"), &neutral());
        assert!(html.contains(r#"value="my-laptop""#));
    }

    #[test]
    fn page_prefill_html_escapes_the_label() {
        let html = render_enroll_page("default", &"h".repeat(64), Some("<b>x</b>"), &neutral());
        assert!(!html.contains("<b>x</b>"));
        assert!(html.contains("&lt;b&gt;x&lt;/b&gt;"));
    }

    // ── Design surface and per-deployment identity ───────────────────────

    /// A duplicated stylesheet would silently double every rule; a missing one
    /// would render the page unstyled. The design holds under every identity.
    #[test]
    fn page_embeds_the_brand_style_exactly_once_under_every_identity() {
        for identity in [
            PageIdentity::neutral(),
            PageIdentity::new(Some("Acme Ops"), false),
            PageIdentity::new(Some("Acme Ops"), true),
        ] {
            let html = render_enroll_page("default", &"i".repeat(64), None, &identity);
            assert_eq!(html.matches(BRAND_STYLE).count(), 1);
        }
    }

    /// An unconfigured deployment serves no project identity.
    #[test]
    fn an_unconfigured_deployment_serves_no_mark_and_no_wordmark() {
        let html = render_enroll_page("default", &"i".repeat(64), None, &neutral());
        assert!(!html.contains(MARK_PATH_DATA), "{html}");
        assert!(!html.contains(">STELLAR<"), "{html}");
        assert!(!html.contains("Agent Wallet"), "{html}");
    }

    /// A configured display name renders escaped; the mark renders only when
    /// the deployment asked for it.
    #[test]
    fn a_configured_identity_renders_the_name_and_the_mark() {
        let named = render_enroll_page(
            "default",
            &"i".repeat(64),
            None,
            &PageIdentity::new(Some("<b>Acme</b>"), false),
        );
        assert!(named.contains("&lt;b&gt;Acme&lt;/b&gt;"), "{named}");
        assert!(!named.contains("<b>Acme</b>"), "{named}");
        assert!(!named.contains(MARK_PATH_DATA), "{named}");

        let marked = render_enroll_page(
            "default",
            &"i".repeat(64),
            None,
            &PageIdentity::new(Some("Acme Ops"), true),
        );
        assert!(marked.contains(MARK_PATH_DATA), "{marked}");
    }

    /// `img-src 'self'` blocks every remote origin, so a page referencing one
    /// would render a hole rather than fail loudly.
    #[test]
    fn page_references_no_external_origin() {
        let html = render_enroll_page("default", &"j".repeat(64), None, &neutral());
        assert!(!html.contains("http://"));
        assert!(!html.contains("https://"));
    }

    /// The enrollment server binds loopback only, so the trust line is a
    /// property of the listener rather than a claim about it. It names the
    /// interface, not one address: the bind guard is
    /// `SocketAddr::ip().is_loopback()`, which admits `::1` too.
    #[test]
    fn page_carries_the_loopback_trust_line() {
        let html = render_enroll_page("default", &"k".repeat(64), None, &neutral());
        assert!(html.contains(TRUST_LINE_LOOPBACK));
        assert!(
            !html.contains("127.0.0.1"),
            "the trust line must not name an address the guard does not require"
        );
    }

    /// Enrolling grants nothing on its own; the page has to say so.
    #[test]
    fn page_states_that_enrollment_alone_grants_nothing() {
        let html = render_enroll_page("default", &"l".repeat(64), None, &neutral());
        assert!(html.contains("allowed_credentials"));
        assert!(html.contains("does not grant that by itself"));
    }
}
