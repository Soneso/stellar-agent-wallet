//! Server-rendered HTML for the interactive operator-enrollment page.
//!
//! One page is rendered server-side: `GET /enroll`. Dynamic values are
//! embedded only through a `<script type="application/json">` data island,
//! never inline JS, matching the convention documented at
//! `crate::templates` — the browser does not execute `application/json`
//! content, so the embedded values cannot escalate to script execution. All
//! executable logic lives in the same-origin `/static/operator-enroll.js`,
//! keeping the CSP at `script-src 'self'` with no `'unsafe-inline'`.

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

/// HTML-escapes a string for safe interpolation into element text.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
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
) -> String {
    let profile_escaped = html_escape(profile);
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
  <title>Enroll operator passkey — Stellar Agent Wallet</title>
  <style>
    body {{ font-family: system-ui, sans-serif; margin: 2rem; max-width: 40rem; }}
    .muted {{ color: #666; }}
    label {{ display: block; margin-top: 1rem; }}
    input[type="text"] {{ width: 100%; font-family: inherit; font-size: 1rem; padding: 0.4rem; box-sizing: border-box; }}
  </style>
</head>
<body>
  <h1>Enroll operator passkey</h1>
  <p class="muted">Profile: <code>{profile_escaped}</code> — registering against <code>localhost</code></p>
  <p>This credential will be able to consent to remote-approval requests for
     this profile only after its id is added to this profile's
     <code>[remote_approval] allowed_credentials</code> list. Enrolling here
     does not grant that by itself.</p>
  <label for="label-input">Label (e.g. "laptop")</label>
  <input type="text" id="label-input" maxlength="64" autocomplete="off"{label_prefill_attr}>
  <p id="status">Enter a label and click below to create a passkey.</p>
  <button id="enroll-btn" type="button">Create passkey</button>
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
        let html = render_enroll_page("default", &"a".repeat(64), None);
        let parsed = parse_island(&html);
        assert_eq!(parsed["rpId"], "localhost");
        assert_eq!(parsed["profile"], "default");
        assert_eq!(parsed["csrfToken"], "a".repeat(64));
    }

    #[test]
    fn page_has_no_inline_event_handler_attributes() {
        let html = render_enroll_page("default", &"b".repeat(64), None);
        assert!(
            !html.to_lowercase().contains("onclick="),
            "page must not use inline event handler attributes"
        );
    }

    #[test]
    fn page_loads_only_the_same_origin_script() {
        let html = render_enroll_page("default", &"c".repeat(64), None);
        assert!(html.contains(r#"src="/static/operator-enroll.js""#));
        // No other <script src=...> beyond the one same-origin file and the
        // JSON data island (which carries no `src` attribute).
        let script_src_count = html.matches("<script src=").count();
        assert_eq!(script_src_count, 1);
    }

    #[test]
    fn page_neutralises_angle_brackets_in_profile() {
        let html = render_enroll_page("<script>x</script>", &"d".repeat(64), None);
        assert!(!html.contains("<script>x</script>"));
        assert_eq!(parse_island(&html)["profile"], "<script>x</script>");
    }

    #[test]
    fn page_contains_label_input_and_button() {
        let html = render_enroll_page("default", &"e".repeat(64), None);
        assert!(html.contains(r#"id="label-input""#));
        assert!(html.contains(r#"id="enroll-btn""#));
    }

    #[test]
    fn page_without_prefill_has_no_value_attribute() {
        let html = render_enroll_page("default", &"f".repeat(64), None);
        assert!(!html.contains(r#"id="label-input" maxlength="64" autocomplete="off" value"#));
    }

    #[test]
    fn page_with_prefill_populates_label_input_value() {
        let html = render_enroll_page("default", &"g".repeat(64), Some("my-laptop"));
        assert!(html.contains(r#"value="my-laptop""#));
    }

    #[test]
    fn page_prefill_html_escapes_the_label() {
        let html = render_enroll_page("default", &"h".repeat(64), Some("<b>x</b>"));
        assert!(!html.contains("<b>x</b>"));
        assert!(html.contains("&lt;b&gt;x&lt;/b&gt;"));
    }
}
