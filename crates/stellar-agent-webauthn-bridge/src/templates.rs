//! Pure-string HTML page templates for the WebAuthn browser-handoff bridge.
//!
//! Generates the `GET /register/<nonce>` and `GET /approve/<nonce>` response
//! bodies.  The JS logic lives in two files loaded in order: (1) the
//! vendored `@simplewebauthn/browser` UMD bundle at `/static/webauthn.js`
//! (exposes the global `SimpleWebAuthnBrowser`), and (2) the wallet-authored
//! DOM/fetch glue at `/static/glue.js` (reads the server-rendered data island
//! and invokes the ceremony).  This module only provides the HTML skeleton
//! and the server-rendered data island.
//!
//! # Security
//!
//! Dynamic values are embedded as a `<script type="application/json">` data
//! island (not inline JS).  The script type `application/json` tells browsers
//! NOT to execute the content, so the values cannot escalate to XSS.
//!
//! The island is serialised with `serde_json`, so every field value is
//! correctly JSON-string-escaped (quotes, backslashes, control characters)
//! regardless of its contents.  The `<`, `>`, and `&` characters are then
//! escaped to their `\uXXXX` JSON forms so the serialised text can never
//! contain a literal `</script>` sequence that would break out of the data
//! island, while remaining valid JSON that the browser's `JSON.parse` accepts.
//!
//! The `Content-Security-Policy` header (injected by `SecurityHeadersLayer`)
//! prevents any inline script execution; `script-src 'self'` allows only the
//! same-origin `/static/webauthn.js` bundle.

// ─────────────────────────────────────────────────────────────────────────────
// Data island
// ─────────────────────────────────────────────────────────────────────────────

/// Serialise `value` to a JSON string safe to embed inside a
/// `<script type="application/json">` element.
///
/// `serde_json` performs all JSON-string escaping; the `<`, `>`, and `&`
/// characters are then replaced with their `\uXXXX` JSON escapes so the text
/// cannot contain a literal `</script>` sequence (a `<script>` element's
/// content is raw text, so only `</script` — not HTML entities — can terminate
/// it). The result is still valid JSON that `JSON.parse` decodes back to the
/// original characters.
fn json_data_island(value: &serde_json::Value) -> String {
    value
        .to_string()
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026")
}

// ─────────────────────────────────────────────────────────────────────────────
// Page renderers
// ─────────────────────────────────────────────────────────────────────────────

/// Render the passkey-registration HTML page.
///
/// The page embeds a `<script type="application/json" id="webauthn-options">`
/// data island containing the server-rendered registration parameters. The
/// `webauthn.js` bundle reads this island and initiates the browser WebAuthn
/// ceremony.
///
/// # Parameters
///
/// - `nonce`: the approval-store nonce (URL path component, already validated).
/// - `csrf_hex`: the 64-character hex-encoded CSRF token for the POST back.
/// - `rp_id`: the WebAuthn RP-ID (e.g. `"localhost"` or `"127.0.0.1"`).
/// - `user_handle_b64`: the 32-byte user handle, base64url-encoded, for the
///   WebAuthn registration ceremony `user.id` field.
///
/// # Security
///
/// The parameters are serialised into the data island via [`json_data_island`],
/// which JSON-escapes every value and neutralises any `</script>` sequence. The
/// data island uses `type="application/json"` so browsers do not execute it.
#[must_use]
pub(crate) fn render_register_page(
    nonce: &str,
    csrf_hex: &str,
    rp_id: &str,
    user_handle_b64: &str,
) -> String {
    let data_island = json_data_island(&serde_json::json!({
        "flow": "register",
        "nonce": nonce,
        "csrfToken": csrf_hex,
        "rpId": rp_id,
        "userHandle": user_handle_b64,
    }));

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Register Passkey — Stellar Agent Wallet</title>
</head>
<body>
  <h1>Register Passkey</h1>
  <p>Wallet is requesting a new passkey registration.</p>
  <div id="status">Initialising…</div>
  <script type="application/json" id="webauthn-options">{data_island}</script>
  <script src="/static/webauthn.js"></script>
  <script src="/static/glue.js"></script>
</body>
</html>"#
    )
}

/// Render the passkey-approval HTML page.
///
/// The page embeds a `<script type="application/json" id="webauthn-options">`
/// data island containing the server-rendered authentication parameters. The
/// `webauthn.js` bundle reads this island and initiates the browser WebAuthn
/// ceremony.
///
/// # Parameters
///
/// - `nonce`: the approval-store nonce.
/// - `csrf_hex`: the 64-character hex-encoded CSRF token for the POST back.
/// - `auth_digest_hex`: hex-encoded 32-byte auth digest (becomes the WebAuthn
///   challenge: `base64url(auth_digest)` in the ceremony).
/// - `credential_id_b64`: base64url-encoded credential ID for `allowCredentials`.
/// - `rp_id`: the WebAuthn RP-ID.
///
/// # `rp_id` source
///
/// The `rp_id` parameter is populated by the `approve_get` handler from the
/// `SignWithPasskey` approval entry, which itself was written by
/// `CredentialsManager::sign_with_passkey_rule` from the credential's
/// registry-persisted `rp_id`.
///
/// # Security
///
/// The parameters are serialised into the data island via [`json_data_island`],
/// which JSON-escapes every value and neutralises any `</script>` sequence. The
/// data island uses `type="application/json"` so browsers do not execute it.
#[must_use]
pub(crate) fn render_approve_page(
    nonce: &str,
    csrf_hex: &str,
    auth_digest_hex: &str,
    credential_id_b64: &str,
    rp_id: &str,
) -> String {
    let data_island = json_data_island(&serde_json::json!({
        "flow": "approve",
        "nonce": nonce,
        "csrfToken": csrf_hex,
        "authDigest": auth_digest_hex,
        "credentialId": credential_id_b64,
        "rpId": rp_id,
    }));

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Approve Transaction — Stellar Agent Wallet</title>
</head>
<body>
  <h1>Approve Transaction</h1>
  <p>Wallet is requesting passkey authentication for a pending transaction.</p>
  <div id="status">Initialising…</div>
  <script type="application/json" id="webauthn-options">{data_island}</script>
  <script src="/static/webauthn.js"></script>
  <script src="/static/glue.js"></script>
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
        reason = "test-only"
    )]
    use super::*;

    /// Extract the JSON text of the `webauthn-options` data island from a
    /// rendered page.
    fn data_island(html: &str) -> &str {
        let open = r#"<script type="application/json" id="webauthn-options">"#;
        let start = html.find(open).expect("data island opening tag") + open.len();
        let rest = &html[start..];
        let end = rest.find("</script>").expect("data island closing tag");
        &rest[..end]
    }

    /// Parse a rendered page's data island back into a JSON value.
    fn parse_island(html: &str) -> serde_json::Value {
        serde_json::from_str(data_island(html)).expect("data island must be valid JSON")
    }

    #[test]
    fn json_data_island_escapes_script_breakout_chars() {
        let out = json_data_island(&serde_json::json!({ "k": "a</script><b>&c" }));
        assert!(
            !out.contains("</script>"),
            "serialised island must not contain a literal </script>, got: {out}"
        );
        assert!(out.contains("\\u003c") && out.contains("\\u003e") && out.contains("\\u0026"));
        // Still valid JSON that round-trips to the original value.
        let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(parsed["k"], "a</script><b>&c");
    }

    #[test]
    fn json_data_island_escapes_quote_and_backslash() {
        // serde_json handles JSON-string escaping for quotes/backslashes, so the
        // island stays valid JSON even for values the old HTML-escape missed.
        let out = json_data_island(&serde_json::json!({ "k": "a\"b\\c" }));
        let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(parsed["k"], "a\"b\\c");
    }

    #[test]
    fn render_register_page_data_island_is_valid_json() {
        let html = render_register_page(
            "abc123nonce",
            &"d".repeat(64),
            "localhost",
            "dXNlcmhhbmRsZQ",
        );
        let parsed = parse_island(&html);
        assert_eq!(parsed["flow"], "register");
        assert_eq!(parsed["nonce"], "abc123nonce");
        assert_eq!(parsed["rpId"], "localhost");
        assert_eq!(parsed["userHandle"], "dXNlcmhhbmRsZQ");
    }

    #[test]
    fn render_approve_page_data_island_is_valid_json() {
        let html = render_approve_page(
            "nonce42",
            &"c".repeat(64),
            &"aabbccdd".repeat(8),
            "credid_b64",
            "localhost",
        );
        let parsed = parse_island(&html);
        assert_eq!(parsed["flow"], "approve");
        assert_eq!(parsed["nonce"], "nonce42");
        assert_eq!(parsed["authDigest"], "aabbccdd".repeat(8));
        assert_eq!(parsed["credentialId"], "credid_b64");
        assert_eq!(parsed["rpId"], "localhost");
    }

    #[test]
    fn render_register_page_neutralises_angle_brackets_in_value() {
        // A value containing `<`/`>` must not appear literally (which could form
        // `</script>`); it is JSON-unicode-escaped, and the island still parses
        // back to the original value.
        let html = render_register_page("n", &"c".repeat(64), "a<b>c", "dXNlcmhhbmRsZQ");
        assert!(
            !html.contains("a<b>c"),
            "raw angle brackets must not appear in the page"
        );
        assert!(html.contains("a\\u003cb\\u003ec"));
        assert_eq!(parse_island(&html)["rpId"], "a<b>c");
    }

    #[test]
    fn render_register_page_contains_script_src() {
        let html = render_register_page("n", &"c".repeat(64), "localhost", "dXNlcmhhbmRsZQ");
        assert!(
            html.contains(r#"src="/static/webauthn.js""#),
            "page must include the webauthn.js bundle script tag"
        );
        assert!(
            html.contains(r#"src="/static/glue.js""#),
            "page must include the glue.js script tag (wallet glue)"
        );
    }

    #[test]
    fn render_approve_page_contains_script_src() {
        let html = render_approve_page("n", &"c".repeat(64), &"a".repeat(64), "cid", "localhost");
        assert!(
            html.contains(r#"src="/static/webauthn.js""#),
            "page must include the webauthn.js bundle script tag"
        );
        assert!(
            html.contains(r#"src="/static/glue.js""#),
            "page must include the glue.js script tag (wallet glue)"
        );
    }

    #[test]
    fn render_register_page_contains_json_data_island_tag() {
        let html = render_register_page("n", &"c".repeat(64), "localhost", "dXNlcmhhbmRsZQ");
        assert!(
            html.contains(r#"type="application/json" id="webauthn-options""#),
            "page must include the JSON data-island script tag"
        );
    }
}
