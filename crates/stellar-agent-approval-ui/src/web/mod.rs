//! Static web assets baked into the binary.
//!
//! Two wallet-authored, same-origin scripts, loaded in order by every page:
//! [`APP_SHARED_JS`] at `GET /static/app-shared.js`, then [`APP_JS`] at
//! `GET /static/app.js`. Vanilla JS, no build step, no external dependency.
//!
//! The split is a single-source-of-truth boundary, not a size optimisation.
//! [`APP_SHARED_JS`] renders an approval — the row markup, the kind labels, the
//! amount and timestamp formatting, the decision-result panel — and
//! `stellar-agent-approval-remote` serves THESE bytes for its own
//! `/static/app-shared.js`, so the two approval surfaces cannot show the same
//! entry differently. [`APP_JS`] holds only what is specific to this loopback
//! server: its poll query, its CSRF header, its decision endpoints.

/// Approval rendering shared by this crate and
/// `stellar-agent-approval-remote`, served at `GET /static/app-shared.js`.
///
/// Public because the remote approval server serves these exact bytes for its
/// own `/static/app-shared.js` route; a test there pins the equality. Loaded
/// before each server's own `app.js` on every page, and publishes the single
/// global `stellarAgentApproval` that the page half reads.
///
/// Source-of-truth: `src/web/app_shared.js`.
pub const APP_SHARED_JS: &[u8] = include_bytes!("app_shared.js");

/// Wallet-authored approval-inbox browser glue served at `GET /static/app.js`.
///
/// Loaded after [`APP_SHARED_JS`], whose `stellarAgentApproval` namespace it
/// consumes.
///
/// Source-of-truth: `src/web/app.js`.
pub(crate) const APP_JS: &[u8] = include_bytes!("app.js");

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only; panics acceptable in unit tests"
    )]
    use super::*;

    #[test]
    fn app_js_is_valid_utf8() {
        std::str::from_utf8(APP_JS).expect("app.js must be valid UTF-8");
    }

    #[test]
    fn app_shared_js_is_valid_utf8() {
        std::str::from_utf8(APP_SHARED_JS).expect("app_shared.js must be valid UTF-8");
    }

    #[test]
    fn app_js_wires_csrf_header() {
        let body = std::str::from_utf8(APP_JS).unwrap();
        assert!(body.contains("X-Stellar-Approval-CSRF"));
        assert!(body.contains("/pending.json"));
    }

    /// The two files are one program split across two `<script>` elements:
    /// the shared half publishes the namespace, the page half consumes it.
    /// A rename on either side breaks every page silently in the browser.
    #[test]
    fn the_two_scripts_agree_on_the_namespace_name() {
        let shared = std::str::from_utf8(APP_SHARED_JS).unwrap();
        let app = std::str::from_utf8(APP_JS).unwrap();
        assert!(
            shared.contains("var stellarAgentApproval = (function ()"),
            "app_shared.js must publish the namespace"
        );
        assert!(
            app.contains("var shared = stellarAgentApproval;"),
            "app.js must consume the namespace"
        );
    }

    /// Every helper the page half calls has to exist on the namespace the
    /// shared half returns; a missing one is a runtime `TypeError` that only
    /// the browser sees.
    #[test]
    fn every_shared_helper_the_page_calls_is_exported() {
        let shared = std::str::from_utf8(APP_SHARED_JS).unwrap();
        let app = std::str::from_utf8(APP_JS).unwrap();
        let exports = shared
            .rsplit_once("  return {")
            .expect("app_shared.js must end with its export table")
            .1;

        let bytes: Vec<char> = app.chars().collect();
        let needle: Vec<char> = "shared.".chars().collect();
        let mut calls = 0usize;
        for start in 0..bytes.len().saturating_sub(needle.len()) {
            if bytes[start..start + needle.len()] != needle[..] {
                continue;
            }
            // Only a member access on the namespace binding itself, so the
            // literal "/static/app-shared.js" in a comment is not a match.
            if start > 0 && (bytes[start - 1].is_ascii_alphanumeric() || bytes[start - 1] == '-') {
                continue;
            }
            let name: String = bytes[start + needle.len()..]
                .iter()
                .take_while(|c| c.is_ascii_alphanumeric() || **c == '_')
                .collect();
            if name.is_empty() {
                continue;
            }
            calls += 1;
            assert!(
                exports.contains(&format!("{name}: {name},")),
                "app.js calls shared.{name}, which app_shared.js does not export"
            );
        }
        assert!(
            calls > 0,
            "the scan must find the namespace calls it checks"
        );
    }
}
