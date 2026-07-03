//! Static web assets baked into the binary.
//!
//! Holds the wallet-authored, same-origin `app.js` served at
//! `GET /static/app.js`. Vanilla JS, no build step, no external dependency —
//! it reads the server-rendered data island and drives the inbox polling and
//! the detail-page approve/reject fetches.

/// Wallet-authored approval-inbox browser glue served at `GET /static/app.js`.
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
    fn app_js_wires_csrf_header() {
        let body = std::str::from_utf8(APP_JS).unwrap();
        assert!(body.contains("X-Stellar-Approval-CSRF"));
        assert!(body.contains("/pending.json"));
    }
}
