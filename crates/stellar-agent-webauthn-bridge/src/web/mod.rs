//! Bridge web assets (vendored bundle + wallet-authored glue).
//!
//! This module ships three static assets baked into the bridge binary via
//! `include_bytes!`:
//!
//! 1. `SIMPLEWEBAUTHN_BUNDLE` — the vendored `@simplewebauthn/browser` v13.3.0
//!    UMD bundle (minified).  Served at `GET /static/webauthn.js`.
//! 2. `SIMPLEWEBAUTHN_BUNDLE_SRC` — the unminified concatenated source form
//!    of the same package, vendored alongside for byte-diffable human audit.
//!    NOT served at runtime; kept in the binary only so the SHA-verification
//!    test can re-compute the digest.
//! 3. `WALLET_GLUE_JS` — the wallet-authored DOM/fetch glue that reads the
//!    server-rendered data island, invokes `SimpleWebAuthnBrowser.start*`,
//!    and POSTs the credential / assertion back to the bridge.  Served at
//!    `GET /static/glue.js`.
//!
//! # Third-party license
//!
//! `@simplewebauthn/browser` is MIT-licensed (Copyright (c) 2020 Matthew
//! Miller). Its `LICENSE.md` is vendored at
//! `vendor/simplewebauthn-browser-13.3.0.LICENSE` and embedded as
//! [`SIMPLEWEBAUTHN_BUNDLE_LICENSE`] so the copyright + permission notice
//! travels with both the repository and the compiled binary, as the MIT
//! license requires.
//!
//! # SHA-256 pinning
//!
//! The exact SHA-256 of each vendored byte buffer is pinned both:
//!
//! - In `vendor/simplewebauthn-browser-13.3.0.sha256.txt` (text file shipped
//!   alongside the bytes, suitable for re-fetching the npm tarball and
//!   re-computing the hash out-of-band).
//! - As a `const &str` here ([`SIMPLEWEBAUTHN_BUNDLE_SHA256_HEX`] /
//!   [`SIMPLEWEBAUTHN_BUNDLE_SRC_SHA256_HEX`]).
//!
//! The unit test [`tests::vendored_bundle_sha256_matches_pin`] computes the
//! SHA-256 of the `include_bytes!`-embedded bytes at `cargo test` time and
//! asserts byte-equality with the pinned hex.  If anyone updates the vendor
//! bytes without touching the pin (or vice-versa), `cargo test` fails before
//! the bytes can reach a release binary.
//!
//! The fingerprint inside the bundle (`/* [@simplewebauthn/browser@13.3.0] */`)
//! is ALSO checked at the same test boundary, defending against a corrupted
//! bundle that happens to collide with the wrong SHA pin.
//!
//! The served responses carry `Cache-Control: no-store` via the router-
//! applied [`crate::SecurityHeadersLayer`] (not via these constants or the
//! `routes` handlers); that header lands on every response unconditionally,
//! so a stale-cache bundle can never outlive a re-vendoring step.

/// Vendored `@simplewebauthn/browser` v13.3.0 minified UMD bundle (9 269 bytes).
///
/// The UMD wrapper exposes the global `SimpleWebAuthnBrowser` object with
/// the two methods the bridge glue uses: `startRegistration` and
/// `startAuthentication`.
pub(crate) const SIMPLEWEBAUTHN_BUNDLE: &[u8] =
    include_bytes!("vendor/simplewebauthn-browser-13.3.0.min.js");

/// SHA-256 of [`SIMPLEWEBAUTHN_BUNDLE`] as lowercase hex.
///
/// Pinned at vendor-in time from the upstream npm tarball
/// `@simplewebauthn/browser@13.3.0` (`package/dist/bundle/index.umd.min.js`).
/// The shipped `*.sha256.txt` allows re-verification against the npm registry
/// out-of-band.
///
/// Consumed only by the `#[cfg(test)]` SHA-verification block; preserved as
/// a non-test `const` so a future operator reading the lib source can see
/// the pin without descending into test code.
#[allow(
    dead_code,
    reason = "consumed by #[cfg(test)] SHA-verification + by the shipped *.sha256.txt"
)]
pub(crate) const SIMPLEWEBAUTHN_BUNDLE_SHA256_HEX: &str =
    "cf4469953efcb5617a870ae3f022b3ad48aee8c06012ccdafcabc73058f123a0";

/// Vendored unminified source companion (29 586 bytes), for human audit
/// only — NOT served at runtime.
///
/// Concatenated from the `package/esm/**/*.js` files in the npm tarball
/// (file-path-header comments, lexicographic order).  The byte-diffable
/// unminified source sits alongside the minified bundle so a future operator
/// can inspect what the runtime bytes mean.
#[allow(
    dead_code,
    reason = "audit companion — consumed only by #[cfg(test)] SHA verification + human audit; vendored bytes remain in the binary so the test can re-hash them"
)]
pub(crate) const SIMPLEWEBAUTHN_BUNDLE_SRC: &[u8] =
    include_bytes!("vendor/simplewebauthn-browser-13.3.0.src.js");

/// SHA-256 of [`SIMPLEWEBAUTHN_BUNDLE_SRC`] as lowercase hex.
///
/// Pinned at vendor-in time, paired with the deterministic concatenation
/// rule (esm/**/*.js, lexicographic, `// ===== file: <rel> =====` headers).
#[allow(
    dead_code,
    reason = "consumed by #[cfg(test)] SHA-verification for the audit-companion source"
)]
pub(crate) const SIMPLEWEBAUTHN_BUNDLE_SRC_SHA256_HEX: &str =
    "f3c60d2fa0045b421d05c24031497ece8879c8115d8c95f76b0d4d108f19a5b7";

/// Wallet-authored browser glue (loaded after [`SIMPLEWEBAUTHN_BUNDLE`]).
///
/// Reads the server-rendered `<script type="application/json"
/// id="webauthn-options">` data island, runs the registration or
/// authentication ceremony via the vendored bundle, POSTs the result to
/// `/register/<nonce>/credential` or `/approve/<nonce>/assertion` with the
/// `X-Stellar-Approval-CSRF` header.
///
/// Source-of-truth: `src/web/glue.js`.  Reviewed under standard repo
/// discipline; not a third-party dependency.
pub(crate) const WALLET_GLUE_JS: &[u8] = include_bytes!("glue.js");

/// Version-marker substring expected inside [`SIMPLEWEBAUTHN_BUNDLE`].
///
/// `@simplewebauthn/browser`'s build emits the version header
/// `/* [@simplewebauthn/browser@13.3.0] */` as the first line of the UMD
/// bundle.  Asserting the substring exists is a second-layer defence
/// against the SHA pin: a corrupted-but-collided bundle would still need
/// to carry the version marker to pass this check.
#[allow(
    dead_code,
    reason = "consumed by #[cfg(test)] version-marker check; non-test `const` so a future operator can see the pinned upstream version without descending into test code"
)]
pub(crate) const SIMPLEWEBAUTHN_BUNDLE_VERSION_MARKER: &str = "[@simplewebauthn/browser@13.3.0]";

/// Upstream MIT license text for the vendored `@simplewebauthn/browser` bundle.
///
/// `@simplewebauthn/browser` is MIT-licensed (Copyright (c) 2020 Matthew
/// Miller). The MIT license requires the copyright and permission notice to be
/// included in all copies or substantial portions of the software, so the
/// upstream `LICENSE.md` is vendored alongside the bundle bytes and embedded in
/// the binary here. A `#[cfg(test)]` check asserts the notice is present.
#[allow(
    dead_code,
    reason = "embedded so the MIT copyright + permission notice ships with the binary alongside the bundle bytes; the notice text is asserted by a #[cfg(test)] check"
)]
pub(crate) const SIMPLEWEBAUTHN_BUNDLE_LICENSE: &str =
    include_str!("vendor/simplewebauthn-browser-13.3.0.LICENSE");

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only"
    )]

    use super::*;
    use sha2::{Digest, Sha256};

    fn sha256_hex(bytes: &[u8]) -> String {
        let mut h = Sha256::new();
        h.update(bytes);
        hex::encode(h.finalize())
    }

    #[test]
    fn vendored_bundle_sha256_matches_pin() {
        let computed = sha256_hex(SIMPLEWEBAUTHN_BUNDLE);
        assert_eq!(
            computed, SIMPLEWEBAUTHN_BUNDLE_SHA256_HEX,
            "vendored simplewebauthn-browser-13.3.0.min.js SHA-256 must match the pinned digest"
        );
    }

    #[test]
    fn vendored_bundle_src_sha256_matches_pin() {
        let computed = sha256_hex(SIMPLEWEBAUTHN_BUNDLE_SRC);
        assert_eq!(
            computed, SIMPLEWEBAUTHN_BUNDLE_SRC_SHA256_HEX,
            "vendored simplewebauthn-browser-13.3.0.src.js SHA-256 must match the pinned digest"
        );
    }

    #[test]
    fn vendored_bundle_license_carries_mit_notice() {
        // The MIT license requires the copyright + permission notice to travel
        // with every copy or substantial portion of the software. Assert both
        // are present in the embedded license text.
        assert!(
            SIMPLEWEBAUTHN_BUNDLE_LICENSE.contains("Copyright (c) 2020 Matthew Miller"),
            "vendored license must carry the upstream copyright line"
        );
        assert!(
            SIMPLEWEBAUTHN_BUNDLE_LICENSE.contains("Permission is hereby granted, free of charge"),
            "vendored license must carry the MIT permission notice"
        );
    }

    #[test]
    fn vendored_bundle_has_version_marker() {
        let body = std::str::from_utf8(SIMPLEWEBAUTHN_BUNDLE)
            .expect("vendored bundle must be valid UTF-8");
        assert!(
            body.contains(SIMPLEWEBAUTHN_BUNDLE_VERSION_MARKER),
            "bundle must carry the upstream version-marker comment \
             (defence-in-depth against a SHA-colliding tamper)"
        );
    }

    #[test]
    fn vendored_bundle_size_matches_audit() {
        // The exact byte count from the npm tarball is pinned here.
        assert_eq!(
            SIMPLEWEBAUTHN_BUNDLE.len(),
            9_269,
            "vendored bundle byte count must match the pinned value from the npm tarball"
        );
    }

    #[test]
    fn vendored_bundle_src_size_matches_pin() {
        // Pin the audit-companion byte count so the documented size cannot
        // silently drift (the SHA-256 pin guards integrity but not the count).
        assert_eq!(
            SIMPLEWEBAUTHN_BUNDLE_SRC.len(),
            29_586,
            "vendored src companion byte count must match the documented value"
        );
    }

    #[test]
    fn wallet_glue_is_valid_utf8() {
        std::str::from_utf8(WALLET_GLUE_JS).expect("wallet glue must be valid UTF-8");
    }

    #[test]
    fn wallet_glue_uses_only_simplewebauthnbrowser_global() {
        // Sanity-check the glue references the expected UMD global; if a
        // future refactor renames the global, this test catches the drift.
        let body = std::str::from_utf8(WALLET_GLUE_JS).expect("utf-8");
        assert!(
            body.contains("SimpleWebAuthnBrowser.startRegistration"),
            "glue must invoke SimpleWebAuthnBrowser.startRegistration"
        );
        assert!(
            body.contains("SimpleWebAuthnBrowser.startAuthentication"),
            "glue must invoke SimpleWebAuthnBrowser.startAuthentication"
        );
    }

    #[test]
    fn vendor_sha256_txt_matches_pinned_constants() {
        // The shipped `*.sha256.txt` file is consumed out-of-band; the pin in
        // this module is consumed by the runtime/test SHA check. They must
        // agree byte-for-byte on the hex digests.
        const SHA256_TXT: &str = include_str!("vendor/simplewebauthn-browser-13.3.0.sha256.txt");
        assert!(
            SHA256_TXT.contains(SIMPLEWEBAUTHN_BUNDLE_SHA256_HEX),
            "vendor/*.sha256.txt must list the min.js SHA pin"
        );
        assert!(
            SHA256_TXT.contains(SIMPLEWEBAUTHN_BUNDLE_SRC_SHA256_HEX),
            "vendor/*.sha256.txt must list the src.js SHA pin"
        );
    }
}
