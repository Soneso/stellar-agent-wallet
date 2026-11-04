//! Assertions that an error never repeats a value the wallet rejected.
//!
//! A test passes one of the markers below where the wallet expects some other
//! input, then asserts with [`assert_no_marker`] that the resulting error does
//! not carry it.

use crate::log_capture::RedactionStrictSubscriber;

/// The S-strkey of the secret seed of 32 bytes of 7. A test passes it where
/// the wallet expects a public value, as an operator who pastes a seed into
/// the wrong place would.
#[cfg(feature = "test-helpers")]
#[must_use]
pub fn seed_marker() -> String {
    stellar_strkey::ed25519::PrivateKey([7; 32])
        .as_unredacted()
        .to_string()
        .as_str()
        .to_owned()
}

/// A credential a test embeds in a URL, a TOML line, or a file name.
pub const CREDENTIAL_MARKER: &str = "CREDMARKER7";

/// Asserts that `marker` appears in neither the `Display` nor the `Debug`
/// rendering of `error`, nor of any error in its source chain.
///
/// # Panics
///
/// Panics naming the rendering and the depth in the chain that holds the
/// marker.
pub fn assert_no_marker(error: &(dyn std::error::Error + 'static), marker: &str) {
    let mut current = Some(error);
    let mut depth = 0_usize;
    while let Some(error) = current {
        assert!(
            !error.to_string().contains(marker),
            "the Display of the error at depth {depth} contains the rejected value"
        );
        assert!(
            !format!("{error:?}").contains(marker),
            "the Debug of the error at depth {depth} contains the rejected value"
        );
        current = error.source();
        depth += 1;
    }
}

/// Asserts that `marker` does not appear in `text`, a rendered envelope,
/// a log line, or a process's output.
///
/// # Panics
///
/// Panics when `text` contains `marker`, without printing either.
pub fn assert_no_marker_in_text(text: &str, marker: &str) {
    assert!(
        !text.contains(marker),
        "the rendered text contains the rejected value"
    );
}

/// Asserts that `error` renders as exactly `expected` and holds no
/// [`CREDENTIAL_MARKER`], then logs it for [`capture_refusal`] to inspect.
///
/// # Panics
///
/// Panics when a rendering holds the marker or the text differs. The marker
/// check runs first, so a text that repeats rejected input reports the leak.
pub fn assert_refusal_text(error: &(dyn std::error::Error + 'static), expected: &str) {
    assert_no_marker(error, CREDENTIAL_MARKER);
    assert_eq!(error.to_string(), expected);
    tracing::warn!(error = %error, debug = ?error, "refusal capture probe");
}

/// Runs `f` under a log capture that forbids [`CREDENTIAL_MARKER`].
///
/// # Panics
///
/// Panics when `f` reached no [`assert_refusal_text`], so an absence check
/// cannot pass on a lost event, and when a captured event holds the marker.
pub fn capture_refusal(f: impl FnOnce()) {
    let capture = RedactionStrictSubscriber::new([CREDENTIAL_MARKER]);
    capture.run(f);
    assert!(capture.captured_str().contains("refusal capture probe"));
    capture.assert_clean();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct Leaf(&'static str);

    impl std::fmt::Display for Leaf {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(self.0)
        }
    }

    impl std::error::Error for Leaf {}

    /// An error whose own renderings hold none of its source, so a marker in
    /// the leaf is reachable only by walking the chain.
    struct Wrapper(Leaf);

    impl std::fmt::Debug for Wrapper {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("Wrapper")
        }
    }

    impl std::fmt::Display for Wrapper {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("wrapper")
        }
    }

    impl std::error::Error for Wrapper {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(&self.0)
        }
    }

    #[test]
    fn a_clean_chain_passes() {
        assert_no_marker(&Wrapper(Leaf("clean")), CREDENTIAL_MARKER);
    }

    #[test]
    #[should_panic(expected = "depth 1")]
    fn a_marker_in_the_source_chain_fails() {
        assert_no_marker(&Wrapper(Leaf(CREDENTIAL_MARKER)), CREDENTIAL_MARKER);
    }

    #[test]
    fn a_refusal_with_its_fixed_text_passes() {
        capture_refusal(|| assert_refusal_text(&Leaf("fixed text"), "fixed text"));
    }

    #[test]
    #[should_panic(expected = "contains the rejected value")]
    fn a_refusal_holding_the_marker_fails_on_the_marker() {
        assert_refusal_text(&Leaf(CREDENTIAL_MARKER), CREDENTIAL_MARKER);
    }

    #[test]
    #[should_panic(expected = "left == right")]
    fn a_refusal_with_another_text_fails() {
        assert_refusal_text(&Leaf("fixed text"), "other text");
    }

    #[test]
    #[should_panic(expected = "refusal capture probe")]
    fn a_capture_without_a_refusal_fails() {
        capture_refusal(|| {});
    }

    #[cfg(feature = "test-helpers")]
    #[test]
    fn the_seed_marker_is_a_secret_seed_strkey() {
        let marker = seed_marker();
        assert_eq!(marker.len(), 56);
        assert!(marker.starts_with('S'));
        assert!(stellar_strkey::ed25519::PrivateKey::from_string(&marker).is_ok());
    }
}
