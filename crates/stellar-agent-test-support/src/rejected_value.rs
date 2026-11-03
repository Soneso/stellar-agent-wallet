//! Assertions that an error never repeats a value the wallet rejected.
//!
//! A test passes one of the markers below where the wallet expects some other
//! input, then asserts with [`assert_no_marker`] that the resulting error does
//! not carry it.

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

    #[cfg(feature = "test-helpers")]
    #[test]
    fn the_seed_marker_is_a_secret_seed_strkey() {
        let marker = seed_marker();
        assert_eq!(marker.len(), 56);
        assert!(marker.starts_with('S'));
        assert!(stellar_strkey::ed25519::PrivateKey::from_string(&marker).is_ok());
    }
}
