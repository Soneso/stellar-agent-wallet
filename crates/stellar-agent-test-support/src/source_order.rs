//! Source-order assertions for tests that pin where a call sits inside a
//! production function.
//!
//! A test reads a source file with `include_str!` and asserts that one call
//! follows another inside a named function. The scan is textual and covers
//! only the production half of the file, the text before its first
//! `#[cfg(test)]`.

#![allow(clippy::panic, reason = "assertion helpers panic to fail the test")]

/// The production half of a source file: the text before its first
/// `#[cfg(test)]`, or the whole file when it has none.
#[must_use]
pub fn production_half(source: &str) -> &str {
    source.split("#[cfg(test)]").next().unwrap_or(source)
}

/// Asserts that, inside the function starting at `function`, a call to
/// `middle` follows the first `first` and precedes the first `last`.
///
/// `file` names the source in failure messages. Only the production half of
/// `source` is scanned.
///
/// # Panics
///
/// When `function`, `first`, or `last` is missing, when no `middle` follows
/// `first`, or when that `middle` does not precede `last`.
pub fn assert_called_between(
    file: &str,
    source: &str,
    function: &str,
    first: &str,
    middle: &str,
    last: &str,
) {
    let source = production_half(source);
    let start = source
        .find(function)
        .unwrap_or_else(|| panic!("{file}: `{function}` not found"));
    let body = &source[start..];
    let first_at = body
        .find(first)
        .unwrap_or_else(|| panic!("{file}: `{first}` not found after `{function}`"));
    let last_at = body
        .find(last)
        .unwrap_or_else(|| panic!("{file}: `{last}` not found after `{function}`"));
    let middle_at = body[first_at..]
        .find(middle)
        .map(|offset| first_at + offset)
        .unwrap_or_else(|| panic!("{file}: no `{middle}` after `{first}`"));
    assert!(
        first_at < middle_at && middle_at < last_at,
        "{file}: in `{function}`, `{middle}` must sit between `{first}` and `{last}`"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOURCE: &str = "fn run() {\n    read();\n    drain();\n    sign();\n}\n\
                          #[cfg(test)]\nmod tests { fn t() { sign(); drain(); } }\n";

    #[test]
    fn the_production_half_stops_at_the_first_test_module() {
        assert!(!production_half(SOURCE).contains("mod tests"));
        assert_eq!(production_half("fn a() {}"), "fn a() {}");
    }

    #[test]
    fn a_call_between_the_two_others_passes() {
        assert_called_between("s.rs", SOURCE, "fn run(", "read(", "drain(", "sign(");
    }

    #[test]
    #[should_panic(expected = "must sit between")]
    fn a_call_after_the_last_one_fails() {
        assert_called_between("s.rs", SOURCE, "fn run(", "read(", "sign(", "drain(");
    }
}
