//! Source-order assertions for tests that pin where a call sits inside a
//! production function.
//!
//! A test reads a source file with `include_str!` and asserts that one call
//! follows another inside a named function. The scan is textual.
//! [`assert_called_between`] covers the production half of the file, the text
//! before its first `#[cfg(test)]`. The function-scoped helpers cover the
//! named function's own text, from its signature to its closing brace.

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

/// The text of the first function whose signature starts with `function`:
/// from the signature to its closing brace, which is the first later line
/// holding only `}` at the signature's indentation.
///
/// `file` names the source in failure messages. The whole of `source` is
/// searched, so a production function that follows a test-only item is found;
/// a file's production functions precede its test module, so the first match
/// of a signature is the production one.
///
/// # Panics
///
/// When `function` or its closing brace is missing.
#[must_use]
pub fn function_body<'a>(file: &str, source: &'a str, function: &str) -> &'a str {
    let start = source
        .find(function)
        .unwrap_or_else(|| panic!("{file}: `{function}` not found"));
    let line_start = source[..start].rfind('\n').map_or(0, |at| at + 1);
    let indent = &source[line_start..start];
    let closing = format!("\n{indent}}}\n");
    let end = source[start..]
        .find(&closing)
        .unwrap_or_else(|| panic!("{file}: closing brace of `{function}` not found"));
    &source[start..start + end + closing.len()]
}

/// Asserts that, inside the function starting at `function`, each of `calls`
/// occurs, and that the first occurrence of each follows the first occurrence
/// of the one before it.
///
/// `file` names the source in failure messages. Only the function's own text
/// is scanned (see [`function_body`]).
///
/// # Panics
///
/// When the function or any call is missing, or when two calls are out of
/// order.
pub fn assert_calls_in_order(file: &str, source: &str, function: &str, calls: &[&str]) {
    let body = function_body(file, source, function);
    let mut previous: Option<(&str, usize)> = None;
    for call in calls {
        let at = body
            .find(call)
            .unwrap_or_else(|| panic!("{file}: `{call}` not found in `{function}`"));
        if let Some((before, before_at)) = previous {
            assert!(
                before_at < at,
                "{file}: in `{function}`, `{before}` must precede `{call}`"
            );
        }
        previous = Some((call, at));
    }
}

/// Asserts that the function starting at `function` contains none of
/// `calls`.
///
/// `file` names the source in failure messages. Only the function's own text
/// is scanned (see [`function_body`]).
///
/// # Panics
///
/// When the function is missing or contains one of `calls`.
pub fn assert_not_called(file: &str, source: &str, function: &str, calls: &[&str]) {
    let body = function_body(file, source, function);
    for call in calls {
        assert!(
            !body.contains(call),
            "{file}: `{function}` must not call `{call}`"
        );
    }
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

    const METHODS: &str = "impl S {\n    fn run() {\n        read();\n        sign();\n    }\n\n    \
                           fn later() {\n        drain();\n    }\n}\n";

    #[test]
    fn a_function_after_a_test_only_item_is_found() {
        let source = "#[cfg(test)]\nfn helper() {}\n\nfn run() {\n    read();\n}\n";
        assert_eq!(
            function_body("s.rs", source, "fn run("),
            "fn run() {\n    read();\n}\n"
        );
    }

    #[test]
    fn the_function_body_ends_at_its_closing_brace() {
        let body = function_body("s.rs", METHODS, "fn run(");
        assert!(body.starts_with("fn run("));
        assert!(body.ends_with("    }\n"));
        assert!(body.contains("sign();"));
        assert!(!body.contains("drain();"));
    }

    #[test]
    fn calls_in_order_pass() {
        assert_calls_in_order("s.rs", METHODS, "fn run(", &["read(", "sign("]);
        assert_not_called("s.rs", METHODS, "fn run(", &["drain("]);
    }

    #[test]
    #[should_panic(expected = "must precede")]
    fn calls_out_of_order_fail() {
        assert_calls_in_order("s.rs", METHODS, "fn run(", &["sign(", "read("]);
    }

    #[test]
    #[should_panic(expected = "not found in")]
    fn a_call_in_a_later_function_does_not_count() {
        assert_calls_in_order("s.rs", METHODS, "fn run(", &["read(", "drain("]);
    }

    #[test]
    #[should_panic(expected = "must not call")]
    fn a_forbidden_call_fails() {
        assert_not_called("s.rs", METHODS, "fn run(", &["sign("]);
    }
}
