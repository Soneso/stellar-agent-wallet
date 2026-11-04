//! Position-only diagnostics for profile TOML.

/// The position of a TOML syntax error that starts at byte `start` of `body`.
///
/// The result is `line {l}, column {c}` and never the text; each caller adds
/// its own prefix naming the file. The line is the number of newlines before
/// `start` plus one, and the column is the number of characters after the
/// last of them plus one. An error without a start, or with a start that is
/// not a character boundary of `body`, gives `position unknown`. The `Display`
/// of the parser's error prints the offending line, which can hold a
/// credential, so it is not used.
pub fn toml_error_position(body: &str, start: Option<usize>) -> String {
    let Some(prefix) = start.and_then(|start| body.get(..start)) else {
        return "position unknown".to_owned();
    };
    let line = prefix.matches('\n').count() + 1;
    let column = prefix
        .rsplit_once('\n')
        .map_or(prefix, |(_, tail)| tail)
        .chars()
        .count()
        + 1;
    format!("line {line}, column {column}")
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test assertions")]
    use super::*;
    use toml_edit::DocumentMut;

    #[test]
    fn toml_error_position_matches_the_display_line() {
        let body =
            "NETWORK_PASSPHRASE = \"x\"\nACCOUNTS = [\"a\"]\nSECRET_MARKER = TOMLSECRET here\n";
        let err = body.parse::<DocumentMut>().unwrap_err();
        let position = toml_error_position(body, err.span().map(|s| s.start));
        assert_eq!(
            format!("TOML parse error at {position}"),
            err.to_string().lines().next().unwrap()
        );
        assert_eq!(position, "line 3, column 17");
        assert!(!position.contains("TOMLSECRET"));
        assert!(!position.contains("SECRET_MARKER"));
        assert_eq!(
            toml_error_position("a\n\u{e9}\u{e9}bc", Some(7)),
            "line 2, column 4"
        );
        let eof_body = "a = 1\nb = ";
        let err = eof_body.parse::<DocumentMut>().unwrap_err();
        assert_eq!(err.span().map(|span| span.start), Some(eof_body.len()));
        assert_eq!(
            toml_error_position(eof_body, err.span().map(|s| s.start)),
            "line 2, column 5"
        );
        assert_eq!(toml_error_position("", Some(0)), "line 1, column 1");
    }

    #[test]
    fn toml_error_without_a_span_reports_the_fixed_text() {
        assert_eq!(toml_error_position("abc", None), "position unknown");
        assert_eq!(toml_error_position("a\u{e9}b", Some(2)), "position unknown");
        assert_eq!(toml_error_position("abc", Some(4)), "position unknown");
    }
}
