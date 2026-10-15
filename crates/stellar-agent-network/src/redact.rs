//! Network-facing redaction helpers for RPC error displays.
//!
//! This module centralises redaction for error strings that originate in the
//! Stellar RPC transport layer before those strings cross CLI, MCP, or SEP
//! protocol wire boundaries.

pub use stellar_agent_core::redact::{redact_url_authority, redact_url_userinfo};

/// Redacts every URL in an RPC error display string to authority only.
///
/// `NetworkError::RpcTimeout` and `NetworkError::RpcUnreachable` can include
/// the full RPC URL in their [`std::fmt::Display`] output. When the underlying
/// HTTP client also embeds the URL in a transport-error tail, the URL can appear
/// more than once. A JSON-RPC error object renders its `data` as raw JSON, where
/// a serializer may escape each slash as `\/`.
///
/// This helper scans case-insensitively for the schemes `http://`, `https://`,
/// `ws://`, and `wss://`, and for their JSON-escaped forms `http:\/\/`,
/// `https:\/\/`, `ws:\/\/`, and `wss:\/\/`. It keeps only `host[:port]` of
/// each URL and strips the scheme, `userinfo@`, path, query, and fragment.
///
/// The authority ends at the first `/`, `?`, `#`, `'`, `)`, space, comma, or
/// `"`. After an escaped scheme it also ends at the backslash of the first
/// `\/`. Userinfo ends at the last `@` inside the authority.
///
/// The stripped token ends at a space or either quote character. A closing
/// parenthesis ends it only when no opening parenthesis remains unmatched since
/// the scheme. Commas, tabs, newlines, and `\/` stay in the token. Output
/// resumes at the character that ends the token.
///
/// Percent-encoded URLs, query fragments without a scheme such as a bare
/// `?token=...`, and doubly escaped forms such as `https:\\/\\/` pass
/// through unchanged.
#[must_use]
pub fn redact_rpc_error(err_display: &str) -> String {
    // INVARIANT: Every character that ends a token (a space, either quote
    // character, and the closing parenthesis) is in `AUTHORITY_TERMINATORS`,
    // as are the URL separators `/`, `?`, and `#`. An escaped scheme can only
    // end its authority earlier. The token end never precedes the authority
    // end, so output never resumes inside a stripped userinfo, path, query, or
    // fragment.
    const AUTHORITY_TERMINATORS: [char; 8] = ['/', '?', '#', '\'', ')', ' ', ',', '"'];

    /// The two-byte JSON escape of a slash.
    const ESCAPED_SLASH: &str = "\\/";

    /// Recognized scheme prefixes, each paired with whether its slashes are
    /// JSON-escaped. No prefix is a prefix of another, so the order of the
    /// table does not change which prefix matches.
    const SCHEMES: [(&[u8], bool); 8] = [
        (b"https://", false),
        (b"http://", false),
        (b"wss://", false),
        (b"ws://", false),
        (b"https:\\/\\/", true),
        (b"http:\\/\\/", true),
        (b"wss:\\/\\/", true),
        (b"ws:\\/\\/", true),
    ];

    /// Returns the byte length of the scheme prefix `s` starts with, and
    /// whether that prefix is JSON-escaped.
    fn scheme_at_ci(s: &str) -> Option<(usize, bool)> {
        let bytes = s.as_bytes();
        SCHEMES.iter().find_map(|&(scheme, escaped)| {
            (bytes.len() >= scheme.len() && bytes[..scheme.len()].eq_ignore_ascii_case(scheme))
                .then_some((scheme.len(), escaped))
        })
    }

    let mut out = String::with_capacity(err_display.len());
    let mut rest = err_display;
    while !rest.is_empty() {
        let scheme_at = rest
            .char_indices()
            .find_map(|(i, _)| scheme_at_ci(&rest[i..]).map(|(len, escaped)| (i, len, escaped)));
        match scheme_at {
            Some((idx, scheme_len, escaped)) => {
                out.push_str(&rest[..idx]);
                let after_scheme = &rest[idx + scheme_len..];
                let mut auth_end = after_scheme
                    .find(AUTHORITY_TERMINATORS)
                    .unwrap_or(after_scheme.len());
                if escaped && let Some(slash_at) = after_scheme.find(ESCAPED_SLASH) {
                    auth_end = auth_end.min(slash_at);
                }
                let authority = &after_scheme[..auth_end];
                let host_port = authority
                    .rsplit_once('@')
                    .map_or(authority, |(_userinfo, host)| host);
                out.push_str(host_port);
                let mut open_parens = 0_usize;
                let tok_end = after_scheme
                    .find(|ch: char| match ch {
                        '(' => {
                            open_parens += 1;
                            false
                        }
                        ')' if open_parens > 0 => {
                            open_parens -= 1;
                            false
                        }
                        ')' | '\'' | '"' => true,
                        _ => ch == ' ',
                    })
                    .unwrap_or(after_scheme.len());
                rest = &after_scheme[tok_end..];
            }
            None => {
                out.push_str(rest);
                break;
            }
        }
    }
    out
}

/// Renders `err` with [`std::fmt::Display`] and scrubs the text with
/// [`redact_rpc_error`].
///
/// The display of a `stellar_rpc_client::Error` that carries a JSON-RPC error
/// object holds the server's `message` and raw `data` in full. Every network
/// error field that takes such a display goes through this helper.
#[must_use]
pub fn redact_rpc_error_display<E: std::fmt::Display + ?Sized>(err: &E) -> String {
    redact_rpc_error(&err.to_string())
}

/// RPC errors that carry a credential-bearing URL in server-provided text, for
/// the unit tests of the modules that map such errors.
#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::panic,
    reason = "test-only fixtures; a malformed fixture is a test bug"
)]
pub(crate) mod rpc_error_fixtures {
    /// The endpoint the mapping tests name, with credentials in every part
    /// the `url` field of an error drops.
    pub(crate) const ENDPOINT: &str =
        "https://op:OPSECRET@rpc.example.com:8443/soroban/rpc?key=OPSECRET";

    /// The authority form of [`ENDPOINT`], which the `url` field keeps.
    pub(crate) const ENDPOINT_AUTHORITY: &str = "https://rpc.example.com:8443";

    /// A credential-bearing URL a server echoes into its error text.
    pub(crate) const ECHOED_URL: &str =
        "https://user:SECRET@archive.example.com:8443/rpc?token=SECRET";

    /// The JSON-RPC error object of a server that echoes [`ECHOED_URL`] in its
    /// `message` only.
    pub(crate) const MESSAGE_ONLY: &str = r#"{"code":-32000,"message":"upstream https://user:SECRET@archive.example.com:8443/rpc?token=SECRET failed"}"#;

    /// The JSON-RPC error object of a server that echoes [`ECHOED_URL`] in its
    /// `data` only, with each slash JSON-escaped.
    pub(crate) const ESCAPED_DATA_ONLY: &str = r#"{"code":-32000,"message":"upstream failed","data":{"url":"https:\/\/user:SECRET@archive.example.com:8443\/rpc?token=SECRET"}}"#;

    /// The JSON-RPC error object of a server that echoes [`ECHOED_URL`] in both
    /// its `message` and its `data`.
    pub(crate) const MESSAGE_AND_DATA: &str = r#"{"code":-32000,"message":"upstream https://user:SECRET@archive.example.com:8443/rpc?token=SECRET failed","data":{"url":"https://user:SECRET@archive.example.com:8443/rpc?token=SECRET"}}"#;

    /// Every JSON-RPC error object above, named for assertion messages.
    pub(crate) const ERROR_OBJECTS: [(&str, &str); 3] = [
        ("message only", MESSAGE_ONLY),
        ("escaped data only", ESCAPED_DATA_ONLY),
        ("message and data", MESSAGE_AND_DATA),
    ];

    /// The jsonrpsee error a JSON-RPC error object parsed from `raw` yields.
    pub(crate) fn call_client_error(raw: &str) -> jsonrpsee_core::ClientError {
        jsonrpsee_core::ClientError::Call(
            serde_json::from_str(raw).expect("fixture is a JSON-RPC error object"),
        )
    }

    /// The RPC client error a JSON-RPC error object parsed from `raw` yields.
    pub(crate) fn call_error(raw: &str) -> stellar_rpc_client::Error {
        stellar_rpc_client::Error::JsonRpc(call_client_error(raw))
    }

    /// An XDR error whose text holds [`ECHOED_URL`].
    pub(crate) fn xdr_error() -> stellar_rpc_client::Error {
        stellar_rpc_client::Error::Xdr(stellar_xdr::Error::Io(std::io::Error::other(format!(
            "unexpected body near {ECHOED_URL}"
        ))))
    }

    /// Asserts that `field` keeps the echoed host and port and holds no part
    /// of the echoed URL's scheme, userinfo, path, or query.
    pub(crate) fn assert_scrubbed(case: &str, field: &str) {
        assert!(
            field.contains("archive.example.com:8443"),
            "{case}: the echoed host and port must remain: {field}"
        );
        for leaked in ["SECRET", "token=", "user:", "https://", "https:\\/", "/rpc"] {
            assert!(
                !field.contains(leaked),
                "{case}: {leaked} survived the scrub: {field}"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use stellar_agent_core::error::NetworkError;

    use super::{redact_rpc_error, redact_rpc_error_display, redact_url_authority};

    #[test]
    fn rpc_unreachable_and_timeout_display_store_authority_only_url() {
        let raw = "https://user:secrettoken@rpc.example.com/path?q=1";
        let url = redact_url_authority(raw);
        let unreachable = NetworkError::RpcUnreachable {
            url: url.clone(),
            reason: "transport failed".to_owned(),
        };
        let timeout = NetworkError::RpcTimeout {
            url: url.clone(),
            timeout_secs: 30,
        };

        for (stored_url, display) in [
            (url.as_str(), unreachable.to_string()),
            (url.as_str(), timeout.to_string()),
        ] {
            assert_eq!(stored_url, "https://rpc.example.com");
            assert!(display.contains("https://rpc.example.com"));
            assert!(!display.contains("secrettoken"));
            assert!(!display.contains("user:"));
            assert!(!display.contains("/path"));
            assert!(!display.contains("?q=1"));
        }
    }

    #[test]
    fn redact_rpc_error_redacts_all_url_occurrences() {
        let raw = "RPC endpoint 'https://private-node.example.com:8443/soroban/rpc?token=SECRET' \
                   is unreachable: getLedgerEntries failed: error sending request for url \
                   (https://private-node.example.com:8443/soroban/rpc?token=SECRET)";
        let redacted = redact_rpc_error(raw);

        assert!(redacted.contains("private-node.example.com:8443"));
        assert!(!redacted.contains("https://"));
        assert!(!redacted.contains("/soroban/rpc"));
        assert!(!redacted.contains("token=SECRET"));
        assert!(redacted.contains("is unreachable: getLedgerEntries failed:"));
        assert_eq!(redacted.matches("private-node.example.com:8443").count(), 2);
    }

    #[test]
    fn redact_rpc_error_strips_userinfo_and_matches_uppercase_scheme() {
        let raw = "RPC endpoint 'HTTPS://admin:s3cr3t@private-node.example.com:8443/rpc' \
                   is unreachable: timed out";
        let redacted = redact_rpc_error(raw);

        assert!(redacted.contains("private-node.example.com:8443"));
        assert!(!redacted.contains("admin") && !redacted.contains("s3cr3t"));
        assert!(!redacted.to_ascii_lowercase().contains("https://"));
        assert!(!redacted.contains("/rpc"));
    }

    #[test]
    fn redact_rpc_error_strips_query_without_path() {
        let raw = "fetch failed: https://node.example.com?token=SECRET stop";
        let redacted = redact_rpc_error(raw);

        assert!(redacted.contains("node.example.com"));
        assert!(!redacted.contains("token=SECRET"));
        assert!(redacted.contains("stop"));
    }

    #[test]
    fn redact_rpc_error_strips_userinfo_and_query_containing_comma() {
        let raw = "error sending request for url \
                   (https://user:SECRET@rpc.example.com:8443/rpc?tags=a,b&token=SECRET) for x";
        assert_eq!(
            redact_rpc_error(raw),
            "error sending request for url (rpc.example.com:8443) for x"
        );
    }

    #[test]
    fn redact_rpc_error_strips_query_containing_parenthesized_value() {
        let raw = "error sending request for url \
                   (https://rpc.example.com/rpc?f=(x)&token=SECRET): timed out";
        assert_eq!(
            redact_rpc_error(raw),
            "error sending request for url (rpc.example.com): timed out"
        );
    }

    #[test]
    fn redact_rpc_error_strips_queries_and_comma_between_urls() {
        let raw = "tried https://a.example/x?t=SECRET, https://b.example/y?t=SECRET";
        assert_eq!(redact_rpc_error(raw), "tried a.example b.example");
    }

    #[test]
    fn redact_rpc_error_strips_userinfo_containing_tab() {
        let raw = "error for https://user:\tSECRET@rpc.example/x done";
        assert_eq!(redact_rpc_error(raw), "error for rpc.example done");
    }

    #[test]
    fn redact_rpc_error_strips_query_containing_nested_parentheses() {
        let raw = "url (https://rpc.example.com/rpc?f=((x))&token=SECRET) end";
        assert_eq!(redact_rpc_error(raw), "url (rpc.example.com) end");
    }

    #[test]
    fn redact_rpc_error_strips_quoted_urls_and_keeps_quotes() {
        let raw = r#"url 'https://rpc.example.com/rpc?token=SECRET' and "https://other.example/p?k=SECRET""#;
        assert_eq!(
            redact_rpc_error(raw),
            r#"url 'rpc.example.com' and "other.example""#
        );
    }

    #[test]
    fn redact_rpc_error_passthrough_without_url() {
        let raw = "decode error: missing contractspecv0 entry";
        assert_eq!(redact_rpc_error(raw), raw);
    }

    #[test]
    fn redact_rpc_error_strips_json_escaped_url_in_raw_data() {
        let raw = r#"data: Some(RawValue({"url":"https:\/\/user:SECRET@archive.example.com:8443\/rpc?token=SECRET"}))"#;
        assert_eq!(
            redact_rpc_error(raw),
            r#"data: Some(RawValue({"url":"archive.example.com:8443"}))"#
        );
    }

    #[test]
    fn redact_rpc_error_strips_escaped_http_url_with_mixed_case_scheme() {
        let raw = r#"{"a":"HtTp:\/\/node.example\/x\/y?k=SECRET","b":1}"#;
        assert_eq!(redact_rpc_error(raw), r#"{"a":"node.example","b":1}"#);
    }

    #[test]
    fn redact_rpc_error_strips_escaped_url_with_query_and_no_path() {
        let raw = r#"{"u":"https:\/\/node.example:443?token=SECRET"} tail"#;
        assert_eq!(redact_rpc_error(raw), r#"{"u":"node.example:443"} tail"#);
    }

    #[test]
    fn redact_rpc_error_strips_escaped_ws_url() {
        let raw = r#"{"u":"ws:\/\/user:SECRET@stream.example.com:443\/ws?token=SECRET"} end"#;
        assert_eq!(
            redact_rpc_error(raw),
            r#"{"u":"stream.example.com:443"} end"#
        );
    }

    #[test]
    fn redact_rpc_error_strips_escaped_wss_url_with_mixed_case_scheme() {
        let raw = r#"{"u":"WsS:\/\/node.example\/x\/y?k=SECRET","n":1}"#;
        assert_eq!(redact_rpc_error(raw), r#"{"u":"node.example","n":1}"#);
    }

    #[test]
    fn redact_rpc_error_strips_websocket_urls() {
        let raw = "stream wss://user:SECRET@stream.example.com:443/ws?token=SECRET closed, \
                   WS://local.example/x?k=SECRET";
        assert_eq!(
            redact_rpc_error(raw),
            "stream stream.example.com:443 closed, local.example"
        );
    }

    #[test]
    fn redact_rpc_error_display_scrubs_the_rendered_error() {
        let err = std::io::Error::other(
            "upstream https://user:SECRET@archive.example.com:8443/rpc?token=SECRET refused",
        );
        assert_eq!(
            redact_rpc_error_display(&err),
            "upstream archive.example.com:8443 refused"
        );
        assert_eq!(
            redact_rpc_error_display("echo https://h.example/p?token=SECRET"),
            "echo h.example"
        );
    }
}
