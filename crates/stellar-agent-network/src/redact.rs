//! Network-facing redaction helpers for RPC error displays.
//!
//! This module centralises redaction for error strings that originate in the
//! Stellar RPC transport layer before those strings cross CLI, MCP, or SEP
//! protocol wire boundaries.

pub use stellar_agent_core::redact::{redact_url_authority, redact_url_userinfo};

/// Redacts every HTTP(S) URL in an RPC error display string to authority only.
///
/// `NetworkError::RpcTimeout` and `NetworkError::RpcUnreachable` can include
/// the full RPC URL in their [`std::fmt::Display`] output. When the underlying
/// HTTP client also embeds the URL in a transport-error tail, the URL can appear
/// more than once. This helper scans every `http(s)://...` token
/// case-insensitively and preserves only `host[:port]`, stripping scheme,
/// `userinfo@`, path, query, and fragment. A space or either quote character
/// ends a token. A closing parenthesis ends a token only when no opening
/// parenthesis remains unmatched since the scheme. A comma stays in the token.
#[must_use]
pub fn redact_rpc_error(err_display: &str) -> String {
    // INVARIANT: Every character that ends a token (a space, either quote
    // character, and the closing parenthesis) is in `AUTHORITY_TERMINATORS`,
    // as are the URL separators `/`, `?`, and `#`. The token end never precedes
    // the authority end, so output never resumes inside a stripped userinfo,
    // path, query, or fragment.
    const AUTHORITY_TERMINATORS: [char; 8] = ['/', '?', '#', '\'', ')', ' ', ',', '"'];

    fn scheme_len_ci(s: &str) -> Option<usize> {
        let bytes = s.as_bytes();
        // `https://` is checked BEFORE `http://` so an `https://` prefix is not
        // mis-matched as `http` + a stray leading `s` left in the output.
        for scheme in [b"https://".as_slice(), b"http://".as_slice()] {
            if bytes.len() >= scheme.len() && bytes[..scheme.len()].eq_ignore_ascii_case(scheme) {
                return Some(scheme.len());
            }
        }
        None
    }

    let mut out = String::with_capacity(err_display.len());
    let mut rest = err_display;
    while !rest.is_empty() {
        let scheme_at = rest
            .char_indices()
            .find_map(|(i, _)| scheme_len_ci(&rest[i..]).map(|len| (i, len)));
        match scheme_at {
            Some((idx, scheme_len)) => {
                out.push_str(&rest[..idx]);
                let after_scheme = &rest[idx + scheme_len..];
                let auth_end = after_scheme
                    .find(AUTHORITY_TERMINATORS)
                    .unwrap_or(after_scheme.len());
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

#[cfg(test)]
mod tests {
    use stellar_agent_core::error::NetworkError;

    use super::{redact_rpc_error, redact_url_authority};

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
}
