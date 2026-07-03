//! Network-facing redaction helpers for RPC error displays.
//!
//! This module centralises redaction for error strings that originate in the
//! Stellar RPC transport layer before those strings cross CLI, MCP, or SEP
//! protocol wire boundaries.

/// Redacts a URL to authority-only form for storage in typed network errors.
///
/// The returned string is `scheme://host[:port]`. Credentials, path, query, and
/// fragment are stripped so URLs such as
/// `https://user:token@rpc.example.com/path?q=1` become
/// `https://rpc.example.com`. Malformed URLs return `"<invalid-url>"`.
///
/// This is the canonical URL-authority redaction function for the workspace.
/// Both `stellar-agent-anchor` and `stellar-agent-network` delegate here so
/// the strip logic is not duplicated.
///
/// For operator-facing URL display where the full URL (minus credentials)
/// must stay readable, use [`redact_url_userinfo`] instead — it strips only
/// the userinfo component and preserves path and query.
#[must_use]
pub fn redact_url_authority(url: &str) -> String {
    url::Url::parse(url)
        .ok()
        .map(|u| {
            let host = u.host_str().unwrap_or("<unknown-host>");
            match u.port() {
                Some(p) => format!("{}://{}:{}", u.scheme(), host, p),
                None => format!("{}://{}", u.scheme(), host),
            }
        })
        .unwrap_or_else(|| "<invalid-url>".to_owned())
}

/// Strips userinfo (credentials) from a URL string before it enters an error
/// message or operator-facing display.
///
/// This is defence-in-depth for code paths where URL validation may be bypassed
/// (e.g. `--friendbot-url-unchecked` on the CLI).  If the URL cannot be parsed,
/// the original string is returned unchanged — this function must never panic.
///
/// Unlike [`redact_url_authority`], the host, port, path, and query are
/// preserved: this variant is for operator-facing display where the URL must
/// stay actionable and only the credentials are sensitive.  For storage in
/// typed network errors, prefer [`redact_url_authority`].
///
/// # Returns
///
/// A `String` with the username and password components removed, or the original
/// string if the URL could not be parsed.
///
/// # Examples
///
/// ```
/// use stellar_agent_network::redact::redact_url_userinfo;
///
/// assert_eq!(
///     redact_url_userinfo("https://user:pass@friendbot.stellar.org/"),
///     "https://friendbot.stellar.org/",
/// );
/// assert_eq!(
///     redact_url_userinfo("https://friendbot.stellar.org"),
///     "https://friendbot.stellar.org/",
/// );
/// // Malformed URLs are returned unchanged (never panics).
/// assert_eq!(redact_url_userinfo("not-a-url"), "not-a-url");
/// ```
#[must_use]
pub fn redact_url_userinfo(url: &str) -> String {
    url::Url::parse(url)
        .ok()
        .map(|mut u| {
            if !u.username().is_empty() || u.password().is_some() {
                // Ignore errors — if set_username/set_password fails (e.g.
                // non-http scheme that doesn't support credentials), fall
                // through to the unchanged serialisation below.
                let _ = u.set_username("");
                let _ = u.set_password(None);
            }
            u.to_string()
        })
        .unwrap_or_else(|| url.to_string())
}

/// Redacts every HTTP(S) URL in an RPC error display string to authority only.
///
/// `NetworkError::RpcTimeout` and `NetworkError::RpcUnreachable` can include
/// the full RPC URL in their [`std::fmt::Display`] output. When the underlying
/// HTTP client also embeds the URL in a transport-error tail, the URL can appear
/// more than once. This helper scans every `http(s)://...` token
/// case-insensitively and preserves only `host[:port]`, stripping scheme,
/// `userinfo@`, path, query, and fragment.
#[must_use]
pub fn redact_rpc_error(err_display: &str) -> String {
    // INVARIANT: TOKEN_TERMINATORS is a strict subset of AUTHORITY_TERMINATORS
    // (the authority set adds the URL structural separators `/ ? #`). Because
    // the token end is found over that subset, `tok_end` always falls at or
    // after `auth_end`, so advancing `rest` to `tok_end` never re-emits the
    // path/query/fragment bytes we just stripped from the authority. Preserve
    // this subset relationship if either array is edited.
    const TOKEN_TERMINATORS: [char; 5] = ['\'', ')', ' ', ',', '"'];
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
                let tok_end = after_scheme
                    .find(TOKEN_TERMINATORS)
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
    fn redact_url_authority_strips_userinfo_path_query_and_fragment() {
        let redacted =
            redact_url_authority("https://user:secrettoken@rpc.example.com:8443/path?q=1#frag");

        assert_eq!(redacted, "https://rpc.example.com:8443");
    }

    #[test]
    fn redact_url_authority_invalid_url_returns_existing_fallback() {
        assert_eq!(redact_url_authority("not a url"), "<invalid-url>");
    }

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
    fn redact_rpc_error_passthrough_without_url() {
        let raw = "decode error: missing contractspecv0 entry";
        assert_eq!(redact_rpc_error(raw), raw);
    }
}
