//! URL redaction helpers for errors and operator-facing displays.

/// Redacts a URL to authority-only form for storage in typed network errors.
///
/// The returned string is `scheme://host[:port]`. Credentials, path, query, and
/// fragment are stripped so URLs such as
/// `https://user:token@rpc.example.com/path?q=1` become
/// `https://rpc.example.com`. Malformed URLs return `"<invalid-url>"`.
///
/// For operator-facing URL display where the full URL (minus credentials)
/// must stay readable, use [`redact_url_userinfo`] instead. It strips only
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
/// This is defense-in-depth for code paths where URL validation may be bypassed
/// (for example `--friendbot-url-unchecked` on the CLI).  If the URL cannot be parsed,
/// the original string is returned unchanged. This function never panics.
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
/// use stellar_agent_core::redact::redact_url_userinfo;
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
                // Schemes without credential support retain their serialization
                // when the userinfo setters return an error.
                let _ = u.set_username("");
                let _ = u.set_password(None);
            }
            u.to_string()
        })
        .unwrap_or_else(|| url.to_string())
}

#[cfg(test)]
mod tests {
    use super::{redact_url_authority, redact_url_userinfo};

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
    fn redact_url_userinfo_strips_user_password() {
        let result = redact_url_userinfo("https://user:pass@friendbot.stellar.org/");
        assert_eq!(
            result, "https://friendbot.stellar.org/",
            "userinfo must be stripped"
        );
    }

    #[test]
    fn redact_url_userinfo_passes_clean_url_unchanged() {
        // Note: the url crate normalizes https://... to include a trailing slash.
        let result = redact_url_userinfo("https://friendbot.stellar.org");
        assert_eq!(
            result, "https://friendbot.stellar.org/",
            "clean URL without userinfo must pass through (normalised)"
        );
    }

    #[test]
    fn redact_url_userinfo_passes_malformed_url_unchanged_string() {
        // Defensive: malformed input must never panic; returns original string.
        let input = "not-a-url";
        let result = redact_url_userinfo(input);
        assert_eq!(result, input, "malformed URL must be returned unchanged");
    }
}
