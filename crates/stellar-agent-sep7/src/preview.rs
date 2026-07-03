//! SEP-7 structured preview assembly.
//!
//! # What this module does
//!
//! Assembles the deterministic JSON preview from a parsed [`Sep7Request`]
//! and a [`SignatureStatus`].  The preview is the operator-facing output that
//! surfaces all relevant fields without triggering any action.
//!
//! # SSRF surface exposure
//!
//! The preview always surfaces the `callback` destination HOST (authority
//! component) explicitly so the operator can make an SSRF decision before
//! choosing to act.  Private-IP callbacks, non-HTTPS callbacks, and unusual
//! schemes are flagged in the preview.
//!
//! # Parse-and-verify-only guarantee
//!
//! The preview output contains no auto-submit, no auto-sign, and no
//! auto-POST fields.  The wallet is parse-and-verify-only; any signing or
//! submission is a separate operator-gated step.
//!
//! Per `sep-0007.md`.

use serde_json::{Value, json};

use crate::parse::{MemoType, Sep7PayParams, Sep7Request, Sep7TxParams};
use crate::verify::SignatureStatus;

// ─────────────────────────────────────────────────────────────────────────────
// Callback SSRF inspection
// ─────────────────────────────────────────────────────────────────────────────

/// Structured callback information for SSRF operator inspection.
///
/// Surfaced in the preview so the operator can evaluate the callback
/// destination before deciding whether to invoke any further action.
#[derive(Debug, Clone)]
pub struct CallbackInfo {
    /// The full callback URL (without the `url:` prefix).
    pub url: String,
    /// The authority component (host\[:port\]) extracted from the URL.
    pub authority: String,
    /// Whether the scheme is HTTPS.
    pub is_https: bool,
    /// Whether the host is a private/loopback IP address.
    pub is_private_or_loopback: bool,
    /// Whether the scheme is a dangerous non-HTTP scheme.
    pub is_dangerous_scheme: bool,
}

/// Inspects a callback `url:...` value and returns structured info.
///
/// Returns `None` if the callback is absent.
pub fn inspect_callback(callback_raw: Option<&str>) -> Option<CallbackInfo> {
    let raw = callback_raw?;

    // Strip the `url:` prefix.
    let url_str = raw.strip_prefix("url:")?;

    let parsed = url::Url::parse(url_str).ok()?;
    let scheme = parsed.scheme().to_ascii_lowercase();
    let authority = parsed.host_str().map_or_else(String::new, |h| {
        if let Some(port) = parsed.port() {
            format!("{h}:{port}")
        } else {
            h.to_owned()
        }
    });

    let is_https = scheme == "https";
    let is_dangerous_scheme = matches!(
        scheme.as_str(),
        "file" | "gopher" | "javascript" | "data" | "ftp"
    );

    // Check for private/loopback IPs.
    let is_private_or_loopback = is_private_or_loopback_host(parsed.host_str().unwrap_or(""));

    Some(CallbackInfo {
        url: url_str.to_owned(),
        authority,
        is_https,
        is_private_or_loopback,
        is_dangerous_scheme,
    })
}

fn is_private_or_loopback_host(host: &str) -> bool {
    // Strip surrounding brackets from IPv6 literal addresses (e.g. "[fd00::1]").
    let host = host
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(host);
    // Check for IPv4 loopback / RFC-1918 private ranges.
    if let Ok(addr) = host.parse::<std::net::IpAddr>() {
        return match addr {
            std::net::IpAddr::V4(v4) => {
                v4.is_loopback()
                    || v4.is_private()
                    || v4.is_link_local()
                    || v4.is_broadcast()
                    || v4.is_unspecified()
                    || v4.is_documentation()
                    || v4.is_multicast()
            }
            std::net::IpAddr::V6(v6) => {
                if v6.is_loopback() || v6.is_unspecified() || v6.is_multicast() {
                    return true;
                }
                // IPv4-mapped IPv6 addresses (::ffff:a.b.c.d) — delegate to the
                // IPv4 check so ::ffff:192.168.1.1 is correctly flagged.
                if let Some(v4) = v6.to_ipv4_mapped() {
                    return is_private_or_loopback_host(&v4.to_string());
                }
                // Unique-local (fc00::/7, i.e. fc00:: through fdff::).
                let octets = v6.octets();
                if (octets[0] & 0xfe) == 0xfc {
                    return true;
                }
                // Link-local (fe80::/10).
                if octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80 {
                    return true;
                }
                false
            }
        };
    }
    // Check well-known loopback hostnames.
    matches!(host, "localhost" | "localhost.localdomain")
}

// ─────────────────────────────────────────────────────────────────────────────
// Preview assembly
// ─────────────────────────────────────────────────────────────────────────────

/// Builds the structured JSON preview for a SEP-7 parse result.
///
/// The preview is deterministic and safe to return to any operator.
/// It never contains signing material, auto-submit commands, or callback
/// POST actions.
///
/// # Panics
///
/// Never panics.
pub fn build_preview(request: &Sep7Request, signature_status: &SignatureStatus) -> Value {
    match request {
        Sep7Request::Tx(tx) => build_tx_preview(tx, signature_status),
        Sep7Request::Pay(pay) => build_pay_preview(pay, signature_status),
    }
}

fn build_tx_preview(tx: &Sep7TxParams, sig_status: &SignatureStatus) -> Value {
    let callback_info = inspect_callback(tx.callback_raw.as_deref());
    let callback_json = build_callback_json(callback_info.as_ref());
    let origin_verified = sig_status == &SignatureStatus::Verified;

    json!({
        "operation": "tx",
        "xdr": tx.xdr_canonical,
        "replace": tx.replace,
        "pubkey": tx.pubkey,
        "msg": tx.msg,
        "network_passphrase": tx.network_passphrase,
        "callback": callback_json,
        "chain_present": tx.chain.is_some(),
        "origin_domain": tx.origin_domain,
        "origin_verified": origin_verified,
        "signature_status": sig_status.as_str(),
        // Wallet action safety: these are always false — parse-and-verify only.
        "will_auto_submit": false,
        "will_auto_post_callback": false,
    })
}

fn build_pay_preview(pay: &Sep7PayParams, sig_status: &SignatureStatus) -> Value {
    let callback_info = inspect_callback(pay.callback_raw.as_deref());
    let callback_json = build_callback_json(callback_info.as_ref());
    let origin_verified = sig_status == &SignatureStatus::Verified;

    let memo_type_str = pay.memo_type.as_ref().map(|mt| match mt {
        MemoType::MemoText => "MEMO_TEXT",
        MemoType::MemoId => "MEMO_ID",
        MemoType::MemoHash => "MEMO_HASH",
        MemoType::MemoReturn => "MEMO_RETURN",
    });

    json!({
        "operation": "pay",
        "destination": pay.destination,
        "amount": pay.amount,
        "asset_code": pay.asset_code,
        "asset_issuer": pay.asset_issuer,
        "memo": pay.memo,
        "memo_type": memo_type_str,
        "msg": pay.msg,
        "network_passphrase": pay.network_passphrase,
        "callback": callback_json,
        "origin_domain": pay.origin_domain,
        "origin_verified": origin_verified,
        "signature_status": sig_status.as_str(),
        // Wallet action safety: these are always false — parse-and-verify only.
        "will_auto_submit": false,
        "will_auto_post_callback": false,
    })
}

fn build_callback_json(info: Option<&CallbackInfo>) -> Value {
    match info {
        None => Value::Null,
        Some(cb) => {
            json!({
                "authority": cb.authority,
                "is_https": cb.is_https,
                "is_private_or_loopback": cb.is_private_or_loopback,
                "is_dangerous_scheme": cb.is_dangerous_scheme,
                // NOTE: the wallet NEVER POSTs to this callback.
                // This field is exposed for SSRF operator inspection only.
                "will_auto_post": false,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use super::*;

    #[test]
    fn private_ip_192_168_flagged() {
        assert!(is_private_or_loopback_host("192.168.1.1"));
    }

    #[test]
    fn loopback_127_flagged() {
        assert!(is_private_or_loopback_host("127.0.0.1"));
    }

    #[test]
    fn localhost_flagged() {
        assert!(is_private_or_loopback_host("localhost"));
    }

    #[test]
    fn public_ip_not_flagged() {
        assert!(!is_private_or_loopback_host("8.8.8.8"));
    }

    #[test]
    fn public_domain_not_flagged() {
        assert!(!is_private_or_loopback_host("example.com"));
    }

    #[test]
    fn dangerous_scheme_flagged() {
        let info = inspect_callback(Some("url:file:///etc/passwd")).unwrap();
        assert!(info.is_dangerous_scheme);
    }

    #[test]
    fn non_https_callback_flagged() {
        let info = inspect_callback(Some("url:http://example.com/cb")).unwrap();
        assert!(!info.is_https);
    }

    #[test]
    fn https_callback_passes() {
        let info = inspect_callback(Some("url:https://example.com/cb")).unwrap();
        assert!(info.is_https);
        assert!(!info.is_private_or_loopback);
    }

    #[test]
    fn no_callback_returns_null() {
        let val = build_callback_json(None);
        assert_eq!(val, Value::Null);
    }

    #[test]
    fn preview_will_auto_post_callback_is_always_false() {
        let pay = Sep7PayParams {
            destination: "GCALNQQBXAPZ2WIRSDDBMSTAKCUH5SG6U76YBFLQLIXJTF7FE5AX7AOO".to_owned(),
            amount: None,
            asset_code: None,
            asset_issuer: None,
            memo: None,
            memo_type: None,
            callback_raw: Some("url:https://example.com/cb".to_owned()),
            msg: None,
            network_passphrase: None,
            origin_domain: None,
            signature_raw: None,
        };
        let preview = build_pay_preview(&pay, &SignatureStatus::Absent);
        assert_eq!(preview["will_auto_post_callback"], false);
        assert_eq!(preview["will_auto_submit"], false);
        // Callback block also has will_auto_post = false.
        assert_eq!(preview["callback"]["will_auto_post"], false);
    }

    // ── build_tx_preview coverage ─────────────────────────────────────────────

    fn minimal_tx_params() -> Sep7TxParams {
        Sep7TxParams {
            // A valid canonical XDR string is not required here — preview does not
            // re-validate; we use a placeholder that represents the field.
            xdr_canonical: "AAAA".to_owned(),
            replace: None,
            callback_raw: None,
            pubkey: None,
            chain: None,
            msg: None,
            network_passphrase: None,
            origin_domain: None,
            signature_raw: None,
        }
    }

    #[test]
    fn build_tx_preview_absent_status() {
        // Exercises build_tx_preview with no callback and no origin_domain.
        let tx = minimal_tx_params();
        let preview = build_tx_preview(&tx, &SignatureStatus::Absent);
        assert_eq!(preview["operation"], "tx");
        assert_eq!(preview["signature_status"], "absent");
        assert_eq!(preview["origin_verified"], false);
        assert_eq!(preview["callback"], Value::Null);
        assert_eq!(preview["chain_present"], false);
        assert_eq!(preview["will_auto_submit"], false);
        assert_eq!(preview["will_auto_post_callback"], false);
    }

    #[test]
    fn build_tx_preview_verified_status_sets_origin_verified() {
        // origin_verified = true only when status is Verified.
        let mut tx = minimal_tx_params();
        tx.origin_domain = Some("example.com".to_owned());
        let preview = build_tx_preview(&tx, &SignatureStatus::Verified);
        assert_eq!(preview["origin_verified"], true);
        assert_eq!(preview["signature_status"], "verified");
    }

    #[test]
    fn build_tx_preview_with_callback_shows_authority() {
        let mut tx = minimal_tx_params();
        tx.callback_raw = Some("url:https://signing.example.com/sign".to_owned());
        tx.chain = Some("web+stellar:pay?destination=G...".to_owned());
        let preview = build_tx_preview(&tx, &SignatureStatus::NotChecked);
        assert_eq!(preview["callback"]["authority"], "signing.example.com");
        assert_eq!(preview["callback"]["is_https"], true);
        assert_eq!(preview["chain_present"], true);
        assert_eq!(preview["signature_status"], "not_checked");
    }

    // ── build_pay_preview memo types ──────────────────────────────────────────

    fn base_pay_params() -> Sep7PayParams {
        Sep7PayParams {
            destination: "GCALNQQBXAPZ2WIRSDDBMSTAKCUH5SG6U76YBFLQLIXJTF7FE5AX7AOO".to_owned(),
            amount: None,
            asset_code: None,
            asset_issuer: None,
            memo: None,
            memo_type: None,
            callback_raw: None,
            msg: None,
            network_passphrase: None,
            origin_domain: None,
            signature_raw: None,
        }
    }

    #[test]
    fn build_pay_preview_memo_text() {
        let mut pay = base_pay_params();
        pay.memo = Some("hello".to_owned());
        pay.memo_type = Some(MemoType::MemoText);
        let preview = build_pay_preview(&pay, &SignatureStatus::Absent);
        assert_eq!(preview["memo_type"], "MEMO_TEXT");
        assert_eq!(preview["memo"], "hello");
    }

    #[test]
    fn build_pay_preview_memo_id() {
        let mut pay = base_pay_params();
        pay.memo = Some("12345".to_owned());
        pay.memo_type = Some(MemoType::MemoId);
        let preview = build_pay_preview(&pay, &SignatureStatus::Absent);
        assert_eq!(preview["memo_type"], "MEMO_ID");
    }

    #[test]
    fn build_pay_preview_memo_hash() {
        let mut pay = base_pay_params();
        pay.memo = Some("aGVsbG8=".to_owned());
        pay.memo_type = Some(MemoType::MemoHash);
        let preview = build_pay_preview(&pay, &SignatureStatus::Absent);
        assert_eq!(preview["memo_type"], "MEMO_HASH");
    }

    #[test]
    fn build_pay_preview_memo_return() {
        let mut pay = base_pay_params();
        pay.memo = Some("aGVsbG8=".to_owned());
        pay.memo_type = Some(MemoType::MemoReturn);
        let preview = build_pay_preview(&pay, &SignatureStatus::Absent);
        assert_eq!(preview["memo_type"], "MEMO_RETURN");
    }

    #[test]
    fn build_pay_preview_no_memo_type_is_null() {
        let pay = base_pay_params();
        let preview = build_pay_preview(&pay, &SignatureStatus::Absent);
        assert_eq!(preview["memo_type"], Value::Null);
    }

    #[test]
    fn build_pay_preview_with_callback_and_origin() {
        let mut pay = base_pay_params();
        pay.callback_raw = Some("url:https://cb.example.com/pay".to_owned());
        pay.origin_domain = Some("example.com".to_owned());
        let preview = build_pay_preview(&pay, &SignatureStatus::Failed);
        assert_eq!(preview["callback"]["authority"], "cb.example.com");
        assert_eq!(preview["origin_domain"], "example.com");
        assert_eq!(preview["origin_verified"], false);
        assert_eq!(preview["signature_status"], "failed");
    }

    #[test]
    fn build_preview_dispatches_to_tx_and_pay() {
        // Exercises the build_preview match dispatch (line 147) for both arms.
        let tx = Sep7Request::Tx(minimal_tx_params());
        let tx_preview = build_preview(&tx, &SignatureStatus::Absent);
        assert_eq!(tx_preview["operation"], "tx");

        let pay = Sep7Request::Pay(base_pay_params());
        let pay_preview = build_preview(&pay, &SignatureStatus::Absent);
        assert_eq!(pay_preview["operation"], "pay");
    }

    // ── IPv6 mapped / loopback edge cases ────────────────────────────────────

    #[test]
    fn ipv6_loopback_flagged() {
        // ::1 is the IPv6 loopback address.
        assert!(is_private_or_loopback_host("::1"));
    }

    #[test]
    fn ipv6_unspecified_flagged() {
        assert!(is_private_or_loopback_host("::"));
    }

    #[test]
    fn ipv6_multicast_flagged() {
        // ff02::1 is a well-known multicast address.
        assert!(is_private_or_loopback_host("ff02::1"));
    }

    #[test]
    fn ipv6_mapped_private_ipv4_flagged() {
        // ::ffff:192.168.1.1 maps to the private IPv4 range.
        assert!(is_private_or_loopback_host("::ffff:192.168.1.1"));
    }

    #[test]
    fn ipv4_broadcast_flagged() {
        assert!(is_private_or_loopback_host("255.255.255.255"));
    }

    #[test]
    fn ipv4_documentation_range_flagged() {
        // 192.0.2.0/24 is reserved for documentation (RFC 5737).
        assert!(is_private_or_loopback_host("192.0.2.1"));
    }

    #[test]
    fn ipv4_multicast_flagged() {
        // 224.0.0.1 is a multicast address.
        assert!(is_private_or_loopback_host("224.0.0.1"));
    }

    #[test]
    fn ipv4_link_local_flagged() {
        // 169.254.x.x is link-local.
        assert!(is_private_or_loopback_host("169.254.1.1"));
    }

    #[test]
    fn ipv4_unspecified_flagged() {
        assert!(is_private_or_loopback_host("0.0.0.0"));
    }

    #[test]
    fn localhost_localdomain_flagged() {
        assert!(is_private_or_loopback_host("localhost.localdomain"));
    }

    #[test]
    fn callback_without_url_prefix_returns_none() {
        // inspect_callback returns None when the `url:` prefix is absent.
        let result = inspect_callback(Some("https://example.com/cb"));
        assert!(result.is_none());
    }

    #[test]
    fn callback_with_port_shows_port_in_authority() {
        let info = inspect_callback(Some("url:https://example.com:8443/cb")).unwrap();
        assert_eq!(info.authority, "example.com:8443");
    }

    #[test]
    fn ipv6_global_unicast_not_flagged() {
        // 2001:db8::1 is a global unicast (documentation range) IPv6 address —
        // not loopback, not unspecified, not multicast, not IPv4-mapped, not unique-local,
        // not link-local. Exercises the `false` return at line 124.
        assert!(!is_private_or_loopback_host("2001:db8::1"));
    }
}
