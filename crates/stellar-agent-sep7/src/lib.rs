//! SEP-7 `web+stellar:` inbound URI parsing and anti-phishing signature verification.
//!
//! # What this crate does
//!
//! Receives `web+stellar:tx/pay?<params>` URIs from untrusted dApps, parses
//! them into a structured preview, and optionally verifies the dApp signature.
//!
//! # Primary consumers
//!
//! - `stellar-agent-mcp` — exposes the `stellar_sep7_parse_uri` MCP tool.
//!
//! # What this crate does NOT do
//!
//! - NEVER signs a URI.
//! - NEVER auto-POSTs to a `callback` endpoint.
//! - NEVER submits a transaction automatically.
//! - NEVER uses a cached `stellar.toml` for signature verification (freshness
//!   per `sep-0007.md`).
//!
//! # Module layout
//!
//! | Module | Responsibility |
//! |--------|----------------|
//! | [`error`] | [`Sep7Error`] typed error enum |
//! | [`parse`] | URI → [`Sep7Request`] strict validation |
//! | [`verify`] | Origin-domain signature verification (fresh stellar.toml fetch) |
//! | [`preview`] | Structured JSON preview assembly |
//!
//! # Replay posture
//!
//! SEP-7 signatures have no nonce or timestamp; they protect integrity and
//! authenticate the origin but do NOT prevent replay.  The parse tool is
//! stateless and cannot deduplicate identical URIs.  The operator or MCP host
//! layer must enforce idempotency if replay protection is needed.  See the
//! adversarial corpus in `tests/sep7_adversarial.rs` for the replay test.
//!
pub mod error;
pub mod parse;
pub mod preview;
pub mod verify;

pub use error::Sep7Error;
pub use parse::{Sep7Request, parse_sep7_uri};
pub use verify::{SignatureStatus, build_signature_payload, verify_origin_signature};

// Re-export the post-fetch verify seam under test-helpers so integration
// tests can inject a stellar.toml body without re-implementing the
// signature-decode order or key-extraction logic.
#[cfg(any(test, feature = "test-helpers"))]
pub use verify::verify_against_toml_body;

// ─────────────────────────────────────────────────────────────────────────────
// Top-level parse API
// ─────────────────────────────────────────────────────────────────────────────

/// Parses a `web+stellar:` URI into a structured preview without performing
/// origin_domain signature verification.
///
/// Use [`parse_and_verify_uri`] to include signature verification.
///
/// Returns the parsed [`Sep7Request`] and the [`SignatureStatus`] determined
/// purely from parameter presence/absence (no network I/O).
///
/// # Errors
///
/// Returns [`Sep7Error`] on any parse or validation failure.
///
/// # Panics
///
/// Never panics.
///
/// # Examples
///
/// ```rust
/// use stellar_agent_sep7::parse_uri;
///
/// let result = parse_uri(
///     "web+stellar:pay?destination=GCALNQQBXAPZ2WIRSDDBMSTAKCUH5SG6U76YBFLQLIXJTF7FE5AX7AOO"
/// );
/// assert!(result.is_ok());
/// ```
pub fn parse_uri(uri: &str) -> Result<(Sep7Request, SignatureStatus), Sep7Error> {
    let request = parse_sep7_uri(uri)?;

    // Determine status purely from parameter presence/absence.
    let status = match &request {
        Sep7Request::Tx(tx) => {
            determine_static_status(tx.origin_domain.as_deref(), tx.signature_raw.as_deref())
        }
        Sep7Request::Pay(pay) => {
            determine_static_status(pay.origin_domain.as_deref(), pay.signature_raw.as_deref())
        }
    };

    Ok((request, status))
}

/// Parses a `web+stellar:` URI and performs live signature verification when
/// `origin_domain` and `signature` are both present.
///
/// Unlike [`parse_uri`], this function may perform a fresh HTTPS fetch of
/// `stellar.toml` for `origin_domain`.  Per `sep-0007.md`, wallets SHOULD NOT
/// cache `stellar.toml` for this verification.
///
/// # Errors
///
/// Returns [`Sep7Error`] on parse failures, fetch failures, or
/// signing-key-not-in-toml.  A failed ed25519 verification is NOT an error —
/// it returns `Ok(..SignatureStatus::Failed..)`.
///
/// # Panics
///
/// Never panics.
pub async fn parse_and_verify_uri(uri: &str) -> Result<(Sep7Request, SignatureStatus), Sep7Error> {
    let request = parse_sep7_uri(uri)?;

    let (origin_domain, signature_raw) = match &request {
        Sep7Request::Tx(tx) => (tx.origin_domain.as_deref(), tx.signature_raw.as_deref()),
        Sep7Request::Pay(pay) => (pay.origin_domain.as_deref(), pay.signature_raw.as_deref()),
    };

    let status = verify_origin_signature(uri, origin_domain, signature_raw).await?;

    Ok((request, status))
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

fn determine_static_status(
    origin_domain: Option<&str>,
    signature_raw: Option<&str>,
) -> SignatureStatus {
    match (origin_domain, signature_raw) {
        (None, _) => SignatureStatus::Absent,
        (Some(_), None) => SignatureStatus::MissingRequired,
        // Both origin_domain and signature are present, but the caller chose
        // parse_only (verify_origin=false).  Return NotChecked so the preview
        // clearly signals "signature present but not verified" — not the same
        // as Absent (no signature supplied at all).
        (Some(_), Some(_)) => SignatureStatus::NotChecked,
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

    // Builds a minimal but valid TransactionEnvelope base64 string for tx-URI tests.
    fn minimal_tx_xdr_urlenc() -> String {
        use stellar_xdr::{
            Limits, Memo, MuxedAccount, Preconditions, SequenceNumber, Transaction,
            TransactionEnvelope, TransactionExt, TransactionV1Envelope, Uint256, WriteXdr,
        };
        let tx = Transaction {
            source_account: MuxedAccount::Ed25519(Uint256([0u8; 32])),
            fee: 100,
            seq_num: SequenceNumber(1),
            cond: Preconditions::None,
            memo: Memo::None,
            operations: vec![].try_into().unwrap(),
            ext: TransactionExt::V0,
        };
        let env = TransactionEnvelope::Tx(TransactionV1Envelope {
            tx,
            signatures: vec![].try_into().unwrap(),
        });
        let b64 = env.to_xdr_base64(Limits::none()).unwrap();
        b64.replace('+', "%2B")
            .replace('/', "%2F")
            .replace('=', "%3D")
    }

    #[test]
    fn parse_uri_returns_absent_when_no_origin() {
        let uri = "web+stellar:pay?\
            destination=GCALNQQBXAPZ2WIRSDDBMSTAKCUH5SG6U76YBFLQLIXJTF7FE5AX7AOO";
        let (_, status) = parse_uri(uri).unwrap();
        assert_eq!(status, SignatureStatus::Absent);
    }

    #[test]
    fn parse_uri_returns_missing_required_when_origin_without_signature() {
        let uri = "web+stellar:pay?\
            destination=GCALNQQBXAPZ2WIRSDDBMSTAKCUH5SG6U76YBFLQLIXJTF7FE5AX7AOO\
            &origin_domain=example.com";
        let (_, status) = parse_uri(uri).unwrap();
        assert_eq!(status, SignatureStatus::MissingRequired);
    }

    #[test]
    fn parse_uri_returns_not_checked_when_origin_and_signature_both_present() {
        // When both origin_domain and signature are present but verify_origin=false
        // (i.e. parse_uri, not parse_and_verify_uri), the status is NotChecked —
        // distinct from Absent to signal "signature present but not verified".
        let uri = "web+stellar:pay?\
            destination=GCALNQQBXAPZ2WIRSDDBMSTAKCUH5SG6U76YBFLQLIXJTF7FE5AX7AOO\
            &origin_domain=example.com\
            &signature=dummysig";
        let (_, status) = parse_uri(uri).unwrap();
        assert_eq!(
            status,
            SignatureStatus::NotChecked,
            "parse_uri with both origin_domain and signature must yield NotChecked"
        );
    }

    #[test]
    fn parse_uri_tx_arm_yields_sep7request_tx() {
        // Exercises the Sep7Request::Tx arm of parse_uri (lib.rs lines 87-88).
        let xdr = minimal_tx_xdr_urlenc();
        let uri = format!("web+stellar:tx?xdr={xdr}");
        let (req, status) = parse_uri(&uri).unwrap();
        assert!(
            matches!(req, Sep7Request::Tx(_)),
            "tx URI must yield Sep7Request::Tx"
        );
        assert_eq!(
            status,
            SignatureStatus::Absent,
            "tx URI without origin_domain must yield Absent"
        );
    }

    #[test]
    fn parse_uri_tx_with_origin_and_sig_yields_not_checked() {
        // Exercises the Tx arm with both origin_domain and signature — NotChecked.
        let xdr = minimal_tx_xdr_urlenc();
        let uri = format!("web+stellar:tx?xdr={xdr}&origin_domain=example.com&signature=dummysig");
        let (req, status) = parse_uri(&uri).unwrap();
        assert!(matches!(req, Sep7Request::Tx(_)));
        assert_eq!(status, SignatureStatus::NotChecked);
    }

    #[tokio::test]
    async fn parse_and_verify_uri_pay_no_origin_returns_absent() {
        // parse_and_verify_uri with no origin_domain calls verify_origin_signature
        // which returns Absent immediately — no network I/O.
        // This exercises the entire parse_and_verify_uri body (lines 114-125).
        let uri = "web+stellar:pay?\
            destination=GCALNQQBXAPZ2WIRSDDBMSTAKCUH5SG6U76YBFLQLIXJTF7FE5AX7AOO";
        let (req, status) = parse_and_verify_uri(uri).await.unwrap();
        assert!(matches!(req, Sep7Request::Pay(_)));
        assert_eq!(
            status,
            SignatureStatus::Absent,
            "pay URI without origin_domain must return Absent (no network)"
        );
    }

    #[tokio::test]
    async fn parse_and_verify_uri_tx_no_origin_returns_absent() {
        // Exercises the Sep7Request::Tx arm inside parse_and_verify_uri (line 118).
        let xdr = minimal_tx_xdr_urlenc();
        let uri = format!("web+stellar:tx?xdr={xdr}");
        let (req, status) = parse_and_verify_uri(&uri).await.unwrap();
        assert!(matches!(req, Sep7Request::Tx(_)));
        assert_eq!(status, SignatureStatus::Absent);
    }

    #[tokio::test]
    async fn parse_and_verify_uri_with_origin_no_sig_returns_missing_required() {
        // origin_domain present, signature absent → MissingRequired from
        // verify_origin_signature early-return, no network fetch performed.
        let uri = "web+stellar:pay?\
            destination=GCALNQQBXAPZ2WIRSDDBMSTAKCUH5SG6U76YBFLQLIXJTF7FE5AX7AOO\
            &origin_domain=example.com";
        let (_, status) = parse_and_verify_uri(uri).await.unwrap();
        assert_eq!(status, SignatureStatus::MissingRequired);
    }
}
