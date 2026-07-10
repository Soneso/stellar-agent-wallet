pub mod policy_mock;
pub mod v1_engine_mock;

use rmcp::model::CallToolResult;

/// Asserts the shared business-error envelope invariants on a tool result and
/// returns `(code, message, full_text)` for further per-test assertions.
///
/// The normalised business-error wire contract is:
///
/// ```json
/// { "ok": false, "error": { "code": "...", "message": "..." }, "request_id": "..." }
/// ```
///
/// This checks `is_error == Some(true)`, `ok == false`, and a non-empty
/// `request_id`, then extracts `error.code` and `error.message`.
///
/// `request_id` is freshly minted per call and therefore intentionally excluded
/// from the returned tuple: indistinguishability comparisons across two refusals
/// must compare `(code, message)`, never the full JSON.
#[must_use]
#[allow(
    dead_code,
    reason = "shared across integration-test binaries; unused in some"
)]
pub fn assert_business_envelope(result: &CallToolResult) -> (String, String, String) {
    assert_eq!(
        result.is_error,
        Some(true),
        "business-error result must set is_error = true"
    );
    let text = result
        .content
        .first()
        .and_then(|c| c.as_text())
        .map(|t| t.text.clone())
        .expect("business-error result must carry a text content block");
    let value: serde_json::Value =
        serde_json::from_str(&text).expect("business-error content must be JSON");
    assert_eq!(
        value["ok"],
        serde_json::json!(false),
        "business-error envelope must have ok:false: {value}"
    );
    assert!(
        value["request_id"].as_str().is_some_and(|s| !s.is_empty()),
        "business-error envelope must carry a non-empty request_id: {value}"
    );
    let code = value["error"]["code"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    let message = value["error"]["message"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    (code, message, text)
}
