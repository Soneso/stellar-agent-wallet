//! Closed-set typed error variants for toolset capability enforcement.
//!
//! Each variant corresponds to exactly one failure mode in the four-part
//! enforcement check. No variant leaks filesystem paths, private keys, or
//! internal implementation details.

use thiserror::Error;

/// Typed refusal errors for toolset capability enforcement.
///
/// Closed set: one variant per failure mode in the four-part check.
/// All author-controlled string fields are pre-sanitised by callers via
/// [`stellar_agent_toolsets::sanitise_display`] before being stored here.
///
/// # Variants
///
/// | Variant | Four-part step | Description |
/// |---------|---------------|-------------|
/// | [`ToolsetRuntimeError::UnknownToolsetAction`] | (a) | Action not in matrix. |
/// | [`ToolsetRuntimeError::CapabilityNotDeclared`] | (c) | Granting capability not in toolset's `CapabilitySet`. |
/// | [`ToolsetRuntimeError::ToolNotAllowed`] | (d) | Tool excluded by toolset's `allowed_tools` narrowing. |
/// | [`ToolsetRuntimeError::ToolsetNotInstalled`] | pre-check | Toolset name has no pin record. |
/// | [`ToolsetRuntimeError::Io`] | pre-check | I/O error reading the pin. |
/// | [`ToolsetRuntimeError::ContentDigestMismatch`] | pre-check | On-disk `TOOLSET.md` hash differs from install-time digest. |
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ToolsetRuntimeError {
    /// Part (a): the action name is not in the capability→tool matrix.
    ///
    /// The action is either a signing/key/policy tool (explicitly excluded),
    /// a dispatcher tool (`stellar_toolset_list` / `stellar_toolset_invoke`), or
    /// simply not a recognised wallet tool name.
    ///
    /// ## Security note
    ///
    /// This variant fires before any capability check — a toolset cannot probe
    /// whether a signing tool "would be allowed" by its capabilities.
    #[error("toolset.unknown_action: action '{action}' is not in the capability→tool matrix")]
    UnknownToolsetAction {
        /// Sanitised action name from the invocation request.
        action: String,
    },

    /// Part (c): the action's granting capability is not in the toolset's
    /// declared [`stellar_agent_toolsets::CapabilitySet`].
    ///
    /// The toolset would need to declare the named capability to invoke this action.
    #[error(
        "toolset.capability_not_declared: action '{action}' requires capability \
         '{capability}' which this toolset did not declare"
    )]
    CapabilityNotDeclared {
        /// Sanitised action name.
        action: String,
        /// Display token of the required capability (e.g. `"read-balance"`).
        capability: String,
    },

    /// Part (d): the resolved tool is not in the toolset's `allowed_tools` list.
    ///
    /// The toolset's `allowed_tools` narrows the capability grant — it can only
    /// subtract, never add. The tool is grantable by the toolset's declared
    /// capabilities but has been excluded by the intersective narrowing.
    #[error(
        "toolset.tool_not_allowed: tool '{tool}' is not in this toolset's allowed_tools list \
         (action '{action}')"
    )]
    ToolNotAllowed {
        /// Sanitised registry tool name.
        tool: String,
        /// Sanitised action name.
        action: String,
    },

    /// Pre-check: the toolset name has no pin record in the toolsets directory.
    ///
    /// The toolset is not installed, or has been uninstalled since the invocation
    /// was queued.
    #[error("toolset.not_installed: toolset '{name}' is not installed")]
    ToolsetNotInstalled {
        /// Sanitised toolset package name.
        name: String,
    },

    /// Pre-check: an I/O error occurred while reading the pin record.
    #[error("toolset.io_error: {0}")]
    Io(String),

    /// Pre-check: the on-disk `TOOLSET.md` SHA-256 digest does not match the
    /// digest recorded in the pin at install time.
    ///
    /// Fires when the pin's `toolset_md_shasum` field is `Some` and the current
    /// file's hash differs. This indicates post-install modification of the
    /// manifest file.
    ///
    /// ## Recovery
    ///
    /// Reinstall the toolset from the signed package:
    /// ```text
    /// stellar-agent toolset install <package> --force
    /// ```
    ///
    /// ## Security note
    ///
    /// The capability-source invariant (capabilities are read from the pin,
    /// never re-parsed from the on-disk `TOOLSET.md`) ensures that a tampered
    /// manifest CANNOT escalate capabilities even before this check fires.
    /// This check adds tamper-evidence for the manifest text and refuses
    /// dispatch to surface the incident rather than silently continuing with
    /// stale metadata.
    #[error(
        "toolset.content_digest_mismatch: TOOLSET.md for '{name}' has been modified since install \
         (dispatch-time content digest check failed; reinstall the toolset to resolve)"
    )]
    ContentDigestMismatch {
        /// Sanitised toolset package name.
        name: String,
    },

    /// Gated path: the first-invoke gate requires out-of-band approval.
    ///
    /// The gated resolver (`resolve_toolset_sign_payment_gated`) returns
    /// `Ok(GatedResolveOutcome::FirstInvokeApprovalRequired { .. })` — NOT this
    /// error variant — when the gate fires. This variant is produced by the
    /// MCP/CLI consumer layer when it surfaces that gate outcome to the client as
    /// a typed error response. It carries the same `approval_nonce`, `toolset_name`,
    /// and `capability` from the `GatedResolveOutcome`.
    ///
    /// # Recovery
    ///
    /// 1. The operator reviews the wallet-rendered summary.
    /// 2. `stellar-agent approve --id <approval_nonce>` is run.
    /// 3. The toolset re-invokes the same `sign-payment` action.
    #[error(
        "toolset.first_invoke_approval_required: first-invoke gate requires operator approval \
         (approval_nonce={approval_nonce}; run `stellar-agent approve --id {approval_nonce}` \
         then re-invoke)"
    )]
    FirstInvokeApprovalRequired {
        /// Nonce of the queued `ToolsetFirstInvokeGate` pending approval.
        ///
        /// The MCP response MUST surface this nonce so the agent can pass it
        /// to `stellar-agent approve --id <nonce>`.
        approval_nonce: String,

        /// Sanitised toolset name (for the human-readable message).
        toolset_name: String,

        /// Capability token (e.g. `"sign-payment"`).
        capability: String,
    },

    /// Gated path: an I/O error occurred accessing the toolset grant store.
    #[error("toolset.grant_store_error: {detail}")]
    GrantStoreError {
        /// Non-secret diagnostic detail.
        detail: String,
    },

    /// Gated path: the authoritative payment amount is not positive.
    ///
    /// `authoritative_amount_stroops` must be greater than zero. A zero or
    /// negative value from the decoded envelope is rejected here before any
    /// grant-store lookup or approval queuing occurs.
    #[error(
        "toolset.invalid_authoritative_amount: authoritative_amount_stroops must be > 0 \
         (got {amount_stroops})"
    )]
    InvalidAuthoritativeAmount {
        /// The non-positive value that was rejected.
        amount_stroops: i64,
    },
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test-only; panics acceptable in unit tests"
)]
mod tests {
    use super::*;

    // All variants must produce distinct Display output so wire-code matching is
    // unambiguous. When adding a new variant, add it to this list.

    #[test]
    fn all_variants_have_distinct_display() {
        let variants = [
            ToolsetRuntimeError::UnknownToolsetAction {
                action: "test-action".to_owned(),
            },
            ToolsetRuntimeError::CapabilityNotDeclared {
                action: "test-action".to_owned(),
                capability: "read-balance".to_owned(),
            },
            ToolsetRuntimeError::ToolNotAllowed {
                tool: "stellar_balances".to_owned(),
                action: "test-action".to_owned(),
            },
            ToolsetRuntimeError::ToolsetNotInstalled {
                name: "test-toolset".to_owned(),
            },
            ToolsetRuntimeError::Io("disk error".to_owned()),
            ToolsetRuntimeError::ContentDigestMismatch {
                name: "test-toolset".to_owned(),
            },
            ToolsetRuntimeError::FirstInvokeApprovalRequired {
                approval_nonce: "AbCdEfGhIjKlMnOpQrStUv".to_owned(),
                toolset_name: "test-toolset".to_owned(),
                capability: "sign-payment".to_owned(),
            },
            ToolsetRuntimeError::GrantStoreError {
                detail: "test error".to_owned(),
            },
            ToolsetRuntimeError::InvalidAuthoritativeAmount { amount_stroops: 0 },
        ];

        // Collect display strings and verify they are all distinct.
        let displays: Vec<String> = variants.iter().map(|v| v.to_string()).collect();
        let unique: std::collections::HashSet<&str> = displays.iter().map(String::as_str).collect();
        assert_eq!(
            unique.len(),
            variants.len(),
            "variant Display strings must all be distinct (closed-set parity): {displays:?}"
        );
    }

    // Error codes appear in Display output for wire-code matching.

    #[test]
    fn error_code_prefixes_present() {
        let e = ToolsetRuntimeError::UnknownToolsetAction {
            action: "x".to_owned(),
        };
        assert!(e.to_string().contains("toolset.unknown_action"));

        let e = ToolsetRuntimeError::CapabilityNotDeclared {
            action: "x".to_owned(),
            capability: "y".to_owned(),
        };
        assert!(e.to_string().contains("toolset.capability_not_declared"));

        let e = ToolsetRuntimeError::ToolNotAllowed {
            tool: "t".to_owned(),
            action: "x".to_owned(),
        };
        assert!(e.to_string().contains("toolset.tool_not_allowed"));

        let e = ToolsetRuntimeError::ToolsetNotInstalled {
            name: "s".to_owned(),
        };
        assert!(e.to_string().contains("toolset.not_installed"));

        let e = ToolsetRuntimeError::Io("err".to_owned());
        assert!(e.to_string().contains("toolset.io_error"));

        let e = ToolsetRuntimeError::ContentDigestMismatch {
            name: "my-distinct-toolset".to_owned(),
        };
        assert!(e.to_string().contains("toolset.content_digest_mismatch"));
        assert!(
            e.to_string().contains("my-distinct-toolset"),
            "toolset name must appear in message"
        );

        let e = ToolsetRuntimeError::FirstInvokeApprovalRequired {
            approval_nonce: "AbCdEfGhIjKlMnOpQrStUv".to_owned(),
            toolset_name: "s".to_owned(),
            capability: "sign-payment".to_owned(),
        };
        assert!(
            e.to_string()
                .contains("toolset.first_invoke_approval_required")
        );
        assert!(
            e.to_string().contains("AbCdEfGhIjKlMnOpQrStUv"),
            "approval_nonce must appear in the error message for agent recovery"
        );

        let e = ToolsetRuntimeError::GrantStoreError {
            detail: "test error".to_owned(),
        };
        assert!(e.to_string().contains("toolset.grant_store_error"));

        let e = ToolsetRuntimeError::InvalidAuthoritativeAmount { amount_stroops: -1 };
        assert!(
            e.to_string()
                .contains("toolset.invalid_authoritative_amount")
        );
        assert!(
            e.to_string().contains("-1"),
            "rejected amount must appear in error message"
        );
    }
}
