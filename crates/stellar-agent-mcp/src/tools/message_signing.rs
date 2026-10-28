//! Checks and the audit row shared by the two message-signing tools,
//! `stellar_sep43_sign_message` and `stellar_sep53_sign_message`.

use std::sync::{Arc, Mutex};

use rmcp::model::CallToolResult;
use stellar_agent_core::audit_log::{AuditEntry, AuditWriter};
use stellar_agent_core::error::ValidationError;
use stellar_agent_core::observability::RedactedStrkey;

use crate::server::WalletServer;
use crate::tools::common::business_error_result;

impl WalletServer {
    /// Runs the message-signing checks that precede key access and returns the
    /// audit writer for the signature row.
    ///
    /// The order is fixed: an overlaid `mcp_signer_default` refuses with
    /// `profile.non_overlayable_field`, then the message-signing key scope
    /// refuses with `profile.key_scope_conflict`, then the audit pre-flight
    /// refuses with its `audit.*` code. These checks read profile files and the
    /// audit chain key only, never the signing key.
    pub(crate) fn message_signing_preflight(
        &self,
    ) -> Result<Arc<Mutex<AuditWriter>>, CallToolResult> {
        if self.profile.is_overlaid("mcp_signer_default") {
            let error = ValidationError::ProfileNonOverlayableField {
                field: "mcp_signer_default",
            };
            return Err(business_error_result(
                error.code(),
                "message signing requires mcp_signer_default from the profile file; remove its overlay",
            ));
        }
        let profile_name = self.profile_name_for_approval();
        stellar_agent_core::profile::key_scope::enforce_message_signing_scope(
            &self.profile,
            &profile_name,
        )
        .map_err(|conflict| {
            let error = ValidationError::from(conflict);
            business_error_result(error.code(), error.to_string())
        })?;
        crate::tools::value_audit::require_value_audit_writer(
            &self.profile,
            &profile_name,
            self.audit_binding,
        )
        .map_err(|error| business_error_result(error.code(), error.to_string()))
    }
}

/// The `opaque_payload_signed` row of a message signature.
///
/// The row carries the redacted hex SEP-53 digest of `message` and the redacted
/// signer, never the message or the signature.
pub(crate) fn message_signed_row(
    tool: &'static str,
    chain_id: &str,
    message: &[u8],
    signer: &str,
) -> AuditEntry {
    let digest = hex::encode(stellar_agent_sep53::message_digest(message));
    AuditEntry::new_opaque_payload_signed(
        tool,
        chain_id,
        stellar_agent_network::submit::redact_tx_hash(&digest),
        RedactedStrkey::from_full(signer),
        uuid::Uuid::new_v4().to_string(),
    )
}
