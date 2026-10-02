//! Shared binding and operator-visible context for approvals.

use super::AttestationBinding;
use crate::profile::schema::Profile;

/// The profile identity rendered and bound by an approving process.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct ApprovalContext {
    /// Approval store file stem.
    pub profile_name: String,
    /// CAIP-2 chain id of the environment-merged profile.
    pub chain_id: String,
    /// RPC authority with credentials and URL paths redacted.
    pub endpoint_host: String,
    /// Enrolled signer account, absent for the enrollment placeholder.
    pub signer_account: Option<String>,
}

impl ApprovalContext {
    /// Builds the rendering context and binding from the selected profile.
    #[must_use]
    pub fn from_profile(profile_name: &str, profile: &Profile) -> Self {
        Self {
            profile_name: profile_name.to_owned(),
            chain_id: profile.chain_id.caip2_str().to_owned(),
            endpoint_host: crate::redact::redact_url_authority(&profile.rpc_url),
            signer_account: (!profile.mcp_signer_default.is_signer_placeholder())
                .then(|| profile.mcp_signer_default.account.clone()),
        }
    }

    /// Borrows the profile and chain used by the attestation preimage.
    #[must_use]
    pub fn binding(&self) -> AttestationBinding<'_> {
        AttestationBinding::new(&self.profile_name, &self.chain_id)
    }
}

/// Builds an approve command with the store profile name.
///
/// Quoting is POSIX. PowerShell reads the same single-quoted word literally
/// except for an embedded apostrophe.
#[must_use]
pub fn approve_hint(approval_nonce: &str, profile_name: &str) -> String {
    format!(
        "stellar-agent approve --id {approval_nonce} --profile {}",
        crate::profile::name::shell_word(profile_name)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approve_hint_quotes_profile_name() {
        assert_eq!(
            approve_hint("nonce", "two words"),
            "stellar-agent approve --id nonce --profile 'two words'"
        );
    }

    #[test]
    fn context_uses_profile_and_redacts_endpoint() {
        let mut profile = Profile::builder_testnet("svc", "default", "nonce", "default").build();
        profile.rpc_url = "https://user:secret@rpc.example:8443/private?token=secret".to_owned();
        let context = ApprovalContext::from_profile("selected", &profile);
        assert_eq!(context.profile_name, "selected");
        assert_eq!(context.chain_id, "stellar:testnet");
        assert!(!context.endpoint_host.contains("secret"));
        assert!(!context.endpoint_host.contains("private"));
        assert!(context.endpoint_host.contains("rpc.example"));
        assert!(context.signer_account.is_none());
        profile.mcp_signer_default.account = "GSIGNER".to_owned();
        assert_eq!(
            ApprovalContext::from_profile("selected", &profile)
                .signer_account
                .as_deref(),
            Some("GSIGNER")
        );
    }
}
