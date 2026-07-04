//! `stellar-agent approve operator` — operator-approval credential
//! enrollment.
//!
//! Manages the dedicated operator-approval credential store
//! (`stellar_agent_core::approval::operator_credentials`) that authenticates
//! an operator for the remote-approval HTTP surface
//! (`stellar-agent-approval-remote`). This is a DIFFERENT trust role from a
//! smart-account signer passkey (`stellar-agent wallet sa add-passkey`):
//! enrolling here only ever grants the ability to consent to pending
//! wallet-controlled approvals, never on-chain signing authority.
//!
//! # Enrollment stays loopback-only
//!
//! `enroll` never runs over the network — it writes directly to the local
//! credential store from operator-supplied arguments. The credential id and
//! public key are obtained from a WebAuthn registration ceremony run on the
//! approving device — normally the `stellar-agent-approval-remote` listener's
//! own `GET /enroll` page (it has to run there: a credential is bound to its
//! `rp.id` at creation), though any standard means producing the same two
//! values works (a browser's WebAuthn devtools, platform tooling). This
//! command's job is only to validate and persist the result, and to remind
//! the operator that enrollment alone grants nothing — the profile's
//! `[remote_approval] allowed_credentials` list is the separate,
//! operator-controlled authorization step.

use clap::{Args, Subcommand};

use stellar_agent_core::approval::error::ApprovalError;
use stellar_agent_core::approval::operator_credentials::{
    OperatorApprovalCredential, OperatorApprovalCredentialStore,
    default_operator_approval_credentials_path,
};
use stellar_agent_core::envelope::Envelope;
use stellar_agent_core::error::{InternalError, WalletError};
use stellar_agent_core::timefmt;

use crate::common::render::render_json;
use crate::common::resolve_profile_name;

/// Arguments for `stellar-agent approve operator`.
#[derive(Debug, Args)]
#[non_exhaustive]
pub struct OperatorArgs {
    /// Nested subcommand (`enroll`).
    #[command(subcommand)]
    pub subcommand: OperatorSubcommand,
}

/// Subcommands of `stellar-agent approve operator`.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum OperatorSubcommand {
    /// Enroll an operator-approval passkey credential.
    ///
    /// Validates and writes the credential to the profile's dedicated
    /// operator-approval credential store. Does NOT authorize the credential
    /// by itself — add its id to the profile's
    /// `[remote_approval] allowed_credentials` list separately.
    Enroll(EnrollArgs),
}

/// Arguments for `stellar-agent approve operator enroll`.
#[derive(Debug, Args)]
#[non_exhaustive]
pub struct EnrollArgs {
    /// Profile name (default: `"default"` or `STELLAR_AGENT_PROFILE` env var).
    #[arg(long = "profile", value_name = "NAME")]
    pub profile: Option<String>,

    /// Base64url WebAuthn credential id (16-64 raw bytes), from the
    /// registration ceremony's `PublicKeyCredential.id`.
    #[arg(long = "credential-id", value_name = "B64URL")]
    pub credential_id_b64url: String,

    /// Base64url-encoded 65-byte uncompressed SEC1 P-256 public key
    /// (`0x04 || X || Y`) extracted from the registration ceremony's
    /// attestation.
    #[arg(long = "public-key", value_name = "B64URL")]
    pub public_key_sec1_b64: String,

    /// WebAuthn Relying Party ID this credential was registered against.
    #[arg(long = "rp-id", value_name = "HOSTNAME")]
    pub rp_id: String,

    /// Operator-chosen human-readable label (e.g. `"laptop"`, `"phone"`).
    #[arg(long = "label", value_name = "LABEL")]
    pub label: String,
}

/// Runs `stellar-agent approve operator`.
///
/// Returns `0` on success, `1` on any error.
///
/// # Panics
///
/// Never panics.
pub async fn dispatch(args: OperatorArgs) -> i32 {
    match args.subcommand {
        OperatorSubcommand::Enroll(enroll_args) => run_enroll(enroll_args).await,
    }
}

async fn run_enroll(args: EnrollArgs) -> i32 {
    let profile_name = resolve_profile_name(args.profile.as_deref());

    let store_path = match default_operator_approval_credentials_path(&profile_name) {
        Ok(p) => p,
        Err(e) => {
            let err = WalletError::Internal(InternalError::UnexpectedState {
                detail: format!("approve.operator_store_unavailable: {e}"),
            });
            render_json(&Envelope::<()>::err(&err));
            return 1;
        }
    };

    let registered_at_unix_ms = match timefmt::now_unix_ms() {
        Ok(n) => n,
        Err(e) => {
            let err = WalletError::Internal(InternalError::UnexpectedState {
                detail: format!("approve.clock_error: {e}"),
            });
            render_json(&Envelope::<()>::err(&err));
            return 1;
        }
    };

    let store = OperatorApprovalCredentialStore::new(store_path);
    let credential = OperatorApprovalCredential {
        credential_id_b64url: args.credential_id_b64url.clone(),
        public_key_sec1_b64: args.public_key_sec1_b64,
        rp_id: args.rp_id,
        label: args.label,
        registered_at_unix_ms,
        sign_count: None,
    };

    match store.enroll(credential) {
        Ok(()) => {
            render_json(&Envelope::ok(EnrollResult {
                credential_id_b64url: args.credential_id_b64url,
                enrolled: true,
                note: "Enrollment does not by itself authorize this credential. Add its id to \
                       this profile's [remote_approval] allowed_credentials list to permit it \
                       to consent to remote approvals."
                    .to_owned(),
            }));
            0
        }
        Err(ApprovalError::DuplicateCredentialId { .. }) => {
            let err = WalletError::Internal(InternalError::UnexpectedState {
                detail: "approve.operator_credential_already_enrolled: a credential with this id \
                         is already enrolled for this profile"
                    .to_owned(),
            });
            render_json(&Envelope::<()>::err(&err));
            1
        }
        Err(ApprovalError::Invalid { reason }) => {
            let err = WalletError::Internal(InternalError::UnexpectedState {
                detail: format!("approve.operator_credential_invalid: {reason}"),
            });
            render_json(&Envelope::<()>::err(&err));
            1
        }
        Err(e) => {
            let err = WalletError::Internal(InternalError::UnexpectedState {
                detail: format!("approve.operator_enroll_failed: {e}"),
            });
            render_json(&Envelope::<()>::err(&err));
            1
        }
    }
}

/// JSON success payload for `approve operator enroll`.
#[derive(Debug, serde::Serialize)]
struct EnrollResult {
    credential_id_b64url: String,
    enrolled: bool,
    note: String,
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "test-only; panics acceptable in unit tests"
    )]
    use super::*;
    use clap::Parser;

    #[derive(Debug, Parser)]
    struct Wrap {
        #[command(flatten)]
        args: EnrollArgs,
    }

    #[test]
    fn parses_required_flags() {
        let w = Wrap::try_parse_from([
            "prog",
            "--credential-id",
            "AAAAAAAAAAAAAAAAAAAAAA",
            "--public-key",
            "BBBBBBBB",
            "--rp-id",
            "wallet.internal",
            "--label",
            "laptop",
        ])
        .expect("flags parse");
        assert_eq!(w.args.credential_id_b64url, "AAAAAAAAAAAAAAAAAAAAAA");
        assert_eq!(w.args.public_key_sec1_b64, "BBBBBBBB");
        assert_eq!(w.args.rp_id, "wallet.internal");
        assert_eq!(w.args.label, "laptop");
    }

    #[test]
    fn missing_required_flag_fails() {
        let result = Wrap::try_parse_from(["prog", "--credential-id", "AAAA"]);
        assert!(result.is_err());
    }
}
