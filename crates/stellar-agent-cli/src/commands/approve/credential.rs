//! `stellar-agent approve credential enroll`: enrolls a WebAuthn approval
//! credential for the owner-signed mainnet policy.
//!
//! Without `--origin-from` the command runs the loopback registration
//! ceremony of `stellar_agent_approval_ui::operator_enroll` for
//! `EnrollmentPurpose::MainnetApproval`. A one-shot server listens on
//! `127.0.0.1` and serves the page at `http://localhost:<port>`. The page
//! creates a credential bound to `rp_id: "localhost"` over the server's
//! challenge. It computes a confirmation code from that credential under the
//! mainnet approval domain. In private-open mode the bearer URL reaches the
//! browser only through [`private_open::open_private`]; it is never printed,
//! and a launch failure refuses with `approval.presence_browser_required`.
//!
//! With `--origin-from <PATH>` the credential is enrolled for the RP of a
//! signed approval origin. The command reads an unsigned policy body, which
//! need not be installed or signed, and validates it as `profile
//! policy-check` does. The body's `approval_origin` supplies the page origin
//! and its host the RP; its `approval_cert_spki_sha256` pins the TLS leaf.
//! The listener uses the profile's `[remote_approval]` bind and TLS paths.
//! The command prints the secret-free URL and an eight-digit enrollment code
//! on stderr; the code opens the page's session once. This mode needs no
//! display and no browser opener.
//!
//! In both modes the operator types the page's confirmation code at this
//! terminal before the deadline. The command then prints one success envelope
//! with the RP ID, the credential ID, the P-256 public key, its fingerprint and the
//! inline-table entry for `mainnet.approval_credentials`. It writes nothing:
//! no profile, policy, keyring entry or operator credential store changes,
//! and the label stays on the page. The credential approves mainnet consent
//! only after the owner adds the entry to the policy and signs it with
//! `profile sign-policy`.
//!
//! The profile must be a persisted mainnet profile; neither an enabled
//! installation nor an existing mainnet policy is required, so a credential
//! can be enrolled before the owner writes the policy that lists it.

use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use clap::{Args, Subcommand};
use serde::Serialize;

use stellar_agent_approval_remote::enroll_listener::{
    SignedEnrollmentConfig, SignedEnrollmentHandle, start_signed_enrollment,
};
use stellar_agent_approval_ui::operator_enroll::{
    OperatorEnrollAwaitError, OperatorEnrollHandle, OperatorEnrollStartError,
    OperatorEnrollmentConfirmationError, PendingOperatorEnrollment, start_mainnet_approval_enroll,
};
use stellar_agent_core::approval::{MAINNET_APPROVAL_RP_ID, MainnetApprovalCredential};
use stellar_agent_core::envelope::Envelope;
use stellar_agent_core::error::{ApprovalFailure, WalletError};
use stellar_agent_core::policy::PolicyError;
use stellar_agent_core::policy::v1::approval_origin::{ApprovalOrigin, validate_bootstrap};
use stellar_agent_core::policy::v1::loader::validate_unsigned_policy;
use stellar_agent_core::profile::ResolvedProfileName;

use super::operator::print_confirmation_prompt;
use crate::common::private_open;
use crate::common::profile_access::load_profile_reconciled;
use crate::common::render::render_json;
use crate::common::served_pages::page_identity_for;
use crate::common::tty::{read_line_from_terminal, stdin_and_stderr_are_terminals};
use crate::common::{display_available, interrupted, validate_path_component_ascii_safe};

/// The note printed on stderr after a successful enrollment.
const POLICY_NOTE: &str = "Add this approval credential to mainnet.approval_credentials in the \
                           policy file, review the key, then run profile sign-policy. \
                           Enrollment alone grants no approval authority.";

/// The refusals of the command, as `(code, message)`.
const TTY_REQUIRED: (&str, &str) = (
    "approve.credential_enroll_tty_required",
    "Approval credential enrollment needs a terminal on stdin and stderr to type the code shown \
     by the browser.",
);
const PROFILE_REQUIRED: (&str, &str) = (
    "approve.credential_enroll_profile_required",
    "Approval credential enrollment requires a persisted mainnet profile selected with --profile.",
);
const CONFIRMATION_MISMATCH: (&str, &str) = (
    "approve.credential_enroll_confirmation_mismatch",
    "The confirmation code does not match the browser credential; no policy credential is \
     exported.",
);
const EXPIRED: (&str, &str) = (
    "approve.credential_enroll_expired",
    "The approval credential enrollment deadline has passed; no policy credential is exported.",
);
const CANCELED: (&str, &str) = (
    "approve.credential_enroll_canceled",
    "Approval credential enrollment is canceled; no policy credential is exported.",
);
const UNAVAILABLE: (&str, &str) = (
    "approve.credential_enroll_unavailable",
    "The approval credential enrollment cannot start or complete; no policy credential is \
     exported.",
);
const CODE_EXHAUSTED: (&str, &str) = (
    "approve.credential_enroll_code_exhausted",
    "The enrollment code attempt limit is exhausted; no policy credential is exported.",
);
const ORIGIN_MISSING: (&str, &str) = (
    "approve.credential_enroll_origin_missing",
    "The policy body requires approval_origin and approval_cert_spki_sha256 for signed-origin \
     enrollment.",
);

/// Arguments for `stellar-agent approve credential`.
#[derive(Debug, Args)]
#[non_exhaustive]
pub struct CredentialArgs {
    /// Nested subcommand (`enroll`).
    #[command(subcommand)]
    pub subcommand: CredentialSubcommand,
}

/// Subcommands of `stellar-agent approve credential`.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum CredentialSubcommand {
    /// Enroll a WebAuthn approval credential for the owner-signed mainnet
    /// policy.
    ///
    /// Runs a local browser ceremony, or with `--origin-from` an HTTPS
    /// ceremony at the signed approval origin. Prints the credential's entry
    /// for `mainnet.approval_credentials` after you type the code the page
    /// shows. Writes nothing: the credential approves mainnet consent
    /// only after the owner adds the entry and signs the policy.
    Enroll(EnrollApprovalCredentialArgs),
}

/// Arguments for `stellar-agent approve credential enroll`.
#[derive(Debug, Args)]
#[non_exhaustive]
pub struct EnrollApprovalCredentialArgs {
    /// Print the local ceremony URL for the operator to open.
    #[arg(long)]
    pub open_by_operator: bool,
    /// The persisted mainnet profile the credential is for.
    #[arg(long = "profile", value_name = "NAME")]
    pub profile: String,

    /// Enroll at the signed approval origin of this unsigned policy body,
    /// installed or not, through the profile's `[remote_approval]` TLS
    /// listener. The body supplies the origin, the RP and the certificate
    /// pin.
    #[arg(
        long = "origin-from",
        value_name = "PATH",
        conflicts_with = "open_by_operator"
    )]
    pub origin_from: Option<PathBuf>,

    /// Optional pre-fill for the page's label field. The label stays on the
    /// page and is absent from the printed policy entry.
    #[arg(long = "label", value_name = "LABEL")]
    pub label: Option<String>,

    /// Ceremony timeout in seconds, covering the browser registration and
    /// the terminal confirmation (1 to 600).
    #[arg(
        long = "timeout-seconds",
        value_name = "SECS",
        default_value_t = 300,
        value_parser = clap::value_parser!(u64).range(1..=600)
    )]
    pub timeout_seconds: u64,
}

impl CredentialArgs {
    /// The profile name the selected subcommand names.
    pub(crate) fn profile_flag(&self) -> Option<&str> {
        match &self.subcommand {
            CredentialSubcommand::Enroll(args) => Some(&args.profile),
        }
    }
}

/// Runs `stellar-agent approve credential`.
///
/// Returns `0` when a credential is exported, `1` on any refusal.
pub async fn dispatch(args: CredentialArgs) -> i32 {
    match args.subcommand {
        CredentialSubcommand::Enroll(args) => {
            run_enroll(args, print_enrollment_code, tokio::signal::ctrl_c(), || {
                read_line_from_terminal("operator-enroll-code")
            })
            .await
        }
    }
}

fn refuse((code, message): (&str, &str)) -> i32 {
    render_json(&Envelope::<()>::err_raw(code, message));
    1
}

/// Runs `approve credential enroll`, handing the enrollment code to
/// `on_code`, with the interruption signal `interrupt`, and the terminal prompt
/// `read_code`.
async fn run_enroll<Code>(
    args: EnrollApprovalCredentialArgs,
    on_code: impl FnOnce(&str),
    interrupt: impl Future<Output = io::Result<()>>,
    read_code: impl FnOnce() -> Code,
) -> i32
where
    Code: Future<Output = io::Result<Option<String>>>,
{
    // The confirmation code is typed at this terminal; without one the
    // ceremony could never be confirmed, so nothing starts.
    if !stdin_and_stderr_are_terminals() {
        return refuse(TTY_REQUIRED);
    }
    if validate_path_component_ascii_safe(&args.profile).is_err() {
        return refuse(PROFILE_REQUIRED);
    }
    let resolved = ResolvedProfileName::from_flag(args.profile.clone());
    let profile = match load_profile_reconciled(&resolved) {
        Ok(profile) if profile.chain_id.is_mainnet() => profile,
        Ok(_) => return refuse(PROFILE_REQUIRED),
        Err(error) if error.requires_refusal() => {
            render_json(&Envelope::<()>::err(&error.to_wallet_error()));
            return 1;
        }
        Err(_) => return refuse(PROFILE_REQUIRED),
    };
    if let Some(path) = args.origin_from.clone() {
        return run_signed(args, &path, profile, on_code, interrupt, read_code).await;
    }
    if args.open_by_operator
        && let Err(envelope) =
            crate::commands::profile::policy_check::guard_operator_open(&args.profile, &profile)
    {
        render_json(&envelope);
        return 1;
    }
    let page_identity = page_identity_for(&profile);
    if !args.open_by_operator && !display_available() {
        return report(
            EnrollmentEnd::BrowserRequired,
            &args.profile,
            MAINNET_APPROVAL_RP_ID,
        );
    }
    let handle = match start_mainnet_approval_enroll(
        args.profile.clone(),
        args.label,
        page_identity,
    )
    .await
    {
        Ok(handle) => handle,
        Err(error) => {
            if let OperatorEnrollStartError::LoopbackPair(pair) = &error {
                crate::common::log_pair_refusal("approval credential enrollment", pair);
            }
            tracing::debug!(error = %error, "approval credential enrollment did not start");
            return refuse(UNAVAILABLE);
        }
    };
    print_startup(&args.profile, args.open_by_operator);
    let end = enroll_until_done(
        handle,
        args.open_by_operator.into(),
        private_open::browser_opener,
        Duration::from_secs(args.timeout_seconds),
        interrupt,
        read_code,
    )
    .await;
    report(end, &args.profile, MAINNET_APPROVAL_RP_ID)
}

/// Runs the enrollment at the signed origin of the unsigned body at `path`.
///
/// Every body, configuration and TLS refusal happens before the listener
/// binds. The signed branch opens no browser and needs no display.
async fn run_signed<Code>(
    args: EnrollApprovalCredentialArgs,
    path: &Path,
    profile: stellar_agent_core::profile::schema::Profile,
    on_code: impl FnOnce(&str),
    interrupt: impl Future<Output = io::Result<()>>,
    read_code: impl FnOnce() -> Code,
) -> i32
where
    Code: Future<Output = io::Result<Option<String>>>,
{
    let (origin, pin) = match signed_origin_from(path, &args.profile, &profile.network_passphrase) {
        Ok(found) => found,
        Err(envelope) => {
            render_json(&envelope);
            return 1;
        }
    };
    let rp_id = origin.rp_id().to_owned();
    let timeout = Duration::from_secs(args.timeout_seconds);
    let page_identity = page_identity_for(&profile);
    let config = SignedEnrollmentConfig::new(args.profile.clone(), profile, origin, pin, timeout)
        .with_label(args.label)
        .with_page_identity(page_identity);
    let handle = match start_signed_enrollment(config, on_code).await {
        Ok(handle) => handle,
        Err(error) => {
            tracing::debug!(error = %error, "signed-origin credential enrollment did not start");
            render_json(&Envelope::<()>::err(&error.into_wallet_error()));
            return 1;
        }
    };
    let end = enroll_until_done(
        handle,
        crate::common::mainnet_presence::OpenMode::Operator,
        refuse_opener,
        timeout,
        interrupt,
        read_code,
    )
    .await;
    report(end, &args.profile, &rp_id)
}

/// The opener of the signed branch, which launches no browser.
fn refuse_opener(_url: &str) -> io::Result<()> {
    Err(io::Error::other(
        "signed-origin enrollment opens no browser",
    ))
}

/// The origin and the pin of the unsigned policy body at `path`.
///
/// The body passes the unsigned policy checks for `profile_name` and
/// `passphrase`, then the bootstrap checks of its `[mainnet]` table. No
/// signature, credential or installed policy plays a part.
fn signed_origin_from(
    path: &Path,
    profile_name: &str,
    passphrase: &str,
) -> Result<(ApprovalOrigin, [u8; 32]), Envelope<()>> {
    let policy_refusal =
        |error: &PolicyError| Envelope::<()>::err_raw(error.wire_code(), error.to_string());
    let body = std::fs::read_to_string(path).map_err(|_| {
        policy_refusal(&PolicyError::PolicyFileLoadFailed {
            detail: "the --origin-from file cannot be read".to_owned(),
        })
    })?;
    validate_unsigned_policy(&body, profile_name, passphrase).map_err(|e| policy_refusal(&e))?;
    let doc = body
        .parse::<toml_edit::DocumentMut>()
        .map_err(|e| policy_refusal(&PolicyError::toml_syntax(&body, &e)))?;
    let missing = || Envelope::<()>::err_raw(ORIGIN_MISSING.0, ORIGIN_MISSING.1);
    let table = doc
        .get("mainnet")
        .and_then(toml_edit::Item::as_table_like)
        .ok_or_else(missing)?;
    match validate_bootstrap(table) {
        Ok((Some(origin), Some(pin))) => Ok((origin, pin)),
        Ok(_) => Err(missing()),
        Err(error) => Err(policy_refusal(&error)),
    }
}

/// The handle operations the shared ceremony loop needs, over both the
/// loopback server and the signed-origin listener.
trait EnrollCeremony {
    /// The URL the operator opens.
    fn enroll_url(&self) -> String;
    /// Waits for the verified registration until `deadline`.
    async fn await_completion_until(
        &mut self,
        deadline: Instant,
    ) -> Result<PendingOperatorEnrollment, OperatorEnrollAwaitError>;
    /// Stops the server.
    async fn shutdown(self) -> Result<(), String>;
}

impl EnrollCeremony for OperatorEnrollHandle {
    fn enroll_url(&self) -> String {
        Self::enroll_url(self)
    }

    async fn await_completion_until(
        &mut self,
        deadline: Instant,
    ) -> Result<PendingOperatorEnrollment, OperatorEnrollAwaitError> {
        Self::await_completion_until(self, deadline).await
    }

    async fn shutdown(self) -> Result<(), String> {
        Self::shutdown(self)
            .await
            .map_err(|error| error.to_string())
    }
}

impl EnrollCeremony for SignedEnrollmentHandle {
    fn enroll_url(&self) -> String {
        Self::enroll_url(self)
    }

    async fn await_completion_until(
        &mut self,
        deadline: Instant,
    ) -> Result<PendingOperatorEnrollment, OperatorEnrollAwaitError> {
        Self::await_completion_until(self, deadline).await
    }

    async fn shutdown(self) -> Result<(), String> {
        Self::shutdown(self).await
    }
}

/// How an enrollment ended.
#[derive(Debug)]
enum EnrollmentEnd {
    /// The operator typed the page's code before the deadline.
    Exported(MainnetApprovalCredential),
    /// No usable local browser: no display, or the private open failed.
    BrowserRequired,
    /// No verified registration arrived before the deadline, or the
    /// deadline passed at the prompt.
    Expired,
    /// The operator interrupted, or the prompt ended without a code.
    Canceled,
    /// The typed code was malformed or not the page's.
    Mismatch,
    /// The enrollment code of a signed origin has no attempt left.
    CodeExhausted,
    /// The server failed, or the confirmed credential has no policy form.
    Unavailable,
}

/// Delivers the ceremony URL, waits for registration, then asks for the page's code.
///
/// Private mode gives `opener` a redirect file's URL; operator mode prints the
/// ceremony URL on stderr. One deadline bounds code entry, registration and
/// the prompt. The server stops and any private handoff closes when the
/// browser phase ends. `interrupt` covers both phases; `read_code` runs after
/// registration is staged.
async fn enroll_until_done<Handle, Code>(
    mut handle: Handle,
    mode: crate::common::mainnet_presence::OpenMode,
    opener: impl FnOnce(&str) -> io::Result<()>,
    timeout: Duration,
    interrupt: impl Future<Output = io::Result<()>>,
    read_code: impl FnOnce() -> Code,
) -> EnrollmentEnd
where
    Handle: EnrollCeremony,
    Code: Future<Output = io::Result<Option<String>>>,
{
    let handoff = match mode.open(&handle.enroll_url(), opener) {
        Ok(handoff) => handoff,
        Err(error) => {
            tracing::debug!(
                error.kind = ?error.kind(),
                "approval credential enrollment: the browser did not open"
            );
            stop(handle).await;
            return EnrollmentEnd::BrowserRequired;
        }
    };
    let deadline = Instant::now() + timeout;
    let interrupt = interrupted(interrupt);
    tokio::pin!(interrupt);
    let staged = tokio::select! {
        result = handle.await_completion_until(deadline) => Some(result),
        () = &mut interrupt => None,
    };
    stop(handle).await;
    if let Err(error) = handoff.map(private_open::PrivateOpen::close).transpose() {
        tracing::debug!(
            error.kind = ?error.kind(),
            "approval credential enrollment: redirect file cleanup failed"
        );
    }
    let pending = match staged {
        Some(Ok(pending)) => pending,
        Some(Err(OperatorEnrollAwaitError::Timeout)) => return EnrollmentEnd::Expired,
        Some(Err(OperatorEnrollAwaitError::CodeExhausted)) => return EnrollmentEnd::CodeExhausted,
        Some(Err(error)) => {
            tracing::debug!(error = %error, "approval credential enrollment server failed");
            return EnrollmentEnd::Unavailable;
        }
        None => return EnrollmentEnd::Canceled,
    };
    print_confirmation_prompt(pending.label());
    let typed = tokio::select! {
        typed = tokio::time::timeout_at(tokio::time::Instant::from_std(pending.deadline()), read_code()) => typed,
        () = &mut interrupt => return EnrollmentEnd::Canceled,
    };
    let line = match typed {
        Ok(Ok(Some(line))) => line,
        Ok(Ok(None) | Err(_)) => return EnrollmentEnd::Canceled,
        Err(_elapsed) => return EnrollmentEnd::Expired,
    };
    match pending
        .confirm(&line, Instant::now())
        .and_then(|confirmed| confirmed.into_mainnet_policy_credential())
    {
        Ok(credential) => EnrollmentEnd::Exported(credential),
        Err(OperatorEnrollmentConfirmationError::Mismatch) => EnrollmentEnd::Mismatch,
        Err(OperatorEnrollmentConfirmationError::Expired) => EnrollmentEnd::Expired,
        Err(
            OperatorEnrollmentConfirmationError::WrongPurpose
            | OperatorEnrollmentConfirmationError::CredentialInvalid,
        ) => EnrollmentEnd::Unavailable,
    }
}

/// Stops the server; a failed shutdown changes no outcome, since the server
/// writes nothing.
async fn stop(handle: impl EnrollCeremony) {
    if let Err(error) = handle.shutdown().await {
        tracing::debug!(
            error = %error,
            "approval credential enrollment: shutdown did not complete cleanly"
        );
    }
}

/// The success data of `approve credential enroll`.
#[derive(Debug, Serialize)]
struct EnrolledCredential {
    profile: String,
    rp_id: String,
    credential_id_b64url: String,
    public_key_sec1_b64url: String,
    credential_fingerprint: String,
    policy_entry_toml: String,
}

/// Renders how the enrollment ends and returns the exit code. `rp_id` is
/// the RP the credential is registered for.
fn report(end: EnrollmentEnd, profile: &str, rp_id: &str) -> i32 {
    match end {
        EnrollmentEnd::Exported(credential) => {
            render_json(&Envelope::ok(EnrolledCredential {
                profile: profile.to_owned(),
                rp_id: rp_id.to_owned(),
                credential_id_b64url: credential.credential_id_b64url(),
                public_key_sec1_b64url: credential.public_key_sec1_b64url(),
                credential_fingerprint: credential.fingerprint(),
                policy_entry_toml: credential.policy_entry_toml(),
            }));
            print_note(POLICY_NOTE);
            0
        }
        EnrollmentEnd::BrowserRequired => {
            render_json(&Envelope::<()>::err(&WalletError::Approval(
                ApprovalFailure::PresenceBrowserRequired,
            )));
            1
        }
        EnrollmentEnd::Expired => refuse(EXPIRED),
        EnrollmentEnd::Canceled => refuse(CANCELED),
        EnrollmentEnd::Mismatch => refuse(CONFIRMATION_MISMATCH),
        EnrollmentEnd::CodeExhausted => refuse(CODE_EXHAUSTED),
        EnrollmentEnd::Unavailable => refuse(UNAVAILABLE),
    }
}

/// Prints the enrollment code of a signed-origin enrollment, once, on
/// stderr. The URL line follows from the ceremony loop.
#[allow(
    clippy::print_stderr,
    reason = "CLI binary intentional guidance; stdout stays JSON-only"
)]
fn print_enrollment_code(code: &str) {
    eprintln!(
        "Enrollment code: {code}\n  Type it on the enrollment page, create the passkey, then \
         type the code the page shows here."
    );
}

/// The startup guidance: what opens and what the terminal then asks for.
/// It carries no URL.
fn startup_notice(profile: &str) -> String {
    format!(
        "stellar-agent: approval credential enrollment for profile {} is opening in the \
         browser.\n  Create the passkey there, then type the code the page shows here.",
        crate::common::render::escape_for_terminal(profile)
    )
}

#[allow(
    clippy::print_stderr,
    reason = "CLI binary intentional guidance; stdout stays JSON-only"
)]
fn print_startup(profile: &str, open_by_operator: bool) {
    if open_by_operator {
        eprintln!("Create the passkey in your browser, then type the code the page shows here.");
    } else {
        eprintln!("{}", startup_notice(profile));
    }
}

#[allow(
    clippy::print_stderr,
    reason = "CLI binary intentional guidance; stdout stays JSON-only"
)]
fn print_note(note: &str) {
    eprintln!("{note}");
}

#[cfg(test)]
pub(crate) mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only; panics acceptable in unit tests"
    )]
    use crate::common::test_support::tree;

    use clap::Parser;
    use stellar_agent_approval_ui::operator_enroll::test_support::{
        EnrollmentClient, SoftwareRegistrar,
    };
    use stellar_agent_approval_ui::operator_enroll::{
        EnrollmentPurpose, start_operator_enroll_server,
    };
    use stellar_agent_loopback_http::brand::PageIdentity;

    use super::*;
    use crate::common::private_open::handoff_probe::HandoffProbe;

    /// The command as `dispatch` runs it, with the terminal and Ctrl-C.
    async fn run_enroll(args: EnrollApprovalCredentialArgs) -> i32 {
        super::run_enroll(args, print_enrollment_code, tokio::signal::ctrl_c(), || {
            read_line_from_terminal("operator-enroll-code")
        })
        .await
    }

    #[derive(Debug, Parser)]
    pub(super) struct Wrap {
        #[command(flatten)]
        pub(super) args: EnrollApprovalCredentialArgs,
    }

    /// A started mainnet approval enrollment server, its URL and bootstrap
    /// token.
    async fn start() -> (OperatorEnrollHandle, String, String) {
        let handle =
            start_mainnet_approval_enroll("main".to_owned(), None, PageIdentity::neutral())
                .await
                .unwrap();
        let url = handle.enroll_url();
        let token = handle.bootstrap_token_hex().to_owned();
        (handle, url, token)
    }

    /// What the operator types at the prompt.
    #[derive(Clone, Copy, Debug)]
    pub(super) enum Typing {
        /// The page's code, in upper case with spaces for separators.
        PageCode,
        /// A well-formed code that is not the page's.
        OtherCode,
        /// End of input.
        EndOfInput,
        /// Nothing until the deadline.
        Nothing,
    }

    /// One enrollment against a real mainnet approval server: a software
    /// registrar registers through the page's HTTP calls, then `typing`
    /// happens at the prompt. The opener records the redirect file's URL.
    /// Returns the end, the registrar and the code the page showed, after
    /// asserting that the server stopped and the redirect file and its
    /// directory are gone.
    async fn case(typing: Typing, timeout: Duration) -> (EnrollmentEnd, SoftwareRegistrar, String) {
        case_with_mode(
            typing,
            timeout,
            crate::common::mainnet_presence::OpenMode::Private,
        )
        .await
    }

    async fn case_with_mode(
        typing: Typing,
        timeout: Duration,
        mode: crate::common::mainnet_presence::OpenMode,
    ) -> (EnrollmentEnd, SoftwareRegistrar, String) {
        let (handle, url, token) = start().await;
        let addr = handle.local_addr();
        let registrar = SoftwareRegistrar::new([0x21; 32], vec![0x5a; 20]);
        let probe = HandoffProbe::default();
        let (typed_tx, typed_rx) = tokio::sync::oneshot::channel::<io::Result<Option<String>>>();
        let (code_tx, code_rx) = tokio::sync::oneshot::channel::<String>();
        let read_code = move || async move {
            match typed_rx.await {
                Ok(typed) => typed,
                Err(_) => std::future::pending().await,
            }
        };
        let driver = {
            let registrar = &registrar;
            let token = token.clone();
            async move {
                let client = EnrollmentClient::connect(addr, &token).await.unwrap();
                let second = stellar_agent_approval_ui::operator_enroll::test_support::request(
                    addr,
                    "GET",
                    &format!("/bootstrap/{token}"),
                    &[],
                    None,
                )
                .await
                .unwrap();
                assert_eq!(second.status, 404);
                let (reply, builder) = client.register_response(registrar, "laptop").await.unwrap();
                assert_eq!(reply.status, 200, "{reply:?}");
                let code = builder.confirmation_code_for(EnrollmentPurpose::MainnetApproval);
                code_tx.send(code.clone()).unwrap();
                let typed = match typing {
                    Typing::PageCode => Some(Ok(Some(code.to_uppercase().replace('-', " ")))),
                    Typing::OtherCode => {
                        let mut other = code.into_bytes();
                        other[0] = if other[0] == b'0' { b'1' } else { b'0' };
                        Some(Ok(Some(String::from_utf8(other).unwrap())))
                    }
                    Typing::EndOfInput => Some(Ok(None)),
                    Typing::Nothing => None,
                };
                if let Some(typed) = typed {
                    let _ = typed_tx.send(typed);
                }
            }
        };
        let ceremony = enroll_until_done(
            handle,
            mode,
            |url| {
                assert_eq!(
                    mode,
                    crate::common::mainnet_presence::OpenMode::Private,
                    "operator-open launches no browser"
                );
                probe.opener(Ok(()))(url)
            },
            timeout,
            std::future::pending(),
            read_code,
        );
        let (end, ()) = tokio::time::timeout(Duration::from_secs(60), async {
            tokio::join!(ceremony, driver)
        })
        .await
        .expect("the enrollment ends");
        assert!(
            std::net::TcpStream::connect(addr).is_err(),
            "the server stopped"
        );
        if mode == crate::common::mainnet_presence::OpenMode::Private {
            let file = probe.redirect_file();
            assert!(!probe.launched()[0].contains(&token));
            assert!(!file.exists() && !file.parent().unwrap().exists());
        } else {
            assert!(probe.launched().is_empty());
        }
        assert!(!url.is_empty());
        (end, registrar, code_rx.await.unwrap())
    }

    async fn operator_enrollment() {
        let (end, registrar, _) = case_with_mode(
            Typing::PageCode,
            Duration::from_secs(5),
            crate::common::mainnet_presence::OpenMode::Operator,
        )
        .await;
        let (exit, envelope) = rendered(end);
        assert_eq!(exit, 0);
        assert_eq!(
            envelope["data"]["credential_id_b64url"],
            registrar.credential_id_b64url()
        );
        assert!(
            envelope["data"]["policy_entry_toml"]
                .as_str()
                .unwrap()
                .contains("credential_id_b64url")
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn credential_open_by_operator_prints_url_once() {
        use crate::common::test_support::{assert_url_output, capture};
        if let Some((stdout, stderr)) = capture("credential_open_by_operator_prints_url_once") {
            assert_url_output(&stdout, &stderr);
            return;
        }
        operator_enrollment().await;
    }

    /// `text` with each `"request_id":"<uuid>"` value replaced by a fixed
    /// name.
    fn without_request_ids(text: &str) -> String {
        let marker = "\"request_id\":\"";
        let mut out = String::new();
        let mut rest = text;
        while let Some(at) = rest.find(marker) {
            let value = at + marker.len();
            out.push_str(&rest[..value]);
            out.push_str("{request_id}");
            rest = &rest[value + 36..];
        }
        out.push_str(rest);
        out
    }

    /// The loopback command output keeps its base bytes: both startup
    /// notices, the operator URL line, the prompt, the export envelope and
    /// note, and every refusal envelope. Only the port, the bootstrap token
    /// and request IDs are normalized.
    #[tokio::test]
    #[serial_test::serial]
    async fn loopback_enrollment_cli_transcript_keeps_base_bytes() {
        use crate::common::test_support::capture;
        use sha2::{Digest as _, Sha256};
        if let Some((stdout, stderr)) =
            capture("loopback_enrollment_cli_transcript_keeps_base_bytes")
        {
            let stdout: Vec<_> = stdout
                .lines()
                .filter(|line| {
                    !line.trim().is_empty()
                        && *line != "running 1 test"
                        && *line != "."
                        && !line.starts_with("test result: ok.")
                })
                .collect();
            let mut stderr = stderr.clone();
            let url_line = stderr
                .lines()
                .find(|line| line.starts_with("Open this URL in your browser: "))
                .unwrap()
                .to_owned();
            let url = url_line.trim_start_matches("Open this URL in your browser: ");
            let (_, rest) = url.split_once("http://localhost:").unwrap();
            let (port, token) = rest.split_once("/bootstrap/").unwrap();
            stderr = stderr
                .replace(token, "{token}")
                .replace(&format!("localhost:{port}"), "localhost:{port}");
            let transcript = format!(
                "{}\n--- stderr\n{stderr}",
                without_request_ids(&stdout.join("\n"))
            );
            assert_eq!(
                hex::encode(Sha256::digest(transcript.as_bytes())),
                "814c59ff347ab260d3c652b5dad467aec35d3a7727600a6a96e4eb793ba48ce9",
                "transcript:\n{transcript}"
            );
            return;
        }
        print_startup("main", false);
        print_startup("main", true);
        operator_enrollment().await;
        for end in [
            EnrollmentEnd::BrowserRequired,
            EnrollmentEnd::Expired,
            EnrollmentEnd::Canceled,
            EnrollmentEnd::Mismatch,
            EnrollmentEnd::Unavailable,
        ] {
            rendered(end);
        }
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn credential_open_by_operator_launches_no_browser() {
        operator_enrollment().await;
    }

    pub(crate) async fn operator_expiry_and_cancellation() {
        use crate::common::mainnet_presence::OpenMode;
        let (end, _, _) = case_with_mode(
            Typing::Nothing,
            Duration::from_millis(200),
            OpenMode::Operator,
        )
        .await;
        assert!(matches!(end, EnrollmentEnd::Expired));
        let (end, _, _) = case_with_mode(
            Typing::OtherCode,
            Duration::from_secs(5),
            OpenMode::Operator,
        )
        .await;
        assert!(matches!(end, EnrollmentEnd::Mismatch));
        for cancel in [false, true] {
            let (handle, _, _) = start().await;
            let addr = handle.local_addr();
            let result = tokio::time::timeout(
                Duration::from_secs(2),
                enroll_until_done(
                    handle,
                    OpenMode::Operator,
                    |_| panic!("no opener"),
                    Duration::from_millis(200),
                    async {
                        if cancel {
                            Ok(())
                        } else {
                            std::future::pending().await
                        }
                    },
                    || async { panic!("no terminal prompt before registration") },
                ),
            )
            .await
            .expect("enrollment deadline and interruption remain bounded");
            assert!(matches!(
                (cancel, result),
                (true, EnrollmentEnd::Canceled) | (false, EnrollmentEnd::Expired)
            ));
            assert!(std::net::TcpStream::connect(addr).is_err());
        }
    }

    /// The rendered envelope of `end`, with the exit code.
    fn rendered(end: EnrollmentEnd) -> (i32, serde_json::Value) {
        crate::common::render::take_rendered_for_test();
        let code = report(end, "main", MAINNET_APPROVAL_RP_ID);
        let mut rendered = crate::common::render::take_rendered_for_test();
        assert_eq!(rendered.len(), 1, "{rendered:?}");
        (code, rendered.remove(0))
    }

    /// The rendered export uses the core's policy entry verbatim.
    #[test]
    fn credential_export_uses_core_policy_entry() {
        let authenticator = stellar_agent_test_support::webauthn::fixture_authenticator();
        let credential = MainnetApprovalCredential::from_encoded(
            &authenticator.credential_id_b64url(),
            &authenticator.public_key_sec1_b64url(),
        )
        .unwrap();
        let expected = credential.policy_entry_toml();
        let (exit, envelope) = rendered(EnrollmentEnd::Exported(credential));
        assert_eq!(exit, 0);
        assert_eq!(envelope["data"]["policy_entry_toml"], expected);
    }

    /// Only the page's code, typed before the deadline, exports the exact
    /// credential, and the exported entry passes the owner-signed policy
    /// loader. Another code, end of input and the deadline export nothing.
    /// No run writes under the wallet home or into the keyring, and neither
    /// the envelope nor the startup notice carries the code or a URL.
    #[tokio::test(flavor = "current_thread")]
    #[serial_test::serial]
    async fn credential_enrollment_exports_only_after_matching_code() {
        use stellar_agent_core::approval::mainnet_fixtures::MainnetConsentFixture;
        use stellar_agent_core::profile::schema::Profile;

        stellar_agent_test_support::keyring_mock::install().unwrap();
        let home = tempfile::tempdir().unwrap();
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(home.path());
        let profile = Profile::builder_mainnet_named(
            "main",
            "https://rpc.example.invalid",
            "stellar-agent-signer-main",
            "default",
            "stellar-agent-nonce-main",
            "default",
        )
        .build();
        stellar_agent_core::profile::loader::save_to_dir(
            "main",
            &profile,
            &home.path().join("profiles"),
        )
        .unwrap();
        std::fs::create_dir_all(home.path().join("policies")).unwrap();
        std::fs::write(
            home.path().join("policies").join("main.toml"),
            "version = 2\n",
        )
        .unwrap();
        let before = tree(home.path());
        let keyring_absent = |entry: &stellar_agent_core::profile::schema::KeyringEntryRef| {
            keyring_core::Entry::new(&entry.service, &entry.account)
                .unwrap()
                .get_password()
                .is_err()
        };
        let coordinates = [
            profile.policy_owner_key_id.clone(),
            profile.attestation_key_id.clone(),
            profile.audit_log_hash_chain_key_id.clone(),
            stellar_agent_core::profile::schema::policy_pin_entry_ref(
                &profile.policy_window_state_key_id,
            ),
            stellar_agent_core::profile::schema::mainnet_enablement_entry_ref(
                &profile.policy_window_state_key_id,
            ),
        ];

        for (typing, timeout, expected) in [
            (Typing::OtherCode, 30, CONFIRMATION_MISMATCH),
            (Typing::EndOfInput, 30, CANCELED),
            (Typing::Nothing, 3, EXPIRED),
        ] {
            let (end, _, code) = case(typing, Duration::from_secs(timeout)).await;
            let (exit, envelope) = rendered(end);
            assert_eq!(exit, 1, "{envelope}");
            assert_eq!(envelope["error"]["code"], expected.0, "{envelope}");
            assert_eq!(envelope["error"]["message"], expected.1, "{envelope}");
            assert!(envelope.get("data").is_none_or(serde_json::Value::is_null));
            assert!(!envelope.to_string().contains(&code));
            assert_eq!(tree(home.path()), before, "{}", expected.0);
        }

        let (end, registrar, code) = case(Typing::PageCode, Duration::from_secs(30)).await;
        let EnrollmentEnd::Exported(credential) = &end else {
            panic!("{end:?}");
        };
        assert_eq!(credential.credential_id(), registrar.credential_id());
        assert_eq!(credential.public_key_sec1(), &registrar.public_key_sec1());
        let fingerprint = credential.fingerprint();
        let (exit, envelope) = rendered(end);
        assert_eq!(exit, 0, "{envelope}");
        let data = &envelope["data"];
        assert_eq!(data["profile"], "main");
        assert_eq!(data["rp_id"], "localhost");
        assert_eq!(
            data["credential_id_b64url"],
            registrar.credential_id_b64url()
        );
        assert_eq!(data["credential_fingerprint"], fingerprint);
        let entry = data["policy_entry_toml"].as_str().unwrap().to_owned();
        assert_eq!(
            entry,
            format!(
                "{{ credential_id_b64url = \"{}\", public_key_sec1_b64url = \"{}\" }}",
                registrar.credential_id_b64url(),
                data["public_key_sec1_b64url"].as_str().unwrap()
            )
        );
        assert!(!envelope.to_string().contains(&code));
        assert!(!envelope.to_string().contains(&code.replace('-', "")));
        assert!(
            !envelope.to_string().contains("laptop"),
            "the label stays on the page"
        );
        assert_eq!(tree(home.path()), before);
        assert!(coordinates.iter().all(keyring_absent));
        let notice = startup_notice("main");
        assert!(
            !notice.contains("http") && !notice.contains("bootstrap"),
            "{notice}"
        );

        // The exported entry, added to the policy and signed by the owner,
        // loads through the verified policy loader.
        let fixture = MainnetConsentFixture::new("main");
        let fixture_entry = format!(
            "{{ credential_id_b64url = \"{}\", public_key_sec1_b64url = \"{}\" }}",
            stellar_agent_test_support::webauthn::fixture_authenticator().credential_id_b64url(),
            stellar_agent_test_support::webauthn::fixture_authenticator().public_key_sec1_b64url()
        );
        let body = fixture
            .policy_body(
                fixture.sequence() + 1,
                &[&stellar_agent_test_support::webauthn::fixture_authenticator()],
            )
            .replace(&fixture_entry, &entry);
        assert!(body.contains(&entry));
        fixture.write_signed(&body);
        let credentials = fixture
            .current_policy()
            .mainnet()
            .unwrap()
            .approval_credentials
            .clone();
        assert_eq!(credentials.len(), 1);
        assert_eq!(credentials[0].credential_id(), registrar.credential_id());
        assert_eq!(credentials[0].fingerprint(), fingerprint);
    }

    /// `--profile` is required and the timeout accepts 1 to 600 seconds.
    #[test]
    fn credential_enrollment_flags_bound_the_timeout() {
        for accepted in ["1", "600"] {
            let parsed =
                Wrap::try_parse_from(["prog", "--profile", "main", "--timeout-seconds", accepted])
                    .unwrap();
            assert_eq!(parsed.args.timeout_seconds.to_string(), accepted);
        }
        assert_eq!(
            Wrap::try_parse_from(["prog", "--profile", "main"])
                .unwrap()
                .args
                .timeout_seconds,
            300
        );
        for refused in ["0", "601"] {
            let error =
                Wrap::try_parse_from(["prog", "--profile", "main", "--timeout-seconds", refused])
                    .unwrap_err();
            assert_eq!(
                error.kind(),
                clap::error::ErrorKind::ValueValidation,
                "{refused}"
            );
        }
        assert_eq!(
            Wrap::try_parse_from(["prog"]).unwrap_err().kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
    }

    /// The browser receives only the private redirect file's URL, which
    /// holds the bearer URL while the ceremony waits; an interrupt cancels,
    /// stops the server and removes the file and its directory. A failed
    /// open refuses with the browser code, leaves nothing behind, stops the
    /// server and exports nothing.
    #[tokio::test(flavor = "current_thread")]
    async fn credential_enrollment_uses_private_open() {
        let never_typed = || std::future::pending::<io::Result<Option<String>>>();
        let (handle, url, token) = start().await;
        let addr = handle.local_addr();
        let probe = HandoffProbe::default();
        let end = tokio::time::timeout(
            Duration::from_secs(30),
            enroll_until_done(
                handle,
                crate::common::mainnet_presence::OpenMode::Private,
                probe.opener(Ok(())),
                Duration::from_secs(3600),
                probe.interrupt(),
                never_typed,
            ),
        )
        .await
        .expect("the interrupt ends the wait");
        assert!(matches!(end, EnrollmentEnd::Canceled), "{end:?}");
        probe.assert_private_handoff(&url, &token);
        assert!(
            std::net::TcpStream::connect(addr).is_err(),
            "the server stopped"
        );
        let (exit, envelope) = rendered(end);
        assert_eq!(exit, 1);
        assert_eq!(envelope["error"]["code"], CANCELED.0);

        let (handle, _url, token) = start().await;
        let addr = handle.local_addr();
        let probe = HandoffProbe::default();
        let end = tokio::time::timeout(
            Duration::from_secs(30),
            enroll_until_done(
                handle,
                crate::common::mainnet_presence::OpenMode::Private,
                probe.opener(Err(io::Error::other("no browser"))),
                Duration::from_secs(3600),
                std::future::pending(),
                never_typed,
            ),
        )
        .await
        .expect("a failed open ends the enrollment");
        assert!(matches!(end, EnrollmentEnd::BrowserRequired), "{end:?}");
        probe.assert_failed_open_left_nothing(&token);
        assert!(!probe.waited());
        assert!(
            std::net::TcpStream::connect(addr).is_err(),
            "the server stopped"
        );
        let (exit, envelope) = rendered(end);
        assert_eq!(exit, 1);
        assert_eq!(
            envelope["error"]["code"],
            "approval.presence_browser_required"
        );
        assert_eq!(
            envelope["error"]["message"],
            "Mainnet consent requires a local browser with WebAuthn user verification; no \
             approval is recorded."
        );
    }

    /// Registrations over another challenge, from another origin, without
    /// user presence or verification, for another RP or cross-origin are
    /// refused and stage nothing. The code an operator credential page
    /// shows never confirms a mainnet approval ceremony, and the mainnet
    /// code never confirms an operator credential ceremony.
    #[tokio::test(flavor = "current_thread")]
    async fn credential_enrollment_refuses_wrong_challenge_origin_and_flags() {
        use base64::Engine as _;
        use sha2::Digest as _;

        let (mut handle, _url, token) = start().await;
        let addr = handle.local_addr();
        let client = EnrollmentClient::connect(addr, &token).await.unwrap();
        let challenge: [u8; 32] = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(
                client.challenge().await.unwrap().json()["challenge"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap()
            .try_into()
            .unwrap();
        let registrar = SoftwareRegistrar::new([0x21; 32], vec![0x5a; 20]);
        let origin = client.origin();
        let mut other_challenge = challenge;
        other_challenge[0] ^= 1;
        let corpus = [
            (
                "another challenge",
                registrar.builder(&other_challenge, &origin),
            ),
            (
                "another port",
                registrar.builder(&challenge, "http://localhost:1"),
            ),
            (
                "the IP origin",
                registrar.builder(&challenge, &format!("http://127.0.0.1:{}", addr.port())),
            ),
            (
                "no user verification",
                registrar.builder(&challenge, &origin).flags(0x41),
            ),
            (
                "no user presence",
                registrar.builder(&challenge, &origin).flags(0x44),
            ),
            (
                "another RP",
                registrar
                    .builder(&challenge, &origin)
                    .rp_id_hash(sha2::Sha256::digest(b"example.com").into()),
            ),
            (
                "cross-origin",
                registrar
                    .builder(&challenge, &origin)
                    .cross_origin(Some(true)),
            ),
        ];
        for (name, builder) in corpus {
            let reply = client.post_credential(&builder.json()).await.unwrap();
            assert_eq!(reply.status, 400, "{name}: {reply:?}");
            assert_eq!(reply.json()["error"], "registration_invalid", "{name}");
        }
        let valid = registrar.builder(&challenge, &origin);
        let reply = client.post_credential(&valid.json()).await.unwrap();
        assert_eq!(reply.status, 200, "{reply:?}");
        let pending = handle
            .await_completion(Duration::from_secs(30))
            .await
            .unwrap();
        assert_eq!(pending.purpose(), EnrollmentPurpose::MainnetApproval);
        assert_eq!(
            pending
                .confirm(
                    &valid.confirmation_code_for(EnrollmentPurpose::RemoteOperator),
                    Instant::now()
                )
                .unwrap_err(),
            OperatorEnrollmentConfirmationError::Mismatch
        );
        handle.shutdown().await.unwrap();

        let dir = tempfile::tempdir().unwrap();
        let mut handle = start_operator_enroll_server(
            dir.path().join("operator.toml"),
            "main",
            std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 0),
            None,
            PageIdentity::neutral(),
        )
        .await
        .unwrap();
        let client = EnrollmentClient::connect(handle.local_addr(), handle.bootstrap_token_hex())
            .await
            .unwrap();
        let (reply, builder) = client
            .register_response(&registrar, "laptop")
            .await
            .unwrap();
        assert_eq!(reply.status, 200, "{reply:?}");
        let pending = handle
            .await_completion(Duration::from_secs(30))
            .await
            .unwrap();
        assert_eq!(pending.purpose(), EnrollmentPurpose::RemoteOperator);
        assert_eq!(
            pending
                .confirm(
                    &builder.confirmation_code_for(EnrollmentPurpose::MainnetApproval),
                    Instant::now()
                )
                .unwrap_err(),
            OperatorEnrollmentConfirmationError::Mismatch
        );
        handle.shutdown().await.unwrap();
    }

    /// Without a terminal on stdin and stderr the command refuses before it
    /// loads a profile or starts a server.
    #[tokio::test(flavor = "current_thread")]
    async fn credential_enrollment_requires_a_terminal() {
        for streams in [(false, true), (true, false), (false, false)] {
            let _tty = crate::common::tty::tests::test_tty(streams.0, streams.1);
            let args =
                Wrap::try_parse_from(["prog", "--profile", "main", "--timeout-seconds", "1"])
                    .unwrap()
                    .args;
            crate::common::render::take_rendered_for_test();
            assert_eq!(run_enroll(args).await, 1);
            let rendered = crate::common::render::take_rendered_for_test();
            assert_eq!(rendered.len(), 1, "{rendered:?}");
            assert_eq!(rendered[0]["error"]["code"], TTY_REQUIRED.0, "{streams:?}");
            assert_eq!(rendered[0]["error"]["message"], TTY_REQUIRED.1);
        }
    }

    /// A missing profile, a testnet profile and an unsafe name refuse with
    /// the profile code before a server starts.
    #[tokio::test(flavor = "current_thread")]
    #[serial_test::serial]
    async fn credential_enrollment_requires_a_persisted_mainnet_profile() {
        use stellar_agent_core::profile::schema::Profile;
        let home = tempfile::tempdir().unwrap();
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(home.path());
        let _tty = crate::common::tty::tests::test_tty(true, true);
        let testnet = Profile::builder_testnet_named("test", "s", "a", "n", "b").build();
        stellar_agent_core::profile::loader::save_to_dir(
            "test",
            &testnet,
            &home.path().join("profiles"),
        )
        .unwrap();
        for name in ["absent", "test", "../main"] {
            let args = Wrap::try_parse_from(["prog", "--profile", name])
                .unwrap()
                .args;
            crate::common::render::take_rendered_for_test();
            assert_eq!(run_enroll(args).await, 1, "{name}");
            let rendered = crate::common::render::take_rendered_for_test();
            assert_eq!(rendered.len(), 1, "{rendered:?}");
            assert_eq!(rendered[0]["error"]["code"], PROFILE_REQUIRED.0, "{name}");
            assert_eq!(
                rendered[0]["error"]["message"], PROFILE_REQUIRED.1,
                "{name}"
            );
        }
    }
}

#[cfg(test)]
#[path = "credential_signed_tests.rs"]
mod signed_tests;
