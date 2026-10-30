//! `stellar-agent approve credential enroll`: enrolls a WebAuthn approval
//! credential for the owner-signed mainnet policy.
//!
//! The command runs the loopback registration ceremony of
//! `stellar_agent_approval_ui::operator_enroll` for
//! `EnrollmentPurpose::MainnetApproval`: a one-shot server on
//! `127.0.0.1`, the page at `http://localhost:<port>`, a credential bound to
//! `rp_id: "localhost"` created over the server's challenge, and a
//! confirmation code the page computes from that credential under the
//! mainnet approval domain. The bearer URL reaches the browser only through
//! [`private_open::open_private`]; it is never printed, and a launch failure
//! refuses with `approval.presence_browser_required`.
//!
//! After the operator types the page's code at this terminal before the
//! deadline, the command prints one success envelope with the credential ID,
//! the P-256 public key, its fingerprint and the inline-table entry for
//! `mainnet.approval_credentials`. It writes nothing: no profile, policy,
//! keyring entry or operator credential store changes, and the label stays
//! on the page. The credential approves mainnet consent only after the owner
//! adds the entry to the policy and signs it with `profile sign-policy`.
//!
//! The profile must be a persisted mainnet profile; neither an enabled
//! installation nor an existing mainnet policy is required, so a credential
//! can be enrolled before the owner writes the policy that lists it.

use std::io;
use std::time::{Duration, Instant};

use clap::{Args, Subcommand};
use serde::Serialize;

use stellar_agent_approval_ui::operator_enroll::{
    OperatorEnrollAwaitError, OperatorEnrollHandle, OperatorEnrollmentConfirmationError,
    start_mainnet_approval_enroll,
};
use stellar_agent_core::approval::{MAINNET_APPROVAL_RP_ID, MainnetApprovalCredential};
use stellar_agent_core::envelope::Envelope;
use stellar_agent_core::error::{ApprovalFailure, WalletError};
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
    /// Runs a local browser ceremony and prints the credential's entry for
    /// `mainnet.approval_credentials` after you type the code the page
    /// shows. Writes nothing: the credential approves mainnet consent only
    /// after the owner adds the entry and signs the policy.
    Enroll(EnrollApprovalCredentialArgs),
}

/// Arguments for `stellar-agent approve credential enroll`.
#[derive(Debug, Args)]
#[non_exhaustive]
pub struct EnrollApprovalCredentialArgs {
    /// The persisted mainnet profile the credential is for.
    #[arg(long = "profile", value_name = "NAME")]
    pub profile: String,

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
        CredentialSubcommand::Enroll(args) => run_enroll(args).await,
    }
}

fn refuse((code, message): (&str, &str)) -> i32 {
    render_json(&Envelope::<()>::err_raw(code, message));
    1
}

async fn run_enroll(args: EnrollApprovalCredentialArgs) -> i32 {
    // The confirmation code is typed at this terminal; without one the
    // ceremony could never be confirmed, so nothing starts.
    if !stdin_and_stderr_are_terminals() {
        return refuse(TTY_REQUIRED);
    }
    if validate_path_component_ascii_safe(&args.profile).is_err() {
        return refuse(PROFILE_REQUIRED);
    }
    let resolved = ResolvedProfileName::from_flag(args.profile.clone());
    let page_identity = match load_profile_reconciled(&resolved) {
        Ok(profile) if profile.chain_id.is_mainnet() => page_identity_for(&profile),
        Ok(_) => return refuse(PROFILE_REQUIRED),
        Err(error) if error.requires_refusal() => {
            render_json(&Envelope::<()>::err(&error.to_wallet_error(&args.profile)));
            return 1;
        }
        Err(_) => return refuse(PROFILE_REQUIRED),
    };
    if !display_available() {
        return report(EnrollmentEnd::BrowserRequired, &args.profile);
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
            tracing::debug!(error = %error, "approval credential enrollment did not start");
            return refuse(UNAVAILABLE);
        }
    };
    print_startup(&args.profile);
    let end = enroll_until_done(
        handle,
        private_open::browser_opener,
        Duration::from_secs(args.timeout_seconds),
        tokio::signal::ctrl_c(),
        || read_line_from_terminal("operator-enroll-code"),
    )
    .await;
    report(end, &args.profile)
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
    /// The server failed, or the confirmed credential has no policy form.
    Unavailable,
}

/// Opens the started ceremony in the browser through a private redirect
/// file, waits for a verified registration, then asks for the page's code.
///
/// `opener` receives only the redirect file's URL; when it fails the server
/// stops and nothing else happens. One deadline, `timeout` after the open,
/// bounds the registration wait and the prompt. The server stops and the
/// redirect file and its directory are removed as soon as the browser phase
/// ends. `interrupt` is watched across both phases, and `read_code` runs
/// only once a registration is staged.
async fn enroll_until_done<Code>(
    mut handle: OperatorEnrollHandle,
    opener: impl FnOnce(&str) -> io::Result<()>,
    timeout: Duration,
    interrupt: impl Future<Output = io::Result<()>>,
    read_code: impl FnOnce() -> Code,
) -> EnrollmentEnd
where
    Code: Future<Output = io::Result<Option<String>>>,
{
    let handoff = match private_open::open_private(&handle.enroll_url(), opener) {
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
    if let Err(error) = handoff.close() {
        tracing::debug!(
            error.kind = ?error.kind(),
            "approval credential enrollment: redirect file cleanup failed"
        );
    }
    let pending = match staged {
        Some(Ok(pending)) => pending,
        Some(Err(OperatorEnrollAwaitError::Timeout)) => return EnrollmentEnd::Expired,
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
async fn stop(handle: OperatorEnrollHandle) {
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
    rp_id: &'static str,
    credential_id_b64url: String,
    public_key_sec1_b64url: String,
    credential_fingerprint: String,
    policy_entry_toml: String,
}

/// Renders how the enrollment ended and returns the exit code.
fn report(end: EnrollmentEnd, profile: &str) -> i32 {
    match end {
        EnrollmentEnd::Exported(credential) => {
            render_json(&Envelope::ok(EnrolledCredential {
                profile: profile.to_owned(),
                rp_id: MAINNET_APPROVAL_RP_ID,
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
        EnrollmentEnd::Unavailable => refuse(UNAVAILABLE),
    }
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
fn print_startup(profile: &str) {
    eprintln!("{}", startup_notice(profile));
}

#[allow(
    clippy::print_stderr,
    reason = "CLI binary intentional guidance; stdout stays JSON-only"
)]
fn print_note(note: &str) {
    eprintln!("{note}");
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only; panics acceptable in unit tests"
    )]
    use std::path::{Path, PathBuf};

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

    #[derive(Debug, Parser)]
    struct Wrap {
        #[command(flatten)]
        args: EnrollApprovalCredentialArgs,
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
    #[derive(Clone, Copy)]
    enum Typing {
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
            probe.opener(Ok(())),
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
        let file = probe.redirect_file();
        assert!(!probe.launched()[0].contains(&token));
        assert!(!url.is_empty());
        assert!(!file.exists() && !file.parent().unwrap().exists());
        (end, registrar, code_rx.await.unwrap())
    }

    /// Every path under `root` with its bytes, sorted.
    fn tree(root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
        fn walk(root: &Path, dir: &Path, out: &mut Vec<(PathBuf, Vec<u8>)>) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    out.push((path.strip_prefix(root).unwrap().to_path_buf(), Vec::new()));
                    walk(root, &path, out);
                } else {
                    let bytes = std::fs::read(&path).unwrap();
                    out.push((path.strip_prefix(root).unwrap().to_path_buf(), bytes));
                }
            }
        }
        let mut out = Vec::new();
        walk(root, root, &mut out);
        out.sort();
        out
    }

    /// The rendered envelope of `end`, with the exit code.
    fn rendered(end: EnrollmentEnd) -> (i32, serde_json::Value) {
        crate::common::render::take_rendered_for_test();
        let code = report(end, "main");
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
