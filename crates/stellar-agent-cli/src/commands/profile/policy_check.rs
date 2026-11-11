//! Unsigned policy validation and the operator-open origin guard.

use std::io::Read as _;

use clap::Args;
use stellar_agent_core::envelope::Envelope;
use stellar_agent_core::policy::PolicyError;
use stellar_agent_core::policy::v1::{
    approval_origin::validate_bootstrap, validate_unsigned_policy,
};
use stellar_agent_core::profile::{loader::default_policy_dir, schema::Profile};

use crate::common::profile_access::{load_profile_reconciled, profile_access_envelope};
use crate::common::render::render_json;
use crate::common::resolve_profile_name;

const INPUT_UNAVAILABLE: (&str, &str) = (
    "profile.policy_input_unavailable",
    "The policy body cannot be read.",
);
const MAINNET_REQUIRED: (&str, &str) = (
    "approve.operator_open_mainnet_required",
    "Operator-open requires a mainnet profile.",
);
const INVALID_BODY: &str = "The policy body fails unsigned validation.";

/// Arguments for `profile policy-check`.
#[derive(Debug, Args)]
pub struct PolicyCheckArgs {
    /// The persisted profile whose name and network govern validation.
    #[arg(long, value_name = "NAME")]
    pub profile: String,
    /// Exit 3 when the valid body declares an approval origin.
    #[arg(long)]
    pub origin: bool,
}

/// The unsigned body's local approval classification.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Classification {
    LocalOnly,
    SignedOrigin,
    Invalid(&'static str),
}

/// Validates the body and its bootstrap origin/pin pair without reading authority.
pub(crate) fn classify(body: &str, name: &str, passphrase: &str) -> Classification {
    let doc = match body.parse::<toml_edit::DocumentMut>() {
        Ok(doc) => doc,
        Err(e) => return Classification::Invalid(PolicyError::toml_syntax(body, &e).wire_code()),
    };
    if let Err(error) = validate_unsigned_policy(body, name, passphrase) {
        return Classification::Invalid(error.wire_code());
    }
    let Some(table) = doc.get("mainnet").and_then(toml_edit::Item::as_table_like) else {
        return Classification::LocalOnly;
    };
    match validate_bootstrap(table) {
        Ok((Some(_), _)) => Classification::SignedOrigin,
        Ok((None, _)) => Classification::LocalOnly,
        Err(error) => Classification::Invalid(error.wire_code()),
    }
}

fn report(body: &str, args: &PolicyCheckArgs, profile: &Profile) -> i32 {
    match classify(body, &args.profile, &profile.network_passphrase) {
        Classification::Invalid(code) => {
            render_json(&Envelope::<()>::err_raw(code, INVALID_BODY));
            65
        }
        classification => {
            let signed_origin = classification == Classification::SignedOrigin;
            render_json(&Envelope::ok(
                serde_json::json!({"valid": true, "signed_origin": signed_origin}),
            ));
            if args.origin && signed_origin { 3 } else { 0 }
        }
    }
}

/// Reads and validates standard input, returning 0, 3, 65, or 1 for access errors.
pub fn run(args: &PolicyCheckArgs) -> i32 {
    let profile = match load_profile_reconciled(&resolve_profile_name(Some(&args.profile))) {
        Ok(profile) => profile,
        Err(error) => {
            render_json(&profile_access_envelope(&error));
            return 1;
        }
    };
    let mut body = String::new();
    if std::io::stdin().read_to_string(&mut body).is_err() {
        render_json(&Envelope::<()>::err_raw(
            INPUT_UNAVAILABLE.0,
            INPUT_UNAVAILABLE.1,
        ));
        return 1;
    }
    report(&body, args, &profile)
}

/// Refuses operator-open before any ceremony resource is acquired.
pub(crate) fn guard_operator_open(name: &str, profile: &Profile) -> Result<(), Envelope<()>> {
    if !profile.chain_id.is_mainnet() {
        return Err(Envelope::err_raw(MAINNET_REQUIRED.0, MAINNET_REQUIRED.1));
    }
    let path = default_policy_dir()
        .map_err(|_| Envelope::err_raw(INPUT_UNAVAILABLE.0, INPUT_UNAVAILABLE.1))?
        .join(format!("{name}.toml"));
    let body = match std::fs::read_to_string(path) {
        Ok(body) => body,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(Envelope::err_raw(INPUT_UNAVAILABLE.0, INPUT_UNAVAILABLE.1)),
    };
    match classify(&body, name, &profile.network_passphrase) {
        Classification::LocalOnly => Ok(()),
        Classification::SignedOrigin => {
            Err(Envelope::err(&stellar_agent_core::WalletError::Approval(
                stellar_agent_core::ApprovalFailure::OriginSignedRemote,
            )))
        }
        Classification::Invalid(code) => Err(Envelope::err_raw(code, INVALID_BODY)),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test assertions"
    )]
    use super::*;
    use crate::common::render::take_rendered_for_test;
    use crate::common::test_support::{capture, tree};
    use clap::Parser;
    use stellar_agent_core::approval::mainnet_fixtures::{
        MainnetConsentFixture, SIGNED_CERT_SPKI_SHA256, SIGNED_ORIGIN, policy_body_with_origin,
    };

    fn body(origin: bool) -> String {
        let body = policy_body_with_origin(
            "main",
            "rpc.example.invalid",
            1,
            &[],
            origin.then_some((SIGNED_ORIGIN, &SIGNED_CERT_SPKI_SHA256)),
        );
        let mut doc: toml_edit::DocumentMut = body.parse().unwrap();
        doc["mainnet"]
            .as_table_mut()
            .unwrap()
            .remove("approval_credentials");
        doc.to_string()
    }

    #[test]
    #[serial_test::serial]
    fn policy_check_exit_codes() {
        let home = tempfile::tempdir().unwrap();
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(home.path());
        let profile = Profile::builder_testnet_named("main", "s", "a", "n", "b").build();
        let v1 = "version = 1\nscope = \"profile:main\"\n[[rules]]\nmatch = { tool = \"stellar_balances\", chain = \"*\" }\ncriteria = []\ndecision = \"allow\"\n";
        let v2 = v1.replace("version = 1", "version = 2\nsequence = 1");
        for valid in [
            v1.to_owned(),
            v2,
            format!("{v1}\n[signature]\nstale = true\n"),
        ] {
            take_rendered_for_test();
            assert_eq!(
                report(
                    &valid,
                    &PolicyCheckArgs {
                        profile: "main".into(),
                        origin: false
                    },
                    &profile
                ),
                0
            );
            assert_eq!(take_rendered_for_test()[0]["ok"], true);
        }
        for invalid in [
            "[".to_owned(),
            format!("unknown = true\n{v1}"),
            v1.replace("profile:main", "profile:foreign"),
        ] {
            let code = validate_unsigned_policy(&invalid, "main", &profile.network_passphrase)
                .unwrap_err()
                .wire_code();
            take_rendered_for_test();
            assert_eq!(
                report(
                    &invalid,
                    &PolicyCheckArgs {
                        profile: "main".into(),
                        origin: false
                    },
                    &profile
                ),
                65
            );
            assert_eq!(take_rendered_for_test()[0]["error"]["code"], code);
        }
    }

    #[test]
    #[serial_test::serial]
    fn policy_check_origin_classification() {
        let mut fixture = MainnetConsentFixture::new("main");
        fixture.sign_signed_origin_policy(
            &[&stellar_agent_test_support::webauthn::fixture_authenticator()],
            &SIGNED_CERT_SPKI_SHA256,
        );
        let signed = std::fs::read_to_string(fixture.policy_path()).unwrap();
        for (text, exit) in [
            (body(false), 0),
            (body(true), 3),
            (signed, 3),
            ("[".into(), 65),
        ] {
            assert_eq!(
                report(
                    &text,
                    &PolicyCheckArgs {
                        profile: "main".into(),
                        origin: true
                    },
                    fixture.profile()
                ),
                exit
            );
        }
        for key in ["approval_origin", "approval_cert_spki_sha256"] {
            let unpaired = body(true)
                .lines()
                .filter(|line| !line.starts_with(&format!("{key} =")))
                .collect::<Vec<_>>()
                .join("\n");
            for origin in [false, true] {
                assert_eq!(
                    report(
                        &unpaired,
                        &PolicyCheckArgs {
                            profile: "main".into(),
                            origin
                        },
                        fixture.profile()
                    ),
                    65
                );
            }
        }
    }

    async fn native(args: &[&str]) -> (i32, serde_json::Value) {
        let cli = crate::Cli::try_parse_from(
            std::iter::once("stellar-agent").chain(args.iter().copied()),
        )
        .unwrap();
        let crate::Commands::Approve(args) = cli.command else {
            panic!("approval command")
        };
        take_rendered_for_test();
        let exit = crate::commands::approve::dispatch(args).await;
        let rendered = take_rendered_for_test();
        assert_eq!(rendered.len(), 1, "{rendered:?}");
        (exit, rendered[0].clone())
    }

    const MODES: [&[&str]; 3] = [
        &[
            "approve",
            "serve",
            "--profile",
            "main",
            "--open-by-operator",
        ],
        &[
            "approve",
            "credential",
            "enroll",
            "--profile",
            "main",
            "--open-by-operator",
        ],
        &[
            "approve",
            "--id",
            "pending",
            "--profile",
            "main",
            "--open-by-operator",
        ],
    ];

    async fn assert_guard(body: &str, code: &str, fixture: &MainnetConsentFixture) {
        std::fs::write(fixture.policy_path(), body).unwrap();
        let before = tree(fixture.home());
        for args in MODES {
            let (exit, envelope) = native(args).await;
            assert_eq!(exit, 1);
            assert_eq!(envelope["error"]["code"], code, "{args:?}: {envelope}");
            assert_eq!(
                tree(fixture.home()),
                before,
                "no ceremony file changes: {args:?}"
            );
        }
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn native_open_by_operator_refused_under_signed_origin() {
        if let Some((stdout, stderr)) =
            capture("native_open_by_operator_refused_under_signed_origin")
        {
            assert!(!stdout.contains("http://") && !stderr.contains("http://"));
            assert!(
                !stderr.contains("Create the passkey"),
                "guard precedes enrollment startup: {stderr}"
            );
            return;
        }
        let _tty = crate::common::tty::tests::test_tty(true, true);
        let mut fixture = MainnetConsentFixture::new("main");
        fixture.sign_signed_origin_policy(
            &[&stellar_agent_test_support::webauthn::fixture_authenticator()],
            &SIGNED_CERT_SPKI_SHA256,
        );
        let signed = std::fs::read_to_string(fixture.policy_path()).unwrap();
        assert_guard(&body(true), "approval.origin_signed_remote", &fixture).await;
        assert_guard(&signed, "approval.origin_signed_remote", &fixture).await;
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn native_guard_refuses_an_invalid_installed_body() {
        let _tty = crate::common::tty::tests::test_tty(true, true);
        let fixture = MainnetConsentFixture::new("main");
        assert_guard("[", "policy.policy_file_parse_failed", &fixture).await;
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn native_guard_passes_a_missing_installed_body() {
        let _tty = crate::common::tty::tests::test_tty(true, true);
        let fixture = MainnetConsentFixture::new("main");
        std::fs::rename(
            fixture.policy_path(),
            fixture.home().join("saved-policy.toml"),
        )
        .unwrap();
        assert!(guard_operator_open("main", fixture.profile()).is_ok());
        for args in [MODES[0], MODES[2]] {
            let (exit, envelope) = native(args).await;
            assert_eq!(exit, 1);
            assert_ne!(envelope["error"]["code"], "approval.origin_signed_remote");
            assert_ne!(
                envelope["error"]["code"],
                "approval.presence_browser_required"
            );
        }
        let mut args = MODES[1].to_vec();
        args.extend(["--timeout-seconds", "1"]);
        let (exit, envelope) = native(&args).await;
        assert_eq!(exit, 1);
        assert_eq!(
            envelope["error"]["code"],
            "approve.credential_enroll_expired"
        );
    }

    #[test]
    fn operator_open_flag_conflicts() {
        for args in [
            vec!["approve", "serve", "--open-by-operator", "--remote"],
            vec!["approve", "serve", "--open-by-operator", "--no-open"],
            vec!["approve", "--open-by-operator", "--yes"],
        ] {
            assert!(
                crate::Cli::try_parse_from(std::iter::once("stellar-agent").chain(args)).is_err()
            );
        }
        let profile = Profile::builder_testnet_named("main", "s", "a", "n", "b").build();
        assert_eq!(
            guard_operator_open("main", &profile)
                .unwrap_err()
                .error
                .unwrap()
                .code,
            MAINNET_REQUIRED.0
        );
    }
}
