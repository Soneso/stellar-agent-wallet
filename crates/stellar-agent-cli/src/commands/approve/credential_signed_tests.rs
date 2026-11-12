//! Signed-origin enrollment tests of `approve credential enroll`.
//!
//! The rows run the command against a real HTTPS listener with a pinned
//! test leaf, a software registrar for the signed RP, and an in-memory
//! keyring. The loopback guards stay in the module's own test module.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics acceptable in unit tests"
)]

use clap::Parser as _;
use stellar_agent_approval_remote::signed_origin_test_leaf as pinned_leaf;
use stellar_agent_approval_remote::test_helpers::PinnedLeaf;
use stellar_agent_approval_ui::operator_enroll::EnrollmentPurpose;
use stellar_agent_approval_ui::operator_enroll::test_support::{
    EnrollmentClient, SoftwareRegistrar, signed_origin_request,
};
use stellar_agent_core::approval::mainnet_fixtures::{
    ENDPOINT_HOST, MainnetConsentFixture, SIGNED_CERT_SPKI_SHA256, SIGNED_RP_ID,
    policy_body_with_origin,
};

use super::tests::{Typing, Wrap};
use super::*;
use crate::common::test_support::tree;

/// A signed origin with a nondefault public port.
const SIGNED_NONDEFAULT: &str = "https://approve.example.invalid:8443";
/// The same host at the default port.
const SIGNED_DEFAULT: &str = "https://approve.example.invalid";

/// A mainnet profile `main` with an enabled `[remote_approval]` table on
/// a free loopback socket and a pinned leaf for the signed host. Its
/// installed signed policy carries an origin pin that conflicts with the leaf.
struct SignedSetup {
    fixture: MainnetConsentFixture,
    leaf: PinnedLeaf,
    files: tempfile::TempDir,
    bind: std::net::SocketAddr,
    origin: String,
}

impl SignedSetup {
    fn new(origin: &str) -> Self {
        let files = tempfile::tempdir().unwrap();
        let leaf = pinned_leaf(SIGNED_RP_ID);
        let cert = files.path().join("cert.pem");
        let key = files.path().join("key.pem");
        std::fs::write(&cert, leaf.chain_pem()).unwrap();
        std::fs::write(&key, &leaf.key_pem).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let bind = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let mut fixture = MainnetConsentFixture::with_profile("main", |profile| {
            profile.remote_approval = Some(
                serde_json::from_value(serde_json::json!({
                    "enabled": true, "bind": bind.to_string(), "rp_id": SIGNED_RP_ID,
                    "cert_path": cert, "key_path": key,
                }))
                .unwrap(),
            );
        });
        fixture.sign_signed_origin_policy(
            &[&stellar_agent_test_support::webauthn::fixture_authenticator()],
            &SIGNED_CERT_SPKI_SHA256,
        );
        Self {
            fixture,
            leaf,
            files,
            bind,
            origin: origin.to_owned(),
        }
    }

    /// The unsigned, credential-free bootstrap body with this setup's
    /// origin and leaf pin.
    fn body(&self) -> String {
        let body = policy_body_with_origin(
            "main",
            ENDPOINT_HOST,
            self.fixture.sequence() + 1,
            &[],
            Some((&self.origin, &self.leaf.pin)),
        );
        let mut doc: toml_edit::DocumentMut = body.parse().unwrap();
        doc["mainnet"]
            .as_table_mut()
            .unwrap()
            .remove("approval_credentials");
        doc.to_string()
    }

    fn write_body(&self, text: &str) -> std::path::PathBuf {
        let path = self.files.path().join("bootstrap.toml");
        std::fs::write(&path, text).unwrap();
        path
    }

    fn args(&self, path: &std::path::Path, extra: &[&str]) -> EnrollApprovalCredentialArgs {
        let path = path.to_str().unwrap();
        let mut argv = vec!["prog", "--profile", "main", "--origin-from", path];
        argv.extend_from_slice(extra);
        Wrap::try_parse_from(argv).unwrap().args
    }

    fn edit_remote(&self, edit: impl FnOnce(&mut serde_json::Value)) {
        let loaded = stellar_agent_core::profile::loader::load_from_dir(
            "main",
            &self.fixture.home().join("profiles"),
            None,
        )
        .unwrap();
        let mut profile = serde_json::to_value(loaded).unwrap();
        edit(&mut profile["remote_approval"]);
        let profile: stellar_agent_core::profile::schema::Profile =
            serde_json::from_value(profile).unwrap();
        stellar_agent_core::profile::loader::save_to_dir(
            "main",
            &profile,
            &self.fixture.home().join("profiles"),
        )
        .unwrap();
    }

    fn socket_is_free(&self) -> bool {
        std::net::TcpListener::bind(self.bind).is_ok()
    }

    async fn request(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: Option<&str>,
    ) -> stellar_agent_approval_ui::operator_enroll::test_support::HttpReply {
        signed_origin_request(
            self.bind,
            &self.origin,
            &self.leaf.cert_pem,
            method,
            path,
            headers,
            body,
        )
        .await
        .unwrap()
    }
}

/// What the browser side of a signed run does once the code is printed.
#[derive(Clone, Copy, Debug)]
enum Browser {
    /// Opens the session, registers, then `Typing` happens at the prompt.
    Register(Typing),
    /// Opens the session, registers, then the operator interrupts.
    Interrupt,
    /// Sends substituted `Host`, `Origin` and forwarded headers first,
    /// then registers and types the page's code.
    Substitute,
    /// Posts five wrong codes, then the right one.
    Exhaust,
    /// Does nothing.
    Idle,
}

/// The observable result of one signed run.
struct SignedRun {
    exit: i32,
    rendered: Vec<serde_json::Value>,
    logs: String,
    code: Option<String>,
    page_code: Option<String>,
    registrar: SoftwareRegistrar,
}

/// Runs `run` under a debug-level tracing capture on this thread and
/// returns its output, the envelopes it renders and the captured log
/// text.
async fn capture_enroll_output<T>(
    run: impl Future<Output = T>,
) -> (T, Vec<serde_json::Value>, String) {
    let capture = stellar_agent_test_support::log_capture::CaptureWriter::new();
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_max_level(tracing::Level::DEBUG)
        .with_writer(capture.clone())
        .finish();
    let _inert = stellar_agent_test_support::log_capture::inert_dispatcher();
    let _subscriber = tracing::subscriber::set_default(subscriber);
    tracing::callsite::rebuild_interest_cache();
    crate::common::render::take_rendered_for_test();
    let output = run.await;
    let rendered = crate::common::render::take_rendered_for_test();
    (output, rendered, capture.captured_str())
}

/// One `approve credential enroll --origin-from` run through
/// [`super::run_enroll`], with `browser` driving the HTTPS listener.
async fn signed_run(
    setup: &SignedSetup,
    args: EnrollApprovalCredentialArgs,
    browser: Browser,
) -> SignedRun {
    let (code_tx, code_rx) = tokio::sync::oneshot::channel::<String>();
    let (typed_tx, typed_rx) = tokio::sync::oneshot::channel::<io::Result<Option<String>>>();
    let (interrupt_tx, interrupt_rx) = tokio::sync::oneshot::channel::<()>();
    let on_code = move |code: &str| {
        print_enrollment_code(code);
        let _ = code_tx.send(code.to_owned());
    };
    let interrupt = async move {
        if interrupt_rx.await.is_ok() {
            Ok(())
        } else {
            std::future::pending().await
        }
    };
    let read_code = move || async move {
        match typed_rx.await {
            Ok(typed) => typed,
            Err(_) => std::future::pending().await,
        }
    };
    let registrar = SoftwareRegistrar::new([0x21; 32], vec![0x5a; 20]).with_rp_id(SIGNED_RP_ID);
    let driver = {
        let registrar = &registrar;
        async move {
            let code = code_rx.await.ok()?;
            let page_code = match browser {
                Browser::Idle => None,
                Browser::Exhaust => {
                    let wrong = if code.starts_with('0') { "1" } else { "0" };
                    let wrong = format!("{wrong}{}", &code[1..]);
                    for (attempt, sent) in [&wrong, &wrong, &wrong, &wrong, &wrong, &code]
                        .into_iter()
                        .enumerate()
                    {
                        let reply = setup
                            .request(
                                "POST",
                                "/enroll/code",
                                &[
                                    ("origin", setup.origin.as_str()),
                                    ("content-type", "application/json"),
                                ],
                                Some(&serde_json::json!({ "code": sent }).to_string()),
                            )
                            .await;
                        assert_eq!(reply.status, 403, "attempt {attempt}");
                        assert!(reply.set_cookie.is_none());
                    }
                    None
                }
                Browser::Register(_) | Browser::Interrupt | Browser::Substitute => {
                    let substitute = matches!(browser, Browser::Substitute);
                    if substitute {
                        substitute_headers(setup).await;
                    }
                    // Forwarded headers name a foreign authority and
                    // scheme on every request of the registration.
                    let forwarded: &[(&str, &str)] = if substitute {
                        &[
                            ("x-forwarded-host", "foreign.example:9443"),
                            ("x-forwarded-proto", "http"),
                            ("forwarded", "host=foreign.example:9443;proto=http"),
                        ]
                    } else {
                        &[]
                    };
                    let client = EnrollmentClient::connect_signed_with_headers(
                        setup.bind,
                        &setup.origin,
                        &setup.leaf.cert_pem,
                        &code,
                        forwarded,
                    )
                    .await
                    .unwrap();
                    if substitute {
                        assert_eq!(client.page_rp_id(), Some(SIGNED_RP_ID), "page rpId");
                        let options = client.challenge().await.unwrap().json();
                        assert_eq!(options["rp_id"], SIGNED_RP_ID, "challenge rp_id");
                    }
                    let (reply, builder) =
                        client.register_response(registrar, "laptop").await.unwrap();
                    assert_eq!(reply.status, 200, "{reply:?}");
                    let page_code =
                        builder.confirmation_code_for(EnrollmentPurpose::MainnetApproval);
                    let typed = match browser {
                        Browser::Register(Typing::PageCode) | Browser::Substitute => {
                            Some(Ok(Some(page_code.clone())))
                        }
                        Browser::Register(Typing::OtherCode) => {
                            let mut other = page_code.clone().into_bytes();
                            other[0] = if other[0] == b'0' { b'1' } else { b'0' };
                            Some(Ok(Some(String::from_utf8(other).unwrap())))
                        }
                        Browser::Register(Typing::EndOfInput) => Some(Ok(None)),
                        Browser::Interrupt => {
                            let _ = interrupt_tx.send(());
                            None
                        }
                        _ => None,
                    };
                    if let Some(typed) = typed {
                        let _ = typed_tx.send(typed);
                    }
                    Some(page_code)
                }
            };
            Some((code, page_code))
        }
    };
    let ((exit, driven), rendered, logs) = tokio::time::timeout(
        Duration::from_secs(60),
        capture_enroll_output(async {
            tokio::join!(
                super::run_enroll(args, on_code, interrupt, read_code),
                driver
            )
        }),
    )
    .await
    .expect("the signed run ends");
    assert!(setup.socket_is_free(), "the listener is released");
    let (code, page_code) = driven.map_or((None, None), |(code, page)| (Some(code), page));
    SignedRun {
        exit,
        rendered,
        logs,
        code,
        page_code,
        registrar,
    }
}

/// A foreign `Host` answers 421, a foreign `Origin` 403, and forwarded
/// headers leave the page at the body's origin.
async fn substitute_headers(setup: &SignedSetup) {
    let host = format!("{SIGNED_RP_ID}:{}", setup.bind.port());
    let foreign = setup
        .request("GET", "/enroll", &[("host", &host)], None)
        .await;
    assert_eq!(foreign.status, 421);
    let posted = setup
        .request(
            "POST",
            "/enroll/code",
            &[
                ("origin", "https://foreign.example"),
                ("content-type", "application/json"),
            ],
            Some(r#"{"code":"00000000"}"#),
        )
        .await;
    assert_eq!(posted.status, 403);
    let page = setup
        .request(
            "GET",
            "/enroll",
            &[
                ("x-forwarded-host", "foreign.example"),
                ("forwarded", "host=foreign.example;proto=http"),
            ],
            None,
        )
        .await;
    assert_eq!(page.status, 200);
    assert!(
        page.body
            .contains(&format!("<code>{}</code>", setup.origin)),
        "{}",
        page.body
    );
}

/// One refused signed run: exit 1, one envelope with `code`, no code
/// handed out and the configured socket free. Returns the envelope.
async fn refused(
    setup: &SignedSetup,
    args: EnrollApprovalCredentialArgs,
    code: &str,
) -> serde_json::Value {
    let run = signed_run(setup, args, Browser::Idle).await;
    assert_eq!(run.exit, 1);
    assert_eq!(run.rendered.len(), 1, "{:?}", run.rendered);
    assert_eq!(
        run.rendered[0]["error"]["code"], code,
        "{}",
        run.rendered[0]
    );
    assert!(run.code.is_none(), "no code before a refusal");
    run.rendered[0].clone()
}

/// The RP and the origin come from the body. The profile `rp_id` equals
/// the body host and the public and bind ports differ. Both the default
/// and a nondefault public port work. A foreign `Host` or
/// `Origin` refuses and forwarded headers change nothing; the challenge
/// RP, the page RP, the expected origin and the exported RP are the
/// body's.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn origin_from_takes_rp_and_origin_from_the_body() {
    let _tty = crate::common::tty::tests::test_tty(true, true);
    for origin in [SIGNED_NONDEFAULT, SIGNED_DEFAULT] {
        let setup = SignedSetup::new(origin);
        assert_ne!(setup.bind.port(), 8443);
        assert_ne!(setup.bind.port(), 443);
        let path = setup.write_body(&setup.body());
        let run = signed_run(&setup, setup.args(&path, &[]), Browser::Substitute).await;
        assert_eq!(run.exit, 0, "{:?}", run.rendered);
        let data = &run.rendered[0]["data"];
        assert_eq!(data["rp_id"], SIGNED_RP_ID);
        assert_eq!(
            data["credential_id_b64url"],
            run.registrar.credential_id_b64url()
        );
    }
}

/// Unsigned, credential-free bodies pass beside a conflicting installed
/// signed policy. A lone origin or pin keeps the minimum refusal and its
/// pairing requirement. An uppercase host and an unknown key keep the
/// parse refusal, and an unreadable file keeps the load refusal. A body
/// without both keys refuses with the origin code. All refuse before the bind.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn origin_from_validates_the_body_without_signature_or_credentials() {
    let _tty = crate::common::tty::tests::test_tty(true, true);
    let setup = SignedSetup::new(SIGNED_NONDEFAULT);
    let installed = std::fs::read_to_string(setup.fixture.policy_path()).unwrap();
    assert!(installed.contains("[signature]"));
    assert!(installed.contains(&stellar_agent_core::hex::encode(&SIGNED_CERT_SPKI_SHA256)));
    let body = setup.body();
    assert!(!body.contains("approval_credentials") && !body.contains("[signature]"));
    let path = setup.write_body(&body);
    let run = signed_run(
        &setup,
        setup.args(&path, &[]),
        Browser::Register(Typing::PageCode),
    )
    .await;
    assert_eq!(run.exit, 0, "{:?}", run.rendered);

    let without = |key: &str| {
        body.lines()
            .filter(|line| !line.starts_with(&format!("{key} =")))
            .collect::<Vec<_>>()
            .join("\n")
    };
    for (text, code, detail) in [
        (
            without("approval_cert_spki_sha256"),
            "policy.mainnet_minimum_unmet",
            Some("approval.origin_without_cert_pin"),
        ),
        (
            without("approval_origin"),
            "policy.mainnet_minimum_unmet",
            Some("approval.cert_pin_without_origin"),
        ),
        (
            body.replace("https://approve.example", "https://APPROVE.example"),
            "policy.policy_file_parse_failed",
            None,
        ),
        (
            body.replace("[mainnet]\n", "[mainnet]\nunknown_key = 1\n"),
            "policy.policy_file_parse_failed",
            None,
        ),
        (
            format!("unknown_key = 1\n{body}"),
            "policy.policy_file_parse_failed",
            None,
        ),
        (
            without("approval_origin")
                .lines()
                .filter(|line| !line.starts_with("approval_cert_spki_sha256 ="))
                .collect::<Vec<_>>()
                .join("\n"),
            ORIGIN_MISSING.0,
            Some(ORIGIN_MISSING.1),
        ),
    ] {
        let path = setup.write_body(&text);
        let envelope = refused(&setup, setup.args(&path, &[]), code).await;
        if let Some(detail) = detail {
            assert!(
                envelope["error"]["message"]
                    .as_str()
                    .unwrap()
                    .contains(detail),
                "{envelope}"
            );
        }
    }
    let missing = setup.files.path().join("absent.toml");
    refused(
        &setup,
        setup.args(&missing, &[]),
        "policy.policy_file_load_failed",
    )
    .await;
}

/// Every TLS file problem renders through the listener's shared TLS
/// mapping, and the top-level code names the field. No default file is
/// generated and nothing binds, also while the socket is held.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn signed_enrollment_refuses_missing_pem_without_fallback() {
    let _tty = crate::common::tty::tests::test_tty(true, true);
    for field in ["cert_path", "key_path"] {
        for problem in ["absent", "missing", "unreadable", "malformed", "mismatched"] {
            if problem == "mismatched" && field == "cert_path" {
                continue;
            }
            let setup = SignedSetup::new(SIGNED_NONDEFAULT);
            let path = setup.write_body(&setup.body());
            setup.edit_remote(|remote| match problem {
                "absent" => {
                    remote.as_object_mut().unwrap().remove(field);
                }
                "missing" => remote[field] = serde_json::json!(setup.files.path().join("none.pem")),
                "unreadable" => remote[field] = serde_json::json!(setup.files.path()),
                "mismatched" => {
                    let other = pinned_leaf(SIGNED_RP_ID);
                    std::fs::write(setup.files.path().join("key.pem"), other.key_pem).unwrap();
                }
                _ => {
                    let file = if field == "cert_path" {
                        "cert.pem"
                    } else {
                        "key.pem"
                    };
                    std::fs::write(setup.files.path().join(file), "bad PEM").unwrap();
                }
            });
            for held in [false, true] {
                let socket = held.then(|| std::net::TcpListener::bind(setup.bind).unwrap());
                let run = signed_run_held(&setup, setup.args(&path, &[])).await;
                assert_eq!(run.exit, 1);
                let error = &run.rendered[0]["error"];
                assert_eq!(
                    error["code"], "approve.remote_tls_unavailable",
                    "{problem} {field}: {error}"
                );
                assert!(
                    error["message"].as_str().unwrap().contains(field),
                    "{error}"
                );
                assert!(run.code.is_none());
                drop(socket);
                assert!(setup.socket_is_free());
            }
            let (cert, key) = stellar_agent_approval_remote::tls::tls_file_paths("main").unwrap();
            assert!(
                !cert.exists() && !key.exists(),
                "no certificate is generated"
            );
        }
    }
}

/// [`signed_run`] for a refusal that may happen while the test holds the
/// configured socket, so the release check is the caller's.
async fn signed_run_held(setup: &SignedSetup, args: EnrollApprovalCredentialArgs) -> SignedRun {
    let (code_tx, code_rx) = tokio::sync::oneshot::channel::<String>();
    let on_code = move |code: &str| {
        let _ = code_tx.send(code.to_owned());
    };
    let ((exit, code), rendered, logs) = capture_enroll_output(async {
        let exit = super::run_enroll(args, on_code, std::future::pending(), || async {
            panic!("no prompt after a startup refusal")
        })
        .await;
        (exit, code_rx.await.ok())
    })
    .await;
    let _ = setup;
    SignedRun {
        exit,
        rendered,
        logs,
        code,
        page_code: None,
        registrar: SoftwareRegistrar::new([0x21; 32], vec![0x5a; 20]),
    }
}

/// The URL is the signed origin and `/enroll` with no code or token, and
/// the listener mounts no bootstrap route.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn origin_from_enrollment_url_carries_no_secret() {
    let setup = SignedSetup::new(SIGNED_NONDEFAULT);
    let path = setup.write_body(&setup.body());
    let (origin, pin) =
        signed_origin_from(&path, "main", &setup.fixture.profile().network_passphrase).unwrap();
    let config = SignedEnrollmentConfig::new(
        "main",
        setup.fixture.profile().clone(),
        origin,
        pin,
        Duration::from_secs(300),
    );
    let handle = start_signed_enrollment(config, |_| {}).await.unwrap();
    let url = EnrollCeremony::enroll_url(&handle);
    assert_eq!(url, format!("{SIGNED_NONDEFAULT}/enroll"));
    assert!(!url.contains(handle.enrollment_code()));
    assert!(!url.contains("bootstrap") && !url.contains('?') && !url.contains('#'));
    let bootstrap = setup
        .request("GET", &format!("/bootstrap/{}", "ab".repeat(32)), &[], None)
        .await;
    assert_eq!(bootstrap.status, 404);
    let posted = setup
        .request(
            "POST",
            &format!("/bootstrap/{}", "ab".repeat(32)),
            &[("origin", SIGNED_NONDEFAULT)],
            None,
        )
        .await;
    assert_eq!(posted.status, 404, "no bootstrap route is mounted");
    handle.shutdown().await.unwrap();
}

/// The sixth code attempt ends the run with the exhaustion code; expiry
/// ends it with the deadline code. Both release the listener and leave
/// files and keyring unchanged.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn origin_from_code_exhaustion_ends_without_export() {
    let _tty = crate::common::tty::tests::test_tty(true, true);
    let setup = SignedSetup::new(SIGNED_NONDEFAULT);
    let path = setup.write_body(&setup.body());
    let before = tree(setup.fixture.home());
    let keyring = stellar_agent_test_support::keyring_mock::record_mutations().unwrap();
    let run = signed_run(&setup, setup.args(&path, &[]), Browser::Exhaust).await;
    assert_eq!(run.exit, 1);
    assert_eq!(run.rendered[0]["error"]["code"], CODE_EXHAUSTED.0);
    assert_eq!(run.rendered[0]["error"]["message"], CODE_EXHAUSTED.1);
    let run = signed_run(
        &setup,
        setup.args(&path, &["--timeout-seconds", "1"]),
        Browser::Idle,
    )
    .await;
    assert_eq!(run.exit, 1);
    assert_eq!(run.rendered[0]["error"]["code"], EXPIRED.0);
    assert_eq!(tree(setup.fixture.home()), before);
    assert_eq!(keyring.mutations(), [], "no keyring write or deletion");
}

/// Another code, end of input, an interrupt and the deadline export
/// nothing. The page's code exports exactly the envelope fields and the
/// registrar's credential. Files and keyring stay unchanged.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn origin_from_exports_only_after_matching_code() {
    let _tty = crate::common::tty::tests::test_tty(true, true);
    let setup = SignedSetup::new(SIGNED_NONDEFAULT);
    let path = setup.write_body(&setup.body());
    let before = tree(setup.fixture.home());
    let keyring = stellar_agent_test_support::keyring_mock::record_mutations().unwrap();
    for (browser, timeout, expected) in [
        (
            Browser::Register(Typing::OtherCode),
            "30",
            CONFIRMATION_MISMATCH,
        ),
        (Browser::Register(Typing::EndOfInput), "30", CANCELED),
        (Browser::Interrupt, "30", CANCELED),
        (Browser::Register(Typing::Nothing), "3", EXPIRED),
    ] {
        let run = signed_run(
            &setup,
            setup.args(&path, &["--timeout-seconds", timeout]),
            browser,
        )
        .await;
        assert_eq!(run.exit, 1, "{browser:?}");
        assert_eq!(run.rendered.len(), 1);
        assert_eq!(run.rendered[0]["error"]["code"], expected.0, "{browser:?}");
        assert!(
            run.rendered[0]
                .get("data")
                .is_none_or(serde_json::Value::is_null)
        );
        assert_eq!(tree(setup.fixture.home()), before);
    }
    let run = signed_run(
        &setup,
        setup.args(&path, &[]),
        Browser::Register(Typing::PageCode),
    )
    .await;
    assert_eq!(run.exit, 0, "{:?}", run.rendered);
    let data = run.rendered[0]["data"].as_object().unwrap();
    let keys: std::collections::BTreeSet<&str> = data.keys().map(String::as_str).collect();
    assert_eq!(
        keys,
        [
            "profile",
            "rp_id",
            "credential_id_b64url",
            "public_key_sec1_b64url",
            "credential_fingerprint",
            "policy_entry_toml"
        ]
        .into_iter()
        .collect()
    );
    assert_eq!(data["profile"], "main");
    assert_eq!(data["rp_id"], SIGNED_RP_ID);
    assert_eq!(
        data["credential_id_b64url"],
        run.registrar.credential_id_b64url()
    );
    let credential = MainnetApprovalCredential::from_encoded(
        data["credential_id_b64url"].as_str().unwrap(),
        data["public_key_sec1_b64url"].as_str().unwrap(),
    )
    .unwrap();
    assert_eq!(
        credential.public_key_sec1(),
        &run.registrar.public_key_sec1()
    );
    assert_eq!(data["policy_entry_toml"], credential.policy_entry_toml());
    assert!(!run.rendered[0].to_string().contains("laptop"));
    assert_eq!(tree(setup.fixture.home()), before);
    assert_eq!(keyring.mutations(), [], "no keyring write or deletion");
}

/// The exported entry, added to a signed-origin policy and signed by the
/// owner, loads through the verified policy loader with the same
/// credential and fingerprint.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn origin_from_export_round_trips_through_the_signed_origin_loader() {
    let _tty = crate::common::tty::tests::test_tty(true, true);
    let setup = SignedSetup::new(SIGNED_NONDEFAULT);
    let path = setup.write_body(&setup.body());
    let run = signed_run(
        &setup,
        setup.args(&path, &[]),
        Browser::Register(Typing::PageCode),
    )
    .await;
    assert_eq!(run.exit, 0, "{:?}", run.rendered);
    let data = &run.rendered[0]["data"];
    let entry = data["policy_entry_toml"].as_str().unwrap();
    assert!(
        !entry.contains("label") && !entry.contains("laptop"),
        "{entry}"
    );
    let fixture_credential = stellar_agent_test_support::webauthn::fixture_authenticator();
    let fixture_entry = format!(
        "{{ credential_id_b64url = \"{}\", public_key_sec1_b64url = \"{}\" }}",
        fixture_credential.credential_id_b64url(),
        fixture_credential.public_key_sec1_b64url()
    );
    let body = policy_body_with_origin(
        "main",
        ENDPOINT_HOST,
        setup.fixture.sequence() + 1,
        &[&fixture_credential],
        Some((SIGNED_NONDEFAULT, &setup.leaf.pin)),
    )
    .replace(&fixture_entry, entry);
    assert!(body.contains(entry));
    setup.fixture.write_signed(&body);
    let policy = setup.fixture.current_policy();
    let mainnet = policy.mainnet().unwrap();
    assert_eq!(
        mainnet.approval_origin.as_ref().unwrap().as_str(),
        SIGNED_NONDEFAULT
    );
    assert_eq!(mainnet.approval_credentials.len(), 1);
    assert_eq!(
        mainnet.approval_credentials[0].credential_id(),
        run.registrar.credential_id()
    );
    assert_eq!(
        mainnet.approval_credentials[0].fingerprint(),
        data["credential_fingerprint"]
    );
}

/// Without a display the signed mode exports without an opener or a
/// private handoff; without a terminal it refuses before the bind.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn origin_from_needs_no_display_or_opener_and_requires_a_terminal() {
    use crate::common::test_support::capture;
    if let Some((stdout, stderr)) =
        capture("origin_from_needs_no_display_or_opener_and_requires_a_terminal")
    {
        assert!(!stderr.contains("Browser launch attempted"), "{stderr}");
        assert!(stdout.contains("\"ok\":true"), "{stdout}");
        return;
    }
    assert!(std::env::var_os("DISPLAY").is_none() && std::env::var_os("WAYLAND_DISPLAY").is_none());
    let setup = SignedSetup::new(SIGNED_NONDEFAULT);
    let path = setup.write_body(&setup.body());
    for streams in [(false, true), (true, false)] {
        let _tty = crate::common::tty::tests::test_tty(streams.0, streams.1);
        let run = signed_run(&setup, setup.args(&path, &[]), Browser::Idle).await;
        assert_eq!(run.exit, 1);
        assert_eq!(run.rendered[0]["error"]["code"], TTY_REQUIRED.0);
        assert!(run.code.is_none());
    }
    let _tty = crate::common::tty::tests::test_tty(true, true);
    let run = signed_run(
        &setup,
        setup.args(&path, &[]),
        Browser::Register(Typing::PageCode),
    )
    .await;
    assert_eq!(run.exit, 0, "{:?}", run.rendered);
    assert!(!run.logs.contains("browser did not open"), "{}", run.logs);
}

/// A profile RP that is not the body host, a held socket, and an absent
/// or disabled configuration refuse with their existing codes, and no
/// enrollment listener stays bound.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn origin_from_refuses_before_bind_with_existing_codes() {
    let _tty = crate::common::tty::tests::test_tty(true, true);
    let setup = SignedSetup::new(SIGNED_NONDEFAULT);
    let path = setup.write_body(&setup.body());
    setup.edit_remote(|remote| remote["rp_id"] = serde_json::json!("other.example.invalid"));
    refused(
        &setup,
        setup.args(&path, &[]),
        "approval.origin_profile_mismatch",
    )
    .await;
    setup.edit_remote(|remote| remote["rp_id"] = serde_json::json!(SIGNED_RP_ID));

    let held = std::net::TcpListener::bind(setup.bind).unwrap();
    let run = signed_run_held(&setup, setup.args(&path, &[])).await;
    assert_eq!(run.rendered[0]["error"]["code"], "approval.listener_busy");
    assert!(run.code.is_none());
    drop(held);
    assert!(setup.socket_is_free());

    setup.edit_remote(|remote| remote["enabled"] = serde_json::json!(false));
    let envelope = refused(&setup, setup.args(&path, &[]), "internal.unexpected_state").await;
    assert!(
        envelope["error"]["message"]
            .as_str()
            .unwrap()
            .contains("approve.remote_not_configured")
    );
    setup.edit_remote(|remote| *remote = serde_json::Value::Null);
    let envelope = refused(&setup, setup.args(&path, &[]), "internal.unexpected_state").await;
    assert!(
        envelope["error"]["message"]
            .as_str()
            .unwrap()
            .contains("approve.remote_not_configured")
    );
}

/// Every public page that documents signed-origin enrollment covers the
/// topics that apply to it. They are the unsigned bootstrap body, the
/// explicit TLS paths, device certificate trust and both codes. They also
/// include the timeout, the terminal confirmation, the export and the
/// provisioning tier.
#[test]
fn signed_enrollment_docs_cover_bootstrap_and_both_codes() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let refusals = [CODE_EXHAUSTED.0, ORIGIN_MISSING.0];
    let cases: &[(&str, &[&str])] = &[
        (
            "docs/cli-reference/profile-and-governance.md",
            &[
                "--origin-from <PATH>",
                "unsigned bootstrap policy body",
                "checks no signature",
                "`cert_path` and `key_path`",
                "never generates a certificate",
                "installed private CA",
                "eight-digit enrollment code",
                "admits five attempts",
                "at most 600 seconds",
                "confirmation code, which you type at the terminal",
                "`rp_id` set to the signed host",
                "provisioning-tier step",
                CODE_EXHAUSTED.1,
                ORIGIN_MISSING.1,
            ],
        ),
        (
            "docs/profiles.md",
            &[
                "--origin-from <unsigned body>",
                "unsigned bootstrap body",
                "explicit `[remote_approval]` paths",
                "must trust the certificate",
                "enrollment code",
                "confirmation code at the terminal",
                "provisioning tier",
            ],
        ),
        (
            "docs/dedicated-user.md",
            &[
                "--origin-from <installed policy file>",
                "provisioning tier",
                "unsigned bootstrap body without a signature check",
                "explicit TLS paths",
                "installed private CA",
                "enrollment code",
                "confirmation code at the terminal before the timeout",
                "only that exports the entry",
            ],
        ),
        (
            "docs/remote-approval.md",
            &[
                "serves no `/enroll` page",
                "unsigned policy body",
                "needs no signature",
                "`cert_path` and `key_path`",
                "must already trust the certificate",
                "eight-digit enrollment code",
                "at most ten minutes",
                "confirmation code at the terminal before the timeout",
                "exports the credential entry",
                "provisioning tier",
            ],
        ),
        (
            "skills/stellar-agent-wallet/references/cli-reference.md",
            &[
                "--origin-from <PATH>",
                "unsigned bootstrap policy body",
                "checks no signature",
                "`cert_path` and `key_path`",
                "never generates a certificate",
                "installed private CA",
                "eight-digit enrollment code",
                "at most 600 seconds",
                "confirmation code still goes to the terminal",
                "`rp_id` set to the signed host",
                "provisioning-tier step",
                CODE_EXHAUSTED.0,
                ORIGIN_MISSING.0,
            ],
        ),
        (
            "skills/stellar-agent-wallet/references/profiles-and-keys.md",
            &[
                "--origin-from <unsigned body>",
                "unsigned bootstrap body",
                "must trust the certificate",
                "enrollment code",
                "confirmation code at the terminal",
                "provisioning tier",
            ],
        ),
        (
            "skills/stellar-agent-wallet/references/troubleshooting.md",
            &[CODE_EXHAUSTED.0, ORIGIN_MISSING.0, "--origin-from"],
        ),
        (
            "CHANGELOG.md",
            &[
                "approve credential enroll --origin-from <PATH>",
                "unsigned bootstrap policy body",
                "enrollment code",
                "confirmation code",
            ],
        ),
    ];
    for (file, required) in cases {
        let text = std::fs::read_to_string(root.join(file)).unwrap();
        for needle in *required {
            assert!(text.contains(needle), "{file} lacks {needle:?}");
        }
        assert!(
            !text.contains("enrollment is a runtime") && !text.contains("runtime-tier enrollment"),
            "{file} classifies enrollment as runtime"
        );
    }
    let governance =
        std::fs::read_to_string(root.join("docs/cli-reference/profile-and-governance.md")).unwrap();
    for code in refusals {
        assert!(governance.contains(&format!("| `{code}` |")), "{code} row");
    }
}

/// `--origin-from` and `--open-by-operator` conflict at parse time, so
/// nothing runs and no URL appears.
#[test]
fn origin_from_conflicts_with_open_by_operator() {
    crate::common::render::take_rendered_for_test();
    let error = Wrap::try_parse_from([
        "prog",
        "--profile",
        "main",
        "--origin-from",
        "body.toml",
        "--open-by-operator",
    ])
    .unwrap_err();
    assert_eq!(error.kind(), clap::error::ErrorKind::ArgumentConflict);
    assert!(!error.to_string().contains("https://"));
    assert!(crate::common::render::take_rendered_for_test().is_empty());
}

/// A key file looser than `0600` keeps its permission refusal through the
/// listener's mapping; nothing binds or exports.
#[cfg(unix)]
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn signed_enrollment_keeps_key_permission_refusal() {
    use std::os::unix::fs::PermissionsExt as _;
    let _tty = crate::common::tty::tests::test_tty(true, true);
    let setup = SignedSetup::new(SIGNED_NONDEFAULT);
    let path = setup.write_body(&setup.body());
    std::fs::set_permissions(
        setup.files.path().join("key.pem"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    let envelope = refused(&setup, setup.args(&path, &[]), "internal.unexpected_state").await;
    let message = envelope["error"]["message"].as_str().unwrap();
    assert!(
        message.contains("approve.remote_tls_provision_failed"),
        "{message}"
    );
    assert!(message.contains("644"), "{message}");
}

/// The wrapper's exact argument order parses, and its default timeout
/// gives the code a 300-second lifetime.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn origin_from_accepts_wrapper_argv() {
    let cli = crate::Cli::try_parse_from([
        "stellar-agent",
        "approve",
        "credential",
        "enroll",
        "--origin-from",
        "policy/body.toml",
        "--profile",
        "mainnet",
    ])
    .unwrap();
    let crate::Commands::Approve(approve) = cli.command else {
        panic!("approve command");
    };
    let Some(crate::commands::approve::ApproveSubcommand::Credential(credential)) =
        approve.subcommand
    else {
        panic!("credential subcommand");
    };
    let CredentialSubcommand::Enroll(args) = credential.subcommand;
    assert_eq!(args.profile, "mainnet");
    assert_eq!(
        args.origin_from.as_deref(),
        Some(std::path::Path::new("policy/body.toml"))
    );
    assert!(!args.open_by_operator);
    assert_eq!(args.timeout_seconds, 300);

    let setup = SignedSetup::new(SIGNED_NONDEFAULT);
    let path = setup.write_body(&setup.body());
    let (origin, pin) =
        signed_origin_from(&path, "main", &setup.fixture.profile().network_passphrase).unwrap();
    let handle = start_signed_enrollment(
        SignedEnrollmentConfig::new(
            "main",
            setup.fixture.profile().clone(),
            origin,
            pin,
            Duration::from_secs(args.timeout_seconds),
        ),
        |_| {},
    )
    .await
    .unwrap();
    assert_eq!(handle.code_lifetime(), Duration::from_secs(300));
    handle.shutdown().await.unwrap();
}

/// The number of signed ceremonies the child of
/// `origin_from_prints_the_code_once_and_logs_it_nowhere` runs.
const CODE_SECRECY_RUNS: usize = 6;

/// Each signed ceremony prints its URL line and its code once on stderr.
/// The export and every refusal (expiry, cancellation, exhaustion,
/// mismatch and unavailability) keep the code out of stdout, the
/// envelope and debug tracing. The handle's `Debug` output carries no
/// code either.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn origin_from_prints_the_code_once_and_logs_it_nowhere() {
    use crate::common::test_support::capture;
    if let Some((stdout, stderr)) = capture("origin_from_prints_the_code_once_and_logs_it_nowhere")
    {
        // A prompt without a trailing newline may precede a code line, so
        // the codes are read after each marker, not at line starts.
        let codes: Vec<&str> = stderr
            .split("Enrollment code: ")
            .skip(1)
            .map(|rest| &rest[..8])
            .collect();
        assert_eq!(codes.len(), CODE_SECRECY_RUNS, "{stderr}");
        for code in &codes {
            assert_eq!(code.len(), 8);
            assert_eq!(stderr.matches(code).count(), 1, "{code}: {stderr}");
            assert!(!stdout.contains(code), "{code}: {stdout}");
        }
        let url_line = format!("Open this URL in your browser: {SIGNED_NONDEFAULT}/enroll\n");
        assert_eq!(
            stderr.matches(&url_line).count(),
            CODE_SECRECY_RUNS,
            "{stderr}"
        );
        assert_eq!(
            stderr.matches("Open this URL in your browser: ").count(),
            CODE_SECRECY_RUNS,
            "{stderr}"
        );
        let envelopes: Vec<_> = stdout
            .lines()
            .filter(|line| line.starts_with('{'))
            .collect();
        assert_eq!(envelopes.len(), CODE_SECRECY_RUNS, "{stdout}");
        assert_eq!(
            envelopes
                .iter()
                .filter(|line| line.contains("\"ok\":true"))
                .count(),
            1,
            "{stdout}"
        );
        return;
    }
    let _tty = crate::common::tty::tests::test_tty(true, true);
    let setup = SignedSetup::new(SIGNED_NONDEFAULT);
    let path = setup.write_body(&setup.body());
    let mut runs = Vec::new();
    for (browser, timeout, expected) in [
        (Browser::Register(Typing::PageCode), "300", None),
        (Browser::Idle, "1", Some(EXPIRED.0)),
        (Browser::Interrupt, "300", Some(CANCELED.0)),
        (Browser::Exhaust, "300", Some(CODE_EXHAUSTED.0)),
        (
            Browser::Register(Typing::OtherCode),
            "300",
            Some(CONFIRMATION_MISMATCH.0),
        ),
    ] {
        let run = signed_run(
            &setup,
            setup.args(&path, &["--timeout-seconds", timeout]),
            browser,
        )
        .await;
        runs.push((format!("{browser:?}"), expected, run));
    }
    runs.push((
        "unavailable".to_owned(),
        Some(UNAVAILABLE.0),
        unavailable_run(&setup, &path).await,
    ));
    assert_eq!(runs.len(), CODE_SECRECY_RUNS);
    for (name, expected, run) in &runs {
        let code = run.code.as_deref().unwrap();
        assert_eq!(run.rendered.len(), 1, "{name}: {:?}", run.rendered);
        let envelope = &run.rendered[0];
        match expected {
            None => assert_eq!(envelope["ok"], true, "{name}: {envelope}"),
            Some(expected) => {
                assert_eq!(envelope["error"]["code"], *expected, "{name}: {envelope}");
            }
        }
        assert!(!envelope.to_string().contains(code), "{name}: {envelope}");
        assert!(
            run.logs
                .contains("signed-origin enrollment listener started"),
            "{name}: {}",
            run.logs
        );
        assert!(!run.logs.contains(code), "{name}: {}", run.logs);
        if name.starts_with("Register") {
            assert!(run.page_code.is_some(), "{name}: the page showed a code");
        }
    }
}

/// One signed ceremony whose server stops after the code exchange, so the
/// shared ceremony loop ends unavailable. The handle's `Debug` output is
/// checked for the code before the ceremony starts.
async fn unavailable_run(setup: &SignedSetup, path: &std::path::Path) -> SignedRun {
    let (origin, pin) =
        signed_origin_from(path, "main", &setup.fixture.profile().network_passphrase).unwrap();
    let config = SignedEnrollmentConfig::new(
        "main",
        setup.fixture.profile().clone(),
        origin,
        pin,
        Duration::from_secs(30),
    );
    let (code_tx, code_rx) = tokio::sync::oneshot::channel::<String>();
    let ((exit, code), rendered, logs) = capture_enroll_output(async {
        let handle = start_signed_enrollment(config, |code| {
            print_enrollment_code(code);
            let _ = code_tx.send(code.to_owned());
        })
        .await
        .unwrap();
        assert!(!format!("{handle:?}").contains(handle.enrollment_code()));
        let stop = handle.stop_trigger();
        let code = code_rx.await.unwrap();
        let driver = async {
            EnrollmentClient::connect_signed(
                setup.bind,
                &setup.origin,
                &setup.leaf.cert_pem,
                &code,
            )
            .await
            .unwrap();
            stop();
        };
        let (end, ()) = tokio::join!(
            enroll_until_done(
                handle,
                crate::common::mainnet_presence::OpenMode::Operator,
                refuse_opener,
                Duration::from_secs(30),
                std::future::pending(),
                std::future::pending::<io::Result<Option<String>>>,
            ),
            driver
        );
        assert!(matches!(end, EnrollmentEnd::Unavailable), "{end:?}");
        (report(end, "main", SIGNED_RP_ID), code)
    })
    .await;
    assert_eq!(exit, 1);
    assert!(setup.socket_is_free(), "the stopped listener is released");
    SignedRun {
        exit,
        rendered,
        logs,
        code: Some(code),
        page_code: None,
        registrar: SoftwareRegistrar::new([0x21; 32], vec![0x5a; 20]),
    }
}
