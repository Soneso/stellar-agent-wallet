//! Dedicated-user command entry points with isolated credentials and an empty audit log.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test assertions"
)]

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest as _, Sha256};
use std::io::Write as _;
use std::process::{Command, Stdio};
use std::sync::Arc;
use stellar_agent_core::approval::{
    PendingApprovalStore,
    mainnet_fixtures::{
        MainnetConsentFixture, SIGNED_CERT_SPKI_SHA256, SIGNED_ORIGIN, policy_body_with_origin,
    },
};
use stellar_agent_core::profile::schema::{mainnet_enablement_entry_ref, policy_pin_entry_ref};

#[allow(
    dead_code,
    reason = "Process capture also serves unit tests in the CLI binary."
)]
#[path = "../../src/common/test_support.rs"]
mod support;

const NAME: &str = "main";
const PROTECTION_KEY: [u8; 32] = [9; 32];

fn fixture() -> MainnetConsentFixture {
    let fixture = MainnetConsentFixture::new(NAME);
    let profile = fixture.profile();
    let entries = [
        profile.policy_owner_key_id.clone(),
        profile.attestation_key_id.clone(),
        mainnet_enablement_entry_ref(&profile.policy_window_state_key_id),
        policy_pin_entry_ref(&profile.policy_window_state_key_id),
    ];
    let values: Vec<_> = entries
        .iter()
        .map(|entry| {
            keyring_core::Entry::new(&entry.service, &entry.account)
                .unwrap()
                .get_password()
                .unwrap()
        })
        .collect();
    keyring_core::set_default_store(Arc::new(
        stellar_agent_headless_keyring::store::HeadlessStore::new(
            fixture.home().join("headless-keyring/store.keyring"),
            stellar_agent_headless_keyring::crypto::ProtectionMode::EnvKey(Arc::new(
                zeroize::Zeroizing::new(PROTECTION_KEY),
            )),
        ),
    ));
    for (entry, value) in entries.iter().zip(values) {
        keyring_core::Entry::new(&entry.service, &entry.account)
            .unwrap()
            .set_password(&value)
            .unwrap();
    }
    let key = &profile.audit_log_hash_chain_key_id;
    keyring_core::Entry::new(&key.service, &key.account)
        .unwrap()
        .set_password(&URL_SAFE_NO_PAD.encode([0xAB; 32]))
        .unwrap();
    std::fs::create_dir_all(fixture.audit_path().parent().unwrap()).unwrap();
    std::fs::write(fixture.audit_path(), "").unwrap();
    fixture
}

fn command(fixture: &MainnetConsentFixture) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_stellar-agent"));
    command
        .env("STELLAR_AGENT_HOME", fixture.home())
        .env("STELLAR_AGENT_KEYRING_BACKEND", "headless-env")
        .env(
            "STELLAR_AGENT_HEADLESS_KEYRING_KEY",
            URL_SAFE_NO_PAD.encode(PROTECTION_KEY),
        )
        .env("STELLAR_AGENT_TEST_PRESENCE_NO_BROWSER", "1")
        .env_remove("STELLAR_AGENT_PROFILE")
        .env_remove("DISPLAY")
        .env_remove("WAYLAND_DISPLAY");
    command
}

fn tree_hash(fixture: &MainnetConsentFixture) -> Vec<u8> {
    let mut hash = Sha256::new();
    for (path, bytes) in support::tree(fixture.home()) {
        let path = path.as_os_str().as_encoded_bytes();
        hash.update(path.len().to_le_bytes());
        hash.update(path);
        hash.update(bytes.len().to_le_bytes());
        hash.update(bytes);
    }
    hash.finalize().to_vec()
}

fn stdin_command(
    fixture: &MainnetConsentFixture,
    verb: &str,
    extra: &[&str],
    body: &str,
) -> (i32, serde_json::Value, String) {
    let mut child = command(fixture)
        .args(["profile", verb, "--profile", NAME])
        .args(extra)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(body.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    let json = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|_| panic!("stdout: {:?}; stderr: {stderr}", output.stdout));
    (output.status.code().unwrap(), json, stderr)
}

// A terminal for stdin and stderr preserves enrollment's real TTY check.
// Stdout stays a separate pipe. The serve process receives Ctrl-C after startup.
const TERMINAL_DRIVER: &str = r#"
import errno, json, os, pty, selectors, signal, subprocess, sys, time
master, slave = pty.openpty()
child = subprocess.Popen(sys.argv[1:], stdin=slave, stderr=slave, stdout=subprocess.PIPE)
os.close(slave)
selector = selectors.DefaultSelector()
selector.register(master, selectors.EVENT_READ, 'stderr')
selector.register(child.stdout, selectors.EVENT_READ, 'stdout')
streams = {'stderr': bytearray(), 'stdout': bytearray()}
deadline = time.monotonic() + 10
signaled = False
while selector.get_map():
    if time.monotonic() > deadline:
        child.terminate()
        child.wait()
        raise RuntimeError('ceremony did not finish: ' + repr(streams))
    for key, _ in selector.select(0.05):
        try:
            chunk = os.read(key.fd, 65536)
        except OSError as error:
            if error.errno != errno.EIO:
                raise
            chunk = b''
        if not chunk:
            selector.unregister(key.fileobj)
        else:
            streams[key.data].extend(chunk)
    if not signaled and b'Mainnet approval inbox listens' in streams['stderr']:
        time.sleep(0.1)
        child.send_signal(signal.SIGINT)
        signaled = True
os.close(master)
print(json.dumps({'code': child.wait(), **{k: v.decode() for k, v in streams.items()}}))
"#;

fn ceremony(fixture: &MainnetConsentFixture, args: &[&str]) -> serde_json::Value {
    let binary = command(fixture);
    let mut driver = Command::new("python3");
    driver
        .args(["-c", TERMINAL_DRIVER])
        .arg(binary.get_program())
        .args(args);
    for (key, value) in binary.get_envs() {
        if let Some(value) = value {
            driver.env(key, value);
        } else {
            driver.env_remove(key);
        }
    }
    let output = driver.output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn assert_ceremony(output: &serde_json::Value, exit: i32, code: Option<&str>) {
    let stdout = output["stdout"].as_str().unwrap();
    let stderr = output["stderr"].as_str().unwrap();
    assert_eq!(output["code"], exit, "{output}");
    let envelope: serde_json::Value = serde_json::from_str(stdout).unwrap();
    if let Some(code) = code {
        assert_eq!(envelope["error"]["code"], code, "{output}");
    } else {
        assert_eq!(envelope["ok"], true, "{output}");
    }
    support::assert_url_output(stdout, stderr);
}

#[test]
#[serial_test::serial]
fn serve_operator_flag_reaches_the_listener() {
    let fixture = fixture();
    let output = ceremony(
        &fixture,
        &["approve", "serve", "--profile", NAME, "--open-by-operator"],
    );
    assert!(
        !output["stderr"]
            .as_str()
            .unwrap()
            .contains("Browser launch attempted in test mode."),
        "no browser launch"
    );
    assert_ceremony(&output, 0, None);
}

#[test]
#[serial_test::serial]
fn enrollment_operator_flag_reaches_the_listener() {
    let fixture = fixture();
    let output = ceremony(
        &fixture,
        &[
            "approve",
            "credential",
            "enroll",
            "--profile",
            NAME,
            "--open-by-operator",
            "--timeout-seconds",
            "1",
        ],
    );
    assert!(
        !output["stderr"]
            .as_str()
            .unwrap()
            .contains("is opening in the browser")
    );
    assert!(
        !output["stderr"]
            .as_str()
            .unwrap()
            .contains("Browser launch attempted in test mode."),
        "no browser launch"
    );
    assert_ceremony(&output, 1, Some("approve.credential_enroll_expired"));
}

#[test]
#[serial_test::serial]
fn one_shot_operator_flag_reaches_the_listener() {
    let fixture = fixture();
    let entry = fixture.payment(5_000);
    let nonce = entry.approval_nonce.clone();
    let mut store = PendingApprovalStore::open(fixture.store_path()).unwrap();
    store
        .insert(entry, stellar_agent_core::timefmt::now_unix_ms().unwrap())
        .unwrap();
    drop(store);
    let output = ceremony(
        &fixture,
        &[
            "approve",
            "--id",
            &nonce,
            "--profile",
            NAME,
            "--open-by-operator",
        ],
    );
    // The Private path refuses before any browser launch.
    assert_ceremony(&output, 1, Some("approval.presence_expired"));
}

fn origin_body() -> String {
    let body = policy_body_with_origin(
        NAME,
        "rpc.example.invalid",
        1,
        &[],
        Some((SIGNED_ORIGIN, &SIGNED_CERT_SPKI_SHA256)),
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
fn policy_check_stdin_codes_and_tree() {
    let fixture = fixture();
    std::fs::write(fixture.policy_path(), "[").unwrap();
    let local = "version = 1\nscope = 'profile:main'\n[[rules]]\nmatch = { tool = 'stellar_balances', chain = '*' }\ncriteria = []\ndecision = 'allow'\n";
    for (body, origin, exit, signed) in [
        (local.to_owned(), false, 0, false),
        (
            local.replace("version = 1", "version = 2\nsequence = 1"),
            false,
            0,
            false,
        ),
        (
            format!("{local}\n[signature]\nstale = true\n"),
            false,
            0,
            false,
        ),
        (origin_body(), false, 0, true),
        (origin_body(), true, 3, true),
        ("[".into(), false, 65, false),
        (format!("unknown = true\n{local}"), true, 65, false),
        (
            local.replace("profile:main", "profile:foreign"),
            false,
            65,
            false,
        ),
    ] {
        let before = tree_hash(&fixture);
        let (code, envelope, stderr) = stdin_command(
            &fixture,
            "policy-check",
            if origin { &["--origin"] } else { &[] },
            &body,
        );
        assert_eq!(code, exit, "{envelope} {stderr}");
        if exit == 65 {
            let error = stellar_agent_core::policy::v1::validate_unsigned_policy(
                &body,
                NAME,
                &fixture.profile().network_passphrase,
            )
            .unwrap_err();
            assert_eq!(envelope["error"]["code"], error.wire_code());
        } else {
            assert_eq!(envelope["ok"], true);
            assert_eq!(
                envelope["data"],
                serde_json::json!({"valid": true, "signed_origin": signed})
            );
        }
        assert_eq!(
            tree_hash(&fixture),
            before,
            "policy-check leaves the tree byte-identical"
        );
    }
}

#[test]
#[serial_test::serial]
fn apply_fragment_stdin_applies_and_refuses() {
    let fixture = fixture();
    let (code, envelope, stderr) = stdin_command(
        &fixture,
        "apply-fragment",
        &[],
        "oracle_provider_url = 'https://oracle.example.invalid'\n\
         [providers.primary]\noperator = 'primary'\nhost = 'rpc.example.invalid'\n\
         [providers.oracle]\noperator = 'oracle'\nhost = 'oracle.example.invalid'\n\
         independent_of_primary = true\n",
    );
    assert_eq!(code, 0, "{envelope} {stderr}");
    assert_eq!(envelope["data"]["applied"], true);
    assert_eq!(stderr, "credential-roles:\n");
    let profile = std::fs::read_to_string(fixture.home().join("profiles/main.toml")).unwrap();
    assert!(profile.contains("https://oracle.example.invalid"));
    let before = tree_hash(&fixture);
    let (code, envelope, stderr) =
        stdin_command(&fixture, "apply-fragment", &[], "rpc_url = 'protected'");
    assert_eq!(code, 65);
    assert_eq!(envelope["error"]["code"], "profile.fragment_key_refused");
    assert_eq!(stderr, "refused: profile.fragment_key_refused\n");
    assert_eq!(
        tree_hash(&fixture),
        before,
        "refused fragment leaves the tree byte-identical"
    );
}

#[test]
#[serial_test::serial]
fn signed_origin_refuses_every_operator_form_before_effects() {
    let mut fixture = fixture();
    fixture.sign_signed_origin_policy(
        &[&stellar_agent_test_support::webauthn::fixture_authenticator()],
        &SIGNED_CERT_SPKI_SHA256,
    );
    let signed = std::fs::read_to_string(fixture.policy_path()).unwrap();
    for body in [origin_body(), signed] {
        std::fs::write(fixture.policy_path(), body).unwrap();
        let before = tree_hash(&fixture);
        for args in [
            vec!["approve", "serve", "--profile", NAME, "--open-by-operator"],
            vec![
                "approve",
                "credential",
                "enroll",
                "--profile",
                NAME,
                "--open-by-operator",
            ],
            vec![
                "approve",
                "--id",
                "pending",
                "--profile",
                NAME,
                "--open-by-operator",
            ],
        ] {
            let output = ceremony(&fixture, &args);
            assert_eq!(output["code"], 1, "{output}");
            let envelope: serde_json::Value =
                serde_json::from_str(output["stdout"].as_str().unwrap()).unwrap();
            assert_eq!(envelope["error"]["code"], "approval.origin_signed_remote");
            assert!(
                !output["stderr"].as_str().unwrap().contains("http://"),
                "{output}"
            );
            assert!(
                !output["stderr"]
                    .as_str()
                    .unwrap()
                    .contains("Create the passkey"),
                "{output}"
            );
            assert_eq!(
                tree_hash(&fixture),
                before,
                "guard precedes ceremony effects: {args:?}"
            );
        }
    }
}
