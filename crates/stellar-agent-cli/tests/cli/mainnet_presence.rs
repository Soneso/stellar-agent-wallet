//! Mainnet stdin input cannot authorize consent: with the owner-signed
//! policy in place, a mainnet approval reaches the browser boundary, and
//! without a browser it refuses whatever stdin carries.
//!
//! The binary runs with [`NO_BROWSER_ENV`], which a `test-helpers` build
//! reads as an unavailable local browser, so no run launches one.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test assertions"
)]

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serial_test::serial;
use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;
use stellar_agent_core::{
    approval::{
        DEFAULT_TTL_MS, PendingApproval, PendingApprovalStore,
        mainnet_fixtures::{ENABLEMENT_NONCE, policy_body_for, signed_policy_text},
        process_uid_for_attestation,
    },
    policy::v1::{
        PolicyStateStore,
        verified::{OwnerKeySource, PinMode, PolicyLoad, load_verified_policy},
    },
    profile::{
        loader::save_new_to_dir,
        schema::{
            KeyringEntryRef, Profile, default_policy_window_state_path_for,
            mainnet_enablement_entry_ref,
        },
    },
};
use stellar_xdr::{
    Asset, Limits, Memo, MuxedAccount, Operation, OperationBody, PaymentOp, Preconditions,
    SequenceNumber, Transaction, TransactionEnvelope, TransactionExt, TransactionV1Envelope,
    Uint256, VecM, WriteXdr,
};

#[test]
#[serial]
fn mainnet_remote_refusal_precedes_invalid_or_unreadable_policy() {
    let dir = tempfile::tempdir().unwrap();
    mainnet_home(dir.path());
    let command = || {
        let output = Command::new(env!("CARGO_BIN_EXE_stellar-agent"))
            .args([
                "approve",
                "serve",
                "--profile",
                NAME,
                "--remote",
                "--confirm-remote-exposure",
            ])
            .env("STELLAR_AGENT_HOME", dir.path())
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        let text = String::from_utf8(output.stdout).unwrap();
        let envelope: serde_json::Value = serde_json::from_str(&text).unwrap();
        (
            text.replace(envelope["request_id"].as_str().unwrap(), "request-id"),
            String::from_utf8(output.stderr).unwrap(),
        )
    };
    let expected = command();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&expected.0).unwrap()["error"]["code"],
        "approval.mainnet_remote_unsupported"
    );
    let policies = dir.path().join("policies");
    std::fs::write(policies.join(format!("{NAME}.toml")), "invalid = [").unwrap();
    let invalid = command();
    assert_eq!(invalid.0, expected.0);
    assert_eq!(invalid.1, expected.1);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&policies, std::fs::Permissions::from_mode(0o000)).unwrap();
        let unreadable = command();
        std::fs::set_permissions(&policies, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(unreadable.0, expected.0);
        assert_eq!(unreadable.1, expected.1);
    }
}

const NAME: &str = "presence-mainnet";
const SIGNER: &str = "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY";
const PROTECTION_KEY: [u8; 32] = [9; 32];

/// The seed of the owner who signs the presence policy.
const OWNER_SEED: [u8; 32] = [11; 32];

/// The variable a `test-helpers` build reads as an unavailable local
/// browser.
pub(crate) const NO_BROWSER_ENV: &str = "STELLAR_AGENT_TEST_PRESENCE_NO_BROWSER";

/// The variable that makes a `test-helpers` build report its bound remote endpoint.
/// The release build never reads it.
#[cfg(all(unix, feature = "test-helpers"))]
const TEST_REMOTE_READY_ENV: &str = "STELLAR_AGENT_TEST_REMOTE_READY";

/// Enables the saved mainnet profile `profile` named `name` under `home` as
/// the enablement ceremony leaves it, in the keyring store the caller
/// installed: the owner key, the window-state key, the policy the presence
/// listener tests sign, admitting the test-support fixture approval
/// credential and signed by [`OWNER_SEED`], its pin, and the installation
/// nonce.
pub(crate) fn sign_presence_policy(home: &Path, name: &str, profile: &Profile) {
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(home);
    let owner = ed25519_dalek::SigningKey::from_bytes(&OWNER_SEED);
    let put = |entry: &KeyringEntryRef, value: &str| {
        keyring_core::Entry::new(&entry.service, &entry.account)
            .unwrap()
            .set_password(value)
            .unwrap();
    };
    put(
        &profile.policy_owner_key_id,
        &stellar_strkey::ed25519::PublicKey(owner.verifying_key().to_bytes()).to_string(),
    );
    stellar_agent_network::keyring::rotate_keyring_secret_32(
        &profile.policy_window_state_key_id.service,
        &profile.policy_window_state_key_id.account,
    )
    .unwrap();
    let host =
        stellar_agent_core::mainnet::enablement::normalize_endpoint_host(&profile.rpc_url).unwrap();
    let body = policy_body_for(
        name,
        &host,
        1,
        &[&stellar_agent_test_support::webauthn::fixture_authenticator()],
    );
    let path = home.join("policies").join(format!("{name}.toml"));
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, signed_policy_text(&body, &owner)).unwrap();
    let window = default_policy_window_state_path_for(name);
    std::fs::create_dir_all(window.parent().unwrap()).unwrap();
    load_verified_policy(
        &PolicyLoad {
            path: &path,
            profile,
            profile_name: name,
            owner_pubkey: &owner.verifying_key().to_bytes(),
            owner_source: OwnerKeySource::Keyring,
            window_path: &window,
        },
        PolicyStateStore::new(),
        PinMode::Advance,
    )
    .expect("the signed presence policy loads and pins");
    put(
        &mainnet_enablement_entry_ref(&profile.policy_window_state_key_id),
        ENABLEMENT_NONCE,
    );
}

/// A mainnet profile with its attestation and audit keys in a headless
/// keyring under `home`, its owner-signed presence policy, and one pending
/// payment in its store. Returns the profile and the entry's nonce.
fn mainnet_home(home: &std::path::Path) -> (Profile, String) {
    let signer = KeyringEntryRef::default_signer(NAME);
    let nonce_ref = KeyringEntryRef::default_nonce(NAME);
    let mut profile = Profile::builder_mainnet_named(
        NAME,
        "https://presence-rpc.example:8443",
        &signer.service,
        SIGNER,
        &nonce_ref.service,
        &nonce_ref.account,
    )
    .audit_log_path(home.join("audit").join("presence.jsonl"))
    .build();
    profile.attestation_key_id = KeyringEntryRef::default_attestation_key(NAME);
    save_new_to_dir(NAME, &profile, &home.join("profiles")).unwrap();
    let store: Arc<keyring_core::CredentialStore> =
        Arc::new(stellar_agent_headless_keyring::store::HeadlessStore::new(
            home.join("headless-keyring").join("store.keyring"),
            stellar_agent_headless_keyring::crypto::ProtectionMode::EnvKey(Arc::new(
                zeroize::Zeroizing::new(PROTECTION_KEY),
            )),
        ));
    keyring_core::set_default_store(store);
    for (entry, key) in [
        (&profile.attestation_key_id, [0x42_u8; 32]),
        (&profile.audit_log_hash_chain_key_id, [0x24_u8; 32]),
    ] {
        keyring_core::Entry::new(&entry.service, &entry.account)
            .unwrap()
            .set_password(&URL_SAFE_NO_PAD.encode(key))
            .unwrap();
    }
    sign_presence_policy(home, NAME, &profile);
    let envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
        tx: Transaction {
            source_account: MuxedAccount::Ed25519(Uint256([2; 32])),
            fee: 100,
            seq_num: SequenceNumber(1),
            cond: Preconditions::None,
            memo: Memo::None,
            operations: vec![Operation {
                source_account: None,
                body: OperationBody::Payment(PaymentOp {
                    destination: MuxedAccount::Ed25519(Uint256([4; 32])),
                    asset: Asset::Native,
                    amount: 1_000_000,
                }),
            }]
            .try_into()
            .unwrap(),
            ext: TransactionExt::V0,
        },
        signatures: VecM::default(),
    })
    .to_xdr_base64(Limits::none())
    .unwrap();
    let entry = PendingApproval::new_payment_pending(
        envelope.clone(),
        envelope.as_bytes(),
        stellar_strkey::ed25519::PublicKey([4; 32])
            .to_string()
            .to_string(),
        1_000_000,
        "XLM".to_owned(),
        None,
        100,
        1,
        process_uid_for_attestation().unwrap(),
        DEFAULT_TTL_MS,
    )
    .unwrap();
    let nonce = entry.approval_nonce.clone();
    let mut approvals =
        PendingApprovalStore::open(home.join("approvals").join(format!("{NAME}.toml"))).unwrap();
    approvals
        .insert(entry, stellar_agent_core::timefmt::now_unix_ms().unwrap())
        .unwrap();
    (profile, nonce)
}

/// Runs `approve --id <nonce> --profile <NAME>` with `extra` arguments and
/// `typed` on stdin, and returns the exit code, the envelope and stderr.
fn approve(
    home: &std::path::Path,
    nonce: &str,
    extra: &[&str],
    typed: &str,
) -> (i32, serde_json::Value, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_stellar-agent"))
        .args(["approve", "--id", nonce, "--profile", NAME])
        .args(extra)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("STELLAR_AGENT_HOME", home)
        .env("STELLAR_AGENT_KEYRING_BACKEND", "headless-env")
        .env(
            "STELLAR_AGENT_HEADLESS_KEYRING_KEY",
            URL_SAFE_NO_PAD.encode(PROTECTION_KEY),
        )
        .env(NO_BROWSER_ENV, "1")
        .env_remove("STELLAR_AGENT_PROFILE")
        .spawn()
        .expect("approve binary runs");
    // The binary may exit before it reads stdin; a closed pipe is not a
    // failure of this test.
    let _ = child.stdin.take().unwrap().write_all(typed.as_bytes());
    let output = child.wait_with_output().unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    let json = serde_json::from_str(&stdout).unwrap_or_else(|_| panic!("{stdout} {stderr}"));
    (output.status.code().unwrap(), json, stderr)
}

/// Stdin supplies no mainnet consent: with the owner-signed policy, a
/// genuine attestation key and a live pending entry, typed `y`, `yes` and
/// the profile name reach the browser boundary and refuse there with the
/// browser-required code, and `--yes` with `y` is refused outright. The
/// pending file stays byte-identical and no audit row is written.
#[cfg(feature = "test-helpers")]
#[test]
#[serial]
fn mainnet_presence_stdin_cannot_supply_signed_authority() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    let (profile, nonce) = mainnet_home(home);
    let pending = home.join("approvals").join(format!("{NAME}.toml"));
    let before = std::fs::read(&pending).unwrap();

    for typed in ["y\n", "yes\n", &format!("{NAME}\n")] {
        let (code, json, stderr) = approve(home, &nonce, &[], typed);
        assert_eq!(code, 1, "{json} {stderr}");
        assert_eq!(json["ok"], false);
        assert_eq!(
            json["error"]["code"], "approval.presence_browser_required",
            "{json} {stderr}"
        );
        assert_eq!(
            json["error"]["message"],
            "Mainnet consent requires a local browser with WebAuthn user verification; no approval is recorded."
        );
        assert!(
            stderr.contains(
                "Review this transaction in the local browser and approve with a pinned passkey."
            ),
            "{stderr}"
        );
        assert!(!stderr.contains("[y/N]"), "no prompt reads stdin: {stderr}");
        assert!(
            stderr.contains(&format!("  Profile:           {NAME}")),
            "{stderr}"
        );
    }

    let (code, json, _stderr) = approve(home, &nonce, &["--yes"], "y\n");
    assert_eq!(code, 1, "{json}");
    assert_eq!(json["error"]["code"], "approve.yes_refused_on_mainnet");
    assert_eq!(
        json["error"]["message"],
        "approve --yes is refused on a mainnet profile; approve with a pinned passkey in the local browser."
    );

    assert_eq!(std::fs::read(&pending).unwrap(), before);
    let store = PendingApprovalStore::open(pending).unwrap();
    let entry = store.get(&nonce).expect("the entry stays pending");
    assert!(entry.attestation_blob_b64.is_none());
    assert!(entry.mainnet_presence.is_none());
    assert!(
        !profile.audit_log_path.exists(),
        "no consent row is written"
    );
}

/// Mainnet startup refusals precede TLS, keyring, and listener setup.
#[test]
#[serial]
fn mainnet_presence_inbox_refuses_remote_and_no_open() {
    let dir = tempfile::tempdir().unwrap();
    mainnet_home(dir.path());
    for (flag, code) in [
        ("--remote", "approval.mainnet_remote_unsupported"),
        ("--no-open", "approval.presence_browser_required"),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_stellar-agent"))
            .args(["approve", "serve", "--profile", NAME, flag])
            .env("STELLAR_AGENT_HOME", dir.path())
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        let body: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(body["error"]["code"], code);
        assert!(!String::from_utf8_lossy(&output.stdout).contains("/bootstrap/"));
    }
}

// This native child harness uses Unix signals; Windows is outside its scope.
#[cfg(all(unix, feature = "test-helpers"))]
mod signed {
    use super::*;
    use serde_json::{Value, json};
    use std::{
        net::SocketAddr,
        time::{Duration, Instant},
    };
    use stellar_agent_core::approval::mainnet_fixtures::{
        SIGNED_ORIGIN, SIGNED_RP_ID, policy_body_with_origin,
    };

    struct Home {
        dir: tempfile::TempDir,
        nonce: String,
        address: std::cell::Cell<SocketAddr>,
        pin: [u8; 32],
    }

    impl Home {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let (mut profile, nonce) = mainnet_home(dir.path());
            let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(dir.path());
            let leaf = stellar_agent_approval_remote::signed_origin_test_leaf(SIGNED_RP_ID);
            let cert = dir.path().join("cert.pem");
            let key = dir.path().join("key.pem");
            std::fs::write(&cert, leaf.chain_pem()).unwrap();
            std::fs::write(&key, &leaf.key_pem).unwrap();
            {
                use std::os::unix::fs::PermissionsExt as _;
                std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
            }
            let address: SocketAddr = "127.0.0.1:0".parse().unwrap();
            profile.remote_approval = Some(
                serde_json::from_value(json!({
                    "enabled":true, "bind":address.to_string(), "rp_id":SIGNED_RP_ID,
                    "cert_path":cert, "key_path":key
                }))
                .unwrap(),
            );
            stellar_agent_core::profile::loader::save_to_dir(
                NAME,
                &profile,
                &dir.path().join("profiles"),
            )
            .unwrap();
            let host =
                stellar_agent_core::mainnet::enablement::normalize_endpoint_host(&profile.rpc_url)
                    .unwrap();
            let body = policy_body_with_origin(
                NAME,
                &host,
                2,
                &[&stellar_agent_test_support::webauthn::fixture_authenticator()],
                Some((SIGNED_ORIGIN, &leaf.pin)),
            );
            let owner = ed25519_dalek::SigningKey::from_bytes(&OWNER_SEED);
            std::fs::write(
                dir.path().join("policies").join(format!("{NAME}.toml")),
                signed_policy_text(&body, &owner),
            )
            .unwrap();
            Self {
                dir,
                nonce,
                address: std::cell::Cell::new(address),
                pin: leaf.pin,
            }
        }
        fn command(&self, serve: bool) -> Command {
            let mut command = Command::new(env!("CARGO_BIN_EXE_stellar-agent"));
            command.arg("approve");
            if serve {
                command.arg("serve");
            } else {
                command.args(["--id", &self.nonce]);
            }
            command
                .args(["--profile", NAME])
                .env("STELLAR_AGENT_HOME", self.dir.path())
                .env("STELLAR_AGENT_KEYRING_BACKEND", "headless-env")
                .env(
                    "STELLAR_AGENT_HEADLESS_KEYRING_KEY",
                    URL_SAFE_NO_PAD.encode(PROTECTION_KEY),
                )
                .env(NO_BROWSER_ENV, "1")
                .env(TEST_REMOTE_READY_ENV, "ready")
                .env_remove("DISPLAY")
                .env_remove("WAYLAND_DISPLAY")
                .env_remove("STELLAR_AGENT_PROFILE")
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            command
        }
        fn stored(&self) -> PendingApproval {
            PendingApprovalStore::open(
                self.dir
                    .path()
                    .join("approvals")
                    .join(format!("{NAME}.toml")),
            )
            .unwrap()
            .get(&self.nonce)
            .unwrap()
            .clone()
        }
        fn expire_after_startup(&self) -> u64 {
            let mut store = PendingApprovalStore::open(
                self.dir
                    .path()
                    .join("approvals")
                    .join(format!("{NAME}.toml")),
            )
            .unwrap();
            let mut entry = store.get(&self.nonce).unwrap().clone();
            store.remove(&self.nonce).unwrap();
            // The entry permits the 15-second readiness budget and a five-second margin.
            let expiry = stellar_agent_core::timefmt::now_unix_ms().unwrap() + 20_000;
            entry.expires_at_unix_ms = expiry;
            store
                .insert(entry, stellar_agent_core::timefmt::now_unix_ms().unwrap())
                .unwrap();
            expiry
        }
    }

    struct OwnedChild {
        child: Option<std::process::Child>,
        stderr: Option<std::thread::JoinHandle<String>>,
        lines: std::sync::mpsc::Receiver<String>,
    }
    impl From<std::process::Child> for OwnedChild {
        fn from(mut child: std::process::Child) -> Self {
            use std::io::BufRead as _;
            let stderr = child.stderr.take().unwrap();
            let (sender, lines) = std::sync::mpsc::channel();
            let reader = std::thread::spawn(move || {
                let mut output = String::new();
                for line in std::io::BufReader::new(stderr).lines() {
                    let Ok(line) = line else { break };
                    output.push_str(&line);
                    output.push('\n');
                    let _ = sender.send(line);
                }
                output
            });
            Self {
                child: Some(child),
                stderr: Some(reader),
                lines,
            }
        }
    }
    impl std::ops::Deref for OwnedChild {
        type Target = std::process::Child;
        fn deref(&self) -> &Self::Target {
            self.child.as_ref().unwrap()
        }
    }
    impl std::ops::DerefMut for OwnedChild {
        fn deref_mut(&mut self) -> &mut Self::Target {
            self.child.as_mut().unwrap()
        }
    }
    impl Drop for OwnedChild {
        fn drop(&mut self) {
            let Some(child) = self.child.as_mut() else {
                return;
            };
            if matches!(child.try_wait(), Ok(Some(_))) {
                return;
            }
            send_interrupt(child);
            let deadline = Instant::now() + Duration::from_secs(2);
            while Instant::now() < deadline {
                if matches!(child.try_wait(), Ok(Some(_))) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            let _ = child.kill();
            let deadline = Instant::now() + Duration::from_secs(2);
            while Instant::now() < deadline {
                if matches!(child.try_wait(), Ok(Some(_))) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }

    async fn ready(child: &mut OwnedChild, home: &Home) {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            while let Ok(line) = child.lines.try_recv() {
                if let Some(link) = line.strip_prefix("Test listener: https://") {
                    home.address
                        .set(link.trim_end_matches('/').parse().unwrap());
                    return;
                }
            }
            assert!(Instant::now() < deadline, "listener startup deadline");
            if let Some(status) = child.try_wait().unwrap() {
                use std::io::Read as _;
                let mut out = String::new();
                child
                    .stdout
                    .take()
                    .unwrap()
                    .read_to_string(&mut out)
                    .unwrap();
                let err = child.stderr.take().unwrap().join().unwrap();
                panic!("listener exited {status}: {out} {err}");
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }
    async fn finish(child: impl Into<OwnedChild>) -> (i32, String, String) {
        finish_by(child, Instant::now() + Duration::from_secs(15)).await
    }
    async fn finish_by(child: impl Into<OwnedChild>, deadline: Instant) -> (i32, String, String) {
        let mut child = child.into();
        while child.try_wait().unwrap().is_none() {
            assert!(Instant::now() < deadline, "command completion deadline");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let out = child.child.take().unwrap().wait_with_output().unwrap();
        let err = child.stderr.take().unwrap().join().unwrap();
        (
            out.status
                .code()
                .expect("the registered interrupt permits normal process completion"),
            String::from_utf8(out.stdout).unwrap(),
            err,
        )
    }
    #[allow(
        unsafe_code,
        reason = "signals only the native child owned by this test"
    )]
    fn send_interrupt(child: &std::process::Child) {
        if let Ok(pid) = libc::pid_t::try_from(child.id()) {
            // The positive PID belongs to this unreaped child.
            unsafe {
                libc::kill(pid, libc::SIGINT);
            }
        }
    }
    struct Browser {
        client: reqwest::Client,
        address: SocketAddr,
        cookie: String,
    }
    impl Browser {
        fn new(address: SocketAddr) -> Self {
            Self {
                client: reqwest::Client::builder()
                    .danger_accept_invalid_certs(true)
                    .no_proxy()
                    .redirect(reqwest::redirect::Policy::none())
                    .build()
                    .unwrap(),
                address,
                cookie: String::new(),
            }
        }
        fn request(&self, method: &str, path: &str) -> reqwest::RequestBuilder {
            self.client
                .request(
                    method.parse().unwrap(),
                    format!("https://{}{path}", self.address),
                )
                .header("host", SIGNED_ORIGIN.trim_start_matches("https://"))
                .header("origin", SIGNED_ORIGIN)
                .header("cookie", &self.cookie)
        }
        async fn login(&mut self) {
            let options: Value = self
                .request("POST", "/login/challenge")
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            let assertion = stellar_agent_test_support::webauthn::fixture_authenticator().assert(
                URL_SAFE_NO_PAD
                    .decode(options["challenge"].as_str().unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap(),
                SIGNED_ORIGIN,
                SIGNED_RP_ID,
                5,
                1,
            );
            let response = self.request("POST", "/login/assertion").json(&json!({"assertion":{
                "id":URL_SAFE_NO_PAD.encode(assertion.credential_id),
                "response":{"authenticator_data":URL_SAFE_NO_PAD.encode(assertion.authenticator_data),
                "client_data_json":URL_SAFE_NO_PAD.encode(assertion.client_data_json),
                "signature":URL_SAFE_NO_PAD.encode(assertion.signature_der)}
            }})).send().await.unwrap();
            assert_eq!(response.status(), 200);
            self.cookie = response.headers()["set-cookie"]
                .to_str()
                .unwrap()
                .split(';')
                .next()
                .unwrap()
                .to_owned();
        }
        async fn page(&self, nonce: &str) -> Value {
            let response = self
                .request("GET", &format!("/approval/{nonce}"))
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), 200);
            let html = response.text().await.unwrap();
            let body = html
                .split("id=\"presence-data\"")
                .nth(1)
                .unwrap()
                .split_once('>')
                .unwrap()
                .1
                .split("</script>")
                .next()
                .unwrap();
            serde_json::from_str(body).unwrap()
        }
        async fn action(
            &self,
            nonce: &str,
            page: &Value,
            action: &str,
            body: &Value,
        ) -> reqwest::Response {
            self.request("POST", &format!("/approval/{nonce}/{action}"))
                .header("x-stellar-approval-csrf", page["csrf"].as_str().unwrap())
                .json(body)
                .send()
                .await
                .unwrap()
        }
        async fn consent(&self, nonce: &str) {
            let page = self.page(nonce).await;
            let response = self
                .action(
                    nonce,
                    &page,
                    "challenge",
                    &json!({"consent_view_digest":page["consent_view_digest"]}),
                )
                .await;
            assert_eq!(response.status(), 200);
            let options: Value = response.json().await.unwrap();
            assert_eq!(options["rp_id"], SIGNED_RP_ID);
            let assertion = stellar_agent_test_support::webauthn::fixture_authenticator().assert(
                URL_SAFE_NO_PAD
                    .decode(options["challenge"].as_str().unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap(),
                SIGNED_ORIGIN,
                SIGNED_RP_ID,
                5,
                2,
            );
            let response = self.action(nonce,&page,"assertion",&json!({
                "request_id":options["request_id"],
                "credential_id_b64url":URL_SAFE_NO_PAD.encode(assertion.credential_id),
                "authenticator_data_b64url":URL_SAFE_NO_PAD.encode(assertion.authenticator_data),
                "client_data_json_b64url":URL_SAFE_NO_PAD.encode(assertion.client_data_json),
                "signature_der_b64url":URL_SAFE_NO_PAD.encode(assertion.signature_der)
            })).await;
            assert_eq!(response.status(), 200);
        }
    }

    async fn complete_signed_one_shot() {
        let home = Home::new();
        let mut child: OwnedChild = home.command(false).spawn().unwrap().into();
        ready(&mut child, &home).await;
        let mut browser = Browser::new(home.address.get());
        browser.login().await;
        browser.consent(&home.nonce).await;
        let (code, out, err) = finish(child).await;
        assert_eq!(code, 0, "{out} {err}");
        assert!(
            err.contains(&format!(
                "Approve at the signed origin: {SIGNED_ORIGIN}/approvals/{}",
                home.nonce
            )),
            "{err}"
        );
        assert!(
            !err.contains("Browser launch attempted")
                && !err.contains("/bootstrap/")
                && !err.contains("?token="),
            "{err}"
        );
        let entry = home.stored();
        assert_eq!(entry.attestation_version, 5);
        let receipt = entry.mainnet_presence.unwrap();
        assert_eq!(receipt.version(), 2);
        assert_eq!(
            receipt.cert_spki_sha256_hex(),
            Some(stellar_agent_core::hex::encode(&home.pin).as_str())
        );
        assert!(
            serde_json::to_string(&receipt)
                .unwrap()
                .contains(SIGNED_ORIGIN)
        );
        assert!(receipt.listener_policy_digest_hex().is_some());
    }

    #[tokio::test]
    #[serial]
    async fn signed_origin_one_shot_prints_url_and_binds_identity() {
        complete_signed_one_shot().await;
    }

    #[tokio::test]
    #[serial]
    async fn one_shot_runs_without_exposure_flag() {
        complete_signed_one_shot().await;
    }

    #[tokio::test]
    #[serial]
    async fn one_shot_refuses_busy_socket() {
        let home = Home::new();
        let held = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = held.local_addr().unwrap();
        let path = home
            .dir
            .path()
            .join("profiles")
            .join(format!("{NAME}.toml"));
        let mut profile: Profile = toml::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        profile.remote_approval.as_mut().unwrap().bind = address.to_string();
        stellar_agent_core::profile::loader::save_to_dir(
            NAME,
            &profile,
            &home.dir.path().join("profiles"),
        )
        .unwrap();
        let (code, out, err) = finish(home.command(false).spawn().unwrap()).await;
        assert_eq!(code, 1, "{out} {err}");
        let json: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(json["error"]["code"], "approval.listener_busy");
        assert!(
            json["error"]["message"]
                .as_str()
                .unwrap()
                .contains("running inbox")
        );
        assert!(!err.contains("Approve at the signed origin:"));
        assert!(home.stored().attestation_blob_b64.is_none());
        drop(held);
    }

    #[tokio::test]
    #[serial]
    async fn signed_origin_serve_requires_exposure_consent_and_prints_policy_origin() {
        let home = Home::new();
        let (code, out, err) = finish(
            home.command(true)
                .args(["--remote", "--no-open"])
                .spawn()
                .unwrap(),
        )
        .await;
        assert_eq!(code, 1, "{out} {err}");
        assert!(
            out.contains("approve.remote_exposure_not_confirmed"),
            "{out}"
        );
        let mut child: OwnedChild = home
            .command(true)
            .args(["--remote", "--no-open", "--confirm-remote-exposure"])
            .spawn()
            .unwrap()
            .into();
        ready(&mut child, &home).await;
        send_interrupt(&child);
        let (code, out, err) = finish(child).await;
        assert_eq!(code, 0, "{out} {err}");
        assert_eq!(out, format!("Remote approval inbox: {SIGNED_ORIGIN}/\n"));
        assert!(!err.contains("Browser launch attempted"));
    }

    #[tokio::test]
    #[serial]
    async fn signed_origin_interrupt_immediately_after_ready() {
        let home = Home::new();
        let mut child: OwnedChild = home.command(false).spawn().unwrap().into();
        ready(&mut child, &home).await;
        send_interrupt(&child);
        let (code, out, err) = finish(child).await;
        assert_eq!(code, 1, "{out} {err}");
        assert_eq!(
            serde_json::from_str::<Value>(&out).unwrap()["error"]["code"],
            "approval.presence_canceled"
        );
        assert!(home.stored().attestation_blob_b64.is_none());
    }

    #[tokio::test]
    #[serial]
    async fn signed_origin_one_shot_closes_after_consent_cancel_expiry_or_interrupt() {
        for action in ["consent", "cancel", "expiry", "interrupt"] {
            let home = Home::new();
            let expiry = (action == "expiry").then(|| home.expire_after_startup());
            let completion_deadline = Instant::now() + Duration::from_secs(35);
            let mut child: OwnedChild = home.command(false).spawn().unwrap().into();
            ready(&mut child, &home).await;
            match action {
                "consent" | "cancel" => {
                    let mut browser = Browser::new(home.address.get());
                    browser.login().await;
                    if action == "consent" {
                        browser.consent(&home.nonce).await;
                    } else {
                        let page = browser.page(&home.nonce).await;
                        assert_eq!(
                            browser
                                .action(
                                    &home.nonce,
                                    &page,
                                    "cancel",
                                    &json!({"reason":"operator_cancel"})
                                )
                                .await
                                .status(),
                            200
                        );
                    }
                }
                "interrupt" => send_interrupt(&child),
                _ => {}
            }
            let (code, out, err) = finish_by(child, completion_deadline).await;
            if let Some(expiry) = expiry {
                assert!(
                    stellar_agent_core::timefmt::now_unix_ms().unwrap() >= expiry,
                    "the command runs until the entry deadline"
                );
            }
            if action == "consent" {
                assert_eq!(code, 0, "{out} {err}");
            } else {
                assert_eq!(code, 1, "{action}: {out} {err}");
                let json: Value = serde_json::from_str(&out).unwrap();
                assert_eq!(
                    json["error"]["code"],
                    if action == "expiry" {
                        "approval.presence_expired"
                    } else {
                        "approval.presence_canceled"
                    }
                );
                assert!(home.stored().attestation_blob_b64.is_none());
            }
            assert!(err.contains("Approve at the signed origin:"));
        }
    }

    #[tokio::test]
    #[serial]
    async fn remote_tls_unavailable_is_a_top_level_code() {
        let home = Home::new();
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(home.dir.path());
        let path = home
            .dir
            .path()
            .join("profiles")
            .join(format!("{NAME}.toml"));
        let mut profile: Profile =
            toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        profile.remote_approval.as_mut().unwrap().cert_path = None;
        stellar_agent_core::profile::loader::save_to_dir(
            NAME,
            &profile,
            &home.dir.path().join("profiles"),
        )
        .unwrap();
        let (code, out, err) = finish(home.command(false).spawn().unwrap()).await;
        assert_eq!(code, 1, "{out} {err}");
        let json: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(json["error"]["code"], "approve.remote_tls_unavailable");
        assert!(
            json["error"]["message"]
                .as_str()
                .unwrap()
                .contains("cert_path")
        );
    }

    #[tokio::test]
    #[serial]
    async fn one_shot_listener_serves_only_the_selected_id() {
        let home = Home::new();
        let mut other = home.stored();
        other.approval_nonce = URL_SAFE_NO_PAD.encode(uuid::Uuid::new_v4().as_bytes());
        PendingApprovalStore::open(
            home.dir
                .path()
                .join("approvals")
                .join(format!("{NAME}.toml")),
        )
        .unwrap()
        .insert(
            other.clone(),
            stellar_agent_core::timefmt::now_unix_ms().unwrap(),
        )
        .unwrap();
        let mut child: OwnedChild = home.command(false).spawn().unwrap().into();
        ready(&mut child, &home).await;
        let mut browser = Browser::new(home.address.get());
        browser.login().await;
        let page = browser.page(&home.nonce).await;
        for prefix in ["approval", "approvals"] {
            let response = browser
                .request("GET", &format!("/{prefix}/{}", other.approval_nonce))
                .send()
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                if prefix == "approvals" { 404 } else { 409 }
            );
            assert!(!response.text().await.unwrap().contains("presence-data"));
        }
        for action in ["challenge", "assertion", "reject", "cancel", "decision"] {
            assert_ne!(
                browser
                    .action(
                        &other.approval_nonce,
                        &page,
                        action,
                        &json!({"reason":"operator_cancel"})
                    )
                    .await
                    .status(),
                200
            );
        }
        for path in ["/inbox", "/pending.json"] {
            let body = browser
                .request("GET", path)
                .send()
                .await
                .unwrap()
                .text()
                .await
                .unwrap();
            assert!(body.contains(&home.nonce));
            assert!(!body.contains(&other.approval_nonce));
        }
        assert_eq!(
            browser
                .action(
                    &home.nonce,
                    &page,
                    "cancel",
                    &json!({"reason":"operator_cancel"})
                )
                .await
                .status(),
            200
        );
        let (code, out, err) = finish(child).await;
        assert_eq!(code, 1, "{out} {err}");
        assert_eq!(
            serde_json::from_str::<Value>(&out).unwrap()["error"]["code"],
            "approval.presence_canceled"
        );
        let store = PendingApprovalStore::open(
            home.dir
                .path()
                .join("approvals")
                .join(format!("{NAME}.toml")),
        )
        .unwrap();
        assert!(
            store
                .get(&other.approval_nonce)
                .unwrap()
                .attestation_blob_b64
                .is_none()
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    #[serial]
    async fn signed_origin_keeps_key_permission_refusal() {
        use std::os::unix::fs::PermissionsExt as _;
        let home = Home::new();
        let path = home
            .dir
            .path()
            .join("profiles")
            .join(format!("{NAME}.toml"));
        let profile: Profile = toml::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let key = profile.remote_approval.unwrap().key_path.unwrap();
        std::fs::set_permissions(key, std::fs::Permissions::from_mode(0o644)).unwrap();
        let (code, out, err) = finish(home.command(false).spawn().unwrap()).await;
        assert_eq!(code, 1, "{out} {err}");
        let json: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(json["error"]["code"], "internal.unexpected_state");
        let message = json["error"]["message"].as_str().unwrap();
        assert!(message.contains("approve.remote_tls_provision_failed"));
        assert!(message.contains("permissions 644"));
    }

    #[tokio::test]
    #[serial]
    async fn testnet_remote_startup_keeps_base_bytes() {
        let home = Home::new();
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(home.dir.path());
        let path = home
            .dir
            .path()
            .join("profiles")
            .join(format!("{NAME}.toml"));
        let mut profile: Profile = toml::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        profile.chain_id = stellar_agent_core::profile::caip2::Caip2::Testnet;
        let remote = profile.remote_approval.as_mut().unwrap();
        remote.cert_path = None;
        remote.key_path = None;
        stellar_agent_core::profile::loader::save_to_dir(
            NAME,
            &profile,
            &home.dir.path().join("profiles"),
        )
        .unwrap();
        let mut child: OwnedChild = home
            .command(true)
            .args(["--remote", "--confirm-remote-exposure"])
            .spawn()
            .unwrap()
            .into();
        ready(&mut child, &home).await;
        send_interrupt(&child);
        let (code, out, err) = finish(child).await;
        assert_eq!(code, 0, "{out} {err}");
        let tls = stellar_agent_approval_remote::provision_or_load(NAME, SIGNED_RP_ID).unwrap();
        assert_eq!(
            out,
            format!(
                "Remote approval inbox: https://{}:{}/\nCertificate SHA-256 fingerprint (verify out-of-band before trusting): {}\n\"{}\" must resolve to this host from the approving device (internal DNS or a hosts-file entry) \u{2014} WebAuthn requires a DNS Relying Party ID, never an IP address.\n",
                SIGNED_RP_ID,
                home.address.get().port(),
                tls.fingerprint_sha256_hex,
                SIGNED_RP_ID,
            )
        );
    }

    #[tokio::test]
    #[serial]
    async fn one_shot_requires_enabled_remote_configuration() {
        let home = Home::new();
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(home.dir.path());
        let path = home
            .dir
            .path()
            .join("profiles")
            .join(format!("{NAME}.toml"));
        let mut profile: Profile = toml::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        profile.remote_approval.as_mut().unwrap().enabled = false;
        stellar_agent_core::profile::loader::save_to_dir(
            NAME,
            &profile,
            &home.dir.path().join("profiles"),
        )
        .unwrap();
        let (code, out, err) = finish(home.command(false).spawn().unwrap()).await;
        assert_eq!(code, 1, "{out} {err}");
        let json: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(json["error"]["code"], "internal.unexpected_state");
        assert!(
            json["error"]["message"]
                .as_str()
                .unwrap()
                .contains("approve.remote_not_configured")
        );
        assert!(!err.contains("Approve at the signed origin:"));
    }

    #[cfg(feature = "mainnet-write")]
    #[tokio::test]
    #[serial]
    async fn signed_origin_consent_persists_v5_receipt_and_commits() {
        use stellar_agent_core::{
            approval::{
                MainnetApprovalAuthority, mainnet_consent_subject,
                witness::{ApprovalExpectation, ApprovedKind, verify_approval},
            },
            audit_log::PolicyDecision,
            mainnet::enablement::verify_enablement,
            profile::{
                name::{ProfileNameSource, ResolvedProfileName},
                receipt::ReceiptStore,
                schema::signer_identity_entry_ref,
                signer_identity::SignerIdentityRecord,
            },
        };
        use stellar_agent_network::{
            MainnetEndpointFlags, NetworkContext,
            keyring::{EnrolledRole, enrolled_signer},
            mainnet::{
                MainnetConsumer,
                audit_readiness::audit_readiness,
                authority::MainnetAuthority,
                resolve::{TxSignRequest, resolve_tx_sign},
            },
            policy_state::PersistedWindowStore,
            signing::{
                envelope_signing::attach_signature_authorized, test_doubles::CountingSigner,
            },
            submission_record::{ApprovalTombstone, WalletSubmissionRecorder},
            submit::{MainnetSubmitGrant, submit_authorized_transaction_and_wait},
        };
        let mut home = Home::new();
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(home.dir.path());
        let profile_path = home
            .dir
            .path()
            .join("profiles")
            .join(format!("{NAME}.toml"));
        let mut profile: Profile =
            toml::from_str(&std::fs::read_to_string(&profile_path).unwrap()).unwrap();
        let now = stellar_agent_core::timefmt::now_unix_ms().unwrap();
        let envelope = stellar_agent_test_support::SignedTestEnvelope::builder([42; 32])
            .network_passphrase(stellar_agent_core::profile::caip2::MAINNET_PASSPHRASE)
            .time_bounds(0, now / 1000 + 120)
            .sequence(2)
            .amount_stroops(10)
            .unsigned()
            .build();
        profile.mcp_signer_default.account = envelope.source().to_owned();
        profile.oracle_provider_url = Some("https://oracle.example.invalid".parse().unwrap());
        let providers = profile.providers.get_or_insert_with(Default::default);
        providers.primary = Some(
            stellar_agent_core::profile::schema::PrimaryProviderRecord::new(
                "primary",
                "presence-rpc.example",
            ),
        );
        providers.oracle = Some(stellar_agent_core::profile::schema::ProviderRecord::new(
            "oracle",
            "oracle.example.invalid",
            true,
        ));
        stellar_agent_core::profile::loader::save_to_dir(
            NAME,
            &profile,
            &home.dir.path().join("profiles"),
        )
        .unwrap();
        let owner = ed25519_dalek::SigningKey::from_bytes(&OWNER_SEED);
        let public = ed25519_dalek::SigningKey::from_bytes(&[42; 32])
            .verifying_key()
            .to_bytes();
        let identity = signer_identity_entry_ref(&profile.mcp_signer_default);
        keyring_core::Entry::new(&identity.service, &identity.account)
            .unwrap()
            .set_password(
                &SignerIdentityRecord::signed_for_test(public, NAME, &profile, &owner)
                    .render()
                    .unwrap(),
            )
            .unwrap();
        let host =
            stellar_agent_core::mainnet::enablement::normalize_endpoint_host(&profile.rpc_url)
                .unwrap();
        let body = policy_body_with_origin(
            NAME,
            &host,
            3,
            &[&stellar_agent_test_support::webauthn::fixture_authenticator()],
            Some((SIGNED_ORIGIN, &home.pin)),
        )
        .replace(
            stellar_agent_core::approval::mainnet_fixtures::ALLOWED_DESTINATION,
            envelope.destination(),
        );
        std::fs::write(
            home.dir
                .path()
                .join("policies")
                .join(format!("{NAME}.toml")),
            signed_policy_text(&body, &owner),
        )
        .unwrap();
        let pending = PendingApproval::new_payment_pending(
            envelope.envelope_xdr().to_owned(),
            envelope.envelope_xdr().as_bytes(),
            envelope.destination().to_owned(),
            10,
            "XLM".to_owned(),
            None,
            100,
            2,
            process_uid_for_attestation().unwrap(),
            60_000,
        )
        .unwrap();
        home.nonce = pending.approval_nonce.clone();
        let store_path = home
            .dir
            .path()
            .join("approvals")
            .join(format!("{NAME}.toml"));
        PendingApprovalStore::open(store_path.clone())
            .unwrap()
            .insert(pending, now)
            .unwrap();
        let mut child: OwnedChild = home.command(false).spawn().unwrap().into();
        ready(&mut child, &home).await;
        let mut browser = Browser::new(home.address.get());
        browser.login().await;
        browser.consent(&home.nonce).await;
        let (code, out, err) = finish(child).await;
        assert_eq!(code, 0, "{out} {err}");
        let entry = home.stored();
        assert_eq!(entry.attestation_version, 5);
        assert_eq!(entry.mainnet_presence.as_ref().unwrap().version(), 2);
        let counter_path = stellar_agent_core::approval::RemoteApprovalAuthority::for_profile(NAME)
            .unwrap()
            .credentials_path()
            .to_path_buf();
        let counters = std::fs::read(&counter_path).unwrap();
        // Authorization uses an in-memory platform store with the fixture's exact entries.
        let wire: Value = serde_json::from_slice(
            &std::fs::read(
                home.dir
                    .path()
                    .join("headless-keyring")
                    .join("store.keyring"),
            )
            .unwrap(),
        )
        .unwrap();
        let secrets: Vec<_> = wire["entries"]
            .as_object()
            .unwrap()
            .keys()
            .map(|coordinate| {
                let (service, account) = coordinate.split_once('\0').unwrap();
                let secret = keyring_core::Entry::new(service, account)
                    .unwrap()
                    .get_secret()
                    .unwrap();
                (
                    service.to_owned(),
                    account.to_owned(),
                    zeroize::Zeroizing::new(secret),
                )
            })
            .collect();
        stellar_agent_test_support::keyring_mock::install().unwrap();
        for (service, account, secret) in secrets {
            keyring_core::Entry::new(&service, &account)
                .unwrap()
                .set_secret(&secret)
                .unwrap();
        }
        let current = MainnetApprovalAuthority::for_profile(NAME)
            .unwrap()
            .load_current()
            .unwrap();
        let store = PendingApprovalStore::open(store_path).unwrap();
        let blob: [u8; 32] = URL_SAFE_NO_PAD
            .decode(entry.attestation_blob_b64.as_ref().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let binding = stellar_agent_core::approval::ApprovalContext::from_profile(NAME, &profile);
        let approval = verify_approval(
            &store,
            &profile,
            NAME,
            &home.nonce,
            &blob,
            &ApprovalExpectation {
                kind: ApprovedKind::Payment,
                subject: mainnet_consent_subject(&entry, &binding.binding()).unwrap(),
            },
            current.policy(),
            stellar_agent_core::timefmt::now_unix_ms().unwrap(),
        )
        .unwrap();
        drop(store);
        let rpc = wiremock::MockServer::start().await;
        let ledger = envelope.ledger_entries_result();
        wiremock::Mock::given(wiremock::matchers::method("POST")).respond_with(move |request:&wiremock::Request| {
            let body:Value=serde_json::from_slice(&request.body).unwrap();
            let result=match body["method"].as_str().unwrap() {
                "getNetwork"=>stellar_agent_test_support::signed_envelope::get_network_result(stellar_agent_core::profile::caip2::MAINNET_PASSPHRASE),
                "getLedgerEntries"=>{
                    let mut result=ledger.clone();
                    let keys=body["params"]["keys"].as_array().unwrap();
                    result["entries"].as_array_mut().unwrap().retain(|entry|keys.contains(&entry["key"]));
                    result
                },
                "getHealth"=>json!({"status":"healthy","latestLedger":100,"oldestLedger":1,"ledgerRetentionWindow":100}),
                "getLatestLedger"=>json!({"id":"00".repeat(32),"protocolVersion":23,"sequence":100}),
                "getLedgers"=>json!({"latestLedger":100,"oldestLedger":1,"latestLedgerCloseTime":(stellar_agent_core::timefmt::now_unix_ms().unwrap()/1000).to_string(),"oldestLedgerCloseTime":1,"cursor":"100","ledgers":[]}),
                "sendTransaction"=>json!({"hash":stellar_agent_test_support::send_transaction_hash_hex(&body,stellar_agent_core::profile::caip2::MAINNET_PASSPHRASE),"status":"PENDING","latestLedger":100,"latestLedgerCloseTime":"1234567890"}),
                "getTransaction"=>json!({"status":"SUCCESS","ledger":101,"txHash":body["params"]["hash"],"createdAt":(stellar_agent_core::timefmt::now_unix_ms().unwrap()/1000).to_string()}),
                method=>panic!("unexpected RPC {method}"),
            };
            wiremock::ResponseTemplate::new(200).set_body_json(json!({"jsonrpc":"2.0","id":body["id"],"result":result}))
        }).mount(&rpc).await;
        let context = NetworkContext::mainnet_write(
            &profile,
            &ResolvedProfileName::from_flag(NAME),
            &home.dir.path().join("profiles"),
            MainnetEndpointFlags::default(),
        )
        .unwrap()
        .with_test_transport_routes(&[
            ("presence-rpc.example", &rpc.uri()),
            ("oracle.example.invalid", &rpc.uri()),
        ]);
        let client = context.primary_client().unwrap();
        use stellar_agent_core::{
            asset_id::CanonicalAsset,
            cross_check::{CrossCheckValue, ThresholdSet},
        };
        use stellar_agent_network::cross_check::{
            AccountObservation, CrossCheckOutcome, DestinationObservation, MemoObservation,
            PayWitnessInputs, obtain_classic_witness_bound,
        };
        let source_view =
            stellar_agent_network::account::fetch_account(&client, envelope.source(), &[])
                .await
                .unwrap();
        let witness = obtain_classic_witness_bound(
            &profile,
            &context.network_context(),
            CrossCheckValue::Amount {
                asset: &CanonicalAsset::Native,
                base_units: 10,
            },
            PayWitnessInputs {
                source: AccountObservation::from_view(&source_view).unwrap(),
                destination: DestinationObservation::from_view(envelope.destination(), None),
                memo: MemoObservation::Read(false),
                trustline: None,
            },
            envelope.envelope_xdr(),
            &ThresholdSet::from_profile_and_signed(
                &profile,
                current
                    .policy()
                    .mainnet()
                    .unwrap()
                    .cross_check_thresholds
                    .as_ref(),
            ),
            "stellar_pay",
        )
        .await
        .unwrap();
        let CrossCheckOutcome::Passed(witness) = witness else {
            panic!("memo observation requires a witness")
        };
        let enablement = verify_enablement(
            current.policy(),
            NAME,
            ProfileNameSource::Flag,
            &profile,
            &home.dir.path().join("profiles"),
            &|_| Ok(ENABLEMENT_NONCE.to_owned()),
        )
        .unwrap();
        let signer = enrolled_signer(
            NAME,
            &home.dir.path().join("profiles"),
            &profile,
            EnrolledRole::Agent,
            &public,
            &current.policy().owner(),
        )
        .unwrap();
        let window = PersistedWindowStore::for_profile(NAME);
        let audit = audit_readiness(&profile, NAME).unwrap();
        let writer = audit.writer().clone();
        let authorization = resolve_tx_sign(TxSignRequest {
            context: &context,
            consumer: MainnetConsumer::CliPay,
            unsigned_envelope_xdr: envelope.envelope_xdr(),
            client: &client,
            probe_deadline: Duration::from_secs(2),
            witness: Some(&witness),
            signer: &signer,
            policy: current.policy(),
            enablement: &enablement,
            authority: &MainnetAuthority::Approval(&approval),
            audit,
            store: &window,
            operation: None,
        })
        .await
        .unwrap();
        let signing = CountingSigner::new([42; 32]);
        let signed = attach_signature_authorized(
            envelope.envelope_xdr(),
            &signing,
            context.network_passphrase(),
            MainnetConsumer::CliPay,
            &authorization,
        )
        .await
        .unwrap();
        let recorder = WalletSubmissionRecorder::new_authorized(
            &profile,
            NAME,
            "stellar_pay",
            Some("stellar:mainnet".to_owned()),
            PolicyDecision::RequireApproval,
            vec![],
            &authorization,
            ReceiptStore::open(NAME).unwrap(),
            window,
            Some(writer),
            None,
            "signed-origin-commit",
            stellar_agent_core::timefmt::now_unix_ms().unwrap(),
        )
        .with_approval(Some(ApprovalTombstone {
            store_dir: home.dir.path().join("approvals"),
            profile_name: NAME.to_owned(),
            approval_nonce: home.nonce.clone(),
        }));
        submit_authorized_transaction_and_wait(
            &client,
            None,
            &signed,
            Duration::from_secs(5),
            context.network_passphrase(),
            None,
            &recorder,
            MainnetConsumer::CliPay,
            MainnetSubmitGrant::Tx(authorization),
        )
        .await
        .unwrap();
        assert_eq!(signing.sign_calls(), 1);
        assert!(matches!(
            home.stored().kind,
            stellar_agent_core::approval::ApprovalKind::Consumed { .. }
        ));
        assert_eq!(std::fs::read(counter_path).unwrap(), counters);
        let requests = rpc.received_requests().await.unwrap();
        assert_eq!(
            requests
                .iter()
                .filter(
                    |request| request.body_json::<Value>().unwrap()["method"] == "sendTransaction"
                )
                .count(),
            1
        );
        stellar_agent_core::audit_log::AuditWriterRegistry::remove_for_test(NAME);
    }
}
