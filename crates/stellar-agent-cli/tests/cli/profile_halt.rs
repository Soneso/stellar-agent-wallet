//! `profile halt` and `profile resume`, driven as subprocesses of the real
//! `stellar-agent` binary.
//!
//! # What the suite observes
//!
//! - Each of the 34 CLI check sites, one invocation per site, refuses a halted
//!   profile with `profile.halted`. The fixture profile holds no signer
//!   secret: its keyring signer entry is never written, and every
//!   `--*-secret-env` variable a verb names is removed from the child's
//!   environment. A verb that read its signer before the halt check would
//!   fail with that signer error instead. The profile's endpoints, and the
//!   Friendbot URL, are a [`ConnectionCounter`], which records zero
//!   connections across each halted run, so no request preceded the refusal.
//! - After `profile resume` the same invocations get past the halt check: each
//!   one fails at a later step with a different code.
//! - `profile halt` and `profile resume` write `profile_halted` and
//!   `profile_resumed` audit rows into a chain that `audit verify` accepts,
//!   and queue them in the outbox while a draining writer holds the log.
//! - A halt whose audit row cannot be written stays in effect. A resume
//!   commits its row before it removes the marker: while the append waits on
//!   the outbox lock the marker stays and a halted verb still refuses. A
//!   resume whose marker cannot be read, whose row cannot be recorded, or
//!   whose marker cannot be removed leaves the profile halted.
//! - `profile show` reports the halt state, a missing profile is refused
//!   without a marker, and resuming a running profile exits 0.
//! - An operator key ceremony and read-only verbs keep working while halted.
//!
//! # Hermetic fixtures
//!
//! `STELLAR_AGENT_HOME` points each child at a temporary data root, and every
//! child runs the headless keyring backend under [`HEADLESS_KEY`]. Profiles,
//! the audit key and its binding are written in-process into the same store.
//! Every test holds the serial lock, because that in-process store is the
//! process-global default.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test assertions"
)]

use std::io::{BufRead as _, BufReader, Read as _};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::Value;
use serial_test::serial;
use stellar_agent_core::audit_log::outbox::OUTBOX_LOCK_WAIT_ENV;
use stellar_agent_core::audit_log::{AuditBinding, AuditWriter, BindingCheck, inspect_outbox};
use stellar_agent_core::profile::loader::save_new_to_dir;
use stellar_agent_core::profile::schema::Profile;
use stellar_agent_network::keyring::{KeyringAuditBindingStore, keyed_audit_access};
use stellar_agent_test_support::ConnectionCounter;

/// The headless keyring key of every child and of the in-process store.
const HEADLESS_KEY: [u8; 32] = [0x6b; 32];

/// The profile every fixture writes and every run names.
const PROFILE: &str = "halt-cli";

/// A smart account, contract, verifier or timelock address.
const CONTRACT: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM";

/// A classic account address.
const ACCOUNT_G: &str = "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5";

/// A second classic account address, for the account a creation names.
const NEW_ACCOUNT_G: &str = "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL";

/// The secret variable every signer-source flag names. No child has it set.
const UNSET_SECRET_ENV: &str = "STELLAR_AGENT_HALT_TEST_UNSET_SECRET";

/// A 32-byte hex value for the hash and operation arguments.
const HEX32: &str = "0101010101010101010101010101010101010101010101010101010101010101";

/// Output of one child invocation.
struct Run {
    code: i32,
    envelope: Value,
    stdout: String,
    stderr: String,
}

impl Run {
    fn from_output(output: &Output) -> Self {
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        let envelope = stdout
            .lines()
            .rev()
            .find(|line| line.trim_start().starts_with('{'))
            .map(|line| serde_json::from_str(line).expect("the envelope line is JSON"))
            .unwrap_or(Value::Null);
        Self {
            code: output.status.code().expect("process must exit with a code"),
            envelope,
            stdout,
            stderr,
        }
    }

    fn error_code(&self) -> Option<&str> {
        self.envelope["error"]["code"].as_str()
    }

    fn describe(&self) -> String {
        format!(
            "exit {}; stdout={}; stderr={}",
            self.code,
            self.stdout.trim(),
            self.stderr.trim()
        )
    }
}

/// A temporary data root with one saved testnet profile whose endpoints are
/// a connection counter.
struct Fixture {
    home: tempfile::TempDir,
    counter: ConnectionCounter,
    profile: Profile,
}

impl Fixture {
    fn new() -> Self {
        let home = tempfile::tempdir().unwrap();
        let counter = ConnectionCounter::start().unwrap();
        let rpc_url = counter.https_uri().replacen("https://", "http://", 1);
        let profile = Profile::builder_testnet_named(PROFILE, "s", "a", "n", "a")
            .rpc_url(&rpc_url)
            .audit_log_path(home.path().join("audit").join(format!("{PROFILE}.jsonl")))
            .with_noop_engine()
            .build();
        let store: Arc<keyring_core::CredentialStore> =
            Arc::new(stellar_agent_headless_keyring::store::HeadlessStore::new(
                home.path().join("headless-keyring").join("store.keyring"),
                stellar_agent_headless_keyring::crypto::ProtectionMode::EnvKey(Arc::new(
                    zeroize::Zeroizing::new(HEADLESS_KEY),
                )),
            ));
        keyring_core::set_default_store(store);
        let coordinate = &profile.audit_log_hash_chain_key_id;
        keyring_core::Entry::new(&coordinate.service, &coordinate.account)
            .unwrap()
            .set_password(&URL_SAFE_NO_PAD.encode([0x2c; 32]))
            .unwrap();
        KeyringAuditBindingStore::for_profile(PROFILE)
            .store(&AuditBinding::for_profile(&profile))
            .unwrap();
        save_new_to_dir(PROFILE, &profile, &home.path().join("profiles")).unwrap();
        Self {
            home,
            counter,
            profile,
        }
    }

    fn rpc_url(&self) -> String {
        self.counter.https_uri().replacen("https://", "http://", 1)
    }

    fn marker(&self) -> PathBuf {
        self.home
            .path()
            .join("profiles")
            .join(format!("{PROFILE}.halt"))
    }

    fn run(&self, args: &[&str]) -> Run {
        run_in(self.home.path(), args)
    }

    /// `trustline`, a verb the halt refuses before any signer read or
    /// request.
    fn halted_verb(&self) -> Command {
        let asset = format!("USDC:{ACCOUNT_G}");
        command_in(
            self.home.path(),
            &[
                "trustline",
                "--profile",
                PROFILE,
                "--from",
                ACCOUNT_G,
                "--asset",
                &asset,
            ],
        )
    }

    /// Runs [`Fixture::halted_verb`] to completion.
    fn run_halted_verb(&self) -> Run {
        let output = self
            .halted_verb()
            .output()
            .expect("stellar-agent binary must run");
        Run::from_output(&output)
    }

    /// The lock every outbox append takes.
    fn outbox_lock(&self) -> PathBuf {
        PathBuf::from(format!(
            "{}.outbox.lock",
            self.profile.audit_log_path.display()
        ))
    }

    /// Removes the audit chain-root key from the store, so no keyed writer
    /// for the profile can open.
    fn remove_audit_key(&self) {
        let coordinate = &self.profile.audit_log_hash_chain_key_id;
        keyring_core::Entry::new(&coordinate.service, &coordinate.account)
            .unwrap()
            .delete_credential()
            .unwrap();
    }

    /// A draining keyed writer on the profile's log, as a running MCP server
    /// holds it.
    fn draining_writer(&self) -> AuditWriter {
        let access = keyed_audit_access(&self.profile, PROFILE, BindingCheck::Enforce).unwrap();
        AuditWriter::open(self.profile.audit_log_path.clone(), Some(access)).unwrap()
    }

    fn outbox_pending(&self) -> usize {
        inspect_outbox(&self.profile.audit_log_path)
            .unwrap()
            .pending
    }

    /// The `kind` of every row in the profile's log; an absent log holds no
    /// rows, and a log that cannot be read fails the test.
    fn audit_kinds(&self) -> Vec<String> {
        let text = match std::fs::read_to_string(&self.profile.audit_log_path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(error) => panic!(
                "the audit log {} cannot be read: {error}",
                self.profile.audit_log_path.display()
            ),
        };
        text.lines()
            .map(|line| {
                let row: Value = serde_json::from_str(line).unwrap();
                row["kind"].as_str().unwrap().to_owned()
            })
            .collect()
    }
}

/// The binary in `home` with `args`, under the headless backend and with
/// every overlay that selects another profile, endpoint or secret removed.
fn command_in(home: &Path, args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_stellar-agent"));
    command
        .args(args)
        .env("STELLAR_AGENT_HOME", home)
        .env("STELLAR_AGENT_KEYRING_BACKEND", "headless-env")
        .env(
            "STELLAR_AGENT_HEADLESS_KEYRING_KEY",
            URL_SAFE_NO_PAD.encode(HEADLESS_KEY),
        )
        .env_remove(UNSET_SECRET_ENV)
        .env_remove("STELLAR_AGENT_PROFILE")
        .env_remove("STELLAR_AGENT_CHAIN_ID")
        .env_remove("STELLAR_AGENT_RPC_URL")
        .env_remove("STELLAR_AGENT_SECONDARY_RPC_URL")
        .env_remove("STELLAR_AGENT_ORACLE_PROVIDER_URL")
        .env_remove("STELLAR_AGENT_MCP_SIGNER_DEFAULT")
        .env_remove(OUTBOX_LOCK_WAIT_ENV);
    command
}

/// Reads `pipe` to its end on a thread and returns everything it carried. When
/// `lines` is given, each line is also sent there as it arrives.
fn drain_pipe(
    pipe: impl std::io::Read + Send + 'static,
    lines: Option<mpsc::Sender<String>>,
) -> JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut reader = BufReader::new(pipe);
        let mut all = Vec::new();
        let Some(lines) = lines else {
            let _ = reader.read_to_end(&mut all);
            return all;
        };
        let mut line = Vec::new();
        loop {
            line.clear();
            match reader.read_until(b'\n', &mut line) {
                Ok(0) | Err(_) => return all,
                Ok(_) => {
                    all.extend_from_slice(&line);
                    let _ = lines.send(String::from_utf8_lossy(&line).into_owned());
                }
            }
        }
    })
}

/// A child process with a deadline: a child that outlives it is killed and
/// reaped, and the test fails naming the child and what it was waiting for. A
/// child still running when the value drops, because an assertion failed, is
/// killed and reaped as well.
struct BoundedChild {
    label: &'static str,
    child: Child,
    deadline: Instant,
    stdout: Option<JoinHandle<Vec<u8>>>,
    stderr: Option<JoinHandle<Vec<u8>>>,
    stderr_lines: Receiver<String>,
}

impl BoundedChild {
    fn spawn(label: &'static str, mut command: Command, limit: Duration) -> Self {
        let mut child = command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("stellar-agent binary must run");
        let deadline = Instant::now() + limit;
        let (sender, stderr_lines) = mpsc::channel();
        let stdout = drain_pipe(child.stdout.take().expect("stdout is piped"), None);
        let stderr = drain_pipe(child.stderr.take().expect("stderr is piped"), Some(sender));
        Self {
            label,
            child,
            deadline,
            stdout: Some(stdout),
            stderr: Some(stderr),
            stderr_lines,
        }
    }

    fn is_running(&mut self) -> bool {
        self.child
            .try_wait()
            .expect("the child status is readable")
            .is_none()
    }

    /// Waits for a stderr line containing `needle`. A child that exits first,
    /// or is still silent at its deadline, fails the test.
    fn wait_for_stderr(&mut self, needle: &str) {
        loop {
            let left = self.deadline.saturating_duration_since(Instant::now());
            match self.stderr_lines.recv_timeout(left) {
                Ok(line) if line.contains(needle) => return,
                Ok(_) => {}
                Err(RecvTimeoutError::Disconnected) => {
                    let run = self.finish();
                    panic!(
                        "{} exited before its stderr reported {needle:?}: {}",
                        self.label,
                        run.describe()
                    );
                }
                Err(RecvTimeoutError::Timeout) => {
                    self.kill_and_fail(&format!("its stderr reporting {needle:?}"));
                }
            }
        }
    }

    /// Waits for the child to exit within its deadline and returns its output.
    fn finish(&mut self) -> Run {
        let status = loop {
            if let Some(status) = self.child.try_wait().expect("the child status is readable") {
                break status;
            }
            if Instant::now() >= self.deadline {
                self.kill_and_fail("its exit");
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        let (stdout, stderr) = self.take_output();
        Run::from_output(&Output {
            status,
            stdout,
            stderr,
        })
    }

    /// Joins both pipe readers; the child has exited, so both pipes are closed.
    fn take_output(&mut self) -> (Vec<u8>, Vec<u8>) {
        let join = |reader: Option<JoinHandle<Vec<u8>>>| {
            reader
                .map(|reader| reader.join().expect("the pipe reader finishes"))
                .unwrap_or_default()
        };
        (join(self.stdout.take()), join(self.stderr.take()))
    }

    fn kill_and_fail(&mut self, awaited: &str) -> ! {
        let _ = self.child.kill();
        let status = self.child.wait();
        let (stdout, stderr) = self.take_output();
        panic!(
            "{} passed its deadline waiting for {awaited}; killed and reaped ({status:?}); \
             stdout={}; stderr={}",
            self.label,
            String::from_utf8_lossy(&stdout).trim(),
            String::from_utf8_lossy(&stderr).trim()
        );
    }
}

impl Drop for BoundedChild {
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

/// Runs `command` to completion within `limit`; see [`BoundedChild`].
fn run_bounded(label: &'static str, command: Command, limit: Duration) -> Run {
    BoundedChild::spawn(label, command, limit).finish()
}

/// Runs the binary in `home` with `args` to completion; see [`command_in`].
fn run_in(home: &Path, args: &[&str]) -> Run {
    let output = command_in(home, args)
        .output()
        .expect("stellar-agent binary must run");
    Run::from_output(&output)
}

/// One invocation per CLI check site, each naming the fixture profile and,
/// where the verb takes one, the unset signer secret. The label names the
/// verb and the source file of its check.
fn checked_site_invocations(rpc_url: &str) -> Vec<(&'static str, Vec<String>)> {
    let owned = |args: &[&str]| args.iter().map(|arg| (*arg).to_owned()).collect::<Vec<_>>();
    let asset = format!("USDC:{ACCOUNT_G}");
    let invocation = format!("{CONTRACT}:transfer:[]");
    let balance_id = format!("00000000{HEX32}");
    let smart_account = |verb: &[&str], extra: &[&str]| {
        let mut args = vec!["smart-account"];
        args.extend_from_slice(verb);
        args.extend_from_slice(&["--profile", PROFILE]);
        args.extend_from_slice(extra);
        args.extend_from_slice(&["--signer-secret-env", UNSET_SECRET_ENV]);
        owned(&args)
    };
    let deploy = |verb: &str, extra: &[&str]| {
        let mut args = vec!["smart-account", verb, "--profile", PROFILE];
        args.extend_from_slice(extra);
        args.extend_from_slice(&["--deployer-secret-env", UNSET_SECRET_ENV]);
        owned(&args)
    };
    let rule = ["--account", CONTRACT, "--rule-id", "1"];
    let with_rule = |extra: &[&'static str]| -> Vec<&'static str> {
        let mut args = rule.to_vec();
        args.extend_from_slice(extra);
        args
    };
    vec![
        (
            "pay (pay.rs)",
            owned(&[
                "pay",
                ACCOUNT_G,
                "1 XLM",
                "--profile",
                PROFILE,
                "--source",
                ACCOUNT_G,
                "--secret-env",
                UNSET_SECRET_ENV,
            ]),
        ),
        (
            "claim (claim.rs)",
            owned(&[
                "claim",
                &balance_id,
                "--profile",
                PROFILE,
                "--source",
                ACCOUNT_G,
                "--secret-env",
                UNSET_SECRET_ENV,
            ]),
        ),
        (
            "accounts create --sponsor (accounts/create.rs)",
            owned(&[
                "accounts",
                "create",
                NEW_ACCOUNT_G,
                "--profile",
                PROFILE,
                "--sponsor",
                ACCOUNT_G,
                "--secret-env",
                UNSET_SECRET_ENV,
                "--starting-balance",
                "1",
            ]),
        ),
        (
            "accounts create --fund-with-friendbot (accounts/create.rs)",
            owned(&[
                "accounts",
                "create",
                NEW_ACCOUNT_G,
                "--profile",
                PROFILE,
                "--fund-with-friendbot",
                "--friendbot-url",
                rpc_url,
            ]),
        ),
        (
            "trustline (trustline.rs)",
            owned(&[
                "trustline",
                "--profile",
                PROFILE,
                "--from",
                ACCOUNT_G,
                "--asset",
                &asset,
            ]),
        ),
        (
            "trade (trade.rs)",
            owned(&[
                "trade",
                "--profile",
                PROFILE,
                "--from",
                CONTRACT,
                "--amount-in",
                "1",
                "--amount-out-min",
                "1",
                "--path",
                &format!("{CONTRACT},{CONTRACT}"),
            ]),
        ),
        (
            "vault deposit (vault.rs, run_deposit)",
            owned(&[
                "vault",
                "deposit",
                "--profile",
                PROFILE,
                "--vault",
                CONTRACT,
                "--from",
                CONTRACT,
                "--amounts-desired",
                "1",
                "--amounts-min",
                "1",
            ]),
        ),
        (
            "vault withdraw (vault.rs, run_withdraw)",
            owned(&[
                "vault",
                "withdraw",
                "--profile",
                PROFILE,
                "--vault",
                CONTRACT,
                "--from",
                CONTRACT,
                "--shares",
                "1",
                "--min-amounts-out",
                "1",
            ]),
        ),
        (
            "mpp charge authorize (mpp.rs)",
            owned(&[
                "mpp",
                "charge",
                "authorize",
                "--profile",
                PROFILE,
                "--approval-id",
                "halt-test",
            ]),
        ),
        (
            "smart-account multicall (smart_account/multicall.rs)",
            owned(&[
                "smart-account",
                "multicall",
                "--profile",
                PROFILE,
                "--smart-account",
                CONTRACT,
                "--rule-id",
                "1",
                "--invocation",
                &invocation,
                "--secondary-rpc-url",
                rpc_url,
                "--signer-secret-env",
                UNSET_SECRET_ENV,
            ]),
        ),
        (
            "smart-account execute (smart_account/execute.rs)",
            owned(&[
                "smart-account",
                "execute",
                "--profile",
                PROFILE,
                "--account",
                CONTRACT,
                "--contract",
                CONTRACT,
                "--function",
                "ping",
                "--auth-rule-id",
                "1",
                "--rule-signer-ed25519-secret-env",
                UNSET_SECRET_ENV,
            ]),
        ),
        (
            "smart-account rules create (rules.rs)",
            smart_account(
                &["rules", "create"],
                &[
                    "--account",
                    CONTRACT,
                    "--name",
                    "halted",
                    "--signer-delegated",
                    ACCOUNT_G,
                ],
            ),
        ),
        (
            "smart-account rules set-name (rules.rs)",
            smart_account(&["rules", "set-name"], &with_rule(&["--name", "renamed"])),
        ),
        (
            "smart-account rules set-valid-until (rules.rs)",
            smart_account(
                &["rules", "set-valid-until"],
                &with_rule(&["--valid-until", "none"]),
            ),
        ),
        (
            "smart-account rules delete (rules.rs)",
            smart_account(&["rules", "delete"], &rule),
        ),
        (
            "smart-account rules add-policy (rules.rs)",
            smart_account(
                &["rules", "add-policy"],
                &with_rule(&[
                    "--kind",
                    "simple-threshold",
                    "--threshold",
                    "1",
                    "--policy",
                    CONTRACT,
                ]),
            ),
        ),
        (
            "smart-account rules remove-policy (rules.rs)",
            smart_account(
                &["rules", "remove-policy"],
                &with_rule(&["--policy-id", "1"]),
            ),
        ),
        (
            "smart-account rules set-spending-limit (rules.rs)",
            smart_account(
                &["rules", "set-spending-limit"],
                &with_rule(&["--limit", "1"]),
            ),
        ),
        (
            "smart-account signers add (signers.rs)",
            smart_account(
                &["signers", "add"],
                &with_rule(&["--signer-delegated", ACCOUNT_G]),
            ),
        ),
        (
            "smart-account signers remove (signers.rs)",
            smart_account(&["signers", "remove"], &with_rule(&["--signer-id", "1"])),
        ),
        (
            "smart-account signers set-threshold (signers.rs)",
            smart_account(
                &["signers", "set-threshold"],
                &with_rule(&["--new-threshold", "1"]),
            ),
        ),
        (
            "smart-account signers set-weighted-threshold (signers.rs)",
            smart_account(
                &["signers", "set-weighted-threshold"],
                &with_rule(&["--new-threshold", "1"]),
            ),
        ),
        (
            "smart-account signers set-signer-weight (signers.rs)",
            smart_account(
                &["signers", "set-signer-weight"],
                &with_rule(&["--new-weight", "1", "--signer-delegated", ACCOUNT_G]),
            ),
        ),
        (
            "smart-account signers batch-add (signers.rs)",
            smart_account(
                &["signers", "batch-add"],
                &with_rule(&["--signer-delegated", ACCOUNT_G]),
            ),
        ),
        (
            "smart-account migrate-verifier (smart_account/migrate_verifier.rs)",
            smart_account(
                &["migrate-verifier"],
                &["--account", CONTRACT, "--from", HEX32, "--to", CONTRACT],
            ),
        ),
        (
            "smart-account deploy-webauthn-verifier (deploy_webauthn_verifier.rs)",
            deploy("deploy-webauthn-verifier", &[]),
        ),
        (
            "smart-account deploy-ed25519-verifier (deploy_ed25519_verifier.rs)",
            deploy("deploy-ed25519-verifier", &[]),
        ),
        (
            "smart-account deploy-spending-limit-policy (deploy_spending_limit_policy.rs)",
            deploy("deploy-spending-limit-policy", &[]),
        ),
        (
            "smart-account deploy-policy (deploy_policy.rs)",
            deploy("deploy-policy", &["--kind", "simple-threshold"]),
        ),
        (
            "accounts deploy-c (accounts/deploy_c.rs)",
            owned(&[
                "accounts",
                "deploy-c",
                "--profile",
                PROFILE,
                "--deployer-secret-env",
                UNSET_SECRET_ENV,
                "--initial-signer",
                ACCOUNT_G,
                "--salt-random",
            ]),
        ),
        (
            "smart-account timelock schedule (timelock/schedule.rs)",
            smart_account(
                &["timelock", "schedule"],
                &[
                    "--timelock",
                    CONTRACT,
                    "--target",
                    CONTRACT,
                    "--function",
                    "ping",
                    "--delay-ledgers",
                    "1",
                ],
            ),
        ),
        (
            "smart-account timelock cancel (timelock/cancel.rs)",
            smart_account(
                &["timelock", "cancel"],
                &["--timelock", CONTRACT, "--operation-id", HEX32],
            ),
        ),
        (
            "smart-account timelock execute (timelock/execute.rs)",
            smart_account(
                &["timelock", "execute"],
                &[
                    "--timelock",
                    CONTRACT,
                    "--target",
                    CONTRACT,
                    "--function",
                    "ping",
                    "--operation-id",
                    HEX32,
                    "--salt",
                    HEX32,
                ],
            ),
        ),
        (
            "pool init (pool/init.rs)",
            owned(&["pool", "init", "--profile", PROFILE, "--size", "1"]),
        ),
    ]
}

/// The expected refusal message for a marker stamped `halted_at` with `reason`.
fn halted_message(halted_at: &str, reason: &str) -> String {
    format!(
        "profile \"{PROFILE}\" is halted since {halted_at}: {reason}; run \"stellar-agent profile resume --profile {PROFILE}\" to lift it"
    )
}

#[test]
#[serial]
fn every_check_site_refuses_while_halted_and_proceeds_after_resume() {
    let f = Fixture::new();
    let halt = f.run(&[
        "profile",
        "halt",
        "--profile",
        PROFILE,
        "--reason",
        "incident",
    ]);
    assert_eq!(halt.code, 0, "{}", halt.describe());
    let halted_at = halt.envelope["data"]["halted_at"]
        .as_str()
        .unwrap()
        .to_owned();
    let expected = halted_message(&halted_at, "incident");
    let sites = checked_site_invocations(&f.rpc_url());
    assert_eq!(sites.len(), 34, "one invocation per check site");
    let mut failures = Vec::new();
    for (name, args) in &sites {
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let before = f.counter.accepted().unwrap();
        let run = f.run(&args);
        let connections = f.counter.accepted().unwrap() - before;
        let message = run.envelope["error"]["message"].as_str();
        if run.code != 1
            || run.error_code() != Some("profile.halted")
            || message != Some(expected.as_str())
            || connections != 0
        {
            failures.push(format!(
                "{name}: {connections} connections; {}",
                run.describe()
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "every check site refuses a halted profile before any signer read or request:\n{}",
        failures.join("\n")
    );

    let resume = f.run(&["profile", "resume", "--profile", PROFILE]);
    assert_eq!(resume.code, 0, "{}", resume.describe());
    let mut failures = Vec::new();
    for (name, args) in &sites {
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let run = f.run(&args);
        let code = run.error_code().unwrap_or_default();
        if run.code != 1 || code.is_empty() || code.starts_with("profile.halt") {
            failures.push(format!("{name}: {}", run.describe()));
        }
    }
    assert!(
        failures.is_empty(),
        "after resume every invocation passes the halt check and fails at a later step:\n{}",
        failures.join("\n")
    );
    assert!(
        f.counter.accepted().unwrap() > 0,
        "the resumed invocations reach the endpoint the halted ones never contacted"
    );
}

#[test]
#[serial]
fn halt_and_resume_write_verified_audit_rows_and_show_reports_the_state() {
    let f = Fixture::new();
    let shown = f.run(&["profile", "show", "--profile", PROFILE]);
    assert_eq!(shown.code, 0, "{}", shown.describe());
    assert_eq!(
        shown.envelope["data"]["halted"],
        false,
        "{}",
        shown.describe()
    );
    assert!(shown.envelope["data"]["halted_at"].is_null());

    let halt = f.run(&[
        "profile",
        "halt",
        "--profile",
        PROFILE,
        "--reason",
        "key leak",
    ]);
    assert_eq!(halt.code, 0, "{}", halt.describe());
    assert_eq!(halt.envelope["data"]["halted"], true);
    assert_eq!(halt.envelope["data"]["reason"], "key leak");
    assert_eq!(
        halt.envelope["data"]["audit_row"],
        "written",
        "{}",
        halt.describe()
    );
    assert!(f.marker().is_file());
    let halted_at = halt.envelope["data"]["halted_at"]
        .as_str()
        .unwrap()
        .to_owned();

    let shown = f.run(&["profile", "show", "--profile", PROFILE]);
    assert_eq!(
        shown.envelope["data"]["halted"],
        true,
        "{}",
        shown.describe()
    );
    assert_eq!(
        shown.envelope["data"]["halted_at"].as_str(),
        Some(halted_at.as_str())
    );
    assert_eq!(shown.envelope["data"]["halt_reason"], "key leak");

    let resume = f.run(&["profile", "resume", "--profile", PROFILE]);
    assert_eq!(resume.code, 0, "{}", resume.describe());
    assert_eq!(resume.envelope["data"]["halted"], false);
    assert_eq!(resume.envelope["data"]["was_halted"], true);
    assert_eq!(
        resume.envelope["data"]["audit_row"],
        "written",
        "{}",
        resume.describe()
    );
    assert!(!f.marker().exists());

    let shown = f.run(&["profile", "show", "--profile", PROFILE]);
    assert_eq!(
        shown.envelope["data"]["halted"],
        false,
        "{}",
        shown.describe()
    );

    let kinds = f.audit_kinds();
    assert_eq!(
        kinds,
        vec!["profile_halted".to_owned(), "profile_resumed".to_owned()],
        "the log holds exactly the two operator rows"
    );
    let rows: Vec<Value> = std::fs::read_to_string(&f.profile.audit_log_path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(rows[0]["profile"], PROFILE);
    assert_eq!(rows[0]["halted_at"].as_str(), Some(halted_at.as_str()));
    assert_eq!(rows[0]["reason"], "key leak");
    assert_eq!(rows[1]["profile"], PROFILE);
    assert_eq!(rows[1]["was_halted"], true);

    let log = f.profile.audit_log_path.to_string_lossy().into_owned();
    let verify = f.run(&["audit", "verify", &log, "--profile", PROFILE]);
    assert_eq!(verify.code, 0, "{}", verify.describe());
    assert_eq!(verify.envelope["ok"], true, "{}", verify.describe());
}

#[test]
#[serial]
fn halting_a_missing_profile_fails_with_the_load_error_and_writes_no_marker() {
    let f = Fixture::new();
    let missing = "halt-cli-missing";
    let reference = f.run(&["profile", "show", "--profile", missing]);
    assert_eq!(reference.code, 1, "{}", reference.describe());
    let halt = f.run(&["profile", "halt", "--profile", missing]);
    assert_eq!(halt.code, 1, "{}", halt.describe());
    assert_eq!(
        halt.error_code(),
        reference.error_code(),
        "{}",
        halt.describe()
    );
    let with_invalid_reason = f.run(&["profile", "halt", "--profile", missing, "--reason", " "]);
    assert_eq!(
        with_invalid_reason.error_code(),
        reference.error_code(),
        "the profile loads before the reason is examined: {}",
        with_invalid_reason.describe()
    );
    assert!(
        !f.home
            .path()
            .join("profiles")
            .join(format!("{missing}.halt"))
            .exists(),
        "a refused halt leaves no marker"
    );
    let resume = f.run(&["profile", "resume", "--profile", missing]);
    assert_eq!(resume.code, 1, "{}", resume.describe());
    assert_eq!(
        resume.error_code(),
        reference.error_code(),
        "{}",
        resume.describe()
    );
}

#[test]
#[serial]
fn resuming_a_running_profile_exits_zero_and_halting_twice_rewrites_the_marker() {
    let f = Fixture::new();
    let resume = f.run(&["profile", "resume", "--profile", PROFILE]);
    assert_eq!(resume.code, 0, "{}", resume.describe());
    assert_eq!(resume.envelope["data"]["halted"], false);
    assert_eq!(resume.envelope["data"]["was_halted"], false);
    assert!(!f.marker().exists());

    let first = f.run(&["profile", "halt", "--profile", PROFILE, "--reason", "first"]);
    assert_eq!(first.code, 0, "{}", first.describe());
    let second = f.run(&[
        "profile",
        "halt",
        "--profile",
        PROFILE,
        "--reason",
        "second",
    ]);
    assert_eq!(second.code, 0, "{}", second.describe());
    let marker = std::fs::read_to_string(f.marker()).unwrap();
    assert!(
        marker.contains("second") && !marker.contains("first"),
        "{marker}"
    );
}

#[test]
#[serial]
fn an_operator_ceremony_and_read_only_verbs_work_while_halted() {
    let f = Fixture::new();
    let halt = f.run(&["profile", "halt", "--profile", PROFILE]);
    assert_eq!(halt.code, 0, "{}", halt.describe());

    let rotate = f.run(&["profile", "rotate-nonce-key", "--profile", PROFILE]);
    assert_eq!(rotate.code, 0, "{}", rotate.describe());

    let list = f.run(&["profile", "list"]);
    assert_eq!(list.code, 0, "{}", list.describe());

    let log = f.profile.audit_log_path.to_string_lossy().into_owned();
    let verify = f.run(&["audit", "verify", &log, "--profile", PROFILE]);
    assert_eq!(verify.code, 0, "{}", verify.describe());

    let build_only = f.run(&[
        "pay",
        ACCOUNT_G,
        "1 XLM",
        "--profile",
        PROFILE,
        "--build-only",
        "--source",
        ACCOUNT_G,
    ]);
    assert_ne!(
        build_only.error_code(),
        Some("profile.halted"),
        "an unsigned build is not refused: {}",
        build_only.describe()
    );
    let dry_run = f.run(&[
        "smart-account",
        "migrate-verifier",
        "--profile",
        PROFILE,
        "--account",
        CONTRACT,
        "--from",
        HEX32,
        "--to",
        CONTRACT,
        "--dry-run",
    ]);
    assert_ne!(
        dry_run.error_code(),
        Some("profile.halted"),
        "a migration plan that reads chain state only is not refused: {}",
        dry_run.describe()
    );
    assert!(
        f.marker().is_file(),
        "the read-only verbs leave the marker in place"
    );
}

#[test]
#[serial]
fn an_unreadable_marker_refuses_with_halt_unreadable() {
    let f = Fixture::new();
    std::fs::create_dir_all(f.marker()).unwrap();
    let run = f.run_halted_verb();
    assert_eq!(run.code, 1, "{}", run.describe());
    assert_eq!(
        run.error_code(),
        Some("profile.halt_unreadable"),
        "{}",
        run.describe()
    );
    assert_eq!(f.counter.accepted().unwrap(), 0);
    let shown = f.run(&["profile", "show", "--profile", PROFILE]);
    assert_eq!(shown.code, 0, "{}", shown.describe());
    assert_eq!(
        shown.envelope["data"]["halted"],
        true,
        "{}",
        shown.describe()
    );
    assert!(
        shown.envelope["data"]["halt_marker_error"].is_string(),
        "{}",
        shown.describe()
    );
}

#[test]
#[serial]
fn a_halt_whose_audit_row_cannot_be_written_stays_in_effect() {
    let f = Fixture::new();
    f.remove_audit_key();
    let halt = f.run(&[
        "profile",
        "halt",
        "--profile",
        PROFILE,
        "--reason",
        "no audit",
    ]);
    assert_eq!(halt.code, 0, "{}", halt.describe());
    assert_eq!(halt.envelope["data"]["halted"], true, "{}", halt.describe());
    assert_eq!(
        halt.envelope["data"]["audit_row"],
        "not_written",
        "{}",
        halt.describe()
    );
    assert!(f.marker().is_file(), "the marker is written");
    assert!(
        !f.audit_kinds().contains(&"profile_halted".to_owned()),
        "no row lands"
    );
    let shown = f.run(&["profile", "show", "--profile", PROFILE]);
    assert_eq!(
        shown.envelope["data"]["halted"],
        true,
        "{}",
        shown.describe()
    );
}

#[test]
#[serial]
fn a_resume_whose_audit_log_is_unavailable_keeps_the_halt() {
    let f = Fixture::new();
    let halt = f.run(&["profile", "halt", "--profile", PROFILE]);
    assert_eq!(halt.code, 0, "{}", halt.describe());
    assert_eq!(halt.envelope["data"]["audit_row"], "written");
    let marker = std::fs::read(f.marker()).unwrap();

    f.remove_audit_key();
    let resume = f.run(&["profile", "resume", "--profile", PROFILE]);
    assert_eq!(resume.code, 1, "{}", resume.describe());
    assert_eq!(
        resume.error_code(),
        Some("audit.chain_key_unavailable"),
        "the refusal names the audit log: {}",
        resume.describe()
    );
    assert_eq!(
        std::fs::read(f.marker()).unwrap(),
        marker,
        "the halt stays in place unchanged"
    );
    assert_eq!(
        f.audit_kinds(),
        vec!["profile_halted".to_owned()],
        "no resume is recorded"
    );
    let shown = f.run(&["profile", "show", "--profile", PROFILE]);
    assert_eq!(
        shown.envelope["data"]["halted"],
        true,
        "{}",
        shown.describe()
    );
}

#[test]
#[serial]
fn beside_a_draining_writer_both_rows_are_queued_and_drain_into_a_verified_log() {
    let f = Fixture::new();
    let server = f.draining_writer();

    let halt = f.run(&[
        "profile",
        "halt",
        "--profile",
        PROFILE,
        "--reason",
        "queued",
    ]);
    assert_eq!(halt.code, 0, "{}", halt.describe());
    assert_eq!(
        halt.envelope["data"]["audit_row"],
        "queued",
        "{}",
        halt.describe()
    );
    assert!(
        f.marker().is_file(),
        "the halt is in effect while its row is queued"
    );
    assert_eq!(f.outbox_pending(), 1);

    let resume = f.run(&["profile", "resume", "--profile", PROFILE]);
    assert_eq!(resume.code, 0, "{}", resume.describe());
    assert_eq!(
        resume.envelope["data"]["audit_row"],
        "queued",
        "{}",
        resume.describe()
    );
    assert!(!f.marker().exists(), "the resume removed the marker");
    assert_eq!(f.outbox_pending(), 2);
    assert!(
        !f.audit_kinds().contains(&"profile_halted".to_owned()),
        "queued, not yet logged"
    );

    drop(server);
    drop(f.draining_writer());
    assert_eq!(
        f.outbox_pending(),
        0,
        "the next draining writer drains both rows"
    );
    let kinds: Vec<String> = f
        .audit_kinds()
        .into_iter()
        .filter(|kind| kind.starts_with("profile_"))
        .collect();
    assert_eq!(
        kinds,
        vec!["profile_halted".to_owned(), "profile_resumed".to_owned()]
    );
    let log = f.profile.audit_log_path.to_string_lossy().into_owned();
    let verify = f.run(&["audit", "verify", &log, "--profile", PROFILE]);
    assert_eq!(verify.code, 0, "{}", verify.describe());
    assert_eq!(verify.envelope["ok"], true, "{}", verify.describe());
}

#[test]
#[serial]
fn a_resume_whose_row_cannot_be_appended_keeps_the_marker() {
    let f = Fixture::new();
    let server = f.draining_writer();
    let halt = f.run(&[
        "profile",
        "halt",
        "--profile",
        PROFILE,
        "--reason",
        "restore",
    ]);
    assert_eq!(halt.code, 0, "{}", halt.describe());
    assert_eq!(
        halt.envelope["data"]["audit_row"],
        "queued",
        "{}",
        halt.describe()
    );
    let marker = std::fs::read(f.marker()).unwrap();

    // The outbox lock path turns into a directory, so the resume's append to
    // the outbox fails.
    let lock = f.outbox_lock();
    if lock.exists() {
        std::fs::remove_file(&lock).unwrap();
    }
    std::fs::create_dir(&lock).unwrap();

    let resume = f.run(&["profile", "resume", "--profile", PROFILE]);
    assert_eq!(resume.code, 1, "{}", resume.describe());
    assert!(
        resume
            .error_code()
            .unwrap_or_default()
            .starts_with("audit."),
        "the refusal names the audit log: {}",
        resume.describe()
    );
    assert_eq!(
        std::fs::read(f.marker()).unwrap(),
        marker,
        "the marker stays as it was"
    );
    assert_eq!(f.outbox_pending(), 1, "only the halt row is queued");
    let verb = f.run_halted_verb();
    assert_eq!(verb.code, 1, "{}", verb.describe());
    assert_eq!(
        verb.error_code(),
        Some("profile.halted"),
        "{}",
        verb.describe()
    );
    assert_eq!(f.counter.accepted().unwrap(), 0);
    drop(server);
}

#[test]
#[serial]
fn a_resume_of_an_unreadable_marker_refuses_and_records_no_resume() {
    let f = Fixture::new();
    std::fs::create_dir_all(f.marker()).unwrap();
    let resume = f.run(&["profile", "resume", "--profile", PROFILE]);
    assert_eq!(resume.code, 1, "{}", resume.describe());
    assert_eq!(
        resume.error_code(),
        Some("profile.halt_unreadable"),
        "{}",
        resume.describe()
    );
    assert!(f.marker().is_dir(), "the directory stays");
    assert_eq!(
        f.audit_kinds(),
        Vec::<String>::new(),
        "a resume that cannot read the marker writes no row to the log"
    );
    assert_eq!(
        f.outbox_pending(),
        0,
        "a resume that cannot read the marker queues no row"
    );
    let verb = f.run_halted_verb();
    assert_eq!(verb.code, 1, "{}", verb.describe());
    assert_eq!(
        verb.error_code(),
        Some("profile.halt_unreadable"),
        "{}",
        verb.describe()
    );
    assert_eq!(f.counter.accepted().unwrap(), 0);
}

#[cfg(unix)]
#[test]
#[serial]
fn a_resume_whose_marker_cannot_be_removed_keeps_the_halt_with_its_row() {
    use std::os::unix::fs::PermissionsExt as _;

    let f = Fixture::new();
    let halt = f.run(&[
        "profile",
        "halt",
        "--profile",
        PROFILE,
        "--reason",
        "sealed",
    ]);
    assert_eq!(halt.code, 0, "{}", halt.describe());
    assert_eq!(halt.envelope["data"]["audit_row"], "written");
    let marker = std::fs::read(f.marker()).unwrap();
    let profiles = f.home.path().join("profiles");

    // A directory without write permission keeps its entries readable and
    // refuses their removal.
    std::fs::set_permissions(&profiles, std::fs::Permissions::from_mode(0o555)).unwrap();
    // A process with CAP_DAC_OVERRIDE writes the directory despite its mode;
    // the removal then succeeds and the resume completes.
    let probe = profiles.join("write-probe");
    let writes_anyway = std::fs::File::create(&probe).is_ok();
    if writes_anyway {
        std::fs::remove_file(&probe).unwrap();
    }
    let resume = f.run(&["profile", "resume", "--profile", PROFILE]);
    std::fs::set_permissions(&profiles, std::fs::Permissions::from_mode(0o755)).unwrap();

    if writes_anyway {
        assert_eq!(resume.code, 0, "{}", resume.describe());
        assert!(!f.marker().exists());
        return;
    }
    assert_eq!(resume.code, 1, "{}", resume.describe());
    assert_eq!(
        resume.error_code(),
        Some("io.halt_marker"),
        "{}",
        resume.describe()
    );
    let message = resume.envelope["error"]["message"]
        .as_str()
        .unwrap_or_default();
    assert!(
        message.contains(&format!(
            "run \"stellar-agent profile resume --profile {PROFILE}\" again"
        )),
        "the refusal names the rerun: {message}"
    );
    assert_eq!(
        std::fs::read(f.marker()).unwrap(),
        marker,
        "the marker stays byte for byte"
    );
    assert_eq!(
        f.audit_kinds(),
        vec!["profile_halted".to_owned(), "profile_resumed".to_owned()],
        "the row of the attempt is recorded"
    );
    let shown = f.run(&["profile", "show", "--profile", PROFILE]);
    assert_eq!(
        shown.envelope["data"]["halted"],
        true,
        "{}",
        shown.describe()
    );
    let verb = f.run_halted_verb();
    assert_eq!(verb.code, 1, "{}", verb.describe());
    assert_eq!(
        verb.error_code(),
        Some("profile.halted"),
        "{}",
        verb.describe()
    );
    assert_eq!(f.counter.accepted().unwrap(), 0);

    let rerun = f.run(&["profile", "resume", "--profile", PROFILE]);
    assert_eq!(rerun.code, 0, "{}", rerun.describe());
    assert!(!f.marker().exists(), "the rerun removes the marker");
    let log = f.profile.audit_log_path.to_string_lossy().into_owned();
    let verify = f.run(&["audit", "verify", &log, "--profile", PROFILE]);
    assert_eq!(verify.code, 0, "{}", verify.describe());
}

/// The outbox lock wait of the resume child in
/// `while_the_resume_row_waits_on_the_outbox_lock_the_halt_holds`.
const HELD_LOCK_WAIT: Duration = Duration::from_secs(20);

/// The deadline of the resume child, above [`HELD_LOCK_WAIT`].
const RESUME_DEADLINE: Duration = Duration::from_secs(60);

/// The deadline of each other child of that test.
const STEP_DEADLINE: Duration = Duration::from_secs(10);

/// The debug event an append emits when it starts to wait on a held outbox
/// lock.
const OUTBOX_WAIT_EVENT: &str = "audit outbox: the outbox lock is held; waiting for it";

#[test]
#[serial]
fn while_the_resume_row_waits_on_the_outbox_lock_the_halt_holds() {
    let f = Fixture::new();
    let server = f.draining_writer();
    let halt = run_bounded(
        "profile halt",
        command_in(
            f.home.path(),
            &["profile", "halt", "--profile", PROFILE, "--reason", "held"],
        ),
        STEP_DEADLINE,
    );
    assert_eq!(halt.code, 0, "{}", halt.describe());
    assert_eq!(
        halt.envelope["data"]["audit_row"],
        "queued",
        "{}",
        halt.describe()
    );
    let marker = std::fs::read(f.marker()).unwrap();

    // Another appender holds the outbox lock for the resume's whole wait.
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(f.outbox_lock())
        .unwrap();
    lock.try_lock().unwrap();

    let mut resume_command =
        command_in(f.home.path(), &["profile", "resume", "--profile", PROFILE]);
    resume_command
        .env(OUTBOX_LOCK_WAIT_ENV, HELD_LOCK_WAIT.as_millis().to_string())
        .env(
            "STELLAR_AGENT_LOG",
            "info,stellar_agent_core::audit_log::outbox=debug",
        );
    let spawned = Instant::now();
    let mut resume = BoundedChild::spawn("profile resume", resume_command, RESUME_DEADLINE);

    // The event follows the append's first refused attempt on the lock, so
    // what the test observes from here on happens after the wait began. The
    // wait began after the spawn, so while less than HELD_LOCK_WAIT has passed
    // since the spawn it has not ended.
    resume.wait_for_stderr(OUTBOX_WAIT_EVENT);
    let marker_during_the_wait = std::fs::read(f.marker());
    let verb = run_bounded("trustline", f.halted_verb(), STEP_DEADLINE);
    let observed_after = spawned.elapsed();
    let resume_still_running = resume.is_running();

    assert!(
        matches!(&marker_during_the_wait, Ok(bytes) if *bytes == marker),
        "the marker holds while the resume row waits: {marker_during_the_wait:?}"
    );
    assert_eq!(verb.code, 1, "{}", verb.describe());
    assert_eq!(
        verb.error_code(),
        Some("profile.halted"),
        "a verb during the resume's wait refuses: {}",
        verb.describe()
    );
    assert!(
        resume_still_running && observed_after < HELD_LOCK_WAIT,
        "the marker read and the refused verb finished inside the resume's lock wait: \
         {observed_after:?} after the spawn, resume running {resume_still_running}"
    );

    let resume = resume.finish();
    lock.unlock().unwrap();
    drop(lock);
    assert!(
        spawned.elapsed() >= HELD_LOCK_WAIT,
        "the resume waited the whole lock wait: {:?}",
        spawned.elapsed()
    );
    assert_eq!(resume.code, 1, "{}", resume.describe());
    assert_eq!(
        resume.error_code(),
        Some("audit.chain_key_unavailable"),
        "{}",
        resume.describe()
    );
    let message = resume.envelope["error"]["message"]
        .as_str()
        .unwrap_or_default();
    assert!(
        message.contains(&format!(
            "audit.outbox_busy: the audit outbox lock stayed held for {} ms",
            HELD_LOCK_WAIT.as_millis()
        )),
        "the append waited on the held lock: {message}"
    );
    assert_eq!(std::fs::read(f.marker()).unwrap(), marker);
    assert_eq!(f.outbox_pending(), 1, "only the halt row is queued");
    assert_eq!(f.counter.accepted().unwrap(), 0);

    let rerun = run_bounded(
        "profile resume, lock released",
        command_in(f.home.path(), &["profile", "resume", "--profile", PROFILE]),
        STEP_DEADLINE,
    );
    assert_eq!(rerun.code, 0, "{}", rerun.describe());
    assert_eq!(rerun.envelope["data"]["audit_row"], "queued");
    assert!(!f.marker().exists());
    assert_eq!(f.outbox_pending(), 2);
    drop(server);
}
