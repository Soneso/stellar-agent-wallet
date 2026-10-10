//! An isolated `stellar-agent` data root on the encrypted headless keyring,
//! and the signed V1 policy ceremony `profile init` prints, as reusable stages.
//!
//! Every child process runs with `STELLAR_AGENT_HOME` at the isolated root,
//! the headless keyring backend under a key generated for that root, and the
//! multicall registry inside the root. The operator's own environment could
//! otherwise select a profile, an endpoint, a registry, or a test-only owner
//! key. Each such variable is removed from every child or pointed into the
//! root, so no run reads or writes anything outside it.
//!
//! The stages run in the order `profile init` prints them: the profile, the
//! audit key, the signer, the nonce key, the owner key, the attestation key,
//! the policy file, and its owner signature. A caller stops after any stage
//! to observe the refusal the missing step produces. The caller supplies the
//! signer and owner keypairs, so an offline test can pass fixed seeds and a
//! live test fresh keys.
//!
//! The offline `cli` target and the live
//! `smart_account_multicall_cli_testnet_acceptance` target both include this
//! file through a `#[path]` attribute; moving or renaming it breaks their
//! build.

#![allow(dead_code, reason = "Helpers are shared by two test targets.")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test helpers assert fixture invariants"
)]

use std::path::{Path, PathBuf};
use std::process::Command;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::SigningKey;
use rand_core::{OsRng, RngCore as _};
use serde_json::Value;
use stellar_agent_core::profile::schema::Profile;
use zeroize::Zeroizing;

/// The variable the signer enrollment reads its secret from. Set only on the
/// enrolling child.
pub const SIGNER_SECRET_ENV: &str = "V1_CEREMONY_SIGNER_SECRET";

/// The variable the owner enrollment and the policy signature read the owner
/// secret from. Set only on those children.
pub const OWNER_SECRET_ENV: &str = "V1_CEREMONY_OWNER_SECRET";

/// Variables removed from every child so the operator's environment cannot
/// redirect a run.
const REMOVED_ENV: &[&str] = &[
    "STELLAR_AGENT_PROFILE",
    "STELLAR_AGENT_CHAIN_ID",
    "STELLAR_AGENT_RPC_URL",
    "STELLAR_AGENT_SECONDARY_RPC_URL",
    "STELLAR_AGENT_ORACLE_PROVIDER_URL",
    "STELLAR_AGENT_MCP_SIGNER_DEFAULT",
    "STELLAR_AGENT_TEST_OWNER_PUBKEY_FILE",
    SIGNER_SECRET_ENV,
    OWNER_SECRET_ENV,
];

/// An ed25519 keypair with its Stellar strkeys.
pub struct Keypair {
    secret: Zeroizing<String>,
    public: String,
}

impl Keypair {
    /// The keypair for a fixed `seed`.
    #[must_use]
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let public = stellar_strkey::ed25519::PublicKey(
            SigningKey::from_bytes(&seed).verifying_key().to_bytes(),
        )
        .to_string()
        .as_str()
        .to_owned();
        let secret = Zeroizing::new(
            stellar_strkey::ed25519::PrivateKey(seed)
                .as_unredacted()
                .to_string()
                .as_str()
                .to_owned(),
        );
        Self { secret, public }
    }

    /// A keypair from the operating system's random source.
    #[must_use]
    pub fn generate() -> Self {
        let mut seed = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(seed.as_mut());
        Self::from_seed(*seed)
    }

    /// The S-strkey secret.
    #[must_use]
    pub fn secret(&self) -> &str {
        &self.secret
    }

    /// The G-strkey address.
    #[must_use]
    pub fn public(&self) -> &str {
        &self.public
    }
}

/// The outcome of one child process.
pub struct CliRun {
    /// The exit code.
    pub code: i32,
    /// The last JSON envelope on stdout.
    pub envelope: Value,
    /// Everything the child wrote to stdout.
    pub stdout: String,
    /// Everything the child wrote to stderr.
    pub stderr: String,
}

impl CliRun {
    /// The envelope's `error.code`, or the empty string on success.
    #[must_use]
    pub fn error_code(&self) -> &str {
        self.envelope["error"]["code"].as_str().unwrap_or_default()
    }

    /// The envelope's `error.message`, or the empty string on success.
    #[must_use]
    pub fn error_message(&self) -> &str {
        self.envelope["error"]["message"]
            .as_str()
            .unwrap_or_default()
    }
}

/// A temporary data root with its own headless keyring.
pub struct IsolatedHome {
    dir: tempfile::TempDir,
    key: Zeroizing<[u8; 32]>,
}

impl IsolatedHome {
    /// A fresh root and a headless keyring key generated for it.
    #[must_use]
    pub fn new() -> Self {
        let mut key = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(key.as_mut());
        Self {
            dir: tempfile::tempdir().unwrap(),
            key,
        }
    }

    /// The root every child sees as `STELLAR_AGENT_HOME`.
    #[must_use]
    pub fn path(&self) -> &Path {
        self.dir.path()
    }

    /// The headless keyring key, for a test that opens the same store
    /// in-process.
    #[must_use]
    pub fn headless_key(&self) -> [u8; 32] {
        *self.key
    }

    /// The headless keyring file every child reads and writes.
    #[must_use]
    pub fn keyring_path(&self) -> PathBuf {
        self.path().join("headless-keyring").join("store.keyring")
    }

    /// The multicall router registry every child reads and writes.
    #[must_use]
    pub fn registry_path(&self) -> PathBuf {
        self.path().join("networks.toml")
    }

    /// Writes the multicall registry entry naming `router` on testnet, with
    /// the vendored router's wasm hash.
    pub fn write_multicall_registry(&self, router: &str) {
        std::fs::write(
            self.registry_path(),
            format!(
                "[multicall.testnet]\nnetwork_passphrase = \"{}\"\naddress = \"{router}\"\n\
                 wasm_sha256 = \"{}\"\n",
                stellar_agent_test_support::signed_envelope::TESTNET_PASSPHRASE,
                stellar_agent_smart_account::multicall::MULTICALL_WASM_SHA256,
            ),
        )
        .unwrap();
    }

    /// The policy file `profile sign-policy` signs for `profile`.
    #[must_use]
    pub fn policy_path(&self, profile: &str) -> PathBuf {
        self.path().join("policies").join(format!("{profile}.toml"))
    }

    /// The profile file `profile init` writes for `profile`.
    #[must_use]
    pub fn profile_path(&self, profile: &str) -> PathBuf {
        self.path().join("profiles").join(format!("{profile}.toml"))
    }

    /// Loads `profile` as the children load it.
    #[must_use]
    pub fn load_profile(&self, profile: &str) -> Profile {
        stellar_agent_core::profile::loader::load_from_path(
            profile,
            &self.profile_path(profile),
            None,
        )
        .unwrap()
    }

    /// The audit rows of `profile` whose `kind` is `kind`, in order.
    #[must_use]
    pub fn audit_rows(&self, profile: &str, kind: &str) -> Vec<Value> {
        let path = self.load_profile(profile).audit_log_path;
        std::fs::read_to_string(&path)
            .unwrap_or_default()
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .filter(|row| row["kind"] == kind)
            .collect()
    }

    /// The `stellar-agent` command with the isolated environment applied.
    #[must_use]
    pub fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_stellar-agent"));
        command
            .args(args)
            .env("STELLAR_AGENT_HOME", self.path())
            .env("STELLAR_AGENT_KEYRING_BACKEND", "headless-env")
            .env(
                "STELLAR_AGENT_HEADLESS_KEYRING_KEY",
                URL_SAFE_NO_PAD.encode(*self.key),
            )
            .env(
                stellar_agent_smart_account::verifiers::STELLAR_AGENT_NETWORKS_TOML_ENV,
                self.registry_path(),
            );
        for name in REMOVED_ENV {
            command.env_remove(name);
        }
        command
    }

    /// Runs the binary with `args` and the extra variables `envs`, which
    /// apply after the isolated environment and may override it.
    pub fn run(&self, args: &[&str], envs: &[(&str, &str)]) -> CliRun {
        let mut command = self.command(args);
        for (name, value) in envs {
            command.env(name, value);
        }
        let output = command.output().unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        let line = stdout
            .lines()
            .rev()
            .find(|line| line.trim_start().starts_with('{'))
            .unwrap_or_else(|| {
                panic!("{args:?}: no JSON envelope; stdout={stdout} stderr={stderr}")
            });
        let envelope: Value = serde_json::from_str(line).unwrap_or_else(|e| {
            panic!("{args:?}: stdout is not a JSON envelope ({e}); stdout={stdout} stderr={stderr}")
        });
        CliRun {
            code: output.status.code().unwrap(),
            envelope,
            stdout,
            stderr,
        }
    }

    /// Runs the binary and requires exit code 0; returns the envelope.
    pub fn run_ok(&self, args: &[&str], envs: &[(&str, &str)]) -> Value {
        let run = self.run(args, envs);
        assert_eq!(
            run.code, 0,
            "{args:?} failed: {} stderr={}",
            run.envelope, run.stderr
        );
        run.envelope
    }

    /// `profile init --profile <profile>` with `extra` flags. The engine is
    /// `v1` unless `extra` passes `--engine noop`. The profile's audit key is
    /// unavailable until [`Self::rotate_audit_key`].
    pub fn init_profile(&self, profile: &str, extra: &[&str]) -> Value {
        let mut args = vec!["profile", "init", "--profile", profile];
        args.extend_from_slice(extra);
        self.run_ok(&args, &[])
    }

    /// `profile rotate-audit-key <profile>`.
    pub fn rotate_audit_key(&self, profile: &str) {
        self.run_ok(&["profile", "rotate-audit-key", profile], &[]);
    }

    /// `profile enroll-signer` with `signer`'s secret, pinned to its address.
    pub fn enroll_signer(&self, profile: &str, signer: &Keypair) {
        self.run_ok(
            &[
                "profile",
                "enroll-signer",
                "--profile",
                profile,
                "--secret-env",
                SIGNER_SECRET_ENV,
                "--expected-address",
                signer.public(),
            ],
            &[(SIGNER_SECRET_ENV, signer.secret())],
        );
    }

    /// `profile rotate-nonce-key <profile>`.
    pub fn rotate_nonce_key(&self, profile: &str) {
        self.run_ok(&["profile", "rotate-nonce-key", profile], &[]);
    }

    /// `profile enroll-owner-key` with `owner`'s secret, pinned to its
    /// address.
    pub fn enroll_owner_key(&self, profile: &str, owner: &Keypair) {
        self.run_ok(
            &[
                "profile",
                "enroll-owner-key",
                "--profile",
                profile,
                "--secret-env",
                OWNER_SECRET_ENV,
                "--expected-address",
                owner.public(),
            ],
            &[(OWNER_SECRET_ENV, owner.secret())],
        );
    }

    /// `profile rotate-attestation-key <profile>`.
    pub fn rotate_attestation_key(&self, profile: &str) {
        self.run_ok(&["profile", "rotate-attestation-key", profile], &[]);
    }

    /// Every keyring stage between `profile init` and the policy file: the
    /// audit key, the signer, the nonce key, the owner key, and the
    /// attestation key.
    pub fn enroll_keys(&self, profile: &str, signer: &Keypair, owner: &Keypair) {
        self.rotate_audit_key(profile);
        self.enroll_signer(profile, signer);
        self.rotate_nonce_key(profile);
        self.enroll_owner_key(profile, owner);
        self.rotate_attestation_key(profile);
    }

    /// Writes `document` as the unsigned policy file of `profile`.
    pub fn write_policy(&self, profile: &str, document: &str) {
        let path = self.policy_path(profile);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, document).unwrap();
    }

    /// `profile sign-policy` with `owner`'s secret.
    pub fn sign_policy(&self, profile: &str, owner: &Keypair) {
        self.run_ok(
            &[
                "profile",
                "sign-policy",
                "--profile",
                profile,
                "--secret-env",
                OWNER_SECRET_ENV,
            ],
            &[(OWNER_SECRET_ENV, owner.secret())],
        );
    }

    /// The whole ceremony: `profile init` with `init_extra`, every keyring
    /// stage, and `document` written and signed by `owner`.
    pub fn provision_v1_profile(
        &self,
        profile: &str,
        init_extra: &[&str],
        signer: &Keypair,
        owner: &Keypair,
        document: &str,
    ) {
        self.init_profile(profile, init_extra);
        self.enroll_keys(profile, signer, owner);
        self.write_policy(profile, document);
        self.sign_policy(profile, owner);
    }
}

/// One `[[rules]]` table. `criteria` is a TOML array literal and `decision`
/// the rule's decision keyword.
#[must_use]
pub fn policy_rule(tool: &str, chain: &str, criteria: &str, decision: &str) -> String {
    format!(
        "[[rules]]\nmatch = {{ tool = \"{tool}\", chain = \"{chain}\" }}\ncriteria = \
         {criteria}\ndecision = \"{decision}\"\n"
    )
}

/// A version 1 policy document scoped to `profile`, with `rules` in order.
#[must_use]
pub fn policy_document(profile: &str, rules: &[String]) -> String {
    let mut document = format!("version = 1\nscope = \"profile:{profile}\"\n");
    for rule in rules {
        document.push('\n');
        document.push_str(rule);
    }
    document
}
