//! A profile with no MPP history is not a broken MPP store — pinned through
//! the release binary.
//!
//! `mpp.state_unavailable` means the durable state, or a prerequisite of it,
//! exists and cannot be used. A profile that has never prepared a charge has
//! nothing stored, so an identifier lookup answers
//! `mpp.authorization_not_found` and housekeeping answers "nothing to prune" —
//! neither is a fault an agent should escalate.
//!
//! # What each test observes
//!
//! The wire code and, where the result is success, the envelope body and the
//! audit trail. The exit code alone cannot tell the two refusals apart: both
//! exit 1.
//!
//! # What is not pinned here
//!
//! `stellar_mpp_charge_commit`, the MCP twin of `charge authorize
//! --approval-id`, reaches its store only behind a minted, unexpired
//! process-bound nonce, so no process-level fixture can drive it to the store
//! open. Its first-run behaviour follows from the shared classifier every
//! other identifier-lookup site uses, which the library tests pin directly.
//!
//! # Hermetic fixtures
//!
//! `STELLAR_AGENT_HOME` redirects every data-root-derived path — the profile
//! directory, the MPP state directory, the audit log, and the headless keyring
//! file — and is set on CHILD processes only. The keyring backend is the
//! headless one, so no child can touch the OS login keychain AND the keyring
//! contents are known: a runner with no usable keychain cannot make the
//! first-run pin pass for the environmental-failure reason it is meant to
//! exclude. `rpc_url` points at an unreachable port; no test here reaches a
//! network, because every verb resolves its answer from durable state first.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    reason = "test-only; the refusal contract is asserted via panic-on-violation"
)]

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::Value;
use serial_test::serial;
use sha2::{Digest as _, Sha256};
use stellar_agent_test_support::profile_fixtures::noop_profile_toml;

/// The profile every test here serves under.
const PROFILE: &str = "mpp-first-run";

/// A throwaway 32-byte URL-safe base64 key for the headless keyring backend.
const HEADLESS_KEY: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";

/// The fixture's `rpc_url`: unreachable, so a run that somehow reached the
/// network would fail loudly rather than quietly succeed.
const FIXTURE_RPC: &str = "http://127.0.0.1:29/mpp-first-run-fixture";

/// A well-formed identifier no store in this suite holds.
const UNKNOWN_ID: &str = "mpp_00000000000000000000000000000000";

/// A well-formed approval identifier no store in this suite holds.
const UNKNOWN_APPROVAL_ID: &str = "approval_nonce_value12";

/// An identifier of the wrong shape, refused before any lookup.
const MALFORMED_ID: &str = "mpp_not-a-valid-identifier";

/// The prune reason, written to the child's stdin verbatim (no trailing
/// newline) so the digest asserted below is the digest of exactly these bytes.
const REASON: &[u8] = b"scheduled housekeeping";

/// A receipt that parses, so `receipt record` reaches its store open instead
/// of refusing on its input.
const RECEIPT_JSON: &str = concat!(
    r#"{"method":"stellar","reference":""#,
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    r#"","status":"success","timestamp":"2026-07-16T12:00:00Z"}"#
);

const NOT_FOUND_CODE: &str = "mpp.authorization_not_found";
const STATE_UNAVAILABLE_CODE: &str = "mpp.state_unavailable";

// ─────────────────────────────────────────────────────────────────────────────
// Harness
// ─────────────────────────────────────────────────────────────────────────────

/// Output of one child invocation.
struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

impl Run {
    fn json(&self) -> Value {
        serde_json::from_str(self.stdout.trim()).unwrap_or_else(|e| {
            panic!(
                "stdout must be a single JSON envelope ({e}); stdout={} stderr={}",
                self.stdout, self.stderr
            )
        })
    }

    fn code_field(&self) -> String {
        self.json()["error"]["code"]
            .as_str()
            .unwrap_or_default()
            .to_owned()
    }

    fn message_field(&self) -> String {
        self.json()["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .to_owned()
    }
}

fn run_cli(home: &Path, args: &[&str], stdin: Option<&[u8]>) -> Run {
    let mut command = Command::new(env!("CARGO_BIN_EXE_stellar-agent"));
    command
        .args(args)
        .env("STELLAR_AGENT_HOME", home)
        .env_remove("STELLAR_AGENT_PROFILE")
        // The crate's own constants, not literals: a rename would otherwise
        // leave children falling back to the platform keyring, which is the
        // exact outcome this harness exists to exclude.
        .env(
            stellar_agent_headless_keyring::BACKEND_ENV_VAR,
            "headless-env",
        )
        .env(stellar_agent_headless_keyring::ENV_KEY_VAR, HEADLESS_KEY)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = command.spawn().expect("stellar-agent binary must run");
    if let Some(bytes) = stdin {
        child
            .stdin
            .as_mut()
            .expect("piped stdin")
            .write_all(bytes)
            .expect("write child stdin");
    }
    let output = child.wait_with_output().expect("child must terminate");
    Run {
        code: output.status.code().expect("process must exit with a code"),
        stdout: String::from_utf8(output.stdout).expect("stdout must be UTF-8"),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

/// A home holding a self-consistent testnet profile and nothing else.
fn fresh_home() -> tempfile::TempDir {
    let home = tempfile::tempdir().expect("temp home");
    let profiles = home.path().join("profiles");
    std::fs::create_dir_all(&profiles).expect("create profiles dir");
    std::fs::write(
        profiles.join(format!("{PROFILE}.toml")),
        noop_profile_toml(PROFILE, "stellar:testnet", FIXTURE_RPC),
    )
    .expect("write fixture");
    home
}

/// Mints the profile's audit chain-root key through the real CLI verb.
///
/// `mpp state prune` records the maintenance request before it reports an
/// outcome and refuses if that row cannot be written, so without this the
/// prune assertions would be observing a missing audit key rather than the
/// store behaviour they are about.
fn mint_audit_key(home: &Path) {
    let run = run_cli(home, &["profile", "rotate-audit-key", PROFILE], None);
    assert_eq!(
        run.code, 0,
        "the audit key must mint; stdout={} stderr={}",
        run.stdout, run.stderr
    );
}

/// Seeds the profile's MPP state key into the SAME headless store file the
/// child reads, reproducing the post-mint, pre-first-write state a prepare
/// leaves behind when it is denied before its first record is stored.
fn mint_mpp_state_key(home: &Path) {
    let mut key = [0_u8; 32];
    let decoded = URL_SAFE_NO_PAD
        .decode(HEADLESS_KEY)
        .expect("headless key must be base64");
    key.copy_from_slice(&decoded);
    let store: Arc<keyring_core::CredentialStore> =
        Arc::new(stellar_agent_headless_keyring::store::HeadlessStore::new(
            home.join("headless-keyring").join("store.keyring"),
            stellar_agent_headless_keyring::crypto::ProtectionMode::EnvKey(Arc::new(
                zeroize::Zeroizing::new(key),
            )),
        ));
    keyring_core::set_default_store(store);

    let entry_ref =
        stellar_agent_core::profile::schema::KeyringEntryRef::default_mpp_state_key(PROFILE);
    keyring_core::Entry::new(&entry_ref.service, &entry_ref.account)
        .expect("headless keyring entry")
        .set_password(&URL_SAFE_NO_PAD.encode([9_u8; 32]))
        .expect("seed the MPP state key");
}

/// The canonical state path for [`PROFILE`] under `home`.
///
/// Derived the way `MppAuthorizationStore::for_profile` derives it. A drift in
/// that convention makes the fabricated-file test fail — the file would land
/// where the store never looks and the run would report first run instead of
/// the refusal asserted there — so this duplication cannot go quietly stale.
fn state_path(home: &Path) -> PathBuf {
    let stem = hex::encode(Sha256::digest(PROFILE.as_bytes()));
    home.join("mpp").join(format!("{stem}.state"))
}

fn status_args() -> Vec<&'static str> {
    status_args_for(UNKNOWN_ID)
}

fn status_args_for(authorization_id: &str) -> Vec<&str> {
    vec![
        "mpp",
        "authorization",
        "status",
        "--profile",
        PROFILE,
        "--authorization-id",
        authorization_id,
    ]
}

/// `charge authorize --approval-id` reaches the store before it reads any
/// input, so this argv exercises the resume path's own store open.
fn resume_args() -> Vec<&'static str> {
    vec![
        "mpp",
        "charge",
        "authorize",
        "--profile",
        PROFILE,
        "--approval-id",
        UNKNOWN_APPROVAL_ID,
    ]
}

fn receipt_args() -> Vec<&'static str> {
    vec![
        "mpp",
        "receipt",
        "record",
        "--profile",
        PROFILE,
        "--authorization-id",
        UNKNOWN_ID,
        "--transport",
        "mcp",
        "--receipt-stdin",
    ]
}

fn prune_args() -> Vec<&'static str> {
    vec![
        "mpp",
        "state",
        "prune",
        "--profile",
        PROFILE,
        "--reason-stdin",
    ]
}

/// Contents of the profile's audit log, or an empty string if no row was ever
/// written.
fn audit_log(home: &Path) -> String {
    std::fs::read_to_string(home.join("audit").join(format!("{PROFILE}.jsonl"))).unwrap_or_default()
}

// ─────────────────────────────────────────────────────────────────────────────
// Pins
// ─────────────────────────────────────────────────────────────────────────────

/// The wire code this suite pins is the one the library defines, which is also
/// the constant `stellar-agent-mcp`'s own MPP tests assert against — so the two
/// surfaces cannot drift apart by asserting different literals.
#[test]
fn the_pinned_codes_are_the_library_wire_codes() {
    assert_eq!(
        NOT_FOUND_CODE,
        stellar_agent_mpp::MppErrorCode::AuthorizationNotFound.as_str()
    );
    assert_eq!(
        STATE_UNAVAILABLE_CODE,
        stellar_agent_mpp::MppErrorCode::StateUnavailable.as_str()
    );
}

/// A profile that has never prepared a charge: the lookup reports an unknown
/// authorization and housekeeping succeeds with nothing pruned.
///
/// This is the reported case. Reporting either as `mpp.state_unavailable` tells
/// an agent the MPP subsystem is broken on a wallet that is merely new.
#[test]
#[serial]
fn a_profile_with_no_mpp_state_reports_not_found_and_prunes_nothing() {
    let home = fresh_home();
    mint_audit_key(home.path());

    let status = run_cli(home.path(), &status_args(), None);
    assert_eq!(
        status.code_field(),
        NOT_FOUND_CODE,
        "`authorization status` must report an unknown authorization; stdout={} stderr={}",
        status.stdout,
        status.stderr
    );
    assert_eq!(status.code, 1);
    // The message, not only the code: this refusal is emitted from a path that
    // holds no store handle, and the MCP twin asserts the same constructor's
    // text, so cross-surface byte-identity is what makes them one contract.
    assert_eq!(
        status.message_field(),
        stellar_agent_mpp::MppError::authorization_not_found().message(),
        "stdout={}",
        status.stdout
    );

    // The resume path takes an approval identifier rather than an
    // authorization one and reaches the store before it reads any input.
    let resume = run_cli(home.path(), &resume_args(), None);
    assert_eq!(
        resume.code_field(),
        NOT_FOUND_CODE,
        "`charge authorize --approval-id` must report an unknown authorization; \
         stdout={} stderr={}",
        resume.stdout,
        resume.stderr
    );

    let receipt = run_cli(home.path(), &receipt_args(), Some(RECEIPT_JSON.as_bytes()));
    assert_eq!(
        receipt.code_field(),
        NOT_FOUND_CODE,
        "`receipt record` must report an unknown authorization; stdout={} stderr={}",
        receipt.stdout,
        receipt.stderr
    );

    // A malformed identifier is an input fault on every store state, so it must
    // not be answered with the code that means "no such authorization" — that
    // difference would let a caller probe whether the profile has MPP state.
    let malformed = run_cli(home.path(), &status_args_for(MALFORMED_ID), None);
    assert_eq!(
        malformed.code_field(),
        STATE_UNAVAILABLE_CODE,
        "a malformed identifier must classify as input, not as a lookup miss; stdout={}",
        malformed.stdout
    );

    let prune = run_cli(home.path(), &prune_args(), Some(REASON));
    assert_eq!(
        prune.code, 0,
        "`state prune` must succeed on a profile with nothing to prune; stdout={} stderr={}",
        prune.stdout, prune.stderr
    );
    let body = prune.json();
    assert_eq!(body["ok"], Value::Bool(true), "stdout={}", prune.stdout);
    assert_eq!(body["data"]["pruned"], 0, "stdout={}", prune.stdout);
    let reason_sha256 = hex::encode(Sha256::digest(REASON));
    assert_eq!(
        body["data"]["reason_sha256"],
        Value::String(reason_sha256.clone()),
        "stdout={}",
        prune.stdout
    );

    // The maintenance request is recorded whether or not there was anything to
    // prune: an operator-initiated state operation must leave a trail even when
    // its outcome is "nothing".
    let log = audit_log(home.path());
    let row = log
        .lines()
        .find(|line| line.contains("stellar_mpp_state_prune"))
        .unwrap_or_else(|| panic!("the prune audit row must exist; log={log}"));
    // `decision_reason` is written through the audit log's hash redaction, so
    // the row carries the digest first-8-last-8 rather than in full.
    let redacted_digest = format!(
        "reason_sha256={}...{}",
        &reason_sha256[..8],
        &reason_sha256[reason_sha256.len() - 8..]
    );
    assert!(
        row.contains(&redacted_digest),
        "the prune row must carry the operator's reason digest; row={row}"
    );

    assert!(
        !state_path(home.path()).exists(),
        "no read may create the state file"
    );
}

/// A state file present without its key: both verbs refuse.
///
/// Only the provable never-minted state — no key AND no file — reads as first
/// run. Deleting or rotating the key under an existing store must not be
/// answered as "nothing was ever here", which would reset replay protection to
/// a clean slate.
///
/// A refused prune leaves no audit row: the store open precedes the audit
/// emission, so the row records maintenance the wallet actually performed, not
/// every attempt at it. Only the outcome-bearing paths — including the
/// nothing-to-prune one — write the row.
#[test]
#[serial]
fn a_state_file_without_its_key_refuses_on_every_read_verb() {
    let home = fresh_home();
    mint_audit_key(home.path());
    let path = state_path(home.path());
    std::fs::create_dir_all(path.parent().expect("state parent")).expect("state directory");
    std::fs::write(&path, [0_u8; 32]).expect("fabricate a state file");

    let status = run_cli(home.path(), &status_args(), None);
    assert_eq!(
        status.code_field(),
        STATE_UNAVAILABLE_CODE,
        "`authorization status` must fail closed; stdout={} stderr={}",
        status.stdout,
        status.stderr
    );

    let prune = run_cli(home.path(), &prune_args(), Some(REASON));
    assert_eq!(
        prune.code_field(),
        STATE_UNAVAILABLE_CODE,
        "`state prune` must fail closed; stdout={} stderr={}",
        prune.stdout,
        prune.stderr
    );
    assert_eq!(prune.code, 1);
    assert!(
        !audit_log(home.path()).contains("stellar_mpp_state_prune"),
        "a refused prune performs no maintenance and records none"
    );
}

/// A minted but still empty store answers an unknown identifier exactly as a
/// profile with no store at all does.
///
/// These runs reach the store's own not-found arms rather than the first-run
/// path, so the narrowed contract is pinned on both sides of the split — and
/// `receipt record`, whose lookup is a mutation rather than a `load`, cannot
/// answer a different code for the same user error.
#[test]
#[serial]
fn an_unknown_id_on_a_minted_empty_store_reports_not_found() {
    let home = fresh_home();
    mint_audit_key(home.path());
    mint_mpp_state_key(home.path());

    let status = run_cli(home.path(), &status_args(), None);
    assert_eq!(
        status.code_field(),
        NOT_FOUND_CODE,
        "an identifier the store does not hold is not a broken store; stdout={} stderr={}",
        status.stdout,
        status.stderr
    );

    // `receipt record` looks its identifier up through a mutation, not through
    // `load`. It answered the state code here while the first-run path answered
    // "not found", which made one user error read two ways depending on store
    // state the caller cannot see — and told the caller which state that was.
    let receipt = run_cli(home.path(), &receipt_args(), Some(RECEIPT_JSON.as_bytes()));
    assert_eq!(
        receipt.code_field(),
        NOT_FOUND_CODE,
        "`receipt record` must answer an unknown identifier the same way on every store \
         state; stdout={} stderr={}",
        receipt.stdout,
        receipt.stderr
    );
    assert_eq!(
        receipt.message_field(),
        stellar_agent_mpp::MppError::authorization_not_found().message(),
        "stdout={}",
        receipt.stdout
    );

    let malformed = run_cli(home.path(), &status_args_for(MALFORMED_ID), None);
    assert_eq!(
        malformed.code_field(),
        STATE_UNAVAILABLE_CODE,
        "a malformed identifier must classify the same way here as on a profile with no \
         state; stdout={}",
        malformed.stdout
    );

    let prune = run_cli(home.path(), &prune_args(), Some(REASON));
    assert_eq!(
        prune.code, 0,
        "`state prune` must succeed against a minted store; stdout={} stderr={}",
        prune.stdout, prune.stderr
    );
    assert_eq!(prune.json()["data"]["pruned"], 0, "stdout={}", prune.stdout);

    // Proof the seeded key was actually used: pruning through a real store
    // writes the state file, while the first-run path — which answers the same
    // code for the lookup above — never creates one. Without this the seeding
    // could be a no-op and every assertion here would still pass.
    assert!(
        state_path(home.path()).exists(),
        "pruning through a minted store must have written the state file"
    );
}
