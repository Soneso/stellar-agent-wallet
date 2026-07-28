//! A profile file whose owner-key coordinate names a DIFFERENT profile is
//! refused — pinned through the release binary, per surface.
//!
//! Both binaries derive the paths that hold a profile's authority from the
//! profile's own contents rather than from the name it was loaded under. On
//! this surface the signed policy file and the owner-key keyring entry follow
//! the name derived from `policy_owner_key_id.service`, while the
//! pending-approval store, the audit log, and the policy-window state key on
//! the name the operator asked for. A file copied or renamed from another
//! profile therefore runs under one profile's policy and accounts against
//! another's state, with every message naming the profile that was asked for.
//!
//! # What each test observes
//!
//! The wire code, never the exit code: a run that accepted the profile and
//! then failed on the unreachable endpoint also exits 1.
//! `network.rpc_unreachable` means the run got PAST profile access, which is
//! what the control tests assert; `profile.name_mismatch` means it refused.
//!
//! # The engine must not matter
//!
//! Every fixture here sets `engine = "noop"`. The V1 policy-engine
//! construction is where an engine-coupled version of this check would sit,
//! and it returns early for `Noop` — so a `Noop` fixture is the one that tells
//! a correctly-placed check apart from a misplaced one. It is also the engine
//! the getting-started flow recommends, making this the common case.
//!
//! # Hermetic fixtures
//!
//! `STELLAR_AGENT_HOME` redirects every data-root-derived path and is set on
//! CHILD processes only. `--rpc-url` points at an unreachable port so no run
//! reaches a network, and the keyring backend is the headless one so no child
//! can touch the OS login keychain.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    reason = "test-only; the refusal contract is asserted via panic-on-violation"
)]

use std::path::Path;
use std::process::Command;

use serde_json::Value;
use stellar_agent_test_support::profile_fixtures::noop_profile_toml;

/// The wire code every CLI surface emits for this refusal.
const MISMATCH_CODE: &str = "profile.name_mismatch";

/// A throwaway 32-byte URL-safe base64 key for the headless keyring backend.
const HEADLESS_KEY: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";

/// Unreachable endpoint: every run that gets PAST profile access fails here.
const UNREACHABLE_RPC: &str = "http://127.0.0.1:9";

/// The `rpc_url` written into every fixture, also unreachable.
const FIXTURE_RPC: &str = "http://127.0.0.1:29/i107-fixture";

const SOURCE_G: &str = "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5";
const DEST_G: &str = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";
const BALANCE_ID_HEX72: &str =
    "000000000000000000000000000000000000000000000000000000000000000000000000";
const SMART_ACCOUNT_C: &str = "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA";

/// The profile name the operator selects in every test here.
const REQUESTED: &str = "i107-requested";

/// The profile the fixture's owner-key coordinate actually names.
const OWNED_BY: &str = "i107-other";

/// Stands in for the per-home audit-log path in a `const` argv, substituted
/// when the case runs.
const AUDIT_LOG_PLACEHOLDER: &str = "<AUDIT_LOG>";

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

fn run_cli(home: &Path, args: &[&str]) -> Run {
    let mut command = Command::new(env!("CARGO_BIN_EXE_stellar-agent"));
    command
        .args(args)
        .env("STELLAR_AGENT_HOME", home)
        .env_remove("STELLAR_AGENT_PROFILE")
        .env("STELLAR_AGENT_KEYRING_BACKEND", "headless-env")
        .env("STELLAR_AGENT_HEADLESS_KEYRING_KEY", HEADLESS_KEY);

    let output = command.output().expect("stellar-agent binary must run");
    Run {
        code: output.status.code().expect("process must exit with a code"),
        stdout: String::from_utf8(output.stdout).expect("stdout must be UTF-8"),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

/// Writes `<home>/profiles/<file_name>.toml` with coordinates derived from
/// `owner_profile`, and returns the bytes written.
fn write_profile(home: &Path, file_name: &str, owner_profile: &str) -> String {
    let profiles = home.join("profiles");
    std::fs::create_dir_all(&profiles).expect("create profiles dir");
    let toml = noop_profile_toml(owner_profile, "stellar:testnet", FIXTURE_RPC);
    std::fs::write(profiles.join(format!("{file_name}.toml")), &toml).expect("write fixture");
    toml
}

/// A home holding `i107-requested.toml` whose coordinates name `i107-other` —
/// exactly what copying `i107-other.toml` to `i107-requested.toml` produces.
fn mismatched_home() -> tempfile::TempDir {
    let home = tempfile::tempdir().expect("temp home");
    write_profile(home.path(), REQUESTED, OWNED_BY);
    home
}

/// A home holding a self-consistent `i107-requested.toml`.
fn consistent_home() -> tempfile::TempDir {
    let home = tempfile::tempdir().expect("temp home");
    write_profile(home.path(), REQUESTED, REQUESTED);
    home
}

fn assert_mismatch_refusal(run: &Run, verb: &str) {
    assert_eq!(
        run.code, 1,
        "`{verb}` must exit 1 for a mismatched profile; stdout={} stderr={}",
        run.stdout, run.stderr
    );
    assert_eq!(
        run.code_field(),
        MISMATCH_CODE,
        "`{verb}` must refuse with the reconciliation's own code; stdout={}",
        run.stdout
    );
    let message = run.message_field();
    assert!(
        message.contains(REQUESTED) && message.contains(OWNED_BY),
        "`{verb}`: the refusal must name both profiles; message={message}"
    );
    assert!(
        message.contains("stellar-agent-owner-i107-other"),
        "`{verb}`: the refusal must quote the offending field; message={message}"
    );
    assert!(
        message.contains("profile init --profile i107-requested"),
        "`{verb}`: the refusal must name the recovery command; message={message}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// The signing surface
// ─────────────────────────────────────────────────────────────────────────────

/// Verbs that sign or move value, with the arguments they need to reach the
/// profile-access step.
///
/// Each validates its own operands first, so an argument shape that refused
/// earlier would make these pass without ever exercising the reconciliation —
/// hence real strkeys, a well-formed balance id, and parseable amounts.
/// The third element is the code a run that got PAST profile access ends on:
/// each verb reports its own unreachable-endpoint failure, and asserting the
/// exact one keeps the control from passing for any non-mismatch outcome.
const SIGNING_VERBS: &[(&str, &[&str], &str)] = &[
    (
        "pay",
        &[
            "pay",
            "--source",
            SOURCE_G,
            DEST_G,
            "1",
            "--build-only",
            "--rpc-url",
            UNREACHABLE_RPC,
        ],
        "network.rpc_unreachable",
    ),
    (
        "claim",
        &[
            "claim",
            BALANCE_ID_HEX72,
            "--source",
            SOURCE_G,
            "--build-only",
            "--rpc-url",
            UNREACHABLE_RPC,
        ],
        "network.rpc_unreachable",
    ),
    (
        "accounts create",
        &[
            "accounts",
            "create",
            DEST_G,
            "--sponsor",
            SOURCE_G,
            "--starting-balance",
            "1 XLM",
            "--rpc-url",
            UNREACHABLE_RPC,
        ],
        "network.rpc_unreachable",
    ),
    (
        "trustline",
        &["trustline", "--from", SOURCE_G, "--asset", "USDC"],
        // `trustline` takes its endpoint from `profile.rpc_url`, which the
        // fixture points at an unreachable port, and fails closed on the
        // issuer-flag fetch.
        "trustline.source_account_fetch_failed",
    ),
];

/// A signing verb refuses a profile whose owner coordinate names another
/// profile — on a `Noop`-engine profile, which is the placement pin.
#[test]
fn a_signing_verb_refuses_a_mismatched_noop_profile() {
    for (verb, argv, _proceeded) in SIGNING_VERBS {
        let home = mismatched_home();
        let mut args = argv.to_vec();
        args.extend_from_slice(&["--profile", REQUESTED]);

        let run = run_cli(home.path(), &args);
        assert_mismatch_refusal(&run, verb);
    }
}

/// The control: a self-consistent profile is NOT refused.
///
/// Without it every assertion above would also pass for a build that refused
/// every profile unconditionally.
#[test]
fn a_self_consistent_profile_is_not_refused() {
    for (verb, argv, proceeded) in SIGNING_VERBS {
        let home = consistent_home();
        let mut args = argv.to_vec();
        args.extend_from_slice(&["--profile", REQUESTED]);

        let run = run_cli(home.path(), &args);
        assert_ne!(
            run.code_field(),
            MISMATCH_CODE,
            "`{verb}` must accept a profile that names itself; stdout={}",
            run.stdout
        );
        assert_eq!(
            &run.code_field(),
            proceeded,
            "`{verb}` must reach the endpoint, proving profile access succeeded; \
             stdout={} stderr={}",
            run.stdout,
            run.stderr
        );
    }
}

/// A `service` field carrying no `stellar-agent-owner-` prefix refuses rather
/// than resolving to `default`.
///
/// The MCP's approval-store derivation resolves a prefix-less coordinate to the
/// literal `"default"`; accepting one here would let a hand-written profile
/// operate under any requested name while its authority points elsewhere.
#[test]
fn a_service_without_the_prefix_refuses_instead_of_resolving_to_default() {
    let home = tempfile::tempdir().expect("temp home");
    let profiles = home.path().join("profiles");
    std::fs::create_dir_all(&profiles).expect("create profiles dir");
    let toml = noop_profile_toml(REQUESTED, "stellar:testnet", FIXTURE_RPC).replace(
        "stellar-agent-owner-i107-requested",
        "hand-written-owner-service",
    );
    std::fs::write(profiles.join(format!("{REQUESTED}.toml")), toml).expect("write fixture");

    let run = run_cli(
        home.path(),
        &[
            "pay",
            "--source",
            SOURCE_G,
            DEST_G,
            "1",
            "--build-only",
            "--rpc-url",
            UNREACHABLE_RPC,
            "--profile",
            REQUESTED,
        ],
    );

    assert_eq!(
        run.code_field(),
        MISMATCH_CODE,
        "a prefix-less owner coordinate must refuse; stdout={}",
        run.stdout
    );
    let message = run.message_field();
    assert!(
        message.contains("hand-written-owner-service"),
        "the refusal must quote the offending field; message={message}"
    );
    assert!(
        message.contains("does not carry the 'stellar-agent-owner-' prefix"),
        "the refusal must explain that no name can be derived; message={message}"
    );
}

/// The refusal beats the zero-config synthesis: a mismatched FILE that EXISTS
/// is refused, never treated as absent.
///
/// With no `--profile` and no `STELLAR_AGENT_PROFILE`, `pay` synthesises an
/// in-memory permissive profile when `default.toml` is absent. A `default.toml`
/// that names another profile must not take that path — substituting the
/// permissive fallback for a file the operator authored would answer under a
/// gate they never chose.
#[test]
fn a_mismatched_default_profile_refuses_rather_than_synthesizing() {
    let home = tempfile::tempdir().expect("temp home");
    write_profile(home.path(), "default", OWNED_BY);

    let run = run_cli(
        home.path(),
        &[
            "pay",
            "--source",
            SOURCE_G,
            DEST_G,
            "1",
            "--build-only",
            "--rpc-url",
            UNREACHABLE_RPC,
        ],
    );

    assert_eq!(
        run.code_field(),
        MISMATCH_CODE,
        "an authored but mismatched default.toml must refuse, not be replaced by the \
         synthesised profile; stdout={}",
        run.stdout
    );
}

/// The refusal follows `STELLAR_AGENT_PROFILE` too: the reconciliation compares
/// the name the resolver produced, whichever input supplied it.
#[test]
fn the_environment_selected_profile_is_reconciled_as_well() {
    let home = mismatched_home();
    let mut command = Command::new(env!("CARGO_BIN_EXE_stellar-agent"));
    command
        .args([
            "pay",
            "--source",
            SOURCE_G,
            DEST_G,
            "1",
            "--build-only",
            "--rpc-url",
            UNREACHABLE_RPC,
        ])
        .env("STELLAR_AGENT_HOME", home.path())
        .env("STELLAR_AGENT_PROFILE", REQUESTED)
        .env("STELLAR_AGENT_KEYRING_BACKEND", "headless-env")
        .env("STELLAR_AGENT_HEADLESS_KEYRING_KEY", HEADLESS_KEY);
    let output = command.output().expect("stellar-agent binary must run");
    let run = Run {
        code: output.status.code().expect("process must exit with a code"),
        stdout: String::from_utf8(output.stdout).expect("stdout must be UTF-8"),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    };

    assert_mismatch_refusal(&run, "pay (STELLAR_AGENT_PROFILE)");
}

// ─────────────────────────────────────────────────────────────────────────────
// The repair commands are NOT exempt
// ─────────────────────────────────────────────────────────────────────────────

/// `profile sign-policy` and `profile enroll-owner-key` mint or replace
/// authority under the DERIVED name: `sign-policy` writes
/// `<policy_dir>/<derived>.toml` and `enroll-owner-key` writes the
/// `stellar-agent-owner-<derived>` keyring entry. Run against a mismatched
/// file they would overwrite ANOTHER profile's root of trust, which is
/// strictly worse than the read defect the reconciliation was introduced for.
///
/// `rotate-audit-key` rotates the key named by the loaded file's own
/// `audit_log_hash_chain_key_id`, destroying the source profile's ability to
/// verify its log.
///
/// None of the three is needed to repair a mismatch: the refusal names the
/// recovery path, and neither `profile init` nor a corrected `service` field
/// requires signing under a mismatched profile.
#[test]
fn the_authority_minting_commands_refuse_a_mismatched_profile() {
    let commands: &[(&str, &[&str])] = &[
        (
            "profile sign-policy",
            &[
                "profile",
                "sign-policy",
                "--profile",
                REQUESTED,
                "--secret-env",
                "I107_NEVER_SET",
                "--file",
                "/nonexistent/policy.toml",
            ],
        ),
        (
            "profile enroll-owner-key",
            &[
                "profile",
                "enroll-owner-key",
                "--profile",
                REQUESTED,
                "--secret-env",
                "I107_NEVER_SET",
            ],
        ),
        (
            "profile rotate-audit-key",
            &["profile", "rotate-audit-key", REQUESTED],
        ),
        (
            "profile rotate-nonce-key",
            &["profile", "rotate-nonce-key", REQUESTED],
        ),
    ];

    for (label, argv) in commands {
        let home = mismatched_home();
        let run = run_cli(home.path(), argv);
        assert_mismatch_refusal(&run, label);
    }
}

/// `profile show` is the ONE exemption, and it must stay one.
///
/// It is the command whose purpose is to display the offending field. A
/// reconciliation refusal here would make a mismatched profile impossible to
/// inspect and leave the refusal's own advice — "correct
/// policy_owner_key_id.service" — uncompletable.
#[test]
fn profile_show_displays_a_mismatched_profile_instead_of_refusing() {
    let home = mismatched_home();
    let run = run_cli(home.path(), &["profile", "show", REQUESTED]);

    assert_eq!(
        run.code, 0,
        "`profile show` must succeed for a mismatched profile; stdout={} stderr={}",
        run.stdout, run.stderr
    );
    assert!(
        run.stdout.contains("stellar-agent-owner-i107-other"),
        "`profile show` must print the offending coordinate the operator has to fix; \
         stdout={}",
        run.stdout
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// The fail-open sites — the refusal must SURFACE, not be swallowed
// ─────────────────────────────────────────────────────────────────────────────

/// Commands whose profile load is (or was) tolerated on failure, each pinned to
/// surface the refusal instead of continuing with a default.
///
/// A swallowed refusal is the defect class this whole change exists to close:
/// the check runs, returns a refusal, and the command proceeds anyway.
#[test]
fn every_fail_open_site_surfaces_the_refusal() {
    let sites: &[(&str, &[&str])] = &[
        // `smart_account/list_rules.rs:511` — the max-scan-id bound. This is
        // where `list-rules` refuses; it never constructs a
        // `CommonHandlerContext` and so never reaches the horizon-cap arm.
        (
            "smart-account list-rules",
            &[
                "smart-account",
                "list-rules",
                "--account",
                SMART_ACCOUNT_C,
                "--rpc-url",
                UNREACHABLE_RPC,
                "--profile",
                REQUESTED,
            ],
        ),
        // `smart-account rules` — the only family that reaches
        // `smart_account/common.rs`'s horizon-cap arm. The refusal it emits
        // fires EARLIER, in `CommonHandlerContext::new`: the signer ceremony
        // (`common.rs:121`) and the audit-writer open (`common.rs:136`) both
        // reconcile the same name first. The horizon-cap arm at `common.rs:203`
        // is therefore defence-in-depth and is not reachable through any
        // process-level path; it is covered by inspection, not by this pin.
        (
            "smart-account rules set-name",
            &[
                "smart-account",
                "rules",
                "set-name",
                "--account",
                SMART_ACCOUNT_C,
                "--rule-id",
                "0",
                "--name",
                "i107",
                "--signer-secret-env",
                "I107_NEVER_SET",
                "--rpc-url",
                UNREACHABLE_RPC,
                "--profile",
                REQUESTED,
            ],
        ),
        // `smart_account/multicall.rs` — the refusal fires at the audit-writer
        // open (`multicall.rs:262`), which reconciles before the secondary-RPC
        // resolution at `:323` is reached. That deeper arm — the only site
        // passing the multicall registry to the loader — is defence-in-depth.
        (
            "smart-account multicall",
            &[
                "smart-account",
                "multicall",
                "--smart-account",
                SMART_ACCOUNT_C,
                "--rule-id",
                "0",
                "--invocation",
                "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA:noop:[]",
                "--signer-secret-env",
                "I107_NEVER_SET",
                "--rpc-url",
                UNREACHABLE_RPC,
                "--profile",
                REQUESTED,
            ],
        ),
        // `approve/run.rs` — the refusal fires at the step-3 profile load
        // (`run.rs:177`). The audit-writer arm at `:266`, which tolerates an
        // open failure, is defence-in-depth: it cannot see a mismatch because
        // step 3 refuses the same name first.
        (
            "approve",
            &["approve", "--id", "i107-nonce", "--profile", REQUESTED],
        ),
        // `credentials/add_passkey.rs:147` — reconciled at the TOP of `run`,
        // before the approval store opens, before the bridge listens, before a
        // PendingApproval is written, and before a browser is launched. A
        // refusal placed at the audit-writer open instead would leave all four
        // behind, and would make this very pin open a browser window on every
        // test run.
        (
            "credentials add-passkey",
            &[
                "credentials",
                "add-passkey",
                "i107-key",
                "--profile",
                REQUESTED,
                "--accept-rp-id-binding-risk",
                "--timeout-seconds",
                "1",
            ],
        ),
        // `accounts/deploy_c.rs:550` — reconciled in the CALLER of the injected
        // loader.
        //
        // This case proves the COMMAND refuses; it does not isolate that arm.
        // `deploy-c` reconciles the same name twice on independent paths — the
        // audit-writer resolution here, and the signer ceremony further down
        // (`deploy_c.rs:947` -> `resolve_wallet_unlock_controls`) — so removing
        // either one still leaves the other refusing. A mutation on the
        // audit-writer reconcile was run and did NOT bite for exactly that
        // reason. The seam PLACEMENT (inject the raw loader, reconcile in the
        // caller) is a review-enforced property here, not a gated one.
        (
            "accounts deploy-c",
            &[
                "accounts",
                "deploy-c",
                "--initial-signer",
                SOURCE_G,
                "--deployer-secret-env",
                "I107_NEVER_SET",
                "--salt-random",
                "--rpc-url",
                UNREACHABLE_RPC,
                "--profile",
                REQUESTED,
            ],
        ),
        // `audit/verify.rs` — cause-discarding. The log path must sit in a
        // directory this process owns: the parent-ownership check runs before
        // the profile is resolved, so a nonexistent path would refuse earlier
        // and the pin would prove nothing.
        (
            "audit verify",
            &[
                "audit",
                "verify",
                AUDIT_LOG_PLACEHOLDER,
                "--profile",
                REQUESTED,
            ],
        ),
        // `fees/stats.rs` — cause-discarding.
        ("fees stats", &["fees", "stats", "--profile", REQUESTED]),
        // `pool/*.rs` — cause-discarding.
        ("pool list", &["pool", "list", "--profile", REQUESTED]),
        ("pool status", &["pool", "status", "--profile", REQUESTED]),
        // `counterparty/*.rs` — cause-discarding.
        (
            "counterparty list",
            &["counterparty", "list", "--profile", REQUESTED],
        ),
        (
            "counterparty evict",
            &[
                "counterparty",
                "evict",
                "example.com",
                "--profile",
                REQUESTED,
            ],
        ),
        (
            "counterparty rotate-hmac-key",
            &["counterparty", "rotate-hmac-key", "--profile", REQUESTED],
        ),
    ];

    for (label, argv) in sites {
        let home = mismatched_home();
        // A log file inside the temp home: `audit verify` checks the parent
        // directory's ownership before it resolves the profile, so the path has
        // to exist and be ours or the run refuses before reaching the pin.
        let audit_log = home.path().join("i107-audit.jsonl");
        std::fs::write(&audit_log, "").expect("write empty audit log");
        let audit_log = audit_log.to_string_lossy().into_owned();
        let args: Vec<&str> = argv
            .iter()
            .map(|a| {
                if *a == AUDIT_LOG_PLACEHOLDER {
                    audit_log.as_str()
                } else {
                    a
                }
            })
            .collect();

        let run = run_cli(home.path(), &args);
        assert_eq!(
            run.code_field(),
            MISMATCH_CODE,
            "`{label}` must surface the reconciliation refusal instead of continuing with a \
             default; stdout={} stderr={}",
            run.stdout,
            run.stderr
        );
    }
}

/// `credentials add-passkey` refuses BEFORE it starts the bridge, writes a
/// `PendingApproval`, or launches a browser.
///
/// Ordering is the whole assertion. A refusal placed at the audit-writer open
/// — the last profile-touching step in the flow — would still produce
/// `profile.name_mismatch`, so the code alone proves nothing. What it would
/// also do is leave a listening socket and a stray pending approval behind on
/// every refusal, skip the `bridge.shutdown()` every sibling error path calls,
/// and open a browser window on the developer's machine every time this test
/// runs.
///
/// The observation is therefore the ABSENCE of bridge output on stderr, taken
/// together with the refusal on stdout.
#[test]
fn add_passkey_refuses_before_the_bridge_starts() {
    let home = mismatched_home();
    let run = run_cli(
        home.path(),
        &[
            "credentials",
            "add-passkey",
            "i107-key",
            "--profile",
            REQUESTED,
            "--accept-rp-id-binding-risk",
            "--timeout-seconds",
            "1",
        ],
    );

    assert_mismatch_refusal(&run, "credentials add-passkey");
    for marker in [
        "bridge HTTP server started",
        "start_bridge_register_only",
        "browser launch failed",
    ] {
        assert!(
            !run.stderr.contains(marker),
            "the refusal must precede the bridge and the browser launch; stderr carried \
             `{marker}`: {}",
            run.stderr
        );
    }
    assert!(
        !run.stdout.contains("credentials.registration_timeout"),
        "a run that reached the polling loop got past the reconciliation; stdout={}",
        run.stdout
    );
}

/// `mpp authorize` surfaces the reconciliation's own code instead of the fixed
/// `"MPP authorization state is unavailable"` its loader failure collapsed into.
///
/// That collapse is the worst of the cause-discarding sites: an operator whose
/// profile file is a copy of another was told the MPP state subsystem was
/// broken, which is neither true nor actionable.
#[test]
fn mpp_surfaces_the_reconciliation_refusal_not_state_unavailable() {
    let home = mismatched_home();
    let run = run_cli(
        home.path(),
        &[
            "mpp",
            "charge",
            "authorize",
            "--profile",
            REQUESTED,
            "--input-file",
            "/nonexistent/challenge.json",
        ],
    );

    assert_eq!(
        run.code_field(),
        MISMATCH_CODE,
        "`mpp authorize` must name the profile problem, not the MPP state subsystem; \
         stdout={} stderr={}",
        run.stdout,
        run.stderr
    );
    assert!(
        !run.message_field().contains("state is unavailable"),
        "the fixed state-unavailable text must not stand in for a profile refusal; \
         message={}",
        run.message_field()
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Parity with `stellar-agent-mcp`
// ─────────────────────────────────────────────────────────────────────────────

/// The two binaries reach the same verdict on the same profile FILE.
///
/// Parity rests on two facts this test makes checkable:
///
/// 1. The bytes are one artefact. `stellar_agent_test_support::profile_fixtures`
///    generates them, and `stellar-agent-mcp`'s
///    `tests/profile_selection_integration.rs` writes the same generator's
///    output in `noop_profile_copied_from_another_profile_refuses_to_serve_under_the_new_name`.
///    Two hand-copied literals could drift; one generator cannot. The MCP's
///    call passes a different `rpc_url` (its own unreachable host), which the
///    reconciliation does not read — the owner-key coordinate asserted below is
///    the input that decides the verdict, and it is identical on both sides.
/// 2. The verdict is one function.
///    `stellar_agent_core::profile::name::profile_name_mismatch_refusal` is
///    called by both surfaces, and this test calls it directly on the parsed
///    fixture. Only the rendered message differs, because the two binaries lay
///    their per-profile state out differently.
///
/// What remains per surface is the wiring, which each binary's own process pin
/// covers: this one for `stellar-agent`, the MCP integration test for the
/// server.
#[test]
fn the_cli_and_the_mcp_server_agree_on_the_same_mismatched_file() {
    use stellar_agent_core::profile::name::{
        OWNER_KEY_SERVICE_PREFIX, ProfileStateLayout, profile_name_mismatch_refusal,
    };

    let home = tempfile::tempdir().expect("temp home");
    write_profile(home.path(), "alice", "default");

    // Loaded through the profile loader — the same path both binaries take —
    // because the TOML omits the fields the loader derives from `chain_id`.
    let profile = stellar_agent_core::profile::loader::load_from_dir(
        "alice",
        &home.path().join("profiles"),
        None,
    )
    .expect("the fixture must load as a profile");

    // The field the reconciliation actually reads, asserted against the
    // constant that defines it. This is what makes the fixture a real
    // mismatch rather than an arbitrary string, and it is the drift guard for
    // the generator's own literal: `stellar-agent-test-support` cannot import
    // this constant (`stellar-agent-core` depends on that crate under
    // `test-helpers`, so the reverse edge is a cycle), so the check lives here,
    // in a crate that can.
    assert_eq!(
        profile.policy_owner_key_id.service,
        format!("{OWNER_KEY_SERVICE_PREFIX}default"),
        "the fixture must carry the owner coordinate of ANOTHER profile, built from the \
         same prefix the reconciliation strips"
    );
    assert_ne!(
        profile.policy_owner_key_id.service,
        format!("{OWNER_KEY_SERVICE_PREFIX}alice"),
        "a fixture that named itself would make every assertion below vacuous"
    );
    let refusal = profile_name_mismatch_refusal(&profile, "alice")
        .expect("the shared reconciliation must refuse this file");
    assert_eq!(refusal.requested(), "alice");
    assert_eq!(refusal.derived(), Some("default"));

    // The two surfaces state their own state layout and share the recovery.
    let cli_message = refusal.message(ProfileStateLayout::PolicyDerivedStateRequested);
    let mcp_message = refusal.message(ProfileStateLayout::DerivedThroughout);
    assert_ne!(
        cli_message, mcp_message,
        "each surface must describe its own per-profile state layout"
    );
    for message in [&cli_message, &mcp_message] {
        assert!(
            message.contains("profile init --profile alice"),
            "{message}"
        );
        assert!(message.contains("stellar-agent-owner-default"), "{message}");
    }

    // This surface's wiring: the same file, through the release binary.
    let run = run_cli(
        home.path(),
        &[
            "pay",
            "--source",
            SOURCE_G,
            DEST_G,
            "1",
            "--build-only",
            "--rpc-url",
            UNREACHABLE_RPC,
            "--profile",
            "alice",
        ],
    );
    assert_eq!(
        run.code_field(),
        MISMATCH_CODE,
        "the CLI must refuse the same file the MCP server refuses; stdout={}",
        run.stdout
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Issue #109 — an unloadable profile is operator input, not a wallet defect
// ─────────────────────────────────────────────────────────────────────────────

/// The four commands that reported an unloadable profile as
/// `internal.unexpected_state` now report a validation-class code.
///
/// `internal.*` means the wallet is broken. An absent or malformed profile is
/// operator-correctable input, and an agent that routes on the code family
/// would treat these as unrecoverable rather than as "fix your profile".
#[test]
fn an_unloadable_profile_is_not_reported_as_an_internal_defect() {
    let absent = "i109-never-authored";
    let commands: &[(&str, &[&str])] = &[
        (
            "profile enroll-owner-key",
            &[
                "profile",
                "enroll-owner-key",
                "--profile",
                absent,
                "--secret-env",
                "I109_NEVER_SET",
            ],
        ),
        (
            "profile enroll-signer",
            &[
                "profile",
                "enroll-signer",
                "--profile",
                absent,
                "--secret-env",
                "I109_NEVER_SET",
            ],
        ),
        (
            "profile sign-policy",
            &[
                "profile",
                "sign-policy",
                "--profile",
                absent,
                "--secret-env",
                "I109_NEVER_SET",
                "--file",
                "/nonexistent/policy.toml",
            ],
        ),
        (
            "profile rotate-nonce-key",
            &["profile", "rotate-nonce-key", absent],
        ),
    ];

    for (label, argv) in commands {
        let home = tempfile::tempdir().expect("temp home");
        let run = run_cli(home.path(), argv);
        assert_eq!(
            run.code_field(),
            "validation.profile_not_found",
            "`{label}` must report an absent profile as operator input; stdout={} stderr={}",
            run.stdout,
            run.stderr
        );
    }
}

/// A malformed profile is operator input too, and its CAUSE survives.
///
/// Reporting it as "not found" would be wrong in the other direction: the file
/// is right there, and the operator needs to know what about it failed to
/// parse.
#[test]
fn a_malformed_profile_reports_a_validation_code_and_keeps_its_cause() {
    let home = tempfile::tempdir().expect("temp home");
    let profiles = home.path().join("profiles");
    std::fs::create_dir_all(&profiles).expect("create profiles dir");
    std::fs::write(
        profiles.join("i109-malformed.toml"),
        "this is not { valid toml [[[",
    )
    .expect("write malformed profile");

    let run = run_cli(
        home.path(),
        &["profile", "rotate-nonce-key", "i109-malformed"],
    );

    assert_eq!(
        run.code_field(),
        "validation.config_invalid",
        "a malformed profile is operator input, not a wallet defect; stdout={} stderr={}",
        run.stdout,
        run.stderr
    );
    assert!(
        run.message_field().contains("i109-malformed"),
        "the refusal must name the profile; message={}",
        run.message_field()
    );
    assert!(
        !run.message_field().contains("was not found"),
        "a file that exists must not be reported as absent; message={}",
        run.message_field()
    );
}
