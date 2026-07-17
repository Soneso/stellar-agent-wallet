//! `stellar-agent profile init` — create and persist a new profile TOML.
//!
//! Docs and the MCP server's first-run guidance reference this command as the
//! way to move past the in-memory testnet fallback (see
//! [`stellar_agent_core::profile::loader::load_default_or_testnet_fallback`]).
//! It mints a version-2 profile with the per-profile-derived keyring entry
//! references [`Profile::builder_testnet_named`] / [`Profile::builder_mainnet_named`]
//! produce, then writes it to `<profile_dir>/<name>.toml`.
//!
//! # Keyring references
//!
//! The signer and nonce coordinates come from
//! [`KeyringEntryRef::default_signer`] / [`KeyringEntryRef::default_nonce`]
//! (`stellar-agent-signer-<name>` / `stellar-agent-nonce-<name>`) — the same
//! derivations `load_default_or_testnet_fallback`'s in-memory fallback
//! profile uses. Both accounts are seeded with the placeholder `"default"` —
//! the signer's eventual G-strkey identity is not known until a seed is
//! enrolled (see "Account-as-identity" in `enroll_signer.rs`'s module
//! documentation for how `enroll-signer` pins it). The five
//! security-substrate references (`audit_log_hash_chain_key_id`,
//! `policy_owner_key_id`, `attestation_key_id`, `counterparty_cache_key_id`,
//! `policy_window_state_key_id`) are derived from the profile name by
//! [`Profile::builder_testnet_named`] / [`Profile::builder_mainnet_named`]. No
//! key material is minted and no audit row is emitted — the key-writing
//! commands (`enroll-signer`, `enroll-owner-key`, the `rotate-*` subcommands)
//! mint their own keys and emit their own `keyring_key_written` rows.
//!
//! # Audit key is required on every engine before signing
//!
//! Because `init` mints the `audit_log_hash_chain_key_id` keyring COORDINATE
//! only (no key material), every value-moving signing verb refuses with
//! `audit.chain_key_unavailable` until `stellar-agent profile rotate-audit-key
//! <name>` mints the key — this applies to the `noop` engine exactly as it
//! does to `v1`, since the audit pre-flight is independent of the policy
//! engine. `next_steps` names `rotate-audit-key` in the ALWAYS list (right
//! after `enroll-signer`) for both engines.
//!
//! # Engine default
//!
//! `--engine` defaults to `v1` — [`PolicyEngineKind::default`] is `V1`, and
//! newly-minted profiles are meant to carry the policy-engine infrastructure
//! from the start (unlike a profile migrated from schema v1, which is set to
//! `noop` explicitly). A v1 profile refuses MCP-server startup and
//! policy-gated dispatch until the V1 ceremony completes (owner key,
//! attestation key, signed policy, on top of the audit key every engine
//! needs — the normative list is in the CLI reference's `profile init` entry,
//! mirrored in `next_steps`).
//! `--engine noop` is the zero-ceremony testnet opt-out: the profile works
//! immediately (once the audit key is minted), with the Noop engine's
//! testnet-allow / mainnet-read-only posture.
//!
//! # Mainnet requires an explicit HTTPS `--rpc-url`
//!
//! The built-in mainnet default endpoint
//! ([`stellar_agent_core::profile::caip2::MAINNET_RPC_URL`]) requires an API
//! key and answers HTTP 401 unauthenticated, so persisting it silently would
//! mint a broken configuration. `init` refuses `--network mainnet` without an
//! explicit `--rpc-url`, and refuses a plaintext (non-`https://`) mainnet
//! endpoint — the requirement exists for endpoint trust. Testnet has no such
//! requirement: `--rpc-url` is optional and defaults to the built-in testnet
//! endpoint.
//!
//! # Overwrite refusal
//!
//! `init` refuses when `<name>.toml` already exists, before building or
//! writing anything, and the write itself goes through
//! [`stellar_agent_core::profile::loader::save_new_to_dir`], whose no-clobber
//! persist repeats the refusal atomically — a file appearing between the
//! check and the write is never overwritten. The existing file is never read
//! or modified by a refused `init`.
//!
//! # Output (JSON envelope)
//!
//! On success:
//!
//! ```json
//! {
//!   "ok": true,
//!   "data": {
//!     "profile": "default",
//!     "path": "/home/user/.local/share/stellar-agent/profiles/default.toml",
//!     "chain_id": "stellar:testnet",
//!     "rpc_url": "https://soroban-testnet.stellar.org",
//!     "engine": "v1",
//!     "next_steps": [
//!       "Run `stellar-agent profile enroll-signer --profile default --secret-env <VAR>` to register the MCP signer seed.",
//!       "Run `stellar-agent profile rotate-audit-key default` to mint the audit-log hash-chain key (required before any signing verb will proceed).",
//!       "Run `stellar-agent profile enroll-owner-key --profile default --secret-env <VAR>` to enroll the policy-file owner key.",
//!       "Run `stellar-agent profile rotate-attestation-key default` to mint the approval-attestation key.",
//!       "Run `stellar-agent profile sign-policy --profile default --secret-env <VAR>` to sign the V1 policy file."
//!     ]
//!   },
//!   "request_id": "..."
//! }
//! ```
//!
//! # Errors
//!
//! Returns exit code `1` when: the profile name is not a safe path
//! component; `--network mainnet` is selected without `--rpc-url`, or with a
//! non-`https://` one; a profile named `--profile <NAME>` already exists; the
//! resolved `rpc_url` fails URL validation; or the write itself fails (I/O
//! error, unwritable directory).

use std::path::Path;

use clap::Args;
use serde::Serialize;

use stellar_agent_core::envelope::Envelope;
use stellar_agent_core::error::{InternalError, ValidationError, WalletError};
use stellar_agent_core::profile::caip2::MAINNET_RPC_URL;
use stellar_agent_core::profile::loader;
use stellar_agent_core::profile::schema::{KeyringEntryRef, PolicyEngineKind, Profile};

use crate::common::network::TargetNetwork;
use crate::common::render;
use crate::common::validate_path_component_ascii_safe;

/// Arguments for `stellar-agent profile init`.
#[derive(Debug, Args)]
#[non_exhaustive]
pub(crate) struct InitArgs {
    /// Name of the profile to create.
    #[arg(long, default_value = "default", value_name = "NAME")]
    pub(crate) profile: String,

    /// Target network for the new profile.
    #[arg(long, default_value_t = TargetNetwork::Testnet, value_name = "NETWORK")]
    pub(crate) network: TargetNetwork,

    /// Soroban RPC endpoint for the new profile.
    ///
    /// Optional for testnet (defaults to the built-in testnet endpoint).
    /// REQUIRED, and required to be `https://`, for `--network mainnet`: the
    /// built-in mainnet default requires an API key and answers HTTP 401
    /// unauthenticated, so persisting it would mint a broken configuration.
    #[arg(long, value_name = "URL")]
    pub(crate) rpc_url: Option<String>,

    /// Policy engine for the new profile.
    #[arg(long, default_value_t = PolicyEngineKind::V1, value_name = "ENGINE")]
    pub(crate) engine: PolicyEngineKind,
}

/// Success payload for the `profile init` envelope.
#[derive(Debug, Serialize)]
struct InitData {
    /// Name of the profile that was created.
    profile: String,
    /// Path the profile TOML was written to.
    path: String,
    /// CAIP-2 chain id (`"stellar:testnet"` or `"stellar:mainnet"`).
    chain_id: String,
    /// Resolved Soroban RPC endpoint.
    rpc_url: String,
    /// Selected policy engine (`"v1"` or `"noop"`).
    engine: String,
    /// Operator-facing enrollment guidance: the follow-up commands needed
    /// before the profile can sign, in order. Always names `enroll-signer`
    /// and `rotate-audit-key` (every signing verb requires the audit
    /// chain-root key to be acquirable, regardless of policy engine); for the
    /// `v1` engine, also names `enroll-owner-key`, `rotate-attestation-key`,
    /// and `sign-policy`.
    next_steps: Vec<String>,
}

/// Runs `stellar-agent profile init`.
///
/// Returns `0` on success, `1` on error.
///
/// # Errors
///
/// Never returns `Err` — errors are captured into the exit code.
///
/// # Panics
///
/// Never panics.
pub async fn run(args: &InitArgs) -> i32 {
    let profile_dir = match loader::default_profile_dir() {
        Ok(dir) => dir,
        Err(e) => {
            let err = WalletError::Internal(InternalError::UnexpectedState {
                detail: format!("could not determine profile directory: {e}"),
            });
            render::render_json(&Envelope::<()>::err(&err));
            return 1;
        }
    };
    run_with_dependencies(args, &profile_dir)
}

/// First-stage typed refusals, evaluated before any build or write work.
///
/// Pinned by unit tests via the wire codes:
/// `validation.address_invalid` (unsafe profile name),
/// `validation.mainnet_rpc_url_required` (mainnet without `--rpc-url`),
/// `validation.config_invalid` (mainnet with a non-HTTPS `--rpc-url` — the
/// whole point of requiring an explicit endpoint is endpoint trust, so a
/// plaintext scheme is refused), and
/// `validation.profile_already_exists` (destination file present; the
/// no-clobber persist repeats this refusal atomically at write time).
fn init_refusal(args: &InitArgs, profile_dir: &Path) -> Option<WalletError> {
    // The name becomes a path component (`<profile_dir>/<name>.toml`);
    // reject path traversal / control characters before any filesystem access.
    if let Err(reason) = validate_path_component_ascii_safe(&args.profile) {
        return Some(WalletError::Validation(ValidationError::AddressInvalid {
            input: format!("invalid profile name '{}': {reason}", args.profile),
        }));
    }

    if args.network == TargetNetwork::Mainnet {
        match args.rpc_url.as_deref() {
            None => {
                return Some(WalletError::Validation(
                    ValidationError::MainnetRpcUrlRequired {
                        default_rpc_url: MAINNET_RPC_URL,
                    },
                ));
            }
            Some(url) if !url.trim().to_ascii_lowercase().starts_with("https://") => {
                return Some(WalletError::Validation(ValidationError::ConfigInvalid {
                    component: "rpc_url",
                    reason: format!(
                        "a mainnet profile requires an https:// RPC endpoint; got '{url}'"
                    ),
                }));
            }
            Some(_) => {}
        }
    }

    let dest = profile_dir.join(format!("{}.toml", args.profile));
    if dest.exists() {
        return Some(WalletError::Validation(
            ValidationError::ProfileAlreadyExists {
                name: args.profile.clone(),
                path: dest.display().to_string(),
            },
        ));
    }
    None
}

/// Testable core of [`run`] with the profile directory injected.
///
/// Production callers use [`run`], which resolves the real OS-conventional
/// profile directory via [`loader::default_profile_dir`]. Tests inject a
/// fresh `tempfile::tempdir()` path so unit tests never read or write the
/// canonical data root.
fn run_with_dependencies(args: &InitArgs, profile_dir: &Path) -> i32 {
    if let Some(err) = init_refusal(args, profile_dir) {
        render::render_json(&Envelope::<()>::err(&err));
        return 1;
    }

    // ── Build the profile ───────────────────────────────────────────────────
    // Signer/nonce references come from the shared
    // `KeyringEntryRef::default_signer` / `default_nonce` derivations — the
    // same helpers the loader's synthesised first-run fallback uses — with the
    // placeholder "default" account; `with_profile_name` derives the five
    // security-substrate references.
    let signer = KeyringEntryRef::default_signer(&args.profile);
    let nonce = KeyringEntryRef::default_nonce(&args.profile);

    let mut builder = match args.network {
        TargetNetwork::Testnet => Profile::builder_testnet_named(
            &args.profile,
            &signer.service,
            &signer.account,
            &nonce.service,
            &nonce.account,
        ),
        TargetNetwork::Mainnet => Profile::builder_mainnet_named(
            &args.profile,
            &signer.service,
            &signer.account,
            &nonce.service,
            &nonce.account,
        ),
    };
    if let Some(url) = &args.rpc_url {
        builder = builder.rpc_url(url.clone());
    }
    if args.engine == PolicyEngineKind::Noop {
        builder = builder.with_noop_engine();
    }
    let profile = builder.build();

    // ── Validate the resolved rpc_url before ever writing the file ─────────
    // Catches a malformed `--rpc-url` (testnet override or the now-mandatory
    // mainnet value) with the same check the loader applies at load time, so
    // `init` never persists a file the loader would then refuse.
    if let Err(e) = profile.validate_rpc_url() {
        let err = WalletError::Validation(ValidationError::ConfigInvalid {
            component: "rpc_url",
            reason: e.to_string(),
        });
        render::render_json(&Envelope::<()>::err(&err));
        return 1;
    }

    // ── Persist (no-clobber: atomic refusal if a file appeared meanwhile) ────
    let written_path = match loader::save_new_to_dir(&args.profile, &profile, profile_dir) {
        Ok(p) => p,
        Err(loader::ProfileSaveError::AlreadyExists { path }) => {
            let err = WalletError::Validation(ValidationError::ProfileAlreadyExists {
                name: args.profile.clone(),
                path: path.display().to_string(),
            });
            render::render_json(&Envelope::<()>::err(&err));
            return 1;
        }
        Err(e) => {
            let err = WalletError::Internal(InternalError::UnexpectedState {
                detail: format!("failed to write profile '{}': {e}", args.profile),
            });
            render::render_json(&Envelope::<()>::err(&err));
            return 1;
        }
    };

    // ── Enrollment guidance ──────────────────────────────────────────────────
    // `rotate-audit-key` is in the ALWAYS list (both engines): every signing
    // verb requires the profile's audit chain-root key to be acquirable
    // BEFORE it signs or submits — `init` mints the keyring COORDINATE only,
    // no key material, so an init-minted profile signs nothing until this
    // step runs, Noop engine included. The remaining V1 list mirrors the
    // normative ceremony in
    // docs/cli-reference/profile-and-governance.md#profile-init: owner key,
    // attestation key, then the signed policy file.
    let mut next_steps = vec![
        format!(
            "Run `stellar-agent profile enroll-signer --profile {} --secret-env <VAR>` to \
             register the MCP signer seed.",
            args.profile
        ),
        format!(
            "Run `stellar-agent profile rotate-audit-key {}` to mint the audit-log \
             hash-chain key (required before any signing verb will proceed).",
            args.profile
        ),
    ];
    if args.engine == PolicyEngineKind::V1 {
        next_steps.push(format!(
            "Run `stellar-agent profile enroll-owner-key --profile {} --secret-env <VAR>` \
             to enroll the policy-file owner key.",
            args.profile
        ));
        next_steps.push(format!(
            "Run `stellar-agent profile rotate-attestation-key {}` to mint the \
             approval-attestation key.",
            args.profile
        ));
        next_steps.push(format!(
            "Run `stellar-agent profile sign-policy --profile {} --secret-env <VAR>` to \
             sign the V1 policy file.",
            args.profile
        ));
        if args.network == TargetNetwork::Mainnet {
            next_steps.push(
                "Set `oracle_provider_url` in the profile before relying on V1 for \
                 mainnet high-value flows (the independent-RPC cross-check is skipped \
                 while it is unset)."
                    .to_owned(),
            );
        }
    }

    tracing::info!(
        profile = %args.profile,
        chain_id = %profile.chain_id,
        engine = %profile.policy.engine,
        "profile initialised"
    );
    render::render_json(&Envelope::ok(InitData {
        profile: args.profile.clone(),
        path: written_path.display().to_string(),
        chain_id: profile.chain_id.caip2_str().to_owned(),
        rpc_url: profile.rpc_url.clone(),
        engine: profile.policy.engine.to_string(),
        next_steps,
    }));
    0
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use stellar_agent_core::profile::loader::load_from_dir;

    use super::*;

    fn args(profile: &str) -> InitArgs {
        InitArgs {
            profile: profile.to_owned(),
            network: TargetNetwork::Testnet,
            rpc_url: None,
            engine: PolicyEngineKind::V1,
        }
    }

    /// RAII env-var guard; `#[serial]` on every test using it prevents
    /// concurrent env access.
    struct EnvGuard {
        var: String,
    }
    impl EnvGuard {
        #[allow(
            unsafe_code,
            reason = "test-only env mutation; #[serial] prevents concurrent access"
        )]
        fn set(var: String, value: &std::ffi::OsStr) -> Self {
            // SAFETY: serialised by #[serial]; no concurrent env access.
            unsafe {
                std::env::set_var(&var, value);
            }
            Self { var }
        }
    }
    impl Drop for EnvGuard {
        #[allow(unsafe_code, reason = "test-only env cleanup")]
        fn drop(&mut self) {
            // SAFETY: same as set(); serialised by #[serial].
            unsafe {
                std::env::remove_var(&self.var);
            }
        }
    }

    /// The test-gated `STELLAR_AGENT_HOME` override reaches the audit-path
    /// resolution: with the variable set, the per-profile audit default
    /// resolves under the redirected root, so tests that follow the
    /// documented override never write audit rows to the real host location.
    #[test]
    #[serial_test::serial]
    fn audit_path_resolution_honors_the_test_home_override() {
        let home = tempfile::tempdir().unwrap();
        let _guard = EnvGuard::set("STELLAR_AGENT_HOME".to_owned(), home.path().as_os_str());

        let path = stellar_agent_core::profile::schema::default_audit_log_path_for("override-x");
        assert!(
            path.starts_with(home.path()),
            "audit path must resolve under the overridden home; got: {path:?}"
        );
        assert_eq!(path.file_name().unwrap(), "override-x.jsonl");
        assert_eq!(path.parent().unwrap().file_name().unwrap(), "audit");
    }

    #[test]
    #[serial_test::serial]
    fn init_on_clean_dir_creates_a_loadable_v1_profile_with_derived_refs() {
        let dir = tempfile::tempdir().unwrap();
        let code = run_with_dependencies(&args("acceptance"), dir.path());
        assert_eq!(code, 0, "init must succeed on a clean directory");

        let path = dir.path().join("acceptance.toml");
        assert!(path.exists(), "profile file must be created");

        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(
            raw.contains("version = 2"),
            "must carry version = 2:\n{raw}"
        );
        assert!(
            raw.contains("[policy]"),
            "must carry a [policy] block:\n{raw}"
        );
        assert!(
            raw.contains("engine = \"v1\""),
            "default engine must be v1:\n{raw}"
        );
        assert!(
            raw.contains("stellar-agent-signer-acceptance"),
            "signer service must be derived from the profile name:\n{raw}"
        );
        assert!(
            raw.contains("stellar-agent-nonce-acceptance"),
            "nonce service must be derived from the profile name:\n{raw}"
        );
        assert!(
            raw.contains("stellar-agent-audit-acceptance"),
            "audit key ref must be derived from the profile name:\n{raw}"
        );
        assert!(
            raw.contains("stellar-agent-owner-acceptance"),
            "owner key ref must be derived from the profile name:\n{raw}"
        );
        assert!(
            raw.contains("stellar-agent-attestation-acceptance"),
            "attestation key ref must be derived from the profile name:\n{raw}"
        );
        assert!(
            raw.contains("stellar-agent-counterparty-acceptance"),
            "counterparty key ref must be derived from the profile name:\n{raw}"
        );

        // Loadable through the real loader, not just readable as text.
        let loaded = load_from_dir("acceptance", dir.path(), None).unwrap();
        assert_eq!(loaded.version, 2);
        assert_eq!(loaded.policy.engine, PolicyEngineKind::V1);
        assert_eq!(loaded.mcp_signer_default.account, "default");
    }

    #[test]
    #[serial_test::serial]
    fn init_default_name_is_loadable_without_the_synthesised_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let code = run_with_dependencies(&args("default"), dir.path());
        assert_eq!(code, 0);

        // The synthesised fallback is only reached on `ProfileLoadError::NotFound`
        // (see `load_default_or_testnet_fallback`); asserting `load_from_dir`
        // succeeds directly proves the persisted file — not the fallback — is
        // what a subsequent load resolves.
        let loaded = load_from_dir("default", dir.path(), None)
            .expect("the persisted default.toml must load directly, not via NotFound + fallback");
        assert_eq!(
            loaded.mcp_signer_default.service,
            "stellar-agent-signer-default"
        );
    }

    #[test]
    fn init_refuses_when_file_already_exists_and_leaves_it_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let code = run_with_dependencies(&args("dup"), dir.path());
        assert_eq!(code, 0, "first init must succeed");

        let path = dir.path().join("dup.toml");
        let before = std::fs::read_to_string(&path).unwrap();

        let code = run_with_dependencies(&args("dup"), dir.path());
        assert_eq!(code, 1, "second init on the same name must refuse");

        let after = std::fs::read_to_string(&path).unwrap();
        assert_eq!(before, after, "a refused init must not modify the file");
    }

    #[test]
    fn init_mainnet_without_rpc_url_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let mut a = args("mainnet-guard");
        a.network = TargetNetwork::Mainnet;
        a.rpc_url = None;

        let code = run_with_dependencies(&a, dir.path());
        assert_eq!(code, 1, "mainnet without --rpc-url must refuse");
        assert!(
            !dir.path().join("mainnet-guard.toml").exists(),
            "a refused mainnet init must not write a file"
        );
    }

    // ── Typed refusal pins (init_refusal) ────────────────────────────────────
    // The run()-level tests above prove the exit code end to end; these pin
    // the SPECIFIC typed refusal so a guard swap cannot pass unnoticed behind
    // an unrelated exit-1 path.

    /// Mainnet without `--rpc-url` refuses with its exact wire code.
    #[test]
    fn refusal_mainnet_without_rpc_url_yields_typed_code() {
        let dir = tempfile::tempdir().unwrap();
        let mut a = args("pin-mainnet");
        a.network = TargetNetwork::Mainnet;
        a.rpc_url = None;
        let err = init_refusal(&a, dir.path()).expect("must refuse");
        assert_eq!(err.code(), "validation.mainnet_rpc_url_required");
    }

    /// A plaintext mainnet endpoint refuses with the config-invalid code:
    /// the explicit-endpoint requirement exists for endpoint trust.
    #[test]
    fn refusal_mainnet_plaintext_rpc_url_yields_typed_code() {
        let dir = tempfile::tempdir().unwrap();
        let mut a = args("pin-plaintext");
        a.network = TargetNetwork::Mainnet;
        a.rpc_url = Some("http://mainnet.example.com/rpc".to_owned());
        let err = init_refusal(&a, dir.path()).expect("must refuse");
        assert_eq!(err.code(), "validation.config_invalid");
    }

    /// An existing destination refuses with its exact wire code.
    #[test]
    fn refusal_existing_profile_yields_typed_code() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("pin-exists.toml"), "version = 2\n").unwrap();
        let err = init_refusal(&args("pin-exists"), dir.path()).expect("must refuse");
        assert_eq!(err.code(), "validation.profile_already_exists");
    }

    /// An unsafe profile name refuses with its exact wire code, and no
    /// refusal fires for a clean state (the gate passes through).
    #[test]
    fn refusal_unsafe_name_yields_typed_code_and_clean_state_passes() {
        let dir = tempfile::tempdir().unwrap();
        let err = init_refusal(&args("../escape"), dir.path()).expect("must refuse");
        assert_eq!(err.code(), "validation.address_invalid");
        assert!(
            init_refusal(&args("clean-name"), dir.path()).is_none(),
            "a clean state must pass the refusal gate"
        );
    }

    #[test]
    #[serial_test::serial]
    fn init_mainnet_with_rpc_url_writes_the_supplied_url() {
        let dir = tempfile::tempdir().unwrap();
        let mut a = args("mainnet-ok");
        a.network = TargetNetwork::Mainnet;
        a.rpc_url = Some("https://mainnet.example.com/rpc".to_owned());

        let code = run_with_dependencies(&a, dir.path());
        assert_eq!(code, 0, "mainnet with --rpc-url must succeed");

        let loaded = load_from_dir("mainnet-ok", dir.path(), None).unwrap();
        assert_eq!(loaded.chain_id.caip2_str(), "stellar:mainnet");
        assert_eq!(loaded.rpc_url, "https://mainnet.example.com/rpc");
    }

    #[test]
    fn init_engine_flag_default_writes_v1() {
        let dir = tempfile::tempdir().unwrap();
        let code = run_with_dependencies(&args("engine-default"), dir.path());
        assert_eq!(code, 0);

        let raw = std::fs::read_to_string(dir.path().join("engine-default.toml")).unwrap();
        assert!(raw.contains("engine = \"v1\""), "raw toml:\n{raw}");
    }

    #[test]
    #[serial_test::serial]
    fn init_engine_noop_writes_noop() {
        let dir = tempfile::tempdir().unwrap();
        let mut a = args("engine-noop");
        a.engine = PolicyEngineKind::Noop;

        let code = run_with_dependencies(&a, dir.path());
        assert_eq!(code, 0);

        let raw = std::fs::read_to_string(dir.path().join("engine-noop.toml")).unwrap();
        assert!(raw.contains("engine = \"noop\""), "raw toml:\n{raw}");

        let loaded = load_from_dir("engine-noop", dir.path(), None).unwrap();
        assert_eq!(loaded.policy.engine, PolicyEngineKind::Noop);
    }

    #[test]
    fn init_invalid_profile_name_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let code = run_with_dependencies(&args("../escape"), dir.path());
        assert_eq!(code, 1, "a path-traversal profile name must be refused");
    }

    #[test]
    #[serial_test::serial]
    fn init_testnet_default_rpc_url_when_omitted() {
        let dir = tempfile::tempdir().unwrap();
        let code = run_with_dependencies(&args("testnet-default-rpc"), dir.path());
        assert_eq!(code, 0);

        let loaded = load_from_dir("testnet-default-rpc", dir.path(), None).unwrap();
        assert_eq!(
            loaded.rpc_url,
            stellar_agent_core::profile::caip2::TESTNET_RPC_URL
        );
    }

    #[test]
    #[serial_test::serial]
    fn init_testnet_explicit_rpc_url_overrides_default() {
        let dir = tempfile::tempdir().unwrap();
        let mut a = args("testnet-explicit-rpc");
        a.rpc_url = Some("https://custom-testnet-rpc.example.com".to_owned());

        let code = run_with_dependencies(&a, dir.path());
        assert_eq!(code, 0);

        let loaded = load_from_dir("testnet-explicit-rpc", dir.path(), None).unwrap();
        assert_eq!(loaded.rpc_url, "https://custom-testnet-rpc.example.com");
    }

    #[test]
    fn init_malformed_rpc_url_is_refused_before_write() {
        let dir = tempfile::tempdir().unwrap();
        let mut a = args("malformed-rpc");
        a.rpc_url = Some("not a url".to_owned());

        let code = run_with_dependencies(&a, dir.path());
        assert_eq!(code, 1, "a malformed --rpc-url must be refused");
        assert!(
            !dir.path().join("malformed-rpc.toml").exists(),
            "a refused init must not write a file"
        );
    }
}
