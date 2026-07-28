//! Shared setup for `stellar-agent smart-account` write/read handlers.
//!
//! The signers and rules command groups both need the same pre-handler
//! plumbing: resolve signer, parse smart-account, resolve profile, open the
//! audit writer, and build manager configs from the same RPC/network inputs.
//!
//! Also provides [`emit_sa_error`] — the canonical `SaError → WalletError::SmartAccount`
//! bridge used by all multicall CLI subcommands.

use std::borrow::Cow;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use clap::{ArgGroup, Args};
use stellar_agent_core::audit_log::writer::AuditWriter;
use stellar_agent_core::envelope::Envelope;
use stellar_agent_core::error::{IoSource, ValidationError, WalletError};
use stellar_agent_core::observability::redact_path_in_message;
use stellar_agent_core::profile::schema::Profile;
use stellar_agent_core::wallet::MlockDegradation;
use stellar_agent_network::Signer;
use stellar_agent_smart_account::SaError;
use stellar_agent_smart_account::managers::rules::{
    ContextRuleManager, ContextRuleManagerConfig, SmartAccountAddress,
    parse_c_strkey_to_smart_account,
};
use stellar_agent_smart_account::managers::signers::{SignersManager, SignersManagerConfig};
use uuid::Uuid;

use crate::common::network::TargetNetwork;
use crate::common::profile_access::{
    ProfileAccessError, load_profile_reconciled_by_requested_name,
};
use crate::common::render::render_json;
use crate::common::signer_ceremony::{
    SignerCeremonyOutcome, record_mlock_degradation, resolve_software_signer_from_env,
};
use crate::common::{ResolvedProfileName, resolve_profile_name};

/// Mutually-exclusive signer source flags shared by wallet write/read handlers.
#[derive(Debug, Args)]
#[command(group(
    ArgGroup::new("signer_source")
        .args(["signer_secret_env", "sign_with_ledger"])
        .required(false)
))]
pub struct SignerSourceFlags {
    /// Signer S-strkey environment variable.
    #[arg(long, value_name = "VAR", group = "signer_source")]
    pub signer_secret_env: Option<String>,

    /// Use a Ledger hardware-wallet signer.
    #[arg(long, group = "signer_source")]
    pub sign_with_ledger: bool,

    /// BIP-44 account index for Ledger derivation (default 0).
    #[arg(long, default_value = "0", value_name = "INDEX")]
    pub account_index: Option<u32>,
}

impl SignerSourceFlags {
    fn account_index_or_default(&self) -> u32 {
        self.account_index.unwrap_or(0)
    }
}

/// View over the common wallet handler arguments.
pub trait CommonArgsView {
    /// Smart-account contract C-strkey.
    fn account(&self) -> &str;
    /// Optional profile override.
    fn profile(&self) -> Option<&str>;
    /// Shared signer-source flags.
    fn signer_source(&self) -> &SignerSourceFlags;
    /// Target network.
    fn network(&self) -> TargetNetwork;
    /// Primary RPC URL.
    fn rpc_url(&self) -> &str;
    /// Secondary RPC URL, if supplied.
    fn secondary_rpc_url(&self) -> Option<&str>;
    /// Submission timeout in seconds.
    fn timeout_seconds(&self) -> u64;
}

/// Common wallet handler context shared by rules and signers handlers.
pub struct CommonHandlerContext {
    /// Resolved signing implementation.
    pub signer: Box<dyn Signer + Send + Sync>,
    /// Parsed smart-account address.
    pub smart_account: SmartAccountAddress,
    /// Resolved profile name.
    pub profile_name: String,
    /// Shared audit writer handle.
    pub audit_writer: Arc<Mutex<AuditWriter>>,
    /// Audit log path backing `audit_writer`.
    pub audit_log_path: PathBuf,
    /// Stellar network passphrase.
    pub network_passphrase: String,
    /// Primary RPC URL.
    pub rpc_url: String,
    /// Secondary RPC URL after defaulting to `rpc_url`.
    pub secondary_rpc_url: String,
    /// Submission timeout.
    pub timeout: Duration,
    /// CAIP-2 chain ID.
    pub chain_id: String,
}

impl CommonHandlerContext {
    /// Builds a context from common CLI args.
    ///
    /// # Errors
    ///
    /// Returns a wallet error when signer resolution, smart-account parsing,
    /// audit-log opening, or path setup fails.
    pub async fn new(args: &impl CommonArgsView) -> Result<Self, WalletError> {
        let resolved = resolve_profile_name(args.profile());
        let profile_name = resolved.name.clone();
        let (signer, mlock_degradation) =
            resolve_signer(args.signer_source(), Some(&profile_name)).await?;
        let smart_account = parse_c_strkey_to_smart_account(args.account()).map_err(|e| {
            WalletError::Validation(ValidationError::AddressInvalid {
                input: format!("--account: {e}"),
            })
        })?;
        let network_passphrase = args.network().passphrase().to_owned();
        let rpc_url = args.rpc_url().to_owned();
        let secondary_rpc_url = args
            .secondary_rpc_url()
            .unwrap_or(args.rpc_url())
            .to_owned();
        let timeout = Duration::from_secs(args.timeout_seconds());
        let chain_id = network_to_chain_id(args.network()).to_owned();

        let (_audit_profile, audit_writer, audit_log_path) = open_profile_audit_writer(&resolved)?;
        record_mlock_degradation(
            &audit_writer,
            mlock_degradation.as_ref(),
            &profile_name,
            &Uuid::new_v4().to_string(),
        );

        Ok(Self {
            signer,
            smart_account,
            profile_name,
            audit_writer,
            audit_log_path,
            network_passphrase,
            rpc_url,
            secondary_rpc_url,
            timeout,
            chain_id,
        })
    }

    /// Builds a `SignersManager` from the resolved context.
    ///
    /// Delegates to [`construct_signers_manager_from_fields`], sharing the
    /// same `audit_writer` and `audit_log_path` already opened by [`Self::new`].
    ///
    /// # Errors
    ///
    /// Returns a wallet validation error if `SignersManager` construction fails.
    pub fn signers_manager(&self) -> Result<SignersManager, WalletError> {
        construct_signers_manager_from_fields(
            &self.profile_name,
            &self.network_passphrase,
            &self.chain_id,
            &self.rpc_url,
            &self.secondary_rpc_url,
            self.timeout,
            Arc::clone(&self.audit_writer),
            &self.audit_log_path,
        )
    }

    /// Builds a `ContextRuleManager` with the same audit writer and signers
    /// manager used by this context.
    ///
    /// Resolves `session_rule_max_horizon_ledgers` from the profile at
    /// construction time and threads it into the config via
    /// [`ContextRuleManagerConfig::with_session_rule_max_horizon_ledgers`].
    ///
    /// A profile that does not load leaves the cap at
    /// `DEFAULT_SESSION_RULE_HORIZON_LEDGERS` (1000 ledgers ≈ 80 min), so the
    /// command stays usable with no authored profile. A profile whose owner-key
    /// coordinate names ANOTHER profile is refused instead: reading a foreign
    /// profile's in-flight-envelope horizon is not a degraded default, it is a
    /// control taken from a profile the operator did not select.
    ///
    /// # Errors
    ///
    /// Returns a wallet validation error if manager construction fails, and
    /// `profile.name_mismatch` when the loaded profile names another profile.
    pub fn context_rule_manager(&self) -> Result<ContextRuleManager, WalletError> {
        let signers_manager = self.signers_manager().map_err(|e| {
            WalletError::Validation(ValidationError::ConfigInvalid {
                component: "SignersManager",
                reason: format!("construction for divergence check: {e}"),
            })
        })?;

        // Resolve the effective horizon cap from the profile's
        // `session_rule_max_horizon_ledgers`.
        let horizon_override =
            match load_profile_reconciled_by_requested_name(&self.profile_name, None) {
                Ok(profile) => profile.session_rule_max_horizon_ledgers,
                Err(e @ ProfileAccessError::NameMismatch(_)) => {
                    return Err(e.to_wallet_error(&self.profile_name));
                }
                Err(e) => {
                    tracing::debug!(
                        profile = %self.profile_name,
                        error = %e,
                        "smart-account: profile load for the session-rule horizon cap failed; \
                         using DEFAULT_SESSION_RULE_HORIZON_LEDGERS"
                    );
                    None
                }
            };

        let mut config = ContextRuleManagerConfig::new(
            self.rpc_url.clone(),
            self.network_passphrase.clone(),
            self.timeout,
            self.chain_id.clone(),
        )
        .with_signers_manager(Arc::new(signers_manager))
        .with_audit_writer(Arc::clone(&self.audit_writer));

        if let Some(ledgers) = horizon_override {
            config = config.with_session_rule_max_horizon_ledgers(ledgers);
        }

        ContextRuleManager::new(config).map_err(|e| {
            WalletError::Validation(ValidationError::ConfigInvalid {
                component: "ContextRuleManager",
                reason: e.to_string(),
            })
        })
    }
}

/// Resolves a signing key from the supplied [`SignerSourceFlags`].
///
/// Used by write commands that need a `Signer` without requiring the full
/// [`CommonHandlerContext`] (e.g. timelock CLI verbs which take `--timelock`
/// instead of `--account`).
///
/// `profile_name` supplies the `[wallet]` posture and TTL for the
/// `--signer-secret-env` path via [`resolve_software_signer_from_env`]; pass
/// `None` when no profile is available at the call site.
///
/// Returns any `mlock` degradation the secret-env ceremony reported
/// alongside the signer (`None` for the Ledger path); the caller records it
/// via [`record_mlock_degradation`] once its audit writer is open.
///
/// # Errors
///
/// Returns a [`WalletError`] when no signer-source flag is supplied
/// (`validation.signer_source_required`), the Ledger device is unavailable
/// (`wallet_state.hardware_not_found` family), or the env-var S-strkey is
/// missing or invalid (`validation.secret_env_not_set` /
/// `validation.secret_env_invalid`).
pub(crate) async fn resolve_signer(
    signer_source: &SignerSourceFlags,
    profile_name: Option<&str>,
) -> Result<(Box<dyn Signer + Send + Sync>, Option<MlockDegradation>), WalletError> {
    if signer_source.sign_with_ledger {
        use stellar_agent_network::signing::hardware::HardwareSigningKey;
        let hw_key = HardwareSigningKey::native()?
            .with_account_index(signer_source.account_index_or_default());
        return Ok((Box::new(hw_key), None));
    }

    let var_name = signer_source.signer_secret_env.as_deref().ok_or_else(|| {
        WalletError::Validation(ValidationError::SignerSourceRequired {
            detail: "no signer-source flag specified; pass --signer-secret-env <VAR> \
                     or --sign-with-ledger (or --dry-run on subcommands that support \
                     read-only operation)"
                .to_owned(),
        })
    })?;
    let SignerCeremonyOutcome {
        signer,
        mlock_degradation,
    } = resolve_software_signer_from_env(var_name, "smart-account-write", profile_name).await?;
    Ok((Box::new(signer), mlock_degradation))
}

/// Maps a [`TargetNetwork`] to its CAIP-2 chain-ID string.
pub(crate) fn network_to_chain_id(network: TargetNetwork) -> &'static str {
    match network {
        TargetNetwork::Testnet => "stellar:testnet",
        TargetNetwork::Mainnet => "stellar:mainnet",
    }
}

/// Constructs a [`SignersManager`] from pre-resolved fields and an already-opened
/// audit-writer.
///
/// This is the single `SignersManager::new(SignersManagerConfig::new(...))` call
/// site in the CLI crate.  Callers obtain `audit_writer` and `audit_log_path`
/// from [`open_audit_writer`] and pass them here; no I/O is performed inside
/// this function.
///
/// The argument count (8) mirrors [`SignersManagerConfig::new`] exactly; a
/// grouping struct would only move the same fields elsewhere without adding
/// structure.
///
/// # Errors
///
/// Returns [`WalletError::Validation`] wrapping
/// [`ValidationError::ConfigInvalid`] with `component = "SignersManager"`
/// when [`SignersManager::new`] fails (e.g. invalid RPC URL format).
#[allow(clippy::too_many_arguments)]
pub(crate) fn construct_signers_manager_from_fields(
    profile_name: &str,
    network_passphrase: &str,
    chain_id: &str,
    rpc_url: &str,
    secondary_rpc_url: &str,
    timeout: Duration,
    audit_writer: Arc<Mutex<AuditWriter>>,
    audit_log_path: &std::path::Path,
) -> Result<SignersManager, WalletError> {
    let config = SignersManagerConfig::new(
        rpc_url.to_owned(),
        secondary_rpc_url.to_owned(),
        audit_writer,
        audit_log_path.to_path_buf(),
        network_passphrase.to_owned(),
        profile_name.to_owned(),
        timeout,
        chain_id.to_owned(),
    );
    SignersManager::new(config).map_err(|e| {
        WalletError::Validation(ValidationError::ConfigInvalid {
            component: "SignersManager",
            reason: e.to_string(),
        })
    })
}

/// Builds the `WalletError::SmartAccount` envelope an `emit_sa_error` call
/// would render, with operator-facing filesystem paths under `$HOME` redacted
/// to `<HOME>/...`.
///
/// Several `SaError` variants embed `path: PathBuf` in their `Display` (e.g.
/// `NetworksTomlIo`, `NetworksTomlParse`). Without
/// redaction the absolute prefix leaks the operator's home directory and
/// active profile name through the wire envelope (same class as the
/// `WalletError::Io.message` path leak handled in [`wallet_io_error`]).
fn build_sa_error_envelope(e: &SaError) -> WalletError {
    WalletError::SmartAccount {
        wire_code: e.wire_code(),
        message: redact_path_in_message(&e.to_string()),
    }
}

/// Maps an [`SaError`] into the `WalletError::SmartAccount { wire_code, message }`
/// envelope shape, without path redaction.
///
/// Distinct from [`build_sa_error_envelope`]: this is the plain mapping used
/// by `execute`, `signers`, and `migrate-verifier`'s `emit_error_sa` helpers,
/// none of whose `SaError` variants carry a `path: PathBuf` in their
/// `Display`. Call sites that do need path redaction use
/// [`emit_sa_error`]/[`build_sa_error_envelope`] instead.
pub(crate) fn wrap_sa_error(err: &SaError) -> WalletError {
    WalletError::SmartAccount {
        wire_code: err.wire_code(),
        message: err.to_string(),
    }
}

/// Serialises a [`SaError`] into a `WalletError::SmartAccount` envelope and
/// renders it to stdout.
///
/// This is the canonical `SaError → wire-code` bridge for all multicall CLI
/// subcommands. It preserves the typed `wire_code()` from the smart-account
/// layer rather than flattening the error into an unrelated `KeyringNotFound`
/// category. Path redaction in the message field is performed via
/// [`build_sa_error_envelope`].
///
/// Returns exit code `1`.
pub(crate) fn emit_sa_error(e: &SaError) -> i32 {
    let wallet_err = build_sa_error_envelope(e);
    render_json(&Envelope::<()>::err(&wallet_err));
    1
}

/// Builds a typed wallet I/O error for operator-facing filesystem failures.
pub(crate) fn wallet_io_error(
    source: IoSource,
    message: impl Into<Cow<'static, str>>,
) -> WalletError {
    let message = message.into();
    WalletError::Io {
        source_kind: source,
        message: Cow::Owned(redact_path_in_message(&message)),
    }
}

/// Renders a typed filesystem I/O error and returns CLI failure status.
pub(crate) fn emit_io_error(source: IoSource, message: impl Into<Cow<'static, str>>) -> i32 {
    let wallet_err = wallet_io_error(source, message);
    render_json(&Envelope::<()>::err(&wallet_err));
    1
}

/// Emits registry load/save I/O failures as `io.*` while preserving parse and
/// semantic registry errors as `sa.*`.
pub(crate) fn emit_multicall_registry_error(e: &SaError, source: IoSource) -> i32 {
    match e {
        SaError::NetworksTomlIo { .. } => emit_io_error(source, e.to_string()),
        _ => emit_sa_error(e),
    }
}

/// Resolves the profile for `resolved` (or synthesizes the zero-config
/// testnet fallback when NO profile was named and no profile file exists) and
/// opens the audit-log writer under the profile's configured `audit_log_path`
/// and audit chain-root HMAC key.
///
/// Takes the whole [`ResolvedProfileName`], not the bare name, because
/// [`load_profile_or_synthesize_testnet`](crate::common::profile_access::load_profile_or_synthesize_testnet)
/// keys the synthesis fallback on the name's provenance: a profile the
/// operator named through `--profile` or `STELLAR_AGENT_PROFILE` but never
/// authored refuses instead of resolving to the permissive fallback.
///
/// Origin-aware, mirroring the value-verb discipline:
///
/// - A PERSISTED profile fails closed
///   (`crate::commands::value_audit::require_value_audit_writer`): the
///   operator minted a trust root, so a manager must not run with an
///   unverifiable or divergent writer. `AuditWriterRegistry` pins one
///   `(path, hmac_key)` pair per profile name for the process lifetime;
///   registering anything but the keyed pair here would brick later opens
///   (`PathMismatch`/`HmacKeyMismatch`) and leave rows outside
///   `stellar-agent audit verify` coverage.
/// - A SYNTHESIZED profile keeps the zero-config quickstart working:
///   keyed when the derived key loads, otherwise an unkeyed writer at the
///   same per-profile path
///   (`crate::commands::value_audit::acquire_best_effort_audit_writer`).
///
/// Returns the resolved profile alongside the writer so callers stop
/// re-deriving paths from the bare name.
pub(crate) fn open_profile_audit_writer(
    resolved: &ResolvedProfileName,
) -> Result<(Profile, Arc<Mutex<AuditWriter>>, PathBuf), WalletError> {
    use crate::common::profile_access::{ProfileOrigin, load_profile_or_synthesize_testnet};

    let profile_name = resolved.name.as_str();
    let (profile, origin) = load_profile_or_synthesize_testnet(resolved)
        .map_err(|e| map_access_error(&e, profile_name))?;
    let log_path = profile.audit_log_path.clone();

    if let Some(parent) = log_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            wallet_io_error(IoSource::AuditWriterSetup, format!("create directory: {e}"))
        })?;
    }

    let writer = match origin {
        ProfileOrigin::Persisted => {
            crate::commands::value_audit::require_value_audit_writer(&profile, profile_name)?
        }
        ProfileOrigin::Synthesized => {
            crate::commands::value_audit::acquire_best_effort_audit_writer(&profile, profile_name)?
        }
    };
    Ok((profile, writer, log_path))
}

/// Maps a profile-access failure onto the typed error the audit-writer helpers
/// return.
///
/// A name mismatch keeps its own `profile.name_mismatch` wire code rather than
/// being flattened into an I/O failure: it is the refusal every caller of these
/// helpers must be able to recognise, and several of them treat a writer-open
/// I/O failure as non-fatal.
fn map_access_error(
    err: &crate::common::profile_access::ProfileAccessError,
    profile_name: &str,
) -> WalletError {
    use crate::common::profile_access::ProfileAccessError;
    match err {
        ProfileAccessError::NameMismatch(_) => err.to_wallet_error(profile_name),
        ProfileAccessError::Load(_) => wallet_io_error(
            IoSource::AuditWriterSetup,
            format!("profile resolution failed: {}", err.message(profile_name)),
        ),
    }
}

/// Best-effort sibling of [`open_profile_audit_writer`] for READ-ONLY
/// commands (list/inspect surfaces and dry-run simulation): they neither
/// sign nor submit, so the fail-closed pre-flight does not apply to them,
/// but manager construction still requires a writer object.
///
/// The acquisition is keyed-first through the same discipline
/// ([`crate::commands::value_audit::acquire_best_effort_audit_writer`]); a
/// profile whose chain key is unminted degrades to an unkeyed writer with a
/// warning instead of refusing, so an operator can always inspect their own
/// state.
///
/// # Errors
///
/// Returns [`WalletError`] on profile-resolution failure or when even the
/// unkeyed open fails (I/O).
pub(crate) fn open_profile_audit_writer_read_only(
    resolved: &ResolvedProfileName,
) -> Result<(Profile, Arc<Mutex<AuditWriter>>, PathBuf), WalletError> {
    use crate::common::profile_access::load_profile_or_synthesize_testnet;

    let profile_name = resolved.name.as_str();
    let (profile, _origin) = load_profile_or_synthesize_testnet(resolved)
        .map_err(|e| map_access_error(&e, profile_name))?;
    let log_path = profile.audit_log_path.clone();

    if let Some(parent) = log_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            wallet_io_error(IoSource::AuditWriterSetup, format!("create directory: {e}"))
        })?;
    }

    let writer =
        crate::commands::value_audit::acquire_best_effort_audit_writer(&profile, profile_name)?;
    Ok((profile, writer, log_path))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::panic, reason = "test-only assertions")]

    use stellar_agent_core::profile::name::ProfileNameSource;

    use super::*;

    /// A resolved name with an explicit source, as `--profile <name>` produces.
    fn named(name: &str) -> ResolvedProfileName {
        ResolvedProfileName {
            name: name.to_owned(),
            source: ProfileNameSource::Flag,
        }
    }

    /// The origin-aware writer gate every smart-account, approve, and
    /// timelock command shares: a PERSISTED profile without a minted audit
    /// chain key refuses (`audit.chain_key_unavailable`), and with the key
    /// minted it opens the writer at the profile's configured path.
    #[test]
    #[serial_test::serial]
    fn open_profile_audit_writer_is_origin_aware() {
        use stellar_agent_core::profile::loader as profile_loader;
        use stellar_agent_test_support::{StellarAgentHomeGuard, keyring_mock};
        let dir = tempfile::TempDir::new().expect("tempdir");
        let _home = StellarAgentHomeGuard::new(dir.path());
        keyring_mock::install().expect("mock store");

        let profile = Profile::builder_testnet_named("gate-test", "svc", "acct", "n-svc", "n-acct")
            .audit_log_path(dir.path().join("audit").join("gate-test.jsonl"))
            .build();
        profile_loader::save_to_dir("gate-test", &profile, &dir.path().join("profiles"))
            .expect("persist profile");

        let err = open_profile_audit_writer(&named("gate-test"))
            .expect_err("a persisted profile without a minted audit key must refuse");
        assert_eq!(err.code(), "audit.chain_key_unavailable");

        stellar_agent_network::keyring::rotate_keyring_secret_32(
            &profile.audit_log_hash_chain_key_id.service,
            &profile.audit_log_hash_chain_key_id.account,
        )
        .expect("mint audit key");
        let (loaded, _writer, path) = open_profile_audit_writer(&named("gate-test"))
            .expect("minted key must open the writer");
        assert_eq!(path, loaded.audit_log_path);
    }

    /// A profile NAMED through `--profile` but never authored refuses: the
    /// smart-account surface must not open a writer under the synthesized
    /// permissive fallback for a name the operator chose.
    #[test]
    #[serial_test::serial]
    fn open_profile_audit_writer_refuses_a_named_absent_profile() {
        use stellar_agent_test_support::{StellarAgentHomeGuard, keyring_mock};
        let dir = tempfile::TempDir::new().expect("tempdir");
        let _home = StellarAgentHomeGuard::new(dir.path());
        keyring_mock::install().expect("mock store");

        let err = open_profile_audit_writer(&named("gate-absent"))
            .expect_err("a named profile with no file must refuse, not synthesize");
        assert!(
            err.to_string().contains("gate-absent"),
            "the refusal must name the profile the operator asked for: {err}"
        );
    }

    /// With NO profile named and no `default.toml`, the zero-config path
    /// still yields a writer — the sibling of the refusal above, and the
    /// invariant that keeps the smart-account quickstart working.
    #[test]
    #[serial_test::serial]
    fn open_profile_audit_writer_synthesizes_when_no_profile_was_named() {
        use stellar_agent_test_support::{StellarAgentHomeGuard, keyring_mock};
        let dir = tempfile::TempDir::new().expect("tempdir");
        let _home = StellarAgentHomeGuard::new(dir.path());
        keyring_mock::install().expect("mock store");

        let unnamed = ResolvedProfileName {
            name: "default".to_owned(),
            source: ProfileNameSource::Default,
        };
        let (_synth, _writer, _path) = open_profile_audit_writer(&unnamed)
            .expect("the synthesized zero-config path must still yield a writer");
    }

    /// The secret-env arm derives the same public key ed25519-dalek derives
    /// from the seed, end to end through the mlock ceremony (unlock, derive,
    /// dispose).
    #[tokio::test(flavor = "multi_thread")]
    #[allow(
        unsafe_code,
        reason = "test-only process environment mutation; the variable name is unique to this test"
    )]
    async fn resolve_signer_secret_env_derives_the_expected_public_key() {
        let seed = [0x42u8; 32];
        let s_strkey = stellar_strkey::ed25519::PrivateKey(seed)
            .as_unredacted()
            .to_string()
            .to_string();
        let expected_g = {
            let vk = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key();
            stellar_strkey::ed25519::PublicKey(vk.to_bytes())
                .to_string()
                .to_string()
        };
        // Unique variable name: env mutation is process-global under the
        // parallel harness.
        let var = "COMMON_RESOLVE_SIGNER_CEREMONY_TEST_SK";
        unsafe {
            std::env::set_var(var, &s_strkey);
        }
        let flags = SignerSourceFlags {
            signer_secret_env: Some(var.to_owned()),
            sign_with_ledger: false,
            account_index: None,
        };
        let (signer, mlock_degradation) = resolve_signer(&flags, None)
            .await
            .expect("resolve must succeed");
        assert!(
            mlock_degradation.is_none(),
            "a real mlock success/opt-out must not report degradation"
        );
        let derived = signer.public_key().await.expect("public key must derive");
        assert_eq!(derived.to_string().to_string(), expected_g);
        unsafe {
            std::env::remove_var(var);
        }
    }

    /// An unset env var refuses with `validation.secret_env_not_set` naming the
    /// variable — an input-validation failure, not a keyring condition.
    #[tokio::test(flavor = "multi_thread")]
    async fn resolve_signer_unset_env_var_is_refused() {
        let flags = SignerSourceFlags {
            signer_secret_env: Some("COMMON_RESOLVE_SIGNER_UNSET_VAR_TEST".to_owned()),
            sign_with_ledger: false,
            account_index: None,
        };
        let err = match resolve_signer(&flags, None).await {
            Ok(_) => panic!("unset env var must refuse"),
            Err(e) => e,
        };
        assert_eq!(err.code(), "validation.secret_env_not_set");
        assert!(
            err.to_string()
                .contains("COMMON_RESOLVE_SIGNER_UNSET_VAR_TEST"),
            "error must name the variable: {err}"
        );
    }

    /// A malformed S-strkey refuses before any unlock with
    /// `validation.secret_env_invalid`, naming the variable but never echoing
    /// its value.
    #[tokio::test(flavor = "multi_thread")]
    #[allow(
        unsafe_code,
        reason = "test-only process environment mutation; the variable name is unique to this test"
    )]
    async fn resolve_signer_invalid_s_strkey_is_refused() {
        let var = "COMMON_RESOLVE_SIGNER_MALFORMED_TEST_SK";
        unsafe {
            std::env::set_var(var, "not-an-s-strkey");
        }
        let flags = SignerSourceFlags {
            signer_secret_env: Some(var.to_owned()),
            sign_with_ledger: false,
            account_index: None,
        };
        let err = match resolve_signer(&flags, None).await {
            Ok(_) => panic!("malformed S-strkey must refuse"),
            Err(e) => e,
        };
        assert_eq!(err.code(), "validation.secret_env_invalid");
        assert!(
            err.to_string().contains(var),
            "error must name the variable: {err}"
        );
        assert!(
            !err.to_string().contains("not-an-s-strkey"),
            "error must not echo the malformed value: {err}"
        );
        unsafe {
            std::env::remove_var(var);
        }
    }

    /// The Ledger signer path never reports a keyring error: with no device
    /// attached (CI) `resolve_signer` surfaces a `wallet_state.*` error; with a
    /// live device it returns a signer. In every case the code is neither
    /// `auth.keyring_not_found` nor `auth.keyring_locked` — a keyring lookup is
    /// never performed on the hardware path.
    #[tokio::test(flavor = "multi_thread")]
    async fn resolve_signer_ledger_source_never_reports_keyring_error() {
        let flags = SignerSourceFlags {
            signer_secret_env: None,
            sign_with_ledger: true,
            account_index: Some(0),
        };
        let err = match resolve_signer(&flags, None).await {
            // A live device resolved a signer; the no-keyring-lookup invariant
            // still holds.
            Ok(_) => return,
            Err(e) => e,
        };
        let code = err.code();
        assert_ne!(
            code, "auth.keyring_not_found",
            "the Ledger path must not surface a keyring-not-found error; got {code}"
        );
        assert_ne!(
            code, "auth.keyring_locked",
            "the Ledger path must not surface a keyring-locked error; got {code}"
        );
    }

    /// With neither signer-source flag, `resolve_signer` refuses before any key
    /// access or network call with `validation.signer_source_required` — a
    /// missing-input failure, not a keyring condition.
    #[tokio::test(flavor = "multi_thread")]
    async fn resolve_signer_missing_source_reports_signer_source_required() {
        let flags = SignerSourceFlags {
            signer_secret_env: None,
            sign_with_ledger: false,
            account_index: None,
        };
        let err = match resolve_signer(&flags, None).await {
            Ok(_) => panic!("a missing signer-source flag must be refused"),
            Err(e) => e,
        };
        assert_eq!(err.code(), "validation.signer_source_required");
    }

    #[test]
    fn wallet_io_error_redacts_home_prefixed_path() {
        let home = std::env::var("HOME").expect("HOME is set in test environment");
        let message = format!(
            "networks.toml I/O error at {home}/.local/share/stellar-agent/networks.toml: Permission denied"
        );

        let err = wallet_io_error(IoSource::MulticallRegistryLoad, message);

        match err {
            WalletError::Io { message, .. } => {
                assert!(message.contains("<HOME>/.local/share/stellar-agent/networks.toml"));
                assert!(!message.contains(&format!("{home}/.local/share/")));
            }
            other => panic!("expected WalletError::Io, got {other:?}"),
        }
    }

    /// Closes the parallel-leak path opened by
    /// `SaError::NetworksTomlParse.path` embedding `$HOME` in its
    /// Display impl. `emit_sa_error` (and therefore
    /// `build_sa_error_envelope`) must redact the message before it reaches
    /// the wire envelope, the same way `wallet_io_error` redacts
    /// `WalletError::Io` paths.
    #[test]
    fn build_sa_error_envelope_redacts_home_prefixed_paths_from_smart_account_message() {
        use std::path::PathBuf;

        let home = std::env::var("HOME").expect("HOME is set in test environment");
        let toml_text = "not = valid = toml";
        let source: toml::de::Error = toml::from_str::<toml::Value>(toml_text)
            .expect_err("malformed TOML must fail to parse");
        let path = PathBuf::from(format!("{home}/.local/share/stellar-agent/networks.toml"));
        let sa_err = SaError::NetworksTomlParse { source, path };

        let wallet_err = build_sa_error_envelope(&sa_err);

        match wallet_err {
            WalletError::SmartAccount { wire_code, message } => {
                assert_eq!(wire_code, "sa.networks_toml_parse");
                assert!(
                    message.contains("<HOME>/.local/share/stellar-agent/networks.toml"),
                    "expected <HOME>-redacted path in message: {message}"
                );
                assert!(
                    !message.contains(&format!("{home}/.local/share/")),
                    "raw home-prefixed path must not leak: {message}"
                );
            }
            other => panic!("expected WalletError::SmartAccount, got {other:?}"),
        }
    }
}
