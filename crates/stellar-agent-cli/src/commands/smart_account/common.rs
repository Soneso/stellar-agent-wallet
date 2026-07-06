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
use stellar_agent_core::audit_log::writer::{AuditWriter, AuditWriterRegistry};
use stellar_agent_core::envelope::Envelope;
use stellar_agent_core::error::{AuthError, IoSource, ValidationError, WalletError};
use stellar_agent_core::observability::redact_path_in_message;
use stellar_agent_core::profile::loader as profile_loader;
use stellar_agent_network::Signer;
use stellar_agent_smart_account::SaError;
use stellar_agent_smart_account::managers::rules::{
    ContextRuleManager, ContextRuleManagerConfig, SmartAccountAddress,
    parse_c_strkey_to_smart_account,
};
use stellar_agent_smart_account::managers::signers::{SignersManager, SignersManagerConfig};

use crate::common::network::TargetNetwork;
use crate::common::render::render_json;
use crate::common::resolve_profile_name;
use crate::common::signer_ceremony::resolve_software_signer_from_env;

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
        let profile_name = resolve_profile_name(args.profile());
        let signer = resolve_signer(args.signer_source(), Some(&profile_name)).await?;
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

        let (audit_writer, audit_log_path) = open_audit_writer(&profile_name)?;

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
    /// Profile load failure is non-fatal for
    /// the horizon cap: the manager uses
    /// `DEFAULT_SESSION_RULE_HORIZON_LEDGERS` (1000 ledgers ≈ 80 min) when
    /// the profile cannot be loaded or the field is absent.
    ///
    /// # Errors
    ///
    /// Returns a wallet validation error if manager construction fails.
    pub fn context_rule_manager(&self) -> Result<ContextRuleManager, WalletError> {
        let signers_manager = self.signers_manager().map_err(|e| {
            WalletError::Validation(ValidationError::ConfigInvalid {
                component: "SignersManager",
                reason: format!("construction for divergence check: {e}"),
            })
        })?;

        // Resolve the effective horizon cap from the profile's
        // `session_rule_max_horizon_ledgers`.  Profile load failure is
        // non-fatal; the manager falls back to
        // `DEFAULT_SESSION_RULE_HORIZON_LEDGERS`.
        let horizon_override = profile_loader::load(&self.profile_name, None)
            .ok()
            .and_then(|p| p.session_rule_max_horizon_ledgers);

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
/// # Errors
///
/// Returns a [`WalletError`] when no signer-source flag is supplied, the
/// Ledger device is unavailable, or the env-var S-strkey is invalid.
pub(crate) async fn resolve_signer(
    signer_source: &SignerSourceFlags,
    profile_name: Option<&str>,
) -> Result<Box<dyn Signer + Send + Sync>, WalletError> {
    if signer_source.sign_with_ledger {
        use stellar_agent_network::signing::hardware::HardwareSigningKey;
        let hw_key = HardwareSigningKey::native()
            .map_err(|e| {
                WalletError::Auth(AuthError::KeyringNotFound {
                    name: format!("Ledger not found or Stellar app not open: {e}"),
                })
            })?
            .with_account_index(signer_source.account_index_or_default());
        return Ok(Box::new(hw_key));
    }

    let var_name = signer_source.signer_secret_env.as_deref().ok_or_else(|| {
        WalletError::Auth(AuthError::KeyringNotFound {
            name: "no signer-source flag specified; pass --signer-secret-env <VAR> \
                   or --sign-with-ledger (or --dry-run on subcommands that support \
                   read-only operation)"
                .to_owned(),
        })
    })?;
    let signer =
        resolve_software_signer_from_env(var_name, "smart-account-write", profile_name).await?;
    Ok(Box::new(signer))
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

/// Opens (or returns the cached) audit-log writer for `profile_name`.
///
/// Delegates to [`AuditWriterRegistry::get_or_open`] so the same
/// `Arc<Mutex<AuditWriter>>` is returned for every call with the same
/// `profile_name` within the process, preventing multiple writers from racing
/// to open the same file.
pub(crate) fn open_audit_writer(
    profile_name: &str,
) -> Result<(Arc<Mutex<AuditWriter>>, PathBuf), WalletError> {
    use stellar_agent_core::profile::schema::default_audit_log_path_for;

    let log_path = default_audit_log_path_for(profile_name);

    if let Some(parent) = log_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            wallet_io_error(IoSource::AuditWriterSetup, format!("create directory: {e}"))
        })?;
    }

    let writer = AuditWriterRegistry::get_or_open(profile_name, &log_path, None).map_err(|e| {
        wallet_io_error(
            IoSource::AuditWriterSetup,
            format!("open audit writer: {e}"),
        )
    })?;

    Ok((writer, log_path))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::panic, reason = "test-only assertions")]

    use super::*;

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
        let signer = resolve_signer(&flags, None)
            .await
            .expect("resolve must succeed");
        let derived = signer.public_key().await.expect("public key must derive");
        assert_eq!(derived.to_string().to_string(), expected_g);
        unsafe {
            std::env::remove_var(var);
        }
    }

    /// An unset env var refuses with the keyring-not-found error naming the
    /// variable.
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
        assert!(
            err.to_string()
                .contains("COMMON_RESOLVE_SIGNER_UNSET_VAR_TEST"),
            "error must name the variable: {err}"
        );
    }

    /// A malformed S-strkey refuses before any unlock.
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
        assert!(
            err.to_string().contains("invalid S-strkey"),
            "error must state the malformed key: {err}"
        );
        unsafe {
            std::env::remove_var(var);
        }
    }

    #[test]
    fn wallet_io_error_redacts_home_prefixed_path() {
        let home = std::env::var("HOME").expect("HOME is set in test environment");
        let message = format!(
            "networks.toml I/O error at {home}/.config/stellar-agent/mainnet/networks.toml: Permission denied"
        );

        let err = wallet_io_error(IoSource::MulticallRegistryLoad, message);

        match err {
            WalletError::Io { message, .. } => {
                assert!(message.contains("<HOME>/.config/stellar-agent/mainnet/networks.toml"));
                assert!(!message.contains(&format!("{home}/.config/")));
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
        let path = PathBuf::from(format!(
            "{home}/.config/stellar-agent/mainnet/networks.toml"
        ));
        let sa_err = SaError::NetworksTomlParse { source, path };

        let wallet_err = build_sa_error_envelope(&sa_err);

        match wallet_err {
            WalletError::SmartAccount { wire_code, message } => {
                assert_eq!(wire_code, "sa.networks_toml_parse");
                assert!(
                    message.contains("<HOME>/.config/stellar-agent/mainnet/networks.toml"),
                    "expected <HOME>-redacted path in message: {message}"
                );
                assert!(
                    !message.contains(&format!("{home}/.config/")),
                    "raw home-prefixed path must not leak: {message}"
                );
            }
            other => panic!("expected WalletError::SmartAccount, got {other:?}"),
        }
    }
}
