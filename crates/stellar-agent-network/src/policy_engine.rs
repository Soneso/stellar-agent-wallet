//! Shared construction of hydrated, verified policy engines.

use crate::policy_state::{PersistedWindowStore, WindowStoreError};
use std::{path::Path, sync::Arc};
use stellar_agent_core::{
    mainnet::{
        enablement::{EnablementRecord, read_enablement_nonce, verify_enablement},
        verified_policy::VerifiedPolicy,
    },
    policy::{
        NoopPolicyEngine, PolicyEngine, PolicyError,
        v1::{
            PolicyStateStore,
            verified::{OwnerKeySource, PinMode, PolicyLoad, load_verified_policy},
        },
    },
    profile::{
        name::{ProfileNameSource, derive_profile_name_from_owner_key},
        schema::{
            PolicyEngineKind, Profile, default_policy_dir, default_policy_window_state_path_for,
        },
    },
};

/// An engine and the proofs produced while constructing it.
pub struct BuiltPolicyEngine {
    /// The shared evaluator.
    pub engine: Arc<dyn PolicyEngine>,
    /// Signature and freshness proof, absent for a Noop engine.
    pub verified: Option<VerifiedPolicy>,
    /// Installation proof, present only for a fully enabled mainnet selection.
    pub enablement: Option<EnablementRecord>,
}

/// The operator's explicit profile selection, which installation verification
/// binds to.
#[derive(Debug, Clone, Copy)]
pub struct ProfileSelection<'a> {
    /// The resolved profile name.
    pub name: &'a str,
    /// How the name was selected.
    pub source: ProfileNameSource,
    /// The directory holding the profile file, read without overlays.
    pub profile_dir: &'a Path,
}

/// A typed cause preserved by binary-specific error rendering.
#[derive(Debug, thiserror::Error)]
pub enum PolicyEngineBuildError {
    /// The profile names an engine kind this build does not support.
    #[error("unsupported policy engine kind {kind:?}")]
    UnsupportedEngineKind {
        /// The unsupported kind.
        kind: PolicyEngineKind,
    },
    /// Policy parsing, signature, restrictions, or freshness failed.
    #[error("{code}: {0}", code = .0.wire_code())]
    Policy(PolicyError),
    /// The persisted window state could not be hydrated.
    #[error(
        "policy-window-state store for profile '{store_name}' failed to load ({source}); run \
         `stellar-agent profile reset-window-state {store_name} --reason <reason>` to recover"
    )]
    WindowState {
        /// The name selecting the store file, which the recovery command takes.
        store_name: String,
        /// The store's error.
        source: WindowStoreError,
    },
    /// Mainnet installation binding failed.
    #[error("{0}")]
    Enablement(stellar_agent_core::error::ValidationError),
    /// The owner-key namespace or the policy directory could not be resolved.
    #[error("{0}")]
    Configuration(String),
}

/// Hydrates the window state, verifies the policy, and verifies installation
/// binding.
///
/// A Noop engine returns before any owner key, directory, or file is used.
/// `selection` is the operator's explicit profile selection; `None` omits
/// installation verification for readers that do not select a profile, and
/// then no profile directory is resolved.
///
/// # Which name keys the window state
///
/// `store_name` selects the window-state FILE, so a binary keeps the file its
/// own writers append to: the CLI passes the requested name, the name every
/// CLI writer of the store, `profile reset-window-state`, and
/// `profile rotate-policy-state-key` use. The entries hydrated from that file
/// and the engine's `StateKey` namespace both stay the name derived from the
/// owner-key coordinate, and they must stay equal: the wire format carries no
/// name, so hydration re-attaches one, and the engine looks entries up under
/// its own namespace. An entry hydrated under any other name would read as an
/// empty window with every cap unbound.
///
/// # Errors
/// Refuses an unsupported engine kind, an unresolvable namespace or policy
/// directory, unloadable window state, an invalid or stale policy, and a
/// failed installation binding.
pub fn build_policy_engine(
    profile: &Profile,
    selection: Option<ProfileSelection<'_>>,
    store_name: &str,
    policy_dir_override: Option<&Path>,
    owner_key: [u8; 32],
    owner_source: OwnerKeySource,
) -> Result<BuiltPolicyEngine, PolicyEngineBuildError> {
    match profile.policy.engine {
        PolicyEngineKind::Noop => {
            return Ok(BuiltPolicyEngine {
                engine: Arc::new(NoopPolicyEngine),
                verified: None,
                enablement: None,
            });
        }
        PolicyEngineKind::V1 => {}
        kind => return Err(PolicyEngineBuildError::UnsupportedEngineKind { kind }),
    }
    let namespace = derive_profile_name_from_owner_key(profile)
        .ok_or_else(|| PolicyEngineBuildError::Configuration("invalid owner-key service".into()))?;
    let directory = policy_dir_override.map_or_else(
        || default_policy_dir().map_err(|e| PolicyEngineBuildError::Configuration(e.to_string())),
        |path| Ok(path.to_path_buf()),
    )?;
    let path = directory.join(format!("{namespace}.toml"));
    let window_path = default_policy_window_state_path_for(store_name);
    let window_state = PolicyStateStore::new();
    PersistedWindowStore::at_path(window_path.clone())
        .load_into(namespace, profile, &window_state)
        .map_err(|source| PolicyEngineBuildError::WindowState {
            store_name: store_name.to_owned(),
            source,
        })?;
    if let Some(parent) = window_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            PolicyEngineBuildError::Policy(PolicyError::StateLockIo { kind: e.kind() })
        })?;
    }
    let verified = load_verified_policy(
        &PolicyLoad {
            path: &path,
            profile,
            profile_name: namespace,
            owner_pubkey: &owner_key,
            owner_source,
            window_path: &window_path,
        },
        window_state,
        PinMode::Advance,
    )
    .map_err(PolicyEngineBuildError::Policy)?;
    let enablement = if cfg!(feature = "mainnet-write")
        && profile.chain_id.is_mainnet()
        && verified.mainnet().is_some()
    {
        selection
            .map(|selection| {
                verify_enablement(
                    &verified,
                    selection.name,
                    selection.source,
                    profile,
                    selection.profile_dir,
                    &read_enablement_nonce,
                )
            })
            .transpose()
            .map_err(PolicyEngineBuildError::Enablement)?
    } else {
        None
    };
    Ok(BuiltPolicyEngine {
        engine: verified.engine(),
        verified: Some(verified),
        enablement,
    })
}
