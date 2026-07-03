//! SEP-43 `ModuleInterface` trait and `StellarAgentModule` dispatch impl.
//!
//! Declares the five async SEP-43 method signatures as a Rust trait
//! [`ModuleAdapter`] and provides [`StellarAgentModule`] as the concrete
//! implementation that dispatches each call to the corresponding per-method
//! submodule.
//!
//! Reference: Stellar-Wallets-Kit `types/mod.ts` — canonical `ModuleInterface`
//! TypeScript definition.

pub mod get_address;
pub mod get_network;
pub mod sign_auth_entry;
pub mod sign_message;
pub mod sign_transaction;

use std::sync::Arc;

use async_trait::async_trait;
use stellar_agent_core::profile::schema::Profile;
use stellar_agent_network::signing::Signer;

use crate::error::Sep43Error;

/// The 5-method SEP-43 `ModuleInterface` as a Rust async trait.
///
/// Mirrors the canonical shape from Stellar-Wallets-Kit `types/mod.ts`.
/// Each method corresponds to one SEP-43 v1.2.1 method.
///
/// The trait is `Send + Sync` so it can be used as a trait object in the
/// MCP server's async dispatch path.
#[async_trait]
pub trait ModuleAdapter: Send + Sync {
    /// Returns the active wallet address.
    ///
    /// Per SEP-43 v1.2.1 `getAddress`. Returns `{ "address": String }`.
    ///
    /// # Errors
    ///
    /// Returns [`Sep43Error`] if the active address cannot be resolved.
    async fn get_address(&self) -> Result<serde_json::Value, Sep43Error>;

    /// Signs a base64-encoded `TransactionEnvelope` XDR.
    ///
    /// Per SEP-43 v1.2.1 `signTransaction`. Returns
    /// `{ "signedTxXdr": String, "signerAddress"?: String }`.
    ///
    /// # Arguments
    ///
    /// - `transaction_xdr` — base64-encoded `TransactionEnvelope`.
    /// - `network_passphrase` — optional; must match profile if provided.
    /// - `address` — optional; validated against the active address if provided.
    ///
    /// # Errors
    ///
    /// Returns [`Sep43Error`] on XDR decode failure, passphrase mismatch, or
    /// signer error.
    async fn sign_transaction(
        &self,
        transaction_xdr: &str,
        network_passphrase: Option<&str>,
        address: Option<&str>,
    ) -> Result<serde_json::Value, Sep43Error>;

    /// Signs a base64-encoded `HashIdPreimage::SorobanAuthorization` preimage.
    ///
    /// Per SEP-43 v1.2.1 `signAuthEntry`. Returns
    /// `{ "signedAuthEntry": String, "signerAddress"?: String }`, where
    /// `signedAuthEntry` is the base64-encoded 64-byte ed25519 signature over
    /// `SHA256(preimage_bytes)`.  The caller assembles the signature into the
    /// final `SorobanAuthorizationEntry`.
    ///
    /// # Arguments
    ///
    /// - `preimage_xdr` — base64-encoded `HashIdPreimage::SorobanAuthorization`
    ///   preimage (not a full `SorobanAuthorizationEntry`).
    /// - `network_passphrase` — optional; must match profile if provided.
    /// - `address` — optional; validated against the active address if provided.
    ///
    /// # Errors
    ///
    /// Returns [`Sep43Error`] on XDR decode failure, wrong preimage variant,
    /// passphrase mismatch, or signer error.
    async fn sign_auth_entry(
        &self,
        preimage_xdr: &str,
        network_passphrase: Option<&str>,
        address: Option<&str>,
    ) -> Result<serde_json::Value, Sep43Error>;

    /// Signs an arbitrary message string.
    ///
    /// Per SEP-43 v1.2.1 `signMessage`. Returns
    /// `{ "signedMessage": String (base64), "signerAddress"?: String }`.
    ///
    /// # Arguments
    ///
    /// - `message` — the UTF-8 string to sign. Signed using the SEP-53 scheme:
    ///   `SHA256("Stellar Signed Message:\n" || message)`.
    /// - `network_passphrase` — optional per SEP-43 v1.2.1; if provided, must
    ///   match the active profile's passphrase (validation gate only — the
    ///   passphrase is not mixed into the signed bytes; message signing is
    ///   network-independent).
    /// - `address` — optional; validated against the active address if provided.
    ///
    /// # Errors
    ///
    /// Returns [`Sep43Error`] if the message is empty, the passphrase mismatches,
    /// or the signer fails.
    async fn sign_message(
        &self,
        message: &str,
        network_passphrase: Option<&str>,
        address: Option<&str>,
    ) -> Result<serde_json::Value, Sep43Error>;

    /// Returns the active network name and passphrase.
    ///
    /// Per SEP-43 v1.2.1 `getNetwork`. Returns
    /// `{ "network": String, "networkPassphrase": String }`.
    ///
    /// # Errors
    ///
    /// Returns [`Sep43Error`] if the profile's network configuration is
    /// invalid (should never occur in practice given profile validation at
    /// load time).
    async fn get_network(&self) -> Result<serde_json::Value, Sep43Error>;
}

/// Concrete SEP-43 `ModuleInterface` implementation for the Stellar agent wallet.
///
/// Holds an `Arc<Profile>` (the active wallet profile, which carries the
/// `network_passphrase`, `chain_id`, and `mcp_signer_default` fields) and
/// a boxed `Signer` for the active signing key.
///
/// # Construction
///
/// Use [`StellarAgentModule::new`].
///
/// # Dispatch
///
/// Each of the five [`ModuleAdapter`] methods delegates to the corresponding
/// submodule (`module::get_address`, `module::sign_transaction`, etc.).
pub struct StellarAgentModule {
    pub(crate) profile: Arc<Profile>,
    pub(crate) signer: Arc<dyn Signer + Send + Sync>,
}

impl StellarAgentModule {
    /// Constructs a `StellarAgentModule` from an active profile and signer.
    ///
    /// # Arguments
    ///
    /// - `profile` — the active wallet profile.
    /// - `signer` — the signing key; must implement [`Signer`] and be `Send + Sync`.
    ///
    /// # Panics
    ///
    /// Never panics.
    pub fn new(profile: Arc<Profile>, signer: Arc<dyn Signer + Send + Sync>) -> Self {
        Self { profile, signer }
    }
}

#[async_trait]
impl ModuleAdapter for StellarAgentModule {
    async fn get_address(&self) -> Result<serde_json::Value, Sep43Error> {
        get_address::dispatch(&self.profile)
    }

    async fn sign_transaction(
        &self,
        transaction_xdr: &str,
        network_passphrase: Option<&str>,
        address: Option<&str>,
    ) -> Result<serde_json::Value, Sep43Error> {
        sign_transaction::dispatch(
            &self.profile,
            self.signer.as_ref(),
            transaction_xdr,
            network_passphrase,
            address,
        )
        .await
    }

    async fn sign_auth_entry(
        &self,
        preimage_xdr: &str,
        network_passphrase: Option<&str>,
        address: Option<&str>,
    ) -> Result<serde_json::Value, Sep43Error> {
        sign_auth_entry::dispatch(
            &self.profile,
            self.signer.as_ref(),
            preimage_xdr,
            network_passphrase,
            address,
        )
        .await
    }

    async fn sign_message(
        &self,
        message: &str,
        network_passphrase: Option<&str>,
        address: Option<&str>,
    ) -> Result<serde_json::Value, Sep43Error> {
        sign_message::dispatch(
            &self.profile,
            self.signer.as_ref(),
            message,
            network_passphrase,
            address,
        )
        .await
    }

    async fn get_network(&self) -> Result<serde_json::Value, Sep43Error> {
        get_network::dispatch(&self.profile)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use std::sync::Arc;

    use stellar_agent_core::profile::schema::Profile;
    use stellar_agent_network::signing::SoftwareSigningKey;

    use super::*;

    fn test_module() -> StellarAgentModule {
        // Account is empty so that get_address returns MissingAddress.
        let profile =
            Arc::new(Profile::builder_testnet("svc", "", "nonce-svc", "nonce-acct").build());
        let key = Arc::new(SoftwareSigningKey::new_from_bytes([1u8; 32]));
        StellarAgentModule::new(profile, key)
    }

    #[tokio::test]
    async fn get_network_returns_testnet() {
        let module = test_module();
        let result = module.get_network().await.unwrap();
        let passphrase = result["networkPassphrase"].as_str().unwrap();
        assert!(
            passphrase.contains("Test SDF"),
            "expected testnet passphrase, got: {passphrase}"
        );
    }

    #[tokio::test]
    async fn get_address_with_empty_account_returns_missing_address_error() {
        // test_module() builds a profile with an empty account, so
        // resolve_active_address returns MissingAddress before strkey parsing.
        let module = test_module();
        let err = module.get_address().await.unwrap_err();
        assert!(
            matches!(err, Sep43Error::MissingAddress),
            "empty account must return MissingAddress, got: {err:?}"
        );
        assert_eq!(err.sep43_code(), -3);
    }

    #[tokio::test]
    async fn sign_transaction_invalid_xdr_returns_error() {
        let module = test_module();
        let result = module.sign_transaction("not-valid-xdr", None, None).await;
        assert!(
            matches!(result, Err(Sep43Error::InvalidXdr { .. })),
            "got: {result:?}"
        );
    }

    #[tokio::test]
    async fn sign_auth_entry_invalid_xdr_returns_error() {
        let module = test_module();
        let result = module.sign_auth_entry("not-valid-xdr", None, None).await;
        assert!(
            matches!(result, Err(Sep43Error::InvalidXdr { .. })),
            "got: {result:?}"
        );
    }

    #[tokio::test]
    async fn sign_message_empty_returns_error() {
        let module = test_module();
        let result = module.sign_message("", None, None).await;
        assert!(
            matches!(result, Err(Sep43Error::InvalidMessage { .. })),
            "got: {result:?}"
        );
    }

    #[tokio::test]
    async fn sign_message_nonempty_returns_signed_message() {
        use base64::Engine as _;

        let module = test_module();
        let result = module
            .sign_message("hello sep43", None, None)
            .await
            .unwrap();
        let b64_sig = result["signedMessage"].as_str().unwrap();
        // Base64-decode the signature; must be exactly 64 bytes.
        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(b64_sig)
            .expect("signedMessage must be valid base64");
        assert_eq!(sig_bytes.len(), 64, "signedMessage must decode to 64 bytes");
        let signer_addr = result["signerAddress"].as_str().unwrap();
        assert!(signer_addr.starts_with('G'), "signer addr: {signer_addr}");
    }
}
