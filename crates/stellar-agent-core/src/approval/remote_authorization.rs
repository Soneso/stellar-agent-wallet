//! Current remote-approval authorization, read from disk at every check.
//!
//! An operator credential may consent over the remote-approval listener only
//! while two independent records both admit it: the profile's
//! `[remote_approval] allowed_credentials` list names its ID, and the
//! operator-credential store holds its enrolled record. Either record can be
//! edited while a listener runs or while an approval waits for its commit,
//! so neither a listener nor a commit keeps a copy of them.
//! [`RemoteApprovalAuthority`] names where the two records live, and each
//! [`RemoteApprovalAuthority::require_credential`] call reads both again.
//!
//! # Fail closed
//!
//! A profile that is missing, unreadable or malformed, a `[remote_approval]`
//! block that is absent or disabled, a chain or relying-party ID that differs
//! from the one the caller serves, and an unreadable credential store each
//! refuse with `approval.remote_authorization_unavailable`. An ID absent
//! from the list or from the store refuses with
//! `approval.operator_credential_revoked`. An empty list admits nobody. No
//! failure ever falls back to an earlier successful read.
//!
//! # What a check establishes
//!
//! A successful check establishes that the credential was authorized when
//! the two files were read. Editing either file afterwards takes effect at
//! the next check: the remote listener checks at every login, every
//! authenticated request and every decision, and the mainnet commit checks
//! again for every approval a remote credential gave. A check is not a
//! transaction with the submission that follows it.

use std::path::{Path, PathBuf};

use crate::error::{ApprovalFailure, WalletError};
use crate::profile::caip2::Caip2;
use crate::profile::name::validate_path_component_ascii_safe;

use super::operator_credentials::{
    OperatorApprovalCredentialStore, default_operator_approval_credentials_path,
};

/// Where a profile's remote-approval authorization lives on disk.
///
/// Holds the validated profile name, the profile directory pinned when the
/// authority was constructed, and the operator-credential store path. It
/// holds no allowlist: every check reads the current one.
#[derive(Debug, Clone)]
pub struct RemoteApprovalAuthority {
    profile_name: String,
    profile_dir: PathBuf,
    credentials_path: PathBuf,
}

/// The remote-approval authorization a profile grants at one read.
///
/// Produced only by [`RemoteApprovalAuthority::load_current`] and
/// [`RemoteApprovalAuthority::require_credential`]; it records what the two
/// files said when they were read and is never refreshed.
#[derive(Clone)]
pub struct RemoteApprovalAuthorization {
    chain: Caip2,
    rp_id: String,
    allowed_credentials: Vec<String>,
}

impl std::fmt::Debug for RemoteApprovalAuthorization {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteApprovalAuthorization")
            .field("chain", &self.chain.caip2_str())
            .field("rp_id", &self.rp_id)
            .field("allowed_credentials", &self.allowed_credentials.len())
            .finish()
    }
}

impl RemoteApprovalAuthorization {
    /// The chain of the profile that granted this authorization.
    #[must_use]
    pub fn chain(&self) -> Caip2 {
        self.chain
    }

    /// The relying-party ID the profile's `[remote_approval]` block names.
    #[must_use]
    pub fn rp_id(&self) -> &str {
        &self.rp_id
    }

    /// The profile's `allowed_credentials` list as read.
    #[must_use]
    pub fn allowed_credentials(&self) -> &[String] {
        &self.allowed_credentials
    }

    /// Whether the list as read names `credential_id_b64url`.
    #[must_use]
    pub fn allows(&self, credential_id_b64url: &str) -> bool {
        !credential_id_b64url.is_empty()
            && self
                .allowed_credentials
                .iter()
                .any(|allowed| allowed == credential_id_b64url)
    }
}

fn unavailable(detail: impl Into<String>) -> WalletError {
    WalletError::Approval(ApprovalFailure::RemoteAuthorizationUnavailable {
        detail: detail.into(),
    })
}

fn revoked(detail: &str) -> WalletError {
    WalletError::Approval(ApprovalFailure::OperatorCredentialRevoked {
        detail: detail.to_owned(),
    })
}

impl RemoteApprovalAuthority {
    /// The authority for `profile_name` at the wallet's own locations: the
    /// default profile directory and the profile's default
    /// operator-credential store.
    ///
    /// # Errors
    ///
    /// `approval.remote_authorization_unavailable` when the name is not a
    /// valid profile name or either location cannot be resolved.
    pub fn for_profile(profile_name: &str) -> Result<Self, WalletError> {
        let profile_dir = crate::profile::schema::default_profile_dir()
            .map_err(|e| unavailable(format!("the profile directory is unavailable: {e}")))?;
        let credentials_path =
            default_operator_approval_credentials_path(profile_name).map_err(|e| {
                unavailable(format!("the operator-credential store is unavailable: {e}"))
            })?;
        Self::from_paths(profile_name.to_owned(), profile_dir, credentials_path)
    }

    /// The authority for `profile_name` read from `profile_dir` and the
    /// operator-credential store at `credentials_path`.
    ///
    /// # Errors
    ///
    /// `approval.remote_authorization_unavailable` when `profile_name` is not
    /// a valid profile name.
    pub fn from_paths(
        profile_name: String,
        profile_dir: PathBuf,
        credentials_path: PathBuf,
    ) -> Result<Self, WalletError> {
        validate_path_component_ascii_safe(&profile_name)
            .map_err(|reason| unavailable(format!("invalid profile name: {reason}")))?;
        Ok(Self {
            profile_name,
            profile_dir,
            credentials_path,
        })
    }

    /// The validated profile name.
    #[must_use]
    pub fn profile_name(&self) -> &str {
        &self.profile_name
    }

    /// The operator-credential store this authority reads.
    #[must_use]
    pub fn credentials_path(&self) -> &Path {
        &self.credentials_path
    }

    /// Reads the profile now and returns its remote-approval authorization.
    ///
    /// Reads the stored profile file without environment overlays, so no
    /// process environment can widen the list.
    ///
    /// # Errors
    ///
    /// `approval.remote_authorization_unavailable` when the profile is
    /// missing, unreadable or malformed, or its `[remote_approval]` block is
    /// absent or disabled.
    pub fn load_current(&self) -> Result<RemoteApprovalAuthorization, WalletError> {
        let profile = crate::profile::loader::load_from_dir_without_overlays(
            &self.profile_name,
            &self.profile_dir,
            None,
        )
        .map_err(|e| unavailable(format!("the profile cannot be read: {e}")))?;
        let Some(remote) = profile.remote_approval else {
            return Err(unavailable("the profile has no [remote_approval] block"));
        };
        if !remote.enabled {
            return Err(unavailable("remote approval is disabled in the profile"));
        }
        Ok(RemoteApprovalAuthorization {
            chain: profile.chain_id,
            rp_id: remote.rp_id,
            allowed_credentials: remote.allowed_credentials,
        })
    }

    /// Reads both records now and returns the authorization only when it
    /// admits `credential_id_b64url` for `expected_chain` and, when given,
    /// the listener's relying-party ID `expected_rp_id`.
    ///
    /// # Errors
    ///
    /// - `approval.remote_authorization_unavailable` for any
    ///   [`Self::load_current`] refusal, a profile chain other than
    ///   `expected_chain`, a relying-party ID other than `expected_rp_id`, or
    ///   an operator-credential store that cannot be read.
    /// - `approval.operator_credential_revoked` when the current list does
    ///   not name `credential_id_b64url` or the store holds no record for it.
    pub fn require_credential(
        &self,
        credential_id_b64url: &str,
        expected_chain: Caip2,
        expected_rp_id: Option<&str>,
    ) -> Result<RemoteApprovalAuthorization, WalletError> {
        let authorization = self.load_current()?;
        if authorization.chain != expected_chain {
            return Err(unavailable(
                "the profile's chain differs from the approval's chain",
            ));
        }
        if let Some(expected) = expected_rp_id
            && authorization.rp_id != expected
        {
            return Err(unavailable(
                "the profile's remote-approval rp_id differs from the listener's",
            ));
        }
        if !authorization.allows(credential_id_b64url) {
            return Err(revoked(
                "the operator credential is not in the profile's allowed_credentials list",
            ));
        }
        let enrolled = OperatorApprovalCredentialStore::new(self.credentials_path.clone())
            .find_by_credential_id(credential_id_b64url)
            .map_err(|e| {
                unavailable(format!("the operator-credential store cannot be read: {e}"))
            })?;
        if enrolled.is_none() {
            return Err(revoked("the operator credential is not enrolled"));
        }
        Ok(authorization)
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use super::*;
    use crate::approval::operator_credentials::OperatorApprovalCredential;
    use crate::profile::schema::{Profile, RemoteApprovalConfig};
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    const RP_ID: &str = "wallet.test.internal";

    fn credential_id(seed: u8) -> String {
        URL_SAFE_NO_PAD.encode([seed; 16])
    }

    struct Fixture {
        dir: tempfile::TempDir,
        authority: RemoteApprovalAuthority,
    }

    impl Fixture {
        fn profile_dir(&self) -> PathBuf {
            self.dir.path().join("profiles")
        }

        fn credentials_path(&self) -> PathBuf {
            self.dir.path().join("credentials").join("remote.toml")
        }

        fn write_profile(&self, edit: impl FnOnce(&mut Profile)) {
            let mut profile =
                Profile::builder_testnet("svc", "default", "nonce", "default").build();
            edit(&mut profile);
            crate::profile::loader::save_to_dir("remote", &profile, &self.profile_dir()).unwrap();
        }

        fn allow(&self, ids: &[String]) {
            let ids = ids.to_vec();
            self.write_profile(move |profile| {
                profile.remote_approval = Some(remote_config(true, RP_ID, ids));
            });
        }

        fn enroll(&self, seed: u8) {
            let mut key = vec![0x04u8; 65];
            key[1] = seed;
            OperatorApprovalCredentialStore::new(self.credentials_path())
                .enroll(OperatorApprovalCredential {
                    credential_id_b64url: credential_id(seed),
                    public_key_sec1_b64: URL_SAFE_NO_PAD.encode(key),
                    rp_id: RP_ID.to_owned(),
                    label: "device".to_owned(),
                    registered_at_unix_ms: 1,
                    sign_count: None,
                })
                .unwrap();
        }
    }

    fn remote_config(enabled: bool, rp_id: &str, ids: Vec<String>) -> RemoteApprovalConfig {
        let mut config: RemoteApprovalConfig = toml::from_str(&format!(
            "enabled = {enabled}\nbind = \"127.0.0.1:8443\"\nrp_id = \"{rp_id}\"\n"
        ))
        .unwrap();
        config.allowed_credentials = ids;
        config
    }

    fn fixture() -> Fixture {
        let dir = tempfile::TempDir::new().unwrap();
        let authority = RemoteApprovalAuthority::from_paths(
            "remote".to_owned(),
            dir.path().join("profiles"),
            dir.path().join("credentials").join("remote.toml"),
        )
        .unwrap();
        Fixture { dir, authority }
    }

    fn code(result: Result<RemoteApprovalAuthorization, WalletError>) -> &'static str {
        result.unwrap_err().code()
    }

    #[test]
    fn current_list_and_enrollment_admit_a_credential() {
        let f = fixture();
        f.allow(&[credential_id(1)]);
        f.enroll(1);
        let authorization = f
            .authority
            .require_credential(&credential_id(1), Caip2::Testnet, Some(RP_ID))
            .unwrap();
        assert_eq!(authorization.rp_id(), RP_ID);
        assert!(authorization.allows(&credential_id(1)));
    }

    /// Removing one ID from the list refuses that credential at the next
    /// check and leaves a credential still listed admitted.
    #[test]
    fn unaffected_credential_survives_allowlist_edit() {
        let f = fixture();
        f.allow(&[credential_id(1), credential_id(2)]);
        f.enroll(1);
        f.enroll(2);
        for seed in [1, 2] {
            f.authority
                .require_credential(&credential_id(seed), Caip2::Testnet, Some(RP_ID))
                .unwrap();
        }
        f.allow(&[credential_id(2)]);
        assert_eq!(
            code(
                f.authority
                    .require_credential(&credential_id(1), Caip2::Testnet, Some(RP_ID))
            ),
            "approval.operator_credential_revoked"
        );
        f.authority
            .require_credential(&credential_id(2), Caip2::Testnet, Some(RP_ID))
            .unwrap();
    }

    /// An allowlisted ID whose enrollment was removed refuses.
    #[test]
    fn removed_enrollment_refuses_an_allowlisted_credential() {
        let f = fixture();
        f.allow(&[credential_id(1)]);
        f.enroll(1);
        assert!(
            OperatorApprovalCredentialStore::new(f.credentials_path())
                .remove(&credential_id(1))
                .unwrap()
        );
        assert_eq!(
            code(
                f.authority
                    .require_credential(&credential_id(1), Caip2::Testnet, Some(RP_ID))
            ),
            "approval.operator_credential_revoked"
        );
    }

    /// Every read failure and every configuration change refuses after a
    /// successful read; none returns the earlier authorization.
    #[test]
    fn authorization_read_failure_never_uses_startup_copy() {
        let id = credential_id(1);
        let check = |f: &Fixture, chain: Caip2| {
            code(f.authority.require_credential(&id, chain, Some(RP_ID)))
        };

        // Missing profile.
        let f = fixture();
        f.enroll(1);
        assert_eq!(
            check(&f, Caip2::Testnet),
            "approval.remote_authorization_unavailable"
        );

        for change in [
            "malformed",
            "unreadable",
            "disabled",
            "absent",
            "rp_id",
            "chain",
            "empty",
            "store",
        ] {
            let f = fixture();
            f.allow(std::slice::from_ref(&id));
            f.enroll(1);
            f.authority
                .require_credential(&id, Caip2::Testnet, Some(RP_ID))
                .unwrap();
            let profile_path = f.profile_dir().join("remote.toml");
            let expected = match change {
                "malformed" => {
                    std::fs::write(&profile_path, "version = 1\n[remote_approval\n").unwrap();
                    "approval.remote_authorization_unavailable"
                }
                "unreadable" => {
                    std::fs::remove_file(&profile_path).unwrap();
                    std::fs::create_dir(&profile_path).unwrap();
                    "approval.remote_authorization_unavailable"
                }
                "disabled" => {
                    f.write_profile(|p| {
                        p.remote_approval = Some(remote_config(false, RP_ID, vec![id.clone()]));
                    });
                    "approval.remote_authorization_unavailable"
                }
                "absent" => {
                    f.write_profile(|p| p.remote_approval = None);
                    "approval.remote_authorization_unavailable"
                }
                "rp_id" => {
                    f.write_profile(|p| {
                        p.remote_approval =
                            Some(remote_config(true, "other.test.internal", vec![id.clone()]));
                    });
                    "approval.remote_authorization_unavailable"
                }
                "chain" => {
                    assert_eq!(
                        check(&f, Caip2::Mainnet),
                        "approval.remote_authorization_unavailable"
                    );
                    continue;
                }
                "empty" => {
                    f.allow(&[]);
                    "approval.operator_credential_revoked"
                }
                "store" => {
                    std::fs::write(f.credentials_path(), "credentials = 7\n").unwrap();
                    "approval.remote_authorization_unavailable"
                }
                _ => unreachable!(),
            };
            assert_eq!(check(&f, Caip2::Testnet), expected, "{change}");
        }
    }

    #[test]
    fn invalid_profile_name_is_refused_at_construction() {
        let err = RemoteApprovalAuthority::from_paths(
            "../escape".to_owned(),
            PathBuf::from("profiles"),
            PathBuf::from("credentials.toml"),
        )
        .unwrap_err();
        assert_eq!(err.code(), "approval.remote_authorization_unavailable");
    }
}
