//! Host-local ownership of profile keyring coordinates.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use crate::audit_log::tip_anchor::{reanchor_count_account, tip_anchor_account};
use crate::error::ValidationError;
use crate::observability::redact_path_in_message;

use super::caip2::Caip2;
use super::loader::{guard_name_for_load, list_profiles_in_dir};
use super::schema::{
    KeyringEntryRef, Profile, ProviderRole, WALLET_KEY_REFERENCE_FIELDS,
    default_audit_log_path_for, default_profile_dir, generation_account, keyring_entry_alias,
};

/// A bounded, path-redacted keyring coordinate carried by a finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Coordinate {
    /// Rendered service part.
    pub service: String,
    /// Rendered account part.
    pub account: String,
}

impl From<&KeyringEntryRef> for Coordinate {
    fn from(entry: &KeyringEntryRef) -> Self {
        Self {
            service: render_part(&entry.service),
            account: render_part(&entry.account),
        }
    }
}

impl fmt::Display for Coordinate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.service, self.account)
    }
}

/// Recovery chosen by canonical ownership of the shared coordinate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SharedRecovery {
    /// The selected profile overrides into another profile's space.
    GiveThisProfileItsOwnEntry,
    /// The sibling claims the selected profile's own entry.
    CorrectTheSiblingFile,
}

/// One failure of profile keyring ownership.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyScopeKind {
    /// An overlay derives a service outside the selected profile's scope.
    OutOfScope {
        /// Profile reference field.
        field: &'static str,
        /// Rendered reference.
        coordinate: Coordinate,
        /// Rendered canonical service.
        expected_service: String,
    },
    /// The owner reader always uses the canonical account.
    OwnerAccountOverride {
        /// Rendered overridden account.
        account: String,
    },
    /// Two roles within the profile share an entry.
    SelfCollision {
        /// First role in enumeration order.
        field: &'static str,
        /// Second role in enumeration order.
        other_field: &'static str,
        /// Rendered reference.
        coordinate: Coordinate,
    },
    /// A sibling names a coordinate the selected profile uses.
    SharedWithSibling {
        /// Selected profile role.
        field: &'static str,
        /// Bounded sibling name.
        sibling: String,
        /// Rendered sibling role.
        sibling_field: String,
        /// Rendered reference.
        coordinate: Coordinate,
        /// Which file needs correction.
        recovery: SharedRecovery,
    },
    /// A sibling cannot be compared and is skipped.
    SiblingUnreadable {
        /// Bounded sibling name; absent for a directory entry without one.
        sibling: Option<String>,
    },
    /// The selected document exists but cannot be read again.
    SelectedDocumentUnreadable,
    /// The profiles directory cannot be listed.
    ProfilesDirUnreadable,
}

impl KeyScopeKind {
    /// Stable snake-case diagnostic kind.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::OutOfScope { .. } => "out_of_scope",
            Self::OwnerAccountOverride { .. } => "owner_account_override",
            Self::SelfCollision { .. } => "self_collision",
            Self::SharedWithSibling { .. } => "shared_with_sibling",
            Self::SiblingUnreadable { .. } => "sibling_unreadable",
            Self::SelectedDocumentUnreadable => "selected_document_unreadable",
            Self::ProfilesDirUnreadable => "profiles_dir_unreadable",
        }
    }
}

/// One key-scope finding of the selected profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyScopeFinding {
    /// Ownership failure, carrying the rendered parts its text names.
    pub kind: KeyScopeKind,
}

impl KeyScopeFinding {
    /// Renders the finding with the selected profile's name.
    #[must_use]
    pub fn message(&self, name: &str) -> String {
        let name = render_part(name);
        match &self.kind {
            KeyScopeKind::OutOfScope {
                field,
                coordinate,
                expected_service,
            } => format!(
                "profile '{name}': {field} names keyring service '{}', which is not this \
                 profile's service '{expected_service}'. Set {field} in the profile file",
                coordinate.service,
            ),
            KeyScopeKind::OwnerAccountOverride { account } => format!(
                "profile '{name}': policy_owner_key_id names account '{account}'; the owner \
                 key is read from account 'default'. Set the account to 'default' in the \
                 profile file"
            ),
            KeyScopeKind::SelfCollision {
                field,
                other_field,
                coordinate,
            } => format!(
                "profile '{name}': {field} and {other_field} name the same keyring entry \
                 '{coordinate}'; give each its own entry in the profile file"
            ),
            KeyScopeKind::SharedWithSibling {
                field,
                sibling,
                sibling_field,
                coordinate,
                recovery,
            } => match recovery {
                SharedRecovery::GiveThisProfileItsOwnEntry => format!(
                    "profile '{name}': {field} names keyring entry '{coordinate}', which \
                     profile '{sibling}' also names as {sibling_field}; give this profile \
                     an entry of its own in its profile file"
                ),
                SharedRecovery::CorrectTheSiblingFile => format!(
                    "profile '{name}': its entry '{coordinate}' ({field}) is also named \
                     by profile '{sibling}' as {sibling_field}; correct that profile's \
                     file, this entry is the default for this profile's name"
                ),
            },
            KeyScopeKind::SiblingUnreadable { sibling } => {
                let subject = sibling.as_ref().map_or_else(
                    || "a profile file".to_owned(),
                    |name| format!("profile '{name}'"),
                );
                format!(
                    "{subject} could not be read for the keyring-entry comparison and is skipped"
                )
            }
            KeyScopeKind::SelectedDocumentUnreadable => format!(
                "profile '{name}': its profile file could not be read again for the \
                 keyring-entry comparison"
            ),
            KeyScopeKind::ProfilesDirUnreadable => {
                "the profiles directory could not be listed for the keyring-entry comparison"
                    .to_owned()
            }
        }
    }
}

pub(crate) fn render_part(s: &str) -> String {
    let rendered = redact_path_in_message(s);
    if rendered.chars().count() <= 128 {
        rendered
    } else {
        let mut bounded: String = rendered.chars().take(125).collect();
        bounded.push_str("...");
        bounded
    }
}

#[derive(Default)]
struct ExplicitFields {
    wallet: BTreeMap<String, KeyringEntryRef>,
    audit_log_path: Option<PathBuf>,
    credentials: Vec<(&'static str, KeyringEntryRef)>,
}

const ROLES: [(ProviderRole, &str); 3] = [
    (ProviderRole::Primary, "providers.primary.credential"),
    (ProviderRole::Secondary, "providers.secondary.credential"),
    (ProviderRole::Oracle, "providers.oracle.credential"),
];

// Positions in `WALLET_KEY_REFERENCE_FIELDS`, which orders the first eight
// enumeration entries; a test pins each name.
const AUDIT_FIELD: usize = 2;
const OWNER_FIELD: usize = 3;
const POOL_FIELD: usize = 6;
const WINDOW_FIELD: usize = 7;

// Labels of the entries the enumeration adds to the eight reference fields.
const POOL_DEFAULT: &str = "pool_master_key_id (default)";
const OWNER_CANONICAL: &str = "policy_owner_key_id (canonical)";
const WINDOW_GENERATION: &str = "policy_window_state_key_id (generation)";
const TIP_ANCHOR: &str = "audit_log_hash_chain_key_id (tip anchor)";
const REANCHOR_COUNTER: &str = "audit_log_hash_chain_key_id (reanchor counter)";
const AUDIT_BINDING: &str = "audit binding (derived)";
const MPP_STATE: &str = "mpp state (derived)";
const MPP_GENERATION: &str = "mpp state (generation)";

fn read_document(path: &Path) -> Result<Option<ExplicitFields>, ()> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(()),
    };
    let text = std::str::from_utf8(&bytes).map_err(|_| ())?;
    let fields: toml::Table = toml::from_str(text).map_err(|_| ())?;
    let mut document = ExplicitFields::default();
    for field in WALLET_KEY_REFERENCE_FIELDS {
        if let Some(value) = fields.get(field) {
            let entry = value.clone().try_into().map_err(|_| ())?;
            document.wallet.insert(field.to_owned(), entry);
        }
    }
    if let Some(value) = fields.get("audit_log_path") {
        document.audit_log_path = Some(value.clone().try_into().map_err(|_| ())?);
    }
    if let Some(providers) = fields.get("providers") {
        let providers = providers.as_table().ok_or(())?;
        for (role, label) in ROLES {
            if let Some(record) = providers.get(role.as_str()) {
                let record = record.as_table().ok_or(())?;
                if let Some(value) = record.get("credential") {
                    let entry = value.clone().try_into().map_err(|_| ())?;
                    document.credentials.push((label, entry));
                }
            }
        }
    }
    Ok(Some(document))
}

fn defaults(name: &str) -> [KeyringEntryRef; 8] {
    [
        KeyringEntryRef::default_signer(name),
        KeyringEntryRef::default_nonce(name),
        KeyringEntryRef::default_audit_key(name),
        KeyringEntryRef::default_owner_key(name),
        KeyringEntryRef::default_attestation_key(name),
        KeyringEntryRef::default_counterparty_key(name),
        KeyringEntryRef::default_pool_master_key(name),
        KeyringEntryRef::default_policy_window_state_key(name),
    ]
}

fn effective_coordinates(
    name: &str,
    document: Option<&ExplicitFields>,
    merged: Option<&Profile>,
) -> Vec<(&'static str, KeyringEntryRef)> {
    let canonical = defaults(name);
    let merged_wallet = merged.map(Profile::wallet_key_references);
    let mut entries = Vec::new();
    for (i, field) in WALLET_KEY_REFERENCE_FIELDS.into_iter().enumerate() {
        let value = merged_wallet
            .as_ref()
            .and_then(|refs| refs[i])
            .or_else(|| document.and_then(|doc| doc.wallet.get(field)));
        let label = if i == POOL_FIELD && value.is_none() {
            POOL_DEFAULT
        } else {
            field
        };
        entries.push((label, value.unwrap_or(&canonical[i]).clone()));
    }
    entries.push((OWNER_CANONICAL, KeyringEntryRef::default_owner_key(name)));
    if let Some(profile) = merged {
        for (role, label) in ROLES {
            if let Some(entry) = profile
                .providers
                .as_ref()
                .and_then(|p| p.record_for(role))
                .and_then(|r| r.credential)
            {
                entries.push((label, entry.clone()));
            }
        }
    } else if let Some(document) = document {
        entries.extend(document.credentials.iter().cloned());
    }
    let window = &entries[WINDOW_FIELD].1;
    entries.push((
        WINDOW_GENERATION,
        KeyringEntryRef {
            service: window.service.clone(),
            account: generation_account(&window.account),
        },
    ));
    let path = merged
        .map(|p| &p.audit_log_path)
        .or_else(|| document.and_then(|d| d.audit_log_path.as_ref()))
        .cloned()
        .unwrap_or_else(|| default_audit_log_path_for(name));
    let audit = entries[AUDIT_FIELD].1.clone();
    entries.push((
        TIP_ANCHOR,
        KeyringEntryRef {
            service: audit.service.clone(),
            account: tip_anchor_account(&audit.account, &path),
        },
    ));
    entries.push((
        REANCHOR_COUNTER,
        KeyringEntryRef {
            service: audit.service,
            account: reanchor_count_account(&audit.account, &path),
        },
    ));
    entries.push((AUDIT_BINDING, KeyringEntryRef::default_audit_binding(name)));
    let mpp = KeyringEntryRef::default_mpp_state_key(name);
    entries.push((MPP_STATE, mpp.clone()));
    entries.push((
        MPP_GENERATION,
        KeyringEntryRef {
            service: mpp.service,
            account: generation_account(&mpp.account),
        },
    ));
    entries
}

fn same_entry(a: &KeyringEntryRef, b: &KeyringEntryRef) -> bool {
    a == b || keyring_entry_alias(a) == keyring_entry_alias(b)
}

fn provider(label: &str) -> bool {
    label.starts_with("providers.")
}

fn owns_entry(profile: &Profile, name: &str, field: &str, entry: &KeyringEntryRef) -> bool {
    let mut canonical_doc = ExplicitFields {
        audit_log_path: Some(profile.audit_log_path.clone()),
        ..ExplicitFields::default()
    };
    for (role, label) in ROLES {
        canonical_doc
            .credentials
            .push((label, KeyringEntryRef::default_rpc_credential(name, role)));
    }
    effective_coordinates(name, Some(&canonical_doc), None)
        .iter()
        .any(|(label, canonical)| {
            let same_field = *label == field
                || (field == WALLET_KEY_REFERENCE_FIELDS[POOL_FIELD] && *label == POOL_DEFAULT);
            same_field && canonical == entry
        })
}

fn finding(kind: KeyScopeKind) -> KeyScopeFinding {
    KeyScopeFinding { kind }
}

/// Computes key-scope findings without reading the keyring or contacting endpoints.
#[must_use]
pub fn key_scope_findings_in_dir(
    profile: &Profile,
    name: &str,
    dir: &Path,
) -> Vec<KeyScopeFinding> {
    let mut findings = Vec::new();
    if guard_name_for_load(name).is_err() {
        return vec![finding(KeyScopeKind::SelectedDocumentUnreadable)];
    }
    let path = dir.join(format!("{name}.toml"));
    let names = match list_profiles_in_dir(dir) {
        Ok(names) => names,
        Err(_) => {
            findings.push(finding(KeyScopeKind::ProfilesDirUnreadable));
            Vec::new()
        }
    };
    let document = match read_document(&path) {
        Ok(document) => document,
        Err(()) => {
            findings.push(finding(KeyScopeKind::SelectedDocumentUnreadable));
            None
        }
    };
    if profile.policy_owner_key_id.account != "default" {
        findings.push(finding(KeyScopeKind::OwnerAccountOverride {
            account: render_part(&profile.policy_owner_key_id.account),
        }));
    }
    if let Some(document) = &document {
        for ((field, entry), canonical) in WALLET_KEY_REFERENCE_FIELDS
            .iter()
            .zip(profile.wallet_key_references())
            .zip(defaults(name))
        {
            if let Some(entry) = entry
                && entry.service != canonical.service
                && document.wallet.get(*field) != Some(entry)
            {
                findings.push(finding(KeyScopeKind::OutOfScope {
                    field,
                    coordinate: entry.into(),
                    expected_service: render_part(&canonical.service),
                }));
            }
        }
    }
    let selected = effective_coordinates(name, document.as_ref(), Some(profile));
    for (i, (field, entry)) in selected.iter().enumerate() {
        for (other_field, other) in selected.iter().skip(i + 1) {
            let owner_pair = *field == WALLET_KEY_REFERENCE_FIELDS[OWNER_FIELD]
                && *other_field == OWNER_CANONICAL;
            if !owner_pair
                && !(provider(field) && provider(other_field))
                && same_entry(entry, other)
            {
                findings.push(finding(KeyScopeKind::SelfCollision {
                    field,
                    other_field,
                    coordinate: entry.into(),
                }));
            }
        }
    }
    // Preserve unreadable directory entries that the profile-name listing skips.
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries {
            if entry.is_err() {
                findings.push(finding(KeyScopeKind::SiblingUnreadable { sibling: None }));
            }
        }
    }
    for sibling in names {
        let sibling_path = dir.join(format!("{sibling}.toml"));
        if sibling == name
            || guard_name_for_load(&sibling).is_err()
            || same_file::is_same_file(&path, &sibling_path).unwrap_or(false)
        {
            continue;
        }
        let sibling_doc = match read_document(&sibling_path) {
            Ok(Some(document)) => document,
            _ => {
                findings.push(finding(KeyScopeKind::SiblingUnreadable {
                    sibling: Some(render_part(&sibling)),
                }));
                continue;
            }
        };
        let others = effective_coordinates(&sibling, Some(&sibling_doc), None);
        // One finding per coordinate and sibling: an explicit owner reference
        // equal to the canonical owner entry is one entry, listed twice.
        let mut reported: Vec<&KeyringEntryRef> = Vec::new();
        for (field, entry) in &selected {
            for (sibling_field, other) in &others {
                if !(provider(field) && provider(sibling_field))
                    && same_entry(entry, other)
                    && !reported.contains(&entry)
                {
                    reported.push(entry);
                    let recovery = if owns_entry(profile, name, field, entry) {
                        SharedRecovery::CorrectTheSiblingFile
                    } else {
                        SharedRecovery::GiveThisProfileItsOwnEntry
                    };
                    findings.push(finding(KeyScopeKind::SharedWithSibling {
                        field,
                        sibling: render_part(&sibling),
                        sibling_field: render_part(sibling_field),
                        coordinate: entry.into(),
                        recovery,
                    }));
                }
            }
        }
    }
    findings
}

/// Computes findings in the current data root's profiles directory.
#[must_use]
pub fn key_scope_findings(profile: &Profile, name: &str) -> Vec<KeyScopeFinding> {
    match default_profile_dir() {
        Ok(dir) => key_scope_findings_in_dir(profile, name, &dir),
        Err(_) => vec![finding(KeyScopeKind::ProfilesDirUnreadable)],
    }
}

/// The refusal of a mainnet profile whose keyring references conflict with
/// their host-local scope.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{detail}")]
pub struct KeyScopeConflict {
    /// Selected profile name.
    pub profile: String,
    /// Snake-case kind of the refusing finding.
    pub kind: &'static str,
    /// Bounded, path-redacted finding text.
    pub detail: String,
}

impl From<KeyScopeConflict> for ValidationError {
    fn from(conflict: KeyScopeConflict) -> Self {
        Self::ProfileKeyScopeConflict {
            profile: conflict.profile,
            kind: conflict.kind,
            detail: conflict.detail,
        }
    }
}

/// Refuses mainnet conflicts and warns about testnet conflicts.
///
/// Unreadable siblings warn on both chains and are skipped. On mainnet any
/// other finding refuses: the first is returned, and each later one is logged
/// at `warn` on target `profile.key_scope`, so one run shows every conflict.
///
/// # Errors
///
/// Returns the first mainnet finding other than an unreadable sibling; it
/// converts into [`ValidationError::ProfileKeyScopeConflict`].
pub fn enforce_key_scope(profile: &Profile, name: &str) -> Result<(), KeyScopeConflict> {
    let findings = key_scope_findings(profile, name);
    let mut refusal = None;
    for finding in findings {
        let detail = finding.message(name);
        let refuses = profile.chain_id == Caip2::Mainnet
            && !matches!(finding.kind, KeyScopeKind::SiblingUnreadable { .. });
        if refuses && refusal.is_none() {
            refusal = Some(KeyScopeConflict {
                profile: name.to_owned(),
                kind: finding.kind.as_str(),
                detail,
            });
        } else {
            tracing::warn!(target: "profile.key_scope", "{detail}");
        }
    }
    refusal.map_or(Ok(()), Err)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test assertions"
    )]
    use super::*;
    use crate::envelope::Envelope;
    use crate::error::WalletError;
    use crate::profile::loader::{load_from_dir, save_to_dir};
    use stellar_agent_test_support::env_guard::StellarAgentHomeGuard;
    use stellar_agent_test_support::log_capture::CaptureWriter;

    struct Fixture {
        _guard: StellarAgentHomeGuard,
        home: tempfile::TempDir,
        dir: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let home = tempfile::tempdir().unwrap();
            let guard = StellarAgentHomeGuard::new(home.path());
            let dir = default_profile_dir().unwrap();
            std::fs::create_dir_all(&dir).unwrap();
            Self {
                _guard: guard,
                home,
                dir,
            }
        }

        fn save(&self, name: &str, profile: &Profile) {
            save_to_dir(name, profile, &self.dir).unwrap();
        }

        fn findings(&self, name: &str, profile: &Profile) -> Vec<KeyScopeFinding> {
            key_scope_findings_in_dir(profile, name, &self.dir)
        }
    }

    fn profile(name: &str) -> Profile {
        let signer = KeyringEntryRef::default_signer(name);
        let nonce = KeyringEntryRef::default_nonce(name);
        Profile::builder_mainnet_named(
            name,
            "https://rpc.example",
            &signer.service,
            &signer.account,
            &nonce.service,
            &nonce.account,
        )
        .build()
    }

    fn shared<'a>(findings: &'a [KeyScopeFinding], label: &str) -> &'a KeyScopeKind {
        &findings
            .iter()
            .find(|f| {
                matches!(
                    &f.kind, KeyScopeKind::SharedWithSibling { field, .. } if *field == label
                )
            })
            .unwrap_or_else(|| panic!("missing shared {label}: {findings:?}"))
            .kind
    }

    /// Runs the chain policy under a scoped capture and returns its result and
    /// the captured text. The subscriber accepts every level, so its interest
    /// rebuild can only enable callsites; the callers match on target and text.
    fn capture_enforce(profile: &Profile, name: &str) -> (Result<(), KeyScopeConflict>, String) {
        let capture = CaptureWriter::new();
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_max_level(tracing::Level::TRACE)
            .with_writer(capture.clone())
            .finish();
        let _subscriber = tracing::subscriber::set_default(subscriber);
        tracing::callsite::rebuild_interest_cache();
        let result = enforce_key_scope(profile, name);
        (result, capture.captured_str())
    }

    fn warn_output(profile: &Profile, name: &str) -> String {
        let (result, output) = capture_enforce(profile, name);
        result.unwrap();
        output
    }

    #[test]
    #[serial_test::serial]
    fn sibling_sharing_refuses_mainnet_and_warns_testnet() {
        let f = Fixture::new();
        let mut a = profile("alice");
        let mut b = profile("bob");
        a.attestation_key_id = KeyringEntryRef::new("shared", "entry");
        b.mcp_nonce_key_alias = a.attestation_key_id.clone();
        f.save("alice", &a);
        f.save("bob", &b);
        let error = enforce_key_scope(&a, "alice").unwrap_err();
        assert_eq!(
            ValidationError::from(error.clone()).code(),
            "profile.key_scope_conflict"
        );
        let message = error.to_string();
        for text in [
            "attestation_key_id",
            "shared/entry",
            "bob",
            "mcp_nonce_key_alias",
        ] {
            assert!(message.contains(text), "{message}");
        }
        a.chain_id = Caip2::Testnet;
        let warning = warn_output(&a, "alice");
        assert!(warning.contains("profile.key_scope"));
        assert!(warning.contains(&message));
    }

    #[test]
    #[serial_test::serial]
    fn canonical_ownership_selects_recovery_from_both_documents() {
        let f = Fixture::new();
        let a = profile("alice");
        let mut b = profile("bob");
        b.attestation_key_id = a.attestation_key_id.clone();
        f.save("alice", &a);
        f.save("bob", &b);
        for (name, recovery) in [
            ("alice", SharedRecovery::CorrectTheSiblingFile),
            ("bob", SharedRecovery::GiveThisProfileItsOwnEntry),
        ] {
            let loaded = load_from_dir(name, &f.dir, None).unwrap();
            let findings = f.findings(name, &loaded);
            assert!(matches!(shared(&findings, "attestation_key_id"),
                KeyScopeKind::SharedWithSibling { recovery: actual, .. } if *actual == recovery));
        }
    }

    #[test]
    #[serial_test::serial]
    fn overlay_scope_is_checked_but_explicit_value_is_exempt() {
        let f = Fixture::new();
        let mut a = profile("alice");
        f.save("alice", &a);
        a.mcp_signer_default.service = "external".to_owned();
        assert!(matches!(
            f.findings("alice", &a)[0].kind,
            KeyScopeKind::OutOfScope { .. }
        ));
        a.chain_id = Caip2::Testnet;
        assert!(warn_output(&a, "alice").contains("not this profile's service"));
        f.save("alice", &a);
        assert!(f.findings("alice", &a).is_empty());
    }

    #[test]
    #[serial_test::serial]
    fn absent_selected_document_keeps_self_and_sibling_checks() {
        let f = Fixture::new();
        let mut a = profile("alice");
        let mut b = profile("bob");
        a.mcp_signer_default = KeyringEntryRef::new("external", "key");
        a.mcp_nonce_key_alias = a.mcp_signer_default.clone();
        b.attestation_key_id = a.mcp_signer_default.clone();
        f.save("bob", &b);
        let findings = f.findings("alice", &a);
        assert!(
            !findings
                .iter()
                .any(|f| matches!(f.kind, KeyScopeKind::OutOfScope { .. }))
        );
        assert!(matches!(
            findings[0].kind,
            KeyScopeKind::SelfCollision { .. }
        ));
        shared(&findings, "mcp_signer_default");
    }

    #[test]
    #[serial_test::serial]
    fn self_collision_refuses() {
        let f = Fixture::new();
        let mut a = profile("alice");
        a.attestation_key_id = a.mcp_nonce_key_alias.clone();
        f.save("alice", &a);
        let err = enforce_key_scope(&a, "alice").unwrap_err();
        assert_eq!(err.kind, "self_collision");
    }

    #[test]
    #[serial_test::serial]
    fn owner_account_override_refuses_and_canonical_entry_stays_reserved() {
        let f = Fixture::new();
        let mut a = profile("alice");
        let mut b = profile("bob");
        a.policy_owner_key_id.account = "override".to_owned();
        b.attestation_key_id = KeyringEntryRef::default_owner_key("alice");
        f.save("alice", &a);
        f.save("bob", &b);
        let err = enforce_key_scope(&a, "alice").unwrap_err();
        assert_eq!(err.kind, "owner_account_override");
        shared(&f.findings("alice", &a), OWNER_CANONICAL);
    }

    #[test]
    #[serial_test::serial]
    fn unset_pool_default_collides_from_both_sides() {
        let f = Fixture::new();
        let a = profile("alice");
        let mut b = profile("bob");
        b.attestation_key_id = KeyringEntryRef::default_pool_master_key("alice");
        f.save("alice", &a);
        f.save("bob", &b);
        for (name, label) in [("alice", POOL_DEFAULT), ("bob", "attestation_key_id")] {
            let loaded = load_from_dir(name, &f.dir, None).unwrap();
            shared(&f.findings(name, &loaded), label);
        }
    }

    #[test]
    #[serial_test::serial]
    fn window_generation_collision_is_symmetric_and_override_is_not_owned() {
        let f = Fixture::new();
        let mut a = profile("alice");
        let mut b = profile("bob");
        a.policy_window_state_key_id = KeyringEntryRef::new("shared", "x-generation");
        b.policy_window_state_key_id = KeyringEntryRef::new("shared", "x");
        f.save("alice", &a);
        f.save("bob", &b);
        for (name, label) in [
            ("alice", WALLET_KEY_REFERENCE_FIELDS[WINDOW_FIELD]),
            ("bob", WINDOW_GENERATION),
        ] {
            let loaded = load_from_dir(name, &f.dir, None).unwrap();
            let findings = f.findings(name, &loaded);
            assert!(matches!(
                shared(&findings, label),
                KeyScopeKind::SharedWithSibling {
                    recovery: SharedRecovery::GiveThisProfileItsOwnEntry,
                    ..
                }
            ));
        }
    }

    /// Builds the derived coordinate of `label` for `a` from the schema
    /// constructors and the public anchor helpers, independently of
    /// [`effective_coordinates`].
    fn expected_derived(label: &str, a: &Profile) -> KeyringEntryRef {
        let audit = &a.audit_log_hash_chain_key_id;
        let mpp = KeyringEntryRef::default_mpp_state_key("alice");
        match label {
            TIP_ANCHOR => KeyringEntryRef::new(
                &audit.service,
                tip_anchor_account(&audit.account, &a.audit_log_path),
            ),
            REANCHOR_COUNTER => KeyringEntryRef::new(
                &audit.service,
                reanchor_count_account(&audit.account, &a.audit_log_path),
            ),
            AUDIT_BINDING => KeyringEntryRef::default_audit_binding("alice"),
            MPP_STATE => mpp,
            MPP_GENERATION => KeyringEntryRef::new(&mpp.service, generation_account(&mpp.account)),
            other => panic!("no derived fixture for {other}"),
        }
    }

    /// A sibling names one derived entry of `alice`, whose base coordinates
    /// differ from the sibling's own and whose audit logs both sit at explicit
    /// paths; the collision must be found from both sides.
    fn derived_collision(label: &'static str) {
        let f = Fixture::new();
        let mut a = profile("alice");
        let mut b = profile("bob");
        a.audit_log_path = f.home.path().join("explicit-audit.log");
        b.audit_log_path = f.home.path().join("other-audit.log");
        assert_ne!(a.audit_log_hash_chain_key_id, b.audit_log_hash_chain_key_id);
        assert_ne!(a.policy_window_state_key_id, b.policy_window_state_key_id);
        let expected = expected_derived(label, &a);
        b.attestation_key_id = expected.clone();
        f.save("alice", &a);
        f.save("bob", &b);
        let loaded = load_from_dir("alice", &f.dir, None).unwrap();
        assert_eq!(
            shared(&f.findings("alice", &loaded), label),
            &KeyScopeKind::SharedWithSibling {
                field: label,
                sibling: "bob".to_owned(),
                sibling_field: "attestation_key_id".to_owned(),
                coordinate: Coordinate::from(&expected),
                recovery: SharedRecovery::CorrectTheSiblingFile,
            }
        );
        let loaded = load_from_dir("bob", &f.dir, None).unwrap();
        shared(&f.findings("bob", &loaded), "attestation_key_id");
        assert!(
            effective_coordinates("alice", None, Some(&a))
                .iter()
                .any(|(field, entry)| *field == label && *entry == expected)
        );
    }

    #[test]
    #[serial_test::serial]
    fn explicit_log_tip_anchor_is_owned() {
        derived_collision(TIP_ANCHOR);
    }

    #[test]
    #[serial_test::serial]
    fn reanchor_counter_is_reserved() {
        derived_collision(REANCHOR_COUNTER);
    }

    #[test]
    #[serial_test::serial]
    fn audit_binding_is_reserved() {
        derived_collision(AUDIT_BINDING);
    }

    #[test]
    #[serial_test::serial]
    fn mpp_entries_are_reserved() {
        derived_collision(MPP_STATE);
        derived_collision(MPP_GENERATION);
    }

    #[test]
    #[serial_test::serial]
    fn owner_entry_named_by_a_sibling_is_one_finding() {
        let f = Fixture::new();
        let a = profile("alice");
        let mut b = profile("bob");
        assert_eq!(
            a.policy_owner_key_id,
            KeyringEntryRef::default_owner_key("alice")
        );
        b.attestation_key_id = a.policy_owner_key_id.clone();
        f.save("alice", &a);
        f.save("bob", &b);
        let loaded = load_from_dir("alice", &f.dir, None).unwrap();
        assert_eq!(
            f.findings("alice", &loaded),
            vec![KeyScopeFinding {
                kind: KeyScopeKind::SharedWithSibling {
                    field: "policy_owner_key_id",
                    sibling: "bob".to_owned(),
                    sibling_field: "attestation_key_id".to_owned(),
                    coordinate: Coordinate::from(&a.policy_owner_key_id),
                    recovery: SharedRecovery::CorrectTheSiblingFile,
                },
            }]
        );
    }

    #[test]
    #[serial_test::serial]
    fn mainnet_refuses_the_first_finding_and_warns_the_rest() {
        let f = Fixture::new();
        let mut a = profile("alice");
        a.policy_owner_key_id.account = "override".to_owned();
        a.attestation_key_id = a.mcp_nonce_key_alias.clone();
        f.save("alice", &a);
        let (result, output) = capture_enforce(&a, "alice");
        let refusal = result.unwrap_err();
        assert_eq!(refusal.kind, "owner_account_override");
        assert!(
            refusal.detail.contains("names account 'override'"),
            "{refusal}"
        );
        assert!(output.contains("profile.key_scope"), "{output}");
        assert!(
            output.contains(
                "profile 'alice': mcp_nonce_key_alias and attestation_key_id name the same \
                 keyring entry"
            ),
            "{output}"
        );
        assert!(!output.contains("names account 'override'"), "{output}");
    }

    #[test]
    fn named_field_indices_match_the_reference_fields() {
        for (index, field) in [
            (AUDIT_FIELD, "audit_log_hash_chain_key_id"),
            (OWNER_FIELD, "policy_owner_key_id"),
            (POOL_FIELD, "pool_master_key_id"),
            (WINDOW_FIELD, "policy_window_state_key_id"),
        ] {
            assert_eq!(WALLET_KEY_REFERENCE_FIELDS[index], field);
        }
    }

    #[test]
    #[serial_test::serial]
    fn joined_alias_collision_is_found() {
        let f = Fixture::new();
        let mut a = profile("alice");
        let mut b = profile("bob");
        a.attestation_key_id = KeyringEntryRef::new("service", "ACCOUNT.part");
        b.attestation_key_id = KeyringEntryRef::new("PART.SERVICE", "account");
        f.save("alice", &a);
        f.save("bob", &b);
        shared(&f.findings("alice", &a), "attestation_key_id");
    }

    #[test]
    #[serial_test::serial]
    fn unreadable_sibling_warns_on_both_chains() {
        let f = Fixture::new();
        let mut a = profile("alice");
        f.save("alice", &a);
        std::fs::create_dir(f.dir.join("bob.toml")).unwrap();
        assert_eq!(
            f.findings("alice", &a),
            vec![KeyScopeFinding {
                kind: KeyScopeKind::SiblingUnreadable {
                    sibling: Some("bob".to_owned()),
                },
            }]
        );
        assert!(warn_output(&a, "alice").contains("is skipped"));
        a.chain_id = Caip2::Testnet;
        assert!(warn_output(&a, "alice").contains("is skipped"));
    }

    #[test]
    #[serial_test::serial]
    fn malformed_sibling_reference_is_unreadable_not_a_default() {
        let f = Fixture::new();
        let a = profile("alice");
        f.save("alice", &a);
        std::fs::write(f.dir.join("bob.toml"), "attestation_key_id = 17").unwrap();
        assert!(matches!(
            f.findings("alice", &a)[0].kind,
            KeyScopeKind::SiblingUnreadable { .. }
        ));
    }

    #[test]
    #[serial_test::serial]
    fn invalid_sibling_name_is_skipped() {
        let f = Fixture::new();
        let a = profile("alice");
        f.save("alice", &a);
        std::fs::write(f.dir.join("bad..name.toml"), "invalid text").unwrap();
        assert!(f.findings("alice", &a).is_empty());
    }

    #[test]
    #[serial_test::serial]
    fn selected_file_alias_is_not_a_sibling() {
        let f = Fixture::new();
        let a = profile("alice");
        f.save("alice", &a);
        // Hard links exercise file identity on case-sensitive filesystems too.
        let alias = f.dir.join("ALICE.toml");
        if !alias.exists() {
            std::fs::hard_link(f.dir.join("alice.toml"), &alias).unwrap();
        }
        assert!(f.findings("alice", &a).is_empty());
    }

    #[test]
    #[serial_test::serial]
    fn selected_document_reread_failure_refuses() {
        let f = Fixture::new();
        let a = profile("alice");
        std::fs::write(f.dir.join("alice.toml"), "invalid text").unwrap();
        assert_eq!(
            enforce_key_scope(&a, "alice").unwrap_err().kind,
            "selected_document_unreadable"
        );
    }

    #[test]
    #[serial_test::serial]
    fn unlistable_profiles_directory_refuses() {
        let f = Fixture::new();
        let a = profile("alice");
        std::fs::remove_dir(&f.dir).unwrap();
        std::fs::write(&f.dir, "obstruction").unwrap();
        assert_eq!(
            enforce_key_scope(&a, "alice").unwrap_err().kind,
            "profiles_dir_unreadable"
        );
    }

    fn set_credentials(profile: &mut Profile, entry: &KeyringEntryRef) {
        use super::super::schema::{PrimaryProviderRecord, ProviderRecord, Providers};
        let primary = PrimaryProviderRecord {
            credential: Some(entry.clone()),
            ..PrimaryProviderRecord::default()
        };
        let other = ProviderRecord {
            credential: Some(entry.clone()),
            ..ProviderRecord::default()
        };
        profile.providers = Some(Providers {
            primary: Some(primary),
            secondary: Some(other.clone()),
            oracle: Some(other),
        });
    }

    #[test]
    #[serial_test::serial]
    fn provider_credentials_may_share_with_providers() {
        let f = Fixture::new();
        let mut a = profile("alice");
        let mut b = profile("bob");
        let entry = KeyringEntryRef::new("subscription", "credential");
        set_credentials(&mut a, &entry);
        set_credentials(&mut b, &entry);
        f.save("alice", &a);
        f.save("bob", &b);
        assert!(f.findings("alice", &a).is_empty());
    }

    #[test]
    #[serial_test::serial]
    fn credential_names_wallet_entry_in_both_directions() {
        let f = Fixture::new();
        let mut a = profile("alice");
        let mut b = profile("bob");
        b.attestation_key_id = KeyringEntryRef::new("subscription", "credential");
        set_credentials(&mut a, &b.attestation_key_id);
        f.save("alice", &a);
        f.save("bob", &b);
        shared(&f.findings("alice", &a), "providers.primary.credential");
        shared(&f.findings("bob", &b), "attestation_key_id");
    }

    #[test]
    #[serial_test::serial]
    fn credential_names_derived_entry() {
        let f = Fixture::new();
        let mut a = profile("alice");
        let b = profile("bob");
        set_credentials(&mut a, &KeyringEntryRef::default_audit_binding("bob"));
        f.save("alice", &a);
        f.save("bob", &b);
        shared(&f.findings("alice", &a), "providers.primary.credential");
    }

    #[test]
    #[serial_test::serial]
    fn selected_profile_alone_has_no_findings() {
        let f = Fixture::new();
        let a = profile("alice");
        f.save("alice", &a);
        assert!(f.findings("alice", &a).is_empty());
    }

    #[test]
    #[serial_test::serial]
    fn findings_follow_document_owner_scope_self_then_sibling_order() {
        let f = Fixture::new();
        let mut a = profile("alice");
        a.policy_owner_key_id.account = "override".to_owned();
        a.attestation_key_id = a.mcp_nonce_key_alias.clone();
        f.save("alice", &a);
        a.mcp_signer_default.service = "overlay".to_owned();
        std::fs::write(f.dir.join("bob.toml"), "invalid text").unwrap();
        // Carol names two of alice's coordinates in the reverse of alice's
        // enumeration order; the second is the entry alice's nonce and
        // attestation fields share, reported once.
        let mut c = profile("carol");
        c.attestation_key_id = a.mcp_nonce_key_alias.clone();
        c.counterparty_cache_key_id = a.mcp_signer_default.clone();
        f.save("carol", &c);
        let findings = f.findings("alice", &a);
        let kinds: Vec<_> = findings.iter().map(|f| f.kind.as_str()).collect();
        assert_eq!(
            kinds,
            [
                "owner_account_override",
                "out_of_scope",
                "self_collision",
                "sibling_unreadable",
                "shared_with_sibling",
                "shared_with_sibling"
            ]
        );
        let shared_fields: Vec<_> = findings
            .iter()
            .filter_map(|f| match &f.kind {
                KeyScopeKind::SharedWithSibling { field, .. } => Some(*field),
                _ => None,
            })
            .collect();
        assert_eq!(shared_fields, ["mcp_signer_default", "mcp_nonce_key_alias"]);
        std::fs::write(f.dir.join("alice.toml"), "invalid text").unwrap();
        let findings = f.findings("alice", &a);
        assert_eq!(findings[0].kind, KeyScopeKind::SelectedDocumentUnreadable);
        assert_eq!(findings[1].kind.as_str(), "owner_account_override");
    }

    #[test]
    #[serial_test::serial]
    fn rendered_parts_are_redacted_and_bounded_at_envelopes_and_warns() {
        let f = Fixture::new();
        if std::env::var("KEY_SCOPE_RENDER_CHILD").as_deref() != Ok("1") {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    concat!(
                        "profile::key_scope::tests::",
                        "rendered_parts_are_redacted_and_bounded_at_envelopes_and_warns"
                    ),
                    "--nocapture",
                ])
                .env("KEY_SCOPE_RENDER_CHILD", "1")
                .env("HOME", "/synthetic-home")
                .env_remove("STELLAR_AGENT_LOG")
                .env_remove("RUST_LOG")
                .output()
                .unwrap();
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(output.status.success(), "{stdout}");
            // A renamed test would match nothing and exit 0.
            assert!(stdout.contains("test result: ok. 1 passed;"), "{stdout}");
            return;
        }
        for kind in ["shared", "scope", "owner"] {
            let mut a = profile("alice");
            let mut b = profile("bob");
            let part = format!("/synthetic-home/{}HIDDEN_MARKER", "x".repeat(300));
            f.save("alice", &a);
            match kind {
                "shared" => {
                    a.attestation_key_id = KeyringEntryRef::new(&part, &part);
                    b.attestation_key_id = a.attestation_key_id.clone();
                    f.save("alice", &a);
                }
                "scope" => a.mcp_signer_default.service = part,
                "owner" => a.policy_owner_key_id.account = part,
                _ => unreachable!(),
            }
            f.save("bob", &b);
            let error = WalletError::Validation(enforce_key_scope(&a, "alice").unwrap_err().into());
            let typed = serde_json::to_string(&Envelope::<()>::err(&error)).unwrap();
            let raw =
                serde_json::to_string(&Envelope::<()>::err_raw(error.code(), error.message()))
                    .unwrap();
            a.chain_id = Caip2::Testnet;
            let warning = warn_output(&a, "alice");
            for rendered in [typed, raw, warning] {
                assert!(rendered.contains("<HOME>"), "{rendered}");
                assert!(rendered.contains("..."), "{rendered}");
                assert!(!rendered.contains("synthetic-home"), "{rendered}");
                assert!(!rendered.contains("HIDDEN_MARKER"), "{rendered}");
                assert!(!rendered.contains(&"x".repeat(128)), "{rendered}");
            }
        }
    }
}
