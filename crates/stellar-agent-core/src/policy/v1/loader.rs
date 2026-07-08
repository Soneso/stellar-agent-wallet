//! Owner-signed policy file loader and document types.
//!
//! The loader provides:
//!
//! - Stable document types ([`crate::policy::v1::loader::PolicyDocument`],
//!   [`crate::policy::v1::loader::PolicyRule`],
//!   [`crate::policy::v1::loader::RuleMatch`],
//!   [`crate::policy::v1::loader::ScopeId`],
//!   [`crate::policy::v1::loader::PolicySignature`]) consumed by
//!   `PolicyEngineV1` and the criteria layer.
//! - [`crate::policy::v1::loader::load_signed_policy`] — loads a TOML policy
//!   file from disk, verifies the owner ed25519 signature, and returns a
//!   ready-to-use [`crate::policy::v1::loader::PolicyDocument`].
//!
//! ## Owner-key contract
//!
//! `stellar-agent-core` must not depend on `stellar-agent-network` (the
//! network crate already depends on `stellar-agent-core`, and a reverse dep
//! would create a cycle).  Therefore the owner public key is NOT fetched from
//! the keyring by this module.  Instead,
//! [`crate::policy::v1::loader::load_signed_policy`] accepts the
//! raw `owner_pubkey` bytes as a parameter.
//!
//! The dispatch site is responsible for:
//!
//! 1. Fetching the owner public key from the keyring entry
//!    `stellar-agent-owner-<profile_name>` (stored as base64-encoded 32 bytes).
//! 2. Decoding it from base64 to `[u8; 32]`.
//! 3. Passing it to `load_signed_policy`.
//!
//! If the keyring entry is absent, the dispatch site maps the absence to
//! [`crate::policy::PolicyError::MissingOwnerKey`] before calling
//! `load_signed_policy`.
//!
//! ## Criteria instantiation
//!
//! The `[[rules]]` TOML array contains inline criterion definitions.  Each
//! element must carry a `kind` field that names one of the supported criterion
//! types (see `parse_criterion` for the full dispatch table).  Unknown or
//! malformed criterion definitions are fail-closed: the loader returns
//! [`crate::policy::PolicyError::PolicyFileParseFailed`] rather than silently
//! skipping the criterion.
//!
//! ## Version range
//!
//! Accepted policy file versions are `[MIN_POLICY_VERSION, MAX_POLICY_VERSION]`
//! (currently `[1, 1]`).  Files with a version outside this range are rejected
//! with [`crate::policy::PolicyError::PolicyFileParseFailed`] to prevent
//! downgrade-replay attacks.

use std::path::Path;
use std::str::FromStr as _;

use serde::{Deserialize, Serialize};
use toml_edit::{DocumentMut, Item};

use crate::counterparty::is_valid_ldh_home_domain;
use crate::policy::v1::canonical::canonical_bytes;
use crate::policy::v1::criteria::counterparty_allowlist::CounterpartyKind;
use crate::policy::v1::criteria::per_period_cap::Window;
use crate::policy::v1::criteria::{
    BundleAggregateCapCriterion, BundlePerPeriodCapCriterion, BundlePerTxCapCriterion,
    BundleRateLimitCriterion, CounterpartyAllowlistCriterion, Criterion,
    InnerInvocationCountCapCriterion, MinimumReserveCriterion, PerPeriodCapCriterion,
    PerTxCapCriterion, RateLimitCriterion, RestrictBundleToRecognisedKindsCriterion,
    SorobanResourceFeeCriterion,
};
use crate::policy::v1::signature::{digest, verify};
use crate::policy::{Decision, DenyReason, PolicyError};

// ─────────────────────────────────────────────────────────────────────────────
// Version range constants (downgrade-replay prevention)
// ─────────────────────────────────────────────────────────────────────────────

/// Minimum accepted policy file version.
///
/// Files with `version < MIN_POLICY_VERSION` are rejected by [`extract_version`]
/// to prevent downgrade-replay attacks.
const MIN_POLICY_VERSION: u32 = 1;

/// Maximum accepted policy file version.
///
/// Files with `version > MAX_POLICY_VERSION` are rejected by [`extract_version`].
/// Bump this constant when a new policy schema version is introduced.
const MAX_POLICY_VERSION: u32 = 1;

/// Default approval time-to-live for `require_approval` policy decisions, in seconds.
const DEFAULT_APPROVAL_TTL_SECONDS: u32 = 300;

// Re-export serde: used only for the on-disk TOML/JSON representation.

// ─────────────────────────────────────────────────────────────────────────────
// PolicySignature
// ─────────────────────────────────────────────────────────────────────────────

/// Verified `[signature]` table from the owner-signed policy file.
///
/// This type is populated from the on-disk TOML `[signature]` table after the
/// signature has been cryptographically verified by [`load_signed_policy`].
/// Constructing a `PolicySignature` outside the loader is technically possible
/// but does not carry the same "already verified" guarantee — callers that
/// build `PolicyDocument` structs in tests MUST verify signatures themselves
/// before depending on the signature field's semantic guarantees.
///
/// `owner_id` is the G-strkey of the owner identity that signed the policy
/// file.  `sig` is the hex-encoded ed25519 signature over
/// `blake3(canonical_toml(rules + scope + version))`.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::policy::v1::loader::PolicySignature;
///
/// let sig = PolicySignature {
///     owner_id: "GABCDE".into(),
///     sig: "deadbeef".into(),
/// };
/// assert_eq!(sig.owner_id, "GABCDE");
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySignature {
    /// G-strkey of the owner identity that signed.
    pub owner_id: String,
    /// Hex-encoded ed25519 signature over `blake3(canonical_toml(...))`.
    pub sig: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// PolicyDocument
// ─────────────────────────────────────────────────────────────────────────────

/// A loaded, scope-resolved policy document with instantiated criteria.
///
/// Produced by [`load_signed_policy`] after signature verification and
/// criterion deserialisation.  The `rules` field holds
/// `Box<dyn Criterion>` objects; this prevents deriving `Clone`,
/// `Serialize`, or `Deserialize` on this type.
///
/// `signature` is `Some` when the document was loaded via
/// [`load_signed_policy`] (the signature was verified before the field was
/// populated).  Test-constructed documents may carry `None`.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::policy::v1::loader::{PolicyDocument, ScopeId};
///
/// let doc = PolicyDocument {
///     version: 1,
///     scope: ScopeId::AllProfiles,
///     rules: vec![],
///     signature: None,
/// };
/// assert_eq!(doc.version, 1);
/// assert!(doc.rules.is_empty());
/// assert!(doc.signature.is_none());
/// ```
#[derive(Debug)]
pub struct PolicyDocument {
    /// Schema version for forward-compatible loading.
    pub version: u32,
    /// The scope this document applies to.
    pub scope: ScopeId,
    /// Ordered list of rules; first match wins.
    pub rules: Vec<PolicyRule>,
    /// The verified owner signature.  `None` for test-constructed documents.
    pub signature: Option<PolicySignature>,
}

// ─────────────────────────────────────────────────────────────────────────────
// ScopeId
// ─────────────────────────────────────────────────────────────────────────────

/// Identifies the profile / project scope a [`PolicyDocument`] applies to.
///
/// Most-specific-wins ordering: `ProfileProject` > `Profile` > `AllProfiles`.
/// See [`ScopeId::specificity`] and [`ScopeId::matches`].
///
/// # Examples
///
/// ```
/// use stellar_agent_core::policy::v1::loader::ScopeId;
///
/// let s = ScopeId::Profile("alice".into());
/// assert!(s.matches("alice", None));
/// assert!(!s.matches("bob", None));
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ScopeId {
    /// Applies to all operations from the named profile.
    Profile(String),
    /// Applies only to the named (profile, project) pair.
    ProfileProject {
        /// Profile name.
        profile: String,
        /// Project identifier.
        project: String,
    },
    /// Applies to all profiles (operator-level default).
    AllProfiles,
}

impl ScopeId {
    /// Returns a numeric specificity for most-specific-wins resolution.
    ///
    /// `ProfileProject` = 3, `Profile` = 2, `AllProfiles` = 1.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::policy::v1::loader::ScopeId;
    ///
    /// assert_eq!(ScopeId::AllProfiles.specificity(), 1);
    /// assert_eq!(ScopeId::Profile("alice".into()).specificity(), 2);
    /// assert_eq!(
    ///     ScopeId::ProfileProject { profile: "alice".into(), project: "p1".into() }.specificity(),
    ///     3,
    /// );
    /// ```
    #[must_use]
    pub fn specificity(&self) -> u8 {
        match self {
            Self::ProfileProject { .. } => 3,
            Self::Profile(_) => 2,
            Self::AllProfiles => 1,
        }
    }

    /// Returns `true` if this scope matches `(profile_name, project_id)`.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::policy::v1::loader::ScopeId;
    ///
    /// let s = ScopeId::ProfileProject { profile: "alice".into(), project: "p1".into() };
    /// assert!(s.matches("alice", Some("p1")));
    /// assert!(!s.matches("alice", None));
    /// assert!(!s.matches("alice", Some("p2")));
    ///
    /// let all = ScopeId::AllProfiles;
    /// assert!(all.matches("any", None));
    /// assert!(all.matches("any", Some("proj")));
    /// ```
    #[must_use]
    pub fn matches(&self, profile_name: &str, project_id: Option<&str>) -> bool {
        match self {
            Self::ProfileProject { profile, project } => {
                profile == profile_name && project_id == Some(project.as_str())
            }
            Self::Profile(p) => p == profile_name,
            Self::AllProfiles => true,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PolicyRule
// ─────────────────────────────────────────────────────────────────────────────

/// A single rule in a [`PolicyDocument`].
///
/// Rules are evaluated in declaration order; the first rule whose
/// [`RuleMatch`] matches the tool call wins.  If all criteria in the rule
/// pass, `decision` is returned.  If any criterion fails, the call is denied.
#[derive(Debug)]
pub struct PolicyRule {
    /// The tool + chain-id match clause.
    pub r#match: RuleMatch,
    /// Criteria evaluated in order; first failing criterion denies.
    pub criteria: Vec<Box<dyn Criterion>>,
    /// The decision to return when all criteria pass.
    pub decision: Decision,
    /// Operator opt-in that this rule may match an `OpaqueSign` tool whose value
    /// effect cannot be sized.
    ///
    /// Value criteria deny an opaque-signing call fail-closed
    /// ([`crate::policy::DenyReason::UnsizableValueEffect`]) by default. Setting
    /// `allow_opaque_signing = true` on a rule that matches such a tool is the
    /// explicit, auditable exemption (design §2.4): the engine treats the
    /// opaque value as not-applicable for that rule so the rule's own
    /// `decision` governs. It has no effect on non-opaque calls.
    pub allow_opaque_signing: bool,
}

impl PolicyRule {
    /// Returns `true` if this rule's [`RuleMatch`] clause matches `tool`.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::policy::v1::loader::{PolicyRule, RuleMatch};
    /// use stellar_agent_core::policy::{Decision, McpToolRegistration, ToolDescriptor};
    ///
    /// let rule = PolicyRule {
    ///     r#match: RuleMatch { tool: "stellar_pay".into(), chain: "*".into() },
    ///     criteria: vec![],
    ///     decision: Decision::Allow,
    ///     allow_opaque_signing: false,
    /// };
    /// let tool = ToolDescriptor::from_registration(&McpToolRegistration {
    ///     name: "stellar_pay",
    ///     destructive_hint: true,
    ///     read_only_hint: false,
    ///     chain_id_required: true,
    ///     value_kind: stellar_agent_core::policy::ToolValueKind::ReadOnly,
    /// });
    /// assert!(rule.matches_tool(&tool));
    /// ```
    #[must_use]
    pub fn matches_tool(&self, tool: &crate::policy::ToolDescriptor) -> bool {
        self.r#match.matches(tool)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RuleMatch
// ─────────────────────────────────────────────────────────────────────────────

/// The tool-name and chain-id match clause of a [`PolicyRule`].
///
/// Wildcards (`"*"`) match any tool name or any chain ID respectively.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::policy::v1::loader::RuleMatch;
/// use stellar_agent_core::policy::{McpToolRegistration, ToolDescriptor};
///
/// let m = RuleMatch { tool: "*".into(), chain: "*".into() };
/// let tool = ToolDescriptor::from_registration(&McpToolRegistration {
///     name: "stellar_pay",
///     destructive_hint: true,
///     read_only_hint: false,
///     chain_id_required: true,
///     value_kind: stellar_agent_core::policy::ToolValueKind::ReadOnly,
/// });
/// assert!(m.matches(&tool));
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleMatch {
    /// Tool name filter; `"*"` matches any tool.
    pub tool: String,
    /// Chain-ID filter (CAIP-2); `"*"` matches any chain.
    pub chain: String,
}

impl RuleMatch {
    /// Returns `true` when this match clause applies to `tool`.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::policy::v1::loader::RuleMatch;
    /// use stellar_agent_core::policy::{McpToolRegistration, ToolDescriptor};
    ///
    /// let exact = RuleMatch { tool: "stellar_pay".into(), chain: "stellar:mainnet".into() };
    /// let td = ToolDescriptor::from_registration(&McpToolRegistration {
    ///     name: "stellar_pay",
    ///     destructive_hint: true,
    ///     read_only_hint: false,
    ///     chain_id_required: true,
    ///     value_kind: stellar_agent_core::policy::ToolValueKind::ReadOnly,
    /// });
    /// // chain_id on ToolDescriptor is populated from the tool call arg at dispatch;
    /// // for the match test the chain_id field of ToolDescriptor is not yet set.
    /// // The wildcard form always passes:
    /// let wild = RuleMatch { tool: "*".into(), chain: "*".into() };
    /// assert!(wild.matches(&td));
    /// ```
    #[must_use]
    pub fn matches(&self, tool: &crate::policy::ToolDescriptor) -> bool {
        let tool_match = self.tool == "*" || self.tool == tool.name;
        let chain_match = self.chain == "*" || self.chain == tool.chain_id;
        tool_match && chain_match
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// load_signed_policy
// ─────────────────────────────────────────────────────────────────────────────

/// Loads and verifies a signed policy file from disk.
///
/// ## Steps
///
/// 1. Read the file at `path`.
/// 2. Compute canonical bytes (excluding the `[signature]` table).
/// 3. Compute a BLAKE3 digest of the canonical bytes.
/// 4. Verify the ed25519 signature in the `[signature]` table against the
///    digest using `owner_pubkey`.
/// 5. Parse `version`, `scope`, and `[[rules]]` into runtime form.
///
/// ## Owner-key contract
///
/// This function does NOT fetch the owner public key from the keyring.
/// `stellar-agent-core` must not depend on `stellar-agent-network` (circular
/// dep).  The dispatch site is responsible for:
///
/// 1. Fetching the keyring entry `stellar-agent-owner-<profile_name>`.
/// 2. Decoding it from base64 to `[u8; 32]`.
/// 3. Passing it to this function as `owner_pubkey`.
///
/// If the keyring entry is absent, the dispatch site maps the absence to
/// [`crate::policy::PolicyError::MissingOwnerKey`] and does NOT call this
/// function.
///
/// # Errors
///
/// - [`PolicyError::PolicyFileLoadFailed`] — the file could not be read
///   (I/O error, path does not exist, permission denied).
/// - [`PolicyError::PolicyFileParseFailed`] — the file contains invalid TOML,
///   is missing required fields (`version`, `scope`), or the `[signature]`
///   table is absent or malformed.
/// - [`PolicyError::OwnerSignatureInvalid`] — the signature in the
///   `[signature]` table does not verify against `owner_pubkey` and the
///   canonical form of the document.
///
/// # Examples
///
/// ```no_run
/// use std::path::Path;
/// use stellar_agent_core::policy::v1::loader::load_signed_policy;
///
/// // In production: owner_pubkey comes from the keyring.
/// let owner_pubkey = [0u8; 32];
/// let doc = load_signed_policy(
///     Path::new("/home/user/.local/state/stellar-agent/policies/alice.toml"),
///     "alice",
///     &owner_pubkey,
/// );
/// ```
pub fn load_signed_policy(
    path: &Path,
    profile_name: &str,
    owner_pubkey: &[u8; 32],
) -> Result<PolicyDocument, PolicyError> {
    // Step 1: read the file.
    let raw = std::fs::read_to_string(path).map_err(|e| {
        let basename = path
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .unwrap_or("<unknown>");
        PolicyError::PolicyFileLoadFailed {
            detail: format!("{basename}: {e}"),
        }
    })?;

    // Step 2: canonical bytes (excludes [signature] table).
    let canon = canonical_bytes(&raw)?;

    // Step 3: BLAKE3 digest.
    let d = digest(&canon);

    // Parse the document to extract [signature].
    let doc = DocumentMut::from_str(&raw).map_err(|e| PolicyError::PolicyFileParseFailed {
        detail: e.to_string(),
    })?;

    // Step 4: extract and verify [signature].
    let sig_item = doc
        .get("signature")
        .ok_or_else(|| PolicyError::PolicyFileParseFailed {
            detail: "policy file missing required `[signature]` table".into(),
        })?;
    let (owner_id, sig_hex) = extract_signature_fields(sig_item)?;
    let sig_bytes = decode_hex_sig(&sig_hex, profile_name)?;

    verify(&d, &sig_bytes, owner_pubkey, profile_name)?;

    // Step 5: parse version, scope, rules.
    let version = extract_version(&doc)?;
    let scope = extract_scope(&doc)?;
    reject_scope_profile_mismatch(&scope, profile_name)?;
    let rules = extract_rules(&doc)?;

    Ok(PolicyDocument {
        version,
        scope,
        rules,
        signature: Some(PolicySignature {
            owner_id,
            sig: sig_hex,
        }),
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal parsing helpers
// ─────────────────────────────────────────────────────────────────────────────

fn reject_scope_profile_mismatch(scope: &ScopeId, profile_name: &str) -> Result<(), PolicyError> {
    let matches_profile = match scope {
        ScopeId::AllProfiles => true,
        ScopeId::Profile(profile) => profile == profile_name,
        ScopeId::ProfileProject { profile, .. } => profile == profile_name,
    };

    if !matches_profile {
        return Err(PolicyError::PolicyFileParseFailed {
            detail: format!("policy scope does not match profile `{profile_name}`"),
        });
    }

    Ok(())
}

/// Extracts `(owner_id, sig)` strings from the `[signature]` item.
fn extract_signature_fields(item: &Item) -> Result<(String, String), PolicyError> {
    let table = match item {
        Item::Table(t) => t,
        _ => {
            return Err(PolicyError::PolicyFileParseFailed {
                detail: "`[signature]` must be a TOML table".into(),
            });
        }
    };

    let owner_id = table
        .get("owner_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| PolicyError::PolicyFileParseFailed {
            detail: "`[signature].owner_id` must be a string".into(),
        })?
        .to_owned();

    let sig = table
        .get("sig")
        .and_then(|v| v.as_str())
        .ok_or_else(|| PolicyError::PolicyFileParseFailed {
            detail: "`[signature].sig` must be a string".into(),
        })?
        .to_owned();

    Ok((owner_id, sig))
}

/// Decodes a hex-encoded ed25519 signature string into a 64-byte array.
fn decode_hex_sig(hex: &str, profile_name: &str) -> Result<[u8; 64], PolicyError> {
    let bytes = hex_to_bytes(hex).ok_or_else(|| PolicyError::OwnerSignatureInvalid {
        profile: profile_name.to_owned(),
    })?;
    bytes
        .try_into()
        .map_err(|_| PolicyError::OwnerSignatureInvalid {
            profile: profile_name.to_owned(),
        })
}

/// Decodes a hex string to bytes.  Returns `None` on invalid hex.
fn hex_to_bytes(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// Extracts and validates the `version` field.
///
/// Accepts only values in `[MIN_POLICY_VERSION, MAX_POLICY_VERSION]`.  Values
/// outside that range are rejected to prevent downgrade-replay attacks.
///
/// # Errors
///
/// Returns [`PolicyError::PolicyFileParseFailed`] when:
/// - `version` is absent or is not an integer.
/// - The value does not fit in `u32`.
/// - The value is below `MIN_POLICY_VERSION` or above `MAX_POLICY_VERSION`.
fn extract_version(doc: &DocumentMut) -> Result<u32, PolicyError> {
    let v = doc
        .get("version")
        .and_then(|i| i.as_integer())
        .ok_or_else(|| PolicyError::PolicyFileParseFailed {
            detail: "`version` must be a positive integer".into(),
        })?;

    let version = u32::try_from(v).map_err(|_| PolicyError::PolicyFileParseFailed {
        detail: format!("`version` value {v} is out of range for u32"),
    })?;

    if version < MIN_POLICY_VERSION {
        return Err(PolicyError::PolicyFileParseFailed {
            detail: format!(
                "`version` {version} is below the minimum supported version \
                 {MIN_POLICY_VERSION}; policy files older than version \
                 {MIN_POLICY_VERSION} are not accepted (downgrade replay prevention)"
            ),
        });
    }

    if version > MAX_POLICY_VERSION {
        return Err(PolicyError::PolicyFileParseFailed {
            detail: format!(
                "`version` {version} is above the maximum supported version \
                 {MAX_POLICY_VERSION}; upgrade the agent to a version that \
                 supports policy schema v{version}"
            ),
        });
    }

    Ok(version)
}

/// Extracts and parses the `scope` field.
fn extract_scope(doc: &DocumentMut) -> Result<ScopeId, PolicyError> {
    let s = doc.get("scope").and_then(|i| i.as_str()).ok_or_else(|| {
        PolicyError::PolicyFileParseFailed {
            detail: "`scope` must be a string".into(),
        }
    })?;

    parse_scope_string(s)
}

/// Parses a scope string into a [`ScopeId`].
///
/// Accepted formats:
/// - `"profile:<name>"` → `ScopeId::Profile`
/// - `"profile:<name>,project:<id>"` → `ScopeId::ProfileProject`
/// - `"profile:*"` → `ScopeId::AllProfiles`
fn parse_scope_string(s: &str) -> Result<ScopeId, PolicyError> {
    // Try profile:*,project: variant first, then profile:*,project,
    // then plain profile:*.
    let parts: Vec<&str> = s.splitn(2, ',').collect();
    let profile_part = parts[0].trim();
    let project_part = parts.get(1).map(|p| p.trim());

    let profile_name = profile_part
        .strip_prefix("profile:")
        .ok_or_else(|| PolicyError::PolicyFileParseFailed {
            detail: format!("invalid scope format: `{s}`; expected `profile:<name>` or `profile:<name>,project:<id>`"),
        })?;

    if profile_name == "*" && project_part.is_none() {
        return Ok(ScopeId::AllProfiles);
    }

    if let Some(proj_str) = project_part {
        let project_name = proj_str.strip_prefix("project:").ok_or_else(|| {
            PolicyError::PolicyFileParseFailed {
                detail: format!(
                    "invalid scope project segment: `{proj_str}`; expected `project:<id>`"
                ),
            }
        })?;
        return Ok(ScopeId::ProfileProject {
            profile: profile_name.to_owned(),
            project: project_name.to_owned(),
        });
    }

    Ok(ScopeId::Profile(profile_name.to_owned()))
}

/// Extracts and parses the `[[rules]]` array.
///
/// Returns an empty vec when no `rules` key is present.
fn extract_rules(doc: &DocumentMut) -> Result<Vec<PolicyRule>, PolicyError> {
    let rules_item = match doc.get("rules") {
        Some(item) => item,
        None => return Ok(vec![]),
    };

    let aot = match rules_item {
        Item::ArrayOfTables(aot) => aot,
        _ => {
            return Err(PolicyError::PolicyFileParseFailed {
                detail: "`rules` must be an array of tables (`[[rules]]`)".into(),
            });
        }
    };

    let mut rules = Vec::with_capacity(aot.len());
    for (i, table) in aot.iter().enumerate() {
        rules.push(parse_rule(table, i)?);
    }
    Ok(rules)
}

/// Parses a single rule table.
///
/// # Errors
///
/// Returns [`PolicyError::PolicyFileParseFailed`] when the table is missing
/// required keys, a criterion is unrecognised or malformed, or the decision
/// value is unknown.
fn parse_rule(table: &toml_edit::Table, idx: usize) -> Result<PolicyRule, PolicyError> {
    // match clause
    let match_item = table
        .get("match")
        .ok_or_else(|| PolicyError::PolicyFileParseFailed {
            detail: format!("rule[{idx}] missing required `match` key"),
        })?;
    let rule_match = parse_rule_match(match_item, idx)?;

    // criteria (may be absent or empty)
    let criteria = parse_criteria(table.get("criteria"), idx)?;

    // decision
    let decision_str = table
        .get("decision")
        .and_then(|v| v.as_str())
        .ok_or_else(|| PolicyError::PolicyFileParseFailed {
            detail: format!("rule[{idx}] `decision` must be a string"),
        })?;

    let reason = parse_optional_reason(table, idx)?;
    let ttl_secs = parse_optional_ttl_secs(table, idx)?;
    let decision = parse_decision(decision_str, idx, reason, ttl_secs)?;

    // Optional opaque-signing exemption (design §2.4). Absent → false; present
    // but not a boolean → parse error (fail-closed on a malformed exemption).
    let allow_opaque_signing = match table.get("allow_opaque_signing") {
        None => false,
        Some(item) => item
            .as_bool()
            .ok_or_else(|| PolicyError::PolicyFileParseFailed {
                detail: format!("rule[{idx}] `allow_opaque_signing` must be a boolean"),
            })?,
    };

    Ok(PolicyRule {
        r#match: rule_match,
        criteria,
        decision,
        allow_opaque_signing,
    })
}

/// Iterates the `criteria` TOML array and instantiates each criterion.
///
/// Returns an empty vec when the `criteria` key is absent.  Returns an error
/// when the key is present but is not an array, or when any criterion item
/// fails to parse.
///
/// # Errors
///
/// Returns [`PolicyError::PolicyFileParseFailed`] when:
/// - `criteria` is present but is not a TOML array.
/// - Any criterion element cannot be parsed (see [`parse_criterion`]).
fn parse_criteria(
    item: Option<&Item>,
    rule_idx: usize,
) -> Result<Vec<Box<dyn Criterion>>, PolicyError> {
    let array = match item {
        None => return Ok(vec![]),
        Some(Item::Value(toml_edit::Value::Array(a))) => a,
        Some(_) => {
            return Err(PolicyError::PolicyFileParseFailed {
                detail: format!("rule[{rule_idx}] `criteria` must be an array"),
            });
        }
    };

    let mut criteria: Vec<Box<dyn Criterion>> = Vec::with_capacity(array.len());
    for (criterion_idx, elem) in array.iter().enumerate() {
        let item = Item::Value(elem.clone());
        criteria.push(parse_criterion(&item, rule_idx, criterion_idx)?);
    }
    Ok(criteria)
}

/// Parses a single criterion element from the `criteria` array and instantiates
/// the corresponding concrete [`Criterion`] implementation.
///
/// `item` must be a TOML inline table with at least a `kind` string field.
/// The dispatcher is **fail-closed**: any `item` the dispatcher cannot fully
/// understand returns [`PolicyError::PolicyFileParseFailed`] rather than
/// silently skipping.
///
/// ## Supported `kind` values
///
/// | `kind`                     | Criterion type                       |
/// |----------------------------|--------------------------------------|
/// | `"per_tx_cap"`             | [`PerTxCapCriterion`]                |
/// | `"per_period_cap"`         | [`PerPeriodCapCriterion`]            |
/// | `"rate_limit"`             | [`RateLimitCriterion`]               |
/// | `"counterparty_allowlist"` | [`CounterpartyAllowlistCriterion`]   |
/// | `"minimum_reserve"`        | [`MinimumReserveCriterion`]          |
/// | `"soroban_resource_fee_cap"` | [`SorobanResourceFeeCriterion`]    |
/// | `"bundle_per_period_cap"`  | [`BundlePerPeriodCapCriterion`]      |
/// | `"bundle_per_tx_cap"`      | [`BundlePerTxCapCriterion`]          |
/// | `"bundle_rate_limit"`      | [`BundleRateLimitCriterion`]         |
/// | `"quorum_satisfied"`       | [`QuorumSatisfiedCriterion`]         |
/// | `"home_domain_resolved"`   | [`HomeDomainResolvedCriterion`]      |
/// | `"sep10_session_active"`   | [`Sep10SessionActiveCriterion`]      |
///
/// # Errors
///
/// Returns [`PolicyError::PolicyFileParseFailed`] when:
/// - `item` is not an inline table.
/// - The `kind` field is absent.
/// - The `kind` value is not one of the recognised strings.
/// - A required field for the matched kind is absent.
/// - A field has an incompatible type (e.g. `max_stroops` is not an integer).
/// - An integer field is out of range (e.g. negative `max_stroops`).
/// - A `window` string is not one of the accepted values.
/// - A `CounterpartyKind` string is not one of the accepted values.
///
/// All `detail` strings include `rule[{rule_idx}].criteria[{criterion_idx}]`
/// for diagnostic locality.
fn parse_criterion(
    item: &Item,
    rule_idx: usize,
    criterion_idx: usize,
) -> Result<Box<dyn Criterion>, PolicyError> {
    let loc = format!("rule[{rule_idx}].criteria[{criterion_idx}]");

    // The element must be an inline table.
    let table = match item {
        Item::Value(toml_edit::Value::InlineTable(t)) => t,
        _ => {
            return Err(PolicyError::PolicyFileParseFailed {
                detail: format!(
                    "{loc}: each criterion must be an inline table `{{ kind = \"...\", ... }}`"
                ),
            });
        }
    };

    // Require a `kind` string field.
    let kind = table.get("kind").and_then(|v| v.as_str()).ok_or_else(|| {
        PolicyError::PolicyFileParseFailed {
            detail: format!("{loc}: missing required `kind` field"),
        }
    })?;

    match kind {
        "per_tx_cap" => {
            let asset = require_str(table, "asset", &loc)?;
            let max_stroops = require_i64(table, "max_stroops", &loc)?;
            if max_stroops < 0 {
                return Err(PolicyError::PolicyFileParseFailed {
                    detail: format!("{loc}: `max_stroops` must be non-negative, got {max_stroops}"),
                });
            }
            Ok(Box::new(PerTxCapCriterion::new(asset, max_stroops)))
        }
        "per_period_cap" => {
            let asset = require_str(table, "asset", &loc)?;
            let window_str = require_str(table, "window", &loc)?;
            let window =
                Window::parse(&window_str).map_err(|_| PolicyError::PolicyFileParseFailed {
                    detail: format!(
                        "{loc}: `window` value `{window_str}` is not accepted; \
                     valid values: 1m, 5m, 1h, 1d, 1w"
                    ),
                })?;
            let max_stroops = require_i64(table, "max_stroops", &loc)?;
            if max_stroops < 0 {
                return Err(PolicyError::PolicyFileParseFailed {
                    detail: format!("{loc}: `max_stroops` must be non-negative, got {max_stroops}"),
                });
            }
            Ok(Box::new(PerPeriodCapCriterion::new(
                asset,
                window,
                max_stroops,
            )))
        }
        "rate_limit" => {
            let window_str = require_str(table, "window", &loc)?;
            let window =
                Window::parse(&window_str).map_err(|_| PolicyError::PolicyFileParseFailed {
                    detail: format!(
                        "{loc}: `window` value `{window_str}` is not accepted; \
                     valid values: 1m, 5m, 1h, 1d, 1w"
                    ),
                })?;
            let max_calls_raw = require_i64(table, "max_calls", &loc)?;
            let max_calls =
                u32::try_from(max_calls_raw).map_err(|_| PolicyError::PolicyFileParseFailed {
                    detail: format!(
                        "{loc}: `max_calls` value {max_calls_raw} is out of range for u32"
                    ),
                })?;
            Ok(Box::new(RateLimitCriterion::new(window, max_calls)))
        }
        "counterparty_allowlist" => {
            let kinds_raw = require_array_of_str(table, "kinds", &loc)?;
            let mut kinds: Vec<CounterpartyKind> = Vec::with_capacity(kinds_raw.len());
            let mut has_home_domain = false;
            for s in &kinds_raw {
                let k =
                    CounterpartyKind::parse(s).map_err(|_| PolicyError::PolicyFileParseFailed {
                        detail: format!(
                            "{loc}: unknown counterparty kind `{s}`; \
                         accepted: G_ACCOUNT, C_ACCOUNT, KNOWN_ISSUER, \
                         SEP10_IDENTITY, HOME_DOMAIN, ONE_TIME_ADDRESS"
                        ),
                    })?;
                if matches!(k, CounterpartyKind::HomeDomain) {
                    has_home_domain = true;
                }
                kinds.push(k);
            }
            let allowlist = require_array_of_str(table, "allowlist", &loc)?;
            // HOME_DOMAIN entries must use the same lowercase LDH validator as
            // the SEP-1 fetch path and on-chain projection.  This rejects
            // non-ASCII, uppercase, underscores, separators at either end,
            // empty or oversized labels, and values longer than the DNS
            // hostname boundary accepted by the fetch path.
            //
            // This validation applies to ALL allowlist entries when `kinds`
            // includes `HOME_DOMAIN`, because the allowlist is shared across all
            // configured kinds for this criterion instance.
            if has_home_domain {
                for (i, entry) in allowlist.iter().enumerate() {
                    if !is_valid_ldh_home_domain(entry) {
                        return Err(PolicyError::PolicyFileParseFailed {
                            detail: format!(
                                "{loc}: `allowlist[{i}]` is not a valid HOME_DOMAIN; \
                                 entries must be lowercase RFC 1035 LDH \
                                 (ASCII a-z, 0-9, hyphen, dot), 1..=255 bytes, \
                                 each label 1..=63 bytes, contain no uppercase \
                                 or non-ASCII bytes, and must not start or end \
                                 with '-' or '.'"
                            ),
                        });
                    }
                }
            }
            Ok(Box::new(CounterpartyAllowlistCriterion::new(
                kinds, allowlist,
            )))
        }
        "minimum_reserve" => {
            let margin_stroops = require_i64(table, "margin_stroops", &loc)?;
            if margin_stroops < 0 {
                return Err(PolicyError::PolicyFileParseFailed {
                    detail: format!(
                        "{loc}: `margin_stroops` must be non-negative, got {margin_stroops}"
                    ),
                });
            }
            Ok(Box::new(MinimumReserveCriterion::new(margin_stroops)))
        }
        "soroban_resource_fee_cap" => {
            let max_resource_fee_stroops = require_i64(table, "max_resource_fee_stroops", &loc)?;
            if max_resource_fee_stroops < 0 {
                return Err(PolicyError::PolicyFileParseFailed {
                    detail: format!(
                        "{loc}: `max_resource_fee_stroops` must be non-negative, \
                         got {max_resource_fee_stroops}"
                    ),
                });
            }
            let max_footprint_raw = require_i64(table, "max_footprint_entries", &loc)?;
            let max_footprint_entries = u32::try_from(max_footprint_raw).map_err(|_| {
                PolicyError::PolicyFileParseFailed {
                    detail: format!(
                        "{loc}: `max_footprint_entries` value {max_footprint_raw} is \
                         out of range for u32"
                    ),
                }
            })?;
            Ok(Box::new(SorobanResourceFeeCriterion::new(
                max_resource_fee_stroops,
                max_footprint_entries,
            )))
        }
        "inner_invocation_count_cap" => {
            let max_count_raw = require_i64(table, "max_count", &loc)?;
            let max_count =
                u32::try_from(max_count_raw).map_err(|_| PolicyError::PolicyFileParseFailed {
                    detail: format!(
                        "{loc}: `max_count` value {max_count_raw} is out of range for u32"
                    ),
                })?;
            Ok(Box::new(InnerInvocationCountCapCriterion { max_count }))
        }
        "bundle_aggregate_cap" => {
            let asset = optional_str(table, "asset");
            // `max_amount` is string-encoded to allow values that exceed TOML's
            // i64 range (i128 can represent sums of many inner transfers).
            let max_amount_str = require_str(table, "max_amount", &loc)?;
            let max_amount = max_amount_str.parse::<i128>().map_err(|_| {
                PolicyError::PolicyFileParseFailed {
                    detail: format!(
                        "{loc}: `max_amount` value `{max_amount_str}` is not a valid i128 decimal"
                    ),
                }
            })?;
            if max_amount < 0 {
                return Err(PolicyError::PolicyFileParseFailed {
                    detail: format!("{loc}: `max_amount` must be non-negative, got {max_amount}"),
                });
            }
            Ok(Box::new(BundleAggregateCapCriterion { asset, max_amount }))
        }
        "restrict_bundle_to_recognised_kinds" => {
            let enabled = require_bool(table, "enabled", &loc)?;
            Ok(Box::new(RestrictBundleToRecognisedKindsCriterion {
                enabled,
            }))
        }
        // ── bundle-variant extensions ────────────────────────────────────────
        //
        // These are additive criterion types for multicall-aware policy rules.
        // They do NOT change the semantics of per_period_cap / per_tx_cap /
        // rate_limit — those existing criteria continue to fire only on
        // stellar_pay / stellar_create_account / etc.
        "bundle_per_period_cap" => {
            let asset = require_str(table, "asset", &loc)?;
            let window_str = require_str(table, "window", &loc)?;
            let window =
                Window::parse(&window_str).map_err(|_| PolicyError::PolicyFileParseFailed {
                    detail: format!(
                        "{loc}: `window` value `{window_str}` is not accepted; \
                         valid values: 1m, 5m, 1h, 1d, 1w"
                    ),
                })?;
            let max_stroops = require_i64(table, "max_stroops", &loc)?;
            if max_stroops < 0 {
                return Err(PolicyError::PolicyFileParseFailed {
                    detail: format!("{loc}: `max_stroops` must be non-negative, got {max_stroops}"),
                });
            }
            Ok(Box::new(BundlePerPeriodCapCriterion::new(
                asset,
                window,
                max_stroops,
            )))
        }
        "bundle_per_tx_cap" => {
            let asset = require_str(table, "asset", &loc)?;
            let max_stroops = require_i64(table, "max_stroops", &loc)?;
            if max_stroops < 0 {
                return Err(PolicyError::PolicyFileParseFailed {
                    detail: format!("{loc}: `max_stroops` must be non-negative, got {max_stroops}"),
                });
            }
            Ok(Box::new(BundlePerTxCapCriterion::new(asset, max_stroops)))
        }
        "bundle_rate_limit" => {
            let window_str = require_str(table, "window", &loc)?;
            let window =
                Window::parse(&window_str).map_err(|_| PolicyError::PolicyFileParseFailed {
                    detail: format!(
                        "{loc}: `window` value `{window_str}` is not accepted; \
                         valid values: 1m, 5m, 1h, 1d, 1w"
                    ),
                })?;
            let max_calls_raw = require_i64(table, "max_calls", &loc)?;
            let max_calls =
                u32::try_from(max_calls_raw).map_err(|_| PolicyError::PolicyFileParseFailed {
                    detail: format!(
                        "{loc}: `max_calls` value {max_calls_raw} is out of range for u32"
                    ),
                })?;
            Ok(Box::new(BundleRateLimitCriterion::new(window, max_calls)))
        }
        "quorum_satisfied" => Ok(Box::new(
            crate::policy::v1::criteria::quorum_satisfied::QuorumSatisfiedCriterion::new(),
        )),
        "home_domain_resolved" => Ok(Box::new(
            crate::policy::v1::criteria::home_domain_resolved::HomeDomainResolvedCriterion::new(),
        )),
        "sep10_session_active" => Ok(Box::new(
            crate::policy::v1::criteria::sep10_session_active::Sep10SessionActiveCriterion::new(),
        )),
        "sep45_session_active" => Ok(Box::new(
            crate::policy::v1::criteria::sep45_session_active::Sep45SessionActiveCriterion::new(),
        )),
        other => Err(PolicyError::PolicyFileParseFailed {
            detail: format!(
                "{loc}: unknown criterion kind `{other}`; accepted kinds: \
                 per_tx_cap, per_period_cap, rate_limit, counterparty_allowlist, \
                 minimum_reserve, soroban_resource_fee_cap, inner_invocation_count_cap, \
                 bundle_aggregate_cap, restrict_bundle_to_recognised_kinds, \
                 bundle_per_period_cap, bundle_per_tx_cap, bundle_rate_limit, \
                 quorum_satisfied, home_domain_resolved, sep10_session_active, \
                 sep45_session_active"
            ),
        }),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Criterion field extraction helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Extracts a required string field from a criterion inline table.
///
/// # Errors
///
/// Returns [`PolicyError::PolicyFileParseFailed`] when the field is absent or
/// is not a string.
fn require_str(
    table: &toml_edit::InlineTable,
    key: &str,
    loc: &str,
) -> Result<String, PolicyError> {
    table
        .get(key)
        .and_then(|v| v.as_str())
        .map(ToOwned::to_owned)
        .ok_or_else(|| PolicyError::PolicyFileParseFailed {
            detail: format!("{loc}: missing or non-string required field `{key}`"),
        })
}

/// Extracts a required integer field (as `i64`) from a criterion inline table.
///
/// # Errors
///
/// Returns [`PolicyError::PolicyFileParseFailed`] when the field is absent or
/// is not an integer.
fn require_i64(table: &toml_edit::InlineTable, key: &str, loc: &str) -> Result<i64, PolicyError> {
    table
        .get(key)
        .and_then(|v| v.as_integer())
        .ok_or_else(|| PolicyError::PolicyFileParseFailed {
            detail: format!("{loc}: missing or non-integer required field `{key}`"),
        })
}

/// Extracts a required boolean field from a criterion inline table.
///
/// # Errors
///
/// Returns [`PolicyError::PolicyFileParseFailed`] when the field is absent or
/// is not a boolean.
fn require_bool(table: &toml_edit::InlineTable, key: &str, loc: &str) -> Result<bool, PolicyError> {
    table
        .get(key)
        .and_then(|v| v.as_bool())
        .ok_or_else(|| PolicyError::PolicyFileParseFailed {
            detail: format!("{loc}: missing or non-boolean required field `{key}`"),
        })
}

/// Extracts an optional string field from a criterion inline table.
///
/// Returns `None` when the key is absent; returns `Some(s)` when present and a
/// string.  Returns `None` (rather than an error) when the value is not a
/// string — callers that need strict validation should use [`require_str`].
fn optional_str(table: &toml_edit::InlineTable, key: &str) -> Option<String> {
    table
        .get(key)
        .and_then(|v| v.as_str())
        .map(ToOwned::to_owned)
}

/// Extracts a required array-of-strings field from a criterion inline table.
///
/// # Errors
///
/// Returns [`PolicyError::PolicyFileParseFailed`] when the field is absent, is
/// not an array, or any element is not a string.
fn require_array_of_str(
    table: &toml_edit::InlineTable,
    key: &str,
    loc: &str,
) -> Result<Vec<String>, PolicyError> {
    let arr = table.get(key).and_then(|v| v.as_array()).ok_or_else(|| {
        PolicyError::PolicyFileParseFailed {
            detail: format!("{loc}: missing or non-array required field `{key}`"),
        }
    })?;

    arr.iter()
        .enumerate()
        .map(|(i, v)| {
            v.as_str()
                .map(ToOwned::to_owned)
                .ok_or_else(|| PolicyError::PolicyFileParseFailed {
                    detail: format!("{loc}: `{key}[{i}]` must be a string"),
                })
        })
        .collect()
}

/// Parses the `match` inline-table or table into a [`RuleMatch`].
fn parse_rule_match(item: &Item, idx: usize) -> Result<RuleMatch, PolicyError> {
    let tool = extract_str_field_from_item(item, "tool", idx)?;
    let chain = extract_str_field_from_item(item, "chain", idx)?;
    reject_empty_match_field(&tool, "tool", idx)?;
    reject_empty_match_field(&chain, "chain", idx)?;
    Ok(RuleMatch { tool, chain })
}

/// Extracts a string field from an inline `match = {}` table or accepted `[rules.match]` table.
fn extract_str_field_from_item(item: &Item, key: &str, idx: usize) -> Result<String, PolicyError> {
    match item {
        Item::Value(toml_edit::Value::InlineTable(t)) => t
            .get(key)
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
            .ok_or_else(|| PolicyError::PolicyFileParseFailed {
                detail: format!("rule[{idx}] `match.{key}` must be a string"),
            }),
        Item::Table(t) => t
            .get(key)
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
            .ok_or_else(|| PolicyError::PolicyFileParseFailed {
                detail: format!("rule[{idx}] `match.{key}` must be a string"),
            }),
        _ => Err(PolicyError::PolicyFileParseFailed {
            detail: format!("rule[{idx}] `match` must be an inline table"),
        }),
    }
}

fn reject_empty_match_field(value: &str, key: &str, idx: usize) -> Result<(), PolicyError> {
    if value.is_empty() {
        return Err(PolicyError::PolicyFileParseFailed {
            detail: format!("rule[{idx}] `match.{key}` must not be empty"),
        });
    }
    Ok(())
}

fn parse_optional_reason(
    table: &toml_edit::Table,
    idx: usize,
) -> Result<Option<String>, PolicyError> {
    match table.get("reason") {
        None => Ok(None),
        Some(v) => v.as_str().map(ToOwned::to_owned).map(Some).ok_or_else(|| {
            PolicyError::PolicyFileParseFailed {
                detail: format!("rule[{idx}] `reason` must be a string"),
            }
        }),
    }
}

fn parse_optional_ttl_secs(
    table: &toml_edit::Table,
    idx: usize,
) -> Result<Option<u32>, PolicyError> {
    match table.get("ttl_secs") {
        None => Ok(None),
        Some(v) => {
            let raw = v
                .as_integer()
                .ok_or_else(|| PolicyError::PolicyFileParseFailed {
                    detail: format!("rule[{idx}] `ttl_secs` must be a non-negative u32"),
                })?;
            u32::try_from(raw)
                .map(Some)
                .map_err(|_| PolicyError::PolicyFileParseFailed {
                    detail: format!("rule[{idx}] `ttl_secs` must be a non-negative u32"),
                })
        }
    }
}

/// Parses a `decision` string into a [`Decision`] variant.
///
/// The `"deny"` keyword maps to [`DenyReason::ExplicitRuleDeny`] — an
/// operator-explicit deny that is distinct from the engine's default-deny
/// fallback ([`DenyReason::NoMatchingRule`]).  The distinction matters at the
/// wire layer: the dispatch gate emits different wire codes for each.
///
/// # Errors
///
/// Returns [`PolicyError::PolicyFileParseFailed`] for any unrecognised value.
fn parse_decision(
    s: &str,
    idx: usize,
    reason: Option<String>,
    ttl_secs: Option<u32>,
) -> Result<Decision, PolicyError> {
    match s {
        "allow" => {
            reject_approval_fields_for_non_approval_decision(idx, &reason, ttl_secs)?;
            Ok(Decision::Allow)
        }
        "deny" => {
            reject_approval_fields_for_non_approval_decision(idx, &reason, ttl_secs)?;
            Ok(Decision::Deny(DenyReason::ExplicitRuleDeny))
        }
        "require_approval" => {
            let mut req = crate::policy::ApprovalRequest::new(
                String::new(),
                ttl_secs.unwrap_or(DEFAULT_APPROVAL_TTL_SECONDS),
            );
            if let Some(reason) = reason {
                req = req.with_reason(reason);
            }
            Ok(Decision::RequireApproval(req))
        }
        other => Err(PolicyError::PolicyFileParseFailed {
            detail: format!(
                "rule[{idx}] `decision` has unknown value `{other}`; \
                 expected `allow`, `deny`, or `require_approval`"
            ),
        }),
    }
}

fn reject_approval_fields_for_non_approval_decision(
    idx: usize,
    reason: &Option<String>,
    ttl_secs: Option<u32>,
) -> Result<(), PolicyError> {
    if reason.is_some() || ttl_secs.is_some() {
        return Err(PolicyError::PolicyFileParseFailed {
            detail: format!(
                "rule[{idx}] `reason` / `ttl_secs` are only valid for \
                 `decision = \"require_approval\"`"
            ),
        });
    }
    Ok(())
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

    use ed25519_dalek::Signer;
    use rand_core::OsRng;
    use serde_json::json;
    use tempfile::TempDir;

    use super::*;
    use crate::policy::v1::criteria::PolicyStateStore;
    use crate::policy::v1::{AccountReserveLookupError, AccountReservesView, EvalContext};
    use crate::policy::{DenyReason, McpToolRegistration, ToolDescriptor};
    use crate::profile::schema::Profile;

    // ── helpers ───────────────────────────────────────────────────────────────

    fn make_keypair() -> (ed25519_dalek::SigningKey, [u8; 32]) {
        let sk = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let pk = sk.verifying_key().to_bytes();
        (sk, pk)
    }

    /// Builds a signed policy TOML string for the given policy body (which must
    /// NOT contain a `[signature]` table).  The signature is computed over the
    /// canonical bytes of the full document (signature table excluded).
    fn make_signed_toml(
        policy_body: &str,
        sk: &ed25519_dalek::SigningKey,
        owner_id: &str,
    ) -> String {
        let canon = canonical_bytes(policy_body)
            .expect("canonical_bytes must succeed for well-formed policy");
        let d = digest(&canon);
        let sig: [u8; 64] = sk.sign(&d).to_bytes();
        let sig_hex: String = sig.iter().map(|b| format!("{b:02x}")).collect();
        format!("{policy_body}\n[signature]\nowner_id = \"{owner_id}\"\nsig = \"{sig_hex}\"\n")
    }

    fn write_policy(dir: &TempDir, name: &str, content: &str) -> std::path::PathBuf {
        let path = dir.path().join(name);
        std::fs::write(&path, content).expect("write must succeed");
        path
    }

    struct LoaderTestAccountView {
        balance: i64,
        reserves: i64,
    }

    impl AccountReservesView for LoaderTestAccountView {
        fn reserves_stroops(&self, _base_reserve_stroops: i64) -> i64 {
            self.reserves
        }

        fn balance_stroops(&self) -> Result<i64, AccountReserveLookupError> {
            Ok(self.balance)
        }
    }

    fn test_tool(name: &'static str) -> ToolDescriptor {
        ToolDescriptor::from_registration(&McpToolRegistration {
            name,
            destructive_hint: true,
            read_only_hint: false,
            chain_id_required: true,
            value_kind: crate::policy::ToolValueKind::ReadOnly,
        })
    }

    fn test_profile() -> Profile {
        Profile::builder_testnet("alice", "acct", "n-svc", "n-acct").build()
    }

    fn eval_first_criterion(
        doc: &PolicyDocument,
        tool: &ToolDescriptor,
        args: &serde_json::Value,
        store: &PolicyStateStore,
        account_view: Option<&dyn AccountReservesView>,
    ) -> Option<DenyReason> {
        let profile = test_profile();
        let ctx = EvalContext {
            tool,
            args,
            profile_name: "alice",
            profile: &profile,
            // This helper emulates the dispatch gate for criterion tests, so it
            // derives the value descriptor exactly as the gate does. Non-value
            // criteria (rate limits, session guards) and tools this derivation
            // does not recognise resolve to ReadOnly and are unaffected.
            value: crate::policy::v1::value::derive_value_class(tool.name.as_str(), args),
            account_view,
            identity_view: None,
            quorum: None,
            counterparty_cache: None,
            sep10_sessions: None,
            sep45_sessions: None,
            state_store: store,
            bundle: None,
        };
        doc.rules[0].criteria[0]
            .evaluate(&ctx)
            .expect("criterion evaluation must succeed")
    }

    const MINIMAL_BODY: &str = "version = 1\nscope = \"profile:alice\"\n";

    const BODY_WITH_RULES: &str = r#"version = 1
scope = "profile:alice"

[[rules]]
match = { tool = "stellar_pay", chain = "*" }
criteria = []
decision = "allow"
"#;

    // ── load_signed_policy_success ────────────────────────────────────────────

    #[test]
    fn load_signed_policy_success() {
        let (sk, pk) = make_keypair();
        let dir = TempDir::new().unwrap();
        let toml = make_signed_toml(BODY_WITH_RULES, &sk, "GABCDE");
        let path = write_policy(&dir, "alice.toml", &toml);

        let doc = load_signed_policy(&path, "alice", &pk).unwrap();
        assert_eq!(doc.version, 1);
        assert!(doc.signature.is_some());
        assert_eq!(doc.rules.len(), 1);
        assert_eq!(doc.rules[0].r#match.tool, "stellar_pay");
    }

    // ── load_signed_policy_invalid_signature_rejected ─────────────────────────

    #[test]
    fn load_signed_policy_invalid_signature_rejected() {
        let (sk, _pk) = make_keypair();
        let (_sk2, pk2) = make_keypair();
        let dir = TempDir::new().unwrap();
        let toml = make_signed_toml(MINIMAL_BODY, &sk, "GABCDE");
        let path = write_policy(&dir, "alice.toml", &toml);

        // Use the wrong public key — verification must fail.
        let err = load_signed_policy(&path, "alice", &pk2).unwrap_err();
        assert!(
            matches!(err, PolicyError::OwnerSignatureInvalid { ref profile } if profile == "alice"),
            "expected OwnerSignatureInvalid, got {err:?}"
        );
    }

    // ── load_signed_policy_missing_signature_rejected ─────────────────────────

    #[test]
    fn load_signed_policy_missing_signature_rejected() {
        let (_sk, pk) = make_keypair();
        let dir = TempDir::new().unwrap();
        // Policy without a [signature] table.
        let path = write_policy(&dir, "alice.toml", MINIMAL_BODY);

        let err = load_signed_policy(&path, "alice", &pk).unwrap_err();
        assert!(
            matches!(err, PolicyError::PolicyFileParseFailed { .. }),
            "missing [signature] must produce PolicyFileParseFailed, got {err:?}"
        );
    }

    // ── load_signed_policy_corrupted_toml_rejected ────────────────────────────

    #[test]
    fn load_signed_policy_corrupted_toml_rejected() {
        let (_sk, pk) = make_keypair();
        let dir = TempDir::new().unwrap();
        let path = write_policy(&dir, "alice.toml", "not valid toml [[[");

        let err = load_signed_policy(&path, "alice", &pk).unwrap_err();
        assert!(
            matches!(err, PolicyError::PolicyFileParseFailed { .. }),
            "invalid TOML must produce PolicyFileParseFailed, got {err:?}"
        );
    }

    // ── load_signed_policy_missing_file_rejected ──────────────────────────────

    #[test]
    fn load_signed_policy_missing_file_rejected() {
        let (_sk, pk) = make_keypair();
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("does_not_exist.toml");

        let err = load_signed_policy(&path, "alice", &pk).unwrap_err();
        assert!(
            matches!(err, PolicyError::PolicyFileLoadFailed { .. }),
            "missing file must produce PolicyFileLoadFailed, got {err:?}"
        );
    }

    #[test]
    fn policy_file_load_failed_redacts_full_path() -> Result<(), String> {
        let (_sk, pk) = make_keypair();
        let dir = TempDir::new().unwrap();
        let parent = dir.path().join("operator-pii-parent");
        let path = parent.join("alice.toml");

        let err = load_signed_policy(&path, "alice", &pk).unwrap_err();
        let detail = match err {
            PolicyError::PolicyFileLoadFailed { detail } => detail,
            other => return Err(format!("expected PolicyFileLoadFailed, got {other:?}")),
        };

        assert!(
            detail.contains("alice.toml"),
            "basename should remain available for debugging"
        );
        assert!(
            !detail.contains(parent.to_string_lossy().as_ref()),
            "full parent directory must be redacted from load error detail"
        );
        Ok(())
    }

    // ── load_signed_policy_zero_rules_accepted ────────────────────────────────

    #[test]
    fn load_signed_policy_zero_rules_accepted() {
        let (sk, pk) = make_keypair();
        let dir = TempDir::new().unwrap();
        let toml = make_signed_toml(MINIMAL_BODY, &sk, "GABCDE");
        let path = write_policy(&dir, "alice.toml", &toml);

        let doc = load_signed_policy(&path, "alice", &pk).unwrap();
        assert!(doc.rules.is_empty(), "zero-rule document must be accepted");
        assert_eq!(doc.version, 1);
    }

    // ── parse_scope_string tests ──────────────────────────────────────────────

    #[test]
    fn parse_scope_profile_default() {
        let s = parse_scope_string("profile:default").unwrap();
        assert!(matches!(s, ScopeId::Profile(p) if p == "default"));
    }

    #[test]
    fn parse_scope_all_profiles() {
        let s = parse_scope_string("profile:*").unwrap();
        assert!(matches!(s, ScopeId::AllProfiles));
    }

    #[test]
    fn parse_scope_profile_project() {
        let s = parse_scope_string("profile:alice,project:payments").unwrap();
        assert!(
            matches!(s, ScopeId::ProfileProject { ref profile, ref project }
                if profile == "alice" && project == "payments")
        );
    }

    #[test]
    fn parse_scope_invalid_prefix_rejected() {
        let err = parse_scope_string("user:alice").unwrap_err();
        assert!(matches!(err, PolicyError::PolicyFileParseFailed { .. }));
    }

    // ── scope_id_specificity ──────────────────────────────────────────────────

    #[test]
    fn scope_id_specificity_all_profiles_returns_1() {
        assert_eq!(ScopeId::AllProfiles.specificity(), 1);
    }

    #[test]
    fn scope_id_specificity_profile_returns_2() {
        assert_eq!(ScopeId::Profile("alice".into()).specificity(), 2);
    }

    #[test]
    fn scope_id_specificity_profile_project_returns_3() {
        let s = ScopeId::ProfileProject {
            profile: "alice".into(),
            project: "p1".into(),
        };
        assert_eq!(s.specificity(), 3);
    }

    // ── scope_id_matches ──────────────────────────────────────────────────────

    #[test]
    fn scope_id_all_profiles_matches_any_profile_and_any_project() {
        let s = ScopeId::AllProfiles;
        assert!(s.matches("alice", None));
        assert!(s.matches("alice", Some("proj")));
        assert!(s.matches("bob", Some("other")));
    }

    #[test]
    fn scope_id_profile_matches_correct_profile_no_project() {
        let s = ScopeId::Profile("alice".into());
        assert!(s.matches("alice", None));
        assert!(!s.matches("bob", None));
    }

    #[test]
    fn scope_id_profile_does_not_require_no_project() {
        // Profile scope matches alice even with a project set.
        let s = ScopeId::Profile("alice".into());
        assert!(s.matches("alice", Some("p1")));
        assert!(!s.matches("bob", Some("p1")));
    }

    #[test]
    fn scope_id_profile_project_requires_both_matching() {
        let s = ScopeId::ProfileProject {
            profile: "alice".into(),
            project: "p1".into(),
        };
        assert!(s.matches("alice", Some("p1")));
        assert!(!s.matches("alice", None));
        assert!(!s.matches("alice", Some("p2")));
        assert!(!s.matches("bob", Some("p1")));
    }

    #[test]
    fn load_signed_policy_rejects_cross_profile_scope_replay() {
        let (sk, pk) = make_keypair();
        let dir = TempDir::new().unwrap();
        let body = "version = 1\nscope = \"profile:bob\"\n";
        let toml = make_signed_toml(body, &sk, "GABCDE");
        let path = write_policy(&dir, "bob.toml", &toml);

        let err = load_signed_policy(&path, "alice", &pk).unwrap_err();
        assert!(
            matches!(
                err,
                PolicyError::PolicyFileParseFailed { ref detail }
                    if detail.contains("policy scope does not match profile `alice`")
            ),
            "cross-profile replay must fail at scope check, got {err:?}"
        );
    }

    #[test]
    fn load_signed_policy_accepts_profile_project_for_same_profile() {
        let (sk, pk) = make_keypair();
        let dir = TempDir::new().unwrap();
        let body = "version = 1\nscope = \"profile:alice,project:p1\"\n";
        let toml = make_signed_toml(body, &sk, "GABCDE");
        let path = write_policy(&dir, "alice-p1.toml", &toml);

        let doc = load_signed_policy(&path, "alice", &pk).unwrap();
        assert!(
            matches!(
                doc.scope,
                ScopeId::ProfileProject { ref profile, ref project }
                    if profile == "alice" && project == "p1"
            ),
            "same-profile project-scoped policy must load"
        );
    }

    // ── rule_match tests ──────────────────────────────────────────────────────

    #[test]
    fn rule_match_wildcard_tool_matches_any_tool() {
        let m = RuleMatch {
            tool: "*".into(),
            chain: "stellar:testnet".into(),
        };
        let mut td =
            crate::policy::ToolDescriptor::from_registration(&crate::policy::McpToolRegistration {
                name: "stellar_pay",
                destructive_hint: true,
                read_only_hint: false,
                chain_id_required: true,
                value_kind: crate::policy::ToolValueKind::ReadOnly,
            });
        td.chain_id = "stellar:testnet".into();
        assert!(m.matches(&td));
    }

    #[test]
    fn rule_match_exact_name_and_chain_matches() {
        let m = RuleMatch {
            tool: "stellar_pay".into(),
            chain: "stellar:mainnet".into(),
        };
        let mut td =
            crate::policy::ToolDescriptor::from_registration(&crate::policy::McpToolRegistration {
                name: "stellar_pay",
                destructive_hint: true,
                read_only_hint: false,
                chain_id_required: true,
                value_kind: crate::policy::ToolValueKind::ReadOnly,
            });
        td.chain_id = "stellar:mainnet".into();
        assert!(m.matches(&td));
    }

    #[test]
    fn rule_match_wrong_tool_name_does_not_match() {
        let m = RuleMatch {
            tool: "stellar_pay".into(),
            chain: "*".into(),
        };
        let td =
            crate::policy::ToolDescriptor::from_registration(&crate::policy::McpToolRegistration {
                name: "stellar_balances",
                destructive_hint: false,
                read_only_hint: true,
                chain_id_required: true,
                value_kind: crate::policy::ToolValueKind::ReadOnly,
            });
        assert!(!m.matches(&td));
    }

    #[test]
    fn policy_rule_matches_tool_rejects_wrong_tool() {
        let rule = PolicyRule {
            r#match: RuleMatch {
                tool: "stellar_pay".into(),
                chain: "*".into(),
            },
            criteria: vec![],
            decision: Decision::Allow,
            allow_opaque_signing: false,
        };
        let tool =
            crate::policy::ToolDescriptor::from_registration(&crate::policy::McpToolRegistration {
                name: "stellar_create_account",
                destructive_hint: true,
                read_only_hint: false,
                chain_id_required: true,
                value_kind: crate::policy::ToolValueKind::ReadOnly,
            });

        assert!(
            !rule.matches_tool(&tool),
            "PolicyRule::matches_tool must delegate to RuleMatch instead of accepting every tool"
        );
    }

    #[test]
    fn policy_rule_matches_tool_accepts_correct_tool() {
        let rule = PolicyRule {
            r#match: RuleMatch {
                tool: "stellar_pay".into(),
                chain: "*".into(),
            },
            criteria: vec![],
            decision: Decision::Allow,
            allow_opaque_signing: false,
        };
        let tool =
            crate::policy::ToolDescriptor::from_registration(&crate::policy::McpToolRegistration {
                name: "stellar_pay",
                destructive_hint: true,
                read_only_hint: false,
                chain_id_required: true,
                value_kind: crate::policy::ToolValueKind::ReadOnly,
            });

        assert!(
            rule.matches_tool(&tool),
            "PolicyRule::matches_tool must accept a matching tool name"
        );
    }

    // ── hex_to_bytes ──────────────────────────────────────────────────────────

    #[test]
    fn hex_to_bytes_valid_even_length() {
        let b = hex_to_bytes("deadbeef").unwrap();
        assert_eq!(b, vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn hex_to_bytes_odd_length_returns_none() {
        assert!(hex_to_bytes("abc").is_none());
    }

    #[test]
    fn hex_to_bytes_invalid_chars_returns_none() {
        assert!(hex_to_bytes("gg").is_none());
    }

    // ── version range tests ───────────────────────────────────────────────────

    #[test]
    fn version_below_min_rejected() {
        let (sk, pk) = make_keypair();
        let dir = TempDir::new().unwrap();
        let body = "version = 0\nscope = \"profile:alice\"\n";
        let toml = make_signed_toml(body, &sk, "GABCDE");
        let path = write_policy(&dir, "alice.toml", &toml);

        let err = load_signed_policy(&path, "alice", &pk).unwrap_err();
        assert!(
            matches!(err, PolicyError::PolicyFileParseFailed { ref detail } if detail.contains("minimum")),
            "version 0 should be rejected with PolicyFileParseFailed (minimum version), got {err:?}"
        );
    }

    #[test]
    fn version_above_max_rejected() {
        let (sk, pk) = make_keypair();
        let dir = TempDir::new().unwrap();
        let body = "version = 2\nscope = \"profile:alice\"\n";
        let toml = make_signed_toml(body, &sk, "GABCDE");
        let path = write_policy(&dir, "alice.toml", &toml);

        let err = load_signed_policy(&path, "alice", &pk).unwrap_err();
        assert!(
            matches!(err, PolicyError::PolicyFileParseFailed { ref detail } if detail.contains("maximum")),
            "version 2 should be rejected with PolicyFileParseFailed (maximum version), got {err:?}"
        );
    }

    // ── criterion success tests (one per kind) ────────────────────────────────

    fn body_with_criterion(criterion_toml: &str) -> String {
        format!(
            r#"version = 1
scope = "profile:alice"

[[rules]]
match = {{ tool = "stellar_pay", chain = "*" }}
criteria = [{criterion_toml}]
decision = "allow"
"#
        )
    }

    fn body_with_decision(decision_toml: &str) -> String {
        format!(
            r#"version = 1
scope = "profile:alice"

[[rules]]
match = {{ tool = "stellar_pay", chain = "*" }}
criteria = []
{decision_toml}
"#
        )
    }

    #[test]
    fn criterion_per_tx_cap_loads_correctly() {
        let (sk, pk) = make_keypair();
        let dir = TempDir::new().unwrap();
        let body = body_with_criterion(
            r#"{ kind = "per_tx_cap", asset = "native", max_stroops = 1000000000 }"#,
        );
        let toml = make_signed_toml(&body, &sk, "GABCDE");
        let path = write_policy(&dir, "alice.toml", &toml);

        let doc = load_signed_policy(&path, "alice", &pk).unwrap();
        assert_eq!(doc.rules.len(), 1);
        assert_eq!(doc.rules[0].criteria.len(), 1);
        assert_eq!(doc.rules[0].criteria[0].kind(), "per_tx_cap");
    }

    #[test]
    fn criterion_per_tx_cap_allows_zero_max_stroops() {
        let (sk, pk) = make_keypair();
        let dir = TempDir::new().unwrap();
        let body =
            body_with_criterion(r#"{ kind = "per_tx_cap", asset = "native", max_stroops = 0 }"#);
        let toml = make_signed_toml(&body, &sk, "GABCDE");
        let path = write_policy(&dir, "alice.toml", &toml);

        let doc = load_signed_policy(&path, "alice", &pk).unwrap();
        assert_eq!(doc.rules[0].criteria[0].kind(), "per_tx_cap");

        let tool = test_tool("stellar_pay");
        let args = json!({ "amount": "0.0000001 XLM", "asset": "native" });
        let store = PolicyStateStore::new();
        let deny = eval_first_criterion(&doc, &tool, &args, &store, None);
        assert!(
            matches!(deny, Some(DenyReason::PerTxCapExceeded { .. })),
            "zero per_tx_cap must deny any positive spend"
        );
    }

    #[test]
    fn criterion_per_period_cap_loads_correctly() {
        let (sk, pk) = make_keypair();
        let dir = TempDir::new().unwrap();
        let body = body_with_criterion(
            r#"{ kind = "per_period_cap", asset = "native", window = "1d", max_stroops = 5000000000 }"#,
        );
        let toml = make_signed_toml(&body, &sk, "GABCDE");
        let path = write_policy(&dir, "alice.toml", &toml);

        let doc = load_signed_policy(&path, "alice", &pk).unwrap();
        assert_eq!(doc.rules[0].criteria.len(), 1);
        assert_eq!(doc.rules[0].criteria[0].kind(), "per_period_cap");
    }

    #[test]
    fn criterion_per_period_cap_allows_zero_max_stroops() {
        let (sk, pk) = make_keypair();
        let dir = TempDir::new().unwrap();
        let body = body_with_criterion(
            r#"{ kind = "per_period_cap", asset = "native", window = "1d", max_stroops = 0 }"#,
        );
        let toml = make_signed_toml(&body, &sk, "GABCDE");
        let path = write_policy(&dir, "alice.toml", &toml);

        let doc = load_signed_policy(&path, "alice", &pk).unwrap();
        assert_eq!(doc.rules[0].criteria[0].kind(), "per_period_cap");

        let tool = test_tool("stellar_pay");
        let args = json!({ "amount": "0.0000001 XLM", "asset": "native" });
        let store = PolicyStateStore::new();
        let deny = eval_first_criterion(&doc, &tool, &args, &store, None);
        assert!(
            matches!(deny, Some(DenyReason::PerPeriodCapExceeded { .. })),
            "zero per_period_cap must deny any positive spend"
        );
    }

    #[test]
    fn criterion_rate_limit_loads_correctly() {
        let (sk, pk) = make_keypair();
        let dir = TempDir::new().unwrap();
        let body = body_with_criterion(r#"{ kind = "rate_limit", window = "1h", max_calls = 10 }"#);
        let toml = make_signed_toml(&body, &sk, "GABCDE");
        let path = write_policy(&dir, "alice.toml", &toml);

        let doc = load_signed_policy(&path, "alice", &pk).unwrap();
        assert_eq!(doc.rules[0].criteria.len(), 1);
        assert_eq!(doc.rules[0].criteria[0].kind(), "rate_limit");
    }

    #[test]
    fn criterion_counterparty_allowlist_loads_correctly() {
        let (sk, pk) = make_keypair();
        let dir = TempDir::new().unwrap();
        // Use a valid G-strkey in the allowlist.
        let body = body_with_criterion(
            r#"{ kind = "counterparty_allowlist", kinds = ["G_ACCOUNT"], allowlist = ["GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN"] }"#,
        );
        let toml = make_signed_toml(&body, &sk, "GABCDE");
        let path = write_policy(&dir, "alice.toml", &toml);

        let doc = load_signed_policy(&path, "alice", &pk).unwrap();
        assert_eq!(doc.rules[0].criteria.len(), 1);
        assert_eq!(doc.rules[0].criteria[0].kind(), "counterparty_allowlist");
    }

    #[test]
    fn criterion_minimum_reserve_loads_correctly() {
        let (sk, pk) = make_keypair();
        let dir = TempDir::new().unwrap();
        let body =
            body_with_criterion(r#"{ kind = "minimum_reserve", margin_stroops = 10000000 }"#);
        let toml = make_signed_toml(&body, &sk, "GABCDE");
        let path = write_policy(&dir, "alice.toml", &toml);

        let doc = load_signed_policy(&path, "alice", &pk).unwrap();
        assert_eq!(doc.rules[0].criteria.len(), 1);
        assert_eq!(doc.rules[0].criteria[0].kind(), "minimum_reserve");
    }

    #[test]
    fn criterion_minimum_reserve_allows_zero_margin_stroops() {
        let (sk, pk) = make_keypair();
        let dir = TempDir::new().unwrap();
        let body = body_with_criterion(r#"{ kind = "minimum_reserve", margin_stroops = 0 }"#);
        let toml = make_signed_toml(&body, &sk, "GABCDE");
        let path = write_policy(&dir, "alice.toml", &toml);

        let doc = load_signed_policy(&path, "alice", &pk).unwrap();
        assert_eq!(doc.rules[0].criteria[0].kind(), "minimum_reserve");

        let tool = test_tool("stellar_pay");
        let args = json!({ "amount": "1 XLM", "asset": "native", "fee_stroops": 0 });
        let store = PolicyStateStore::new();
        let view = LoaderTestAccountView {
            balance: 10_000_000,
            reserves: 10_000_000,
        };
        let deny = eval_first_criterion(&doc, &tool, &args, &store, Some(&view));
        assert!(
            matches!(deny, Some(DenyReason::MinimumReserveBreached { .. })),
            "zero minimum_reserve margin still enforces the protocol reserve floor"
        );
    }

    #[test]
    fn criterion_soroban_resource_fee_cap_loads_correctly() {
        let (sk, pk) = make_keypair();
        let dir = TempDir::new().unwrap();
        let body = body_with_criterion(
            r#"{ kind = "soroban_resource_fee_cap", max_resource_fee_stroops = 100000000, max_footprint_entries = 50 }"#,
        );
        let toml = make_signed_toml(&body, &sk, "GABCDE");
        let path = write_policy(&dir, "alice.toml", &toml);

        let doc = load_signed_policy(&path, "alice", &pk).unwrap();
        assert_eq!(doc.rules[0].criteria.len(), 1);
        assert_eq!(doc.rules[0].criteria[0].kind(), "soroban_resource_fee_cap");
    }

    #[test]
    fn criterion_soroban_resource_fee_cap_allows_zero_resource_fee() {
        let (sk, pk) = make_keypair();
        let dir = TempDir::new().unwrap();
        let body = body_with_criterion(
            r#"{ kind = "soroban_resource_fee_cap", max_resource_fee_stroops = 0, max_footprint_entries = 50 }"#,
        );
        let toml = make_signed_toml(&body, &sk, "GABCDE");
        let path = write_policy(&dir, "alice.toml", &toml);

        let doc = load_signed_policy(&path, "alice", &pk).unwrap();
        assert_eq!(doc.rules[0].criteria[0].kind(), "soroban_resource_fee_cap");

        let tool = test_tool("stellar_invoke_contract");
        let args = json!({ "resource_fee_stroops": 1, "footprint_entries": 1 });
        let store = PolicyStateStore::new();
        let deny = eval_first_criterion(&doc, &tool, &args, &store, None);
        assert!(
            matches!(deny, Some(DenyReason::EvaluationError { .. })),
            "zero soroban resource-fee cap must deny any positive resource fee"
        );
    }

    /// Standard-table `match` syntax is intentionally accepted as an alternate to inline tables.
    #[test]
    fn extract_str_field_from_standard_table_match_item() {
        let doc = DocumentMut::from_str(
            r#"
[match]
tool = "stellar_pay"
chain = "*"
"#,
        )
        .unwrap();
        let item = doc.get("match").unwrap();

        assert_eq!(
            extract_str_field_from_item(item, "tool", 0).unwrap(),
            "stellar_pay"
        );
        assert_eq!(extract_str_field_from_item(item, "chain", 0).unwrap(), "*");
    }

    #[test]
    fn parse_rule_match_rejects_empty_tool() {
        let doc = DocumentMut::from_str(r#"match = { tool = "", chain = "*" }"#).unwrap();
        let item = doc.get("match").unwrap();

        let err = parse_rule_match(item, 7).unwrap_err();
        assert!(
            matches!(
                err,
                PolicyError::PolicyFileParseFailed { ref detail }
                    if detail.contains("rule[7]")
                        && detail.contains("match.tool")
                        && detail.contains("must not be empty")
            ),
            "empty match.tool must fail closed with field-specific detail, got {err:?}"
        );
    }

    #[test]
    fn parse_rule_match_rejects_empty_chain() {
        let doc = DocumentMut::from_str(r#"match = { tool = "stellar_pay", chain = "" }"#).unwrap();
        let item = doc.get("match").unwrap();

        let err = parse_rule_match(item, 3).unwrap_err();
        assert!(
            matches!(
                err,
                PolicyError::PolicyFileParseFailed { ref detail }
                    if detail.contains("rule[3]")
                        && detail.contains("match.chain")
                        && detail.contains("must not be empty")
            ),
            "empty match.chain must fail closed with field-specific detail, got {err:?}"
        );
    }

    #[test]
    fn parse_rule_match_accepts_wildcard_tool_and_non_empty_chain() {
        let doc =
            DocumentMut::from_str(r#"match = { tool = "*", chain = "stellar:testnet" }"#).unwrap();
        let item = doc.get("match").unwrap();

        let parsed = parse_rule_match(item, 0).unwrap();
        assert_eq!(parsed.tool, "*");
        assert_eq!(parsed.chain, "stellar:testnet");
    }

    // ── criterion failure tests ───────────────────────────────────────────────

    #[test]
    fn unknown_criterion_kind_rejected() {
        let (sk, pk) = make_keypair();
        let dir = TempDir::new().unwrap();
        let body = body_with_criterion(r#"{ kind = "made_up_thing", foo = 1 }"#);
        let toml = make_signed_toml(&body, &sk, "GABCDE");
        let path = write_policy(&dir, "alice.toml", &toml);

        let err = load_signed_policy(&path, "alice", &pk).unwrap_err();
        assert!(
            matches!(err, PolicyError::PolicyFileParseFailed { ref detail } if detail.contains("made_up_thing")),
            "unknown criterion kind should produce PolicyFileParseFailed, got {err:?}"
        );
    }

    #[test]
    fn missing_required_criterion_field_rejected() {
        let (sk, pk) = make_keypair();
        let dir = TempDir::new().unwrap();
        // per_tx_cap missing `max_stroops`.
        let body = body_with_criterion(r#"{ kind = "per_tx_cap", asset = "native" }"#);
        let toml = make_signed_toml(&body, &sk, "GABCDE");
        let path = write_policy(&dir, "alice.toml", &toml);

        let err = load_signed_policy(&path, "alice", &pk).unwrap_err();
        assert!(
            matches!(err, PolicyError::PolicyFileParseFailed { ref detail } if detail.contains("max_stroops")),
            "missing max_stroops should produce PolicyFileParseFailed mentioning the field, got {err:?}"
        );
    }

    #[test]
    fn negative_max_stroops_rejected() {
        let (sk, pk) = make_keypair();
        let dir = TempDir::new().unwrap();
        let body =
            body_with_criterion(r#"{ kind = "per_tx_cap", asset = "native", max_stroops = -1 }"#);
        let toml = make_signed_toml(&body, &sk, "GABCDE");
        let path = write_policy(&dir, "alice.toml", &toml);

        let err = load_signed_policy(&path, "alice", &pk).unwrap_err();
        assert!(
            matches!(err, PolicyError::PolicyFileParseFailed { .. }),
            "negative max_stroops should produce PolicyFileParseFailed, got {err:?}"
        );
    }

    #[test]
    fn invalid_window_string_rejected() {
        let (sk, pk) = make_keypair();
        let dir = TempDir::new().unwrap();
        let body =
            body_with_criterion(r#"{ kind = "rate_limit", window = "never", max_calls = 5 }"#);
        let toml = make_signed_toml(&body, &sk, "GABCDE");
        let path = write_policy(&dir, "alice.toml", &toml);

        let err = load_signed_policy(&path, "alice", &pk).unwrap_err();
        assert!(
            matches!(err, PolicyError::PolicyFileParseFailed { ref detail } if detail.contains("never")),
            "invalid window string should produce PolicyFileParseFailed, got {err:?}"
        );
    }

    #[test]
    fn unknown_counterparty_kind_rejected() {
        let (sk, pk) = make_keypair();
        let dir = TempDir::new().unwrap();
        let body = body_with_criterion(
            r#"{ kind = "counterparty_allowlist", kinds = ["address"], allowlist = [] }"#,
        );
        let toml = make_signed_toml(&body, &sk, "GABCDE");
        let path = write_policy(&dir, "alice.toml", &toml);

        let err = load_signed_policy(&path, "alice", &pk).unwrap_err();
        assert!(
            matches!(err, PolicyError::PolicyFileParseFailed { .. }),
            "unknown counterparty kind should produce PolicyFileParseFailed, got {err:?}"
        );
    }

    /// A `HOME_DOMAIN` allowlist entry that contains non-ASCII bytes (Cyrillic
    /// 'с' U+0441 encoded as two UTF-8 bytes) must be rejected at parse time
    /// with `PolicyFileParseFailed`.  This prevents silent-deny scenarios where
    /// an operator pastes a visually-similar but byte-different domain.
    #[test]
    fn home_domain_allowlist_entry_with_non_ascii_bytes_rejected() {
        let (sk, pk) = make_keypair();
        let dir = TempDir::new().unwrap();
        // The allowlist entry "\u{0441}ircle.com" starts with Cyrillic 'с'
        // (U+0441), encoded as 0xD1 0x81 in UTF-8.  The TOML string is valid
        // UTF-8 but contains non-ASCII bytes.
        let body = body_with_criterion(
            "{ kind = \"counterparty_allowlist\", kinds = [\"HOME_DOMAIN\"], allowlist = [\"\u{0441}ircle.com\"] }",
        );
        let toml = make_signed_toml(&body, &sk, "GABCDE");
        let path = write_policy(&dir, "alice.toml", &toml);

        let err = load_signed_policy(&path, "alice", &pk).unwrap_err();
        assert!(
            matches!(
                err,
                PolicyError::PolicyFileParseFailed { ref detail }
                    if detail.contains("non-ASCII")
            ),
            "non-ASCII HOME_DOMAIN allowlist entry should produce \
             PolicyFileParseFailed mentioning non-ASCII, got {err:?}"
        );
    }

    /// A `HOME_DOMAIN` kind with a mixed allowlist where one entry is ASCII and
    /// one is not.  The second (non-ASCII) entry must trigger the rejection
    /// regardless of the position of the invalid entry.
    #[test]
    fn home_domain_allowlist_second_entry_non_ascii_rejected() {
        let (sk, pk) = make_keypair();
        let dir = TempDir::new().unwrap();
        // First entry is valid ASCII; second contains a non-ASCII byte.
        let body = body_with_criterion(
            "{ kind = \"counterparty_allowlist\", kinds = [\"HOME_DOMAIN\"], allowlist = [\"circle.com\", \"caf\u{00e9}.com\"] }",
        );
        let toml = make_signed_toml(&body, &sk, "GABCDE");
        let path = write_policy(&dir, "alice.toml", &toml);

        let err = load_signed_policy(&path, "alice", &pk).unwrap_err();
        assert!(
            matches!(
                err,
                PolicyError::PolicyFileParseFailed { ref detail }
                    if detail.contains("non-ASCII")
            ),
            "second non-ASCII HOME_DOMAIN entry should produce \
             PolicyFileParseFailed, got {err:?}"
        );
    }

    /// A `HOME_DOMAIN` allowlist entry with uppercase ASCII letters must be
    /// rejected at policy-load time.
    #[test]
    fn home_domain_allowlist_entry_with_uppercase_rejected() {
        let (sk, pk) = make_keypair();
        let dir = TempDir::new().unwrap();
        // "Circle.com" contains uppercase 'C'.
        let body = body_with_criterion(
            r#"{ kind = "counterparty_allowlist", kinds = ["HOME_DOMAIN"], allowlist = ["Circle.com"] }"#,
        );
        let toml = make_signed_toml(&body, &sk, "GABCDE");
        let path = write_policy(&dir, "alice.toml", &toml);

        let err = load_signed_policy(&path, "alice", &pk).unwrap_err();
        assert!(
            matches!(
                err,
                PolicyError::PolicyFileParseFailed { ref detail }
                    if detail.contains("uppercase")
            ),
            "uppercase HOME_DOMAIN entry should produce PolicyFileParseFailed mentioning uppercase, \
             got {err:?}"
        );
    }

    /// `HOME_DOMAIN` allowlist entries route through the shared LDH
    /// helper, which rejects underscores and other printable ASCII that are
    /// invalid in RFC 1035 LDH hostnames.
    #[test]
    fn home_domain_allowlist_entry_with_underscore_rejected() {
        let (sk, pk) = make_keypair();
        let dir = TempDir::new().unwrap();
        let body = body_with_criterion(
            r#"{ kind = "counterparty_allowlist", kinds = ["HOME_DOMAIN"], allowlist = ["circle_pay.com"] }"#,
        );
        let toml = make_signed_toml(&body, &sk, "GABCDE");
        let path = write_policy(&dir, "alice.toml", &toml);

        let err = load_signed_policy(&path, "alice", &pk).unwrap_err();
        assert!(
            matches!(
                err,
                PolicyError::PolicyFileParseFailed { ref detail }
                    if detail.contains("HOME_DOMAIN")
            ),
            "underscore HOME_DOMAIN entry should produce PolicyFileParseFailed, got {err:?}"
        );
    }

    #[test]
    fn require_approval_with_reason_and_ttl_secs_propagates_both() -> Result<(), String> {
        let (sk, pk) = make_keypair();
        let dir = TempDir::new().unwrap();
        let body = body_with_decision(
            "decision = \"require_approval\"\nreason = \"high-value\"\nttl_secs = 600",
        );
        let toml = make_signed_toml(&body, &sk, "GABCDE");
        let path = write_policy(&dir, "alice.toml", &toml);

        let doc = load_signed_policy(&path, "alice", &pk).unwrap();
        let req = match &doc.rules[0].decision {
            Decision::RequireApproval(req) => req,
            other => return Err(format!("expected RequireApproval, got {other:?}")),
        };
        assert_eq!(req.nonce, "");
        assert_eq!(req.reason.as_deref(), Some("high-value"));
        assert_eq!(req.ttl_seconds, 600);
        Ok(())
    }

    #[test]
    fn require_approval_with_only_reason_uses_default_ttl() -> Result<(), String> {
        let (sk, pk) = make_keypair();
        let dir = TempDir::new().unwrap();
        let body =
            body_with_decision("decision = \"require_approval\"\nreason = \"manual-review\"");
        let toml = make_signed_toml(&body, &sk, "GABCDE");
        let path = write_policy(&dir, "alice.toml", &toml);

        let doc = load_signed_policy(&path, "alice", &pk).unwrap();
        let req = match &doc.rules[0].decision {
            Decision::RequireApproval(req) => req,
            other => return Err(format!("expected RequireApproval, got {other:?}")),
        };
        assert_eq!(req.nonce, "");
        assert_eq!(req.reason.as_deref(), Some("manual-review"));
        assert_eq!(req.ttl_seconds, DEFAULT_APPROVAL_TTL_SECONDS);
        Ok(())
    }

    #[test]
    fn require_approval_with_only_ttl_uses_empty_reason() -> Result<(), String> {
        let (sk, pk) = make_keypair();
        let dir = TempDir::new().unwrap();
        let body = body_with_decision("decision = \"require_approval\"\nttl_secs = 600");
        let toml = make_signed_toml(&body, &sk, "GABCDE");
        let path = write_policy(&dir, "alice.toml", &toml);

        let doc = load_signed_policy(&path, "alice", &pk).unwrap();
        let req = match &doc.rules[0].decision {
            Decision::RequireApproval(req) => req,
            other => return Err(format!("expected RequireApproval, got {other:?}")),
        };
        assert_eq!(req.nonce, "");
        assert!(req.reason.is_none());
        assert_eq!(req.ttl_seconds, 600);
        Ok(())
    }

    #[test]
    fn allow_with_reason_field_is_rejected() {
        let (sk, pk) = make_keypair();
        let dir = TempDir::new().unwrap();
        let body = body_with_decision("decision = \"allow\"\nreason = \"manual-review\"");
        let toml = make_signed_toml(&body, &sk, "GABCDE");
        let path = write_policy(&dir, "alice.toml", &toml);

        let err = load_signed_policy(&path, "alice", &pk).unwrap_err();
        assert!(
            matches!(err, PolicyError::PolicyFileParseFailed { ref detail } if detail.contains("only valid")),
            "allow rule with reason should produce PolicyFileParseFailed, got {err:?}"
        );
    }

    #[test]
    fn require_approval_with_invalid_ttl_secs_is_rejected() {
        let (sk, pk) = make_keypair();
        let dir = TempDir::new().unwrap();
        let body = body_with_decision("decision = \"require_approval\"\nttl_secs = -1");
        let toml = make_signed_toml(&body, &sk, "GABCDE");
        let path = write_policy(&dir, "alice.toml", &toml);

        let err = load_signed_policy(&path, "alice", &pk).unwrap_err();
        assert!(
            matches!(err, PolicyError::PolicyFileParseFailed { ref detail } if detail.contains("ttl_secs")),
            "invalid ttl_secs should produce PolicyFileParseFailed, got {err:?}"
        );
    }

    // ── new bundle-criterion loader tests ────────────────────────────────────

    /// `inner_invocation_count_cap` with valid `max_count` parses and round-trips
    /// through `kind()`.
    #[test]
    fn inner_invocation_count_cap_parses_correctly() {
        let (sk, pk) = make_keypair();
        let dir = TempDir::new().unwrap();
        let body =
            body_with_criterion(r#"{ kind = "inner_invocation_count_cap", max_count = 25 }"#);
        let toml = make_signed_toml(&body, &sk, "GABCDE");
        let path = write_policy(&dir, "alice.toml", &toml);

        let doc = load_signed_policy(&path, "alice", &pk).unwrap();
        assert_eq!(doc.rules[0].criteria.len(), 1);
        assert_eq!(
            doc.rules[0].criteria[0].kind(),
            "inner_invocation_count_cap"
        );
    }

    /// `inner_invocation_count_cap` with a value that overflows `u32` is rejected.
    #[test]
    fn inner_invocation_count_cap_out_of_u32_range_rejected() {
        let (sk, pk) = make_keypair();
        let dir = TempDir::new().unwrap();
        // 2^32 overflows u32.
        let body = body_with_criterion(
            r#"{ kind = "inner_invocation_count_cap", max_count = 4294967296 }"#,
        );
        let toml = make_signed_toml(&body, &sk, "GABCDE");
        let path = write_policy(&dir, "alice.toml", &toml);

        let err = load_signed_policy(&path, "alice", &pk).unwrap_err();
        assert!(
            matches!(err, PolicyError::PolicyFileParseFailed { ref detail } if detail.contains("max_count")),
            "out-of-u32-range max_count must be rejected with PolicyFileParseFailed, got {err:?}"
        );
    }

    /// `bundle_aggregate_cap` with valid fields parses and round-trips.
    #[test]
    fn bundle_aggregate_cap_parses_correctly() {
        let (sk, pk) = make_keypair();
        let dir = TempDir::new().unwrap();
        let body = body_with_criterion(
            r#"{ kind = "bundle_aggregate_cap", asset = "native", max_amount = "10000000000" }"#,
        );
        let toml = make_signed_toml(&body, &sk, "GABCDE");
        let path = write_policy(&dir, "alice.toml", &toml);

        let doc = load_signed_policy(&path, "alice", &pk).unwrap();
        assert_eq!(doc.rules[0].criteria.len(), 1);
        assert_eq!(doc.rules[0].criteria[0].kind(), "bundle_aggregate_cap");
    }

    /// `bundle_aggregate_cap` with `asset` omitted (wildcard) parses correctly.
    #[test]
    fn bundle_aggregate_cap_without_asset_parses_correctly() {
        let (sk, pk) = make_keypair();
        let dir = TempDir::new().unwrap();
        let body =
            body_with_criterion(r#"{ kind = "bundle_aggregate_cap", max_amount = "999999" }"#);
        let toml = make_signed_toml(&body, &sk, "GABCDE");
        let path = write_policy(&dir, "alice.toml", &toml);

        let doc = load_signed_policy(&path, "alice", &pk).unwrap();
        assert_eq!(doc.rules[0].criteria[0].kind(), "bundle_aggregate_cap");
    }

    /// `bundle_aggregate_cap` with a non-i128-parseable `max_amount` is rejected.
    #[test]
    fn bundle_aggregate_cap_invalid_max_amount_rejected() {
        let (sk, pk) = make_keypair();
        let dir = TempDir::new().unwrap();
        let body = body_with_criterion(
            r#"{ kind = "bundle_aggregate_cap", max_amount = "not-a-number" }"#,
        );
        let toml = make_signed_toml(&body, &sk, "GABCDE");
        let path = write_policy(&dir, "alice.toml", &toml);

        let err = load_signed_policy(&path, "alice", &pk).unwrap_err();
        assert!(
            matches!(err, PolicyError::PolicyFileParseFailed { ref detail } if detail.contains("max_amount")),
            "non-parseable max_amount must be rejected, got {err:?}"
        );
    }

    /// `bundle_aggregate_cap` with a negative `max_amount` is rejected.
    #[test]
    fn bundle_aggregate_cap_negative_max_amount_rejected() {
        let (sk, pk) = make_keypair();
        let dir = TempDir::new().unwrap();
        let body = body_with_criterion(r#"{ kind = "bundle_aggregate_cap", max_amount = "-1" }"#);
        let toml = make_signed_toml(&body, &sk, "GABCDE");
        let path = write_policy(&dir, "alice.toml", &toml);

        let err = load_signed_policy(&path, "alice", &pk).unwrap_err();
        assert!(
            matches!(err, PolicyError::PolicyFileParseFailed { .. }),
            "negative max_amount must be rejected, got {err:?}"
        );
    }

    /// `restrict_bundle_to_recognised_kinds` with valid `enabled = true` parses.
    #[test]
    fn restrict_bundle_to_recognised_kinds_parses_correctly() {
        let (sk, pk) = make_keypair();
        let dir = TempDir::new().unwrap();
        let body = body_with_criterion(
            r#"{ kind = "restrict_bundle_to_recognised_kinds", enabled = true }"#,
        );
        let toml = make_signed_toml(&body, &sk, "GABCDE");
        let path = write_policy(&dir, "alice.toml", &toml);

        let doc = load_signed_policy(&path, "alice", &pk).unwrap();
        assert_eq!(doc.rules[0].criteria.len(), 1);
        assert_eq!(
            doc.rules[0].criteria[0].kind(),
            "restrict_bundle_to_recognised_kinds"
        );
    }

    /// `restrict_bundle_to_recognised_kinds` with missing `enabled` field is rejected.
    #[test]
    fn restrict_bundle_to_recognised_kinds_missing_enabled_rejected() {
        let (sk, pk) = make_keypair();
        let dir = TempDir::new().unwrap();
        let body = body_with_criterion(r#"{ kind = "restrict_bundle_to_recognised_kinds" }"#);
        let toml = make_signed_toml(&body, &sk, "GABCDE");
        let path = write_policy(&dir, "alice.toml", &toml);

        let err = load_signed_policy(&path, "alice", &pk).unwrap_err();
        assert!(
            matches!(err, PolicyError::PolicyFileParseFailed { ref detail } if detail.contains("enabled")),
            "missing enabled field must be rejected mentioning 'enabled', got {err:?}"
        );
    }

    // ── bundle-variant criteria loader tests ────────────────────────────────

    /// `bundle_per_period_cap` with valid fields parses and round-trips.
    #[test]
    fn bundle_per_period_cap_parses_correctly() {
        let (sk, pk) = make_keypair();
        let dir = TempDir::new().unwrap();
        let body = body_with_criterion(
            r#"{ kind = "bundle_per_period_cap", asset = "native", window = "1h", max_stroops = 5000000000 }"#,
        );
        let toml = make_signed_toml(&body, &sk, "GABCDE");
        let path = write_policy(&dir, "alice.toml", &toml);

        let doc = load_signed_policy(&path, "alice", &pk).unwrap();
        assert_eq!(doc.rules[0].criteria.len(), 1);
        assert_eq!(doc.rules[0].criteria[0].kind(), "bundle_per_period_cap");
    }

    /// `bundle_per_period_cap` with a negative `max_stroops` is rejected.
    #[test]
    fn bundle_per_period_cap_negative_max_stroops_rejected() {
        let (sk, pk) = make_keypair();
        let dir = TempDir::new().unwrap();
        let body = body_with_criterion(
            r#"{ kind = "bundle_per_period_cap", asset = "native", window = "1h", max_stroops = -1 }"#,
        );
        let toml = make_signed_toml(&body, &sk, "GABCDE");
        let path = write_policy(&dir, "alice.toml", &toml);

        let err = load_signed_policy(&path, "alice", &pk).unwrap_err();
        assert!(
            matches!(err, PolicyError::PolicyFileParseFailed { ref detail } if detail.contains("max_stroops")),
            "negative max_stroops must be rejected, got {err:?}"
        );
    }

    /// `bundle_per_period_cap` with unsupported window string is rejected.
    #[test]
    fn bundle_per_period_cap_unsupported_window_rejected() {
        let (sk, pk) = make_keypair();
        let dir = TempDir::new().unwrap();
        let body = body_with_criterion(
            r#"{ kind = "bundle_per_period_cap", asset = "native", window = "2h", max_stroops = 100 }"#,
        );
        let toml = make_signed_toml(&body, &sk, "GABCDE");
        let path = write_policy(&dir, "alice.toml", &toml);

        let err = load_signed_policy(&path, "alice", &pk).unwrap_err();
        assert!(
            matches!(err, PolicyError::PolicyFileParseFailed { ref detail } if detail.contains("window")),
            "unsupported window must be rejected mentioning 'window', got {err:?}"
        );
    }

    /// `bundle_per_tx_cap` with valid fields parses and round-trips.
    #[test]
    fn bundle_per_tx_cap_parses_correctly() {
        let (sk, pk) = make_keypair();
        let dir = TempDir::new().unwrap();
        let body = body_with_criterion(
            r#"{ kind = "bundle_per_tx_cap", asset = "native", max_stroops = 1000000000 }"#,
        );
        let toml = make_signed_toml(&body, &sk, "GABCDE");
        let path = write_policy(&dir, "alice.toml", &toml);

        let doc = load_signed_policy(&path, "alice", &pk).unwrap();
        assert_eq!(doc.rules[0].criteria.len(), 1);
        assert_eq!(doc.rules[0].criteria[0].kind(), "bundle_per_tx_cap");
    }

    /// `bundle_per_tx_cap` with a negative `max_stroops` is rejected.
    #[test]
    fn bundle_per_tx_cap_negative_max_stroops_rejected() {
        let (sk, pk) = make_keypair();
        let dir = TempDir::new().unwrap();
        let body = body_with_criterion(
            r#"{ kind = "bundle_per_tx_cap", asset = "native", max_stroops = -1 }"#,
        );
        let toml = make_signed_toml(&body, &sk, "GABCDE");
        let path = write_policy(&dir, "alice.toml", &toml);

        let err = load_signed_policy(&path, "alice", &pk).unwrap_err();
        assert!(
            matches!(err, PolicyError::PolicyFileParseFailed { ref detail } if detail.contains("max_stroops")),
            "negative max_stroops must be rejected, got {err:?}"
        );
    }

    /// `bundle_rate_limit` with valid fields parses and round-trips.
    #[test]
    fn bundle_rate_limit_parses_correctly() {
        let (sk, pk) = make_keypair();
        let dir = TempDir::new().unwrap();
        let body =
            body_with_criterion(r#"{ kind = "bundle_rate_limit", window = "1m", max_calls = 5 }"#);
        let toml = make_signed_toml(&body, &sk, "GABCDE");
        let path = write_policy(&dir, "alice.toml", &toml);

        let doc = load_signed_policy(&path, "alice", &pk).unwrap();
        assert_eq!(doc.rules[0].criteria.len(), 1);
        assert_eq!(doc.rules[0].criteria[0].kind(), "bundle_rate_limit");
    }

    /// `bundle_rate_limit` with unsupported window is rejected.
    #[test]
    fn bundle_rate_limit_unsupported_window_rejected() {
        let (sk, pk) = make_keypair();
        let dir = TempDir::new().unwrap();
        let body = body_with_criterion(
            r#"{ kind = "bundle_rate_limit", window = "never", max_calls = 5 }"#,
        );
        let toml = make_signed_toml(&body, &sk, "GABCDE");
        let path = write_policy(&dir, "alice.toml", &toml);

        let err = load_signed_policy(&path, "alice", &pk).unwrap_err();
        assert!(
            matches!(err, PolicyError::PolicyFileParseFailed { ref detail } if detail.contains("window")),
            "unsupported window must be rejected mentioning 'window', got {err:?}"
        );
    }

    // ── deny decision uses ExplicitRuleDeny ───────────────────────────────────

    #[test]
    fn deny_decision_uses_explicit_rule_deny() {
        let (sk, pk) = make_keypair();
        let dir = TempDir::new().unwrap();
        let body = r#"version = 1
scope = "profile:alice"

[[rules]]
match = { tool = "*", chain = "*" }
criteria = []
decision = "deny"
"#;
        let toml = make_signed_toml(body, &sk, "GABCDE");
        let path = write_policy(&dir, "alice.toml", &toml);

        let doc = load_signed_policy(&path, "alice", &pk).unwrap();
        assert_eq!(doc.rules.len(), 1);
        assert!(
            matches!(
                doc.rules[0].decision,
                Decision::Deny(DenyReason::ExplicitRuleDeny)
            ),
            "deny decision should carry ExplicitRuleDeny, got {:?}",
            doc.rules[0].decision
        );
    }
}
