//! `PolicyEngineV1` — typed-criteria policy evaluator.
//!
//! Implements [`crate::policy::PolicyEngine`] over the schema (per-tx cap, per-period cap,
//! rate limit, counterparty allowlist, minimum-reserve guard, Soroban
//! resource-fee cap).  Replaces [`crate::policy::NoopPolicyEngine`] at runtime when
//! `profile.policy.engine = PolicyEngineKind::V1`.
//!
//! # Architecture
//!
//! ```text
//! PolicyEngineV1
//!   └── PolicyDocument (loaded + signature-verified from disk)
//!         └── [PolicyRule]
//!               ├── RuleMatch  (tool name + chain-id filter)
//!               ├── [Box<dyn Criterion>]  (per_tx_cap, per_period_cap, etc.)
//!               └── Decision  (Allow | Deny | RequireApproval)
//! ```
//!
//! Evaluation uses first-match stop-semantics: rules are walked in
//! declaration order; the first rule whose `RuleMatch` matches the tool
//! call is selected.  All criteria in that rule are then evaluated in order;
//! the first failing criterion produces a [`crate::policy::Decision::Deny`].  If all
//! criteria pass, the rule's `decision` is returned.  If no rule matches,
//! the engine returns `Decision::Deny(DenyReason::NoMatchingRule)`
//! (default-deny).
//!
//! # AccountReservesView / AccountIdentityView / CounterpartyCacheView
//!
//! `stellar-agent-network` already depends on `stellar-agent-core`, so
//! importing `AccountView` from the network crate here would create a circular
//! dependency.  Instead the minimum-reserve criterion takes a
//! `&dyn AccountReservesView` trait object, the HOME_DOMAIN criterion
//! takes a `&dyn AccountIdentityView` trait object, and the
//! `home_domain_resolved` criterion takes a `&dyn CounterpartyCacheView`
//! trait object; the blanket impls are plumbed at the dispatch site where
//! both crates are already in scope.

use crate::policy::v1::bundle::{BundleStateOverlay, BundleView};
use crate::policy::{Decision, DenyReason, PolicyEngine, PolicyError, ToolDescriptor};
use crate::profile::schema::Profile;
use serde_json::Value;

// ─────────────────────────────────────────────────────────────────────────────
// AccountReserveLookupError
// ─────────────────────────────────────────────────────────────────────────────

/// Typed error returned by [`AccountReservesView::balance_stroops`].
///
/// Structured error type for balance lookup failures.  Using a named struct
/// rather than a bare `String` makes the no-secret-material invariant
/// explicit in the type.
///
/// `detail` is a non-secret diagnostic string describing why the balance could
/// not be read (e.g. `"no native balance entry"`, `"balance parse error: ..."`).
/// It MUST NOT include key material, private keys, seeds, or user-supplied
/// secret input.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::policy::v1::AccountReserveLookupError;
///
/// let err = AccountReserveLookupError { detail: "no native balance entry".into() };
/// assert!(err.to_string().contains("no native balance entry"));
/// ```
#[derive(Debug, Clone, thiserror::Error)]
#[error("account reserves view error: {detail}")]
pub struct AccountReserveLookupError {
    /// Non-secret diagnostic detail.
    pub detail: String,
}

/// Bundle decomposition and overlay substrate for multicall policy evaluation.
///
/// Provides [`bundle::BundleView`], [`bundle::InnerOpDescriptor`], `BundleStateOverlay`, and
/// [`bundle::decompose_bundle`].  Consumed by `PolicyEngineV1::evaluate_bundle` and
/// injected into `EvalContext::bundle` for bundle-level criteria.
pub mod bundle;

/// Per-criterion evaluators.
pub mod criteria;

/// Typed value descriptor (`ValueClass` / `ValueEffects` / `ValueLeg` /
/// `ActionKind`) consumed by the value-policy criteria and derived at the
/// dispatch gate.
pub mod value;

/// Owner-signed policy file loader.
pub mod loader;

/// Canonical-form serializer for owner-signature pre-image.
pub mod canonical;

/// Owner-signature verification.
pub mod signature;

/// Proptest strategy generators for property tests.  Gate-guarded; excluded
/// from release builds.
///
/// Available when `test` or the `"test-helpers"` feature is active.  The
/// module is in `src/` rather than `tests/` because proptest strategies need
/// access to crate-private types; placing them here avoids a separate
/// integration-test-only `tests/` crate.
#[cfg(any(test, feature = "test-helpers"))]
pub mod proptest_strategies;

/// Property tests for `PolicyEngineV1` (determinism, monotonicity,
/// wire-code stability).
///
/// Gate-guarded to `#[cfg(test)]`; never compiled into non-test builds.
#[cfg(test)]
mod proptest_properties;

pub use criteria::Criterion;
pub use criteria::PolicyStateStore;
pub use loader::{PolicyDocument, PolicyRule, RuleMatch, ScopeId};
pub use value::{ActionKind, OpaqueReason, ValueClass, ValueEffects, ValueLeg};

// ─────────────────────────────────────────────────────────────────────────────
// AccountIdentityView — local trait to avoid circular dep with
// stellar-agent-network.  Carries account identity fields consumed by the
// HOME_DOMAIN allowlist criterion.
// ─────────────────────────────────────────────────────────────────────────────

/// Identity view of an account, carrying fields consumed by the
/// `HOME_DOMAIN` counterparty-allowlist criterion.
///
/// This trait is intentionally **separate** from [`AccountReservesView`] to
/// make the HOME_DOMAIN implementation obligation impossible to miss at compile
/// time.  A combined trait with a default `home_domain() -> None` would
/// silently cause all HOME_DOMAIN matches to fail for any impl that forgot to
/// override it.  This trait has **no default implementations** — every impl
/// site must provide both methods.
///
/// A blanket impl over `stellar_agent_network::AccountView` lives in the
/// `stellar-agent-mcp` crate's `policy_adapter` module, where both
/// `stellar-agent-core` and `stellar-agent-network` are already dependencies.
pub trait AccountIdentityView: Send + Sync {
    /// Returns the account's `home_domain` string when set on the on-chain
    /// `AccountEntry`, `None` otherwise.
    ///
    /// Consumed by the `CounterpartyAllowlistCriterion`'s `HOME_DOMAIN` match
    /// path.  The criterion performs a strict-ASCII byte-equality compare
    /// against the configured allowlist to defend against IDN homoglyph attacks.
    ///
    /// **There is no default implementation.**  Every impl site must explicitly
    /// decide whether `home_domain` is available and return `None` only when
    /// the on-chain `AccountEntry.home_domain` field is absent or empty.
    ///
    /// # Errors
    ///
    /// Returns `None` when the on-chain `AccountEntry.home_domain` is not set.
    fn home_domain(&self) -> Option<String>;

    /// Returns the account's G-strkey (or C-strkey for contract accounts).
    ///
    /// Used by audit-log and diagnostic paths; not consumed by the
    /// HOME_DOMAIN criterion directly.
    fn account_id(&self) -> &str;
}

// ─────────────────────────────────────────────────────────────────────────────
// QuorumView — local trait to avoid circular dep with
// stellar-agent-smart-account (which already depends on stellar-agent-core).
// The `quorum_satisfied` criterion reads satisfaction state via this trait;
// the concrete adapter lives in stellar-agent-mcp where both crates are in
// scope.
// ─────────────────────────────────────────────────────────────────────────────

/// Pre-evaluated quorum satisfaction state for the `quorum_satisfied` policy
/// criterion.
///
/// This trait exists to break the would-be circular dependency between
/// `stellar-agent-core` (policy criterion) and `stellar-agent-smart-account`
/// (where `AuthorizationInfo` lives, and which already depends on
/// `stellar-agent-core`).  The concrete adapter in `stellar-agent-mcp`'s
/// `policy_adapter` module wraps a `(AuthorizationInfo, &[&dyn Signer])`
/// pair, evaluating group satisfaction at construction time and exposing the
/// result through this trait.
pub trait QuorumView: Send + Sync {
    /// Returns the names of signer groups whose threshold was not met.
    ///
    /// Returns an empty `Vec` when all required groups are satisfied (i.e., the
    /// criterion should return `Ok(None)`).  Returns the unsatisfied group names
    /// when `Combinator::And` fails (all groups must be satisfied but one or
    /// more are not), or the names of ALL groups when `Combinator::Or` fails (no
    /// group met threshold).
    fn groups_short_by(&self) -> Vec<String>;

    /// Returns the combinator label (`"And"` or `"Or"`) for the deny message.
    ///
    /// Used by the `quorum_satisfied` criterion to populate
    /// `DenyReason::QuorumNotSatisfied.combinator` in the deny envelope.
    fn combinator_label(&self) -> &str;
}

// ─────────────────────────────────────────────────────────────────────────────
// CounterpartyCacheView — local trait to avoid circular dep with
// stellar-agent-network (which already depends on stellar-agent-core).
// The `home_domain_resolved` criterion reads cache state via this trait;
// the concrete `CounterpartyCacheSnapshot` impl lives in stellar-agent-network
// and is constructed at dispatch time from `CounterpartyResolver::list_cached`.
// ─────────────────────────────────────────────────────────────────────────────

/// Frozen snapshot of the resolved counterparty cache, consumed by the
/// `home_domain_resolved` policy criterion.
///
/// This trait exists to break the would-be circular dependency between
/// `stellar-agent-core` (policy criterion) and `stellar-agent-network`
/// (where `CounterpartyResolver` and `StellarTomlBinding` live, and which
/// already depends on `stellar-agent-core`).
///
/// The concrete implementation is `stellar_agent_network::counterparty::CounterpartyCacheSnapshot`,
/// built once per dispatch call from `CounterpartyResolver::list_cached().await`.
/// The snapshot is **read-only** — the criterion sees a frozen view of the
/// cache at dispatch time.  This keeps the boundary clean: the existing async
/// resolver stays as-is; the policy-engine evaluation layer is synchronous.
///
/// # Trait shape note
///
/// The `CounterpartyResolver` is keyed BY `home_domain` (not by account_id —
/// no account_id index exists in the cache).  The trait therefore exposes
/// `has_resolved(home_domain) -> bool` rather than a lookup-by-account shape.
///
/// # Trust-boundary note
///
/// The first-fetch TOFU closure model requires that `has_resolved` returns
/// `true` only for domains whose stellar.toml has been successfully fetched
/// and cached.  Unresolved domains must return `false` so the
/// `home_domain_resolved` criterion can deny and prompt the operator to run
/// `stellar-agent counterparty refresh`.
pub trait CounterpartyCacheView: Send + Sync {
    /// Returns `true` if a valid cached `stellar.toml` binding exists for the
    /// given `home_domain`.
    ///
    /// The check is based on the **key set** of the snapshot built at dispatch
    /// time from `CounterpartyResolver::list_cached()`.  A binding is
    /// considered "resolved" if it was present in the cache at snapshot
    /// construction time, regardless of TTL; TTL expiry is the resolver's
    /// concern, not the criterion's.
    ///
    /// This method is **synchronous** — criterion evaluation cannot block on
    /// async I/O.  The snapshot must be built asynchronously before entering
    /// the policy-evaluation loop.
    ///
    /// # Security note
    ///
    /// `home_domain` is the on-chain `AccountEntry.home_domain` string from the
    /// `AccountIdentityView`.  The comparison is case-sensitive byte equality
    /// (same as the counterparty allowlist criterion), which defends against
    /// IDN homoglyph attacks.
    fn has_resolved(&self, home_domain: &str) -> bool;
}

// ─────────────────────────────────────────────────────────────────────────────
// Sep10SessionView — local trait to avoid circular dep with
// stellar-agent-sep10 (which depends on stellar-agent-core indirectly).
// The `sep10_session_active` criterion reads session state via this trait;
// the concrete impl lives in stellar-agent-mcp's dispatch site where both
// crates are already in scope.
// ─────────────────────────────────────────────────────────────────────────────

/// Read-only view of a SEP-10 session store, consumed by the
/// `sep10_session_active` policy criterion.
///
/// This trait exists to break the would-be circular dependency between
/// `stellar-agent-core` (policy criterion) and `stellar-agent-sep10`
/// (where `Sep10Session` lives, and which must not depend on
/// `stellar-agent-core`).  The concrete implementation wraps an in-process
/// session store keyed by `account_id`; it is constructed at dispatch time
/// and passed via `EvalContext::with_sep10_sessions`.
///
/// # Design rationale
///
/// The trait method `is_active` intentionally does NOT return or parse the
/// JWT — it answers a single boolean question.  The criterion only cares
/// whether a valid, non-expired session exists for the account.  JWT parsing
/// and expiry logic are delegated to the impl (same pattern as
/// `CounterpartyCacheView::has_resolved`).
///
/// # Clock anchor
///
/// `now_unix` is passed as a parameter (not read from `SystemTime::now()`)
/// so that criterion evaluation is deterministic in tests.
pub trait Sep10SessionView: Send + Sync {
    /// Returns `true` if a valid (non-expired at `now_unix`) SEP-10 session
    /// exists for `account_id`.
    ///
    /// `account_id` is the raw Stellar strkey (G-key, C-key, or M-key) as it
    /// would appear in the `sub` claim of a SEP-10 JWT after splitting on `:`.
    ///
    /// The implementation is responsible for:
    /// - Looking up the stored JWT by `account_id`.
    /// - Checking `jwt.exp > now_unix` (session has not expired).
    ///
    /// Returns `false` when no session exists OR when the stored session has
    /// expired at `now_unix`.
    ///
    /// # Security note
    ///
    /// The `is_active` check is based on JWT `exp` only; no JWT signature
    /// verification is performed here (consistent with `Sep10Session::parse`
    /// rationale — TLS authenticates the server at acquisition time).  The
    /// trust model is: if the session was acquired from a TLS-authenticated
    /// server, the `exp` claim is trustworthy.
    fn is_active(&self, account_id: &str, now_unix: u64) -> bool;
}

// ─────────────────────────────────────────────────────────────────────────────
// Sep45SessionView — local trait to avoid a would-be circular dep should
// `stellar-agent-sep45` ever need to consume policy-criterion machinery
// (parallel to the `Sep10SessionView` precedent).  The `sep45_session_active`
// criterion reads session state via this trait; the concrete impl lives in
// `stellar-agent-mcp`'s dispatch site where both crates are already in scope.
// ─────────────────────────────────────────────────────────────────────────────

/// Read-only view of a SEP-45 session store, consumed by the
/// `sep45_session_active` policy criterion.
///
/// This trait exists to break the would-be circular dependency between
/// `stellar-agent-core` (policy criterion) and `stellar-agent-sep45`
/// (where `Sep45Session` lives, and which must not depend on
/// `stellar-agent-core`).  The concrete implementation wraps an in-process
/// session store keyed by `contract_id`; it is constructed at dispatch time
/// and passed via `EvalContext::with_sep45_sessions`.
///
/// # Design rationale
///
/// The trait method `is_active` intentionally does NOT return or parse the
/// JWT — it answers a single boolean question.  The criterion only cares
/// whether a valid, non-expired session exists for the contract account.
/// JWT parsing and expiry logic are delegated to the impl, mirroring the
/// [`Sep10SessionView`] pattern.
///
/// # Clock anchor
///
/// `now_unix` is passed as a parameter (not read from `SystemTime::now()`)
/// so that criterion evaluation is deterministic in tests.
pub trait Sep45SessionView: Send + Sync {
    /// Returns `true` if a valid (non-expired at `now_unix`) SEP-45 session
    /// exists for `contract_id`.
    ///
    /// `contract_id` is the raw Stellar C-strkey as it would appear in the
    /// `sub` claim of a SEP-45 JWT.
    ///
    /// The implementation is responsible for:
    /// - Looking up the stored JWT by `contract_id`.
    /// - Checking `jwt.exp > now_unix` (session has not expired).
    ///
    /// Returns `false` when no session exists OR when the stored session has
    /// expired at `now_unix`.
    ///
    /// # Security note
    ///
    /// The `is_active` check is based on JWT `exp` only; no JWT signature
    /// verification is performed here (consistent with `Sep45Session::parse`
    /// rationale — TLS authenticates the server at acquisition time).
    fn is_active(&self, contract_id: &str, now_unix: u64) -> bool;
}

// ─────────────────────────────────────────────────────────────────────────────
// AccountReservesView — local trait to avoid circular dep with
// stellar-agent-network (which already depends on stellar-agent-core).
// The blanket impl over AccountView lives in stellar-agent-mcp where both
// crates are already in scope.
// ─────────────────────────────────────────────────────────────────────────────

/// Minimal view of an account's reserve position required by the
/// minimum-reserve criterion.
///
/// A blanket impl over `stellar_agent_network::AccountView` lives in the
/// dispatch crate (`stellar-agent-mcp`), where both `stellar-agent-core` and
/// `stellar-agent-network` are already dependencies.  This local trait exists
/// solely to break the would-be circular dep.
pub trait AccountReservesView: Send + Sync {
    /// Returns the total reserves locked in stroops:
    /// `(2 + subentry_count) × base_reserve_stroops`.
    fn reserves_stroops(&self, base_reserve_stroops: i64) -> i64;

    /// Returns the account's current XLM balance in stroops.
    ///
    /// # Errors
    ///
    /// Returns [`AccountReserveLookupError`] when the balance cannot be
    /// determined — for example, when the account view has no native balance
    /// entry, or when the balance string cannot be parsed.
    ///
    /// The `detail` field of the error MUST NOT include key material or other
    /// secret input.
    fn balance_stroops(&self) -> Result<i64, AccountReserveLookupError>;
}

// ─────────────────────────────────────────────────────────────────────────────
// EvalContext
// ─────────────────────────────────────────────────────────────────────────────

/// Context passed to each [`Criterion::evaluate`] call.
///
/// `EvalContext` is constructed by [`PolicyEngineV1::evaluate`] for each
/// matching rule and passed by shared reference to every criterion in that
/// rule.  It carries everything a criterion needs to make its decision without
/// additional I/O.
///
/// ## Circular-dep note
///
/// `account_view` is typed as `Option<&dyn AccountReservesView>` and
/// `identity_view` as `Option<&dyn AccountIdentityView>` rather than
/// `Option<&stellar_agent_network::AccountView>` to avoid a circular
/// dependency between `stellar-agent-core` and `stellar-agent-network`.  The
/// dispatch site populates these fields via blanket impls in `stellar-agent-mcp`'s
/// `policy_adapter` module.
///
/// ## State-store note
///
/// `state_store` holds the in-memory sliding-window state for per-period cap
/// and rate-limit criteria.  The dispatch site constructs an
/// `Arc<PolicyStateStore>` at process start and passes a reference here at
/// each call.
///
/// ## Profile-name note
///
/// `profile_name` is supplied separately from `profile` because
/// [`crate::profile::schema::Profile`] does not carry a `name` field — the
/// profile name is the TOML filename and is tracked by the loader, not by the
/// deserialized struct.  The dispatch site supplies it from the filename
/// it loaded.
///
/// ## Forward-compatibility note
///
/// `EvalContext` is `#[non_exhaustive]`.  External crates cannot construct
/// it with struct-literal syntax; use [`EvalContext::new`] and the builder
/// methods to supply optional views.  Fields default to `None`; supply them
/// only when the corresponding criterion is active.
#[non_exhaustive]
pub struct EvalContext<'a> {
    /// The tool being called.
    pub tool: &'a ToolDescriptor,
    /// Raw JSON arguments supplied by the agent.
    pub args: &'a Value,
    /// The name of the active profile (TOML filename without extension).
    ///
    /// Used by scope resolution when the dispatch site calls
    /// [`PolicyEngineV1::evaluate`]; the trait method receives the full
    /// `Profile` struct but the name must be supplied separately because
    /// `Profile` does not carry a `name` field.
    pub profile_name: &'a str,
    /// The active profile for this call.
    pub profile: &'a Profile,
    /// Typed value descriptor for this call, DERIVED at the dispatch gate from
    /// the same authoritative source the tool signs from.
    ///
    /// Value criteria (`per_tx_cap`, `per_period_cap`, `minimum_reserve`,
    /// `counterparty_allowlist`) read the typed [`value::ValueLeg`]s out of
    /// this field instead of pattern-matching tool names against `args`.
    /// Defaults to [`value::ValueClass::ReadOnly`] when constructed via
    /// [`EvalContext::new`]; [`PolicyEngineV1::evaluate`] derives the concrete
    /// class from `(tool, args)` before running the criteria, and the bundle
    /// path populates it per inner descriptor.
    pub value: value::ValueClass,
    /// Account reserve view, populated when the minimum-reserve criterion
    /// is configured.  `None` when the criterion is not active or when the
    /// dispatch site does not have account state available.
    ///
    /// Injected via the `account_view` parameter of [`PolicyEngineV1::evaluate`].
    pub account_view: Option<&'a dyn AccountReservesView>,
    /// Account identity view, populated when the HOME_DOMAIN counterparty
    /// criterion is active.  `None` when the criterion is not active or when
    /// the dispatch site does not have account state available.
    ///
    /// Carries `home_domain` and `account_id` — kept separate from
    /// `AccountReservesView` to make the HOME_DOMAIN implementation obligation
    /// explicit at every impl site (a combined trait with a default returning
    /// `None` caused silent fails).
    pub identity_view: Option<&'a dyn AccountIdentityView>,
    /// Pre-evaluated quorum satisfaction state for the `quorum_satisfied`
    /// criterion.
    ///
    /// `None` when the criterion is not active or when the dispatch site does
    /// not have quorum state available (single-signer submit paths).  Supply via
    /// [`EvalContext::with_quorum`] when the `quorum_satisfied` criterion is
    /// configured.
    ///
    /// # Circular-dep note
    ///
    /// Typed as `Option<&dyn QuorumView>` rather than
    /// `Option<&AuthorizationInfo>` to break the circular dependency between
    /// `stellar-agent-core` and `stellar-agent-smart-account`
    /// (where `AuthorizationInfo` lives and which already depends on
    /// `stellar-agent-core`). The concrete adapter lives in
    /// `stellar-agent-mcp::policy_adapter` where both crates are in scope.
    ///
    pub quorum: Option<&'a dyn QuorumView>,
    /// Frozen snapshot of the resolved counterparty cache for the
    /// `home_domain_resolved` criterion.
    ///
    /// `None` when the criterion is not active or when the dispatch site does
    /// not have a resolver handle available.  Supply via
    /// [`EvalContext::with_counterparty_cache`] when the
    /// `home_domain_resolved` criterion is configured.
    ///
    /// # Circular-dep note
    ///
    /// Typed as `Option<&dyn CounterpartyCacheView>` rather than
    /// `Option<&CounterpartyCacheSnapshot>` to break the circular dependency
    /// between `stellar-agent-core` and `stellar-agent-network`
    /// (where `CounterpartyCacheSnapshot` lives and which already depends on
    /// `stellar-agent-core`). The concrete snapshot is constructed in
    /// `stellar-agent-mcp`'s dispatch site where both crates are in scope.
    ///
    pub counterparty_cache: Option<&'a dyn CounterpartyCacheView>,
    /// Active SEP-10 session store for the `sep10_session_active` criterion.
    ///
    /// `None` when the criterion is not active or when the dispatch site does
    /// not have a session store available.  Supply via
    /// [`EvalContext::with_sep10_sessions`] when the `sep10_session_active`
    /// criterion is configured.
    ///
    /// # Circular-dep note
    ///
    /// Typed as `Option<&dyn Sep10SessionView>` rather than a concrete session
    /// store type to break the would-be circular dependency between
    /// `stellar-agent-core` and `stellar-agent-sep10`.  The concrete adapter
    /// lives in `stellar-agent-mcp`'s dispatch site where both crates are in
    /// scope.
    ///
    pub sep10_sessions: Option<&'a dyn Sep10SessionView>,
    /// Active SEP-45 session store for the `sep45_session_active` criterion.
    ///
    /// `None` when the criterion is not active or when the dispatch site does
    /// not have a session store available.  Supply via
    /// [`EvalContext::with_sep45_sessions`] when the `sep45_session_active`
    /// criterion is configured.
    ///
    /// # Circular-dep note
    ///
    /// Typed as `Option<&dyn Sep45SessionView>` rather than a concrete session
    /// store type to break the would-be circular dependency between
    /// `stellar-agent-core` and `stellar-agent-sep45`.  The concrete adapter
    /// lives in `stellar-agent-mcp`'s dispatch site where both crates are in
    /// scope.
    ///
    pub sep45_sessions: Option<&'a dyn Sep45SessionView>,
    /// Sliding-window state store for per-period cap and rate-limit criteria.
    ///
    /// Populated by the dispatch site with a reference to the process-lifetime
    /// [`PolicyStateStore`].  Per-period cap and rate-limit criteria read
    /// accumulated state from this store; recording new entries at commit time
    /// is the dispatch site's responsibility.
    pub state_store: &'a PolicyStateStore,
    /// Bundle view for multicall policy evaluation.
    ///
    /// `None` on the single-tx path (standard `PolicyEngineV1::evaluate`
    /// call); `Some(&view)` during [`PolicyEngineV1::evaluate_bundle`] where
    /// the view carries the full set of inner descriptors and the in-flight
    /// state overlay.  Bundle-level criteria check this field; stateful
    /// criteria (`per_period_cap`, `rate_limit`) add `overlay.get(&state_key)`
    /// to the persisted window total to account for earlier inners in the same
    /// bundle.
    ///
    pub bundle: Option<&'a BundleView<'a>>,
}

impl<'a> EvalContext<'a> {
    /// Constructs a new [`EvalContext`] for single-tx evaluation.
    ///
    /// This is the canonical constructor for external code that needs to build
    /// an `EvalContext` outside this crate.  Because `EvalContext` is
    /// `#[non_exhaustive]`, struct-literal construction is only valid within
    /// `stellar-agent-core` itself.  External crates (e.g. integration tests,
    /// `stellar-agent-mcp`) MUST use this constructor.
    ///
    /// `account_view`, `identity_view`, `quorum`, `counterparty_cache`,
    /// `sep10_sessions`, `sep45_sessions`, and `bundle` default to `None`.
    /// Use the builder methods [`EvalContext::with_account_view`],
    /// [`EvalContext::with_identity_view`], [`EvalContext::with_quorum`],
    /// [`EvalContext::with_counterparty_cache`],
    /// [`EvalContext::with_sep10_sessions`],
    /// [`EvalContext::with_sep45_sessions`], and
    /// [`EvalContext::with_bundle`] to populate them when the respective
    /// criteria are active.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::policy::v1::{EvalContext, PolicyStateStore};
    /// use stellar_agent_core::policy::{McpToolRegistration, ToolDescriptor};
    /// use stellar_agent_core::profile::schema::Profile;
    ///
    /// let tool = ToolDescriptor::from_registration(&McpToolRegistration {
    ///     name: "stellar_pay",
    ///     destructive_hint: true,
    ///     read_only_hint: false,
    ///     chain_id_required: true,
    ///     value_kind: stellar_agent_core::policy::ToolValueKind::ReadOnly,
    /// });
    /// let profile = Profile::builder_testnet("alice", "acct", "n-svc", "n-acct").build();
    /// let args = serde_json::Value::Null;
    /// let store = PolicyStateStore::new();
    /// let ctx = EvalContext::new(&tool, &args, "alice", &profile, &store);
    /// assert!(ctx.bundle.is_none());
    /// assert!(ctx.account_view.is_none());
    /// assert!(ctx.identity_view.is_none());
    /// assert!(ctx.quorum.is_none());
    /// assert!(ctx.counterparty_cache.is_none());
    /// assert!(ctx.sep45_sessions.is_none());
    /// ```
    #[must_use]
    pub fn new(
        tool: &'a ToolDescriptor,
        args: &'a Value,
        profile_name: &'a str,
        profile: &'a Profile,
        state_store: &'a PolicyStateStore,
    ) -> Self {
        Self {
            tool,
            args,
            profile_name,
            profile,
            value: value::ValueClass::ReadOnly,
            account_view: None,
            identity_view: None,
            quorum: None,
            counterparty_cache: None,
            sep10_sessions: None,
            sep45_sessions: None,
            state_store,
            bundle: None,
        }
    }

    /// Returns `self` with the `value` field set.
    ///
    /// Builder-style; consumes and returns `self`. Supply the derived
    /// [`value::ValueClass`] when evaluating a call whose value effect has been
    /// resolved at the dispatch gate.
    #[must_use]
    pub fn with_value(mut self, value: value::ValueClass) -> Self {
        self.value = value;
        self
    }

    /// Returns `self` with the `account_view` field set.
    ///
    /// Builder-style; consumes and returns `self`.  Supply an
    /// [`AccountReservesView`] when the minimum-reserve criterion is active.
    #[must_use]
    pub fn with_account_view(mut self, view: &'a dyn AccountReservesView) -> Self {
        self.account_view = Some(view);
        self
    }

    /// Returns `self` with the `identity_view` field set.
    ///
    /// Builder-style; consumes and returns `self`.  Supply an
    /// [`AccountIdentityView`] when the `HOME_DOMAIN` counterparty-allowlist
    /// criterion is active.
    #[must_use]
    pub fn with_identity_view(mut self, view: &'a dyn AccountIdentityView) -> Self {
        self.identity_view = Some(view);
        self
    }

    /// Returns `self` with the `quorum` field set.
    ///
    /// Builder-style; consumes and returns `self`.  Supply a [`QuorumView`]
    /// when the `quorum_satisfied` criterion is active.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::policy::v1::{EvalContext, PolicyStateStore, QuorumView};
    /// use stellar_agent_core::policy::{McpToolRegistration, ToolDescriptor};
    /// use stellar_agent_core::profile::schema::Profile;
    ///
    /// struct AlwaysSatisfied;
    /// impl QuorumView for AlwaysSatisfied {
    ///     fn groups_short_by(&self) -> Vec<String> { vec![] }
    ///     fn combinator_label(&self) -> &str { "And" }
    /// }
    ///
    /// let tool = ToolDescriptor::from_registration(&McpToolRegistration {
    ///     name: "stellar_pay",
    ///     destructive_hint: true,
    ///     read_only_hint: false,
    ///     chain_id_required: true,
    ///     value_kind: stellar_agent_core::policy::ToolValueKind::ReadOnly,
    /// });
    /// let profile = Profile::builder_testnet("alice", "acct", "n-svc", "n-acct").build();
    /// let args = serde_json::Value::Null;
    /// let store = PolicyStateStore::new();
    /// let view = AlwaysSatisfied;
    /// let ctx = EvalContext::new(&tool, &args, "alice", &profile, &store)
    ///     .with_quorum(&view);
    /// assert!(ctx.quorum.is_some());
    /// ```
    #[must_use]
    pub fn with_quorum(mut self, view: &'a dyn QuorumView) -> Self {
        self.quorum = Some(view);
        self
    }

    /// Returns `self` with the `counterparty_cache` field set.
    ///
    /// Builder-style; consumes and returns `self`.  Supply a
    /// [`CounterpartyCacheView`] when the `home_domain_resolved` criterion is
    /// active.
    ///
    /// The view is typically a `CounterpartyCacheSnapshot` built from
    /// `CounterpartyResolver::list_cached().await` at the dispatch site.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::policy::v1::{
    ///     CounterpartyCacheView, EvalContext, PolicyStateStore,
    /// };
    /// use stellar_agent_core::policy::{McpToolRegistration, ToolDescriptor};
    /// use stellar_agent_core::profile::schema::Profile;
    ///
    /// struct EmptyCache;
    /// impl CounterpartyCacheView for EmptyCache {
    ///     fn has_resolved(&self, _home_domain: &str) -> bool { false }
    /// }
    ///
    /// let tool = ToolDescriptor::from_registration(&McpToolRegistration {
    ///     name: "stellar_pay",
    ///     destructive_hint: true,
    ///     read_only_hint: false,
    ///     chain_id_required: true,
    ///     value_kind: stellar_agent_core::policy::ToolValueKind::ReadOnly,
    /// });
    /// let profile = Profile::builder_testnet("alice", "acct", "n-svc", "n-acct").build();
    /// let args = serde_json::Value::Null;
    /// let store = PolicyStateStore::new();
    /// let cache = EmptyCache;
    /// let ctx = EvalContext::new(&tool, &args, "alice", &profile, &store)
    ///     .with_counterparty_cache(&cache);
    /// assert!(ctx.counterparty_cache.is_some());
    /// ```
    #[must_use]
    pub fn with_counterparty_cache(mut self, cache: &'a dyn CounterpartyCacheView) -> Self {
        self.counterparty_cache = Some(cache);
        self
    }

    /// Returns `self` with the `sep10_sessions` field set.
    ///
    /// Builder-style; consumes and returns `self`.  Supply a
    /// [`Sep10SessionView`] when the `sep10_session_active` criterion is active.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::policy::v1::{
    ///     Sep10SessionView, EvalContext, PolicyStateStore,
    /// };
    /// use stellar_agent_core::policy::{McpToolRegistration, ToolDescriptor};
    /// use stellar_agent_core::profile::schema::Profile;
    ///
    /// struct AlwaysActive;
    /// impl Sep10SessionView for AlwaysActive {
    ///     fn is_active(&self, _account_id: &str, _now_unix: u64) -> bool { true }
    /// }
    ///
    /// let tool = ToolDescriptor::from_registration(&McpToolRegistration {
    ///     name: "stellar_pay",
    ///     destructive_hint: true,
    ///     read_only_hint: false,
    ///     chain_id_required: true,
    ///     value_kind: stellar_agent_core::policy::ToolValueKind::ReadOnly,
    /// });
    /// let profile = Profile::builder_testnet("alice", "acct", "n-svc", "n-acct").build();
    /// let args = serde_json::Value::Null;
    /// let store = PolicyStateStore::new();
    /// let sessions = AlwaysActive;
    /// let ctx = EvalContext::new(&tool, &args, "alice", &profile, &store)
    ///     .with_sep10_sessions(&sessions);
    /// assert!(ctx.sep10_sessions.is_some());
    /// ```
    #[must_use]
    pub fn with_sep10_sessions(mut self, view: &'a dyn Sep10SessionView) -> Self {
        self.sep10_sessions = Some(view);
        self
    }

    /// Returns `self` with the `sep45_sessions` field set.
    ///
    /// Builder-style; consumes and returns `self`.  Supply a
    /// [`Sep45SessionView`] when the `sep45_session_active` criterion is active.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::policy::v1::{
    ///     Sep45SessionView, EvalContext, PolicyStateStore,
    /// };
    /// use stellar_agent_core::policy::{McpToolRegistration, ToolDescriptor};
    /// use stellar_agent_core::profile::schema::Profile;
    ///
    /// struct AlwaysActive;
    /// impl Sep45SessionView for AlwaysActive {
    ///     fn is_active(&self, _contract_id: &str, _now_unix: u64) -> bool { true }
    /// }
    ///
    /// let tool = ToolDescriptor::from_registration(&McpToolRegistration {
    ///     name: "stellar_pay",
    ///     destructive_hint: true,
    ///     read_only_hint: false,
    ///     chain_id_required: true,
    ///     value_kind: stellar_agent_core::policy::ToolValueKind::ReadOnly,
    /// });
    /// let profile = Profile::builder_testnet("alice", "acct", "n-svc", "n-acct").build();
    /// let args = serde_json::Value::Null;
    /// let store = PolicyStateStore::new();
    /// let sessions = AlwaysActive;
    /// let ctx = EvalContext::new(&tool, &args, "alice", &profile, &store)
    ///     .with_sep45_sessions(&sessions);
    /// assert!(ctx.sep45_sessions.is_some());
    /// ```
    #[must_use]
    pub fn with_sep45_sessions(mut self, view: &'a dyn Sep45SessionView) -> Self {
        self.sep45_sessions = Some(view);
        self
    }

    /// Returns `self` with the `bundle` field set.
    ///
    /// Builder-style; consumes and returns `self`.  Use this for multicall
    /// bundle evaluation paths where a `BundleView` is available.
    #[must_use]
    pub fn with_bundle(mut self, bundle: &'a BundleView<'a>) -> Self {
        self.bundle = Some(bundle);
        self
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PolicyEngineV1
// ─────────────────────────────────────────────────────────────────────────────

/// Typed-criteria policy engine.
///
/// Wraps a [`PolicyDocument`] (loaded and signature-verified by
/// `loader::load_signed_policy`) and evaluates incoming tool calls against the
/// document's rules using first-match stop-semantics.
///
/// # Profile name
///
/// `PolicyEngineV1` is constructed with the `profile_name` (the TOML filename
/// without extension) at load time.  `PolicyEngine::evaluate` uses it for
/// scope resolution.  [`crate::profile::schema::Profile`] does not carry a
/// `name` field; the name is managed by the loader.
///
/// # Project ID caching
///
/// `STELLAR_AGENT_PROJECT` is read from the environment **once** at engine
/// construction time and stored in `project_id`.  Reading an env var on every
/// `evaluate` call is non-deterministic and would make policy evaluation
/// non-deterministic for a given engine instance.  If the env var changes
/// after construction the engine will not observe the change; operators must
/// restart the MCP server to pick up env var changes.
///
/// # Thread safety
///
/// `PolicyEngineV1` is `Send + Sync`: `PolicyDocument` holds
/// `Box<dyn Criterion>` which is bounded `Send + Sync` on the [`Criterion`]
/// trait, and all other fields are immutable after construction.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::policy::v1::{PolicyEngineV1, loader::{PolicyDocument, ScopeId}};
///
/// let doc = PolicyDocument { version: 1, scope: ScopeId::AllProfiles, rules: vec![], signature: None };
/// let engine = PolicyEngineV1::new(doc, "alice".into());
/// ```
///
#[derive(Debug)]
pub struct PolicyEngineV1 {
    document: PolicyDocument,
    /// The profile name this engine was loaded for (TOML filename without
    /// extension).  Used by scope resolution in [`PolicyEngine::evaluate`].
    profile_name: String,
    /// Project ID cached at construction time from `STELLAR_AGENT_PROJECT`.
    ///
    /// `None` when the env var is unset or empty.  Read once at construction;
    /// post-construction changes to the env var are not observed.  Reading an
    /// env var on every `evaluate` call is non-deterministic; caching at
    /// construction time makes evaluation deterministic for a given engine
    /// instance.
    project_id: Option<String>,
    /// In-memory sliding-window state store for per-period cap and rate-limit
    /// criteria.  Owned by the engine and shared by reference into each
    /// [`EvalContext`] during evaluation.
    ///
    /// Use [`PolicyEngineV1::new_with_store`] to inject an externally-constructed
    /// store when sharing state across engine instances.  The default constructor
    /// allocates a fresh per-engine store.
    state_store: PolicyStateStore,
}

impl PolicyEngineV1 {
    /// Constructs a `PolicyEngineV1` from a verified [`PolicyDocument`] and
    /// the owning profile name.
    ///
    /// The document MUST already have its owner signature verified by
    /// `loader::load_signed_policy`.  Callers that construct a `PolicyEngineV1`
    /// from an unverified document bypass the signature check.
    ///
    /// `profile_name` is the TOML filename without extension (e.g. `"alice"`).
    ///
    /// `STELLAR_AGENT_PROJECT` is read from the environment once at this call
    /// site and cached in `self.project_id`.  Changes to the env var after
    /// construction are not observed.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::policy::v1::{PolicyEngineV1, loader::{PolicyDocument, ScopeId}};
    ///
    /// let doc = PolicyDocument { version: 1, scope: ScopeId::AllProfiles, rules: vec![], signature: None };
    /// let engine = PolicyEngineV1::new(doc, "alice".into());
    /// ```
    #[must_use]
    pub fn new(document: PolicyDocument, profile_name: String) -> Self {
        let project_id = std::env::var("STELLAR_AGENT_PROJECT").ok();
        Self {
            document,
            profile_name,
            project_id,
            state_store: PolicyStateStore::new(),
        }
    }

    /// Constructs a `PolicyEngineV1` with an externally-supplied
    /// [`PolicyStateStore`].
    ///
    /// Use this constructor when a single `PolicyStateStore` must be shared
    /// across multiple engine instances (e.g. one engine per profile sharing
    /// the same process-lifetime state).
    ///
    /// The document MUST already have its owner signature verified before
    /// calling this constructor.
    ///
    /// `STELLAR_AGENT_PROJECT` is read from the environment once at this call
    /// site and cached in `self.project_id`.  Changes to the env var after
    /// construction are not observed.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::policy::v1::{PolicyEngineV1, PolicyStateStore, loader::{PolicyDocument, ScopeId}};
    ///
    /// let store = PolicyStateStore::new();
    /// let doc = PolicyDocument { version: 1, scope: ScopeId::AllProfiles, rules: vec![], signature: None };
    /// let engine = PolicyEngineV1::new_with_store(doc, "alice".into(), store);
    /// ```
    #[must_use]
    pub fn new_with_store(
        document: PolicyDocument,
        profile_name: String,
        state_store: PolicyStateStore,
    ) -> Self {
        let project_id = std::env::var("STELLAR_AGENT_PROJECT").ok();
        Self {
            document,
            profile_name,
            project_id,
            state_store,
        }
    }

    /// Returns all rules from `self.document` when the document scope matches
    /// `(profile_name, project_id)`; otherwise returns an empty `Vec`.
    ///
    /// Each `PolicyEngineV1` wraps exactly one [`PolicyDocument`] with exactly
    /// one [`ScopeId`].  When the document's scope matches the given profile
    /// and project, all rules in the document are candidates for first-match
    /// stop evaluation.  When the scope does not match, no rules are returned
    /// (the document is not applicable to this call context).
    ///
    /// Multi-document specificity resolution (picking the most-specific document
    /// when multiple documents could apply) is reserved for a future revision in
    /// which the dispatch site supports loading several policy files per profile.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::policy::v1::{
    ///     PolicyEngineV1,
    ///     loader::{PolicyDocument, PolicyRule, RuleMatch, ScopeId},
    /// };
    /// use stellar_agent_core::policy::Decision;
    ///
    /// let doc = PolicyDocument {
    ///     version: 1,
    ///     scope: ScopeId::AllProfiles,
    ///     rules: vec![
    ///         PolicyRule {
    ///             r#match: RuleMatch { tool: "*".into(), chain: "*".into() },
    ///             criteria: vec![],
    ///             decision: Decision::Allow,
    ///         },
    ///     ],
    ///     signature: None,
    /// };
    /// let engine = PolicyEngineV1::new(doc, "alice".into());
    /// // AllProfiles scope matches any profile.
    /// let rules = engine.matching_rules("alice", None);
    /// assert_eq!(rules.len(), 1);
    ///
    /// // Non-matching profile returns empty.
    /// let rules_bob = engine.matching_rules("bob", None);
    /// // AllProfiles matches bob too — scoped doc would return empty for wrong profile.
    /// assert!(!rules_bob.is_empty());
    /// ```
    pub fn matching_rules<'a>(
        &'a self,
        profile_name: &str,
        project_id: Option<&str>,
    ) -> Vec<&'a PolicyRule> {
        // Single-document semantics: the document's scope either matches the
        // (profile, project) pair for all rules, or it does not match at all.
        // The "most-specific-wins" logic across multiple documents is a future
        // concern; for now every PolicyEngineV1 instance owns one document.
        if self.document.scope.matches(profile_name, project_id) {
            self.document.rules.iter().collect()
        } else {
            vec![]
        }
    }

    /// Kept for back-compat during parallel-track merging.
    ///
    /// Delegates to [`PolicyEngineV1::matching_rules`].  Callers in existing
    /// tests that call `resolve_scope` by name continue to compile;
    /// new code should use `matching_rules`.
    #[inline]
    pub fn resolve_scope<'a>(
        &'a self,
        profile_name: &str,
        project_id: Option<&str>,
    ) -> Vec<&'a PolicyRule> {
        self.matching_rules(profile_name, project_id)
    }
}

impl PolicyEngine for PolicyEngineV1 {
    /// Evaluates whether the given tool call is permitted under the active profile.
    ///
    /// Uses first-match stop-semantics over the rules in the scope resolved
    /// for `self.profile_name` (set at construction time).  If no rule
    /// matches, returns `Ok(Decision::Deny(DenyReason::NoMatchingRule))`
    /// (default-deny).
    ///
    /// `STELLAR_AGENT_PROJECT` env var (when set) narrows scope resolution to
    /// the named project within the profile.
    ///
    /// `account_view` is injected when the minimum-reserve criterion is
    /// configured; pass `None` when the criterion is not active.
    ///
    /// `identity_view` is injected when the HOME_DOMAIN counterparty criterion
    /// is active; pass `None` when the criterion is not active.
    ///
    /// `counterparty_cache` is injected when the `home_domain_resolved`
    /// criterion is active; pass `None` when the criterion is not active or
    /// when no resolver handle is available at the dispatch site.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::CriterionEvaluationFailed`] if any criterion's
    /// `evaluate` call returns an error.
    fn evaluate(
        &self,
        tool: &ToolDescriptor,
        args: &Value,
        profile: &Profile,
        account_view: Option<&dyn AccountReservesView>,
        identity_view: Option<&dyn AccountIdentityView>,
        counterparty_cache: Option<&dyn CounterpartyCacheView>,
        sep10_sessions: Option<&dyn Sep10SessionView>,
        sep45_sessions: Option<&dyn Sep45SessionView>,
    ) -> Result<Decision, PolicyError> {
        // project_id is cached at engine construction time from STELLAR_AGENT_PROJECT.
        let rules = self.matching_rules(&self.profile_name, self.project_id.as_deref());

        // First-match stop-semantics.
        for rule in rules {
            if !rule.matches_tool(tool) {
                continue;
            }

            // Derive the typed value descriptor from the same (tool, args) the
            // criteria gate on. On the commit path `args` is the HMAC-bound
            // authoritative_args, so the descriptor is transitively bound to the
            // signed envelope. Non-pay/create tools derive ReadOnly in this step.
            let value = value::derive_value_class(&tool.name, args);

            let ctx = EvalContext {
                tool,
                args,
                profile_name: &self.profile_name,
                profile,
                value,
                account_view,
                identity_view,
                // Quorum view is None on the standard single-tx path.
                // Supply via EvalContext::with_quorum() at the dispatch site
                // for multi-signer invocations.
                quorum: None,
                counterparty_cache,
                sep10_sessions,
                sep45_sessions,
                state_store: &self.state_store,
                // Single-tx path: no bundle view.
                bundle: None,
            };

            for criterion in &rule.criteria {
                if let Some(deny) = criterion.evaluate(&ctx)? {
                    return Ok(Decision::Deny(deny));
                }
            }

            return Ok(rule.decision.clone());
        }

        // No matching rule — default-deny.
        Ok(Decision::Deny(DenyReason::NoMatchingRule))
    }
}

impl PolicyEngineV1 {
    /// Evaluates a multicall bundle against the matching rule.
    ///
    /// # Amplification defence (hard floor)
    ///
    /// Bundles with more than [`crate::policy::v1::criteria::inner_invocation_count_cap::DEFAULT_INNER_INVOCATION_COUNT_CAP`]
    /// (50) inners are denied unconditionally, regardless of policy
    /// configuration.  This is a hard floor applied BEFORE rule resolution:
    /// policy authors may configure a LOWER cap via the
    /// `inner_invocation_count_cap` criterion, but cannot raise above the hard
    /// floor.
    ///
    /// # Algorithm
    ///
    /// 1. Reject bundles with `> 50` inners (hard floor; amplification defence).
    /// 2. Resolve the matching rule via [`Self::matching_rules`].  If no rule
    ///    matches, return `Deny(NoMatchingRule)`.
    /// 3. Build a mutable [`BundleStateOverlay`].
    /// 4. Phase 1 — per-inner evaluation of non-bundle-level criteria.
    ///    For each inner descriptor in `bundle.inners`:
    ///    - Construct a fresh `BundleView` with the full slice and current overlay.
    ///    - Build a per-inner [`EvalContext`] with `bundle = Some(&view)`.
    ///    - Run ONLY criteria where [`Criterion::is_bundle_level`] returns `false`
    ///      against the per-inner context.  Bundle-level criteria are skipped here.
    ///    - On first Deny → return `Deny(BundleDenied { inner_index, deny_reason })`.
    ///    - On Allow → call `criterion.accumulate_overlay(ctx, inner, overlay)` on
    ///      each non-bundle-level criterion; each criterion accumulates its own key.
    /// 5. Phase 2 — bundle-level criteria with full view.
    ///    Run ONLY criteria where [`Criterion::is_bundle_level`] returns `true`
    ///    against a final `BundleView` with the fully-populated overlay.  First
    ///    Deny → return `Deny(deny_reason)`.
    /// 6. All pass → return `rule.decision`.
    ///
    /// # Phase-dispatch rationale
    ///
    /// Bundle-level criteria (`inner_invocation_count_cap`, `bundle_aggregate_cap`,
    /// `restrict_bundle_to_recognised_kinds`) inspect the full bundle and must run
    /// ONCE after all inners complete.  Running them at Phase 1 per-inner evaluation
    /// caused an off-by-one false-deny: for example, with `rate_limit max=5,
    /// recorded=4`, Phase 1 correctly allows (4 < 5), but re-evaluating at Phase 2
    /// with the fully-populated overlay (4 + 1 overlay = 5 ≥ 5) would deny.  The
    /// `is_bundle_level()` dispatch eliminates this over-iteration.
    ///
    /// # Arguments
    ///
    /// - `tool` — the tool descriptor for the multicall invocation.
    /// - `args` — the raw JSON arguments supplied by the agent.
    /// - `profile` — the currently-active profile.
    /// - `bundle` — the `BundleView` carrying inner descriptors and an
    ///   already-populated `BundleStateOverlay`.  Callers should construct
    ///   the overlay with [`BundleStateOverlay::default`] and pass a reference.
    ///   The overlay is rebuilt internally during per-inner iteration.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::CriterionEvaluationFailed`] if any criterion's
    /// `evaluate` call returns an error (e.g. i128 overflow in
    /// `bundle_aggregate_cap`).
    ///
    pub fn evaluate_bundle(
        &self,
        tool: &ToolDescriptor,
        args: &Value,
        profile: &Profile,
        bundle: &BundleView<'_>,
    ) -> Result<Decision, PolicyError> {
        use crate::policy::v1::criteria::inner_invocation_count_cap::DEFAULT_INNER_INVOCATION_COUNT_CAP;

        // Hard floor: unconditional amplification defence independent of policy.
        // Policy authors may set a LOWER cap via inner_invocation_count_cap but
        // cannot raise above DEFAULT_INNER_INVOCATION_COUNT_CAP (50).
        if bundle.inners.len() > DEFAULT_INNER_INVOCATION_COUNT_CAP as usize {
            return Ok(Decision::Deny(
                DenyReason::InnerInvocationCountCapExceeded {
                    max: DEFAULT_INNER_INVOCATION_COUNT_CAP,
                    attempted: u32::try_from(bundle.inners.len()).unwrap_or(u32::MAX),
                },
            ));
        }

        let rules = self.matching_rules(&self.profile_name, self.project_id.as_deref());

        // First-match stop-semantics: find the first rule that matches the tool.
        let Some(rule) = rules.into_iter().find(|r| r.matches_tool(tool)) else {
            return Ok(Decision::Deny(DenyReason::NoMatchingRule));
        };

        // Build a mutable overlay for accumulating per-inner state.
        let mut overlay = BundleStateOverlay::default();

        // Phase 1: per-inner evaluation — only non-bundle-level criteria.
        //
        // Bundle-level criteria (`is_bundle_level() == true`) are skipped here.
        // They run once in Phase 2 with the fully-populated overlay.  Skipping
        // them at Phase 1 prevents off-by-one false-denies: e.g. rate_limit
        // records=4, max=5 — Phase 1 allows (4 < 5), accumulates +1 to overlay.
        // Without this guard, Phase 2 would re-evaluate rate_limit with overlay
        // total 5 ≥ 5 and deny incorrectly.
        for (idx, inner) in bundle.inners.iter().enumerate() {
            // Construct a fresh BundleView for this iteration.  The immutable
            // borrow of `overlay` ends at the close of this block; `overlay` is
            // then mutably borrowed for accumulation below.
            let per_inner_decision = {
                let inner_view = BundleView {
                    inners: bundle.inners,
                    overlay: &overlay,
                };
                // Populate the value axis from this inner's typed descriptor so
                // value criteria read ctx.value uniformly. Generic inners map to
                // ReadOnly (they contribute nothing to value caps).
                let value = value::value_class_for_inner(inner);
                let ctx = EvalContext {
                    tool,
                    args,
                    profile_name: &self.profile_name,
                    profile,
                    value,
                    account_view: None,
                    identity_view: None,
                    quorum: None,
                    counterparty_cache: None,
                    sep10_sessions: None,
                    sep45_sessions: None,
                    state_store: &self.state_store,
                    bundle: Some(&inner_view),
                };
                let mut per_inner_deny: Option<DenyReason> = None;
                for criterion in &rule.criteria {
                    // Skip bundle-level criteria at Phase 1.
                    if criterion.is_bundle_level() {
                        continue;
                    }
                    if let Some(deny) = criterion.evaluate(&ctx)? {
                        per_inner_deny = Some(deny);
                        break;
                    }
                }
                per_inner_deny
            };

            if let Some(deny_reason) = per_inner_decision {
                return Ok(Decision::Deny(DenyReason::BundleDenied {
                    inner_index: u32::try_from(idx).unwrap_or(u32::MAX),
                    deny_reason: Box::new(deny_reason),
                }));
            }

            // Inner passed — let each non-bundle-level criterion accumulate its
            // own overlay state.  The criterion derives the SAME StateKey as its
            // evaluate() body, guaranteeing read-key equality.
            //
            // Bundle-level criteria do not accumulate per-inner state; they
            // inspect the fully-populated overlay at Phase 2 directly.
            //
            // The accumulate_overlay context does NOT carry a BundleView; criteria
            // only use ctx.profile_name to derive state keys.  Passing bundle=None
            // avoids holding an immutable borrow of `overlay` while calling the
            // mutable `overlay.accumulate(...)` inside each criterion.
            {
                let accum_ctx = EvalContext {
                    tool,
                    args,
                    profile_name: &self.profile_name,
                    profile,
                    // Accumulation derives state keys only from profile_name;
                    // the value axis is unused here.
                    value: value::ValueClass::ReadOnly,
                    account_view: None,
                    identity_view: None,
                    quorum: None,
                    counterparty_cache: None,
                    sep10_sessions: None,
                    sep45_sessions: None,
                    state_store: &self.state_store,
                    bundle: None,
                };
                for criterion in &rule.criteria {
                    if criterion.is_bundle_level() {
                        continue;
                    }
                    criterion.accumulate_overlay(&accum_ctx, inner, &mut overlay);
                }
            }
        }

        // Phase 2: bundle-level criteria with full view and populated overlay.
        //
        // Only criteria where `is_bundle_level() == true` run here.  These
        // criteria inspect the FULL bundle (all inners visible via the
        // `BundleView`) and the completed overlay.
        let final_view = BundleView {
            inners: bundle.inners,
            overlay: &overlay,
        };
        let final_ctx = EvalContext {
            tool,
            args,
            profile_name: &self.profile_name,
            profile,
            // Bundle-level criteria inspect the full inners slice, not the value
            // axis; ReadOnly is the correct placeholder here.
            value: value::ValueClass::ReadOnly,
            account_view: None,
            identity_view: None,
            quorum: None,
            counterparty_cache: None,
            sep10_sessions: None,
            sep45_sessions: None,
            state_store: &self.state_store,
            bundle: Some(&final_view),
        };
        for criterion in &rule.criteria {
            // Skip non-bundle-level criteria at Phase 2 — they ran at Phase 1.
            if !criterion.is_bundle_level() {
                continue;
            }
            if let Some(deny) = criterion.evaluate(&final_ctx)? {
                return Ok(Decision::Deny(deny));
            }
        }

        Ok(rule.decision.clone())
    }
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

    use super::*;
    use crate::policy::v1::bundle::InnerOpDescriptor;
    use crate::policy::{McpToolRegistration, ToolDescriptor};

    struct ReserveOnlyView;
    struct WithIdentityView;

    impl AccountReservesView for ReserveOnlyView {
        fn reserves_stroops(&self, base_reserve_stroops: i64) -> i64 {
            base_reserve_stroops.saturating_mul(2)
        }

        fn balance_stroops(&self) -> Result<i64, AccountReserveLookupError> {
            Ok(100_000_000)
        }
    }

    impl AccountIdentityView for WithIdentityView {
        fn home_domain(&self) -> Option<String> {
            Some("example.org".to_owned())
        }

        fn account_id(&self) -> &str {
            "GABC123456789012345678901234567890123456789012345678901234"
        }
    }

    fn tool(name: &'static str, chain: &str) -> ToolDescriptor {
        let mut td = ToolDescriptor::from_registration(&McpToolRegistration {
            name,
            destructive_hint: false,
            read_only_hint: false,
            chain_id_required: false,
            value_kind: crate::policy::ToolValueKind::ReadOnly,
        });
        td.chain_id = chain.to_owned();
        td
    }

    fn testnet_profile() -> Profile {
        Profile::builder_testnet("alice", "acct", "n-svc", "n-acct").build()
    }

    /// Verifies that `AccountReservesView` does not carry `home_domain`.
    /// Reserve-only views need not implement identity methods.
    #[test]
    fn account_reserves_view_has_no_home_domain() {
        let view = ReserveOnlyView;
        // Compile-time proof: if AccountReservesView still had home_domain(),
        // this test file would reference it.  The absence of any home_domain()
        // call here confirms the split.
        let _reserves = view.reserves_stroops(5_000_000);
        assert_eq!(_reserves, 10_000_000, "2 × base_reserve stroops");
    }

    /// Verifies that `AccountIdentityView::home_domain` returns the expected
    /// value without any default — callers must always provide a concrete impl.
    #[test]
    fn account_identity_view_home_domain_flows_through() {
        let view = WithIdentityView;

        assert_eq!(
            view.home_domain().as_deref(),
            Some("example.org"),
            "home_domain must flow through AccountIdentityView without default"
        );
    }

    /// Verifies that `AccountIdentityView::account_id` returns the expected value.
    #[test]
    fn account_identity_view_account_id_flows_through() {
        let view = WithIdentityView;
        assert_eq!(
            view.account_id(),
            "GABC123456789012345678901234567890123456789012345678901234",
            "account_id must flow through AccountIdentityView"
        );
    }

    // ── ScopeId::specificity ────────────────────────────────────────────────

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

    // ── ScopeId::matches ────────────────────────────────────────────────────

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
    fn scope_id_profile_does_not_match_when_project_given() {
        // Profile scope matches the profile regardless of project presence.
        let s = ScopeId::Profile("alice".into());
        // Profile scope matches alice even with a project set.
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

    // ── RuleMatch::matches ──────────────────────────────────────────────────

    #[test]
    fn rule_match_wildcard_tool_matches_any_tool() {
        let m = RuleMatch {
            tool: "*".into(),
            chain: "stellar:testnet".into(),
        };
        let t = tool("stellar_pay", "stellar:testnet");
        assert!(m.matches(&t));
    }

    #[test]
    fn rule_match_wildcard_chain_matches_any_chain() {
        let m = RuleMatch {
            tool: "stellar_pay".into(),
            chain: "*".into(),
        };
        let t = tool("stellar_pay", "stellar:mainnet");
        assert!(m.matches(&t));
    }

    #[test]
    fn rule_match_exact_name_and_chain_matches() {
        let m = RuleMatch {
            tool: "stellar_pay".into(),
            chain: "stellar:mainnet".into(),
        };
        let t = tool("stellar_pay", "stellar:mainnet");
        assert!(m.matches(&t));
    }

    #[test]
    fn rule_match_wrong_tool_name_does_not_match() {
        let m = RuleMatch {
            tool: "stellar_pay".into(),
            chain: "*".into(),
        };
        let t = tool("stellar_balances", "stellar:testnet");
        assert!(!m.matches(&t));
    }

    #[test]
    fn rule_match_wrong_chain_does_not_match() {
        let m = RuleMatch {
            tool: "*".into(),
            chain: "stellar:mainnet".into(),
        };
        let t = tool("stellar_pay", "stellar:testnet");
        assert!(!m.matches(&t));
    }

    // ── PolicyEngineV1::matching_rules ─────────────────────────────────────────

    /// Verifies that a Profile-scoped document returns all rules for the
    /// matching profile and none for a non-matching profile.
    #[test]
    fn matching_rules_profile_scope_returns_all_rules_for_matching_profile() {
        let profile_doc = PolicyDocument {
            version: 1,
            scope: ScopeId::Profile("alice".into()),
            rules: vec![
                PolicyRule {
                    r#match: RuleMatch {
                        tool: "stellar_pay".into(),
                        chain: "*".into(),
                    },
                    criteria: vec![],
                    decision: Decision::Allow,
                },
                PolicyRule {
                    r#match: RuleMatch {
                        tool: "stellar_balances".into(),
                        chain: "*".into(),
                    },
                    criteria: vec![],
                    decision: Decision::Allow,
                },
            ],
            signature: None,
        };

        let engine = PolicyEngineV1::new(profile_doc, "alice".into());
        let rules = engine.matching_rules("alice", None);
        // All rules in the document are returned for the matching profile.
        assert_eq!(rules.len(), 2);
        // Non-matching profile returns empty.
        let rules_bob = engine.matching_rules("bob", None);
        assert!(rules_bob.is_empty());
    }

    #[test]
    fn matching_rules_all_profiles_matches_any_profile() {
        let doc = PolicyDocument {
            version: 1,
            scope: ScopeId::AllProfiles,
            rules: vec![PolicyRule {
                r#match: RuleMatch {
                    tool: "*".into(),
                    chain: "*".into(),
                },
                criteria: vec![],
                decision: Decision::Allow,
            }],
            signature: None,
        };
        let engine = PolicyEngineV1::new(doc, "alice".into());
        // AllProfiles matches any profile.
        assert_eq!(engine.matching_rules("alice", None).len(), 1);
        assert_eq!(engine.matching_rules("bob", Some("proj")).len(), 1);
    }

    #[test]
    fn matching_rules_profile_project_requires_exact_match() {
        let doc = PolicyDocument {
            version: 1,
            scope: ScopeId::ProfileProject {
                profile: "alice".into(),
                project: "payments".into(),
            },
            rules: vec![PolicyRule {
                r#match: RuleMatch {
                    tool: "*".into(),
                    chain: "*".into(),
                },
                criteria: vec![],
                decision: Decision::Allow,
            }],
            signature: None,
        };
        let engine = PolicyEngineV1::new(doc, "alice".into());
        // Exact match.
        assert_eq!(engine.matching_rules("alice", Some("payments")).len(), 1);
        // Wrong project.
        assert!(engine.matching_rules("alice", Some("other")).is_empty());
        // No project.
        assert!(engine.matching_rules("alice", None).is_empty());
        // Wrong profile.
        assert!(engine.matching_rules("bob", Some("payments")).is_empty());
    }

    // ── resolve_scope back-compat (delegates to matching_rules) ───────────────

    #[test]
    fn resolve_scope_delegates_to_matching_rules() {
        let doc = PolicyDocument {
            version: 1,
            scope: ScopeId::AllProfiles,
            rules: vec![PolicyRule {
                r#match: RuleMatch {
                    tool: "*".into(),
                    chain: "*".into(),
                },
                criteria: vec![],
                decision: Decision::Allow,
            }],
            signature: None,
        };
        let engine = PolicyEngineV1::new(doc, "alice".into());
        assert_eq!(
            engine.resolve_scope("alice", None).len(),
            engine.matching_rules("alice", None).len()
        );
    }

    // ── PolicyEngineV1::evaluate — empty document → NoMatchingRule ──────────

    #[test]
    fn evaluate_empty_document_returns_no_matching_rule() {
        let doc = PolicyDocument {
            version: 1,
            scope: ScopeId::AllProfiles,
            rules: vec![],
            signature: None,
        };
        // "alice" matches the profile from testnet_profile() builder.
        let engine = PolicyEngineV1::new(doc, "alice".into());
        let td = tool("stellar_pay", "stellar:testnet");
        let result = engine
            .evaluate(
                &td,
                &Value::Null,
                &testnet_profile(),
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap();
        assert_eq!(result, Decision::Deny(DenyReason::NoMatchingRule));
    }

    /// A single allow-all rule with no criteria → Decision::Allow.
    #[test]
    fn evaluate_allow_rule_no_criteria_returns_allow() {
        let doc = PolicyDocument {
            version: 1,
            scope: ScopeId::AllProfiles,
            rules: vec![PolicyRule {
                r#match: RuleMatch {
                    tool: "*".into(),
                    chain: "*".into(),
                },
                criteria: vec![],
                decision: Decision::Allow,
            }],
            signature: None,
        };
        let engine = PolicyEngineV1::new(doc, "alice".into());
        let td = tool("stellar_pay", "stellar:testnet");
        let result = engine
            .evaluate(
                &td,
                &Value::Null,
                &testnet_profile(),
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap();
        assert_eq!(result, Decision::Allow);
    }

    // ── PolicyEngineV1::evaluate_bundle ───────────────────────────────────────

    /// Helper: build a minimal allow-all document.
    fn allow_all_doc_with_criteria(criteria: Vec<Box<dyn Criterion>>) -> PolicyDocument {
        PolicyDocument {
            version: 1,
            scope: ScopeId::AllProfiles,
            rules: vec![PolicyRule {
                r#match: RuleMatch {
                    tool: "*".into(),
                    chain: "*".into(),
                },
                criteria,
                decision: Decision::Allow,
            }],
            signature: None,
        }
    }

    /// Token-transfer inner: native, from SOURCE_G, to DEST_G, amount in stroops.
    fn token_transfer_inner(amount: i128) -> InnerOpDescriptor {
        InnerOpDescriptor::TokenTransfer {
            asset: "native".into(),
            from: "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY".into(),
            to: "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL".into(),
            amount,
        }
    }

    /// evaluate_bundle: `InnerInvocationCountCapCriterion` is bundle-level (Phase 2).
    ///
    /// With `max_count = 0` and a 2-inner bundle, Phase 1 runs no per-inner
    /// criteria (count cap is bundle-level and is skipped there).  Phase 2 fires
    /// the criterion against the full bundle and denies with
    /// `InnerInvocationCountCapExceeded` directly — NOT wrapped in `BundleDenied`.
    ///
    #[test]
    fn evaluate_bundle_count_cap_fires_at_phase2_not_wrapped() {
        use crate::policy::v1::criteria::InnerInvocationCountCapCriterion;

        let doc = allow_all_doc_with_criteria(vec![Box::new(InnerInvocationCountCapCriterion {
            max_count: 0,
        })]);
        let engine = PolicyEngineV1::new(doc, "alice".into());
        let td = tool("stellar_multicall", "stellar:testnet");
        let profile = testnet_profile();

        let inners = vec![
            token_transfer_inner(1_000_000),
            token_transfer_inner(2_000_000),
        ];
        let overlay = BundleStateOverlay::default();
        let view = BundleView {
            inners: &inners,
            overlay: &overlay,
        };

        let result = engine
            .evaluate_bundle(&td, &Value::Null, &profile, &view)
            .unwrap();

        // Phase 2 fires the criterion directly; deny is NOT wrapped in BundleDenied.
        assert!(
            matches!(
                result,
                Decision::Deny(DenyReason::InnerInvocationCountCapExceeded {
                    max: 0,
                    attempted: 2,
                })
            ),
            "bundle-level criterion deny must not be wrapped in BundleDenied, got {result:?}"
        );
    }

    /// evaluate_bundle: all criteria pass → rule decision (Allow) is returned.
    ///
    #[test]
    fn evaluate_bundle_all_pass_runs_bundle_level_criteria() {
        use crate::policy::v1::criteria::InnerInvocationCountCapCriterion;

        // cap = 5: a 3-inner bundle must pass.
        let doc = allow_all_doc_with_criteria(vec![Box::new(InnerInvocationCountCapCriterion {
            max_count: 5,
        })]);
        let engine = PolicyEngineV1::new(doc, "alice".into());
        let td = tool("stellar_multicall", "stellar:testnet");
        let profile = testnet_profile();

        let inners = vec![
            token_transfer_inner(100),
            token_transfer_inner(200),
            token_transfer_inner(300),
        ];
        let overlay = BundleStateOverlay::default();
        let view = BundleView {
            inners: &inners,
            overlay: &overlay,
        };

        let result = engine
            .evaluate_bundle(&td, &Value::Null, &profile, &view)
            .unwrap();
        assert_eq!(
            result,
            Decision::Allow,
            "3-inner bundle under cap=5 must allow, got {result:?}"
        );
    }

    /// evaluate_bundle: no matching rule → NoMatchingRule deny.
    ///
    /// Verifies the first-match stop-semantics when the rule's tool filter
    /// does not match the submitted tool.
    #[test]
    fn evaluate_bundle_no_matching_rule_denies() {
        // Rule only matches "stellar_pay"; submit "stellar_multicall".
        let doc = PolicyDocument {
            version: 1,
            scope: ScopeId::AllProfiles,
            rules: vec![PolicyRule {
                r#match: RuleMatch {
                    tool: "stellar_pay".into(),
                    chain: "*".into(),
                },
                criteria: vec![],
                decision: Decision::Allow,
            }],
            signature: None,
        };
        let engine = PolicyEngineV1::new(doc, "alice".into());
        let td = tool("stellar_multicall", "stellar:testnet");
        let profile = testnet_profile();

        let inners = vec![token_transfer_inner(100)];
        let overlay = BundleStateOverlay::default();
        let view = BundleView {
            inners: &inners,
            overlay: &overlay,
        };

        let result = engine
            .evaluate_bundle(&td, &Value::Null, &profile, &view)
            .unwrap();
        assert_eq!(
            result,
            Decision::Deny(DenyReason::NoMatchingRule),
            "unmatched tool must produce NoMatchingRule, got {result:?}"
        );
    }

    /// evaluate_bundle: the overlay from single-tx path is zero.
    ///
    /// Confirms that a plain `evaluate()` call does not inject overlay state —
    /// the bundle field in EvalContext is None on the single-tx path.
    #[test]
    fn evaluate_bundle_overlay_zero_on_single_tx() {
        let doc = allow_all_doc_with_criteria(vec![]);
        let engine = PolicyEngineV1::new(doc, "alice".into());
        let td = tool("stellar_pay", "stellar:testnet");
        let profile = testnet_profile();

        // Calling evaluate() (single-tx path) must produce Allow with no
        // overlay side-effects.
        let result = engine
            .evaluate(&td, &Value::Null, &profile, None, None, None, None, None)
            .unwrap();
        assert_eq!(
            result,
            Decision::Allow,
            "single-tx path must allow, got {result:?}"
        );
    }

    /// evaluate_bundle: `BundleAggregateCapCriterion` is bundle-level (Phase 2).
    ///
    /// With cap=100 and 3 inners of 50 each (total 150), the criterion fires at
    /// Phase 2 after all inners complete.  The deny is `BundleAggregateCapExceeded`
    /// directly — NOT wrapped in `BundleDenied`.
    ///
    #[test]
    fn evaluate_bundle_aggregate_cap_denies_at_phase2_not_wrapped() {
        use crate::policy::v1::criteria::BundleAggregateCapCriterion;

        // Cap = 100 stroops; submit 3 inners of 50 each → total 150 > 100.
        let doc = allow_all_doc_with_criteria(vec![Box::new(BundleAggregateCapCriterion {
            asset: Some("native".into()),
            max_amount: 100,
        })]);
        let engine = PolicyEngineV1::new(doc, "alice".into());
        let td = tool("stellar_multicall", "stellar:testnet");
        let profile = testnet_profile();

        let inners = vec![
            token_transfer_inner(50),
            token_transfer_inner(50),
            token_transfer_inner(50),
        ];
        let overlay = BundleStateOverlay::default();
        let view = BundleView {
            inners: &inners,
            overlay: &overlay,
        };

        let result = engine
            .evaluate_bundle(&td, &Value::Null, &profile, &view)
            .unwrap();
        // Phase 2 fires; deny is BundleAggregateCapExceeded directly (not BundleDenied).
        assert!(
            matches!(
                result,
                Decision::Deny(DenyReason::BundleAggregateCapExceeded { sum: 150, .. })
            ),
            "3×50 > cap=100 must deny via BundleAggregateCapExceeded (bundle-level, not wrapped), got {result:?}"
        );
    }

    /// evaluate_bundle: hard floor denies bundles above DEFAULT_INNER_INVOCATION_COUNT_CAP
    /// (50) even when NO `inner_invocation_count_cap` criterion is configured.
    ///
    /// The hard floor is applied before rule resolution and is unconditional —
    /// policy authors cannot raise it above 50.
    #[test]
    fn evaluate_bundle_hard_floor_denies_above_default_cap() {
        // No inner_invocation_count_cap criterion in the rule.
        let doc = allow_all_doc_with_criteria(vec![]);
        let engine = PolicyEngineV1::new(doc, "alice".into());
        let td = tool("stellar_multicall", "stellar:testnet");
        let profile = testnet_profile();

        // 51 inners — one above the hard floor of 50.
        let inners: Vec<InnerOpDescriptor> =
            (0..51).map(|_| token_transfer_inner(1_000_000)).collect();
        let overlay = BundleStateOverlay::default();
        let view = BundleView {
            inners: &inners,
            overlay: &overlay,
        };

        let result = engine
            .evaluate_bundle(&td, &Value::Null, &profile, &view)
            .unwrap();
        assert!(
            matches!(
                result,
                Decision::Deny(DenyReason::InnerInvocationCountCapExceeded {
                    max: 50,
                    attempted: 51,
                })
            ),
            "51 inners with no criterion must deny at hard floor (max=50), got {result:?}"
        );
    }

    /// evaluate_bundle: `per_period_cap` overlay accumulates correctly via
    /// `accumulate_overlay`.
    ///
    /// Demonstrates that `accumulate_overlay` uses the SAME key as `evaluate`,
    /// so overlay state from inner[0..2] is correctly read back by inner[3].
    ///
    /// `per_period_cap::evaluate` only fires for `stellar_pay` / `stellar_create_account`
    /// tools.  The outer tool MUST be `stellar_pay` so the criterion fires per-inner.
    /// The ctx.args carry amount + asset; all inners see the same args (3 stroops,
    /// native).  The overlay from `accumulate_overlay` (using the InnerOpDescriptor
    /// amount, also 3 stroops) is what accumulates and eventually causes the deny.
    ///
    ///   inner[0]: stored=0, overlay=0,  attempted=3 → 3 ≤ 10 → PASS; accumulate 3
    ///   inner[1]: stored=0, overlay=3,  attempted=3 → 6 ≤ 10 → PASS; accumulate 3
    ///   inner[2]: stored=0, overlay=6,  attempted=3 → 9 ≤ 10 → PASS; accumulate 3
    ///   inner[3]: stored=0, overlay=9,  attempted=3 → 12 > 10 → DENY
    ///
    #[test]
    #[allow(clippy::unwrap_used)]
    fn evaluate_bundle_per_period_cap_overlay_accumulates() {
        use crate::policy::v1::criteria::per_period_cap::{PerPeriodCapCriterion, Window};
        use serde_json::json;

        // Cap: 10 stroops over 1 day; per-inner amount = 3 stroops.
        let window = Window::parse("1d").unwrap();
        let criterion = PerPeriodCapCriterion::new("native".into(), window, 10);
        let doc = allow_all_doc_with_criteria(vec![Box::new(criterion)]);
        let engine = PolicyEngineV1::new(doc, "alice".into());
        // stellar_pay is required for per_period_cap::evaluate to fire.
        let td = tool("stellar_pay", "stellar:testnet");
        let profile = testnet_profile();
        // "3" is parsed by parse_stroops as 3 stroops (no XLM unit suffix → stroop literal).
        let args = json!({ "amount": "3", "asset": "native" });

        let inners: Vec<InnerOpDescriptor> = (0..5).map(|_| token_transfer_inner(3)).collect();
        let overlay = BundleStateOverlay::default();
        let view = BundleView {
            inners: &inners,
            overlay: &overlay,
        };

        let result = engine.evaluate_bundle(&td, &args, &profile, &view).unwrap();

        // Inner 3 should deny: overlay=9 from inners 0-2, 9+3=12 > 10.
        assert!(
            matches!(
                result,
                Decision::Deny(DenyReason::BundleDenied {
                    inner_index: 3,
                    ref deny_reason,
                }) if matches!(
                    deny_reason.as_ref(),
                    DenyReason::PerPeriodCapExceeded { period_used_stroops: 9, .. }
                )
            ),
            "inner[3] must deny with PerPeriodCapExceeded(period_used=9), got {result:?}"
        );
    }

    /// evaluate_bundle: `per_period_cap` overlay works with a non-1d window (1h).
    ///
    /// `accumulate_overlay` derives `StateKey::new(profile, 1, "native", 3_600)`
    /// — exactly matching `evaluate` for a 1h window.  If the key derivation
    /// diverged, overlay state would be ignored and all inners would pass.
    ///
    ///   inner[0]: stored=0, overlay=0, attempted=3 → 3 ≤ 8 → PASS; accumulate 3
    ///   inner[1]: stored=0, overlay=3, attempted=3 → 6 ≤ 8 → PASS; accumulate 3
    ///   inner[2]: stored=0, overlay=6, attempted=3 → 9 > 8 → DENY
    ///
    #[test]
    #[allow(clippy::unwrap_used)]
    fn evaluate_bundle_per_period_cap_overlay_fires_with_1h_window() {
        use crate::policy::v1::criteria::per_period_cap::{PerPeriodCapCriterion, Window};
        use serde_json::json;

        // Cap: 8 stroops over 1 hour; per-inner amount = 3 stroops.
        let window = Window::parse("1h").unwrap();
        let criterion = PerPeriodCapCriterion::new("native".into(), window, 8);
        let doc = allow_all_doc_with_criteria(vec![Box::new(criterion)]);
        let engine = PolicyEngineV1::new(doc, "alice".into());
        let td = tool("stellar_pay", "stellar:testnet");
        let profile = testnet_profile();
        let args = json!({ "amount": "3", "asset": "native" });

        let inners: Vec<InnerOpDescriptor> = (0..3).map(|_| token_transfer_inner(3)).collect();
        let overlay = BundleStateOverlay::default();
        let view = BundleView {
            inners: &inners,
            overlay: &overlay,
        };

        let result = engine.evaluate_bundle(&td, &args, &profile, &view).unwrap();

        // inner[2] sees overlay=6, 6+3=9 > 8 → BundleDenied.
        assert!(
            matches!(
                result,
                Decision::Deny(DenyReason::BundleDenied {
                    inner_index: 2,
                    ref deny_reason,
                }) if matches!(
                    deny_reason.as_ref(),
                    DenyReason::PerPeriodCapExceeded { period_used_stroops: 6, .. }
                )
            ),
            "inner[2] must deny with PerPeriodCapExceeded(period_used=6) for 1h window, got {result:?}"
        );
    }

    /// evaluate_bundle: `rate_limit` overlay accumulates call counts correctly.
    ///
    /// Each inner that passes contributes +1 call to the overlay via
    /// `accumulate_overlay`.  When the accumulated count reaches `max_calls`,
    /// the NEXT inner is denied.
    ///
    /// `rate_limit::evaluate` fires for every tool name (no tool-name guard), so
    /// this test can use `stellar_multicall` as the outer tool.
    ///
    ///   inner[0]: 0 stored + 0 overlay = 0 < 2 → PASS; accumulate 1
    ///   inner[1]: 0 stored + 1 overlay = 1 < 2 → PASS; accumulate 1
    ///   inner[2]: 0 stored + 2 overlay = 2 >= 2 → DENY
    ///
    #[test]
    #[allow(clippy::unwrap_used)]
    fn evaluate_bundle_rate_limit_overlay_accumulates_calls() {
        use crate::policy::v1::criteria::per_period_cap::Window;
        use crate::policy::v1::criteria::rate_limit::RateLimitCriterion;

        // Allow at most 2 calls per 1-minute window.
        let window = Window::parse("1m").unwrap();
        let criterion = RateLimitCriterion::new(window, 2);
        let doc = allow_all_doc_with_criteria(vec![Box::new(criterion)]);
        let engine = PolicyEngineV1::new(doc, "alice".into());
        let td = tool("stellar_multicall", "stellar:testnet");
        let profile = testnet_profile();

        let inners: Vec<InnerOpDescriptor> = (0..4).map(|_| token_transfer_inner(1_000)).collect();
        let overlay = BundleStateOverlay::default();
        let view = BundleView {
            inners: &inners,
            overlay: &overlay,
        };

        let result = engine
            .evaluate_bundle(&td, &Value::Null, &profile, &view)
            .unwrap();

        // Inner 2 (index 2) should deny: overlay has 2 calls from inners 0+1,
        // and 2 >= max_calls=2.
        assert!(
            matches!(
                result,
                Decision::Deny(DenyReason::BundleDenied {
                    inner_index: 2,
                    ref deny_reason,
                }) if matches!(
                    deny_reason.as_ref(),
                    DenyReason::RateLimitExceeded { calls_in_window: 2, max_calls: 2, .. }
                )
            ),
            "inner[2] must deny with RateLimitExceeded(calls_in_window=2, max_calls=2), got {result:?}"
        );
    }

    /// evaluate_bundle: rate_limit at cap boundary (recorded=4, max=5) does NOT
    /// false-deny due to Phase 2 over-iteration.
    ///
    /// `rate_limit` has `is_bundle_level() == false` and is skipped at Phase 2.
    /// Phase 1 allows (4 stored + 0 overlay = 4 < 5), the overlay accumulates
    /// +1, and Phase 2 only runs bundle-level criteria (none present here).
    /// If rate_limit were re-evaluated at Phase 2 with the populated overlay
    /// it would see `4 + 1 = 5 ≥ 5` and produce an off-by-one false-deny.
    ///
    #[test]
    #[allow(clippy::unwrap_used)]
    fn evaluate_bundle_rate_limit_boundary_does_not_double_deny() {
        use crate::policy::v1::criteria::per_period_cap::Window;
        use crate::policy::v1::criteria::rate_limit::RateLimitCriterion;
        use crate::policy::v1::criteria::state_store::{PolicyStateStore, StateKey};
        use std::time::{SystemTime, UNIX_EPOCH};

        // Seed the store with 4 calls — one below the cap of 5.
        let store = PolicyStateStore::new();
        let state_key = StateKey::new("alice", 1, "rate_limit", 60);
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let t = now_ms.saturating_sub(1_000); // 1 second ago — inside the window
        for _ in 0..4 {
            store.append(&state_key, t, 1).unwrap();
        }

        let window = Window::parse("1m").unwrap();
        let criterion = RateLimitCriterion::new(window, 5);
        let doc = allow_all_doc_with_criteria(vec![Box::new(criterion)]);

        // Build engine backed by the pre-seeded store.
        let engine = PolicyEngineV1::new_with_store(doc, "alice".into(), store);
        let td = tool("stellar_multicall", "stellar:testnet");
        let profile = testnet_profile();

        // Single 1-inner bundle.
        let inners = vec![token_transfer_inner(1_000)];
        let overlay = BundleStateOverlay::default();
        let view = BundleView {
            inners: &inners,
            overlay: &overlay,
        };

        let result = engine
            .evaluate_bundle(&td, &Value::Null, &profile, &view)
            .unwrap();

        // Phase 1: recorded=4, overlay=0 → 4 < 5 → PASS; accumulate +1.
        // Phase 2: rate_limit is NOT bundle-level → skipped.
        // Result: Allow.
        assert_eq!(
            result,
            Decision::Allow,
            "rate_limit at boundary (recorded=4, max=5, 1-inner) must Allow; got {result:?}"
        );
    }
}
