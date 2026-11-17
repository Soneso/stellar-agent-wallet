//! Restricted classic resolution through the public resolver.
//!
//! The outer `stellar_toolset_invoke` rules below are built under the
//! fixture's signed-text loader and substituted below the minimum validator.
//! These focused rules isolate resolution; signed admission is exercised by
//! the MCP public-route tests with complete payment minimums.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test fixtures"
)]

use super::*;
use crate::mainnet::authority::MainnetAuthority;
use crate::mainnet::digest::{BindingFacts, bindings_digest};
use crate::mainnet::fixtures::{ResolverFixture, SIGNER_SEED};
use crate::mainnet::resolve::{
    InvalidationStage, TxSignRequest, invalidate_unconsumed, resolve_tx_sign,
};
use crate::mainnet::{MainnetAuthorizationError, MainnetConsumer};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use stellar_agent_core::asset_id::CanonicalAsset;
use stellar_agent_core::mainnet::decision::{AuthorityScope, MainnetDecision};
use stellar_agent_core::mainnet::toolset_grant::{ToolsetGrantEvidence, ToolsetGrantFacts};
use stellar_agent_core::mainnet::verified_policy::VerifiedPolicy;
use stellar_agent_core::policy::Decision;
use stellar_agent_core::policy::v1::criteria::state_store::{StateKey, WindowEntry, WindowLimit};

const MAINNET_PASSPHRASE: &str = "Public Global Stellar Network ; September 2015";
const UNREACHABLE: &str = "http://127.0.0.1:0";

type ObservationHook = Box<dyn Fn(&str, &serde_json::Value, u64)>;
thread_local! {
    static OBSERVATION_HOOK: std::cell::RefCell<Option<ObservationHook>> = const { std::cell::RefCell::new(None) };
}

pub(crate) fn observe(tool: &str, args: &serde_json::Value, now: u64) {
    OBSERVATION_HOOK.with_borrow(|slot| {
        if let Some(hook) = slot {
            hook(tool, args, now);
        }
    });
}

struct Observing;
impl Drop for Observing {
    fn drop(&mut self) {
        OBSERVATION_HOOK.with_borrow_mut(|slot| *slot = None);
    }
}

fn observing(hook: impl Fn(&str, &serde_json::Value, u64) + 'static) -> Observing {
    OBSERVATION_HOOK.with_borrow_mut(|slot| *slot = Some(Box::new(hook)));
    Observing
}

/// Owned grant facts whose evidence counts its live instances.
#[derive(Clone)]
struct Facts {
    grant_id: String,
    expires_at_unix_ms: u64,
    install_id: String,
    package_version: String,
    package_shasum: String,
    profile_name: String,
    chain_id: String,
    toolset_name: String,
    action: String,
    destination: String,
    asset: String,
    amount_stroops: i64,
}

struct Evidence {
    facts: Facts,
    live: Arc<AtomicUsize>,
}

impl ToolsetGrantEvidence for Evidence {
    fn facts(&self) -> ToolsetGrantFacts<'_> {
        ToolsetGrantFacts {
            grant_id: &self.facts.grant_id,
            expires_at_unix_ms: self.facts.expires_at_unix_ms,
            install_id: &self.facts.install_id,
            package_version: &self.facts.package_version,
            package_shasum: &self.facts.package_shasum,
            profile_name: &self.facts.profile_name,
            chain_id: &self.facts.chain_id,
            toolset_name: &self.facts.toolset_name,
            action: &self.facts.action,
            destination: &self.facts.destination,
            asset: &self.facts.asset,
            amount_stroops: self.facts.amount_stroops,
        }
    }
}

impl Drop for Evidence {
    fn drop(&mut self) {
        self.live.fetch_sub(1, Ordering::SeqCst);
    }
}

impl Facts {
    fn new(f: &ResolverFixture, destination: &str) -> Self {
        Self {
            grant_id: "grant-1".to_owned(),
            expires_at_unix_ms: f.now + 3_600_000,
            install_id: "install-1".to_owned(),
            package_version: "1.0.0".to_owned(),
            package_shasum: "dd".to_owned(),
            profile_name: "operator".to_owned(),
            chain_id: "stellar:mainnet".to_owned(),
            toolset_name: "pay-toolset".to_owned(),
            action: "stellar_pay_commit".to_owned(),
            destination: destination.to_owned(),
            asset: "native".to_owned(),
            amount_stroops: 10,
        }
    }

    fn restriction(&self, live: &Arc<AtomicUsize>) -> ToolsetRestriction {
        live.fetch_add(1, Ordering::SeqCst);
        ToolsetRestriction::new(Box::new(Evidence {
            facts: self.clone(),
            live: Arc::clone(live),
        }))
    }
}

/// The fixture's verified policy over `routed` for `stellar_pay_commit` and
/// `outer` for `stellar_toolset_invoke`, each a rule body after its match.
fn policy(f: &ResolverFixture, routed: &str, outer: &str) -> VerifiedPolicy {
    use ed25519_dalek::Signer as _;
    use stellar_agent_core::policy::v1::{
        PolicyEngineV1, canonical::canonical_bytes, loader::load_signed_policy_text,
        signature::digest,
    };
    let body = format!(
        "version = 2\nscope = \"profile:operator\"\nsequence = 7\n\
         [[rules]]\nmatch = {{ tool = \"stellar_pay_commit\", chain = \"stellar:mainnet\" }}\n{routed}\n\
         [[rules]]\nmatch = {{ tool = \"stellar_toolset_invoke\", chain = \"stellar:mainnet\" }}\n{outer}\n"
    );
    let owner = ed25519_dalek::SigningKey::from_bytes(&[11; 32]);
    let signature = owner.sign(&digest(&canonical_bytes(&body).unwrap()));
    let signed = format!(
        "{body}\n[signature]\nowner_id = \"{}\"\nsig = \"{}\"\n",
        stellar_strkey::ed25519::PublicKey(owner.verifying_key().to_bytes()),
        stellar_agent_core::hex::encode(&signature.to_bytes())
    );
    let document = load_signed_policy_text(
        &signed,
        "operator",
        &owner.verifying_key().to_bytes(),
        MAINNET_PASSPHRASE,
    )
    .unwrap();
    f.policy.with_engine_for_test(Arc::new(
        PolicyEngineV1::new(document, "operator".to_owned())
            .with_policy_digest_for_test(f.policy.digest()),
    ))
}

const ALLOW: &str = "criteria = []\ndecision = \"allow\"";
const DENY_AMOUNT: &str = "criteria = [{ kind = \"per_tx_cap\", asset = \"native\", max_stroops = \"9\" }]\ndecision = \"allow\"";
/// An approval requirement whose 450-second lifetime is shorter than the
/// 600 seconds an `Allow` governs.
const REQUIRE: &str =
    "criteria = []\ndecision = \"require_approval\"\nttl_secs = 450\nreason = \"review\"";
/// An approval lifetime both decisions above permit. The fixture clock runs
/// 300 seconds behind the wall clock, which consent issuance reads.
const LIFETIME: u64 = 450_000;
const OUTER_CAP: &str = "criteria = [{ kind = \"per_period_cap\", window = \"1d\", asset = \"native\", max_stroops = \"100\" }]\ndecision = \"allow\"";

fn policy_authority(f: &ResolverFixture) -> MainnetAuthority<'static> {
    let decision = MainnetDecision::for_test(
        Decision::Allow,
        None,
        f.policy.digest(),
        f.policy.sequence(),
        0,
        "operator",
        "stellar:mainnet",
        f.now,
        60_000,
        AuthorityScope::Classic,
    );
    MainnetAuthority::from_decision(&decision, None).unwrap()
}

#[allow(clippy::too_many_arguments, reason = "every request input varies")]
fn request<'a>(
    f: &'a ResolverFixture,
    context: &'a crate::MainnetWriteContext,
    client: &'a crate::StellarRpcClient,
    policy: &'a VerifiedPolicy,
    authority: &'a MainnetAuthority<'a>,
    envelope: &'a str,
    consumer: MainnetConsumer,
    restriction: Option<ToolsetRestriction>,
) -> TxSignRequest<'a> {
    TxSignRequest {
        context,
        consumer,
        unsigned_envelope_xdr: envelope,
        client,
        probe_deadline: std::time::Duration::from_secs(1),
        witness: None,
        signer: &f.signer,
        policy,
        enablement: &f.enablement,
        authority,
        audit: f.audit(),
        store: &f.window,
        operation: None,
        restriction,
    }
}

/// An unsigned payment of 10 stroops with a text memo to the fixture
/// destination, muxed under `id` when given, valid at the fixture clock.
fn envelope(f: &ResolverFixture, id: Option<u64>) -> String {
    use stellar_xdr::{Limits, Memo, ReadXdr as _, TransactionEnvelope, WriteXdr as _};
    let mut builder =
        stellar_agent_test_support::signed_envelope::SignedTestEnvelope::builder(SIGNER_SEED)
            .network_passphrase(MAINNET_PASSPHRASE)
            .time_bounds(0, f.now / 1000 + 120)
            .amount_stroops(10)
            .sequence(2);
    if let Some(id) = id {
        builder = builder.muxed_destination_id(id);
    }
    let built = builder.unsigned().build();
    let mut decoded =
        TransactionEnvelope::from_xdr_base64(built.envelope_xdr(), Limits::none()).unwrap();
    let TransactionEnvelope::Tx(tx) = &mut decoded else {
        unreachable!()
    };
    tx.tx.memo = Memo::Text(b"approved".to_vec().try_into().unwrap());
    decoded.to_xdr_base64(Limits::none()).unwrap()
}

fn destination_of(envelope: &str) -> String {
    stellar_agent_core::envelope_decode::decode_authoritative_args(envelope, "stellar_pay_commit")
        .unwrap()["destination"]
        .as_str()
        .unwrap()
        .to_owned()
}

fn endpoint_host(f: &ResolverFixture) -> String {
    stellar_agent_core::mainnet::enablement::normalize_endpoint_host(f.context.authority()).unwrap()
}

fn refused(result: Result<impl Sized, MainnetAuthorizationError>) -> P {
    match result {
        Err(MainnetAuthorizationError::Refused(precondition)) => precondition,
        Err(other) => panic!("expected a refused precondition, got {other:?}"),
        Ok(_) => panic!("expected a refused precondition, got an authorization"),
    }
}

#[tokio::test]
#[serial_test::serial(mainnet_clock)]
#[serial_test::serial]
async fn restricted_resolution_binds_the_checked_invocation() {
    let f = ResolverFixture::new();
    let server = f.server().await;
    let live = Arc::new(AtomicUsize::new(0));
    let policy = policy(&f, ALLOW, ALLOW);
    let authority = policy_authority(&f);
    let host = endpoint_host(&f);
    let reachable = f.context_with_routes(&[(&host, &server.uri())]);
    let unreachable = f.context_with_routes(&[(&host, UNREACHABLE)]);
    let plain = envelope(&f, None);
    let base = destination_of(&plain);
    let mut escaped = Facts::new(&f, &base);
    escaped.toolset_name = "pay-\"é\n\u{202e}".to_owned();
    escaped.amount_stroops = 9;
    let restriction = escaped.restriction(&live);
    let mut detail = None;
    let args = stellar_agent_core::envelope_decode::decode_authoritative_args(
        &plain,
        "stellar_pay_commit",
    )
    .unwrap();
    assert_eq!(
        refused(restriction.bind(
            &reachable,
            MainnetConsumer::McpPay,
            &args,
            f.now,
            &mut detail
        )),
        P::ToolsetRestrictionMismatch,
    );
    assert_eq!(
        detail.as_deref(),
        Some("toolset \"pay-\\\"é\\n\\u{202e}\" action \"stellar_pay_commit\"")
    );
    let public = stellar_agent_core::WalletError::from(MainnetAuthorizationError::Refused(
        P::ToolsetRestrictionMismatch,
    ));
    assert_eq!(public.code(), "network.mainnet_authorization_refused");
    assert_eq!(
        public.to_string(),
        "the mainnet write was refused before submission; nothing was sent"
    );
    drop(restriction);
    let base_key = stellar_strkey::ed25519::PublicKey::from_string(&base)
        .unwrap()
        .0;
    let muxed = |id| {
        stellar_strkey::ed25519::MuxedAccount {
            ed25519: base_key,
            id,
        }
        .to_string()
        .to_string()
    };
    for (case, edit, consumer, expected) in [
        (
            "consumer",
            (|_: &mut Facts| {}) as fn(&mut Facts),
            MainnetConsumer::CliPay,
            P::ToolsetRestrictionConsumer,
        ),
        (
            "action",
            |facts| facts.action = "stellar_pay".to_owned(),
            MainnetConsumer::McpPay,
            P::ToolsetRestrictionConsumer,
        ),
        (
            "profile",
            |facts| facts.profile_name = "other".to_owned(),
            MainnetConsumer::McpPay,
            P::ToolsetRestrictionMismatch,
        ),
        (
            "chain",
            |facts| facts.chain_id = "stellar:testnet".to_owned(),
            MainnetConsumer::McpPay,
            P::ToolsetRestrictionMismatch,
        ),
        (
            "destination",
            |facts| facts.destination = crate::mainnet::fixtures::account([9; 32]),
            MainnetConsumer::McpPay,
            P::ToolsetRestrictionMismatch,
        ),
        (
            "asset",
            |facts| {
                facts.asset =
                    "USD:GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF".to_owned();
            },
            MainnetConsumer::McpPay,
            P::ToolsetRestrictionMismatch,
        ),
        (
            "amount",
            |facts| facts.amount_stroops = 11,
            MainnetConsumer::McpPay,
            P::ToolsetRestrictionMismatch,
        ),
        (
            "expired",
            |facts| facts.expires_at_unix_ms = 0,
            MainnetConsumer::McpPay,
            P::ToolsetGrantExpired,
        ),
    ] {
        let mut facts = Facts::new(&f, &base);
        edit(&mut facts);
        let client = unreachable.primary_client().unwrap();
        let before = f.wire();
        let result = resolve_tx_sign(request(
            &f,
            &unreachable,
            &client,
            &policy,
            &authority,
            &plain,
            consumer,
            Some(facts.restriction(&live)),
        ))
        .await;
        assert_eq!(refused(result), expected, "{case}");
        assert_eq!(f.wire(), before, "a refused binding mints nothing: {case}");
    }
    // A muxed ID of the same base account is another invocation.
    let client = unreachable.primary_client().unwrap();
    let result = resolve_tx_sign(request(
        &f,
        &unreachable,
        &client,
        &policy,
        &authority,
        &plain,
        MainnetConsumer::McpPay,
        Some(Facts::new(&f, &muxed(0)).restriction(&live)),
    ))
    .await;
    assert_eq!(refused(result), P::ToolsetRestrictionMismatch, "M0 for G");
    for (id, asset) in [
        (None, "native"),
        (Some(0), "XLM"),
        (Some(u64::MAX), "native"),
    ] {
        let paid = envelope(&f, id);
        let destination = destination_of(&paid);
        assert_eq!(destination, id.map_or(base.clone(), muxed), "{id:?}");
        let mut facts = Facts::new(&f, &destination);
        facts.asset = asset.to_owned();
        let client = reachable.primary_client().unwrap();
        let auth = resolve_tx_sign(request(
            &f,
            &reachable,
            &client,
            &policy,
            &authority,
            &paid,
            MainnetConsumer::McpPay,
            Some(facts.restriction(&live)),
        ))
        .await
        .unwrap_or_else(|error| panic!("{id:?}: {error:?}"));
        invalidate_unconsumed(
            &f.window,
            &reachable,
            auth.id(),
            InvalidationStage::PreSendRefused,
        )
        .unwrap();
        if id.is_some() {
            let mut other = Facts::new(&f, &muxed(id.unwrap().wrapping_add(1)));
            other.asset = asset.to_owned();
            let client = unreachable.primary_client().unwrap();
            let result = resolve_tx_sign(request(
                &f,
                &unreachable,
                &client,
                &policy,
                &authority,
                &paid,
                MainnetConsumer::McpPay,
                Some(other.restriction(&live)),
            ))
            .await;
            assert_eq!(refused(result), P::ToolsetRestrictionMismatch, "{id:?}");
        }
    }
    // The restriction compares exact signed amounts and canonical assets,
    // including the largest amount representable in a classic payment.
    for issued in [false, true] {
        for amount in [1, i64::MAX] {
            use stellar_xdr::{
                AccountId, AlphaNum4, Asset, AssetCode4, Limits, OperationBody, PublicKey,
                ReadXdr as _, TransactionEnvelope, Uint256, WriteXdr as _,
            };
            let mut decoded = TransactionEnvelope::from_xdr_base64(&plain, Limits::none()).unwrap();
            let TransactionEnvelope::Tx(tx) = &mut decoded else {
                unreachable!()
            };
            let mut operations = tx.tx.operations.to_vec();
            let OperationBody::Payment(payment) = &mut operations[0].body else {
                unreachable!()
            };
            payment.amount = amount;
            let asset = if issued {
                payment.asset = Asset::CreditAlphanum4(AlphaNum4 {
                    asset_code: AssetCode4(*b"USD\0"),
                    issuer: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([7; 32]))),
                });
                format!("USD:{}", stellar_strkey::ed25519::PublicKey([7; 32]))
            } else {
                "native".to_owned()
            };
            tx.tx.operations = operations.try_into().unwrap();
            let paid = decoded.to_xdr_base64(Limits::none()).unwrap();
            for matches in [false, true] {
                let mut facts = Facts::new(&f, &base);
                facts.asset = asset.clone();
                facts.amount_stroops = if matches { amount } else { amount - 1 };
                let args = stellar_agent_core::envelope_decode::decode_authoritative_args(
                    &paid,
                    "stellar_pay_commit",
                )
                .unwrap();
                let restriction = facts.restriction(&live);
                let result =
                    restriction.bind(&reachable, MainnetConsumer::McpPay, &args, f.now, &mut None);
                if matches {
                    assert!(result.is_ok(), "asset {asset}, amount {amount}: {result:?}");
                } else {
                    assert_eq!(
                        refused(result),
                        P::ToolsetRestrictionMismatch,
                        "asset {asset}, amount {amount} must bind exactly"
                    );
                }
            }
        }
    }
    drop(server);
    assert_eq!(live.load(Ordering::SeqCst), 0, "every restriction released");
}

/// Resolves the fixture payment under `policy` and `authority` with a
/// matching restriction.
async fn restricted(
    f: &ResolverFixture,
    policy: &VerifiedPolicy,
    authority: &MainnetAuthority<'_>,
    facts: Facts,
    live: &Arc<AtomicUsize>,
) -> Result<crate::mainnet::authorization::MainnetTxSignAuthorization, MainnetAuthorizationError> {
    let server = f.server().await;
    let context = f.context_with_routes(&[(&endpoint_host(f), &server.uri())]);
    let client = context.primary_client().unwrap();
    let result = resolve_tx_sign(request(
        f,
        &context,
        &client,
        policy,
        authority,
        &f.envelope,
        MainnetConsumer::McpPay,
        Some(facts.restriction(live)),
    ))
    .await;
    if let Ok(auth) = &result {
        invalidate_unconsumed(
            &f.window,
            &context,
            auth.id(),
            InvalidationStage::PreSendRefused,
        )
        .unwrap();
    }
    result
}

fn fixture_facts(f: &ResolverFixture) -> Facts {
    Facts::new(f, &destination_of(&f.envelope))
}

#[tokio::test]
#[serial_test::serial(mainnet_clock)]
#[serial_test::serial]
async fn restricted_pair_uses_one_final_frame_and_checks_both_decisions() {
    let f = ResolverFixture::new();
    let live = Arc::new(AtomicUsize::new(0));
    let witness = f.approval(&f.envelope, f.now, LIFETIME);
    let approval = f.approval_authority(&witness);
    let policy_authority = policy_authority(&f);
    // The outer amount cap reads the authoritative amount of 10.
    let denying = policy(&f, ALLOW, DENY_AMOUNT);
    let denied = restricted(&f, &denying, &approval, fixture_facts(&f), &live).await;
    let Err(MainnetAuthorizationError::PolicyDenied(reason)) = denied else {
        panic!("the final outer cap must deny ten against nine: {denied:?}")
    };
    assert_eq!(
        *reason,
        stellar_agent_core::policy::DenyReason::PerTxCapExceeded {
            asset: "native".to_owned(),
            max_stroops: 9,
            attempted_stroops: 10,
        },
        "the final outer evaluation sizes the decoded payment"
    );
    assert_eq!(
        refused(restricted(&f, &denying, &policy_authority, fixture_facts(&f), &live).await),
        P::FreshDecisionRequiresApproval
    );
    let requiring = policy(&f, ALLOW, REQUIRE);
    assert_eq!(
        refused(restricted(&f, &requiring, &policy_authority, fixture_facts(&f), &live).await),
        P::FreshDecisionRequiresApproval,
        "an outer approval requirement needs an approval"
    );
    restricted(&f, &requiring, &approval, fixture_facts(&f), &live)
        .await
        .expect("an approval covers the outer requirement");
    // Durable spend of 95 leaves 5 under the outer cap; only the private
    // frame hydrated from the store sees it.
    let capped = policy(&f, ALLOW, OUTER_CAP);
    f.window
        .record_authorized(
            &f.profile,
            &[WindowEntry::new(
                StateKey::new("operator", 1, "native", 86_400),
                f.now,
                95,
                WindowLimit::Amount {
                    asset: "native".to_owned(),
                    window: "1d".to_owned(),
                    max_stroops: 100,
                },
            )],
        )
        .unwrap();
    let before = f.wire();
    assert_eq!(
        refused(restricted(&f, &capped, &policy_authority, fixture_facts(&f), &live).await),
        P::FreshDecisionRequiresApproval,
        "the outer evaluation reads durable spend at the frame's instant"
    );
    assert_eq!(f.wire(), before);
    assert_eq!(live.load(Ordering::SeqCst), 0);
}

#[tokio::test]
#[serial_test::serial(mainnet_clock)]
#[serial_test::serial]
async fn unrestricted_resolution_keeps_literal_singleton_facts() {
    let f = ResolverFixture::new();
    // No rule permits the outer descriptor, so an outer evaluation would deny.
    let policy = policy(
        &f,
        "criteria = [{ kind = \"rate_limit\", window = \"1d\", max_calls = 10 }, { kind = \"rate_limit\", window = \"1d\", max_calls = 10 }]\ndecision = \"allow\"",
        DENY_AMOUNT,
    );
    let witness = f.approval(&f.envelope, f.now, LIFETIME);
    let authority = f.approval_authority(&witness);
    let server = f.server().await;
    let context = f.context_with_routes(&[(&endpoint_host(&f), &server.uri())]);
    let client = context.primary_client().unwrap();
    let observed = Arc::new(std::sync::Mutex::new(Vec::new()));
    let events = Arc::clone(&observed);
    let _observing = observing(move |tool, args, now| {
        events
            .lock()
            .unwrap()
            .push((tool.to_owned(), args.clone(), now))
    });
    let auth = resolve_tx_sign(request(
        &f,
        &context,
        &client,
        &policy,
        &authority,
        &f.envelope,
        MainnetConsumer::McpPay,
        None,
    ))
    .await
    .unwrap();
    let hold = WindowEntry::new(
        StateKey::new("operator", 1, "rate_limit", 86_400),
        f.now,
        1,
        WindowLimit::Count {
            window: "1d".to_owned(),
            max_calls: 10,
        },
    );
    assert_eq!(auth.entries(), &[hold.clone(), hold][..]);
    assert_eq!(auth.expires_at_ms(), f.now + 60_000);
    assert_eq!(
        f.wire()["authorizations"][0]["bindings_digest"],
        stellar_agent_core::hex::encode(&auth.0.header.bindings_digest),
        "the unrestricted stored binding is the returned authorization binding"
    );
    assert_eq!(
        refused(auth.check_unsigned_envelope(&[0xff; 32])),
        P::UnsignedEnvelope
    );
    let events = observed.lock().unwrap().clone();
    assert_eq!(
        events.len(),
        1,
        "unrestricted resolution performs one evaluation and no private hydration"
    );
    assert_eq!(events[0].0, "stellar_pay_commit");
    assert_eq!(events[0].2, f.now);
    let requests = server.received_requests().await.unwrap();
    let reads: Vec<serde_json::Value> = requests
        .iter()
        .map(|request| serde_json::from_slice(&request.body).unwrap())
        .filter(|request: &serde_json::Value| request["method"] == "getLedgerEntries")
        .collect();
    assert_eq!(reads.len(), 1);
    assert_eq!(
        reads[0]["params"]["keys"],
        serde_json::json!([
            stellar_agent_test_support::xdr_fixtures::account_ledger_key_xdr(f.source.source())
        ])
    );
}

#[tokio::test]
#[serial_test::serial(mainnet_clock)]
#[serial_test::serial]
async fn restricted_pair_observes_one_frame_despite_shared_state_changes() {
    let f = ResolverFixture::new();
    let policy = policy(&f, ALLOW, OUTER_CAP);
    let authority = policy_authority(&f);
    let live = Arc::new(AtomicUsize::new(0));
    let server = f.server().await;
    let context = f.context_with_routes(&[(&endpoint_host(&f), &server.uri())]);
    let client = context.primary_client().unwrap();
    let observed = Arc::new(std::sync::Mutex::new(Vec::new()));
    let events = Arc::clone(&observed);
    let engine = policy.engine();
    let _observing = observing(move |tool, args, now| {
        events
            .lock()
            .unwrap()
            .push((tool.to_owned(), args.clone(), now));
        if tool == "stellar_toolset_invoke" {
            engine
                .state_store()
                .append(&StateKey::new("operator", 1, "native", 86_400), now, 95)
                .unwrap();
        }
    });
    let auth = resolve_tx_sign(request(
        &f,
        &context,
        &client,
        &policy,
        &authority,
        &f.envelope,
        MainnetConsumer::McpPay,
        Some(fixture_facts(&f).restriction(&live)),
    ))
    .await
    .expect("the private pair retains its original empty window despite a shared-state write");
    assert_eq!(auth.entries().len(), 1);
    assert_eq!(auth.entries()[0].amount(), 10);
    let events = observed.lock().unwrap().clone();
    assert_eq!(
        events
            .iter()
            .map(|event| event.0.as_str())
            .collect::<Vec<_>>(),
        ["hydrate", "stellar_pay_commit", "stellar_toolset_invoke"]
    );
    assert!(events.iter().all(|event| event.2 == f.now));
    let mut outer = events[1].1.clone();
    outer["toolset"] = "pay-toolset".into();
    outer["action"] = "stellar_pay_commit".into();
    assert_eq!(
        events[2].1, outer,
        "the outer evaluation retains every authoritative argument"
    );
    assert_eq!(
        outer,
        serde_json::json!({
            "source": f.source.source(), "destination": f.source.destination(), "amount_stroops": "10", "asset": "XLM",
            "total_fee_stroops": 100, "sequence_number": 2, "memo": "approved", "memo_kind": "text",
            "toolset": "pay-toolset", "action": "stellar_pay_commit",
        })
    );
    let requests = server.received_requests().await.unwrap();
    let reads: Vec<serde_json::Value> = requests
        .iter()
        .map(|request| serde_json::from_slice(&request.body).unwrap())
        .filter(|request: &serde_json::Value| request["method"] == "getLedgerEntries")
        .collect();
    assert_eq!(
        reads.len(),
        1,
        "the pair reads its source once and no destination/cache identity"
    );
    assert_eq!(
        reads[0]["params"]["keys"],
        serde_json::json!([
            stellar_agent_test_support::xdr_fixtures::account_ledger_key_xdr(f.source.source())
        ])
    );
}

#[tokio::test]
#[serial_test::serial(mainnet_clock)]
#[serial_test::serial]
async fn restricted_outer_memo_and_absent_identity_use_authoritative_facts() {
    let f = ResolverFixture::new();
    let live = Arc::new(AtomicUsize::new(0));
    let witness = f.approval(&f.envelope, f.now, LIFETIME);
    let authority = f.approval_authority(&witness);
    for (memo, allowed) in [("approved", true), ("changed", false)] {
        let outer = format!(
            "criteria = [{{ kind = \"memo_binding\", bindings = [{{ destination = \"{}\", kind = \"text\", value = \"{memo}\" }}] }}]\ndecision = \"allow\"",
            f.source.destination()
        );
        let policy = policy(&f, ALLOW, &outer);
        let result = restricted(&f, &policy, &authority, fixture_facts(&f), &live).await;
        if allowed {
            assert!(
                result.is_ok(),
                "the exact signed memo permits resolution: {result:?}"
            );
        } else {
            assert!(
                matches!(result, Err(MainnetAuthorizationError::PolicyDenied(_))),
                "the outer rule must reject a different memo: {result:?}"
            );
        }
    }
    let policy = policy(
        &f,
        ALLOW,
        "criteria = [{ kind = \"home_domain_resolved\" }]\ndecision = \"allow\"",
    );
    assert_eq!(
        refused(restricted(&f, &policy, &authority, fixture_facts(&f), &live).await),
        P::PolicyEvaluationFailed,
        "below-validator identity rules refuse without an identity view"
    );
    assert_eq!(live.load(Ordering::SeqCst), 0);
}

#[tokio::test]
#[serial_test::serial(mainnet_clock)]
#[serial_test::serial]
async fn restricted_composition_holds_the_outer_only_cap() {
    let f = ResolverFixture::new();
    let live = Arc::new(AtomicUsize::new(0));
    let policy = policy(&f, ALLOW, OUTER_CAP);
    let authority = policy_authority(&f);
    let server = f.server().await;
    let context = f.context_with_routes(&[(&endpoint_host(&f), &server.uri())]);
    let client = context.primary_client().unwrap();
    let auth = resolve_tx_sign(request(
        &f,
        &context,
        &client,
        &policy,
        &authority,
        &f.envelope,
        MainnetConsumer::McpPay,
        Some(fixture_facts(&f).restriction(&live)),
    ))
    .await
    .unwrap();
    assert_eq!(
        auth.entries(),
        &[WindowEntry::new(
            StateKey::new("operator", 1, "native", 86_400),
            f.now,
            10,
            WindowLimit::Amount {
                asset: "native".to_owned(),
                window: "1d".to_owned(),
                max_stroops: 100,
            },
        )][..],
        "the outer-only cap is held"
    );
}

#[tokio::test]
#[serial_test::serial(mainnet_clock)]
#[serial_test::serial]
async fn restricted_authorization_keeps_the_original_grant_end() {
    let f = ResolverFixture::new();
    let live = Arc::new(AtomicUsize::new(0));
    let permitting = policy(&f, ALLOW, ALLOW);
    let authority = policy_authority(&f);
    for (end, expected) in [
        (f.now + 5_000, Ok(f.now + 5_000)),
        (f.now + 1, Ok(f.now + 1)),
        (u64::MAX, Ok(f.now + 60_000)),
        (f.now, Err(P::ToolsetGrantExpired)),
        (0, Err(P::ToolsetGrantExpired)),
    ] {
        let mut facts = fixture_facts(&f);
        facts.expires_at_unix_ms = end;
        let result = restricted(&f, &permitting, &authority, facts, &live).await;
        match expected {
            Ok(expires) => {
                let auth = result.unwrap();
                assert_eq!(auth.expires_at_ms(), expires, "grant end {end}");
                let record = f.wire()["authorizations"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|record| record["id"] == serde_json::to_value(auth.id()).unwrap())
                    .unwrap()
                    .clone();
                assert_eq!(record["expires_ms"], expires, "grant end {end}");
            }
            Err(precondition) => assert_eq!(refused(result), precondition, "grant end {end}"),
        }
    }
    // An approval lifetime that fits the routed rule must also fit the outer.
    let requiring = policy(&f, ALLOW, REQUIRE);
    for (lifetime, fits) in [(LIFETIME, true), (LIFETIME + 1, false)] {
        let witness = f.approval(&f.envelope, f.now, lifetime);
        let approval = f.approval_authority(&witness);
        let result = restricted(&f, &requiring, &approval, fixture_facts(&f), &live).await;
        if fits {
            result.unwrap();
        } else {
            assert_eq!(refused(result), P::ApprovalTtlExceedsRule, "{lifetime}");
        }
    }
    assert_eq!(live.load(Ordering::SeqCst), 0);
}

#[tokio::test]
#[serial_test::serial(mainnet_clock)]
#[serial_test::serial]
async fn restriction_facts_change_bindings_without_changing_none() {
    let f = ResolverFixture::new();
    let base = fixture_facts(&f);
    let digest = |facts: &Facts| {
        let live = Arc::new(AtomicUsize::new(0));
        let restriction = facts.restriction(&live);
        let facts = restriction.facts();
        facts.fact_digest(&facts.canonical_asset().unwrap())
    };
    let reference = digest(&base);
    let mut alias = base.clone();
    alias.asset = "XLM".to_owned();
    assert_eq!(
        digest(&alias),
        reference,
        "equivalent asset spellings bind alike"
    );
    let edits: [fn(&mut Facts); 12] = [
        |facts| facts.grant_id = "grant-2".to_owned(),
        |facts| facts.expires_at_unix_ms += 1,
        |facts| facts.install_id = "install-2".to_owned(),
        |facts| facts.profile_name = "other".to_owned(),
        |facts| facts.chain_id = "stellar:testnet".to_owned(),
        |facts| facts.toolset_name = "pay-toolset\u{0}é".to_owned(),
        |facts| facts.action = "stellar_pay".to_owned(),
        |facts| facts.destination.push('X'),
        |facts| {
            facts.asset = "USD:GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF".to_owned()
        },
        |facts| facts.amount_stroops += 1,
        |facts| facts.package_version = "1.0.1".to_owned(),
        |facts| facts.package_shasum = "ee".to_owned(),
    ];
    let mut seen = vec![reference];
    for (index, edit) in edits.into_iter().enumerate() {
        let mut facts = base.clone();
        edit(&mut facts);
        let changed = digest(&facts);
        assert!(!seen.contains(&changed), "fact {index} changes the digest");
        seen.push(changed);
    }
    let unrestricted = BindingFacts {
        endpoint: Some([1; 32]),
        signer: [2; 32],
        policy: [3; 32],
        enablement: [4; 32],
        witness: None,
        reservation: Some([6; 32]),
        authority: [7; 32],
        audit: [8; 32],
        restriction: None,
    };
    let restricted = |digest| BindingFacts {
        restriction: Some(digest),
        ..unrestricted
    };
    assert_ne!(
        bindings_digest(&restricted(seen[0])),
        bindings_digest(&unrestricted)
    );
    assert_ne!(
        bindings_digest(&restricted(seen[0])),
        bindings_digest(&restricted(seen[1])),
        "changing only the grant ID changes the bindings"
    );
    assert_eq!(
        stellar_agent_core::hex::encode(&bindings_digest(&unrestricted)),
        "9d918e1e1855fd58664f4e9944871ad629dbfb2c1f038ff9266e51498ff2bcc2",
        "an unrestricted digest keeps its earlier bytes"
    );
    assert_eq!(
        CanonicalAsset::parse_payment_asset("XLM"),
        CanonicalAsset::parse_payment_asset("native")
    );
}

#[tokio::test]
#[serial_test::serial(mainnet_clock)]
#[serial_test::serial]
async fn restricted_authorization_keeps_lease_until_drop() {
    let f = ResolverFixture::new();
    let live = Arc::new(AtomicUsize::new(0));
    let policy = policy(&f, ALLOW, ALLOW);
    let authority = policy_authority(&f);
    let server = f.server().await;
    let context = f.context_with_routes(&[(&endpoint_host(&f), &server.uri())]);
    let client = context.primary_client().unwrap();
    let auth = resolve_tx_sign(request(
        &f,
        &context,
        &client,
        &policy,
        &authority,
        &f.envelope,
        MainnetConsumer::McpPay,
        Some(fixture_facts(&f).restriction(&live)),
    ))
    .await
    .unwrap();
    assert_eq!(
        live.load(Ordering::SeqCst),
        1,
        "the authorization owns the restriction"
    );
    drop(auth);
    assert_eq!(
        live.load(Ordering::SeqCst),
        0,
        "dropping the authorization releases it"
    );
    let mut expired = fixture_facts(&f);
    expired.expires_at_unix_ms = f.now;
    let _ = restricted(&f, &policy, &authority, expired, &live).await;
    assert_eq!(live.load(Ordering::SeqCst), 0, "a refusal releases it");
}

#[tokio::test]
#[serial_test::serial(mainnet_clock)]
#[serial_test::serial]
async fn restriction_never_bypasses_routed_authority() {
    let f = ResolverFixture::new();
    let live = Arc::new(AtomicUsize::new(0));
    let witness = f.approval(&f.envelope, f.now, LIFETIME);
    let approval = f.approval_authority(&witness);
    let policy_authority = policy_authority(&f);
    let denying = policy(&f, DENY_AMOUNT, ALLOW);
    assert!(matches!(
        restricted(&f, &denying, &approval, fixture_facts(&f), &live).await,
        Err(MainnetAuthorizationError::PolicyDenied(_))
    ));
    assert_eq!(
        refused(restricted(&f, &denying, &policy_authority, fixture_facts(&f), &live).await),
        P::FreshDecisionRequiresApproval
    );
    let requiring = policy(&f, REQUIRE, ALLOW);
    assert_eq!(
        refused(restricted(&f, &requiring, &policy_authority, fixture_facts(&f), &live).await),
        P::FreshDecisionRequiresApproval,
        "a routed approval requirement needs an approval"
    );
    restricted(&f, &requiring, &approval, fixture_facts(&f), &live)
        .await
        .expect("an approval covers both permitting decisions");
}
