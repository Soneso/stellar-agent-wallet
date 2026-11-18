mod composed {
    use super::*;
    use ed25519_dalek::{Signer as _, SigningKey};
    use stellar_agent_core::policy::v1::PolicyEngineV1;
    use stellar_agent_core::policy::v1::canonical::canonical_bytes;
    use stellar_agent_core::policy::v1::loader::load_signed_policy_text;
    use stellar_agent_core::policy::v1::signature::digest;
    use stellar_agent_core::policy::v1::value::{ActionKind, ValueClass, ValueLeg};
    use stellar_agent_core::policy::{
        Decision, Evaluation, McpToolRegistration, PolicyEngine as _, PolicyEvaluationInputs,
        PolicyEvaluationSnapshot, ToolDescriptor, ToolValueKind,
    };

    const DEST: &str = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";

    struct Rules {
        engine: PolicyEngineV1,
        digest: [u8; 32],
        routed: ToolDescriptor,
        outer: ToolDescriptor,
    }

    fn descriptor(name: &'static str) -> ToolDescriptor {
        ToolDescriptor::from_registration(&McpToolRegistration {
            name,
            destructive_hint: true,
            read_only_hint: false,
            chain_id_required: true,
            value_kind: ToolValueKind::MovesValue,
        })
    }

    impl Rules {
        fn new(l: &Ledger, kind: &str, listed: (bool, bool)) -> Self {
            let wide = kind == "unlisted_wide";
            let kind = if wide { "unlisted" } else { kind };
            let criterion = |cap, listed| match kind {
                "count" => {
                    format!("{{ kind = \"rate_limit\", window = \"1d\", max_calls = {cap} }}")
                }
                "total" => format!(
                    "{{ kind = \"total_budget\", asset = \"native\", max_stroops = {cap} }}"
                ),
                "unlisted" => format!(
                    "{{ kind = \"counterparty_allowlist\", kinds = [\"G_ACCOUNT\"], allowlist = [{}], unlisted = {{ mode = \"budget\", per_tx_stroops = 200, per_period_stroops = {cap}, asset = \"native\", window = \"1d\" }} }}",
                    if listed {
                        format!("\"{DEST}\"")
                    } else {
                        String::new()
                    }
                ),
                _ => format!(
                    "{{ kind = \"per_period_cap\", asset = \"native\", window = \"1d\", max_stroops = {cap} }}"
                ),
            };
            // Signed policies require every unlisted table to be identical.
            let routed = criterion(
                if wide {
                    200
                } else if matches!(kind, "unlisted" | "repeated_tight") {
                    100
                } else {
                    200
                },
                listed.0,
            );
            let mut outer = criterion(
                match kind {
                    "count" => 42,
                    _ if wide => 200,
                    _ => 100,
                },
                listed.1,
            );
            if kind == "amount" {
                outer = outer.replace("asset = \"native\"", "asset = \"XLM\"");
            } else if kind == "total" {
                let contract = stellar_agent_core::asset_id::CanonicalAsset::Native
                    .sac_contract_id(&l.profile.network_passphrase)
                    .unwrap();
                outer = outer.replace("asset = \"native\"", &format!("asset = \"{contract}\""));
            }
            let routed = if kind.starts_with("repeated") {
                format!("{routed}, {routed}")
            } else {
                routed
            };
            let body = format!(
                "version = 2\nscope = \"profile:ledger\"\nsequence = 7\n\
                 [[rules]]\nmatch = {{ tool = \"stellar_pay_commit\", chain = \"*\" }}\n\
                 criteria = [{routed}]\ndecision = \"allow\"\n\
                 [[rules]]\nmatch = {{ tool = \"stellar_pay\", chain = \"*\" }}\n\
                 criteria = [{outer}, {{ kind = \"rate_limit\", window = \"1h\", max_calls = 100 }}]\n\
                 decision = \"allow\"\n"
            );
            let digest = digest(&canonical_bytes(&body).unwrap());
            let owner = SigningKey::from_bytes(&[11; 32]);
            let signed = format!(
                "{body}\n[signature]\nowner_id = \"{}\"\nsig = \"{}\"\n",
                stellar_strkey::ed25519::PublicKey(owner.verifying_key().to_bytes()),
                stellar_agent_core::hex::encode(&owner.sign(&digest).to_bytes())
            );
            let document = load_signed_policy_text(
                &signed,
                "ledger",
                &owner.verifying_key().to_bytes(),
                &l.profile.network_passphrase,
            )
            .unwrap();
            l.pin(7, digest);
            Self {
                engine: PolicyEngineV1::new(document, "ledger".to_owned())
                    .with_policy_digest_for_test(digest),
                digest,
                routed: descriptor("stellar_pay_commit"),
                outer: descriptor("stellar_pay"),
            }
        }

        fn snapshot(&self, l: &Ledger) -> PolicyEvaluationSnapshot {
            let memory = PolicyStateStore::new();
            l.store
                .load_into_at("ledger", &l.profile, &memory, T0)
                .unwrap();
            PolicyEvaluationSnapshot::new(memory, T0)
        }

        fn evaluate(
            &self,
            l: &Ledger,
            snapshot: &PolicyEvaluationSnapshot,
            tool: &ToolDescriptor,
            amount: i128,
        ) -> Evaluation {
            let evaluation = self
                .engine
                .evaluate_in_snapshot(
                    PolicyEvaluationInputs {
                        tool,
                        args: &serde_json::Value::Null,
                        profile: &l.profile,
                        value: Some(ValueClass::single(ValueLeg {
                            kind: ActionKind::Payment,
                            amount: Some(amount),
                            asset: Some("native".to_owned()),
                            destination: Some(DEST.to_owned()),
                        })),
                        account_view: None,
                        identity_view: None,
                        counterparty_cache: None,
                        sep10_sessions: None,
                        sep45_sessions: None,
                        provisional: false,
                    },
                    snapshot,
                )
                .unwrap();
            assert_eq!(
                evaluation.decision,
                Decision::Allow,
                "real rule permits before atomic admission"
            );
            evaluation
        }

        fn holds(
            &self,
            l: &Ledger,
            snapshot: &PolicyEvaluationSnapshot,
            amount: i128,
            composed: bool,
        ) -> Vec<WindowEntry> {
            let routed = self.evaluate(l, snapshot, &self.routed, amount);
            let outer = self.evaluate(l, snapshot, &self.outer, amount);
            crate::mainnet::holds::size_evaluated_holds(
                &self.engine,
                &l.profile,
                (&self.routed, &routed),
                composed.then_some((&self.outer, &outer)),
                snapshot.now_ms(),
            )
            .unwrap()
        }

        fn request(&self, l: &Ledger, id: u8, holds: Vec<WindowEntry>) -> MintRequest {
            let mut request = l.request(tx(id), holds);
            request.policy_digest = self.digest;
            request
        }

        fn recovery_request(&self, l: &Ledger, holds: Vec<WindowEntry>) -> MintRequest {
            let mut request = self.request(l, 1, holds);
            request.authority = MintAuthority::Policy(PolicyAuthorityBinding {
                policy_digest: self.digest,
                ..policy_binding(T0 + APPROVAL_MS)
            });
            request
        }
    }

    fn assert_holds(l: &Ledger, id: AuthorizationId, expected: &[WindowEntry]) {
        let reopened = PersistedWindowStore::at_path(l.store.path().to_owned());
        let wire = reopened.read_for_inspection(&l.profile).unwrap().unwrap();
        let actual: Vec<_> = wire
            .holds
            .iter()
            .filter(|h| h.authorization_id == id)
            .map(|h| {
                (
                    h.ordinal,
                    h.scope_specificity,
                    h.bucket.clone(),
                    h.window_secs,
                    h.ts_ms,
                    h.amount,
                    h.epoch,
                )
            })
            .collect();
        let expected: Vec<_> = expected
            .iter()
            .enumerate()
            .map(|(i, e)| {
                (
                    u32::try_from(i).unwrap(),
                    e.key().scope_specificity(),
                    e.key().bucket().to_owned(),
                    e.key().window_secs(),
                    e.timestamp_ms(),
                    e.amount(),
                    e.epoch(),
                )
            })
            .collect();
        assert_eq!(
            actual, expected,
            "reopened authorization keeps every composed hold"
        );
    }

    // Ordinary authorization holds are durable-only; hydration supplies history.
    fn usage_with_holds(
        l: &Ledger,
        memory: &PolicyStateStore,
        key: &StateKey,
        now: u64,
    ) -> (i128, u32) {
        let history = memory.query_window(key, now).unwrap();
        l.wire()
            .holds
            .iter()
            .filter(|h| {
                h.scope_specificity == key.scope_specificity()
                    && h.bucket == key.bucket()
                    && h.window_secs == key.window_secs()
            })
            .fold(history, |(sum, count), h| (sum + h.amount, count + 1))
    }

    #[test]
    #[serial(mainnet_clock)]
    #[serial]
    fn classified_union_reaches_real_mint_with_tighter_caps() {
        let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
        for kind in ["amount", "count", "unlisted", "total"] {
            for next in [10, 11] {
                let l = Ledger::new();
                let rules = Rules::new(&l, kind, (false, false));
                let empty = rules.snapshot(&l);
                let seed = rules.holds(&l, &empty, 40, false);
                let seed = if kind == "count" {
                    vec![seed[0].clone(); 40]
                } else {
                    seed
                };
                l.store.record_authorized(&l.profile, &seed).unwrap();
                let captured = rules.snapshot(&l);
                let entries = rules.holds(&l, &captured, 50, true);
                let request = rules.request(&l, 1, entries.clone());
                let minted = l
                    .mint(&request)
                    .expect("40 used plus one payment of 50 fits cap 100");
                assert_eq!(
                    l.wire().holds.len(),
                    2,
                    "mint stores the shared and outer-only holds"
                );
                assert_holds(&l, minted.id, &entries);
                assert_eq!(entries.len(), 2, "shared and outer-only key: {kind}");
                assert_eq!(entries[0].amount(), if kind == "count" { 1 } else { 50 });
                assert_eq!(
                    entries[1].key(),
                    &StateKey::new("ledger", 1, "rate_limit", 3_600)
                );
                let memory = PolicyStateStore::new();
                l.store
                    .load_into_at("ledger", &l.profile, &memory, T0)
                    .unwrap();
                let used = if kind == "total" {
                    memory.query_epoch(entries[0].key(), rules.digest).unwrap()
                } else {
                    usage_with_holds(&l, &memory, entries[0].key(), T0)
                };
                assert_eq!(
                    used,
                    if kind == "count" { (41, 41) } else { (90, 2) },
                    "one debit per payment: {kind}"
                );
                let later = rules.holds(&l, &captured, next, true);
                let later_id = if kind == "count" && next == 11 {
                    let minted = l
                        .mint(&rules.request(&l, 2, later.clone()))
                        .expect("one remaining call fits the count cap");
                    assert_holds(&l, minted.id, &later);
                    3
                } else {
                    2
                };
                let before = l.bytes();
                if kind == "unlisted" && next == 11 {
                    // The unlisted allowance is approval-satisfiable: a policy
                    // authority refuses with nothing written, and the
                    // approval mints the full excess.
                    let mut policy = rules.request(&l, later_id, later.clone());
                    policy.authority = MintAuthority::Policy(PolicyAuthorityBinding {
                        policy_digest: rules.digest,
                        ..policy_binding(T0 + APPROVAL_MS)
                    });
                    assert!(
                        matches!(
                            l.mint(&policy),
                            Err(WindowStoreError::UnlistedApprovalRequired)
                        ),
                        "policy authority needs approval beyond the allowance"
                    );
                    assert_eq!(l.bytes(), before, "approval-needed writes nothing");
                }
                let result = l.mint(&rules.request(&l, later_id, later.clone()));
                if next == 10 || kind == "unlisted" {
                    let minted = result.expect("remaining headroom or an approval admits it");
                    assert_holds(&l, minted.id, &later);
                    if kind == "unlisted" {
                        assert_eq!(
                            usage_with_holds(&l, &memory, later[0].key(), T0),
                            (90 + next, 3),
                            "the minted payment is charged in full"
                        );
                    }
                } else {
                    assert!(
                        matches!(result, Err(WindowStoreError::PolicyDenied { .. })),
                        "{}: {kind}",
                        if kind == "unlisted" {
                            "shared unlisted budget refuses excess"
                        } else {
                            "outer cap refuses excess"
                        }
                    );
                    assert_eq!(l.bytes(), before, "refusal writes no partial holds");
                }
            }
        }
    }

    #[test]
    #[serial(mainnet_clock)]
    #[serial]
    fn classified_union_keeps_outer_unlisted_and_distinct_windows() {
        let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
        for listed in [(true, false), (false, true), (false, false)] {
            let l = Ledger::new();
            let rules = Rules::new(&l, "unlisted", listed);
            let snapshot = rules.snapshot(&l);
            let entries = rules.holds(&l, &snapshot, 50, true);
            let minted = l.mint(&rules.request(&l, 1, entries.clone())).unwrap();
            assert_eq!(
                l.wire().holds.len(),
                2,
                "mint retains each descriptor's recipient class: {listed:?}"
            );
            assert_holds(&l, minted.id, &entries);
            assert_eq!(
                entries.len(),
                2,
                "each descriptor retains its recipient class: {listed:?}"
            );
            assert_eq!(
                entries[0].key(),
                &StateKey::new("ledger", 1, "unlisted:native", 86_400)
            );
            assert_eq!(entries[0].amount(), 50);
            assert_eq!(
                entries[0].limit(),
                &WindowLimit::Unlisted {
                    asset: "native".to_owned(),
                    window: "1d".to_owned(),
                    max_stroops: 100,
                }
            );
        }
        let l = Ledger::new();
        let rules = Rules::new(&l, "count", (false, false));
        let snapshot = rules.snapshot(&l);
        let entries = rules.holds(&l, &snapshot, 50, true);
        assert_eq!(
            entries
                .iter()
                .map(|e| e.key().window_secs())
                .collect::<Vec<_>>(),
            vec![86_400, 3_600]
        );
        let singleton = rules.holds(&l, &snapshot, 50, false);
        assert_eq!(
            singleton,
            vec![WindowEntry::new(
                StateKey::new("ledger", 1, "rate_limit", 86_400),
                T0,
                1,
                WindowLimit::Count {
                    window: "1d".to_owned(),
                    max_calls: 200
                }
            )]
        );
        let request = rules.request(&l, 1, singleton.clone());
        let minted = l.mint(&request).unwrap();
        assert_eq!(minted.expires_at_ms, T0 + TTL_MS);
        assert_eq!(l.record(minted.id).consumer, request.consumer);
        assert_holds(&l, minted.id, &singleton);
        let l = Ledger::new();
        let rules = Rules::new(&l, "repeated", (false, false));
        let snapshot = rules.snapshot(&l);
        let singleton = rules.holds(&l, &snapshot, 50, false);
        assert_eq!(
            singleton.len(),
            2,
            "single-rule repeated criteria stay additive"
        );
        assert_eq!(singleton[0], singleton[1]);
        let composed = rules.holds(&l, &snapshot, 50, true);
        let cap = |max_stroops| WindowLimit::Amount {
            asset: "native".to_owned(),
            window: "1d".to_owned(),
            max_stroops,
        };
        assert_eq!(
            composed
                .iter()
                .map(|e| (e.key().clone(), e.amount(), e.limit().clone()))
                .collect::<Vec<_>>(),
            vec![
                (StateKey::new("ledger", 1, "native", 86_400), 50, cap(100)),
                (StateKey::new("ledger", 1, "native", 86_400), 50, cap(200)),
                (
                    StateKey::new("ledger", 1, "rate_limit", 3_600),
                    1,
                    WindowLimit::Count {
                        window: "1h".to_owned(),
                        max_calls: 100,
                    }
                ),
            ],
            "composition keeps both repeated payment debits and the outer-only entry"
        );
        let minted = l.mint(&rules.request(&l, 1, singleton.clone())).unwrap();
        assert_holds(&l, minted.id, &singleton);
        let l = Ledger::new();
        let rules = Rules::new(&l, "repeated", (false, false));
        let minted = l
            .mint(&rules.request(&l, 1, composed.clone()))
            .expect("two debits of 50 fit the tighter cap of 100");
        assert_holds(&l, minted.id, &composed);
    }

    /// The mint bounds an authorization by the restricting grant's end on
    /// its own clock: an end at or before that instant refuses, and an end
    /// past every other term changes nothing. An overflowing lifetime refuses.
    #[test]
    #[serial(mainnet_clock)]
    #[serial]
    fn restriction_end_bounds_the_mint_on_its_own_clock() {
        let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
        for (end, expected) in [
            (T0 + 1, Some(T0 + 1)),
            (T0 + TTL_MS - 1, Some(T0 + TTL_MS - 1)),
            (u64::MAX, Some(T0 + TTL_MS)),
            (T0, None),
            (0, None),
        ] {
            let l = Ledger::new();
            let mut request = l.request(tx(1), vec![]);
            request.restriction_end_ms = Some(end);
            let before = std::fs::read(l.store.path()).ok();
            let result = l.mint(&request);
            match expected {
                Some(expires) => {
                    let minted = result.unwrap();
                    assert_eq!(minted.expires_at_ms, expires, "end {end}");
                    assert_eq!(l.record(minted.id).expires_ms, expires, "end {end}");
                }
                None => {
                    assert_eq!(refusal(result), MainnetPrecondition::LifetimeInvalid);
                    assert_eq!(std::fs::read(l.store.path()).ok(), before, "end {end}");
                }
            }
        }
        let l = Ledger::new();
        let mut request = l.request(tx(1), vec![]);
        request.authorization_ttl_ms = u64::MAX;
        assert_eq!(
            refusal(l.mint(&request)),
            MainnetPrecondition::LifetimeInvalid,
            "an overflowing lifetime refuses"
        );
    }

    /// Two separately signed policies can each load a different unlisted
    /// table. Each descriptor is sized through its own policy's engine, and
    /// the composition keeps the tighter cap of 100, not the routed 200. A
    /// policy authority beyond that cap needs approval.
    #[test]
    #[serial(mainnet_clock)]
    #[serial]
    fn unequal_unlisted_tables_compose_to_the_tighter_cap() {
        let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
        for next in [10, 11] {
            let l = Ledger::new();
            let wide = Rules::new(&l, "unlisted_wide", (false, false));
            let tight = Rules::new(&l, "unlisted", (false, false));
            let size = |rules: &Rules, tool: &ToolDescriptor, amount| {
                let snapshot = rules.snapshot(&l);
                let evaluation = rules.evaluate(&l, &snapshot, tool, amount);
                crate::mainnet::holds::size_evaluated_holds(
                    &rules.engine,
                    &l.profile,
                    (tool, &evaluation),
                    None,
                    T0,
                )
                .unwrap()
            };
            let compose = |amount| {
                stellar_agent_core::policy::v1::criteria::state_store::compose_window_entries(
                    &size(&wide, &wide.routed, amount),
                    Some(&size(&tight, &tight.outer, amount)),
                )
                .unwrap()
            };
            l.store
                .record_authorized(&l.profile, &size(&tight, &tight.outer, 40))
                .unwrap();
            let first = compose(50);
            assert_eq!(
                first[0].limit(),
                &WindowLimit::Unlisted {
                    asset: "native".to_owned(),
                    window: "1d".to_owned(),
                    max_stroops: 100,
                },
                "the tighter table's cap holds the shared unlisted key"
            );
            l.mint(&tight.request(&l, 1, first))
                .expect("40 plus 50 fits the cap of 100");
            let before = l.bytes();
            if next == 10 {
                l.mint(&tight.request(&l, 2, compose(next)))
                    .expect("exact remaining headroom is permitted");
            } else {
                // A policy authority beyond the unlisted allowance needs approval.
                let mut policy = tight.request(&l, 2, compose(next));
                policy.authority = MintAuthority::Policy(PolicyAuthorityBinding {
                    policy_digest: tight.digest,
                    ..policy_binding(T0 + APPROVAL_MS)
                });
                assert!(
                    matches!(
                        l.mint(&policy),
                        Err(WindowStoreError::UnlistedApprovalRequired)
                    ),
                    "the routed cap of 200 lends no headroom"
                );
                assert_eq!(l.bytes(), before);
            }
        }
    }

    /// A routed rule that repeats a cap of 100 debits a payment of 50 twice;
    /// over 40 spent its own admission needs 140 and refuses, and an outer
    /// evaluation sharing the key cannot collapse the debits into headroom.
    #[test]
    #[serial(mainnet_clock)]
    #[serial]
    fn composed_repeated_debits_cannot_gain_headroom() {
        let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
        for composed in [false, true] {
            let l = Ledger::new();
            let rules = Rules::new(&l, "repeated_tight", (false, false));
            let seed = rules.holds(&l, &rules.snapshot(&l), 40, false);
            l.store.record_authorized(&l.profile, &seed[..1]).unwrap();
            let entries = rules.holds(&l, &rules.snapshot(&l), 50, composed);
            assert_eq!(
                entries.len(),
                if composed { 3 } else { 2 },
                "both routed debits stay in the composition"
            );
            let before = l.bytes();
            assert!(
                matches!(
                    l.mint(&rules.request(&l, 1, entries)),
                    Err(WindowStoreError::PolicyDenied { .. })
                ),
                "repeated debits refuse over the cap of 100: composed {composed}"
            );
            assert_eq!(l.bytes(), before, "refusal writes no partial holds");
            let entries = rules.holds(&l, &rules.snapshot(&l), 5, composed);
            l.mint(&rules.request(&l, 2, entries))
                .expect("two debits of 5 over 40 spent fit the cap of 100");
        }
    }

    #[test]
    #[serial(mainnet_clock)]
    #[serial]
    fn composed_mint_recovers_every_commit_boundary_once() {
        use super::super::super::store::{
            COMMIT_FAULT_AFTER_COUNTER, COMMIT_FAULT_AFTER_PREPARED, COMMIT_FAULT_COMPACTION,
            arm_accounting_fault,
        };
        let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
        for seam in [
            COMMIT_FAULT_AFTER_COUNTER,
            COMMIT_FAULT_AFTER_PREPARED,
            COMMIT_FAULT_COMPACTION,
        ] {
            let l = Ledger::new();
            let rules = Rules::new(&l, "total", (false, false));
            let seed = rules.holds(&l, &rules.snapshot(&l), 40, false);
            l.store.record_authorized(&l.profile, &seed).unwrap();
            let generation = l.wire().generation;
            // A repeated debit would fit; replay protection must refuse it.
            let entries = rules.holds(&l, &rules.snapshot(&l), 20, true);
            let request = rules.recovery_request(&l, entries.clone());
            let fault = arm_accounting_fault(seam);
            let result = l.mint(&request);
            drop(fault);
            assert_eq!(
                result.is_ok(),
                seam == COMMIT_FAULT_COMPACTION,
                "fault reaches mint commit: {seam}"
            );
            let reopened = PersistedWindowStore::at_path(l.store.path().to_owned());
            let wire = reopened.read_for_inspection(&l.profile).unwrap().unwrap();
            let committed = seam != COMMIT_FAULT_AFTER_PREPARED;
            assert_eq!(wire.generation, generation + u64::from(committed));
            assert_eq!(
                wire.authorizations.len(),
                usize::from(committed),
                "one complete authorization or none"
            );
            if committed {
                assert_holds(&l, wire.authorizations[0].id, &entries);
            } else {
                assert!(
                    wire.holds.is_empty(),
                    "uncommitted mint has no partial holds"
                );
                let minted = reopened.mint_authorization(&l.profile, &request).unwrap();
                assert_holds(&l, minted.id, &entries);
            }
            let before = l.bytes();
            assert_eq!(
                refusal(reopened.mint_authorization(&l.profile, &request)),
                MainnetPrecondition::DuplicateOpen,
                "committed retry cannot mint twice"
            );
            assert_eq!(l.bytes(), before);
            assert_eq!(l.wire().authorizations.len(), 1);
            let memory = PolicyStateStore::new();
            reopened
                .load_into_at("ledger", &l.profile, &memory, T0)
                .unwrap();
            assert_eq!(
                memory.query_epoch(entries[0].key(), rules.digest).unwrap(),
                (60, 2)
            );
        }
    }

    #[test]
    #[serial(mainnet_clock)]
    #[serial]
    fn composed_expiry_releases_only_unused_holds_and_keeps_epochs() {
        let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
        for kind in ["amount", "total"] {
            for claimed in [false, true] {
                let l = Ledger::new();
                let rules = Rules::new(&l, kind, (false, false));
                let entries = rules.holds(&l, &rules.snapshot(&l), 50, true);
                let request = rules.request(&l, 1, entries.clone());
                let minted = l.mint(&request).unwrap();
                if claimed {
                    l.clock.set(T0 + 7);
                    l.claim(&request, &minted).unwrap();
                }
                let earlier = PolicyStateStore::new();
                l.store
                    .load_into_at("ledger", &l.profile, &earlier, T0 - 1)
                    .unwrap();
                let used = if kind == "total" {
                    earlier.query_epoch(entries[0].key(), rules.digest).unwrap()
                } else {
                    usage_with_holds(&l, &earlier, entries[0].key(), T0 - 1)
                };
                assert_eq!(used, (50, 1), "an earlier clock releases no capacity");
                l.clock.set(minted.expires_at_ms);
                l.store
                    .invalidate_authorization(&l.profile, minted.id, "expiry")
                    .unwrap();
                let wire = l.wire();
                assert!(wire.holds.is_empty());
                assert_eq!(wire.authorizations[0].state, AuthorizationState::Expired);
                let records: Vec<_> = wire.entries.iter().flat_map(|b| &b.records).collect();
                assert_eq!(
                    records.len(),
                    if claimed { 2 } else { 0 },
                    "only unused authorizations release every unique hold"
                );
                let reopened = PersistedWindowStore::at_path(l.store.path().to_owned());
                for entry in &entries {
                    let boundary = T0 + 7 + entry.key().window_secs() * 1000;
                    for at in [boundary, boundary + 1] {
                        let memory = PolicyStateStore::new();
                        reopened
                            .load_into_at("ledger", &l.profile, &memory, at)
                            .unwrap();
                        let used = if let Some(epoch) = entry.epoch() {
                            assert_eq!(memory.query_epoch(entry.key(), [9; 32]).unwrap(), (0, 0));
                            memory.query_epoch(entry.key(), epoch).unwrap()
                        } else {
                            memory.query_window(entry.key(), at).unwrap()
                        };
                        let retained = claimed && (entry.epoch().is_some() || at == boundary);
                        assert_eq!(
                            used,
                            if retained {
                                (entry.amount(), 1)
                            } else {
                                (0, 0)
                            },
                            "epoch and inclusive window boundary retain exposed spend"
                        );
                    }
                }
                let before = l.bytes();
                assert!(
                    l.mint(&request).is_err(),
                    "expired request cannot repeat its effect"
                );
                assert_eq!(l.bytes(), before);
            }
        }
    }

    pub(super) fn process_ledger(dir: &std::path::Path) -> Ledger {
        let mut l = Ledger::new();
        l.store = PersistedWindowStore::at_path(dir.join("composed.window"));
        l.profile.audit_log_path = dir.join("audit.jsonl");
        let backend: std::sync::Arc<keyring_core::CredentialStore> =
            std::sync::Arc::new(stellar_agent_headless_keyring::store::HeadlessStore::new(
                dir.join("composed.keyring"),
                stellar_agent_headless_keyring::crypto::ProtectionMode::EnvKey(
                    std::sync::Arc::new(zeroize::Zeroizing::new([7; 32])),
                ),
            ));
        keyring_core::set_default_store(backend);
        l
    }

    #[test]
    #[serial(mainnet_clock)]
    #[serial]
    fn composed_epochs_refuse_missing_stale_retired_and_survive_reset() {
        let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
        let l = Ledger::new();
        let rules = Rules::new(&l, "total", (false, false));
        let captured = rules.snapshot(&l);
        let seed = rules.holds(&l, &captured, 40, false);
        l.store.record_authorized(&l.profile, &seed).unwrap();
        l.reset(T0).unwrap();
        let reopened = PersistedWindowStore::at_path(l.store.path().to_owned());
        let memory = PolicyStateStore::new();
        reopened
            .load_into_at("ledger", &l.profile, &memory, T0)
            .unwrap();
        assert_eq!(
            memory.query_epoch(seed[0].key(), rules.digest).unwrap(),
            (40, 1),
            "reset preserves the total epoch's charge"
        );
        for epoch in [None, Some([9; 32])] {
            let mut entries = rules.holds(&l, &captured, 50, true);
            entries[0] = entries[0].clone().with_epoch(epoch);
            let before = l.bytes();
            let result = l.mint(&rules.request(&l, 1, entries));
            if epoch.is_none() {
                assert!(
                    matches!(result, Err(WindowStoreError::Invalid { .. })),
                    "missing epoch refuses before mint"
                );
            } else {
                assert!(
                    matches!(result, Err(WindowStoreError::TotalEpochStale)),
                    "stale epoch refuses before mint"
                );
            }
            assert_eq!(l.bytes(), before);
        }
        let total = |amount| {
            WindowEntry::new(
                seed[0].key().clone(),
                T0,
                amount,
                WindowLimit::Total {
                    asset: "native".to_owned(),
                    max_stroops: i128::MAX,
                },
            )
            .with_epoch(Some(rules.digest))
        };
        l.store
            .record_authorized(&l.profile, &[total(i128::MAX - 40)])
            .unwrap();
        for amount in [1, -1] {
            let entry = total(amount);
            let entries =
                stellar_agent_core::policy::v1::criteria::state_store::compose_window_entries(
                    std::slice::from_ref(&entry),
                    Some(std::slice::from_ref(&entry)),
                )
                .unwrap();
            let before = l.bytes();
            let refusal = l.mint(&rules.request(&l, 3, entries)).unwrap_err();
            if amount > 0 {
                assert!(
                    matches!(refusal, WindowStoreError::PolicyDenied { reason }
                    if *reason == stellar_agent_core::policy::DenyReason::TotalBudgetExhausted {
                        asset: "native".into(), max_stroops: i128::MAX, remaining_stroops: 0,
                    }),
                    "a composed overflow is the governing total-budget denial"
                );
            } else {
                assert!(
                    matches!(refusal, WindowStoreError::Invalid { detail }
                    if detail == "a total-budget debit is negative"),
                    "a negative debit remains invalid"
                );
            }
            assert_eq!(l.bytes(), before);
        }
        let zero = total(0);
        let entries =
            stellar_agent_core::policy::v1::criteria::state_store::compose_window_entries(
                std::slice::from_ref(&zero),
                Some(std::slice::from_ref(&zero)),
            )
            .unwrap();
        let minted = l.mint(&rules.request(&l, 4, entries.clone())).unwrap();
        assert_holds(&l, minted.id, &entries);
        let l = Ledger::new();
        let rules = Rules::new(&l, "total", (false, false));
        l.store.record_and_persist(&l.profile, &[hold(1)]).unwrap();
        l.store.write_earlier_build_for_test(&l.profile).unwrap();
        let captured = rules.snapshot(&l);
        assert_eq!(l.wire().retired_total_epoch, Some(rules.digest));
        let entries = rules.holds(&l, &captured, 50, true);
        let before = l.bytes();
        assert!(
            matches!(
                l.mint(&rules.request(&l, 1, entries)),
                Err(WindowStoreError::TotalEpochRetired)
            ),
            "retired epoch refuses the complete composition"
        );
        assert_eq!(l.bytes(), before);
    }

    pub(super) fn handshake() {
        use std::io::Write as _;
        writeln!(std::io::stdout(), "COMPOSED_READY").unwrap();
        std::io::stdout().flush().unwrap();
        let mut signal = String::new();
        std::io::stdin().read_line(&mut signal).unwrap();
        assert_eq!(signal, "continue\n");
    }

    pub(super) fn child_at_boundary(
        dir: &std::path::Path,
        mode: &str,
        test: &str,
    ) -> std::process::Child {
        use std::io::BufRead as _;
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", test, "--nocapture"])
            .env("STELLAR_AGENT_COMPOSED_MODE", mode)
            .env("STELLAR_AGENT_COMPOSED_DIRECTORY", dir)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let mut output = std::io::BufReader::new(child.stdout.take().unwrap());
        loop {
            let mut line = String::new();
            assert_ne!(
                output.read_line(&mut line).unwrap(),
                0,
                "child reaches the composed boundary"
            );
            if line.contains("COMPOSED_READY") {
                break;
            }
        }
        // Preserve the child's pipe until its final assertion or deliberate exit.
        child.stdout = Some(output.into_inner());
        child
    }

    pub(super) fn release_child(mut child: std::process::Child) -> std::process::Output {
        use std::io::Write as _;
        child
            .stdin
            .take()
            .unwrap()
            .write_all(b"continue\n")
            .unwrap();
        child.wait_with_output().unwrap()
    }

    #[test]
    #[serial(mainnet_clock)]
    #[serial]
    fn composed_two_process_snapshots_admit_only_available_budget() {
        let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
        let child_dir = std::env::var_os("STELLAR_AGENT_COMPOSED_DIRECTORY");
        let parent_dir = child_dir.is_none().then(|| TempDir::new().unwrap());
        let dir = child_dir
            .as_ref()
            .map(std::path::Path::new)
            .unwrap_or_else(|| parent_dir.as_ref().unwrap().path());
        let l = process_ledger(dir);
        let rules = Rules::new(&l, "total", (false, false));
        if child_dir.is_some() {
            l.nonces.set(100);
            let entries = rules.holds(&l, &rules.snapshot(&l), 50, true);
            handshake();
            let request = rules.request(&l, 2, entries);
            for _ in 0..2 {
                let before = l.bytes();
                let result = l.mint(&request);
                assert!(
                    matches!(result, Err(WindowStoreError::PolicyDenied { .. })),
                    "fresh locked mint refuses the stale second request"
                );
                assert_eq!(
                    l.bytes(),
                    before,
                    "loser creates no authorization or partial hold"
                );
            }
            return;
        }
        let seed = rules.holds(&l, &rules.snapshot(&l), 40, false);
        l.store.record_authorized(&l.profile, &seed).unwrap();
        let entries = rules.holds(&l, &rules.snapshot(&l), 50, true);
        let child = child_at_boundary(
            dir,
            "stale",
            "policy_state::ledger::tests::composed::composed_two_process_snapshots_admit_only_available_budget",
        );
        let minted = l.mint(&rules.request(&l, 1, entries.clone())).unwrap();
        let output = release_child(child);
        assert!(
            output.status.success(),
            "stale request refuses after competing mint: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        assert_eq!(l.wire().authorizations.len(), 1);
        assert_holds(&l, minted.id, &entries);
    }

    /// A second process mints while the first holds the window lock inside
    /// its commit: the loser refuses on the lock with unchanged bytes, then
    /// its retry reads the committed spend and refuses on the budget.
    #[test]
    #[serial(mainnet_clock)]
    #[serial]
    fn composed_mint_contending_for_the_window_lock_refuses_then_rereads() {
        use super::super::super::store::{COMMIT_FAULT_AFTER_PREPARED, COMMIT_STEP_OBSERVER};
        let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
        if let Some(dir) = std::env::var_os("STELLAR_AGENT_COMPOSED_DIRECTORY") {
            let l = process_ledger(std::path::Path::new(&dir));
            let rules = Rules::new(&l, "total", (false, false));
            l.nonces.set(100);
            let entries = rules.holds(&l, &rules.snapshot(&l), 50, true);
            COMMIT_STEP_OBSERVER.with_borrow_mut(|observer| {
                *observer = Some(Box::new(|point| {
                    if point == COMMIT_FAULT_AFTER_PREPARED {
                        handshake();
                    }
                }))
            });
            l.mint(&rules.request(&l, 2, entries))
                .expect("the lock holder commits after the handshake");
            return;
        }
        let dir = TempDir::new().unwrap();
        let l = process_ledger(dir.path());
        let rules = Rules::new(&l, "total", (false, false));
        let seed = rules.holds(&l, &rules.snapshot(&l), 40, false);
        l.store.record_authorized(&l.profile, &seed).unwrap();
        let entries = rules.holds(&l, &rules.snapshot(&l), 50, true);
        let request = rules.request(&l, 1, entries);
        let child = child_at_boundary(
            dir.path(),
            "hold",
            "policy_state::ledger::tests::composed::composed_mint_contending_for_the_window_lock_refuses_then_rereads",
        );
        let before = l.bytes();
        assert!(
            matches!(l.mint(&request), Err(WindowStoreError::WriterLocked)),
            "a held window lock refuses the contending mint"
        );
        assert_eq!(l.bytes(), before, "the lock refusal writes nothing");
        let output = release_child(child);
        assert!(
            output.status.success(),
            "lock holder commits: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        assert_eq!(l.wire().authorizations.len(), 1);
        let before = l.bytes();
        assert!(
            matches!(l.mint(&request), Err(WindowStoreError::PolicyDenied { .. })),
            "the retry reads 40 plus the committed 50 and refuses 50 more"
        );
        assert_eq!(l.bytes(), before);
    }

    #[test]
    #[serial(mainnet_clock)]
    #[serial]
    fn composed_process_exit_recovers_complete_generation() {
        use super::super::super::store::{
            COMMIT_FAULT_AFTER_COUNTER, COMMIT_FAULT_AFTER_PREPARED, COMMIT_FAULT_COMPACTION,
            COMMIT_STEP_OBSERVER,
        };
        let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
        if let Ok(mode) = std::env::var("STELLAR_AGENT_COMPOSED_MODE") {
            let dir = std::path::PathBuf::from(
                std::env::var_os("STELLAR_AGENT_COMPOSED_DIRECTORY").unwrap(),
            );
            let l = process_ledger(&dir);
            let rules = Rules::new(&l, "total", (false, false));
            let entries = rules.holds(&l, &rules.snapshot(&l), 20, true);
            let request = rules.recovery_request(&l, entries);
            let seam: u8 = mode.parse().unwrap();
            COMMIT_STEP_OBSERVER.with_borrow_mut(|observer| {
                *observer = Some(Box::new(move |point| {
                    if point == seam {
                        handshake();
                        std::process::exit(73);
                    }
                }))
            });
            l.mint(&request).unwrap();
            panic!("child must exit inside the durable commit");
        }
        for seam in [
            COMMIT_FAULT_AFTER_COUNTER,
            COMMIT_FAULT_AFTER_PREPARED,
            COMMIT_FAULT_COMPACTION,
        ] {
            let dir = TempDir::new().unwrap();
            let l = process_ledger(dir.path());
            let rules = Rules::new(&l, "total", (false, false));
            let seed = rules.holds(&l, &rules.snapshot(&l), 40, false);
            l.store.record_authorized(&l.profile, &seed).unwrap();
            // A repeated debit would fit; replay protection must refuse it.
            let entries = rules.holds(&l, &rules.snapshot(&l), 20, true);
            let request = rules.recovery_request(&l, entries.clone());
            let generation = l.wire().generation;
            let child = child_at_boundary(
                dir.path(),
                &seam.to_string(),
                "policy_state::ledger::tests::composed::composed_process_exit_recovers_complete_generation",
            );
            let output = release_child(child);
            assert_eq!(
                output.status.code(),
                Some(73),
                "child exits at the durable handshake"
            );
            let reopened = PersistedWindowStore::at_path(l.store.path().to_owned());
            let wire = reopened.read_for_inspection(&l.profile).unwrap().unwrap();
            let committed = seam != COMMIT_FAULT_AFTER_PREPARED;
            assert_eq!(wire.generation, generation + u64::from(committed));
            assert_eq!(wire.authorizations.len(), usize::from(committed));
            if committed {
                assert_holds(&l, wire.authorizations[0].id, &entries);
            } else {
                assert!(wire.holds.is_empty());
                let minted = reopened.mint_authorization(&l.profile, &request).unwrap();
                assert_holds(&l, minted.id, &entries);
            }
            let before = l.bytes();
            assert_eq!(
                refusal(reopened.mint_authorization(&l.profile, &request)),
                MainnetPrecondition::DuplicateOpen,
                "restart retry cannot debit twice"
            );
            assert_eq!(l.bytes(), before);
            assert_eq!(l.wire().authorizations.len(), 1);
            let memory = PolicyStateStore::new();
            reopened
                .load_into_at("ledger", &l.profile, &memory, T0)
                .unwrap();
            assert_eq!(
                memory.query_epoch(entries[0].key(), rules.digest).unwrap(),
                (60, 2),
                "process recovery retains prior spend and one composed debit"
            );
        }
    }
}
