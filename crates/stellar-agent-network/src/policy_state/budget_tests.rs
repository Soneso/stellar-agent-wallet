/// The budget projection over windows its writers and sealed fixtures hold.
mod budget {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use stellar_agent_core::mainnet::verified_policy::VerifiedPolicy;
    use stellar_agent_core::policy::Decision;
    use stellar_agent_core::policy::v1::PolicyEngineV1;
    use stellar_agent_core::policy::v1::criteria::counterparty_allowlist::{
        CounterpartyAllowlistCriterion, CounterpartyKind, UnlistedBudget, UnlistedMode,
    };
    use stellar_agent_core::policy::v1::criteria::descriptor::BucketKind;
    use stellar_agent_core::policy::v1::criteria::per_period_cap::Window;
    use stellar_agent_core::policy::v1::criteria::total_budget::TotalBudgetCriterion;
    use stellar_agent_core::policy::v1::criteria::{
        Criterion, PerPeriodCapCriterion, PerTxCapCriterion,
    };
    use stellar_agent_core::policy::v1::loader::{PolicyDocument, PolicyRule, RuleMatch, ScopeId};

    use super::*;
    use crate::policy_state::budget::{
        BucketUsage, BudgetError, BudgetProjection, InformationalBound, NativeClass,
        NativeObligation, SnapshotUnavailable, Undecided, UsageUnavailable,
    };
    use crate::policy_state::ledger::NativeReservation;
    use crate::policy_state::ledger::SubmissionBinding;
    use crate::policy_state::store::{
        RecordStatus, WIRE_VERSION_TOTAL_INTENTS, WireRecord, WireTotalSum, find_or_insert_bucket,
    };

    const ISSUED: &str = "USDC:GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";

    /// A fixture policy under the pinned digest whose one rule carries
    /// `criteria`.
    fn policy(criteria: Vec<Box<dyn Criterion>>) -> VerifiedPolicy {
        policy_as([7; 32], criteria)
    }

    fn policy_as(digest: [u8; 32], criteria: Vec<Box<dyn Criterion>>) -> VerifiedPolicy {
        let rule = PolicyRule {
            r#match: RuleMatch {
                tool: "*".to_owned(),
                chain: "*".to_owned(),
            },
            criteria,
            decision: Decision::Allow,
            allow_opaque_signing: false,
        };
        let document = PolicyDocument {
            version: 2,
            scope: ScopeId::AllProfiles,
            rules: vec![rule],
            signature: None,
        };
        VerifiedPolicy::for_test(
            digest,
            Arc::new(PolicyEngineV1::new(document, "ops".to_owned())),
        )
    }

    fn project(fx: &Fx, policy: &VerifiedPolicy) -> Result<BudgetProjection, BudgetError> {
        BudgetProjection::for_profile("ops", &fx.profile, &fx.store, policy, fx.now())
    }

    /// An obligation's counting, class and informational bound.
    pub(super) type Native = (
        Result<bool, Undecided>,
        NativeClass,
        Option<InformationalBound>,
    );

    /// The disposition and obligation the projection of `fx`'s window gives
    /// authorization `id`.
    pub(super) fn projected(fx: &Fx, id: AuthorizationId) -> (Option<Disposition>, Option<Native>) {
        let projection = project(fx, &policy(Vec::new())).unwrap();
        let view = projection
            .authorizations
            .iter()
            .find(|view| view.id == id)
            .unwrap();
        (
            view.disposition,
            view.native_obligation
                .map(|native| (native.counted, native.class, native.release_bound)),
        )
    }

    /// Seals `wire` as the next committed generation, without the writers'
    /// snapshot checks.
    fn seal(fx: &Fx, mut wire: WireFile) -> u64 {
        wire.generation += 1;
        fx.store.seal_unchecked_for_test(&fx.profile, &wire);
        wire.generation
    }

    fn row(id: &str, amount: i128, status: RecordStatus, ts_ms: u64) -> WireRecord {
        WireRecord {
            id: id.to_owned(),
            amount,
            status,
            ts_ms,
            chain_scope: Some(ChainScope::for_chain(Caip2::Mainnet)),
            ..WireRecord::confirmed_defaults()
        }
    }

    fn period(asset: &str, window: &str, cap: i128) -> Box<dyn Criterion> {
        Box::new(PerPeriodCapCriterion::new(
            asset.to_owned(),
            Window::parse(window).unwrap(),
            cap,
        ))
    }

    fn figures(
        projection: &BudgetProjection,
    ) -> Vec<(
        BucketKind,
        Option<u64>,
        Result<BucketUsage, UsageUnavailable>,
    )> {
        projection.rules[0]
            .buckets
            .iter()
            .map(|bucket| {
                (
                    bucket.descriptor.kind,
                    bucket.descriptor.window_secs,
                    bucket.usage,
                )
            })
            .collect()
    }

    fn usage(used: i128, reserved: i128, remaining: i128) -> Result<BucketUsage, UsageUnavailable> {
        Ok(BucketUsage {
            used,
            reserved,
            remaining,
        })
    }

    /// A settled row of 30, two holds of one authorization at ordinals 0 and
    /// 1 (10 and 15), and a pending debit of 20 give used 30, reserved 45 and
    /// remaining 25 under a daily cap of 100. A row linked to a signed intent
    /// adds nothing, an aged row is out of the window, and another asset
    /// stays apart. The weekly bucket counts the pending debit charged under
    /// the daily window and floors its remaining at zero. The total counts
    /// its own epoch only. The unlisted bucket and a retired epoch report
    /// why they have no figures, and an overflowing sum refuses typed.
    #[test]
    #[serial]
    fn budget_bucket_breakdown_and_dedup() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        let fx = Fx::new();
        let mut plan = crate::signed_intent::test_helpers::with_legs(
            &crate::signed_intent::test_helpers::intent_fixture_plan(1, 60).0,
            &[hold(40)],
        );
        plan.facts.chain_scope = ChainScope::for_chain(Caip2::Mainnet);
        let _proof = fx.store.admit_signed_intent(&fx.profile, &plan).unwrap();
        let total_hold = WindowEntry::new(
            StateKey::new("ops", 1, "total:native", 0),
            T0,
            3,
            WindowLimit::Total {
                asset: "native".to_owned(),
                max_stroops: CAP,
            },
        )
        .with_epoch(Some([7; 32]));
        for holds in [vec![hold(10), hold(15)], vec![total_hold]] {
            let request = fx.mint_request(tx(holds.len() as u8), fx.approval(), holds);
            fx.store.mint_authorization(&fx.profile, &request).unwrap();
        }
        let now = fx.now();
        let mut wire = fx.wire();
        wire.version = WIRE_VERSION_TOTAL_INTENTS;
        let day = StateKey::new("ops", 1, "native", 86_400);
        find_or_insert_bucket(&mut wire.entries, &day)
            .records
            .extend([
                row("settled", 30, RecordStatus::Confirmed, now - 1_000),
                row("aged", 50, RecordStatus::Confirmed, now - 86_400_001),
                row("exposed", 20, RecordStatus::Pending, now),
            ]);
        find_or_insert_bucket(
            &mut wire.entries,
            &StateKey::new("ops", 1, "native", 604_800),
        )
        .records
        .push(row("weekly", 7, RecordStatus::Confirmed, now - 1_000));
        find_or_insert_bucket(&mut wire.entries, &StateKey::new("ops", 1, ISSUED, 86_400))
            .records
            .push(row("issued", 9, RecordStatus::Confirmed, now - 1_000));
        let total = StateKey::new("ops", 1, "total:native", 0);
        find_or_insert_bucket(&mut wire.entries, &total)
            .records
            .extend([
                WireRecord {
                    epoch: Some([7; 32]),
                    ..row("total-row", 5, RecordStatus::Confirmed, now)
                },
                WireRecord {
                    epoch: Some([8; 32]),
                    ..row("other-epoch", 100, RecordStatus::Confirmed, now)
                },
            ]);
        wire.total_sums.push(WireTotalSum {
            scope_specificity: 1,
            bucket: "total:native".to_owned(),
            epoch: [7; 32],
            amount: 4,
            settled_until_ms: now,
        });
        let unlisted = UnlistedBudget::new("native".to_owned(), 2, 6, Window::parse("1d").unwrap());
        let policy = policy(vec![
            Box::new(PerTxCapCriterion::new("native".to_owned(), 500)),
            period("native", "1d", 200),
            period("native", "1w", 10),
            period(ISSUED, "1d", 50),
            Box::new(TotalBudgetCriterion::new("native".to_owned(), 200)),
            Box::new(
                CounterpartyAllowlistCriterion::new(vec![CounterpartyKind::GAccount], Vec::new())
                    .with_unlisted(UnlistedMode::Budget(unlisted)),
            ),
        ]);
        let generation = seal(&fx, wire.clone());

        let projection = project(&fx, &policy).unwrap();
        assert_eq!(projection.generation, generation);
        let per_call: Vec<_> = projection.rules[0]
            .per_call
            .iter()
            .map(|cap| (cap.kind, cap.cap_stroops))
            .collect();
        assert_eq!(
            per_call,
            vec![
                (BucketKind::Transaction, 500),
                (BucketKind::UnlistedTransaction, 2)
            ]
        );
        assert_eq!(
            figures(&projection),
            vec![
                (BucketKind::Period, Some(86_400), usage(30, 85, 85)),
                (BucketKind::Period, Some(604_800), usage(7, 60, 0)),
                (BucketKind::Period, Some(86_400), usage(9, 0, 41)),
                (BucketKind::Total, None, usage(9, 3, 188)),
                (
                    BucketKind::UnlistedPeriod,
                    Some(86_400),
                    Err(UsageUnavailable::UnlistedAccounting)
                ),
            ]
        );

        let mut retired = wire.clone();
        retired.retired_total_epoch = Some([7; 32]);
        seal(&fx, retired);
        let projection = project(&fx, &policy).unwrap();
        assert_eq!(figures(&projection)[0].2, usage(30, 85, 85));
        assert_eq!(
            figures(&projection)[3].2,
            Err(UsageUnavailable::TotalEpochRetired)
        );

        let mut overflowing = wire;
        find_or_insert_bucket(&mut overflowing.entries, &day)
            .records
            .extend([
                row("max", i128::MAX, RecordStatus::Confirmed, now),
                row("one", 1, RecordStatus::Confirmed, now),
            ]);
        seal(&fx, overflowing);
        let error = project(&fx, &policy).unwrap_err();
        assert!(
            matches!(
                &error,
                BudgetError::State(WindowStoreError::Invalid { detail })
                    if detail == "a budget figure overflows"
            ),
            "{error:?}"
        );
        assert_eq!(error.code(), "policy.window_state_unverifiable");
    }

    /// The projection reads the generation counter once, holding the shared
    /// window lock that refuses a writer meanwhile, and writes nothing. A
    /// verified absence projects generation zero. A committed file that is
    /// missing or unreadable names its generation, an unreadable counter
    /// names none, corrupt bytes keep the store's refusal, and a pin naming
    /// another policy refuses. None of them reads as zero.
    #[test]
    #[serial]
    fn budget_one_snapshot_and_integrity() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        let fx = Fx::new();
        let counter = generation_entry_ref(&fx.profile);
        let reads = Arc::new(AtomicUsize::new(0));
        let probing = Arc::new(AtomicBool::new(false));
        let writer_refused = Arc::new(AtomicBool::new(false));
        let (path, entry) = (
            fx.store.path().to_owned(),
            fx.profile.policy_window_state_key_id.clone(),
        );
        let hook = {
            let (reads, probing, writer_refused) = (
                Arc::clone(&reads),
                Arc::clone(&probing),
                Arc::clone(&writer_refused),
            );
            Arc::new(move || {
                if probing.load(Ordering::SeqCst) {
                    reads.fetch_add(1, Ordering::SeqCst);
                    writer_refused.store(
                        WindowStoreLock::acquire_for(&path, &entry).is_err(),
                        Ordering::SeqCst,
                    );
                }
            })
        };
        keyring_mock::install_with_read_hooks(vec![keyring_mock::ReadHook::new(
            &counter.service,
            &counter.account,
            hook,
        )])
        .unwrap();
        // The fresh keyring store holds no pin; the fixture's pin goes back
        // in before the first read.
        let lock =
            WindowStoreLock::acquire_for(fx.store.path(), &fx.profile.policy_window_state_key_id)
                .unwrap();
        pin::write_for_test(
            &lock,
            &PinScope::for_profile(fx.store.path(), &fx.profile),
            &Pin::new(7, [7; 32], owner_of(11)).unwrap(),
        )
        .unwrap();
        drop(lock);
        let policy = policy(vec![period("native", "1d", 100)]);
        let observed = |fx: &Fx| {
            reads.store(0, Ordering::SeqCst);
            probing.store(true, Ordering::SeqCst);
            let result = project(fx, &policy);
            probing.store(false, Ordering::SeqCst);
            (result, reads.load(Ordering::SeqCst))
        };

        let (fresh, _) = observed(&fx);
        let fresh = fresh.unwrap();
        assert_eq!(fresh.generation, 0);
        assert_eq!(figures(&fresh)[0].2, usage(0, 0, 100));
        assert_eq!(fresh.native.counted, Err(Undecided::NoObservation));
        assert!(!fx.store.path().exists(), "a projection creates no file");

        fx.store
            .record_and_persist(&fx.profile, &[hold(12)])
            .unwrap();
        let generation = fx.generation();
        let before = (fs::read(fx.store.path()).unwrap(), get_counter(&counter));
        let (read, counter_reads) = observed(&fx);
        assert_eq!(read.unwrap().generation, generation);
        assert_eq!(counter_reads, 1, "one snapshot read");
        assert!(
            writer_refused.load(Ordering::SeqCst),
            "the shared lock refuses a writer during the read"
        );
        assert_eq!(
            (fs::read(fx.store.path()).unwrap(), get_counter(&counter)),
            before,
            "the projection writes nothing"
        );
        assert!(
            WindowStoreLock::acquire_for(fx.store.path(), &fx.profile.policy_window_state_key_id)
                .is_ok()
        );

        let unavailable = |fx: &Fx| match project(fx, &policy) {
            Err(BudgetError::Unavailable { generation, reason }) => (generation, reason),
            other => panic!("expected unavailable state, got {other:?}"),
        };
        let bytes = fs::read(fx.store.path()).unwrap();
        fs::remove_file(fx.store.path()).unwrap();
        assert_eq!(
            unavailable(&fx),
            (Some(generation), SnapshotUnavailable::FileMissing)
        );
        fs::create_dir(fx.store.path()).unwrap();
        assert_eq!(
            unavailable(&fx),
            (Some(generation), SnapshotUnavailable::Unreadable)
        );
        fs::remove_dir(fx.store.path()).unwrap();
        fs::write(fx.store.path(), &bytes).unwrap();
        let committed = get_counter(&counter).unwrap();
        set_counter(&counter, "not a commitment");
        assert_eq!(
            unavailable(&fx),
            (None, SnapshotUnavailable::GenerationUnreadable)
        );
        set_counter(&counter, &committed);
        assert_eq!(project(&fx, &policy).unwrap().generation, generation);

        fs::write(fx.store.path(), b"{").unwrap();
        let corrupt = project(&fx, &policy).unwrap_err();
        assert!(matches!(corrupt, BudgetError::State(_)), "{corrupt:?}");
        assert_eq!(corrupt.code(), "policy.window_state_unverifiable");
        fs::write(fx.store.path(), &bytes).unwrap();

        let stale = project(&fx, &policy_as([8; 32], Vec::new())).unwrap_err();
        assert!(
            matches!(stale, BudgetError::State(WindowStoreError::TotalEpochStale)),
            "{stale:?}"
        );
        assert_eq!(stale.code(), "policy.total_epoch_stale");
    }

    /// Missing lock protection admits fresh absence, but never committed
    /// history, even when the caller presents another policy digest.
    #[test]
    #[serial]
    fn budget_missing_lock_refuses_committed_history() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        let fx = Fx::new();
        let lock_path = stellar_agent_core::policy::state_lock::window_lock_path(
            fx.store.path(),
            &fx.profile.policy_window_state_key_id,
        );
        let moved_lock = lock_path.with_extension("moved");
        fs::rename(&lock_path, &moved_lock).unwrap();
        let current = policy(vec![period("native", "1d", 100)]);
        let fresh = project(&fx, &current).unwrap();
        assert_eq!(fresh.generation, 0);
        assert_eq!(figures(&fresh)[0].2, usage(0, 0, 100));
        assert!(!lock_path.exists());
        fs::rename(&moved_lock, &lock_path).unwrap();
        fx.store
            .record_and_persist(&fx.profile, &[hold(12)])
            .unwrap();
        fs::rename(&lock_path, &moved_lock).unwrap();
        let other = policy_as([8; 32], vec![period("native", "1d", 100)]);
        for supplied in [&current, &other] {
            let result = project(&fx, supplied);
            assert!(
                matches!(
                    &result,
                    Err(BudgetError::Policy(
                        stellar_agent_core::policy::PolicyError::PinAbsent
                    ))
                ),
                "committed history without the shared guard must refuse: {result:?}"
            );
            assert_eq!(result.unwrap_err().code(), "policy.pin_absent");
        }
        let moved_window = fx.store.path().with_extension("moved");
        fs::rename(fx.store.path(), &moved_window).unwrap();
        assert!(matches!(
            project(&fx, &current),
            Err(BudgetError::Policy(
                stellar_agent_core::policy::PolicyError::PinAbsent
            ))
        ));
        assert!(!lock_path.exists());
    }

    /// Project rules use the engine's cached project even after the
    /// environment changes, retaining document order and inactive scopes.
    #[test]
    #[serial]
    fn budget_rules_use_cached_project_scope() {
        use stellar_agent_test_support::env_guard::ScopedEnvVar;

        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        let fx = Fx::new();
        let scoped = |project: &str| {
            let document = PolicyDocument {
                version: 2,
                scope: ScopeId::ProfileProject {
                    profile: "ops".to_owned(),
                    project: project.to_owned(),
                },
                rules: [123, 456]
                    .into_iter()
                    .map(|cap| PolicyRule {
                        r#match: RuleMatch {
                            tool: "*".to_owned(),
                            chain: "*".to_owned(),
                        },
                        criteria: vec![Box::new(PerTxCapCriterion::new("native".to_owned(), cap))],
                        decision: Decision::Allow,
                        allow_opaque_signing: false,
                    })
                    .collect(),
                signature: None,
            };
            VerifiedPolicy::for_test(
                [7; 32],
                Arc::new(PolicyEngineV1::new(document, "ops".to_owned())),
            )
        };
        let _initial = ScopedEnvVar::new("STELLAR_AGENT_PROJECT", Some("active".as_ref()));
        let active = scoped("active");
        let inactive = scoped("other");
        let _changed = ScopedEnvVar::new("STELLAR_AGENT_PROJECT", Some("other".as_ref()));
        let projection = project(&fx, &active).unwrap();
        let caps: Vec<_> = projection
            .rules
            .iter()
            .map(|rule| (rule.index, rule.per_call[0].cap_stroops))
            .collect();
        assert_eq!(caps, vec![(0, 123), (1, 456)], "cached project rules");
        assert!(project(&fx, &inactive).unwrap().rules.is_empty());
    }

    /// Individually representable used and reserved totals must also fit
    /// together, as the admission total reader requires.
    #[test]
    #[serial]
    fn budget_combined_used_and_reserved_overflow_refuses() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        let fx = Fx::new();
        fx.store
            .record_and_persist(&fx.profile, &[hold(12)])
            .unwrap();
        let mut wire = fx.wire();
        let total = StateKey::new("ops", 1, "total:native", 0);
        find_or_insert_bucket(&mut wire.entries, &total)
            .records
            .extend([
                WireRecord {
                    epoch: Some([7; 32]),
                    ..row("used-max", i128::MAX, RecordStatus::Confirmed, T0)
                },
                WireRecord {
                    epoch: Some([7; 32]),
                    ..row("reserved-one", 1, RecordStatus::Pending, T0)
                },
            ]);
        seal(&fx, wire);
        let admission = fx.store.total_usage(&fx.profile, [7; 32]).unwrap_err();
        let result = project(
            &fx,
            &policy(vec![Box::new(TotalBudgetCriterion::new(
                "native".to_owned(),
                100,
            ))]),
        );
        assert!(
            matches!(
                &result,
                Err(BudgetError::State(WindowStoreError::Invalid { detail }))
                    if detail == "a total-budget sum overflows"
            ),
            "used plus reserved must refuse overflow: {result:?}"
        );
        let error = result.unwrap_err();
        assert_eq!(error.to_string(), admission.to_string());
        assert_eq!(error.code(), admission.code());
    }

    /// Exposure of one authorization in another window falls back to its
    /// summed rows. Rows of `i128::MAX` and 1 refuse the projection with the
    /// typed invalid-state error, not a clock error.
    #[test]
    #[serial]
    fn budget_fallback_history_overflow_refuses_typed() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        let fx = Fx::new();
        fx.store
            .record_and_persist(&fx.profile, &[hold(12)])
            .unwrap();
        let now = fx.now();
        let mut wire = fx.wire();
        find_or_insert_bucket(
            &mut wire.entries,
            &StateKey::new("ops", 1, "native", 604_800),
        )
        .records
        .extend([
            row("fallback", i128::MAX, RecordStatus::Pending, now),
            row("fallback", 1, RecordStatus::Pending, now),
        ]);
        seal(&fx, wire);
        let error = project(&fx, &policy(vec![period("native", "1d", 100)])).unwrap_err();
        assert!(
            matches!(
                &error,
                BudgetError::State(WindowStoreError::Invalid { detail })
                    if *detail == stellar_agent_core::policy::v1::criteria::state_store::StateStoreError::SumOverflow.to_string()
            ),
            "{error:?}"
        );
    }

    /// Missing native amounts stay disclosed until an admissible observation
    /// proves a bounded release, or an `Always` row releases unconditionally.
    #[test]
    #[serial]
    fn budget_legacy_disclosure_requires_proven_release() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        let fx = Fx::new();
        let request = fx.mint_request(tx(1), fx.approval(), vec![]);
        let id = fx
            .store
            .mint_authorization(&fx.profile, &request)
            .unwrap()
            .id;
        let wire = fx.wire();
        let policy = policy(Vec::new());
        for bound in [
            None,
            Some(ReleaseBound::Always),
            Some(ReleaseBound::Ledger(500)),
            Some(ReleaseBound::CloseTime(9_000)),
        ] {
            let mut disclosed = Vec::new();
            for (observation, floors) in [
                (None, (None, None)),
                (Some((500, 9_000)), (Some(501), None)),
                (Some((500, 9_000)), (None, Some(9_001))),
                (Some((499, 8_999)), (None, None)),
                (Some((500, 9_000)), (Some(500), Some(9_000))),
                (Some((501, 9_001)), (None, None)),
            ] {
                let mut wire = wire.clone();
                wire.authorizations[0].native_release = bound.map(|bound| ReleaseRow {
                    class: ReleaseClass::Unknown,
                    bound,
                    observed_ledger: None,
                    commit_id: CommitId::from_bytes([0xc0; 16]),
                });
                wire.last_observation =
                    observation.map(|(ledger, close_time_floor_ms)| WindowObservation {
                        ledger,
                        close_time_floor_ms,
                        observed_at_ms: T0,
                    });
                (
                    wire.admissible_floor_ledger,
                    wire.admissible_floor_close_time_ms,
                ) = floors;
                seal(&fx, wire);
                let projection = project(&fx, &policy).unwrap();
                assert_eq!(obligation(&projection, id), None);
                disclosed.push(projection.native.unreserved_legacy);
            }
            let expected = match bound {
                None => vec![vec![id]; 6],
                Some(ReleaseBound::Always) => vec![vec![]; 6],
                _ => vec![vec![id], vec![id], vec![id], vec![id], vec![], vec![]],
            };
            assert_eq!(disclosed, expected, "legacy release evidence: {bound:?}");
        }
    }

    fn get_counter(entry: &stellar_agent_core::profile::schema::KeyringEntryRef) -> Option<String> {
        keyring_core::Entry::new(&entry.service, &entry.account)
            .unwrap()
            .get_password()
            .ok()
    }

    fn set_counter(entry: &stellar_agent_core::profile::schema::KeyringEntryRef, value: &str) {
        keyring_core::Entry::new(&entry.service, &entry.account)
            .unwrap()
            .set_password(value)
            .unwrap();
    }

    fn obligation(projection: &BudgetProjection, id: AuthorizationId) -> Option<NativeObligation> {
        projection
            .authorizations
            .iter()
            .find(|view| view.id == id)
            .unwrap()
            .native_obligation
    }

    fn counted(
        projection: &BudgetProjection,
        ids: &[AuthorizationId],
    ) -> Vec<Result<bool, Undecided>> {
        ids.iter()
            .map(|id| obligation(projection, *id).unwrap().counted)
            .collect()
    }

    /// Six reservations under one stored window: a live one, a sweep's
    /// `Always` row, a cleared unknown `Always` row, a settled `Ledger(500)`
    /// row, an unknown `CloseTime(9000)` row, and a used authorization
    /// without a row; a seventh has no amounts. Without an observation and
    /// below either floor, only the `Always` rows decide, as false. At
    /// ledger 500 and close time 9000 both bounded rows release at equality;
    /// one below each, they count. A used authorization always counts, the
    /// sum adds debit plus fee once per counted authorization, the legacy
    /// authorization is listed, and an observation dated after the clock
    /// refuses as a clock error.
    #[test]
    #[serial]
    fn budget_native_observation_matrix() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        let fx = Fx::new();
        let ids: Vec<AuthorizationId> = (1..=7_u8)
            .map(|n| {
                let mut request = fx.mint_request(tx(n), fx.approval(), vec![]);
                request.native_reservation = (n != 7).then_some(NativeReservation {
                    debit_stroops: 100 * i64::from(n),
                    fee_stroops: i64::from(n),
                });
                fx.store
                    .mint_authorization(&fx.profile, &request)
                    .unwrap()
                    .id
            })
            .collect();
        let commit = CommitId::from_bytes([0xc0; 16]);
        let release = |class, bound| {
            Some(ReleaseRow {
                class,
                bound,
                observed_ledger: None,
                commit_id: commit,
            })
        };
        let mut wire = fx.wire();
        for auth in &mut wire.authorizations {
            let n = ids.iter().position(|id| *id == auth.id).unwrap() + 1;
            match n {
                2 => {
                    auth.state = AuthorizationState::Invalidated;
                    auth.settled_ms = Some(T0);
                    auth.disposition = Some(Disposition::Unused);
                    auth.native_release =
                        release(ReleaseClass::ProvedUnspent, ReleaseBound::Always);
                }
                3 => auth.native_release = release(ReleaseClass::Unknown, ReleaseBound::Always),
                4 => {
                    auth.native_release = release(ReleaseClass::Settled, ReleaseBound::Ledger(500))
                }
                5 => {
                    auth.native_release =
                        release(ReleaseClass::Unknown, ReleaseBound::CloseTime(9_000));
                }
                6 => {
                    auth.state = AuthorizationState::Used;
                    auth.settled_ms = Some(T0);
                    auth.disposition = Some(Disposition::Used);
                    auth.consumption = Some(ConsumptionBinding::Transaction(SubmissionBinding {
                        destinations: Default::default(),
                        chain_scope: Some(ChainScope::for_chain(Caip2::Mainnet)),
                        fee_bump: None,
                        envelope_hash: [0x5c; 32],
                        tx_hash: [0x86; 32],
                        source: SOURCE.to_owned(),
                        sequence: 106,
                        max_time: T0 / 1_000 + 60,
                        pending_since_ms: T0,
                        submission_ledger: 1,
                        submission_anchor: None,
                    }));
                }
                _ => {}
            }
        }
        let policy = policy(Vec::new());
        let at = |ledger, close_time_floor_ms, floors: (Option<u32>, Option<u64>)| {
            let mut wire = wire.clone();
            wire.last_observation = Some(WindowObservation {
                ledger,
                close_time_floor_ms,
                observed_at_ms: T0 - 250,
            });
            (
                wire.admissible_floor_ledger,
                wire.admissible_floor_close_time_ms,
            ) = floors;
            seal(&fx, wire);
            project(&fx, &policy).unwrap()
        };
        let tracked = &ids[..6];

        seal(&fx, wire.clone());
        let absent = project(&fx, &policy).unwrap();
        let undecided = Err(Undecided::NoObservation);
        assert_eq!(
            counted(&absent, tracked),
            vec![
                undecided,
                Ok(false),
                Ok(false),
                undecided,
                undecided,
                undecided
            ]
        );
        assert_eq!(absent.native.counted, Err(Undecided::NoObservation));
        assert_eq!(
            (absent.native.observation, absent.native.observation_age_ms),
            (None, None)
        );
        assert_eq!(absent.native.unreserved_legacy, vec![ids[6]]);
        assert_eq!(obligation(&absent, ids[6]), None);

        let below = Err(Undecided::ObservationBelowFloor);
        for floors in [(Some(501), None), (None, Some(9_001))] {
            let projection = at(500, 9_000, floors);
            assert_eq!(
                counted(&projection, tracked),
                vec![below, Ok(false), Ok(false), below, below, below],
                "{floors:?}"
            );
            assert_eq!(
                projection.native.counted,
                Err(Undecided::ObservationBelowFloor)
            );
        }

        let equal = at(500, 9_000, (Some(500), Some(9_000)));
        assert_eq!(
            counted(&equal, tracked),
            vec![
                Ok(true),
                Ok(false),
                Ok(false),
                Ok(false),
                Ok(false),
                Ok(true)
            ]
        );
        assert_eq!(equal.native.counted, Ok(101 + 606));
        assert_eq!(equal.native.observation_age_ms, Some(250));

        let earlier = at(499, 8_999, (None, None));
        assert_eq!(
            counted(&earlier, tracked),
            vec![Ok(true), Ok(false), Ok(false), Ok(true), Ok(true), Ok(true)]
        );
        assert_eq!(earlier.native.counted, Ok(101 + 404 + 505 + 606));

        let views: Vec<_> = tracked
            .iter()
            .map(|id| {
                let view = earlier
                    .authorizations
                    .iter()
                    .find(|view| view.id == *id)
                    .unwrap();
                let native = view.native_obligation.unwrap();
                (view.disposition, native.class, native.release_bound)
            })
            .collect();
        assert_eq!(
            views,
            vec![
                (None, NativeClass::Live, None),
                (Some(Disposition::Unused), NativeClass::ProvedUnspent, None),
                (None, NativeClass::Unknown, None),
                (
                    None,
                    NativeClass::Settled,
                    Some(InformationalBound::Ledger(500))
                ),
                (
                    None,
                    NativeClass::Unknown,
                    Some(InformationalBound::AfterMs(9_000))
                ),
                (Some(Disposition::Used), NativeClass::Live, None),
            ]
        );

        let mut future = wire;
        future.last_observation = Some(WindowObservation {
            ledger: 500,
            close_time_floor_ms: 9_000,
            observed_at_ms: T0 + 1,
        });
        seal(&fx, future);
        let error = project(&fx, &policy).unwrap_err();
        assert!(matches!(error, BudgetError::Clock { .. }), "{error:?}");
        assert_eq!(error.code(), "wallet.clock_error");
    }

    /// An exposed, timed classic attempt's reservation is live while its
    /// operation is pending, settled once it succeeds or fails, and unknown
    /// once it is cancelled, has its payload released, or expires after the
    /// exposure; its informational bound is the attempt's `max_time` in
    /// milliseconds, and it counts in every class without a row.
    #[test]
    #[serial]
    fn authorization_projection_classes_follow_operation_evidence() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        let mut fx = Fx::new();
        let handle = fx.open_new(&request("budget-class", canonical(1)));
        let mut minted = fx.mint_request(tx(1), fx.policy(), vec![]);
        minted.native_reservation = Some(NativeReservation {
            debit_stroops: 40,
            fee_stroops: 2,
        });
        let started = fx.begin_mint(&handle, &minted).unwrap();
        fx.claim(&minted, started.minted.as_ref().unwrap());
        let identity = ExposureIdentity::Classic {
            envelope_sha256: [0x5b; 32],
            tx_hash: [0x81; 32],
            sequence: 101,
            max_time: T0 / 1_000 + 60,
            receipt: stellar_agent_core::hex::encode(&[0x5b; 32]),
        };
        fx.recorder()
            .expose(handle.id(), started.attempt_index, &identity, Some(10))
            .unwrap();
        let mut wire = fx.wire();
        wire.last_observation = Some(WindowObservation {
            ledger: 20,
            close_time_floor_ms: T0,
            observed_at_ms: T0,
        });
        let policy = policy(Vec::new());
        let auth_id = started.authorization_id;
        for (state, class) in [
            (OperationState::Sending, NativeClass::Live),
            (OperationState::SentOutcomeUnknown, NativeClass::Live),
            (OperationState::Succeeded, NativeClass::Settled),
            (OperationState::Failed, NativeClass::Settled),
            (OperationState::PayloadReleased, NativeClass::Unknown),
            (OperationState::Cancelled, NativeClass::Unknown),
            (OperationState::Expired, NativeClass::Unknown),
        ] {
            let mut changed = wire.clone();
            let record = &mut section_mut(&mut changed).records[0];
            record.history.push(HistoryEntry {
                from: Some(record.state),
                to: state,
                at_ms: T0,
                evidence: None,
            });
            record.state = state;
            record.closed_at_ms = state.is_terminal().then_some(T0);
            seal(&fx, changed);
            let projection = project(&fx, &policy).unwrap();
            assert_eq!(
                obligation(&projection, auth_id),
                Some(NativeObligation {
                    counted: Ok(true),
                    class,
                    release_bound: Some(InformationalBound::AfterMs((T0 / 1_000 + 60) * 1_000)),
                }),
                "{state:?}"
            );
            assert_eq!(projection.native.counted, Ok(42));
        }
    }
}
