use crate::operation_entry::{IntentBaseFacts, classic_intent, intent_envelope};
use crate::policy_state::{
    ApprovalRecorder, AttemptAuthorization, AttemptEnvelope, AttemptRequest, BusinessId,
    ConsentPayload, ConsentRow, IntentSlot, LookupOutcome, OpenOutcome, OpenRequest,
    OperationHandle, OperationKind, OperationRecorder, OperationStatus, OperationTool,
    PendingApprovalFacts,
};
use stellar_agent_core::approval::{
    PendingApproval,
    intent::{ClassicIntent, IntentAsset, IntentPayload, MemoFact},
    subject::{SubjectKind, approval_subject_classic},
};
use stellar_agent_core::mainnet::decision::{AuthorityScope, MainnetDecision};
use stellar_agent_core::policy::Decision;
use stellar_xdr::Limits;

struct CanonicalFx {
    f: ResolverFixture,
    intent: ClassicIntent,
    witness: ApprovalWitness,
    handle: OperationHandle,
    link: OperationLink,
    claim: Option<stellar_xdr::ClaimableBalanceEntry>,
}

fn claim_policy(raw: &str) -> String {
    raw.lines()
        .filter(|line| !line.contains("kind = \"asset_allowlist\""))
        .collect::<Vec<_>>()
        .join("\n")
}

impl CanonicalFx {
    fn new(claim: bool, ttl: u64, policy_edit: impl FnOnce(&str) -> String) -> Self {
        let mut f = ResolverFixture::configured(
            |profile| {
                if claim {
                    use stellar_agent_core::profile::schema::{
                        PrimaryProviderRecord, ProviderRecord,
                    };
                    let mut oracle = profile.rpc_url.parse::<url::Url>().unwrap();
                    let providers = profile.providers.get_or_insert_with(Default::default);
                    providers.primary = Some(PrimaryProviderRecord::new(
                        "primary",
                        oracle.host_str().unwrap(),
                    ));
                    oracle
                        .set_host(Some(&format!("oracle.{}", oracle.host_str().unwrap())))
                        .unwrap();
                    providers.oracle = Some(ProviderRecord::new(
                        "oracle",
                        oracle.host_str().unwrap(),
                        true,
                    ));
                    profile.oracle_provider_url = Some(oracle);
                }
            },
            |raw| {
                policy_edit(&if claim {
                    raw.replace("stellar_pay", "stellar_claim")
                } else {
                    raw.to_owned()
                })
            },
        );
        f.now = stellar_agent_core::timefmt::now_unix_ms().unwrap();
        f.clock.set(f.now);
        let asset = IntentAsset::Issued {
            code: "UsD".to_owned(),
            issuer: f.source.destination().to_owned(),
        };
        let balance =
            stellar_xdr::ClaimableBalanceId::ClaimableBalanceIdTypeV0(stellar_xdr::Hash([9; 32]));
        let balance_id = format!("00000000{}", "09".repeat(32));
        let payload = if claim {
            IntentPayload::Claim {
                balance_id: balance_id.clone(),
                asset: asset.clone(),
                amount_stroops: 10,
                claimant: f.source.source().to_owned(),
            }
        } else {
            IntentPayload::Pay {
                destination: f.source.destination().to_owned(),
                asset: IntentAsset::Native,
                amount_stroops: 10,
            }
        };
        let intent = classic_intent(
            IntentBaseFacts {
                chain_id: f.profile.chain_id.caip2_str(),
                source: f.source.source(),
                policy_digest: f.policy.digest(),
                signed_fee_cap: Some(500),
                profile_fee_cap: None,
                fee_choice: crate::fees::ClassicFeeChoice::ProfileDefault,
                memo: MemoFact::Text("approved".to_owned()),
            },
            payload,
        )
        .unwrap();
        f.envelope = intent_envelope(
            &intent,
            f.context.network_passphrase(),
            1,
            100,
            f.now / 1000 + 120,
        )
        .unwrap();
        let mut entry = if claim {
            PendingApproval::new_claim_pending(
                f.envelope.clone(),
                f.envelope.as_bytes(),
                balance_id,
                stellar_strkey::ClaimableBalance::V0([9; 32])
                    .to_string()
                    .to_string(),
                format!("UsD:{}", f.source.destination()),
                10,
                f.source.source().to_owned(),
                100,
                1,
                "1000".to_owned(),
                ttl,
            )
            .unwrap()
        } else {
            PendingApproval::new_payment_pending(
                f.envelope.clone(),
                f.envelope.as_bytes(),
                f.source.destination().to_owned(),
                10,
                "XLM".to_owned(),
                Some("approved".to_owned()),
                100,
                1,
                "1000".to_owned(),
                ttl,
            )
            .unwrap()
        };
        entry.subject_kind = SubjectKind::IntentDigest;
        entry.created_at_unix_ms = f.now - 60_000;
        entry.expires_at_unix_ms = entry.created_at_unix_ms + ttl;
        let decision = MainnetDecision::for_test(
            Decision::RequireApproval(stellar_agent_core::policy::ApprovalRequest::new(
                String::new(),
                (ttl / 1000).try_into().unwrap(),
            )),
            None,
            f.policy.digest(),
            f.policy.sequence(),
            0,
            f.context.profile_name(),
            f.profile.chain_id.caip2_str(),
            f.now,
            ttl,
            AuthorityScope::Classic,
        );
        let witness = f.attested_intent(&entry, &intent, &decision);
        f.clock.set(entry.created_at_unix_ms);
        let mut rows = ApprovalRows;
        let OpenOutcome::New(handle) =
            OperationRecorder::new(&f.window, &f.profile, &mut rows, "open")
                .open(&OpenRequest {
                    business_id: BusinessId::parse(witness.nonce()).unwrap(),
                    tool: if claim {
                        OperationTool::CliClaim
                    } else {
                        OperationTool::CliPay
                    },
                    kind: if claim {
                        OperationKind::Claim
                    } else {
                        OperationKind::Pay
                    },
                    intent: IntentSlot::Canonical {
                        intent_digest: *intent.digest().as_bytes(),
                        intent: serde_json::to_value(&intent).unwrap(),
                    },
                    envelope_xdr: None,
                    prepared_decision: None,
                    rule_ttl_ms: Some(ttl),
                })
                .unwrap()
        else {
            panic!("new canonical operation")
        };
        let mut recorder = ApprovalRecorder::new(&f.window, &f.profile, &mut rows, "pending");
        let pending = recorder
            .open_pending(
                handle.id(),
                &PendingApprovalFacts {
                    nonce: witness.nonce().to_owned(),
                    kind: witness.kind(),
                    subject_kind: witness.subject_kind(),
                    subject: witness.subject(),
                    intent_digest: *intent.digest().as_bytes(),
                    created_at_ms: witness.created_at_ms(),
                    waiting_expires_at_ms: witness.expires_at_ms(),
                    rule_ttl_ms: ttl,
                },
                stellar_agent_core::audit_log::PolicyDecision::RequireApproval,
            )
            .unwrap();
        use base64::Engine as _;
        let inbox =
            stellar_agent_core::approval::PendingApprovalStore::open(f.dir.path().join(format!(
                "{}-{}.toml",
                witness.nonce(),
                stellar_agent_core::hex::encode(&witness.subject()),
            )))
            .unwrap();
        let consented = inbox.get(witness.nonce()).unwrap();
        let blob = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(consented.attestation_blob_b64.as_ref().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        f.now = witness.consent_at_ms();
        f.clock.set(f.now);
        recorder
            .record_consent(
                pending.record.id,
                &witness,
                &ConsentPayload::new(
                    blob,
                    consented.mainnet_presence.clone().unwrap(),
                    consented.process_uid.clone(),
                    ConsentRow::Written,
                ),
            )
            .unwrap();
        let claim = claim.then(|| stellar_xdr::ClaimableBalanceEntry {
            balance_id: balance,
            claimants: vec![stellar_xdr::Claimant::ClaimantTypeV0(
                stellar_xdr::ClaimantV0 {
                    destination: stellar_xdr::AccountId(
                        stellar_xdr::PublicKey::PublicKeyTypeEd25519(stellar_xdr::Uint256(
                            f.signer.public_key(),
                        )),
                    ),
                    predicate: stellar_xdr::ClaimPredicate::Unconditional,
                },
            )]
            .try_into()
            .unwrap(),
            asset: stellar_xdr::Asset::CreditAlphanum4(stellar_xdr::AlphaNum4 {
                asset_code: stellar_xdr::AssetCode4(*b"UsD\0"),
                issuer: stellar_xdr::AccountId(stellar_xdr::PublicKey::PublicKeyTypeEd25519(
                    stellar_xdr::Uint256(
                        stellar_strkey::ed25519::PublicKey::from_string(f.source.destination())
                            .unwrap()
                            .0,
                    ),
                )),
            }),
            amount: 10,
            ext: stellar_xdr::ClaimableBalanceEntryExt::V0,
        });
        let link = OperationLink {
            operation_id: handle.id(),
            attempt_index: 1,
        };
        Self {
            f,
            intent,
            witness,
            handle,
            link,
            claim,
        }
    }

    fn decision_for(f: &ResolverFixture, ttl: u64, now: u64) -> MainnetDecision {
        MainnetDecision::for_test(
            Decision::Allow,
            None,
            f.policy.digest(),
            f.policy.sequence(),
            0,
            f.context.profile_name(),
            f.profile.chain_id.caip2_str(),
            now,
            ttl,
            AuthorityScope::Classic,
        )
    }

    fn envelope_at(&self, now: u64, sequence: i64) -> String {
        self.envelope_until(now / 1000 + 120, sequence)
    }

    /// The envelope a caller rebuilds at `now` under an authority ending at
    /// `end_ms`: its deadline is the earlier of 120 seconds after `now` and
    /// the last whole second strictly before the end.
    fn envelope_under(&self, now: u64, end_ms: u64, sequence: i64) -> String {
        self.envelope_until((now / 1000 + 120).min(end_ms.saturating_sub(1) / 1000), sequence)
    }

    /// The intent's envelope at `sequence` with the deadline `max_time_s`.
    fn envelope_until(&self, max_time_s: u64, sequence: i64) -> String {
        intent_envelope(
            &self.intent,
            self.f.context.network_passphrase(),
            sequence,
            100,
            max_time_s,
        )
        .unwrap()
    }

    async fn claim_response(
        &self,
        server: &wiremock::MockServer,
        entry: Option<&stellar_xdr::ClaimableBalanceEntry>,
    ) {
        use stellar_agent_test_support::EchoIdResponder;
        use wiremock::{Mock, matchers::body_partial_json};
        let key =
            stellar_xdr::LedgerKey::ClaimableBalance(stellar_xdr::LedgerKeyClaimableBalance {
                balance_id: self.claim.as_ref().unwrap().balance_id.clone(),
            })
            .to_xdr_base64(Limits::none())
            .unwrap();
        let entries: Vec<_> = entry.into_iter().map(|entry| serde_json::json!({
            "key": key, "xdr": stellar_xdr::LedgerEntryData::ClaimableBalance(entry.clone()).to_xdr_base64(Limits::none()).unwrap(),
            "lastModifiedLedgerSeq": 1,
        })).collect();
        Mock::given(body_partial_json(
            serde_json::json!({"method": "getLedgerEntries", "params": {"keys": [key]}}),
        ))
        .respond_with(EchoIdResponder::new(
            serde_json::json!({"entries": entries, "latestLedger": 1}),
        ))
        .with_priority(1)
        .mount(server)
        .await;
    }

    fn context(&self, server: &wiremock::MockServer) -> MainnetWriteContext {
        let url = self.f.profile.rpc_url.parse::<url::Url>().unwrap();
        self.f
            .context_with_routes(&[(url.host_str().unwrap(), &server.uri())])
    }

    async fn resolve(
        &self,
        context: &MainnetWriteContext,
        envelope: &str,
        now: u64,
        approval: bool,
    ) -> Result<MainnetTxSignAuthorization, MainnetAuthorizationError> {
        self.resolve_with(context, envelope, now, approval, |pending| {
            self.begin(envelope, pending)
        })
        .await
    }

    /// Resolves `envelope` through the canonical route and hands the checked
    /// signing to `finish`.
    async fn resolve_with<T>(
        &self,
        context: &MainnetWriteContext,
        envelope: &str,
        now: u64,
        approval: bool,
        finish: impl FnOnce(PendingTxSign<'_>) -> T,
    ) -> Result<T, MainnetAuthorizationError> {
        self.f.clock.set(now);
        let decision = Self::decision_for(&self.f, 900_000, now);
        let authority =
            MainnetAuthority::from_decision(&decision, approval.then_some(&self.witness)).unwrap();
        let client = context.primary_client().unwrap();
        let mut req = request(&self.f, context, &client, &authority);
        req.unsigned_envelope_xdr = envelope;
        req.operation = Some(self.link);
        if self.claim.is_some() {
            req.consumer = MainnetConsumer::CliClaim;
        }
        let oracle_witness = self.claim.as_ref().map(|_| {
            let decoded =
                stellar_xdr::TransactionEnvelope::from_xdr_base64(envelope, Limits::none())
                    .unwrap();
            let hash =
                crate::submit::compute_local_tx_hash_hex(&decoded, context.network_passphrase())
                    .unwrap();
            crate::cross_check::CrossCheckWitness::for_crate_tests(
                self.f
                    .profile
                    .oracle_provider_url
                    .as_ref()
                    .unwrap()
                    .as_str(),
                1,
                [1; 32],
                vec![],
            )
            .bound_for_crate_tests(stellar_agent_core::hex::decode_hex32(&hash).unwrap())
        });
        req.witness = oracle_witness.as_ref();
        Ok(finish(resolve_canonical_tx_sign(req).await?))
    }

    /// Begins the operation's next attempt under `pending`'s mint.
    fn begin(&self, envelope: &str, pending: PendingTxSign<'_>) -> MainnetTxSignAuthorization {
        // Each begin writes under a log of its own, since every test writer
        // holds a fresh anchor store.
        static BEGINS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = BEGINS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let writer = crate::submission_flow::recovery::tests::writer_at(
            &self.f.dir.path().join(format!("attempt-{n}-audit.jsonl")),
        );
        let (attempt, auth) = crate::operation_entry::begin_canonical_attempt(
            &writer,
            "attempt",
            &self.handle,
            envelope,
            pending,
        )
        .unwrap_or_else(|error| panic!("the canonical attempt's begin refused: {error:?}"));
        assert_eq!(attempt.attempt_index, self.link.attempt_index);
        let view = OperationStatus::new(&self.f.window, &self.f.profile)
            .view(&BusinessId::parse(self.witness.nonce()).unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(view.attempts, self.link.attempt_index);
        assert_eq!(view.state, crate::policy_state::OperationState::Sending);
        auth
    }

    async fn sign(
        &self,
        context: &MainnetWriteContext,
        envelope: &str,
        auth: &MainnetTxSignAuthorization,
    ) {
        let signer = crate::signing::test_doubles::CountingSigner::new(
            super::super::super::fixtures::SIGNER_SEED,
        );
        crate::signing::envelope_signing::attach_signature_authorized(
            envelope,
            &signer,
            context.network_passphrase(),
            if self.claim.is_some() {
                MainnetConsumer::CliClaim
            } else {
                MainnetConsumer::CliPay
            },
            auth,
        )
        .await
        .unwrap();
        assert_eq!(signer.sign_calls(), 1);
    }
}

#[tokio::test]
#[serial_test::serial(mainnet_clock)]
#[serial_test::serial]
async fn canonical_resolver_binds_intent_and_envelope() {
    let fx = CanonicalFx::new(false, 900_000, str::to_owned);
    let server = fx.f.server().await;
    let context = fx.context(&server);
    let auth = fx
        .resolve(&context, &fx.f.envelope, fx.f.now, true)
        .await
        .unwrap();
    assert_eq!(
        auth.0.header.intent_digest,
        Some(*fx.intent.digest().as_bytes())
    );
    assert_eq!(auth.0.header.operation, Some(fx.link));
    assert_eq!(auth.0.header.predecessor, None);
    auth.check_unsigned_envelope(&approval_subject_classic(&fx.f.envelope))
        .unwrap();
    let other = fx.envelope_at(fx.f.now, 2);
    let signer = crate::signing::test_doubles::CountingSigner::new(
        super::super::super::fixtures::SIGNER_SEED,
    );
    let refused = crate::signing::envelope_signing::authorized_signature(
        &other,
        &signer,
        context.network_passphrase(),
        MainnetConsumer::CliPay,
        &auth,
    )
    .await
    .unwrap_err();
    assert!(format!("{refused:?}").contains("UnsignedEnvelope"));
    assert_eq!(signer.sign_calls(), 0);
    fx.sign(&context, &fx.f.envelope, &auth).await;
}

/// A canonical envelope signs only when its deadline lies strictly before
/// the authority's end. 60 seconds before an approval's execution end, an
/// envelope whose deadline is the last whole second before that end signs;
/// one whose deadline is the first whole second at or after the end refuses
/// with `DeadlineTooFar` and writes nothing.
#[tokio::test]
#[serial_test::serial(mainnet_clock)]
#[serial_test::serial]
async fn a_canonical_deadline_lies_strictly_before_the_authority_end() {
    let fx = CanonicalFx::new(false, 300_000, str::to_owned);
    let end = fx.witness.execution_expires_at_ms();
    let now = end - 60_000;
    let server = fx.f.server().await;
    let context = fx.context(&server);

    let at_end = fx.envelope_until(end.div_ceil(1000), 1);
    let before = fx.f.wire();
    let refused = fx.resolve(&context, &at_end, now, true).await;
    assert!(
        matches!(
            refused,
            Err(MainnetAuthorizationError::Refused(P::DeadlineTooFar))
        ),
        "a deadline at the end: {refused:?}"
    );
    assert_eq!(fx.f.wire(), before, "the refusal writes nothing");

    let last_second = fx.envelope_until((end - 1) / 1000, 1);
    let auth = fx.resolve(&context, &last_second, now, true).await.unwrap();
    fx.sign(&context, &last_second, &auth).await;
}

#[tokio::test]
#[serial_test::serial(mainnet_clock)]
#[serial_test::serial]
async fn canonical_resolver_rereads_the_claim() {
    for changed in ["same", "amount", "vanished", "transport", "decode"] {
        let fx = CanonicalFx::new(true, 900_000, claim_policy);
        let server = fx.f.server().await;
        let context = fx.context(&server);
        let mut entry = fx.claim.clone().unwrap();
        if changed == "amount" {
            entry.amount += 1;
        }
        if !matches!(changed, "transport" | "decode") {
            fx.claim_response(&server, (changed != "vanished").then_some(&entry))
                .await;
        }
        if matches!(changed, "transport" | "decode") {
            let response = move |request: &wiremock::Request| {
                if changed == "transport" {
                    wiremock::ResponseTemplate::new(503)
                } else {
                    wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "jsonrpc": "2.0", "id": serde_json::from_slice::<serde_json::Value>(&request.body).unwrap()["id"], "result": {"entries": [{
                        "key": "", "xdr": "invalid", "lastModifiedLedgerSeq": 1
                    }], "latestLedger": 1}
                }))
                }
            };
            wiremock::Mock::given(wiremock::matchers::body_partial_json(serde_json::json!({
                "method": "getLedgerEntries", "params": {"keys": [stellar_xdr::LedgerKey::ClaimableBalance(stellar_xdr::LedgerKeyClaimableBalance {
                    balance_id: entry.balance_id.clone(),
                }).to_xdr_base64(Limits::none()).unwrap()]}
            }))).respond_with(response).with_priority(1).mount(&server).await;
        }
        let before = fx.f.wire();
        let result = fx.resolve(&context, &fx.f.envelope, fx.f.now, true).await;
        if changed == "same" {
            fx.sign(&context, &fx.f.envelope, &result.unwrap()).await;
        } else {
            // A reread balance that differs from the stored intent is a
            // field divergence; an unreadable entry is no intent match.
            let expected = match changed {
                "transport" => P::EndpointUnavailable,
                "amount" | "vanished" => P::IntentDivergence,
                _ => P::IntentMismatch,
            };
            assert!(
                matches!(
                    result,
                    Err(MainnetAuthorizationError::Refused(p)) if p == expected
                ),
                "claim reread {changed}: {result:?}"
            );
            assert_eq!(fx.f.wire(), before);
        }
        let reads = server.received_requests().await.unwrap();
        let key =
            stellar_xdr::LedgerKey::ClaimableBalance(stellar_xdr::LedgerKeyClaimableBalance {
                balance_id: entry.balance_id,
            })
            .to_xdr_base64(Limits::none())
            .unwrap();
        assert!(reads.iter().any(
            |r| serde_json::from_slice::<serde_json::Value>(&r.body).unwrap()["params"]["keys"]
                == serde_json::json!([key])
        ));
    }
}

#[tokio::test]
#[serial_test::serial(mainnet_clock)]
#[serial_test::serial]
async fn intent_clock_reaches_real_signing() {
    for ttl in [300_000, 900_000] {
        for offset in [None, Some(-32_000_i64), Some(-1), Some(0), Some(1)] {
            let fx = CanonicalFx::new(false, ttl, str::to_owned);
            let end = fx.witness.execution_expires_at_ms();
            assert_eq!(end, fx.witness.consent_at_ms() + ttl.min(900_000));
            let decision = CanonicalFx::decision_for(&fx.f, 1_000, fx.f.now);
            let MainnetAuthority::Approval(bounded) =
                MainnetAuthority::from_decision(&decision, Some(&fx.witness)).unwrap()
            else {
                panic!("consent must remain approval authority");
            };
            assert_eq!(bounded.expires_at_ms(), fx.f.now + 1_000);
            let now = offset.map_or(
                fx.handle
                    .waiting_expires_at_ms()
                    .max(fx.witness.expires_at_ms())
                    + 1,
                |offset| end.checked_add_signed(offset).unwrap(),
            );
            assert!(now > fx.witness.expires_at_ms());
            let server = fx.f.server().await;
            let context = fx.context(&server);
            // Before the end the envelope is the one a caller rebuilds, whose
            // deadline lies strictly before the end; at and after the end it
            // keeps the plain 120-second deadline.
            let envelope = if now < end {
                fx.envelope_under(now, end, 1)
            } else {
                fx.envelope_at(now, 1)
            };
            let deadline_ms = (now / 1000 + 120).min((end - 1) / 1000) * 1000;
            if offset.is_none() {
                let early = fx
                    .resolve(
                        &context,
                        &fx.f.envelope,
                        fx.witness.consent_at_ms() - 1,
                        true,
                    )
                    .await;
                assert!(
                    matches!(
                        early,
                        Err(MainnetAuthorizationError::Refused(P::ApprovalExpired))
                    ),
                    "clock before consent refuses: {early:?}"
                );
            }
            if now < end {
                // An envelope whose deadline passes the end refuses while the
                // authority still holds.
                let late = fx
                    .resolve(&context, &fx.envelope_at(now, 1), now, true)
                    .await;
                assert!(
                    matches!(
                        late,
                        Err(MainnetAuthorizationError::Refused(P::DeadlineTooFar))
                    ),
                    "a deadline past the end: {late:?}"
                );
            }
            let result = fx.resolve(&context, &envelope, now, true).await;
            if now < end && deadline_ms <= now + 30_000 {
                // Within the send margin of the last second before the end,
                // no envelope can sign: that second has passed, or lies
                // within the margin.
                let expected = if deadline_ms <= now {
                    P::DeadlineElapsed
                } else {
                    P::DeadlineWithinMargin
                };
                assert!(
                    matches!(
                        result,
                        Err(MainnetAuthorizationError::Refused(p)) if p == expected
                    ),
                    "{result:?}"
                );
            } else if now < end {
                let auth = result.unwrap();
                assert_eq!(
                    auth.expires_at_ms(),
                    (now + 60_000).min(end).min(deadline_ms)
                );
                fx.sign(&context, &envelope, &auth).await;
                assert!(matches!(
                    auth.check_not_expired(end),
                    Err(MainnetAuthorizationError::Refused(P::Expired))
                ));
                assert!(matches!(
                    auth.check_not_expired(end + 1),
                    Err(MainnetAuthorizationError::Refused(P::Expired))
                ));
            } else {
                assert!(
                    matches!(
                        result,
                        Err(MainnetAuthorizationError::Refused(P::ApprovalExpired))
                    ),
                    "{result:?}"
                );
            }
        }
    }
}

#[tokio::test]
#[serial_test::serial(mainnet_clock)]
#[serial_test::serial]
async fn rebuilt_policy_governs() {
    for (allowed, required, approval) in [
        (true, false, true),
        (true, false, false),
        (true, true, true),
        (true, true, false),
        (false, false, true),
        (false, false, false),
    ] {
        let fx = CanonicalFx::new(false, 900_000, |raw| {
            let raw = if allowed {
                raw.to_owned()
            } else {
                raw.replace("max_stroops = \"100\"", "max_stroops = \"5\"")
            };
            if required {
                raw.replace(
                    "decision = \"allow\"",
                    "decision = \"require_approval\"\nttl_secs = 600",
                )
            } else {
                raw
            }
        });
        let server = fx.f.server().await;
        let context = fx.context(&server);
        let before = fx.f.wire();
        let result = fx
            .resolve(&context, &fx.f.envelope, fx.f.now, approval)
            .await;
        if !allowed && approval {
            assert!(
                matches!(result, Err(MainnetAuthorizationError::PolicyDenied(_))),
                "{result:?}"
            );
        } else if !allowed || (required && !approval) {
            assert!(
                matches!(
                    result,
                    Err(MainnetAuthorizationError::Refused(
                        P::FreshDecisionRequiresApproval
                    ))
                ),
                "{result:?}"
            );
        } else {
            let auth = result.unwrap();
            assert_eq!(
                matches!(
                    auth.0.header.authority,
                    super::super::super::authorization::AuthorityBinding::Approval(_)
                ),
                approval,
                "a supplied witness remains Approval under Allow"
            );
            fx.sign(&context, &fx.f.envelope, &auth).await;
            continue;
        }
        assert_eq!(fx.f.wire(), before, "denied operations write no holds");
    }
    let fx = CanonicalFx::new(false, 900_000, str::to_owned);
    let server = fx.f.server().await;
    let context = fx.context(&server);
    let client = context.primary_client().unwrap();
    let changed = fx.f.another_policy();
    let decision = MainnetDecision::for_test(
        Decision::Allow,
        None,
        changed.digest(),
        changed.sequence(),
        0,
        fx.f.context.profile_name(),
        fx.f.profile.chain_id.caip2_str(),
        fx.f.now,
        900_000,
        AuthorityScope::Classic,
    );
    let authority = MainnetAuthority::from_decision(&decision, None).unwrap();
    {
        use stellar_agent_core::policy::{
            pin::{self, Pin, PinScope},
            state_lock::WindowStoreLock,
        };
        let lock = WindowStoreLock::acquire_for(
            fx.f.window.path(),
            &fx.f.profile.policy_window_state_key_id,
        )
        .unwrap();
        pin::write_for_test(
            &lock,
            &PinScope::for_profile(fx.f.window.path(), &fx.f.profile),
            &Pin::new(changed.sequence(), changed.digest(), changed.owner()).unwrap(),
        )
        .unwrap();
    }
    let mut req = request(&fx.f, &context, &client, &authority);
    req.operation = Some(fx.link);
    req.policy = &changed;
    let before = fx.f.wire();
    let result = resolve_tx_sign(req).await;
    assert!(
        matches!(
            result,
            Err(MainnetAuthorizationError::Refused(P::IntentMismatch))
        ),
        "a re-signed policy refuses: {result:?}"
    );
    assert_eq!(fx.f.wire(), before);
}

#[tokio::test]
#[serial_test::serial(mainnet_clock)]
#[serial_test::serial]
async fn consented_unminted_intent_survives_waiting_end() {
    use crate::policy_state::{OperationState, PersistedWindowStore};
    for case in [
        "restart",
        "begin",
        "end-minus-one",
        "end",
        "end-plus-one",
        "revoked",
        "unconsented",
        "released",
        "envelope",
    ] {
        let fx = CanonicalFx::new(false, 900_000, str::to_owned);
        let end = fx.witness.execution_expires_at_ms();
        let now = match case {
            "end-minus-one" => end - 1,
            "end" => end,
            "end-plus-one" => end + 1,
            _ => fx.handle.waiting_expires_at_ms() + 1,
        };
        let other = PersistedWindowStore::at_path(fx.f.window.path().to_owned());
        if case == "revoked" {
            let id = record_facts(&fx.f, &fx.witness).record().id;
            ApprovalRecorder::new(&other, &fx.f.profile, &mut ApprovalRows, "revoke")
                .revoke(id)
                .unwrap();
        } else if ["unconsented", "released", "envelope"].contains(&case) {
            crate::policy_state::operations::tests::edit_canonical_fixture(
                &fx.f.window,
                &fx.f.profile,
                case,
            );
        }
        fx.f.clock.set(now);
        let survives = ["restart", "begin", "end-minus-one"].contains(&case);
        if case != "begin" {
            let result =
                OperationRecorder::new(&other, &fx.f.profile, &mut ApprovalRows, "restart")
                    .lookup(&BusinessId::parse(fx.witness.nonce()).unwrap())
                    .unwrap()
                    .unwrap();
            assert_eq!(
                matches!(result, LookupOutcome::Resumable(_)),
                survives,
                "waiting survival: {case}"
            );
            assert_eq!(
                OperationStatus::new(&other, &fx.f.profile)
                    .view(&BusinessId::parse(fx.witness.nonce()).unwrap())
                    .unwrap()
                    .unwrap()
                    .state,
                if survives {
                    OperationState::AwaitingApproval
                } else {
                    OperationState::Expired
                }
            );
        }
        if case == "revoked" {
            let result = OperationRecorder::new(
                &fx.f.window,
                &fx.f.profile,
                &mut ApprovalRows,
                "stale-begin",
            )
            .begin_attempt(
                &fx.handle,
                &AttemptRequest {
                    envelope: None,
                    authorization: AttemptAuthorization::Linked,
                    send_by_ms: u64::MAX,
                },
            );
            assert!(
                result.is_err(),
                "a stale handle cannot revive revoked consent"
            );
        }
        if case == "begin" || case == "restart" {
            let server = fx.f.server().await;
            let context = fx.context(&server);
            let envelope = fx.envelope_at(now, 1);
            if case == "restart" {
                // The resolution begins the first attempt under its mint,
                // with the deadline a caller rebuilds under the execution end.
                let envelope = fx.envelope_under(now, end, 1);
                fx.resolve(&context, &envelope, now, true).await.unwrap();
            } else {
                let decoded =
                    stellar_xdr::TransactionEnvelope::from_xdr_base64(&envelope, Limits::none())
                        .unwrap();
                let tx_hash = crate::submit::compute_local_tx_hash_hex(
                    &decoded,
                    context.network_passphrase(),
                )
                .unwrap();
                let authorization =
                    AttemptAuthorization::Mint(Box::new(crate::policy_state::MintRequest {
                    chain: fx.f.profile.chain_id,
                    binding: crate::policy_state::DomainBinding::Transaction {
                        unsigned_envelope_sha256: approval_subject_classic(&envelope),
                        tx_hash: stellar_agent_core::hex::decode_hex32(&tx_hash).unwrap(),
                        source: fx.intent.base().source().to_owned(),
                        sequence: 2,
                    },
                    consumer: MainnetConsumer::CliPay,
                    policy_sequence: fx.f.policy.sequence(),
                    policy_digest: fx.f.policy.digest(),
                    authority: crate::policy_state::MintAuthority::Approval {
                        nonce: fx.witness.nonce().to_owned(),
                        expires_at_ms: fx.witness.execution_expires_at_ms(),
                    },
                    chain_deadline_ms: Some((now / 1000 + 120) * 1000),
                    restriction_end_ms: None,
                    authorization_ttl_ms: 60_000,
                    bindings: crate::mainnet::digest::BindingFacts {
                        endpoint: None,
                        signer: [1; 32],
                        policy: [2; 32],
                        enablement: [3; 32],
                        witness: None,
                        reservation: None,
                        authority: [4; 32],
                        audit: [5; 32],
                        restriction: None,
                    },
                    holds: vec![],
                    parent: None,
                    operation: Some(fx.link),
                    intent_digest: Some(*fx.intent.digest().as_bytes()),
                    predecessor: None,
                    approval_operation: None,
                    native_reservation: None,
                    floor: None,
                }));
                let first =
                    OperationRecorder::new(&fx.f.window, &fx.f.profile, &mut ApprovalRows, "first")
                        .begin_attempt(
                            &fx.handle,
                            &AttemptRequest {
                                envelope: Some(AttemptEnvelope {
                                    xdr: envelope.clone(),
                                    unsigned_envelope_sha256: approval_subject_classic(&envelope),
                                }),
                                authorization,
                                send_by_ms: u64::MAX,
                            },
                        )
                        .expect("first begin with no prior mint survives waiting expiry");
                assert_eq!(first.attempt_index, 1);
            }
            assert_eq!(
                record_facts(&fx.f, &fx.witness).record().disposition,
                stellar_agent_core::approval::witness::ApprovalDisposition::Consumed
            );
        }
    }
}

#[tokio::test]
#[serial_test::serial(mainnet_clock)]
#[serial_test::serial]
async fn canonical_header_binds_attempt_and_intent() {
    use super::super::super::types::AuthorizationId;
    for field in ["intent", "operation", "predecessor"] {
        let fx = CanonicalFx::new(false, 900_000, str::to_owned);
        let server = fx.f.server().await;
        let context = fx.context(&server);
        let mut auth = fx
            .resolve(&context, &fx.f.envelope, fx.f.now, false)
            .await
            .unwrap();
        let expected = match field {
            "intent" => {
                auth.0.header.intent_digest = Some([0xff; 32]);
                P::IntentMismatch
            }
            "operation" => {
                auth.0.header.operation = None;
                P::BindingMismatch
            }
            _ => {
                auth.0.header.predecessor = Some(AuthorizationId::from_bytes([0xff; 32]));
                P::PredecessorMismatch
            }
        };
        let before = fx.f.wire();
        assert!(
            matches!(auth.0.header.claim(), Err(MainnetAuthorizationError::Refused(p)) if p == expected),
            "header lineage claim: {field}"
        );
        assert_eq!(fx.f.wire(), before);
    }
    use crate::policy_state::{
        DecidedTransition, EvidenceInput, ExposureIdentity, OperationState, SequenceReleaseInput,
        TransitionEvidence,
    };
    let mut fx = CanonicalFx::new(false, 900_000, str::to_owned);
    let server = fx.f.server().await;
    let context = fx.context(&server);
    let first = fx
        .resolve(&context, &fx.f.envelope, fx.f.now, false)
        .await
        .unwrap();
    fx.sign(&context, &fx.f.envelope, &first).await;
    let crate::policy_state::DomainBinding::Transaction {
        tx_hash, sequence, ..
    } = &first.0.binding
    else {
        panic!("transaction")
    };
    let tx_hash = *tx_hash;
    let mut rows = ApprovalRows;
    let mut recorder = OperationRecorder::new(&fx.f.window, &fx.f.profile, &mut rows, "outcome");
    recorder
        .expose(
            fx.handle.id(),
            1,
            &ExposureIdentity::Classic {
                envelope_sha256: [5; 32],
                tx_hash,
                sequence: *sequence,
                max_time: fx.f.now / 1000 + 120,
                receipt: stellar_agent_core::hex::encode(&[5; 32]),
            },
            Some(10),
        )
        .unwrap();
    recorder
        .transition(
            fx.handle.id(),
            Some(1),
            OperationState::SentOutcomeUnknown,
            &TransitionEvidence::default(),
        )
        .unwrap();
    recorder
        .record_evidence(
            fx.handle.id(),
            1,
            &EvidenceInput {
                sequence_released: Some(SequenceReleaseInput {
                    primary_ledger: 130,
                    witness_ledger: 130,
                    min_close_time_ms: fx.f.now,
                }),
                ..EvidenceInput::default()
            },
        )
        .unwrap();
    let attempt = OperationStatus::new(&fx.f.window, &fx.f.profile)
        .outcome_snapshot(Some(&tx_hash))
        .unwrap()
        .pop()
        .unwrap();
    let decision = crate::policy_state::operations::tests::decide(
        &attempt,
        DecidedTransition::NotIncluded(crate::policy_state::operations::tests::not_included_proof()),
    );
    let commit = recorder.commit_decision(&decision).unwrap();
    recorder
        .acknowledge_projection(fx.handle.id(), 1, commit)
        .unwrap();
    fx.link.attempt_index = 2;
    let envelope = fx.envelope_at(fx.f.now, 2);
    let next = fx
        .resolve(&context, &envelope, fx.f.now, false)
        .await
        .unwrap();
    assert_eq!(
        next.0.header.predecessor,
        Some(first.0.header.id),
        "second header names the prior attempt"
    );
    assert_eq!(next.0.header.operation, Some(fx.link));
    assert_eq!(
        next.0.header.intent_digest,
        Some(*fx.intent.digest().as_bytes())
    );
    fx.sign(&context, &envelope, &next).await;
}

#[tokio::test]
#[serial_test::serial(mainnet_clock)]
#[serial_test::serial]
async fn legacy_binding_is_never_promoted() {
    // An unrecorded approval refuses `ApprovalNotFound`. A recorded approval
    // resolves only for its own operation's link; no link and another
    // operation's link refuse `ApprovalNonceReused`.
    for (slot, refusal) in [
        ("unrecorded", Some(P::ApprovalNotFound)),
        ("absent", Some(P::ApprovalNonceReused)),
        ("envelope", None),
        ("x402", Some(P::ApprovalNonceReused)),
    ] {
        let f = current_record_fixture(false);
        f.record_approvals.set(slot != "unrecorded");
        let server = f.server().await;
        let url = f.profile.rpc_url.parse::<url::Url>().unwrap();
        let context = f.context_with_routes(&[(url.host_str().unwrap(), &server.uri())]);
        let client = context.primary_client().unwrap();
        let witness = f.approval(&f.envelope, f.now, 600_000);
        f.clock.set(witness.consent_at_ms());
        let link = if slot == "envelope" {
            Some(durable_record(&f, &witness, true))
        } else if slot == "x402" {
            let OpenOutcome::New(handle) =
                OperationRecorder::new(&f.window, &f.profile, &mut ApprovalRows, "x402")
                    .open(&OpenRequest {
                        business_id: BusinessId::parse("legacy-x402").unwrap(),
                        tool: OperationTool::X402CreatePayment,
                        kind: OperationKind::X402Payment,
                        intent: IntentSlot::X402 {
                            intent_digest: [3; 32],
                            intent: crate::policy_state::X402Intent {
                                network: f.profile.chain_id.caip2_str().to_owned(),
                                asset: "asset".to_owned(),
                                payer: f.source.source().to_owned(),
                                pay_to: f.source.destination().to_owned(),
                                amount: "10".to_owned(),
                            },
                        },
                        envelope_xdr: None,
                        prepared_decision: None,
                        rule_ttl_ms: None,
                    })
                    .unwrap()
            else {
                panic!("new x402 slot")
            };
            Some(OperationLink {
                operation_id: handle.id(),
                attempt_index: 1,
            })
        } else {
            None
        };
        let authority = f.approval_authority(&witness);
        let other = changed_envelope(&f, |tx| tx.tx.seq_num.0 += 1);
        let mut req = request(&f, &context, &client, &authority);
        req.operation = link;
        req.unsigned_envelope_xdr = &other;
        let refused = resolve_tx_sign(req).await;
        let expected = refusal.unwrap_or(P::ApprovalSubjectMismatch);
        assert!(
            matches!(refused, Err(MainnetAuthorizationError::Refused(p)) if p == expected),
            "legacy envelope remains exact: {slot}: {refused:?}"
        );
        let mut req = request(&f, &context, &client, &authority);
        req.operation = link;
        let resolved = resolve_tx_sign(req).await;
        if let Some(refusal) = refusal {
            assert!(
                matches!(resolved, Err(MainnetAuthorizationError::Refused(p)) if p == refusal),
                "{slot}: {resolved:?}"
            );
            continue;
        }
        let auth = resolved.unwrap();
        assert_eq!(auth.0.header.intent_digest, None);
        assert_eq!(auth.0.header.predecessor, None);
        let signer = crate::signing::test_doubles::CountingSigner::new(
            super::super::super::fixtures::SIGNER_SEED,
        );
        crate::signing::envelope_signing::attach_signature_authorized(
            &f.envelope,
            &signer,
            context.network_passphrase(),
            MainnetConsumer::CliPay,
            &auth,
        )
        .await
        .unwrap();
        assert_eq!(signer.sign_calls(), 1);
    }
}

#[tokio::test]
#[serial_test::serial(mainnet_clock)]
#[serial_test::serial]
async fn bad_canonical_slots_refuse_only_use() {
    use crate::policy_state::OperationState;
    for case in ["malformed", "digest"] {
        let fx = CanonicalFx::new(false, 900_000, str::to_owned);
        crate::policy_state::operations::tests::edit_canonical_fixture(
            &fx.f.window,
            &fx.f.profile,
            case,
        );
        let server = fx.f.server().await;
        let context = fx.context(&server);
        let before = fx.f.wire();
        let business = BusinessId::parse(fx.witness.nonce()).unwrap();
        assert!(
            OperationStatus::new(&fx.f.window, &fx.f.profile)
                .view(&business)
                .expect("bad canonical content must remain inspectable")
                .is_some()
        );
        assert!(
            matches!(
                fx.resolve(&context, &fx.f.envelope, fx.f.now, true).await,
                Err(MainnetAuthorizationError::Refused(P::IntentMismatch))
            ),
            "bad slot refuses signing: {case}"
        );
        assert_eq!(fx.f.wire(), before);
        let id = record_facts(&fx.f, &fx.witness).record().id;
        ApprovalRecorder::new(&fx.f.window, &fx.f.profile, &mut ApprovalRows, "revoke")
            .revoke(id)
            .unwrap();
        fx.f.clock.set(fx.witness.execution_expires_at_ms());
        let result =
            OperationRecorder::new(&fx.f.window, &fx.f.profile, &mut ApprovalRows, "expire")
                .lookup(&business)
                .unwrap()
                .unwrap();
        assert!(
            matches!(result, LookupOutcome::Replay(view) if view.state == OperationState::Expired)
        );
        fx.f.clock.set(
            fx.witness.execution_expires_at_ms()
                + crate::policy_state::operations::TERMINAL_RETENTION_MS
                + 1,
        );
        OperationRecorder::new(&fx.f.window, &fx.f.profile, &mut ApprovalRows, "collect")
            .lookup(&business)
            .unwrap();
        assert!(
            OperationStatus::new(&fx.f.window, &fx.f.profile)
                .view(&business)
                .unwrap()
                .unwrap()
                .compacted
        );
    }
}

#[test]
#[serial_test::serial(mainnet_clock)]
#[serial_test::serial]
fn consented_waiters_keep_capacity_until_execution_end() {
    let fx = CanonicalFx::new(false, 900_000, str::to_owned);
    let open = |name: &str| OpenRequest {
        business_id: BusinessId::parse(name).unwrap(),
        tool: OperationTool::CliPay,
        kind: OperationKind::Pay,
        intent: fx.handle.intent().clone(),
        envelope_xdr: None,
        prepared_decision: None,
        rule_ttl_ms: Some(900_000),
    };
    for index in 1..16 {
        OperationRecorder::new(&fx.f.window, &fx.f.profile, &mut ApprovalRows, "fill")
            .open(&open(&format!("capacity-{index}")))
            .unwrap();
    }
    fx.f.clock.set(fx.handle.waiting_expires_at_ms() + 1);
    let result = OperationRecorder::new(&fx.f.window, &fx.f.profile, &mut ApprovalRows, "full")
        .open(&open("seventeenth"));
    assert!(
        matches!(
            result,
            Err(crate::policy_state::WindowStoreError::OperationCapacity { .. })
        ),
        "consented waiters count toward 16: {result:?}"
    );
    fx.f.clock.set(fx.witness.execution_expires_at_ms());
    assert!(matches!(
        OperationRecorder::new(&fx.f.window, &fx.f.profile, &mut ApprovalRows, "freed")
            .open(&open("seventeenth"))
            .unwrap(),
        OpenOutcome::New(_)
    ));
    fx.f.clock.set(fx.witness.consent_at_ms() - 1);
    let old = OperationRecorder::new(&fx.f.window, &fx.f.profile, &mut ApprovalRows, "rewind")
        .lookup(&BusinessId::parse(fx.witness.nonce()).unwrap())
        .unwrap()
        .unwrap();
    assert!(
        matches!(old, LookupOutcome::Replay(view) if view.state == crate::policy_state::OperationState::Expired),
        "rewinding never revives an ended operation"
    );
}

#[test]
#[serial_test::serial(mainnet_clock)]
#[serial_test::serial]
fn revoked_consent_wins_over_stale_process_handle() {
    use crate::policy_state::operations::tests::{
        revoke_in_child_if_requested, revoke_in_other_process,
    };
    if revoke_in_child_if_requested() {
        return;
    }
    let fx = CanonicalFx::new(false, 900_000, str::to_owned);
    let id = record_facts(&fx.f, &fx.witness).record().id;
    let _keyring = revoke_in_other_process(
        &fx.f.window,
        &fx.f.profile,
        id,
        concat!(
            module_path!(),
            "::revoked_consent_wins_over_stale_process_handle"
        ),
    );
    assert_eq!(
        record_facts(&fx.f, &fx.witness).record().disposition,
        stellar_agent_core::approval::witness::ApprovalDisposition::Revoked
    );
    fx.f.clock.set(fx.handle.waiting_expires_at_ms() + 1);
    let before = fx.f.wire();
    let result = OperationRecorder::new(
        &fx.f.window,
        &fx.f.profile,
        &mut ApprovalRows,
        "stale-handle",
    )
    .begin_attempt(
        &fx.handle,
        &AttemptRequest {
            envelope: None,
            authorization: AttemptAuthorization::Linked,
            send_by_ms: u64::MAX,
        },
    );
    assert!(
        matches!(
            result,
            Err(
                crate::policy_state::WindowStoreError::AuthorizationRefused {
                    precondition: P::Expired
                }
            )
        ),
        "locked begin observes the other process's revocation: {result:?}"
    );
    assert_eq!(fx.f.wire(), before);
}

/// A candidate envelope whose amount differs from the stored canonical
/// intent refuses with `intent_divergence`, which renders
/// `simulation.divergence`, and writes nothing. An elapsed envelope
/// deadline, another precondition, keeps
/// `network.mainnet_authorization_refused`.
#[tokio::test]
#[serial_test::serial]
async fn canonical_divergence_renders_at_the_resolver_exit() {
    let fx = CanonicalFx::new(false, 900_000, str::to_owned);
    let server = fx.f.server().await;
    let context = fx.context(&server);
    let other = classic_intent(
        IntentBaseFacts {
            chain_id: fx.f.profile.chain_id.caip2_str(),
            source: fx.f.source.source(),
            policy_digest: fx.f.policy.digest(),
            signed_fee_cap: Some(500),
            profile_fee_cap: None,
            fee_choice: crate::fees::ClassicFeeChoice::ProfileDefault,
            memo: MemoFact::Text("approved".to_owned()),
        },
        IntentPayload::Pay {
            destination: fx.f.source.destination().to_owned(),
            asset: IntentAsset::Native,
            amount_stroops: 11,
        },
    )
    .unwrap();
    let diverged =
        intent_envelope(&other, context.network_passphrase(), 1, 100, fx.f.now / 1000 + 120)
            .unwrap();
    let elapsed = intent_envelope(
        &fx.intent,
        context.network_passphrase(),
        1,
        100,
        fx.f.now / 1000 - 10,
    )
    .unwrap();
    for (envelope, precondition, code) in [
        (
            &diverged,
            P::IntentDivergence,
            "simulation.divergence",
        ),
        (
            &elapsed,
            P::DeadlineElapsed,
            "network.mainnet_authorization_refused",
        ),
    ] {
        let before = fx.f.wire();
        let refused = fx
            .resolve_with(&context, envelope, fx.f.now, false, |_| ())
            .await
            .unwrap_err();
        assert!(
            matches!(refused, MainnetAuthorizationError::Refused(p) if p == precondition),
            "{refused:?}"
        );
        assert_eq!(
            stellar_agent_core::error::WalletError::from(refused).code(),
            code
        );
        assert_eq!(fx.f.wire(), before);
    }
}
