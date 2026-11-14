//! Admission capabilities consumed immediately before a signer call.

use crate::SaError;
use std::sync::{Mutex, OnceLock, PoisonError};
use stellar_agent_network::{
    AuthSubject, ExposedIntent, IntentProof, PermittedSigning, PlannedPayload, SignedIntentPlan,
    SignerDescriptor, SigningPayload,
};

/// How a signing request identifies its signer.
#[derive(Clone, Debug)]
pub enum SignerMatch {
    /// The request names the entire admitted descriptor.
    Exact(SignerDescriptor),
    /// A passkey ceremony names the hash of its encoded credential key data.
    ExternalKeyData([u8; 32]),
}

/// The credential, signer and payload about to reach a signer.
#[derive(Clone, Debug)]
pub struct SigningRequest<'a> {
    /// The canonical credential this signature authorizes.
    pub subject: AuthSubject,
    /// The signer identity to match against the plan.
    pub signer: SignerMatch,
    /// The exact signing payload.
    pub payload: SigningPayload<'a>,
}

struct Remaining {
    proof: Option<IntentProof>,
    signings: Vec<(PermittedSigning, usize)>,
}

/// Permits only the signings named by one durably admitted plan.
pub struct SigningGate {
    plan: SignedIntentPlan,
    remaining: Mutex<Remaining>,
    exposure: OnceLock<ExposedIntent>,
}

impl SigningGate {
    /// Builds the gate immediately after admission returns its proof.
    #[must_use]
    pub fn new(proof: IntentProof) -> Self {
        let plan = proof.plan().clone();
        let mut signings: Vec<(PermittedSigning, usize)> = Vec::new();
        for signing in plan.permitted_signings() {
            if let Some((_, count)) = signings.iter_mut().find(|(prior, _)| {
                prior.subject == signing.subject
                    && prior.signer == signing.signer
                    && prior.payload == signing.payload
            }) {
                *count += 1;
            } else {
                signings.push((signing.clone(), 1));
            }
        }
        Self {
            plan,
            remaining: Mutex::new(Remaining {
                proof: Some(proof),
                signings,
            }),
            exposure: OnceLock::new(),
        }
    }

    /// Consumes one permitted signing before the signer future is constructed.
    ///
    /// # Errors
    /// Refuses an unplanned credential, signer, payload, envelope or extra signing.
    #[allow(
        clippy::needless_pass_by_value,
        reason = "authorization consumes the signing request"
    )]
    pub fn authorize(&self, request: SigningRequest<'_>) -> Result<(), SaError> {
        if let SigningPayload::Envelope(envelope) = &request.payload {
            self.plan
                .check_envelope(envelope)
                .map_err(|field| SaError::IntentBindingMismatch { field })?;
        }
        let mut state = self
            .remaining
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if state.proof.is_none() && self.exposure.get().is_none() {
            return Err(SaError::IntentBindingMismatch {
                field: "intent_state",
            });
        }
        let index =
            state
                .signings
                .iter()
                .position(|(signing, count)| {
                    *count > 0
                        && signing.subject == request.subject
                        && match (&request.signer, &signing.signer) {
                            (SignerMatch::Exact(requested), permitted) => requested == permitted,
                            (
                                SignerMatch::ExternalKeyData(requested),
                                SignerDescriptor::External {
                                    key_data_sha256, ..
                                },
                            ) => requested == key_data_sha256,
                            _ => false,
                        }
                        && match (&request.payload, &signing.payload) {
                            (SigningPayload::AuthDigest(a), PlannedPayload::AuthDigest(b))
                            | (
                                SigningPayload::AddressPayload(a),
                                PlannedPayload::AddressPayload(b),
                            ) => a == b,
                            (SigningPayload::Envelope(_), PlannedPayload::Envelope) => true,
                            _ => false,
                        }
                })
                .ok_or(SaError::IntentBindingMismatch {
                    field: "signing_request",
                })?;
        if let Some(proof) = state.proof.take() {
            self.exposure
                .set(proof.expose())
                .map_err(|_| SaError::IntentBindingMismatch {
                    field: "intent_state",
                })?;
        }
        state.signings[index].1 -= 1;
        Ok(())
    }

    /// Returns the exposure after the first authorized signing request.
    #[must_use]
    pub fn exposure(&self) -> Option<&ExposedIntent> {
        self.exposure.get()
    }

    pub(crate) fn delegated_nonce(
        &self,
        address: &stellar_xdr::ScAddress,
        invocation: &stellar_xdr::SorobanAuthorizedInvocation,
    ) -> Result<i64, SaError> {
        use sha2::{Digest as _, Sha256};
        let subject = AuthSubject::account_key(address)
            .map_err(|field| SaError::IntentBindingMismatch { field })?;
        let state = self
            .remaining
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        for candidate in self.plan.subjects() {
            if candidate.auth_subject() != subject || candidate.root_invocation() != invocation {
                continue;
            }
            if let (Some(nonce), Some(signature_expiration_ledger)) =
                (candidate.nonce(), candidate.expiration())
            {
                let preimage = stellar_agent_soroban_auth::build_auth_preimage(
                    stellar_agent_soroban_auth::AuthCredentialsVersion::V1,
                    Sha256::digest(
                        self.plan
                            .chain_scope()
                            .chain()
                            .network_passphrase()
                            .as_bytes(),
                    )
                    .into(),
                    nonce,
                    signature_expiration_ledger,
                    address,
                    invocation.clone(),
                );
                let payload = stellar_agent_network::SorobanAuthPayload::from_preimage(&preimage)
                    .map_err(|_| SaError::IntentBindingMismatch {
                    field: "signing_request",
                })?;
                if state.signings.iter().any(|(signing, count)| {
                    *count > 0
                        && signing.subject == subject
                        && signing.payload == PlannedPayload::AddressPayload(*payload.as_bytes())
                }) {
                    return Ok(nonce);
                }
            }
        }
        Err(SaError::IntentBindingMismatch {
            field: "signing_request",
        })
    }

    pub(crate) fn take_unexposed(&self) -> Option<IntentProof> {
        self.remaining
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .proof
            .take()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, reason = "test assertions")]
    use super::*;
    use stellar_agent_core::profile::caip2::TESTNET_PASSPHRASE;
    use stellar_agent_network::IntentSubject;
    use stellar_xdr::*;

    fn root() -> SorobanAuthorizedInvocation {
        SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
                contract_address: ScAddress::Contract(ContractId(Hash([1; 32]))),
                function_name: ScSymbol::try_from("call").unwrap(),
                args: Default::default(),
            }),
            sub_invocations: Default::default(),
        }
    }

    fn plan(subjects: Vec<IntentSubject>) -> SignedIntentPlan {
        let expiration = subjects.iter().filter_map(IntentSubject::expiration).max();
        let source = stellar_strkey::ed25519::PublicKey([0; 32])
            .to_string()
            .as_str()
            .to_owned();
        SignedIntentPlan::new(
            TESTNET_PASSPHRASE,
            "fixture",
            &source,
            1,
            [7; 32],
            subjects,
            expiration,
        )
        .unwrap()
    }

    async fn gate(plan: SignedIntentPlan) -> SigningGate {
        let (_directory, admission) = super::super::intent_test_helpers::no_value_admission_owned();
        SigningGate::new(admission.admit(&plan).await.unwrap())
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn the_gate_refuses_what_the_plan_does_not_name() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        stellar_agent_test_support::keyring_mock::install().unwrap();
        super::super::intent_test_helpers::assert_envelope_bounds_refuse_before_signing().await;
        let address = ScAddress::Contract(ContractId(Hash([1; 32])));
        let other = ScAddress::Contract(ContractId(Hash([2; 32])));
        let descriptor = SignerDescriptor::Delegated { account: [3; 32] };
        let subject = IntentSubject::smart_account(
            &address,
            4,
            100,
            &root(),
            vec![1],
            vec![descriptor.clone()],
        )
        .unwrap();
        let plan = plan(vec![subject.clone()]);
        let PlannedPayload::AuthDigest(digest) = plan.permitted_signings()[0].payload else {
            panic!("auth digest required");
        };
        let request = |subject, digest| SigningRequest {
            subject,
            signer: SignerMatch::Exact(descriptor.clone()),
            payload: SigningPayload::AuthDigest(digest),
        };
        let gate = gate(plan).await;
        assert!(matches!(
            gate.authorize(request(AuthSubject::smart_account(&other).unwrap(), digest)),
            Err(SaError::IntentBindingMismatch {
                field: "signing_request"
            })
        ));
        assert!(gate.exposure().is_none());
        assert!(
            gate.authorize(request(subject.auth_subject(), [9; 32]))
                .is_err()
        );
        gate.authorize(request(subject.auth_subject(), digest))
            .unwrap();
        assert!(gate.exposure().is_some());
        assert!(gate.take_unexposed().is_none());
        assert!(matches!(
            gate.authorize(request(subject.auth_subject(), digest)),
            Err(SaError::IntentBindingMismatch {
                field: "signing_request"
            })
        ));
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn a_refused_request_keeps_the_proof_and_multiplicity_is_exact() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let address = ScAddress::Contract(ContractId(Hash([1; 32])));
        let descriptor = SignerDescriptor::External {
            verifier: stellar_strkey::Contract([4; 32])
                .to_string()
                .as_str()
                .into(),
            key_data_sha256: [5; 32],
        };
        let subject = IntentSubject::smart_account(
            &address,
            4,
            100,
            &root(),
            vec![1],
            vec![descriptor.clone()],
        )
        .unwrap();
        let planned = plan(vec![subject.clone(), subject.clone()]);
        let PlannedPayload::AuthDigest(digest) = planned.permitted_signings()[0].payload else {
            panic!("auth digest required");
        };
        let request = |key| SigningRequest {
            subject: subject.auth_subject(),
            signer: SignerMatch::ExternalKeyData(key),
            payload: SigningPayload::AuthDigest(digest),
        };
        let refused = gate(planned.clone()).await;
        assert!(refused.authorize(request([6; 32])).is_err());
        assert!(refused.take_unexposed().is_some());
        assert!(matches!(
            refused.authorize(request([5; 32])),
            Err(SaError::IntentBindingMismatch {
                field: "intent_state"
            })
        ));
        assert!(refused.exposure().is_none());
        let allowed = gate(planned).await;
        allowed.authorize(request([5; 32])).unwrap();
        allowed.authorize(request([5; 32])).unwrap();
        assert!(allowed.authorize(request([5; 32])).is_err());
    }
    #[tokio::test]
    #[serial_test::serial]
    async fn an_envelope_outside_the_plan_refuses_before_exposure() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        stellar_agent_test_support::keyring_mock::install().unwrap();
        for kind in [0, 1, 2] {
            let (plan, envelope) =
                stellar_agent_network::signed_intent::test_helpers::intent_fixture_kind(kind);
            for field in ["envelope_sequence", "host_invocation", "envelope_source"] {
                let mut changed = envelope.clone();
                let TransactionEnvelope::Tx(tx) = &mut changed else {
                    panic!("V1");
                };
                if field == "envelope_sequence" {
                    tx.tx.seq_num.0 += 1;
                } else {
                    let mut operations = tx.tx.operations.to_vec();
                    if field == "envelope_source" {
                        operations[0].source_account =
                            Some(MuxedAccount::Ed25519(Uint256([9; 32])));
                    } else {
                        let OperationBody::InvokeHostFunction(op) = &mut operations[0].body else {
                            panic!("invoke");
                        };
                        let HostFunction::InvokeContract(call) = &mut op.host_function else {
                            panic!("call");
                        };
                        call.function_name = ScSymbol::try_from("other").unwrap();
                    }
                    tx.tx.operations = operations.try_into().unwrap();
                }
                let source = stellar_strkey::ed25519::PublicKey([0; 32])
                    .to_string()
                    .to_string();
                let signing_gate = gate(plan.clone()).await;
                let error = signing_gate
                    .authorize(SigningRequest {
                        subject: AuthSubject::source(&source).unwrap(),
                        signer: SignerMatch::Exact(SignerDescriptor::AccountKey {
                            public_key: [0; 32],
                        }),
                        payload: SigningPayload::Envelope(&changed),
                    })
                    .unwrap_err();
                assert!(
                    matches!(error, SaError::IntentBindingMismatch { field: actual } if actual == field),
                    "{error:?}"
                );
                assert!(signing_gate.take_unexposed().is_some());
                assert!(signing_gate.exposure().is_none());
            }
        }
    }
    #[tokio::test]
    #[serial_test::serial]
    async fn bound_mismatch_refuses_at_gate_and_bind() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        stellar_agent_test_support::keyring_mock::install().unwrap();
        use stellar_agent_network::signing::test_doubles::CountingSigner;
        use stellar_agent_network::signing::{Signer, TxSigningPayload};
        let signer = CountingSigner::new([0; 32]);
        let (fixture, envelope) =
            stellar_agent_network::signed_intent::test_helpers::intent_fixture_kind(2);
        let plan = fixture.with_envelope_max_ledger(50).unwrap();
        let signing_gate = gate(plan).await;
        for maximum in [None, Some(0), Some(49), Some(51)] {
            let mut changed = envelope.clone();
            let TransactionEnvelope::Tx(tx) = &mut changed else {
                panic!("V1 envelope")
            };
            tx.tx.cond = Preconditions::V2(PreconditionsV2 {
                time_bounds: None,
                ledger_bounds: maximum.map(|max_ledger| LedgerBounds {
                    min_ledger: 0,
                    max_ledger,
                }),
                min_seq_num: None,
                min_seq_age: Duration(0),
                min_seq_ledger_gap: 0,
                extra_signers: VecM::default(),
            });
            let source = stellar_strkey::ed25519::PublicKey([0; 32])
                .to_string()
                .to_string();
            let result = signing_gate.authorize(SigningRequest {
                subject: AuthSubject::source(&source).unwrap(),
                signer: SignerMatch::Exact(SignerDescriptor::AccountKey {
                    public_key: [0; 32],
                }),
                payload: SigningPayload::Envelope(&changed),
            });
            if result.is_ok() {
                let _ = signer
                    .sign_tx_payload(
                        &TxSigningPayload::for_envelope(&changed, TESTNET_PASSPHRASE).unwrap(),
                    )
                    .await;
            }
            assert!(
                matches!(
                    result,
                    Err(SaError::IntentBindingMismatch {
                        field: "expiration"
                    })
                ),
                "{maximum:?}: {result:?}"
            );
            assert_eq!(signer.sign_calls(), 0);
            assert!(signing_gate.exposure().is_none());
        }
        assert!(signing_gate.take_unexposed().is_some());
    }
}
