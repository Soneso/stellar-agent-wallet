//! The check a Soroban authorization-entry signing runs against a mainnet
//! intent authorization before any key access.
//!
//! The authorized SEP-43 signing path compares the preimage with the bound
//! intent here. The intent digest is recomputed from the preimage's invocation
//! under its network id. The invocation tree, root included, is bound; the nonce
//! and signature expiration ledger, which the requester picks, are excluded.

use stellar_agent_core::profile::caip2::{Caip2, MAINNET_PASSPHRASE, TESTNET_PASSPHRASE};
use stellar_agent_soroban_auth::{preimage_invocation, preimage_parts};
use stellar_xdr::HashIdPreimage;

use super::authorization::MainnetSorobanIntentAuthorization;
use super::digest::soroban_intent_digest;
use super::refusal::require;
use super::{MainnetAuthorizationError, MainnetConsumer, MainnetPrecondition as P};

/// Requires `preimage` to be the Soroban authorization preimage
/// `authorization` covers, for `consumer`, at `now_ms`.
///
/// `network_id` is the network id the caller expects, `SHA-256` of its
/// network passphrase. In order: the preimage must be envelope type 9 or 10
/// and carry `network_id`; the network must be mainnet and the bound chain;
/// `consumer` must be the bound consuming verb; the authorization must be
/// unexpired at `now_ms`; and the intent digest of the preimage's invocation
/// under `network_id` must be the bound one.
///
/// # Errors
///
/// [`MainnetAuthorizationError::Refused`] naming the broken precondition: a
/// preimage of another type is a binding mismatch, an invocation that does
/// not encode refuses as an intent digest mismatch, and a network id of
/// neither mainnet nor testnet is not mainnet.
pub fn check_preimage_against_authorization(
    authorization: &MainnetSorobanIntentAuthorization,
    consumer: MainnetConsumer,
    preimage: &HashIdPreimage,
    network_id: &[u8; 32],
    now_ms: u64,
) -> Result<(), MainnetAuthorizationError> {
    let (Some((_, preimage_network, _)), Some(invocation)) =
        (preimage_parts(preimage), preimage_invocation(preimage))
    else {
        return Err(MainnetAuthorizationError::Refused(P::BindingMismatch));
    };
    require(&preimage_network == network_id, P::ChainMismatch)?;
    authorization.check_chain(chain_of(network_id)?)?;
    authorization.check_consumer(consumer)?;
    authorization.check_not_expired(now_ms)?;
    let digest = soroban_intent_digest(network_id, invocation)
        .map_err(|_| MainnetAuthorizationError::Refused(P::IntentDigest))?;
    authorization.check_intent_digest(&digest)
}

/// The chain whose network id is `network_id`.
fn chain_of(network_id: &[u8; 32]) -> Result<Caip2, MainnetAuthorizationError> {
    use sha2::{Digest as _, Sha256};
    [MAINNET_PASSPHRASE, TESTNET_PASSPHRASE]
        .into_iter()
        .find(|passphrase| <[u8; 32]>::from(Sha256::digest(passphrase.as_bytes())) == *network_id)
        .and_then(Caip2::from_passphrase)
        .ok_or(MainnetAuthorizationError::Refused(P::ChainNotMainnet))
}

#[cfg(all(test, feature = "mainnet-write"))]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "unit tests; a failed setup is a failed test"
    )]

    use std::sync::{Arc, Mutex};

    use sha2::{Digest as _, Sha256};
    use stellar_agent_core::audit_log::AuditWriter;
    use stellar_agent_core::audit_log::writer::VerifiedTipFacts;
    use stellar_agent_soroban_auth::{AuthCredentialsVersion, build_auth_preimage};
    use stellar_xdr::{
        ContractId, ContractIdPreimage, ContractIdPreimageFromAddress, Hash,
        HashIdPreimageContractId, InvokeContractArgs, ScAddress, SorobanAuthorizedFunction,
        SorobanAuthorizedInvocation, Uint256, VecM,
    };
    use tempfile::TempDir;

    use super::*;
    use crate::mainnet::AuthorizationDomain;
    use crate::mainnet::authorization::SorobanIntentInner;
    use crate::mainnet::fixtures::{self, TTL_MS};
    use crate::policy_state::DomainBinding;

    const NOW: u64 = 1_800_000_000_000;

    fn network_id(passphrase: &str) -> [u8; 32] {
        Sha256::digest(passphrase.as_bytes()).into()
    }

    fn invocation(
        function: &str,
        sub_invocations: Vec<SorobanAuthorizedInvocation>,
    ) -> SorobanAuthorizedInvocation {
        SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
                contract_address: ScAddress::Contract(ContractId(Hash([0xc4; 32]))),
                function_name: function.try_into().unwrap(),
                args: VecM::default(),
            }),
            sub_invocations: sub_invocations.try_into().unwrap(),
        }
    }

    /// The invocation every authorization in this module is minted over.
    fn approved_invocation() -> SorobanAuthorizedInvocation {
        invocation("transfer", vec![invocation("approve", vec![])])
    }

    /// The address a type 10 preimage in this module is bound to.
    fn signer_address() -> ScAddress {
        ScAddress::Contract(ContractId(Hash([0x5a; 32])))
    }

    fn versioned_preimage(
        version: AuthCredentialsVersion,
        network: [u8; 32],
        nonce: i64,
        expiration_ledger: u32,
        invocation: SorobanAuthorizedInvocation,
    ) -> HashIdPreimage {
        build_auth_preimage(
            version,
            network,
            nonce,
            expiration_ledger,
            &signer_address(),
            invocation,
        )
    }

    /// A type 9 preimage.
    fn preimage(
        network: [u8; 32],
        nonce: i64,
        expiration_ledger: u32,
        invocation: SorobanAuthorizedInvocation,
    ) -> HashIdPreimage {
        versioned_preimage(
            AuthCredentialsVersion::V1,
            network,
            nonce,
            expiration_ledger,
            invocation,
        )
    }

    /// An intent authorization for `X402Create` over the approved invocation
    /// on mainnet, valid at [`NOW`].
    struct Case {
        _dir: TempDir,
        authorization: MainnetSorobanIntentAuthorization,
    }

    impl Case {
        fn new() -> Self {
            let dir = TempDir::new().unwrap();
            let writer = Arc::new(Mutex::new(
                AuditWriter::open(dir.path().join("audit.jsonl"), None).unwrap(),
            ));
            let facts = VerifiedTipFacts {
                segment_start_hash: [0; 32],
                entry_count: 0,
                tip_hash: [0; 32],
                log_path_sha256: [5; 32],
                anchor_covers_tip: true,
            };
            let mut header = fixtures::header("fixture", None, &writer, facts, NOW);
            header.domain = AuthorizationDomain::Soroban;
            header.consumer = MainnetConsumer::X402Create;
            let intent_digest =
                soroban_intent_digest(&network_id(MAINNET_PASSPHRASE), &approved_invocation())
                    .unwrap();
            let authorization =
                MainnetSorobanIntentAuthorization::for_crate_tests(SorobanIntentInner {
                    entries: vec![],
                    facts: super::super::digest::BindingFacts {
                        endpoint: None,
                        signer: [0; 32],
                        policy: [0; 32],
                        enablement: [0; 32],
                        witness: None,
                        reservation: None,
                        approval: [0; 32],
                        audit: [0; 32],
                    },
                    authorization_ttl_ms: TTL_MS,
                    header,
                    binding: DomainBinding::Soroban { intent_digest },
                });
            Self {
                _dir: dir,
                authorization,
            }
        }

        fn check(
            &self,
            consumer: MainnetConsumer,
            preimage: &HashIdPreimage,
            network: [u8; 32],
            now: u64,
        ) -> Result<(), MainnetAuthorizationError> {
            check_preimage_against_authorization(
                &self.authorization,
                consumer,
                preimage,
                &network,
                now,
            )
        }
    }

    fn refused(result: Result<(), MainnetAuthorizationError>) -> P {
        match result {
            Err(MainnetAuthorizationError::Refused(precondition)) => precondition,
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn the_approved_preimage_is_accepted() {
        let case = Case::new();
        let mainnet = network_id(MAINNET_PASSPHRASE);
        case.check(
            MainnetConsumer::X402Create,
            &preimage(mainnet, 7, 1_000, approved_invocation()),
            mainnet,
            NOW,
        )
        .expect("the approved invocation on mainnet is accepted");
    }

    /// A type 10 preimage, bound to its signer's address, over the approved
    /// invocation is accepted as well.
    #[test]
    fn the_approved_address_bound_preimage_is_accepted() {
        let case = Case::new();
        let mainnet = network_id(MAINNET_PASSPHRASE);
        case.check(
            MainnetConsumer::X402Create,
            &versioned_preimage(
                AuthCredentialsVersion::V2,
                mainnet,
                7,
                1_000,
                approved_invocation(),
            ),
            mainnet,
            NOW,
        )
        .expect("the approved invocation in a type 10 preimage is accepted");
    }

    /// The nonce and the signature expiration ledger are the requester's and
    /// are not part of the intent digest.
    #[test]
    fn the_nonce_and_expiration_ledger_are_excluded() {
        let case = Case::new();
        let mainnet = network_id(MAINNET_PASSPHRASE);
        for (nonce, expiration_ledger) in [(7, 1_000), (-91, 77_777)] {
            case.check(
                MainnetConsumer::X402Create,
                &preimage(mainnet, nonce, expiration_ledger, approved_invocation()),
                mainnet,
                NOW,
            )
            .expect("nonce and expiration ledger do not change the intent");
        }
    }

    #[test]
    fn another_root_invocation_is_refused() {
        let case = Case::new();
        let mainnet = network_id(MAINNET_PASSPHRASE);
        let changed = invocation("transfer_from", vec![invocation("approve", vec![])]);
        assert_eq!(
            refused(case.check(
                MainnetConsumer::X402Create,
                &preimage(mainnet, 7, 1_000, changed),
                mainnet,
                NOW,
            )),
            P::IntentDigest
        );
    }

    #[test]
    fn another_sub_invocation_is_refused() {
        let case = Case::new();
        let mainnet = network_id(MAINNET_PASSPHRASE);
        let changed = invocation("transfer", vec![invocation("burn", vec![])]);
        assert_eq!(
            refused(case.check(
                MainnetConsumer::X402Create,
                &preimage(mainnet, 7, 1_000, changed),
                mainnet,
                NOW,
            )),
            P::IntentDigest
        );
    }

    #[test]
    fn another_consumer_is_refused() {
        let case = Case::new();
        let mainnet = network_id(MAINNET_PASSPHRASE);
        assert_eq!(
            refused(case.check(
                MainnetConsumer::X402Authenticated,
                &preimage(mainnet, 7, 1_000, approved_invocation()),
                mainnet,
                NOW,
            )),
            P::ConsumerMismatch
        );
    }

    #[test]
    fn an_expired_authorization_is_refused() {
        let case = Case::new();
        let mainnet = network_id(MAINNET_PASSPHRASE);
        assert_eq!(
            refused(case.check(
                MainnetConsumer::X402Create,
                &preimage(mainnet, 7, 1_000, approved_invocation()),
                mainnet,
                NOW + TTL_MS,
            )),
            P::Expired
        );
    }

    /// A preimage carrying another network id than the expected one is
    /// refused even when both are known networks.
    #[test]
    fn a_preimage_of_another_network_is_refused() {
        let case = Case::new();
        assert_eq!(
            refused(case.check(
                MainnetConsumer::X402Create,
                &preimage(
                    network_id(TESTNET_PASSPHRASE),
                    7,
                    1_000,
                    approved_invocation()
                ),
                network_id(MAINNET_PASSPHRASE),
                NOW,
            )),
            P::ChainMismatch
        );
    }

    #[test]
    fn a_testnet_preimage_is_refused() {
        let case = Case::new();
        let testnet = network_id(TESTNET_PASSPHRASE);
        assert_eq!(
            refused(case.check(
                MainnetConsumer::X402Create,
                &preimage(testnet, 7, 1_000, approved_invocation()),
                testnet,
                NOW,
            )),
            P::ChainNotMainnet
        );
    }

    #[test]
    fn an_unknown_network_is_refused() {
        let case = Case::new();
        let unknown = network_id("Standalone Network ; February 2017");
        assert_eq!(
            refused(case.check(
                MainnetConsumer::X402Create,
                &preimage(unknown, 7, 1_000, approved_invocation()),
                unknown,
                NOW,
            )),
            P::ChainNotMainnet
        );
    }

    #[test]
    fn a_preimage_of_another_type_is_refused() {
        let case = Case::new();
        let mainnet = network_id(MAINNET_PASSPHRASE);
        let other = HashIdPreimage::ContractId(HashIdPreimageContractId {
            network_id: Hash(mainnet),
            contract_id_preimage: ContractIdPreimage::Address(ContractIdPreimageFromAddress {
                address: ScAddress::Contract(ContractId(Hash([0xc4; 32]))),
                salt: Uint256([0; 32]),
            }),
        });
        assert_eq!(
            refused(case.check(MainnetConsumer::X402Create, &other, mainnet, NOW)),
            P::BindingMismatch
        );
    }
}
