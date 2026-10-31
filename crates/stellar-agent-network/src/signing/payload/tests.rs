//! Payload domain, authorization, and trusted-signer binding tests.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "unit tests; a failed setup is a failed test"
)]

use stellar_agent_core::profile::caip2::TESTNET_PASSPHRASE;
use stellar_agent_soroban_auth::{AuthCredentialsVersion, build_auth_preimage};
use stellar_xdr::{
    ContractId, ContractIdPreimage, ContractIdPreimageFromAddress, FeeBumpTransaction,
    FeeBumpTransactionEnvelope, FeeBumpTransactionExt, FeeBumpTransactionInnerTx,
    HashIdPreimageContractId, InvokeContractArgs, Memo, MuxedAccount, Preconditions,
    SequenceNumber, SorobanAuthorizedFunction, SorobanAuthorizedInvocation, Transaction,
    TransactionExt, TransactionV0, TransactionV0Envelope, TransactionV0Ext, TransactionV1Envelope,
    VecM,
};

use super::*;
use crate::submit::bytes_to_hex;

/// The SEP-23 hash of [`kat_tx_envelope`] under the testnet passphrase,
/// a fixed vector of the `ENVELOPE_TYPE_TX` signature payload.
const KAT_TX: &str = "fc59ffb4787862170d118466cb791eb39d1b81991409a4c3e2ac3c34bdd1c97d";
/// The SEP-23 hash of [`kat_fee_bump_envelope`] under the testnet
/// passphrase, a fixed vector of the `ENVELOPE_TYPE_TX_FEE_BUMP` signature
/// payload.
const KAT_FEE_BUMP: &str = "89ac70849a33bb0e68b6bd431ee3cf8d08c6f8d3dcc54b6f505a604c7c52323c";

fn kat_inner() -> TransactionV1Envelope {
    TransactionV1Envelope {
        tx: Transaction {
            source_account: MuxedAccount::Ed25519(Uint256([0x11; 32])),
            fee: 100,
            seq_num: SequenceNumber(4242),
            cond: Preconditions::None,
            memo: Memo::None,
            operations: VecM::default(),
            ext: TransactionExt::V0,
        },
        signatures: VecM::default(),
    }
}

fn kat_tx_envelope() -> TransactionEnvelope {
    TransactionEnvelope::Tx(kat_inner())
}

fn kat_fee_bump() -> FeeBumpTransaction {
    FeeBumpTransaction {
        fee_source: MuxedAccount::Ed25519(Uint256([0x22; 32])),
        fee: 200,
        inner_tx: FeeBumpTransactionInnerTx::Tx(kat_inner()),
        ext: FeeBumpTransactionExt::V0,
    }
}

fn kat_fee_bump_envelope() -> TransactionEnvelope {
    TransactionEnvelope::TxFeeBump(FeeBumpTransactionEnvelope {
        tx: kat_fee_bump(),
        signatures: VecM::default(),
    })
}

fn tx_v0_envelope() -> TransactionEnvelope {
    TransactionEnvelope::TxV0(TransactionV0Envelope {
        tx: TransactionV0 {
            source_account_ed25519: Uint256([0; 32]),
            fee: 100,
            seq_num: SequenceNumber(1),
            time_bounds: None,
            memo: Memo::None,
            operations: VecM::default(),
            ext: TransactionV0Ext::V0,
        },
        signatures: VecM::default(),
    })
}

fn network_id(passphrase: &str) -> [u8; 32] {
    Sha256::digest(passphrase.as_bytes()).into()
}

fn invocation(function: &str) -> SorobanAuthorizedInvocation {
    SorobanAuthorizedInvocation {
        function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
            contract_address: ScAddress::Contract(ContractId(Hash([0xc4; 32]))),
            function_name: function.try_into().unwrap(),
            args: VecM::default(),
        }),
        sub_invocations: VecM::default(),
    }
}

fn soroban_preimage(
    version: AuthCredentialsVersion,
    passphrase: &str,
    address: &ScAddress,
) -> HashIdPreimage {
    build_auth_preimage(
        version,
        network_id(passphrase),
        7,
        1_000,
        address,
        invocation("transfer"),
    )
}

fn contract_id_preimage(passphrase: &str) -> HashIdPreimage {
    HashIdPreimage::ContractId(HashIdPreimageContractId {
        network_id: Hash(network_id(passphrase)),
        contract_id_preimage: ContractIdPreimage::Address(ContractIdPreimageFromAddress {
            address: ScAddress::Contract(ContractId(Hash([0xc4; 32]))),
            salt: Uint256([0; 32]),
        }),
    })
}

fn assert_mainnet_forbidden(error: &WalletError) {
    assert_eq!(error.code(), "network.mainnet_write_forbidden", "{error:?}");
}

fn assert_codec_failed(error: &WalletError) {
    assert_eq!(error.code(), "protocol.xdr_codec_failed", "{error:?}");
}

/// The transaction constructors refuse the mainnet passphrase, for every
/// envelope kind, and `for_envelope` refuses a legacy `TxV0` envelope.
#[test]
fn the_transaction_constructors_refuse_mainnet_and_tx_v0() {
    for envelope in [kat_tx_envelope(), kat_fee_bump_envelope(), tx_v0_envelope()] {
        assert_mainnet_forbidden(
            &TxSigningPayload::for_envelope(&envelope, MAINNET_PASSPHRASE).unwrap_err(),
        );
    }
    for tagged in [
        TransactionSignaturePayloadTaggedTransaction::Tx(kat_inner().tx),
        TransactionSignaturePayloadTaggedTransaction::TxFeeBump(kat_fee_bump()),
    ] {
        assert_mainnet_forbidden(
            &TxSigningPayload::for_tagged(&tagged, MAINNET_PASSPHRASE).unwrap_err(),
        );
    }
    assert_codec_failed(
        &TxSigningPayload::for_envelope(&tx_v0_envelope(), TESTNET_PASSPHRASE).unwrap_err(),
    );
}

/// The testnet payloads are the fixed SEP-23 hashes of a `Tx` and a fee
/// bump, through either constructor, so the typed payloads sign the bytes
/// every Stellar signer signs.
#[test]
fn the_transaction_payloads_match_the_sep23_vectors() {
    let tx = TxSigningPayload::for_envelope(&kat_tx_envelope(), TESTNET_PASSPHRASE).unwrap();
    assert_eq!(bytes_to_hex(tx.as_bytes()), KAT_TX);
    let fee_bump =
        TxSigningPayload::for_envelope(&kat_fee_bump_envelope(), TESTNET_PASSPHRASE).unwrap();
    assert_eq!(bytes_to_hex(fee_bump.as_bytes()), KAT_FEE_BUMP);
    assert_eq!(
        TxSigningPayload::for_tagged(
            &TransactionSignaturePayloadTaggedTransaction::Tx(kat_inner().tx),
            TESTNET_PASSPHRASE,
        )
        .unwrap(),
        tx
    );
    assert_eq!(
        TxSigningPayload::for_tagged(
            &TransactionSignaturePayloadTaggedTransaction::TxFeeBump(kat_fee_bump()),
            TESTNET_PASSPHRASE,
        )
        .unwrap(),
        fee_bump
    );
}

/// A Soroban payload is refused for a mainnet preimage of either type and
/// for a preimage of another type, and is `SHA-256` of the preimage's XDR
/// otherwise.
#[test]
fn the_soroban_payload_refuses_mainnet_and_hashes_the_preimage() {
    let address = ScAddress::Contract(ContractId(Hash([0x5a; 32])));
    for version in [AuthCredentialsVersion::V1, AuthCredentialsVersion::V2] {
        assert_mainnet_forbidden(
            &SorobanAuthPayload::from_preimage(&soroban_preimage(
                version,
                MAINNET_PASSPHRASE,
                &address,
            ))
            .unwrap_err(),
        );
        let preimage = soroban_preimage(version, TESTNET_PASSPHRASE, &address);
        let payload = SorobanAuthPayload::from_preimage(&preimage).unwrap();
        let expected: [u8; 32] = Sha256::digest(preimage.to_xdr(Limits::none()).unwrap()).into();
        assert_eq!(*payload.as_bytes(), expected, "{version:?}");
        assert_eq!(
            *payload.as_bytes(),
            stellar_agent_soroban_auth::auth_signature_payload(&preimage).unwrap(),
            "{version:?}"
        );
    }
    assert_codec_failed(
        &SorobanAuthPayload::from_preimage(&contract_id_preimage(TESTNET_PASSPHRASE)).unwrap_err(),
    );
}

/// A smart-account digest is refused for a mainnet preimage and for a
/// preimage of another type, and is `compute_auth_digest` over the
/// preimage's signature payload and the rule ids otherwise.
#[test]
fn the_smart_account_digest_refuses_mainnet_and_binds_the_rule_ids() {
    let address = ScAddress::Contract(ContractId(Hash([0x5a; 32])));
    let rule_ids_xdr = [0, 0, 0, 0x10, 0, 0, 0, 1, 0, 0, 0, 0];
    assert_mainnet_forbidden(
        &SmartAccountAuthDigest::new(
            &soroban_preimage(AuthCredentialsVersion::V1, MAINNET_PASSPHRASE, &address),
            &rule_ids_xdr,
        )
        .unwrap_err(),
    );
    assert_codec_failed(
        &SmartAccountAuthDigest::new(&contract_id_preimage(TESTNET_PASSPHRASE), &rule_ids_xdr)
            .unwrap_err(),
    );
    let preimage = soroban_preimage(AuthCredentialsVersion::V1, TESTNET_PASSPHRASE, &address);
    let signature_payload: [u8; 32] =
        Sha256::digest(preimage.to_xdr(Limits::none()).unwrap()).into();
    let mut bound = signature_payload.to_vec();
    bound.extend_from_slice(&rule_ids_xdr);
    let expected: [u8; 32] = Sha256::digest(&bound).into();
    assert_eq!(
        *SmartAccountAuthDigest::new(&preimage, &rule_ids_xdr)
            .unwrap()
            .as_bytes(),
        expected
    );
}

/// The message payload is the SEP-53 digest: the 24-byte prefix, and the
/// digest of "Hello, World!" computed independently of this crate.
#[test]
fn the_message_payload_is_the_sep53_digest() {
    assert_eq!(SEP53_MESSAGE_PREFIX, b"Stellar Signed Message:\n");
    assert_eq!(SEP53_MESSAGE_PREFIX.len(), 24);
    assert_eq!(
        bytes_to_hex(MessagePayload::sep53(b"Hello, World!").as_bytes()),
        "d52eb59c06bb510d065997ff93077068eed0a486c20215b5e02e1ab0d2ebea5f"
    );
}

#[cfg(feature = "mainnet-write")]
mod authorized {
    use std::sync::{Arc, Mutex};

    use serial_test::serial;
    use stellar_agent_core::audit_log::AuditWriter;
    use stellar_agent_core::audit_log::writer::VerifiedTipFacts;
    use stellar_xdr::ReadXdr as _;
    use tempfile::TempDir;

    use super::*;
    use crate::mainnet::authorization::MainnetSorobanIntentAuthorization;
    use crate::mainnet::clock::{set_clock_error_for_test, set_now_ms_for_test};
    use crate::mainnet::fixtures::{self, SIGNER_SEED, TTL_MS};
    use crate::policy_state::DomainBinding;
    use crate::signing::test_doubles::CountingSigner;
    use crate::submission_record::AuditWriterHandle;

    const NOW: u64 = 1_800_000_000_000;
    /// The nonce every Soroban authorization in this module binds.
    const NONCE: i64 = 7;
    /// The signature expiration ledger every Soroban authorization in
    /// this module binds.
    const EXPIRATION_LEDGER: u32 = 1_000;
    const OTHER_SEED: [u8; 32] = [0x3b; 32];

    struct Case {
        _dir: TempDir,
        writer: AuditWriterHandle,
    }

    impl Case {
        fn new() -> Self {
            let dir = TempDir::new().unwrap();
            let writer = Arc::new(Mutex::new(
                AuditWriter::open(dir.path().join("audit.jsonl"), None).unwrap(),
            ));
            Self { _dir: dir, writer }
        }

        /// A Soroban intent authorization over the `transfer` invocation
        /// under [`NONCE`] and [`EXPIRATION_LEDGER`], valid at [`NOW`].
        fn soroban(&self) -> MainnetSorobanIntentAuthorization {
            fixtures::soroban_authorization(
                &self.writer,
                &invocation("transfer"),
                NONCE,
                EXPIRATION_LEDGER,
                NOW,
            )
        }

        /// A transaction authorization over the fixture's unsigned
        /// mainnet envelope, after `edit`.
        fn transaction(
            &self,
            edit: impl FnOnce(&mut crate::mainnet::authorization::Header, &mut DomainBinding),
        ) -> MainnetTxSignAuthorization {
            let envelope = fixtures::unsigned_envelope();
            let facts = VerifiedTipFacts {
                segment_start_hash: [0; 32],
                entry_count: 0,
                tip_hash: [0; 32],
                log_path_sha256: [5; 32],
                anchor_covers_tip: true,
                entry_tags_in_force: true,
            };
            let mut header = fixtures::header("fixture", None, &self.writer, facts, NOW);
            let mut binding = fixtures::tx_binding(envelope.envelope_xdr(), envelope.tx_hash_hex());
            edit(&mut header, &mut binding);
            fixtures::tx_authorization(header, binding)
        }
    }

    fn agent() -> [u8; 32] {
        fixtures::public_key(SIGNER_SEED)
    }

    fn account_of(key: [u8; 32]) -> ScAddress {
        account_address(&key)
    }

    /// A mainnet Soroban preimage of `version`, bound to `address` when
    /// it is of type 10.
    fn mainnet_preimage(
        version: AuthCredentialsVersion,
        address: &ScAddress,
        nonce: i64,
        expiration_ledger: u32,
        function: &str,
    ) -> HashIdPreimage {
        build_auth_preimage(
            version,
            network_id(MAINNET_PASSPHRASE),
            nonce,
            expiration_ledger,
            address,
            invocation(function),
        )
    }

    /// The preimage the case's Soroban authorization covers.
    fn approved(version: AuthCredentialsVersion) -> HashIdPreimage {
        mainnet_preimage(
            version,
            &account_of(agent()),
            NONCE,
            EXPIRATION_LEDGER,
            "transfer",
        )
    }

    fn soroban_refusal(result: Result<MainnetSorobanAuthPayload, AuthorizedPayloadError>) -> P {
        match result {
            Err(AuthorizedPayloadError::Refused(MainnetAuthorizationError::Refused(p))) => p,
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    fn unsigned_mainnet_envelope() -> TransactionEnvelope {
        TransactionEnvelope::from_xdr_base64(
            fixtures::unsigned_envelope().envelope_xdr(),
            Limits::none(),
        )
        .unwrap()
    }

    /// The mainnet transaction payload is the transaction hash the
    /// authorization binds.
    #[test]
    fn the_mainnet_transaction_payload_is_the_bound_hash() {
        let case = Case::new();
        let payload = TxSigningPayload::authorized(
            &unsigned_mainnet_envelope(),
            &case.transaction(|_, _| {}),
        )
        .unwrap();
        assert_eq!(
            bytes_to_hex(payload.as_bytes()),
            fixtures::unsigned_envelope().tx_hash_hex()
        );
    }

    /// An authorization for another transaction hash builds no payload.
    #[test]
    fn another_transaction_hash_is_refused() {
        let case = Case::new();
        let authorization = case.transaction(|_, binding| {
            if let DomainBinding::Transaction { tx_hash, .. } = binding {
                *tx_hash = [0x99; 32];
            }
        });
        assert!(matches!(
            TxSigningPayload::authorized(&unsigned_mainnet_envelope(), &authorization),
            Err(AuthorizedPathError::Refused(P::TxHash))
        ));
    }

    /// An authorization bound to a chain other than mainnet builds no
    /// payload.
    #[test]
    fn a_non_mainnet_authorization_is_refused() {
        let case = Case::new();
        let authorization = case.transaction(|header, _| header.chain = Caip2::Testnet);
        assert!(matches!(
            TxSigningPayload::authorized(&unsigned_mainnet_envelope(), &authorization),
            Err(AuthorizedPathError::Refused(P::ChainNotMainnet))
        ));
    }

    /// A fee bump is a domain of its own and builds no transaction
    /// payload under a transaction authorization.
    #[test]
    fn a_fee_bump_is_refused_under_a_transaction_authorization() {
        let case = Case::new();
        assert!(matches!(
            TxSigningPayload::authorized(&kat_fee_bump_envelope(), &case.transaction(|_, _| {})),
            Err(AuthorizedPathError::Refused(P::BindingMismatch))
        ));
    }

    /// The approved preimage, of either type, yields a payload whose one
    /// signing call asks for the public key, then signs once, returns a
    /// signature over `SHA-256` of the preimage's XDR, and hands back the
    /// signed intent of the same authorization.
    #[tokio::test]
    #[serial]
    async fn the_approved_preimage_signs_once_and_yields_the_signed_intent() {
        let _clock = set_now_ms_for_test(NOW);
        let case = Case::new();
        for version in [AuthCredentialsVersion::V1, AuthCredentialsVersion::V2] {
            let authorization = case.soroban();
            let id = authorization.id();
            let preimage = approved(version);
            let payload = SorobanAuthPayload::authorized(
                &preimage,
                MainnetConsumer::X402Create,
                &agent(),
                authorization,
            )
            .unwrap();
            let signer = CountingSigner::new(SIGNER_SEED);
            let (signature, signed) = payload.sign(&signer).await.unwrap();

            assert_eq!(signer.public_key_calls(), 1, "{version:?}");
            assert_eq!(signer.sign_calls(), 1, "{version:?}");
            assert!(signed.id() == id, "{version:?}");
            let hash: [u8; 32] = Sha256::digest(preimage.to_xdr(Limits::none()).unwrap()).into();
            assert!(
                signature_verifies(&agent(), &hash, &signature),
                "{version:?}"
            );
        }
    }

    /// A preimage the authorization does not name builds no payload:
    /// another invocation, nonce, expiration ledger, network, consumer, or
    /// preimage type.
    #[test]
    #[serial]
    fn a_preimage_the_authorization_does_not_name_is_refused() {
        let _clock = set_now_ms_for_test(NOW);
        let case = Case::new();
        let agent_account = account_of(agent());
        let refuse = |preimage: HashIdPreimage, consumer| {
            soroban_refusal(SorobanAuthPayload::authorized(
                &preimage,
                consumer,
                &agent(),
                case.soroban(),
            ))
        };
        for version in [AuthCredentialsVersion::V1, AuthCredentialsVersion::V2] {
            assert_eq!(
                refuse(
                    mainnet_preimage(
                        version,
                        &agent_account,
                        NONCE,
                        EXPIRATION_LEDGER,
                        "transfer_from"
                    ),
                    MainnetConsumer::X402Create,
                ),
                P::IntentDigest
            );
            assert_eq!(
                refuse(
                    mainnet_preimage(
                        version,
                        &agent_account,
                        NONCE + 1,
                        EXPIRATION_LEDGER,
                        "transfer"
                    ),
                    MainnetConsumer::X402Create,
                ),
                P::EntryNonce
            );
            assert_eq!(
                refuse(
                    mainnet_preimage(
                        version,
                        &agent_account,
                        NONCE,
                        EXPIRATION_LEDGER + 1,
                        "transfer"
                    ),
                    MainnetConsumer::X402Create,
                ),
                P::EntryExpiration
            );
            assert_eq!(
                refuse(approved(version), MainnetConsumer::X402Authenticated),
                P::ConsumerMismatch
            );
            assert_eq!(
                refuse(
                    soroban_preimage(version, TESTNET_PASSPHRASE, &agent_account),
                    MainnetConsumer::X402Create,
                ),
                P::ChainNotMainnet
            );
        }
        assert_eq!(
            refuse(
                contract_id_preimage(MAINNET_PASSPHRASE),
                MainnetConsumer::X402Create
            ),
            P::BindingMismatch
        );
    }

    /// A type 10 preimage bound to another address than the
    /// authorization's signer is refused before the expected signer is
    /// compared, so a mismatch of both reports the address.
    #[test]
    #[serial]
    fn a_preimage_bound_to_another_address_is_refused_first() {
        let _clock = set_now_ms_for_test(NOW);
        let case = Case::new();
        let other = fixtures::public_key(OTHER_SEED);
        for expected_signer in [agent(), other] {
            assert_eq!(
                soroban_refusal(SorobanAuthPayload::authorized(
                    &mainnet_preimage(
                        AuthCredentialsVersion::V2,
                        &account_of(other),
                        NONCE,
                        EXPIRATION_LEDGER,
                        "transfer",
                    ),
                    MainnetConsumer::X402Create,
                    &expected_signer,
                    case.soroban(),
                )),
                P::PreimageAddress
            );
        }
    }

    /// An expected signer other than the authorization's builds no
    /// payload.
    #[test]
    #[serial]
    fn another_expected_signer_is_refused() {
        let _clock = set_now_ms_for_test(NOW);
        let case = Case::new();
        for version in [AuthCredentialsVersion::V1, AuthCredentialsVersion::V2] {
            assert_eq!(
                soroban_refusal(SorobanAuthPayload::authorized(
                    &approved(version),
                    MainnetConsumer::X402Create,
                    &fixtures::public_key(OTHER_SEED),
                    case.soroban(),
                )),
                P::SignerKeyMismatch,
                "{version:?}"
            );
        }
    }

    /// The constructor decides freshness on the mainnet clock: the same
    /// call is accepted at the issue time, refused before it and at the
    /// expiry, and fails when the clock cannot be read.
    #[test]
    #[serial]
    fn the_constructor_reads_the_mainnet_clock() {
        let case = Case::new();
        let build = || {
            SorobanAuthPayload::authorized(
                &approved(AuthCredentialsVersion::V1),
                MainnetConsumer::X402Create,
                &agent(),
                case.soroban(),
            )
        };
        let clock = set_now_ms_for_test(NOW);
        build().unwrap();
        clock.set(NOW - 1);
        assert_eq!(soroban_refusal(build()), P::NotYetValid);
        clock.set(NOW + TTL_MS);
        assert_eq!(soroban_refusal(build()), P::Expired);
        drop(clock);

        let _failing = set_clock_error_for_test();
        match build() {
            Err(AuthorizedPayloadError::Wallet(error)) => {
                assert_eq!(error.code(), "wallet.clock_error");
            }
            other => panic!("expected the clock error, got {other:?}"),
        }
    }

    /// The signing call refuses a signer whose key is not the
    /// authorization's after one public-key call and before any
    /// signature.
    #[tokio::test]
    #[serial]
    async fn the_signing_call_refuses_another_signer_key() {
        let _clock = set_now_ms_for_test(NOW);
        let case = Case::new();
        let payload = SorobanAuthPayload::authorized(
            &approved(AuthCredentialsVersion::V1),
            MainnetConsumer::X402Create,
            &agent(),
            case.soroban(),
        )
        .unwrap();
        let signer = CountingSigner::new(OTHER_SEED);
        match payload.sign(&signer).await {
            Err(AuthorizedPayloadError::Refused(MainnetAuthorizationError::Refused(
                P::SignerKeyMismatch,
            ))) => {}
            other => panic!("expected the signer key refusal, got {other:?}"),
        }
        assert_eq!(signer.public_key_calls(), 1);
        assert_eq!(signer.sign_calls(), 0);
    }

    struct ForwardingSigner {
        target: crate::signing::SoftwareSigningKey,
        signature: Mutex<Option<[u8; 64]>>,
    }

    #[async_trait::async_trait]
    impl Signer for ForwardingSigner {
        async fn public_key(&self) -> Result<stellar_strkey::ed25519::PublicKey, WalletError> {
            Ok(stellar_strkey::ed25519::PublicKey(agent()))
        }

        async fn sign_soroban_address_auth_payload(
            &self,
            payload: &SorobanAuthPayload,
        ) -> Result<[u8; 64], WalletError> {
            let signature = self
                .target
                .sign_soroban_address_auth_payload(payload)
                .await?;
            *self.signature.lock().unwrap() = Some(signature);
            Ok(signature)
        }

        async fn sign_tx_payload(
            &self,
            payload: &TxSigningPayload,
        ) -> Result<[u8; 64], WalletError> {
            let signature = self.target.sign_tx_payload(payload).await?;
            *self.signature.lock().unwrap() = Some(signature);
            Ok(signature)
        }

        async fn sign_auth_digest(
            &self,
            _: &SmartAccountAuthDigest,
        ) -> Result<[u8; 64], WalletError> {
            panic!("unexpected smart-account signing")
        }

        async fn sign_message(&self, _: &MessagePayload) -> Result<[u8; 64], WalletError> {
            panic!("unexpected message signing")
        }

        async fn sign_webauthn_assertion(
            &self,
            _: &SmartAccountAuthDigest,
            _: &[u8],
        ) -> Result<crate::signing::WebAuthnAssertion, WalletError> {
            panic!("unexpected WebAuthn signing")
        }
    }

    /// A transaction callback forwards only to the authorization's signer key.
    #[tokio::test]
    #[serial]
    async fn forwarding_a_mainnet_transaction_checks_the_software_key() {
        let _clock = set_now_ms_for_test(NOW);
        let case = Case::new();
        for seed in [OTHER_SEED, SIGNER_SEED] {
            let signer = ForwardingSigner {
                target: crate::signing::SoftwareSigningKey::new_from_bytes(seed),
                signature: Mutex::new(None),
            };
            let result = crate::signing::envelope_signing::authorized_signature(
                fixtures::unsigned_envelope().envelope_xdr(),
                &signer,
                MAINNET_PASSPHRASE,
                MainnetConsumer::CliPay,
                &case.transaction(|_, _| {}),
            )
            .await;
            if seed == OTHER_SEED {
                assert!(
                    matches!(result, Err(AuthorizedPathError::Wallet(ref error))
                    if error.code() == "network.mainnet_authorization_refused"),
                    "{result:?}"
                );
                assert!(signer.signature.lock().unwrap().is_none());
            } else {
                result.unwrap();
                let expected = crate::signing::SoftwareSigningKey::new_from_bytes(SIGNER_SEED)
                    .sign_raw(
                        &envelope_hash(&unsigned_mainnet_envelope(), MAINNET_PASSPHRASE).unwrap(),
                    );
                assert_eq!(*signer.signature.lock().unwrap(), Some(expected));
            }
        }
    }

    /// The trusted target checks the authorization's signer binding even
    /// when the callback reports the authorized key itself.
    #[tokio::test]
    #[serial]
    async fn forwarding_a_mainnet_payload_to_another_software_key_is_refused() {
        let _clock = set_now_ms_for_test(NOW);
        let case = Case::new();
        for version in [AuthCredentialsVersion::V1, AuthCredentialsVersion::V2] {
            let payload = SorobanAuthPayload::authorized(
                &approved(version),
                MainnetConsumer::X402Create,
                &agent(),
                case.soroban(),
            )
            .unwrap();
            let signer = ForwardingSigner {
                target: crate::signing::SoftwareSigningKey::new_from_bytes(OTHER_SEED),
                signature: Mutex::new(None),
            };
            match payload.sign(&signer).await {
                Err(AuthorizedPayloadError::Wallet(error)) => {
                    assert_eq!(error.code(), "network.mainnet_authorization_refused");
                }
                other => panic!("expected the trusted signer's key refusal, got {other:?}"),
            }
            assert!(signer.signature.lock().unwrap().is_none());
        }
    }

    /// Forwarding within the callback to the authorized key returns the
    /// same signature as the consuming wrapper.
    #[tokio::test]
    #[serial]
    async fn forwarding_a_mainnet_payload_to_the_same_software_key_matches() {
        let _clock = set_now_ms_for_test(NOW);
        let case = Case::new();
        for version in [AuthCredentialsVersion::V1, AuthCredentialsVersion::V2] {
            let preimage = approved(version);
            let payload = SorobanAuthPayload::authorized(
                &preimage,
                MainnetConsumer::X402Create,
                &agent(),
                case.soroban(),
            )
            .unwrap();
            let signer = ForwardingSigner {
                target: crate::signing::SoftwareSigningKey::new_from_bytes(SIGNER_SEED),
                signature: Mutex::new(None),
            };
            let (signature, _) = payload.sign(&signer).await.unwrap();
            let expected = crate::signing::SoftwareSigningKey::new_from_bytes(SIGNER_SEED)
                .sign_raw(&preimage_hash(&preimage).unwrap());
            assert_eq!(signature, expected);
            assert!(signature_verifies(
                &agent(),
                &preimage_hash(&preimage).unwrap(),
                &signature
            ));
        }
    }

    /// A payload held until expiry refuses before the signing callback.
    #[tokio::test]
    #[serial]
    async fn the_signing_call_rechecks_freshness_on_the_mainnet_clock() {
        let clock = set_now_ms_for_test(NOW);
        let case = Case::new();
        let payload = SorobanAuthPayload::authorized(
            &approved(AuthCredentialsVersion::V1),
            MainnetConsumer::X402Create,
            &agent(),
            case.soroban(),
        )
        .unwrap();
        clock.set(NOW + TTL_MS);
        let signer = CountingSigner::new(SIGNER_SEED);
        assert!(matches!(
            payload.sign(&signer).await,
            Err(AuthorizedPayloadError::Refused(
                MainnetAuthorizationError::Refused(P::Expired)
            ))
        ));
        assert_eq!(signer.public_key_calls(), 1);
        assert_eq!(signer.sign_calls(), 0);
    }

    /// A signature that does not verify under the authorization's signer
    /// is refused after the one signing call.
    #[tokio::test]
    #[serial]
    async fn a_signature_that_does_not_verify_is_refused() {
        let _clock = set_now_ms_for_test(NOW);
        let case = Case::new();
        let payload = SorobanAuthPayload::authorized(
            &approved(AuthCredentialsVersion::V1),
            MainnetConsumer::X402Create,
            &agent(),
            case.soroban(),
        )
        .unwrap();
        let signer = CountingSigner::corrupting(SIGNER_SEED);
        match payload.sign(&signer).await {
            Err(AuthorizedPayloadError::Refused(MainnetAuthorizationError::Refused(
                P::SignatureInvalid,
            ))) => {}
            other => panic!("expected the signature refusal, got {other:?}"),
        }
        assert_eq!(signer.sign_calls(), 1);
    }
}
