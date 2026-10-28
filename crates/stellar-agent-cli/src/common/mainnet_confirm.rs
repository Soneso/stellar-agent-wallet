//! Typed-profile consent for one decoded mainnet transaction.

use super::consent::{ConsentSink, acquire_consent_sink};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use std::io::{BufRead, Write};
use stellar_agent_core::{
    approval::{
        AttestationBinding, ConsentAudit, PendingApproval, PendingApprovalStore,
        attest::{attest_mainnet_confirmation, record_error},
        error::ApprovalError,
        load_attestation_key, process_uid_for_attestation,
        store::MAINNET_CONFIRMATION_TTL_SECONDS,
        subject::approval_subject_classic,
        witness::{ApprovalExpectation, ApprovalWitness, ApprovedKind, verify_approval},
    },
    envelope_decode::decode_authoritative_args,
    error::{ApprovalFailure, ProtocolError, ValidationError, WalletError},
    policy::v1::value::{ValueClass, derive_value_class},
    profile::owner_key::OwnerKeyContext,
};
use stellar_agent_network::{
    MainnetWriteContext,
    mainnet::{MainnetConsumer, resolve::classic_consumer_tools},
};
use stellar_xdr::{ReadXdr as _, TransactionEnvelope};

pub(crate) enum ConfirmDecision {
    Allow,
    RequireApproval { ttl_ms: u64 },
}
impl ConfirmDecision {
    fn ttl_ms(self) -> u64 {
        match self {
            Self::Allow => MAINNET_CONFIRMATION_TTL_SECONDS * 1000,
            Self::RequireApproval { ttl_ms } => ttl_ms,
        }
    }
}

pub(crate) struct MainnetWriteSummary {
    envelope: String,
    consumer: MainnetConsumer,
    policy_tool: &'static str,
    kind: ApprovedKind,
    args: serde_json::Value,
    value: ValueClass,
    sequence: i64,
    fee: u32,
    fee_cap: u32,
    memo: String,
}

/// `approval.wrong_kind`: the consumer has no approval kind this
/// confirmation writes.
fn wrong_kind(detail: &str) -> WalletError {
    WalletError::Approval(ApprovalFailure::WrongKind {
        detail: detail.to_owned(),
    })
}
/// `protocol.xdr_codec_failed`: the envelope or a value decoded from it is
/// unusable, the code every CLI verb gives an undecodable envelope.
#[expect(
    clippy::needless_pass_by_value,
    reason = "Result::map_err supplies owned errors"
)]
fn envelope_error(detail: impl ToString) -> WalletError {
    WalletError::Protocol(ProtocolError::XdrCodecFailed {
        detail: detail.to_string(),
    })
}
/// `approval.attestation_invalid`: the attestation the confirmation just
/// persisted cannot be read back.
fn attestation_invalid(detail: &str) -> WalletError {
    WalletError::Approval(ApprovalFailure::AttestationInvalid {
        detail: detail.to_owned(),
    })
}
#[expect(
    clippy::needless_pass_by_value,
    reason = "Result::map_err supplies owned errors"
)]
fn store_error(error: ApprovalError) -> WalletError {
    record_error(&error)
}

impl MainnetWriteSummary {
    pub(crate) fn from_envelope(
        envelope_xdr: &str,
        consumer: MainnetConsumer,
        fee_cap: u32,
    ) -> Result<Self, WalletError> {
        let tools = match consumer {
            MainnetConsumer::CliPay
            | MainnetConsumer::CliCreateAccount
            | MainnetConsumer::CliTrustline
            | MainnetConsumer::CliClaim => classic_consumer_tools(consumer),
            _ => None,
        }
        .ok_or_else(|| wrong_kind("mainnet confirmation requires a classic CLI consumer"))?;
        let args =
            decode_authoritative_args(envelope_xdr, tools.decoder_tool).map_err(envelope_error)?;
        let TransactionEnvelope::Tx(tx) = TransactionEnvelope::from_xdr_base64(
            envelope_xdr,
            stellar_agent_xdr_limits::untrusted_decode_limits(envelope_xdr.len()),
        )
        .map_err(envelope_error)?
        else {
            return Err(envelope_error(
                "mainnet confirmation requires a version 1 transaction envelope",
            ));
        };
        let policy_tool = tools.policy_tool;
        let value = derive_value_class(policy_tool, &args);
        let classic_kind = match tools.approved_kind {
            ApprovedKind::Payment => {
                stellar_agent_core::envelope_decode::ClassicTransactionKind::Payment
            }
            ApprovedKind::Trustline => {
                stellar_agent_core::envelope_decode::ClassicTransactionKind::Trustline
            }
            ApprovedKind::Claim => {
                stellar_agent_core::envelope_decode::ClassicTransactionKind::Claim
            }
            _ => {
                return Err(wrong_kind(
                    "mainnet confirmation requires a classic CLI consumer",
                ));
            }
        };
        let memo = stellar_agent_core::envelope_decode::classic_summary(envelope_xdr, classic_kind)
            .map_err(envelope_error)?
            .memo
            .display();
        Ok(Self {
            envelope: envelope_xdr.to_owned(),
            consumer,
            policy_tool,
            kind: tools.approved_kind,
            args,
            value,
            sequence: tx.tx.seq_num.0,
            fee: tx.tx.fee,
            fee_cap,
            memo,
        })
    }

    fn render(
        &self,
        context: &MainnetWriteContext,
        output: &mut impl Write,
    ) -> std::io::Result<()> {
        let esc = super::render::escape_for_terminal;
        writeln!(
            output,
            "Profile: {}\nChain: {}\nEndpoint: {}\nSigner: {}",
            esc(context.profile_name()),
            esc(context.chain().caip2_str()),
            esc(context.authority()),
            esc(self.args["source"].as_str().unwrap_or(""))
        )?;
        if let ValueClass::Value(effects) = &self.value {
            let unknown = if self.kind == ApprovedKind::Claim {
                "not known to the wallet before the claim"
            } else {
                "not applicable"
            };
            for leg in effects.legs() {
                writeln!(
                    output,
                    "Action: {:?}\nAsset: {}\nAmount: {}\nDestination: {}",
                    leg.kind,
                    leg.asset
                        .as_deref()
                        .map_or_else(|| unknown.to_owned(), super::render::escape_for_terminal),
                    leg.amount
                        .map_or_else(|| unknown.to_owned(), |amount| amount.to_string()),
                    esc(leg.destination.as_deref().unwrap_or(""))
                )?;
            }
        }
        if self.kind == ApprovedKind::Claim {
            writeln!(
                output,
                "Balance ID: {}",
                esc(&self.string("balance_id_strkey"))
            )?;
        }
        writeln!(output, "Memo: {}", esc(&self.memo))?;
        writeln!(
            output,
            "Fee: {} stroops\nFee cap: {} stroops per operation\nType the profile name to confirm:",
            self.fee, self.fee_cap
        )
    }
    fn string(&self, key: &str) -> String {
        self.args[key].as_str().unwrap_or("").to_owned()
    }
    fn amount(&self, key: &str) -> Result<i64, WalletError> {
        self.string(key).parse().map_err(envelope_error)
    }
    fn pending(&self, uid: String, ttl: u64) -> Result<PendingApproval, WalletError> {
        let text = self.envelope.clone();
        let bytes = self.envelope.as_bytes();
        match self.consumer {
            MainnetConsumer::CliPay | MainnetConsumer::CliCreateAccount => {
                PendingApproval::new_payment_pending(
                    text,
                    bytes,
                    self.string("destination"),
                    self.amount(if self.consumer == MainnetConsumer::CliPay {
                        "amount_stroops"
                    } else {
                        "starting_balance_stroops"
                    })?,
                    if self.consumer == MainnetConsumer::CliPay {
                        self.string("asset")
                    } else {
                        "XLM".into()
                    },
                    self.args["memo"].as_str().map(str::to_owned),
                    self.fee,
                    self.sequence,
                    uid,
                    ttl,
                )
            }
            MainnetConsumer::CliTrustline => PendingApproval::new_trustline_pending(
                text,
                bytes,
                self.string("source"),
                self.string("asset_code"),
                self.string("asset_issuer"),
                Some(self.amount("limit_stroops")?),
                self.fee,
                self.sequence,
                uid,
                ttl,
            ),
            MainnetConsumer::CliClaim => PendingApproval::new_claim_pending_unvalued(
                text,
                bytes,
                self.string("balance_id_hex72"),
                self.string("balance_id_strkey"),
                self.string("source"),
                self.fee,
                self.sequence,
                uid,
                ttl,
            ),
            _ => return Err(wrong_kind("unsupported confirmation consumer")),
        }
        .map_err(store_error)
    }
}

fn read_name(input: &mut impl BufRead, expected: &str) -> Result<(), WalletError> {
    let mut line = String::new();
    if input
        .read_line(&mut line)
        .map_err(|_| WalletError::from(ValidationError::ConfirmInputUnavailable))?
        == 0
    {
        return Err(ValidationError::ConfirmInputUnavailable.into());
    }
    let line = line.strip_suffix('\n').unwrap_or(&line);
    let line = line.strip_suffix('\r').unwrap_or(line);
    if line != expected {
        return Err(ValidationError::ConfirmProfileNameMismatch.into());
    }
    Ok(())
}

/// Shows the operator the summary of the mainnet write on stderr, reads the
/// profile name from stdin, and persists the attested confirmation.
///
/// # Errors
///
/// `confirm.tty_required` without a terminal on stdin and stderr,
/// `confirm.input_unavailable` when the summary cannot be written or the
/// name cannot be read, `confirm.profile_name_mismatch` for another name, and
/// the summary's, the attestation's and the store's refusals.
pub(crate) fn confirm_mainnet_write(
    summary: &MainnetWriteSummary,
    decision: ConfirmDecision,
    context: &MainnetWriteContext,
    pending: &mut PendingApprovalStore,
) -> Result<ApprovalWitness, WalletError> {
    confirm_on_terminal(summary, decision, context, pending)
}

fn confirm_with_io(
    summary: &MainnetWriteSummary,
    decision: ConfirmDecision,
    context: &MainnetWriteContext,
    pending: &mut PendingApprovalStore,
    input: &mut impl BufRead,
    output: &mut impl Write,
) -> Result<ApprovalWitness, WalletError> {
    super::tty::require_tty_for_mainnet()?;
    summary
        .render(context, output)
        .and_then(|()| output.flush())
        .map_err(|_| WalletError::from(ValidationError::ConfirmInputUnavailable))?;
    read_name(input, context.profile_name())?;
    persist_confirmation(summary, decision, context, pending)
}

fn persist_confirmation(
    summary: &MainnetWriteSummary,
    decision: ConfirmDecision,
    context: &MainnetWriteContext,
    pending: &mut PendingApprovalStore,
) -> Result<ApprovalWitness, WalletError> {
    let profile = context.profile();
    let uid = process_uid_for_attestation().map_err(store_error)?;
    let entry = summary.pending(uid, decision.ttl_ms())?;
    let key = load_attestation_key(
        &profile.attestation_key_id,
        &OwnerKeyContext::for_profile(context.profile_name(), profile),
    )?;
    let sink = acquire_consent_sink(profile, context.profile_name())?;
    pending
        .insert(entry.clone(), entry.created_at_unix_ms)
        .map_err(store_error)?;
    let binding = AttestationBinding::new(context.profile_name(), context.chain().caip2_str());
    match sink {
        ConsentSink::Writer(writer) => {
            let mut guard = writer.lock().map_err(|_| {
                WalletError::from(ValidationError::AuditWriterOpenFailed {
                    profile: context.profile_name().to_owned(),
                })
            })?;
            attest_mainnet_confirmation(
                pending,
                &entry,
                &key,
                &binding,
                ConsentAudit::Writer(&mut guard),
                summary.policy_tool,
            )?;
        }
        ConsentSink::Outbox(outbox) => attest_mainnet_confirmation(
            pending,
            &entry,
            &key,
            &binding,
            ConsentAudit::Outbox(&outbox),
            summary.policy_tool,
        )?,
    }
    let attestation = persisted_attestation(pending, &entry.approval_nonce)?;
    let now = stellar_agent_core::timefmt::now_unix_ms().map_err(|error| {
        WalletError::Approval(ApprovalFailure::ClockError {
            detail: error.to_string(),
        })
    })?;
    verify_approval(
        pending,
        profile,
        context.profile_name(),
        &entry.approval_nonce,
        &attestation,
        &ApprovalExpectation {
            kind: summary.kind,
            subject: approval_subject_classic(&summary.envelope),
        },
        now,
    )
}

/// The attestation persisted for `nonce`, refused with
/// `approval.attestation_invalid` when it is absent, not base64url, or not
/// 32 bytes.
fn persisted_attestation(
    pending: &PendingApprovalStore,
    nonce: &str,
) -> Result<[u8; 32], WalletError> {
    let encoded = pending
        .get(nonce)
        .and_then(|entry| entry.attestation_blob_b64.as_deref())
        .ok_or_else(|| attestation_invalid("the persisted attestation is missing"))?;
    URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| attestation_invalid("the persisted attestation is not base64url"))?
        .try_into()
        .map_err(|_| attestation_invalid("the persisted attestation has the wrong length"))
}

/// Runs the confirmation on the process's stdin and stderr.
#[cfg(not(test))]
fn confirm_on_terminal(
    summary: &MainnetWriteSummary,
    decision: ConfirmDecision,
    context: &MainnetWriteContext,
    pending: &mut PendingApprovalStore,
) -> Result<ApprovalWitness, WalletError> {
    confirm_with_io(
        summary,
        decision,
        context,
        pending,
        &mut std::io::stdin().lock(),
        &mut std::io::stderr().lock(),
    )
}

/// The input a test answers the confirmation with: called with the rendered
/// prompt while the input is pending, it returns the typed line, `None` for
/// end of input, or a read error.
#[cfg(test)]
pub(crate) type ConfirmationInput = Box<dyn FnMut(&str) -> std::io::Result<Option<String>>>;

#[cfg(test)]
thread_local! {
    /// The confirmation input a test set on this thread.
    static CONFIRMATION_INPUT: std::cell::RefCell<Option<ConfirmationInput>> =
        const { std::cell::RefCell::new(None) };
}

/// Clears the confirmation input of this thread when dropped.
#[cfg(all(test, feature = "mainnet-write"))]
pub(crate) struct ConfirmationInputGuard(());

#[cfg(all(test, feature = "mainnet-write"))]
impl Drop for ConfirmationInputGuard {
    fn drop(&mut self) {
        CONFIRMATION_INPUT.with(|slot| slot.borrow_mut().take());
    }
}

/// Answers every confirmation on this thread through `input` until the guard
/// drops.
#[cfg(all(test, feature = "mainnet-write"))]
pub(crate) fn set_confirmation_input(input: ConfirmationInput) -> ConfirmationInputGuard {
    CONFIRMATION_INPUT.with(|slot| *slot.borrow_mut() = Some(input));
    ConfirmationInputGuard(())
}

/// Runs the confirmation through the test's input when one is set, and on
/// stdin and stderr otherwise.
///
/// The prompt the confirmation writes is captured, and the input is asked for
/// the line when the confirmation first reads, so the callback sees exactly
/// what the operator would see before typing.
#[cfg(test)]
fn confirm_on_terminal(
    summary: &MainnetWriteSummary,
    decision: ConfirmDecision,
    context: &MainnetWriteContext,
    pending: &mut PendingApprovalStore,
) -> Result<ApprovalWitness, WalletError> {
    use std::cell::RefCell;
    use std::rc::Rc;

    struct Prompt(Rc<RefCell<Vec<u8>>>);
    impl Write for Prompt {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.borrow_mut().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    struct Answer {
        prompt: Rc<RefCell<Vec<u8>>>,
        input: ConfirmationInput,
        line: Option<std::io::Cursor<Vec<u8>>>,
    }
    impl std::io::Read for Answer {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let available = self.fill_buf()?;
            let n = available.len().min(buf.len());
            buf[..n].copy_from_slice(&available[..n]);
            self.consume(n);
            Ok(n)
        }
    }
    impl BufRead for Answer {
        fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
            if self.line.is_none() {
                let prompt = String::from_utf8_lossy(&self.prompt.borrow()).into_owned();
                let bytes = match (self.input)(&prompt)? {
                    Some(line) => format!("{line}\n").into_bytes(),
                    None => Vec::new(),
                };
                self.line = Some(std::io::Cursor::new(bytes));
            }
            self.line.as_mut().map_or(Ok(&[][..]), BufRead::fill_buf)
        }
        fn consume(&mut self, amount: usize) {
            if let Some(line) = self.line.as_mut() {
                line.consume(amount);
            }
        }
    }

    let Some(input) = CONFIRMATION_INPUT.with(|slot| slot.borrow_mut().take()) else {
        return confirm_with_io(
            summary,
            decision,
            context,
            pending,
            &mut std::io::stdin().lock(),
            &mut std::io::stderr().lock(),
        );
    };
    let prompt = Rc::new(RefCell::new(Vec::new()));
    let mut answer = Answer {
        prompt: Rc::clone(&prompt),
        input,
        line: None,
    };
    let result = confirm_with_io(
        summary,
        decision,
        context,
        pending,
        &mut answer,
        &mut Prompt(prompt),
    );
    CONFIRMATION_INPUT.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.is_none() {
            *slot = Some(answer.input);
        }
    });
    result
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, reason = "test assertions")]
    use super::*;
    #[test]
    fn confirm_refuses_wrong_name() {
        assert_eq!(
            read_name(&mut &b"other\n"[..], "selected")
                .unwrap_err()
                .code(),
            "confirm.profile_name_mismatch"
        );
    }
    #[test]
    fn confirm_refuses_end_of_input() {
        assert_eq!(
            read_name(&mut &b""[..], "selected").unwrap_err().code(),
            "confirm.input_unavailable"
        );
    }
    #[test]
    fn confirm_refuses_read_error() {
        struct Broken;
        impl std::io::Read for Broken {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("unavailable"))
            }
        }
        impl BufRead for Broken {
            fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
                Err(std::io::Error::other("unavailable"))
            }
            fn consume(&mut self, _: usize) {}
        }
        assert_eq!(
            read_name(&mut Broken, "selected").unwrap_err().code(),
            "confirm.input_unavailable"
        );
    }
    #[test]
    fn confirm_ttl_follows_decision() {
        assert_eq!(ConfirmDecision::Allow.ttl_ms(), 600_000);
        assert_eq!(
            ConfirmDecision::RequireApproval { ttl_ms: 17_000 }.ttl_ms(),
            17_000
        );
    }
    #[test]
    #[serial_test::serial]
    fn summary_renders_envelope_legs() {
        use stellar_agent_test_support::SignedTestEnvelope;
        use stellar_xdr::{Hash, Limits, Memo, WriteXdr as _};
        #[cfg(feature = "mainnet-write")]
        let (_dir, context, _) = confirmation_fixture("confirm-memos");
        let built = SignedTestEnvelope::builder([8; 32])
            .unsigned()
            .amount_stroops(17)
            .build();
        for (memo, rendered) in [
            (Memo::None, "none".to_owned()),
            (
                Memo::Text(b"order".to_vec().try_into().unwrap()),
                "text \"order\"".into(),
            ),
            (
                Memo::Text("café\u{202e}".as_bytes().to_vec().try_into().unwrap()),
                "text \"café\u{202e}\"".into(),
            ),
            (Memo::Id(7), "id 7".into()),
            (
                Memo::Hash(Hash([1; 32])),
                format!("hash {}", "01".repeat(32)),
            ),
            (
                Memo::Return(Hash([2; 32])),
                format!("return {}", "02".repeat(32)),
            ),
        ] {
            let TransactionEnvelope::Tx(mut tx) =
                TransactionEnvelope::from_xdr_base64(built.envelope_xdr(), Limits::none()).unwrap()
            else {
                unreachable!()
            };
            tx.tx.memo = memo;
            let summary = MainnetWriteSummary::from_envelope(
                &TransactionEnvelope::Tx(tx)
                    .to_xdr_base64(Limits::none())
                    .unwrap(),
                MainnetConsumer::CliPay,
                500,
            )
            .unwrap();
            assert_eq!(summary.memo, rendered);
            #[cfg(feature = "mainnet-write")]
            {
                let mut output = Vec::new();
                summary.render(&context, &mut output).unwrap();
                assert!(String::from_utf8(output).unwrap().contains(&format!(
                    "Memo: {}",
                    crate::common::render::escape_for_terminal(&rendered)
                )));
            }
            assert_eq!(summary.fee_cap, 500);
            let ValueClass::Value(value) = &summary.value else {
                panic!("value legs missing")
            };
            assert_eq!(value.legs()[0].amount, Some(17));
            assert_eq!(
                value.legs()[0].destination.as_deref(),
                Some(built.destination())
            );
            let pending = summary.pending("1000".into(), 600_000).unwrap();
            assert_eq!(
                pending.expires_at_unix_ms - pending.created_at_unix_ms,
                600_000
            );
        }
    }

    #[test]
    #[cfg(feature = "mainnet-write")]
    #[serial_test::serial]
    fn summary_renders_every_classic_consumer() {
        use stellar_xdr::*;
        let (_dir, context, envelope) = confirmation_fixture("confirm-summary");
        let TransactionEnvelope::Tx(original) =
            TransactionEnvelope::from_xdr_base64(&envelope, Limits::none()).unwrap()
        else {
            unreachable!()
        };
        let OperationBody::Payment(payment) = &original.tx.operations[0].body else {
            unreachable!()
        };
        let destination = match &payment.destination {
            MuxedAccount::Ed25519(key) => AccountId(PublicKey::PublicKeyTypeEd25519(key.clone())),
            _ => unreachable!(),
        };
        let issuer = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([7; 32])));
        let credit = AlphaNum4 {
            asset_code: AssetCode4(*b"USD\0"),
            issuer,
        };
        let cases = [
            (
                MainnetConsumer::CliPay,
                OperationBody::PathPaymentStrictReceive(PathPaymentStrictReceiveOp {
                    send_asset: Asset::Native,
                    send_max: 23,
                    destination: payment.destination.clone(),
                    dest_asset: Asset::CreditAlphanum4(credit.clone()),
                    dest_amount: 19,
                    path: vec![].try_into().unwrap(),
                }),
                vec![
                    "Action: Payment",
                    "Amount: 23",
                    "Action: PathPaymentReceive",
                    "Amount: 19",
                ],
            ),
            (
                MainnetConsumer::CliCreateAccount,
                OperationBody::CreateAccount(CreateAccountOp {
                    destination,
                    starting_balance: 29,
                }),
                vec!["Action: AccountCreation", "Amount: 29", "Asset: native"],
            ),
            (
                MainnetConsumer::CliTrustline,
                OperationBody::ChangeTrust(ChangeTrustOp {
                    line: ChangeTrustAsset::CreditAlphanum4(credit),
                    limit: 31,
                }),
                vec!["Action: Trustline", "Asset: USD:"],
            ),
            (
                MainnetConsumer::CliClaim,
                OperationBody::ClaimClaimableBalance(ClaimClaimableBalanceOp {
                    balance_id: ClaimableBalanceId::ClaimableBalanceIdTypeV0(Hash([4; 32])),
                }),
                vec![
                    "Action: Claim",
                    "not known to the wallet before the claim",
                    "Balance ID: B",
                ],
            ),
        ];
        for (consumer, body, expected) in cases {
            let mut tx = original.clone();
            tx.tx.operations = vec![Operation {
                source_account: None,
                body,
            }]
            .try_into()
            .unwrap();
            let encoded = TransactionEnvelope::Tx(tx)
                .to_xdr_base64(Limits::none())
                .unwrap();
            let summary = MainnetWriteSummary::from_envelope(&encoded, consumer, 500).unwrap();
            let mut output = Vec::new();
            summary.render(&context, &mut output).unwrap();
            let output = String::from_utf8(output).unwrap();
            for expected in expected {
                assert!(output.contains(expected), "{output}");
            }
            for decision in [
                ConfirmDecision::Allow,
                ConfirmDecision::RequireApproval { ttl_ms: 300_000 },
            ] {
                let ttl = decision.ttl_ms();
                let entry = summary.pending("1000".into(), ttl).unwrap();
                assert_eq!(entry.expires_at_unix_ms - entry.created_at_unix_ms, ttl);
            }
            assert!(output.contains(context.profile_name()));
            assert!(output.contains(context.authority()));
            assert!(output.contains("stellar:mainnet"));
            assert!(output.contains(&summary.string("source")));
            assert!(output.contains("Fee: 100 stroops"));
        }
    }

    /// A trustline envelope with `asset_code` and a text memo of `memo`
    /// bytes, built from the confirmation fixture's envelope.
    #[cfg(feature = "mainnet-write")]
    fn trustline_envelope(envelope: &str, asset_code: [u8; 4], memo: &[u8]) -> String {
        use stellar_xdr::*;
        let TransactionEnvelope::Tx(mut tx) =
            TransactionEnvelope::from_xdr_base64(envelope, Limits::none()).unwrap()
        else {
            unreachable!()
        };
        tx.tx.memo = Memo::Text(memo.to_vec().try_into().unwrap());
        tx.tx.operations = vec![Operation {
            source_account: None,
            body: OperationBody::ChangeTrust(ChangeTrustOp {
                line: ChangeTrustAsset::CreditAlphanum4(AlphaNum4 {
                    asset_code: AssetCode4(asset_code),
                    issuer: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([7; 32]))),
                }),
                limit: 31,
            }),
        }]
        .try_into()
        .unwrap();
        TransactionEnvelope::Tx(tx)
            .to_xdr_base64(Limits::none())
            .unwrap()
    }

    /// An asset code holding control bytes cannot be shown faithfully, so the
    /// confirmation refuses the envelope before it renders anything, and the
    /// refusal carries none of the raw bytes.
    #[test]
    #[cfg(feature = "mainnet-write")]
    #[serial_test::serial]
    fn summary_refuses_an_asset_code_it_cannot_show() {
        let (_dir, _context, envelope) = confirmation_fixture("confirm-asset");
        let encoded = trustline_envelope(&envelope, [b'U', 0x1b, b'[', 0x07], b"order");
        let Err(error) =
            MainnetWriteSummary::from_envelope(&encoded, MainnetConsumer::CliTrustline, 500)
        else {
            panic!("an asset code with control bytes must be refused");
        };
        assert_eq!(error.code(), "protocol.xdr_codec_failed");
        let message = error.message();
        assert!(message.contains("asset code"), "{message}");
        assert!(!message.contains('\u{1b}'), "{message:?}");
        assert!(!message.contains('\u{7}'), "{message:?}");
    }

    /// A value that decodes is rendered with every control character as a
    /// visible escape: the memo's cursor and bell bytes reach the terminal
    /// only as `\u{1b}` and `\u{7}`.
    #[test]
    #[cfg(feature = "mainnet-write")]
    #[serial_test::serial]
    fn summary_escapes_control_characters_it_shows() {
        let (_dir, context, envelope) = confirmation_fixture("confirm-memo-escape");
        let encoded = trustline_envelope(&envelope, *b"USD\0", b"U\x1b[2K\x07");
        let summary =
            MainnetWriteSummary::from_envelope(&encoded, MainnetConsumer::CliTrustline, 500)
                .unwrap();
        let mut output = Vec::new();
        summary.render(&context, &mut output).unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(
            output.contains("Memo: text \"U\\u{1b}[2K\\u{7}\""),
            "{output}"
        );
        assert!(!output.contains('\u{1b}'), "{output:?}");
        assert!(!output.contains('\u{7}'), "{output:?}");
    }

    #[cfg(feature = "mainnet-write")]
    fn confirmation_fixture(name: &str) -> (tempfile::TempDir, MainnetWriteContext, String) {
        confirmation_fixture_with(name, |_| {})
    }
    /// A stored mainnet profile, edited by `edit` before it is saved, and the
    /// write context built from it.
    #[cfg(feature = "mainnet-write")]
    fn confirmation_fixture_with(
        name: &str,
        edit: impl FnOnce(&mut stellar_agent_core::profile::schema::Profile),
    ) -> (tempfile::TempDir, MainnetWriteContext, String) {
        use stellar_agent_core::profile::{loader, name::ResolvedProfileName, schema::Profile};
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let dir = tempfile::tempdir().unwrap();
        // The served source account is at sequence 1, so its next
        // transaction carries sequence 2.
        let envelope = stellar_agent_test_support::SignedTestEnvelope::builder([8; 32])
            .unsigned()
            .sequence(2)
            .amount_stroops(17)
            .build();
        let mut profile = Profile::builder_mainnet_named(
            name,
            "https://rpc.example.invalid",
            &format!("stellar-agent-signer-{name}"),
            envelope.source(),
            &format!("stellar-agent-nonce-{name}"),
            "default",
        )
        .build();
        profile.audit_log_path = dir.path().join("audit.jsonl");
        edit(&mut profile);
        for entry in [
            &profile.attestation_key_id,
            &profile.audit_log_hash_chain_key_id,
        ] {
            stellar_agent_network::keyring::rotate_keyring_secret_32(
                &entry.service,
                &entry.account,
            )
            .unwrap();
        }
        loader::save_to_dir(name, &profile, &dir.path().join("profiles")).unwrap();
        let context = stellar_agent_network::NetworkContext::mainnet_write(
            &profile,
            &ResolvedProfileName::from_flag(name),
            &dir.path().join("profiles"),
            stellar_agent_network::MainnetEndpointFlags::default(),
        )
        .unwrap();
        (dir, context, envelope.envelope_xdr().to_owned())
    }
    #[cfg(feature = "mainnet-write")]
    #[test]
    #[serial_test::serial]
    fn confirm_accepts() {
        let (dir, context, envelope) = confirmation_fixture("confirm-accepts");
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(dir.path());
        let _tty = super::super::tty::tests::test_tty(true, true);
        let summary =
            MainnetWriteSummary::from_envelope(&envelope, MainnetConsumer::CliPay, 500).unwrap();
        let mut pending = PendingApprovalStore::open(dir.path().join("pending.toml")).unwrap();
        let witness = confirm_with_io(
            &summary,
            ConfirmDecision::Allow,
            &context,
            &mut pending,
            &mut format!("{}\n", context.profile_name()).as_bytes(),
            &mut Vec::new(),
        )
        .unwrap();
        assert_eq!(witness.subject(), approval_subject_classic(&envelope));
        assert_eq!(witness.expires_at_ms() - witness.created_at_ms(), 600_000);
        assert_eq!(pending.len(), 1);
        let entry = pending.get(witness.nonce()).unwrap();
        assert!(entry.attestation_blob_b64.is_some());
        let rows: Vec<serde_json::Value> =
            std::fs::read_to_string(&context.profile().audit_log_path)
                .unwrap()
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .filter(|row: &serde_json::Value| row["kind"] == "approval_attested")
                .collect();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["origin"], "cli-mainnet-confirm");
        assert_eq!(rows[0]["gated_tool"], "stellar_pay");
    }
    #[cfg(feature = "mainnet-write")]
    #[test]
    #[serial_test::serial]
    fn confirm_accepts_claim_with_unknown_value() {
        use stellar_xdr::{
            ClaimClaimableBalanceOp, ClaimableBalanceId, Hash, Limits, Operation, OperationBody,
            WriteXdr as _,
        };
        let (dir, context, envelope) = confirmation_fixture("confirm-claim");
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(dir.path());
        let _tty = super::super::tty::tests::test_tty(true, true);
        let TransactionEnvelope::Tx(mut tx) =
            TransactionEnvelope::from_xdr_base64(&envelope, Limits::none()).unwrap()
        else {
            unreachable!()
        };
        tx.tx.operations = vec![Operation {
            source_account: None,
            body: OperationBody::ClaimClaimableBalance(ClaimClaimableBalanceOp {
                balance_id: ClaimableBalanceId::ClaimableBalanceIdTypeV0(Hash([3; 32])),
            }),
        }]
        .try_into()
        .unwrap();
        let envelope = TransactionEnvelope::Tx(tx)
            .to_xdr_base64(Limits::none())
            .unwrap();
        let summary =
            MainnetWriteSummary::from_envelope(&envelope, MainnetConsumer::CliClaim, 500).unwrap();
        let mut pending = PendingApprovalStore::open(dir.path().join("pending.toml")).unwrap();
        let mut output = Vec::new();
        let witness = confirm_with_io(
            &summary,
            ConfirmDecision::Allow,
            &context,
            &mut pending,
            &mut format!("{}\n", context.profile_name()).as_bytes(),
            &mut output,
        )
        .unwrap();
        assert_eq!(witness.kind(), ApprovedKind::Claim);
        let stellar_agent_core::approval::ApprovalKind::ClaimSimulated {
            summary_asset,
            summary_amount_stroops,
            summary_balance_id_hex72: balance_id_hex72,
            summary_source: source,
            summary_simulated_fee_stroops: simulated_fee_stroops,
            summary_simulated_seq_num: simulated_seq_num,
            ..
        } = &pending.get(witness.nonce()).unwrap().kind
        else {
            panic!("claim required")
        };
        assert_eq!(summary_asset, &None);
        assert_eq!(summary_amount_stroops, &None);
        assert_eq!(balance_id_hex72, &format!("00000000{}", "03".repeat(32)));
        assert_eq!(source, &summary.string("source"));
        assert_eq!(*simulated_fee_stroops, summary.fee);
        assert_eq!(*simulated_seq_num, summary.sequence);
        let rendered = String::from_utf8(output).unwrap();
        assert_eq!(
            rendered
                .matches("not known to the wallet before the claim")
                .count(),
            2
        );
        let audit = std::fs::read_to_string(&context.profile().audit_log_path).unwrap();
        assert!(audit.contains("stellar_claim"));
        assert!(audit.contains("cli-mainnet-confirm"));
    }
    #[cfg(all(feature = "mainnet-write", feature = "test-helpers"))]
    #[test]
    #[serial_test::serial]
    fn failed_consent_leaves_no_attestation() {
        let (dir, context, envelope) = confirmation_fixture("confirm-failure");
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(dir.path());
        let _tty = super::super::tty::tests::test_tty(true, true);
        let _server =
            stellar_agent_core::audit_log::writer::AuditWriterRegistry::get_or_open_keyed(
                "confirm-server",
                &context.profile().audit_log_path,
                stellar_agent_network::keyring::keyed_audit_access(
                    context.profile(),
                    context.profile_name(),
                    stellar_agent_core::audit_log::BindingCheck::Enforce,
                )
                .unwrap(),
            )
            .unwrap();
        let outbox =
            stellar_agent_core::audit_log::AuditOutbox::for_log(&context.profile().audit_log_path);
        stellar_agent_core::audit_log::outbox::test_seam::arm_partial_write(outbox.path(), 5);
        let summary =
            MainnetWriteSummary::from_envelope(&envelope, MainnetConsumer::CliPay, 500).unwrap();
        let mut pending = PendingApprovalStore::open(dir.path().join("pending.toml")).unwrap();
        let result = confirm_with_io(
            &summary,
            ConfirmDecision::Allow,
            &context,
            &mut pending,
            &mut format!("{}\n", context.profile_name()).as_bytes(),
            &mut Vec::new(),
        );
        stellar_agent_core::audit_log::outbox::test_seam::disarm(outbox.path());
        assert_eq!(result.unwrap_err().code(), "audit.chain_key_unavailable");
        let text = std::fs::read_to_string(dir.path().join("pending.toml")).unwrap();
        assert!(!text.contains("attestation_blob_b64"));
    }
    #[cfg(feature = "mainnet-write")]
    #[tokio::test]
    #[serial_test::serial]
    async fn confirmed_claim_witness_resolves() {
        use sha2::Digest as _;
        use stellar_agent_core::cross_check::{CrossCheckValue, ThresholdSet};
        use stellar_agent_core::{
            mainnet::enablement::verify_enablement,
            policy::v1::{
                canonical,
                criteria::state_store::PolicyStateStore,
                signature,
                verified::{OwnerKeySource, PinMode, PolicyLoad, load_verified_policy},
            },
            profile::{
                name::ProfileNameSource, schema::signer_identity_entry_ref,
                signer_identity::SignerIdentityRecord,
            },
        };
        use stellar_agent_network::{
            cross_check::{
                AccountObservation, ClaimWitnessInputs, ClaimableBalanceObservation,
                CrossCheckOutcome, obtain_classic_witness_bound,
            },
            keyring,
            mainnet::{
                audit_readiness::audit_readiness,
                resolve::{TxSignRequest, resolve_tx_sign},
            },
            policy_state::PersistedWindowStore,
        };
        use stellar_agent_test_support::{
            EchoIdResponder, SignedTestEnvelope, signed_envelope::get_network_result,
        };
        use stellar_xdr::*;
        let (dir, context, encoded) =
            confirmation_fixture_with("confirm-claim-resolve", |profile| {
                use stellar_agent_core::profile::schema::{PrimaryProviderRecord, ProviderRecord};
                let providers = profile.providers.get_or_insert_with(Default::default);
                providers.primary =
                    Some(PrimaryProviderRecord::new("primary", "rpc.example.invalid"));
                providers.oracle = Some(ProviderRecord::new(
                    "oracle",
                    "oracle.example.invalid",
                    true,
                ));
                profile.oracle_provider_url =
                    Some("https://oracle.example.invalid".parse().unwrap());
            });
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(dir.path());
        let _tty = super::super::tty::tests::test_tty(true, true);
        let TransactionEnvelope::Tx(mut tx) =
            TransactionEnvelope::from_xdr_base64(&encoded, Limits::none()).unwrap()
        else {
            unreachable!()
        };
        tx.tx.operations = vec![Operation {
            source_account: None,
            body: OperationBody::ClaimClaimableBalance(ClaimClaimableBalanceOp {
                balance_id: ClaimableBalanceId::ClaimableBalanceIdTypeV0(Hash([3; 32])),
            }),
        }]
        .try_into()
        .unwrap();
        let encoded = TransactionEnvelope::Tx(tx)
            .to_xdr_base64(Limits::none())
            .unwrap();
        let summary =
            MainnetWriteSummary::from_envelope(&encoded, MainnetConsumer::CliClaim, 500).unwrap();
        let mut pending = PendingApprovalStore::open(dir.path().join("pending.toml")).unwrap();
        let approval = confirm_with_io(
            &summary,
            ConfirmDecision::Allow,
            &context,
            &mut pending,
            &mut format!("{}\n", context.profile_name()).as_bytes(),
            &mut Vec::new(),
        )
        .unwrap();
        drop(pending);
        let profile = context.profile();
        let name = context.profile_name();
        let owner = ed25519_dalek::SigningKey::from_bytes(&[11; 32]);
        keyring_core::Entry::new(
            &profile.policy_owner_key_id.service,
            &profile.policy_owner_key_id.account,
        )
        .unwrap()
        .set_password(
            &stellar_strkey::ed25519::PublicKey(owner.verifying_key().to_bytes()).to_string(),
        )
        .unwrap();
        keyring::rotate_keyring_secret_32(
            &profile.policy_window_state_key_id.service,
            &profile.policy_window_state_key_id.account,
        )
        .unwrap();
        let public = ed25519_dalek::SigningKey::from_bytes(&[8; 32])
            .verifying_key()
            .to_bytes();
        let identity = signer_identity_entry_ref(&profile.mcp_signer_default);
        keyring_core::Entry::new(&identity.service, &identity.account)
            .unwrap()
            .set_password(&SignerIdentityRecord::agent(public).render())
            .unwrap();
        let source = SignedTestEnvelope::builder([8; 32]).unsigned().build();
        let nonce = "installation-nonce";
        let nonce_digest = stellar_agent_core::hex::encode(&sha2::Sha256::digest(nonce.as_bytes()));
        let raw = include_str!("../../../stellar-agent-core/tests/fixtures/policy-v2.toml")
            .replace("operator", name)
            .replace("stellar_pay", "stellar_claim")
            .replace(
                "    { kind = \"asset_allowlist\", assets = [\"native\"] },\n",
                "",
            )
            .replace(&"0".repeat(64), &nonce_digest)
            .replace("decision = \"require_approval\"", "decision = \"allow\"")
            .replace("ttl_secs = 3600", "")
            .replace("reason = \"review\"", "");
        let signed = signature::sign(
            &signature::digest(&canonical::canonical_bytes(&raw).unwrap()),
            &owner,
        );
        let path = dir.path().join("policy.toml");
        std::fs::write(
            &path,
            format!(
                "{raw}\n[signature]\nowner_id = \"{}\"\nsig = \"{}\"\n",
                stellar_strkey::ed25519::PublicKey(owner.verifying_key().to_bytes()),
                stellar_agent_core::hex::encode(&signed)
            ),
        )
        .unwrap();
        let window_path = dir.path().join("state.window");
        let policy = load_verified_policy(
            &PolicyLoad {
                path: &path,
                profile,
                profile_name: name,
                owner_pubkey: &owner.verifying_key().to_bytes(),
                owner_source: OwnerKeySource::Keyring,
                window_path: &window_path,
            },
            PolicyStateStore::new(),
            PinMode::Advance,
        )
        .unwrap();
        let enablement = verify_enablement(
            &policy,
            name,
            ProfileNameSource::Flag,
            profile,
            &dir.path().join("profiles"),
            &|_| Ok(nonce.to_owned()),
        )
        .unwrap();
        let signer = keyring::enrolled_signer(
            name,
            &dir.path().join("profiles"),
            profile,
            keyring::EnrolledRole::Agent,
            &public,
        )
        .unwrap();
        let mut servers = Vec::new();
        for _ in 0..2 {
            let server = wiremock::MockServer::start().await;
            for (method, response) in [
                (
                    "getNetwork",
                    get_network_result(context.network_passphrase()),
                ),
                ("getLedgerEntries", source.ledger_entries_result()),
            ] {
                wiremock::Mock::given(wiremock::matchers::body_partial_json(
                    serde_json::json!({"method": method}),
                ))
                .respond_with(EchoIdResponder::new(response))
                .mount(&server)
                .await;
            }
            servers.push(server);
        }
        let (primary, oracle) = (&servers[0], &servers[1]);
        let context = context.with_test_transport_routes(&[
            ("rpc.example.invalid", &primary.uri()),
            ("oracle.example.invalid", &oracle.uri()),
        ]);
        let client = context.primary_client().unwrap();
        let view = stellar_agent_network::account::fetch_account(&client, source.source(), &[])
            .await
            .unwrap();
        let outcome = obtain_classic_witness_bound(
            context.profile(),
            &context.network_context(),
            CrossCheckValue::Unvalued,
            ClaimWitnessInputs {
                source: AccountObservation::from_view(&view).unwrap(),
                trustline: None,
                balance: Some(ClaimableBalanceObservation {
                    balance_id: [3; 32],
                    entry: None,
                }),
            },
            &encoded,
            &ThresholdSet::from_profile_and_signed(
                context.profile(),
                policy.mainnet().unwrap().cross_check_thresholds.as_ref(),
            ),
            "stellar_claim",
        )
        .await
        .unwrap();
        let CrossCheckOutcome::Passed(witness) = outcome else {
            panic!("a bound claim witness is required on mainnet")
        };
        assert_eq!(witness.authority(), "https://oracle.example.invalid");
        assert!(!oracle.received_requests().await.unwrap().is_empty());
        let store = PersistedWindowStore::at_path(window_path);
        let request = |witness| TxSignRequest {
            context: &context,
            consumer: MainnetConsumer::CliClaim,
            unsigned_envelope_xdr: &encoded,
            client: &client,
            probe_deadline: std::time::Duration::from_secs(2),
            witness,
            signer: &signer,
            policy: &policy,
            enablement: &enablement,
            approval: &approval,
            audit: audit_readiness(context.profile(), context.profile_name()).unwrap(),
            store: &store,
        };
        assert_eq!(
            resolve_tx_sign(request(None))
                .await
                .map(|_| ())
                .unwrap_err(),
            stellar_agent_network::mainnet::MainnetAuthorizationError::Refused(
                stellar_agent_network::mainnet::MainnetPrecondition::WitnessRequired
            )
        );
        let auth = resolve_tx_sign(request(Some(&witness))).await.unwrap();
        auth.check_consumer(MainnetConsumer::CliClaim).unwrap();
        assert_eq!(
            store
                .open_authorizations(
                    context.profile(),
                    stellar_agent_core::timefmt::now_unix_ms().unwrap()
                )
                .unwrap()
                .len(),
            1
        );
    }

    /// The `approval_attested` rows of the profile's audit log.
    #[cfg(feature = "mainnet-write")]
    fn consent_rows(context: &MainnetWriteContext) -> usize {
        std::fs::read_to_string(&context.profile().audit_log_path)
            .unwrap_or_default()
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .filter(|row| row["kind"] == "approval_attested")
            .count()
    }

    /// Drives the confirmation with `streams` as the terminal state of
    /// stdin and stderr and `typed` as the operator's line, and returns the
    /// refusal code after asserting that nothing was recorded.
    #[cfg(feature = "mainnet-write")]
    fn refused_confirmation(name: &str, streams: (bool, bool), typed: &str) -> String {
        let (dir, context, envelope) = confirmation_fixture(name);
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(dir.path());
        let _tty = super::super::tty::tests::test_tty(streams.0, streams.1);
        let summary =
            MainnetWriteSummary::from_envelope(&envelope, MainnetConsumer::CliPay, 500).unwrap();
        let mut pending = PendingApprovalStore::open(dir.path().join("pending.toml")).unwrap();
        let mut output = Vec::new();
        let code = confirm_with_io(
            &summary,
            ConfirmDecision::Allow,
            &context,
            &mut pending,
            &mut typed.as_bytes(),
            &mut output,
        )
        .unwrap_err()
        .code()
        .to_owned();
        assert_eq!(pending.len(), 0);
        assert_eq!(consent_rows(&context), 0);
        let stored = std::fs::read_to_string(dir.path().join("pending.toml")).unwrap_or_default();
        assert!(!stored.contains("attestation_blob_b64"), "{stored}");
        code
    }

    #[cfg(feature = "mainnet-write")]
    #[test]
    #[serial_test::serial]
    fn confirm_refuses_a_stream_that_is_not_a_terminal() {
        for (index, streams) in [(false, true), (true, false)].into_iter().enumerate() {
            assert_eq!(
                refused_confirmation(
                    &format!("confirm-tty-{index}"),
                    streams,
                    &format!("confirm-tty-{index}\n"),
                ),
                "confirm.tty_required",
                "{streams:?}"
            );
        }
    }

    #[cfg(feature = "mainnet-write")]
    #[test]
    #[serial_test::serial]
    fn confirm_refuses_a_wrong_profile_name() {
        assert_eq!(
            refused_confirmation("confirm-name", (true, true), "confirm-other\n"),
            "confirm.profile_name_mismatch"
        );
    }

    #[cfg(feature = "mainnet-write")]
    #[test]
    #[serial_test::serial]
    fn confirm_without_the_attestation_key_records_nothing() {
        let (dir, context, envelope) = confirmation_fixture("confirm-no-key");
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(dir.path());
        let _tty = super::super::tty::tests::test_tty(true, true);
        let key = &context.profile().attestation_key_id;
        keyring_core::Entry::new(&key.service, &key.account)
            .unwrap()
            .delete_credential()
            .unwrap();
        let summary =
            MainnetWriteSummary::from_envelope(&envelope, MainnetConsumer::CliPay, 500).unwrap();
        let mut pending = PendingApprovalStore::open(dir.path().join("pending.toml")).unwrap();
        confirm_with_io(
            &summary,
            ConfirmDecision::Allow,
            &context,
            &mut pending,
            &mut format!("{}\n", context.profile_name()).as_bytes(),
            &mut Vec::new(),
        )
        .unwrap_err();
        assert_eq!(pending.len(), 0);
        assert_eq!(consent_rows(&context), 0);
    }

    #[cfg(feature = "mainnet-write")]
    #[test]
    #[serial_test::serial]
    fn confirm_without_a_consent_sink_records_nothing() {
        let (dir, context, envelope) = confirmation_fixture("confirm-no-sink");
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(dir.path());
        let _tty = super::super::tty::tests::test_tty(true, true);
        let chain_key = &context.profile().audit_log_hash_chain_key_id;
        keyring_core::Entry::new(&chain_key.service, &chain_key.account)
            .unwrap()
            .delete_credential()
            .unwrap();
        let summary =
            MainnetWriteSummary::from_envelope(&envelope, MainnetConsumer::CliPay, 500).unwrap();
        let mut pending = PendingApprovalStore::open(dir.path().join("pending.toml")).unwrap();
        let error = confirm_with_io(
            &summary,
            ConfirmDecision::Allow,
            &context,
            &mut pending,
            &mut format!("{}\n", context.profile_name()).as_bytes(),
            &mut Vec::new(),
        )
        .unwrap_err();
        assert_eq!(error.code(), "audit.chain_key_unavailable");
        assert_eq!(pending.len(), 0);
        assert_eq!(consent_rows(&context), 0);
        let stored = std::fs::read_to_string(dir.path().join("pending.toml")).unwrap_or_default();
        assert!(!stored.contains("attestation_blob_b64"), "{stored}");
    }

    #[test]
    fn summary_refusals_carry_their_codes() {
        use stellar_agent_test_support::SignedTestEnvelope;
        use stellar_xdr::{
            Limits, TransactionV0, TransactionV0Envelope, TransactionV0Ext, Uint256, WriteXdr as _,
        };
        let built = SignedTestEnvelope::builder([8; 32])
            .unsigned()
            .amount_stroops(17)
            .build();
        let code = |envelope: &str, consumer| {
            MainnetWriteSummary::from_envelope(envelope, consumer, 500)
                .err()
                .unwrap()
                .code()
                .to_owned()
        };
        for consumer in [
            MainnetConsumer::McpPay,
            MainnetConsumer::McpClaim,
            MainnetConsumer::X402Create,
        ] {
            assert_eq!(
                code(built.envelope_xdr(), consumer),
                "approval.wrong_kind",
                "{consumer:?}"
            );
        }
        assert_eq!(
            code("AAAA", MainnetConsumer::CliPay),
            "protocol.xdr_codec_failed"
        );
        let TransactionEnvelope::Tx(tx) =
            TransactionEnvelope::from_xdr_base64(built.envelope_xdr(), Limits::none()).unwrap()
        else {
            unreachable!()
        };
        let stellar_xdr::MuxedAccount::Ed25519(source) = tx.tx.source_account.clone() else {
            unreachable!()
        };
        let v0 = TransactionEnvelope::TxV0(TransactionV0Envelope {
            tx: TransactionV0 {
                source_account_ed25519: Uint256(source.0),
                fee: tx.tx.fee,
                seq_num: tx.tx.seq_num.clone(),
                time_bounds: None,
                memo: tx.tx.memo.clone(),
                operations: tx.tx.operations.clone(),
                ext: TransactionV0Ext::V0,
            },
            signatures: vec![].try_into().unwrap(),
        })
        .to_xdr_base64(Limits::none())
        .unwrap();
        assert_eq!(
            code(&v0, MainnetConsumer::CliPay),
            "protocol.xdr_codec_failed"
        );
        let summary =
            MainnetWriteSummary::from_envelope(built.envelope_xdr(), MainnetConsumer::CliPay, 500)
                .unwrap();
        assert_eq!(
            summary.amount("memo").unwrap_err().code(),
            "protocol.xdr_codec_failed"
        );
    }

    #[test]
    fn persisted_attestation_refusals_carry_their_code() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = PendingApprovalStore::open(dir.path().join("pending.toml")).unwrap();
        assert_eq!(
            persisted_attestation(&store, "absent").unwrap_err().code(),
            "approval.attestation_invalid"
        );
        let built = stellar_agent_test_support::SignedTestEnvelope::builder([8; 32])
            .unsigned()
            .amount_stroops(17)
            .build();
        let summary =
            MainnetWriteSummary::from_envelope(built.envelope_xdr(), MainnetConsumer::CliPay, 500)
                .unwrap();
        let entry = summary.pending("1000".into(), 600_000).unwrap();
        let five = URL_SAFE_NO_PAD.encode([5; 32]);
        let mut stored_with = |blob: Option<&str>| {
            let mut stored = entry.clone();
            stored.attestation_blob_b64 = blob.map(str::to_owned);
            store.remove(&entry.approval_nonce).unwrap();
            store.insert(stored, entry.created_at_unix_ms).unwrap();
            persisted_attestation(&store, &entry.approval_nonce)
        };
        for blob in [None, Some("not base64url!"), Some("AAAA")] {
            assert_eq!(
                stored_with(blob).unwrap_err().code(),
                "approval.attestation_invalid",
                "{blob:?}"
            );
        }
        assert_eq!(stored_with(Some(&five)).unwrap(), [5; 32]);
    }
}
