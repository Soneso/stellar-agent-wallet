//! A `getTransaction` answer read as received, with XDR decoded on demand.
//!
//! [`TransactionRecord`] owns the endpoint's raw `getTransaction` response.
//! The fields every reader consumes (`status`, `ledger`, `createdAt`,
//! `txHash`) are plain JSON values and are read as received. The XDR fields
//! are decoded only by the accessor that needs them, under
//! [`untrusted_decode_limits`], and a field that does not decode is a typed
//! error naming that field. The result meta is never decoded: no reader needs
//! it, so a meta the current XDR cannot decode does not affect a status read.

use stellar_agent_core::error::NetworkError;
use stellar_agent_xdr_limits::untrusted_decode_limits;
use stellar_rpc_client::GetTransactionResponseRaw;
use stellar_xdr::{ContractEvent, ReadXdr, TransactionEnvelope, TransactionResult};

/// The JSON-RPC method a [`TransactionRecord`] answers.
const METHOD: &str = "getTransaction";

/// One endpoint's `getTransaction` answer.
///
/// Built by [`crate::StellarRpcClient::get_transaction_raw`]. The raw
/// response stays reachable through [`Self::raw`] for fields no accessor
/// covers.
#[derive(Debug, Clone)]
pub struct TransactionRecord {
    raw: GetTransactionResponseRaw,
}

impl TransactionRecord {
    /// Wraps a raw `getTransaction` response.
    pub(crate) fn from_raw(raw: GetTransactionResponseRaw) -> Self {
        Self { raw }
    }

    /// The `getTransaction` status string as received: `SUCCESS`, `FAILED`
    /// or `NOT_FOUND`, or any other string the endpoint sent.
    #[must_use]
    pub fn status(&self) -> &str {
        &self.raw.status
    }

    /// The ledger the transaction was applied in, when the endpoint reports
    /// one.
    #[must_use]
    pub fn ledger(&self) -> Option<u32> {
        self.raw.ledger
    }

    /// The close time of that ledger in Unix seconds, when the endpoint
    /// reports one.
    #[must_use]
    pub fn created_at(&self) -> Option<i64> {
        self.raw.created_at
    }

    /// The transaction hash the endpoint reports, as received.
    #[must_use]
    pub fn tx_hash(&self) -> Option<&str> {
        self.raw.tx_hash.as_deref()
    }

    /// The raw response, for fields no accessor covers.
    #[must_use]
    pub fn raw(&self) -> &GetTransactionResponseRaw {
        &self.raw
    }

    /// Decodes `resultXdr`, when present.
    ///
    /// # Errors
    ///
    /// [`NetworkError::RpcResponseMalformed`] naming `resultXdr` when the
    /// field does not decode under the untrusted-decode limits; no other
    /// error is returned.
    pub fn result(&self) -> Result<Option<TransactionResult>, NetworkError> {
        self.raw
            .result_xdr
            .as_deref()
            .map(|b64| decode_field("resultXdr", b64))
            .transpose()
    }

    /// Decodes `envelopeXdr`, when present.
    ///
    /// # Errors
    ///
    /// [`NetworkError::RpcResponseMalformed`] naming `envelopeXdr` when the
    /// field does not decode under the untrusted-decode limits.
    pub fn envelope(&self) -> Result<Option<TransactionEnvelope>, NetworkError> {
        self.raw
            .envelope_xdr
            .as_deref()
            .map(|b64| decode_field("envelopeXdr", b64))
            .transpose()
    }

    /// Decodes `events.contractEventsXdr`: the contract events of each
    /// operation, outer index per operation.
    ///
    /// The events are read from the `events` field and do not depend on the
    /// result meta. A response without the field has no events.
    ///
    /// # Errors
    ///
    /// [`NetworkError::RpcResponseMalformed`] naming the position of the
    /// first event that does not decode under the untrusted-decode limits.
    pub fn contract_events(&self) -> Result<Vec<Vec<ContractEvent>>, NetworkError> {
        let Some(per_op) = self
            .raw
            .events
            .as_ref()
            .and_then(|events| events.contract_events_xdr.as_ref())
        else {
            return Ok(Vec::new());
        };
        per_op
            .iter()
            .enumerate()
            .map(|(op, events)| {
                events
                    .iter()
                    .enumerate()
                    .map(|(i, b64)| {
                        ContractEvent::from_xdr_base64(b64, untrusted_decode_limits(b64.len()))
                            .map_err(|e| malformed(&format!("contractEventsXdr[{op}][{i}]"), &e))
                    })
                    .collect()
            })
            .collect()
    }
}

/// Decodes one base64 XDR field of the response.
fn decode_field<T: ReadXdr>(field: &str, b64: &str) -> Result<T, NetworkError> {
    T::from_xdr_base64(b64, untrusted_decode_limits(b64.len())).map_err(|e| malformed(field, &e))
}

fn malformed(field: &str, e: &stellar_xdr::Error) -> NetworkError {
    NetworkError::RpcResponseMalformed {
        method: METHOD.to_owned(),
        detail: format!("{field} does not decode: {e}"),
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only fixture construction"
    )]

    use super::*;
    use stellar_xdr::{
        ContractEventBody, ContractEventType, ContractEventV0, ExtensionPoint, Limits, ScVal,
        ScVec, WriteXdr,
    };

    fn record(json: serde_json::Value) -> TransactionRecord {
        TransactionRecord::from_raw(serde_json::from_value(json).expect("raw response"))
    }

    fn event_b64(data: ScVal) -> String {
        ContractEvent {
            ext: ExtensionPoint::V0,
            contract_id: None,
            type_: ContractEventType::Contract,
            body: ContractEventBody::V0(ContractEventV0 {
                topics: vec![ScVal::Bool(true)].try_into().unwrap(),
                data,
            }),
        }
        .to_xdr_base64(Limits::none())
        .unwrap()
    }

    /// A contract event whose data is a 600-deep `ScVal::Vec` chain, above the
    /// untrusted-decode depth bound. Encoded on a thread with an extended
    /// stack because XDR encoding of the chain is recursive.
    fn depth_bomb_event_b64() -> String {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                let mut nested = ScVal::Bool(false);
                for _ in 0..600 {
                    nested = ScVal::Vec(Some(ScVec(vec![nested].try_into().unwrap())));
                }
                event_b64(nested)
            })
            .expect("spawn encoder")
            .join()
            .expect("encoder thread")
    }

    fn detail(e: NetworkError) -> String {
        match e {
            NetworkError::RpcResponseMalformed { method, detail } => {
                assert_eq!(method, "getTransaction");
                detail
            }
            other => panic!("expected RpcResponseMalformed, got {other:?}"),
        }
    }

    #[test]
    fn received_fields_are_read_as_received() {
        let r = record(serde_json::json!({
            "status": "SUCCESS",
            "ledger": 42,
            "createdAt": "1700000000",
            "txHash": "ab".repeat(32),
            "resultMetaXdr": "AAAAYw==",
        }));
        assert_eq!(r.status(), "SUCCESS");
        assert_eq!(r.ledger(), Some(42));
        assert_eq!(r.created_at(), Some(1_700_000_000));
        assert_eq!(r.tx_hash(), Some("ab".repeat(32).as_str()));
    }

    #[test]
    fn created_at_reads_a_number() {
        let r = record(serde_json::json!({"status": "SUCCESS", "createdAt": 1_700_000_001}));
        assert_eq!(r.created_at(), Some(1_700_000_001));
    }

    #[test]
    fn absent_xdr_fields_decode_to_none_and_no_events() {
        let r = record(serde_json::json!({"status": "NOT_FOUND"}));
        assert!(r.result().expect("no result").is_none());
        assert!(r.envelope().expect("no envelope").is_none());
        assert!(r.contract_events().expect("no events").is_empty());
    }

    #[test]
    fn contract_events_decode_per_operation() {
        let a = event_b64(ScVal::U32(1));
        let b = event_b64(ScVal::U32(2));
        let r = record(serde_json::json!({
            "status": "SUCCESS",
            "events": {"contractEventsXdr": [[a], [], [b]]},
        }));
        let events = r.contract_events().expect("events decode");
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].len(), 1);
        assert!(events[1].is_empty());
        let ContractEventBody::V0(body) = &events[2][0].body;
        assert_eq!(body.data, ScVal::U32(2));
    }

    #[test]
    fn undecodable_event_is_a_typed_error_naming_its_position() {
        let good = event_b64(ScVal::U32(1));
        let r = record(serde_json::json!({
            "status": "SUCCESS",
            "events": {"contractEventsXdr": [[good, "AAAA"]]},
        }));
        let d = detail(r.contract_events().expect_err("undecodable event"));
        assert!(
            d.starts_with("contractEventsXdr[0][1] does not decode: "),
            "got {d}"
        );
    }

    #[test]
    fn contract_events_depth_bomb_is_a_typed_error_without_panic() {
        let r = record(serde_json::json!({
            "status": "SUCCESS",
            "events": {"contractEventsXdr": [[depth_bomb_event_b64()]]},
        }));
        let d = detail(r.contract_events().expect_err("depth bomb"));
        assert_eq!(
            d,
            "contractEventsXdr[0][0] does not decode: depth limit exceeded"
        );
    }

    /// `TransactionResult` has no recursive type, so no well-formed result
    /// reaches the depth bound. A hostile `resultXdr` carrying a depth bomb
    /// built for another type is refused as a typed error naming the field.
    #[test]
    fn result_depth_bomb_bytes_are_a_typed_error_without_panic() {
        let r = record(serde_json::json!({
            "status": "FAILED",
            "resultXdr": depth_bomb_event_b64(),
        }));
        let d = detail(r.result().expect_err("not a result"));
        assert!(d.starts_with("resultXdr does not decode: "), "got {d}");
    }

    #[test]
    fn undecodable_envelope_is_a_typed_error_naming_the_field() {
        let r = record(serde_json::json!({"status": "SUCCESS", "envelopeXdr": "AAAA"}));
        let d = detail(r.envelope().expect_err("undecodable envelope"));
        assert!(d.starts_with("envelopeXdr does not decode: "), "got {d}");
    }
}
