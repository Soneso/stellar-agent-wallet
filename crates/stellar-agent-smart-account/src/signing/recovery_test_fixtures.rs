//! Distinct simulation responses for unsigned recovery tests.

#![allow(clippy::unwrap_used, reason = "test-only")]

// The rejected response uses this nonce and prediction.
const INITIAL_VALUE: u32 = 41;
// The accepted replacement uses this nonce and prediction.
pub(crate) const REPLACEMENT_VALUE: u32 = 73;
// This height falls one ledger below the accepted floor for a pair at 1000.
const BEHIND_LEDGER: u32 = 997;
// This height exceeds the accepted ceiling for a pair at 1000 by one ledger.
const AHEAD_LEDGER: u32 = 1003;
// This byte identifies a foreign contract in the replacement credential.
const FOREIGN_CONTRACT_BYTE: u8 = 0x99;

/// Response variations that exercise recovery and replacement validation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RecoveryCase {
    Valid,
    Behind,
    ReplacementAhead,
    Ahead,
    Tree,
    Count,
    Credential,
    Error,
    Fee,
    Data,
    Decode,
    Empty,
    Prediction,
    Schedule,
    Cross,
}

/// Supplies distinct unsigned responses and leaves signed simulation intact.
pub(crate) fn recovery_response(
    case: RecoveryCase,
    number: usize,
    response: &mut serde_json::Value,
) {
    use serde_json::json;
    use stellar_xdr::{
        Limits, ReadXdr, ScVal, SorobanAuthorizationEntry, SorobanCredentials, WriteXdr,
    };
    if number > 2 {
        return;
    }
    response["latestLedger"] = json!(if number == 1 {
        if case == RecoveryCase::Ahead {
            AHEAD_LEDGER
        } else {
            BEHIND_LEDGER
        }
    } else {
        match case {
            RecoveryCase::Behind => BEHIND_LEDGER,
            RecoveryCase::ReplacementAhead => AHEAD_LEDGER,
            _ => 1000,
        }
    });
    let xdr = response["results"][0]["auth"][0].as_str().unwrap();
    let mut entry = SorobanAuthorizationEntry::from_xdr_base64(xdr, Limits::none()).unwrap();
    if let SorobanCredentials::Address(creds) = &mut entry.credentials {
        creds.nonce = i64::from(if number == 1 {
            INITIAL_VALUE
        } else {
            REPLACEMENT_VALUE
        });
    }
    if number == 2 {
        match case {
            RecoveryCase::Tree => {
                entry.root_invocation.sub_invocations =
                    vec![entry.root_invocation.clone()].try_into().unwrap()
            }
            RecoveryCase::Count => entry.root_invocation.sub_invocations = Default::default(),
            RecoveryCase::Credential => {
                if let SorobanCredentials::Address(creds) = &mut entry.credentials {
                    creds.address = stellar_xdr::ScAddress::Contract(stellar_xdr::ContractId(
                        stellar_xdr::Hash([FOREIGN_CONTRACT_BYTE; 32]),
                    ));
                }
            }
            RecoveryCase::Error => response["error"] = json!("fixture failure"),
            RecoveryCase::Fee => response["minResourceFee"] = json!("0"),
            RecoveryCase::Data => response["transactionData"] = json!(""),
            RecoveryCase::Decode => response["results"][0]["xdr"] = json!("invalid"),
            RecoveryCase::Empty => {
                response["results"] = json!([]);
                return;
            }
            _ => {}
        }
    }
    response["results"][0]["auth"][0] = json!(entry.to_xdr_base64(Limits::none()).unwrap());
    if case != RecoveryCase::Decode {
        response["results"][0]["xdr"] = json!(
            ScVal::U32(if number == 1 {
                INITIAL_VALUE
            } else {
                REPLACEMENT_VALUE
            })
            .to_xdr_base64(Limits::none())
            .unwrap()
        );
    }
    if case == RecoveryCase::Prediction && number == 2 {
        response["results"][0]["xdr"] = json!(ScVal::Void.to_xdr_base64(Limits::none()).unwrap());
    }
    if case == RecoveryCase::Schedule {
        response["results"][0]["xdr"] = json!(
            ScVal::Bytes(
                vec![if number == 1 { 7 } else { 8 }; 32]
                    .try_into()
                    .unwrap()
            )
            .to_xdr_base64(Limits::none())
            .unwrap()
        );
    }
    if case == RecoveryCase::Valid || (case == RecoveryCase::Cross && number == 2) {
        response["minResourceFee"] = json!(if number == 1 { "0" } else { "2222" });
    }
}
