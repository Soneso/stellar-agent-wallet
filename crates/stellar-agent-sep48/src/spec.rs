//! Contract Wasm fetch and SEP-48 spec-section parse.
//!
//! # Overview
//!
//! This module resolves the Wasm a contract currently runs, fetches the Wasm
//! bytes from the Stellar RPC layer and parses the embedded `contractspecv0`
//! custom section into a [`soroban_spec_tools::Spec`] value. Parsed entries are
//! cached in memory per Wasm hash.
//!
//! # Fetch path
//!
//! 1. Resolve the contract's executable through
//!    [`stellar_agent_network::fetch_contract_wasm_hash`]: one
//!    `getLedgerEntries` for the contract instance, and one more for the
//!    owner's executable-tag entry when the executable is a CAP-85 external
//!    reference. The result is the 32-byte hash of the Wasm the contract runs
//!    now.
//! 2. On a cache miss for that hash, look up `LedgerKey::ContractCode { hash }`
//!    to obtain the Wasm bytes, keep only the entry returned under that key,
//!    and verify that the bytes hash to it.
//! 3. Parse via `soroban_spec_tools::Spec::from_wasm` (wraps
//!    `soroban_spec::read::from_wasm`, which reads the `contractspecv0` custom
//!    section).
//!
//! # SEP-48 specification
//!
//! The SEP-48 specification ("Wasm Custom Section"): "The contract interface is
//! stored in one `contractspecv0` Wasm custom section." Each entry is a binary
//! XDR-encoded `SCSpecEntry` appended with no frame or delimiter.
//!
//! # Cache semantics
//!
//! `SPEC_CACHE` stores the parsed `Vec<ScSpecEntry>` keyed on the lowercase hex
//! of the Wasm hash. The code behind a contract can change while the process
//! runs (an owner repointing an executable tag, or a contract upgrading its own
//! Wasm), so every call resolves the instance first and only the parsed spec
//! per hash is cached. Contracts running the same code share one entry and one
//! code fetch. A code fetch whose bytes do not hash to the requested key is
//! refused and nothing is cached. The SEP-47 discovery path
//! ([`crate::discovery`]) resolves and fetches through the same two steps but
//! parses a different section and does not read this cache.
//!
//! Upstream contract specs are treated as trusted: the typed preview is a
//! non-authoritative display and does not validate spec semantics beyond the
//! bounded XDR parse.
//!
//! # KMP reference
//!
//! KMP Stellar SDK `SorobanContractParser.kt`: `parseContractSpec` reads
//! `contractspecv0` and iterates `SCSpecEntryXdr`, the same section name and
//! parse loop this module delegates to `soroban_spec_tools`.

use std::{collections::HashMap, sync::Mutex};

use sha2::{Digest, Sha256};
use stellar_agent_network::{
    FetchContractWasmHashError, StellarRpcClient, WasmHashFetch, fetch_contract_wasm_hash,
    redact_rpc_error,
};
use stellar_agent_xdr_limits::untrusted_decode_limits;
use stellar_xdr::{Hash, LedgerEntryData, LedgerKey, LedgerKeyContractCode, ReadXdr};

use soroban_spec_tools::Spec;

use crate::error::Sep48Error;

// ─────────────────────────────────────────────────────────────────────────────
// In-process spec cache (one parsed spec per Wasm hash per process lifetime)
// ─────────────────────────────────────────────────────────────────────────────

/// In-process cache of parsed [`Spec`] entries, keyed on the lowercase hex of
/// the Wasm hash.
///
/// The cache is process-global but lock-protected. A Wasm hash names immutable
/// code, so an entry never goes stale; which hash a contract runs is resolved
/// on every call and is never cached. The cache persists for the lifetime of
/// the process with no TTL.
static SPEC_CACHE: Mutex<Option<HashMap<String, Vec<stellar_xdr::ScSpecEntry>>>> = Mutex::new(None);

fn with_cache<F, T>(f: F) -> T
where
    F: FnOnce(&mut HashMap<String, Vec<stellar_xdr::ScSpecEntry>>) -> T,
{
    // `Mutex::lock` panics only if the mutex is poisoned (a previous lock-holder
    // panicked while holding the guard). Re-initialise the cache on poison:
    // the cache is a plain HashMap with no cross-guard invariants, so this is safe.
    let mut guard = SPEC_CACHE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let cache = guard.get_or_insert_with(HashMap::new);
    f(cache)
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Constructs the `LedgerKey::ContractCode` key for a Wasm hash.
fn contract_code_ledger_key(wasm_hash: &[u8; 32]) -> LedgerKey {
    LedgerKey::ContractCode(LedgerKeyContractCode {
        hash: Hash(*wasm_hash),
    })
}

/// Applies first-5-last-5 redaction to a strkey for use in error messages.
///
/// Account and contract IDs are redacted before inclusion in log-visible fields
/// or error messages to prevent leaking user identifiers at info level.
fn redact_strkey(s: &str) -> String {
    if s.len() <= 10 {
        return "REDACTED".to_owned();
    }
    format!("{}...{}", &s[..5], &s[s.len() - 5..])
}

/// Returns the lowercase hex of `bytes`.
fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Returns the lowercase hex of the first 8 bytes of a Wasm hash, the form
/// used in refusal reasons.
fn hash_first8(hash: &[u8; 32]) -> String {
    hex_lower(&hash[..8])
}

/// Builds the RPC client for `rpc_url`.
///
/// # Errors
///
/// Returns [`Sep48Error::RpcFetchFailure`] when the URL is rejected; the
/// reason passes through [`redact_rpc_error`].
pub(crate) fn rpc_client(rpc_url: &str) -> Result<StellarRpcClient, Sep48Error> {
    StellarRpcClient::new(rpc_url).map_err(|e| Sep48Error::RpcFetchFailure {
        reason: redact_rpc_error(&format!("RPC client construction failed: {e}")),
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API: fetch_contract_spec
// ─────────────────────────────────────────────────────────────────────────────

/// Fetches the SEP-48 contract spec for the given contract address.
///
/// Every call resolves the Wasm the contract runs now; the parsed spec is
/// cached per Wasm hash for the lifetime of the process, so a contract whose
/// code changes (an upgrade, or an external reference whose owner repoints its
/// tag) returns the spec of its current code.
///
/// # Fetch path
///
/// 1. Resolve the Wasm hash the contract runs now through
///    [`stellar_agent_network::fetch_contract_wasm_hash`] against this one
///    endpoint: one `getLedgerEntries`, or two for an external reference,
///    which resolves through its owner's executable-tag entry.
/// 2. On a cache miss, fetch the Wasm bytes for that hash with one more
///    `getLedgerEntries` on `LedgerKey::ContractCode` and verify them against
///    the hash.
/// 3. Parse via `soroban_spec_tools::Spec::from_wasm`, which reads the
///    `contractspecv0` Wasm custom section.
///
/// # Errors
///
/// - [`Sep48Error::InvalidContractAddress`]: invalid C-strkey.
/// - [`Sep48Error::RpcFetchFailure`]: a `getLedgerEntries` call failed, the
///   contract has no Wasm to read (absent, a Stellar Asset Contract, or an
///   external reference with no live tag entry), or the code entry is missing
///   or does not match its hash.
/// - [`Sep48Error::WasmParseFailure`]: Wasm bytes present but spec parse failed.
/// - [`Sep48Error::SpecSectionMissing`]: no `contractspecv0` section in the Wasm.
pub async fn fetch_contract_spec(
    rpc_url: &str,
    contract_strkey: &str,
) -> Result<Vec<stellar_xdr::ScSpecEntry>, Sep48Error> {
    let client = rpc_client(rpc_url)?;
    let wasm_hash = resolve_wasm_hash(&client, contract_strkey).await?;
    let cache_key = hex_lower(&wasm_hash);

    if let Some(entries) = with_cache(|c| c.get(&cache_key).cloned()) {
        tracing::debug!(
            contract = %redact_strkey(contract_strkey),
            wasm_hash = %hash_first8(&wasm_hash),
            "sep48: spec cache hit"
        );
        return Ok(entries);
    }

    tracing::debug!(
        contract = %redact_strkey(contract_strkey),
        wasm_hash = %hash_first8(&wasm_hash),
        "sep48: fetching contract code from RPC"
    );

    let wasm_bytes = fetch_wasm_bytes_by_hash(&client, &wasm_hash).await?;

    let entries = Spec::from_wasm(&wasm_bytes)
        .map(|spec| spec.0.unwrap_or_default())
        .map_err(|e| {
            let reason = e.to_string();
            if reason.contains("not found") || reason.contains("NotFound") {
                Sep48Error::SpecSectionMissing
            } else {
                Sep48Error::WasmParseFailure { reason }
            }
        })?;

    if entries.is_empty() {
        return Err(Sep48Error::SpecSectionMissing);
    }

    with_cache(|c| c.insert(cache_key, entries.clone()));

    Ok(entries)
}

/// Resolves the 32-byte hash of the Wasm `contract_strkey` runs now.
///
/// Delegates to [`fetch_contract_wasm_hash`] with no secondary endpoint: the
/// typed preview and the SEP-47 discovery result are non-authoritative
/// displays, so one endpoint is consulted. The profile may carry a secondary
/// endpoint; it is not used here. An external reference resolves through its
/// owner's executable-tag entry at the same endpoint.
///
/// # Errors
///
/// - [`Sep48Error::InvalidContractAddress`]: invalid C-strkey.
/// - [`Sep48Error::RpcFetchFailure`]: the contract is absent, is a Stellar
///   Asset Contract, or is an external reference with no live tag entry; or
///   the fetch failed, in which case the reason is the fetch error passed
///   through [`redact_rpc_error`].
pub(crate) async fn resolve_wasm_hash(
    client: &StellarRpcClient,
    contract_strkey: &str,
) -> Result<[u8; 32], Sep48Error> {
    match fetch_contract_wasm_hash(client, None, contract_strkey).await {
        Ok(WasmHashFetch::Wasm(hash)) => Ok(hash),
        Ok(WasmHashFetch::ExternalRef(external)) => match external.resolved {
            Some(hash) => {
                tracing::debug!(
                    contract = %redact_strkey(contract_strkey),
                    owner = %external.owner_redacted(),
                    tag = %external.tag_display(),
                    "sep48: external-reference executable resolved through the owner's tag entry"
                );
                Ok(hash)
            }
            None => Err(Sep48Error::RpcFetchFailure {
                reason: format!(
                    "contract {} executable is an external reference managed by {} under \
                     tag \"{}\" with no live tag entry",
                    redact_strkey(contract_strkey),
                    external.owner_redacted(),
                    external.tag_display(),
                ),
            }),
        },
        Ok(WasmHashFetch::Sac) => Err(Sep48Error::RpcFetchFailure {
            reason: format!(
                "contract {} is a Stellar Asset Contract (SAC), not a Wasm contract",
                redact_strkey(contract_strkey)
            ),
        }),
        Ok(WasmHashFetch::Absent) => Err(Sep48Error::RpcFetchFailure {
            reason: format!(
                "no instance ledger entry for contract {}",
                redact_strkey(contract_strkey)
            ),
        }),
        Ok(_) => Err(Sep48Error::RpcFetchFailure {
            reason: format!(
                "contract {} executable is not a Wasm executable this path reads",
                redact_strkey(contract_strkey)
            ),
        }),
        Err(FetchContractWasmHashError::InvalidAddress { .. }) => {
            Err(Sep48Error::InvalidContractAddress {
                addr: redact_strkey(contract_strkey),
            })
        }
        Err(e) => Err(Sep48Error::RpcFetchFailure {
            reason: redact_rpc_error(&e.to_string()),
        }),
    }
}

/// Fetches the Wasm bytes stored under `LedgerKey::ContractCode { hash }`.
///
/// Only the returned entry whose own key is the requested key is read, and
/// its bytes must hash to `wasm_hash`.
///
/// # Errors
///
/// Returns [`Sep48Error::RpcFetchFailure`] when the `getLedgerEntries` call
/// fails (reason through [`redact_rpc_error`]) or the response fails
/// [`extract_wasm_bytes_from_code_response`].
pub(crate) async fn fetch_wasm_bytes_by_hash(
    client: &StellarRpcClient,
    wasm_hash: &[u8; 32],
) -> Result<Vec<u8>, Sep48Error> {
    let code_key = contract_code_ledger_key(wasm_hash);
    let code_resp = client
        .get_ledger_entries(std::slice::from_ref(&code_key))
        .await
        .map_err(|e| Sep48Error::RpcFetchFailure {
            reason: redact_rpc_error(&format!("getLedgerEntries(code) failed: {e}")),
        })?;

    extract_wasm_bytes_from_code_response(&code_resp, &code_key, wasm_hash)
}

/// Extracts the Wasm bytes of the `ContractCode` entry returned under
/// `code_key` and verifies that they hash to `wasm_hash`.
///
/// Returned keys and entry data come from the network and decode under
/// [`untrusted_decode_limits`]. Entries under any other key are ignored.
///
/// # Errors
///
/// Returns [`Sep48Error::RpcFetchFailure`] when a returned key does not
/// decode, no entry is returned under `code_key`, that entry does not decode
/// or is not a `ContractCode` entry, or its bytes do not hash to `wasm_hash`.
fn extract_wasm_bytes_from_code_response(
    resp: &stellar_agent_network::GetLedgerEntriesResponse,
    code_key: &LedgerKey,
    wasm_hash: &[u8; 32],
) -> Result<Vec<u8>, Sep48Error> {
    let hash_display = hash_first8(wasm_hash);
    let mut matched = None;
    for entry in resp.entries.as_deref().unwrap_or_default() {
        let entry_key =
            LedgerKey::from_xdr_base64(&entry.key, untrusted_decode_limits(entry.key.len()))
                .map_err(|_| Sep48Error::RpcFetchFailure {
                    reason: format!(
                        "code ledger entry key does not decode (requested Wasm hash {hash_display})"
                    ),
                })?;
        if &entry_key == code_key {
            matched = Some(entry);
            break;
        }
    }

    let entry = matched.ok_or_else(|| Sep48Error::RpcFetchFailure {
        reason: format!("no code ledger entry for Wasm hash {hash_display}"),
    })?;

    let entry_data =
        LedgerEntryData::from_xdr_base64(&entry.xdr, untrusted_decode_limits(entry.xdr.len()))
            .map_err(|e| Sep48Error::RpcFetchFailure {
                reason: format!("malformed LedgerEntryData XDR for Wasm hash {hash_display}: {e}"),
            })?;

    let LedgerEntryData::ContractCode(cc) = entry_data else {
        return Err(Sep48Error::RpcFetchFailure {
            reason: format!(
                "unexpected ledger entry type (not ContractCode) for Wasm hash {hash_display}"
            ),
        });
    };

    let code = cc.code.into_vec();
    let actual: [u8; 32] = Sha256::digest(&code).into();
    if &actual != wasm_hash {
        return Err(Sep48Error::RpcFetchFailure {
            reason: format!(
                "code hash mismatch: the code entry for Wasm hash {hash_display} hashes to {}",
                hash_first8(&actual)
            ),
        });
    }

    Ok(code)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics acceptable in unit tests"
)]
mod tests {
    use super::*;
    use stellar_agent_network::{GetLedgerEntriesResponse, LedgerEntryResult};
    use stellar_xdr::{
        ContractCodeCostInputs, ContractCodeEntry, ContractCodeEntryExt, ContractCodeEntryV1,
        ContractDataDurability, ContractDataEntry, ContractId, ExtensionPoint, Hash,
        LedgerEntryData, Limits, ScAddress, ScVal, WriteXdr,
    };

    // ── Helpers ───────────────────────────────────────────────────────────────

    const CONTRACT: &str = "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA";
    const WASM: &[u8] = b"\x00asm\x01\x00\x00\x00";

    fn sha256(data: &[u8]) -> [u8; 32] {
        Sha256::digest(data).into()
    }

    fn key_b64(key: &LedgerKey) -> String {
        key.to_xdr_base64(Limits::none()).unwrap()
    }

    fn make_resp(entries: Option<Vec<(String, String)>>) -> GetLedgerEntriesResponse {
        GetLedgerEntriesResponse {
            entries: entries.map(|list| {
                list.into_iter()
                    .map(|(key, xdr)| LedgerEntryResult {
                        key,
                        xdr,
                        last_modified_ledger: 1,
                        live_until_ledger_seq_ledger_seq: None,
                    })
                    .collect()
            }),
            latest_ledger: 100,
        }
    }

    fn contract_data_bool_xdr() -> String {
        LedgerEntryData::ContractData(ContractDataEntry {
            ext: ExtensionPoint::V0,
            contract: ScAddress::Contract(ContractId(Hash(
                stellar_strkey::Contract::from_string(CONTRACT)
                    .expect("valid strkey")
                    .0,
            ))),
            key: ScVal::LedgerKeyContractInstance,
            durability: ContractDataDurability::Persistent,
            val: ScVal::Bool(false),
        })
        .to_xdr_base64(Limits::none())
        .unwrap()
    }

    fn contract_code_xdr(code: &[u8]) -> String {
        let code_bytes: stellar_xdr::BytesM = code.try_into().unwrap();
        LedgerEntryData::ContractCode(ContractCodeEntry {
            ext: ContractCodeEntryExt::V1(ContractCodeEntryV1 {
                ext: ExtensionPoint::V0,
                cost_inputs: ContractCodeCostInputs {
                    ext: ExtensionPoint::V0,
                    n_instructions: 0,
                    n_functions: 0,
                    n_globals: 0,
                    n_table_entries: 0,
                    n_types: 0,
                    n_data_segments: 0,
                    n_elem_segments: 0,
                    n_imports: 0,
                    n_exports: 0,
                    n_data_segment_bytes: 0,
                },
            }),
            hash: Hash(sha256(code)),
            code: code_bytes,
        })
        .to_xdr_base64(Limits::none())
        .unwrap()
    }

    fn expect_reason(result: Result<Vec<u8>, Sep48Error>) -> String {
        match result {
            Err(Sep48Error::RpcFetchFailure { reason }) => reason,
            other => panic!("expected RpcFetchFailure, got: {other:?}"),
        }
    }

    // ── extract_wasm_bytes_from_code_response ─────────────────────────────────

    /// `entries: None` names the missing code entry.
    #[test]
    fn extract_wasm_bytes_null_code_entries_returns_error() {
        let hash = sha256(WASM);
        let key = contract_code_ledger_key(&hash);
        let reason = expect_reason(extract_wasm_bytes_from_code_response(
            &make_resp(None),
            &key,
            &hash,
        ));
        assert_eq!(
            reason,
            format!("no code ledger entry for Wasm hash {}", hash_first8(&hash))
        );
    }

    /// `entries: Some([])` names the missing code entry.
    #[test]
    fn extract_wasm_bytes_empty_code_entries_returns_error() {
        let hash = sha256(WASM);
        let key = contract_code_ledger_key(&hash);
        let reason = expect_reason(extract_wasm_bytes_from_code_response(
            &make_resp(Some(vec![])),
            &key,
            &hash,
        ));
        assert!(
            reason.starts_with("no code ledger entry for Wasm hash "),
            "got: {reason}"
        );
    }

    /// A returned key that does not decode as a `LedgerKey` is a refusal.
    #[test]
    fn extract_wasm_bytes_undecodable_key_returns_error() {
        let hash = sha256(WASM);
        let key = contract_code_ledger_key(&hash);
        let resp = make_resp(Some(vec![("dummy".to_owned(), contract_code_xdr(WASM))]));
        let reason = expect_reason(extract_wasm_bytes_from_code_response(&resp, &key, &hash));
        assert!(
            reason.starts_with("code ledger entry key does not decode"),
            "got: {reason}"
        );
    }

    /// An entry under the requested key that is not `ContractCode` is refused.
    #[test]
    fn extract_wasm_bytes_non_contract_code_entry_returns_error() {
        let hash = sha256(WASM);
        let key = contract_code_ledger_key(&hash);
        let resp = make_resp(Some(vec![(key_b64(&key), contract_data_bool_xdr())]));
        let reason = expect_reason(extract_wasm_bytes_from_code_response(&resp, &key, &hash));
        assert!(
            reason.contains("unexpected ledger entry type (not ContractCode)"),
            "got: {reason}"
        );
    }

    /// Entry data under the requested key that does not decode is refused.
    #[test]
    fn extract_wasm_bytes_malformed_entry_xdr_returns_error() {
        let hash = sha256(WASM);
        let key = contract_code_ledger_key(&hash);
        let resp = make_resp(Some(vec![(key_b64(&key), "not-valid-xdr".to_owned())]));
        let reason = expect_reason(extract_wasm_bytes_from_code_response(&resp, &key, &hash));
        assert!(
            reason.starts_with("malformed LedgerEntryData XDR for Wasm hash "),
            "got: {reason}"
        );
    }

    /// The entry under the requested key is selected even when an entry under
    /// another key precedes it.
    #[test]
    fn extract_wasm_bytes_selects_the_entry_under_the_requested_key() {
        let hash = sha256(WASM);
        let key = contract_code_ledger_key(&hash);
        let other_key = contract_code_ledger_key(&[7u8; 32]);
        let resp = make_resp(Some(vec![
            (key_b64(&other_key), contract_data_bool_xdr()),
            (key_b64(&key), contract_code_xdr(WASM)),
        ]));
        let bytes = extract_wasm_bytes_from_code_response(&resp, &key, &hash)
            .expect("the entry under the requested key must be read");
        assert_eq!(bytes, WASM.to_vec());
    }

    /// Bytes that do not hash to the requested hash are refused.
    #[test]
    fn extract_wasm_bytes_hash_mismatch_returns_error() {
        let requested = [9u8; 32];
        let key = contract_code_ledger_key(&requested);
        let resp = make_resp(Some(vec![(key_b64(&key), contract_code_xdr(WASM))]));
        let reason = expect_reason(extract_wasm_bytes_from_code_response(
            &resp, &key, &requested,
        ));
        assert_eq!(
            reason,
            format!(
                "code hash mismatch: the code entry for Wasm hash {} hashes to {}",
                hash_first8(&requested),
                hash_first8(&sha256(WASM))
            )
        );
    }

    #[test]
    fn redact_strkey_short() {
        assert_eq!(redact_strkey("CSHORT"), "REDACTED");
    }

    #[test]
    fn redact_strkey_long() {
        let s = "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA";
        let redacted = redact_strkey(s);
        assert_eq!(redacted, "CBIEL...QDAMA", "must emit first-5 ... last-5");
    }

    #[test]
    fn hex_lower_renders_lowercase_pairs() {
        assert_eq!(hex_lower(&[0x00, 0xab, 0x0f, 0xff]), "00ab0fff");
    }
}
