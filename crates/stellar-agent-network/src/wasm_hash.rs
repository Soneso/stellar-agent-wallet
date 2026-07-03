//! On-chain WASM-hash fetch primitive for DeFi contract-pin verification.
//!
//! # What this module does
//!
//! Provides [`fetch_contract_wasm_hash`], a two-RPC parallel fetch that returns
//! an explicit tri-state [`WasmHashFetch`] (`Wasm`, `Sac`, `Absent`) for a
//! single Soroban contract address.  Primary and secondary endpoints are
//! cross-checked; divergence is a hard error.
//!
//! This primitive is the shared single-contract fetch core: the smart-account
//! path delegates here and applies its own per-caller absent-handling policy
//! to the returned tri-state.  Only the smart-account multi-key batch fetch
//! (`fetch_contract_wasm_hashes`) keeps a separate implementation — it has no
//! single-contract analogue.
//!
//! # Per-caller absent-handling policy
//!
//! This primitive returns an explicit tri-state and NEVER collapses absent
//! or SAC to a zero hash — callers must handle all three variants.  The DeFi
//! sign-time gate (`stellar_agent_defi::pins::verify_pin_for_sign`) maps
//! `Absent` and `Sac` to `Err` directly (fail-closed by type).  The
//! smart-account caller maps `Sac`/`Absent` to `None`, and its verifier
//! paths apply `unwrap_or([0u8;32])` to support an accept-unknown-verifier
//! install flow that has no DeFi analogue; the zero sentinel exists only on
//! that caller's side, never in this primitive.
//!
//! # Divergence detection
//!
//! For the single-contract case this module compares the two 32-byte hashes
//! directly and reports first-8 hex of each side on divergence (or the
//! `<SAC>` / `<Absent>` sentinel for a non-WASM side).  The multi-key
//! smart-account batch path uses a SHA-256 digest-of-concatenation to
//! compare aligned result vectors instead.
//!
//! # SAC variant
//!
//! `ContractExecutable::StellarAsset` is the on-chain XDR variant that
//! indicates a Stellar Asset Contract (SAC) rather than an ordinary WASM
//! contract (`pub enum ContractExecutable { Wasm(Hash), StellarAsset }` in
//! the XDR schema).

use stellar_xdr::{
    ContractDataDurability, ContractExecutable, ContractId, Hash, LedgerEntryData, LedgerKey,
    LedgerKeyContractData, ReadXdr, ScAddress, ScVal,
};

use crate::StellarRpcClient;
use stellar_agent_core::error::NetworkError;

// ─────────────────────────────────────────────────────────────────────────────
// WasmHashFetch — explicit tri-state (NO zero-sentinel)
// ─────────────────────────────────────────────────────────────────────────────

/// The result of fetching a contract's on-chain WASM hash.
///
/// This is a **strict tri-state**.  Callers MUST handle all three variants and
/// MUST NOT collapse `Absent` or `Sac` to a zero hash or any other sentinel.
///
/// The distinction matters for the DeFi sign-time gate:
/// `stellar_agent_defi::pins::verify_pin_for_sign` maps `Wasm` to a
/// match-or-drift check, and maps `Sac` and `Absent` to typed `Err` variants
/// fail-closed by type.
///
/// # Design note
///
/// The smart-account caller collapses `Absent` to `[0u8;32]` via
/// `unwrap_or([0u8;32])` to support an accept-unknown-verifier install flow
/// that has no DeFi analogue.  This type is the stronger form: the zero-sentinel
/// path is impossible to express here.
///
/// # SAC variant
///
/// `ContractExecutable::StellarAsset` (from the XDR schema) maps to `Sac`.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum WasmHashFetch {
    /// The contract has an ordinary WASM executable; carries the 32-byte hash.
    Wasm([u8; 32]),
    /// The contract is a Stellar Asset Contract (SAC).
    ///
    /// Corresponds to `ContractExecutable::StellarAsset` in the XDR schema.
    Sac,
    /// The contract address is absent from the ledger (no instance entry found).
    Absent,
}

// ─────────────────────────────────────────────────────────────────────────────
// WasmHashDivergenceError
// ─────────────────────────────────────────────────────────────────────────────

/// Error returned when primary and secondary RPC endpoints disagree on the
/// on-chain WASM hash.
///
/// Carries first-8 hex of each side; full 32-byte hashes are NOT included.
/// This guards against contract-substitution by requiring both endpoints to
/// agree before the caller proceeds.
#[derive(Debug, thiserror::Error)]
#[error(
    "two-RPC WASM-hash divergence for {contract_redacted}: \
     primary={primary_first8} secondary={secondary_first8}"
)]
pub struct WasmHashDivergenceError {
    /// First-5-last-5 redacted contract address.
    pub contract_redacted: String,
    /// First-8 hex from the primary RPC.
    pub primary_first8: String,
    /// First-8 hex from the secondary RPC.
    pub secondary_first8: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// fetch_contract_wasm_hash
// ─────────────────────────────────────────────────────────────────────────────

/// Fetches the on-chain WASM hash for a single contract address using a
/// two-RPC parallel cross-check.
///
/// Calls `getLedgerEntries` on both `primary_rpc` and `secondary_rpc` in
/// parallel (via `tokio::join!`), then compares the results.  If the two RPCs
/// disagree, returns [`WasmHashDivergenceError`].  If `secondary_rpc` is `None`,
/// only the primary is queried (single-RPC trust, permitted ONLY when the
/// profile configures no secondary endpoint).
///
/// The returned [`WasmHashFetch`] is a strict tri-state:
/// - `Wasm(hash)` — ordinary WASM contract.
/// - `Sac` — Stellar Asset Contract (`ContractExecutable::StellarAsset`).
/// - `Absent` — no instance entry found on-chain.
///
/// # Divergence detection
///
/// For the single-contract case, divergence compares the two 32-byte hashes
/// directly and reports first-8 hex of each side.  The multi-key smart-account
/// batch path uses a SHA-256 digest-of-concatenation for aligned result vectors
/// instead.
///
/// # Errors
///
/// - [`FetchContractWasmHashError::InvalidAddress`] — `contract_address` is
///   not a valid Stellar C-strkey.
/// - [`FetchContractWasmHashError::Unavailable`] — the primary or secondary
///   RPC request failed (connection refused, DNS failure, TLS error, etc.).
///   The `url` in the underlying [`NetworkError::RpcUnreachable`] is
///   authority-only (scheme://host\[:port\]); credentials are stripped.
/// - [`FetchContractWasmHashError::Divergent`] — the primary and secondary
///   RPC endpoints returned different on-chain states for the same contract
///   key.  This is always possible when two independent endpoints are queried;
///   it indicates either a ledger fork or a misconfigured endpoint.
pub async fn fetch_contract_wasm_hash(
    primary_rpc: &StellarRpcClient,
    secondary_rpc: Option<&StellarRpcClient>,
    contract_address: &str,
) -> Result<WasmHashFetch, FetchContractWasmHashError> {
    let contract_redacted = redact_strkey_first5_last5(contract_address);
    let key = contract_instance_ledger_key(contract_address)?;

    match secondary_rpc {
        Some(secondary) => {
            // Two-RPC parallel fetch via `tokio::join!`.
            let (primary_result, secondary_result) = tokio::join!(
                fetch_single_wasm_hash(primary_rpc, &key),
                fetch_single_wasm_hash(secondary, &key),
            );

            let primary_fetch =
                primary_result.map_err(|e| FetchContractWasmHashError::Unavailable {
                    contract_redacted: contract_redacted.clone(),
                    source: e,
                })?;
            let secondary_fetch =
                secondary_result.map_err(|e| FetchContractWasmHashError::Unavailable {
                    contract_redacted: contract_redacted.clone(),
                    source: e,
                })?;

            // Compare the two tri-state results directly for the single-contract case.
            if primary_fetch != secondary_fetch {
                let primary_first8 = wasm_hash_fetch_first8_hex(&primary_fetch);
                let secondary_first8 = wasm_hash_fetch_first8_hex(&secondary_fetch);
                return Err(FetchContractWasmHashError::Divergent(
                    WasmHashDivergenceError {
                        contract_redacted,
                        primary_first8,
                        secondary_first8,
                    },
                ));
            }

            Ok(primary_fetch)
        }
        // No secondary configured — single-RPC trust (explicit operator config only).
        None => fetch_single_wasm_hash(primary_rpc, &key)
            .await
            .map_err(|e| FetchContractWasmHashError::Unavailable {
                contract_redacted,
                source: e,
            }),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FetchContractWasmHashError
// ─────────────────────────────────────────────────────────────────────────────

/// Error returned by [`fetch_contract_wasm_hash`].
///
/// All variants carry first-8 hex redactions or first-5-last-5 contract
/// addresses; full hashes and full addresses NEVER appear in `Display` or
/// `Debug`.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FetchContractWasmHashError {
    /// The contract address is not a valid Stellar strkey.
    #[error("invalid contract address {contract_redacted}: {reason}")]
    InvalidAddress {
        /// First-5-last-5 redacted contract address.
        contract_redacted: String,
        /// Non-sensitive reason string.
        reason: String,
    },
    /// The RPC fetch failed (primary or secondary).
    #[error("WASM-hash fetch unavailable for {contract_redacted}: {source}")]
    Unavailable {
        /// First-5-last-5 redacted contract address.
        contract_redacted: String,
        /// Underlying network error.
        #[source]
        source: NetworkError,
    },
    /// Primary and secondary RPC disagree on the on-chain state.
    #[error(transparent)]
    Divergent(#[from] WasmHashDivergenceError),
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Fetches the `WasmHashFetch` tri-state for a single contract key from one
/// RPC endpoint.
async fn fetch_single_wasm_hash(
    client: &StellarRpcClient,
    key: &LedgerKey,
) -> Result<WasmHashFetch, NetworkError> {
    let keys = std::slice::from_ref(key);
    let response = client.get_ledger_entries(keys).await?;
    let raw_entries = response.entries.unwrap_or_default();

    for entry_result in &raw_entries {
        // Decode the entry data (LedgerEntryData XDR, base64-encoded).
        // `LedgerEntryResult.xdr` contains `LedgerEntryData` from an untrusted
        // RPC response. `LedgerEntryData::ContractData.val` is a recursive
        // `ScVal`; the depth bound prevents a crafted depth-bomb from exhausting
        // the stack. `Err` continues to the next entry (fail-open per existing
        // behaviour for malformed entries).
        let entry_data = match LedgerEntryData::from_xdr_base64(
            &entry_result.xdr,
            stellar_agent_xdr_limits::untrusted_decode_limits(entry_result.xdr.len()),
        ) {
            Ok(d) => d,
            Err(_) => continue, // malformed entry — skip
        };

        // ContractExecutable::Wasm(Hash) → ordinary WASM contract.
        // ContractExecutable::StellarAsset → SAC.
        if let LedgerEntryData::ContractData(cd) = &entry_data
            && let ScVal::ContractInstance(instance) = &cd.val
        {
            return match &instance.executable {
                ContractExecutable::Wasm(Hash(bytes)) => Ok(WasmHashFetch::Wasm(*bytes)),
                ContractExecutable::StellarAsset => Ok(WasmHashFetch::Sac),
            };
        }
    }

    // No matching entry found.
    Ok(WasmHashFetch::Absent)
}

/// Constructs a `LedgerKey::ContractData` for the contract-instance slot.
fn contract_instance_ledger_key(
    contract_address: &str,
) -> Result<LedgerKey, FetchContractWasmHashError> {
    let contract_redacted = redact_strkey_first5_last5(contract_address);

    let contract = stellar_strkey::Contract::from_string(contract_address).map_err(|e| {
        FetchContractWasmHashError::InvalidAddress {
            contract_redacted: contract_redacted.clone(),
            reason: e.to_string(),
        }
    })?;

    let hash = Hash(contract.0);
    let sc_addr = ScAddress::Contract(ContractId(hash));

    Ok(LedgerKey::ContractData(LedgerKeyContractData {
        contract: sc_addr,
        key: ScVal::LedgerKeyContractInstance,
        durability: ContractDataDurability::Persistent,
    }))
}

/// Returns first-8 hex of a `WasmHashFetch` variant for divergence reporting.
///
/// `Sac` and `Absent` return distinguishable constant strings so divergence
/// messages can identify the exact mismatch without leaking full hash bytes.
fn wasm_hash_fetch_first8_hex(fetch: &WasmHashFetch) -> String {
    match fetch {
        WasmHashFetch::Wasm(hash) => hash[..8].iter().map(|b| format!("{b:02x}")).collect(),
        WasmHashFetch::Sac => "<SAC>".to_owned(),
        WasmHashFetch::Absent => "<Absent>".to_owned(),
    }
}

/// Redacts a strkey to first-5-last-5 characters for safe error reporting.
fn redact_strkey_first5_last5(strkey: &str) -> String {
    if strkey.len() <= 10 {
        return strkey.to_owned();
    }
    let (head, tail) = strkey.split_at(5);
    let last5 = &tail[tail.len() - 5..];
    format!("{head}\u{2026}{last5}")
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only fixture construction"
    )]

    use super::*;
    use stellar_agent_test_support::{echo_id_responder::EchoIdResponder, xdr_fixtures};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer};

    // ── Helpers ──────────────────────────────────────────────────────────────

    /// A testnet-format contract address (56 chars, starts with C).
    const TEST_CONTRACT: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM";

    fn wasm_result_json(wasm_hash: [u8; 32]) -> serde_json::Value {
        // Build the result JSON via xdr_fixtures then extract the result payload.
        // The full JSON-RPC envelope is built by EchoIdResponder.
        let full_json =
            xdr_fixtures::contract_instance_ledger_entries_json(TEST_CONTRACT, wasm_hash);
        let parsed: serde_json::Value = serde_json::from_str(&full_json).expect("valid json");
        parsed["result"].clone()
    }

    fn absent_result_json() -> serde_json::Value {
        serde_json::json!({"entries": null, "latestLedger": 100})
    }

    async fn mock_rpc_with_result(result: serde_json::Value) -> (MockServer, StellarRpcClient) {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(EchoIdResponder::new(result))
            .mount(&server)
            .await;
        let client = StellarRpcClient::new(&server.uri()).expect("valid URL");
        (server, client)
    }

    // ── Two-RPC divergence path ────────────────────────────────────────────

    /// Asserts that when primary and secondary return different hashes, the
    /// function returns `FetchContractWasmHashError::Divergent`.
    #[tokio::test]
    async fn two_rpc_divergence_returns_error() {
        let hash_a = [0xaau8; 32];
        let hash_b = [0xbbu8; 32];

        let (_s1, primary) = mock_rpc_with_result(wasm_result_json(hash_a)).await;
        let (_s2, secondary) = mock_rpc_with_result(wasm_result_json(hash_b)).await;

        let result = fetch_contract_wasm_hash(&primary, Some(&secondary), TEST_CONTRACT).await;

        assert!(
            matches!(result, Err(FetchContractWasmHashError::Divergent(_))),
            "expected Divergent; got {result:?}"
        );
        // Inspect divergence detail — must contain first-8 of each hash.
        if let Err(FetchContractWasmHashError::Divergent(e)) = result {
            assert_eq!(e.primary_first8, "aaaaaaaaaaaaaaaa");
            assert_eq!(e.secondary_first8, "bbbbbbbbbbbbbbbb");
        }
    }

    // ── Two-RPC agreement — Wasm ──────────────────────────────────────────

    #[tokio::test]
    async fn two_rpc_agreement_wasm_returns_hash() {
        let hash = [0x01u8; 32];
        let (_s1, primary) = mock_rpc_with_result(wasm_result_json(hash)).await;
        let (_s2, secondary) = mock_rpc_with_result(wasm_result_json(hash)).await;

        let result = fetch_contract_wasm_hash(&primary, Some(&secondary), TEST_CONTRACT).await;

        assert!(
            matches!(result, Ok(WasmHashFetch::Wasm(h)) if h == hash),
            "expected Wasm(hash); got {result:?}"
        );
    }

    // ── Single-RPC (no secondary) ──────────────────────────────────────────

    #[tokio::test]
    async fn single_rpc_absent_returns_absent() {
        let (_s, primary) = mock_rpc_with_result(absent_result_json()).await;
        let result = fetch_contract_wasm_hash(&primary, None, TEST_CONTRACT).await;
        assert!(
            matches!(result, Ok(WasmHashFetch::Absent)),
            "expected Absent; got {result:?}"
        );
    }

    // ── Primary absent, secondary wasm → divergence ────────────────────────

    #[tokio::test]
    async fn divergence_absent_vs_wasm() {
        let hash = [0x01u8; 32];
        let (_s1, primary) = mock_rpc_with_result(absent_result_json()).await;
        let (_s2, secondary) = mock_rpc_with_result(wasm_result_json(hash)).await;

        let result = fetch_contract_wasm_hash(&primary, Some(&secondary), TEST_CONTRACT).await;

        assert!(
            matches!(result, Err(FetchContractWasmHashError::Divergent(_))),
            "expected Divergent (Absent vs Wasm); got {result:?}"
        );
    }

    // ── Unavailable Display: no host/credential leakage ──────────────────

    /// Asserts that `FetchContractWasmHashError::Unavailable.to_string()` does
    /// NOT contain any credential substring embedded in the originating URL.
    ///
    /// `StellarRpcClient::get_ledger_entries` strips credentials from the URL
    /// before storing it in `NetworkError::RpcUnreachable.url`, so only
    /// `scheme://host[:port]` is retained. This test drives the error path
    /// end-to-end and asserts the credential string never reaches the formatter.
    #[tokio::test]
    async fn unavailable_display_does_not_leak_credentials() {
        // Build a client pointed at a URL that embeds userinfo credentials.
        // The RPC call will fail immediately (no server listening), which is
        // sufficient to trigger the Unavailable error path.
        let client = StellarRpcClient::new("https://user:secret-token@rpc.example.invalid")
            .expect("URL parses successfully");

        let result = fetch_contract_wasm_hash(&client, None, TEST_CONTRACT).await;

        let err = result.expect_err("expected RPC failure against an unreachable host");
        let display = err.to_string();
        let debug = format!("{err:?}");

        // The raw credential must not appear in Display or Debug output.
        assert!(
            !display.contains("secret-token"),
            "credential appeared in Display: {display}"
        );
        assert!(
            !debug.contains("secret-token"),
            "credential appeared in Debug: {debug}"
        );
        // The host should be present (authority-only form), but the userinfo must not.
        assert!(
            !display.contains("user:secret-token"),
            "full userinfo appeared in Display: {display}"
        );
    }

    /// Same credential-leak assertion as
    /// [`unavailable_display_does_not_leak_credentials`], but against a
    /// reachable server that returns HTTP 500 — exercising the post-connect
    /// transport-error path.
    #[tokio::test]
    async fn unavailable_display_does_not_leak_credentials_on_http_error() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        // Inject userinfo credentials into the mock server's URI.
        let credentialed = server.uri().replace("http://", "http://user:secret-token@");
        let client = StellarRpcClient::new(&credentialed).expect("credentialed mock URL parses");

        let result = fetch_contract_wasm_hash(&client, None, TEST_CONTRACT).await;

        let err = result.expect_err("expected RPC failure against an HTTP-500 server");
        let display = err.to_string();
        let debug = format!("{err:?}");

        assert!(
            !display.contains("secret-token"),
            "credential appeared in Display: {display}"
        );
        assert!(
            !debug.contains("secret-token"),
            "credential appeared in Debug: {debug}"
        );
    }

    // ── Depth-bomb regression ─────────────────────────────────────────────
    //
    // A `LedgerEntryData::ContractData` whose `val` field is a 600-deep
    // `ScVal::Vec` chain is returned by the mocked RPC. The bounded decoder
    // in `fetch_single_wasm_hash` must skip the entry (Err → continue) and
    // return `WasmHashFetch::Absent` rather than panicking with a stack
    // overflow. Without the depth bound the decode would be unbounded and
    // exhaust the stack.

    /// A `getLedgerEntries` response whose single entry carries a 600-deep
    /// `ScVal::Vec` chain in the `ContractDataEntry.val` field is skipped by
    /// the bounded decoder and the call returns `WasmHashFetch::Absent`.
    ///
    /// The fixture is encoded on a thread with an extended stack
    /// (32 MiB) because XDR encoding of a 600-deep `ScVal::Vec` chain is also
    /// recursive and overflows the default 8 MiB thread stack. Only the
    /// production decode path applies the depth bound; the encode-side stack
    /// extension is test-only scaffolding.
    #[tokio::test]
    async fn depth_bomb_ledger_entry_is_skipped_without_panic() {
        use stellar_strkey::Contract as StrkeyContract;
        use stellar_xdr::{
            ContractDataDurability, ContractDataEntry, ContractId, ExtensionPoint, Hash,
            LedgerEntryData, LedgerKey, LedgerKeyContractData, Limits, ScAddress, ScVal, ScVec,
            WriteXdr,
        };

        let contract = StrkeyContract::from_string(TEST_CONTRACT).expect("valid contract strkey");
        let sc_addr = ScAddress::Contract(ContractId(Hash(contract.0)));

        // Build a 600-deep `ScVal::Vec` chain iteratively (innermost first,
        // wrap outward). 600 > XDR_DECODE_MAX_DEPTH (500), so the bounded
        // decoder rejects it at the read side.
        let mut nested: ScVal = ScVal::Bool(false);
        for _ in 0..600 {
            nested = ScVal::Vec(Some(ScVec(
                vec![nested].try_into().expect("single-element ScVec"),
            )));
        }

        let entry_data = LedgerEntryData::ContractData(ContractDataEntry {
            ext: ExtensionPoint::V0,
            contract: sc_addr.clone(),
            key: ScVal::LedgerKeyContractInstance,
            durability: ContractDataDurability::Persistent,
            val: nested,
        });

        let key = LedgerKey::ContractData(LedgerKeyContractData {
            contract: sc_addr,
            key: ScVal::LedgerKeyContractInstance,
            durability: ContractDataDurability::Persistent,
        });

        // ENCODE on a thread with 32 MiB stack — write-side recursion for a
        // 600-deep ScVal::Vec overflows the default 8 MiB thread stack. The
        // extended stack is test-only; it is not available to the production
        // decode path, which remains bounded at XDR_DECODE_MAX_DEPTH.
        let (key_b64, val_b64) = std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(move || {
                let k = key.to_xdr_base64(Limits::none()).expect("key XDR encode");
                let v = entry_data
                    .to_xdr_base64(Limits::none())
                    .expect("entry XDR encode");
                (k, v)
            })
            .expect("thread spawn")
            .join()
            .expect("thread join");

        let result_json = serde_json::json!({
            "entries": [{
                "key": key_b64,
                "xdr": val_b64,
                "lastModifiedLedgerSeq": 100,
                "liveUntilLedgerSeq": 999_999
            }],
            "latestLedger": 100
        });

        let (_s, primary) = mock_rpc_with_result(result_json).await;
        let result = fetch_contract_wasm_hash(&primary, None, TEST_CONTRACT).await;

        // The depth-bomb entry is skipped (Err → continue in the loop);
        // no matching entry is found so the function returns Absent.
        assert!(
            matches!(result, Ok(WasmHashFetch::Absent)),
            "expected Absent (depth-bomb entry skipped); got {result:?}"
        );
    }

    // ── Display/Debug redaction audit ─────────────────────────────────────

    #[test]
    fn divergence_error_display_redacts_full_hash() {
        let err = WasmHashDivergenceError {
            contract_redacted: "CAAAA\u{2026}AAB".to_owned(),
            primary_first8: "aaaaaaaaaaaaaaa1".to_owned(),
            secondary_first8: "bbbbbbbbbbbbbbb2".to_owned(),
        };
        let display = err.to_string();
        // Full hex of a known hash must not appear
        let full_hash_hex: String = [0xaau8; 32].iter().map(|b| format!("{b:02x}")).collect();
        assert!(!display.contains(&full_hash_hex));
        assert!(display.contains("aaaaaaaaaaaaaaa1"));
    }
}
