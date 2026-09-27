//! Dependency upgrades require inspection of the RPC client's XDR decodes.
//!
//! The wallet reads `getTransaction` raw. `StellarRpcClient::get_transaction_record`
//! deserializes `stellar-rpc-client`'s `GetTransactionResponseRaw` (28.0.0,
//! `src/lib.rs` lines 130-182, events at 186-208), which carries every XDR
//! field as base64, and decodes none of them. The wallet decodes those fields
//! itself, on demand, under `untrusted_decode_limits(encoded.len())`, bounding
//! depth to 500 and length to the encoded input size:
//!
//! - `TransactionRecord::result()`, called only by `map_failed_record` for a
//!   `FAILED` answer: the confirmation polls in `submit.rs` and
//!   `idempotent_submit.rs`, the idempotent stale-pending recovery, and
//!   spending-window reconciliation in `policy_state/store.rs`.
//! - `TransactionRecord::envelope()`, called by MPP reconciliation
//!   (`StellarReconciliationRpc`).
//! - `TransactionRecord::contract_events()`, called by the smart-account
//!   timelock event cross-confirmation.
//!
//! The result meta and the diagnostic events are never decoded.
//!
//! Of the typed calls the wallet still makes through the client, only
//! `sendTransaction` decodes XDR inside the client: its error result at lines
//! 1229-1236, with `Limits::depth(XDR_DEPTH_LIMIT)` (500, line 37) and no
//! length bound. A version change can move the raw type's fields or add
//! decodes to the typed calls, so this test fails until someone reads them
//! again and updates both this inventory and the boundary description in
//! `docs/maintainers/mpp.md`.

#[test]
fn reconciliation_decode_boundary_requires_pinned_client() {
    let lock = include_str!("../../../Cargo.lock");
    let versions: Vec<_> = lock
        .split("[[package]]")
        .filter(|package| {
            package
                .lines()
                .any(|line| line == "name = \"stellar-rpc-client\"")
        })
        .flat_map(|package| {
            package
                .lines()
                .filter(|line| line.starts_with("version = "))
        })
        .collect();
    assert_eq!(
        versions,
        ["version = \"28.0.0\""],
        "inspect the client's raw getTransaction type and its internal decodes, and update the RPC decode boundary documentation when its version changes"
    );
}
