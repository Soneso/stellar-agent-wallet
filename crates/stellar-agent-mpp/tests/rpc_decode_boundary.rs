//! Dependency upgrades require inspection of reconciliation's internal XDR decodes.
//!
//! `get_transaction` decodes its response inside the client, so the wallet
//! cannot bound those decodes the way it bounds the simulation fields it
//! receives encoded. In `stellar-rpc-client` 28.0.0's `src/lib.rs`,
//! `get_transaction` at line 1324 converts `GetTransactionResponseRaw`; that
//! conversion begins at line 230 and decodes result metadata at line 237,
//! contract, diagnostic and transaction events at lines 255, 267 and 276, the
//! top-level diagnostic events of a failed transaction at line 303, the
//! envelope at line 317, and the result at line 321, each with
//! `Limits::depth(XDR_DEPTH_LIMIT)` (500, line 37): depth-bounded, with no
//! length bound. A version change moves those lines and may change the
//! limits, so this test fails until someone reads them again and updates both
//! this inventory and the boundary description in `docs/maintainers/mpp.md`.

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
        "inspect the client's get_transaction conversion and update the trusted-RPC decode boundary documentation when its version changes"
    );
}
