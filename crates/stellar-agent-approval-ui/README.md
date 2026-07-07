# stellar-agent-approval-ui

Localhost approval-inbox web UI for the stellar-agent-wallet.

This crate runs a loopback HTTP server that gives the operator a browser view of the pending-approval queue that would otherwise be actioned only from a terminal. It renders the wallet-controlled summary for each pending entry and drives the same attest/reject spine as the CLI.

The server refuses any non-loopback bind address. A one-time bootstrap token is exchanged for an `HttpOnly; SameSite=Strict` session cookie; every other route requires that cookie, and an absent or mismatched cookie collapses to a `404` so no route reveals that a session concept exists. State-changing POSTs carry a per-nonce CSRF token that is recomputed and constant-time-compared server-side. The server never touches signing keys or private key material; the attestation key is read from the platform keyring only inside the decision seam and zeroized after use.

It is part of the stellar-agent-wallet workspace and is launched by the `stellar-agent-cli` approve flow rather than used directly.

## Status

Pre-release alpha. APIs may change between alpha releases without notice.

## License

Apache-2.0. See the repository LICENSE file.

https://github.com/Soneso/stellar-agent-wallet
