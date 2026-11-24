# stellar-agent-approval-ui

Localhost approval-inbox web UI for the stellar-agent-wallet.

This crate runs a loopback HTTP server that gives the operator a browser view of the pending-approval queue that would otherwise be actioned only from a terminal. It renders the wallet-controlled summary for each pending entry and drives the same attest/reject spine as the CLI.

The server refuses any non-loopback bind address. A one-time bootstrap token is exchanged for a session proof and an `HttpOnly; SameSite=Strict` session cookie with a per-listener name. The bootstrap page keeps the proof in the tab's `sessionStorage`. Every other route except the bootstrap page's fixed script requires the cookie, and an absent, mismatched or expired cookie collapses to a `404` so no route reveals that a session concept exists. A decision POST carries the session proof and a per-nonce CSRF token, and the activity POST carries the proof and a CSRF token for a fixed label, all checked server-side in constant time. Browsers send loopback cookies to every port on the host, so another local service can receive the cookie. `sessionStorage` is scoped to the full origin, so that service cannot read the proof and cannot approve or reject. It can still read what the cookie authorizes until the session ends. A session expires after 15 minutes without operator activity or 8 hours after the bootstrap exchange; background polling does not extend it. The server never touches signing keys or private key material; the attestation key is read from the platform keyring inside the decision seam and when the detail page shows an attested trustline clawback opt-in again, and it is zeroized after use.

It is part of the stellar-agent-wallet workspace and is launched by the `stellar-agent-cli` approve flow rather than used directly.

## Status

Pre-release alpha. APIs may change between alpha releases without notice.

## License

Apache-2.0. See the repository LICENSE file.

https://github.com/Soneso/stellar-agent-wallet
