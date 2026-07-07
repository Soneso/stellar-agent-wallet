# stellar-agent-webauthn-bridge

Localhost WebAuthn browser-handoff bridge for the stellar-agent-wallet.

This crate runs a loopback HTTP listener that ferries WebAuthn ceremony bytes from the operator's browser into the wallet-owned approval spine. It binds exclusively to a loopback address (a random OS-assigned port by default, preventing port-scan guessing) and exposes two entry points: one for registration-only sessions and one for signing sessions, where the caller injects a pubkey lookup so an assertion route can resolve the registered credential before verifying it. Both return a handle for querying the bound port and requesting graceful shutdown.

The listener applies the shared `stellar-agent-loopback-http` defence stack (Host allowlist for DNS-rebinding defence, hardened response headers with CSP, and an Origin allowlist on state-changing methods), the same layers used by the approval UI.

It is part of the stellar-agent-wallet workspace and is launched by the wallet's approval flows rather than used directly.

## Status

Pre-release alpha. APIs may change between alpha releases without notice.

## License

Apache-2.0. See the repository LICENSE file.

https://github.com/Soneso/stellar-agent-wallet
