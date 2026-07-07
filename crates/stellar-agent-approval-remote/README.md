# stellar-agent-approval-remote

TLS-protected, passkey-authenticated remote approval HTTP surface for the stellar-agent-wallet.

This crate lets an operator approve or reject pending agent actions from a device other than the wallet host, without SSH access. TLS is mandatory: there is no plaintext remote path. Every approve or reject action requires a fresh WebAuthn passkey assertion computed over a challenge cryptographically bound to the exact pending approval, so an assertion verified for one entry can never authorize a different entry.

Two independent authorization layers guard each action: the HTTP layer verifies the fresh assertion, and the core approval gate independently re-checks allowlist membership and the witness's entry binding. Enrollment of a new operator credential stays loopback-only and is never accepted over the network. The attestation this listener produces is byte-identical to the local loopback path's; the distinction between local and remote approval lives only in the audit log.

It is part of the stellar-agent-wallet workspace. The listener is bound by the `stellar-agent-cli` `approve serve --remote` flow rather than used directly.

## Status

Pre-release alpha. APIs may change between alpha releases without notice.

## License

Apache-2.0. See the repository LICENSE file.

https://github.com/Soneso/stellar-agent-wallet
