# stellar-agent-loopback-http

Internal support crate for the stellar-agent-wallet.

This crate is the single implementation of the tower/axum defence-in-depth middleware shared by the workspace's loopback-only HTTP listeners (the WebAuthn bridge and the approval UI). It provides three layers against the browser-facing threat model those listeners share: a `Host:` header allowlist for DNS-rebinding defence, an `Origin:` header allowlist on state-changing methods, and hardened response headers with a Content-Security-Policy on every response. Each consumer constructs the layers with its own bound socket address; the crate exposes no router or server surface of its own.

It is published as part of the stellar-agent-wallet workspace to complete the dependency graph on crates.io and is not designed for standalone use.

## Status

Pre-release alpha. APIs may change between alpha releases without notice.

## License

Apache-2.0. See the repository LICENSE file.

https://github.com/Soneso/stellar-agent-wallet
