# stellar-agent-loopback-http

Internal support crate for the stellar-agent-wallet.

This crate is the single implementation of what the workspace's browser-facing HTTP listeners share. Its consumers are the WebAuthn bridge and the loopback approval UI, both bound to the loopback interface, and the remote-approval surface, which is served over TLS on a private network and shares the same browser-facing threat model.

It provides three tower/axum middleware layers: a `Host:` header allowlist for DNS-rebinding defence, an `Origin:` header allowlist on state-changing methods, and hardened response headers with a Content-Security-Policy on every response. Each consumer constructs the layers with its own bound socket address; the crate exposes no router or server surface of its own.

The `brand` module carries the presentation those listeners' pages share: `BRAND_STYLE` (the stylesheet with the design tokens and the common components), `BUDDY_MARK_SVG` (the inline brand mark), and the card fragments the single-card pages repeat. They are constants emitted inline rather than served assets, because the Content-Security-Policy above admits no external origin and a self-hosted wallet has no CDN to fall back to. Nothing in the module emits a script, an event-handler attribute, or an external URL.

It is published as part of the stellar-agent-wallet workspace to complete the dependency graph on crates.io and is not designed for standalone use.

## Status

Pre-release alpha. APIs may change between alpha releases without notice.

## License

Apache-2.0. See the repository LICENSE file.

https://github.com/Soneso/stellar-agent-wallet
