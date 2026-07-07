# stellar-agent-sep43

SEP-43 Wallet Protocol dispatch substrate for the stellar-agent-wallet.

This crate implements the agent-side SEP-43 `ModuleInterface`, covering the five methods `get_address`, `sign_transaction`, `sign_auth_entry`, `sign_message`, and `get_network`. It provides a typed `Sep43Error` enum (each variant carries a stable wire code and a spec-compliant JSON serialiser), active-address resolution across the classic-G, smart-account-C, and muxed-M kinds, strkey validation, the async `ModuleAdapter` trait, and the concrete `StellarAgentModule` implementation that dispatches each method.

It does not implement the optional submit/submitUrl options of `signTransaction`; transactions are returned signed, not submitted.

It is part of the stellar-agent-wallet workspace. Most users interact with it through the five `stellar_sep43_*` tools in `stellar-agent-mcp` rather than directly.

## Status

Pre-release alpha. APIs may change between alpha releases without notice.

## License

Apache-2.0. See the repository LICENSE file.

https://github.com/Soneso/stellar-agent-wallet
