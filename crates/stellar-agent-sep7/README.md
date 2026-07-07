# stellar-agent-sep7

SEP-7 `web+stellar:` inbound URI parsing and anti-phishing signature verification for the stellar-agent-wallet.

This crate receives `web+stellar:tx/pay?<params>` URIs from untrusted dApps, parses them into a structured preview with strict validation, and optionally verifies the dApp signature against a freshly fetched `stellar.toml`. It never signs a URI, never auto-POSTs to a callback endpoint, never submits a transaction automatically, and never uses a cached `stellar.toml` for signature verification.

SEP-7 signatures carry no nonce or timestamp, so they authenticate origin and protect integrity but do not prevent replay; the parse tool is stateless, and the operator or MCP host layer must enforce idempotency if replay protection is needed.

It is part of the stellar-agent-wallet workspace. Most users interact with it through the `stellar_sep7_parse_uri` tool in `stellar-agent-mcp` rather than directly.

## Status

Pre-release alpha. APIs may change between alpha releases without notice.

## License

Apache-2.0. See the repository LICENSE file.

https://github.com/Soneso/stellar-agent-wallet
