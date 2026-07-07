# stellar-agent-toolsets-runtime

Capability-to-tool matrix and enforcement layer for installed toolsets in the stellar-agent-wallet.

This crate is the toolset isolation boundary. It provides the static, ungated capability-to-tool allowlist (`grants_for_capability`), a separate gated tier for signing-adjacent capabilities, an explicit signing/key/policy denylist of tools that are never grantable, closed-set typed refusal variants, the four-part enforcement function, the gated resolver entry point for the signing path, and an enumerator over installed toolsets.

Signing isolation is structural: the ungated matrix contains no signing, key, or policy tool regardless of any capability declaration, so even a toolset declaring every capability cannot reach a signing tool through the ungated path. The one gated signing tool is reachable only through the gated resolver, which requires both the four-part check and a current first-invoke grant, and any allow outcome from the policy engine is overridden to require per-action approval for toolset-routed payments.

It is part of the stellar-agent-wallet workspace and backs the toolset flows driven by the `stellar-agent-cli` and `stellar-agent-mcp` binaries rather than being used directly.

## Status

Pre-release alpha. APIs may change between alpha releases without notice.

## License

Apache-2.0. See the repository LICENSE file.

https://github.com/Soneso/stellar-agent-wallet
