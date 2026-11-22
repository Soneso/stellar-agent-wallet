# stellar-agent-toolsets-runtime

Capability-to-tool matrix and enforcement layer for installed toolsets in the stellar-agent-wallet.

This crate is the toolset isolation boundary. It provides:

- the static, ungated capability-to-tool allowlist (`grants_for_capability`)
- a separate gated tier for signing-adjacent capabilities
- an explicit signing/key/policy denylist of tools that are never grantable
- closed-set typed refusal variants
- the four-part enforcement function
- the gated resolver entry point for the signing path
- an enumerator over installed toolsets

Signing isolation is structural: the ungated matrix contains no signing, key, or policy tool regardless of any capability declaration, so even a toolset declaring every capability cannot reach a signing tool through the ungated path. The two gated signing tools, `stellar_pay_commit` (`sign-payment`) and `stellar_rule_create_commit` (`sign-rule-create`), are reachable only through the gated resolver, which requires both the four-part check and a current first-invoke grant. A toolset-routed payment requires per-action approval when the routed payment rule or the outer `stellar_toolset_invoke` rule returns `RequireApproval`. A composed `Allow` submits under a current first-invoke grant without another approval. A toolset-routed rule-create commit always requires its per-proposal attestation.

It is part of the stellar-agent-wallet workspace and backs the toolset flows of the `stellar-agent` executable, CLI and MCP server alike, rather than being used directly.

## Status

Pre-release alpha. APIs may change between alpha releases without notice.

## License

Apache-2.0. See the repository LICENSE file.

https://github.com/Soneso/stellar-agent-wallet
