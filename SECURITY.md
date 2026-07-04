# Security policy

This is the security policy for the Stellar Agent Wallet — a Stellar wallet for AI agents,
shipping the `stellar-agent` CLI binary and the `stellar-agent-mcp` MCP stdio server.
It covers which versions are supported, how to report a vulnerability, the scope of the
current public alpha, and a high-level summary of the security model.

## Supported versions

This project is a pre-1.0 public alpha. Only the latest `0.1.x` alpha is supported.

| Version | Supported |
| ------- | --------- |
| latest `0.1.x` | Yes |
| any older `0.1.x` | No |

There are no backports to earlier alpha builds. No tagged release exists yet, so build
from source (see the [README](README.md)) and report against the latest build.

## Reporting a vulnerability

Report security issues privately through GitHub private security advisories. Do not open
a public issue, discussion, or pull request for a security report.

1. Go to the repository [Security tab](https://github.com/Soneso/stellar-agent-wallet/security/advisories).
2. Choose "Report a vulnerability".
3. Submit the advisory with the details below.

Please include:

- A description of the vulnerability and its impact.
- Steps to reproduce, including any required profile configuration or environment.
- The affected version or commit (the `0.1.x` build, or the source commit you built from).
- Any proof-of-concept input, log excerpt, or transaction envelope — with secrets redacted.

Do not include real secret seeds, private keys, or keyring secrets in a report. The
wallet never logs argument values or secret material, and reports should follow the same
discipline; a redacted strkey or a SHA-256 digest is enough to identify an affected
account or envelope.

We handle reports under coordinated disclosure and aim to acknowledge and triage valid
reports in good faith as promptly as we can. We will keep you informed as we
investigate and work toward a fix. Please give us reasonable time to address an issue
before any public disclosure.

## Scope notes for the current alpha

Keep the following properties of the current alpha in mind when assessing impact.

- Writes and signing are testnet-only. Read-only commands accept both
  `stellar:testnet` and `stellar:mainnet`, but nearly all write and signing commands
  structurally refuse `stellar:mainnet` (wire code `network.mainnet_write_forbidden`)
  before any RPC call or signing takes place. The narrow exceptions are explicit,
  consent-gated mainnet operations (for example `smart-account migrate-verifier`, which
  requires `--confirm-mainnet-migrate`). Friendbot funding is scoped to `testnet` and
  `futurenet` and structurally refuses `mainnet`
  (`network.friendbot_mainnet_forbidden`).
- The threat model centers on an autonomous agent transacting under wallet guardrails:
  a policy engine, an out-of-band operator-approval spine, and a tamper-evident audit
  log. Reports that demonstrate an agent escaping or bypassing these guardrails — for
  example, executing a signing action that should have been denied, forced to approval,
  or recorded — are in scope and of high interest.
- A report that lets an autonomous agent reach `stellar:mainnet` for a write or signing
  action, despite the structural refusal (outside the explicitly consent-gated
  exceptions), is in scope.

Out of scope: defects in your own keyring backend, operating system, RPC endpoint, or
anchor; and issues that require already holding the wallet's keyring secrets (the seed,
nonce key, or HMAC keys), since custody of those secrets is the security boundary.

## Security model summary

For the full design see [docs/concepts.md](docs/concepts.md) and
[docs/maintainers/security-internals.md](docs/maintainers/security-internals.md). Key
properties:

- Keyring custody. The signing seed, the nonce key, and the HMAC keys live in the
  platform keyring. A profile is a per-environment TOML config that holds no secrets; it
  only names keyring entries by a service-plus-account keyring entry reference. Profile
  TOML is safe to back up.
- Unlock window with zeroize and mlock. To sign, the 32-byte signing seed is loaded into
  an unlock window: a short, TTL-bounded period (default 30s, hard cap 600s) during which
  the seed is resident in pinned, zeroize-on-drop memory (`mlock`). On every drop path —
  normal return, error propagation, or panic — the seed is zeroized and the lock
  released.
- Policy engine plus operator approval. Each tool or command is evaluated to Allow, Deny,
  or RequireApproval. The Noop engine allows everything on testnet, allows read-only on
  mainnet, and refuses mainnet destructive actions (`policy.engine_required`); the V1
  engine evaluates signature-verified typed criteria with first-match default-deny. When
  approval is required, the action is recorded in a per-profile pending-approval store and
  released only when the operator runs `approve`, which mints an HMAC-SHA256 attestation
  proving the keyring holder approved it. The attestation is constant-time verified and
  binds the approval nonce, the envelope SHA-256, and the OS process uid.
- Tamper-evident audit log. Every tool invocation and lifecycle event is appended to a
  per-profile hash-chained JSONL audit log. Argument values are never logged — only key
  names. The chain is verified end-to-end with `audit verify`.

The core library compiles under `#![forbid(unsafe_code)]`. Logging redaction is enforced
throughout: secret material is never written to logs, and account, strkey, and
transaction-hash fields are truncated at the output boundary.
