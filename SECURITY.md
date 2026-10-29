# Security policy

See [Mainnet configurations and scope](docs/getting-started.md#mainnet-configurations-and-scope)
for build configuration, admitted operations, and exclusions.

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

There are no backports to earlier alpha builds. Install the latest tagged release
(see the [README](README.md) for the release archives and crates.io install paths)
or build from source, and report against that latest build.

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
wallet never logs secret material or raw argument values, and reports should follow the same
discipline; a redacted strkey or a SHA-256 digest is enough to identify an affected
account or envelope.

We handle reports under coordinated disclosure and aim to acknowledge and triage valid
reports in good faith as promptly as we can. We will keep you informed as we
investigate and work toward a fix. Please give us reasonable time to address an issue
before any public disclosure.

## Scope notes for the current alpha

Keep the following properties of the current alpha in mind when assessing impact.

- Released binaries have `mainnet-write` disabled. With the feature off, no code
  path in the shipped binary can satisfy the mainnet-write guard, and the binary
  attests its feature state.
  The guarantee has one precondition: the claim holds only under the dependency
  set pinned and verified by the release.
  Feature-enabled builds admit only configured operations with per-action approval.
  Policy evaluation alone grants no signing authority. Signing, submission, and
  x402 payload release independently check sealed authorization.
  The wallet's own signing paths sign mainnet payloads only under mainnet
  authorization. Library signing primitives do not enforce this requirement.
  Code running as the same OS user with access to a keyring entry can read its
  seed directly. The keyring entry is the custody boundary.
  The endpoint's network binds each envelope signature.
  Read-only commands accept both `stellar:testnet` and `stellar:mainnet`.
  Every MPP tool refuses mainnet with `mpp.network_forbidden`.
  `smart-account rules verify-pins`, `signers list`, and `signers refresh` retain
  local audit writes without signing or writing on chain. Friendbot funding is
  scoped to testnet and futurenet and refuses mainnet with
  `network.friendbot_mainnet_forbidden`.

- The threat model centers on an autonomous agent transacting under wallet guardrails:
  a policy engine, an out-of-band operator-approval spine, and a tamper-evident audit
  log. Reports that demonstrate an agent escaping or bypassing these guardrails — for
  example, executing a signing action that should have been denied, forced to approval,
  or recorded — are in scope and of high interest.
- Unauthorized mainnet signing, payload release, or submission is a reportable
  violation.

Out of scope: defects in your own keyring backend, operating system, RPC endpoint, or
anchor; and issues that require already holding the wallet's keyring secrets (the seed,
nonce key, or HMAC keys), since custody of those secrets is the security boundary.

For code running as the same OS user, the owner of an enabled mainnet profile
changes only with a statement signed by the previous owner. The policy pin and
the enablement nonce that carry this continuity sit at the profile's default
window-state entry, and a mainnet profile that names another entry is refused.
Raw deletion of the pin, enablement, and owner entry outside the wallet rests
on the platform keyring.

## Security model summary

For the full design see [docs/concepts.md](docs/concepts.md) and
[docs/maintainers/security-internals.md](docs/maintainers/security-internals.md). Key
properties:

- Keyring custody. The signing seed, the nonce key, and the HMAC keys live in the
  platform keyring. A profile is a per-environment TOML config that names keyring entries
  by a service-plus-account keyring entry reference instead of holding keys. An endpoint
  URL can embed a credential in its path or query on any network. Mainnet refuses only
  a username or password in the URL. Profile TOML is safe to back up only when no
  endpoint URL embeds a credential.
- Unlock window with zeroize and mlock. When a CLI command signs with a seed read from a
  `--*-secret-env` variable, the 32-byte seed is loaded into an unlock window. The window
  is a short, TTL-bounded period (default 30s, hard cap 600s) during which the seed is
  resident in pinned, zeroize-on-drop memory (`mlock`). On every drop path (normal
  return, error propagation, or panic) the seed is zeroized and the lock released.
  Keyring signers, the Ledger, and the MCP server never enter the window. A keyring
  signer loads its key for each signature into a zeroize-on-drop buffer without a
  memory lock.
- Policy engine plus operator approval. The MCP dispatch gate and the CLI value-moving
  verbs evaluate each action to Allow, Deny, or RequireApproval. Read-only CLI commands
  such as `balances` evaluate no policy. The Noop engine allows everything on testnet, allows read-only on
  mainnet, and refuses mainnet destructive actions (`policy.engine_required`); the V1
  engine evaluates signature-verified typed criteria with first-match default-deny.
  A verified policy alone does not confer mainnet authorization. When
  approval is required, the action is recorded in a per-profile pending-approval store and
  released only when the operator runs `approve`, which mints an HMAC-SHA256 attestation
  proving the keyring holder approved it. The attestation is constant-time verified and
  binds the approval nonce, the envelope SHA-256, and the OS process uid.
- Tamper-evident audit log. Approvals, submission lifecycle events, and explicit
  authorization, key-management, and lifecycle events are appended to a per-profile
  hash-chained JSONL audit log. A balance read writes no row.
  The raw argument map is recorded as key names only. Typed value events retain each
  leg's amount, asset, and redacted destination. The chain is verified end-to-end with `audit verify`. The value-moving signing and
  submitting verbs are `pay`, `claim`, `accounts create`, `trustline`, `trade`,
  `vault`, the x402 payment tools, and the MPP charge commit. Each proves its audit writer
  is acquirable BEFORE the signing key is touched or a transaction is submitted. It refuses
  with `audit.chain_key_unavailable` rather than signing unaudited when the profile's
  audit chain-root key was never minted. This pre-flight fails closed for a persisted profile.
  `pay`, `claim`, and `accounts create` fall back to the zero-config synthesized profile
  when no profile was named and no `default.toml` file exists. That profile stays
  fail-open for this check, matching its documented no-profile-required posture. The SEP-43 sign-only pair (`signTransaction`,
  `signAuthEntry`) runs the same pre-flight and records an
  `opaque_payload_signed` audit row when the signature is produced. The x402 tools
  write `x402_payment_authorized` before the signed authorization leaves the wallet in
  the RPC re-simulation, and withhold it when that row cannot be written. An approval or
  rejection takes effect only after its audit row is durable, in the log or in the
  log's outbox. A queued row reaches the log before the consumer of the approval loads
  a signing key.
- Code running as the same OS user. Such code can write the audit log and the wallet's
  files. The wallet detects an edited or removed entry inside the log, a log rolled back
  or truncated behind the tip anchor the keyring holds, a deleted anchor on a log that
  shows it was anchored (`audit.tip_anchor_missing`), and a changed audit binding.
  For an empty active file, only a surviving sidecar establishes prior anchoring.
  These conditions refuse value-moving verbs. After investigation, `audit reanchor`
  accepts an intact prefix and records the acknowledgement; it refuses a broken chain.
  Profile verification checks the chain and HMAC sidecars before anchor agreement,
  unless the missing-anchor rule applies after an unkeyed chain walk. The wallet does
  not detect a well-formed entry appended at the tip. Raw
  deletion or restore of platform keyring items outside the wallet, together with a
  matching log, rests on the platform keyring's own access control. A headless keyring
  backend keeps those items in a file that same-user code can restore, so mainnet
  readiness and `profile enable-mainnet` refuse it
  (`network.mainnet_keyring_backend_unsupported`).

The core library compiles under `#![forbid(unsafe_code)]`. Logging redaction is enforced
throughout: secret material is never written to logs, and account, strkey, and
transaction-hash fields are truncated at the output boundary.
