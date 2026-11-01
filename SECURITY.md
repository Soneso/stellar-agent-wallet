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

- Released binaries have `mainnet-write` on. With the feature on, only a typed
  authorization issued for the action can satisfy the mainnet-write guard, and
  the binary attests its feature state. A build with `--no-default-features`
  has the feature off, and no code path in it can satisfy the guard.
  The guarantee has one precondition: the claim holds only under the dependency
  set pinned and verified by the release.
  Feature-enabled builds admit only configured operations with per-action approval.
  Policy evaluation alone grants no signing authority. Signing, submission, and
  x402 payload release independently check sealed authorization.
  The wallet's own signing paths sign mainnet payloads only under mainnet
  authorization. The library signers enforce it too: every `Signer`, the
  public keyring handle included, signs a mainnet transaction or Soroban
  authorization payload only under a mainnet authorization.
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
nonce key, or HMAC keys), since custody of those secrets is the security boundary. On
mainnet the attestation HMAC key alone mints no consent: a mainnet approval also needs
a verified passkey assertion from an approval credential in the owner-signed policy.
Two residues remain. A same-user process that holds the HMAC key can wrap a version 5
record around a user-verified assertion that its own localhost page obtained, so a
misleading local page is a residue. The owner seed admits approval credentials, so
signing the policy on a host where same-user code runs exposes that seed.

For code running as the same OS user, the owner of an enabled mainnet profile
changes only with a statement signed by the previous owner. The policy pin and
the enablement nonce that carry this continuity sit at the profile's default
window-state entry, and a mainnet profile that names another entry is refused.
Raw deletion of the pin, enablement, and owner entry outside the wallet rests
on the platform keyring.

Mainnet consent requires a fresh WebAuthn assertion with user presence and user
verification from a credential in the owner-signed policy. The assertion binds the
exact consent, request, profile, chain and policy. The wallet verifies it before
recording consent and again before mainnet authorization. Terminal input and a
same-user process identity provide no mainnet presence proof.

User verification is the authenticator's signed statement that its configured
verification ceremony succeeds. It does not prove that a human reads or understands
the transaction. The browser displays the transaction; the authenticator need not
display it. Credential enrollment verifies a registration response and a terminal code,
and the owner admits the public key by signing the policy. The wallet does not certify
authenticator hardware or detect credential clones from signature counters.

These checks constrain actions through the wallet. Same-user code with an extracted
signing seed can sign outside those paths. Protection of authenticator private keys,
user-verification prompts, browser integrity and platform keyring items rests on the
platform. Raw deletion or restoration of keyring state outside wallet commands also
rests on the platform. A compromised authenticator or browser, a misleading approval
page outside the wallet, or an operator approving an unwanted request can defeat the
intended consent. The wallet requires the signed proof and does not claim an
operating-system security boundary against all same-user code.

Mainnet approve, the local inbox, and direct CLI confirmation open a localhost
passkey page. The operator reviews the authoritative transaction and approves
with an owner-pinned credential. Headless consent, `--yes`, `--no-open` on the
mainnet inbox, and remote mainnet approval refuse. Ledger signing also requires
this passkey ceremony.

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
- Unlock window with zeroize and mlock. CLI environment signing copies the
  borrowed seed into an isolated home after the configured lock attempt.
  The clock bounds wallet seed access and transfer, default 30 seconds, cap 600.
  The seed stays in a zeroize-on-drop page, locked when the lock succeeds, until
  its wallet or signer drops it. Drop zeroizes before unlocking and freeing,
  including during unwind.
  Mainnet environment signers unlock once per signature and drop the seed afterward.
  Testnet environment signers keep it for the command, which can outlast the TTL.
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
  binds the approval nonce, the envelope SHA-256, and the OS process uid. A mainnet
  approval is a version 5 attestation that also binds a verified passkey assertion from
  an approval credential in the owner-signed policy; terminal input and the HMAC key
  alone record no mainnet consent.
- Settlement on an independent answer. On mainnet a spending-window reservation
  is released only on the answer of the oracle named by `oracle_provider_url`,
  once that oracle reports the mainnet passphrase: a failure, refusal, or
  unknown outcome the primary endpoint reports keeps the reservation until the
  oracle confirms it or the operator clears it.
- Tamper-evident audit log. Approvals, submission lifecycle events, and explicit
  authorization, key-management, and lifecycle events are appended to a per-profile
  hash-chained JSONL audit log. A balance read writes no row.
  The raw argument map is recorded as key names only. Typed value events retain each
  leg's amount, asset, and redacted destination. Once the log holds its
  `audit_entry_tags_started` boundary row, every entry carries a keyed entry tag
  derived from the profile's audit key. The chain is verified end-to-end with `audit verify`;
  `audit verify --profile` checks the chain and the entry tags. The value-moving signing and
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
  a signing key. Queued rows are committed by count and SHA-256 chain head in the
  platform keyring, and only committed operator rows drain. A removed, changed, or
  reordered committed row, a line past the commitment, or a committed row of
  another kind refuses keyed acquisition until `audit acknowledge-outbox-loss`
  records the loss and revokes decided approvals and toolset grants. An absent outbox state reads as zero;
  raw deletion or restore of that keyring entry shares the boundary below.
  The queue commitment does not authenticate who appended a row.
- Code running as the same OS user. Such code can write the audit log and the wallet's
  files. The wallet detects an edited or removed entry inside the log, a log rolled back
  or truncated behind the tip anchor the keyring holds, a deleted anchor on a log that
  shows it was anchored (`audit.tip_anchor_missing`), and a changed audit binding.
  For an empty active file, only a surviving sidecar establishes prior anchoring.
  These conditions refuse value-moving verbs. After investigation, `audit reanchor`
  accepts an intact prefix and records the acknowledgement; it refuses a broken chain.
  Profile verification checks the chain and HMAC sidecars before anchor agreement,
  unless the missing-anchor rule applies after an unkeyed chain walk. Past the
  boundary row, an appended entry without a valid entry tag is refused by keyed
  writers (`audit.tip_anchor_mismatch`, reason `unauthenticated_tail`) and by
  `audit verify --profile` (`audit.entry_tag_invalid`), and readers stop at the
  writer's verified tip. Still open: code that can read the audit key can compute
  valid tags, rows before the boundary row rest on the anchor alone, `audit verify`
  without `--profile` checks no tag, and zero-config logs carry no tags. Raw
  deletion or restore of platform keyring items outside the wallet, together with a
  matching log, rests on the platform keyring's own access control. A headless keyring
  backend keeps those items in a file that same-user code can restore, so mainnet
  readiness and `profile enable-mainnet` refuse it
  (`network.mainnet_keyring_backend_unsupported`).

The core library compiles under `#![forbid(unsafe_code)]`. Logging redaction is enforced
throughout: secret material is never written to logs, and account, strkey, and
transaction-hash fields are truncated at the output boundary.
