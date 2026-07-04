# Concepts: the security and governance model

This document explains how the Stellar Agent Wallet lets an autonomous agent transact while keeping the agent inside guardrails it cannot bypass. It covers key custody, the policy engine, the operator-approval spine, the audit log, and smart-account authorization rules. It is conceptual; for command syntax see the [CLI reference](cli-reference/profile-and-governance.md), and for profile fields see [Profiles](profiles.md).

## The problem this model solves

An AI agent calls wallet tools on its own initiative. The model does not assume the agent is correct or honest. Instead, the wallet places fixed controls between every tool call and any network or signing action:

- A **policy engine** evaluates each call to allow, deny, or require approval, before any RPC call or signature.
- Out-of-band **operator approval** is required for the cases the policy engine flags, and the approval is cryptographically bound to the exact transaction that will be signed.
- A **hash-chained audit log** records every invocation so tampering is detectable after the fact.
- **Key custody** keeps the signing seed out of the agent's reach: it lives in the platform keyring and is only briefly resident in pinned memory.

Two structural rules apply across all surfaces in this alpha. The default network is `stellar:testnet`. Every write or signing command structurally refuses `stellar:mainnet` (wire code `network.mainnet_write_forbidden`) before any RPC call or signing, while `stellar:mainnet` remains accepted for read-only commands.

## Two account models

The wallet operates against two different kinds of Stellar account, and each command belongs to one of them. Knowing which model a command uses tells you what you must have in place before it can run.

**Classic account operations** work with a keyring-held ed25519 key on its own. There is no contract to deploy: the source account is a standard Stellar account and the signing key is the account's secret. These commands are `pay`, `balances`, `trustline`, `claim`, and `pool`. The read-only helpers `friendbot` (testnet funding) and `fees` (network fee stats) sit in the same bucket, as does `accounts create`, which creates a plain classic account. If you hold a funded classic key, you can run any of these directly.

**Smart-account operations** center on a deployed OpenZeppelin smart-account contract. The contract holds the context rules, signer sets, thresholds, and policy attachments; the keyring key signs as a delegated signer rather than as the account itself. The commands that operate against an existing contract — `trade`, `lend`, the `vault` write verbs, and `smart-account rules`, `signers`, `list-rules`, `migrate-verifier`, `timelock`, plus `multicall` (which names its target via `--smart-account`) — cannot run until that contract address exists. Four verbs in the `smart-account` group (alias `sa`) need no deployed contract: `list-verifiers` reads the compile-time verifier allowlist, `register-multicall` and `unregister-multicall` edit the local per-network router registry, and `deploy-webauthn-verifier` deploys a new verifier contract from a classic deployer key.

**Bootstrapping** bridges the two. `accounts deploy-c` is itself a classic operation — the deployer signs the deployment with a keyring key — but its *output* is a new smart-account contract address. That address is the prerequisite the second bucket needs. So the usual path is: fund a classic key (`friendbot` on testnet), deploy the contract (`accounts deploy-c`), then install rules and signers (`smart-account rules`, `smart-account signers`) before the agent can trade, lend, or run vault writes through it.

A handful of commands need neither model directly. `profile`, `credentials`, `approve`, `audit`, `toolsets`, and `counterparty` operate at the profile and operator layer — they configure the wallet, manage the approval spine and audit trail, or resolve counterparty metadata, independent of any single account.

### Prerequisite map

| Command group | Account model | What you need first |
|---|---|---|
| `pay`, `balances`, `trustline`, `claim`, `pool`, `friendbot`, `fees` | Classic | A funded classic keyring key (`friendbot` funds one on testnet). |
| `accounts create` | Classic | A keyring key to hold the new account's secret. |
| `accounts deploy-c` | Classic (bridge) | A funded classic deployer key; the command's output is the smart-account contract address. |
| `smart-account` (alias `sa`) | Smart-account | For `rules`, `signers`, `list-rules`, `migrate-verifier`, `timelock`, `multicall`: a deployed OZ smart-account contract address (from `accounts deploy-c`), plus at least one signer or context rule installed for write verbs. `list-verifiers`, `register-multicall`, `unregister-multicall`, and `deploy-webauthn-verifier` need no deployed contract. |
| `trade`, `lend`, `vault` (writes) | Smart-account | A smart-account contract address with a context rule authorizing the operation. |
| `profile`, `credentials`, `approve`, `audit`, `toolsets`, `counterparty` | Neither | An initialized profile; these operate at the profile/operator layer. |

## Key custody and the unlock window

Secrets are never stored in configuration. A Profile is a per-environment TOML file (schema version 2) that binds a CAIP-2 chain id, an RPC endpoint, keyring entry references, thresholds, and the active policy engine. It holds no secret material; each `*_key_id` field is a Keyring entry reference (a `service` + `account` pair) that names a platform-keyring secret. The signer seed, the nonce key, and every HMAC key live in the platform keyring (macOS Keychain, Linux Secret Service, Windows Credential Manager). The profile TOML is therefore safe to back up. The profile's `Debug` output additionally redacts `rpc_url` and `secondary_rpc_url`, since those may embed RPC credentials.

When a tool needs to sign, the 32-byte signing seed is loaded into a short Unlock window:

- The seed is moved into a zeroize-on-drop buffer, and its backing page is pinned in physical RAM via `mlock` (Linux/macOS) or `VirtualLock` (Windows). Pinning the page keeps the seed out of swap.
- The window is TTL-bounded. The default is 30 seconds; the value is downward-only configurable per profile and the hard cap is 600 seconds. A background timer fires at the TTL and marks the wallet disposed.
- On every exit path, including normal return, error propagation, and panic-unwind, the seed is zeroized and the lock released.

The `mlock_required` posture in `[wallet]` controls what happens when pinning fails. The value `true` (default on Linux/macOS) fails closed and aborts the unlock; `"warn"` (default on Windows) proceeds with unprotected memory and emits a warning; `false` proceeds silently, with the operator accepting the swap-disclosure risk. No path logs the seed.

```toml
[wallet]
mlock_required = true       # default on Linux/macOS
unlock_ttl_seconds = 30     # default; downward-only
```

## The policy engine

Every tool or command invocation is evaluated by the active Policy engine before it does anything. The engine returns one of three decisions:

- **Allow** — the call proceeds.
- **Deny** — the call is refused, carrying a typed reason.
- **RequireApproval** — the call is held pending an out-of-band operator approval.

Which engine runs is selected per profile in `[policy]`.

### Noop engine

The Noop engine is the binding gate used when no full engine is configured. Its behavior is fixed:

| Profile | Tool | Result |
|---------|------|--------|
| testnet | any | Allow |
| mainnet | read-only | Allow |
| mainnet | destructive | refused with `policy.engine_required` |

A destructive tool on a mainnet profile cannot pass the Noop engine. Newly minted profiles default to the V1 engine; profiles carried over from schema version 1 are set to Noop explicitly so they retain the mainnet gate until the operator completes the key-rotation steps that stand up a V1 owner key.

### V1 engine

The V1 engine evaluates a signed policy document against typed Criteria. The document carries an ed25519 owner signature over its canonical form; an invalid signature, or a signature from a key that was rotated after signing, is rejected.

Evaluation is **first-match, default-deny**:

1. Rules are walked in declaration order.
2. The first rule whose match (tool name plus chain-id filter) applies is selected.
3. That rule's criteria run in order; the first failing criterion produces a Deny.
4. If all criteria pass, the rule's decision is returned.
5. If no rule matches, the call is denied (`no_matching_rule`).

A Criterion is one typed check. The available criteria include per-transaction cap, per-period (windowed) cap, rate limit, counterparty allowlist (by classic account, contract account, asset issuer, or resolved home domain; the `SEP10_IDENTITY` and `ONE_TIME_ADDRESS` kinds are reserved and not yet evaluated), minimum-reserve guard, Soroban resource-fee cap, bundle-level checks for multicall (inner-count cap, aggregate cap, rejection of unrecognized inner shapes), quorum satisfaction, a home-domain-resolved guard (requires the destination's on-chain `home_domain` to have been resolved and cached), and SEP-10 / SEP-45 session-active checks. Criteria that need external state (account reserves, account identity, the counterparty cache, an active session) receive that state as an injected view at the dispatch site; when a required session or cache view is absent, the criterion fails closed rather than passing.

Each Deny carries a structured reason with a stable wire code. At the MCP boundary, account, strkey, and contract-id fields inside a deny reason are redacted to first-five-last-five characters before they cross the wire.

The tool registry is also fail-closed at startup: a duplicate tool registration, or an unrecognized policy-engine kind, is a fatal error rather than a silent fallback. This prevents a registration that mislabels a destructive tool as read-only from shadowing the real one and slipping past the mainnet gate.

## The approval spine

When the policy engine returns RequireApproval, the action does not proceed on the agent's say-so. It is held in the Approval spine until the operator approves it out-of-band — interactively with `approve --id`, or through the loopback approval inbox started by `approve serve`, which lists pending entries (`approve list` does the same in the terminal), notifies the operator, and drives the identical attestation path. The spine is a per-profile pending-approval store plus a cryptographic Attestation minted at approve time. Both approval surfaces record an audit event; an inbox rejection replaces the entry with a short-lived rejection marker so the agent's commit is refused with `policy.approval_rejected` rather than the generic pending code.

### The pending-approval store

The store is a per-profile TOML file holding a flat list of pending entries:

- A single exclusive advisory lock on a sidecar lock file is held for the store's lifetime. A second opener is rejected immediately.
- Writes are atomic (write-to-temp then rename, with a parent-directory fsync) and the file is created with owner-only permissions.
- Nonces are validated on load; malformed nonces are rejected. The store has a hard cap on the number of pending entries (expired entries are pruned first) and a default entry TTL of 24 hours.

Entries are kinded. The kinds are `PaymentSimulated`, `SignWithPasskey`, `RegisterPasskey`, `ToolsetFirstInvokeGate`, and `TrustlineClawbackOptIn`.

### What `approve` does

`stellar-agent approve --id <nonce>` loads the store and renders a wallet-controlled summary of the pending action. The destination G-strkey and asset are validated when the entry is deserialized, so a hostile entry cannot inject terminal-rendering content into that summary. The operator confirms at the terminal, and the command then computes and records the attestation. Recording is one-shot: a nonce that is expired, of the wrong kind, or already attested is rejected.

### The attestation

The Attestation is an HMAC-SHA256 tag, keyed by the profile's attestation key (which lives only in the keyring), over a length-prefixed canonical input. The input binds three things:

```text
HMAC-SHA256(attestation_key,
    len(approval_nonce) || approval_nonce
    || envelope_sha256            (32 bytes)
    || len(process_uid) || process_uid)
```

The length prefixes on the variable fields prevent boundary-collision attacks (two different nonce/uid pairs cannot collide into the same input). The `envelope_sha256` slot binds the attestation to the exact transaction envelope that will be signed. The `process_uid` (numeric OS uid on Unix) gives cross-account-on-host non-replay: a tag minted by one local user cannot be replayed by another.

The MCP commit-path verifier recomputes the tag and compares it in constant time. It collapses the distinct internal outcomes (`Expired`, `NotFound`, `AlreadyAttested`) into the single wire code `policy.approval_required`, so a caller cannot probe which state a nonce is in; the distinction is kept only in internal debug tracing.

The attestation proves that **the keyring holder ran `approve`** — not that a human clicked "yes" in some agent-controlled UI. The agent's own UI is not a trust input; the wallet-controlled `approve` step is.

What an attacker who can write to the store file can and cannot do: deleting a pending entry forces re-approval, which is a denial-of-service nuisance, not a bypass. The attacker cannot forge an attestation, because the HMAC key is in the keyring, not in the file. Rotating the attestation key invalidates all outstanding pending approvals.

## First-invoke gate vs. per-action payment approval

Toolset-routed payments use two distinct controls, and only one of them is suppressible.

- The **first-invoke gate** fires the first time a toolset uses a signing-adjacent capability with no matching grant. It queues a one-time `ToolsetFirstInvokeGate` entry. Once the operator approves it, a time-boxed toolset grant is persisted (default TTL 30 days) and matched on later invocations by the toolset, capability, destination, asset, and an amount range, plus its TTL.
- The grant suppresses **only** the first-invoke re-prompt. It does not stand in for payment approval.

The **per-action payment approval** (`PaymentSimulated`) fires unconditionally on every toolset-routed payment, and its attestation binds the actual executed envelope. A forged or tampered grant can at most suppress a re-prompt; it cannot bypass the per-action approval, because that approval is forced regardless of any grant and is bound to the real transaction. See [Toolsets](toolsets.md) for how toolsets route payments.

## The hash-chained audit log

The Audit log is a per-profile, append-only JSONL file recording every tool invocation and lifecycle event. The writer is a per-profile singleton holding an exclusive lock, appending with an fsync per line; a second opener is rejected. Files rotate at a size bound with a fixed number of rotated files retained.

### What is recorded

Each entry carries a timestamp, the tool name, the chain id, the **argument key names** (`arg_keys`), the envelope hash, the nonce id, the policy decision (`allow` / `deny:<reason>` / `require_approval`), an optional decision reason, a request id, the event kind, and the previous entry's hash. The event kind enumerates tool invocations alongside smart-account lifecycle events (rule changes, signer-set and threshold changes, passkey registration and assertion, multicall, timelock, channel-pool, rotation handoff, and others).

Argument **values are never logged** — only their key names. Strkeys appearing in a decision reason are redacted to first-five-last-five and transaction hashes to first-eight-last-eight; the envelope hash is left intact because it is a SHA-256 digest carrying no user data.

### Tamper evidence

Each entry's hash is computed over its own canonical JSON (with the previous-hash field treated as empty) concatenated with the previous entry's hash, chaining every entry to the one before it. The first entry of the very first file chains off a fixed zero block; the first entry of each later file chains off the prior file's rotation-handoff entry. Each file also carries a `root_hmac` sidecar signing the chain root with the profile's audit key.

`audit verify` walks the files oldest-first and checks that each entry's recorded previous-hash matches the recomputed prior-entry hash, that each file's first entry chains correctly across the rotation boundary, that each rotation handoff names the actual next file (defeating file-substitution), and, when an HMAC key is supplied, that the chain-root sidecar verifies. Verification failures use a closed set of wire codes (for example `audit.chain_broken`, `audit.rotation_gap`, `audit.hmac_mismatch`), with line and file detail kept out of the code.

## Smart-account context rules

Some agent accounts are on-chain OpenZeppelin smart accounts rather than plain key-pair accounts. Authorization for these is governed by Context rules.

- A **context rule** is identified by a `u32` rule id and governs which signers may authorize which actions.
- An **AuthorizationInfo** declares groups of signers, each with an M-of-N threshold, combined across groups by an AND/OR combinator (the quorum). Quorum semantics are fail-closed: an empty signer set is an error, not a no-auth transaction.
- The **auth digest** is `sha256(signature_payload || context_rule_ids_xdr)`. A smart-account signer signs this digest rather than the raw signature payload. Binding the rule ids into the signed value closes a downgrade attack in which a hostile transaction sponsor swaps in a weaker set of rules; the digest matches the on-chain check. The `context_rule_ids_xdr` portion must be produced by the canonical encoder, since a hand-assembled byte string yields a wrong digest that fails only on-chain at submission.

Passkey (WebAuthn) ceremonies use a browser handoff: registration and signing entries live in the approval spine, the assertion is pre-verified off-chain (including signature normalization) before being accepted, and the registration and assertion are recorded as audit events. The approval-spine and attestation mechanics these entries rely on are detailed in [Security internals](maintainers/security-internals.md).

## Glossary

| Term | Meaning |
|------|---------|
| Profile | Per-environment TOML config (schema version 2) binding a CAIP-2 chain, RPC endpoint, keyring entry references, thresholds, and the active policy engine. Holds no secrets. |
| CAIP-2 chain id | `stellar:testnet` or `stellar:mainnet`; drives passphrase resolution and the mainnet-write gate. |
| Keyring entry reference | A `service` + `account` pair naming a platform-keyring secret; never the secret itself. |
| Unlock window | The short, TTL-bounded period during which the signing seed is resident in pinned, zeroize-on-drop memory. See [Key custody and the unlock window](#key-custody-and-the-unlock-window). |
| Policy engine | Evaluates each tool/command to Allow, Deny, or RequireApproval. Noop and V1 are the two engines. |
| Criterion | One typed check inside a V1 policy rule (per-tx cap, per-period cap, rate limit, counterparty allowlist, minimum-reserve, resource-fee cap, session-active, and others). |
| Approval spine | The storage and cryptographic substrate recording out-of-band operator approvals: a per-profile pending-approval store plus an HMAC attestation minted at approve time. |
| Attestation | An HMAC-SHA256 tag, keyed by the profile attestation key, over a length-prefixed input binding the approval nonce, the envelope SHA-256, and the process uid; proves the keyring holder ran `approve`. Constant-time verified. |
| Audit log | A per-profile append-only hash-chained JSONL record of every tool invocation and lifecycle event; argument values are never logged. Verified with `audit verify`. |
| Context rule | An on-chain OpenZeppelin smart-account authorization rule, identified by a `u32` rule id; governs which signers may authorize which actions. |
| Auth digest | `sha256(signature_payload || context_rule_ids_xdr)`; the value a smart-account signer signs, binding the rule ids to close a downgrade attack. |
| First-invoke gate | A one-time gate on a toolset's first use of a signing-adjacent capability; once approved, a time-boxed grant suppresses only that re-prompt. |
| Per-action payment approval | The payment approval that fires unconditionally on every toolset-routed payment and binds the actual executed envelope. |
