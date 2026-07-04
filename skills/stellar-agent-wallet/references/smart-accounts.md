# Smart-account governance

The `smart-account` CLI group (alias `sa`) governs an on-chain OpenZeppelin smart-account: its context rules, the signer sets and thresholds on each rule, the policy contracts attached to a rule, and the supporting infrastructure (verifier registry, multicall-router registry, upgrade timelock). Every command prints one JSON envelope on stdout and returns exit code `0` on success, `1` on any error.

This file is self-contained. For the MCP tool surface and result-envelope shape see `./mcp-tools.md`. For the value-transfer / DeFi verbs see `./defi.md`.

## Output envelope and amount/asset conventions

- Envelope: `{ ok, data | error, request_id }`. On success `ok: true` with a `data` object; on error `ok: false` with an `error` object carrying a wire code (for example `network.mainnet_write_forbidden`, `validation.rule_name_too_long`, `sa.threshold_policy_identification_failed`).
- Amounts are always decimal strings with a unit, for example `"10 XLM"`, never JSON numbers. Assets are `native` / `XLM` or `CODE:GISSUER`. (These verbs are governance-only; no amounts are taken except per-op fees in stroops.)
- MCP tools take `chain_id`, the CAIP-2 id of the target network, and it is required by most tools. The CLI uses `--network <testnet|mainnet>` instead.

## Mainnet write refusal

Most signing verbs that mutate context-rule, signer, or timelock state refuse `mainnet` structurally — before any RPC call or signing-key access — surfacing the wire code `network.mainnet_write_forbidden`. This covers: the `smart-account rules` write verbs, all `smart-account signers` verbs (including `list` and `refresh`, which emit audit rows), the timelock write verbs (`schedule`, `cancel`, `execute`), and `smart-account deploy-webauthn-verifier`.

Exceptions:

| Verb | Mainnet behavior |
|------|------------------|
| `smart-account migrate-verifier` | Mainnet dry-run allowed; mainnet submit allowed only with `--confirm-mainnet-migrate`; never returns `network.mainnet_write_forbidden`. |
| `smart-account multicall` | `mainnet` accepted at the flag level but requires a router registered for mainnet. |
| `smart-account register-multicall` / `unregister-multicall` | Accept `mainnet` as a local-registry key. |
| Read-only verbs | `smart-account rules get`, `smart-account rules verify-pins`, `smart-account rules list` / `smart-account list-rules`, `smart-account list-verifiers`, `smart-account timelock list-pending` accept `mainnet` unconditionally. |

## Signer source (write verbs)

Write verbs take a signer-source group: exactly one of `--signer-secret-env <VAR>` (an env-var name holding the source-account S-strkey) or `--sign-with-ledger` (mutually exclusive; the command refuses if neither is given). `--account-index <INDEX>` selects the Ledger BIP-44 index (default `0`). Pass the variable name, never the secret:

```bash
export WALLET_SK="S..."
```

All write signing goes through the smart-account auth-entry digest path: the signer signs the auth digest, which binds the authorizing context-rule ids.

Shared flags available on most verbs: `--profile`, `--network`, `--rpc-url`, `--secondary-rpc-url`, `--timeout-seconds`, `--output` (`json` default or `table`). The `smart-account signers` verbs do not accept `--output`.

## Context rules

A context rule has a `rule_id` (`u32`), a name (OZ cap: 20 bytes), an optional expiry ledger, a signer set (OZ cap: 15 signers), and up to 5 policy contracts. On the write verbs `--auth-rule-id` names the rule whose signers authorize the operation; where it is optional it defaults to the rule being modified (`--rule-id`). Rule `0` is the bootstrap rule installed at deploy time and is the default authorizer.

### `smart-account rules` verbs

| Verb | Purpose | Key flags | Notes |
|------|---------|-----------|-------|
| `create` | Install a rule (OZ `add_context_rule`); returns new `rule_id` | `--account` (req), `--name` (req), `--signer-delegated <G>` (repeatable), `--signer-webauthn <CRED>` (repeatable), `--accept-no-delegated-fallback`, `--accept-mutable-verifier`, `--accept-unknown-verifier`, `--auth-rule-id` (repeatable, default `[0]`), `--valid-until <LEDGER\|none>` (default `none`) | Testnet only. At least one `--signer-delegated` or `--signer-webauthn` required. |
| `get` | Read one rule (OZ `get_context_rule`) | `--account` (req), `--rule-id` (req), `--source-account <G>` (req) | Read-only, mainnet OK. Source account is for simulation only, not debited. Envelope: `present: true\|false`. |
| `set-name` | Rename (OZ `update_context_rule_name`) | `--account`, `--rule-id`, `--name` (all req), `--auth-rule-id` (opt, default `--rule-id`) | Testnet only. 20-byte name cap. |
| `set-valid-until` | Change expiry (OZ `update_context_rule_valid_until`) | `--account`, `--rule-id`, `--valid-until <LEDGER\|none>` (all req), `--auth-rule-id` (opt) | Testnet only. `none` clears expiry (permanent rule). |
| `delete` | Remove a rule (OZ `remove_context_rule`) | `--account`, `--rule-id` (req), `--auth-rule-id` (opt) | Testnet only. |
| `verify-pins` | Drift-check pinned verifier/policy WASM hashes vs on-chain | `--account`, `--rule-id` (req) | Read-only, mainnet OK. Exit `1` if any pin status is `drift`. |
| `add-policy` | Attach a policy (OZ `add_policy`); returns `policy_id` | `--account`, `--rule-id`, `--policy-address <C>`, `--install-param <SCVAL_BASE64>` (all req), `--auth-rule-id` (opt, repeatable) | Testnet only. Per-rule cap of 5 enforced via pre-fetch. `--install-param` is standard-base64 XDR `ScVal` (not base64url), passed through raw. |
| `remove-policy` | Detach a policy (OZ `remove_policy`) | `--account`, `--rule-id`, `--policy-id <U32>` (all req), `--auth-rule-id` (opt, repeatable) | Testnet only. |
| `list` | Enumerate active rules (on-chain scan) | same as `smart-account list-rules` | Read-only, mainnet OK. Alias of `smart-account list-rules`. |

Name-related errors: a name over 20 bytes is refused with `validation.rule_name_too_long`. A rule with only `--signer-webauthn` signers and no `--accept-no-delegated-fallback` is refused with `validation.passkey_only_rule_no_delegated_fallback`.

Create example:

```bash
stellar-agent smart-account rules create \
  --account CABC...WXYZ \
  --name agent-ops \
  --signer-delegated GABC...WXYZ \
  --signer-secret-env WALLET_SK
```

`verify-pins` reports each `*_pin_status` as one of `match`, `drift`, `unavailable`, `no_pin`, `no_contracts`.

## Signer kinds

The wallet maps to three OpenZeppelin signer kinds. `smart-account signers list` returns parallel `signer_ids` and `signer_kinds` lists; the kind discriminator strings are:

| Kind string | OZ signer | How added |
|-------------|-----------|-----------|
| `ed25519` | `Signer::Delegated(Address)` — a G-strkey ed25519 keypair | `--signer-delegated <G>` (alias `--new-signer`) |
| `webauthn` | WebAuthn passkey signer (verifier-backed) | `--signer-webauthn <CRED>`, resolved from the profile passkey registry; verifier address read from the verifier registry |
| `external` | Custom external-verifier signer | `--signer-external <C>` with `--signer-key-data <HEX>` |

## Signer-set and threshold lifecycle

All `smart-account signers` verbs take `--account <C>` and `--rule-id <U32>` (both required), the signer-source group, `--profile`, `--network`, `--rpc-url`, `--secondary-rpc-url`, `--timeout-seconds`. None accept `--output`. All structurally refuse `mainnet` (including `list` and `refresh`). `list` and `refresh` require a signer source because the manager needs a source account to assemble the read envelope.

| Verb | Purpose | Extra flags | Notes |
|------|---------|-------------|-------|
| `list` | Read on-chain signer set; baseline if none exists | — | Testnet only. Writes a `SaSignerSetBaselined` audit row on first sight of a `(rule_id, account)` pair. Envelope: `signer_count`, `threshold`, `signer_ids`, `signer_kinds`. No on-chain tx. |
| `refresh` | Re-anchor the baseline unconditionally | — | Testnet only. Audit-log write only; use after an intentional out-of-band signer change. |
| `add` | Add a signer (OZ `add_signer`); returns `new_signer_id` | exactly one of `--signer-delegated <G>` (alias `--new-signer`) / `--signer-external <C>` / `--signer-webauthn <CRED>`; `--signer-key-data <HEX>` required with and only with `--signer-external` | Testnet only. Per-rule cap of 15 checked via pre-fetch. |
| `remove` | Remove a signer (OZ `remove_signer`) | `--signer-id <U32>` (req) | Testnet only. Refused if removing would drop `signer_count` below `threshold` — lower the threshold first. |
| `set-threshold` | Change quorum threshold via the threshold-policy contract `set_threshold` | `--new-threshold <U32>` (req) | Testnet only. No `--auth-rule-id` override (the authorizing rule is `--rule-id`). The threshold-policy contract is found by WASM-hash allowlist lookup; zero or multiple matches refuse with `sa.threshold_policy_identification_failed`. |

Quorum update sequence — to raise then add, or to lower then remove, order matters:

```bash
# Lower threshold before removing a signer
stellar-agent smart-account signers set-threshold --account CABC...WXYZ --rule-id 0 --new-threshold 1 --signer-secret-env WALLET_SK
stellar-agent smart-account signers remove --account CABC...WXYZ --rule-id 0 --signer-id 2 --signer-secret-env WALLET_SK
```

## Verifier and policy WASM-hash pinning

Verifier contracts are governed by a compile-time allowlist; no central server is consulted. Each entry carries a SHA-256 WASM hash and an audit status with `kind` discriminator `audited`, `unaudited`, `revoked`, or `retired`:

| Status | Meaning | Install gate | Advisory |
|--------|---------|--------------|----------|
| `audited` | Auditor-attested (`auditor` + `audited_at` fields) | Allowed | None |
| `unaudited` | No audit attached | Operator-acknowledged risk required | None |
| `revoked` | Disclosed-vulnerable (`revoked_at` + `reason`) | Blocked unless overridden | Fires on every CLI invocation until migrated |
| `retired` | `revoked` past 24-month retention (`revoked_at` + `retired_at`; reason dropped) | Blocked unless overridden | Still fires |

`smart-account list-verifiers` enumerates the allowlist with this taxonomy (read-only, no network, only flag is `--output`). It has two `audited` OZ `multisig-webauthn-verifier-example` entries: the canonical v0.7.2 (WASM SHA-256 `9427e3dd71fb29115c6f0efdf2f703b32fec566b151421f991c3b4e248ebb1f7`), which new deployments use, and the legacy v0.7.1 (WASM SHA-256 `678006909b50c6c365c033f137197e910d8396a2c68e9281327a2ed7dbf4b27a`), still recognised for verifier contracts already deployed on-chain. The two versions share an identical ABI.

Override flags on `smart-account rules create`:

- `--accept-mutable-verifier` — proceed even if a referenced verifier or policy contract has a mutable admin/owner key (envelope reports `mutable_override: true`).
- `--accept-unknown-verifier` — proceed even if a referenced verifier or policy WASM hash is not in the allowlist (envelope reports `unknown_override: true`).

Drift detection: `smart-account rules verify-pins` compares a rule's pinned verifier and policy hashes against the live on-chain contracts (see the rules table).

## Smart-account infrastructure

### Verifier deploy and migration

`smart-account deploy-webauthn-verifier` deploys the OZ WebAuthn-verifier WASM and records its address in the verifier registry (`~/.config/stellar-agent/networks.toml`). Idempotent — if the registry already holds a same-WASM-hash entry for the network it returns `status: "already_deployed"` with no RPC traffic. Testnet only.

- Deployer source (exactly one): `--deployer-secret-env <VAR>` or `--sign-with-ledger`; `--account-index <INDEX>` default `0`.
- `--rpc-url` default `https://soroban-testnet.stellar.org`. `--fee <STROOPS|auto[:pNN]>` (`auto` = p95; also `auto:p50`/`auto:p75`/`auto:p95`/`auto:p99`; absent uses the profile default 100-stroop base plus simulated Soroban resource fees). `--timeout-seconds` default `60`.
- `--dry-run` derives the verifier address with no network access or signing; returns `status: "dry_run"`.

```bash
stellar-agent smart-account deploy-webauthn-verifier --deployer-secret-env DEPLOYER_SK
```

`smart-account migrate-verifier` builds and optionally executes a plan that moves all `external` signers from one verifier to another across every context rule. Dry-run is read-only and renders the plan as JSON; without `--dry-run` it signs and submits `remove_signer` / `add_signer` pairs. Mainnet dry-run allowed; mainnet submit additionally requires `--confirm-mainnet-migrate`. Pre-flight gates (fail-closed): destination verifier hash must be allowlisted, its audit status must be `audited` or `unaudited`, and the destination contract must be immutable.

- `--account <C>` (req), `--from <HASH_HEX>` (req, 64-char hex SHA-256 of the source verifier WASM), `--to <C>` (req, destination verifier), `--dry-run`, `--confirm-mainnet-migrate`, signer-source group (required for submit, not for dry-run).

```bash
stellar-agent smart-account migrate-verifier \
  --account CABC...WXYZ \
  --from 678006909b50c6c365c033f137197e910d8396a2c68e9281327a2ed7dbf4b27a \
  --to CNEW...WXYZ \
  --dry-run
```

### Rule enumeration

`smart-account list-rules` (alias backing `smart-account rules list`) scans the on-chain `[0, max_scan_id)` rule-id space and returns each active rule in `rule_id` order. Read-only, mainnet OK.

- `--account <C>` (req), `--source-account <G>` (optional on testnet, where it defaults to a well-known funded account; required on mainnet, where any funded account works and is not debited), `--rpc-url` (default testnet RPC), `--secondary-rpc-url` (defaults to `--rpc-url`), `--network` (default `testnet`), `--profile`, `--max-scan-id <N>` (range `1..=10000`, rejected at parse otherwise; default from profile else `50`), `--timeout-seconds` (default `60`), `--output`.

### Multicall router registry

`smart-account register-multicall` records a deployed multicall-router address and its WASM hash in `~/.config/stellar-agent/networks.toml` (local file plus audit row, idempotent). Refuses if `--wasm-sha256` does not equal the binary's compiled-in router WASM hash.

- `--network` (default `testnet`), `--address <C>` (req), `--wasm-sha256 <HEX>` (req, 64-char lowercase hex), `--profile`.

`smart-account unregister-multicall` removes the entry. The normal path validates and removes. `--force` is for registry-file corruption recovery (bypasses strkey/hex validation, locates by network name) and needs interactive `[y/N]` confirmation on a TTY or `--yes-i-have-verified-the-prior-values` for non-TTY; the audit row is written before the file is mutated.

- `--network` (default `testnet`), `--force`, `--yes-i-have-verified-the-prior-values`, `--profile`.

## Multicall submission

`smart-account multicall` submits an atomic multicall bundle (1–50 invocations) through the registered router for the target network. Signs and submits. The router address is resolved from the local registry; `mainnet` is accepted at the flag level but requires a router registered for mainnet. Signer source required.

Each `--invocation` is `<target>:<fn>:<json-args>` where `<target>` is the C-strkey of the contract to call, `<fn>` is the function name, and `<json-args>` is a JSON array of **scalar** arguments encoded directly: a JSON number becomes an `i128`, a JSON string becomes a Soroban `String` (raw UTF-8), and `null` becomes `Void`. Booleans, objects, and nested arrays are rejected. There is no automatic typed encoding — a string is not turned into an `Address`, so functions that take addresses or other non-scalar types cannot be driven through this JSON form.

| Flag | Meaning |
|------|---------|
| `--smart-account <C>` (req) | Smart-account executing the bundle |
| `--rule-id <U32>` (req) | Context rule authorizing the bundle |
| `--invocation <TARGET:FN:JSON_ARGS>` (req, repeatable, 1–50) | One invocation descriptor |
| `--secondary-rpc-url <URL>` | Secondary RPC for cross-verification; resolved as `profile.secondary_rpc_url`, then this flag (overrides the profile value), then a typed error if neither set |
| `--fee <STROOPS>` | Per-op base fee, default `100`; `auto[:pNN]` is rejected here (unlike the deploy verbs) |

```bash
stellar-agent smart-account multicall \
  --smart-account CABC...WXYZ \
  --rule-id 0 \
  --invocation 'CCTR...WXYZ:set_value:[42]' \
  --secondary-rpc-url https://rpc2.example \
  --signer-secret-env WALLET_SK
```

## Upgrade timelock (`smart-account timelock`)

Schedule, cancel, execute, and list pending operations on an OpenZeppelin timelock contract. The signer must hold the appropriate role for each write verb. All four share `--timelock <C>` (req), `--rpc-url`, `--secondary-rpc-url`, `--network`, `--profile`; the write verbs add the signer-source group. Write verbs (`schedule`, `cancel`, `execute`) refuse `mainnet`; `list-pending` is read-only and accepts `mainnet`. When `--secondary-rpc-url` is omitted it defaults to `--rpc-url`; supplying an independent endpoint restores cross-RPC divergence detection.

| Verb | Role | Extra flags | Notes |
|------|------|-------------|-------|
| `schedule` | PROPOSER | `--target <C>` (req), `--function <NAME>` (req), `--delay-ledgers <N>` (req) | Salt is derived non-deterministically and returned as the `salt` field (64-char lowercase hex). The envelope also carries `operation_id_full_hex`. Record the salt immediately — it is required by `execute` and `cancel` and cannot be recomputed. |
| `cancel` | CANCELLER | `--operation-id <HEX>` (req, 64-char hex from schedule) | Cross-confirms the on-chain cancellation event. |
| `execute` | EXECUTOR (or open-execution) | `--target <C>` (req), `--function <NAME>` (req), `--operation-id <HEX>` (req), `--salt <HEX>` (req) | Dual-RPC ready-window check, fails closed if not ready. `--target`, `--function`, `--operation-id`, `--salt` must exactly match the scheduled operation, since OZ re-derives the operation id from them. |
| `list-pending` | — | — | Read-only, mainnet OK. Cross-references the local audit log with a dual-RPC `get_operation_state` query. |

The schedule-then-execute flow centers on the returned `{operation_id, salt}`:

```bash
# 1. Schedule (PROPOSER). Save the "salt" and operation id from the JSON output.
stellar-agent smart-account timelock schedule \
  --timelock CTLCK...WXYZ \
  --target CTGT...WXYZ \
  --function upgrade \
  --delay-ledgers 100 \
  --signer-secret-env PROPOSER_SK

# 2. After the delay, execute (EXECUTOR) with the exact saved target/function/operation-id/salt.
stellar-agent smart-account timelock execute \
  --timelock CTLCK...WXYZ \
  --target CTGT...WXYZ \
  --function upgrade \
  --operation-id abcdef01...89abcdef \
  --salt 11223344...aabbccdd \
  --signer-secret-env EXECUTOR_SK
```

To abort before the delay elapses, cancel with the operation id:

```bash
stellar-agent smart-account timelock cancel \
  --timelock CTLCK...WXYZ \
  --operation-id abcdef01...89abcdef \
  --signer-secret-env CANCELLER_SK
```

## External-contract submit convention

When a smart-account authorizes a call into an external contract (a DeFi adapter, a router, a token), the auth-entry locator distinguishes the contract being invoked from the wallet credential providing the authorization:

- The invoked contract is the target.
- The wallet credential address is the auth address (defaults to the target when not overridden; pass it explicitly for entrypoints that require a different C-strkey credential address — G-strkey addresses are rejected at strkey parse).
- One or more authorizing context-rule ids bind the auth digest; a single rule id is auto-expanded to match the number of invocation contexts.

This is the same convention the higher-level value-transfer and DeFi verbs use under the hood when the source is a smart-account.
