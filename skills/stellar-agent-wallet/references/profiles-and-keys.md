# Profiles and keys

A profile is a per-environment TOML config file (schema `version = 2`) that binds
a CAIP-2 chain, an RPC endpoint, a set of keyring entry references, behavioural
thresholds, and the active policy engine. It is the single source of truth read
by the `stellar-agent` CLI, the `stellar-agent-mcp` server, and the policy
engine.

A profile holds no secrets. Every key it references lives in the platform
keyring; the profile only names those entries. See [Secret discipline](#secret-discipline).

## File location and selection

Profile files live one-per-name in the OS-conventional data directory:

| Platform | Profile file |
|----------|--------------|
| Linux    | `~/.local/share/stellar-agent/profiles/<name>.toml` |
| macOS    | `~/Library/Application Support/Soneso.stellar-agent/profiles/<name>.toml` |
| Windows  | `%LOCALAPPDATA%\Soneso\stellar-agent\data\profiles\<name>.toml` |

A profile is selected by name (the file stem). The name `default` is the profile
the MCP server reads on startup; when no `default.toml` exists yet, the server
falls back to an in-memory testnet configuration so it can still serve read-only
requests. This fallback is never written to disk.

Create a new profile file with `stellar-agent profile init` (default `default`,
testnet, `engine = "v1"`); mainnet requires an explicit `https://` `--rpc-url`.
See [cli-reference.md](cli-reference.md) for flags.

`init` mints the `audit_log_hash_chain_key_id` keyring COORDINATE only, no key
material. Run `stellar-agent profile enroll-signer` then
`stellar-agent profile rotate-audit-key <name>` next — required before any
signing verb will proceed, on **either** policy engine — or every value-moving
CLI command and MCP tool refuses `audit.chain_key_unavailable`. See
[Approvals and audit](approvals-and-audit.md#fail-closed-on-an-unminted-audit-key).

## Loader source order

A profile is assembled from three layered sources. Higher-priority sources
override lower ones field-by-field:

1. TOML file — `<profile_dir>/<name>.toml` (lowest priority).
2. Environment overlay — variables prefixed `STELLAR_AGENT_`. For example,
   `STELLAR_AGENT_RPC_URL=https://...` overrides the `rpc_url` field.
3. CLI overlay — programmatic key/value pairs supplied by a command at resolve
   time (highest priority).

After merging, the loader resolves derived fields and validates:

- `network_passphrase` is always derived from `chain_id`; it is never read from
  the TOML or any overlay.
- `rpc_url` defaults to the chain's built-in endpoint when omitted, then is
  validated as a well-formed URL. A malformed URL fails the load.
- `audit_log_path` defaults to the OS-conventional location when omitted.
- A `version` 2 profile must carry an explicit `[policy]` section; a v2 file with
  no `[policy]` block is refused rather than silently inheriting a default
  engine.

## Schema version handling

Every profile carries a top-level `version` field. The loader dispatches on it:

- `version = 2` — current schema; loads directly.
- `version = 1` — not loaded directly. The loader fails fast and the file must
  first be migrated with `stellar-agent profile migrate <name>` (see
  [Migration and key rotation](#migration-and-key-rotation)).
- `version > 2` — refused. A profile written by a newer wallet is rejected so an
  older wallet never silently applies stale defaults.

## Field reference

Fields are written at the top level of the TOML unless a `[section]` header is
shown. Keyring entry reference fields (`KeyringEntryRef`) are TOML tables with a
`service` and an `account` key; they name a keyring entry and never hold a
secret.

### Network and identity

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `version` | integer | yes | — | Schema version. Must be `2`. |
| `chain_id` | string (CAIP-2) | yes | — | `stellar:testnet` or `stellar:mainnet`. Drives passphrase resolution and the mainnet-write gate. |
| `rpc_url` | string (URL) | no | chain default | Soroban RPC endpoint. Testnet default `https://soroban-testnet.stellar.org`. Validated as a URL at load. |
| `network_passphrase` | string | resolved | from `chain_id` | The Stellar network passphrase. Resolved from `chain_id`; not overridable from the TOML or overlays. Surfaced for callers. |

### Signer and nonce references

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `[mcp_signer_default]` | keyring ref | yes | — | Keyring entry for the default MCP signer seed. |
| `[mcp_nonce_key_alias]` | keyring ref | yes | — | Keyring entry for the HMAC nonce key. |

### Thresholds and fees

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `cross_check_threshold_stroops` | integer (stroops) | no | `0` | High-value cross-check threshold. The effective value is `max(cross_check_threshold_stroops, 10_000_000_000)`; the floor of 1000 XLM (10^10 stroops) cannot be configured lower, so a profile with `cross_check_threshold_stroops = 0` behaves as if it were the floor. Transactions at or above the effective threshold trigger the independent-RPC cross-check when `oracle_provider_url` is set. The legacy key `usd_threshold` is still accepted on load; do not set both keys (across the file, environment, and CLI sources) — the load is refused as a duplicate field. |
| `classic_fee_per_op_stroops` | integer | no | unset (protocol default) | Per-operation base fee for classic transactions, in stroops. When unset, classic tools use the built-in default. |
| `classic_max_fee_per_op_stroops` | integer | no | unset (no cap) | Per-operation fee cap, in stroops. When set, classic tools fail before envelope construction if the selected fee exceeds the cap. A guardrail, not a silent clamp. |
| `submit_timeout_seconds` | integer | no | `60` | How long the wallet polls for transaction confirmation. |

### Security-substrate key references

These four `KeyringEntryRef` fields name the keyring entries holding the security
substrate's keys. A migrated profile populates them with default-derived names
but mints no key material; the rotation commands mint the actual keys (see
[Migration and key rotation](#migration-and-key-rotation)).

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `[audit_log_hash_chain_key_id]` | keyring ref | yes | HMAC key signing the audit log's chain root. |
| `[policy_owner_key_id]` | keyring ref | yes | ed25519 key whose signature every V1 policy file must carry. |
| `[attestation_key_id]` | keyring ref | yes | HMAC key minting approval attestations at `approve` time. |
| `[counterparty_cache_key_id]` | keyring ref | yes | HMAC key protecting the local `stellar.toml` cache integrity. |

### Cross-check, MCP, and scan bounds

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `oracle_provider_url` | string (URL) | no | unset (cross-check off) | Independent RPC endpoint used to re-simulate high-value transactions. When unset, the high-value cross-check is skipped. Set this before enabling V1 for mainnet high-value flows. |
| `mcp_disabled` | bool | no | `false` | When `true`, `stellar-agent mcp` refuses to start with error `mcp.disabled_per_profile`. |
| `audit_log_path` | string (path) | no | OS-conventional | Path to the per-profile audit log. |
| `secondary_rpc_url` | string (URL) | no | unset | Independent secondary RPC for the multicall cross-RPC trust-anchor check. Must point to a node operated independently of `rpc_url`. Required when a multicall router is registered for the profile's network; loading otherwise fails. Redacted in debug output. |
| `smart_account_max_context_rule_scan_id` | integer | no | engine default | Override for the maximum rule-id scan bound. Rejected at load when above `10000`. |
| `session_rule_max_horizon_ledgers` | integer | no | engine default | Override for the maximum session-rule lookahead window, in ledgers. Rejected at load when above `10000`. |

### `[wallet]` block

Controls the unlock window — the short, TTL-bounded period during which the
32-byte signing seed is resident in pinned, zeroize-on-drop memory.

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `mlock_required` | bool or `"warn"` | no | platform-dependent | `mlock(2)` failure posture. `true` (default on Linux/macOS): fail closed if the seed cannot be pinned in RAM. `"warn"` (default on Windows): proceed with unprotected memory and emit a warning. `false`: do not attempt memory locking. |
| `unlock_ttl_seconds` | integer | no | `30` | Unlock-window TTL in seconds. Hard cap `600` (10 minutes); a value above the cap is refused when the window is constructed. Operators may shorten the window. |

### `[policy]` block

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `engine` | string | yes (in v2) | — | `"noop"` or `"v1"`. `noop`: testnet allow-all; mainnet read-only allowed; mainnet destructive operations refused with `policy.engine_required`. `v1`: signature-verified typed-criteria engine, first-match default-deny. Newly minted profiles default to `v1`; a profile migrated from v1 is set to `noop` explicitly. |

## Conventions for amounts, assets, and result envelopes

These conventions apply throughout the wallet and matter when reading or writing
profile-driven values.

- Human-scale amounts are decimal strings with a unit, e.g. `"10 XLM"`. Never
  JSON numbers.
- Every value-denominated field on the MCP tool wire (`amount_in_stroops`,
  `amount_stroops`, `starting_balance_stroops`, `limit_stroops`, fee fields,
  fee-stats percentiles) is a bare decimal string in stroops/base units — no
  unit suffix, e.g. `"100000000"`. A raw JSON number is rejected on inputs: a
  JSON number backed by `f64` cannot represent a stroop amount exactly once
  it exceeds `2^53`. The SEP-6 anchor passthrough fields
  (`sep6_deposit_info` fee/min/max amounts) are the one documented exception —
  they relay a third-party anchor's own SEP-6 payload verbatim.
- Stroop-denominated profile fields (`cross_check_threshold_stroops`, fee
  fields) are TOML integers in stroops; 1 XLM = 10^7 stroops. This is a
  separate convention from the MCP wire fields above — profile.toml is an
  operator-authored config file, not a JSON wire message.
- An asset is `native`/`XLM`, or `CODE:GISSUER` (code, colon, issuer G-address).
- `chain_id` is the CAIP-2 id (`stellar:testnet` or `stellar:mainnet`) and is
  required by most MCP tools.
- The MCP result envelope is `{ok, data|error, request_id}`: `ok` is a boolean,
  `data` carries the result on success, `error` carries `{code, message}` on
  failure, and `request_id` correlates the call with the audit log.

## Secret discipline

No profile field holds a secret. The signer seed, nonce key, and every HMAC and
ed25519 key live in the platform keyring (macOS Keychain, Linux Secret Service,
Windows Credential Manager). Each `*_key_id` field, the signer reference, and the
nonce reference are `KeyringEntryRef` values that only name a keyring entry.

Consequences:

- The profile TOML is safe to back up and to copy between hosts. The keyring
  backend is the actual defence for secret material.
- `rpc_url` and `secondary_rpc_url` are redacted in the wallet's debug output
  because a URL may embed RPC credentials. They are still written verbatim to the
  TOML, so avoid embedding credentials in those URLs if the file is shared.
- `stellar-agent profile show <name>` prints the resolved configuration as a JSON
  envelope; keyring references appear as opaque `{service, account}` objects,
  never the secret.

### Headless deployments: the opt-in file-backed keyring store

The platform keyring is unreachable in some deployment shapes — most notably
Windows Credential Manager, which requires an interactive logon session:
running under a Windows service, an SSH session, or a "run whether user is
logged on or not" scheduled task fails closed with
`auth.keyring_interactive_session_required`. For exactly those shapes the
wallet ships an opt-in, file-backed store. Set on the process environment
before any `stellar-agent` / `stellar-agent-mcp` command:

- `STELLAR_AGENT_KEYRING_BACKEND=headless-dpapi` — Windows only; entries are
  protected with DPAPI (CurrentUser scope).
- `STELLAR_AGENT_KEYRING_BACKEND=headless-env` — any platform; entries are
  encrypted with XChaCha20-Poly1305 under a 32-byte URL-safe-base64 key
  supplied in `STELLAR_AGENT_HEADLESS_KEYRING_KEY`.

The platform keyring remains the default when the variable is unset; there is
no silent fallback in either direction — a misconfigured backend fails closed
rather than switching stores. In `headless-env` mode the operator-held
environment key is the custody boundary: whoever can read the process
environment can decrypt the store, so scope it to the service user.

A profile migrated from schema v1 stays on the `noop` engine until the operator
completes key rotation and opts in to `v1`. Migration populates the four
security-key reference names but mints no key material; the rotation commands
below mint the actual keys. The engine choice governs the policy layer only:
every mainnet write is additionally refused at the network layer
(`network.mainnet_write_forbidden`) in this alpha, on `noop` and `v1` alike.

### Migrate first

```bash
stellar-agent profile migrate my-profile
```

This rewrites the file in place (atomically), sets the four `*_key_id` reference
names, and sets `[policy] engine = "noop"`. Running it again on an already-current
profile is a no-op.

### Rotate each key

Each command generates fresh key material from the OS CSPRNG and stores it in the
named keyring entry. The CLI prints a JSON envelope and exits `0` on success, `1`
on error.

The policy-file owner key is not rotated here. It is an ed25519 key whose PUBLIC
half is enrolled with `stellar-agent profile enroll-owner-key` (from an operator
`S...` seed; only the public key is stored) and whose seed signs policy files via
`stellar-agent profile sign-policy`. Re-enrolling a different owner key
invalidates policy files signed by the previous one.

| Command | Mints into | Notes |
|---------|------------|-------|
| `stellar-agent profile rotate-attestation-key <name>` | `attestation_key_id` | Fresh 32-byte HMAC key. All pending approvals are invalidated. |
| `stellar-agent profile rotate-audit-key <name>` | `audit_log_hash_chain_key_id` | Fresh 32-byte HMAC key. Re-signs every existing per-file chain-root sidecar with the new key, so `audit verify --profile <name>` stays green across the rotation and the old key stops verifying; the response carries `sidecars_resigned`. |
| `stellar-agent profile rotate-counterparty-key <name>` | `counterparty_cache_key_id` | Fresh 32-byte HMAC key. All cached `stellar.toml` entries are invalidated and re-fetched on next use. |
| `stellar-agent profile rotate-nonce-key <name>` | `mcp_nonce_key_alias` | Fresh 32-byte HMAC key. Outstanding nonces minted with the old key are invalidated. |

### Enroll the MCP signer

The signer seed is imported, not minted. `stellar-agent profile enroll-signer`
reads the operator's `S...` ed25519 secret from a named environment variable and
stores it verbatim at the profile's `mcp_signer_default` keyring coordinate — the
signer every MCP fund-movement tool and every keyring-signing CLI verb
(`trustline`, `lend`, `trade`, `vault`) resolves. On a clean install that entry
is absent and those paths fail with `auth.keyring_not_found`.

```bash
export WALLET_SK=S...signer-secret...
stellar-agent profile enroll-signer --profile default --secret-env WALLET_SK
```

Flags: `--secret-env <VAR>` (required; the variable NAME, never the secret),
`--profile <NAME>` (default `default`), `--expected-address <G_STRKEY>` (refuse
unless the seed derives to it), `--force` (replace an already-enrolled entry).
Enrollment derives the seed's public address. A profile fresh from
`profile init` (and a v1-migrated profile that still carries it) holds the placeholder `"default"` in
`mcp_signer_default.account`; enrollment overwrites it in place with the
derived address. A profile whose `account` already pins a G-strkey — from a
prior enrollment, or set by hand — is left untouched, and enrollment refuses if
the seed does not derive to that exact address, printing the address to set
`account` to.

### Opt in to V1

On top of `profile rotate-audit-key` (required on every engine, see above),
the V1-specific ceremony, in order, is `profile enroll-owner-key`,
`profile rotate-attestation-key`, then `profile sign-policy`. An
`init`-minted profile already carries `engine = "v1"` — complete the ceremony
and it becomes operational. A profile migrated from schema v1 stays on
`noop`; after the ceremony, set the engine in the profile TOML:

```toml
[policy]
engine = "v1"
```

Until this is done, a migrated profile continues to run under `noop`, which
refuses mainnet destructive operations with `policy.engine_required`. Opting in
to `v1` changes the policy layer only — mainnet writes stay structurally refused
at the network layer in this alpha.

## Example profile

A minimal testnet profile on the V1 engine:

```toml
version = 2
chain_id = "stellar:testnet"
rpc_url = "https://soroban-testnet.stellar.org"
cross_check_threshold_stroops = 50000000000
mcp_disabled = false

[mcp_signer_default]
service = "stellar-agent-signer-my-profile"
account = "default"

[mcp_nonce_key_alias]
service = "stellar-agent-nonce-my-profile"
account = "default"

[audit_log_hash_chain_key_id]
service = "stellar-agent-audit-my-profile"
account = "default"

[policy_owner_key_id]
service = "stellar-agent-owner-my-profile"
account = "default"

[attestation_key_id]
service = "stellar-agent-attestation-my-profile"
account = "default"

[counterparty_cache_key_id]
service = "stellar-agent-counterparty-my-profile"
account = "default"

[wallet]
mlock_required = true
unlock_ttl_seconds = 30

[policy]
engine = "v1"
```
