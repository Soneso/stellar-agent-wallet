# Profile configuration reference

A **profile** is a per-environment TOML config file (schema `version = 2`) that
binds a CAIP-2 chain, an RPC endpoint, a set of keyring entry references,
behavioural thresholds, and the active policy engine. It is the single source of
truth that the `stellar-agent` CLI, the `stellar-agent-mcp` server, and the
policy engine all read.

A profile holds **no secrets**. Every key it references lives in the platform
keyring; the profile only names those entries. See
[Secret discipline](#secret-discipline) below.

For the surrounding security model and terminology, see
[concepts.md](concepts.md). For the CLI commands that create, inspect, migrate,
and rotate profiles, see
[cli-reference/profile-and-governance.md](cli-reference/profile-and-governance.md).
For a first-run walkthrough, see [getting-started.md](getting-started.md).

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
requests (this fallback is never written to disk).

## Loader source order

A profile is assembled from three layered sources. Higher-priority sources
override lower ones field-by-field:

1. **TOML file** — `<profile_dir>/<name>.toml` (lowest priority).
2. **Environment overlay** — variables prefixed `STELLAR_AGENT_`. For example,
   `STELLAR_AGENT_RPC_URL=https://...` overrides the `rpc_url` field.
3. **CLI overlay** — programmatic key/value pairs supplied by a command at
   resolve time (highest priority).

After merging, the loader resolves derived fields and validates:

- `network_passphrase` is always derived from `chain_id`; it is never read from
  the TOML or any overlay.
- `rpc_url` defaults to the chain's built-in endpoint when omitted, then is
  validated as a well-formed URL. A malformed URL fails the load.
- `audit_log_path` defaults to the OS-conventional location when omitted.
- A `version` 2 profile must carry an explicit `[policy]` section; a v2 file
  with no `[policy]` block is refused rather than silently inheriting a default
  engine.

## Schema version handling

Every profile carries a top-level `version` field. The loader dispatches on it:

- `version = 2` — the current schema; loads directly.
- `version = 1` — **not** loaded directly. The loader fails fast and the file
  must first be migrated with
  `stellar-agent profile migrate <name>` (see
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
| `network_passphrase` | string | resolved | from `chain_id` | The Stellar network passphrase. Resolved from `chain_id`; **not overridable** from the TOML or overlays. Surfaced for callers. |

### Signer and nonce references

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `[mcp_signer_default]` | keyring ref | yes | — | Keyring entry for the default MCP signer seed. Its `account` is the signer identity: `signer_from_keyring` verifies the loaded seed derives to it, so `account` must be the signer's G-strkey (public address), not a placeholder. Populate the entry with [`profile enroll-signer`](cli-reference/profile-and-governance.md#profile-enroll-signer). |
| `[mcp_nonce_key_alias]` | keyring ref | yes | — | Keyring entry for the HMAC nonce key. Here `account` is only a coordinate label. |

### Thresholds and fees

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `usd_threshold` | integer (stroops) | no | `0` | High-value cross-check threshold. The effective value is `max(usd_threshold, 10_000_000_000)`; the floor of 1000 XLM (10^10 stroops) cannot be configured lower, so a profile with `usd_threshold = 0` behaves as if it were the floor. Transactions at or above the effective threshold trigger the independent-RPC cross-check when `oracle_provider_url` is set. |
| `classic_fee_per_op_stroops` | integer | no | unset (protocol default) | Per-operation base fee for classic transactions, in stroops. When unset, classic tools use the built-in default. |
| `classic_max_fee_per_op_stroops` | integer | no | unset (no cap) | Per-operation fee cap, in stroops. When set, classic tools fail before envelope construction if the selected fee exceeds the cap. This is a guardrail, not a silent clamp. |
| `submit_timeout_seconds` | integer | no | `60` | How long the wallet polls for transaction confirmation. |

### Security-substrate key references

These four `KeyringEntryRef` fields name the keyring entries holding the
security substrate's keys. A migrated profile populates them with
default-derived names but mints no key material; the rotation commands mint the
actual keys (see [Migration and key rotation](#migration-and-key-rotation)).

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `[audit_log_hash_chain_key_id]` | keyring ref | yes | HMAC key signing the audit log's chain root. |
| `[policy_owner_key_id]` | keyring ref | yes | ed25519 owner PUBLIC key whose signature every V1 policy file must carry (enrolled with `profile enroll-owner-key`). |
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

Controls the [unlock window](concepts.md) — the short, TTL-bounded period during
which the 32-byte signing seed is resident in pinned, zeroize-on-drop memory.

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `mlock_required` | bool or `"warn"` | no | platform-dependent | `mlock(2)` failure posture. `true` (default on Linux/macOS): fail closed if the seed cannot be pinned in RAM. `"warn"` (default on Windows): proceed with unprotected memory and emit a warning. `false`: do not attempt memory locking. |
| `unlock_ttl_seconds` | integer | no | `30` | Unlock-window TTL in seconds, for the CLI `--secret-env` signing path. Must be in the range 1 to 600 (10 minutes); a value of 0 or above 600 is refused when the window is constructed, never clamped. |

### `[policy]` block

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `engine` | string | yes (in v2) | — | `"noop"` or `"v1"`. `noop`: testnet allow-all; mainnet read-only allowed; mainnet destructive operations refused with `policy.engine_required`. `v1`: signature-verified typed-criteria engine, first-match default-deny. Newly minted profiles default to `v1`; a profile migrated from v1 is set to `noop` explicitly. |

### `[remote_approval]` block

Optional; absent by default. Enables `approve serve --remote` — see
[Remote approval](remote-approval.md) for the full setup walkthrough.

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `enabled` | bool | no | `false` | Must be `true`, together with the CLI's `--confirm-remote-exposure` flag, for `--remote` to take effect. The profile block alone does not start remote mode. |
| `bind` | string | yes (if block present) | — | Socket address to bind, e.g. `"0.0.0.0:8443"`. Must parse as a valid address; validated fail-closed before any TLS provisioning or bind attempt. |
| `rp_id` | string | yes (if block present) | — | The WebAuthn Relying Party ID — a DNS hostname that resolves to this host from the approving device. Must NOT be an IP literal (WebAuthn Level 2 §5.1.2 forbids IP-literal Relying Party IDs); rejected fail-closed if it is one. |
| `allowed_credentials` | array of strings | no | `[]` | Base64url WebAuthn credential IDs authorized to approve or reject. A credential enrolled via `approve operator enroll` but absent from this list is refused identically to an unknown credential. |

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

## Migration and key rotation

A profile migrated from schema v1 stays on the `noop` engine, which keeps the
mainnet-write gate in force, until the operator completes key rotation and opts
in to `v1`. Migration populates the four security-key reference names but mints
no key material; the rotation commands below mint the actual keys.

### Migrate first

```bash
stellar-agent profile migrate my-profile
```

This rewrites the file in place (atomically), sets the four `*_key_id` reference
names, and sets `[policy] engine = "noop"`. Running it again on an
already-current profile is a no-op.

### Rotate each key

Each command generates fresh key material from the OS CSPRNG and stores it in the
named keyring entry. The CLI prints a JSON envelope and exits `0` on success, `1`
on error.

| Command | Mints into | Notes |
|---------|------------|-------|
| `stellar-agent profile enroll-owner-key` | `policy_owner_key_id` | Enrols the owner ed25519 PUBLIC key from an operator seed. Sign policy files with `profile sign-policy`; re-enrolling a different key invalidates policy files signed by the previous one. |
| `stellar-agent profile rotate-attestation-key <name>` | `attestation_key_id` | Fresh 32-byte HMAC key. All pending approvals are invalidated. |
| `stellar-agent profile rotate-audit-key <name>` | `audit_log_hash_chain_key_id` | Fresh 32-byte HMAC key. New audit-log files opened after rotation use the new key for their chain-root signature. |
| `stellar-agent profile rotate-counterparty-key <name>` | `counterparty_cache_key_id` | Fresh 32-byte HMAC key. All cached `stellar.toml` entries are invalidated and re-fetched on next use. |
| `stellar-agent profile rotate-nonce-key <name>` | `mcp_nonce_key_alias` | Fresh 32-byte HMAC key. Outstanding nonces minted with the old key are invalidated. |

### Enroll the MCP signer

The signer seed is imported, not minted: it is the operator's own account key.
Set `[mcp_signer_default] account` to that account's G-strkey (public address),
then import the matching `S...` secret from a named environment variable:

```bash
export WALLET_SK=S...signer-secret...
stellar-agent profile enroll-signer --profile <name> --secret-env WALLET_SK
```

Enrollment derives the seed's public address, refuses if it does not equal the
profile's `account` (printing the address to set `account` to), and stores the
seed in the keyring. Without it, the MCP tools and the keyring-signing CLI verbs
(`trustline`, `lend`, `trade`, `vault`) fail with `auth.keyring_not_found`. See
[cli-reference/profile-and-governance.md](cli-reference/profile-and-governance.md#profile-enroll-signer)
for flags and the envelope shape.

### Opt in to V1

After rotating the owner, attestation, and audit keys, set the engine to V1 in
the profile TOML:

```toml
[policy]
engine = "v1"
```

Until this is done, a migrated profile continues to run under `noop` and refuses
mainnet destructive operations. For the governance flow that V1 then enforces,
see
[cli-reference/profile-and-governance.md](cli-reference/profile-and-governance.md).

## Example profile

A minimal testnet profile on the V1 engine:

```toml
version = 2
chain_id = "stellar:testnet"
rpc_url = "https://soroban-testnet.stellar.org"
usd_threshold = 50000000000
mcp_disabled = false

[mcp_signer_default]
service = "stellar-agent-signer-my-profile"
account = "GABC...WXYZ"

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
