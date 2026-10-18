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

A profile is selected by name (the file stem): an explicit `--profile <NAME>`,
then the `STELLAR_AGENT_PROFILE` environment variable, then `default`. Both the
CLI and the MCP server resolve it that way, with no exceptions. When no name
was given and no `default.toml` exists yet, both fall back to an in-memory
testnet configuration — the MCP server so it can still serve read-only
requests, the CLI so `pay`, `claim`, and `accounts create` work before any
profile is authored. This fallback is never written to disk, and a profile that
WAS named but has no file is refused by both binaries rather than replaced by
it.

A profile name becomes a path component, so both binaries validate it before the
path is built: 1 to 64 printable ASCII characters; no `/`, `\`, `:`, or `..`; no
leading `-`; and not a Windows reserved device name (`CON`, `PRN`, `AUX`, `NUL`,
`COM1`-`COM9`, `LPT1`-`LPT9`, in any letter case). Windows cuts a name at the
first `.` and then drops trailing spaces before resolving it, so `NUL.toml`,
`nul `, and `nul .toml` all name the device and are all refused; `COM0`, `COM10`,
and `LPT0` are not reserved. The names `CONIN$` and `CONOUT$` are refused as
whole names only — Windows resolves those two console devices on an exact match,
so `conin$.toml` and `myconin$` stay valid. The last rules refuse names usable on
one host and not on another: a write to `NUL.toml` on Windows goes to the null
device, so the file never has content, and a name beginning with `-` is read as
the next flag by every argument parser that has to take it. The CLI exits `1`
with a typed refusal; `stellar-agent-mcp` exits `2` before serving. A profile
file already carrying such a name can no longer be selected — run `profile init`
under a valid name, or rename the file, correct its
`policy_owner_key_id.service`, and, on a `v1` profile, re-run
`profile enroll-owner-key` and `profile sign-policy` under the new name.

A profile file is bound to its name by its keyring coordinates. Renaming or
copying `<a>.toml` to `<b>.toml` does not create profile `b`; both binaries
refuse it under the new name with `profile.name_mismatch` — the MCP server at
startup, the CLI at every command that loads a profile. Use `profile init` for
a second profile, or correct the file's `policy_owner_key_id.service` to
`stellar-agent-owner-<name>`. `profile show <name>` still displays a
mismatched profile, so the offending field can be read.

Create a new profile file with `stellar-agent profile init` (name resolves
`--profile` -> `STELLAR_AGENT_PROFILE` -> `default`; testnet,
`engine = "v1"`); mainnet requires an explicit `https://` `--rpc-url`.
See [cli-reference.md](cli-reference.md) for flags.

`init` writes the `audit_log_hash_chain_key_id` coordinate only.
Run `stellar-agent profile rotate-audit-key <name>` before
`stellar-agent profile enroll-signer` so the first enrollment writes its audit row.
Then run `stellar-agent profile rotate-nonce-key <name>` before MCP payment simulation.
Every value-moving signing command requires the audit key on either engine,
refusing `audit.chain_key_unavailable` until it exists. See
[Approvals and audit](approvals-and-audit.md#fail-closed-on-an-unminted-audit-key).

## Loader source order

A profile is assembled from three layered sources. Higher-priority sources
override lower ones field-by-field:

1. TOML file: `<profile_dir>/<name>.toml` (lowest priority).
2. Environment overlay: variables prefixed `STELLAR_AGENT_`. For example, on a
   testnet profile `STELLAR_AGENT_RPC_URL=https://...` overrides the `rpc_url`
   field.
3. CLI overlay: programmatic key/value pairs supplied by a command at resolve
   time (highest priority).

The two overlays may set only these fields; a profile's trust roots come from
the file only:

| Class | Keys |
|---|---|
| Every chain | `submit_timeout_seconds` |
| Testnet only | See the testnet overlay keys below. |
| Tighten only, every chain | `mcp_disabled`, and only to `true` |

Testnet overlay keys are `rpc_url`, `secondary_rpc_url`, `oracle_provider_url`,
`mcp_signer_default`, `cross_check_threshold_stroops` (alias `usd_threshold`),
`cross_check_thresholds`, `classic_fee_per_op_stroops`, `classic_max_fee_per_op_stroops`,
`smart_account_max_context_rule_scan_id`, and `session_rule_max_horizon_ledgers`.

Every other key (`chain_id`, `version`, every `*_key_id` coordinate,
`mcp_nonce_key_alias`, `audit_log_path`, `policy`, `wallet`, `providers`, `remote_approval`,
`served_pages`, and the pool fields) is refused on every chain with
`profile.non_overlayable_field`, even when the value equals the file. A
`STELLAR_AGENT_*` variable that names no profile key, such as
`STELLAR_AGENT_HOME` or `STELLAR_AGENT_KEYRING_BACKEND`, is ignored.

After merging, the loader resolves derived fields and validates:

- `network_passphrase` is always derived from `chain_id`; it is never read from
  the TOML or any overlay.
- `rpc_url` defaults to the testnet endpoint when a testnet file omits it.
  Mainnet has no default endpoint, because no provider is implied: a mainnet
  file without `rpc_url` fails the load with
  `validation.mainnet_rpc_url_required`.
- `rpc_url`, `secondary_rpc_url`, and `oracle_provider_url` follow one
  endpoint rule. Each must be an `http` or `https` URL. On mainnet, each must
  be an `https` URL with no username or password; there is no plaintext
  exception for a loopback address. A value that breaks the rule fails the
  load with `validation.config_invalid`, and the message names the field, not
  the URL. A local development endpoint over plain HTTP belongs on a testnet
  profile. A provider key in the URL path or query passes this rule and stays
  in the file; a `credential` in the role's provider record keeps it in the
  keyring (see [Provider credentials](#provider-credentials)).
- Provider records must match their role's URL and satisfy the chain's
  independence rules in [Provider attestations](#provider-attestations) and
  the credential rules in [Provider credentials](#provider-credentials).
- `audit_log_path` defaults to the OS-conventional PER-PROFILE location
  (`<data root>/audit/<name>.jsonl`) when omitted; profiles never share an
  audit file unless one is configured explicitly. The first keyed audit write
  records the path's digest and the audit-key coordinate in the keyring as the
  profile's audit binding. A later edit to either refuses with
  `audit.log_binding_changed` until the operator acknowledges it. Two profile
  files of one name in two data roots that share one keyring refuse each
  other; set an explicit `audit_log_path` there.
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

`chain_id` and every other key outside the overlay classes above are read from the file on every chain. Mainnet also reads `rpc_url`, `secondary_rpc_url`, `oracle_provider_url`, `mcp_signer_default`, and the other testnet-only keys from the file only.

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
| `rpc_url` | string (URL) | on mainnet | testnet endpoint | Profile endpoint used by transaction commands. Omitted testnet values use `https://soroban-testnet.stellar.org`. Mainnet has no default endpoint, so a mainnet profile must set this field. Follows the endpoint rule in [Loader source order](#loader-source-order): `http` or `https`, and on mainnet `https` with no username or password. Mainnet endpoint flags and overlays are refused. `[providers.primary]` names its operator and host and can name a keyring credential for this endpoint. |
| `network_passphrase` | string | resolved | from `chain_id` | The Stellar network passphrase. Resolved from `chain_id`; not overridable from the TOML or overlays. Surfaced for callers. |

### Signer and nonce references

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `[mcp_signer_default]` | keyring ref | yes | — | Keyring entry for the default MCP signer seed. |
| `[mcp_nonce_key_alias]` | keyring ref | yes | — | Keyring entry for the HMAC nonce key. |

### Thresholds and fees

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `cross_check_threshold_stroops` | integer | no | `0` | Native threshold; see below. |
| `[cross_check_thresholds]` | table | no | empty | Asset thresholds; testnet-only overlay. |
| `classic_fee_per_op_stroops` | integer | no | unset (protocol default) | Per-operation base fee for classic transactions, in stroops. When unset, classic tools use the built-in default. |
| `classic_max_fee_per_op_stroops` | integer | mainnet, at action time | unset (no cap) | Per-operation fee cap, in stroops; see below. |
| `submit_timeout_seconds` | integer | no | `60` | How long the wallet polls for transaction confirmation. |

CLI `pay` and `claim` check the cap in the full pipeline, `--build-only`,
`--sign-only`, and `--submit-only`. MCP pay, create-account, trustline, and
claim check it in both prepare and commit. No other stage checks it, including
CLI `trustline`, sponsored `accounts create`, `pool init`, opaque staged
envelopes, and the SEP-43 signing tools.

The cap applies to the resolved auto-selected, explicit, profile, or command
fee, or the decoded envelope fee. A fee equal to the cap passes. A fee above
it refuses with `fees.percentile_exceeds_cap`, naming the fee's source.
At these covered stages, a mainnet profile without the cap refuses with
`validation.mainnet_fee_cap_required`. `profile init --network mainnet`
writes `10000`. The cap refuses an excessive fee; it never lowers the bid.

#### Witness thresholds

The native threshold is `max(cross_check_threshold_stroops, 10_000_000_000)`
stroops. The floor is 1000 XLM, so zero also means 1000 XLM.
An MCP payment or account-creation commit at or above its threshold needs an
oracle witness. A memo-less MCP payment needs a witness whenever an oracle is
configured, even below threshold or without a testnet asset threshold.
A mainnet profile without `oracle_provider_url` cannot run these required
comparisons. Testnet continues with a warning when the oracle is absent.
Mainnet writes remain structurally refused.

The legacy key `usd_threshold` also sets the native threshold. Setting both
names across the file, environment, or CLI sources refuses as a duplicate field.

`[cross_check_thresholds]` sets per-asset thresholds in base units. Keys are
case-sensitive `CODE:ISSUER` identities or canonical contract addresses (`C...`).
Native aliases, including `native` and `xlm` in any case, are refused.
Use `cross_check_threshold_stroops` for native XLM and its SAC.
A classic key also covers its Stellar Asset Contract on the profile's network.
Naming both identities for one asset refuses the load.
Values are non-negative integers or ASCII digit strings within the `i128` range.
The string form supports values above TOML's integer range.

On mainnet, a missing asset threshold refuses with `network.witness_unavailable`,
including a memo-less payment. On testnet, a payment with a memo and no asset
threshold skips the comparison with reason `no_threshold_for_asset`.
The memo-less rule above takes precedence on testnet.
A skipped or not-required outcome makes no oracle comparison of any kind.

This mainnet example sets thresholds for two different tokens: the classic
EURC asset and the USDC Stellar Asset Contract.

```toml
[cross_check_thresholds]
"EURC:GDHU6WRG4IEQXM5NZ4BMPKOXHW76MZM4Y2IEMFDVXBSDP6SJY4ITNPP2" = 5000000000
"CCW67TSZV3SSS2HXMBQ5JFGCKJNXKZM7UQUWUZPUTHXSTZLEO7SJMI75" = "1000000000000000000000"
```

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
| `oracle_provider_url` | URL | no | unset | Oracle witness endpoint; see below. |
| `mcp_disabled` | bool | no | `false` | When `true`, the `stellar-agent-mcp` server refuses to start with error `mcp.disabled_per_profile`. |
| `audit_log_path` | string (path) | no | OS-conventional | Path to the per-profile audit log. |
| `secondary_rpc_url` | string (URL) | no | unset | Secondary endpoint for cross-RPC checks. `smart-account multicall` requires an effective secondary from the profile or a testnet flag. Follows the endpoint rule in [Loader source order](#loader-source-order). Mainnet reads this field from the file only and requires `providers.secondary`, its independence assertion, a host distinct from the primary, and a `[providers.primary]` record. Debug output is redacted. `providers.secondary` can name a keyring credential; the smart-account and DeFi commands that read this endpoint send none. |
| `smart_account_max_context_rule_scan_id` | integer | no | engine default | Override for the maximum rule-id scan bound. Rejected at load when above `10000`. |
| `session_rule_max_horizon_ledgers` | integer | no | engine default | Override for the maximum session-rule lookahead window, in ledgers. Rejected at load when above `10000`. |

#### Oracle witness endpoint

`oracle_provider_url` supplies the oracle for MCP payment and account-creation
commits. Before signing, the oracle re-reads the ledger entries the decision used.
When a required witness has no oracle, mainnet refuses and testnet warns.
A mainnet profile requires `providers.oracle`, a host distinct from `rpc_url`,
and a `[providers.primary]` record. Endpoint validation and URL redaction apply.
`providers.oracle` can name a keyring credential for the endpoint.


### Provider attestations

Edit the profile file to configure the optional URLs and provider records.
No CLI flag sets them.
`profile enroll-rpc-credential` adds `credential` and `placement` to an existing record and changes nothing else.
A file with mixed line endings is written with LF endings.
On mainnet, each configured secondary or oracle URL requires its matching record,
a true independence assertion, and a host distinct from the primary.
On mainnet, a configured secondary or oracle URL also requires a `[providers.primary]` record.
On every chain, a record asserting `independent_of_primary = true` needs a host distinct from the primary.
Secondary and oracle may share a host and operator; each role keeps its own record.

```toml
# Merge these root keys into an existing profile before any table header.
rpc_url = "https://primary.example/rpc"
secondary_rpc_url = "https://independent.example/secondary"
oracle_provider_url = "https://independent.example/oracle"

[providers.primary]
operator = "Primary RPC Organization"
host = "primary.example"

[providers.secondary]
operator = "Independent RPC Organization"
host = "independent.example"
independent_of_primary = true

[providers.oracle]
operator = "Independent RPC Organization"
host = "independent.example"
independent_of_primary = true
```

Set `operator` to the organization administering the endpoint and `host` to its host.
The loader normalizes both hosts for comparison and preserves the record as written.
Normalization uses the URL crate's host, IDNA, canonical IP text, and one removed trailing dot.
HTTP and HTTPS hosts are lowercase; IPv6 keeps brackets.
A record host cannot include a scheme, port, userinfo, path, or whitespace.
The check compares hosts only: scheme, port, userinfo, path, query, and fragment are ignored, and a different subdomain counts as a different host.
One provider often serves several hostnames, so a different host does not show a different provider.
The host predicate is a naming convention, not a proof; the operator attestation carries the responsibility.

On testnet, records may be absent or assert false; present records still need an operator and matching host.
Environment and programmatic URL overlays are checked against a present file record.
Changing such an overlay to another host requires updating the file record.
CLI flags and the `stellar_fee_stats` `rpc_url` input override after loading, are not checked against these records, and get the primary credential only when the value equals the profile's `rpc_url`.
The `--secondary-rpc-url` flag and the MCP secondary input send no credential.
Remove a role's record when removing its URL; URLs absent together with their records remain allowed.
Provider records are file-only on every chain and appear in `profile show` and `Debug` because operator and host are not secrets.
Do not put credentials in these metadata fields.
`[providers.primary]` names the operator and host of `rpc_url` and may carry a credential; it takes no `independent_of_primary`.
On mainnet, a secondary or oracle record naming the primary's operator, compared after trimming and case folding, refuses.
Provider refusals use `validation.provider_attestation_invalid`; the message identifies the field and its repair.
On testnet, an oracle sharing the primary host emits the degraded-verification warning.
This also applies when its path or query differs, or its record names the primary's operator.

### Provider credentials

A provider record can name the keyring entry that holds the provider's key for its endpoint, and where requests carry the key.
The key itself lives only in the keyring; the reference and the placement are public metadata and print in `profile show`.

```toml
[providers.primary]
operator = "Example RPC Ltd"
host = "rpc.example.com"
credential = { service = "stellar-agent-rpc-prod", account = "primary" }
placement = { kind = "header", name = "X-API-Key" }
# placement = { kind = "query", name = "apikey" }
# placement = { kind = "path" }
```

The loader checks a record that names a credential:

- `credential` and `placement` come together.
- `credential` holds exactly `service` and `account`, each printable ASCII without leading or trailing spaces.
- `credential` names no entry another wallet key of the profile uses, and no service in the `stellar-agent-` namespace except under `stellar-agent-rpc-`.
- A header placement sends the stored value as the header value, a scheme such as `Bearer ` included. The name follows the HTTP token rule; `Host`, `Content-Type`, `Content-Length`, `Accept`, `Connection`, `Transfer-Encoding`, `TE`, `Trailer`, `Upgrade`, and `Keep-Alive` refuse, and `Authorization` is allowed.
- A query placement appends `name=value`, form-urlencoded. The name uses ASCII letters, digits, `-`, `.`, `_`, and `~`, and repeats no parameter of the endpoint URL.
- A path placement appends the value as one percent-encoded path segment. A path ending in `/`, a bare host included, keeps the trailing slash: `https://h/` becomes `https://h/KEY/`, and `https://h/v2` becomes `https://h/v2/KEY`.
- The role's URL uses `https` unless its host is a loopback address (`localhost`, `127.0.0.0/8`, or `[::1]`), and it carries no username or password.

Look up the header or parameter name in your provider's documentation.
Store the key with `stellar-agent profile enroll-rpc-credential`; see [the CLI reference](cli-reference.md).
The stored value is at most 1024 bytes and holds no control character.

A client reads the key from the keyring when it is built for the role's URL from the profile.
A URL that differs by any byte, such as a CLI flag or the `stellar_fee_stats` `rpc_url` input, gets no credential, and no keyring entry is opened.
A testnet environment overlay of the role's URL keeps the credential, because the loader checked the record against the merged URL.

These commands send the primary credential: `pay`, `claim`, `accounts create --sponsor`, `trustline`, `pool init`, `pool list`, `tx status`, `tx receipt clear`, and `fees stats --profile`.
The MCP classic tools send it too: `stellar_pay`, `stellar_create_account`, `stellar_trustline`, `stellar_claim` and their commits, `stellar_balances`, `stellar_transaction_status`, `stellar_fee_stats`, and the x402 tools.
The cross-check witness sends the oracle credential.
`balances` takes `--rpc-url` without a profile and sends none.
The Friendbot path of `accounts create`, `stellar_friendbot`, `stellar_sep43_sign_and_submit_transaction`, and the smart-account, DeFi, and MPP commands and tools send none either.

A missing entry reports `auth.keyring_not_found` naming `service/account`.
A stored value that is empty, longer than 1024 bytes, or holds a control character reports `network.rpc_credential_refused`.
An endpoint that answers a request with HTTP 401 or 403 reports the same code.
That request is not retried.
The client removes the stored value and the form it sends from every error text it returns, before it shortens URLs to host and port.
A key the endpoint re-encodes, truncates, or splits is not caught.

### `[wallet]` block

These controls apply to every CLI seed read, including `pay`, `claim`, and `accounts create`. The zero-config testnet profile uses the `"warn"` posture and a 30-second TTL.

Controls the unlock window — the short, TTL-bounded period during which the
32-byte signing seed is resident in pinned, zeroize-on-drop memory.

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `mlock_required` | bool or `"warn"` | no | platform-dependent | `mlock(2)` failure posture. `true` (default on Linux/macOS): fail closed if the seed cannot be pinned in RAM. `"warn"` (default on Windows): proceed with unprotected memory and emit a warning. `false`: do not attempt memory locking. The posture is set in this file and is not overlayable. |
| `unlock_ttl_seconds` | integer | no | `30` | Unlock-window TTL in seconds. Hard cap `600` (10 minutes); a value above the cap is refused when the window is constructed. Operators may shorten the window. |

### `[policy]` block

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `engine` | string | yes (in v2) | — | `"noop"` or `"v1"`. `noop`: testnet allow-all; mainnet read-only allowed; mainnet destructive operations refused with `policy.engine_required`; `smart-account multicall` refused on testnet with `policy.engine_required`, since mainnet refuses it earlier with `network.mainnet_write_forbidden`. `v1`: signature-verified typed-criteria engine, first-match default-deny. Newly minted profiles default to `v1`; a profile migrated from v1 is set to `noop` explicitly. |

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

- The profile TOML holds no secret when no endpoint URL embeds a key; it is
  then safe to back up and to copy between hosts. Keep provider keys in the
  keyring through `providers.<role>.credential` (see
  [Provider credentials](#provider-credentials)). The keyring backend is the
  actual defence for secret material.
- `rpc_url`, `secondary_rpc_url`, and `oracle_provider_url` are redacted in
  debug output because URLs may embed credentials. `profile show` prints them
  as scheme, host, and port. A mainnet profile whose endpoint URL carries a
  username or password refuses to load; remove the userinfo from the file. A
  testnet file may hold such a URL, and the TOML retains the full URL, so
  avoid embedding credentials if the file is shared.
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
- `STELLAR_AGENT_KEYRING_BACKEND=headless-env`: any platform; entries are
  encrypted with XChaCha20-Poly1305. Supply 32 random bytes, encoded as URL-safe
  base64 without padding, in `STELLAR_AGENT_HEADLESS_KEYRING_KEY`.
  See the [POSIX shell and PowerShell generation commands](https://github.com/Soneso/stellar-agent-wallet/blob/main/docs/getting-started.md#generate-a-headless-keyring-key).

The platform keyring remains the default when the variable is unset; there is
no silent fallback in either direction — a misconfigured backend fails closed
with `auth.keyring_config_invalid` rather than switching stores. In `headless-env` mode the operator-held
environment key is the custody boundary: whoever can read the process
environment can decrypt the store, so scope it to the service user.

A profile migrated from schema v1 stays on the `noop` engine until the operator
completes key rotation and opts in to `v1`. Migration populates the four
security-key reference names but mints no key material; the rotation commands
below mint the actual keys. The engine choice governs the policy layer only:
every mainnet write is additionally refused at the network layer
(`network.mainnet_write_forbidden`) in this alpha, on `noop` and `v1` alike.
That layer binds each submission to the network the RPC endpoint reports it
serves, not to the profile's declared `network_passphrase`. A profile whose
`rpc_url` and network do not name the same chain is refused before anything is
sent (`network.endpoint_network_mismatch`). The classic payment, sponsored
account creation, trustline, claim, and pool paths refuse it before their
first read. The same answer carries the endpoint's protocol version, checked
against the supported range as
[cli-reference.md](cli-reference.md#submit-layer-network-binding) describes.
MPP refuses mainnet with `mpp.network_forbidden` instead of
`network.mainnet_write_forbidden`.

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
`S...` seed; only the public key is stored, as its G-strkey) and whose seed signs
policy files via `stellar-agent profile sign-policy`. Re-enrolling a different
owner key invalidates policy files signed by the previous one. Every symmetric
key loader refuses a coordinate in the owner namespace and a key equal to the
owner public key, with `validation.key_matches_owner_public_key`. An owner entry
in the older base64 form is rewritten as its G-strkey by the next V1 verb or
`enroll-owner-key`, for every profile in the profile directory.

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
(`trustline`, `trade`, `vault`) resolves. On a clean install that entry
is absent and those paths fail with `auth.keyring_not_found`.

The operator sets `WALLET_SK` as [Pass a secret seed](https://github.com/Soneso/stellar-agent-wallet/blob/main/docs/getting-started.md#pass-a-secret-seed) shows. In the operator's terminal, run this line on its own, paste the signer seed when prompted, and press Enter. The line reads the seed from the terminal, so the operator runs it, not the agent.

```bash
printf 'WALLET_SK seed: ' && read -rs WALLET_SK && echo && export WALLET_SK
```

```bash
stellar-agent profile enroll-signer --profile default --secret-env WALLET_SK
unset WALLET_SK
```

Flags: `--secret-env <VAR>` (required; the variable NAME, never the secret),
`--profile <NAME>` (resolves `--profile` -> `STELLAR_AGENT_PROFILE` ->
`default`), `--expected-address <G_STRKEY>` (refuse
unless the seed derives to it), `--force` (replace an already-enrolled entry).
Enrollment derives the seed's public address. A profile fresh from
`profile init` (and a v1-migrated profile that still carries it) holds the placeholder `"default"` in
`mcp_signer_default.account`; enrollment overwrites it in place with the
derived address. A profile whose `account` already pins a G-strkey — from a
prior enrollment, or set by hand — is left untouched, and enrollment refuses if
the seed does not derive to that exact address, printing the address to set
`account` to.

### Opt in to V1

Complete these steps for a persistent profile, using its name in place of `<name>`:

1. `stellar-agent profile rotate-audit-key <name>`: mint the audit key before
   the first key-writing command so its audit row is written.
2. [Enroll the MCP signer](#enroll-the-mcp-signer): register the signer seed.
3. `stellar-agent profile rotate-nonce-key <name>`: mint the nonce key before
   MCP payment simulation. Without it, simulation fails with `nonce.mint_failed`.
4. `profile enroll-owner-key`, then `profile rotate-attestation-key <name>`:
   enroll the policy owner and mint the approval key.
5. [Create the V1 policy file](https://github.com/Soneso/stellar-agent-wallet/blob/main/docs/profiles.md#create-the-v1-policy-file), then run `profile sign-policy`. A missing file refuses with `sign_policy.policy_file_unreadable`.

An `init`-minted profile already carries `engine = "v1"`. This setup supplies
its policy and key prerequisites. A profile migrated from schema v1 stays on
`noop`; after completing these steps, set the engine in the profile TOML:

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
