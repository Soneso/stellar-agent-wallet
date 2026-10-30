# Profile configuration reference

See [Mainnet configurations and scope](getting-started.md#mainnet-configurations-and-scope)
for build configuration, admitted operations, and exclusions.

A **profile** is a per-environment TOML config file (schema `version = 2`) that
binds a CAIP-2 chain, an RPC endpoint, a set of keyring entry references,
behavioural thresholds, and the active policy engine. It is the single source of
truth that the `stellar-agent` CLI, the `stellar-agent-mcp` server, and the
policy engine all read.

A profile holds **no keys**. Every key it references lives in the platform
keyring; the profile only names those entries. An endpoint URL can still
embed a credential. See [Secret discipline](#secret-discipline) below.

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

A profile is selected by name (the file stem). Both binaries resolve the name
the same way: an explicit `--profile <NAME>`, then the `STELLAR_AGENT_PROFILE`
environment variable, then `default`. When no name was given and no
`default.toml` exists yet, both fall back to an in-memory testnet
configuration. The fallback lets the MCP server serve read-only requests and
the CLI run `pay`, `claim`, and `accounts create` before any profile is
authored. This fallback is never written to disk. A profile that WAS named but
has no file is refused by both binaries rather than replaced by that fallback:
the fallback is a testnet, no-policy-engine configuration, so substituting it
for a profile you named would answer on the wrong network under a governance
setting you did not choose.

A profile file is bound to its name by its keyring coordinates: renaming or
copying `<a>.toml` to `<b>.toml` does not make it profile `b`. Both binaries
refuse it under the new name. The MCP server refuses it at startup, and the CLI
refuses it at every command that loads a profile, with the wire code
`profile.name_mismatch`. The
refusal names both profiles and quotes the offending
`policy_owner_key_id.service`. Recover by creating the second profile with
`profile init --profile <name>`, or by correcting that field to
`stellar-agent-owner-<name>`.

`profile show <name>` is the one command that still displays a mismatched
profile: it is what you read to find the offending field.

After name reconciliation, both binaries compare keyring entries with sibling
profile files in the same profiles directory. Mainnet conflicts refuse with
`profile.key_scope_conflict`; testnet conflicts warn and keep the verb's behavior.
The check includes wallet keys, provider credentials and derived entries.
Provider credentials may share with other provider credentials, but cannot share
with wallet or derived entries. Two fields in one profile cannot name one entry,
and the owner account must be `default`. Explicit wallet references must be set
in the file; an out-of-scope overlay is a conflict.
A mainnet profile's `policy_window_state_key_id` must name its default entry,
`stellar-agent-policy-window-<name>` with account `default`, even when the file
sets it explicitly. The policy pin and the mainnet enablement nonce sit beside
that entry, so another entry would start from an empty pin and nonce.

A copied profile file, including a backup in that directory, counts as a sibling.
If this profile names a sibling's entry, give this profile its own entry.
If the sibling claims this profile's canonical entry, correct the sibling file.
Moving an enrolled reference orphans its stored key; enroll or rotate at the new
entry before use. An unreadable sibling warns and is skipped on both chains.
An unreadable selected document or profiles directory refuses on mainnet and
warns on testnet. `profile show` still displays the document for diagnosis.

Message signing refuses signer-scope conflicts on every chain with
`profile.key_scope_conflict`. This includes the signer's enrolled identity entry
and a signer account matching a mainnet sibling (`mainnet_signer_identity`).
An unreadable sibling, selected document, or profiles directory also refuses
message signing. Both message tools reject an `mcp_signer_default` overlay with
`profile.non_overlayable_field`, even on testnet. Other testnet tools retain
the overlay behavior. The comparison covers the selected data root; the keyring
entry remains the custody boundary for keys accessible outside that root.

The policy spend window does not travel with a copied file either. Rolling
caps (`per_period_cap`, `rate_limit`, and their bundle forms) accumulate in a
per-profile store keyed on the profile's `policy_window_state_key_id`. A copy
that keeps that field shares the original's anti-rollback counter while
pointing at a store file that does not exist, so every value-moving command
can refuse on its generation check. Mainnet key-scope reconciliation already
refuses the shared entry. A copy without the field starts a fresh, empty window;
the original's spend does not count against it. Neither is a way to inherit or reset a spend window on
purpose. Use `profile init` for a new profile and `profile reset-window-state`
for a deliberate reset. Amount caps size outbound value, so a vault withdrawal,
which returns underlying assets and burns the wallet's shares, reserves no
amount against them.

`profile list` lists all profile names and takes no profile selector.
Every other `profile` subcommand accepts `--profile <NAME>`.
`show`, `migrate`, the `rotate-*` commands, `reset-window-state`, and
`reset-mpp-state` accept exactly one positional `<NAME>` or `--profile <NAME>`.

Create a new profile file with `stellar-agent profile init`; see
[cli-reference/profile-and-governance.md](cli-reference/profile-and-governance.md#profile-init)
for flags and defaults.

Save profile edits as UTF-8; a UTF-8 BOM is accepted. In PowerShell, use
`Set-Content -Encoding utf8`. Windows PowerShell 5.1's `Out-File` and `>` default
to UTF-16LE, which the loader refuses. The surfaced code depends on the command:
`profile show` reports `validation.config_invalid`; `pay` reports `profile.load_failed`.

## Profile names

A profile name becomes a path component of the profile file itself and of the
per-profile audit log and policy-window state files derived from it, so both
binaries validate it before building any path. A name must be:

- 1 to 64 printable ASCII characters (`0x20`-`0x7E`), no control characters;
- free of `/`, `\`, `:`, and `..`, and not `.` or `..` itself;
- not beginning with `-`;
- not a Windows reserved device name (`CON`, `PRN`, `AUX`, `NUL`,
  `COM1`-`COM9`, `LPT1`-`LPT9`) in any letter case. Windows reduces a name to
  the device it names by cutting it at the first `.` and then dropping trailing
  spaces, so `NUL.toml`, `nul `, and `nul .toml` all name the NUL device and are
  all refused. `COM0`, `COM10`, and `LPT0` are not reserved and stay valid names.
- not exactly `CONIN$` or `CONOUT$`, in any letter case. Windows resolves these
  two console devices on the whole name only, so `conin$.toml` and `myconin$`
  stay valid names.

The last three rules refuse names that work on one host and not on another.
`<profile_dir>/NUL.toml` opens the NUL device on Windows rather than a file, so
a write to that path is discarded and a read returns nothing, while the path
itself still reports as present. A name beginning with `-` is read as the next
flag by every argument parser that has to take it, so `--profile -x` selects no
profile at all.

An unusable name is refused before the profile path is built: the CLI exits `1`
with a typed refusal quoting the name and the rule it broke, and
`stellar-agent-mcp` exits `2` before serving anything.

A profile file that already carries such a name (possible on Unix, where both
classes are legal file names) can no longer be selected. The clean recovery is
`stellar-agent profile init --profile <new-name>` followed by the enrollment
steps that command prints. Renaming the file works too, but the name is part of
the profile's identity: correct `policy_owner_key_id.service` to
`stellar-agent-owner-<new-name>`, and on a `v1` profile also re-run `profile
enroll-owner-key` and `profile sign-policy` under the new name. The owner key
is stored under `stellar-agent-owner-<old-name>` and the signed policy file
carries the old name in its signed scope, so neither is usable under the new
one.

## Loader source order

The profile file is the record the operator audits, and a profile's trust
roots come from that file only. An environment or programmatic overlay may set
a fixed allowlist of operational fields, in three classes:

| Class | Keys |
| --- | --- |
| Every chain | `submit_timeout_seconds` |
| Testnet only | See the testnet overlay keys below. |
| Tighten only, every chain | `mcp_disabled`, and only to `true` |

Testnet overlay keys are `rpc_url`, `secondary_rpc_url`, `oracle_provider_url`,
`mcp_signer_default`, `cross_check_threshold_stroops` (alias `usd_threshold`),
`cross_check_thresholds`, `classic_fee_per_op_stroops`, `classic_max_fee_per_op_stroops`,
`smart_account_max_context_rule_scan_id`, and `session_rule_max_horizon_ledgers`.

Every other profile key is never overlayable, on any chain: `chain_id`,
`version`, every `*_key_id` coordinate and `mcp_nonce_key_alias`,
`audit_log_path`, `policy`, `wallet`, `providers`, `remote_approval`, `served_pages`,
`pool_master_key_id`, `pool_config`, and `pool_initialization`. An overlay
naming one is refused with `profile.non_overlayable_field`, even when its value
equals the file; an equal overlay can hide a later edit to the audited record.
An overlay that sets `mcp_disabled` to anything but `true` is refused with the
same code. The loader checks `chain_id` first and then each key in a fixed
order, so the refused key it names is the same on every run. A nested key is
checked by its top-level name, so `wallet.mlock_required` is `wallet`. A
`STELLAR_AGENT_*` variable that names no profile key, such as
`STELLAR_AGENT_HOME`, `STELLAR_AGENT_PROFILE`, `STELLAR_AGENT_KEYRING_BACKEND`,
`STELLAR_AGENT_HEADLESS_KEYRING_KEY`, or `STELLAR_AGENT_LOG`, is not an overlay
and is ignored.

The permitted fields merge in increasing priority:

1. **TOML file:** `<profile_dir>/<name>.toml`.
2. **Environment overlay:** variables prefixed `STELLAR_AGENT_`.
3. **Programmatic overlay:** key/value pairs supplied by a command.

A mainnet profile loads only through `--profile <name>`. `STELLAR_AGENT_PROFILE` never selects one, and a mainnet `default.toml` needs `--profile default`. Keep the filename: its identity is bound to its keyring entries.

To recover from the refusal, unset the `STELLAR_AGENT_*` variable for the key the message names, set the value in the profile file if it is needed, and remove the key from programmatic overlays too. On mainnet that includes `STELLAR_AGENT_RPC_URL`, `STELLAR_AGENT_SECONDARY_RPC_URL`, `STELLAR_AGENT_ORACLE_PROVIDER_URL`, and `STELLAR_AGENT_MCP_SIGNER_DEFAULT`; on every chain it includes `STELLAR_AGENT_CHAIN_ID` and `STELLAR_AGENT_AUDIT_LOG_PATH`. Then run `stellar-agent profile show --profile <name>` to confirm the file's chain and endpoint. Correct the profile file if either value differs from the intended configuration.

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
  `audit.log_binding_changed` until the operator runs `stellar-agent audit
  reanchor --profile <name> --acknowledge-binding-change`. The default derives
  from the OS data directory, which follows `$HOME` and `$XDG_DATA_HOME`. Two
  profile files of one name in two data roots that share one keyring therefore
  bind different digests and refuse each other. Set an explicit
  `audit_log_path` in such a deployment.
- A `version` 2 profile must carry an explicit `[policy]` section; a v2 file
  with no `[policy]` block is refused rather than silently inheriting a default
  engine.

Overlays are load-time-only. Commands that update an existing profile
(`profile enroll-signer`, `pool init`) patch only the keys they own on the
on-disk document; the merged view is never written back, so a transient
override cannot become persistent configuration and derived defaults are not
materialised into the stored file.

Enabled writes require an explicit nondefault mainnet profile whose stored
chain and normalized endpoint host match its installation binding. A mainnet
`default` profile can serve reads but cannot be enabled for writes.

## Schema version handling

Every profile carries a top-level `version` field. The loader dispatches on it:

- `version = 2`: the current schema; loads directly.
- `version = 1`: **not** loaded directly. The loader fails fast and the file
  must first be migrated with
  `stellar-agent profile migrate <name>` (see
  [Migration and key rotation](#migration-and-key-rotation)).
- `version > 2`: refused. A profile written by a newer wallet is rejected so an
  older wallet never silently applies stale defaults.

## Field reference

Fields are written at the top level of the TOML unless a `[section]` header is
shown. Keyring entry reference fields (`KeyringEntryRef`) are TOML tables with a
`service` and an `account` key; they name a keyring entry and never hold a
secret.

### Network and identity

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `version` | integer | yes | none | Schema version. Must be `2`. |
| `chain_id` | string (CAIP-2) | yes | none | `stellar:testnet` or `stellar:mainnet`. Drives passphrase resolution and the mainnet-write gate. |
| `rpc_url` | string (URL) | on mainnet | testnet endpoint | Profile endpoint used by transaction commands. Omitted testnet values use `https://soroban-testnet.stellar.org`. Mainnet has no default endpoint, so a mainnet profile must set this field. Follows the endpoint rule in [Loader source order](#loader-source-order): `http` or `https`, and on mainnet `https` with no username or password. Mainnet endpoint flags and overlays are refused. `[providers.primary]` names its operator and host and can name a keyring credential for this endpoint. |
| `network_passphrase` | string | resolved | from `chain_id` | The Stellar network passphrase. Resolved from `chain_id`; **not overridable** from the TOML or overlays. Surfaced for callers. |

### Signer and nonce references

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `[mcp_signer_default]` | keyring ref | yes | none | Keyring entry for the default MCP signer seed. Its `account` is the signer identity: `signer_from_keyring` verifies the loaded seed derives to it, so `account` must be the signer's G-strkey (public address), not a placeholder. Populate the entry with [`profile enroll-signer`](cli-reference/profile-and-governance.md#profile-enroll-signer). |
| `[mcp_nonce_key_alias]` | keyring ref | yes | none | Keyring entry for the HMAC nonce key. Here `account` is only a coordinate label. |

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
claim check it in both prepare and commit. CLI sponsored `accounts create`,
`trustline`, and every sending `pool init` path also check the cap.
Opaque, fee-bump, and multi-operation staged envelopes and the SEP-43 signing
tools remain outside this coverage.

The cap applies to the resolved auto-selected, explicit, profile, or command
fee, or the decoded envelope fee. A fee equal to the cap passes. A fee above
it refuses with `fees.percentile_exceeds_cap`, naming the fee's source.
Mainnet action checks use the smaller signed/profile cap, or the one available
value. A higher profile value warns. The enabled-policy minimum requires the
signed cap even when a profile cap exists. MCP preparation uses this effective
cap too. The resolver checks it independently when authorizing the action.
A missing effective cap reports `validation.mainnet_fee_cap_required`.
A total-fee overflow reports `validation.fee_total_overflow`. Resolver fee
failures become `network.mainnet_authorization_refused`.
`profile init --network mainnet` writes `10000`. The cap never lowers the bid.

Full-mode CLI `pay`, `claim`, sponsored `accounts create`, and `trustline`
include `total_fee_stroops` in policy arguments on both networks. It is a JSON
number equal to the unsigned envelope's `tx.fee`. `pay --build-only` and
`claim --build-only` include it too.
Mainnet excludes staged modes and pool submission.

#### Witness thresholds

The native threshold is `max(cross_check_threshold_stroops, 10_000_000_000)`
stroops. The floor is 1000 XLM, so zero also means 1000 XLM.
Payment and account-creation stages require a witness at or above their threshold.
They use the source debit or starting balance. A memo-less payment requires one
whenever an oracle is configured, including below threshold on testnet.
Trustline changes, claims, and pool initialization are unvalued: they require a
witness whenever an oracle is configured. Without an oracle, testnet reports
`skipped`; the mainnet requirement rule refuses `network.witness_unavailable`.
A mainnet profile without an oracle refuses before that rule, with
`profile.mainnet_oracle_required`.
Caller checks do not replace the resolver's bound witness checks.
A resolver-detected witness gap reports `network.mainnet_authorization_refused`.

The classic witness covers CLI `pay`, `claim`, sponsored `accounts create`,
`trustline`, and every sending `pool init` path. It also covers MCP
`stellar_pay_commit`, `stellar_create_account_commit`, `stellar_trustline_commit`,
and `stellar_claim_commit`. The x402 payment tools `stellar_x402_create_payment`
and `stellar_x402_authenticated_payment` are covered by a second simulation on
the oracle: before the payer signs, the oracle simulates the same unsigned
transfer, and the answers are compared. For admitted mainnet x402 payments,
signed and profile thresholds determine the required witness. The oracle compares
the unsigned transfer before the payer signs. Opaque staged envelopes and the
SEP-43 signing tools remain uncovered.

On an enabled profile, signed and profile thresholds combine per asset using
the smaller value. A higher profile threshold warns. One available value
suffices; another asset's threshold never covers a missing one. A signed
threshold is a positive TOML integer or a positive decimal string within the
i128 range. Signed threshold keys are pinned asset identities. Classic assets
and their SAC representations share network-specific identity. Duplicate
equivalents and native-SAC aliases refuse.

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

These five `KeyringEntryRef` fields name the keyring entries holding the
security substrate's keys. A migrated profile populates them with
default-derived names but mints no key material; the rotation commands mint the
actual keys (see [Migration and key rotation](#migration-and-key-rotation)).

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `[audit_log_hash_chain_key_id]` | keyring ref | yes | HMAC key signing the audit log's chain root. |
| `[policy_owner_key_id]` | keyring ref | yes | ed25519 owner PUBLIC key whose signature every V1 policy file must carry (enrolled with `profile enroll-owner-key`). |
| `[attestation_key_id]` | keyring ref | yes | HMAC key minting approval attestations at `approve` time. |
| `[counterparty_cache_key_id]` | keyring ref | yes | HMAC key protecting the local `stellar.toml` cache integrity. |
| `[policy_window_state_key_id]` | keyring ref | no (name-derived default) | HMAC key protecting the persisted policy-window-state store (`per_period_cap` / `rate_limit` / `bundle_per_period_cap` / `bundle_rate_limit` accumulated history). Absent from profiles predating this field; the loader derives `stellar-agent-policy-window-<profile>` when omitted, so existing profile TOMLs keep loading unchanged. |

### Cross-check, MCP, and scan bounds

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `oracle_provider_url` | URL | for mainnet enablement and mainnet writes | unset | Oracle witness endpoint, with its `providers.oracle` record. Mainnet reads run without it; see below. |
| `mcp_disabled` | bool | no | `false` | When `true`, the `stellar-agent-mcp` server refuses to start with error `mcp.disabled_per_profile`. |
| `audit_log_path` | string (path) | no | OS-conventional | Path to the per-profile audit log. |
| `secondary_rpc_url` | string (URL) | no | unset | Secondary endpoint for cross-RPC checks. `smart-account multicall` requires an effective secondary from the profile or a testnet flag. Follows the endpoint rule in [Loader source order](#loader-source-order). Mainnet reads this field from the file only and requires `providers.secondary`, its independence assertion, a host distinct from the primary, and a `[providers.primary]` record. Debug output is redacted. `providers.secondary` can name a keyring credential; the smart-account and DeFi commands that read this endpoint send none. |
| `smart_account_max_context_rule_scan_id` | integer | no | engine default | Override for the maximum rule-id scan bound. Rejected at load when above `10000`. |
| `session_rule_max_horizon_ledgers` | integer | no | engine default | Override for the maximum session-rule lookahead window, in ledgers. Rejected at load when above `10000`. |

#### Oracle witness endpoint

`oracle_provider_url` supplies the oracle for MCP payment and account-creation
commits. Before signing, the oracle re-reads the ledger entries the decision used.
Mainnet enablement and mainnet writes require the oracle; mainnet reads run
without it. A mainnet profile that sets `oracle_provider_url` without its
`providers.oracle` record does not load: commands report the loader's
`validation.provider_attestation_invalid`, and `profile enable-mainnet`
reports `profile.enable_mainnet_precondition` with the loader's message. A
mainnet profile that loads without `oracle_provider_url` is refused with
`profile.mainnet_oracle_required`: `profile enable-mainnet` refuses before it
reads a keyring entry and writes no enablement state, and every mainnet
write, in the CLI and in the MCP server, refuses before any signature. An
enabled profile whose oracle is removed refuses every mainnet write until the
oracle is set again. The MCP server reads the profile at startup, so it
applies an oracle change from its next start. On testnet the oracle is
optional, and a required witness without one warns.
For the x402 payment tools, the oracle simulates the same unsigned transfer the
primary simulated, and the answers are compared before the payer signs.
Both admitted mainnet x402 tools obtain the required witness before the payer signs.
Missing required evidence refuses the payment.
A mainnet profile requires `providers.oracle`, a host distinct from `rpc_url`,
and a `[providers.primary]` record. Endpoint validation and URL redaction apply.
`providers.oracle` can name a keyring credential for the endpoint.

On mainnet the oracle also witnesses settlement, once it reports the mainnet
passphrase. A submission the primary endpoint reports failed, refused, or
unknown is settled on the oracle's answers: its transaction status, and for an
unknown transaction its retention window, ledger close time and account
sequence. When the profile names no oracle at settlement, as after the
operator removes it, every such submission stays pending, with its
spending-window reservation held, until the operator clears it with
`stellar-agent tx receipt clear`.

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
Store the key with `stellar-agent profile enroll-rpc-credential`; see [the command reference](cli-reference/profile-and-governance.md#profile-enroll-rpc-credential).
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

### Channel-pool state

`pool init` writes these three fields, patching only the pool keys. They hold
public data; the pool master seed stays in the keyring.

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `[pool_master_key_id]` | keyring ref | no | unset | Keyring entry holding the pool master seed. Channel keys derive from it at `m/44'/148'/<index>'`. |
| `[pool_config]` | table | no | unset | The initialized pool: `pool_size` and one `channels` record per channel, each a BIP-44 index and public G-strkey. `pool list` and `pool status` read it. |
| `[pool_initialization]` | table | no | unset | Recovery checkpoint for `pool init`: funder, network passphrase, channel records, seed readiness, attempt memo, submission hashes, and the completion ledger. `pool init --resume` continues from it. |

### `[wallet]` block

These controls apply to every CLI seed read from a `--*-secret-env` variable, including `pay`, `claim`, and `accounts create`. Keyring signers, the Ledger, and the MCP server never enter the unlock window. The zero-config testnet profile uses the `"warn"` posture and a 30-second TTL.

Controls the [unlock window](concepts.md): the period in which the unlocked
wallet hands out its 32-byte signing seed. The seed stays in its zeroize-on-drop
home, locked when the lock succeeds, for as long as the wallet or the signer
built from it holds it. A testnet environment signer keeps it for its command.

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `mlock_required` | bool or `"warn"` | no | platform-dependent | `mlock(2)` failure posture. `true` (default on Linux/macOS): fail closed if the seed cannot be pinned in RAM. `"warn"` (default on Windows): proceed with unprotected memory and emit a warning. `false`: do not attempt memory locking. The posture is set in this file and is not overlayable. |
| `unlock_ttl_seconds` | integer | no | `30` | Unlock-window TTL in seconds, for the CLI `--secret-env` signing path. Must be in the range 1 to 600 (10 minutes); a value of 0 or above 600 is refused when the window is constructed, never clamped. |

### `[policy]` block

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `engine` | string | yes (in v2) | none | `"noop"` or `"v1"`. `noop`: testnet allow-all; mainnet read-only allowed; mainnet destructive operations refused with `policy.engine_required`; `smart-account multicall` refused on testnet with `policy.engine_required`, since mainnet refuses it earlier with `network.mainnet_write_forbidden`. `v1`: signature-verified typed-criteria engine, first-match default-deny. Newly minted profiles default to `v1`; a profile migrated from v1 is set to `noop` explicitly. |

### `[remote_approval]` block

Optional; absent by default. Enables `approve serve --remote`; see
[Remote approval](remote-approval.md) for the full setup walkthrough.

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `enabled` | bool | no | `false` | Must be `true`, together with the CLI's `--confirm-remote-exposure` flag, for `--remote` to take effect. The profile block alone does not start remote mode. |
| `bind` | string | yes (if block present) | none | Socket address to bind, e.g. `"0.0.0.0:8443"`. Must parse as a valid address; validated fail-closed before any TLS provisioning or bind attempt. |
| `rp_id` | string | yes (if block present) | none | The WebAuthn Relying Party ID, a DNS hostname that resolves to this host from the approving device. Must NOT be an IP literal (WebAuthn Level 2 §5.1.2 forbids IP-literal Relying Party IDs); rejected fail-closed if it is one. |
| `allowed_credentials` | array of strings | no | `[]` | Base64url WebAuthn credential IDs authorized to approve or reject. A credential enrolled via `approve operator enroll` but absent from this list is refused identically to an unknown credential. A running listener reads this list at every login and decision, so removing an id revokes that credential at once. The listener approves testnet requests only; mainnet consent uses the [approval credentials](#approval-credentials) of the signed policy, which this list does not revoke. To revoke a credential, remove its id here first, then remove its enrollment with `approve operator remove`. |

### `[served_pages]` block

Optional; absent by default. Names this deployment on the operator-facing web
pages the wallet serves: the approval inbox and detail pages, the local and
remote approval surfaces, the passkey ceremony pages, and the
operator-enrollment page.

**Absent means neutral, not "the project's identity".** A deployment that
writes no `[served_pages]` block serves pages with a plain title, no name, and
no mark. The wallet is a self-hosted runtime that third parties deploy, so a
default identity would put this project's name and mark inside somebody else's
deployment.

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `display_name` | string | no | unset (no name) | The name the served pages announce, in the page title and above each page's heading. At most 64 characters; a longer value is refused at load. An empty or whitespace-only value means no name. HTML-escaped wherever it renders. |
| `show_project_mark` | bool | no | `false` | Renders the project mark on the served pages. Set by the project's own demo and documentation captures; a third-party deployment has no reason to. |

The page DESIGN (layout, palette, typography, and the decision page's
hierarchy) is not configurable, and neither is anything the approval page says
about a transaction. The approval page is a consent surface: its purpose is the
faithful display of what is about to be signed, so the amount, the destination,
the facts grid, the approve and reject controls, the caution line, and the
expiry sentence are rendered from the approval entry alone. Configured CSS,
markup, or asset URLs would let anything able to write this file make the page
misstate the transaction without touching a signing key.

## Secret discipline

No profile field holds a key. An endpoint URL can still embed a
credential, as the list below describes. The signer seed, nonce key, and every HMAC and
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

For a headless file-backed keyring, set `STELLAR_AGENT_KEYRING_BACKEND=headless-env`
and `STELLAR_AGENT_HEADLESS_KEYRING_KEY` in the process environment. The key must
encode 32 random bytes as URL-safe base64 without padding. See
[Generate a headless keyring key](getting-started.md#generate-a-headless-keyring-key)
for POSIX shell and PowerShell commands. Keep the key in your secret manager and
reuse it for every process that opens the same store. The headless backends
serve testnet only; mainnet needs the platform keyring and refuses them with
`network.mainnet_keyring_backend_unsupported`.

## Migration and key rotation

A profile migrated from schema v1 stays on the `noop` engine until the operator
completes key rotation and opts in to `v1`. Migration populates the four
security-key reference names but mints no key material; the rotation commands
below mint the actual keys. Note that the engine choice governs the policy
layer only. Admitted mainnet writes also require installation binding and
sealed authorization at signing and submission.
MPP refuses mainnet with `mpp.network_forbidden` instead.

### Migrate first

```bash
stellar-agent profile migrate my-profile
```

This rewrites the file in place (atomically), sets the four `*_key_id` reference
names, and sets `[policy] engine = "noop"`. Running it again on an
already-current profile is a no-op.
The atomic rewrite relies on a rename, which is atomic on single-host POSIX
filesystems; NFS, SMB, and FUSE mounts may rename with weaker guarantees.

The counterparty cache reads and mints its HMAC key at
`counterparty_cache_key_id`, the entry `profile rotate-counterparty-key` writes.
With an explicit reference, previously cached entries read as absent until
a refresh rewrites them. `counterparty refresh <domain>` rewrites the entry
for that domain. `counterparty warm-up` refreshes only the `HOME_DOMAIN`
entries of the policy allowlist.

### Rotate the policy owner

For an enabled mainnet profile, prepare the new policy with both owner seeds.
Use this order whenever a policy pin exists, including on testnet:

```bash
stellar-agent profile sign-policy --profile operator --secret-env NEW_OWNER_SEED --previous-owner-secret-env PREVIOUS_OWNER_SEED
stellar-agent profile enroll-owner-key --profile operator --secret-env NEW_OWNER_SEED --force
```

Supply each variable through the secret-entry procedure and unset both afterward.
If signing uses `--file`, install that file at `policies/operator.toml` before
running enrollment. The previous seed must match the pinned owner, or the
enrolled owner when no pin exists.
Enrollment checks the installed policy whenever an enablement nonce or a
policy pin exists at the profile's window-state entry, or an enablement nonce
exists at its default entry, whatever chain the profile file names. A pin
alone at the default entry of a testnet profile that names another entry
does not block enrollment; the next load there refuses a new owner without a
statement.
The `[owner_rotation]` table names `previous_owner` and `new_owner` as G-strkeys
and carries a hex `sig` from the previous owner.
It binds the scope, sequence, and every rule; the new owner's signature covers
that table too. The next verified load advances the pin to the new owner.
A later load of the same policy succeeds without another rotation.

Enrolling the pinned owner's own key needs no statement, so
`enroll-owner-key --force` with that seed restores a lost or overwritten owner
entry. The pinned owner's seed is the only authority for an owner change: if it
is lost on a profile with a policy pin, on mainnet or testnet, no wallet command
rotates the owner. Keep that seed until the new owner's policy has loaded.

### Rotate each key

Each command generates fresh key material from the OS CSPRNG and stores it in the
named keyring entry. The CLI prints a JSON envelope and exits `0` on success, `1`
on error.

| Command | Mints into | Notes |
|---------|------------|-------|
| `stellar-agent profile enroll-owner-key` | `policy_owner_key_id` | Enrols the owner ed25519 PUBLIC key from an operator seed, stored as its G-strkey, which no 32-byte symmetric-key loader accepts. Owner readers refuse older base64 entries; enroll the owner public key again after upgrading. Sign policy files with `profile sign-policy`; re-enrolling a different key invalidates policy files signed by the previous one. |
| `stellar-agent profile rotate-attestation-key <name>` | `attestation_key_id` | Fresh 32-byte HMAC key. All pending approvals are invalidated. |
| `stellar-agent profile rotate-audit-key <name>` | `audit_log_hash_chain_key_id` | Fresh 32-byte HMAC key. Rotation re-signs every existing per-file chain-root sidecar with the new key, so the whole log verifies under it; the old key stops verifying. |
| `stellar-agent profile rotate-counterparty-key <name>` | `counterparty_cache_key_id` | Fresh 32-byte HMAC key. Cached `stellar.toml` entries read as absent until a refresh rewrites them. `counterparty refresh <domain>` rewrites the entry for that domain. `counterparty warm-up` refreshes only the `HOME_DOMAIN` entries of the policy allowlist. |
| `stellar-agent profile rotate-nonce-key <name>` | `mcp_nonce_key_alias` | Fresh 32-byte HMAC key. Outstanding nonces minted with the old key are invalidated. |
| `stellar-agent profile rotate-policy-state-key <name>` | `policy_window_state_key_id` | Fresh 32-byte HMAC key. Unlike the other rotations, the accumulated window-state store is re-signed under the new key, so `per_period_cap` / `rate_limit` history is preserved, not invalidated. |
| `stellar-agent profile reset-window-state <name> --reason <reason>` | `policy_window_state_key_id` (mints if absent) | Re-initialises the window-state store to empty. Recovery path for an unreadable, tampered, or unparseable store. The affected criteria fail closed until reset. Discards history only after its audit row is written under the audit writer and store lock. Stop the MCP server first. An enablement nonce requires `--owner-secret-env VAR` matching the pinned owner in every build. The audit row records the owner signature. |

### Enroll the MCP signer

The signer seed is imported, not minted: it is the operator's own account key.
Import the `S...` secret from a named environment variable, set as shown in
[Pass a secret seed](getting-started.md#pass-a-secret-seed). Run this line on
its own, paste the seed when prompted, and press Enter:

```bash
printf 'WALLET_SK seed: ' && read -rs WALLET_SK && echo && export WALLET_SK
```

Enroll the seed, then remove it from the shell:

```bash
stellar-agent profile enroll-signer --profile <name> --secret-env WALLET_SK
unset WALLET_SK
```

Enrollment derives the seed's public address and stores the seed in the
keyring. What happens to `[mcp_signer_default] account` depends on its current
value: a profile fresh from `profile init` (and a v1-migrated profile that
still carries it) holds the
placeholder `"default"`, which enrollment overwrites in place with the derived
address; a profile whose `account` already pins a G-strkey (from a prior
enrollment, or set by hand) is left untouched, and enrollment refuses if the
seed does not derive to that exact address (printing the address to set
`account` to). Without an enrolled seed, the MCP tools and the
keyring-signing CLI verbs (`trustline`, `trade`, `vault`) fail with
`auth.keyring_not_found`. See
[cli-reference/profile-and-governance.md](cli-reference/profile-and-governance.md#profile-enroll-signer)
for flags and the envelope shape.

### Opt in to V1

Complete these steps for a persistent profile, using its name in place of `<name>`:

1. `stellar-agent profile rotate-audit-key <name>`: mint the audit key before
   the first key-writing command so its audit row is written.
2. [Enroll the MCP signer](#enroll-the-mcp-signer): register the signer seed.
3. `stellar-agent profile rotate-nonce-key <name>`: mint the nonce key before
   MCP payment simulation. Without it, simulation fails with `nonce.mint_failed`.
4. `profile enroll-owner-key`, then `profile rotate-attestation-key`: enroll
   the policy owner and mint the approval key.
5. [Create the V1 policy file](#create-the-v1-policy-file), then run
   `profile sign-policy`.

An `init`-minted profile already carries `engine = "v1"`. This setup supplies
its policy and key prerequisites. A profile migrated from schema v1 stays
on `noop`; after completing these steps, set the engine in the profile TOML:

```toml
[policy]
engine = "v1"
```

Until this is done, a migrated profile continues to run under `noop`, which
refuses mainnet destructive operations with `policy.engine_required`. Opting in
to `v1` changes policy evaluation. Mainnet writes also need a feature-enabled
build, enablement, a signed v2 body, and approval for each action. For the governance flow that V1
enforces, see
[cli-reference/profile-and-governance.md](cli-reference/profile-and-governance.md).

### Create the V1 policy file

Before `profile sign-policy`, create `policies/<name>.toml` in the wallet's
state directory. The default paths are:

| Platform | Policy file for `default` |
|----------|---------------------------|
| Linux | `${XDG_DATA_HOME:-$HOME/.local/share}/stellar-agent/policies/default.toml` |
| macOS | `~/Library/Application Support/Soneso.stellar-agent/policies/default.toml` |
| Windows | `%LOCALAPPDATA%\Soneso\stellar-agent\data\policies\default.toml` |

Create the parent directory first. On Linux or macOS:

```sh
case "$(uname -s)" in
  Linux) policy_dir="${XDG_DATA_HOME:-$HOME/.local/share}/stellar-agent/policies" ;;
  Darwin) policy_dir="$HOME/Library/Application Support/Soneso.stellar-agent/policies" ;;
esac
mkdir -p "$policy_dir"
```

On Windows PowerShell:

```powershell
$policyDir = Join-Path $env:LOCALAPPDATA 'Soneso\stellar-agent\data\policies'
New-Item -ItemType Directory -Force -Path $policyDir | Out-Null
```

Save this minimal policy as `default.toml` in that directory, using UTF-8:

```toml
version = 1
scope = "profile:default"

[[rules]]
match = { tool = "stellar_balances", chain = "*" }
criteria = []
decision = "allow"

[[rules]]
match = { tool = "*", chain = "*" }
criteria = []
decision = "require_approval"
```

For another profile, replace `default` in the filename and `scope`.
The first rule allows balance queries; the second requests operator approval
for other policy-gated calls. Both use `chain = "*"` because the profile binds
the chain. Review the rules before signing; an empty `criteria` list adds no
spending cap. See [policy rules](concepts.md#the-policy-engine)
for additional restrictions.

The signature covers every key the policy schema accepts outside the
`[signature]` table, including a rule's `reason`, `ttl_secs`, and
`allow_opaque_signing`. Any change to a key or a value outside that table
therefore needs a new signature. Comments, whitespace, quoting style, and number
notation are outside the signed form; the order of keys inside a `match` table
or a criterion is part of it.
The loader refuses unknown keys, while `profile sign-policy` refuses them
in the policy body and replaces the `[signature]` table whole, dropping any
extra key in that table.

Then run `stellar-agent profile sign-policy --profile default --secret-env WALLET_OWNER_SK`
with the enrolled owner's seed in `WALLET_OWNER_SK`.
[Pass a secret seed](getting-started.md#pass-a-secret-seed) covers setting and
clearing that variable. The command adds the signature table. It refuses a
missing file with `sign_policy.policy_file_unreadable`, a key outside the policy
schema with `sign_policy.canonicalization_failed`, and a body the engine would
refuse with `sign_policy.policy_body_invalid`.

### Mainnet policy body

The first enablement requires a signed v2 policy and pins its sequence, digest,
and owner before storing the nonce. A v1 or unsigned policy is refused and
nothing is written. Prepare this policy without `[mainnet]`, sign it, run
`enable-mainnet`, then complete and sign the bound policy. The completed policy
lists at least one [approval credential](#approval-credentials).
An installation with a stored enablement nonce refuses an absent pin with
`policy.pin_absent`: every mainnet write and both forms of `enable-mainnet`
refuse, and no wallet command establishes that pin. Nonce rotation and
window-state reset preserve an existing pin. To recover, remove the keyring
entry with service `stellar-agent-policy-window-<name>` and account
`default-mainnet-enablement` with the platform keyring tool, run
`profile enable-mainnet --profile <name>`, which pins the installed signed
policy and stores a new nonce, and sign the rebound policy at a higher
sequence. That enablement trusts the installed signed policy and its owner,
as the first enablement of a new installation does.
A new owner at a higher sequence requires a valid previous-owner statement.
An absent statement refuses with `policy.owner_rotation_required`; an invalid
one refuses with `policy.owner_rotation_invalid`.

Engine `v1`, policy-body version 2, and profile-schema version 2 are separate.
The enabled-policy minimum applies to feature-on mainnet profiles with a
signed v2 body containing `[mainnet]`. `profile enable-mainnet --check`
evaluates the restrictions in either build. The `approval_credentials`
requirement holds in either build for every policy with a `[mainnet]` table.

The profile file and policy file are separate documents. This policy example
contains complete payment rules for CLI and MCP. Replace the destination with
the intended account. The zero nonce digest and example endpoint are placeholders.
Use the profile, endpoint host, and nonce digest written by
[the enablement ceremony](cli-reference/profile-and-governance.md#profile-enable-mainnet).
These installation bindings cannot be reused from another installation.

```toml
version = 2
scope = "profile:operator"
sequence = 1

[mainnet]
endpoint_host = "rpc.example.invalid"
profile = "operator"
installation_nonce_sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
classic_max_fee_per_op_stroops = 500
authorization_ttl_seconds = 60
approval_credentials = [
    { credential_id_b64url = "WlpaWlpaWlpaWlpaWlpaWg", public_key_sec1_b64url = "BEYtuhrk_BqWi02s8gzdbb4frjSqlxUUpj00BcPRz9ODtYu7CMEzg0KMWFPHHEyFHhNLBWgh5Gj-Cpd6v0MT3eE" },
]
[mainnet.cross_check_thresholds]
native = "10000000000"
"USD:GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF" = "100"

[[rules]]
match = { tool = "stellar_pay", chain = "stellar:mainnet" }
criteria = [
    { kind = "asset_allowlist", assets = ["native"] },
    { kind = "counterparty_allowlist", kinds = ["G_ACCOUNT"], allowlist = ["GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF"] },
    { kind = "per_tx_cap", asset = "native", max_stroops = "10000000" },
    { kind = "per_period_cap", window = "1d", asset = "native", max_stroops = "20000000" },
    { kind = "rate_limit", window = "1d", max_calls = 10 },
]
decision = "require_approval"
allow_opaque_signing = false
ttl_secs = 600
reason = "review"

[[rules]]
match = { tool = "stellar_pay_commit", chain = "stellar:mainnet" }
criteria = [
    { kind = "asset_allowlist", assets = ["native"] },
    { kind = "counterparty_allowlist", kinds = ["G_ACCOUNT"], allowlist = ["GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF"] },
    { kind = "per_tx_cap", asset = "native", max_stroops = "10000000" },
    { kind = "per_period_cap", window = "1d", asset = "native", max_stroops = "20000000" },
    { kind = "rate_limit", window = "1d", max_calls = 10 },
]
decision = "require_approval"
allow_opaque_signing = false
ttl_secs = 600
reason = "review"
```

| Policy-body element | Meaning |
|---|---|
| `version`, `scope`, `sequence`, `[[rules]]` | `version = 2`, profile-specific scope, a positive sequence, and explicit rules. This policy is separate from the profile document. |
| Sequence allocation | Signing assigns `max(pin, body) + 1`. Signing does not advance the pin. A verified load can advance it. |
| Pin comparison | A pin refuses v1 or a lower sequence. Equal sequence with another digest or owner is a fork. |
| `[mainnet].profile` | Dedicated profile name. |
| `[mainnet].endpoint_host` | Ceremony-normalized endpoint host. This policy field remains named `endpoint_host`. |
| `[mainnet].installation_nonce_sha256` | Installation nonce digest as 64 lowercase hexadecimal characters. |
| `[mainnet].classic_max_fee_per_op_stroops` | Required signed `u32` classic per-operation cap. |
| `[mainnet].authorization_ttl_seconds` | Optional lifetime from 1 through 120 seconds, distinct from approval lifetime. |
| `[mainnet].approval_credentials` | Required. 1 to 16 inline tables with exactly `credential_id_b64url` and `public_key_sec1_b64url`, placed in `[mainnet]` before any `[mainnet.*]` subtable. Both values are canonical unpadded base64url: an ID of 16 to 64 bytes and a 65-byte uncompressed SEC1 P-256 point. IDs are unique. The example entry is a placeholder; use the entry `approve credential enroll` prints. |
| `[mainnet.cross_check_thresholds]` | Optional signed thresholds, each a positive TOML integer or a positive decimal string within the i128 range, such as `native = "10000000000"`. |
| Signature coverage | V2 signs sequence and mainnet fields. Match and criterion keys are sorted canonically. The approval credentials are signed sorted by raw credential ID, so reordering entries or their keys keeps the signed bytes. |

#### Approval credentials

Mainnet consent requires a fresh WebAuthn assertion, with user presence and
user verification, from a credential this list names. The owner admits a
credential by signing the policy that lists it; enrollment alone grants
nothing.

1. Run `stellar-agent approve credential enroll --profile <name>` on the wallet
   host, create the passkey in the local browser, and type the code the page
   shows. The command prints the credential and its `policy_entry_toml`; see
   [`approve credential enroll`](cli-reference/profile-and-governance.md#approve-credential-enroll).
2. Review the credential and add the entry to `approval_credentials` in the
   `[mainnet]` table.
3. Sign the policy with `profile sign-policy`, which assigns a higher sequence,
   then restart the MCP server and every `approve serve` inbox of the profile.

A missing or empty list refuses with `policy.mainnet_minimum_unmet` and
`requirement=approval_credentials`. A malformed list, an unknown key, a
duplicate ID, or an invalid ID or key refuses with
`policy.policy_file_parse_failed` and a fixed detail that names the problem.
`sign-policy` refuses both and writes nothing. An existing mainnet policy
without the list needs it and a new signature before the MCP server or
`approve serve` starts on that profile, read-only use included.

To revoke a credential, remove its entry and sign the policy at a higher
sequence. An approval recorded under an earlier policy needs fresh consent,
also when its credential stays listed. The `[remote_approval]` allowlist and
`approve operator remove` do not change the approval credentials.

This release connects no presence ceremony to the consent surfaces: every
mainnet consent refuses with `approval.presence_required`, so mainnet writes
remain unavailable. See [Mainnet write behavior](cli-reference/index.md#mainnet-write-behavior).

#### Enabled-policy minimum

| Requirement | Restriction |
|---|---|
| `body_version` | Body v2 with sequence from 1 through `i64::MAX`. |
| `mainnet_table` | A `[mainnet]` table exists. |
| `rules_empty` | At least one rule exists. |
| `scope` | Scope names this profile, optionally followed by project scope. Wildcard profile scope refuses. |
| `chain` | Every rule names exactly `stellar:mainnet`. |
| `tool` | Every rule names an admitted policy tool or an explicitly listed read/local tool. A rule does not itself admit a binary operation. |
| `opaque` | `allow_opaque_signing` is absent or false. |
| `rule_ttl` | Every RequireApproval rule supplies `ttl_secs` from 1 through 3600. |
| `asset_allowlist` | Non-deny value-out and trustline rules contain exactly one nonempty pinned asset allowlist. Claim rules contain none. |
| `destination` | Non-deny value-out rules require `G_ACCOUNT` or `C_ACCOUNT`. `KNOWN_ISSUER` may accompany them. No other kind may appear in that restriction. |
| `home_domain` | Rules contain neither `HOME_DOMAIN` nor `home_domain_resolved`. |
| `per_tx_cap` | Non-deny value-out rules cap every allowlisted asset per transaction. |
| `per_period_cap` | Non-deny value-out rules cap every allowlisted asset per period. |
| `rate_limit` | Non-deny value-out rules contain a rate limit. |
| `fee_cap` | The signed mainnet table contains the classic per-operation cap. |
| `thresholds` | Signed thresholds use pinned identities and positive i128 values. The native threshold meets the floor. |
| `ttl` | Authorization TTL is absent or from 1 through 120 seconds. |
| `approval_credentials` | The `[mainnet]` table lists 1 to 16 approval credentials. Required in either build. |

The minimum has no memo criterion. SEP-29 still refuses a missing memo when
the destination's `config.memo_required` entry is `1`. The operator supplies
required deposit memos for destinations without that entry.

#### Policy-tool names

| CLI full-mode operation | CLI and MCP prepare name | MCP commit name |
|---|---|---|
| `pay` | `stellar_pay` | `stellar_pay_commit` |
| Sponsored `accounts create` | `stellar_create_account` | `stellar_create_account_commit` |
| `trustline` | `stellar_trustline` | `stellar_trustline_commit` |
| `claim` | `stellar_claim` | `stellar_claim_commit` |

Both MCP names need matching rules. Missing matches deny with
`policy.deny.no_matching_rule`. A matching rule grants no admission to an
excluded operation.

Signing assigns `max(pin, body) + 1` without advancing the pin. A verified
load can advance it. A pin refuses v1 or a lower sequence with
`policy.sequence_rollback`. Equal sequence with another digest or owner
refuses with `policy.sequence_fork`. The maximum sequence is `i64::MAX`;
signing at that maximum refuses with `sign_policy.sequence_exhausted`.
V2 signatures cover sequence and mainnet fields, with match and criterion keys
sorted canonically. After signing or enablement, restart the MCP server.

### Policy and setup diagnostics

These are policy-library and setup codes. CLI engine construction preserves
enablement errors but wraps other build failures as `policy.engine_unavailable`
or `trustline.policy_engine_unavailable`.

| Code | Meaning or remedy |
|---|---|
| `policy.engine_required` | Noop refuses destructive mainnet policy decisions. Surface entry checks can refuse earlier. |
| `policy.engine_unavailable` | The policy engine cannot be built. Enabled mainnet refuses `test_owner_key` before pin advancement. |
| `policy.mainnet_table_on_testnet` | The policy contains `[mainnet]` on a testnet profile. |
| `policy.sequence_rollback` | The policy is older than the installation pin, or uses v1 after a pin exists. |
| `policy.sequence_fork` | The pinned sequence has a different digest or owner. |
| `policy.state_lock_busy` | The state lock remains held through the bounded acquisition attempts. |
| `policy.state_lock_io` | The lock cannot be opened. The detail identifies the I/O failure. |
| `policy.mainnet_minimum_unmet` | The enabled policy fails a named minimum requirement. |
| `policy.pin_unusable` | The installation pin cannot be read or is malformed. |
| `profile.mainnet_enablement_invalid` | The message names the failed binding: `mainnet_table`, `profile`, `source`, `default`, `on_disk`, `chain_id`, `on_disk_host`, `merged_host`, or `nonce_digest`. |
| `profile.enable_mainnet_profile_flag_required` | Supply an explicit `--profile`. |
| `profile.enable_mainnet_default_refused` | Select a dedicated profile whose name is not `default`. |
| `profile.enable_mainnet_not_mainnet` | Select a mainnet profile. |
| `profile.enable_mainnet_precondition` | A named ceremony prerequisite or effect failed. |
| `profile.enable_mainnet_nonce_exists` | Use `--rotate` to replace the installation nonce. |
| `sign_policy.sequence_exhausted` | The maximum of body and pinned sequence is `i64::MAX`. |
| `profile.enroll_signer_identity_incomplete` | Follow the reported repair or enrollment remedy. |
| `enroll_signer.repair_unpinned` | Identity repair requires the stored public-key pin. |
| `enroll_signer.identity_conflict` | The stored identity conflicts with the enrolled signer. |
| `auth.enrolled_identity_unusable` | The enrolled identity cannot establish the signer proof. Ledger enrollment is unavailable. |
| `profile.reset_window_state_owner_required` | Supply `--owner-secret-env VAR` with the pinned owner's seed on an enabled installation. |
| `profile.reset_window_state_owner_mismatch` | The supplied seed must derive to the pinned owner. |
| `sign_policy.owner_key_older_form` | Enroll the owner public key again with `profile enroll-owner-key --force`. |
| `profile.reset_window_state_newer_version` | This build cannot reset an unsupported newer state format. |
| `policy.window_state_unverifiable` | Enabled-mainnet state cannot be verified. Follow the operator recovery procedure. |
| `profile.reset_window_state_open_authorizations` | Effective open authorizations prevent reset. |
| `approval.presence_required` | Mainnet consent requires a verified assertion from an approval credential in the owner-signed policy. This release records no mainnet consent. |
| `approval.presence_policy_unavailable` | The current owner-signed mainnet policy cannot be verified, lists no approval credential, or changed since the consent was recorded. |
| `approval.mainnet_remote_unsupported` | The remote approval listener does not approve mainnet requests. |
| `approve.yes_refused_on_mainnet` | On mainnet, `--yes` refuses before store access in either build. |
| `accounts.create.generate_refused_on_mainnet` | Mainnet creation requires a destination public key. Generated-key creation is a testnet convenience. |

Policy denials retain their `policy.deny.*` codes. The installed skill
[lists the denial vocabulary](../skills/stellar-agent-wallet/references/troubleshooting.md#policy-denial-codes).

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
