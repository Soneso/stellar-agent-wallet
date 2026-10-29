# The MCP server

See [Mainnet configurations and scope](getting-started.md#mainnet-configurations-and-scope)
for build configuration, admitted operations, and exclusions. Per tool on
`stellar:mainnet`:

- The sign-only tools are `stellar_sep43_sign_transaction`,
  `stellar_sep43_sign_auth_entry`, `stellar_sep43_sign_message`,
  `stellar_sep53_sign_message`, `stellar_x402_create_payment`, and
  `stellar_x402_authenticated_payment`.
- The tools that sign and submit are `stellar_sep43_sign_and_submit_transaction`
  and the DeFi tools `stellar_defindex_vault_deposit`,
  `stellar_defindex_vault_withdraw`, and `stellar_dex_trade`. The commit tools
  `stellar_pay_commit`, `stellar_claim_commit`, `stellar_create_account_commit`,
  `stellar_trustline_commit`, and `stellar_rule_create_commit` also sign and
  submit.
- Every tool named above and the signing actions of `stellar_toolset_invoke`
  refuse at handler entry with `network.mainnet_write_forbidden` in every
  build, except both x402 payment tools and the four classic commits. A
  feature-enabled build admits the four classic commits and both x402 payment
  tools after setup. With the feature off, these tools refuse mainnet at entry
  with the same code.
- `stellar_toolset_invoke` is annotated destructive, so its own policy gate
  refuses its other actions on mainnet: the default engine refuses a
  destructive tool, and a mainnet policy rule cannot name it.

`stellar-agent-mcp` is a [Model Context Protocol](https://modelcontextprotocol.io)
server that exposes the Stellar Agent Wallet to an MCP client. It speaks
JSON-RPC over stdio and presents wallet capabilities as MCP tools, so an AI
assistant can read account state and submit Stellar transactions through the
same policy engine, operator-approval spine, and tamper-evident audit log that
back the `stellar-agent` CLI.

Gated tools evaluate policy before signing. Mainnet writes also require a
feature-enabled build, operator setup, and per-action authorization. The four
classic commit tools use independent signing and submission checks. See
[Concepts](./concepts.md) for the shared guardrail model.

## What it is

- One process: the `stellar-agent-mcp` binary, built from the
  `stellar-agent-mcp` crate.
- Transport: MCP JSON-RPC over stdio. The client spawns the binary as a
  subprocess and exchanges newline-delimited JSON-RPC on the subprocess
  stdin/stdout.
- Protocol version: `2024-11-05`. Declared capabilities: `tools` and
  `resources`.
- Server identity reported at initialize: name `stellar-agent-mcp`, version
  matching the crate's package version (`0.1.0-alpha.12` as of this release).

`stdout` is reserved for the JSON-RPC wire. Structured logs go to `stderr`, and
they pass through a redaction layer before they are written, so a client that
captures `stderr` receives already-redacted output. Mixing log lines into
`stdout` would corrupt the protocol stream, which is why the split is strict.

The transport enforces a 1 MiB maximum line length on inbound and outbound
JSON-RPC frames. Frames longer than that are rejected.

This alpha does not offer an HTTP or SSE transport. stdio is the only transport.

### Availability

This is a public alpha. Install with
`cargo binstall --locked --disable-strategies quick-install,compile stellar-agent-mcp@0.1.0-alpha.12`
(prebuilt binary from the tagged GitHub release, resolved through crates.io),
with `cargo install --locked stellar-agent-mcp@0.1.0-alpha.12` (built from the
published sources and their `Cargo.lock`), or build from source. While
crates.io holds only prerelease versions, the version must be spelled out. A
bare crate name matches stable versions only. See
[the CLI reference](./cli-reference/) and the repository README for build
instructions; the build that produces `stellar-agent` produces
`stellar-agent-mcp` alongside it.

## Launching the server

The server is started by running the binary. Configuration comes from the
selected profile.

```bash
stellar-agent-mcp                    # profile `default`
stellar-agent-mcp --profile alice    # profile `alice`
```

The profile is selected by `--profile <NAME>` (also spelled
`--profile=<NAME>`), then by the `STELLAR_AGENT_PROFILE` environment variable,
then by the name `default`, the same order the CLI uses. The selected profile
binds at startup and stays bound for the life of the process; there is no
per-request profile switching. Any other argument is refused with a non-zero
exit rather than ignored, so a mistyped flag cannot silently start the server on
a different profile than intended.

A mainnet profile loads only through `--profile <name>`. `STELLAR_AGENT_PROFILE` never selects one, and a mainnet `default.toml` needs `--profile default`. Keep the filename: its identity is bound to its keyring entries.

Implicit mainnet selection exits with `profile.mainnet_requires_explicit_profile`.
The message names the selection source and the recovery command:
`stellar-agent-mcp --profile <name>`.
An environment or programmatic overlay may set only operational fields.
`submit_timeout_seconds` is overlayable on every chain. `rpc_url`,
`secondary_rpc_url`, `oracle_provider_url`, `mcp_signer_default`,
`cross_check_threshold_stroops` (alias `usd_threshold`),
`cross_check_thresholds`, the two classic fee fields,
`smart_account_max_context_rule_scan_id`, and
`session_rule_max_horizon_ledgers` are overlayable on testnet only.
`mcp_disabled` accepts only `true`. Every other profile key, `chain_id` and
every keyring coordinate included, comes from the file only. A refused overlay
exits with `profile.non_overlayable_field` and asks the operator to remove the
field from the environment or the overlay. A variable that names no profile
key, such as `STELLAR_AGENT_HOME`, is ignored.

Unset the refused `STELLAR_AGENT_*` variable named in the message, remove the key from programmatic overlays too, and set the value in the profile file instead. Then run `stellar-agent profile show --profile <name>` to confirm the file's chain and endpoint. Correct the profile file if either value differs from the intended configuration.

The server resolves one `NetworkContext` at construction for tool network reads.
Profile resources keep their loader behavior: a profile under a refused overlay
reads as `profile_resource_unloadable`. Account enumeration skips that profile.

On startup the process, in order:

1. Parses the command line, resolves the profile name (`--profile`, then
   `STELLAR_AGENT_PROFILE`, then `default`), and validates that the name is
   usable as a path component. An unrecognised argument or an unusable name is
   refused here, before any of the steps below run.
2. Applies process-isolation hardening on Linux (`PR_SET_DUMPABLE 0`,
   `PR_SET_NO_NEW_PRIVS 1`). On macOS and Windows it relies on the platform
   keyring's per-application access model and operator policy instead.
3. Installs the redacting log subscriber on `stderr`.
4. Initialises the platform keyring store. If the platform has no supported
   keyring backend, it logs a warning and continues: the read-only and simulate
   surface still works, and signing tools refuse at call time.
5. Loads the selected profile. When no profile was named (neither `--profile`
   nor `STELLAR_AGENT_PROFILE`) and no profile file exists yet, it synthesises
   a testnet fallback profile (the first-run case). A profile that WAS named but
   has no file is refused: the fallback is a testnet, `noop`-engine
   configuration, so substituting it would answer on the wrong network and
   downgrade the profile's policy engine.
6. Refuses to start if the active profile sets `mcp_disabled = true` (the
   operator kill-switch), exiting non-zero with `mcp.disabled_per_profile`.
7. Refuses to start if the profile file's `policy_owner_key_id.service` names a
   different profile than the one selected, the state a profile file renamed or
   copied from another profile is in. The server derives the name it uses for
   the signed policy file, the pending-approval store, and the policy-window
   state from that field, so a mismatch would read and write another profile's
   state.
8. Serves the MCP loop until the client disconnects.

You normally do not launch `stellar-agent-mcp` by hand. The MCP client spawns
it. The command above is what the client is configured to run.

**Windows deployment note:** Credential Manager requires an interactive logon
session. Running the server as a Windows service, over SSH, or from a
scheduled task prevents access to Credential Manager. The server itself starts,
but every signing tool refuses at the keyring step. Most tools report
`auth.keyring_interactive_session_required`.
The SEP-43 sign tools report `sep43.wallet_unlock_failed`.
`stellar_sep53_sign_message` reports `sep53.keyring_load_failed`, and
`stellar_mpp_charge_commit` reports `mpp.signing_failed`.
Launch it from an interactive desktop session (including Remote Desktop), or
run it inside a container / Linux VM where the platform keyring backend has
no such restriction. Alternatively, set
`STELLAR_AGENT_KEYRING_BACKEND=headless-dpapi` on the process environment to
opt into the headless file-backed keyring store with DPAPI CurrentUser scope.
DPAPI needs access to the current user's master key and can fail in
key-authenticated SSH sessions. An interactive desktop logon may help.
A protect failure reports `auth.keyring_platform_error`, naming DPAPI and its
numeric error code when available. The `headless-env` backend avoids this DPAPI dependency
and requires `STELLAR_AGENT_HEADLESS_KEYRING_KEY`. The headless backends serve testnet only: every mainnet write checks mainnet
readiness, which refuses them with
`network.mainnet_keyring_backend_unsupported`. See
[security-internals.md's headless keyring section](maintainers/security-internals.md#headless-keyring-store)
for the trust model before enabling it.

### How a profile selects the signer and keys

The wallet holds no keys in its config, though an endpoint URL can embed a
credential. A [profile](./profiles.md) is a
per-environment TOML file (schema version 2) that binds a CAIP-2 chain id, an
RPC endpoint, keyring entry references, thresholds, and the active policy
engine. Each keyring entry reference is a service-plus-account pair naming a
secret held in the platform keyring; it is never the secret itself.

The loaded profile therefore determines:

- which network the server operates on (`stellar:testnet` by default;
  `stellar:mainnet` supports reads and the admitted operations described above
  when their authorization requirements hold). The profile's declared network is
  what the server asks for, not what it trusts: the network layer establishes
  the endpoint's own identity before it sends and binds the submission to that.
  See
  [How gating applies to every tool call](#how-gating-applies-to-every-tool-call)
  for the refusal layers and their wire codes;
- which keyring entries the signing tools resolve their seed from;
- which policy engine evaluates each tool call.

The synthesized testnet fallback profile carries placeholder keyring
coordinates. Read-only tools work under it. The simulate steps of
`stellar_pay`, `stellar_create_account`, `stellar_trustline`, and
`stellar_claim` mint their nonce from the profile's nonce-key entry. They
report `nonce.mint_failed` until that entry holds a key. `stellar_rule_create`
mints no envelope nonce: it stores the proposal, and its commit requires that
proposal's `approval_nonce`. Signer keyring
access fails until a profile names a populated signer entry. Most tools report `auth.keyring_not_found`.
The SEP-43 sign tools report `sep43.wallet_unlock_failed`.
`stellar_sep53_sign_message` reports `sep53.keyring_load_failed`, and
`stellar_mpp_charge_commit` reports `mpp.signing_failed`.
This fallback applies only when no profile was named at all;
`--profile <NAME>` and `STELLAR_AGENT_PROFILE` always require a real profile
file.

The profile field `mcp_disabled` is a per-profile kill-switch. When `true`, the
server refuses to start, exiting non-zero with `mcp.disabled_per_profile`. The
flag is also surfaced as non-secret metadata on the
`mcp-resource://profiles/<name>` resource so a client can read whether the MCP
surface is enabled for that profile.

## Configuring an MCP client

Most MCP clients are configured with a JSON stanza that names a command to spawn
and its arguments. Point the command at the `stellar-agent-mcp` binary. A
generic stanza:

```json
{
  "mcpServers": {
    "stellar-agent": {
      "command": "/absolute/path/to/stellar-agent-mcp",
      "args": []
    }
  }
}
```

Notes:

- Use an absolute path to the binary, or ensure it is on the `PATH` the client
  uses to spawn subprocesses.
- No arguments are required. To bind the server to a profile other than
  `default`, pass one: `"args": ["--profile", "alice"]`, or set
  `STELLAR_AGENT_PROFILE` in the environment the client spawns the process with.
  Arguments other than `--profile`, `--help`, and `--version` are refused.
- The second line of `--version` and `-V` output,
  `STELLAR_AGENT_BUILD_MAINNET_WRITE=off` or `=on`, reports the build state of
  the default-off `mainnet-write` Cargo feature.
- The exact location and schema of the configuration file depend on the MCP
  client. Consult that client's documentation for where to place the stanza.

After the client connects it issues an MCP `initialize`, then `tools/list` and
`resources/list`. The tool catalog below is what `tools/list` returns.

## Resources

The server exposes three MCP resources. None contains a secret.

- `mcp-resource://usage.md`: tool usage documentation.
- `mcp-resource://profiles/<name>`: non-secret profile metadata (chain id, the RPC
  endpoint as scheme, host, and port, network passphrase, `mcp_disabled`, and
  the cross-check threshold in stroops).
  An agent passing this resource's `rpc_url` to `stellar_fee_stats` passes an
  authority-only URL; the allowlisted hosts have no path, so the call behaves
  the same.
- `mcp-resource://accounts/<G>`: public account directory for the enrolled
  accounts across all configured profiles.

## How gating applies to every tool call

Every tool call except three MPP tools and `stellar_dex_quote` passes through
the same gate before the tool signs or submits. Reads the decision needs, such as the source account,
can run first. `stellar_mpp_record_receipt`,
`stellar_mpp_reconcile_transaction`, and `stellar_mpp_authorization_status`
check the profile and read the MPP store without a policy verdict.
`stellar_dex_quote` passes no gate and never compares its `chain_id` with the profile. It picks the Soroswap router from `chain_id` and reads through the profile's RPC endpoint. The gate
looks up the tool's registry descriptor and calls
`policy_engine.evaluate(...)`. The verdict is one of:

- `Allow`: the tool proceeds.
- `Deny`: the call is refused with wire code `policy.deny.<reason>`.
- `RequireApproval`: an out-of-band operator approval is required.

### Classic mainnet authorization

A feature-enabled server admits `stellar_pay_commit`, `stellar_claim_commit`,
`stellar_create_account_commit`, and `stellar_trustline_commit` after setup.
Both prepare and commit policy names need matching rules. The four pairs require
approval even under Allow. A pending approval uses the shorter lifetime from
the prepare and commit evaluations. Allow contributes 600 seconds;
RequireApproval supplies its configured lifetime. Authorization defaults to
120 seconds and cannot outlive approval.

On an admitted mainnet server, both x402 payment tools require approval even
when their matching rule allows the action. [x402](#x402) describes their two
calls.

Paired preparation refuses an undecodable envelope with `simulation.divergence`.
A denied rule retains `policy.deny.*`; an unknown decision uses
`policy.unexpected_decision`. None of these refusals persists an approval.
Each commit forces confirmation before attestation validation.

Feature-on startup loads the mainnet write context for a verified enabled
profile. Failed enablement or policy checks abort startup. Admission refusals
use `network.mainnet_write_forbidden` for unsupported tools or missing V1 engine,
verified policy, enablement, enabled context, or profiles directory. A stored
profile without `oracle_provider_url` refuses at admission with
`profile.mainnet_oracle_required`, before signing. The server reads the
profile at startup, so it applies an oracle change from its next start.

After `profile enable-mainnet` or `profile sign-policy`, restart the MCP server.
Freshness compares current policy and enablement facts without advancing the pin.
A changed binding reports `network.mainnet_write_forbidden` with
`enablement or policy changed, restart the server`. Missing startup authority
instead names the missing prerequisite.

Missing, invalid, expired, or unverifiable approvals use
`policy.approval_required`. A live rejection uses `policy.approval_rejected`. A
live consumed approval or an approval held by a submission receipt uses
`policy.approval_consumed`. Expired tombstones use `policy.approval_required`.
Authorization consumption followed by pre-send recording failure can leave an
unspent pending approval. Reusing it can produce
`network.mainnet_authorization_refused` without a tombstone.

The wallet's own signing paths sign mainnet payloads only under mainnet
authorization. The library signers enforce it too: every `Signer`, the public
keyring handle included, signs a mainnet transaction or Soroban authorization
payload only under a mainnet authorization. Code running as the same OS user
with access to a keyring entry can read its seed directly. The keyring entry
is the custody boundary.
Authorized signing and submission check sealed authority independently.
Durable consumption precedes sending.
Classic MCP authorization refusal renders
`the mainnet write was refused before submission; nothing was sent`.
Classic MCP uses this message at both signing and submission boundaries.
A signer may run before its result is rejected. An envelope may already carry
a signature.

Report authorization refusal to the operator. Fresh preparation and fresh
approval are required for a retry; do not switch networks. The operator reads
`path` and `precondition` in the warn-level `mainnet authorization refused` log.
A submission timeout has an unknown outcome and requires transaction
reconciliation.

DeFi, public SEP-43 signing, generic SEP-53 signing, rule writes, and toolset
signing actions remain excluded on mainnet. Wallet entry guards use
`network.mainnet_write_forbidden`; library entry points retain their namespaced
codes. MPP refuses with `mpp.network_forbidden`. Noop permits mainnet reads and
refuses destructive policy decisions with `policy.engine_required`.

The network layer does not take the profile's declared network on trust either.
Before sending, it asks the endpoint which network it serves and which protocol
it runs (`getNetwork`), on the same client instance that sends. That answer is
authoritative. Ordinary submission refuses a mainnet endpoint with
`network.mainnet_write_forbidden`. Authorized submission verifies the bound
mainnet context. One reporting a different network than the profile declares
is refused with `network.endpoint_network_mismatch`. One whose
identity cannot be established within the submission timeout is refused with
`network.endpoint_identity_unavailable`. One that answers the identity request
with HTTP 401 or 403 is refused with `network.rpc_credential_refused`. The
probe is retried with bounded exponential backoff inside the caller's timeout
and never falls back to the declaration; an answer that does not parse, and a
401 or 403 answer, is not retried.
[Retries, deadlines, and failover](maintainers/security-internals.md#retries-deadlines-and-failover)
gives the numbers. This release supports protocol version 29. On testnet and
other networks, a version outside that range is logged as a warning. On mainnet
authorized submission refuses with `network.unsupported_protocol_version`.
The network layer then fetches the relevant accounts' ed25519 signer sets.
It verifies every decorated signature on the envelope against the network id
the endpoint reports. An account absent from the ledger is
`network.account_not_found`. A signature that fails under the endpoint network
but verifies under mainnet reports `network.envelope_signed_for_mainnet`. One
that verifies under neither network is `network.envelope_signature_unverifiable`.
An envelope
carrying no signature is `network.envelope_unsigned`. For fee bumps, this code
also applies when either the outer or inner transaction has no signature.

The classic prepare tools `stellar_pay`, `stellar_create_account`,
`stellar_trustline`, and `stellar_claim` run the same check on their client
before the first read on it. Their commit tools do the same on the client they
submit with. The fee, the sequence, the claim entry, and the account views
these tools read feed the envelope that is signed or the policy gate. An
admitted mainnet prepare probes the mainnet endpoint before action reads. A
prepare refuses a mismatched or unavailable endpoint with its network code. A
commit runs the check before any other
request and before the single-use nonce is burned, so a refusal there does not
consume the nonce. The submit layer's own check comes after the nonce is
consumed. A commit reads the clock for the nonce's expiry after its check, so
the check's time counts toward that expiry.

The classic prepare tools check the per-operation fee against the effective
signed/profile `classic_max_fee_per_op_stroops`. They use the smaller value,
or the one available value. A higher profile value warns. The enabled-policy
minimum separately requires the signed field. The resolver independently
checks effective fees and thresholds when authorizing the action. The commit tools
`stellar_pay_commit`, `stellar_create_account_commit`,
`stellar_trustline_commit`, and `stellar_claim_commit` check the fee of the
presented envelope the same way, before anything is signed or sent. A fee
above the cap returns `fees.percentile_exceeds_cap`. The message names where
the fee came from: an auto-selected fee and its percentile, an explicit
`classic_base`, the profile's `classic_fee_per_op_stroops`, or the envelope.
A missing effective cap returns `validation.mainnet_fee_cap_required`.
Resolver fee failures become `network.mainnet_authorization_refused`.

An endpoint refusal precedes a missing account or claim entry, a policy
denial, an approval refusal, a rebuild divergence, the audit pre-flight, and a
malformed nonce. It also precedes the chain, fee, asset, and amount checks that
follow a read. Where such a check ends in an `invalid_params` protocol error,
the endpoint refusal is an error result instead. Checks that need no request
come first: argument and envelope decoding, the structural mainnet refusal,
and the forced approval of a toolset-gated pay commit that carries no approval
fields.

The two [policy engines](./concepts.md) are Noop (testnet allow-all; mainnet
read-only allow, mainnet destructive refused) and V1 (signature-verified typed
criteria, first-match default-deny).

A tool that requires `chain_id` refuses any other chain with `invalid_params`
before policy evaluation. `stellar_dex_quote` is the exception: it uses the
supplied `chain_id` to select the router. Policy rules match on the profile's chain for
evaluation and accounting, including gated tools without a `chain_id` argument.

How a `RequireApproval` verdict is satisfied depends on the tool shape:

- Two-phase signing verbs (`stellar_pay`, `stellar_create_account`,
  `stellar_trustline`, `stellar_claim`, each paired with a `*_commit`) split into a simulate step
  and a commit step. The simulate step builds an envelope and mints a single-use
  nonce. It records a pending approval when policy requires approval for either
  the simulate tool or its paired commit tool. The commit step re-checks the
  nonce, byte-compares the envelope against a fresh rebuild, verifies the
  HMAC-SHA256 [attestation](./concepts.md) minted at approve time, signs from
  the keyring, and submits. It re-evaluates its own tool name against current
  state and can still deny an approved request. An exhausted cap returns
  `policy.deny.per_period_cap_exceeded`. The loaded policy document stays fixed
  for the server's lifetime. The wire error on any approval-path failure is the
  uniform `policy.approval_required`, with two exceptions. An explicit operator
  rejection recorded via the approval inbox is reported as
  `policy.approval_rejected`, so the agent stops retrying. An approval already
  spent on a submission is reported as `policy.approval_consumed`; reconcile
  that transaction instead of retrying.
- One-shot signing verbs sign in a single call. If the policy returns
  `RequireApproval` for one of these tools, the call is refused fail-closed with
  `policy.approval_required_unsupported`; the wallet never signs without a
  verified approval.
- `stellar_rule_create` / `stellar_rule_create_commit` (Package D, GH issue
  #8) is a two-phase pair with a DIFFERENT approval-block contract. Unlike the
  signing verbs above, there is no envelope fallback for the commit step to
  fall back on, so `stellar_rule_create` persists the pending approval
  UNCONDITIONALLY. The `approval_nonce` in its response is always present.
  A `requires_operator_approval` field reports the PROPOSE-time policy
  verdict, but this is informational only: `stellar_rule_create_commit`
  ALWAYS requires operator attestation, unconditionally, regardless of this
  field's value or of the policy engine's verdict at commit time. On testnet,
  an `Allow` verdict on a classic commit lets the call proceed without an
  attestation. An `Allow` verdict on rule creation would let the agent grant
  itself permanent, potentially account-wide authority, which this feature's
  contract forbids. The agent NEVER holds rule-write authority at any point
  in this flow. `stellar_rule_create` only simulates and resolves the
  definition (no signing, no submission).
  `stellar_rule_create_commit` verifies the operator's attestation over the
  resolved definition through a DEDICATED gate
  (`PendingApprovalStore::verify_rule_proposal_gate`, distinct from the
  shared pay/claim attestation gate) and unconditionally recomputes the
  digest from the stored snapshot before installing. A mismatch is
  `simulation.divergence` regardless of the policy verdict. The commit spends
  the approval before the install starts, so a retry with the same approval
  returns `policy.approval_consumed` whether the install confirmed, failed, or
  lost its confirmation. After a failed install, list the account's rules
  before proposing the rule again. Every approval
  surface renders the full resolved rule: context, every signer, every policy,
  and the override flags. This includes CLI `approve` and both approval inboxes.
  Operator consent binds to the resolved rule that the wallet installs, not to
  a name or a hash. Both tools structurally refuse `chain_id=stellar:mainnet`
  (`network.mainnet_write_forbidden`), matching every other smart-account
  write surface: `stellar_rule_create` refuses at propose time,
  `stellar_rule_create_commit` refuses again at commit time as defense in
  depth.

Raw argument values are never written to the [audit log](./concepts.md); only
key names and lifecycle metadata are recorded. Typed value events retain each leg's amount, asset, and redacted destination. Verify the chain with
`stellar-agent audit verify <LOG_PATH> --profile <NAME>`.

### Audit pre-flight (fail-closed)

Separately from the policy verdict above, every commit/submit tool that moves
value or signs (`stellar_pay_commit`, `stellar_claim_commit`,
`stellar_create_account_commit`, `stellar_trustline_commit`,
`stellar_sep43_sign_and_submit_transaction`, `stellar_x402_create_payment`,
`stellar_x402_authenticated_payment`, `stellar_dex_trade`,
`stellar_defindex_vault_deposit`,
`stellar_defindex_vault_withdraw`) proves the active profile's audit
chain-root key is acquirable BEFORE the signer is loaded or anything is
submitted. `profile init` mints the audit-log keyring COORDINATE only, no key
material, so a freshly-initialized profile refuses with
`audit.chain_key_unavailable` until the operator runs
`stellar-agent profile rotate-audit-key <name>`. Read-only tools and the
simulate/build phases of the two-phase verbs above are unaffected. They
never sign or submit, so they never reach this pre-flight; the MCP server's
synthesized first-run fallback profile continues to serve them.
`stellar_mpp_charge_commit` runs the same acquisition after it reads its
approval and before it loads the signing key. Its delivery gate writes
`mpp_charge_authorized` before it releases the credential, and withholds the
credential when that row cannot be written (see
[Agent payments with MPP](agent-payments.md)). Every keyed acquisition also
drains the audit outbox. The queue's count and chain head are committed in the
platform keyring. A missing or changed committed prefix refuses acquisition with
`audit.outbox_rows_missing`, before a signing key loads. The operator investigates
and runs `audit acknowledge-outbox-loss`, which revokes decided approvals and
toolset grants before recording the loss. A consent row `stellar-agent approve` queued while this
server held the writer enters the log there. A commit that consumes an approval
therefore has its consent row in the log before the signing key loads.

Acquiring the writer also proves the audit log still contains the chain tip its
keyring-held anchor names. This check runs on every acquisition, including
writer open. The MCP server acquires its audit writer when an operation needs
it, such as a commit preflight before signing. MCP balance reads do not acquire
it. Under V1, payment simulations can reconcile overdue reservations, acquire
the writer, and write settlement audit rows.

The registry normally caches the writer and holds its lock until process exit. A replaced-file refusal during acquisition marks the cached writer for eviction. After callers release it, the next acquisition drops it and checks the file at the path against the anchor.

A log restored from an older copy, truncated, or substituted refuses with
`audit.tip_anchor_mismatch`. Both in-place overwrites and replacements by
rename are checked. The file at the path is compared by identity against
the handle the server holds; its tip is also checked. Every row the server appends is checked
again, for identity and for the file still ending where the server left it, and
a refused row is anchored so the refusal survives a restart. A log that simply moved FORWARD past its anchor
is not a refusal. Unkeyed writers append without moving it, and the next
acquisition absorbs the gap and re-anchors. A log with no anchor at all is
adopted on first use with no operator action when nothing shows it was anchored
before, such as a log written only by unkeyed writers. A recorded audit
binding, a chain-root sidecar, or an `audit_tip_anchored` row in the file shows
it was, and the server then refuses with `audit.tip_anchor_missing`. An
adoption writes its `audit_tip_anchored` row only for a non-empty file.
Recovery from a mismatch or a missing anchor is `stellar-agent audit reanchor
--profile <name> --acknowledge-rollback`. Stop this server first if it holds that profile's
audit writer.

Acquiring the writer also checks the profile's audit binding: the keyring
records the log path digest and the audit-key coordinate the profile writes
under. A profile loaded from its file, the unnamed `default.toml` included,
records an absent binding; the synthesized first-run profile only compares. A
profile that names a different log path or audit key refuses every value tool
with `audit.log_binding_changed` before any key loads, and nothing is created at
the new path. Recovery is `stellar-agent audit reanchor --profile <name>
--acknowledge-binding-change`. The zero-config first-run profile has no profile
file, and `audit reanchor` loads only a profile file: restore the `default.toml`
that recorded the binding, or write one that names the log, then run the
reanchor. A binding change needs no server stop: a server running the edited
profile refuses before it opens the new path, so it holds no lock there, and
its next acquisition finds the accepted binding. A server still running the old
profile refuses after the acknowledgement until it restarts.

## Tool catalog

The server registers 43 tools. For each tool below: the exact registered name,
its purpose, and whether it is read-only, signs without submitting, or signs and
submits. Every tool except `stellar_x402_parse_receipt`, `stellar_toolset_list`,
`stellar_toolset_invoke`, and the five `stellar_mpp_*` tools requires a
`chain_id` argument carrying the CAIP-2 chain id, which must match the profile.
The MPP tools reject a `chain_id` field as unknown and act on the server
profile's chain. `stellar_toolset_invoke` accepts an optional `chain_id` and
forwards it to the routed tool. For `stellar_sep43_get_address` and
`stellar_sep43_get_network` the `chain_id` is optional and defaults to the
profile chain when omitted, but is still validated against the profile when
supplied. `stellar_dex_quote` requires a `chain_id` but never matches it
against the profile; it selects the router from it.

The four classic MCP commits obtain a witness after their policy and fee checks
and before the audit pre-flight, nonce consumption, and signer load.
Results include `cross_check`; pending and submitted rows carry a passed witness.
Trustline and claim commits are unvalued. Testnet without an oracle reports
`skipped`; a configured but unavailable oracle refuses `network.witness_unavailable`.
Disagreements refuse `simulation.divergence`. Credential failures keep
`network.rpc_credential_refused` or the keyring code of the oracle credential
read (`auth.keyring_*`). A witness refusal leaves the nonce usable.
The nonce expiry is checked against the clock read after the witness, so a nonce
that expires while the oracle answers refuses `nonce.expired`.

`stellar_trustline_commit` reads the issuer again and verifies the stored
clawback opt-in for that trustline. An absent issuer refuses `trustline.gate_refused`.
Other issuer read errors keep their own codes and scrubbed messages.
Clawback without a current, verified opt-in refuses
`trustline.clawback_opt_in_required`, including when the issuer enables clawback
after prepare. Nothing is signed and no new approval is minted.
Re-invoke `stellar_trustline` to obtain a new opt-in request.
A verified opt-in permits the commit to continue to its witness.

`stellar_claim_commit` witnesses the source account and complete fresh
claimable-balance record. It does not re-read the source trustline at commit.

### Payments and accounts

| Tool | Purpose | Gating |
| --- | --- | --- |
| `stellar_pay` | Simulate a payment: build the Payment envelope, run the SEP-29 memo-required check, mint a single-use nonce. | No signing; no submission. Not annotated read-only (mints the single-use nonce the commit step consumes). |
| `stellar_pay_commit` | Verify the nonce, re-check the envelope, sign from the keyring, submit. | Signs and submits. Two-phase verb; approval spine. |
| `stellar_create_account` | Simulate account creation: build the CreateAccount envelope, mint a single-use nonce. | No signing; no submission. Not annotated read-only (mints the single-use nonce the commit step consumes). |
| `stellar_create_account_commit` | Verify the nonce, re-check the envelope, sign, submit. | Signs and submits. Two-phase verb; approval spine. |
| `stellar_claim` | Simulate claiming a claimable balance by ID: fetch the entry, run the claimant / predicate / trustline guards, render the typed preview, mint a single-use nonce. | No signing; no submission. Not annotated read-only (mints the single-use nonce the commit step consumes). |
| `stellar_claim_commit` | Recheck record, witness, sign, submit. | Signs and submits. Two-phase verb; approval spine. |
| `stellar_balances` | Fetch native XLM balance and optional trustline balances for an account. | Read-only. |
| `stellar_friendbot` | Fund a testnet account via Friendbot. | Mutating, testnet-only; gated. |
| `stellar_transaction_status` | Reconcile one submitted transaction against the chain and settle the wallet's record of it, by its receipt or, when the receipt is missing, by its reservation. The way out of `submission.tx_timeout`. Reports `record.release_code` for a release on chain evidence and `reservation` for a hold that remains. On a mainnet profile the primary's `FAILED` and `NOT_FOUND` settle nothing until the oracle confirms them. | Reads the chain and writes the wallet's record; moves no value and never sends. Not annotated read-only. |

`stellar_pay` and `stellar_pay_commit` take at most one memo: `memo_text`, `memo_id`, `memo_hash_hex`, or `memo_return_hex`.
`memo_text` is UTF-8 text of at most 28 bytes.
On every network, a `memo_text` holding a control character (U+0000 to U+001F, U+007F to U+009F) or a Unicode format character (category Cf), line separator (U+2028), or paragraph separator (U+2029) is refused as invalid parameters whose message names `validation.memo_control_character` and the character, before any request is sent.
The format characters include the zero-width non-joiner (U+200C) and joiner (U+200D), so a memo cannot carry them.
Other non-ASCII text is accepted.

A v1 rule set that names tools explicitly must include `stellar_transaction_status` to settle timed-out submissions through that server; the server logs `policy.transaction_status_unmatched` at startup when neither that tool nor `*` appears.

### Trustline

| Tool | Purpose | Gating |
| --- | --- | --- |
| `stellar_trustline` | Simulate a trustline change: build the ChangeTrust envelope, run the issuer clawback-flag gate, mint a single-use nonce. | No signing; no submission. Not annotated read-only (mints the single-use nonce the commit step consumes). |
| `stellar_trustline_commit` | Recheck issuer, witness, sign, submit. | Signs and submits. Two-phase verb; approval spine. |

### Fees

| Tool | Purpose | Gating |
| --- | --- | --- |
| `stellar_fee_stats` | Fetch network fee statistics (classic and Soroban inclusion-fee distributions) for fee estimation. | Read-only. |

### Smart-account rules

| Tool | Purpose | Gating |
| --- | --- | --- |
| `stellar_rules_list` | Enumerate active context rules on a smart account: `rule_id`, `name`, `context_type_label`, `valid_until`, `signer_count`, `policy_count`, `baseline`, plus `as_of_ledger`. `baseline` is the rule's signer-set baseline in the profile's audit log: `none`, `v1`, `v2`, `unreadable` (an audit-log integrity error for that rule), or `unknown` when the tool cannot open the log, which leaves the listing working. An integrity error in the log refuses the listing with `sa.audit_log`. A rule reporting `none` refuses signing until its baseline is recorded. Scans up to the same `max_scan_id` default as the CLI `smart-account rules list`. A rule the shared context-rule decoder refuses fails the listing, and so `stellar_rules_get` for every rule of the account, with `sa.deployment_failed` naming the rule id. | Read-only. |
| `stellar_rules_get` | Read one context rule's metadata and its signer-set `baseline` (as `stellar_rules_list` reports it) plus its attached policies (`address`, `identified_kind`: `threshold`, `spending-limit`, or `unknown`), and, when exactly one policy identifies as `spending-limit`, the budget snapshot (`spending_limit`, `period_ledgers`, `in_window_spent`, `remaining_budget`, `as_of_ledger`). A policy whose code hash is missing or unrecognized reports `unknown`. An RPC error during the classification fails the call with `sa.deployment_failed`, and a failed budget read leaves out the snapshot. An integrity error in the log refuses the call with `sa.audit_log`. | Read-only. |
| `stellar_rule_create` | Testnet-only. Resolve and simulate an agent-proposed `add_context_rule` installation from its signers, policies, context, name, expiry, and `auth_rule_ids`. A signer is delegated (to a G-strkey account or a C-strkey contract), raw external, or a WebAuthn passkey by credential name, resolved to bytes at propose time; a policy is raw or typed spending-limit. Mints a domain-separated digest over the resolved arguments and parks the full definition as a pending approval. Install and simulation refuse an invalid simple-threshold parameter with `sa.simple_threshold_install_refused`. A duplicate policy address or two simple-threshold policies refuse with `sa.deployment_failed` at phase `build`. An `external` entry whose `pubkey_data_hex` decodes to empty key data refuses with `sa.auth_entry_construction_failed`. | No signing; no submission. Mints the pending-approval nonce the commit step consumes. |
| `stellar_rule_create_commit` | Testnet-only. Verify the operator's attestation over the resolved definition through a dedicated gate and recompute its digest from the stored snapshot. Operator attestation is always required, regardless of the policy verdict. The commit spends the approval before the install starts, so a retry with the same approval returns `policy.approval_consumed` for every install outcome. Install and simulation refuse an invalid simple-threshold parameter with `sa.simple_threshold_install_refused`. A duplicate policy address or two simple-threshold policies refuse with `sa.deployment_failed` at phase `build`. An `external` entry whose `pubkey_data_hex` decodes to empty key data refuses with `sa.auth_entry_construction_failed`. Every non-zero `auth_rule_ids` entry first passes the pre-submission checks, and a refusal signs nothing. Baseline and comparison refusals are `sa.signer_set_missing_baseline`, `sa.signer_set_diverged`, `sa.audit_log`, and `network.rpc_divergence`. Lock timeout is `sa.auth_entry_construction_failed` at stage `rule_lock`. A deadline that elapses during the baseline read or the comparison uses that code at `baseline_read` or `signer_set_compare`. Pin refusals are `sa.verifier_hash_drift`, `sa.policy_hash_drift`, `sa.pinned_policy_absent`, `sa.pinned_verifier_absent`, and `sa.pin_check_unavailable`. A version 1 authorizing rule compares through its projection. Its own refusals are `sa.threshold_policy_not_installed`, `sa.threshold_policy_identification_failed`, and `sa.deployment_failed`. After the install confirms, the observed rule's signer identities and simple threshold must equal the proposal's. That observation is recorded as the rule's signer-set baseline. The name, context, expiry, and other policy attachments are not compared. Otherwise the rule stays on chain without a baseline, and the tool returns `sa.install_state_mismatch` or `sa.baseline_write_failed` with the transaction hash. | Signs and submits. Two-phase verb; approval spine. |

`spending_limit`, `in_window_spent`, and `remaining_budget` are decimal
strings (i128, stroops), not JSON numbers. A raw JSON number above `2^53`
cannot be represented exactly by an `f64`-backed parser. `in_window_spent`
and `remaining_budget` are exact only as of `as_of_ledger`: forward ledger
movement past that point only grows headroom (older spend entries fall out
of the rolling window), but an intervening spend shrinks it. The numbers are
a point-in-time estimate, not a guarantee for a future submission. A later
write can still fail with `SpendingLimitExceeded`.

Both tools are grantable to a toolset via the `read-rules` capability token,
separately from `read-balance`. See [Toolsets](./toolsets.md).

#### Why there is no agent-facing execute tool

The CLI has `smart-account execute` (see [Agent delegation](./agent-delegation.md)
and [CLI reference: smart-account](./cli-reference/smart-account.md#smart-account-execute)):
an operator-run verb that submits one `CallContract` invocation signed by an
agent's External-Ed25519 rule key. There is deliberately no MCP equivalent.

Every value-moving MCP tool in this catalog is a TYPED verb whose rendered
preview is what the operator consents to. The three SEP-43 transaction and
auth-entry signing tools are the exception: they sign caller-supplied material
as `opaque_sign`. A value criterion, such as a per-transaction or per-period
cap, refuses them with `policy.deny.unsizable_value_effect`. A matching rule
that sets `allow_opaque_signing = true` exempts them from that refusal. A
matching rule without criteria returns its own decision. `stellar_pay_commit` renders a
payment, `stellar_rule_create_commit` renders a full rule definition, and so
on. An arbitrary-invocation `execute` tool on the agent surface would have no
such preview: it would sign whatever contract, function, and `ScVal` arguments
the agent supplied, with nothing meaningful to show the operator before
consenting. That contradicts the typed-tool consent model this catalog is
built on. The CLI verb has no such conflict, because the CLI itself is
operator authority: there is no separate consent step to bypass.

This is a scope decision, not a permanent gap: a concrete agent use case that
needs a typed, previewable, approval-spine-backed shape (for example, a
narrowly-typed "agent-signed SEP-41 transfer" tool with a rendered preview,
rather than an arbitrary-invocation tool) would be evaluated on its own
terms.

### DeFi

| Tool | Purpose | Gating |
| --- | --- | --- |
| `stellar_defindex_vault_deposit` | Deposit into a DeFindex vault behind an ordered trust gate (vault WASM-hash pin, upgradable-flag check, role and asset disclosure), then a smart-account submit. | Signs via the smart account and submits; policy gate. |
| `stellar_defindex_vault_withdraw` | Withdraw from a DeFindex vault by redeeming shares, behind the same trust gate. | Signs via the smart account and submits; policy gate. |
| `stellar_dex_trade` | Soroswap router-direct swap, behind a venue allowlist, router WASM-hash pin, and on-chain slippage re-verify, then a smart-account submit. | Signs via the smart account and submits; policy gate. |
| `stellar_dex_quote` | On-chain Soroswap `router_get_amounts_out` quote for a token path. | Read-only. |

The three DeFi signing tools accept an optional `secondary_rpc_url`. On testnet, it overrides the profile secondary; absent input uses that secondary.
Credentialed input URLs are refused. On a mainnet profile the three tools refuse at entry with `network.mainnet_write_forbidden`, before this input, the lookups, and the gates.

### SEP-43 (wallet interface)

| Tool | Purpose | Gating |
| --- | --- | --- |
| `stellar_sep43_get_address` | Return the active wallet address. | Read-only. |
| `stellar_sep43_get_network` | Return the active network name and passphrase. | Read-only. |
| `stellar_sep43_sign_transaction` | Sign a `TransactionEnvelope` XDR; return `signedTxXdr` and `signerAddress`. | Signs; does not submit. Requires the audit chain key (refuses `audit.chain_key_unavailable` before signing) and records an `opaque_payload_signed` audit row. |
| `stellar_sep43_sign_auth_entry` | Sign the base64 `HashIdPreimage` of a Soroban authorization entry (envelope type 9, or type 10 bound to the signing key's account); return the raw signature as `signedAuthEntry` and `signerAddress`. | Signs; does not submit. Requires the audit chain key (refuses `audit.chain_key_unavailable` before signing) and records an `opaque_payload_signed` audit row. |
| `stellar_sep43_sign_message` | Sign an arbitrary UTF-8 message via `SHA-256("Stellar Signed Message:\n" + message)` then ed25519; return `signedMessage` (base64) and `signerAddress`. | Signs; does not submit. Refuses an overlaid or out-of-scope signer. Requires the audit chain key (refuses `audit.chain_key_unavailable` before signing) and records an `opaque_payload_signed` audit row. |
| `stellar_sep43_sign_and_submit_transaction` | Sign a `TransactionEnvelope` XDR, submit it, and poll until confirmed; return `signedTxXdr`, `txHash`, and `status`. | Signs and submits; policy gate. |

These six tools use the standard `{ ok, data, request_id }` / `{ ok, error:
{ code, message }, request_id }` result envelope like every other tool. The
SEP-43 raw protocol payload (`signedTxXdr`, `signerAddress`, `network`, etc.)
is carried inside `data` on success. Protocol failures carry a `sep43.*` wire
code derived from the SEP-43 error taxonomy (e.g.
`sep43.wallet_unlock_failed`, `sep43.invalid_network_passphrase`); the
structural mainnet refusal shares the canonical `network.mainnet_write_forbidden`
code used by wallet entry guards. Library signing uses
`sep43.mainnet_signing_forbidden` or `sep43.mainnet_authorization_refused`.
A policy `RequireApproval` verdict (which every single-shot sign tool,
including SEP-43, refuses fail-closed) carries
`policy.approval_required_unsupported`.
SEP-53 and x402 use the same standard envelope for every business error.

Both `stellar_sep43_sign_message` and `stellar_sep53_sign_message` use these
refusals before loading the signer:

| Code | Meaning |
| --- | --- |
| `network.mainnet_write_forbidden` | The selected profile is mainnet. |
| `profile.non_overlayable_field` | Message signing requires `mcp_signer_default` from the profile file. Unset `STELLAR_AGENT_MCP_SIGNER_DEFAULT`. |
| `profile.key_scope_conflict` | The signer entry or its enrolled-identity entry is out of scope, shared with a sibling, or collides with another entry of this profile, or the signer account is the signer account of a mainnet profile in the same data root (`mainnet_signer_identity`). |
| `profile.key_scope_conflict` | A sibling, selected document, or profiles directory cannot be read for the scope check. |
| `audit.chain_key_unavailable` | The audit writer cannot be acquired before signing. The error identifies the recovery. |

Message scope checks apply on every chain within the selected data root.
Each successful signature writes one `opaque_payload_signed` audit row with
the redacted SEP-53 digest and signer. The row contains neither the message nor
the signature. A post-signature append failure warns and preserves the result.

### SEP-45, SEP-47, SEP-48, SEP-53

| Tool | Purpose | Gating |
| --- | --- | --- |
| `stellar_sep47_discover` | Read the `contractmetav0` `sep` meta entry of a contract and return the SEPs it claims to implement. | Read-only. |
| `stellar_sep48_preview_invocation` | Fetch the on-chain contract spec and render typed argument names and JSON values for an `InvokeHostFunction`, from a transaction XDR or a contract id plus function name. | Read-only. |
| `stellar_sep53_sign_message` | Sign a prefixed message: `SHA-256('Stellar Signed Message:\n' + message)` then ed25519; return the base64 signature and signer public key. Uses the same digest and signature bytes as SEP-43 `signMessage`. | Signs; does not submit. Refuses an overlaid or out-of-scope signer. Requires the audit chain key (refuses `audit.chain_key_unavailable` before signing) and records an `opaque_payload_signed` audit row. |
| `stellar_sep53_verify_message` | Verify a SEP-53 base64 signature against a G-strkey public key and message. | Read-only; no keyring. |

SEP-45 is the contract-account authentication scheme used by the SEP-10/45 JWT
that `stellar_sep24_interactive_url` consumes; it has no standalone tool. See
[Protocols](./protocols.md) for the SEP coverage in detail.

### SEP-6, SEP-7, SEP-24

| Tool | Purpose | Gating |
| --- | --- | --- |
| `stellar_sep6_deposit_info` | SEP-6 anchor capability discovery: `GET /info` only. Returns the decoded anchor capabilities, including `authentication_required` per asset. Never calls `/deposit`, `/withdraw`, or any KYC endpoint. | Read-only. |
| `stellar_sep7_parse_uri` | Parse an inbound `web+stellar:tx?...` or `web+stellar:pay?...` URI into a structured preview, optionally fetching the `stellar.toml` and verifying the ed25519 origin signature. Never auto-signs or auto-POSTs. | Read-only. |
| `stellar_sep24_interactive_url` | SEP-24 interactive deposit/withdraw hand-off: resolve the SEP-24 transfer server, POST the interactive endpoint with a SEP-10/45 JWT, and return the interactive URL, transaction id, and a hand-off note. The wallet never opens or scrapes the URL and never transmits KYC fields. | Hand-off; does not sign or submit. |

### x402

| Tool | Purpose | Gating |
| --- | --- | --- |
| `stellar_x402_create_payment` | Construct and sign an x402 v2 Exact Stellar `PAYMENT-SIGNATURE` from a `PaymentRequirements` object; obtain the cross-check witness before signing; return the payment signature, its fields, and `cross_check`. The wallet does not submit. On an admitted mainnet server, call 1 returns approval instructions. Call 2 verifies approval and releases the authorized payment payload. | Signs the payment authorization entry; does not submit. |
| `stellar_x402_parse_receipt` | Decode an x402 v2 `PAYMENT-RESPONSE` into a structured settlement receipt. Text fields are escaped and cut at 200 characters. | Read-only; no keyring, no network. No `chain_id`. |
| `stellar_x402_authenticated_payment` | Run a SEP-10 identity gate against a `home_domain` (stellar.toml, SSRF bind, ephemeral challenge/response, JWT), then construct the `PAYMENT-SIGNATURE` with the cross-check witness. Any identity failure aborts before payment. On an admitted mainnet server, call 1 returns approval instructions. Call 2 verifies approval and releases the authorized payment payload. Call 2 signs and submits the bound SEP-10 challenge before payment construction. | Signs the payment authorization entry; does not submit. |

The `chain_id` argument of both payment tools takes the wallet's spelling,
`stellar:testnet` or `stellar:mainnet`. The x402 requirement `network` spells
mainnet `stellar:pubnet`; that spelling is not a valid `chain_id`.

Both payment tools run in this order:

1. The remaining steps describe a testnet profile. A mainnet profile refuses
   with `network.mainnet_write_forbidden` unless the server admits mainnet
   writes. An admitted server runs the two calls described below.
2. The `payment_required` input is decoded and validated in full. An invalid
   field answers its own `x402.*` code, such as `x402.invalid_recipient_address`
   or `x402.invalid_payment_required` for a `maxTimeoutSeconds` of zero. This
   step consumes no spending window.
3. The dispatch gate checks `chain_id` and the policy. A `chain_id` mismatch
   is a JSON-RPC invalid-params error, which invalid requirements never reach.
4. The audit pre-flight runs, then the SEP-10 gate for the authenticated tool.
   The cross-check rule then decides from the transfer amount, in the asset's
   atomic units, and the profile's thresholds and oracle whether the payment
   needs the witness. A required witness builds the oracle client from
   `oracle_provider_url` without a request.
   A credential failure keeps its own code. Other client construction failures
   refuse with `network.witness_unavailable`. The signer load follows.
5. The tool builds one RPC client from the profile's `rpc_url`, with the
   primary credential the profile names. A URL the transport cannot parse
   refuses with `network.rpc_unreachable`; a credential the keyring cannot
   supply refuses with its keyring code or `network.rpc_credential_refused`.
6. The payment is admitted against the spending window.
7. The payment is built on that client. Its first request is the endpoint
   identity check, under the profile's `submit_timeout_seconds` (default 60
   seconds); `maxTimeoutSeconds` never sets this deadline. The first
   simulation must hold exactly one result with the payer's unsigned
   authorization entry for the built transfer. When the witness is required,
   the oracle then simulates the same unsigned transfer. Its answer must hold
   the same authorization entries apart from the nonce and the expiration.
   Its `minResourceFee` lies between 1 and 10,000,000 stroops.
   Its ledger trails the primary's by at most two and lies before the
   signature expiration. The health read follows under the same deadline,
   and only then does the payer sign.

An identity refusal answers `network.endpoint_network_mismatch`,
`network.endpoint_identity_unavailable`, `network.rpc_credential_refused`, or
`network.mainnet_write_forbidden` through both tools. A witness refusal answers
`simulation.divergence`, `network.witness_unavailable`,
`network.rpc_credential_refused`, or the oracle credential read's keyring code
(`auth.keyring_*`). Both tools refuse before the payer signs and without an
x402 row. The authenticated tool answers every other build failure
with `x402.payment_build_failed`. On testnet, admission comes before the
identity check, so a refusal there, or any later failure, keeps the admitted
spend.

Results include `cross_check`, and the `x402_payment_authorized` row carries a
passed witness when the payment required one. The row also records
`signature_expiration_ledger`, the last ledger at which the signed
authorization is valid. Below the asset's threshold, the result reports
`not_required`. On mainnet the oracle still bounds the ledger of such a
payment: it answers `getNetwork` and `getLatestLedger`, and its ledger must
trail the primary's simulation by at most two ledgers and lie before the
expiration ledger, or the payment refuses with `simulation.divergence`. A
mainnet profile without `oracle_provider_url` refuses every x402 payment with
`network.witness_unavailable` before the payer signs. On testnet, a payment
below the threshold sends no oracle request, with or without an oracle, and a
payment at or above the threshold without an oracle reports `skipped`.
An asset without a threshold reports `skipped` on testnet, with or without
an oracle.

#### Mainnet x402 calls

On an admitted mainnet server, each x402 payment takes two calls. Both tools
take the optional `approval_nonce` and `approval_attestation` arguments.
`approval_nonce` is optional in the schema. Omit it with `approval_attestation`
for mainnet call 1, and supply both for call 2. Mainnet call 2 requires the
CLI-issued attestation alongside its approval nonce. Supplying only one approval
argument returns `policy.approval_required`.

Call 1 runs these checks and stores the pending approval:

1. The entry and startup checks refuse with `network.mainnet_write_forbidden`.
   They require the server's mainnet context, an admitted tool, the V1 engine,
   the verified policy and enablement, the enabled context, and the profiles
   directory.
2. The `payment_required` input is decoded and validated. An invalid field
   answers its own `x402.*` code.
3. `chain_id` must match the profile, or the call returns a JSON-RPC
   invalid-params error.
4. The approval pair is checked. A call without either argument is call 1.
5. The authenticated tool validates `home_domain` as a lowercase LDH name and
   refuses another with `identity.home_domain_invalid`. A malformed domain is
   never approved.
6. The enrolled signer is loaded, and an `address` that names another key
   refuses with `x402.invalid_payment_required`.
7. The payment root and its intent digest are computed.
8. Local policy evaluation runs without an account-reserve view. A matching
   `minimum_reserve` criterion refuses with `policy.engine_required` before
   approval is stored.
9. Forced approval turns an Allow verdict into a required approval.
10. The pending approval is stored and returned.

Call 1 reads enrollment and local policy state. It sends no payment RPC or
SEP-10 request and performs no signing. Call 1 returns `data.approval` without a
payment payload. Its fields are `approval_nonce`, `profile`, `chain_id`,
`expires_at_unix_ms`, `reason`, `endpoint_host`, `signer`, `summary`, and
`instructions`. `summary` contains `payTo`, `amount`, and `asset`.

Approve x402 payments through `stellar-agent approve --id <nonce> --profile <name>`
in a terminal. Approval-ui and remote approval do not attest this approval kind.
For an x402 payment, `stellar-agent approve` shows the payee, amount, and asset,
and a `Home domain:` line that reads `none` for the plain tool.
The authenticated approval subject binds the payment intent digest and home
domain. Changing the home domain requires a matching approval.

Call 2 repeats the request with both approval arguments and runs these steps:

1. The entry checks, the requirements, `chain_id`, the approval pair, and the
   home domain run as in call 1.
2. Startup freshness compares the current policy and enablement with the
   startup binding. A changed binding returns `network.mainnet_write_forbidden`
   with `enablement or policy changed, restart the server`.
3. Enrollment and address, local policy evaluation, and forced approval run as
   in call 1.
4. The attestation and its bound subject are verified. A missing, invalid, or
   mismatched approval returns `policy.approval_required`. A live rejection
   returns `policy.approval_rejected`.
5. The authenticated tool checks audit readiness, then runs the identity
   exchange. It fetches `stellar.toml`, prepares and validates the SEP-10
   challenge, and consumes its message authorization. It then signs and submits
   the challenge.
6. Payment audit readiness is acquired, and the signing handle is constructed.
   The seed is read only at signing.
7. The bound primary client is built. Its first request checks that the
   configured endpoint serves mainnet.
8. The unsigned simulation, the oracle check, and the health read run before
   the payer signs. At or above the threshold the oracle simulates the
   payment; below it the oracle answers its latest ledger.
9. The payment intent authorization is minted over the invocation, the
   entry's nonce, and its signature expiration ledger, and the payer signs
   that one authorization entry.
10. The `x402_payment_authorized` audit row is written and anchored.
11. The payment intent is consumed, and the signed re-simulation follows.
12. The release authorization is minted for the final envelope, and the payload
    is encoded.
13. The release authorization is consumed, then the pending approval.
14. The payload is released.

Call 2 verifies approval before the identity exchange. The authenticated tool
completes SEP-10 authentication before the payment endpoint check, witness, and
payer signature.

The plain tool's call 2 returns `data` with `paymentSignature`, `payer`,
`asset`, `amount`, `payTo`, `network`, and `cross_check`. The authenticated
tool returns the plain fields plus `authorization`, `home_domain`, and
`payto_anchored`. `authorization` contains the Bearer JWT companion.

For the plain tool, authorization refusals use
`network.mainnet_authorization_refused`. Policy denials keep `policy.deny.*`.
Other payment errors keep their own codes.

For the authenticated tool, authorization refusals identify the withheld payment
payload. Policy, endpoint, and witness errors keep their codes. Other
payment-build failures use `x402.payment_build_failed`. The tool maps the
identity library's `identity.mainnet_signing_forbidden` and
`identity.mainnet_authorization_refused` to `network.mainnet_write_forbidden`
and `network.mainnet_authorization_refused`, respectively. Its two withholding
messages are:

```text
the mainnet authorization for this SEP-10 authentication was refused; no signed challenge was submitted
the mainnet authorization for this payment was refused; the payment payload was withheld
```

A withheld payment payload does not establish that no signature exists. The
configured RPC can already have received the signed authorization during
re-simulation. Every mainnet x402 error reply after the transmit gate passes
appends this sentence, where `<L>` is the `signature_expiration_ledger` of the
audit row of step 10:

```text
; the signed authorization may have reached the configured RPC and is valid through ledger <L>
```

The authorization can still settle until ledger `L`, so a new payment for the
same resource before then can pay twice. A consumed payment intent retains its
debit after a later failure. An open intent can be invalidated before
consumption.

After `profile enable-mainnet` or `profile sign-policy`, restart the MCP server.
A live consumed approval returns `policy.approval_consumed`. Without its
pending-store tombstone, the authorization ledger refuses reuse.

After a failed SEP-10 challenge submission, the Message record stays used and
the approval stays pending. A repeat of the same call 2 fetches and validates a
new challenge, then refuses with `network.mainnet_authorization_refused` at the
Message mint. It submits no second signed challenge. The remedy is a new call 1
and a fresh approval. A challenge that names another client account
refuses before the Message record is minted. The approval stays unspent, and the
same call 2 can be repeated.

[Mainnet refusal order](getting-started.md#mainnet-refusal-order) lists what
has been signed or sent when a mainnet check refuses.

### Machine Payments Protocol

MPP is testnet-only, sponsored-pull, and credential-only. The server refuses all
five tools on a mainnet profile before state, RPC, keyring, or signer access.

| Tool | Arguments | Purpose |
| --- | --- | --- |
| `stellar_mpp_charge_prepare` | `profile`, tagged `challenge` | Strictly validate and context-bind an HTTP/native-MCP challenge, simulate, evaluate policy, and persist a preview plus nonce. Never signs. |
| `stellar_mpp_charge_commit` | `authorization_id`, `nonce`, `expires_at_unix_ms` | Load only stored exact terms, verify approval/policy, sign once, re-simulate, audit, and return one sensitive credential. |
| `stellar_mpp_record_receipt` | `authorization_id`, tagged `receipt` | Record a trusted-host receipt digest without claiming ledger settlement. |
| `stellar_mpp_reconcile_transaction` | `authorization_id`, lowercase `transaction_hash` | Verify the exact final transaction, transfer, payer authorization and signature through RPC. |
| `stellar_mpp_authorization_status` | `authorization_id` | Return redacted lifecycle, accounting, receipt, and ledger-outcome state. |

Commit accepts no replacement payment terms. The trusted host must use the exact
bound request context over TLS, keep credentials and receipts out of logs, avoid
fallback payment after ambiguity, and never retry a consumed commit. The
configured RPC sees signed authorization during mandatory re-simulation. See
[Agent payments with MPP](agent-payments.md) for schemas and recovery behavior.

### Toolsets

| Tool | Purpose | Gating |
| --- | --- | --- |
| `stellar_toolset_list` | Enumerate installed toolsets and their invocable actions. | Read-only. No `chain_id`. |
| `stellar_toolset_invoke` | Invoke a named action of an installed toolset, routed to a registered tool through capability enforcement. | Dispatcher. Destructive; refused on mainnet. The toolset signs nothing directly; the dispatcher's and the routed tool's policy gates apply. Optional `chain_id`, forwarded to the routed tool. |

The toolsets dispatcher enforces a toolset's declared capabilities, read from its
install record, which is authenticated by an HMAC under an installation key in the
platform keyring and carries the `TOOLSET.md` digest both resolvers check. Its
ungated routes never reach a signing tool regardless of those declarations; the
signing actions route to the commit tools only behind the first-invoke gate and
the per-action approval described in [Toolsets](./toolsets.md). A toolset narrows
what this dispatcher routes. It does not narrow the native tools this server
registers, the caller chooses the `toolset` argument, and the server binds no
session to a toolset; the operator policy and the approvals bound native and
routed calls alike. A record that does not verify refuses with
`toolset.pin_unverifiable`.

## Output and exit behavior

Tool results are returned as MCP tool-call content; read-only tools return JSON
shaped like their CLI counterparts. The server runs until the MCP client closes
the connection. An unloadable profile or a duplicate tool registration makes
the process exit non-zero before serving any request. A missing keyring backend
alone is not fatal: the server starts, and signing tools fail closed at call
time. A profile that selects the V1 engine still fails to start without one,
because building the engine reads the owner key.

Business errors return `{ "ok": false, "error": { "code", "message" }, "request_id" }`
with `is_error` set; consumers branch on `error.code`. Every tool, including
the SEP-43 family, uses this same envelope for business errors. Success results
use `{ "ok": true, "data", "request_id" }` with five exceptions.
`stellar_toolset_list` returns a bare JSON array. `stellar_dex_trade`,
`stellar_dex_quote`, `stellar_defindex_vault_deposit`, and
`stellar_defindex_vault_withdraw` return a bare object carrying a `status`
field. Some refusals use the JSON-RPC error channel instead of the envelope: invalid
arguments, a `chain_id` mismatch, and the toolset capability refusals.
`toolset.first_invoke_approval_required` is a JSON-RPC error too, and its error
data carries the `approval_nonce`. See
[The result envelope](agents.md#the-result-envelope).

Three codes carry an additional `details` object on the error:
`submission.tx_timeout`, `submission.tx_already_submitted` and
`submission.hash_mismatch`. Each describes a submission whose outcome the
wallet cannot settle on its own, and resolving it needs the full transaction
hash, which the message redacts. A `submission.tx_timeout` submission may
still apply: the message says to settle it by its transaction hash and not to
resubmit. `details` carries that hash, `outcome: "unknown"`,
`reconcile_with: "stellar_transaction_status"`, and the envelope hash naming
the submission record where the reporting tool holds the signed bytes.
DeFi submission errors carry both hashes, and `stellar_transaction_status`
also reports `record.envelope_hash`. No other code carries
`details`, and the field is absent from the serialised envelope when it is not
set. The recovery protocol is in
[the MCP usage reference](../crates/stellar-agent-mcp/docs/usage.md).
