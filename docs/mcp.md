# The MCP server

`stellar-agent-mcp` is a [Model Context Protocol](https://modelcontextprotocol.io)
server that exposes the Stellar Agent Wallet to an MCP client. It speaks
JSON-RPC over stdio and presents wallet capabilities as MCP tools, so an AI
assistant can read account state and submit Stellar transactions through the
same policy engine, operator-approval spine, and tamper-evident audit log that
back the `stellar-agent` CLI.

MCP and CLI handlers share policy primitives but determine their own gate
coverage. MCP balance reads evaluate policy; CLI balance reads do not.
The policy engine evaluates gated calls to `Allow`, `Deny`, or `RequireApproval`
before signing.
`stellar_dex_quote`, `stellar_x402_parse_receipt`, `stellar_mpp_record_receipt`,
`stellar_mpp_reconcile_transaction`, and `stellar_mpp_authorization_status`
run without a policy verdict. Tools with an approval flow wait for operator
consent. The SEP-43 auth-entry and message tools, `stellar_sep53_sign_message`,
and the DeFi tools refuse `RequireApproval` with
`policy.approval_required_unsupported`. The x402 payment tools queue an
approval. The two SEP-43 transaction tools
approve one payment, path payment, account creation or trustline change in two
calls.
Default builds enable the `mainnet-write` feature. Mainnet writes also require operator setup and per-action
authorization. The four classic commit tools use independent signing and
submission checks. See
[Concepts](./concepts.md) for the shared guardrail model.

## What it is

- One process: the `stellar-agent` executable of the `stellar-agent-cli`
  crate, started as `stellar-agent mcp serve` or under the file name
  `stellar-agent-mcp`. The server code is the `stellar-agent-mcp` library
  crate.
- Transport: MCP JSON-RPC over stdio. The client spawns the binary as a
  subprocess and exchanges newline-delimited JSON-RPC on the subprocess
  stdin/stdout.
- Protocol version: `2024-11-05`. Declared capabilities: `tools` and
  `resources`.
- Server identity reported at initialize: name `stellar-agent-mcp`, version
  equal to the crate's package version.

`stdout` is reserved for the JSON-RPC wire. Structured logs go to `stderr`, and
they pass through a redaction layer before they are written, so a client that
captures `stderr` receives already-redacted output. Mixing log lines into
`stdout` would corrupt the protocol stream, which is why the split is strict.

The transport reads one line at a time and enforces a 1 MiB maximum length on
each inbound line. An empty line, or one that holds only `\r`, is skipped. A
line that is not a JSON-RPC message, or one over the 1 MiB limit, is answered
with a JSON-RPC `-32700` error without an `id`, and the session continues. A
line that is not a JSON-RPC message and holds a `method` the server does not
know and no `id` is skipped without an answer. The session ends at end of
input, on a read error, or when an answer cannot be written. The server's own
outbound frames are not checked against the limit.

This alpha does not offer an HTTP or SSE transport. stdio is the only transport.

### Availability

Install the one package with
`cargo binstall --locked --disable-strategies quick-install,compile stellar-agent-cli@0.2.0-alpha.1`
(prebuilt binary from the tagged GitHub release, resolved through crates.io),
with `cargo install --locked stellar-agent-cli@0.2.0-alpha.1` (built from the
published sources and their `Cargo.lock`), or build from source.
[Install](./getting-started.md#install) states when to spell out the version.

Each of these installs `stellar-agent` only, which also runs the server. The
stanzas below start
`stellar-agent-mcp`, so copy the executable to that name next to it:

```bash
cp ~/.cargo/bin/stellar-agent ~/.cargo/bin/stellar-agent-mcp
```

Repeat the copy after each upgrade. The direct release archives already hold
both names as byte-equal files. See [Install](./getting-started.md#install)
for the Windows command.

## Launching the server

The server is started by running the executable under its server name, or with
the `mcp serve` subcommand. Configuration comes from the selected profile.
The server name is the last component of the invoked path, and it must equal
`stellar-agent-mcp` exactly. On Windows the comparison ignores ASCII case and
also accepts `stellar-agent-mcp.exe`. Under any other file name the executable
runs the CLI, whose `mcp serve` subcommand starts the server.

```bash
stellar-agent-mcp                    # profile `default`
stellar-agent-mcp --profile alice    # profile `alice`
stellar-agent mcp serve --profile alice
```

The profile is selected by `--profile <NAME>` (also spelled
`--profile=<NAME>`), then by the `STELLAR_AGENT_PROFILE` environment variable,
then by the name `default`, the same order the CLI uses. The selected profile
binds at startup and stays bound for the life of the process; there is no
per-request profile switching. Any other argument is refused with exit 2
rather than ignored, so a mistyped flag cannot silently start the server on
a different profile than intended.

A mainnet profile loads only through `--profile <name>`. `STELLAR_AGENT_PROFILE` never selects one, and a mainnet `default.toml` needs `--profile default`. Keep the filename: its identity is bound to its keyring entries.

Implicit mainnet selection exits with `profile.mainnet_requires_explicit_profile`.
The message names the selection source and the recovery command:
`stellar-agent-mcp --profile <name>`.
The message leaves out the requested name, which may be a value typed into the
wrong place; the CLI message for this refusal names the profile. The server's
refusal of a named profile without a file leaves the name out too.
An environment or programmatic overlay may set only operational fields.
`submit_timeout_seconds` is overlayable on every chain, and `mcp_disabled`
accepts only `true`. [Loader source order](profiles.md#loader-source-order)
lists the keys that are overlayable on testnet only. Every other profile key, `chain_id` and
every keyring coordinate included, comes from the file only. A refused overlay
exits with `profile.non_overlayable_field` and asks the operator to remove the
field from the environment or the overlay. A variable that names no profile
key, such as `STELLAR_AGENT_HOME`, is ignored.

Unset the refused `STELLAR_AGENT_*` variable named in the message, remove the key from programmatic overlays too, and set the value in the profile file instead. Then run `stellar-agent profile show --profile <name>` to confirm the file's chain and endpoint. Correct the profile file if either value differs from the intended configuration.

The server resolves one `NetworkContext` at construction for tool network reads.
Profile resources keep their loader behavior: a profile under a refused overlay
reads as `profile_resource_unloadable`. Account enumeration skips that profile.

On startup the process, in order:

1. Applies process-isolation hardening on Linux (`PR_SET_DUMPABLE 0`,
   `PR_SET_NO_NEW_PRIVS 1`) on the initial thread before spawning any other
   thread, so every thread of the server process carries both. On macOS and
   Windows it relies on the platform keyring's per-application access model
   and operator policy instead.
2. Parses the command line, resolves the profile name (`--profile`, then
   `STELLAR_AGENT_PROFILE`, then `default`), and validates that the name is
   usable as a path component. An unrecognized argument or an unusable name is
   refused here, before any of the steps below run.
3. Installs the redacting log subscriber on `stderr`.
4. Initializes the platform keyring store. If the platform has no supported
   keyring backend, it logs a warning and continues: the read-only and simulate
   surface still works, and signing tools refuse at call time. A headless
   backend that cannot be set up, such as an unknown
   `STELLAR_AGENT_KEYRING_BACKEND` value or a missing, padded, or
   standard-alphabet `STELLAR_AGENT_HEADLESS_KEYRING_KEY`, takes the same path:
   the warning carries the `auth.keyring_config_invalid` cause, no keyring store
   is registered, and the server serves without one.
5. Loads the selected profile. When no profile was named (neither `--profile`
   nor `STELLAR_AGENT_PROFILE`) and no profile file exists yet, it synthesizes
   a testnet fallback profile (the first-run case). A profile that was named but
   has no file is refused: the fallback is a testnet, `noop`-engine
   configuration, so substituting it would answer on the wrong network and
   downgrade the profile's policy engine.
6. Refuses to start if the active profile sets `mcp_disabled = true` (the
   operator kill-switch), exiting 1 with `mcp.disabled_per_profile`.
7. Refuses to start if the profile file's `policy_owner_key_id.service` names a
   different profile than the one selected, the state a profile file renamed or
   copied from another profile is in. The server derives the name it uses for
   the signed policy file, the pending-approval store, and the policy-window
   state from that field, so a mismatch would read and write another profile's
   state.
8. Refuses a mainnet profile whose keyring entries conflict with another
   profile, with `profile.key_scope_conflict`. A testnet conflict logs a
   warning.
9. Builds the server and serves the MCP loop until the client disconnects.

You normally do not launch `stellar-agent-mcp` by hand. The MCP client spawns
it. The command above is what the client is configured to run.

**Windows deployment note:** Credential Manager requires an interactive logon
session. Running the server as a Windows service, over SSH, or from a
scheduled task prevents access to Credential Manager. At startup the server
reads the policy owner entry from the keyring, for every engine. When
Credential Manager refuses that read, the server exits 1 before serving, with
`auth.keyring_interactive_session_required`. The server starts only when that
read returns a key or no entry. A signing tool whose own keyring read is
refused then reports the refusal at call time. Most tools report
`auth.keyring_interactive_session_required`. `stellar_sep43_sign_message` and
`stellar_sep53_sign_message` report it too, because both read the signer
identity record before the signing key.
The other SEP-43 sign tools report `sep43.wallet_unlock_failed`, and
`stellar_mpp_charge_commit` reports `mpp.signing_failed`.
A host with no registered keyring backend starts unless the profile selects the
V1 engine, and its signing tools refuse at call time.
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
access fails until the profile's signer is enrolled. The enrolled-signer loader
reports `auth.enrolled_identity_unusable` (`missing`) when the identity record
is absent. After the record passes validation, a missing seed reports
`auth.keyring_not_found` on most tools.
The SEP-43 sign tools report `sep43.wallet_unlock_failed`.
`stellar_sep53_sign_message` reports `sep53.keyring_load_failed`, and
`stellar_mpp_charge_commit` reports `mpp.signing_failed`.
This fallback applies only when no profile was named at all;
`--profile <NAME>` and `STELLAR_AGENT_PROFILE` always require a real profile
file.

The profile field `mcp_disabled` is a per-profile kill-switch. When `true`, the
server refuses to start, exiting 1 with `mcp.disabled_per_profile`. The
flag is also surfaced as non-secret metadata on the
`mcp-resource://profiles/<name>` resource so a client can read whether the MCP
surface is enabled for that profile.

### Emergency stop

`mcp_disabled` takes effect at the next start. To stop an agent on a running
server, the operator runs `stellar-agent profile halt <name>` (see
[`profile halt`](cli-reference/profile-and-governance.md#profile-halt-name---reason-reason)).
The server reads the profile's halt marker at the start of every tool call
that is not read-only, so the halt takes effect on the next call without a
restart. A call that passed
the check before the halt was written runs to completion.

While the profile is halted, every tool whose descriptor is not read-only
refuses with `profile.halted` before any keyring access, policy evaluation,
store reload, or network request. The refusal is a business error envelope; its
message names the halt time, the operator's reason, and the resume command.
Besides the signing and submitting tools, the refused set holds the simulate
steps (`stellar_pay`, `stellar_create_account`, `stellar_trustline`,
`stellar_claim`, `stellar_rule_create`), `stellar_mpp_charge_prepare`,
`stellar_mpp_record_receipt`, `stellar_mpp_reconcile_transaction`,
`stellar_transaction_status`, `stellar_friendbot`, and
`stellar_sep24_interactive_url`. `stellar_toolset_invoke` applies the check to
the tool its action routes to, so a signing action refuses and a read-only
action answers.

These tools keep answering: `stellar_balances`, `stellar_fee_stats`,
`stellar_dex_quote`, `stellar_approval_status`, `stellar_signed_intents_list`,
`stellar_rules_list`, `stellar_rules_get`,
`stellar_sep43_get_address`, `stellar_sep43_get_network`,
`stellar_sep47_discover`, `stellar_sep48_preview_invocation`,
`stellar_sep53_verify_message`, `stellar_sep6_deposit_info`,
`stellar_sep7_parse_uri`, `stellar_x402_parse_receipt`,
`stellar_mpp_authorization_status`, and `stellar_toolset_list`. The resources
stay readable, and `mcp-resource://profiles/<name>` reports `halted` and
`halted_at`.

A marker that exists but cannot be read refuses the same tools with
`profile.halt_unreadable`, so the stop fails closed. The resource then reports
`halted: true` with a null `halted_at`. `stellar-agent profile resume <name>`
refuses such a marker too, so the operator repairs the file or removes the
marker path by hand. Once the marker is gone, the next call is served normally.

## Configuring an MCP client

Most MCP clients are configured with a JSON stanza that names a command to spawn
and its arguments. Point the command at the `stellar-agent-mcp` copy of the
executable, or at `stellar-agent` with `"args": ["mcp", "serve"]`. A
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
  Arguments other than `--profile`, `--help` (`-h`), and `--version` (`-V`) are refused.
  On both routes the first line of `--version` and `--help` output is
  `stellar-agent-mcp <version>`, `stellar-agent mcp serve --version` included.
- Default builds enable the `mainnet-write` feature. The second line of `--version` and `-V` output,
  `STELLAR_AGENT_BUILD_MAINNET_WRITE=off` or `=on`, reports the compiled
  feature state.
- The exact location and schema of the configuration file depend on the MCP
  client. Consult that client's documentation for where to place the stanza.

After the client connects it issues an MCP `initialize`, then `tools/list` and
`resources/list`. The tool catalog below is what `tools/list` returns.

### Manual JSON-RPC requests

Send newline-delimited JSON-RPC messages to the server's stdio input. MCP clients
usually initialize the connection automatically. For a manual session, send
`initialize` first, then the `notifications/initialized` notification. Replace
each placeholder with a value from the selected profile or an earlier response.
Use a funded testnet account for payment calls. The selected profile needs
populated signer, nonce-key and audit chain key entries in the keyring, and the
signer must match the payment source. Amounts are strings with a unit:
`"10 XLM"` for native, or the exact, case-sensitive asset code for an issued
asset, such as `"10.5 USDC"` with `USDC:<issuer>`.

Initialize the connection:

```json
{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "manual-client", "version": "1.0.0"}}}
```

After the initialize response, send this notification:

```json
{"jsonrpc": "2.0", "method": "notifications/initialized"}
```

The first request must be `initialize`. A `ping` request before it is answered.
Any other JSON-RPC message first ends the session before it starts: the server
logs that the client must open the session with an initialize request and
exits 1. That includes a JSON-RPC notification with a method the server does
not know. A line before it that is not a JSON-RPC message, or one over the line
limit, gets its `-32700` answer, and the server keeps waiting for
`initialize`. A line before it that is not a JSON-RPC message and holds a
`method` the server does not know and no `id` is skipped without an answer.

List the tools and the resources, and read one resource:

```json
{"jsonrpc": "2.0", "id": 7, "method": "tools/list"}
{"jsonrpc": "2.0", "id": 8, "method": "resources/list"}
{"jsonrpc": "2.0", "id": 9, "method": "resources/read", "params": {"uri": "mcp-resource://usage.md"}}
```

`resources/list` returns `mcp-resource://usage.md`, one
`mcp-resource://profiles/<name>` entry per profile file, and one
`mcp-resource://accounts/<G-strkey>` entry per enrolled signer account.

Then send these five tool requests, one per line and one at a time:

```json
{"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "stellar_balances", "arguments": {"chain_id": "stellar:testnet", "account_id": "<G-strkey-account>"}}}
{"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "stellar_friendbot", "arguments": {"chain_id": "stellar:testnet", "account_id": "<testnet-account-to-fund>"}}}
{"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "stellar_pay", "arguments": {"chain_id": "stellar:testnet", "source": "<funded-source-G-strkey>", "destination": "<destination-M-strkey-with-id>", "amount": "10 XLM", "asset": "native"}}}
{"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "stellar_pay_commit", "arguments": {"chain_id": "stellar:testnet", "source": "<same-source>", "destination": "<same-destination>", "amount": "10 XLM", "asset": "native", "nonce": "<nonce-from-stellar_pay>", "expires_at_unix_ms": 1893456000000, "envelope_xdr": "<envelope_xdr-from-stellar_pay>"}}}
{"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {"name": "stellar_transaction_status", "arguments": {"chain_id": "stellar:testnet", "tx_hash": "<64-lowercase-hex-transaction-hash>"}}}
```

No wallet tool or command builds the M address of the `stellar_pay` line:
encode it outside the wallet as a SEP-23 strkey of the G account and a 64-bit
id, or pay the G account itself.

The commit request needs values from the simulation response, and the status
request needs the transaction hash from the commit response. Use the same
payment arguments in `stellar_pay` and `stellar_pay_commit`. Copy
`nonce`, `expires_at_unix_ms`, and `envelope_xdr` unchanged from the simulation
response; replace the example expiry with its returned integer. The commit call
signs and submits the payment. Its result carries `destination`, the complete
G or M address the sent envelope pays, including the full muxed ID. When policy requires operator approval, the
simulation response carries `approval_nonce` in its `approval` object. The
operator runs `stellar-agent approve --id <approval_nonce> --profile <name>` as
the same local user as the server. The commit request then carries that nonce
and the `approval_attestation` the approval returned.

For payment approvals, `approval.summary` describes the exact retained envelope,
including its destination, asset, amount, fee, and sequence. Its additive
`memo_details` member is a tagged object: `{"kind":"none"}`, or a `kind` of
`text`, `id`, `hash`, or `return` with a `value`. Text preserves UTF-8, IDs use
decimal strings, and hash and return values are arrays of 32 bytes. The
`memo` member is null, text, a numeric ID, or hexadecimal bytes.

Approval creation and expiry retain the policy evaluation interval in Unix
milliseconds. Paired payment decisions and retained mainnet operation deadlines
can shorten that interval. Queueing delay never restarts it: a positive
subsecond remainder remains usable, and an expired interval refuses before
issuing a protocol nonce. Mainnet signing authority also ends at the earlier
of the captured decision end and the operator witness expiry.

On mainnet, `stellar_pay`, `stellar_create_account`, `stellar_trustline` and
`stellar_claim` store the lasting intent under the business id. Their commits
rebuild the envelope from that intent with a fresh sequence and deadline, so
`nonce`, `expires_at_unix_ms` and `envelope_xdr` are optional there and a
commit after a server restart still proceeds. The rebuild pays the fee per
operation of the envelope the preparation returned; a fee above the current
caps refuses as it would on the presented envelope. The commit's other
arguments must name the stored intent, or it refuses with
`operation.business_id_conflict`, also after the operation ran. For a payment
these are the source, the destination as supplied (a G account, or an M
address with its ID), the asset, the amount and the memo. A payment through a
toolset, a commit of an operation recorded with its exact envelope, and every
commit off mainnet require all three fields; an omitted one answers the
tool's fixed argument refusal.

A retried mainnet preparation, and a commit of an operation recorded with its
exact envelope, use the retained envelope, including the original sequence.
Repeated preparation of the same envelope under the same verified policy,
profile, chain, and retained operation returns the original approval nonce and
interval. An attestation already recorded on that approval stays unchanged.
The preparation may issue a new protocol nonce for committing that envelope.
A preparation that finds the approval producer lock held refuses with
`approval.writer_locked`; retry with the same `business_id`.
When the operation's linked approval entry is gone, the preparation refuses
with `approval.not_found` and, except in the case below, the business id
ends; prepare the operation again under a new `business_id`.
A payment whose own rules allow it, and whose lost entry is the outer toolset
approval, still completes by a direct `stellar_pay_commit`. Its toolset
preparation refuses with `approval.not_found`, and its toolset commit too
while the running server holds its nonce; after a restart that commit refuses
with `nonce.expired`. A record a toolset preparation opened needs the stored
envelope, a live nonce and its expiry for the direct commit; a direct
`stellar_pay` preparation under the same `business_id` returns them. Commit
it, or let the record's window or, for such a record, its envelope's deadline
end, before preparing again under a new `business_id`.
Direct preparation needs a signed, verified policy to queue a new payment
approval. Without one, a policy-required toolset approval queues an entry with no
recovery binding.

Expired, rejected, consumed, or collected approvals retain their refusal while
their recovery binding remains stored. A recorded terminal state stays terminal
if the clock moves backward. Mainnet bindings last through the operation's
waiting window; completed operations use their stored replay response.
Off-mainnet bindings last through the original approval interval. Once a
binding's retention ends, the same request receives new consent. A binding that
no longer matches its stored approval refuses only that payment, with
`approval.entry_inconsistent`. Legacy approvals remain usable by nonce and gain
no recovery binding.

## Resources

The server exposes three MCP resources. None contains a secret.

- `mcp-resource://usage.md`: tool usage documentation.
- `mcp-resource://profiles/<name>`: non-secret profile metadata (chain id, the RPC
  endpoint as scheme, host, and port, network passphrase, `mcp_disabled`,
  `halted` and `halted_at` from the [halt marker](#emergency-stop), and the
  cross-check threshold in stroops).
  `stellar_fee_stats` accepts this resource's `rpc_url`, because its scheme,
  host, and port match the profile's endpoint. The call reads that
  authority-only URL. It gets the primary credential only when that URL equals
  the profile's `rpc_url`. Omit `rpc_url` to read the profile's own endpoint.
- `mcp-resource://accounts/<G>`: public account directory for the enrolled
  accounts across all configured profiles.

## How gating applies to every tool call

Every tool call except three MPP tools, `stellar_x402_parse_receipt`, and `stellar_dex_quote` passes through
the same gate before the tool signs or submits. Reads the decision needs, such as the source account,
can run first. `stellar_mpp_record_receipt`,
`stellar_mpp_reconcile_transaction`, and `stellar_mpp_authorization_status`
check the profile and read the MPP store without a policy verdict.
`stellar_x402_parse_receipt` decodes caller-supplied text offline, with no policy verdict and no profile, keyring, or network access.
`stellar_dex_quote` passes no gate and never compares its `chain_id` with the profile. It picks the Soroswap router from `chain_id` and reads through the profile's RPC endpoint. The gate
looks up the tool's registry descriptor and calls
`policy_engine.evaluate(...)`. The verdict is one of:

- `Allow`: the tool proceeds.
- `Deny`: the call is refused with the denial's wire code, `policy.deny.<reason>`
  for a policy refusal or `account.unread`, `account.stale`, or
  `account.floor_refused` for a balance floor.
- `RequireApproval`: an out-of-band operator approval is required.

### Mainnet tool scope

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
- Every tool named above refuses at handler entry with
  `network.mainnet_write_forbidden` in every build, except both x402 payment
  tools and the four classic commits. The `stellar_rule_create_commit` action
  of `stellar_toolset_invoke` refuses at handler entry with the same code.
  Default builds enable the `mainnet-write` feature. These builds admit the four classic commits and both x402
  payment tools after setup. With the feature off, these tools refuse mainnet
  at entry with the same code.
- `stellar_toolset_invoke` admits only exact `stellar_pay` and
  `stellar_pay_commit` actions on enabled mainnet profiles. Its signed outer
  rule meets payment minimums and composes with the routed payment policy.
  Other mainnet actions remain excluded. On testnet the outer gate evaluates
  the payment action's effects before routing.

### Classic mainnet authorization

Default builds enable the `mainnet-write` feature. The MCP server in these builds admits `stellar_pay_commit`,
`stellar_claim_commit`, `stellar_create_account_commit`, and
`stellar_trustline_commit` after setup.
Both prepare and commit policy names need matching rules. Under Allow, a
mainnet commit signs without an approval. Under RequireApproval, it needs a
verified approval. On mainnet a commit evaluates both its own name and its
preparation's name, and the stricter decision governs.
On testnet the commit's own rule alone decides, so a commit rule needs its own
`decision = "require_approval"` to require an approval.
On mainnet a pending approval uses the shorter lifetime from the two evaluations. Allow
contributes 600 seconds; RequireApproval supplies its configured lifetime.
Authorization defaults to 120 seconds and cannot outlive the governing
decision.

Paired gates retain one private window image, one local counterparty-cache
image, and one policy instant. Each stage keeps its own validated argument
projection and reuses the handler's account observations. Concurrent requests
cannot clear or replace that image. A failed authenticated state load refuses
the call. The gate evaluates its captured frame, final resolution reads the
shared store refreshed at each gate, and mint rechecks durable headroom under
the window lock.

Classic final resolution uses the shared hold-sizing adapter with one
evaluation. It sizes holds from that evaluation and keeps the existing lifetime
and authority checks. The mainnet toolset payment commit supplies a toolset
restriction to the network resolver. A restricted payment commit binds the
checked grant, installation, and exact invocation before any endpoint request.
It evaluates the routed rule and the `stellar_toolset_invoke` rule against one
private window image at one instant, and both must permit under the same
authority. Its holds keep each evaluation's repeated criteria; a shared key
takes the larger count and the tighter cap. The authorization expires no later
than the grant, and the grant's lease is held until submission returns.
On mainnet, the toolset dispatcher admits only the exact `stellar_pay` and
`stellar_pay_commit` actions.

On an admitted mainnet server, an x402 payment under Allow returns the payment
in one call. Under RequireApproval it takes two calls. [x402](#x402) describes
both.

Paired preparation refuses an undecodable envelope with `simulation.divergence`.
A denied rule retains `policy.deny.*`; an unknown decision uses
`policy.unexpected_decision`. None of these refusals persists an approval.
On mainnet, each commit evaluates both names before attestation validation. A
proof supplied there under Allow to a classic commit or an x402 payment tool verifies
against its approval's durable record and is spent like a required one. A proof
without a durable record refuses and stays unspent. Off mainnet, Allow neither
verifies nor spends a proof supplied to `stellar_pay_commit`,
`stellar_claim_commit`, `stellar_create_account_commit`,
`stellar_trustline_commit`, `stellar_x402_create_payment`, or
`stellar_x402_authenticated_payment`. `stellar_rule_create_commit` always
requires approval, so it verifies and spends its approval under Allow too.
`stellar_mpp_charge_commit` takes no approval arguments.

Classic mainnet previews carry an on-chain deadline 120 seconds after they are
built; a `stellar_pay` preview carries the earlier of that deadline and the
last whole second before the end of its preparation's decision. A commit of an operation recorded with its exact envelope, and every
toolset commit of `stellar_pay_commit`, copies this deadline into the
rebuild; the deadline is bound into consent and the protocol nonce. A
mainnet direct commit of a stored intent, which `stellar_pay`,
`stellar_create_account`, `stellar_trustline` and `stellar_claim` store,
sets a new deadline at the earlier of 120 seconds after the commit and the
last whole second strictly before the end of its authority: an approval's
execution end, or a policy decision's governing end. The authority holds
strictly before its end, and a ledger that closes at the deadline still
includes the transaction. A successor attempt's deadline also stays before
the execution end the first attempt set, and the signing refuses a deadline
that does not lie before the end. An approved commit signs until just before
the consent's execution end, the consent time plus the shorter of the rule's
lifetime and 900 seconds, which can lie after the approval's
`expires_at_unix_ms`.
A commit whose envelope carries no valid deadline refuses
with `simulation.deadline_invalid`; simulate again for a fresh envelope.
A commit within 30 seconds of the deadline refuses with the same code, so
commit within 90 seconds of the preview.

| Classic commit code | Meaning |
|---|---|
| `simulation.divergence` | The rebuilt envelope differs from the presented bytes, or, for a stored intent, the ledger no longer matches it (a claimable balance that changed). |
| `simulation.deadline_invalid` | The mainnet envelope has no valid on-chain deadline. Simulate again for a fresh envelope. |

Feature-on startup loads the mainnet write context for a verified enabled
profile. Failed enablement or policy checks abort startup. Admission refusals
use `network.mainnet_write_forbidden` for unsupported tools or missing V1 engine,
verified policy, enablement, enabled context, or profiles directory. A stored
or merged `oracle_provider_url` that is absent or names another host than the
signed `[mainnet].oracle_host` fails enablement, so startup aborts with
`profile.mainnet_enablement_invalid` naming `on_disk_oracle_host` or
`merged_oracle_host`. Admission also refuses a context profile without
`oracle_provider_url` with `profile.mainnet_oracle_required`, before signing.
The server builds its clients from the profile it read at startup, so it
applies an oracle change from its next start. Each value tool, the status
tool and the dispatch-gate pass verify the enablement against the stored
profile again first, so a stored `rpc_url` or `oracle_provider_url` changed
to another host refuses them with `network.mainnet_write_forbidden` before
any settlement step. A mainnet server without an enablement record runs no
reconciliation, recovery or release: the gate skips its pass, and the status
tool answers from the stored state and the primary's lookup.

After `profile enable-mainnet` or `profile sign-policy`, restart the MCP server.
Startup refuses a mainnet policy whose `[mainnet]` table lists no approval
credentials, read-only use included, with `policy.mainnet_minimum_unmet` and
`requirement=approval_credentials`. A signed policy without a `[mainnet]`
table needs no approval credentials to start, and serves no mainnet write; see
[Approval credentials](profiles.md#approval-credentials).
Freshness compares current policy and enablement facts without advancing the pin.
A changed binding reports `network.mainnet_write_forbidden` with
`enablement or policy changed, restart the server`. Missing startup authority
instead names the missing prerequisite.

Missing, invalid, expired, or unverifiable approvals use
`policy.approval_required`. On mainnet that includes every approval without a
verified presence receipt: a version 4 approval, an assertion that does not
verify or comes from a credential the signed policy does not list, and a
receipt bound to a policy other than the current one. Mainnet consent
requires a verified passkey assertion from an approval credential in the
owner-signed policy, and the operator approves on the local passkey page or at the signed approval origin. The
approval hint names the same `stellar-agent approve --id <nonce> --profile <name>`
command on every network. A live rejection uses `policy.approval_rejected`. On
testnet a live consumed approval or an approval held by a submission receipt
uses `policy.approval_consumed`, and expired tombstones use
`policy.approval_required`. On mainnet a repeated proof of a completed payment
answers `policy.approval_required`; only a submission receipt or a proof of
another operation answers `policy.approval_consumed`.

On mainnet a commit verifies the presented attestation against the wallet's
durable approval record, never against the approval inbox. An approval
without a record uses `policy.approval_required`, also when the inbox holds a
consent for it. Removing, locking or editing the inbox entry changes no
outcome, except that a live rejection entry answers `policy.approval_rejected`.
A revoked approval returns the wallet error `approval.revoked` with
`isError` set. A verified approval of another operation, such as a commit
under another `business_id`, uses `policy.approval_consumed`. The inbox is
read only to report a live rejection after the proof has failed.
Authorization consumption followed by a pre-send recording failure consumes
the durable approval record and ends the operation unsent. A retry under the
same `business_id` returns that stored outcome; a retry under another
`business_id` refuses with `policy.approval_required`.

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

DeFi, public SEP-43 signing, generic SEP-53 signing, and rule writes are
excluded on mainnet. On mainnet, `stellar_toolset_invoke` admits only its exact
`stellar_pay` and `stellar_pay_commit` actions; every other toolset action
refuses. Wallet entry guards use
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
identity cannot be established is refused with
`network.endpoint_identity_unavailable`, and one that does not answer within
the 30-second pre-send budget with `network.pre_send_timeout`. One that answers
the identity request with HTTP 401 or 403 is refused with
`network.rpc_credential_refused`. The probe is retried with bounded exponential
backoff inside the pre-send budget and never falls back to the declaration; an
answer that does not parse, and a 401 or 403 answer, is not retried. Every
classic prepare then checks, on the same client and before it reads the account
it signs against, that the endpoint reports a healthy status and that its
latest ledger closed within 60 seconds of the host clock; a failed check is
refused with `network.endpoint_not_ready`. The classic prepares and commits run
the probe, the readiness check and the reads before the send under the
pre-send budget, and the profile's `submit_timeout_seconds` bounds only the
send and the confirmation poll.
[Retries, deadlines, and failover](maintainers/security-internals.md#retries-deadlines-and-failover)
gives the numbers. This release supports protocol versions 29 and 30. On testnet and
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
presented envelope the same way, before anything is signed or sent; a
mainnet commit of a stored intent checks the fee of the envelope its
preparation returned. A fee
above the cap returns `fees.percentile_exceeds_cap`. The message names where
the fee came from: an auto-selected fee and its percentile, an explicit
`fee` argument, the profile's `classic_fee_per_op_stroops`, or the envelope.
On mainnet a missing effective cap returns `validation.mainnet_fee_cap_required`.
Resolver fee failures become `network.mainnet_authorization_refused`.

An endpoint refusal precedes a missing account or claim entry, a policy
denial, an approval refusal, a rebuild divergence, the audit pre-flight, and a
malformed nonce. It also precedes the chain, fee, asset, and amount checks that
follow a read. Where such a check ends in an `invalid_params` protocol error,
the endpoint refusal is an error result instead. Checks that need no request
come first: argument and envelope decoding and the structural mainnet refusal.
Toolset payment approval follows the composed policies and precedes nonce
consumption. On mainnet a read-only lookup of the issued nonce supplies its
prepared operation identity before consent is queued.

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
  the simulate tool or its paired commit tool. On mainnet the simulate step
  also opens a durable approval record linked to the operation of its
  `business_id`. The commit step re-checks the
  nonce, byte-compares the envelope against a fresh rebuild, verifies the
  [attestation](./concepts.md), signs from the keyring, and submits. On testnet
  it verifies the HMAC-SHA256 attestation minted at approve time. On mainnet it
  verifies the approval witness against the current signed policy. It re-evaluates its own tool name against current
  state and can still deny an approved request. An exhausted cap returns
  `policy.deny.per_period_cap_exceeded`. The loaded policy document stays fixed
  for the server's lifetime. The wire error on any approval-path failure is the
  uniform `policy.approval_required`, with these exceptions. An explicit operator
  rejection recorded via the approval inbox is reported as
  `policy.approval_rejected`, so the agent stops retrying. An approval already
  spent on a submission is reported as `policy.approval_consumed`; reconcile
  that transaction instead of retrying. A revoked mainnet approval is reported
  as `approval.revoked`. Off mainnet, an entry whose stored payment destination
  is not a canonical G account or M address, or whose payment recovery binding
  is inconsistent, is reported as `approval.entry_inconsistent`. A verified
  mainnet approval whose queued consent row has no exact Delivered evidence is
  reported as `approval.consent_undelivered`.
- One-shot signing verbs sign in a single call. If the policy returns
  `RequireApproval` for one of these tools, the call is refused fail-closed with
  `policy.approval_required_unsupported`; the wallet never signs without a
  verified approval. The SEP-43 transaction tools use the two-call flow of
  [SEP-43 transaction effects](#sep-43-transaction-effects) for a transaction
  an approval surface shows.
- `stellar_rule_create` / `stellar_rule_create_commit` is a two-phase pair with a different approval-block contract. Unlike the
  signing verbs above, there is no envelope fallback for the commit step to
  fall back on, so `stellar_rule_create` persists the pending approval
  unconditionally. The `approval_nonce` in its response is always present.
  A `requires_operator_approval` field reports the propose-time policy
  verdict, but this is informational only: `stellar_rule_create_commit`
  always requires operator attestation, regardless of this
  field's value or of the policy engine's verdict at commit time. On testnet,
  an `Allow` verdict on a classic commit lets the call proceed without an
  attestation. An `Allow` verdict on rule creation would let the agent grant
  itself permanent, potentially account-wide authority, which this feature's
  contract forbids. The agent never holds rule-write authority at any point
  in this flow. `stellar_rule_create` only simulates and resolves the
  definition (no signing, no submission).
  `stellar_rule_create_commit` verifies the operator's attestation over the
  resolved definition through a dedicated gate
  (`PendingApprovalStore::verify_rule_proposal_gate`, distinct from the
  shared pay/claim attestation gate) and unconditionally recomputes the
  digest from the stored snapshot before installing. A mismatch is
  `simulation.divergence` regardless of the policy verdict. The commit spends
  the approval in the platform keyring beside the attestation key before the
  install starts. Restoring the pending store or moving the clock back does not
  re-arm it. When the record cannot be read or written, does not parse, is busy,
  holds 16 live approvals, or is past this approval's expiry, the commit refuses
  with `approval.spent_record_unavailable` and installs nothing. A marker-write
  error leaves the pending entry unconsumed but can leave the marker stored. A
  stored marker keeps the approval spent. A commit that stores the record and
  then cannot update the pending store refuses with `approval.record_failed` and
  installs nothing; the approval stays spent. A retry with the same spent approval
  returns `policy.approval_consumed` whether the install confirmed, failed, or
  lost its confirmation. After a failed install, list the account's rules
  before proposing the rule again. Every approval
  surface renders the full resolved rule: context, every signer, every policy,
  and the override flags. This includes CLI `approve` and both approval inboxes.
  Operator consent binds to the resolved rule that the wallet installs, not to
  a name or a hash. Both tools refuse mainnet with
  `network.mainnet_write_forbidden`, as every other smart-account write
  surface does. `stellar_rule_create` refuses `chain_id=stellar:mainnet` with
  JSON-RPC error -32602, and the message starts with the code.
  `stellar_rule_create_commit` on a mainnet profile returns the code in the
  business error envelope. On another profile it refuses
  `chain_id=stellar:mainnet` with JSON-RPC error -32602.

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
chain-root key is acquirable before the signer is loaded or anything is
submitted. `profile init` mints the audit-log keyring coordinate only, no key
material, so a freshly-initialized profile refuses with
`audit.chain_key_unavailable` until the operator runs
`stellar-agent profile rotate-audit-key <name>`.
`stellar_sep43_sign_transaction`, `stellar_sep43_sign_auth_entry`,
`stellar_sep43_sign_message`, and `stellar_sep53_sign_message` run the same
pre-flight before signing. Read-only tools and the
simulate/build phases of the two-phase verbs above are unaffected. They
never sign or submit, so they never reach this pre-flight; the MCP server's
synthesized first-run fallback profile continues to serve them.
`stellar_mpp_charge_commit` runs the same acquisition after it reads its
approval and before it loads the signing key. Its delivery gate writes
`mpp_charge_authorized` before it releases the credential, and withholds the
credential when that row cannot be written (see
[Agent payments with MPP](agent-payments.md)). Every keyed acquisition also
drains the audit outbox. A queue without owner state commits its count and
chain head in the platform keyring. A missing, changed, or reordered committed
row refuses acquisition with `audit.outbox_rows_missing`, before a signing key
loads. The operator investigates and runs `audit acknowledge-outbox-loss`, which
removes decided, unexpired approvals from the approval inbox and revokes toolset
grants before recording the loss. A queue under owner state authenticates each
row by its tag and commits delivered batches. A dropped tail of queued rows that
carry no reference, such as halt and resume rows, is not detected before
delivery. A mainnet commit whose queued consent row was not delivered refuses
with `approval.consent_undelivered`. A consent row `stellar-agent approve` queued while this
server held the writer enters the log there. A commit that consumes an approval
therefore has its consent row in the log before the signing key loads.

Acquiring the writer also proves the audit log still contains the chain tip its
keyring-held anchor names. This check runs on every acquisition, including
writer open. The MCP server acquires its audit writer when an operation needs
it, such as a commit preflight before signing. MCP balance reads do not acquire
it. Under V1, payment simulations can reconcile overdue reservations, acquire
the writer, and deliver owed accounting events.

The registry normally caches the writer and holds its lock until process exit. A replaced-file refusal during acquisition marks the cached writer for eviction. After callers release it, the next acquisition drops it and checks the file at the path against the anchor. When the server exits, it drains the outbox of every keyed writer it still caches. It exits on client EOF, on SIGINT or SIGTERM on Unix, and on Ctrl-C, Ctrl-Break, or console close on Windows. A queued operator row then reaches the log at shutdown; a refused drain leaves it queued and is logged. The drain waits at most two seconds for each cached writer's mutex. The bound covers the mutex wait only, not the drain's filesystem and keyring work. A writer still held after two seconds is logged with its profile, and its rows stay queued for the next draining writer. A second shutdown signal or console event during the shutdown wait or the drain ends the process at once with exit code 3. Rows the drain did not deliver stay queued, as after a crash. The next draining writer appends them in order with their original timestamps.

A log restored from an older copy, truncated, or substituted refuses with
`audit.tip_anchor_mismatch`. Both in-place overwrites and replacements by
rename are checked. The file at the path is compared by identity against
the handle the server holds; its tip is also checked. Every row the server appends is checked
again, for identity and for the file still ending where the server left it, and
a refused row is anchored so the refusal survives a restart. A log that moved forward past its anchor
before the log's `audit_entry_tags_started` row is not a refusal: the next
acquisition absorbs the gap once, counts it in that row, and re-anchors. Once
entry tags are in force, growth past the anchor is accepted only when every
appended entry carries a valid entry tag; otherwise the server refuses with
`audit.tip_anchor_mismatch`, reason `unauthenticated_tail`, and a writer
without the audit key refuses the log with `audit.chain_key_unavailable`. A log with no anchor at all is
adopted on first use with no operator action when nothing shows it was anchored
before, such as a log written only by unkeyed writers. A log with keyed
history first needs `stellar-agent audit bind-carriers --profile <NAME>` with
every wallet process stopped. A recorded audit
binding, a chain-root sidecar, or an anchoring row or entry tag in the file
shows it was, and the server then refuses with `audit.tip_anchor_missing`. An
adoption writes its `audit_tip_anchored` row only for a non-empty file.
Recovery from a mismatch or a missing anchor is `stellar-agent audit reanchor
--profile <name> --acknowledge-rollback`, with
`--acknowledge-unauthenticated-tail` for an unauthenticated tail, which it keeps
and quarantines. Stop this server first if it holds that profile's
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

The server registers 45 tools. For each tool below: the exact registered name,
its purpose, and whether it is read-only, signs without submitting, or signs and
submits. Every tool except `stellar_x402_parse_receipt`, `stellar_toolset_list`,
`stellar_toolset_invoke`, `stellar_approval_status`, `stellar_signed_intents_list`,
and the five `stellar_mpp_*` tools requires a
`chain_id` argument carrying the CAIP-2 chain id, which must match the profile.
The MPP tools, `stellar_approval_status`, and `stellar_signed_intents_list` reject a `chain_id` field as
unknown and act on the server profile's chain. `stellar_toolset_invoke` accepts an optional `chain_id` and
forwards it to the routed tool. For `stellar_sep43_get_address` and
`stellar_sep43_get_network` the `chain_id` is optional and defaults to the
profile chain when omitted, but is still validated against the profile when
supplied. `stellar_dex_quote` requires a `chain_id` but never matches it
against the profile; it selects the router from it.

The four classic MCP commits obtain a witness after their policy and fee checks
and before the audit pre-flight, nonce consumption, and signer load.
Results include `cross_check`; the pending row carries a passed witness.
Trustline and claim commits are unvalued. Testnet without an oracle reports
`skipped`; a configured but unavailable oracle refuses `network.witness_unavailable`.
Disagreements refuse `simulation.divergence`. Credential failures keep
`network.rpc_credential_refused` or the keyring code of the oracle credential
read (`auth.keyring_*`). A witness refusal leaves the nonce usable.
The nonce expiry is checked against the clock read after the witness, so a nonce
that expires while the oracle answers refuses `nonce.expired`.

### Cross-check status and reason

The `cross_check` result carries a `status` and an optional `reason`. Only a passed
comparison supplies an oracle witness.

| Status | Reason | Meaning |
| --- | --- | --- |
| `skipped` | `oracle_not_configured` | A required comparison can be skipped on testnet when no oracle is configured. No oracle comparison takes place. No oracle witness is supplied. |
| `not_required` | `below_threshold` | The amount is below its effective threshold and no memo observation or unvalued operation independently requires a comparison. No oracle witness is supplied; amount thresholds do not override memo or unvalued requirements. |

### Payments and accounts

For `stellar_pay` and `stellar_pay_commit`:

| Field | Amount units |
| --- | --- |
| `amount` | Use `"10 XLM"` for native or the exact, case-sensitive asset code for issued assets, such as `"10.5 USDC"` with `USDC:<issuer>`. |
| `amount_in_stroops` | Raw base units without a unit label; mutually exclusive with `amount`. |

A C contract or W muxed contract destination refuses with
`validation.contract_payment_unavailable` before any request, approval, or
nonce; with a memo it refuses with `validation.contract_payment_memo_unsupported`. A commit envelope holding one
`transfer(Account, Contract, I128)` invocation is a payment, not an unknown
envelope. Without a valid `asset` argument it refuses with
`validation.contract_payment_invalid`. Otherwise it refuses with
`validation.contract_payment_memo_unsupported` when it carries a memo, with
the unavailable code once proven for `asset` on the server's network, and with
`validation.contract_payment_invalid` when not proven. On mainnet,
`stellar_pay_commit` and the toolset payment actions answer the admission and freshness refusals
(`network.mainnet_write_forbidden`) first; the contract refusal follows them.
The SEP-43 transaction tools keep their own policy decision for such an
envelope.

| Tool | Purpose | Gating |
| --- | --- | --- |
| `stellar_pay` | Simulate a payment: build the Payment envelope, run the SEP-29 memo-required check, mint a single-use nonce. | No signing; no submission. Not annotated read-only (mints the single-use nonce the commit step consumes). |
| `stellar_pay_commit` | Verify the nonce, re-check the envelope, sign from the keyring, submit. A direct mainnet commit of an intent stored under `business_id` rebuilds the envelope from that intent without the nonce. | Signs and submits. Two-phase verb; approval spine. |
| `stellar_create_account` | Simulate account creation: build the CreateAccount envelope, mint a single-use nonce. | No signing; no submission. Not annotated read-only (mints the single-use nonce the commit step consumes). |
| `stellar_create_account_commit` | Verify the nonce, re-check the envelope, sign, submit. A mainnet commit of an intent stored under `business_id` rebuilds the envelope from that intent without the nonce. | Signs and submits. Two-phase verb; approval spine. |
| `stellar_claim` | Simulate claiming a claimable balance by ID: fetch the entry, run the claimant / predicate / trustline guards, render the typed preview, mint a single-use nonce. | No signing; no submission. Not annotated read-only (mints the single-use nonce the commit step consumes). |
| `stellar_claim_commit` | Recheck record, witness, sign, submit. A mainnet commit of an intent stored under `business_id` rebuilds the envelope from that intent without the nonce. | Signs and submits. Two-phase verb; approval spine. |
| `stellar_balances` | Fetch native XLM balance and optional trustline balances for an account. | Read-only. |
| `stellar_friendbot` | Fund a testnet account via Friendbot. | Mutating, testnet-only; gated. |
| `stellar_transaction_status` | Reconcile one submitted transaction against the chain and update the wallet's record of it, by its receipt or, when the receipt is missing, by its reservation. The way out of `submission.tx_timeout`. A reported failure or missing transaction does not release possible spending. Reports `record.release_code` for an accounting disposition such as `submission.accounting_expired`, `record.settlement_evidence: "unavailable"` with an optional `record.settlement_decision_id`, and `reservation` for a hold that remains. On a mainnet profile an authenticated classic attempt reports cached recovery evidence or `UNKNOWN` and sends no additional lookup. For an unmanaged record the primary's `FAILED` and `NOT_FOUND` decide nothing alone; the oracle the enablement binds is asked as well. On mainnet the call reconciles only with the startup enablement record and a fresh check of it, which refuses with `network.mainnet_write_forbidden`; without a record it answers from the stored state and the primary's lookup. | Reads the chain and writes the wallet's record; moves no value and never sends. Not annotated read-only. |

`stellar_claim_commit` witnesses the source account and complete fresh
claimable-balance record. It does not re-read the source trustline at commit.

`stellar_pay` and `stellar_pay_commit` take at most one memo: `memo_text`, `memo_id`, `memo_hash_hex`, or `memo_return_hex`.
`memo_text` is UTF-8 text of at most 28 bytes.
On every network, a `memo_text` holding a control character (U+0000 to U+001F, U+007F to U+009F) or a Unicode format character (category Cf), line separator (U+2028), or paragraph separator (U+2029) is refused as invalid parameters whose message names `validation.memo_control_character` and the character, before any request is sent.
The format characters include the zero-width non-joiner (U+200C) and joiner (U+200D), so a memo cannot carry them.
Other non-ASCII text is accepted.
Besides SEP-29, a version 2 policy's `memo_binding` criterion can require an exact memo kind and value for a destination and its muxed addresses.
`stellar_pay` evaluates the parsed memo argument; `stellar_pay_commit` evaluates the memo encoded in the envelope, which caller fields cannot replace.
A missing or different memo refuses `policy.deny.memo_binding_mismatch`, which names only the required kind.

For an authenticated classic mainnet attempt, transaction status uses cached
recovery evidence or `UNKNOWN` and sends no additional transaction lookup.
An unmanaged record keeps its primary lookup. A managed attempt also returns
`recovery` with typed results, retry class, `earliest_retry_ms` and
`next_action`. The optional `retry_recovery` argument, default `false`,
starts one new bounded evidence run for a stopped attempt, as
`stellar-agent tx status --retry-recovery` does. It never resubmits and
authorizes no successor. Unknown-submission errors carry
the shared [recovery guidance](agents.md), including a checked retry
time or the typed reason that the time is unavailable.

The classic envelopes the wallet builds on testnet carry no time bound, so the
hold of a testnet commit that reserved spending has no accounting horizon.
After a reported `SUCCESS` the call answers `chain_status: SUCCESS` with
`record.reservation_open: true`. The hold stays open until the operator runs
`stellar-agent tx receipt clear <ENVELOPE_HASH> --acknowledge --acknowledge-unbounded`.
A commit whose policy produced no window entries holds nothing and answers
`record.reservation_open: false`.

On mainnet only a checked recovery decision settles a managed attempt. The
decision runs once this host's clock is at least six seconds past the
envelope's maxTime. It needs the oracle the enablement binds and identical
answers from the primary endpoint and the oracle. It also takes the profile's
audit writer. While this server holds that writer, a CLI `tx status` for the
profile answers `chain_status: UNKNOWN`, `record.reservation_open: true` and
`recovery.refusal.code: audit.chain_key_unavailable`. Run it again after the
server stops to settle the attempt.

`stellar_transaction_status` refuses with `submission.record_unavailable` when the spending-window file cannot be read.

`stellar_transaction_status` takes `tx_hash`, `business_id`, or both, beside the required `chain_id`.

| Argument | Type | Required | Meaning |
| --- | --- | --- | --- |
| `chain_id` | string | yes | CAIP-2 chain identifier; must match the profile. |
| `tx_hash` | string | one of `tx_hash` and `business_id` | Transaction hash, 64 lowercase hex characters: the `details.tx_hash` of an unknown-outcome error. |
| `business_id` | string | one of `tx_hash` and `business_id` | Business id of a mainnet operation. With `tx_hash`, both must name the same operation. On testnet it is checked for shape and echoed. |
| `retry_recovery` | bool | no, default `false` | Starts one new bounded evidence run for a stopped mainnet attempt. It never sends a transaction. |

The selectors follow `stellar-agent tx status --business-id`: neither refuses with `validation.usage_error`, an unknown mainnet business id with `operation.unknown`, and two selectors naming different operations with `validation.usage_error`.
A mainnet business id alone targets the latest exposed classic hash; without one it reads no network and reports null hash keys.
Every success payload adds `operation`, the stored projection described for [`tx status`](cli-reference/stellar-ops.md), or `null` for an unrecorded hash and on testnet.
A testnet business id alone returns `business_id`, `operation`, `chain`, `receipt` and `reservation`, the last four null.

A v1 rule set that names tools explicitly must include `stellar_transaction_status` to reconcile timed-out submissions through that server; the server logs `policy.transaction_status_unmatched` at startup when neither that tool nor `*` appears.

#### Business ids

On `stellar:mainnet` every value tool requires `business_id`: `stellar_pay`,
`stellar_create_account`, `stellar_claim`, `stellar_trustline`, their commit
tools, and both x402 payment tools. The id names one value operation and has
1 to 64 printable ASCII characters without a space. A missing id refuses with
`validation.business_id_required` and a malformed one with
`validation.business_id_invalid`, after the argument and endpoint refusals of
the call.

The preparation looks the id up once the endpoint is known to serve the
profile's network and before it builds anything. An unknown id builds the
envelope and opens the operation record. A record that still waits returns
the envelope it stores. A retained operation answers with its stored state
and does no new work: no signature, mint, send or audit row. The same id with
another intent refuses with `operation.business_id_conflict` and leaves the
record unchanged. A new record past the store's bounds refuses with
`operation.capacity`. The commit takes the preparation's id; another id
refuses with `operation.business_id_mismatch` before anything signs or sends.
The commit looks the id up before it verifies the approval, rebuilds the
envelope or consumes the nonce. A commit of an envelope that the id's record
does not bind refuses there with `operation.business_id_conflict`. A retried
commit of a retained operation thus answers with its stored state. A claim names its balance id and claimant. A
retry answers with the stored claim after the balance left the ledger or its
predicate expired, and another balance under the id refuses as a conflict.

A replay is a success result:

```json
{
  "ok": true,
  "data": {
    "status": "replayed",
    "business_id": "invoice-42",
    "operation": {
      "id": "<32 hex characters>",
      "state": "sent_outcome_unknown",
      "tx_hash": "<64 hex characters>",
      "ledger": null,
      "error_code": null
    },
    "next": "wait",
    "destination": "<complete G or M destination>"
  }
}
```

A retained payment carries `destination` when its payment operations pay one
destination. A payment to several destinations carries `destinations` instead,
one `{"operation": n, "destination": "..."}` entry per payment operation. A
compacted retry carries neither, and other operations carry neither.

`next` is `none` once the operation ended and `wait` while it is prepared,
sending or of unknown outcome. It is `approve` while it awaits approval and
`retry` while it is authorized or not included. A sent attempt reads
`sent_outcome_unknown` with its transaction hash until reconciliation settles
it.

Every success result of a call that names an id carries it in
`data.business_id`. On mainnet these are each preparation, commit and payment.
On another chain a supplied id is validated and echoed, and no record exists.
Without an id the result is unchanged.

### Trustline

| Tool | Purpose | Gating |
| --- | --- | --- |
| `stellar_trustline` | Simulate a trustline change: build the ChangeTrust envelope, run the issuer clawback-flag gate, mint a single-use nonce. | No signing; no submission. Not annotated read-only (mints the single-use nonce the commit step consumes). |
| `stellar_trustline_commit` | Recheck issuer, witness, sign, submit. A mainnet commit of an intent stored under `business_id` rebuilds the envelope from that intent without the nonce. | Signs and submits. Two-phase verb; approval spine. |

Both trustline tools take `business_id` as described under
[Business ids](#business-ids).

`stellar_trustline_commit` reads the issuer again and verifies the stored
clawback opt-in for that trustline. An absent issuer refuses `trustline.gate_refused`.
Other issuer read errors keep their own codes and scrubbed messages.
Clawback without a current, verified opt-in refuses
`trustline.clawback_opt_in_required`, including when the issuer enables clawback
after prepare. Nothing is signed and no new approval is minted.
Re-invoke `stellar_trustline` to obtain a new opt-in request.
A verified opt-in permits the commit to continue to its witness.

### Fees

| Tool | Purpose | Gating |
| --- | --- | --- |
| `stellar_fee_stats` | Fetch network fee statistics (classic and Soroban inclusion-fee distributions) for fee estimation. | Read-only. |

Arguments: `chain_id`, and an optional `rpc_url` override.
The tool accepts `rpc_url` only when its scheme, host, and port equal those of an endpoint the active profile configures: `rpc_url`, `secondary_rpc_url`, or `oracle_provider_url`.
The path may differ.
Any other value, or one with embedded credentials, refuses with `invalid_params`, naming the rule and never the URL.
The primary credential goes only to a value equal to the profile's `rpc_url`.
Without `rpc_url`, the tool reads the profile's own endpoint.

### Smart-account rules

| Tool | Purpose | Gating |
| --- | --- | --- |
| `stellar_rules_list` | Enumerate active context rules on a smart account: `rule_id`, `name`, `context_type_label`, `valid_until`, `signer_count`, `policy_count`, `baseline`, plus `as_of_ledger`. `baseline` is the rule's signer-set baseline in the profile's audit log: `none`, `v1`, `v2`, `unreadable` (an audit-log integrity error for that rule), or `unknown` when the tool cannot open the log, which leaves the listing working. An integrity error in the log refuses the listing with `sa.audit_log`. A rule reporting `none` refuses signing until its baseline is recorded. Scans up to the same `max_scan_id` default as the CLI `smart-account rules list`. A rule the shared context-rule decoder refuses fails the listing, and so `stellar_rules_get` for every rule of the account, with `sa.deployment_failed` naming the rule id. | Read-only. |
| `stellar_signed_intents_list` | List the profile's signed smart-account intents from the verified window state, with status, legs and accounting horizon. The policy gate decides the call first. An unreadable window store refuses with `submission.record_unavailable`. | Read-only. |
| `stellar_approval_status` | Inspect retained consent by `approval_id`, the public approval nonce. The chain comes from the active profile; no `chain_id` argument is accepted. See [approval status](cli-reference/profile-and-governance.md#approve-status) for fields and refusals. | Read-only; no consumption, collection, repair, or retry authority. Policy evaluation uses the same verified window image as the view. The policy gate runs before the view. A V1 rule set without a rule for `stellar_approval_status` refuses it with `policy.deny.no_matching_rule`. |
| `stellar_rules_get` | Read one context rule's metadata and its signer-set `baseline` (as `stellar_rules_list` reports it) plus its attached policies (`address`, `identified_kind`: `threshold`, `spending-limit`, or `unknown`), and, when exactly one policy identifies as `spending-limit`, the budget snapshot (`spending_limit`, `period_ledgers`, `in_window_spent`, `remaining_budget`, `as_of_ledger`). `threshold` names the simple-threshold policy. Any other code hash, the weighted-threshold policy's included, reports `unknown`, and so does a missing hash. An RPC error during the classification fails the call with `sa.deployment_failed`, and a failed budget read leaves out the snapshot. An integrity error in the log refuses the call with `sa.audit_log`. | Read-only. |
| `stellar_rule_create` | Testnet-only. Resolve and simulate an agent-proposed `add_context_rule` installation from its signers, policies, context, name, expiry, and `auth_rule_ids`. Mints a domain-separated digest over the resolved arguments and parks the full definition as a pending approval. See [Rule creation checks and refusals](#rule-creation-checks-and-refusals). | No signing; no submission. Mints the pending-approval nonce the commit step consumes. |
| `stellar_rule_create_commit` | Testnet-only. Verify the operator's attestation over the resolved definition through a dedicated gate and recompute its digest from the stored snapshot. Operator attestation is always required, regardless of the policy verdict. See [Rule creation checks and refusals](#rule-creation-checks-and-refusals). | Signs and submits. Two-phase verb; approval spine. |

`spending_limit`, `in_window_spent`, and `remaining_budget` are decimal
strings (i128, stroops), not JSON numbers. A raw JSON number above `2^53`
cannot be represented exactly by an `f64`-backed parser. `in_window_spent`
and `remaining_budget` are exact only as of `as_of_ledger`: forward ledger
movement past that point only grows headroom (older spend entries fall out
of the rolling window), but an intervening spend shrinks it. The numbers are
a point-in-time estimate, not a guarantee for a future submission. A later
write can still fail with `SpendingLimitExceeded`.

`stellar_rules_list` and `stellar_rules_get` are grantable to a toolset via the `read-rules` capability token,
separately from `read-balance`. See [Toolsets](./toolsets.md).

#### Rule creation checks and refusals

A signer is delegated (to a G-strkey account or a C-strkey contract), raw external, or a WebAuthn passkey by credential name, resolved to bytes at propose time; a policy is raw or typed spending-limit.

In both tools, install and simulation refuse an invalid simple-threshold parameter with `sa.simple_threshold_install_refused`. A duplicate policy address or two simple-threshold policies refuse with `sa.deployment_failed` at phase `build`. An `external` entry whose `pubkey_data_hex` decodes to empty key data refuses with `sa.auth_entry_construction_failed`.

In `stellar_rule_create`, a verifier or policy contract with no Wasm code returns `sa.contract_instance_unsupported` with reason `NoWasmCode` (displayed as `no Wasm code`). This covers an absent instance or a built-in executable such as the Stellar Asset Contract, neither of which has a Wasm hash to pin. Neither override flag admits it. The result carries the pins the install records: `pinned_verifier_wasm_hashes` and `pinned_policy_wasm_hashes` list each pinned contract's full code hash. When a pinned contract is an external reference, `pinned_verifier_executable_refs` / `pinned_policy_executable_refs` are aligned with those lists, an entry (`owner_redacted`, `tag`, `ref_key_hex`, `resolved_hash`) at a reference's position and `null` at a position pinned by its Wasm hash. Every hash, `resolved_hash` included, is a 64-character lowercase hex string.

`stellar_rule_create_commit` spends the approval before the install starts, so a retry with the same approval returns `policy.approval_consumed` for every install outcome. An unusable spent record refuses with `approval.spent_record_unavailable` and installs nothing. Every non-zero `auth_rule_ids` entry first passes the pre-submission checks, and a refusal signs nothing. Baseline and comparison refusals are `sa.signer_set_missing_baseline`, `sa.signer_set_diverged`, `sa.audit_log`, and `network.rpc_divergence`. Lock timeout is `sa.auth_entry_construction_failed` at stage `rule_lock`. A deadline that elapses during the baseline read or the comparison uses that code at `baseline_read` or `signer_set_compare`.

Pin refusals are `sa.verifier_hash_drift`, `sa.policy_hash_drift`, `sa.pinned_policy_absent`, `sa.pinned_verifier_absent`, `sa.verifier_wasm_revoked`, `sa.verifier_wasm_retired`, `sa.wasm_pin_incomplete` (a pin record of eight-byte hash prefixes, which no flag bypasses; reinstall the rule through rule 0), and `sa.pin_check_unavailable`. Every pin comparison covers all 32 bytes of the code hash. A version 1 authorizing rule compares through its projection. Its own refusals are `sa.threshold_policy_not_installed`, `sa.threshold_policy_identification_failed`, and `sa.deployment_failed`.

After the install confirms, the observed rule's signer identities and simple threshold must equal the proposal's. That observation is recorded as the rule's signer-set baseline. The name, context, expiry, and other policy attachments are not compared. Otherwise the rule stays on chain without a baseline, and the tool returns `sa.install_state_mismatch` or `sa.baseline_write_failed` with the transaction hash.

#### Why there is no agent-facing execute tool

The CLI has `smart-account execute` (see [Agent delegation](./agent-delegation.md)
and [CLI reference: smart-account](./cli-reference/smart-account.md#smart-account-execute)):
an operator-run verb that submits one `CallContract` invocation signed by an
agent's External-Ed25519 rule key. There is deliberately no MCP equivalent.

Every value-moving MCP tool in this catalog is a typed verb whose rendered
preview is what the operator consents to. The three SEP-43 transaction and
auth-entry signing tools are the exception: they sign caller-supplied material
as `opaque_sign`. A value criterion of the tool's own rule, such as a
per-transaction or per-period cap, refuses them with
`policy.deny.unsizable_value_effect`. A matching rule that sets
`allow_opaque_signing = true` exempts them from that refusal. A matching rule
without criteria returns its own decision. The two transaction tools then
decide each payment in the transaction under its payment tool's rule; see
[SEP-43 transaction effects](#sep-43-transaction-effects). The auth-entry tool
decides each token transfer the signing account authorizes under the
`stellar_pay_commit` rule; see
[SEP-43 auth-entry effects](#sep-43-auth-entry-effects). `stellar_pay_commit` renders a
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
Signing requires a secondary endpoint on the same network and on a host other than the primary's. Without one the tools refuse with `smart_account.ledger_witness_unavailable`. Endpoint disagreement beyond two ledgers refuses with `simulation.divergence.ledger_skew`. The simulated ledger height must lie between the lower observation minus two and the higher observation plus two, inclusive. A height below this range permits one unsigned re-simulation against the same pair. A height above it, or a replacement outside it, refuses with `simulation.divergence.ledger_skew`. Recovery runs within the same pre-submit deadline.
Credentialed input URLs are refused. On a mainnet profile the three tools refuse at entry with `network.mainnet_write_forbidden`, before this input, the lookups, and the gates.

### SEP-43 (wallet interface)

| Tool | Purpose | Gating |
| --- | --- | --- |
| `stellar_sep43_get_address` | Return the active wallet address. | Read-only. |
| `stellar_sep43_get_network` | Return the active network name and passphrase. | Read-only. |
| `stellar_sep43_sign_transaction` | Sign a `TransactionEnvelope` XDR; return `signedTxXdr` and `signerAddress`. | Signs; does not submit. Decides each payment under its payment tool's rule and charges the policy windows when it signs. Requires the audit chain key (refuses `audit.chain_key_unavailable` before signing) and records an `opaque_payload_signed` audit row with the allowed payment legs. An approval requirement returns `approval` first; the attested repeat with `approval_nonce` and `approval_attestation` signs and spends the approval. |
| `stellar_sep43_sign_auth_entry` | Sign the base64 `HashIdPreimage` of a Soroban authorization entry (envelope type 9, or type 10 bound to the signing key's account); return the raw signature as `signedAuthEntry` and `signerAddress`. | Signs; does not submit. Decides each token transfer the signing account authorizes under the `stellar_pay_commit` rule and charges the policy windows when it signs. Requires the audit chain key (refuses `audit.chain_key_unavailable` before signing) and records an `opaque_payload_signed` audit row with the allowed legs. An approval requirement refuses with `policy.approval_required_unsupported`. |
| `stellar_sep43_sign_message` | Sign an arbitrary UTF-8 message via `SHA-256("Stellar Signed Message:\n" + message)` then ed25519; return `signedMessage` (base64) and `signerAddress`. | Signs; does not submit. Refuses an overlaid or out-of-scope signer. Requires the audit chain key (refuses `audit.chain_key_unavailable` before signing) and records an `opaque_payload_signed` audit row. |
| `stellar_sep43_sign_and_submit_transaction` | Sign a `TransactionEnvelope` XDR, submit it, and poll until confirmed; return `signedTxXdr`, `txHash`, and `status`. | Signs and submits; policy gate. Decides each payment under its payment tool's rule and charges the policy windows before it signs; the pending row carries the allowed legs. An approval requirement returns `approval` first; the attested repeat with `approval_nonce` and `approval_attestation` submits, and the send spends the approval. |

These six tools use the standard `{ ok, data, request_id }` / `{ ok, error:
{ code, message }, request_id }` result envelope like every other tool. The
SEP-43 raw protocol payload (`signedTxXdr`, `signerAddress`, `network`, etc.)
is carried inside `data` on success. Protocol failures carry a `sep43.*` wire
code derived from the SEP-43 error taxonomy (e.g.
`sep43.wallet_unlock_failed`, `sep43.invalid_network_passphrase`); the
structural mainnet refusal shares the canonical `network.mainnet_write_forbidden`
code used by wallet entry guards. Library signing uses
`sep43.mainnet_signing_forbidden` or `sep43.mainnet_authorization_refused`.
A policy `RequireApproval` verdict that a tool cannot carry to an approval
refuses fail-closed with `policy.approval_required_unsupported`. The SEP-43
auth-entry and message tools always refuse it; the transaction tools refuse it
for a transaction no approval surface shows.
The transaction and auth-entry tools refuse XDR containing a muxed contract
address (W) with `sep43.invalid_xdr` before key access or storing a request.
SEP-53 and x402 use the same standard envelope for every business error.

#### SEP-43 transaction effects

After the tool's own rule allows, both transaction tools decode what the
signature authorizes. The order is: mainnet refusal, address forms, own rule,
effects decision, audit pre-flight, admission, signer, signature.

- Each payment, path payment, claimable-balance claimant, account creation,
  trustline, claim and wallet-authorized token transfer is decided by the rule
  of its payment tool (`stellar_pay_commit`, `stellar_create_account_commit`,
  `stellar_trustline_commit` or `stellar_claim_commit`). Each decision uses
  the signed asset, amount, recipient and memo, inside the own rule's policy
  state and instant. A denial returns that rule's code; an approval
  escalation follows the two-call flow below.
- A wallet payment to the wallet itself is a payment. A claimable balance
  counts only claimants other than its source and the wallet, so a balance
  without such a claimant has no payment. Another account's payment or merge
  into the wallet has no value effect; a wallet merge refuses.
- An operation of another source account counts only when that account's
  signer set lists the wallet key, at any weight. Each call reads those signer
  sets once, before any classification, and a read failure refuses with its
  own code, such as `network.account_not_found`. The set is the one observed
  at signing time: a later signer change can make a retained signature
  relevant to a source this call excluded. Fees and fee bumps keep their rules.
- An offer, a liquidity pool deposit, reserve sponsorship, a wallet clawback
  or a contract call the wallet cannot value needs `allow_opaque_signing = true`
  on the tool's own rule. A contract call that also transfers tokens needs the
  flag, and each of its transfers is still decided as a payment.
- An account merge and a signer, master weight or threshold change refuse with
  `policy.deny.unsizable_value_effect` under every rule.
- A malformed or legacy envelope, a negative operation amount, a resource fee
  above the total fee, and a text memo that is not UTF-8 on a valued
  transaction refuse with `sep43.invalid_xdr`. A wallet-sourced pool share
  `ChangeTrust` makes a transaction valued, as a credit `ChangeTrust` does, so
  that memo refuses both.
- A fee the wallet account pays passes the classic per-operation cap, rounded
  up. A transaction with a resource fee also passes its full total through the
  contract transfer fee cap. Without a signed cap, testnet bounds the total at
  1,000,000 stroops. A larger total refuses with
  `validation.contract_transfer_fee_exceeded`.
- A transaction with a payment reads the wallet account and each recipient
  account over RPC. Each muxed recipient is read once per call at its base
  account.

Admission records every allowed payment, and for the sign-only tool its own
rule's count, in one durable batch before the signer loads. A refused batch
records nothing. A signer, signing or send failure keeps the admitted usage,
and each new sign-only call charges again, identical bytes included. The
submitting tool's recorder charges only its own count, so value is charged
once.

An approval requirement of the tool's own rule or of a payment rule is met in
two calls. The transaction holds exactly one operation: a payment, a path
payment, an account creation or a trustline change. Every other shape refuses
with `policy.approval_required_unsupported`. An envelope that does not decode
refuses with `sep43.invalid_xdr` before any approval decision and stores no
pending approval.

1. The first call stores a pending approval over the exact `transaction_xdr`
   text and returns `{ "approval": { approval_nonce, profile, chain_id,
   expires_at_unix_ms, reason, instructions } }`. It signs nothing, reads no
   seed and admits no usage.
2. The operator runs `stellar-agent approve --id <approval_nonce> --profile
   <profile>`.
3. The repeat call passes the same `transaction_xdr` with `approval_nonce` and
   `approval_attestation`. It runs admission, signs, and spends the approval.

The shorter lifetime of the two requirements governs the approval. A proof for
other envelope text, or half a proof, refuses with `policy.approval_required`.
A spent approval refuses with `policy.approval_consumed`. The submitting tool's
send spends the approval. The sign-only tool spends it before it returns the
signature; a failed spend returns `submission.record_unavailable` and no
signature. Its `opaque_payload_signed` row records `require_approval`.

#### SEP-43 auth-entry effects

After the tool's own rule allows, `stellar_sep43_sign_auth_entry` decides the
invocation tree of the preimage. The order is: mainnet refusal, address forms,
own rule, preimage checks, effects decision, audit pre-flight, admission,
signer, signature.

- The preimage passes the signing checks for the profile signer's G-key before
  any read: base64 and bounded XDR (`sep43.invalid_xdr`), envelope type 9 or
  10 (`sep43.malformed_auth_entry`), the profile network
  (`sep43.invalid_network_passphrase`), a type 10 binding to that account
  (`sep43.invalid_address`), and a caller `address` that is not that G-key
  (`sep43.invalid_address`). A profile signer that is not a G-strkey refuses
  with `policy.engine_required`, since the debited account is unknown.
- Each `transfer`, `transfer_from`, `approve` and `burn` or `burn_from` call
  the signer's account authorizes, at any depth, is a payment of the contract
  asset decided by the `stellar_pay_commit` rule. Each decision uses the signed
  contract address, the exact `i128` quantity and the recipient, with no memo
  and no fee, inside the own rule's policy state and instant. A zero transfer
  is a payment; a zero allowance has no payment. A memo binding on the
  recipient refuses, since a preimage carries no memo.
- A call the wallet cannot value, a negative quantity or a call another
  account authorizes needs `allow_opaque_signing = true` on the tool's own
  rule, and the token transfers beside it are still decided. A contract
  creation has no payment.
- An approval requirement of the own rule or of the pay rule refuses with
  `policy.approval_required_unsupported`. No pending approval is stored.

Admission records every allowed payment and the tool's own count in one
durable batch before the signer loads. A refused batch records nothing. A
signer or signing failure keeps the admitted usage, and each call charges
again, identical bytes included. The `opaque_payload_signed` row records the
allowed legs with their contract asset and redacted recipients.

Both `stellar_sep43_sign_message` and `stellar_sep53_sign_message` use these
refusals before loading the signer:

| Code | Meaning |
| --- | --- |
| `network.mainnet_write_forbidden` | The selected profile is mainnet. |
| `profile.non_overlayable_field` | Message signing requires `mcp_signer_default` from the profile file. Unset `STELLAR_AGENT_MCP_SIGNER_DEFAULT`. |
| `profile.key_scope_conflict` | The signer entry or its enrolled-identity entry is out of scope, shared with a sibling, or collides with another entry of this profile, or the signer account is the signer account of a mainnet profile in the same data root (`mainnet_signer_identity`). |
| `profile.key_scope_conflict` | A sibling, selected document, or profiles directory cannot be read for the scope check. |
| `audit.chain_key_unavailable` | The audit writer cannot be acquired before signing. The error identifies the recovery. |

After the mainnet refusal, the tool's own rule decides the call; a policy
denial or an approval requirement refuses before the checks below it in the
table.

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

Supply `approval_nonce` with `approval_attestation` when the policy requires approval, on either network.
On testnet, a clock reading before approval creation refuses the approval without consuming it.

When the policy requires approval, the tool queues the payment and returns
`data.approval` with the approval nonce. Nothing is signed.
The owner approves with `stellar-agent approve`. The repeated call with
`approval_nonce` and `approval_attestation` pays.
Queueing reads no key and runs no SEP-10 exchange.

The approval binds the network, asset, payer, payee including its mux id, and amount.
The authenticated tool also binds the home domain.
A call with changed terms or an expired approval answers `policy.approval_required`
and signs nothing. Final verification follows attestation and payer-key reads,
immediately before the signing primitive, with no intervening I/O or await.

An approval releases at most one signed authorization.
A failed or interrupted call can spend it without returning a payment payload.
On testnet a repeated proof with a live spent tombstone answers `policy.approval_consumed`.
An expired or pruned tombstone can answer `policy.approval_required`.
On mainnet a repeated proof of a completed payment answers `policy.approval_required`; only a submission receipt or a proof of another operation answers `policy.approval_consumed`.
The authorization expires within 60 ledgers of the paying call's simulation ledger.
The protocol estimates five seconds per ledger.

On mainnet, Allow without approval arguments pays in one call under policy authority.
A supplied proof must verify, even under Allow.
On testnet, Allow pays without owner approval and ignores supplied approval arguments for valid terms.
Owner approval is required only when the policy requires it.

Before testnet dispatch, a complete approval pair answers `policy.approval_required` for invalid network,
asset, amount, or payee terms, including a W payee on an unsupported protocol.
A later protocol refusal keeps `x402.muxed_contract_protocol_unsupported`.
On testnet, without approval arguments, an address mismatch under RequireApproval
answers `policy.approval_required_unsupported`. Nothing is queued or signed.
On mainnet, an address mismatch refuses with `x402.invalid_payment_required`
before the policy decision.

Rejected consent respects the owner's refusal. Expiry bounds consent lifetime.
Store, clock, and audit failures withhold authority.
A crash after spending keeps the approval spent, even before transmission.
The store, audit log, and RPC share no atomic transaction.
A spent approval does not prove the RPC receives a signature.
The counterparty can stop honoring requirements while the owner waits.
Account-identity criteria lack account-view inputs and fail closed.
On mainnet, `minimum_reserve` and `balance_floor` read the enrolled payer; off mainnet `minimum_reserve` fails closed and a matched `balance_floor` refuses with `account.unread`.
The SEP-43 auth-entry and message tools, SEP-53 signing, and the DeFi tools refuse an approval requirement with `policy.approval_required_unsupported`.


| Tool | Purpose | Gating |
| --- | --- | --- |
| `stellar_x402_create_payment` | Construct and sign an x402 v2 Exact Stellar `PAYMENT-SIGNATURE` from a `PaymentRequirements` object; obtain the cross-check witness before signing; return the payment signature, its fields, and `cross_check`. The wallet does not submit. On an admitted mainnet server, an Allow rule releases the authorized payment payload in one call. Under RequireApproval, call 1 returns approval instructions, and call 2 verifies approval and releases the payload. | Signs the payment authorization entry; does not submit. |
| `stellar_x402_parse_receipt` | Decode an x402 v2 `PAYMENT-RESPONSE` into a structured settlement receipt. Text fields are escaped and cut at 200 characters. | Read-only; no keyring, no network. No `chain_id`. |
| `stellar_x402_authenticated_payment` | Run a SEP-10 identity gate against a `home_domain` (stellar.toml, SSRF bind, ephemeral challenge/response, JWT), then construct the `PAYMENT-SIGNATURE` with the cross-check witness. Any identity failure aborts before payment. On an admitted mainnet server, an Allow rule releases the authorized payment payload in one call. Under RequireApproval, call 1 returns approval instructions, and call 2 verifies approval and releases the payload. The signing call signs and submits the bound SEP-10 challenge before payment construction. | Signs the payment authorization entry; does not submit. |

The `chain_id` argument of both payment tools takes the wallet's spelling,
`stellar:testnet` or `stellar:mainnet`. The x402 requirement `network` spells
mainnet `stellar:pubnet`; that spelling is not a valid `chain_id`.

Both payment tools take `business_id` as described under
[Business ids](#business-ids).

Both payment tools run in this order:

1. The remaining steps describe a testnet profile. A mainnet profile refuses
   with `network.mainnet_write_forbidden` unless the server admits mainnet
   writes. An admitted server pays in one call under Allow and runs the two calls
   described below under RequireApproval.
2. The `payment_required` input is decoded and validated in full. An invalid
   field answers its own `x402.*` code, such as `x402.invalid_recipient_address`
   or `x402.invalid_payment_required` for a `maxTimeoutSeconds` of zero. This
   step consumes no spending window. For W, the primary endpoint identity is
   checked next, before policy, records, approval preparation and SEP-10.
   Protocols below 30 return `x402.muxed_contract_protocol_unsupported` after
   the endpoint's network and supported-range checks. G, C and M send no
   extra identity request at this stage.
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

On an admitted mainnet server, an x402 payment under Allow takes one call
without approval arguments, and that call signs and pays. Under
RequireApproval it takes two calls: call 1 stores the pending approval, and
call 2 presents it and pays. On mainnet, call 2 reuses call 1's `business_id`
for both tools, and a call 2 under another `business_id` refuses with
`policy.approval_consumed`. The call that pays is the signing
call. For the authenticated tool it also runs the SEP-10 exchange. Each
authorization the signing call mints lasts at most 120 seconds. Both tools
take the optional `approval_nonce` and `approval_attestation` arguments.

Each call opens the payment's operation record under its `business_id` once
the requirements and the payer are known, so a retained payment answers with
its stored state. The signing call commits the attempt as `sending` after the intent
mint and before the signature. The exposure commits after the intent
consumption and before the signed re-simulation, the first request that
carries the signed entries. A returned payload ends the attempt as
`payload_released`. A failure before the exposure ends it as `not_sent` with
the failure's code. A failure after it, or a withheld payload, ends it as
`sent_outcome_unknown`.
`approval_nonce` is optional in the schema. Omit it with `approval_attestation`
for the queueing call. Under RequireApproval, supply both for call 2, which
requires the CLI-issued attestation alongside its approval nonce. Supplying
only one approval argument returns `policy.approval_required`.

Call 1 runs these checks. Under Allow it pays, and under RequireApproval it
stores the pending approval:

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
8. Local policy evaluation reads the enrolled payer first when the matching
   rule carries `minimum_reserve` or `balance_floor`. A breach refuses with
   `policy.deny.minimum_reserve_breached` or `account.floor_refused` before
   approval is stored, and a floor without the native coverage marker refuses
   with `account.unread`.
9. An Allow verdict makes this call the signing call. It continues with
   the signing call's step 2 and skips the attestation step.
10. Under RequireApproval, the pending approval is stored and returned.

Under RequireApproval, call 1 reads enrollment and local policy state. It
checks W eligibility with `getNetwork`, sends no simulation or SEP-10 request,
and performs no signing. It returns
`data.approval` without a payment payload. Its fields are `approval_nonce`, `profile`, `chain_id`,
`expires_at_unix_ms`, `reason`, `endpoint_host`, `signer`, `summary`, and
`instructions`. `summary` contains `payTo`, `amount`, and `asset`.

Approve x402 payments through `stellar-agent approve --id <nonce> --profile <name>`
in the local browser or signed-origin HTTPS listener on mainnet, or in a terminal on testnet.
The mainnet local inbox also supports this approval kind when no signed origin is configured.
For an x402 payment, `stellar-agent approve` shows the payee, amount, and asset,
and a `Home domain:` line that reads `none` for the plain tool.
The authenticated approval subject binds the payment intent digest and home
domain. Changing the home domain requires a matching approval.

The signing call runs these steps. Under Allow it is call 1 without approval
arguments. Under RequireApproval it is call 2, which repeats the request with
both approval arguments:

1. The entry checks, the requirements, `chain_id`, the approval pair, and the
   home domain run as in call 1.
2. Startup freshness compares the current policy and enablement with the
   startup binding. A changed binding returns `network.mainnet_write_forbidden`
   with `enablement or policy changed, restart the server`.
3. Enrollment and address and local policy evaluation run as in call 1.
4. With approval arguments, the attestation and its bound subject are
   verified, under Allow as under RequireApproval. A call without them skips
   this step under Allow. A missing, invalid, or mismatched approval returns
   `policy.approval_required`. A live rejection returns
   `policy.approval_rejected`.
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
13. The release authorization is consumed, then any pending approval.
14. The payload is released.

The signing call verifies any approval before the identity exchange. The
authenticated tool completes SEP-10 authentication before the payment endpoint
check, witness, and payer signature.

The plain tool's signing call returns `data` with `paymentSignature`, `payer`,
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
debit after a later failure. An intent can be invalidated before it is
signed. Once signed, it stays charged until it is consumed or leaves the
spending windows. A signer that refuses or fails after the claim leaves the
spend counted, and an identical retry waits for the record's expiry.

After `profile enable-mainnet` or `profile sign-policy`, restart the MCP server.

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
| `stellar_mpp_charge_commit` | `authorization_id`, `nonce`, `expires_at_unix_ms` (prepare's `nonce_expires_at_unix_ms`) | Load only stored exact terms, verify approval/policy, sign once, re-simulate, audit, and return one sensitive credential. |
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
| `stellar_toolset_invoke` | Invoke a named action of an installed toolset, routed to a registered tool through capability enforcement. | Destructive dispatcher. Enabled mainnet setup admits exact `stellar_pay` and `stellar_pay_commit` actions. The outer and routed policies apply. Optional `chain_id`, forwarded to the routed tool. |

The toolsets dispatcher enforces a toolset's declared capabilities, read from its
pin record, which is authenticated by an HMAC under an installation key in the
platform keyring and carries the `TOOLSET.md` digest both resolvers check. Its
ungated routes never reach a signing tool regardless of those declarations; the
signing actions route to the commit tools only behind the first-invoke gate and
the payment policy or rule approval described in [Toolsets](./toolsets.md). A toolset narrows
what this dispatcher routes. It does not narrow the native tools this server
registers, the caller chooses the `toolset` argument, and the server binds no
session to a toolset; the operator policy and the approvals bound native and
routed calls alike. A record that does not verify refuses with
`toolset.pin_unverifiable`. The `toolset` and `action` arguments are compared
exactly as sent, at the halt check and in routing; a decorated or altered name
names no tool. A gated payment call that meets an install or grant change in
progress answers the business code `toolset.coordination_busy`. A gated
rule-creation call in that state answers an internal error whose message is
`toolset.enforcement_error:` followed by the nested `toolset.coordination_busy`
diagnostic. A `stellar_pay_commit` action of `stellar_toolset_invoke` rechecks
its grant before it uses the nonce and holds the grant lease through
submission. That recheck answers its refusals as business codes:
`toolset.grant_invocation_mismatch`, `toolset.coordination_busy`,
`toolset.coordination_unavailable`, `toolset.grant_changed`,
`toolset.grant_expired`, and `toolset.io_error` with `clock_unavailable` for a
clock failure. See
[Grant and installation locks](./toolsets.md#grant-and-installation-locks).

## Output and exit behavior

Tool results are returned as MCP tool-call content; read-only tools return JSON
shaped like their CLI counterparts. The server runs until the MCP client closes
the connection. An unloadable profile or a duplicate tool registration makes
the process exit 1 before serving any request. A missing keyring backend
alone is not fatal: the server starts, and signing tools fail closed at call
time. A profile that selects the V1 engine still fails to start without one,
because building the engine reads the owner key. A registered backend that
refuses the enrolled-owner read stops the start for every engine with exit 1,
for example Credential Manager outside an interactive session with
`auth.keyring_interactive_session_required`.

Exit codes: 0 after the client closes the connection or after a shutdown
signal; 1 for a startup refusal, a failed initialization handshake, or a
server error; 2 for a refused argument or an unusable profile name; 3 when a
second shutdown event arrives during the shutdown wait or the drain.
At startup, an invalid V1 owner signature prompts policy review and re-signing, while a policy body error, such as an unknown key, gets no signing hint.

Business errors return `{ "ok": false, "error": { "code", "message" }, "request_id" }`
with `isError: true`; consumers branch on `error.code`. Every tool, including
the SEP-43 family, uses this same envelope for business errors. Success results
use `{ "ok": true, "data", "request_id" }` with five exceptions.
`stellar_toolset_list` returns a bare JSON array. `stellar_dex_trade`,
`stellar_dex_quote`, `stellar_defindex_vault_deposit`, and
`stellar_defindex_vault_withdraw` return a bare object carrying a `status`
field. Arguments that do not match the tool's input schema (a missing or
unknown field, or a field of the wrong type) return a tool result with
`isError: true` and the text
`<tool>: the arguments have a missing field or a field of the wrong type or value`.
Some refusals use the JSON-RPC error channel instead of the envelope.
Arguments that match the schema but fail a value check, and a `chain_id`
mismatch, return JSON-RPC error -32602. The toolset capability refusals are
JSON-RPC errors too.
`toolset.first_invoke_approval_required` is a JSON-RPC error too, and its error
data carries the `approval_nonce`. See
[The result envelope](agents.md#the-result-envelope).

`stellar_dex_trade`, `stellar_defindex_vault_deposit`, `stellar_defindex_vault_withdraw`, `stellar_x402_create_payment`, and `stellar_x402_authenticated_payment` preserve signer and keyring failures with their original `auth.*` codes and messages.

Three codes carry an additional `details` object on the error:
`submission.tx_timeout`, `submission.tx_already_submitted` and
`submission.hash_mismatch`. Each describes a submission whose outcome the
wallet cannot settle on its own, and resolving it needs the full transaction
hash, which the message redacts. A `submission.tx_timeout` submission may
still apply: the message says to settle it by its transaction hash and not to
resubmit. `details` carries that hash, `outcome: "unknown"`,
`reconcile_with: "stellar_transaction_status"`, a `recovery` object
(`result: "NeedsEvidence"`, `reason: "RecoveryRequired"`,
`next_action: "TargetedStatus"`, and `earliest_retry_ms` or
`retry_time_unavailable`), and the envelope hash naming
the submission record where the reporting tool holds the signed bytes.
DeFi submission errors carry both hashes, and `stellar_transaction_status`
also reports `record.envelope_hash`. No other code carries
`details`, and the field is absent from the serialized envelope when it is not
set. The recovery protocol is in
[the MCP usage reference](../crates/stellar-agent-mcp/docs/usage.md).
