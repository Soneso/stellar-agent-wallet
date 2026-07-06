# CLI reference: profiles, credentials, approvals, and audit

This page documents four `stellar-agent` command groups: `profile`, `credentials`, `approve`, and `audit`. Together they configure a profile, manage its WebAuthn passkeys, and operate the operator-side governance loop: recording out-of-band approvals and verifying the tamper-evident audit log.

For the conventions shared by every command (profile and network resolution, the signer-source flags, the JSON output envelope, exit codes, and the mainnet-write refusal), see the [CLI reference index](index.md). For the underlying concepts (the policy engine, the approval spine, attestations, the audit log, and toolset gating), see [concepts](../concepts.md). For profile file structure, see [profiles](../profiles.md), and for toolset gating see [toolsets](../toolsets.md).

All four groups operate on local state — TOML files and platform-keyring entries. None of them submits a Stellar transaction, so the network flags and the mainnet-write gate do not apply here. Every command prints JSON on stdout and exits `0` on success or `1` on any error. The `profile`, `approve`, and `audit` commands use the standard `{ok, data, request_id}` envelope; the `credentials` commands print a flat status/result object (shown per command below).

## `profile`

The `profile` group lists, shows, and migrates profiles, and rotates the keyring-backed keys a profile names. A profile is a per-environment TOML config (schema version 2) binding a CAIP-2 chain id, an RPC endpoint, keyring entry references, thresholds, and the active policy engine. It holds no secrets; it only names keyring entries.

The subcommands that take a profile name do so as a positional `<NAME>` argument, not as a `--profile` flag, and they have no confirmation flag.

### `profile list`

```bash
stellar-agent profile list
```

Read-only. Reads the OS-conventional profile directory and returns the known profile names, sorted, as a JSON array. Takes no flags.

```json
{"ok":true,"data":["default","mainnet-ops"],"request_id":"..."}
```

### `profile show <NAME>`

```bash
stellar-agent profile show default
```

Read-only. Loads the named profile (applying any environment-variable overlays) and prints its resolved configuration as a JSON envelope. Keyring entry references appear as opaque `{service, account}` objects; the secret material they name is never read or printed.

- `<NAME>` (positional, required) — the profile to display.

Exits `1` with `ProfileNotFound` when the profile does not exist, or with an unsupported-version error when the on-disk schema version is one this build does not support.

### `profile migrate <NAME>`

```bash
stellar-agent profile migrate default
```

State-changing (local file). Reads the named profile, applies any pending schema migrations, and writes the result atomically (temp-file plus rename). If the profile is already at the current version, the command is a no-op and the file is left untouched.

- `<NAME>` (positional, required) — the profile to migrate.

On a no-op it reports `status` `no_op` and the current version; on a migration it reports `status` `migrated` with `from_version`, `to_version`, and the file path:

```json
{"ok":true,"data":{"status":"no_op","version":2},"request_id":"..."}
```

```json
{"ok":true,"data":{"status":"migrated","from_version":1,"to_version":2,"path":"..."},"request_id":"..."}
```

### Key-rotation subcommands

Each rotation subcommand generates a fresh 32-byte secret from the OS CSPRNG, encodes it as URL-safe base64 (no padding), and atomically replaces one keyring entry the profile names. The raw bytes never leave the keyring, are never logged, and are never returned. All four take the profile as a positional `<NAME>` argument, change keyring state (no network), and are not reversible. Rotate deliberately, because each one invalidates material minted under the old key.

| Subcommand | Keyring entry rotated | Key kind | Effect on outstanding material |
|---|---|---|---|
| `rotate-owner-key` | policy-file owner ed25519 key (`policy_owner_key_id`) | ed25519 seed | Policy files signed by the old owner key are rejected on next load; re-sign every policy file with the new key. |
| `rotate-attestation-key` | approval-spine attestation HMAC key (`attestation_key_id`) | 32-byte HMAC | All pending approvals are invalidated; the simulate-and-approve round trip must be re-run. |
| `rotate-audit-key` | audit-log chain-root HMAC key (`audit_log_hash_chain_key_id`) | 32-byte HMAC | New log files use the new key for their chain-root signature; existing files keep the key active when they were opened. |
| `rotate-nonce-key` | HMAC nonce key (`mcp_nonce_key_alias`) | 32-byte HMAC | All outstanding nonces minted with the old key are invalidated. |

`rotate-owner-key` mints an ed25519 signing-key seed that the policy engine reconstructs the signing key from; the other three mint raw HMAC keys.

```bash
stellar-agent profile rotate-owner-key default
stellar-agent profile rotate-attestation-key default
stellar-agent profile rotate-audit-key default
stellar-agent profile rotate-nonce-key default
```

Each returns the profile name and a `rotated` flag. The owner-key (ed25519), attestation-key, and audit-key paths additionally report a `key_kind` (`ed25519_seed` or `hmac_32_bytes`); `rotate-nonce-key` returns only `profile` and `rotated`:

```json
{"ok":true,"data":{"profile":"default","rotated":true,"key_kind":"ed25519_seed"},"request_id":"..."}
```

A fifth rotation subcommand, `profile rotate-counterparty-key <NAME>`, rotates the `stellar.toml` cache-integrity HMAC key (`counterparty_cache_key_id`); it invalidates every cached counterparty binding, which the wallet re-fetches on the next counterparty-allowlist check. Its data object adds `"key_kind": "hmac_32_bytes"` and `"cache_invalidated": true` to the `profile` and `rotated` fields. This rotates the same keyring entry as `stellar-agent counterparty rotate-hmac-key` (see [core operations](stellar-ops.md)); the two verbs are interchangeable.

Each rotation exits `1` with `ProfileNotFound` if the profile does not exist, or with a keyring error if the platform keyring is unavailable.

## `credentials`

The `credentials` group manages the WebAuthn passkey lifecycle for a profile. Passkeys are stored in a per-profile registry that holds only public metadata: credential name, a redacted credential ID, RP-ID, transports, and a registration timestamp. The private key never leaves the authenticator. Registered passkeys can be installed as WebAuthn signers on a context rule (see the `smart-account` commands).

Two flags are common to every subcommand:

- `--profile <NAME>` — the profile whose passkey registry to use. Optional; resolves from `--profile`, then `STELLAR_AGENT_PROFILE`, then `"default"`.
- `--rp-id <DOMAIN>` — the WebAuthn relying-party ID. Default `localhost`, the correct loopback value for a local wallet. For a self-hosted deployment, set the deployment domain (for example `wallet.example.com`). The RP-ID must be a valid DNS domain string; IP literals are rejected by browser WebAuthn implementations. Changing the RP-ID after registration renders existing passkeys unusable.

`credential_id` values are redacted to first-five-last-five base64url everywhere they are printed.

### `credentials add-passkey <NAME>`

State-changing (writes the registry; performs a browser WebAuthn ceremony). Opens the OS default browser to the wallet-owned bridge registration URL and polls the approval store until the browser-side ceremony completes or the deadline elapses. On success it writes the credential metadata to the registry. If the browser cannot be launched, the URL is printed to stderr and polling continues.

- `<NAME>` (positional, required) — a name for the credential. 1 to 64 printable ASCII characters; `/`, `\`, and `:` are not allowed.
- `--profile <NAME>` — profile override (see above).
- `--rp-id <DOMAIN>` — relying-party ID (default `localhost`).
- `--timeout-seconds <SECS>` — registration deadline. Default `300`.
- `--accept-rp-id-binding-risk` — skip the first-registration RP-ID binding warning.

On the first registration for a profile (the registry is empty), the command prints an RP-ID binding warning and prompts `[y/N]` before starting the ceremony, unless `--accept-rp-id-binding-risk` is set. Declining exits `1`.

```bash
stellar-agent credentials add-passkey laptop-key --rp-id wallet.example.com
```

The completion envelope reports a status of `registered`, `timeout`, `user_canceled`, or `entry_missing`. A declined first-registration prompt also emits status `user_canceled` (with a recovery `hint` and `runbook`), and internal failures emit status `error`:

```json
{"status":"registered","credential_id":"AABBC...IJJKK","credential_name":"laptop-key","rp_id":"wallet.example.com","registered_at_unix_ms":0}
```

### `credentials list`

```bash
stellar-agent credentials list
```

Read-only. Lists the registered passkeys for the resolved profile and RP-ID.

- `--profile <NAME>` — profile override.
- `--rp-id <DOMAIN>` — relying-party ID (default `localhost`).

```json
{"credentials":[{"credential_id":"AABBC...IJJKK","credential_name":"laptop-key","rp_id":"localhost","registered_at_unix_ms":0}]}
```

### `credentials show <NAME>`

```bash
stellar-agent credentials show laptop-key
```

Read-only. Prints the metadata for one named passkey, including its transports. No secret material is included.

- `<NAME>` (positional, required) — the credential to show.
- `--profile <NAME>` — profile override.
- `--rp-id <DOMAIN>` — relying-party ID (default `localhost`).

Exits `1` when the credential is not found.

### `credentials delete <NAME>`

```bash
stellar-agent credentials delete laptop-key --yes
```

State-changing (removes the registry entry). Verifies the credential exists, prompts `[y/N]` for confirmation, then deletes it. Deleting a passkey does not remove it as a signer from any on-chain rule.

- `<NAME>` (positional, required) — the credential to delete.
- `--profile <NAME>` — profile override.
- `--rp-id <DOMAIN>` — relying-party ID (default `localhost`).
- `--yes`, `-y` — skip the confirmation prompt.

Declining the prompt exits `1` with a `canceled` status; a missing credential exits `1` with a not-found error.

## `approve`

`approve` is the operator-side half of the approval spine. When a signing-adjacent action requires an out-of-band approval, the agent surface (the MCP server) records a pending approval and returns an approval nonce. The wallet owner runs `approve --id <NONCE>` in a separate, trusted context to inspect a wallet-controlled summary and consent.

The summary is rendered by this command from the stored pending-approval fields, not from anything the agent supplied, so the agent cannot influence what the operator sees. Approval is bound to the local user: the process uid recorded when the approval was created is re-derived at approve time and must match, so a different local user cannot consent on the holder's behalf. On consent, the command records an HMAC attestation (or, for a toolset first-invoke gate, mints and persists a toolset grant and consumes the pending entry). The attestation is an HMAC-SHA256 tag keyed by the profile attestation key over a canonical input including the approval nonce, the envelope SHA-256, and the process uid; the agent surface verifies it before executing. See [concepts](../concepts.md) for the spine and attestation model, and [toolsets](../toolsets.md) for the first-invoke gate versus per-action approval distinction.

### `approve --id <NONCE>`

State-changing (records an attestation or a grant in the on-disk pending-approval store).

- `--id <NONCE>` (required in this form) — the approval nonce printed in the agent surface's simulate response.
- `--profile <NAME>` — the profile whose attestation key and pending-approval store to use. Optional; resolves from `--profile`, then `STELLAR_AGENT_PROFILE`, then `"default"`.
- `--yes` — non-interactive auto-approve. Bypasses the stdin prompt; the wallet-controlled summary is still printed so there is a visible record. Intended for trusted automation and tests, not routine operator use.

Interactively, the command prints the summary and prompts `Approve? [y/N]:`; anything other than `y`/`yes` denies. It exits `1` when the nonce is unknown, expired, already attested, created by a different local user, denied at the prompt, or on an I/O error.

For a payment-style approval the response also returns `approval_attestation`: the HMAC blob the agent surface must present as the `approval_attestation` argument to the matching `*_commit` tool. The operator relays it to the agent over a trusted channel; the attestation binds the specific envelope, so it authorises only that one transaction. The field is omitted for approval kinds whose gate reads the recorded consent from the store directly (toolset first-invoke grants, trustline clawback opt-ins).

```bash
stellar-agent approve --id ABCxyzNonce
```

```json
{"ok":true,"data":{"approval_nonce":"ABCxyzNonce","attested":true,"process_uid":"501","expires_at_unix_ms":1717000000000,"approval_attestation":"q83vEjRWeJq83v..."},"request_id":"..."}
```

### `approve gc`

```bash
stellar-agent approve gc --profile default
```

State-changing (removes expired entries). Opens the pending-approval store and evicts every entry whose TTL has elapsed, then reports the count.

- `--profile <NAME>` — the profile whose store to garbage-collect. Optional; same resolution as above.

When the `gc` subcommand is present, any `--id` is ignored. Evicting zero entries is a success.

```json
{"ok":true,"data":{"profile":"default","evicted_count":3},"request_id":"..."}
```

### `approve list`

```bash
stellar-agent approve list --profile default
```

Read-only. Enumerates the profile's pending approvals with their
wallet-controlled summaries and expiry, so the operator does not depend on the
agent relaying a nonce.

- `--include-expired` — also show entries whose TTL has elapsed (they are
  counted in `expired_count` either way).
- `--output json|table` — envelope JSON (default) or one sanitized row per
  entry with an expires-in countdown.

```json
{"ok":true,"data":{"profile":"default","pending":[{"approval_nonce":"ABCxyzNonce","kind_name":"PaymentSimulated","created_at_unix_ms":1717000000000,"expires_at_unix_ms":1717086400000,"expired":false,"attested":false,"summary":{"kind":"payment","to":"GDEST...","amount_stroops":"100000000","asset":"XLM","memo":null,"fee_stroops":"100","seq_num":12345}}],"expired_count":0},"request_id":"..."}
```

### `approve serve`

```bash
stellar-agent approve serve --profile default
```

Starts a resident, loopback-only approval inbox: a local web page that lists
pending approvals as they arrive, renders each wallet-controlled summary, and
offers Approve and Reject. Approve drives the same attestation path as
`approve --id` and displays the attestation for copying back to the agent;
Reject replaces the entry with a short-lived rejection marker so the agent's
next commit attempt is refused with the distinct `policy.approval_rejected`
code instead of waiting out the TTL. (`approve --id` answering `n` keeps its
leave-to-expire behavior; only the inbox's Reject records an explicit
rejection.)

The printed URL contains a single-use bootstrap token: the first visit
exchanges it for an HttpOnly session cookie and the token dies. All state
mutation requires that cookie plus a per-action CSRF header; the server binds
`127.0.0.1` only and refuses non-loopback hosts and origins.

- `--port <PORT>` — fixed port (default: ephemeral). Use a fixed port when
  tunneling.
- `--no-open` — print the URL instead of opening a browser (default on
  headless hosts).
- `--notify on|off` — best-effort OS notification on new entries (count only,
  never amounts or addresses); `--bell` adds a terminal bell.
- `--include-expired` — grey-list expired entries in the inbox.

Run `serve` as the same OS user as the agent's MCP server: approvals are
bound to the user that parked them, and a different user's consent is
refused (`approval.user_mismatch`).

Remote operation (agent on a remote or headless host): keep the server
loopback-bound and reach it through an SSH local port-forward with the SAME
port on both ends, then open the printed `127.0.0.1` URL in the local
browser:

```bash
ssh -L 8791:127.0.0.1:8791 wallet-user@agent-host   # then start: approve serve --port 8791 --no-open
```

There is no OS-notification push for remote operators; the open inbox page
updates itself and the serve terminal prints a count line when new approvals
arrive.

### `approve serve --remote`

```bash
stellar-agent approve serve --remote --confirm-remote-exposure --profile default
```

Binds a TLS-protected, passkey-authenticated listener beyond loopback instead
of the local inbox above — for approving from a device other than the wallet
host, without an SSH tunnel. Requires the profile's `[remote_approval]` block
with `enabled = true` AND `--confirm-remote-exposure` as a separate, explicit
consent flag; either alone refuses to start. See
[Remote approval](../remote-approval.md) for the full setup, trust model, and
walkthrough.

### `approve operator enroll`

Writes a WebAuthn credential to the profile's dedicated operator-approval
credential store, for use with `approve serve --remote`. Enrollment alone
never authorizes anything — the credential still has to be added to the
profile's `[remote_approval] allowed_credentials` list, a separate,
operator-controlled step. Runs entirely locally in both modes below; neither
touches the network.

A WebAuthn credential is bound to its `rp.id` at creation time, and that
binding is what decides which of the two modes applies:

- **`--interactive`** — for a loopback or SSH-tunnelled `approve serve
  --remote` listener. Starts a one-shot local server, prints (and by default
  opens) an enrollment page, and persists the credential automatically once
  your authenticator completes the ceremony. The printed URL contains a
  single-use bootstrap token: the first visit exchanges it for an HttpOnly
  session cookie and the token dies, and both serving the page and the POST
  that persists the credential require that cookie, so a local non-browser
  process cannot drive the ceremony. The server binds `127.0.0.1` only and
  refuses non-loopback hosts and origins. Always produces a credential bound
  to `rp_id: "localhost"` — the only effective domain a loopback origin can
  claim.
- **`--credential-id` / `--public-key` / `--rp-id` / `--label`** (all four
  together) — for a domain-configured remote listener. Imports the id and
  public key from a WebAuthn ceremony run elsewhere: normally the remote
  listener's own `GET /enroll` page, which has to be served from
  `https://<rp_id>` for the resulting credential to bind to that domain. See
  [Remote approval](../remote-approval.md) for that page's walkthrough.

```bash
# Local or SSH-tunnelled listener
stellar-agent approve operator enroll --interactive --label laptop

# Domain-configured remote listener: import a credential enrolled via its
# own /enroll page
stellar-agent approve operator enroll \
  --credential-id <B64URL> --public-key <B64URL> --rp-id <HOSTNAME> \
  --label laptop --sign-count <N>
```

- `--no-open` — print the enrollment URL instead of opening a browser
  (interactive mode only).
- `--timeout-seconds <SECS>` — interactive-ceremony timeout (default: 300).
- `--sign-count <U32>` — seeds the clone-detection baseline from a counter
  read at enrollment time (argument mode only; interactive mode extracts
  this automatically). Advisory only — a caller reporting a false value only
  weakens that credential's own clone-detection baseline and never affects
  authorization, which is decided solely by `allowed_credentials`.

## `audit`

The `audit` group verifies the per-profile audit log, an append-only, hash-chained JSONL record of every tool invocation and lifecycle event. Argument values are never logged; only argument key names are recorded. The chain links each entry to the SHA-256 of the prior entry's canonical body, so any external modification breaks verification.

### `audit verify <LOG_PATH>`

Read-only. Walks the log at `<LOG_PATH>`, following rotation manifests across rotated files, and verifies that the hash chain is intact end to end. When `--profile` is supplied, it additionally loads that profile's audit chain-root HMAC key and verifies the chain-root sidecars; without `--profile`, only the hash chain is checked and `hmac_verified` is reported as `false`.

- `<LOG_PATH>` (positional, required) — path to the audit log file. By default this is `~/.local/state/stellar-agent/audit/<profile>.jsonl` on Linux, `~/Library/Application Support/stellar-agent/audit/<profile>.jsonl` on macOS, and `%LOCALAPPDATA%\stellar-agent\audit\<profile>.jsonl` on Windows.
- `--profile <NAME>` — the profile whose chain-root HMAC key verifies the sidecars. Optional; when omitted, only the hash chain is verified.
- `--output <FORMAT>` — output format. `json` is the default and only stable format.

On Unix, the command refuses to verify a log whose parent directory is owned by a different user, since such a directory could be used to substitute log files or sidecars. It exits `0` when the chain is intact and `1` on any integrity violation (a broken chain, a rotation gap, an HMAC mismatch, a missing sidecar, or an unparseable line), a path-contract failure, or an I/O error.

```bash
stellar-agent audit verify ~/.local/state/stellar-agent/audit/default.jsonl --profile default
```

```json
{"ok":true,"data":{"entries_verified":42,"files_walked":2,"hmac_verified":true,"per_file":[],"warnings":[],"audit_writer_degraded":false},"request_id":"..."}
```

## The governance loop

`approve` and `audit verify` are the operator's two touch points in the guardrail loop:

1. The agent surface evaluates an action against the policy engine. An action that needs operator consent records a pending approval and returns its nonce instead of executing.
2. The wallet owner runs `approve --id <NONCE>` in a trusted context, reads the wallet-controlled summary, and consents. The command writes an HMAC attestation (or a toolset grant) bound to the approval nonce, the executed envelope's hash, and the local user.
3. The agent surface verifies the attestation and executes. Every invocation and lifecycle event is appended to the hash-chained audit log.
4. The operator periodically runs `audit verify` to confirm the log has not been tampered with, supplying `--profile` to check the chain-root HMAC sidecars as well as the hash chain.

Key rotation backs this loop: `rotate-attestation-key` invalidates outstanding approvals, and `rotate-audit-key` re-keys the chain root for new log files. See [concepts](../concepts.md) for the full model.
