# The wallet's toolsets feature

This file describes a built-in wallet feature called **toolsets** (a
capability-isolation mechanism). Do not confuse it with the knowledge skill you
are reading right now.

| | Knowledge skill (this package) | Wallet toolset (the feature) |
|---|---|---|
| Purpose | Teaches you how to use the wallet | Restricts what an agent may do |
| Form | Documentation you read | A signed, installed package the wallet enforces |
| Effect | Gives you context | Grants a narrow, wallet-enforced capability set |
| Execution | You read and act on it | The wallet never executes its body; it is data |

The feature exists to enforce least privilege. A wallet toolset grants an
agent a narrow, declared capability set; the wallet treats the toolset as data
(a manifest plus a capability declaration), never executes toolset-supplied code,
and never lets a toolset reach a signing, key, or policy tool through its declared
capabilities. This FEATURE restricts what an agent may do. It is NOT a way to
teach an agent.

For the broader MCP tool surface used to invoke actions, see `./mcp-tools.md`
(ships alongside this file).

## What a wallet toolset is

A toolset is a directory named `<package>` containing a `TOOLSET.md` file in the
agentskills format: YAML frontmatter followed by a Markdown instruction body.
The wallet-specific part is a capability manifest carried in a `metadata` key.

```text
---
name: balance-reporter
description: Reports the agent account balance on request.
license: Apache-2.0
allowed-tools: stellar_balances
metadata:
  stellar-agent-capabilities: read-balance
---

# balance-reporter

Body with the toolset's instructions.
```

Frontmatter fields read by the parser:

| Field | Rule |
|---|---|
| `name` | Required. ASCII `[a-z0-9-]`, 1-64 chars; no leading/trailing hyphen; no `--`. Must equal the containing directory name (byte-exact, homoglyph-spoof defence). |
| `description` | Required. Non-empty after trim; <= 1024 Unicode scalar values. |
| `license` | Optional. SPDX identifier or reference to a bundled license file. |
| `compatibility` | Optional. <= 500 Unicode scalar values. |
| `allowed-tools` | Optional. Whitespace-tokenised list of tool names; an intersective narrowing list. |
| `metadata` | Optional string->string map. May carry `stellar-agent-capabilities`. |

The capability manifest is the space-separated value of
`metadata.stellar-agent-capabilities`.

## Capability tokens

| Token | Meaning |
|---|---|
| `read-balance` | Read native XLM + trustline balances. |
| `propose-transaction` | Build an unsigned transaction envelope for review; not sign or submit. |
| `suggest-destination` | Suggest a destination via read-only discovery/preview tools. |
| `observe-event` | Observe a ledger event. No tool is wired to this capability yet, so it grants nothing. |
| `sign-payment` | Sign and submit a classic payment. Signing-adjacent and gated; inert until the first-invoke gate converts it to a runtime grant. |
| `read-rules` | Read the agent's own context rules (spending-limit budgets, expiry, signer/policy counts). Separately grantable from `read-balance`. |

The bare token `sign-transaction` is always refused with a format error. There
is no flat "sign" capability. Signing is never grantable as a plain manifest
token.

## Capability isolation model

The boundary between toolset-declared capabilities and the wallet's signing
infrastructure is structural, not advisory. There are two tiers.

### Ungated matrix

The ungated matrix maps each non-signing capability to a fixed allowlist of
trusted tool names:

| Capability | Tools granted |
|---|---|
| `read-balance` | `stellar_balances` |
| `propose-transaction` | `stellar_pay` (build unsigned only) |
| `suggest-destination` | `stellar_sep47_discover`, `stellar_sep48_preview_invocation`, `stellar_sep7_parse_uri` |
| `observe-event` | (none) |
| `read-rules` | `stellar_rules_list`, `stellar_rules_get` |

The ungated matrix contains no signing, key-derivation, or policy-mutation tool.
A toolset that declares every capability still cannot resolve a signing tool
through the ungated path, because no such tool exists in the matrix to resolve
to. The build-vs-commit split is load-bearing: `propose-transaction` grants
`stellar_pay` (which builds an unsigned envelope), never `stellar_pay_commit`
(which signs and submits).

### Gated tier

A separate table for the one signing-adjacent capability:

| Capability | Tool | Admission |
|---|---|---|
| `sign-payment` | `stellar_pay_commit` | First-invoke gate plus unconditional per-action approval only |

### Signing denylist

A signing denylist names every signing, key, and policy-mutation tool by literal
string, including `stellar_pay_commit`, the SEP-43 and SEP-53 signing tools, the
`*_commit` tools, the x402 tools, and the toolset dispatcher's own tools
`stellar_toolset_list` / `stellar_toolset_invoke` (the last two prevent a toolset from
re-invoking the dispatcher to escalate). The denylist and the ungated matrix are
disjoint by literal name, so the gated tool is unreachable from the ungated
resolver.

### The four-part check

A toolset action passes only this check:

1. The action name resolves, through a closed lookup against the matrix, to a
   `&'static str` registry tool name `T`. The resolved name is a compile-time
   constant; a toolset-supplied string can never become the routed tool name.
2. `T` is in the grant set of some capability `C` (implied by step 1).
3. `C` is in the toolset's declared capability set, read from the pin record.
4. `T` is in the toolset's `allowed_tools`. `allowed_tools` can only subtract from
   a capability grant, never add to it; an empty list applies no narrowing.

The toolset check is additive. After it passes, the routed tool's own dispatch
gate (operator policy, chain, registry checks) still runs. The toolset gate never
replaces those checks.

## Parse safety

`TOOLSET.md` is parsed as fully untrusted input, independent of any signature
check:

- 256 KiB file-size cap before parse; non-UTF-8 is rejected, never a panic.
- YAML anchors and aliases are refused at the event level before any tree is
  built (billion-laughs / alias-bomb defence).
- Nesting depth is bounded at 8 for both block and flow styles via an iterative
  event pull loop.
- Duplicate mapping keys are refused (viewer-vs-parser confusion defence).
- A `metadata` value that is a list or mapping rather than a string is refused.
- Any other `metadata` key beginning with the reserved prefix `stellar-agent-`
  (other than `stellar-agent-capabilities`) is refused.

## Signed install and auditor attestation

Installation verifies origin and integrity before extraction, then validates the
package, then gates key-touching capabilities behind an auditor attestation.

Install pipeline:

1. Validate the package name (`[a-z0-9-]`, <= 64 chars), the version (SemVer,
   <= 64 chars), and the shasum (exactly 64 lowercase hex chars).
2. Load the publisher trust set and check that the publisher key is a member.
3. Recompute the SHA-256 of the package bytes and compare to the supplied
   shasum, constant-time.
4. Verify the publisher's ed25519 signature with `verify_strict` over a
   domain-separated, length-prefixed preimage of
   `(domain tag, package, version, recomputed shasum)`. The shasum in the
   preimage is the locally recomputed digest, not a caller-supplied value, which
   closes the hash-substitution attack.
5. Safe-extract the tar into a staging directory: per-entry type checks, lexical
   containment, no-follow writes, ASCII-only entry names, entry-count and size
   bounds. The extractor never calls `tar::Archive::unpack`.
6. Parse and validate `TOOLSET.md` from the staging directory; roll back on
   failure.
7. Cross-check that the parsed `name` equals the package name.
8. Run the attestation gate for key-touching toolsets.
9. Atomically rename staging into place and write the pin record.

Verification proves origin and integrity, not content safety. The extractor and
parser are safe on adversarial input on their own merits; signature verification
is defence-in-depth layered before them.

### The attestation gate

A toolset that declares a key-touching capability (currently `sign-payment`)
requires a `ToolsetAttestation` signed by an auditor key in a **separate** auditor
trust set (`auditor-trust.txt`), distinct from the publisher trust set
(`trust.txt`). The gate fires after the `name == package` identity cross-check
and before the atomic rename. It checks the attestation's `package`, `version`,
`shasum`, and `capabilities` against the verified package, confirms the auditor
key is trusted, and `verify_strict`-checks the auditor signature over a
domain-separated, length-prefixed preimage binding the capability tokens in
canonical order. The attestation domain tag differs in length and content from
the publisher signature tag, so neither signature can be replayed as the other.

An absent or empty auditor trust set fails closed for a key-touching toolset. The
only sanctioned bypass is `--override-attestation`, which logs a structured
warning and proceeds; no environment variable or config default skips the gate.
Even under override the `sign-payment` capability is persisted inert, and the
runtime first-invoke and per-action approval gates still fire at signing time.

The install records its result as one of `attested`, `overridden`, or
`not-required`, reflecting what the gate actually did rather than what flags were
set: `--override-attestation` on a non-key-touching toolset reports `not-required`.

### The pin record and the capability-source invariant

A successful install writes a pin record holding `package`, `version`, `shasum`,
`publisher`, `installed_at`, the verified `capabilities`, `allowed_tools`, and a
SHA-256 digest of the installed `TOOLSET.md`.

The capability-source invariant: the install gate, the attestation preimage, and
every runtime capability decision read capabilities from the signature-verified
pin record, never from a re-parse of the on-disk `TOOLSET.md`. A toolset installed
with no declared capability whose on-disk `TOOLSET.md` is later edited to add
`sign-payment` is still refused at the signing path, because the runtime reads
the pin, not the file. As additional tamper-evidence, dispatch re-reads the
on-disk `TOOLSET.md`, recomputes its digest, and refuses dispatch on a mismatch
against the pinned digest.

## First-invoke gate and per-action payment approval

`stellar_pay_commit` is reachable only through the gated resolver, never the
ungated path. The gated resolver enforces, in order:

1. The four-part check against the gated matrix: the toolset declares
   `sign-payment`, the action maps to the gated `stellar_pay_commit` constant,
   and the tool is within `allowed_tools`.
2. The first-invoke gate: it looks for a current matching grant in the
   per-profile grant store. Matching is computed from the authoritative
   destination, asset, and amount decoded from the transaction envelope, never
   from toolset-supplied arguments. A non-positive authoritative amount is refused
   before any grant lookup.

If no current matching grant exists (first call, expired grant, or a novel
destination / asset / amount bucket), the gate queues a one-time
`ToolsetFirstInvokeGate` pending approval and refuses, returning an approval
nonce. The operator approves out of band with
`stellar-agent approve --id <nonce>`, which records a time-boxed grant. The
agent then re-invokes.

A matching grant suppresses only the first-invoke re-prompt. The per-action
payment approval fires unconditionally on every toolset-routed payment: a
policy-engine `Allow` is overridden to `RequireApproval`, and the approval binds
the actual executed envelope. A forged or tampered grant can at most suppress
the re-prompt; it cannot bypass the forced per-action approval, whose
attestation key lives only in the keyring.

## How an agent invokes a toolset action

The agent never executes a toolset body. It enumerates installed toolsets, then
invokes a named action through the dispatcher, which runs the four-part check and
routes to the trusted registry tool.

1. Call `stellar_toolset_list` to discover installed toolsets and their reachable
   actions.
2. Call `stellar_toolset_invoke` with the toolset name, action, optional `chain_id`,
   and tool-specific `args`.

### `stellar_toolset_list`

Takes no arguments. Returns a JSON array of installed-toolset entries. Each entry
reports `name`, `description` (always empty; the pin record stores no
description), `capabilities`, `allowed_tools`, `version`, and `actions` (the tool
names reachable through the ungated matrix; gated tools such as
`stellar_pay_commit` are not listed here because they are reachable only through
the gated path). Read-only and non-destructive.

```json
{}
```

### `stellar_toolset_invoke`

| Field | Meaning |
|---|---|
| `toolset` | Installed package name, e.g. `balance-reporter`. |
| `action` | Exact registry tool name the toolset's capabilities grant, e.g. `stellar_balances`, `stellar_pay`. |
| `chain_id` | Optional CAIP-2 chain id forwarded to the routed tool; ignored by tools that do not require it. |
| `args` | JSON object of tool-specific arguments forwarded to the routed tool. |

```json
{
  "toolset": "balance-reporter",
  "action": "stellar_balances",
  "chain_id": "stellar:testnet",
  "args": { "account_id": "GABC...WXYZ" }
}
```

No signing, key, or policy tool is reachable through any capability, so an
`action` naming a signing tool returns `toolset.unknown_action` (the tool is not in
the matrix to resolve). For a `sign-payment` toolset, `action:
"stellar_pay_commit"` is routed through the gated resolver instead: `args` must
carry the `envelope_xdr` produced by a prior `stellar_pay` simulate call, from
which the destination, asset, and amount are decoded authoritatively. If the
first-invoke gate fires, the call returns `toolset.first_invoke_approval_required`
with the approval nonce; once a grant exists, the per-action payment approval is
still forced on for the commit.

All wallet tool results use the envelope `{ok, data|error, request_id}`. Amounts
are decimal strings with a unit such as `"10 XLM"`, never JSON numbers. Asset is
`"native"`/`"XLM"` or `"CODE:GISSUER"`.

## CLI commands

The subcommand group is `stellar-agent toolsets` (plural). All four subcommands are
local and offline (no network calls, no chain signing) and print a JSON
envelope. Each prints its success envelope on stdout. `install` and `uninstall`
write the error envelope to stderr; `list` and `run` write the error envelope to
stdout. Exit code is `0` on success, `1` on any error. The toolsets root defaults
to the OS-conventional toolsets directory; `--toolsets-dir <PATH>` overrides it on
every subcommand.

### `toolsets install <PKG@VERSION>`

Installs a toolset from a local signed `.tar.gz` and runs the verification and
attestation pipeline.

Positional: `<PKG@VERSION>` — `<name>@<version>`, e.g. `balance-reporter@1.0.0`.

| Flag | Meaning | Req/Opt | Default |
|---|---|---|---|
| `--file <PATH>` | Path to the `.tar.gz` package. | Required | — |
| `--shasum <HEX>` | Expected SHA-256 of the package (64 lowercase hex chars). | Required | — |
| `--signature <HEX>` | Publisher ed25519 signature (128 hex chars / 64 bytes). | Required | — |
| `--publisher <G-STRKEY>` | Publisher ed25519 public key as a Stellar G-strkey. | Required | — |
| `--trust-set <PATH>` | Publisher trust-set file. | Optional | `<toolsets_dir>/trust.txt` |
| `--toolsets-dir <PATH>` | Toolsets root override. | Optional | OS-conventional toolsets dir |
| `--force` | Reinstall even if already installed. | Optional | `false` |
| `--allow-downgrade` | Allow installing an older version (only effective with `--force`). | Optional | `false` |
| `--attestation-file <PATH>` | JSON `ToolsetAttestation` file; required for key-touching toolsets unless overridden. | Optional | none |
| `--auditor-trust-set <PATH>` | Auditor trust-set file (distinct from the publisher trust set). | Optional | `<toolsets_dir>/auditor-trust.txt` |
| `--override-attestation` | Bypass the attestation gate for key-touching toolsets; the only sanctioned bypass. | Optional | `false` |

```bash
stellar-agent toolsets install balance-reporter@1.0.0 \
  --file ./balance-reporter-1.0.0.tar.gz \
  --shasum 3b1f...e9 \
  --signature a4c5...7b \
  --publisher GABC...WXYZ
```

The success envelope reports `status`, `package`, `version`, and `attestation`
(`attested` / `overridden` / `not-required`).

### `toolsets list`

Enumerates installed toolsets and their declared actions as JSON. This is the
canonical scriptable enumeration; it is read from pin records, not parsed from
help text. Each entry reports `name`, `description` (always empty; the pin record
stores no description), `capabilities`, `allowed_tools`, `version`, and `actions`
(the tool names reachable through the ungated matrix; gated tools such as
`stellar_pay_commit` are not listed here).

| Flag | Meaning | Req/Opt | Default |
|---|---|---|---|
| `--toolsets-dir <PATH>` | Toolsets root override. | Optional | OS-conventional toolsets dir |

```bash
stellar-agent toolsets list
```

### `toolsets run <TOOLSET-NAME> <ACTION>`

Runs the four-part capability enforcement check for a toolset action and resolves
the trusted registry tool it routes to. It does **not** execute the routed tool;
on success it reports `status: "resolved"` with the `routed_to` tool name and a
note that execution is not wired in the CLI. Use the MCP surface for execution.

Positionals: `<TOOLSET-NAME>` — the installed package name (e.g.
`balance-reporter`); `<ACTION>` — the exact registry tool name granted by the
toolset's capabilities (e.g. `stellar_balances`).

| Flag | Meaning | Req/Opt | Default |
|---|---|---|---|
| `--toolsets-dir <PATH>` | Toolsets root override. | Optional | OS-conventional toolsets dir |

```bash
stellar-agent toolsets run balance-reporter stellar_balances
```

On enforcement failure the error envelope carries a `code` such as
`toolset.not_installed`, `toolset.unknown_action`, `toolset.capability_not_declared`,
or `toolset.tool_not_allowed`.

### `toolsets uninstall <PACKAGE>`

Removes an installed toolset's directory and pin record. Refuses if the toolset is
not installed. Uninstall reads the pin, re-validates the stored package name,
reconstructs the directory path from that validated name (never from a stored
path), refuses a symlinked leaf, and removes the directory and pin.

Positional: `<PACKAGE>` — the package name (`[a-z0-9-]`).

| Flag | Meaning | Req/Opt | Default |
|---|---|---|---|
| `--toolsets-dir <PATH>` | Toolsets root override. | Optional | OS-conventional toolsets dir |

```bash
stellar-agent toolsets uninstall balance-reporter
```

## Error codes

| Code | Cause |
|---|---|
| `toolset.not_installed` | Named toolset has no pin record. |
| `toolset.unknown_action` | Action does not resolve through the matrix (includes any signing tool named directly). |
| `toolset.capability_not_declared` | Resolved tool's capability is not in the toolset's declared set. |
| `toolset.tool_not_allowed` | Resolved tool is excluded by the toolset's `allowed_tools` narrowing. |
| `toolset.first_invoke_approval_required` | Gated payment has no current matching grant; returns an approval nonce for `stellar-agent approve --id <nonce>`. |
