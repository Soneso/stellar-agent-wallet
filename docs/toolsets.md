# Agent toolsets

An agent toolset is a signed, installable package that grants an AI agent a narrow,
declared set of wallet capabilities. The wallet treats a toolset as data: a
`TOOLSET.md` manifest plus a capability declaration. It never executes toolset-supplied
code and never lets a toolset reach a signing, key, or policy tool through its
declared capabilities.

> This capability-isolation feature is the opposite of the
> [agent knowledge skill](../skills/) (`skills/stellar-agent-wallet/`), which
> *teaches* an agent how to operate the wallet and is loaded by an agentskills.io
> runtime. The feature on this page *restricts* what an agent may do; the
> knowledge skill *teaches* it. The knowledge skill uses its own `SKILL.md` file;
> a toolset uses a `TOOLSET.md` manifest in the same frontmatter-plus-body format.

This page is for a developer packaging or running signed toolsets. Two runnable
examples are in [`examples/toolsets/`](../examples/toolsets/). For the policy
engine, approval spine, and audit log that sit underneath toolset dispatch, see
[concepts.md](concepts.md). For the operator-side `approve` flow, see
[cli-reference/profile-and-governance.md](cli-reference/profile-and-governance.md).
For the MCP server surface, see [mcp.md](mcp.md).

## What a toolset is

A toolset is a directory named `<package>` containing a `TOOLSET.md` file in the
agentskills format: YAML frontmatter followed by a Markdown body of instructions.
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
| `name` | Required. ASCII `[a-z0-9-]`, 1–64 chars; no leading/trailing hyphen; no `--`. Must equal the containing directory name (byte-exact, homoglyph-spoof defence). |
| `description` | Required. Non-empty after trim; ≤ 1024 Unicode scalar values. |
| `license` | Optional. SPDX identifier or reference to a bundled license file. |
| `compatibility` | Optional. ≤ 500 Unicode scalar values. |
| `allowed-tools` | Optional. Whitespace-tokenised list of tool names; an intersective narrowing list (see below). |
| `metadata` | Optional string→string map. May carry `stellar-agent-capabilities`. |

The capability manifest is the space-separated value of
`metadata.stellar-agent-capabilities`. Recognised capability tokens:

| Token | Meaning |
|---|---|
| `read-balance` | Read native XLM + trustline balances. |
| `propose-transaction` | Build an unsigned transaction envelope for review; not sign or submit. |
| `suggest-destination` | Suggest a destination via read-only discovery/preview tools. |
| `observe-event` | Observe a ledger event. No tool is wired to this capability yet, so it grants nothing. |
| `sign-payment` | Sign and submit a classic payment. Signing-adjacent and gated; inert until the first-invoke gate converts it to a runtime grant. |
| `read-rules` | Read the agent's own context rules (spending-limit budgets, expiry, signer/policy counts). Separately grantable from `read-balance` — rule visibility and balance visibility are distinct concerns. |
| `sign-rule-create` | Install an agent-proposed context rule on-chain. Signing-adjacent and gated; inert until the first-invoke gate converts it to a runtime grant. The per-proposal operator attestation (`RuleProposalSimulated`) fires unconditionally regardless of the grant. |

The bare token `sign-transaction` is always refused with a format error. There is
no flat "sign" capability — signing is never grantable as a plain manifest token.

### Parse safety

`TOOLSET.md` is parsed as fully untrusted input, independent of any signature check:

- 256 KiB file-size cap before parse; non-UTF-8 is rejected, never a panic.
- YAML anchors and aliases are refused at the event level before any tree is built
  (billion-laughs / alias-bomb defence).
- Nesting depth is bounded at 8 for both block and flow styles via an iterative
  event pull loop; deeply nested compact block or flow documents are refused with
  bounded stack use.
- Duplicate mapping keys are refused (viewer-vs-parser confusion defence).
- A `metadata` value that is a list or mapping rather than a string is refused.
- Any other `metadata` key beginning with the reserved prefix `stellar-agent-`
  (other than `stellar-agent-capabilities`) is refused.

## Capability isolation model

The boundary between toolset-declared capabilities and the wallet's signing
infrastructure is structural, not advisory.

There are two tiers.

The **ungated matrix** maps each non-signing capability to a fixed allowlist of
trusted tool names:

| Capability | Tools granted |
|---|---|
| `read-balance` | `stellar_balances` |
| `propose-transaction` | `stellar_pay`, `stellar_claim` (build unsigned only) |
| `suggest-destination` | `stellar_sep47_discover`, `stellar_sep48_preview_invocation`, `stellar_sep7_parse_uri` |
| `observe-event` | (none) |
| `read-rules` | `stellar_rules_list`, `stellar_rules_get` |

The ungated matrix contains no signing, key-derivation, or policy-mutation tool.
A toolset that declares every capability still cannot resolve a signing tool through
the ungated path, because no such tool exists in the matrix to resolve to. The
build-vs-commit split is load-bearing here: `propose-transaction` grants
`stellar_pay`, `stellar_claim`, and `stellar_rule_create` (which build an unsigned
envelope or a simulated rule proposal only), never `stellar_pay_commit`,
`stellar_claim_commit`, or `stellar_rule_create_commit` (which sign and submit).

The **gated tier** is a separate table for the signing-adjacent capabilities:

| Capability | Tool | Admission |
|---|---|---|
| `sign-payment` | `stellar_pay_commit` | First-invoke gate plus unconditional per-action approval only |
| `sign-rule-create` | `stellar_rule_create_commit` | First-invoke gate plus unconditional per-proposal `RuleProposalSimulated` attestation only |

`sign-rule-create`'s first-invoke gate reuses the same payment-shaped
`ToolsetFirstInvokeGate` grant mechanism, with the smart-account C-strkey as
the bucket-matching dimension (a different smart account re-triggers
first-invoke consent, exactly as a different payment destination does) and a
fixed sentinel in place of the asset/amount fields, which carry no
independent meaning for rule creation.

A **signing denylist** names every signing, key, and policy-mutation tool by
literal string, including `stellar_pay_commit`, `stellar_rule_create_commit`,
the SEP-43 and SEP-53 signing tools, the `*_commit` tools, the x402 tools, and
the toolset dispatcher's own tools `stellar_toolset_list` /
`stellar_toolset_invoke` (the last two prevent a toolset from
re-invoking the dispatcher to escalate). The denylist and the ungated matrix are
disjoint by literal name, so the gated tool is unreachable from the ungated
resolver.

A toolset action passes only the **four-part check**:

1. The action name resolves, through a closed lookup against the matrix, to a
   `&'static str` registry tool name `T`. The resolved name is a compile-time
   constant — a toolset-supplied string can never become the routed tool name.
2. `T` is in the grant set of some capability `C` (implied by step 1).
3. `C` is in the toolset's declared capability set, read from the pin record.
4. `T` is in the toolset's `allowed_tools`. `allowed_tools` can only subtract from a
   capability grant, never add to it; an empty list applies no narrowing.

The toolset check is additive. After it passes, the routed tool's own dispatch gate
(operator policy, chain, registry checks) still runs. The toolset gate never replaces
those checks.

## Signed install and verification

Installation verifies origin and integrity before extraction, then validates the
package, then gates key-touching capabilities behind an auditor attestation.

The install pipeline:

1. Validate the package name (`[a-z0-9-]`, ≤ 64 chars), the version (SemVer,
   ≤ 64 chars), and the shasum (exactly 64 lowercase hex chars).
2. Load the publisher trust set and check that the publisher key is a member.
3. Recompute the SHA-256 of the package bytes and compare to the supplied shasum,
   constant-time.
4. Verify the publisher's ed25519 signature with `verify_strict` over a
   domain-separated, length-prefixed preimage of
   `(domain tag, package, version, recomputed shasum)`. The shasum in the preimage
   is the locally recomputed digest, not a caller-supplied value, which closes the
   hash-substitution attack.
5. Safe-extract the tar into a staging directory: per-entry type checks, lexical
   containment, no-follow writes, ASCII-only entry names, entry-count and size
   bounds. The extractor never calls `tar::Archive::unpack`.
6. Parse and validate `TOOLSET.md` from the staging directory; roll back on failure.
7. Cross-check that the parsed `name` equals the package name.
8. Run the attestation gate (below) for key-touching toolsets.
9. Atomically rename staging into place and write the pin record.

Verification proves origin and integrity, not content safety. A trusted but
compromised publisher, or an operator-added key, can still ship hostile bytes;
the extractor and parser are therefore safe on adversarial input on their own
merits, and signature verification is defence-in-depth layered before them.

### The attestation gate

A toolset that declares a key-touching capability (currently `sign-payment`) requires
a `ToolsetAttestation` signed by an auditor key in a **separate** auditor trust set
(`auditor-trust.txt`), distinct from the publisher trust set (`trust.txt`). The
gate fires after the `name == package` identity cross-check and before the atomic
rename. It checks the attestation's `package`, `version`, `shasum`, and
`capabilities` against the verified package, confirms the auditor key is trusted,
and `verify_strict`-checks the auditor signature over a domain-separated,
length-prefixed preimage binding the capability tokens in canonical order. The
attestation domain tag differs in length and content from the publisher signature
tag, so neither signature can be replayed as the other.

An absent or empty auditor trust set fails closed for a key-touching toolset. The
only sanctioned bypass is `--override-attestation`, which logs a structured warning
and proceeds; no environment variable or config default skips the gate. Even under
override the `sign-payment` capability is persisted inert, and the runtime
first-invoke and per-action approval gates still fire at signing time.

The install records its result as one of `attested`, `overridden`, or
`not-required`, reflecting what the gate actually did rather than what flags were
set: `--override-attestation` on a non-key-touching toolset reports `not-required`.

### The pin record and the capability-source invariant

A successful install writes a pin record holding `package`, `version`, `shasum`,
`publisher`, `installed_at`, the verified `capabilities`, `allowed_tools`, and a
SHA-256 digest of the installed `TOOLSET.md`.

The capability-source invariant: the install gate, the attestation preimage, and
every runtime capability decision read capabilities from the signature-verified
pin record, never from a re-parse of the on-disk `TOOLSET.md`. A toolset installed with
no declared capability whose on-disk `TOOLSET.md` is later edited to add
`sign-payment` is still refused at the signing path, because the runtime reads the
pin, not the file. As additional tamper-evidence, dispatch re-reads the on-disk
`TOOLSET.md`, recomputes its digest, and refuses dispatch on a mismatch against the
pinned digest.

Uninstall reads the pin, re-validates the stored package name, reconstructs the
directory path from that validated name (never from a stored path), refuses a
symlinked leaf, and removes the directory and pin.

## First-invoke gate and per-action payment approval

`stellar_pay_commit` is reachable only through the gated resolver, never the
ungated path. The gated resolver enforces, in order:

1. The four-part check against the gated matrix: the toolset declares `sign-payment`,
   the action maps to the gated `stellar_pay_commit` constant, and the tool is
   within `allowed_tools`.
2. The first-invoke gate: it looks for a current matching grant in the per-profile
   grant store. Matching is computed from the authoritative destination, asset, and
   amount decoded from the transaction envelope — never from toolset-supplied
   arguments. A non-positive authoritative amount is refused before any grant
   lookup.

If no current matching grant exists (first call, expired grant, or a novel
destination / asset / amount bucket), the gate queues a one-time
`ToolsetFirstInvokeGate` pending approval and refuses, returning an approval nonce.
The operator approves out of band with `stellar-agent approve --id <nonce>` (see
[cli-reference/profile-and-governance.md](cli-reference/profile-and-governance.md)),
which records a time-boxed grant. The agent then re-invokes.

A matching grant suppresses only the first-invoke re-prompt. The per-action payment
approval fires unconditionally on every toolset-routed payment: a policy-engine
`Allow` is overridden to `RequireApproval`, and the approval binds the actual
executed envelope. A forged or tampered grant can at most suppress the
re-prompt; it cannot bypass the forced per-action approval, whose attestation key
lives only in the keyring.

## CLI commands

The subcommand group is `stellar-agent toolsets` (plural). All four subcommands are
local and offline — no network calls, no chain signing — and print a JSON envelope.
Each prints its success envelope on stdout. `install` and `uninstall` write the
error envelope to stderr; `list` and `run` write the error envelope to stdout.
Exit code is `0` on success, `1` on any error. The toolsets root defaults to the
OS-conventional toolsets directory; `--toolsets-dir <PATH>` overrides it on every
subcommand.

### `toolsets install <PKG@VERSION>`

Installs a toolset from a local signed `.tar.gz` and runs the verification and
attestation pipeline above.

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
canonical scriptable enumeration — it is read from pin records, not parsed from
help text. Each entry reports `name`, `description` (always empty; the pin record stores no
description), `capabilities`, `allowed_tools`, `version`, and `actions` (the tool names reachable
through the ungated matrix; gated tools such as `stellar_pay_commit` are not listed
here because they are reachable only through the gated path).

| Flag | Meaning | Req/Opt | Default |
|---|---|---|---|
| `--toolsets-dir <PATH>` | Toolsets root override. | Optional | OS-conventional toolsets dir |

```bash
stellar-agent toolsets list
```

### `toolsets run <TOOLSET-NAME> <ACTION>`

Runs the four-part capability enforcement check for a toolset action and resolves the
trusted registry tool it routes to. It does **not** execute the routed tool; on
success it reports `status: "resolved"` with the `routed_to` tool name and a note
that execution is not wired in the CLI. Use the MCP surface for execution.

Positionals: `<TOOLSET-NAME>` — the installed package name (e.g. `balance-reporter`);
`<ACTION>` — the exact registry tool name granted by the toolset's capabilities
(e.g. `stellar_balances`).

| Flag | Meaning | Req/Opt | Default |
|---|---|---|---|
| `--toolsets-dir <PATH>` | Toolsets root override. | Optional | OS-conventional toolsets dir |

```bash
stellar-agent toolsets run balance-reporter stellar_balances
```

On enforcement failure the error envelope carries a `code` such as
`toolset.not_installed`, `toolset.unknown_action`, `toolset.capability_not_declared`, or
`toolset.tool_not_allowed`.

### `toolsets uninstall <PACKAGE>`

Removes an installed toolset's directory and pin record. Refuses if the toolset is not
installed.

Positional: `<PACKAGE>` — the package name (`[a-z0-9-]`).

| Flag | Meaning | Req/Opt | Default |
|---|---|---|---|
| `--toolsets-dir <PATH>` | Toolsets root override. | Optional | OS-conventional toolsets dir |

```bash
stellar-agent toolsets uninstall balance-reporter
```

## MCP tools

The MCP server exposes two statically registered toolset tools. Their routing is
dynamic (it reads installed pin records at call time), but the tools themselves are
fixed. See [mcp.md](mcp.md) for the server as a whole.

### `stellar_toolset_list`

Takes no arguments and returns a JSON array of installed-toolset entries. Each entry
has the same per-toolset shape as the elements of the `toolsets` array inside the
`toolsets list` envelope; the MCP tool returns the bare array rather than the
`{status, toolsets}` wrapper. Read-only and non-destructive.

```json
{}
```

### `stellar_toolset_invoke`

Invokes a named action of an installed toolset, routing it through the four-part
enforcement check to the trusted tool it maps to, then running that tool's own
dispatch gate.

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

No signing, key, or policy tool is reachable through any capability, so an `action`
naming a signing tool returns `toolset.unknown_action` (the tool is not in the matrix
to resolve). For a `sign-payment` toolset, `action: "stellar_pay_commit"` is routed
through the gated resolver instead: `args` must carry the `envelope_xdr` produced by
a prior `stellar_pay` simulate call, from which the destination, asset, and amount
are decoded authoritatively. If the first-invoke gate fires, the call returns
`toolset.first_invoke_approval_required` with the approval nonce; once a grant exists,
the per-action payment approval is still forced on for the commit.
