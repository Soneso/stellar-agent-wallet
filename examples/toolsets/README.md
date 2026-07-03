# Example toolsets (capability isolation)

These are runnable examples of the wallet's **toolsets feature** — a
capability-isolation mechanism. A wallet toolset is a signed, installable package
that grants an AI agent a **narrow, wallet-enforced set of capabilities** (least
privilege). The wallet treats a toolset as data: it reads the `TOOLSET.md` frontmatter
(name, description, capabilities, allowed-tools) and never executes the toolset's
instructions itself. See [docs/toolsets.md](../../docs/toolsets.md) for the feature.

> Not to be confused with the **knowledge skill** at `skills/stellar-agent-wallet/`,
> which *teaches* an agent how to operate the wallet and is distributed for
> agentskills.io runtimes (Claude Code, Codex, Cursor). These examples do the
> opposite — they *restrict* what an agent may do.

| Toolset | Capabilities | What it shows |
|---|---|---|
| [`balance-reporter`](balance-reporter/TOOLSET.md) | `read-balance` | The simplest toolset: one read-only action, no signing path reachable. |
| [`payment-sender`](payment-sender/TOOLSET.md) | `propose-transaction`, `sign-payment` | The build-then-commit payment flow behind the first-invoke gate and the unconditional per-action approval. |

These directories are toolset **source**, not packaged artifacts. The signing
material that `install` verifies is not, and should not be, committed here. The
steps below show how a publisher turns a source directory into something the
wallet will install.

## The install contract

`stellar-agent toolsets install` verifies origin and integrity before it extracts
anything: the package name and version, the package SHA-256 against `--shasum`,
and the publisher's ed25519 signature against a trust set. A key-touching toolset
(`sign-payment`, as `payment-sender` declares) additionally requires an auditor
attestation from a **separate** auditor trust set. See
[docs/toolsets.md](../../docs/toolsets.md) for the ordered checks and the
parse-safety guarantees.

This alpha ships no packaging or signing subcommand. The preimage layouts are
available as library functions so publisher-side tooling can reproduce the bytes
the wallet verifies: `signature::build_preimage` for the publisher signature and
`attestation::build_attestation_preimage` (which also binds the capability set)
for the auditor attestation, both in the `stellar-agent-toolsets-install` crate.

## Packaging and installing a toolset

1. Package the directory as a gzipped tar whose single top-level entry is the
   toolset directory (its name must equal the `name` in the frontmatter):

   ```bash
   tar -czf balance-reporter-1.0.0.tar.gz balance-reporter
   ```

2. Compute the package shasum — exactly the 64 lowercase hex characters, with no
   trailing filename, that `--shasum` expects:

   ```bash
   shasum -a 256 balance-reporter-1.0.0.tar.gz | cut -d' ' -f1
   ```

3. Sign the publisher preimage with your ed25519 publisher key, using
   `stellar_agent_toolsets_install::signature::build_preimage(package, version, shasum_hex)`
   to reconstruct the exact bytes the wallet checks, and encode the 64-byte
   signature as 128 hex characters.

4. Install, naming your publisher key as a Stellar G-strkey and pointing
   `--trust-set` at a file that lists it:

   ```bash
   stellar-agent toolsets install balance-reporter@1.0.0 \
     --file ./balance-reporter-1.0.0.tar.gz \
     --shasum <64-hex-sha256> \
     --signature <128-hex-ed25519-sig> \
     --publisher <G-STRKEY> \
     --trust-set ./trust.txt
   ```

For `payment-sender`, also produce a `ToolsetAttestation` JSON signed by an auditor
key (over `attestation::build_attestation_preimage(package, version, shasum_hex, &capabilities)`),
list that key in an auditor trust-set file, and add
`--attestation-file ./attestation.json` and
`--auditor-trust-set ./auditor-trust.txt`. Without an auditor attestation the
install of a key-touching toolset fails closed. The only sanctioned bypass is
`--override-attestation`, which logs a warning and still persists the
`sign-payment` capability inert, so the runtime first-invoke and per-action
gates fire at signing time regardless.

## After install

```bash
stellar-agent toolsets list                    # enumerate installed toolsets + actions
stellar-agent toolsets run balance-reporter stellar_balances   # resolve-only check
stellar-agent toolsets uninstall balance-reporter
```

`toolsets run` only runs the capability-enforcement check and reports the tool the
action routes to; it does not execute the tool. Execution happens through the MCP
surface (`stellar_toolset_invoke`). See
[docs/agents.md](../../docs/agents.md) for how an agent drives an installed toolset.
