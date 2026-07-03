# Agent skill for the Stellar Agent Wallet

An [Agent Skill](https://agentskills.io) that teaches AI agents how to operate the
Stellar Agent Wallet — a Stellar wallet for AI agents — through its `stellar-agent`
CLI and `stellar-agent-mcp` MCP server. Compatible with any agent that supports
the Agent Skills open standard (Claude Code, Codex CLI, Cursor, Gemini CLI, and
others).

## What it does

When installed, the skill gives your AI agent working knowledge of the wallet:
how to create a profile and custody keys, read account state, send payments
through the two-phase build-then-commit flow, satisfy the operator-approval gate,
drive smart-account governance and DeFi, and use the SEP and x402 surfaces — with
the correct commands, MCP tool names, arguments, and safe call patterns so the
agent does not have to guess or clone the repository.

This skill teaches an agent to **operate the wallet**. It is distinct from the
wallet's built-in [toolsets feature](../docs/toolsets.md), which is a signed,
capability-restricting package the wallet enforces at runtime — the opposite
purpose. See `references/toolsets-feature.md` in this skill for that
distinction.

## Installation

### Manual

Download [stellar-agent-wallet.zip](stellar-agent-wallet.zip) and extract it into
your agent's skill directory. Refer to your agent's documentation for the exact
path.

```bash
# Claude Code
unzip stellar-agent-wallet.zip -d .claude/skills/

# Codex CLI
unzip stellar-agent-wallet.zip -d .codex/skills/
```

The archive contains the `stellar-agent-wallet/` skill directory, so extraction
places it at `.claude/skills/stellar-agent-wallet/`.

### Claude Code (via marketplace)

```bash
/plugin marketplace add Soneso/stellar-agent-wallet
/plugin install stellar-agent-wallet@soneso-stellar-agent-wallet
```

## Skill structure

```
stellar-agent-wallet/
  SKILL.md                       # Core: how to operate the wallet (loaded when the skill activates)
  references/                    # Detailed docs (loaded on demand by the agent)
    cli-reference.md             # The stellar-agent command surface
    mcp-tools.md                 # The stellar-agent-mcp tool catalog
    profiles-and-keys.md         # Profiles, the keyring, and key rotation
    approvals-and-audit.md       # Policy engine, the approval spine, the audit log
    smart-accounts.md            # OpenZeppelin smart-account governance
    defi.md                      # Blend, Soroswap, DeFindex, and the channel pool
    protocols.md                 # SEP support and x402 agent payments
    toolsets-feature.md          # The wallet's capability-isolation feature
    troubleshooting.md           # Wire and error codes
    security.md                  # The security model and safe operation
```

The skill uses progressive disclosure: only `SKILL.md` is loaded into context
initially. Reference files are loaded by the agent only when needed, keeping token
usage efficient.

## Status

This is a public alpha. The `stellar-agent` and `stellar-agent-mcp` binaries
install from a tagged release when one is available, or build from source; the
skill teaches the same surface either way. See the repository
[README](https://github.com/Soneso/stellar-agent-wallet) for build instructions.
