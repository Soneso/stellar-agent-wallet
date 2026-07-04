# What is the Stellar Agent Wallet?

The Stellar Agent Wallet is a wallet an AI agent can use — and a human can
trust. It lets an AI assistant such as Claude hold and move funds on the
Stellar network on your behalf, inside rules you set, with your explicit
approval for anything sensitive, and with a tamper-evident record of
everything it did.

This page is the non-technical tour: what the wallet is, what it can do, and
how a first session with an AI agent looks. When you are ready to actually
set it up, [Getting started](getting-started.md) has the step-by-step
commands.

## The idea in one minute

AI agents are becoming useful enough to do real work with real money: pay an
invoice, subscribe to a paid API, rebalance a small treasury, claim an
incoming payment. The hard question is not whether an agent *can* sign a
transaction — it is how you stay in control while it does.

The wallet answers that with a strict division of roles:

- **The agent acts.** It reads balances, prepares payments, trades, and
  submits transactions — through a set of tools designed for machines.
- **The wallet enforces.** Every single action passes a policy check you
  configured: allowed, refused, or held for your approval. The agent cannot
  talk its way around a rule, because the rules never see the agent's words —
  only the transaction itself.
- **You decide.** Actions held for approval land in your approval inbox. You
  see what the wallet itself decoded from the transaction — never the agent's
  description of it — and approve or reject with one click.
- **Everything is recorded.** An append-only, hash-chained audit log captures
  every action and decision. If anyone edits the log afterwards, verification
  fails.

Your secret keys never reach the agent. They live in your operating system's
keyring (Keychain on macOS, Secret Service on Linux, Credential Manager on
Windows), and only the wallet process touches them. The agent asks the wallet
to sign; it never sees what signs.

## What the agent can do with it

In plain terms, an agent connected to the wallet can:

- **Hold and move money** — check balances, send XLM or issued assets like
  USDC, create accounts, and claim incoming claimable balances (payments
  parked on-chain until the recipient collects them).
- **Manage asset access** — open trustlines (an account's opt-in to hold a
  given asset) to stablecoins behind built-in protections: a known-issuer
  table, lookalike detection, and a hard refusal of assets with hostile
  settings.
- **Pay other agents and services** — the x402 payment scheme lets an agent
  pay for API access machine-to-machine, optionally verifying who it is
  paying first.
- **Use DeFi, carefully** — lend on Blend, swap on Soroswap, and use DeFindex
  vaults through typed, simulation-checked verbs. The wallet refuses raw or
  opaque contract calls outright; only recognized, decoded operations reach
  signing.
- **Talk to anchors** — start deposits and withdrawals with regulated
  on/off-ramp services (the SEP-6 and SEP-24 standards), handing you the
  interactive part.
- **Prove identity** — authenticate to services with Stellar's standard
  web-auth flows (SEP-10, SEP-45) instead of ad-hoc credentials.
- **Operate a smart account** — for advanced setups, an on-chain
  OpenZeppelin smart account with spending rules enforced by the network
  itself, passkey signers, multi-signer quorums, and timelocked upgrades.

Two guardrail features frame all of it:

- **Toolsets** let you hand a specific agent a restricted subset of
  capabilities — for example "read balances and propose payments, nothing
  else" — cryptographically signed and isolated from the signing tools.
- **The approval inbox** is where held actions wait for you. Run it as a
  terminal command (`stellar-agent approve list`) or as a small local web
  page (`stellar-agent approve serve`) that updates live, notifies you when
  something arrives, and shows exactly what the agent wants to do. If the
  agent runs on a different machine, [remote approval](remote-approval.md)
  lets you review and approve from another device over TLS with a passkey,
  no SSH tunnel required.

## What it costs you to trust it

Nothing is asked of you on faith. The alpha is deliberately conservative:

- **Testnet only.** Every write and signing command structurally refuses the
  main Stellar network in this alpha. You experiment with test funds from
  the free Friendbot faucet; nothing real is at stake while you learn.
- **Guardrails scale with you.** Running without a profile on testnet is
  permissive, so you can experiment with faucet funds. A profile you mint
  yourself defaults to the V1 policy engine, which is first-match,
  default-deny: anything you have not explicitly allowed is refused, and
  rules can require your approval above a chosen amount.
- **Approvals are unforgeable.** An approval is a cryptographic attestation
  bound to the exact transaction bytes you saw and to your OS user account.
  If the transaction changes by one byte afterwards, the approval is void.
- **The audit log does not lie.** Each entry is chained to the previous one
  by hash. `stellar-agent audit verify` proves the record was not touched.

## Using it with Claude Code

The wallet speaks the Model Context Protocol (MCP), which is how Claude Code
and other AI coding agents discover tools. A first session looks like this:

1. **Build the wallet** (a Rust toolchain is the only prerequisite):

   ```bash
   git clone https://github.com/Soneso/stellar-agent-wallet
   cd stellar-agent-wallet && cargo build --release
   ```

2. **Fund a test account** — Friendbot gives you free testnet XLM, and the
   first-payment quickstart in [Getting started](getting-started.md) works
   without any configuration. When you move past experimenting, a profile
   stores your settings and puts the signing keys into your OS keyring;
   the same page covers that setup.

3. **Connect Claude Code to the wallet's MCP server:**

   ```bash
   claude mcp add stellar-agent -- /absolute/path/to/target/release/stellar-agent-mcp
   ```

4. **Optionally install the knowledge skill.** The [`skills/`](../skills/)
   directory ships a downloadable skill that teaches the agent how to
   operate the wallet well — which tools exist, the safe call patterns, and
   how approvals work — without it having to figure that out from scratch.

5. **Talk to it.** In a Claude Code session:

   > "Check my Stellar testnet balance."
   >
   > "Send 25 XLM to GDEST... with the memo invoice-42."
   >
   > "There is a claimable balance with ID BAAD... for my account — claim it."

6. **Approve when asked.** If your policy holds an action, the agent tells
   you it needs approval. In another terminal, `stellar-agent approve serve`
   opens your approval inbox in the browser; you review what the wallet
   decoded — recipient, amount, asset — and click Approve or Reject. On
   approval you hand the agent a short attestation code and it completes the
   payment; on rejection it is told no, definitively.

The same MCP server works with any MCP-capable agent runtime, and the skill
format is an open standard supported beyond Claude Code. For an engineer's
view of the integration — tool catalog, call patterns, error handling — see
[Driving the wallet from an AI agent](agents.md).

## Where to go next

- [Getting started](getting-started.md) — install, profile, faucet, first
  payment.
- [Concepts](concepts.md) — the security and governance model in depth.
- [The MCP server](mcp.md) — the full tool catalog.
- [Agent toolsets](toolsets.md) — restricting what a given agent may do.
- [CLI reference](cli-reference/index.md) — every `stellar-agent` command.
