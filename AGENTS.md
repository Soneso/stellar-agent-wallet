# Agent contribution guide

Stellar Agent Wallet is a self-custodial Stellar wallet for AI agents. It exposes
the `stellar-agent` CLI and the `stellar-agent-mcp` MCP server over a shared core.

## The bar for changes

Meet [The bar for changes](CONTRIBUTING.md#the-bar-for-changes) for every change.

## Proof

Start local verification with `bash .github/scripts/preflight.sh` and run the
issue-specific acceptance commands. Use `bash .github/scripts/preflight.sh --list`
to see the selection. `bash .github/scripts/preflight.sh --full` runs the complete
local registry, including coverage.

CI runs the offline workspace suite on every pull request. Pull-request
coverage requires the `coverage` label; live acceptance uses its separate
workflow. Local coverage, machete, and deny are optional reproductions.
See [the building guide](docs/maintainers/building.md#preflight) for the gates.

## Self-review

Complete the [self-review](docs/maintainers/review-checklist.md#self-review-before-you-open-a-pull-request)
before opening a pull request.

## Writing style

Apply [Writing style](CONTRIBUTING.md#writing-style) to documentation, comments,
commit messages, and pull request descriptions.

## Commits and pull requests

Follow [Commit and pull request conventions](CONTRIBUTING.md#commit-and-pull-request-conventions)
and fill in [.github/PULL_REQUEST_TEMPLATE.md](.github/PULL_REQUEST_TEMPLATE.md).

## Tasks

Choose an unassigned issue labeled `good first issue` or `help wanted`, with
`agent-ready` identifying tasks whose Where, Acceptance, and Gates are commands.
Comment "I'll take this" and hold one open assignment at a time, as described in
[CONTRIBUTING.md](CONTRIBUTING.md#contributing-with-a-coding-agent).

## First changes

Avoid signing paths, key handling, and serialized state for a first change; see
[CONTRIBUTING.md](CONTRIBUTING.md#contributing-with-a-coding-agent).

## Skills

[skills/stellar-agent-wallet](skills/stellar-agent-wallet/SKILL.md) teaches the wallet.
[skills/contributing](skills/contributing/SKILL.md) teaches this contribution path.
