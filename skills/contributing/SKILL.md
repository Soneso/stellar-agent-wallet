---
name: stellar-agent-wallet-contributing
description: Use when a coding agent chooses, implements, or prepares a pull request for a Stellar Agent Wallet contribution from a repository checkout.
license: Apache-2.0
metadata:
  version: "0.1.0"
---

# Contributing to Stellar Agent Wallet

Use this procedure from the repository checkout. Resolve the repository paths
in these steps from the checkout root.

1. Choose an unassigned issue labeled `good first issue` or `help wanted`,
   prioritizing `agent-ready` tasks. Read its Where, Acceptance, and Gates fields
   in [.github/ISSUE_TEMPLATE/contribution_task.md](../../.github/ISSUE_TEMPLATE/contribution_task.md).
   When the issue has no Gates section, its Acceptance section holds the gate
   commands.
   See [CONTRIBUTING.md](../../CONTRIBUTING.md#contributing-with-a-coding-agent)
   for the labels and suitable first changes.
2. Claim the issue by commenting "I'll take this". Hold one open assignment at a
   time, following [CONTRIBUTING.md](../../CONTRIBUTING.md#contributing-with-a-coding-agent).
3. Fork the repository and create a branch whose name says what the change
   does, such as `fix/claim-refusal-codes`, following
   [CONTRIBUTING.md](../../CONTRIBUTING.md#contributing-with-a-coding-agent).
4. Implement the acceptance criteria to
   [The bar for changes in CONTRIBUTING.md](../../CONTRIBUTING.md#the-bar-for-changes).
   Apply [Writing style](../../CONTRIBUTING.md#writing-style) to the edits.
5. Run `bash .github/scripts/preflight.sh` and every test command named in the
   issue's Gates. Use `bash .github/scripts/preflight.sh --list` to inspect the
   selection. Follow [docs/maintainers/building.md](../../docs/maintainers/building.md#preflight)
   for the gates, and record each exit code and unavailable gate.
6. Complete the self-review in
   [docs/maintainers/review-checklist.md](../../docs/maintainers/review-checklist.md#self-review-before-you-open-a-pull-request).
   Confirm each new test fails when you revert the behavior it checks, and name
   the tests you probe in the pull request.
7. Fill in [.github/PULL_REQUEST_TEMPLATE.md](../../.github/PULL_REQUEST_TEMPLATE.md),
   including the preflight table and the issue it closes. Follow the commit and
   pull request conventions in
   [CONTRIBUTING.md](../../CONTRIBUTING.md#commit-and-pull-request-conventions).
8. Answer review questions and make requested revisions when the pull request
   carries `waiting on author`; `waiting on maintainer` means the maintainer acts
   next. Follow the response expectations in
   [CONTRIBUTING.md](../../CONTRIBUTING.md#review-process).
