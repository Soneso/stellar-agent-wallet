# Contributing

Thanks for your interest in Stellar Agent Wallet. Contributions are welcome.
Questions and ideas go to
[Discussions](https://github.com/Soneso/stellar-agent-wallet/discussions); bugs
and feature requests are issues.

This is a public alpha under active development. Interfaces, output schemas, and
internal structure can change between commits. Expect change, and check the current
source before relying on a behavior.

## Getting set up

Stellar Agent Wallet is a Cargo workspace of `stellar-agent-*` crates that builds
two binaries: `stellar-agent` (the CLI, from crate `stellar-agent-cli`) and
`stellar-agent-mcp` (the MCP stdio server, from crate `stellar-agent-mcp`).

The toolchain channel is `stable` (pinned in `rust-toolchain.toml`, with the
`rustfmt` and `clippy` components) and the workspace targets Rust edition 2024. See
[docs/maintainers/building.md](docs/maintainers/building.md) for the prerequisites,
the gate-tool installation, the build commands, and the test tiers.

## The bar for changes

Every change must be production-ready. There is no separate "good enough for alpha"
standard.

The workspace lints are declared in the root `Cargo.toml` and denied across the
workspace. In particular:

- No `unsafe` code (`unsafe_code` is denied).
- No `unwrap`, `expect`, or `panic` in library code unless a path is provably
  infallible with an inline justification (`unwrap_used`, `expect_used`, and `panic`
  are denied).
- No `print_stdout`, `print_stderr`, or `dbg_macro` in library code.
- Every public item carries rustdoc (`missing_docs` is denied), with `# Errors`,
  `# Panics`, and `# Examples` where applicable.

Beyond the lints, a change is expected to:

- Fail closed. Every error path must refuse rather than proceed; nothing fails open.
- Keep secrets out of logs, `Debug` output, and error messages. Account identifiers
  and transaction hashes are redacted at info level. Secret material zeroizes on
  drop.
- Reuse the maintained Stellar crates (`stellar-xdr`, `stellar-strkey`,
  `stellar-rpc-client`, `stellar-baselib`) and existing repository code rather than
  hand-rolling equivalents. A decision not to reuse is documented.
- Ship tests that assert correct behavior. A test must fail if the behavior it
  covers regresses. A test that only raises the coverage number by exercising or
  asserting wrong behavior, or that would still pass if the code were broken, is a
  blocking finding. The fix is to correct the code or the expected value, never to
  keep a test that pins a defect.
- Document user-facing behavior (CLI commands, MCP tools) under `docs/`, and
  architecture and subsystem internals under `docs/maintainers/`.

The full production-readiness bar is the
[review checklist](docs/maintainers/review-checklist.md).

## Gate suite

These gates must pass before a change is accepted:

- `cargo fmt --all -- --check`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo test --all-features` (unit, integration, and doc-tests)
- `cargo llvm-cov` + `python3 .github/scripts/check-coverage.py` (per-crate
  line-coverage floors; 90% per crate is the aspirational target, shortfalls
  below it justified in review)
- `cargo machete` (no unused dependencies)
- `cargo deny check` (permissive-only license allowlist and advisory check)

`bash .github/scripts/preflight.sh` runs the local CI checks that apply to the
files your branch changes and prints their results for the pull request
description. `--full` runs every gate in its registry. The gates above remain
the acceptance bar for a change outside documentation, scripts, and workflows;
run the ones that apply. The exact commands, the gate-tool installation, and
the test tiers are in
[docs/maintainers/building.md](docs/maintainers/building.md).

CI runs the coverage gate on a pull request once a maintainer adds the
`coverage` label, and weekly on main.

## Review process

Your first pull request or issue gets an automatic welcome comment that names the next step.

A maintainer acknowledges a new pull request within one working day (Monday to
Friday, Central European Time). The review follows within three working days for
a change to documentation, scripts, or workflows, and within five working days
for a change to Rust code. Questions in the review thread get an answer within
two working days. [GOVERNANCE.md](GOVERNANCE.md) states who merges and how a
contributor gains the triage role. The depth of the review follows what the pull
request changes:

- A maintainer reviews a pull request that changes only documentation, scripts,
  or workflows from the diff and the repository's CI checks, with no testnet
  run.
- Every other pull request, such as a change to Rust code, also runs the
  [gate suite](#gate-suite).
- A pull request that changes signing paths, key handling, or serialized state
  also gets a second review pass.

The second review pass checks the change against the full
[review checklist](docs/maintainers/review-checklist.md) before merge, and the
testnet acceptance suites of the crates it touches run. Expect that review to
take longer and to ask for tests that prove the refusal paths.

A maintainer pushes small fixes, such as wording, a test case, or a rebase,
onto your branch so that the pull request can land the same day. You stay the
author of the squash commit. This needs "Allow edits by maintainers" on the pull
request. If you prefer to make every change yourself, say so in the pull
request.

A `waiting on maintainer` label means the next step is ours; `waiting on author`
means it is yours. The labels move by themselves when either side comments,
pushes, or reviews.

A pull request that waits on its author for 14 days gets a reminder, and it
closes after 21 days. You can reopen it at any time.

## Contributing with a coding agent

Coding agents start at [AGENTS.md](AGENTS.md) and can install
[skills/contributing](skills/README.md#contributing-skill).
The `agent-ready` label marks issues whose Where, Acceptance, and Gates are stated
as commands.

### Start here with your agent

Pick an unassigned issue labeled `agent-ready`, note its number, and give your
coding agent this prompt with the number in place of NNN:

> You are contributing to https://github.com/Soneso/stellar-agent-wallet for me,
> as an outside contributor, with my GitHub account through the `gh` CLI. The
> issue is #NNN.
>
> 1. Read the issue with `gh issue view NNN --repo Soneso/stellar-agent-wallet`.
> If nobody is assigned, ask me, then comment exactly "I'll take this" on it. A
> workflow assigns the issue to me. Confirm the assignment before you continue.
> If nothing assigns it within a few minutes, stop and tell me.
> 2. Fork and clone with `gh repo fork Soneso/stellar-agent-wallet --clone`,
> then create a branch named for the change.
> 3. Read `AGENTS.md`, the sections "Contributing with a coding agent", "Commit
> and pull request conventions", and "Writing style" in `CONTRIBUTING.md`, and
> the section "Self-review before you open a pull request" in
> `docs/maintainers/review-checklist.md`. Follow them.
> 4. Make exactly the changes the issue describes, nothing more. A test asserts
> the correct behavior. If a test passes only by accepting something wrong, the
> code is wrong, not the test. If you add or change a test, revert the behavior
> it pins and confirm the test fails, then restore it and note how you checked.
> 5. Verify the result: every acceptance command in the issue gives the value
> the issue states, and `bash .github/scripts/preflight.sh` passes.
> 6. Show me the diff, the gate results, and a pull request description that
> fills in `.github/PULL_REQUEST_TEMPLATE.md` with the preflight table and
> "Closes #NNN". After I confirm, commit in conventional-commit style, push to
> my fork, and open the pull request against `main` with `gh pr create`. Keep
> "Allow edits by maintainers" enabled.
> 7. When a review comment arrives, show it to me with your proposed answer or
> change before you reply or push.

The agent stops three times: before it claims the issue, before it opens the
pull request, and before it answers a review comment. Read the diff before you
confirm the pull request. You own it and answer the review questions.

This is a wallet built for AI agents, and contributions built with AI agents are
welcome. Three things make that work:

- You own the pull request. The quality bar in
  [The bar for changes](#the-bar-for-changes) does not move, and the checks that
  apply to the change must pass. You, the human contributor, need to understand
  the change, answer review questions, and make requested revisions. A pull
  request whose author cannot explain it does not clear review, whatever tool
  wrote it.
- Teach your agent the wallet first. The repository ships an
  [agent knowledge skill](skills/) that teaches a coding agent the CLI surface,
  the MCP tools, the error-code families, and the security model. Install it
  before you start so your agent works from the project's conventions; see
  [skills/README.md](skills/README.md) for setup.
- Before the pull request, your agent runs `bash .github/scripts/preflight.sh`
  and the self-review section of the
  [review checklist](docs/maintainers/review-checklist.md). The pull request
  description carries the preflight table and names the tests it probed.

Good entry points are the issues labeled
[`help wanted`](https://github.com/Soneso/stellar-agent-wallet/issues?q=is%3Aissue+is%3Aopen+label%3A%22help+wanted%22)
and
[`good first issue`](https://github.com/Soneso/stellar-agent-wallet/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22).
Issues labeled `good first issue` need no Rust toolchain beyond what the issue
names; `help wanted` issues change Rust code and run the gate suite.

Issues touching signing paths, key handling, or serialized state get the second
review pass and are better second contributions than first ones.

To claim an issue that carries `good first issue` or `help wanted` and has no
assignee, comment "I'll take this" on it, and the repository assigns it to you
at once. Hold one open assignment at a time. After 14 days with no pull
request and no comment, a maintainer releases the assignment and says so on the
issue.

If an issue is unassigned when you open a pull request for it, the first pull
request that fills in the template is the one reviewed. A maintainer closes a
later pull request for the same issue, with thanks and a pointer to another open
issue.

Work on a branch named for the change, for example `docs/exit-code-2` or
`fix/claim-refusal-codes`. Changes land through pull requests from a fork. CI
runs on every pull request. On your first contribution, the run starts after a
maintainer approves it. Every required check must pass before merge.

## Writing style

Documentation, code comments, commit messages, and pull request descriptions
follow these rules:

- Sentences under 35 words, in present tense.
- No em dash or en dash. Use a comma, a period, or a colon.
- American spelling.
- No emojis.
- A comment states what holds and why. It does not tell the history of the code,
  and it does not describe behavior by contrast with something the code does not
  do.
- No filler words that only praise or soften. Give the number or the measure,
  or cut the word.

`python3 .github/scripts/check-docs-style.py <file>` checks the mechanical rules.

## Commit and pull request conventions

- Write commit messages in conventional-commit style, for example
  `fix: redact account id in network error` or `feat: add per-period cap criterion`.
- Keep one focused change per pull request. Split unrelated work into separate
  pull requests.
- Describe what the change does and why. State the rationale, not the history of how
  the code got there.
- Fill in every part of the
  [pull request template](.github/PULL_REQUEST_TEMPLATE.md), which GitHub places
  in the description when you open a pull request.

## Reporting bugs and requesting features

Open a GitHub issue at
[github.com/Soneso/stellar-agent-wallet](https://github.com/Soneso/stellar-agent-wallet/issues).

For a bug, include:

- What you did and what you expected.
- The output you got, with secrets removed.
- The version (`stellar-agent --version`) or the commit you built from, and your platform and target.
- A minimal reproduction where possible.

For a feature request, describe the use case and the behavior you want.

Do not report security vulnerabilities in a public issue. Follow
[SECURITY.md](SECURITY.md) instead.

## Code of conduct

Participation in this project is governed by the
[Code of Conduct](CODE_OF_CONDUCT.md).

## License

Stellar Agent Wallet is licensed under Apache-2.0. By contributing, you agree that
your contributions are licensed under Apache-2.0.
