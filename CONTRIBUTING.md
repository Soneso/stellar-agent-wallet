# Contributing

Thanks for your interest in Stellar Agent Wallet. Contributions are welcome.

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

Run them locally before you request review of a change outside documentation,
scripts, and workflows. The exact commands, the gate-tool installation, and the
test tiers are in
[docs/maintainers/building.md](docs/maintainers/building.md).

## Review process

A maintainer acknowledges a new pull request within one working day (Monday to
Friday, Central European Time). The review follows within three working days for
a change to documentation, scripts, or workflows, and within five working days
for a change to Rust code. Questions in the review thread get an answer within
two working days. The depth of the review follows what the pull request changes:

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

## Contributing with a coding agent

This is a wallet built for AI agents, and contributions built with AI agents are
welcome. Two things make that work:

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

Good entry points are the issues labeled
[`help wanted`](https://github.com/Soneso/stellar-agent-wallet/issues?q=is%3Aissue+is%3Aopen+label%3A%22help+wanted%22)
and
[`good first issue`](https://github.com/Soneso/stellar-agent-wallet/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22).
Issues touching signing paths, key handling, or serialized state get the second
review pass and are better second contributions than first ones.

To claim an issue, comment "I'll take this" on it, and the repository assigns it
to you at once. Hold one open assignment at a time. After 14 days with no pull
request and no comment, a maintainer releases the assignment and says so on the
issue.

If an issue is unassigned when you open a pull request for it, the first pull
request that fills in the template is the one reviewed. A maintainer closes a
later pull request for the same issue, with thanks and a pointer to another open
issue.

Changes land through pull requests from a fork. CI runs on every pull request.
On your first contribution, the run starts after a maintainer approves it. Every
required check must pass before merge.

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
