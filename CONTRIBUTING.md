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
- `cargo deny check` (permissive-only license allow-list and advisory check)

Run them locally before requesting review. The exact commands, the gate-tool
installation, and the test tiers are in
[docs/maintainers/building.md](docs/maintainers/building.md).

## Review process

A fresh review team (Security, Code, and Architecture reviewers) checks every change
against the [review checklist](docs/maintainers/review-checklist.md) before it is
committed. Review repeats on a fresh pass until every reviewer approves with no
blocking findings.

## Commit and pull request conventions

- Write commit messages in conventional-commit style, for example
  `fix: redact account id in network error` or `feat: add per-period cap criterion`.
- Keep one focused change per pull request. Split unrelated work into separate
  pull requests.
- Describe what the change does and why. State the rationale, not the history of how
  the code got there.

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
