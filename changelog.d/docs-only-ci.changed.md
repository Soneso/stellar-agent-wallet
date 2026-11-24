- A pull request into `mainnet-write` that changes only documentation skips
  the `ci.yml` build and test jobs. The new `changes` job decides with
  `.github/scripts/classify-docs-only.py`, which prints `docs_only=false`
  for every other event, base, or path, and after any error.
- On such a pull request the new `docs-tests` job runs the tests that read a
  documentation path, in both feature states, and checks every listed package
  with `cargo check --all-targets`. The registry `.github/docs-tests.tsv`
  lists the tests, and `.github/scripts/check-docs-reads.py` fails on a
  documentation read that the registry does not cover.
