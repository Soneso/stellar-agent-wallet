- Coverage measures feature-off and feature-on in two parallel jobs,
  `coverage (feature-off)` and `coverage (feature-on)`. The required `coverage`
  check passes only when both jobs succeed and both reports pass their floors.
- Pushes to `mainnet-write` and `main` run the Coverage workflow and seed its
  caches. Rust caches in CI and Coverage save on push runs only. The
  stellar-cli caches save on push and schedule runs only.
- Each coverage report carries the run attempt in its artifact name, so the
  `coverage` check reads only reports of its own attempt. After a failed
  download, a maintainer reruns all jobs.
- The changelog guard refuses a sync merge whose `CHANGELOG.md` differs from
  the clean three-way merge and names only the maintainer remedy.
