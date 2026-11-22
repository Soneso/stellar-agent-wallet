- `url` moves from 2.5.8 to 2.5.9, which resolves RUSTSEC-2026-0592, and
  `form_urlencoded` moves from 1.2.2 to 1.2.3 because `url` 2.5.9 requires it.
  In `url` 2.5.8, `Url::origin()` and `url::quirks::origin()` on a nested
  `blob:` URL recurse until the stack overflows and abort the process. The two
  wallet calls of `Url::origin()` take the origin and resource URLs of an MPP
  challenge's HTTP request context, which comes from an MCP tool argument or
  `mpp charge authorize` input, and run only after both URLs pass a check that
  refuses every scheme other than `https`, so a `blob:` URL never reaches them.
  No wallet crate calls `url::quirks::origin()`.
