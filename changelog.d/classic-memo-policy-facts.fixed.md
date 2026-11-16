- A classic CLI or MCP payment to a destination with a memo binding no longer
  fails with `policy.deny.memo_binding_mismatch` when it carries the bound
  memo. Policy evaluation keeps the kind and exact value of every classic memo,
  including an ID of zero and the full 64-bit ID range. Preparation checks the
  parsed memo, and signing and commit check the memo signed in the envelope.
