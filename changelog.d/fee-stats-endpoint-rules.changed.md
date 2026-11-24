- `fees stats --rpc-url` with `--profile` follows the shared endpoint rules.
  Without `--profile`, it takes an HTTPS URL without credentials. MCP
  `stellar_fee_stats` accepts `rpc_url` only when its scheme, host, and port
  match an endpoint the profile configures; other values refuse with
  `invalid_params`. No fixed host list applies.
- `profile rotate-audit-key`, `audit reanchor`, `audit bind-carriers`,
  `audit acknowledge-outbox-loss`, and `audit verify` report a keyring refusal
  on the tip anchor or its companion entries under its `auth.*` code, such as
  `auth.keyring_platform_error`. Another failure on that state keeps its code.
  When `profile rotate-audit-key` refuses at the anchor write it owes, the
  message says that the audit key was not rotated and names the command to
  rerun.
- `auth.enrolled_identity_unusable` names the remedy for its reason. A source
  mismatch names the enrolled signer address to pass as the source. On the
  CLI, it names the verb's source flag: `--source` on `pay` and `claim`,
  `--from` on `trustline`, and `--sponsor` on `accounts create`. A missing
  or malformed record names `profile enroll-signer --repair-identity`, and an
  unbound signer or a rotated owner names `profile bind-signer`.
