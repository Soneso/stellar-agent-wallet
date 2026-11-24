# Dedicated-user validation record

The [deployment recipe](../dedicated-user.md) requires real-host evidence before operational use.
No real-host run is recorded here. Native unit tests do not establish host isolation.
Every macOS result is conditional: validated by the real-host run.

Run `scripts/deploy/validate-linux.sh --record <dir>` or `scripts/deploy/validate-macos.sh --record <dir>` as the operator.
Name a record directory that does not exist yet.
The script creates it with mode 0700 and refuses an existing path or a missing `--record` with exit 64.
A provisioning step whose input flag is absent records `skipped`.
The input flags are `--rpc-url`, `--providers`, `--policy`, `--cert`, `--key`, `--bind`, and `--rp-id`.
The scripts call only the installed wrappers through `sudo -n -u stellar-agent`.
They read no secret. Keep refusal text when an interface is unavailable.
Do not record seeds, provider values, passwords, PEM contents, or bootstrap URLs.

| Measurement | Linux status | macOS recorded state |
|---|---|---|
| Non-admin account, fixed home, disabled login | Not recorded | Not recorded |
| Home and data-root owner and 0700 modes | Not recorded | Not recorded |
| Profile owner, 0600 mode, and symlink refusal | Not recorded | Not recorded |
| Executable and project-file ownership | Not recorded | Not recorded |
| Extended ACL refusal | Not applicable | Not recorded |
| Argument refusal, exit 64 | Not recorded | Not recorded |
| Ownership and eligibility refusal, exit 65 | Not recorded | Not recorded |
| Conflicting-process refusal, exit 66 | Not recorded | Not recorded |
| Keychain unlock | Not recorded | Not recorded |
| Keychain lock | Not recorded | Not recorded |
| Other-user file access denial | Not recorded | Not recorded |
| Other-user keyring access denial | Not recorded | Not recorded |
| Non-TTY MCP stdio through the client command | Not recorded | Not recorded |
| Platform keyring write | Not recorded | Not recorded |
| Platform keyring read | Not recorded | Not recorded |
| Local provisioning order and final check | Not recorded | Not recorded |
| Signed-origin provisioning order and final check | Not recorded | Not recorded |
| Guided approval and commit round trip | Not recorded | Not recorded |
| Integrated wrappers, `profile enable-mainnet --state`, binding-free signing, initial-pin verification, and signed-origin listeners and enrollment | Required dependency; not recorded | Required dependency; not recorded |
| Native audit writer lock race | Not recorded | Not recorded |
| Approval UID binding | Not recorded | Not recorded |
| D-Bus and keyring daemon reuse | Not recorded | Not applicable |
| Keychain access lists with `security dump-keychain -a` | Not applicable | Not recorded |
| Binary designated requirement | Not applicable | Not recorded |
| Signed-binary upgrade retains access | Not applicable | Not recorded |
| Dialog counts, including zero item-access prompts | Not applicable | Not recorded |
| Operation without a wallet desktop session | Not applicable | Not recorded |

The validation scripts write one `provisioning-order` entry, which runs the
signed-origin steps when their flags are passed.
They also write a `binary-identity` entry and exit 1 when it is not ok.
They write no entry for the data-root mode, the profile file's owner, mode, and
symlink refusal, the native audit writer lock race, approval UID binding,
extended ACL refusal, or the integrated-wrappers row.
Record those rows by hand with the binary digest, command, exit status, and
sanitized output.

Use neither `security dump-keychain -d` nor `-g` when recording access metadata.
The macOS SSH run has no wallet desktop session, validated by the real-host run.
Record the binary digest, platform version, command, exit status, and sanitized
evidence for each measurement. Mark an unavailable native interface `not available`
and include its refusal text.
