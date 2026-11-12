# Dedicated wallet user

Run the wallet as the non-admin `stellar-agent` account to separate its files
and platform keyring from the operator's ordinary processes.
The operator delegates commands through three fixed wrappers.
Code running as the wallet user can read unlocked wallet keys.
The wrappers constrain delegated commands; the signed policy constrains wallet actions.

Deployment evidence lives in the [validation record](maintainers/dedicated-user-validation.md).
The record identifies interfaces that need an integrated deployment build.
Every macOS deployment claim is conditional: validated by the real-host run.

## Account and bootstrap

Run the bootstrap as root with production binaries:

```bash
bash scripts/deploy/bootstrap.sh --operator <account> --project <name> --cli <binary> --mcp <mcp-binary>
```

The bootstrap takes no secret. It creates a non-admin account, disables password
login, and selects a non-login shell.
The macOS account is hidden, validated by the real-host run.
Production binaries require mainnet writes and exclude test helpers.
The wallet cannot change its root-owned executables.
A repeated bootstrap installs upgrades and preserves files below the data root.
An existing account with another home or administrative membership refuses.

The fixed profile is `mainnet`. Home, `run`, `tmp`, and the data root are
wallet-owned, mode 0700. Profiles, policies, and PEM files are mode 0600.
The profile lives at `<data-root>/profiles/mainnet.toml`.
The installed policy is `<data-root>/policies/mainnet.toml`.
Leave `audit_log_path` unset; the default is `<data-root>/audit/mainnet.jsonl`.

Linux uses home `/var/lib/stellar-agent` and data root
`<home>/.local/share/stellar-agent`.
macOS uses home `/Users/stellar-agent` and data root
`<home>/Library/Application Support/Soneso.stellar-agent`, validated by the real-host run.
The wrappers and binaries live under `/usr/local/libexec/stellar-agent`, root-owned 0755.
The binaries occupy its `bin` directory.
The project file `/usr/local/etc/stellar-agent/project` is root-owned 0644
and contains one project-name line.

## Delegation and client command

The bootstrap validates and installs this sudoers grant, with the operator account substituted:

```sudoers
<operator> ALL=(stellar-agent) NOPASSWD: /usr/local/libexec/stellar-agent/mcp-launch, /usr/local/libexec/stellar-agent/cli-launch, /usr/local/libexec/stellar-agent/provision
Defaults!/usr/local/libexec/stellar-agent/mcp-launch !requiretty
Defaults!/usr/local/libexec/stellar-agent/cli-launch !requiretty
Defaults!/usr/local/libexec/stellar-agent/provision !requiretty
```

Keep `env_reset` enabled. Grant no shell or wildcard command.
Configure the MCP client to execute:

```bash
sudo -n -u stellar-agent /usr/local/libexec/stellar-agent/mcp-launch
```

Use the same `sudo -n -u stellar-agent` prefix for `cli-launch` and `provision`.
Each installed wrapper enforces its argument forms, supplies `--profile mainnet`,
and ends in `exec`. MCP stdout remains protocol-only; CLI stdout carries JSON.

Wrappers construct a clean environment: `HOME`, `PATH`, `TMPDIR`, and the
root-owned project name in `STELLAR_AGENT_PROJECT`.
Linux also supplies its private D-Bus address and keyring control directory.
No caller profile overlay, display variable, alternate wallet home, or headless
keyring setting crosses the wrapper boundary.

## Exact wrapper forms

`mcp-launch` accepts no arguments.
The other wrappers accept exactly the following forms, with no extra suffix.
Caller `--profile`, `--audit-log`, and unknown tokens refuse.
An approval ID contains 1 to 64 ASCII letters, digits, underscores, or hyphens.
Provider roles are `primary`, `secondary`, and `oracle`.

| Wrapper | Caller arguments |
|---|---|
| `cli-launch` | `keychain-unlock` |
| `cli-launch` | `keychain-lock` |
| `cli-launch` | `profile show` |
| `cli-launch` | `profile enable-mainnet --state` |
| `cli-launch` | `profile enable-mainnet --check` |
| `cli-launch` | `audit verify` |
| `cli-launch` | `approve credential enroll --open-by-operator` |
| `cli-launch` | `approve credential enroll --origin-from-installed` |
| `cli-launch` | `approve serve --open-by-operator` |
| `cli-launch` | `approve serve --remote --confirm-remote-exposure` |
| `cli-launch` | `approve --id <id> --open-by-operator` |
| `cli-launch` | `approve --id <id>` |
| `provision` | `profile init --network mainnet --rpc-url <https URL>` |
| `provision` | `profile rotate-audit-key` |
| `provision` | `profile enroll-owner-key` |
| `provision` | `profile enroll-signer` |
| `provision` | `profile bind-signer` |
| `provision` | `profile rotate-nonce-key` |
| `provision` | `profile rotate-attestation-key` |
| `provision` | `profile sign-policy` |
| `provision` | `profile enable-mainnet` |
| `provision` | `providers` |
| `provision` | `provider-credential --role <role>` |
| `provision` | `policy-install` |
| `provision` | `remote-config --bind <addr> --rp-id <host>` |
| `provision` | `remote-cert` |
| `provision` | `remote-key` |

Unlock, profile initialization, and the state diagnostic bypass the enablement predicate.
Other forms accept an absent or enabled nonce, except signer enrollment,
signer binding, providers, and enablement itself, which require an absent nonce.
An unreadable nonce refuses every non-exempt form.
Use the state diagnostic to inspect its classified error and keyring coordinates.
The final `--check` diagnostic does not decide wrapper eligibility.

## Secrets and stdin

Owner enrollment, signer enrollment, signer binding, and policy signing prompt
silently on the operator terminal. Only these forms receive the prompted seed
through `STELLAR_AGENT_PROVISION_SECRET`.
Provider credentials reach native `profile enroll-rpc-credential --stdin --force`
on stdin, once per requested role. No seed or password becomes a command argument.

Feed policies, provider fragments, certificates, and keys through stdin.
The wallet account needs no access to the operator's source files.
`policy-install` validates the complete body with `profile policy-check` before
an atomic rename. Refusal preserves the installed bytes.
`providers` requires a top-level HTTPS `oracle_provider_url` and provider records.
It calls `profile apply-fragment`, then prompts for each reported credential role.
Each supplied table replaces the whole stored table, including omitted roles.
Unrelated fields and comments stay intact.

`remote-config` supplies `[remote_approval]` with `enabled = true`, `bind`, `rp_id`,
`cert_path = <data-root>/remote/cert.pem`, and `key_path = <data-root>/remote/key.pem`.
`remote-cert` and `remote-key` install stdin PEM bytes at those fixed paths.
The private-key PEM is a secret file; its directory is mode 0700.

## Provisioning orders

Both orders begin with `cli-launch keychain-unlock`.
Then use `provision` for these forms, in order:

1. `profile init --network mainnet --rpc-url <https URL>`.
2. `profile rotate-audit-key` and `profile enroll-owner-key`.
3. `profile enroll-signer` and `profile bind-signer`.
4. `profile rotate-nonce-key` and `profile rotate-attestation-key`.
5. `providers`, with the complete provider fragment on stdin.

For local approval, run `cli-launch approve credential enroll --open-by-operator`.
Add its exported entry to the complete policy body, then use `provision policy-install`.

For a signed origin, first use `provision remote-config`, `remote-cert`, and `remote-key`.
Install the unsigned bootstrap policy with `approval_origin` and `approval_cert_spki_sha256` together.
Run `cli-launch approve credential enroll --origin-from-installed`.
The wrapper runs `approve credential enroll --origin-from <installed policy file>` in the provisioning tier.
The command reads the unsigned bootstrap body without a signature check and loads the explicit TLS paths before it binds.
The approving device must trust the certificate through a public CA or an installed private CA.
Open the printed URL there and type the enrollment code from the terminal.
Then type the page's confirmation code at the terminal before the timeout; only that exports the entry.
Add the exported entry and install the complete policy body again.

Finish either order with `provision profile sign-policy` for the binding-free body,
`provision profile enable-mainnet`, then `provision profile sign-policy` for the bound body.
Finally run `cli-launch profile enable-mainnet --check` before starting runtime services.
Binding-free signing, the state diagnostic, and signed-origin listeners require
the integrated interfaces listed in the validation record.

## Operator-open and runtime

The three `--open-by-operator` forms require a mainnet profile and a local-only policy.
Each prints its URL on exactly one stderr line:

```text
Open this URL in your browser: <url>
```

Open it in the operator's browser. It contains a single-use bootstrap token;
keep stderr private. The wallet launches no browser and creates no handoff file.
A remote operator must forward both loopback addresses to preserve the localhost origin.
Passkey verification, session limits, expiry, and cancellation still apply.
Enrollment also requires a terminal and the code from its page before export.
`--remote`, `--no-open`, and `--yes` conflict with operator-open where those flags exist.

An installed body that declares an origin counts as signed-origin before signing.
Each native operator-open verb refuses it with `approval.origin_signed_remote`
before acquiring ceremony resources. An invalid body refuses with its policy code.
A missing policy is local-only for this guard; runtime authority checks still apply.

Signed-origin wrappers use the remote serve form and bare `approve --id <id>`.
Bare approval refuses for a local-only wrapper profile and names the operator-open form.
Serve refuses while MCP runs, and MCP refuses while the CLI serves.
The native audit writer lock resolves races after those early checks.

## Refusals and keychain lifetime

| Exit | Wrapper meaning |
|---|---|
| 64 | Arguments do not match an allowed form. |
| 65 | Ownership, mode, ACL, eligibility, origin, or stdin validation refuses. |
| 66 | The early process check finds a conflicting wallet process. |

Wrapper refusal lines are `stellar-agent-wrapper: refused: <reason>` on stderr.
They contain a fixed reason and echo no rejected token.
Native failures otherwise retain their native exit codes and envelopes.
`apply-fragment` exits 65 with `refused: <code>` on stderr for a rejected candidate.
Success ends stderr with `credential-roles:` and roles in `primary secondary oracle` order.

Linux unlock starts private D-Bus and Secret Service daemons through `setsid`.
PID files live in `<home>/run`; repeated unlock reuses live daemons.
Lock stops those daemons through their PID files.
macOS unlock creates and selects the login keychain when needed, validated by the real-host run.
It uses `security unlock-keychain` without a password argument, validated by the real-host run.
`security set-keychain-settings` removes timeout and sleep locking for that keychain only,
validated by the real-host run.
Explicit lock uses `security lock-keychain`, validated by the real-host run.
No password is stored. Unlock lasts until reboot or explicit lock.
After reboot, the operator unlocks again before starting the wallet.
