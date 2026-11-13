# Keychain measurement

This page describes how to count and classify the macOS keychain consent
dialogs that the CLI (`stellar-agent`) and the MCP server
(`stellar-agent-mcp`) raise, per install channel. The results let the docs
state what an operator sees on first use, after a restart, and when the two
binaries take turns on the same keychain items.

## Install channels

Measure each channel on its own, in its own dedicated user account:

- The signed archive. Run the
  [notarization smoke](releasing.md#run-the-notarization-smoke) with the
  `export_archive` input, download the artifact
  `signed-aarch64-apple-darwin-smoke` from that run, and unpack the archive it
  holds. Its two names are byte-equal copies of one executable with a
  Developer ID Application signature and one CDHash.
- A `cargo install` build. Install the `stellar-agent-cli` package from
  crates.io as the [README](../../README.md#cargo-install-from-cratesio) shows,
  and copy `stellar-agent` to `stellar-agent-mcp`. The copy carries the ad hoc
  signature of the local build, with the CDHash of the original.

## Host

- A macOS host on Apple silicon, since the smoke archive is built for
  `aarch64-apple-darwin`.
- A dedicated macOS user account created for the measurement, with a fresh
  login keychain. The keychain then holds only the wallet's items, so the
  dump below reveals nothing else. The operator's own account is never used.
- The platform keyring. `STELLAR_AGENT_KEYRING_BACKEND` stays unset, because
  a headless backend never reaches the keychain.
- Delete the dedicated account once the report is written.

## Probe sequence

Run the steps in order, once per channel, in the dedicated account. The
profile is a testnet profile throughout. The setup follows
[Set up a profile](../getting-started.md#set-up-a-profile); pass each seed as
[Pass a secret seed](../getting-started.md#pass-a-secret-seed) describes, in
`WALLET_SK` for the source and `WALLET_OWNER_SK` for the owner.

1. Create the source account: `stellar-agent accounts create --generate --fund-with-friendbot`.
2. Create the destination account with the same command.
3. Create the policy owner's keypair with the same command.
4. Initialize the profile: `stellar-agent profile init --profile default --network testnet`.
5. Mint the audit key: `stellar-agent profile rotate-audit-key default`.
6. Enroll the source as the signer: `stellar-agent profile enroll-signer --profile default --secret-env WALLET_SK`.
7. Mint the nonce key: `stellar-agent profile rotate-nonce-key default`.
8. Enroll the owner key: `stellar-agent profile enroll-owner-key --profile default --secret-env WALLET_OWNER_SK`.
9. Mint the attestation key: `stellar-agent profile rotate-attestation-key default`.
10. Write the policy file of [Create the V1 policy file](../getting-started.md#create-the-v1-policy-file), with an `approval_above` threshold of 50 XLM in place of the period cap on both payment rules, as [the policy engine](../concepts.md#the-policy-engine) shows.
11. Sign the policy: `stellar-agent profile sign-policy --profile default --secret-env WALLET_OWNER_SK`.
12. Configure the MCP client to launch `stellar-agent-mcp --profile default`, as [Configuring an MCP client](../mcp.md#configuring-an-mcp-client) describes.
13. Start the server from the client.
14. Read through the server: a `stellar_balances` call for the source.
15. Simulate a 60 XLM payment through the server: a `stellar_pay` call whose response carries an `approval_nonce`.
16. Approve with the CLI: `stellar-agent approve --id <approval_nonce> --profile default`.
17. Commit through the server: the `stellar_pay_commit` call of the approved payment.
18. Stop the server, and wait until no `stellar-agent-mcp` process remains.
19. Pay with the CLI: a 10 XLM `stellar-agent pay` from the source to the destination.
20. Start the server from the client.
21. Read and commit through the server: a `stellar_balances` call, then a 10 XLM `stellar_pay` and its `stellar_pay_commit`.
22. Stop the server, and wait until no `stellar-agent-mcp` process remains.
23. Pay with the CLI again, as in step 19.

A CLI `pay` needs the audit writer, which a running server holds, so the
server is stopped before each CLI payment. The CLI `approve` runs beside the
server: it queues its consent row for the server's writer.

Every step must succeed. A refusal is not a measurement: record it, fix its
cause, and repeat the channel from step 1 in a new dedicated account.

## What to record

After each step, setup steps included, record every dialog that appeared,
and record a step that raised none:

- The dialog text class. An application request names the application and
  the item and asks whether to allow access. A password request asks for the
  login keychain password.
- The item name the dialog shows.
- The choice made. The measurement always chooses Always Allow; a password
  request gets the dedicated account's password first.

## Read the access lists

After each step, setup steps included, read the access lists of the
dedicated account's login keychain:

```bash
security dump-keychain -a login.keychain-db
```

Without `-d`, the command prints the item attributes and their access lists
and never the secret data. Never pass `-d` to `dump-keychain`, and never pass
`-g` to `find-generic-password`: both print secrets. Record the partition list
that the output shows for each wallet item.

## Acceptance

For the signed archive:

- At most one application request per item per binary version.
- No password request when the CLI and the server take turns on the same
  items.

For the `cargo install` build, the measured counts are recorded in the docs
as the expected experience of that channel. No threshold applies.

## Report

Write one row per step and channel, and one row per item when a step touches
several items. The report holds item names and partition lists, never a
secret.

| step | channel | outcome | application requests | password requests | item | partition list after the step |
| --- | --- | --- | --- | --- | --- | --- |

Fill in the step number from the probe sequence, the channel (`signed` or
`cargo install`), the outcome (`ok`, or the refusal code), the count of each
dialog class, the item name, and the partition list from the dump.
