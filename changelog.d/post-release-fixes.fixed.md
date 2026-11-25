- Mainnet CLI `pay` and `claim` start a fresh readiness deadline after
  reservation reconciliation, policy reload, and operation start, so keychain
  dialogs during those steps no longer cause `network.endpoint_not_ready`.
- The operator enrollment page disables "Create passkey" during an attempt
  and after the passkey is sent, so a second click cannot start another
  passkey creation. A failed attempt enables the button again.
- `approve list --output table` shows `expired` instead of `expires in expired`.
  The note about hidden expired entries appears only when entries are hidden,
  and stays absent with `--include-expired`.
