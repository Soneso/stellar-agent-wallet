- Bind canonical transaction authorizations to their stored intent, exact envelope, operation, and previous attempt.
  Reread claimable balances during canonical resolution.
  Refuse a canonical intent prepared under a different signed policy.
  Keep consented intent operations resumable through their execution window after the waiting window closes.
  Persist optional authorization lineage under store wire version 17, retaining compatibility with legacy records.
  Canonical slot creation remains internal; command and tool preparation continues to use envelope slots.
