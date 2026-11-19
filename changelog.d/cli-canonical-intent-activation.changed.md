- The CLI verbs `pay`, `claim`, `trustline` and sponsored `accounts create`
  on mainnet now prepare a canonical record: the lasting intent, the policy
  decision and the envelope built at preparation. The confirmation shows the
  intent. After it the verb rebuilds the envelope with the account's current
  sequence, the fee the `--fee` choice gives now, a new deadline at the
  earlier of 120 seconds and the last second before the end of the
  approval's execution window or the policy decision's authority, and a
  fresh oracle check, then mints the authorization inside the attempt's
  begin. A slow confirmation no longer refuses with `deadline_elapsed`, and
  a refused begin leaves no authorization.
- A business id whose record holds an exact envelope keeps that envelope: the
  verb signs the stored transaction and never rebuilds it.
- A rebuilt claim whose balance no longer matches the stored intent refuses
  with `simulation.divergence` before any signature.
- After a canonical send the inbox approval stays unconsumed until the
  operation ends or its execution window passes; `tx status` then records the
  consumption.
- A published consent of a canonical record, on `approve --id` and at the
  confirmation, now completes as a consent to the stored intent.
