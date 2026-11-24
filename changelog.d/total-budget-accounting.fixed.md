- A `total_budget` allocation counts every debit of its signed policy across
  restarts, state refreshes, pruning, and owner resets.
- A policy with a different signed digest starts its total budget at zero,
  and an engine under a replaced policy cannot spend.
- An expired hold frees total-budget capacity only once a committed sweep
  removes it, so a clock rollback cannot revive capacity already reused.
- A multi-leg debit whose total-budget sum overflows refuses with a typed
  error.
