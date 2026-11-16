- Add a budget projection to the network library. It reads one verified
  window generation under the shared lock. It writes no policy, budget,
  approval, or audit state. It reports each rule's limits with the used,
  reserved, and remaining amounts of each accumulating limit, or why it has
  none. It also reports every authorization's native obligation at the
  stored observation. A missing or unreadable committed file, or an
  unreadable generation counter, refuses with a typed error. The
  transaction, period, total, and unlisted budget criteria describe their
  amount limits.
