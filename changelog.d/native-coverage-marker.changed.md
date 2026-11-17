- The policy window store writes format version 18, which carries an
  authenticated native coverage marker. Builds that read at most version 17
  refuse the file. Retention and a window reset keep every value-holding or
  fee-holding authorization without a release row, and a reset keeps both
  admissible floors. The first write that sets the marker raises the
  close-time floor 300 seconds past the store clock.
- The native floor projection refuses with `account.unread` when the store
  file or its marker is missing. A legacy claimed authorization without
  amounts keeps floor use refused on its profile; a new profile is the remedy.
  A floor that passes still refuses with `account.unread` on every public
  path.
