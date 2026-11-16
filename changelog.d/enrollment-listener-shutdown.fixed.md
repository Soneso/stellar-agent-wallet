- The enrollment prompt could start while a loopback listener was still open
  after the shutdown timeout. On that timeout, shutdown now aborts both server
  tasks and waits for both cancellations before the prompt starts.
