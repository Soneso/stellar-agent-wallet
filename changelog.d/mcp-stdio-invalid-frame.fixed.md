- One invalid line on the MCP stdio input no longer ends the session. An empty
  line or a line that holds only `\r` is skipped. A line that is not a JSON-RPC
  message, or one over the 1 MiB line limit, is answered with a JSON-RPC
  `-32700` error without an `id`, and the server reads the next line, also
  before `initialize`. A line that is not a JSON-RPC message and holds a
  `method` the server does not know and no `id` is skipped without an answer.
  The session still ends at end of input or on a read error, and also when an
  answer cannot be written.
