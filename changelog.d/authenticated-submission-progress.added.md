- Add authenticated submission progress to library transaction status. It
  separates ordinary evidence recovery, checked receipt projection and
  predecessor eligibility for a suitably authorized successor. Admission
  revalidates the prospective authorization, policy and envelope.
- Keep failed current receipt repair visible as pending even after its
  decision was acknowledged, without changing successor permission. A later
  successful repair clears display pending. CLI and MCP payloads stay unchanged.
