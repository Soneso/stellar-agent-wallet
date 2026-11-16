- A browser that negotiated HTTP/2 with a signed-origin listener got `421 host_header_rejected` and could not sign in, approve, or enroll.
  The signed consent listener and the signed enrollment listener now offer only `http/1.1` over ALPN, so browsers send the `Host` header that the signed authority check reads.
  A client that offers only `h2` fails the TLS handshake.
  Testnet remote listeners keep their protocol list.
