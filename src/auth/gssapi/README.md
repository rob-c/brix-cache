# GSI GSSAPI Accept Engine

Server-side Globus GSI GSSAPI mechanism for the GridFTP gateway's RFC 2228
`AUTH GSSAPI` / `ADAT` token exchange (the dialect globus-url-copy and gfal2
speak). A single OpenSSL `SSL` object bound to a pair of memory BIOs drives a
TLS 1.2 handshake whose flights travel as ADAT tokens: the caller base64-decodes
each token off the wire, feeds the raw bytes to `brix_gssapi_srv_step()`, and
base64-encodes the returned out-token back into a 335 (continue) or 235 (done)
reply. The engine is transport-agnostic — it never touches a socket.

The state machine covers three phases: (1) the mem-BIO `SSL_accept` handshake,
with the client presenting an RFC 3820 proxy as its certificate; (2) an optional
GSI credential-delegation sub-exchange as application data over the same SSL —
delegator sends `'D'`, we reply with a proxy-certificate request
(`brix_gsi_build_pxyreq`), the delegator signs it, and we assemble the delegated
credential (`brix_gsi_assemble_proxy`); (3) post-auth confidentiality, where
`brix_gssapi_wrap`/`_unwrap` (SSL_write/SSL_read) protect the RFC 2228
MIC/CONF/ENC control channel.

File split:

- `gsi_mech.h` — the public API: `brix_gssapi_srv_create/step/peer/
  peer_cert_pem/wrap/unwrap/free` and the `BRIX_GSS_CONTINUE/COMPLETE/FAILED`
  status enum, with full per-function contracts.
- `gsi_mech.c` — the accept engine: the mem-BIO plumbing, the
  `ST_TLS → ST_WAIT_D → ST_WAIT_SIGNED → ST_DONE` state machine, and the
  post-handshake proxy-chain verification via `brix_gsi_verify_chain()`.

Gotchas visible in the code: TLS is pinned to 1.2 because the GSI ADAT state
machine expects the acceptor's CCS+Finished as the final 335/235 token — TLS
1.3's flight shape breaks it. The TLS-layer verify callback accepts any client
cert; the real RFC 3820 proxy verification runs post-handshake (OpenSSL's
default path building would reject proxy chains). All OpenSSL objects are
released via a pool cleanup, so no explicit free is needed on the happy path.
