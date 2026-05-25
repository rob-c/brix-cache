# Session Sources

These files cover the XRootD session layer, before file I/O and namespace
operations take over:

- `tls_config.c`: nginx directive parsers for in-protocol TLS (`xrootd_tls on`, cert/key paths, SSL context construction)
- `protocol.c`: `kXR_protocol` version, auth, manager, and TLS capability negotiation
- `login.c`: `kXR_login` session id response and auth plugin advertisement
- `lifecycle.c`: `kXR_ping` and `kXR_endsess` connection/session lifecycle requests
- `bind.c`: `kXR_bind` session binding — associate a session with a file handle
- `handles.c`: File handle management — open/close tracking, handle reuse
| `registry.c` | Session registry: active sessions lookup, session lifecycle coordination |
| `registry.h` | Registry types and prototypes |
| `session.h` | Public session types and cross-file prototypes |
| `signing.c` | Request signing: HMAC-SHA256 sigver computation for GSI sessions |
| `tls_config.c` | TLS configuration within a session: upgrade from cleartext to TLS |
- `registry.c`: Session registry — active session list, cleanup on disconnect
- `registry.h`: Session registry types and prototypes
- `session.h`: Session-level types shared across session submodules
- `signing.c`: Request signing (kXR_sigver) — HMAC-SHA256 for GSI auth

The public handler prototypes remain in `src/ngx_xrootd_module.h` because the
central dispatcher calls them directly.
