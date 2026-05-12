# Session Sources

These files cover the XRootD session layer, before file I/O and namespace
operations take over:

- `tls_config.c`: nginx directive parsers for in-protocol TLS (`xrootd_tls on`, cert/key paths, SSL context construction)
- `protocol.c`: `kXR_protocol` version, auth, manager, and TLS capability negotiation
- `login.c`: `kXR_login` session id response and auth plugin advertisement
- `lifecycle.c`: `kXR_ping` and `kXR_endsess` connection/session lifecycle requests
- `signing.c`: `kXR_sigver` request-signing preflight state

The public handler prototypes remain in `src/ngx_xrootd_module.h` because the
central dispatcher calls them directly.
