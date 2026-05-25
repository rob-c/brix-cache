# Upstream Sources

This directory owns the outbound XRootD redirector client used when local
resolution misses and `xrootd_upstream` is configured.

| File | Responsibility |
|---|---|
| `bootstrap.c` | Handshake/protocol/login bootstrap bytes and response phases |
| `events.c` | Non-blocking upstream read/write event handlers and wait retry timer |
| `lifecycle.c` | Cleanup and abort-to-client behavior |
| `request.c` | Saved client request serialization and write flushing |
| `response.c` | Upstream response translation back to the client |
| `start.c` | Context allocation, DNS/TCP setup, and connect start |
| `upstream.h` | Public upstream API |
| `upstream_internal.h` | Internal upstream state shared by split sources |
| `auth.c` | Upstream authentication: login handshake with backend server |
| `directives.c` | nginx directives for `xrootd_upstream_*` (upstream host, timeout) |
| `tls.c` | TLS setup for upstream connection: certificate verification, SSL context |

