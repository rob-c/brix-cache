# proxy — Transparent XRootD proxy mode

Slides nginx-xrootd in front of any existing XRootD server, terminating TLS/auth/metrics locally while relaying opcodes verbatim to the backend. The backend is invisible to clients: lazy upstream connect on first post-login opcode, file-handle translation end-to-end, opaque relay of all responses. Every request lands in Prometheus counters and access logs.

| File | Responsibility |
|---|---|
| `connect_lifecycle.c` | Upstream connection lifecycle: lazy connect, keepalive, reconnect on failure |
| `connect_upstream.c` | TCP/TLS upstream connection setup: hostname resolution, SSL handshake |
| `directives.c` | nginx directives for `xrootd_proxy_*` (on/off, upstream, timeout) |
| `events_bootstrap.c` | Event loop bootstrap for proxy mode: arm/disarm recv/send events on upstream connect |
| `events_read.c` | Read-side event handling: client recv → upstream send → upstream recv → client send |
| `events_splice.c` | Splice-based zero-copy relay between client and upstream sockets |
| `events_write.c` | Write-side event handling: client write → upstream send → upstream ack → client response |
| `forward_relay.c` | Opcode relay core: forward request to upstream, receive response back to client |
| `forward_relay_audit.c` | Relay audit logging: record every forwarded opcode with timing and status |
| `forward_relay_dispatch.c` | Dispatch relayed opcodes: handle kXR_redirect, kXR_locate special cases |
| `forward_relay_response.c` | Response formatting for relayed upstream replies to clients |
| `forward_request.c` | Request construction: build wire request from client opcode for upstream send |
| `forward_rewrite_helpers.c` | Wire-level rewrite helpers: handle translation, path adjustment for proxy mode |
| `forward_session_helpers.c` | Session helpers: login relay, auth state sync between client and upstream |
| `pool.c` | Thread pool management for proxy async operations (read/write offload) |
| `proxy.h` | Public proxy types and cross-file prototypes |
| `proxy_internal.h` | Internal proxy types: ctx state machine, handle translation table |
