# outbound — the blocking source-session client for native TPC pulls

## Overview

This is the destination server acting as an XRootD *client*: for each
native-TPC pull, a thread-pool worker (`thread.c::brix_tpc_pull_thread()`,
posted by [../engine/](../engine/)'s `src/tpc/engine/launch.c`) opens its own connection
to the remote source, authenticates, opens the file, and pulls the bytes.
Everything here is deliberately blocking — it owns a whole pool thread for
the transfer's duration and must never run on the event loop.

`bootstrap.c` performs the 3-step anonymous session handshake;
`connect.c` resolves the origin via `getaddrinfo` and validates candidate
addresses; `tls.c` runs the client-side TLS handshake when the source
requires it; `tpc_token.c` fetches OAuth2/OIDC access tokens when token
auth is in play; GSI lives in [../gsi/](../gsi/). `source.c` completes the
pull (open, read loop, close) using the three blocking I/O primitives in
`io.c`.

## Files

| File | Responsibility |
|---|---|
| `thread.c` | the thread-pool worker: full source-side pull lifecycle |
| `bootstrap.c` | anonymous XRootD session establishment (3-step handshake) |
| `connect.c` | origin resolution (`getaddrinfo`) + candidate validation |
| `io.c` | the blocking send/recv primitives used by every stage |
| `source.c` | open/read/close of the remote file; drives the byte pull |
| `tls.c` | blocking client TLS handshake over the TPC socket |
| `tpc_token.c` | OAuth2/OIDC access-token fetch for token-authenticated sources |

### Other files

| File | Responsibility |
|---|---|
| `source_internal.h` | cross-file seam for the TPC remote-source pull, split (phase-79 file-size burndown) from a single oversized source.c into three cohesive units with zero behaviour change:. |
| `source_open.c` | tpc_open_source() builds a ClientOpenRequest for the remote origin (src_path + opaque tpc.key/org or a delegated authenticated read), sends the kXR_open, resolves the reply through the asynchronous XRootD flow-control st. |
| `source_stream.c` | tpc_stream_to_dst() streams the whole origin into t->dst_fd one TPC_CHUNK_SIZE kXR_read window at a time (draining the kXR_oksofar/kXR_ok frame sequence per request, writing each frame's body through the VFS core), then. |
| `tpc_token_exchange.c` | Fetches a delegated OAuth2 access token by exchanging the destination's own bearer (subject) token at an external OAuth2 token endpoint, via a fork/exec of curl. |
| `tpc_token_internal.h` | Cross-declares the two functions that call across the tpc_token.c / tpc_token_exchange.c file boundary. |

## Invariants, security & gotchas

1. Blocking-only: no function here may be called from the nginx event loop.
2. Outbound connect honors the address-family policy and SSRF restrictions
   configured for TPC (`enforce_ssrf` and friends) — validation happens in
   `connect.c` before any byte is sent.
3. Timeouts everywhere: a stalled source must fail the transfer, not wedge
   the pool thread (stall/idle deadlines on every blocking primitive).

## See also

- [../engine/README.md](../engine/README.md) — who launches this and how completion returns
- [../gsi/README.md](../gsi/README.md) — the GSI leg of source auth
