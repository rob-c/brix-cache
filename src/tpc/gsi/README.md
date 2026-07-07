# gsi — outbound GSI authentication for the TPC pull socket

## Overview

When a native-TPC pull connects to a source server that demands GSI (x509)
authentication, this directory drives the *client* half of the GSI
handshake over the pull socket. It runs entirely on the blocking
thread-pool path (never the event loop), called from
[../outbound/](../outbound/)'s `bootstrap.c` after the login response
announces the server's required sec protocol.

The flow is staged across four files matching the wire round-trips:
initiate (`certreq`), exchange, `kXR_authmore` continuation (shared with
JWT bearer continuation), and final auth-path selection based on the
server's login/auth response.

## Files

| File | Responsibility |
|---|---|
| `gsi_outbound_certreq.c` | initiate the outbound GSI handshake on the TPC pull socket |
| `gsi_outbound_exchange.c` | complete the outbound GSI handshake (cert/DH exchange) |
| `gsi_outbound_common.c` | `kXR_authmore` continuation shared by GSI and JWT paths |
| `gsi_outbound_finish.c` | pick the auth path from the server's login/auth response |

## Invariants, security & gotchas

1. Blocking I/O only — this code runs on a thread-pool worker; it must
   never be called from the event loop.
2. Delegated credentials (when used) live in per-transfer temp files with
   owner-only permissions and are removed on completion — never reused
   across transfers.
3. Auth logic here is the *client* side; the server-side GSI verify lives
   in [../../auth/gsi/](../../auth/gsi/) — keep them separate.

## See also

- [../outbound/README.md](../outbound/README.md) — the socket + session this authenticates
- [../../auth/gsi/README.md](../../auth/gsi/README.md) — the server-side GSI machinery
