# handoff — single-port protocol handoff for the stream xrootd listener

## Overview

When a connection on a `root://` stream port opens with a non-XRootD first
byte and `brix_http_handoff` is configured, the connection is transparently
spliced to a local HTTP/WebDAV listener instead of being closed. Detection
is unambiguous: the XRootD client hello always begins with a zero streamid
word, so an HTTP method letter or a TLS ClientHello (0x16) cannot be XRootD.

This closes a deployment gap with stock xrootd: XrdHttp multiplexes HTTP on
the xrootd data port, so a stock redirector sends HTTP clients to a data
server's *data* port. nginx serves WebDAV on a separate `http{}` port —
without the handoff, an nginx data node behind a stock redirector would be
unreachable over WebDAV. With it, one registered port serves both protocols.

`brix_http_handoff_start()` dials `conf->http_handoff_addr`, replays the
already-read prefix bytes, then runs a small bidirectional buffered TCP
relay (no XRootD framing) until either side closes or the relay idles out.

## Files

| File | Responsibility |
|---|---|
| `handoff.c` | prefix replay + bidirectional buffered relay pump, idle/stall timeouts |
| `handoff.h` | directive (`brix_http_handoff host:port`) + `brix_http_handoff_start()` contract |

## Invariants, security & gotchas

1. The relay holds no protocol state and terminates nothing — auth happens
   entirely on the HTTP listener it splices to.
2. Detection happens on the FIRST bytes only; once handed off, the
   connection never returns to the XRootD state machine.
3. The relay buffers are pool-allocated per connection; teardown must go
   through the single disconnect path (no leaked upstream sockets).

## See also

- [../connection/README.md](../connection/README.md) — where the first-byte detection hooks in
- [../relay/README.md](../relay/README.md) — the same pump pattern, used for full-connection proxying
