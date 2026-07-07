# relay — transparent pass-through relay with a passive observation tap

## Overview

When `brix_transparent_proxy host:port` is configured, every connection on
the port is relayed verbatim to an upstream official XRootD server. The
client's auth handshake (anonymous / token / x509 / GSI) travels
end-to-end, so the relay holds no credential. In parallel a non-consuming
tap decodes the cleartext XRootD frames it forwards and emits them to a
JSON audit log, and feeds the bad-actor guard core.

This exists for operators who want to monitor protocol metadata (opcodes,
paths, handles) crossing into a backend storage server without terminating
auth or altering the byte stream. It observes whatever travels in cleartext
(classic root:// auth-without-bulk-encryption).

The engine is a small bidirectional buffered TCP relay (modeled on
[../handoff/](../handoff/)) plus a per-direction `brix_tap_stream`
([../../../net/tap/](../../../net/tap/)) fed each freshly-received chunk.
The client→upstream decoder skips the 20-byte handshake preamble before
framing.

## Files

| File | Responsibility |
|---|---|
| `relay.c` | connection takeover at the top of the stream handler, relay pump, stall detection |
| `relay.h` | directive (`brix_transparent_proxy host:port`) + engagement contract |
| `relay_guard.c` | maps decoded tap frames onto the pure-C guard core (opcode classification, kXR_error errnum) |

## Invariants, security & gotchas

1. Byte-exact passthrough — the tap NEVER consumes or reorders; framing is
   observed, not terminated.
2. Never capture a connection's `ngx_log_t` into a tap sink: the session's
   log handler can go stale and SIGSEGV. Keep a scrubbed relay-struct copy
   with `handler`/`data`/`action` = NULL.
3. Engages at the very top of `ngx_stream_brix_handler()` — nothing else in
   the root tree runs for a relayed connection.

## See also

- [../../../net/tap/](../../../net/tap/) — the ngx-free decode/fan-out core
- [../../../net/guard/](../../../net/guard/) — the bad-actor guard `relay_guard.c` feeds
- [../handoff/README.md](../handoff/README.md) — the sibling pump for HTTP handoff
