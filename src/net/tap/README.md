# tap — ngx-free protocol observation tap (decode + sink fan-out)

## Overview

A passive observation layer that turns raw XRootD wire bytes into frame
descriptors and fans them out to registered sinks (JSON audit log, guard,
metrics) — without consuming, reordering, or altering the stream. The core
is deliberately ngx-free (plain C, no nginx types) so it is testable
standalone and reusable from any pump.

`tap_decode.c` decodes request/response frames and classifies path-bearing
vs non-path opcodes; `tap_stream.c` is the streaming decoder for
mid-stream observation (the client→upstream direction skips the 20-byte
handshake preamble before framing, and descriptor-only `dlen` framing for
kXR_writev/chkpoint is handled correctly); `tap_emit.c` fans decoded
frames out to sinks; `tap_audit.c` provides the compact opcode → name
mapping for the JSON audit format.

Consumers: the transparent relay
([../../protocols/root/relay/](../../protocols/root/relay/)) and the
terminating tap proxy ([../proxy/](../proxy/)).

## Files

| File | Responsibility |
|---|---|
| `tap.h` | frame descriptor + sink fan-out contract (the public surface) |
| `tap_decode.c` | wire → frame decode; path vs non-path opcode classification |
| `tap_stream.c` | streaming decoder: preamble skip, partial-frame reassembly, writev/chkpoint dlen rules |
| `tap_emit.c` | sink registration + fan-out |
| `tap_audit.c` | opcode → name mapping for the JSON audit sink |

## Invariants, security & gotchas

1. Non-consuming: a tap failure must never affect the relayed byte stream.
2. Never capture a connection's `ngx_log_t` into a sink — the session's
   log handler goes stale and SIGSEGVs. Keep a scrubbed `ngx_log_t` copy
   with `handler`/`data`/`action` = NULL.
3. kXR_writev and chkpoint/ckpXeq frame descriptors only in `dlen` (body
   streamed after) — the decoder must not expect body bytes inside the
   frame.
4. Keep this directory ngx-free — it is built and tested standalone.

## See also

- [../../protocols/root/relay/README.md](../../protocols/root/relay/README.md) — the passive relay consumer
- [../guard/](../guard/) — the bad-actor core fed by decoded frames
