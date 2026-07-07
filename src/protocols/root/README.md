# root — the XRootD (`root://` / `roots://`) protocol plane

## Overview

Everything needed to speak the XRootD wire protocol lives under this
directory: TCP/TLS connection lifecycle, request framing, opcode dispatch,
the session/auth handshake, and one subdirectory per opcode family. The
per-connection entry point is `ngx_stream_brix_handler()`
([connection/handler.c](connection/)), installed by the stream module
descriptor in [stream/module.c](stream/). After framing
([connection/recv.c](connection/)) every complete request passes through
`brix_dispatch()` ([handshake/dispatch.c](handshake/)), which routes by
opcode to the family dispatchers and on to the handlers below.

All storage access goes through the VFS seam
([../../fs/vfs/](../../fs/vfs/)) — no raw file I/O in this tree
(CLAUDE.md INVARIANT 11). Identity and authorization live in
[../../auth/](../../auth/); this tree only *invokes* the auth gate at the
dispatch boundary.

## Subdirectories

| Dir | Responsibility | Entry point |
|---|---|---|
| [connection/](connection/) | TCP lifecycle, recv/send state machine, fd table, in-protocol TLS upgrade | `handler.c` |
| [stream/](stream/) | nginx stream-module descriptor + config lifecycle | `module.c` |
| [handshake/](handshake/) | opcode routers (read/write/session/signing), client hello, policy, sigver | `dispatch.c` |
| [session/](session/) | login, protocol negotiation, bind, ping/endsess, SHM session registry | dispatched |
| [protocol/](protocol/) | header-only wire-format constants, opcodes, codecs (mirror of XProtocol.hh) | — |
| [read/](read/) | kXR_open/read/readv/pgread/stat/locate/close/clone + prefetch | `open_request.c` |
| [write/](write/) | kXR_write/pgwrite/writev/sync/truncate, namespace ops (mkdir/rm/mv/chmod), chkpoint | dispatched |
| [query/](query/) | kXR_query + kXR_prepare (staging) | dispatched |
| [dirlist/](dirlist/) | kXR_dirlist + per-entry checksum (`cks.type` CGI) | `handler.c` |
| [fattr/](fattr/) | kXR_fattr get/set/del/list via the VFS xattr seam | `dispatch.c` |
| [zip/](zip/) | `?xrdcl.unzip=` archive-member serving (security-critical read-only ZIP locator) | `zip_http.c` |
| [path/](path/) | wire-path extraction, sanitization, CGI stripping, stat-body formatting | `extract.c` |
| [response/](response/) | wire response framing: basic, async kXR_attn, kXR_status(4007), CRC32c | `basic.c` |
| [handoff/](handoff/) | non-XRootD clients on a root:// port spliced to the HTTP/WebDAV listener | `handoff.c` |
| [relay/](relay/) | transparent pass-through relay + tap + bad-actor guard hook | `relay.c` |

## Control & data flow

```
accept → connection/handler.c (ctx + session id)
       → connection/recv.c    (frame: 20B hello → 24B header → dlen payload)
       → handshake/dispatch.c → dispatch_{read,write,session,signing}.c
       → opcode handler (read/, write/, query/, dirlist/, fattr/, zip/)
       → response/*.c → connection/write_helpers.c (out_ring FIFO) → send
```

Alternate routes engage before dispatch: a non-XRootD first byte diverts to
[handoff/](handoff/); a configured `brix_transparent_proxy` diverts the whole
connection to [relay/](relay/).

## Invariants, security & gotchas

1. Every wire path is resolved through the VFS/`resolve_path()` seam before
   any open — no exceptions (CLAUDE.md INVARIANT 4).
2. pgread/pgwrite responses use kXR_status(4007) framing with per-page
   CRC32c (INVARIANT 1).
3. TLS buffers are memory-backed only; cleartext uses file-backed+sendfile;
   never mix (INVARIANT 2).
4. Wire file handles are 0–255 indexes into the per-session fd table
   (connection/fd_table.c) — never kernel fds on the wire.
5. SHM tables (session registry, TPC keys) use spin+yield mutexes via
   `brix_shm_table_alloc()` — never POSIX-semaphore mode (INVARIANT 10).
6. kXR_writev and chkpoint/ckpXeq frame descriptors only in `dlen`; the
   body is streamed after — do not "fix" a short dlen back to
   descriptors+body (stock parity, 2026-07-02).

## See also

- [connection/README.md](connection/README.md) — the async I/O spine
- [../../fs/README.md](../../fs/README.md) — the VFS storage seam
- [../../tpc/](../../tpc/) — third-party-copy engine reached from `read/open_request.c`
- [../../auth/](../../auth/) — identity + the authorization gate
- Wire spec: `XProtocol.hh` (see the CLAUDE.md header for its location)
