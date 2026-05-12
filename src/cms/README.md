# cms — CMS manager heartbeat client

Maintains a persistent TCP connection to an XRootD CMS manager and sends
periodic load/availability reports so the manager can route client requests
to this server.

| File | Responsibility |
|------|----------------|
| `config.c` | nginx directive parser for `xrootd_cms_manager`, `xrootd_cms_paths`, `xrootd_cms_interval` |
| `connect.c` | TCP connection lifecycle: `ngx_xrootd_cms_start`, connect, disconnect, timer, write handler, exponential backoff scheduler |
| `recv.c` | Incoming frame read loop and opcode dispatch (ping → pong, space → avail, status) |
| `send.c` | Outgoing frame builders: login, load heartbeat, avail reply, pong reply |
| `space.c` | Filesystem space measurement via `statvfs`; exported path selection |
| `wire.c` | Big-endian encode/decode helpers used by send and recv |
| `cms_internal.h` | Shared types (`ngx_xrootd_cms_ctx_s`), constants, and cross-file prototypes |

## Connection lifecycle

`ngx_xrootd_cms_start` (called from `config/process.c` at worker init) allocates
the context and arms a one-shot timer.  On expiry the timer handler calls
`ngx_xrootd_cms_connect`, which calls `ngx_event_connect_peer`.  On successful
connection the write handler fires, sends a login frame followed by the first
load report, then arms the periodic heartbeat timer (`xrootd_cms_interval`
seconds).  Any I/O error triggers `ngx_xrootd_cms_disconnect` and exponential
backoff retry up to `NGX_XROOTD_CMS_BACKOFF_MAX` (60 s).

## Wire protocol

Each CMS frame is an 8-byte header (`streamid u32`, `rrCode u8`, `modifier u8`,
`dlen u16`) followed by `dlen` bytes of payload.  Fields are big-endian.
Payload values are length-prefixed with a type tag: `CMS_PT_SHORT` (0x80) for
16-bit values, `CMS_PT_INT` (0xa0) for 32-bit values.
