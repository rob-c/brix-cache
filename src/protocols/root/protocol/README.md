# protocol — XRootD `root://` wire-format constants & packed structs

## Overview

This subsystem is the single source of truth for the **XRootD binary wire
protocol** (`root://` / `roots://`). It is a **header-only library**: every file
is pure `#define` constants and `#pragma pack(1)` `typedef struct` declarations —
**no `.c` code, no functions, no allocation, no runtime state**. It is an
**independent reimplementation** of the XRootD wire protocol, written from the
published **XRootD Protocol Specification v5.2.0** and cross-checked against the
upstream `xrootd/xrootd src/XProtocol/XProtocol.hh` header and the
`dcache/xrootd4j` (Java) and `go-hep/hep` (Go) reference implementations, so that
the rest of the module frames and parses the wire **byte-for-byte identically**
to a real XRootD server.

### Provenance & licensing

These definitions are **wire-protocol facts** — opcode numbers, status/error
codes, option bitmasks, field names, and packed byte layouts that any
interoperable implementation must reproduce. They are expressed here in this
project's own code and comments; **no XRootD source code is copied, linked, or
distributed** by this module. Such interface facts are what every independent
client/server (xrootd4j, go-hep, etc.) re-states, and reproducing them is what
makes interoperability possible.

XRootD itself is independent software distributed by its authors under the
**LGPL-3.0** (see <https://github.com/xrootd/xrootd>); LGPL-3.0 is compatible with
this project's **AGPL-3.0** license. The XRootD relationship and the licenses of
all third-party components linked into the built binary are recorded in the
repo-root [`THIRD-PARTY-NOTICES`](../../../../THIRD-PARTY-NOTICES) file.

It exists so that opcodes, status/error codes, option bitmasks, and on-the-wire
byte layouts are declared **once** and shared by every consumer instead of being
re-derived at each call site. Anyone asking "what opcode is X?", "what does this
flag bit mean?", or "what is the byte layout of request Y?" answers it from here.
These definitions are **wire facts, not policy**: they describe what bytes look
like on the network, never how a request is authorized, confined, or executed.

In the request lifecycle this subsystem sits *underneath* everything on the
stream path. The umbrella module header `../ngx_brix_module.h` pulls in
`protocol/protocol.h`, which transitively makes every constant and struct visible
to the connection/handshake/dispatch layers, the per-opcode handlers
(`../read/`, `../write/`, `../dirlist/`, `../query/`, `../fattr/`), the auth
layers (`../gsi/`, `../session/`), the response framer (`../response/`), and the
cluster/proxy layers (`../cms/`, `../manager/`, `../proxy/`, `../tpc/`). It is
consumed **only by the stream (`root://`) side**; the HTTP-side protocols
(WebDAV in `../webdav/`, S3 in `../s3/`) speak text/HTTP and do not use these
structs.

## Files

| File | Responsibility |
|------|----------------|
| `protocol.h` | Umbrella header — what consumers `#include`. Pulls in the five sub-headers below in dependency order (`types` → `opcodes` → `flags` → `wire` → `gsi`). |
| `types.h` | Primitive aliases matching `XProtocol.hh`: `kXR_char`=u8, `kXR_unt16`/`unt32`/`unt64`, `kXR_int16`/`int32`/`int64`. Used by every struct so they read like the published spec. Depends only on `<stdint.h>`. |
| `opcodes.h` | The numeric vocabulary: request IDs (`kXR_auth` 3000 … `kXR_clone` 3032), response status codes (`kXR_ok`/`kXR_oksofar`/`kXR_error`/`kXR_redirect`/`kXR_wait`/`kXR_status` 4007 …), `kXR_attn` action codes (`kXR_asyncms`/`kXR_asynresp`), XRootD error codes (`kXR_NotFound` … `kXR_TooManyErrs`, distinct from POSIX errno), `kXR_query` infotypes (`kXR_Qcksum`/`kXR_Qspace`/`kXR_Qconfig` …), `kXR_fattr` subcodes (`kXR_fattrGet`/`Set`/`Del`/`List`), version/port constants, server-type codes, and fixed wire sizes. |
| `flags.h` | Every option/capability bitmask: open flags (`kXR_open_read`/`kXR_new`/`kXR_delete`/`kXR_retstat`/`kXR_posc` …), ASCII-stat flag bits (`kXR_isDir`/`kXR_readable`/`kXR_writable` + local extensions `kXR_statAttrCache`/`kXR_cachersp`), protocol request/response capability bits (`kXR_ableTLS`/`kXR_wantTLS` ↔ `kXR_haveTLS`/`kXR_gotoTLS`/`kXR_isServer`/`kXR_isManager`/`kXR_attrProxy`/`kXR_attrCache` …), login capver bits, per-op options (dirlist `kXR_dstat`/`kXR_dcksm`, stat `kXR_vfs`, prepare/mkdir/sigver/set/chkpoint/fattr), and readv/writev/pgread/pgwrite sizing (`BRIX_*_MAXSEGS`=1024, `kXR_pgPageSZ`=4096, `kXR_pgUnitSZ`=4100). |
| `wire.h` | Public framing header — a thin aggregator that `#include`s the two struct fragments below. **Include this, not the fragments directly.** |
| `wire_core_requests.h` | Packed structs for handshake + common framing + core/read ops: `ClientInitHandShake`/`ServerInitHandShake`, the universal `ClientRequestHdr`/`ServerResponseHdr`, the `kXR_status` integrity bodies (`ServerResponseBody_Status`/`_pgRead`/`_pgWrite`, `ServerStatusResponse_pgRead`/`_pgWrite`), `ServerErrorBody`/`ServerRedirectBody`, and the protocol/login/auth/open/prepare/read/stat/close/ping/query/dirlist requests + response bodies. |
| `wire_write_extended_requests.h` | Packed structs for write/extended ops: `ClientPgWriteRequest`, `ClientWriteRequest`, sync/truncate/mkdir/rm/rmdir/mv/chmod/bind/endsess/locate/sigver/statx/fattr/set/writev/pgread/clone/chkpoint, plus the payload-element structs `clone_item` (32 B), `readahead_list` (16 B), `write_list` (16 B), and `ServerResponseBody_ChkPoint`. |
| `gsi.h` | GSI (x509) handshake constants: step numbers (`kXGS_*` server→client, `kXGC_*` client→server) and `XrdSutBucket` type codes (`kXRS_*`, `kXRS_none`=0 terminator, `[type:4B][len:4B][data]`). The GSI *logic* lives in `../gsi/`. |

## Key types & data structures

- **`ClientRequestHdr` (24 B)** — the universal client request header:
  `streamid[2]` (client-chosen, echoed back), `requestid` (a `kXR_*` opcode),
  16-byte request-specific `body`, then `dlen` (payload length; payload follows
  inline). **Every opcode struct in `wire.h` is just this 24-byte shape with the
  `body` region reinterpreted into named fields** — that is why all of them are
  exactly 24 bytes.
- **`ServerResponseHdr` (8 B)** — the universal response header: echoed
  `streamid`, `status` (a `kXR_*` status code), `dlen`. The `status` value
  decides what body follows: `kXR_ok`→result, `kXR_error`→`ServerErrorBody`,
  `kXR_redirect`→`ServerRedirectBody`, `kXR_status`→CRC32c integrity body.
- **`ServerResponseBody_Status` (16 B) + `ServerStatusResponse_pgRead` /
  `_pgWrite` (32 B)** — the `kXR_status` (4007) extended-framing structs used
  **only** for `kXR_pgread`/`kXR_pgwrite`. The 32-bit `crc32c` covers everything
  from `streamID` to end of body; `requestid` is stored as `requestcode -
  kXR_1stRequest` so it fits one byte (e.g. `kXR_pgwrite` 3026 → 26); `resptype`
  is 0=final / 1=partial; `dlen` is the bad-page-list length (0 = no bad pages).
- **`ClientInitHandShake` (20 B)** — the first bytes a client sends; the server
  validates `first==0`, `fourth==htonl(4)`, `fifth==htonl(2012=ROOTD_PQ)` to
  confirm a real XRootD client. `ServerInitHandShake` (12 B) is the **legacy**
  reply shape, kept for reference only — see gotchas.
- **Variable-length flexible-array bodies** — `ServerErrorBody{errnum[4],
  errmsg[1]}` and `ServerRedirectBody{port[4], host[1]}` carry a 1-byte stub
  array; the real string length is `dlen - 4`. `ClientLoginRequest.username[8]`
  is NUL-padded and **not** NUL-terminated at exactly 8 chars.
- **Vector-op payload elements** — `clone_item` (32 B), `readahead_list` (16 B,
  kXR_readv), `write_list` (16 B, kXR_writev): requests carry an inline array of
  these, bounded by `BRIX_READV_MAXSEGS` / `BRIX_WRITEV_MAXSEGS` = 1024.
- **Opcode/code numbering domains (`opcodes.h`)** — request IDs run 3000–3032
  (`kXR_auth` … `kXR_clone`); legacy ROOTD opcodes (<3000) are unsupported.
  Error codes and query infotypes **also** start near 3000 but are **separate
  numbering domains** from request IDs and from POSIX errno. Status codes live in
  the 4000s.
- **GSI step/bucket constants (`gsi.h`)** — `kXGS_*`/`kXGC_*` drive the GSI
  handshake state machine; `kXRS_*` tag each length-delimited
  `[type:4B][len:4B][data]` bucket, parsed until `kXRS_none` (0).

## Control & data flow

Nothing *executes* here — this subsystem is **included, not called**. The flow
that *uses* it on the `root://` path:

1. A connection is accepted in `../connection/handler.c`; `../connection/recv.c`
   accumulates bytes into a `ClientRequestHdr` and calls `brix_dispatch()` in
   `../handshake/dispatch.c`.
2. `brix_dispatch()` reads `requestid` (compared against the `kXR_*` opcodes
   here) and routes to the handshake/session, read, or write dispatch families
   (`../handshake/dispatch_session.c` / `dispatch_read.c` / `dispatch_write.c`),
   after honouring any `kXR_sigver` envelope (constants from `flags.h`,
   verification in `../session/signing.c`).
3. Per-opcode handlers cast the 24-byte header to the matching struct here (e.g.
   `ClientOpenRequest`, `ClientReadRequest`, `ClientPgWriteRequest`), resolve and
   confine the path via `../path/`, offload blocking I/O to `../aio/`, and build
   the reply.
4. The reply is framed by `../response/` using `ServerResponseHdr` + the matching
   body struct and the `kXR_*` status codes here; integrity replies use the
   `kXR_status` structs and CRC32c from `../compat/`.
5. GSI auth (`../gsi/`) uses `gsi.h` step/bucket codes; manager/cluster redirects
   (`../manager/`, `../cms/`) and proxy forwarding (`../proxy/`) emit
   `kXR_redirect` (`ServerRedirectBody`) and advertise role bits from `flags.h`
   (`kXR_isServer`/`kXR_isManager`/`kXR_attrProxy`/`kXR_attrCache` …) in the
   `kXR_protocol` response (`ServerProtocolBody`).

Outbound dependency: **only `<stdint.h>`** (via `types.h`). This subsystem
depends on no other module code, which is why it can sit at the very bottom of
the include graph.

## Invariants, security & gotchas

- **Big-endian, exact byte layout.** All multi-byte integers are network byte
  order — use `htonl`/`ntohl`/`htons`/`ntohs`. `#pragma pack(1)` is mandatory:
  any compiler-inserted padding corrupts parsing immediately
  (`wire_core_requests.h:8-15`, `:15` / `:350` for the `pack(push,1)`/`pop`).
  Every `Client*Request` is exactly 24 bytes by construction.
- **stat field order is `<id> <size> <flags> <mtime>`** — `<size>` comes BEFORE
  `<flags>` in the ASCII body. Swapping them makes the client read `kXR_isDir`
  (2) or `kXR_readable` (16) as the file size ("file size = 16" bugs)
  (`flags.h:52-57`, `wire_core_requests.h:390-394`).
- **`kXR_dstat` requires the 10-byte lead-in `".\n0 0 0 0\n"`.** The XRootD
  client only enters stat-pairing mode if it sees the 9-byte prefix
  `".\n0 0 0 0"`; without it every newline line (including stat lines) is read as
  a filename. The lead-in is sent once on the final/only chunk, not on
  intermediate `kXR_oksofar` chunks; `kXR_dcksm` implies `kXR_dstat` and uses the
  extended-stat shape so clients recognise the `adler32:` token
  (`wire_core_requests.h:450-469`, `flags.h:167-172`).
- **Never send the legacy `ServerInitHandShake` (12 B) to a v5 client.** v5
  clients send handshake + `kXR_protocol` as one 44-byte segment and expect each
  reply to be a standard 8-byte `ServerResponseHdr` + body; the old frame parses
  as `status=0x0008 / dlen=1312` and stalls the client. The struct is reference
  only — reply with `ServerResponseHdr{streamid={0,0}, status=kXR_ok, dlen=8}` +
  8 bytes of `protover`+`msgval` (`wire_core_requests.h:48-81`).
- **pgread/pgwrite integrity is non-negotiable, and the interleave order is
  inverted between directions.** Both MUST use `kXR_status` (4007) framing with
  per-page CRC32c. Page size `kXR_pgPageSZ`=4096, unit `kXR_pgUnitSZ`=4100,
  `kXR_pgPageBL`=12 (`page_index = offset >> 12`). pgwrite (client→server) is
  `[crc32c_be[4]][data]` per fragment; pgread (server→client) is
  `[data][crc32c_be[4]]` (`flags.h:206-240`,
  `wire_write_extended_requests.h:1-21`, `wire_core_requests.h:122-166`).
- **Error/redirect/login bodies are variable-length.** `ServerErrorBody.errmsg`
  and `ServerRedirectBody.host` are 1-byte stub arrays; real length is
  `dlen - 4`. `ClientLoginRequest.username[8]` is NUL-padded and **not**
  NUL-terminated at exactly 8 chars — use `strnlen`, never `strlen`
  (`wire_core_requests.h:183-202,261-262`).
- **`dlen` is untrusted input.** It comes straight off the wire; validate it
  before allocating or reading that many bytes (e.g.
  `ClientLoginRequest.dlen`, `wire_core_requests.h:267-270`).
- **`kXR_mv` has a split-arg layout.** `ClientMvRequest.arg1len` (a `kXR_int16`)
  gives the source-path length; the payload is `src\0dst\0`, not a single string
  (`wire_write_extended_requests.h:127-135`). Parsing it as one path is a classic
  bug.
- **Three separate numbering domains.** Request IDs, error codes, and query
  infotypes all start near 3000 but never mix; status codes are 4000s.
  `kXR_status` (4007) is a status code, not an error code. Map POSIX errno →
  `kXR_*` in the response helpers — see `../compat/error_mapping.h` and the
  errno→kXR table in `../../CLAUDE.md`.
- **Capability bits gate TLS and role.** TLS flows through
  `kXR_ableTLS`/`kXR_wantTLS` (request) ↔ `kXR_haveTLS`/`kXR_gotoTLS`/
  `kXR_tlsLogin` (response). Role/feature bits
  (`kXR_isServer`/`kXR_isManager`/`kXR_attrProxy`/`kXR_attrCache`/`kXR_attrMeta`/
  `kXR_attrSuper`/`kXR_supposc`/`kXR_suppgrw`/`kXR_collapseRedir`) are set from
  config and read by clients to learn what this node is (`flags.h:78-138`).
- **Local extensions vs spec — do not assume upstream clients understand them.**
  Flagged in comments: stat bits `kXR_statAttrCache` (256) and `kXR_cachersp`
  (512), and `kXR_fa_recurse` (0x20) fattr-list option. `kXR_ecRedir`,
  `kXR_supgpf`, `kXR_anongpf` are declared for completeness but **never set** (no
  backing implementation) (`flags.h:67-76,119-132,294-296`).
- **Doc-comment opcode typos (cosmetic — trust `opcodes.h`).** The
  `ClientChkPointRequest` section is labelled `kXR_chkpoint (3033)` but the real
  opcode is `kXR_chkpoint = 3012` (3033 is the unrelated error code
  `kXR_TooManyErrs`) (`wire_write_extended_requests.h:316` vs `opcodes.h:56`).
  The `ClientPgReadRequest` section is labelled `kXR_pgread (3031)` but the real
  opcode is `kXR_pgread = 3030` (3031 is `kXR_writev`)
  (`wire_write_extended_requests.h:282` vs `opcodes.h:74-75`). Several comments
  also reference a dispatcher named `brix_dispatch_opcode()`; the actual
  function is **`brix_dispatch()`** in `../handshake/dispatch.c`.

## Entry points / extending

To add a **new XRootD opcode** (mirrors the `../../CLAUDE.md` recipe; the parts
that touch *this* subsystem):

1. **`opcodes.h`** — add the request ID `#define kXR_<name> <id>`; add any new
   error code / query infotype / fattr subcode it needs. Keep the comment opcode
   number in sync with the `#define` (see the cosmetic typos above).
2. **`flags.h`** — add any option/capability bitmasks and sizing constants the op
   uses.
3. **`wire_core_requests.h`** *or* **`wire_write_extended_requests.h`** — add the
   `#pragma pack(1)` `Client<Name>Request` struct (the 24-byte header shape) and
   any response-body struct. Keep field order and reserved-byte counts exact;
   annotate units and big-endianness. Total request size must stay 24 bytes.
4. Then leave this subsystem: register the handler in the matching
   `../handshake/dispatch_*.c`, implement the op under `../read/`/`../write/`/etc.,
   frame the reply via `../response/`, and add the 3 required tests
   (success + error + security-negative).

Adding a **new flag / error code / infotype only** is a one-line `#define` in
`opcodes.h` or `flags.h` — no `./configure` and no new-file registration in the
top-level `config` script (the module's `ngx_module_srcs` / `NGX_ADDON_SRCS`
list), because this subsystem ships **no `.c` files**.

## See also

- `../README.md` — master subsystem index.
- `../handshake/` — opcode dispatcher (`brix_dispatch()`) that reads these IDs.
- `../connection/` — byte accumulation into `ClientRequestHdr`.
- `../response/` — frames `ServerResponseHdr` + bodies using these status codes.
- `../read/`, `../write/`, `../dirlist/`, `../query/`, `../fattr/` — per-opcode
  handlers that cast the request structs.
- `../gsi/` — GSI auth logic that uses `gsi.h` step/bucket constants.
- `../session/` — login/bind/sigver; `signing.c` consumes the `kXR_sigver` flags.
- `../manager/`, `../cms/`, `../proxy/`, `../tpc/` — cluster/redirect/forwarding
  paths that emit `kXR_redirect` and advertise role bits from `flags.h`.
- `../compat/error_mapping.h` — errno → `kXR_*` mapping for response bodies;
  `../compat/` — CRC32c for the `kXR_status` integrity framing.
- Upstream sources: `xrootd/xrootd src/XProtocol/XProtocol.hh`,
  `src/XrdSecgsi/XrdSecProtocolgsi.hh`, `src/XrdSut/XrdSutBuffer.hh`;
  `dcache/xrootd4j`; `go-hep/hep xrdproto/`; XRootD Protocol Spec v5.2.0.
