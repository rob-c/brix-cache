# dirlist — XRootD `kXR_dirlist` directory enumeration (stream protocol)

## Overview

This subsystem implements the `root://` / `roots://` directory-listing
operation, `kXR_dirlist`. A client asks to enumerate one directory and
receives the entries as a flat, newline-delimited text block. Depending on the
request `options` bitfield, each entry may also carry a per-entry **stat** line
(`kXR_dstat`) and a per-entry **checksum** token (`kXR_dcksm`). Because a single
directory can contain far more entries than fit in one wire frame, the response
is streamed as a series of `kXR_oksofar` continuation frames followed by a final
`kXR_ok` frame that marks end-of-listing.

It sits in the **stream protocol handler** layer. The opcode dispatcher
(`../handshake/dispatch_read.c`) routes `kXR_dirlist` to
`brix_handle_dirlist()` (`handler.c`) after login/auth has completed. The
handler parses the request, confines the requested path beneath the export root,
applies an auth gate, opens the directory with `openat(O_DIRECTORY)`, iterates
with `readdir`/`fstatat`, and frames the result. This is the stream-protocol
sibling of the HTTP enumeration paths — WebDAV `PROPFIND`
(`../webdav/propfind.c`) and S3 `ListObjectsV2` (`../s3/list.c`) — which present
the *same* on-disk export through different wire encodings.

Two execution modes exist. The default is **synchronous**: the full
enumeration runs inline on the event loop. An **AIO/thread-pool** variant lives
in `../aio/dirlist.c` (`brix_dirlist_aio_thread` / `_done`) and offloads the
blocking `readdir`/`fstatat`/checksum work; however, in `handler.c` it is
currently gated off behind `if (0 && ...)` because the AIO path could complete
without delivering a response frame, wedging `xrdfs` readiness probes in
one-worker test deployments. Reviewers should treat the synchronous path as the
live code path.

Since phase-54 the VFS-owned thread-safe core `brix_vfs_io_execute()` has an
`OPENDIR` op (in [`../fs/vfs_io_core.c`](../../../fs/README.md)) that scans a confined
directory fd and builds the `kXR_dirlist` wire body off the event loop. **It is
wired into the `../aio/dirlist.c` worker only** — and that worker is currently
gated off (see above) — so the **live** path is still the synchronous
`fdopendir`/`readdir` loop in `handler.c`. Routing that live path through the
core (and ungating the worker) is the tracked follow-up that finishes bringing
dirlist into the unified VFS I/O core.

In **manager / redirector mode** the handler does not enumerate locally at all:
it selects a registered data server via `brix_srv_select()`
(`../manager/registry.h`) and replies with `kXR_redirect`, or `kXR_Overloaded`
if no server is available.

## Files

| File | Responsibility |
|------|----------------|
| `handler.c` | `brix_handle_dirlist()` — the whole operation: parse `options`/CGI, manager-mode redirect, path confinement + auth gate, `openat`+`fdopendir`, `readdir` loop building one line per entry, chunked `kXR_oksofar` flushing, terminal `kXR_ok`. Also `brix_dirlist_name_is_unsafe()` — skips entries whose names contain control bytes that would corrupt the `\n`-delimited wire format. |
| `dcksm.c` | `kXR_dcksm` (checksum) support: `brix_dirlist_checksum_algorithm()` parses the `?cks.type=<algo>` CGI parameter (default `adler32`); `brix_dirlist_checksum_token()` computes one entry's digest into an `algo:hexdigest` token; `brix_dirlist_make_dcksm_stat_body()` formats the extended 9-field stat body used in checksum mode. |
| `dcksm.h` | Prototypes/contract for the three `dcksm.c` helpers. Note: `_checksum_token` takes `ngx_log_t*` (not `ngx_connection_t*`) so it is safe to call from a thread-pool worker. |
| `dirlist.h` | Public prototype for `brix_handle_dirlist()` (the subsystem's only external entry point), called from the read-opcode dispatcher. |

## Key types & data structures

- **`ClientDirlistRequest`** (`../protocol`, XRootD wire struct) — overlaid
  directly on `ctx->hdr_buf`. The relevant field is `options`, a `u_char`
  bitfield: `kXR_dstat` (0x01) requests per-entry stat lines, `kXR_dcksm`
  (0x02) requests per-entry checksums and *implies* dstat
  (`want_stat = options & (kXR_dstat | kXR_dcksm)`).
- **The chunk buffer** — a single `XRD_RESPONSE_HDR_LEN + 65536` byte
  allocation from `c->pool`. The leading `XRD_RESPONSE_HDR_LEN` bytes are
  reserved so the response header can be written in-place by
  `brix_build_resp_hdr()`; entry bytes accumulate after it and are flushed
  whenever the next entry would overflow `chunk_cap` (65536).
- **dStat / dcksm line format** — plain mode emits `name\n`. dStat mode emits
  `name\n<statbody>\n`. dcksm mode emits `name\n<dcksm-statbody> [ algo:hex ]\n`.
  When stat is requested the block opens with a fixed lead-in `".\n0 0 0 0\n"`
  (the reference XRootD dstat preamble for the current directory).
- **`brix_integrity_info_t` / `brix_integrity_opts_t`**
  (`../compat/integrity_info.h`) — checksum result + options used by
  `brix_dirlist_checksum_token()`; it enables the xattr digest cache
  (`allow_xattr_cache` / `update_xattr_cache`) so repeated listings do not
  re-hash unchanged files.
- **`brix_dirlist_aio_t`** (`../aio/aio.h`) — the offload context for the
  (currently disabled) thread-pool variant: carries the resolved path, streamid,
  flags, a `BRIX_DIRLIST_AIO_RESPONSE_MAX` (4 MiB) response buffer, and error
  fields. Defined and consumed in `../aio/dirlist.c`.

## Control & data flow

**Entry:** `../handshake/dispatch_read.c` calls `brix_handle_dirlist(ctx, c,
conf)` for the `kXR_dirlist` opcode, after the session is authenticated.

Inside the handler (`handler.c`):

1. **Parse** `options`; reject an empty payload with `kXR_ArgMissing`.
2. **Checksum negotiation** (if `kXR_dcksm`): `brix_dirlist_checksum_algorithm()`
   (`dcksm.c`) → reject unsupported algorithms with `kXR_ServerError`.
3. **Extract path:** `brix_extract_path()` (`../path/path.h`) parses the
   NUL-terminated path (and strips trailing CGI) from the payload.
4. **Manager mode:** if `conf->manager_mode`, `brix_srv_select()`
   (`../manager/registry.h`) → `BRIX_RETURN_REDIR` (`kXR_redirect`) or
   `kXR_Overloaded`. No local I/O occurs.
5. **Confinement + auth:** `brix_beneath_full_path()` (`../path/beneath.h`)
   builds the logging path; the real open uses `brix_open_beneath(conf->rootfd,
   reqpath, O_RDONLY|O_DIRECTORY)` (`../path/beneath.h`), which performs the
   kernel-level `RESOLVE_BENEATH` confinement. `brix_auth_gate()`
   (`../path/auth_gate`) authorizes the lookup (`BRIX_AUTH_LOOKUP`).
6. **Iterate:** `fdopendir` → `readdir`; per entry, skip `.`/`..`, skip
   control-byte names, optionally `fstatat(AT_SYMLINK_NOFOLLOW)` for stat,
   optionally compute the checksum token via `dcksm.c`.
7. **Frame & flush:** when the buffer would overflow, write a `kXR_oksofar`
   header (`brix_build_resp_hdr`) and `brix_queue_response()` the chunk
   (`../response` / connection send path); the final partial buffer is sent as
   `kXR_ok`. The last byte of the final block is NUL-terminated per wire
   convention.
8. **Account & log:** bump `BRIX_OP_OK(... BRIX_OP_DIRLIST)` metrics
   (`../metrics`) and `brix_log_access()` (`../path/access_log`).

**Calls out to:** `../path/` (extract/confine/auth/access-log), `../manager/`
(server selection in manager mode), `../compat/checksum.{c,h}` +
`../compat/integrity_info.h` (digest compute + xattr cache), `../response` /
connection send for framing, `../metrics` for counters, and optionally
`../aio/dirlist.c` for the thread-pool variant.

## Invariants, security & gotchas

- **Kernel-confined directory open is mandatory.** The directory is opened with
  `brix_open_beneath(conf->rootfd, reqpath, O_RDONLY|O_DIRECTORY)`
  (`handler.c:205`) — never a raw `open()` on a client path. Entry files for
  checksums are opened with `openat(dfd, name, O_RDONLY|O_CLOEXEC|O_NOFOLLOW)`
  relative to the already-confined directory fd (`dcksm.c:131`), and
  `fstatat(..., AT_SYMLINK_NOFOLLOW)` is used for stat — symlinks are never
  followed out of the export root.
- **Control bytes corrupt the wire format.** Entries are separated by `'\n'`;
  any name byte `< 0x20` or `== 0x7f` would be read as a record separator by the
  client. `brix_dirlist_name_is_unsafe()` silently drops such entries and logs
  the name *sanitized* via `brix_sanitize_log_string()` (never the raw name).
- **`kXR_dcksm` implies `kXR_dstat`.** Checksums are only computed for entries
  that successfully stat *and* are regular files; otherwise the token is
  `algo:none` (directories, specials, open/hash failures). The stat body in
  checksum mode is the 9-field form (`dcksm.c`), distinct from the plain dstat
  body produced by `brix_make_stat_body()`.
- **Fail-closed checksum negotiation.** An unsupported `cks.type=` value aborts
  the whole request with `kXR_ServerError` (`handler.c:90-102`); it does not
  silently fall back to `adler32`.
- **Per-connection memory cap.** Before allocating the 64 KiB chunk the handler
  checks `ctx->pool_bytes_used + ... > BRIX_MAX_CONN_POOL_BYTES` and closes the
  connection with `kXR_NoMemory` on breach (`handler.c:231`) — a guard against a
  flood of dirlist calls exhausting the connection pool. The allocation is
  charged back into `ctx->pool_bytes_used`.
- **Event-loop discipline.** The live path runs `readdir`/`fstatat`/hashing
  synchronously on the event loop — acceptable because each call is bounded and
  the response is chunk-flushed, but it is the reason the AIO offload exists. The
  AIO path is intentionally disabled (`if (0 && conf->common.thread_pool ...)`,
  `handler.c:151`) because it could complete without emitting a frame and wedge
  `xrdfs` readiness probes; do not re-enable without fixing that.
- **`PATH_MAX` truncation.** When building `full_path/name` for the checksum
  path, an overflow yields an `algo:none` token rather than a truncated/incorrect
  path (`handler.c:316`).
- **Manager mode never lists locally.** Reviewers debugging "empty listing on a
  redirector" should remember step 4 short-circuits to a redirect; the data
  server performs the real enumeration.

## Entry points / extending

- **Add a new dirlist option/sub-mode:** branch on a new `req->options` bit in
  `handler.c` (mirror how `want_stat` / `want_cksum` are derived). Keep the
  emitted bytes inside the chunked-flush loop so large directories still frame
  correctly.
- **Add a new checksum algorithm:** it is centralized — extend
  `brix_checksum_parse()` / the integrity layer in `../compat/`; `dcksm.c`
  picks it up automatically through `brix_dirlist_checksum_algorithm()` and
  `brix_integrity_get_fd()`. Do not hardcode algorithm logic in `dirlist`.
- **Adjust framing/chunk size:** change `chunk_cap` (64 KiB) in `handler.c`; the
  `XRD_RESPONSE_HDR_LEN` reservation and `kXR_oksofar`/`kXR_ok` boundary logic
  must stay intact.
- **Re-enable AIO offload:** work in `../aio/dirlist.c` and the gated block in
  `handler.c`; the offload context (`brix_dirlist_aio_t`) and the 4 MiB
  `BRIX_DIRLIST_AIO_RESPONSE_MAX` cap are defined in `../aio/aio.h`.

## See also

- `../handshake/README.md` — read-opcode dispatcher that invokes this handler
- `../path/README.md` — `RESOLVE_BENEATH` confinement, path extraction, auth gate, access log
- `../manager/README.md` — `brix_srv_select()` server selection for manager-mode redirects
- `../aio/README.md` — thread-pool offload variant (`dirlist.c`) and `brix_dirlist_aio_t`
- `../compat/README.md` — checksum / integrity (xattr-cached digest) helpers
- `../read/README.md` — sibling stat/open/read stream operations sharing the export root
- `../webdav/README.md` — `PROPFIND`, the HTTP enumeration of the same export
- `../s3/README.md` — `ListObjectsV2`, the S3 enumeration of the same export
- `../README.md` — master subsystem index
