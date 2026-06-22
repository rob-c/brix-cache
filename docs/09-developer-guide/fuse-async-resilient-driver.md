# Async, network-resilient FUSE driver (`xrootdfs`)

**Status:** implemented and validated (2026-06). This async core is the **default**
`xrootdfs` driver; the simple synchronous driver is kept as a `--legacy` mode of
the same binary (`xrd mount --legacy`).

## Why

The simple synchronous driver (`xrootdfs --legacy`) is solid on a LAN but is built on
a **blocking, one-request-in-flight, connect-per-file, no-retry** client core. On a
poor link (high RTT, jitter, transient disconnects, server restarts — "bad wifi from
a laptop abroad") that means serialized throughput, multi-second stalls, and a
transient drop surfaced to the application as `EIO`. `xrootdfs` is a ground-up async
rewrite of the client transport plus a driver that is **faster** (pipelining
hides RTT), **reliable** (transparent reconnect), and **network-tolerant** (an
in-progress transfer survives a drop / restart byte-exact, with no `EIO`) — so it is
the default. It also speaks an http(s)/WebDAV read-only transport (see below).

It remains clean-room: only `libxrdc` + `libxrdproto` + `libfuse3` + OpenSSL/zlib,
no `libXrdCl`/`libXrdSec`/`XrdFfs` (asserted by `ldd`).

## Architecture (bottom to top)

All of the new transport lives in `client/lib/aio.c` / `aio.h` (the event loop) and
`client/lib/aio_mgr.c` (the connection manager + resilient open file). The driver
is `client/apps/xrootdfs.c` (the synchronous fallback is `client/apps/xrootdfs_legacy.c`).

### 1. Async transport core — `aio.c`

One `epoll` event loop runs on its own thread and owns **all** per-connection state
(an outgoing byte queue, an incoming parse buffer, and an in-flight
`streamid → request` map). Other threads never touch that state: they post onto a
mutex-guarded command queue and kick an `eventfd`; the loop drains the queue and
does every socket read/write itself. So the data plane needs no per-field locking.

* A connection is brought up **synchronously** the usual way (`xrdc_connect`:
  connect → [TLS] → login → auth), then its fd is set non-blocking and handed to
  the loop with `xrdc_aconn_attach`.
* Many requests are in flight at once over one socket (pipelining), demultiplexed
  by the wire's per-request `streamid`. `kXR_oksofar` partial frames accumulate
  into one reply before the completion callback fires.
* `xrdc_aio_submit` is fire-and-forget (callback on the loop thread);
  `xrdc_aio_call` is a blocking submit-and-wait wrapper. The FUSE worker threads
  call the blocking form, and the many concurrent calls pipeline over the shared
  socket — that is the throughput win.
* Cleartext and **non-blocking TLS** (an `SSL_read`/`SSL_write`
  `WANT_READ`/`WANT_WRITE` state machine) are both handled. Cleartext sends use
  `MSG_NOSIGNAL`; apps additionally ignore `SIGPIPE` for the TLS path.

> Limitation: a GSI **request-signing** session cannot pipeline (each request
> would need an inline `kXR_sigver` round-trip), so `xrdc_aconn_attach` rejects it
> and the caller falls back to the synchronous pool.

### 2. Resilience layer — `aio.c` (+ `sock.c`, `status.c`)

* **Adaptive deadlines.** A smoothed RTT estimate (RFC-6298 `srtt + 4·rttvar`,
  clamped) yields a per-request deadline when the caller does not specify one — a
  slow link gets patience, a fast link fails promptly, all bounded.
* **Transparent reconnect.** On a transport drop the connection enters a
  `RECONNECTING` state and a **worker thread** re-establishes the session (off the
  loop thread, so other connections keep flowing) with exponential backoff + jitter
  up to a `max_stall` budget. It signals the loop via a flag + the `eventfd`; no
  raw connection pointer is passed back, so there is no use-after-free if the
  connection is closed mid-reconnect.
* **Request parking.** Retry-safe (idempotent, non-handle) requests that were in
  flight at the drop are parked and re-issued on the new socket; new submissions
  during the reconnect are parked too (they were never sent). Non-retry-safe
  requests fail so the layer above can recover (see §3).
* **Socket tuning + heartbeat.** `TCP_NODELAY` + `SO_KEEPALIVE` on every socket; a
  `kXR_ping` heartbeat on an idle link, whose own timeout is promoted to a
  transport error so a silently-dead link is detected without waiting for real
  traffic.
* **Retryable vs fatal.** `xrdc_status_retryable` classifies transport faults /
  `Overloaded` / `noserver` / `ServerError` as transient; auth / not-found /
  bad-arg / exists / checksum as fatal (retrying cannot help).

### 3. Connection manager + file-handle resumption — `aio_mgr.c`

An XRootD file handle is valid **only on the session that opened it**, so a
reconnect invalidates it. `xrdc_mfile` is an open file that survives a drop:

* It is a blocking façade over the loop (each `pread`/`pwrite` is one
  `xrdc_aio_call`; the many FUSE workers pipeline over the shared connection).
* On a transport failure **or** a stale handle (`kXR_FileNotOpen`), it **reopens**
  the file non-destructively (writable → update-in-place, never re-truncating;
  read → open-read) and **re-issues** the read/write at the same absolute offset.
  Re-issuing the identical offset is idempotent, so no data is lost or duplicated.
* A per-file mutex + generation counter makes concurrent callers reopen **at most
  once** and then reuse the fresh handle. Bounded by `max_stall` (wall) and
  `max_retries`.

`xrdc_mgr` ties it together: the loop plus a small pool of attached connections,
round-robined for new files and for metadata calls.

### 4. The driver — `xrootdfs.c`

A hybrid that reuses the proven libxrdc code:

* **Metadata** (`getattr`, readdir-plus, `mkdir`, `chmod`, `statfs`, `xattr`, …)
  runs the existing synchronous ops on a thread-safe pool, wrapped in a small
  retry-on-transient harness (`xfs_meta`) so a brief drop is ridden out.
* **File I/O** uses `xrdc_mfile` on the async manager, under the same read-ahead /
  write-back buffering as the classic driver.
* `SIGPIPE` is ignored at startup. New options: `--streams`, `--max-stall`,
  `--keepalive`, `--max-retries` (plus the classic cache/buffering/`--xattr`).

### 5. Alternate transport — HTTP(S)/WebDAV — `webfile.c`

When the endpoint scheme is `http`/`https`/`dav`/`davs`, the same namespace is
mounted **read-only** over HTTP/WebDAV instead of root://, so one driver can serve
either protocol against this module *or* an official XRootD `XrdHttp` endpoint —
the basis for an apples-to-apples **root-vs-https** comparison.

* **`getattr`/`readdir`** issue `PROPFIND` (Depth 0 / 1). The multistatus XML is
  scraped **namespace-prefix- and attribute-tolerantly** (`D:`, `lp1:`, none; open
  tags with or without attributes) via `next_response_open`/`next_response_close`,
  so nginx (`<D:response>`) and XrdHttp (`<D:response xmlns:lp1="DAV:" …>`) both
  parse. Directory detection keys on a `collection` element by **exact local
  name** — rejecting `<D:collection-set/>` (DAV ACL on files) and
  `<lp1:iscollection>0</lp1:iscollection>` (substring `collection>`), which a naive
  match mislabels as dirs.
* **Reads** use HTTP `Range` `GET` over a **persistent keep-alive** socket (so
  sequential FUSE reads don't pay a TCP+TLS handshake each), with one transparent
  reconnect on a dropped link. Responses are framed by `Content-Length` (or
  chunked) — **never read-to-EOF** — because `XrdHttp` advertises
  `Connection: Close` yet keeps the socket open, which would otherwise hang every
  request until timeout. The buffered metadata path (`http.c httpx_exchange`)
  applies the same framing.
* Writes return `EROFS`; auth is anonymous or `--token`/`$BEARER_TOKEN`;
  `--noverifyhost` skips the (usually self-signed) server-cert check.
* A URL `/base` path component roots the mount at that subtree for **either**
  transport (`srv_path`), e.g. `root://h/data` or `https://h/data`.

`client/bench_fuse_protocols.py` mounts the same file over each transport (a fresh
cold mount per iteration) and reports median MB/s plus an md5 cross-check.

## Testing

| Layer | Test | What it proves |
|---|---|---|
| M1 transport | `tests/c/aio_smoke.c` (`make -C client aio-smoke`) | 256 concurrent pings, 64+4 concurrent reads (incl. large reads forcing `oksofar`) byte-exact, 8×50 multi-threaded blocking calls — demux + accumulation + pipelining |
| M2 resilience | `tests/c/aio_resil.c` (`make -C client aio-resil`) | 200 retry-safe requests survive a mid-stream server kill+restart, 0 failures |
| M3 resumption | `tests/c/aio_mfile.c` (`make -C client aio-mfile`) | a 4 MiB read **and** write survive a mid-transfer server bounce, byte-exact |
| M4 driver | `tests/test_xrootdfs.py` (default `XROOTDFS_BIN=xrootdfs`) | the full existing FUSE/preload suite (16) passes unchanged |
| M6 end-to-end | `tests/test_xrootdfs_resilience.py` + `tests/c/fault_proxy.c` | mount through a fault proxy: high latency, a mid-read connection drop, and a 2 s outage — all byte-exact, no `EIO` |
| HTTP transport | `tests/test_xrootdfs_http.py` | root:// vs http/WebDAV (and opt-in official root:// vs `XrdHttp`) read byte-exact, list correctly, return identical bytes cross-protocol, and the HTTP mount is read-only (`EROFS`) |

The fault proxy (`fault_proxy.c`, `make -C client fault-proxy`) is a root-free TCP
relay with a control port (`latency <ms>` / `drop` / `block` / `unblock`). It does
**not** simulate packet loss — dropping bytes from an already-ACKed TCP stream
would corrupt it rather than emulate loss, which lives below TCP; latency,
disconnect, and outage are the faithfully-simulatable faults and are exactly what
the resilience layer must survive. A `tc/netem` path (needs `CAP_NET_ADMIN`) is an
optional complement.

Example run against a private server:

```bash
make -C client xrootdfs fault-proxy
TEST_ROOT=/tmp/xrd-aio TEST_NGINX_ANON_PORT=11199 TEST_SKIP_SERVER_SETUP=1 \
  PYTHONPATH=tests python3 -m pytest tests/test_xrootdfs_resilience.py -v
```

## POSIX-completeness extensions (set-mtime / chown / symlink / hard link)

XRootD has no base-protocol opcode for set-mtime, chown, or links, so these are
**capability-negotiated vendor opcodes** — `kXR_setattr` (3500), `kXR_symlink`
(3501), `kXR_readlink` (3502), `kXR_link` (3503), defined in
`src/protocol/wire_vendor_ext.h`, well above the standard range. The server
advertises support via `kXR_Qconfig "xrdfs.ext"`; the client probes it
(`xrdc_ext_probe`) and only emits the opcodes when advertised, so a stock XRootD
server never receives one and a stock client never triggers the handlers.

* **Server** (`src/write/ext_ops.c`): handlers do confined `utimensat`/`fchownat`/
  `symlinkat`/`readlinkat`/`linkat` under the export jail (new
  `xrootd_setattr/symlink/readlink_confined_canon` in `resolve_confined_ops.c`,
  reusing the existing `xrootd_link_confined_canon`); registered in the write
  dispatcher (setattr/symlink/link) and read dispatcher (readlink).
* **lstat for getattr**: a vendor `kXR_statNoFollow` option on `kXR_stat` (honoured
  by `xrootd_lstat_beneath`, `O_PATH|O_NOFOLLOW`) lets the FUSE `getattr` see a
  symlink as `S_IFLNK` (default stat still follows, so other clients are
  unaffected). `xrdc_lstat` is the client side.
* **Client** (`client/lib/ops_ext.c`): `xrdc_setattr/symlink/readlink/link` +
  `xrdc_ext_probe`. **Driver**: `utimens`/`chown` use `setattr` when advertised
  (else accepted no-ops so `cp -p` still works); `symlink`/`readlink`/`link` are
  registered and gated (ENOTSUP when unadvertised); the mount banner reports the
  negotiated set.
* **Build**: new `.c` files → `./configure` + `make` for the module (the protocol
  header is shared, so a clean rebuild of both module and client).
* **Tested**: `tests/test_xrootdfs_ext.py` (5) — capability banner, setattr mtime
  round-trip, symlink to existing + dangling, hard-link inode sharing — plus the
  16 FUSE regression tests stay green (the lstat change does not regress stat).

### readdir-plus shows symlinks as links

`ls -l <dir>` over the mount reports a symlink as a symlink, not its target: both
dirlist stat paths (`src/dirlist/handler.c`, `src/aio/dirlist.c`) stat each entry
with `fstatat(..., AT_SYMLINK_NOFOLLOW)`, so `xrootd_make_stat_body` flags it
`kXR_other`, the client carries that in `xrdc_dirent.st.flags`, and `xfs_readdir`
maps it to `S_IFLNK` via `FUSE_FILL_DIR_PLUS` — matching local `ls -l` (lstat)
semantics. (Covered by `tests/test_xrootdfs_ext.py::test_readdir_reports_symlink`.)

## Not yet done

* Per-op Prometheus counters for the vendor ops. They reuse existing op slots
  (CHMOD/MKDIR/STAT) and the access log records the precise verb. A dedicated-slot
  version was prototyped (bump `XROOTD_NOPS`, add names) but **reverted**: it adds
  an SHM-struct-ABI change for no observed benefit — and surfaced a *pre-existing*
  quirk where a single op on a round-robin pooled connection is not reliably
  reflected in the per-listener counters (high-frequency ops mask it). Investigate
  the per-connection metrics-slot assignment separately before re-attempting.
* Async read-ahead **prefetch** (submit-ahead) — the current read-ahead coalesces
  into larger synchronous reads; a true background prefetch is a future refinement.
  Deferred: it is the highest-risk item (async use-after-free on close, must keep
  resilience intact) and its throughput win is structural under latency but not
  measurable as wall-clock MB/s on the loopback dev host. Design is in
  `.claude/plans/fizzy-finding-beaver.md` (workstream C): a best-effort
  `xrdc_mfile_pread_async` + a per-handle prefetch buffer with a drain-before-free
  barrier, gated behind `--prefetch`, validated under ASan.
