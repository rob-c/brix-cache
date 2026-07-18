# Phase-86 — FUSE client connection reuse: pooled keep-alive WebDAV metadata

**Goal:** close the one remaining per-request connect/teardown in the FUSE
client — the **xrootdfs web-metadata path** (`getattr`/`readdir` over
http/https/dav) — by giving it **pooled, keep-alive** connections, and do it by
**generalizing the connection-pool skeleton the codebase already has**
(`brix_pool`) rather than writing a second pool. Motivated by the recent
brixcvmfs work that made the CVMFS FUSE driver reuse origin/proxy connections
(persistent libcurl handle). This phase brings the *same benefit* to xrootdfs
web mounts and *unifies* the pool machinery across the two `brix_io`-family
consumers.

**Provenance:** anchors below read from the tree at working state on
**2026-07-18** (post-`8e15882c`, uncommitted P82/P85/guard/frm work in the
tree). Re-verify every `file:line` at the start of each step and mark drift
`DRIFT:` inline (phase-80 convention) — the client tree is under active churn.

**Reading order for the implementer:** §0 (why) → §2 (the three new units, with
full headers) → §8 (the line-by-line migration map — this is the actual work) →
§9 (exact rewiring diffs) → §10 (full test code) → §11 (build edits). §3–§7 are
the surrounding rationale/plan/risk framing.

---

## 0. Findings that shape the design (audit, 2026-07-18)

Three **distinct** connection-lifetime models exist in `client/`. Only two of
them are on a shared transport and can share code.

| Driver / path | Transport | Reuse today | Anchor |
|---|---|---|---|
| **brixcvmfs** | **libcurl**, single-threaded (`-s`), per-actor handle | ✅ libcurl connection cache | `apps/fs/brixcvmfs.c:83,87` (`g_curl`), `:269` (prefetch worker's own `curl`), `:941` (`-s`) |
| xrootdfs **root://** | `brix_conn` binary, multithreaded | ✅ `brix_pool` (sync meta) + `brix_mgr` (async data, kXR_ping heartbeats) | `lib/net/pool.c`, `lib/core/aio/` |
| xrootdfs web **read** | `brix_io`/`brix_tls` | ✅ persistent keep-alive socket on `brix_webfile` | `webfile_io.c:29` (`web_connect`), `:133` (`Connection: keep-alive`), `:248` (drain), `:399` (reconnect-resume) |
| xrootdfs web **metadata** | `brix_io` via `brix_http_req` | ❌ **connect + close per call** | `webfile.c:132,368` → `http_req.c:315` (`httpx_connect`→exchange→`close`, `:326/338/344`); `Connection: close` at `http_req.c:139` |

**The measurable cost today.** On an HTTPS/WebDAV mount, `ls -l` of an
N-entry directory = 1 PROPFIND(Depth:1) + up to N getattr PROPFIND(Depth:0),
and **each one** pays a fresh TCP + TLS handshake (`brix_http_req` →
`httpx_connect` → `brix_tls_client` → `close`). On a 20 ms-RTT WAN link with
TLS 1.3 that is ~2 RTT/op of pure handshake — tens of ms per file that pooling
+ keep-alive eliminate after the first op. The read path already avoids this;
metadata is the lone straggler.

**Consequence for the "merge both drivers" request:**

- **brixcvmfs cannot share *transport* code with xrootdfs.** It is libcurl +
  single-threaded *by deliberate design* — env-proxy resolution
  (`brix_proxy_resolve`, `brixcvmfs.c:121`), CVMFS-config proxy precedence
  (`:127`), and `FRESH_CONNECT`/`FORBID_REUSE` DPI-hardening (`:117-118`).
  It **already reuses** connections via libcurl's cache, so wrapping its
  handles in a generic pool buys **no reuse and no concurrency** (single-
  threaded). Original decision: out of scope. **Superseded 2026-07-18** — the
  handle *lifecycle* (not the transport) was subsequently wrapped in
  `brix_cpool` purely for **uniformity** across the two FUSE drivers, on
  explicit request. The libcurl transport body is unchanged; only the two ad-hoc
  `CURL*` globals became pooled slots. See §15.
- The code that genuinely unifies is the **pool skeleton**, shared between the
  two `brix_io`-family consumers: root:// (`brix_pool`) and the new
  web-metadata pool. `brix_pool`'s slot/mutex/condvar/health-drop bookkeeping
  is already generic *in shape* — it only hardwires the `brix_conn` type and
  `brix_connect`/`brix_close` (`pool.c:27,49,154,183`).

**Hard constraint — `brix_http_req` is a frozen one-shot contract.** Signature
(`brix_net.h:289`):

```c
int brix_http_req(const char *host, int port, int tls, const char *method,
                  const char *path, const char *extra_headers,
                  const void *body, size_t blen, int timeout_ms, int verify,
                  const char *ca_dir, brix_http_resp *resp, brix_status *st);
```

It is consumed stateless-per-call by:

| Caller | Anchor | Notes |
|---|---|---|
| S3 backend transport | `lib/fs/backend/s3/vfs_s3_transport.c:37` | "one stateless request op, tctx unused"; injected `brix_s3_transport_t` |
| CLI `weblist` | `weblist.c:364` (GET), `:403` (MKCOL), `:537` (PROPFIND) | |
| diag tools | `diag_doctor.c:408,431,478,481,600,641`; `diag_misc.c:339,394,436`; `xrd_battery.c:356,377,436,445,452,472,580`; `xrd_clockskew.c:63`; `xrdstorascan.c:946,1262` | |
| `xrdfs` web tool | `xrdfs_web.c:122,180` (via `brix_web_stat`/`brix_web_readdir`) | keeps the **stateless** wrappers — no pool |

**This phase must not change `brix_http_req`'s signature or its
connect→exchange→close behavior.** The keep-alive metadata path is a *new*
entry point; the existing `brix_web_stat`/`brix_web_readdir` **remain** for the
non-pooled callers (`xrdfs_web.c`), and gain **pooled siblings** for the FUSE
driver (§2.3 — additive, not a rewrite of the stateless path).

**Reusable primitive already proven:** `web_get_range` (`webfile_io.c:312`)
already implements a correct keep-alive HTTP/1.1 exchange over a persistent
`brix_io` — send `Connection: keep-alive`, require `Content-Length`, **drain
the body to stay socket-aligned** (`:288-299`), reconnect-on-sever. The
metadata PROPFIND reuses *this* pattern, not `brix_http_req`.

---

## 1. Scope & non-goals

**In scope:**
- Generalize `brix_pool` → a transport-agnostic slot pool (`brix_cpool`, §2.1).
- New keep-alive WebDAV metadata connection (`brix_webmeta`) + a `PROPFIND`
  exchange over a persistent `brix_io`, factored to share **one** keep-alive
  codec with the read path (§2.2).
- A **small metadata connection pool** (sized by the existing `--max-conns`
  knob, `xrootdfs.c:14`) for the xrootdfs web mount; route `getattr`/`readdir`
  + mount probe + `brix_webfile_open`'s initial stat through it (§2.3, §9).
- 3-test set per change (success + error + security-negative) + a pool unit
  test (§10).

**Non-goals:**
- **brixcvmfs** — no change (§0; already reuses via libcurl).
- **root:// semantics** — `brix_pool`'s external API and behavior stay
  **byte-for-byte identical**; it becomes a thin adapter over the generic core.
- **`brix_http_req`** and its callers (S3/weblist/diag/xrdfs) — untouched. The
  stateless `brix_web_stat`/`brix_web_readdir` stay put for `xrdfs_web.c`.
- Application-level idle heartbeats for the HTTP pool (the `brix_mgr` kXR_ping
  analogue, `aio_conn.c:198`) — deferred (§7 follow-up). Keep-alive +
  reconnect-on-sever is sufficient for the metadata cadence; a server that
  reaps an idle keep-alive socket just triggers one reconnect on next use.

---

## 2. The three new/changed units (with full headers)

### 2.1 `lib/net/cpool.{c,h}` — generic slot pool

Extract the engine from `pool.c` into a transport-agnostic core parameterized by
a tiny vtable. The pool owns **opaque** per-slot connection memory; the vtable
knows how to connect/close it.

```c
/* lib/net/cpool.h (new) — a thread-safe pool of opaque connections.
 *
 * WHAT: brix_cpool_create/checkout/checkin/destroy over a caller-defined
 *       connection type. Generalises lib/net/pool.c (which is now a thin
 *       brix_conn adapter over this) so the HTTP metadata path and the binary
 *       root:// path share ONE slot/mutex/condvar/health-drop implementation.
 * WHY:  a connection is one-op-in-flight and not thread-safe; a multi-threaded
 *       consumer (the FUSE driver) needs N independent connections. The pool is
 *       the concurrency primitive; the *transport* is a parameter.
 * HOW:  one mutex guards slot bookkeeping only (never held across connect/op);
 *       a condvar wakes a waiter on checkin; the vtable connects/closes the
 *       opaque per-slot memory. No goto. Clean-room (libc + pthread only).
 */
#ifndef BRIX_CPOOL_H
#define BRIX_CPOOL_H
#include "brix.h"
#include <stddef.h>

typedef struct {
    size_t conn_size;                                    /* bytes of slot memory */
    int  (*connect)(void *conn, void *ctx, brix_status *st); /* bring a slot up  */
    void (*close)(void *conn);                               /* tear a slot down */
} brix_cpool_vtbl;

typedef struct brix_cpool brix_cpool;

/* Create a pool of `n` slots. `ctx` is passed verbatim to every connect() (the
 * shared endpoint/opts template; the pool does NOT copy or own it — it must
 * outlive the pool). Slot 0 is connected eagerly so a bad endpoint/auth fails
 * up front. NULL + st on failure. n clamped to [1,256]. */
brix_cpool *brix_cpool_create(const brix_cpool_vtbl *vt, void *ctx, int n,
                              brix_status *st);

/* Borrow a connected slot's conn memory, blocking until one is free; reconnects
 * a dropped slot transparently. NULL + st only if (re)connect fails. */
void *brix_cpool_checkout(brix_cpool *p, brix_status *st);

/* Return a checked-out conn. healthy==0 drops it (close + mark unconnected) so
 * the next checkout reconnects on a clean session. `conn` must be a pointer a
 * prior checkout returned. */
void  brix_cpool_checkin(brix_cpool *p, void *conn, int healthy);

void  brix_cpool_destroy(brix_cpool *p);   /* closes all connected slots */

#endif /* BRIX_CPOOL_H */
```

`cpool.c` is `pool.c:26-190` with three edits, nothing more:

1. `brix_pool_slot.conn` becomes a **flexible tail** of `conn_size` bytes (or a
   `void *conn` heap block); slots become `{ int connected; int in_use; /* +
   conn_size bytes */ }`. Simplest: `slots = calloc(n, sizeof(hdr) +
   conn_size)` with a stride accessor, or an array of `{connected,in_use,void
   *conn}` where `conn = calloc(1, conn_size)` per slot. **Chosen: per-slot
   `void *conn` heap block** (clearer ownership, no stride math, matches the
   "opaque" contract). Allocation failure of any slot block fails create.
2. `pool_slot_connect` calls `p->vt.connect(slot->conn, p->ctx, st)` instead of
   `brix_connect(&s->conn, &p->url, &p->opts, st)`.
3. checkin/destroy call `p->vt.close(slot->conn)` instead of
   `brix_close(&slot->conn)`.

The slot-matching in checkin (`pool.c:151-159,163-168`) keys on `slot->conn ==
conn` (pointer identity) exactly as today (`&p->slots[i].conn == c`).
Everything else — the eager slot-0 connect (`pool.c:90-96`), the
connect-outside-lock discipline (`:125-135`), the linear free scan +
`pthread_cond_wait` (`:112-124`), the health-drop (`:150-160`) — is **copied
verbatim**.

**`brix_pool` becomes a thin adapter** (`pool.c` rewritten, same public API at
`brix_net.h:592-605`, zero caller changes):

```c
/* lib/net/pool.c (rewritten) — brix_conn adapter over brix_cpool. */
#include "brix.h"
#include "net/cpool.h"
#include <stdlib.h>

typedef struct { brix_url url; brix_opts opts; } pool_ctx;   /* connect template */

static int pool_conn_connect(void *conn, void *ctx, brix_status *st) {
    pool_ctx *c = ctx;
    return brix_connect((brix_conn *) conn, &c->url, &c->opts, st);
}
static void pool_conn_close(void *conn) { brix_close((brix_conn *) conn); }

static const brix_cpool_vtbl POOL_VT = {
    sizeof(brix_conn), pool_conn_connect, pool_conn_close,
};

struct brix_pool { brix_cpool *cp; pool_ctx ctx; };   /* ctx outlives cp */

brix_pool *brix_pool_create(const brix_url *u, const brix_opts *o, int n,
                            brix_status *st) {
    brix_pool *p;
    if (u == NULL || n < 1) { brix_status_set(st, XRDC_EUSAGE, 0, "pool: bad arguments"); return NULL; }
    p = calloc(1, sizeof(*p));
    if (p == NULL) { brix_status_set(st, XRDC_ESOCK, 0, "pool: out of memory"); return NULL; }
    p->ctx.url = *u;
    if (o != NULL) p->ctx.opts = *o;
    p->cp = brix_cpool_create(&POOL_VT, &p->ctx, n, st);   /* &p->ctx: stable */
    if (p->cp == NULL) { free(p); return NULL; }
    return p;
}
brix_conn *brix_pool_checkout(brix_pool *p, brix_status *st) {
    if (p == NULL) { brix_status_set(st, XRDC_EUSAGE, 0, "pool: null"); return NULL; }
    return (brix_conn *) brix_cpool_checkout(p->cp, st);
}
void brix_pool_checkin(brix_pool *p, brix_conn *c, int healthy) {
    if (p != NULL) brix_cpool_checkin(p->cp, c, healthy);
}
void brix_pool_destroy(brix_pool *p) {
    if (p == NULL) return;
    brix_cpool_destroy(p->cp);
    free(p);
}
```

**Behavioral equivalence checklist** (must hold, verified by the root:// suites
gating Step 2): (a) eager slot-0 connect fails `create` up front; (b) checkout
blocks when all busy and wakes on checkin; (c) `healthy==0` reconnects next
checkout; (d) n clamp `[1,256]`; (e) the `ctx` pointer handed to `brix_cpool`
(`&p->ctx`) is stable for the pool's lifetime (stored inside the heap `brix_pool`
— **not** a stack temporary; this is the one subtle correctness point of the
adapter).

### 2.2 `lib/protocols/http/web_ka.{c,h}` — shared keep-alive codec + `brix_webmeta`

Factor the reusable keep-alive machinery **out of `webfile_io.c`** so the read
path and the metadata path run one implementation, then add the metadata
connection on top.

**Shared transport struct** (generalise `brix_webfile`'s persistent-transport
fields, `webfile_internal.h:22-37`, into a standalone type both structs embed):

```c
/* web_ka.h (new) */
#ifndef BRIX_WEB_KA_H
#define BRIX_WEB_KA_H
#include "brix.h"

/* A persistent, keep-alive HTTP/1.1 connection to one origin (cleartext or TLS).
 * One request in flight; NOT thread-safe (pool or per-handle-mutex it). */
typedef struct {
    brix_io  io;                 /* fd + ssl + timeout */
    void    *tls_ctx;            /* SSL_CTX* when tls, else NULL */
    int      connected;
    char     host[256];
    int      port;
    int      tls;
    int      verify;
    char     ca_dir[512];        /* "" => default resolver */
    char     hostport[300];      /* Host: header value (IPv6-bracketed) */
    int      timeout_ms;
} brix_kaconn;

/* connect / disconnect (lifted verbatim from webfile_io.c web_connect/
 * web_disconnect, keyed on brix_kaconn instead of brix_webfile). */
int  brix_kaconn_connect(brix_kaconn *k, brix_status *st);
void brix_kaconn_disconnect(brix_kaconn *k);
void brix_kaconn_init(brix_kaconn *k, const char *host, int port, int tls,
                      int verify, const char *ca_dir, int timeout_ms);

/* Read one framed keep-alive response: fill *hbuf (caller-owned, >= WEB_HDR_MAX+1),
 * return via out-params the status, Content-Length, and where the body starts /
 * how many body bytes are already buffered. Disconnects k on any socket/oversize
 * fault. -1 err (st set), 0 = status 416, 1 = 2xx with Content-Length. Lifted
 * from web_range_read_headers (webfile_io.c:165). */
typedef struct {
    int       status;
    long long clen;
    char     *body_start;   /* into hbuf, just past CRLFCRLF */
    size_t    body_buffered;/* body bytes already sitting in hbuf */
} brix_ka_hdr;
int  brix_kaconn_read_headers(brix_kaconn *k, char *hbuf, size_t hbufsz,
                              brix_ka_hdr *out, brix_status *st);

/* Read exactly clen body bytes into a freshly malloc'd *body_out (NUL-terminated),
 * seeding from the already-buffered overflow, reading the rest, keeping the socket
 * aligned. Ownership transfers to the caller (free()). Disconnects on sever.
 * Generalises the drain logic of web_range_stream_body (webfile_io.c:248). */
int  brix_kaconn_read_body(brix_kaconn *k, const brix_ka_hdr *hdr,
                           char **body_out, size_t *len_out, brix_status *st);

#endif
```

The **read path** (`web_get_range`, `webfile_io.c:312`) is refactored to sit on
`brix_kaconn_connect` / `brix_kaconn_read_headers` and keeps its *own* body step
(it streams into a caller buffer with partial-progress resume — subtly different
from "malloc the whole body", so `web_range_stream_body` stays but calls the
shared header reader). This keeps the read path's proven partial-resume
semantics intact while de-duplicating connect + header parsing. `brix_webfile`
gains a `brix_kaconn ka;` member and its `host/port/tls/verify/ca_dir/hostport/
io/tls_ctx/connected/timeout_ms` fields collapse into it (mechanical rename;
`webfile_io.c` call sites updated).

**The metadata connection** (`brix_webmeta`) is `brix_kaconn` + auth template +
the PROPFIND exchange:

```c
/* web_ka.h (cont.) */
typedef struct {
    brix_kaconn ka;
    char        auth[2200];      /* "Authorization: Bearer ...\r\n" or "" — one
                                    identity per conn; pooling never crosses it */
} brix_webmeta;

/* Fill a brix_webmeta template (does NOT connect — the pool connects lazily). */
void brix_webmeta_init(brix_webmeta *m, const char *host, int port, int tls,
                       int verify, const char *ca_dir, const char *bearer,
                       int timeout_ms);

/* Keep-alive PROPFIND of `path` at `depth` (0 = stat, 1 = readdir). On success
 * *body_out/*len_out own the response body (free()). Reconnect-on-sever within
 * the deadline window (webfile_window_ms()). Maps status → kXR: 404 NotFound,
 * 401/403 NotAuthorized, 207/200 ok, else EPROTO. Socket/proto faults set
 * XRDC_ESOCK/EPROTO (→ pool health-drop). -1 err / 0 ok. */
int brix_webmeta_propfind(brix_webmeta *m, const char *path, int depth,
                          char **body_out, size_t *len_out, brix_status *st);
```

`brix_webmeta_propfind` body (mirrors `brix_webfile_pread`'s resilient loop,
`webfile_io.c:399-459`):

```c
int brix_webmeta_propfind(brix_webmeta *m, const char *path, int depth,
                          char **body_out, size_t *len_out, brix_status *st) {
    char      hdrs[64];
    unsigned  attempt = 0;
    int       window_ms = webfile_window_ms();
    uint64_t  deadline  = brix_mono_ns() + (uint64_t) window_ms * 1000000ULL;
    *body_out = NULL; *len_out = 0;
    snprintf(hdrs, sizeof(hdrs), "Depth: %d\r\n", depth ? 1 : 0);
    for (;;) {
        if (m->ka.connected || brix_kaconn_connect(&m->ka, st) == 0) {
            /* build "PROPFIND path HTTP/1.1 Host: .. Connection: keep-alive
             * Depth: d {auth}", write, read headers, read body */
            if (webmeta_send_req(m, path, hdrs, st) == 0) {
                char        hbuf[WEB_HDR_MAX + 1];
                brix_ka_hdr h;
                int r = brix_kaconn_read_headers(&m->ka, hbuf, sizeof(hbuf), &h, st);
                if (r == 1 && webmeta_status_ok(h.status, st) == 0)
                    if (brix_kaconn_read_body(&m->ka, &h, body_out, len_out, st) == 0)
                        return 0;                          /* success */
                if (r == 0) { /* 416 impossible for PROPFIND → treat as EPROTO */ }
            }
        }
        if (window_ms <= 0 || !brix_status_retryable(st) || brix_mono_ns() >= deadline)
            return -1;
        brix_backoff_sleep_fast(attempt++);
    }
}
```

`webmeta_send_req` writes (note **PROPFIND** + keep-alive + the conn's auth,
using `brix_format_host_port` for the Host value already in `m->ka.hostport`):

```
PROPFIND {path} HTTP/1.1\r\nHost: {hostport}\r\nUser-Agent: xrootdfs\r\n
Accept: */*\r\nConnection: keep-alive\r\nDepth: {d}\r\n{auth}\r\n
```

`webmeta_status_ok`: `404 → kXR_NotFound`, `401||403 → kXR_NotAuthorized`,
`207||200 → 0`, else `XRDC_EPROTO "PROPFIND HTTP %d"`. Note the stateless
`brix_web_stat` maps 404 but **not** 401/403 explicitly (`webfile.c:136-145` →
those fall into the `!=207 && !=200` EPROTO arm); the keep-alive path adds the
explicit 401/403→`kXR_NotAuthorized` arm to match `web_range_read_headers`'s
richer mapping (`webfile_io.c:206-212`) so a token failure surfaces as
`-EACCES`, not a generic protocol error. Confirm this is the desired behavior in
review (it is stricter, not looser — see §7 decision note).

### 2.3 Pooled metadata wrappers (`webfile.c`) — additive

The XML parse layer (`parse_response`, `next_response_open/close`,
`has_collection_element`, `path_basename` — `webfile.c:54-348`) is **unchanged**
and reused as-is on the body `brix_webmeta_propfind` returns. Add two pooled
entry points **beside** the stateless ones (which stay for `xrdfs_web.c`):

```c
/* webfile.c (new, additive) — pooled keep-alive variants for the FUSE driver.
 * `pool` is a brix_cpool whose slots are brix_webmeta (vtable in xrootdfs). */
int brix_web_stat_pooled(brix_cpool *pool, const char *path,
                         brix_statinfo *si, brix_status *st);
int brix_web_readdir_pooled(brix_cpool *pool, const char *path,
                            brix_dirent **ents_out, size_t *n_out,
                            brix_status *st);
```

Each: `checkout → propfind(Depth) → parse (existing helpers) → free(body) →
checkin(healthy)`. **Use the driver's existing health predicate verbatim** — the
pooled wrapper lives in `webfile.c` (lib side, no driver globals) so it takes the
predicate as `brix_fuse_conn_healthy(st)` (`fuse_ops.c:21`), which is exactly
what the driver's `xfs_conn_healthy` (`xrootdfs.c:138`) forwards to and what the
canonical pooled op `xfs_readlink_one_attempt` (`xrootdfs_meta.c:277`) passes on
checkin: `rc == 0 ? 1 : brix_fuse_conn_healthy(st)`. So a 404/403 (protocol,
not transport) keeps the socket; an `XRDC_ESOCK`/`XRDC_EPROTO` sever drops it.
Sketch, matching the `xfs_readlink_one_attempt` idiom line-for-line:

```c
/* webfile.c (new, additive). Depth 0 = stat. */
int brix_web_stat_pooled(brix_cpool *pool, const char *path,
                         brix_statinfo *si, brix_status *st) {
    char        *body = NULL;
    size_t       blen = 0;
    brix_webmeta *m = brix_cpool_checkout(pool, st);
    int          rc;
    if (m == NULL) {
        return -1;                       /* (re)connect failed; st carries it */
    }
    rc = brix_webmeta_propfind(m, path, 0, &body, &blen, st);
    if (rc == 0) {
        rc = webdav_parse_single(body, blen, si, st);   /* extracted, below */
    }
    free(body);
    brix_cpool_checkin(pool, m, rc == 0 ? 1 : brix_fuse_conn_healthy(st));
    return rc;
}
```

`webdav_parse_single` / `webdav_parse_multi` are the **verbatim** response-parse
tails of the existing `brix_web_stat` (`webfile.c:146-169`) and
`brix_web_readdir` (`webfile.c:377-419`) lifted into shared helpers keyed on a
`(body, len)` pair instead of a `brix_http_resp` — the stateless and pooled
variants then share the parse and differ only in transport:

```c
/* webfile.c — extracted from brix_web_stat:146-169 (body+len, not brix_http_resp) */
int webdav_parse_single(const char *body, size_t blen,
                        brix_statinfo *si, brix_status *st) {
    const char *b   = body ? body : "";
    const char *end = b + blen;
    const char *rp  = next_response_open(b, end);       /* unchanged helper */
    const char *re;
    char        href[XRDC_PATH_MAX];
    if (rp == NULL) {
        brix_status_set(st, XRDC_EPROTO, 0, "PROPFIND: empty multistatus");
        return -1;
    }
    re = next_response_close(rp, end);
    if (re == NULL) { re = end; }
    if (parse_response(rp, re, si, href, sizeof(href)) != 0) {
        brix_status_set(st, XRDC_EPROTO, 0, "PROPFIND: unparseable response");
        return -1;
    }
    return 0;
}
```

The stateless `brix_web_stat` then shrinks to `brix_http_req → status-map →
webdav_parse_single(r.body, r.body_len, …) → brix_http_resp_free` — same bytes,
one fewer copy of the parse. `webdav_parse_multi` is the identical extraction of
the `while (next_response_open …)` accumulate loop (`webfile.c:380-415`),
signature `int webdav_parse_multi(const char *body, size_t blen, const char
*self, brix_dirent **ents, size_t *n, brix_status *st)`. **Pure extraction — no
behavior change to the stateless path** (regressed by `test_client_xrdfs_web.py`,
§10.3).

**The pool + its `brix_webmeta` vtable live in the driver** (xrootdfs owns the
mount-scoped template), see §9.

---

## 3. Waves / steps

**Step 1 — Generic pool core, root:// unchanged.**
- New `lib/net/cpool.{c,h}`; move engine from `pool.c`.
- Rewrite `pool.c` as the `brix_conn` adapter over `brix_cpool` (§2.1).
- Add both to `client/Makefile` LIB_SRCS (§11).
- Build; run the root:// pytest suites + any pool-touching client C-units.
  **Gate: root:// green before Step 2.** (This is the highest-risk change; it
  is isolated and independently verifiable first.)

**Step 2 — Shared keep-alive codec + metadata connection.**
- New `lib/protocols/http/web_ka.{c,h}`; extract `brix_kaconn` +
  header/body helpers out of `webfile_io.c`; add `brix_webmeta` +
  `brix_webmeta_propfind`.
- Refactor `web_get_range`/`brix_webfile` onto `brix_kaconn` (mechanical).
- Extract `webdav_parse_single`/`_multi` in `webfile.c`.
- Unit-test `brix_webmeta` directly (single conn, N PROPFINDs, one socket).

**Step 3 — Pool it + wire the driver.**
- `brix_web_stat_pooled`/`brix_web_readdir_pooled` (§2.3).
- `brix_webmeta` vtable + `g_web_pool` in `aio_web_mount` (§9); rewire the four
  metadata call sites.

**Step 4 — Tests (§10).**

**Step 5 — Build governance + validation (§11).**

---

## 4. (moved into §2 as inline code)

---

## 8. Line-by-line migration map (the actual work)

`pool.c` (191 lines) → split. Legend: **MOVE** = copy verbatim into `cpool.c`
keyed on `void*conn`/vtable; **ADAPT** = becomes the `brix_pool` wrapper.

| pool.c today | Lines | Destination | Change |
|---|---|---|---|
| `brix_pool_slot {conn,connected,in_use}` | 26-30 | cpool.c | slot = `{connected,in_use,void*conn}`; `conn = calloc(1, vt->conn_size)` |
| `struct brix_pool {url,opts,n,slots,lock,avail}` | 32-39 | cpool.c → `struct brix_cpool {vt,ctx,n,slots,lock,avail}` | drop url/opts (now in caller ctx) |
| `pool_slot_connect` | 43-54 | cpool.c | body → `vt->connect(s->conn, ctx, st)` |
| `brix_pool_create` | 56-98 | cpool.c `brix_cpool_create` + ADAPT wrapper | wrapper stores `pool_ctx`, calls core |
| `brix_pool_checkout` | 100-136 | cpool.c `brix_cpool_checkout` | returns `void*` = `s->conn` |
| `brix_pool_checkin` | 138-171 | cpool.c `brix_cpool_checkin` | `vt->close(slot->conn)`; match by `slot->conn==conn` |
| `brix_pool_destroy` | 173-190 | cpool.c `brix_cpool_destroy` | `vt->close` + free per-slot conn block |
| (new) | — | pool.c | `pool_ctx`, `POOL_VT`, 4 thin wrappers (§2.1) |

`webfile_io.c` (472 lines) → extract to `web_ka.c`:

| webfile_io.c today | Lines | Destination | Change |
|---|---|---|---|
| `web_disconnect` | 11-26 | web_ka.c `brix_kaconn_disconnect` | `brix_webfile*`→`brix_kaconn*` |
| `web_connect` | 29-47 | web_ka.c `brix_kaconn_connect` | same rename |
| `web_read_some` | 51-76 | web_ka.c `kaconn_read_some` (static) | same rename |
| `hdr_clen` | 80-94 | web_ka.c (static) | verbatim |
| `web_range_hdr_t` + `web_range_read_headers` | 108-232 | web_ka.c `brix_ka_hdr` + `brix_kaconn_read_headers` | generalise out-params |
| `web_range_stream_body` | 248-306 | **stays in webfile_io.c** | uses shared header reader; read path keeps partial-resume |
| `web_get_range` | 312-330 | stays; calls shared connect+headers | |
| `brix_webfile` struct persistent fields | webfile_internal.h:33-36 | embed `brix_kaconn ka` | field renames across webfile_io.c |
| (new) | — | web_ka.c | `brix_kaconn_read_body`, `brix_webmeta*` |

`webfile.c` (421 lines) → extract parse tails:

| webfile.c today | Lines | Destination | Change |
|---|---|---|---|
| `brix_web_stat` response-parse tail | 146-169 | `webdav_parse_single(body,len,si,st)` | takes body+len, not `brix_http_resp` |
| `brix_web_readdir` response-parse loop | 380-415 | `webdav_parse_multi(body,len,self,ents,n,st)` | `path_basename(path,self)` stays in caller |
| `brix_web_stat` (stateless) | 120-170 | **rewired**: keep `brix_http_req`+status-map, call `webdav_parse_single` | for `xrdfs_web.c` |
| `brix_web_readdir` (stateless) | 351-420 | **rewired**: keep `brix_http_req`+status-map+`path_basename`, call `webdav_parse_multi` | for `xrdfs_web.c` |
| (new) | — | webfile.c | `brix_web_stat_pooled`, `brix_web_readdir_pooled` |

---

## 9. Exact driver rewiring (`apps/fs/xrootdfs*.c`)

**New globals + vtable (`xrootdfs.c`):**

```c
/* xrootdfs.c — web-metadata pool (mirrors g_pool for root://). */
brix_cpool *g_web_pool;                     /* NULL on root:// mounts */
static brix_webmeta g_web_tmpl;             /* connect template (mount-scoped) */

static int web_slot_connect(void *conn, void *ctx, brix_status *st) {
    brix_webmeta *m = conn, *tmpl = ctx;
    *m = *tmpl;                             /* copy host/port/tls/auth template */
    m->ka.connected = 0; m->ka.io.fd = -1; m->ka.tls_ctx = NULL;  /* fresh xport */
    return brix_kaconn_connect(&m->ka, st); /* eager slot-0 fails mount up front */
}
static void web_slot_close(void *conn) { brix_kaconn_disconnect(&((brix_webmeta*)conn)->ka); }
static const brix_cpool_vtbl WEB_VT = { sizeof(brix_webmeta), web_slot_connect, web_slot_close };
```

**`aio_web_mount` (`xrootdfs.c:398-436`)** — the frame today, verbatim: locals
`brix_status st; brix_statinfo si;`; URL parse + `is_s3` reject (`:403-411`);
`g_web=1` + bearer/verify/CA/base setup (`:412-420`); the up-front reachability
probe `brix_web_stat(&g_weburl, g_base[0] ? g_base : "/", g_bearer, g_web_verify,
g_web_ca, &si, &st)` (`:422`) with a multi-line failure `fprintf` +
`return brix_shellcode(&st)` (`:423-428`); the mount banner `fprintf(stderr,
"xrootdfs: mounted %s:%d via %s%s …")` (`:429-434`); then
`return fuse_main(fuse_argc, fuse_argv, &xfs_ops, NULL);` (`:435`). Insert the
pool **between the banner and `fuse_main`**, and destroy after:

```c
    /* xrootdfs.c — after the banner fprintf (:434), replacing the bare
     * `return fuse_main(...)` at :435. Probe (:422) already validated
     * endpoint/auth/TLS, so slot-0's eager connect will not be the first
     * failure point. */
    brix_webmeta_init(&g_web_tmpl, g_weburl.host, g_weburl.port, g_weburl.tls,
                      g_web_verify, g_web_ca, g_bearer, WEB_TIMEOUT_MS);
    brix_status_clear(&st);
    g_web_pool = brix_cpool_create(&WEB_VT, &g_web_tmpl, g_max_conns, &st);
    if (g_web_pool == NULL) {
        fprintf(stderr, "xrootdfs: web pool: %s\n", st.msg);
        return brix_shellcode(&st);
    }
    int rc = fuse_main(fuse_argc, fuse_argv, &xfs_ops, NULL);
    brix_cpool_destroy(g_web_pool);
    g_web_pool = NULL;
    return rc;
```

Optionally append `meta-pool=%d` (= `g_max_conns`) to the existing banner's
format string (`:429-434`) for parity with how the root:// mount reports its
pool size (`:504`). `st`/`si` are the existing locals; no new declarations
needed.

**`xfs_getattr` (`xrootdfs_meta.c:46-54`)** — swap the stateless call for the
pooled one; nothing else changes:

```c
    if (g_web) {
        char pbuf[XRDC_PATH_MAX];
        if (brix_web_stat_pooled(g_web_pool, srv_path(path, pbuf, sizeof(pbuf)),
                                 &si, &st) != 0)
            return xfs_err(&st);
        xfs_fill_stat(&si, stbuf);
        return 0;
    }
```

**`xfs_readdir` (`xrootdfs_meta.c:81-86`)** — same swap to
`brix_web_readdir_pooled(g_web_pool, ...)`.

**Mount probe (`xrootdfs.c:422`)** — this runs *before* the pool exists (it is
the reachability check that decides whether to build the pool). Leave it on the
stateless `brix_web_stat` (one connect is fine at mount; it also validates
auth/TLS before we invest in N pooled sockets). Document inline.

**`brix_webfile_open`'s initial stat (`webfile_io.c:342`)** — this is on the
lib side and has no pool handle. Two options: (a) leave it stateless (one extra
connect per file *open*, not per read — acceptable, opens are rarer than
getattrs); (b) thread `g_web_pool` down. **Chosen: (a)** — keeps the lib free of
driver globals and the cost is one connect per open, dwarfed by the read
traffic that follows on the persistent `brix_webfile` socket. Noted as a
possible follow-up if open-heavy workloads show it.

**`extern brix_cpool *g_web_pool;`** added to `xrootdfs_internal.h` (beside
`extern brix_pool *g_pool;` at `xrootdfs_internal.h:68`; the web-mount globals
`g_web`/`g_web_ca`/`g_web_verify`/`g_weburl` sit at `:72-75`, `g_bearer` at
`:54`, `g_max_conns` at `xrootdfs.c:14`). The legacy sync driver
(`xrootdfs_legacy.c`) has its own pooled ops (`:491-683`) but is **not** on the
web path — no change there.

---

## 10. Test plan — full specs (3 per change: success + error + security-neg)

### 10.1 Pool core C-unit — `client/lib/net/cpool_unittest.c` + `tests/cmdscripts/cpool_unit.py`

A fake transport (vtable over an `int` "conn" that increments a global connect
counter) exercises the engine with **no network**:

- **success:** create(n=4) → 4× checkout/checkin cycles reuse ≤4 connects
  (connect counter proves reuse, not reconnect); `brix_pool` adapter path over a
  loopback endpoint reuses identically.
- **error:** `checkin(healthy=0)` then checkout → connect counter increments
  (dropped slot reconnects); a connect callback returning -1 on slot 0 fails
  `create` (returns NULL + st).
- **security-neg / concurrency:** N+1 threads contend for N slots → the extra
  thread blocks in checkout then proceeds after a checkin (assert no
  double-issue: each in-flight conn pointer is unique); destroy with slots
  checked out is not attempted (contract), destroy after all checkin closes
  exactly the connected slots (close counter == connects).

Registered like `brixmount_unit.py` (`compile_run.compile_binary` with
`client/lib/net/cpool_unittest.c client/lib/net/cpool.c` + pthread), added to
`pytest.ini` collection via the cmdscripts shim.

### 10.2 Connection-reuse integration — `tests/test_xrootdfs_web_conn_reuse.py`

Drives a **real** `xrootdfs` web mount against the test WebDAV server (pattern
from `test_a_webdav_clients.py` / `test_http_webdav.py`; ports from
`settings.py`). The proof of the phase:

- **success (reuse):** mount `http(s)://…`; run `stat` on 20 files in a dir (or
  `ls -l`); assert the server saw **≤ `--max-conns` accepted connections**, not
  ~20. Measure via the server access log / a counting reverse-proxy shim, or (if
  the module exposes it) a connections-accepted metric. Baseline the pre-phase
  behavior in the same test marked `xfail`-until-landed so the delta is explicit.
- **error (sever → reconnect):** kill the keep-alive socket mid-session (server
  restart or idle-reap), then `stat` again → succeeds (pool drops + reconnects),
  and the earlier files are still correct. Deadline path: point at a black-hole
  port → honest error within the window, no hang.
- **security-neg:** (i) a 401/403 path still returns `-EACCES`/`-EPERM` and does
  **not** poison the pooled socket for the next authorized op; (ii) two mounts
  with different bearers never share a socket (auth is per-conn template — assert
  by mounting both and checking no cross-identity 200); (iii) a truncated /
  missing `Content-Length` response disconnects the slot rather than desyncing
  (next op still parses correctly).

### 10.3 Regression

Run existing web suites unchanged: `test_http_webdav.py`,
`test_https_webdav_status_codes.py`, `test_https_webdav_token_status_codes.py`,
`test_client_xrdfs_web.py` (proves the **stateless** `brix_web_stat`/`readdir`
still serve `xrdfs_web.c`), plus the root:// xrootdfs suites (prove the
`brix_pool` adapter is behavior-identical). `test_compression_fuse_resilience.py`
guards the read path after the `brix_kaconn` refactor.

Commands:
```
make -C client -j$(nproc)
PYTHONPATH=tests pytest tests/test_xrootdfs_web_conn_reuse.py \
    tests/test_http_webdav.py tests/test_client_xrdfs_web.py \
    tests/cmdscripts/cpool_unit.py -v
```

---

## 11. Build governance & validation

- New client `.c` files go in the **explicit** `LIB_SRCS` list in
  **`client/Makefile`** — it is a hand-maintained list, *not* a wildcard:
  - `lib/net/cpool.c` → append on the `lib/net/…` line (`client/Makefile:109`,
    next to `lib/net/pool.c`).
  - `lib/protocols/http/web_ka.c` → append on the `lib/protocols/http/…` line
    (`client/Makefile:119`, next to `webfile_io.c`).
- Cross-check `split_files_three_build_systems`: if the client lib also compiles
  under `CMakeLists.txt`/`cmake/`, add both files there in the same change
  (never one build system alone — this bit prior phases).
- Coding standard (MANDATORY): `docs/09-developer-guide/coding-standards.md` —
  no `goto`, functional/modular early-return, reuse HELPERS, clean-room (compose
  the public `brix_*` API only, as `pool.c:18` already asserts for the pool).
- Validate: `make -C client -j$(nproc)`; C-unit + web pytest (§10.3). No nginx
  module rebuild is needed (client-only change), so `objs/nginx -t` is N/A here.

---

## 6. Risks & mitigations

- **Core root:// path regression (Step 1).** The `brix_pool` engine moves. Mit:
  behavior-identical extraction + a thin adapter whose only subtlety (the stable
  `&p->ctx` pointer, §2.1) is called out and unit-tested; root:// suites **gate**
  Step 2; the engine is *copied*, not rewritten.
- **Keep-alive desync** (a pooled socket left mis-aligned between requests).
  Mit: the drain-to-`Content-Length` discipline is lifted verbatim from the
  proven `web_get_range` (`webfile_io.c:288-299`); any absent/short
  `Content-Length` disconnects the slot (health-drop) rather than reusing a
  dirty socket. Tested in 10.2 security-neg (iii).
- **Identity bleed across pooled conns.** Mit: `auth` is fixed in the pool's
  template ctx (one identity per mount); the vtable copies the template into each
  slot. Documented invariant; tested in 10.2 security-neg (ii).
- **PROPFIND response without `Content-Length`** (chunked). `web_get_range`
  already bails on this (`webfile_io.c:218-224`); test servers (nginx dav /
  XrdHttp) send CL for PROPFIND. Mit: same bail → health-drop → the stateless
  path is *not* a fallback here (would reintroduce per-call connect), so instead
  we return `XRDC_EPROTO` and log once. If a real server is found to chunk
  PROPFIND, add a chunked-drain to `brix_kaconn_read_body` (noted).
- **`brix_kaconn` refactor breaks the read path.** Mit: mechanical field-rename
  only; `web_range_stream_body` (the partial-resume logic) stays put;
  `test_compression_fuse_resilience.py` + the webdav read suites regress it.
- **Concurrent-session build contention** (`[[concurrent_session_build_
  contention]]`): another Claude session's uncommitted `.c` compiled into the
  rebuild has bitten this tree repeatedly — build in a private tree if a shared
  `make` is in flight.

---

## 7. Status / decision log

- **2026-07-18 — planned, not started.** Design ratified: the merge is at the
  **pool layer** between root:// and xrootdfs-web (`brix_cpool`); brixcvmfs stays
  on libcurl (already reuses; single-threaded so a generic pool is churn, not a
  win).
- **Open decisions for OP (recorded pending confirmation):**
  1. Accept the realistic merge scope above (leave brixcvmfs untouched) vs. also
     wrap cvmfs's libcurl handles in the generic pool for uniformity. *Rec:
     leave untouched.*
  2. Green-light the `brix_pool` → `brix_cpool` extraction on the core root://
     path (Step 1, behavior-identical). *Rec: yes, gated by root:// suites.*
  3. The keep-alive PROPFIND maps `401/403 → kXR_NotAuthorized` (→ `-EACCES`),
     whereas the stateless `brix_web_stat` today folds those into a generic
     `XRDC_EPROTO` (`webfile.c:141-144`). This is *stricter/more-correct* (a
     token failure becomes `EACCES`, not `EIO`) and matches the read path
     (`webfile_io.c:206-212`). *Rec: adopt the richer mapping on the pooled
     path; optionally backport it to the stateless path for consistency —
     flagged so it is a conscious choice, not silent drift.*
- **Deferred follow-ups:** (a) HTTP-pool idle heartbeat (kXR_ping analogue,
  `aio_conn.c:198`) if servers reap idle keep-alives aggressively; (b) thread
  `g_web_pool` into `brix_webfile_open`'s initial stat if open-heavy workloads
  show the one-connect-per-open cost; (c) chunked PROPFIND drain if any server
  omits `Content-Length`.

---

*Cross-refs:* audit anchors throughout; `[[data_posix_backend_confinement]]`,
`[[concurrent_session_build_contention]]`; on landing, add a row to
`docs/09-developer-guide/history-client-tooling.md`.

---

## 12. Complete code appendix (compile-ready, not sketches)

Every new/rewritten file below is written end-to-end against the real public
`brix_*` API (`brix_net.h`: `brix_tcp_connect:161`, `brix_read_full:167`,
`brix_write_full:168`, `brix_backoff_sleep_fast:215`, `brix_tls_read_some:235`,
`brix_tls_client:266`, `brix_tls_client_free:268`, `brix_status_set:451`,
`brix_status_retryable:456`, `brix_mono_ns:512`; `brix_format_host_port` in
`src/core/compat/host_format.h:45`). These are the intended landing form — treat
line-level details (buffer sizes, status codes) as authoritative and re-verify
only the surrounding API at implementation time.

### 12.1 `client/lib/net/cpool.c` (full)

`pool.c` (191 lines) transformed to the generic engine: slot memory is a per-slot
`void *conn` heap block of `vt->conn_size` bytes; connect/close go through the
vtable; `ctx` is the caller's connect template (not owned). Everything else — the
eager slot-0 connect, the connect-outside-lock discipline, the linear free scan +
condvar wait, the health-drop — is byte-for-byte the original logic.

```c
/*
 * cpool.c — a small thread-safe pool of opaque connections (generic engine).
 *
 * WHAT: brix_cpool_create/checkout/checkin/destroy over a caller-defined
 *       connection type (vtable {conn_size, connect, close}). Extracted from
 *       lib/net/pool.c so the binary root:// path (brix_pool adapter) and the
 *       HTTP keep-alive metadata path (brix_webmeta) share ONE pool.
 * WHY:  a connection is one-op-in-flight and NOT thread-safe; a multi-threaded
 *       consumer needs N independent connections. The pool is the concurrency
 *       primitive; the transport is a vtable parameter.
 * HOW:  one mutex guards slot bookkeeping only (never held across connect/op);
 *       a condvar wakes a waiter on checkin; the vtable connects/closes the
 *       opaque per-slot memory. No goto. Clean-room (libc + pthread only).
 */
#include "brix.h"
#include "net/cpool.h"

#include <pthread.h>
#include <stdlib.h>

typedef struct {
    void *conn;        /* calloc(1, vt->conn_size) — opaque to the pool */
    int   connected;   /* 1 once a successful connect/reconnect has run */
    int   in_use;      /* checked out by a thread */
} cpool_slot;

struct brix_cpool {
    brix_cpool_vtbl vt;
    void           *ctx;    /* connect template; NOT owned, must outlive pool */
    int             n;
    cpool_slot     *slots;
    pthread_mutex_t lock;
    pthread_cond_t  avail;
};

/* Bring a reserved (in_use) slot to a connected state; lock NOT held. */
static int
cpool_slot_connect(brix_cpool *p, cpool_slot *s, brix_status *st)
{
    if (s->connected) {
        return 0;
    }
    if (p->vt.connect(s->conn, p->ctx, st) != 0) {
        return -1;
    }
    s->connected = 1;
    return 0;
}

brix_cpool *
brix_cpool_create(const brix_cpool_vtbl *vt, void *ctx, int n, brix_status *st)
{
    brix_cpool *p;
    int         i;

    if (vt == NULL || vt->connect == NULL || vt->close == NULL
        || vt->conn_size == 0 || n < 1) {
        brix_status_set(st, XRDC_EUSAGE, 0, "cpool: bad arguments");
        return NULL;
    }
    if (n > 256) {
        n = 256;   /* sanity cap */
    }
    p = calloc(1, sizeof(*p));
    if (p == NULL) {
        brix_status_set(st, XRDC_ESOCK, 0, "cpool: out of memory");
        return NULL;
    }
    p->slots = calloc((size_t) n, sizeof(*p->slots));
    if (p->slots == NULL) {
        free(p);
        brix_status_set(st, XRDC_ESOCK, 0, "cpool: out of memory");
        return NULL;
    }
    for (i = 0; i < n; i++) {
        p->slots[i].conn = calloc(1, vt->conn_size);
        if (p->slots[i].conn == NULL) {
            while (--i >= 0) {
                free(p->slots[i].conn);
            }
            free(p->slots);
            free(p);
            brix_status_set(st, XRDC_ESOCK, 0, "cpool: out of memory");
            return NULL;
        }
    }
    p->vt  = *vt;
    p->ctx = ctx;
    p->n   = n;
    pthread_mutex_init(&p->lock, NULL);
    pthread_cond_init(&p->avail, NULL);

    /* Connect slot 0 eagerly so a bad endpoint / auth fails up front; the
     * remaining slots connect lazily on first use. */
    p->slots[0].in_use = 1;
    if (cpool_slot_connect(p, &p->slots[0], st) != 0) {
        p->slots[0].in_use = 0;
        brix_cpool_destroy(p);
        return NULL;
    }
    p->slots[0].in_use = 0;
    return p;
}

void *
brix_cpool_checkout(brix_cpool *p, brix_status *st)
{
    cpool_slot *s = NULL;
    int         i;

    if (p == NULL) {
        brix_status_set(st, XRDC_EUSAGE, 0, "cpool: null");
        return NULL;
    }
    pthread_mutex_lock(&p->lock);
    for (;;) {
        for (i = 0; i < p->n; i++) {
            if (!p->slots[i].in_use) {
                s = &p->slots[i];
                s->in_use = 1;
                break;
            }
        }
        if (s != NULL) {
            break;
        }
        pthread_cond_wait(&p->avail, &p->lock);   /* all busy: wait for checkin */
    }
    pthread_mutex_unlock(&p->lock);

    /* Connect/reconnect outside the lock (the slot is reserved). */
    if (cpool_slot_connect(p, s, st) != 0) {
        pthread_mutex_lock(&p->lock);
        s->in_use = 0;
        pthread_cond_signal(&p->avail);
        pthread_mutex_unlock(&p->lock);
        return NULL;
    }
    return s->conn;
}

void
brix_cpool_checkin(brix_cpool *p, void *conn, int healthy)
{
    int i;

    if (p == NULL || conn == NULL) {
        return;
    }
    /* A connection-level failure (healthy==0) means this conn's socket/session
     * is suspect — close it and clear `connected` so the next checkout
     * reconnects on a clean session rather than handing back a dead socket. */
    if (!healthy) {
        for (i = 0; i < p->n; i++) {
            if (p->slots[i].conn == conn) {
                if (p->slots[i].connected) {
                    p->vt.close(p->slots[i].conn);
                    p->slots[i].connected = 0;
                }
                break;
            }
        }
    }
    pthread_mutex_lock(&p->lock);
    for (i = 0; i < p->n; i++) {
        if (p->slots[i].conn == conn) {
            p->slots[i].in_use = 0;
            break;
        }
    }
    pthread_cond_signal(&p->avail);
    pthread_mutex_unlock(&p->lock);
}

void
brix_cpool_destroy(brix_cpool *p)
{
    int i;

    if (p == NULL) {
        return;
    }
    for (i = 0; i < p->n; i++) {
        if (p->slots[i].connected) {
            p->vt.close(p->slots[i].conn);
        }
        free(p->slots[i].conn);
    }
    pthread_mutex_destroy(&p->lock);
    pthread_cond_destroy(&p->avail);
    free(p->slots);
    free(p);
}
```

The `brix_pool` adapter (`pool.c` rewritten) is exactly §2.1 — unchanged public
API at `brix_net.h:592-605`, zero caller edits.

### 12.2 `client/lib/protocols/http/web_ka.c` (full)

The keep-alive transport + PROPFIND exchange. `brix_kaconn_connect` /
`brix_kaconn_disconnect` / `kaconn_read_some` are the verbatim
`web_connect`/`web_disconnect`/`web_read_some` bodies (`webfile_io.c:29,11,51`)
re-keyed on `brix_kaconn`. `brix_kaconn_read_headers` generalises
`web_range_read_headers` (`webfile_io.c:165`) but drops the 206/Range specifics
(PROPFIND is a plain 2xx). `brix_kaconn_read_body` is the "malloc the whole
body" cousin of the read path's streaming drain.

```c
/*
 * web_ka.c — persistent keep-alive HTTP/1.1 transport + PROPFIND exchange.
 *
 * WHAT: brix_kaconn (connect/disconnect/read-headers/read-body) and brix_webmeta
 *       (a kaconn + fixed auth) with brix_webmeta_propfind. One request in
 *       flight; NOT thread-safe — pool it (brix_cpool) or serialise it.
 * WHY:  the FUSE web-metadata path (getattr/readdir) reconnected per call via
 *       the one-shot brix_http_req. Keep-alive + a small pool removes the
 *       per-op TCP+TLS handshake, matching the read path (webfile_io.c) and the
 *       recent brixcvmfs connection-reuse work.
 * HOW:  the transport/codec is lifted verbatim from webfile_io.c so the read and
 *       metadata paths run one implementation; the PROPFIND loop mirrors
 *       brix_webfile_pread's deadline-bounded reconnect-on-sever. No goto.
 * Clean-room: composes the public brix_* connection API only.
 */
#include "web_ka.h"
#include "core/compat/host_format.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <poll.h>
#include <errno.h>
#include <unistd.h>

#define KA_HDR_MAX     16384     /* mirrors WEB_HDR_MAX */
#define KA_BODY_MAX    (4 * 1024 * 1024)   /* a PROPFIND body over 4 MiB is abuse */

void
brix_kaconn_init(brix_kaconn *k, const char *host, int port, int tls,
                 int verify, const char *ca_dir, int timeout_ms)
{
    memset(k, 0, sizeof(*k));
    k->io.fd = -1;
    snprintf(k->host, sizeof(k->host), "%s", host ? host : "");
    k->port = port;
    k->tls = tls;
    k->verify = verify;
    if (ca_dir != NULL) {
        snprintf(k->ca_dir, sizeof(k->ca_dir), "%s", ca_dir);
    }
    k->timeout_ms = timeout_ms > 0 ? timeout_ms : 30000;
    brix_format_host_port(k->host, (uint16_t) k->port, k->hostport,
                          sizeof(k->hostport));
}

void
brix_kaconn_disconnect(brix_kaconn *k)
{
    if (!k->connected) {
        return;
    }
    if (k->tls) {
        brix_tls_client_free(&k->io, k->tls_ctx);
        k->tls_ctx = NULL;
    }
    if (k->io.fd >= 0) {
        close(k->io.fd);
    }
    k->io.fd = -1;
    k->connected = 0;
}

int
brix_kaconn_connect(brix_kaconn *k, brix_status *st)
{
    memset(&k->io, 0, sizeof(k->io));
    k->io.fd = brix_tcp_connect(k->host, k->port, k->timeout_ms, st);
    if (k->io.fd < 0) {
        return -1;
    }
    k->io.timeout_ms = k->timeout_ms;
    if (k->tls && brix_tls_client(&k->io, k->host, k->verify, k->verify,
                                  k->ca_dir[0] ? k->ca_dir : NULL,
                                  &k->tls_ctx, st) != 0) {
        close(k->io.fd);
        k->io.fd = -1;
        return -1;
    }
    k->connected = 1;
    return 0;
}

/* Read up to n bytes (branches on TLS). >0 bytes, 0 EOF, -1 error. Verbatim
 * from web_read_some (webfile_io.c:51), keyed on brix_kaconn. */
static ssize_t
kaconn_read_some(brix_kaconn *k, void *buf, size_t n, brix_status *st)
{
    if (k->io.ssl != NULL) {
        size_t got = 0;
        if (brix_tls_read_some(&k->io, buf, n, &got, st) != 0) {
            return -1;
        }
        return (ssize_t) got;
    }
    struct pollfd pfd;
    ssize_t       r;
    int           pr;
    pfd.fd = k->io.fd; pfd.events = POLLIN; pfd.revents = 0;
    do { pr = poll(&pfd, 1, k->io.timeout_ms); } while (pr < 0 && errno == EINTR);
    if (pr <= 0) {
        brix_status_set(st, XRDC_ESOCK, pr == 0 ? ETIMEDOUT : errno, "ka read");
        return -1;
    }
    do { r = read(k->io.fd, buf, n); } while (r < 0 && errno == EINTR);
    if (r < 0) {
        brix_status_set(st, XRDC_ESOCK, errno, "ka read: %s", strerror(errno));
        return -1;
    }
    return r;
}

/* Case-insensitive Content-Length lookup (verbatim from hdr_clen). */
static long long
ka_hdr_clen(const char *hdrs)
{
    const char *p = hdrs;
    while ((p = strchr(p, '\n')) != NULL) {
        p++;
        if (strncasecmp(p, "Content-Length:", 15) == 0) {
            return strtoll(p + 15, NULL, 10);
        }
    }
    if (strncasecmp(hdrs, "Content-Length:", 15) == 0) {
        return strtoll(hdrs + 15, NULL, 10);
    }
    return -1;
}

int
brix_kaconn_read_headers(brix_kaconn *k, char *hbuf, size_t hbufsz,
                         brix_ka_hdr *out, brix_status *st)
{
    size_t     hlen = 0;
    char      *eoh = NULL;
    int        status = 0;
    long long  clen;

    for (;;) {
        ssize_t r;
        if (hlen + 1 >= hbufsz) {
            brix_kaconn_disconnect(k);
            brix_status_set(st, XRDC_EPROTO, 0, "ka: header too large");
            return -1;
        }
        r = kaconn_read_some(k, hbuf + hlen, hbufsz - 1 - hlen, st);
        if (r <= 0) {
            brix_kaconn_disconnect(k);
            if (r == 0) {
                brix_status_set(st, XRDC_ESOCK, 0, "ka: peer closed");
            }
            return -1;
        }
        hlen += (size_t) r;
        hbuf[hlen] = '\0';
        eoh = strstr(hbuf, "\r\n\r\n");
        if (eoh != NULL) {
            break;
        }
    }
    if (strncmp(hbuf, "HTTP/", 5) == 0) {
        const char *sp = strchr(hbuf, ' ');
        status = sp ? atoi(sp + 1) : 0;
    }
    /* Content-Length is required to stay keep-alive-aligned. Terminate the
     * header block for ka_hdr_clen, then restore the body byte. */
    {
        char saved = eoh[0];
        eoh[0] = '\0';
        clen = ka_hdr_clen(hbuf);
        eoh[0] = saved;
    }
    if (clen < 0 || clen > KA_BODY_MAX) {
        brix_kaconn_disconnect(k);
        brix_status_set(st, XRDC_EPROTO, 0, "ka: bad/absent Content-Length");
        return -1;
    }
    out->status        = status;
    out->clen          = clen;
    out->body_start    = eoh + 4;
    out->body_buffered = hlen - (size_t) (out->body_start - hbuf);
    return 1;
}

int
brix_kaconn_read_body(brix_kaconn *k, const brix_ka_hdr *hdr,
                      char **body_out, size_t *len_out, brix_status *st)
{
    size_t total = (size_t) hdr->clen;
    char  *body  = malloc(total + 1);
    size_t have  = hdr->body_buffered < total ? hdr->body_buffered : total;

    if (body == NULL) {
        brix_kaconn_disconnect(k);
        brix_status_set(st, XRDC_EPROTO, 0, "ka: out of memory");
        return -1;
    }
    memcpy(body, hdr->body_start, have);
    if (have < total
        && brix_read_full(&k->io, body + have, total - have, st) != 0) {
        brix_kaconn_disconnect(k);   /* sever mid-body → drop the slot */
        free(body);
        return -1;
    }
    body[total] = '\0';
    *body_out = body;
    *len_out  = total;
    return 0;
}

void
brix_webmeta_init(brix_webmeta *m, const char *host, int port, int tls,
                  int verify, const char *ca_dir, const char *bearer,
                  int timeout_ms)
{
    brix_kaconn_init(&m->ka, host, port, tls, verify, ca_dir, timeout_ms);
    if (bearer != NULL && bearer[0] != '\0') {
        snprintf(m->auth, sizeof(m->auth),
                 "Authorization: Bearer %s\r\n", bearer);
    } else {
        m->auth[0] = '\0';
    }
}

/* Build + write "PROPFIND path HTTP/1.1 … Depth: d {auth}". On write fault the
 * kaconn is disconnected (caller reconnects + retries). */
static int
webmeta_send_req(brix_webmeta *m, const char *path, int depth, brix_status *st)
{
    char req[3200];
    int  rn = snprintf(req, sizeof(req),
                       "PROPFIND %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: xrootdfs\r\n"
                       "Accept: */*\r\nConnection: keep-alive\r\nDepth: %d\r\n%s\r\n",
                       path[0] ? path : "/", m->ka.hostport,
                       depth ? 1 : 0, m->auth);
    if (rn < 0 || (size_t) rn >= sizeof(req)) {
        brix_status_set(st, XRDC_EUSAGE, 0, "PROPFIND: request too long");
        return -1;
    }
    if (brix_write_full(&m->ka.io, req, (size_t) rn, st) != 0) {
        brix_kaconn_disconnect(&m->ka);
        return -1;
    }
    return 0;
}

/* status → kXR (matches web_range_read_headers:206-212; richer than the
 * stateless brix_web_stat, see §2.2 / §7 decision 3). 0 ok, -1 err (st set). */
static int
webmeta_status_ok(int status, brix_status *st)
{
    if (status == 207 || status == 200) {
        return 0;
    }
    if (status == 404) {
        brix_status_set(st, kXR_NotFound, 0, "not found");
    } else if (status == 401 || status == 403) {
        brix_status_set(st, kXR_NotAuthorized, 0, "HTTP %d", status);
    } else {
        brix_status_set(st, XRDC_EPROTO, 0, "PROPFIND HTTP %d", status);
    }
    return -1;
}

int
brix_webmeta_propfind(brix_webmeta *m, const char *path, int depth,
                      char **body_out, size_t *len_out, brix_status *st)
{
    unsigned attempt = 0;
    int      window_ms = webfile_window_ms();
    uint64_t deadline  = brix_mono_ns() + (uint64_t) window_ms * 1000000ULL;

    *body_out = NULL;
    *len_out  = 0;

    for (;;) {
        if (m->ka.connected || brix_kaconn_connect(&m->ka, st) == 0) {
            if (webmeta_send_req(m, path, depth, st) == 0) {
                char        hbuf[KA_HDR_MAX + 1];
                brix_ka_hdr h;
                if (brix_kaconn_read_headers(&m->ka, hbuf, sizeof(hbuf), &h, st)
                    == 1) {
                    if (webmeta_status_ok(h.status, st) != 0) {
                        /* protocol-level (404/403/…): socket stays aligned
                         * (we consumed headers; body is buffered/framed), but
                         * the simplest correct thing is to drain then keep it.
                         * A 4xx PROPFIND still carries a CL body, so drain it. */
                        char  *drain = NULL;
                        size_t dl = 0;
                        if (brix_kaconn_read_body(&m->ka, &h, &drain, &dl, st) == 0) {
                            free(drain);
                        }
                        /* status already set by webmeta_status_ok; do NOT retry
                         * a genuine 404/403 — it is not retryable. */
                        brix_status_set(st, webmeta_status_kxr(h.status), 0,
                                        "PROPFIND HTTP %d", h.status);
                        return -1;
                    }
                    if (brix_kaconn_read_body(&m->ka, &h, body_out, len_out, st)
                        == 0) {
                        return 0;               /* success */
                    }
                }
            }
        }
        if (window_ms <= 0 || !brix_status_retryable(st)
            || brix_mono_ns() >= deadline) {
            return -1;
        }
        brix_backoff_sleep_fast(attempt++);
    }
}
```

> **Note on the 4xx-drain branch:** `webmeta_status_ok` already sets the status
> and returns -1; the extra drain keeps the socket reusable after a *non-fatal*
> 4xx so the pool doesn't needlessly reconnect. `webmeta_status_kxr()` is a
> trivial split of `webmeta_status_ok`'s classification (returns the kXR code
> without setting `st`) so the drain path can re-assert it after the drain — or,
> simpler and preferred at implementation time: **health-drop on any non-2xx**
> (return with the socket disconnected) and skip the drain entirely, trading one
> reconnect for less code. Pick the simpler form unless a profiler shows the
> reconnect matters; documented here so the choice is explicit, not incidental.

### 12.3 `client/lib/net/cpool_unittest.c` (full — the pool C-unit)

No network: a fake transport over an `int` conn with atomic connect/close
counters proves reuse, health-drop reconnect, create-fails-on-bad-endpoint, and
N+1-thread contention with no double-issue.

```c
/* cpool_unittest.c — brix_cpool engine, no network. Compiled by
 * tests/cmdscripts/cpool_unit.py with cpool.c + pthread, -Wall -Wextra -Werror. */
#include "brix.h"
#include "net/cpool.h"
#include <assert.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

typedef struct { int id; } fake_conn;

typedef struct {
    atomic_int connects;
    atomic_int closes;
    int        fail_slot0;   /* make the very first connect fail */
    atomic_int seen;         /* how many connects have happened, for fail_slot0 */
} fake_ctx;

static int
fake_connect(void *conn, void *ctx, brix_status *st)
{
    fake_ctx  *c = ctx;
    fake_conn *fc = conn;
    if (c->fail_slot0 && atomic_fetch_add(&c->seen, 1) == 0) {
        brix_status_set(st, XRDC_ESOCK, 0, "fake: refused");
        return -1;
    }
    fc->id = atomic_fetch_add(&c->connects, 1) + 1;
    return 0;
}
static void fake_close(void *conn) { (void) conn; }
/* separate close-counting vtable for the destroy test */
static fake_ctx *g_close_ctx;
static void fake_close_counting(void *conn) { (void) conn; atomic_fetch_add(&g_close_ctx->closes, 1); }

static const brix_cpool_vtbl VT       = { sizeof(fake_conn), fake_connect, fake_close };

static void
test_reuse(void)
{
    fake_ctx     ctx = {0};
    brix_status  st; brix_status_clear(&st);
    brix_cpool  *p = brix_cpool_create(&VT, &ctx, 4, &st);
    int          i;
    assert(p != NULL);
    assert(atomic_load(&ctx.connects) == 1);          /* eager slot-0 only */
    for (i = 0; i < 20; i++) {
        void *c = brix_cpool_checkout(p, &st);
        assert(c != NULL);
        brix_cpool_checkin(p, c, 1);                  /* healthy → reuse */
    }
    /* single-threaded serial reuse never opens a 2nd slot */
    assert(atomic_load(&ctx.connects) == 1);
    brix_cpool_destroy(p);
    printf("ok test_reuse\n");
}

static void
test_health_drop_reconnects(void)
{
    fake_ctx     ctx = {0};
    brix_status  st; brix_status_clear(&st);
    brix_cpool  *p = brix_cpool_create(&VT, &ctx, 1, &st);
    void        *c;
    assert(p != NULL && atomic_load(&ctx.connects) == 1);
    c = brix_cpool_checkout(p, &st); assert(c != NULL);
    brix_cpool_checkin(p, c, 0);                       /* unhealthy → drop */
    c = brix_cpool_checkout(p, &st); assert(c != NULL);
    assert(atomic_load(&ctx.connects) == 2);           /* reconnected */
    brix_cpool_checkin(p, c, 1);
    brix_cpool_destroy(p);
    printf("ok test_health_drop_reconnects\n");
}

static void
test_create_fails_on_bad_endpoint(void)
{
    fake_ctx     ctx = {0}; ctx.fail_slot0 = 1;
    brix_status  st; brix_status_clear(&st);
    brix_cpool  *p = brix_cpool_create(&VT, &ctx, 4, &st);
    assert(p == NULL);                                 /* eager slot-0 failed */
    assert(st.kxr == XRDC_ESOCK);
    printf("ok test_create_fails_on_bad_endpoint\n");
}

/* N+1 threads contend for N slots: assert no conn pointer is ever held by two
 * threads at once (unique-issue), and the (N+1)th blocks then proceeds. */
#define NSLOT 3
#define NTHR  (NSLOT + 1)
static brix_cpool  *g_p;
static atomic_int    g_inflight[64];   /* per-slot-id in-use flag */
static void *
worker(void *arg)
{
    int          rounds = *(int *) arg, r;
    brix_status  st; brix_status_clear(&st);
    for (r = 0; r < rounds; r++) {
        fake_conn *c = brix_cpool_checkout(g_p, &st);
        assert(c != NULL);
        int prev = atomic_fetch_add(&g_inflight[c->id], 1);
        assert(prev == 0);                             /* NOT double-issued */
        atomic_fetch_sub(&g_inflight[c->id], 1);
        brix_cpool_checkin(g_p, c, 1);
    }
    return NULL;
}
static void
test_contention_unique_issue(void)
{
    fake_ctx     ctx = {0};
    brix_status  st; brix_status_clear(&st);
    pthread_t    th[NTHR];
    int          rounds = 500, i;
    memset(g_inflight, 0, sizeof(g_inflight));
    g_p = brix_cpool_create(&VT, &ctx, NSLOT, &st);
    assert(g_p != NULL);
    for (i = 0; i < NTHR; i++) pthread_create(&th[i], NULL, worker, &rounds);
    for (i = 0; i < NTHR; i++) pthread_join(th[i], NULL);
    assert(atomic_load(&ctx.connects) <= NSLOT);       /* never more than N */
    brix_cpool_destroy(g_p);
    printf("ok test_contention_unique_issue\n");
}

static void
test_destroy_closes_connected(void)
{
    fake_ctx           ctx = {0};
    brix_cpool_vtbl    vt = { sizeof(fake_conn), fake_connect, fake_close_counting };
    brix_status        st; brix_status_clear(&st);
    brix_cpool        *p;
    void              *a, *b;
    g_close_ctx = &ctx;
    p = brix_cpool_create(&vt, &ctx, 4, &st); assert(p != NULL);   /* 1 connect */
    a = brix_cpool_checkout(p, &st);                                /* slot reuse */
    brix_cpool_checkin(p, a, 1);
    b = brix_cpool_checkout(p, &st);
    brix_cpool_checkin(p, b, 1);
    brix_cpool_destroy(p);
    assert(atomic_load(&ctx.closes) == atomic_load(&ctx.connects)); /* balanced */
    printf("ok test_destroy_closes_connected\n");
}

int
main(void)
{
    test_reuse();
    test_health_drop_reconnects();
    test_create_fails_on_bad_endpoint();
    test_contention_unique_issue();
    test_destroy_closes_connected();
    printf("ALL PASS\n");
    return 0;
}
```

### 12.4 `tests/cmdscripts/cpool_unit.py` (compile-list entry)

Mirrors `brixmount_unit.py`: compile the C-unit with the engine + pthread under
`-Wall -Wextra -Werror` and assert `ALL PASS`.

```python
# tests/cmdscripts/cpool_unit.py
from cmdscripts.compile_run import compile_binary, run_binary

SRCS = ["client/lib/net/cpool_unittest.c", "client/lib/net/cpool.c"]
INCLUDES = ["client/lib", "src"]          # net/cpool.h, brix.h, compat headers
CFLAGS = ["-Wall", "-Wextra", "-Werror", "-pthread"]

def test_cpool_unit():
    exe = compile_binary("cpool_unit", SRCS, includes=INCLUDES, cflags=CFLAGS)
    out = run_binary(exe)
    assert "ALL PASS" in out, out
```

> Confirm the exact `compile_run` helper API + include roots against
> `tests/cmdscripts/brixmount_unit.py` at implementation time (it is the
> pattern-of-record); `cpool.c` pulls in only `brix.h` + `net/cpool.h` + libc +
> pthread, so no other translation units are needed. If `brix_status_set` /
> `brix_status_clear` live in a `.c` that must be linked (not header-inline), add
> it to `SRCS` — grep `client/lib` for their definitions first.

### 12.5 Build-list edits (exact)

```
# client/Makefile — LIB_SRCS, the lib/net line (:109): append cpool.c
   lib/net/pool.c  ->  lib/net/pool.c lib/net/cpool.c

# client/Makefile — LIB_SRCS, the lib/protocols/http line (:119): append web_ka.c
   lib/protocols/http/webfile_io.c  ->  ... webfile_io.c lib/protocols/http/web_ka.c
```

Plus the `split_files_three_build_systems` cross-check (§11): if `CMakeLists.txt`
/ `cmake/*.cmake` also enumerate the client lib sources, add `cpool.c` and
`web_ka.c` there **in the same change**. The C-unit `cpool_unittest.c` is a test
TU (compiled only by `cpool_unit.py`), so it goes in **no** production build list.

### 12.6 `client/lib/protocols/http/web_ka.h` (consolidated full header)

The §2.2 declarations as one file (the fragments there are split for exposition;
this is the landing form):

```c
/* web_ka.h — persistent keep-alive HTTP/1.1 transport + WebDAV PROPFIND.
 * Private split contract; include only from client/lib/. */
#ifndef BRIX_WEB_KA_H
#define BRIX_WEB_KA_H
#include "brix.h"

/* A persistent, keep-alive HTTP/1.1 connection to one origin (cleartext/TLS).
 * One request in flight; NOT thread-safe (pool it via brix_cpool). */
typedef struct {
    brix_io io;
    void   *tls_ctx;              /* SSL_CTX* when tls, else NULL */
    int     connected;
    char    host[256];
    int     port;
    int     tls;
    int     verify;
    char    ca_dir[512];          /* "" => default resolver */
    char    hostport[300];        /* Host: header value (IPv6-bracketed) */
    int     timeout_ms;
} brix_kaconn;

typedef struct {
    int       status;
    long long clen;
    char     *body_start;         /* into caller hbuf, just past CRLFCRLF */
    size_t    body_buffered;      /* body bytes already sitting in hbuf */
} brix_ka_hdr;

void brix_kaconn_init(brix_kaconn *k, const char *host, int port, int tls,
                      int verify, const char *ca_dir, int timeout_ms);
int  brix_kaconn_connect(brix_kaconn *k, brix_status *st);
void brix_kaconn_disconnect(brix_kaconn *k);
int  brix_kaconn_read_headers(brix_kaconn *k, char *hbuf, size_t hbufsz,
                              brix_ka_hdr *out, brix_status *st);
int  brix_kaconn_read_body(brix_kaconn *k, const brix_ka_hdr *hdr,
                           char **body_out, size_t *len_out, brix_status *st);

typedef struct {
    brix_kaconn ka;
    char        auth[2200];       /* "Authorization: Bearer ...\r\n" or "" */
} brix_webmeta;

void brix_webmeta_init(brix_webmeta *m, const char *host, int port, int tls,
                       int verify, const char *ca_dir, const char *bearer,
                       int timeout_ms);
int  brix_webmeta_propfind(brix_webmeta *m, const char *path, int depth,
                           char **body_out, size_t *len_out, brix_status *st);

/* webfile_window_ms() (webfile_io.c) is reused by the PROPFIND retry loop —
 * declared in webfile_internal.h; include it in web_ka.c, or hoist the one-line
 * prototype here if you keep web_ka.c free of the webfile split header. */
#endif /* BRIX_WEB_KA_H */
```

### 12.7 `webfile.c` — `webdav_parse_multi` + the pooled readdir + rewired stateless funcs

`webdav_parse_multi` is the verbatim accumulate loop from `brix_web_readdir`
(`webfile.c:380-415`) keyed on `(body, len)`; the caller still computes `self`
via `path_basename` (the directory's own basename to skip):

```c
/* webfile.c — extracted from brix_web_readdir:378-415 (body+len, self supplied). */
int
webdav_parse_multi(const char *body, size_t blen, const char *self,
                   brix_dirent **ents_out, size_t *n_out, brix_status *st)
{
    const char  *p   = body ? body : "";
    const char  *end = p + blen;
    brix_dirent *ents = NULL;
    size_t       n = 0, cap = 0;

    *ents_out = NULL;
    *n_out = 0;
    while ((p = next_response_open(p, end)) != NULL) {
        const char   *open = p;
        const char   *close = next_response_close(open, end);
        brix_statinfo si;
        char          href[XRDC_PATH_MAX], name[XRDC_NAME_MAX];
        if (close == NULL) {
            break;
        }
        if (parse_response(open, close, &si, href, sizeof(href)) == 0 && href[0]) {
            path_basename(href, name, sizeof(name));
            if (name[0] != '\0' && strcmp(name, self) != 0) {
                if (n == cap) {
                    size_t       nc = cap ? cap * 2 : 32;
                    brix_dirent *ne = realloc(ents, nc * sizeof(*ne));
                    if (ne == NULL) {
                        free(ents);
                        brix_status_set(st, XRDC_EPROTO, 0, "readdir: out of memory");
                        return -1;
                    }
                    ents = ne;
                    cap = nc;
                }
                memset(&ents[n], 0, sizeof(ents[n]));
                snprintf(ents[n].name, sizeof(ents[n].name), "%s", name);
                ents[n].have_stat = 1;
                ents[n].st = si;
                n++;
            }
        }
        p = close + 2;
    }
    *ents_out = ents;
    *n_out = n;
    return 0;
}

/* Pooled keep-alive readdir (Depth 1). Same checkout/checkin idiom as
 * brix_web_stat_pooled (§2.3). */
int
brix_web_readdir_pooled(brix_cpool *pool, const char *path,
                        brix_dirent **ents_out, size_t *n_out, brix_status *st)
{
    char         *body = NULL;
    size_t        blen = 0;
    char          self[XRDC_PATH_MAX];
    brix_webmeta *m = brix_cpool_checkout(pool, st);
    int           rc;

    *ents_out = NULL;
    *n_out = 0;
    if (m == NULL) {
        return -1;
    }
    rc = brix_webmeta_propfind(m, path, 1, &body, &blen, st);
    if (rc == 0) {
        path_basename(path, self, sizeof(self));
        rc = webdav_parse_multi(body, blen, self, ents_out, n_out, st);
    }
    free(body);
    brix_cpool_checkin(pool, m, rc == 0 ? 1 : brix_fuse_conn_healthy(st));
    return rc;
}
```

The **rewired stateless** functions keep `brix_http_req` + the status map and
delegate the parse (so `xrdfs_web.c` is unaffected — same output, one parse
copy). `brix_web_stat` (`webfile.c:120-170`) becomes:

```c
int
brix_web_stat(const brix_weburl *u, const char *path, const char *bearer,
              int verify, const char *ca_dir, brix_statinfo *si, brix_status *st)
{
    char           hdrs[2400], auth[2200];
    brix_http_resp r;
    int            rc;

    web_auth(bearer, auth, sizeof(auth));
    snprintf(hdrs, sizeof(hdrs), "Depth: 0\r\n%s", auth);
    if (brix_http_req(u->host, u->port, u->tls, "PROPFIND", path, hdrs, NULL, 0,
                      WEB_TIMEOUT_MS, verify, ca_dir, &r, st) != 0) {
        return -1;
    }
    if (r.status == 404) {
        brix_http_resp_free(&r);
        brix_status_set(st, kXR_NotFound, 0, "not found");
        return -1;
    }
    if (r.status != 207 && r.status != 200) {
        brix_status_set(st, XRDC_EPROTO, 0, "PROPFIND HTTP %d", r.status);
        brix_http_resp_free(&r);
        return -1;
    }
    rc = webdav_parse_single(r.body, r.body ? r.body_len : 0, si, st);
    brix_http_resp_free(&r);
    return rc;
}
```

`brix_web_readdir` (`webfile.c:351-420`) becomes the same shape: `brix_http_req`
→ `!=207 && !=200` guard → `path_basename(path, self)` →
`webdav_parse_multi(r.body, r.body_len, self, ents_out, n_out, st)` →
`brix_http_resp_free`. Byte-identical behavior; regressed by
`test_client_xrdfs_web.py`.

`webfile_internal.h` gains the three new prototypes (`webdav_parse_single`,
`webdav_parse_multi`, and — since the pooled wrappers live in `webfile.c` — the
`#include "web_ka.h"` for `brix_webmeta`/`brix_cpool`), plus the public
`brix_web_stat_pooled`/`brix_web_readdir_pooled` go in the client public header
alongside `brix_web_stat` (grep `brix_net.h`/`brix.h` for the existing
declaration and add beside it).

### 12.8 `tests/test_xrootdfs_web_conn_reuse.py` (full integration test)

Self-contained connection-counting TCP forwarder in front of the test WebDAV
server proves the headline claim: an `ls -l` of N files opens **≤ `--max-conns`**
upstream connections, not ~N. Mount pattern lifted from
`test_compression_fuse_resilience.py` (`XROOTDFS`, `_FUSE_OK`, `fusermount3 -u`).

```python
"""
Phase-86: xrootdfs web-metadata connection reuse.

WHAT: mount xrootdfs over http WebDAV THROUGH a counting TCP forwarder; stat many
      files in one directory and assert the upstream connection count stays at or
      below --max-conns (keep-alive + pool), not one-per-stat.
WHY:  proves the metadata path stopped reconnecting per getattr/readdir.
"""
import os
import shutil
import socket
import subprocess
import threading
import time

import pytest

from settings import CLIENT_DIR, NGINX_HTTP_WEBDAV_PORT, SERVER_HOST, BIND_HOST

XROOTDFS = os.path.join(CLIENT_DIR, "bin", "xrootdfs")
_FUSE_OK = os.path.exists("/dev/fuse") and shutil.which("fusermount3") is not None


def _free_port():
    s = socket.socket()
    s.bind((BIND_HOST, 0))
    p = s.getsockname()[1]
    s.close()
    return p


class CountingForwarder:
    """Accept-counting TCP forwarder BIND_HOST:lport -> SERVER_HOST:rport."""

    def __init__(self, rport):
        self.lport = _free_port()
        self.rport = rport
        self.accepts = 0
        self._srv = socket.socket()
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind((BIND_HOST, self.lport))
        self._srv.listen(64)
        self._stop = False
        self._th = threading.Thread(target=self._loop, daemon=True)
        self._th.start()

    def _pump(self, a, b):
        try:
            while True:
                d = a.recv(65536)
                if not d:
                    break
                b.sendall(d)
        except OSError:
            pass
        finally:
            for s in (a, b):
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    def _loop(self):
        self._srv.settimeout(0.5)
        while not self._stop:
            try:
                cli, _ = self._srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            self.accepts += 1
            up = socket.create_connection((SERVER_HOST, self.rport))
            threading.Thread(target=self._pump, args=(cli, up), daemon=True).start()
            threading.Thread(target=self._pump, args=(up, cli), daemon=True).start()

    def close(self):
        self._stop = True
        try:
            self._srv.close()
        except OSError:
            pass


@pytest.fixture(scope="module")
def built():
    if not _FUSE_OK:
        pytest.skip("FUSE unavailable (/dev/fuse or fusermount3 missing)")
    r = subprocess.run(["make", "-C", CLIENT_DIR, "xrootdfs"],
                       capture_output=True, text=True)
    if r.returncode != 0 or not os.path.exists(XROOTDFS):
        pytest.skip(f"xrootdfs build failed:\n{r.stdout}\n{r.stderr}")


@pytest.fixture
def forwarder():
    fw = CountingForwarder(NGINX_HTTP_WEBDAV_PORT)
    yield fw
    fw.close()


def _mount(endpoint, mnt, max_conns):
    os.makedirs(mnt, exist_ok=True)
    argv = [XROOTDFS, "--max-conns", str(max_conns), endpoint, mnt]
    p = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(50):
        if os.path.ismount(mnt):
            return p
        time.sleep(0.1)
    subprocess.run(["fusermount3", "-u", mnt], capture_output=True)
    p.terminate()
    pytest.skip("xrootdfs web mount did not come up")


def test_stat_many_reuses_connections(built, forwarder, tmp_path):
    """ls -l of N files opens <= max_conns upstream connections, not ~N."""
    mnt = str(tmp_path / "mnt")
    max_conns = 4
    endpoint = f"http://{SERVER_HOST}:{forwarder.lport}/"   # forwarded origin
    p = _mount(endpoint, mnt, max_conns)
    try:
        entries = sorted(os.listdir(mnt))[:20]
        assert entries, "test dir is empty; seed the WebDAV export first"
        before = forwarder.accepts
        for name in entries:
            os.stat(os.path.join(mnt, name))     # one getattr each
        opened = forwarder.accepts - before
        # keep-alive + pool: at most max_conns NEW upstream conns for 20 stats.
        assert opened <= max_conns, (
            f"{opened} upstream conns for {len(entries)} stats "
            f"(expected <= {max_conns}); metadata path is not reusing")
    finally:
        subprocess.run(["fusermount3", "-u", mnt], capture_output=True)
        p.terminate()


def test_missing_path_is_enoent_and_keeps_socket(built, forwarder, tmp_path):
    """A 404 returns ENOENT and does NOT poison the pooled socket."""
    mnt = str(tmp_path / "mnt")
    endpoint = f"http://{SERVER_HOST}:{forwarder.lport}/"
    p = _mount(endpoint, mnt, 2)
    try:
        with pytest.raises(FileNotFoundError):
            os.stat(os.path.join(mnt, "definitely-not-here-xyz"))
        # the next authorized stat still works (socket not poisoned)
        entries = sorted(os.listdir(mnt))
        assert entries
        os.stat(os.path.join(mnt, entries[0]))
    finally:
        subprocess.run(["fusermount3", "-u", mnt], capture_output=True)
        p.terminate()


def test_upstream_sever_reconnects(built, forwarder, tmp_path):
    """Killing the forwarder mid-session then restarting it -> stat recovers."""
    mnt = str(tmp_path / "mnt")
    endpoint = f"http://{SERVER_HOST}:{forwarder.lport}/"
    p = _mount(endpoint, mnt, 2)
    try:
        entries = sorted(os.listdir(mnt))
        assert entries
        os.stat(os.path.join(mnt, entries[0]))
        forwarder.close()                        # sever every pooled socket
        time.sleep(0.3)
        fw2 = CountingForwarder(NGINX_HTTP_WEBDAV_PORT)
        try:
            # remount against the new forwarder port is out of scope; instead
            # assert the sever surfaced as an honest errno, not a hang:
            with pytest.raises(OSError):
                os.stat(os.path.join(mnt, entries[0]))
        finally:
            fw2.close()
    finally:
        subprocess.run(["fusermount3", "-u", mnt], capture_output=True)
        p.terminate()
```

> **Test caveats to resolve at implementation time:** (1) confirm
> `CLIENT_DIR`/`SERVER_HOST`/`BIND_HOST` are exported by `settings.py` (grep — the
> compression test imports the same names); (2) the WebDAV export must contain a
> handful of files — reuse whatever fixture `test_http_webdav.py` seeds, or create
> them via the mount is read-only so seed server-side; (3) `--max-conns` must be
> the real flag name (grep `xrootdfs.c:276` — it is parsed from an env/arg there;
> if it is env-only, set `XRDC_MAX_CONNS` instead of the `--max-conns` argv);
> (4) the sever test asserts *an honest error, not a hang* — tighten once the
> reconnect-to-same-port semantics are settled. These are the three-per-change
> tiers: success (reuse count), security-neg (404 ENOENT + no poison), error
> (sever → errno not hang).

---

## 13. Completeness statement

Every file this phase creates or rewrites now has a full body in this document:
`cpool.{c,h}` (§2.1, §12.1), the `brix_pool` adapter (§2.1), `web_ka.{c,h}`
(§12.2, §12.6), the `webfile.c` extractions + pooled + rewired stateless
functions (§2.3, §12.7), the driver wiring (§9), the pool C-unit (§12.3) with its
compile shim (§12.4), the integration test (§12.8), and the exact build-list
edits (§11, §12.5). The migration map (§8) accounts for every moved line. What
remains is not more detail but **execution + the three §7 decisions** — the doc
is at implementation-ready saturation.

---

## 14. Implementation notes — LANDED 2026-07-18 (UNCOMMITTED)

Implemented inline. Build green (`make -C client -j` clean, no warnings), all
tests pass. Deviations from the plan's provisional sketches, resolved during
execution:

- **`web_ka.c` is self-contained (read-path NOT refactored).** The keep-alive
  metadata transport duplicates the small connect/read helpers keyed on
  `brix_kaconn` rather than re-basing `webfile_io.c`'s read path onto the same
  struct. Chosen to keep the already-reusing read path untouched (lower risk);
  the duplication is ~2 short helpers. If the read path is later migrated onto
  `brix_kaconn`, delete the dupes then.
- **`brix_webmeta_propfind` health-drop is the simple form:** non-2xx →
  `disconnect` + return −1 with status set (not drain-and-keep). The status→kXR
  map (404→NotFound, 401/403→NotAuthorized, 207/200→ok, else EPROTO) is applied
  before the drop so callers still get the right errno.
- **`brix_webmeta_init` takes `timeout_ms=0` from the driver** → defaults to
  30 s internally (the driver TU cannot see `WEB_TIMEOUT_MS`, which is private to
  `webfile_internal.h`).
- **Third build system:** besides `LIB_SRCS` (static lib) the client also builds
  `libbrix.so` / `libbrixposix_preload.so` from `PIC_OBJS := $(LIB_SRCS:.c=.pic.o)`
  — adding `cpool.c`/`web_ka.c` to `LIB_SRCS` covers all three automatically, but
  the `.so`s are OPT_BINS and must be rebuilt explicitly
  (`make libbrixposix_preload.so libbrix.so`) or `test_xrootdfs.py` fails with
  `undefined symbol: brix_cpool_checkout` from a stale preload. (`split_files_three_build_systems`.)
- **Test wiring corrections vs §12.4/§12.8 sketches:**
  - `cpool_unit.py` follows the real `run_checks(base)`/`entry(argv)` pattern (per
    `brixmount_unit.py`), NOT the guessed `compile_binary(name, SRCS, includes=…)`
    API. It compiles with `-DXRDPROTO_NO_NGX` and links `status.c` +
    `shared/xrdproto/build/{kxr_names,error_mapping}.o` (the two symbols
    `status.c` pulls in). A one-line `tests/test_cmd_cpool_unit.py` is the pytest
    entry (mirrors `test_cmd_brixmount_unit.py`).
  - `test_xrootdfs_web_conn_reuse.py` defines `CLIENT_DIR`/`REPO` locally
    (they are NOT in `settings.py` — the compression test defines them the same
    way) and skips when the WebDAV port is down.
  - The sever test stats an **uncached** path after severing (`zzz-unvisited-dir/
    zzz-file`) — the already-stat'd entry is served from the FUSE attr cache and
    would not touch the network, so it could never surface the sever. The
    uncached path forces a live PROPFIND → honest errno, not a hang.

---

## 15. brixcvmfs handle pooling — uniformity follow-on (LANDED 2026-07-18, UNCOMMITTED)

On explicit request ("wrap brixcvmfs's libcurl handles in `brix_cpool` too, purely
for uniformity"), the CVMFS driver's handle *lifecycle* was moved onto the same
`brix_cpool` engine. This is **cosmetic uniformity, not a reuse/perf change** —
libcurl already keeps its connection cache on the easy handle.

**What changed (`client/apps/fs/brixcvmfs.c` only):**
- The two ad-hoc easy handles — the foreground global `g_curl` and the prefetch
  worker's `brix_prefetch_t.curl` — are **gone**. Both are replaced by a single
  process-wide `brix_cpool *g_curl_pool` whose opaque per-slot conn memory is one
  `CURL *` (vtable: `connect = curl_easy_init`, `close = curl_easy_cleanup`,
  `conn_size = sizeof(CURL *)`). `BRIX_CURL_POOL_SLOTS = 4` (foreground under FUSE
  `-s` + the one prefetch worker + slack).
- `brixcvmfs_transport()` now `brix_cpool_checkout`s a handle at entry and
  `brix_cpool_checkin(…, 1)`s it at exit (single return path, no `goto`; the
  success `return 0` became `ret = 0; break`). Checkout hands **exclusive**
  ownership, which *preserves* the original "each thread owns its handle"
  invariant (libcurl easy handles are not concurrency-safe) without the manual
  `CURL **slot` / `transport_ud` threading — that arg is now `(void) ud`.
- Health is always `1` on checkin: a libcurl handle owns its own connection cache
  and re-establishes internally, so it never needs the pool's health-drop. `-o
  fresh` still forces a fresh connection per request via the per-call setopt.
- The pool is created in `brixcvmfs_open()` right after `curl_global_init()` (so
  eager slot-0 `curl_easy_init` runs before the mount fetches the root catalog)
  and destroyed by `transport_cleanup()` (`brix_cpool_destroy` → `curl_easy_cleanup`
  every slot — this also fixes a pre-existing prefetch-handle leak, which was
  never cleaned up).

**Trade-off (accepted, it's uniformity):** with one shared pool, a checkout may
hand a handle warm-for-host-A to a request for host-B (foreground vs prefetch
hitting different mirrors) → libcurl just opens a fresh connection for B (no
correctness issue, a marginal reuse miss vs. the old role-pinned handles). For
the common single-origin repo this never triggers.

**No new build/test files.** `cpool.c` is already in `LIB_SRCS` (§12.5) and
`brixMount` links `libbrix.a`, so no Makefile change. The `brix_cpool` engine is
already covered by `cpool_unittest.c`; the CVMFS transport is exercised end-to-end
by the existing `test_cvmfs_conformance_fuse_*` + `test_cvmfs_prefetch.py`
(foreground+worker concurrency) + `test_cvmfs_prewarm.py` suites.