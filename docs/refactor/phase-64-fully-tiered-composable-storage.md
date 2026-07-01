# Phase 64 — Fully-tiered composable storage: backend + read-cache + write-stage as interchangeable filesystems, FRM/tape migrated into a backend FS, one cache + one stage

**Status: DESIGN (2026-06-30) — implementation-ready, self-contained.** Builds on
phase-63 (composable cache/stage/backend stack), phase-62 (VFS namespace + metadata
seam closure), phase-55+ (the SD-driver seam), the §14 `xrootd_credential` block, the
FRM durable stage queue, and the `xfer` generic byte-mover. Umbrella spec, decomposed
into five independently-shippable sub-projects (SP1 §22, SP2 §23, SP3 §24, SP4 §25,
SP5 §26). SP1 is specified to file-and-function depth; SP2–SP5 to interface depth.

> **Five standing principles.**
>
> **P1 — "Needs development", never "blocker".** Every driver is intended to serve in
> every role. A driver lacking a slot for a role is a tracked **development task**
> (§3 status matrix, the sub-project backlogs), never "won't work" / "cannot" /
> "unsupported." A new slot drops in behind the existing vtable.
>
> **P2 — No legacy, no back-compat.** No cache deployments exist to preserve. The
> tiered grammar is the **only** configuration after this phase. The legacy
> `xrootd_cache_origin*`, `xrootd_cache_root`, `xrootd_cache_storage_backend`,
> `xrootd_storage_staging` directives and the legacy origin-fetch dispatch are
> **deleted** (§14), not aliased. Cache and stage are **optional, modular**; with
> neither, an export is just its backend tier.
>
> **P3 — Keep the cache and VFS layers generic.** The cache is a driver-agnostic
> decorator (`sd_cache`) over a `cstore` adapter; the VFS resolves to the composed top
> and never special-cases a driver/protocol/tier. Every expansion (§10) is generic —
> no branch above the SD vtable.
>
> **P4 — Tape/FRM is a tier and makes cache+stage REQUIRED.** A nearline backend
> cannot be served directly; a recall *is* an async cache-fill, a migration *is* a
> stage-flush. A `tape` backend **requires** a cache tier (the recall target) and —
> for writes — a stage tier. FRM's durable queue + waiter + the `xfer` mover are the
> **one async-staging engine** for recall, migrate, write-back, and upload (§11).
>
> **P5 — One cache, one stage; delete the duplicates.** Exactly one caching mechanism
> (`sd_cache`+`cstore`) and one staging mechanism (`sd_stage` + the staging engine).
> The parallel systems — POSC upload-stage (`compat/staged_file.c`), `vfs_scratch`, S3
> multipart staging, the slice cache, `writethrough_*` flush, the FRM-private stage
> path — are **folded into** the two decorators + the one engine, and their
> non-generic duplicate code is **removed** (§13).
>
> **P6 — FRM migrates INTO a backend filesystem.** FRM is not a parallel subsystem
> that drivers call — it **becomes** the `frm` nearline backend FS driver. `src/frm/`
> is dissolved (§13b): its generic durable-transfer substrate (the queue + waiter +
> reconcile + index) is extracted into the shared `stage_engine` (P5's one engine),
> and its tape-residency logic (recall / migrate / purge / the online↔offline model)
> moves into `src/fs/backend/frm/sd_frm.*`, exposing the SD vtable (`stat`/`pread`/
> `staged_*`/`recall`) over the residency model and using `stage_engine` for
> durability. Tape storage is then *just another backend tier* (P4) served by a real
> SD driver — no special FRM code path remains above the seam.

> **Reading guide.** §1–§9 model; §10–§17 mechanisms in detail; §13 the
> duplicate-consolidation manifest; §14 the legacy-removal manifest; §18–§21
> cross-cutting detail (failure, observability, security, perf); §22–§25 per
> sub-project manifests + tests; Appendices A–H exact references.

---

## 1. Vision

A nginx-xrootd node is a **stateless composing router** over up to three **tiers**,
each a complete, self-describing filesystem holding **its own data AND metadata**:

```
        client  (root:// / WebDAV / S3)
              │            ┌─ each tier = ONE xrootd_sd_instance_t from
   ┌──────────▼───────────┐│   { driver, location, credential }, addressable as:
   │  read-cache   (tier)  ││     posix:/dir   pblock:/dir
   │   store: <any FS>     ││     roots://host:1094[/sub]   (xroot + ztn/GSI)
   └──────────┬───────────┘│     https://host/base         (WebDAV + token/mTLS)
   ┌──────────▼───────────┐│     s3://host/bucket          (SigV4)
   │  write-stage  (tier)  ││     rados://pool[/ns]         (cephx)
   │   store: <any FS>     ││     tape://mss[/pool]         (FRM recall/migrate)
   └──────────┬───────────┘│
   ┌──────────▼───────────┐│   node holds NO durable state: cinfo, locks, slice
   │   backend     (tier)  ││   index, and the recall/write-back journal live on
   │   store: <any FS>     ││   each tier's own FS. cache+stage are OPTIONAL,
   └──────────────────────┘│   EXCEPT a tape backend REQUIRES them (P4).
```

The cache always fronts the backend tier (one authoritative source). A node can be
three physical servers — a fast read-cache server, a fast write-stage server, a slow
block (or tape) backend — composed into one logical namespace.

### 1.1 Goals (acceptance criteria)

| # | Goal | Verified by |
|---|---|---|
| G1 | `backend`/`cache`/`stage` orthogonal | §4 grammar; SP1 compose-matrix |
| G2 | Any tier store = any driver, local/remote, with a credential | §3 matrix; SP1+SP3 |
| G3 | Each store holds 100% of its bytes (data **and** metadata) | SP2 restart-survives-warm-hit |
| G4 | Zero handler changes across root:// / WebDAV / S3 | composed instance via the existing VFS dispatch |
| G5 | Cache+VFS have **no** driver/protocol special-casing (P3) | review: only `cstore`/`tier_build` `strcmp` a driver |
| G6 | No legacy cache config/fetch path survives (P2) | `grep` of deleted symbols = 0 (§14) |
| G7 | Missing role slot = **"needs development"** (P1) | §8.4; §3 |
| G8 | `tape` backend without cache = config error (P4) | §9.4; SP4 |
| G9 | Exactly one cache + one stage mechanism (P5) | §13: deleted/folded inventory `grep`s to 0 |

### 1.2 Non-goals

No new client protocols; no multi-node cache coherence; no replacement of pblock's
SQLite catalog or the FRM **queue** model (reused, §11).

---

## 2. The tier model

### 2.1 Types (`src/fs/tier/tier.h`)

```c
typedef enum { XROOTD_TIER_BACKEND=0, XROOTD_TIER_CACHE=1, XROOTD_TIER_STAGE=2 }
    xrootd_tier_role_t;

/* One tier, parsed from "<scheme>:<location> [credential=<n>] [block_size=<n>]". */
typedef struct {
    xrootd_tier_role_t          role;
    char                        driver[16];   /* posix|pblock|xroot|http|s3|rados|tape */
    char                        host[256];    /* remote; "" local                   */
    int                         port, tls;
    char                        path[1024];   /* dir | /sub|/bucket|/pool[/ns]|/mss  */
    const xrootd_credential_t  *credential;   /* §14; NULL = anonymous              */
    size_t                      block_size;   /* pblock                             */
    unsigned                    nearline:1;   /* driver reports async-recall reads   */
    unsigned                    configured:1;
} xrootd_tier_cfg_t;

typedef struct {
    xrootd_tier_cfg_t     backend, cache_store, stage_store;
    xrootd_cache_policy_t cache;
    xrootd_stage_policy_t stage;
    xrootd_sd_instance_t *composed;           /* top-of-stack, lazy per worker      */
} xrootd_tier_stack_t;

typedef struct { char slot[32]; char cap[24]; char sp_item[16]; } xrootd_tier_gap_t;
typedef enum { XROOTD_TIER_READY=0, XROOTD_TIER_NEEDS_DEV=1 } xrootd_tier_status_t;
```

### 2.2 Per-role capability contract — a **development target** (P1)

| Role | Target slots (non-NULL) | Target caps |
|---|---|---|
| `backend` read-only | `open`,`pread`,`stat`,`fstat` | `RANGE_READ` |
| `backend` writable | + `staged_open/_write/_commit/_abort` | + `RANDOM_WRITE` |
| `backend` nearline (tape) | + `recall` (§9.3); reads may return `EINPROGRESS` | + `NEARLINE` |
| `cache_store` | `open`,`pread`,`stat`,`staged_*`,`unlink`,`opendir`,`readdir`,`closedir`,`getxattr`,`setxattr` | `RANGE_READ`,`RANDOM_WRITE`,`DIRS`,`XATTR` |
| `stage_store` | `staged_*`,`open`,`pread`,`unlink`,`getxattr`,`setxattr` | `RANDOM_WRITE`,`XATTR` |

```c
xrootd_tier_status_t xrootd_tier_status(const xrootd_tier_cfg_t *t,
    xrootd_sd_instance_t *probe, xrootd_tier_gap_t *gap_out);
```
Returns `READY`, or `NEEDS_DEV` with the first missing slot/cap + the sub-project that
will add it (§8.4). The design commits to closing every gap; the §3 matrix is the
backlog. Two new caps over phase-55: `XROOTD_SD_CAP_NEARLINE` and the `recall` slot;
both additive (existing drivers leave them 0/NULL).

### 2.3 Cache policy (`xrootd_cache_policy_t`) — fresh fields (no legacy conf, P2)

```c
typedef struct {
    off_t       max_file_size;    /* xrootd_cache_max_object                       */
    ngx_uint_t  evict_at;         /* xrootd_cache_evict_at  (percent full → evict)  */
    ngx_uint_t  evict_to;         /* xrootd_cache_evict_to  (percent target)        */
    int         verify;           /* xrootd_cache_verify    (OFF|ON|STRICT)         */
    regex_t    *include_regex;    /* xrootd_cache_include                           */
    ngx_array_t*deny_prefixes;    /* xrootd_cache_deny                              */
    ngx_array_t*allow_prefixes;   /* xrootd_cache_allow                             */
    time_t      dirty_max_age;    /* xrootd_cache_dirty_max_age                     */
    size_t      slice_size;       /* xrootd_cache_slice (0 = whole-file)            */
    int         meta_mode;        /* XROOTD_CMETA_AUTO|_LOCAL|_XATTR|_SIDECAR        */
    int         batch_cinfo;      /* -1 auto | 0 per-op | 1 batch-on-commit          */
    size_t      l1_entries;       /* xrootd_cache_index_cache (per-worker LRU)        */
} xrootd_cache_policy_t;
```

### 2.4 Stage policy (`xrootd_stage_policy_t`)

```c
typedef struct {
    int                    flush_mode;   /* XROOTD_WT_MODE_SYNC|_ASYNC                */
    xrootd_wt_decision_fn  fn;           /* prefix/size decide policy (kept)          */
    void                  *decision_conf;
} xrootd_stage_policy_t;
```

---

## 3. The development-status matrix (P1, P4)

`READY` = done; `DEV/SPn` = tracked in that sub-project. No cell is a permanent "no".

| Driver | `backend` | `cache_store` | `stage_store` | data | metadata | recall |
|---|---|---|---|---|---|---|
| `posix` | READY | READY | READY | file | xattr/sidecar | n/a |
| `pblock` | READY | READY | READY | block file | `user.*` row | n/a |
| `xroot` | READY | READY | READY | kXR_read/write | kXR_fattr | n/a |
| `http`/WebDAV | r READY; w READY | READY | READY | GET/PUT | DAV prop | n/a |
| `s3` | r READY; w READY | READY | READY | GET/PUT/MPU | `x-amz-meta-*` | n/a |
| `rados` | READY | READY | READY | librados obj | omap | n/a |
| `frm` (nearline; `tape://`) | READY³ | n/a | migrate→this backend | online `pread` / offline recall | residency + MSS adapter | READY³ |

The `frm` driver is the migrated FRM subsystem as a backend FS (P6, §13b); `tape://`
is its config scheme. There is no separate "tape" driver — `frm` *is* it.

³ The `frm` nearline backend serves (recall + cache) and migrates (write→stage→tape)
over a pluggable `xrootd_mss_adapter_t`: the built-in **stub** (local-dir simulator,
sync or — with a delay — async) and a real **`exec`** adapter ($XROOTD_FRM_STAGECMD,
the classic FRM stage-command HSM model). An **async** recall does not block: the open
"parks" and the HTTP plane answers **202 "staging" + Retry-After** (§9.2, the WLCG
HTTP-tape model); the client polls until the recall brings the object online into the
cache tier and it serves. Verified by `run_tape_recall_async.sh` +
`run_tape_exec_adapter.sh` (sync recall + the §3 stage_store flush already cover
migrate). **SP4 durable recovery — DONE for staged writes (§11.3):** with
`$XROOTD_STAGE_JOURNAL_DIR` set, an async stage **FLUSH** is journaled; on restart
worker-0 `xrootd_stage_reconcile` rebuilds both tiers from the export anchor on the
record and re-flushes the durable staged object — so a crash mid-flush never loses
the write. A NON-staged direct write is the opposite: its interrupted
`<final>.xrd-tmp.<pid>.*` temp is **reaped** at startup (dead owner pid ⇒ orphan;
live pid ⇒ an in-flight write of a draining worker, kept — reload-safe). Verified by
`run_stage_reconcile.sh` (kill -9 before flush → reconcile recovers it) +
`run_nonstaged_reap.sh`. The async stage-flush **mover runs off-loop** (the scheduler
tick offloads it to the thread pool, bounded in-flight, inline fallback), so an async
FLUSH to a *remote* backend completes without blocking/failing on the un-pumped loop
(`run_stage_async_remote_flush.sh`: flush to a remote `root://` origin). The nearline
**recall parks over both protocols**: WebDAV answers 202 + Retry-After, and root://
answers **kXR_wait** (the open faults `EAGAIN` from the cache driver →
`xrootd_send_wait`; the native client sleeps + re-sends, the worker never blocks) —
`run_tape_recall_stream.sh`. **Remaining SP4/SP5 (substrate, not capability):**
HPSS/CTA-native MSS adapters (the `exec` stagecmd adapter covers the generic case,
and these need their vendor libraries to build/test), and the mechanical
**dissolution of `src/frm/`** (§13b: move the generic queue/waiter/reconcile into
`stage_engine`, delete the `xrootd_frm_*` directives — a large P6 refactor).

The `xroot` row is fully READY: a socket-wire driver cannot open/read on the
un-pumped HTTP event loop (eager connect + `kXR_read` + `kXR_fattr`), so serving a
remote `xroot` primary backend OR a remote `xroot` `cache_store` runs the whole
open + cinfo + miss-fill + read on the thread pool, materialises a local temp, and
sendfiles it (`src/shared/http_serve_offload.c` — the serve-readback complement to
the off-loop FILL). In-process (`rados`) and curl (`s3`/`http`) backends block-but-
complete on-loop and serve inline. Verified by `run_remote_backend_serve_offload.sh`
+ `run_xroot_cachestore_serve.sh`.

The `http`/`s3` rows are writable: `sd_http` gained a buffered staged PUT + DELETE
and `sd_remote` (s3) gained `staged_*` (single-PUT / multipart upload via `sd_s3`) +
DELETE, so an HTTP/WebDAV origin or an S3 endpoint serves as a writable backend and a
`stage_store` (the flush reads the staged object on the write worker, then drops it).
Their `cache_store` role works too via **SIDECAR** cinfo mode (`cstore.c` +
`cinfo_sidecar.c`): a store with no `user.*` xattr surface persists each object's
hit-state as a co-located `<key>.xrdcinfo` OBJECT, written through the store's own
staged PUT and read back via open/pread — the same self-contained POD as XATTR/LOCAL,
a different carrier (§6.2/6.3). Verified by `run_http_store_writable.sh` +
`run_s3_store_writable.sh` + `run_cachestore_sidecar.sh` (cold fill writes the
sidecar; a post-restart hit with the source hidden loads cinfo from the sidecar and
serves from the store).

**Every driver now serves in every role** (`frm`/`tape` is SP4): SP3's §3 matrix is
closed. The remaining SP3 long tail is efficiency, not capability — object-store
eviction wants `enumerate`-based scanning (object stores have no `opendir`), and the
serve off-load currently targets only the socket-wire `xroot` driver (curl s3/http and
in-process rados serve inline, blocking-but-completing).

---

## 4. The config grammar (the only grammar, P2)

### 4.1 The orthogonal trio (+ a tape example)

```nginx
xrootd_credential grid { x509_proxy /etc/grid-security/x509up; ca_dir /etc/grid-security/certificates; tls on; }

stream { server {
    listen 1094; xrootd on; xrootd_root /export;

    xrootd_storage_backend tape://mss.example credential=grid;   # nearline backend
    xrootd_cache  on;  xrootd_cache_store  pblock:/disk/cache;    # REQUIRED for tape (P4)
    xrootd_cache_evict_at 90;  xrootd_cache_evict_to 80;  xrootd_cache_verify on;
    xrootd_stage  on;  xrootd_stage_store  posix:/nvme/stage;     # writes → migrate to tape
    xrootd_stage_flush async;
}}
```

### 4.2 Store-URL grammar (`xrootd_tier_parse_store`)

```
store-directive := <name> <store-url> [credential=<cred>] [block_size=<size>]
store-url       := <scheme> ":" <location>
scheme          := "posix"|"pblock"|"root"|"roots"|"http"|"https"|"s3"|"rados"|"tape"
location        := posix/pblock: an absolute directory path
                 := root[s]/http[s]/s3/tape: "//" host [":" port] [ "/" path ]
                 := rados: "//" pool [ "/" namespace ]
```

`xrootd_tier_parse_store(ngx_conf_t *cf, ngx_str_t *url, ngx_array_t *args,
xrootd_tier_cfg_t *out, char *err, size_t errcap)`:
1. Split on first `:`; scheme → `out->driver` (`root`/`roots`→`xroot`,
   `http`/`https`→`http`, else literal); `roots`/`https`→`tls=1`; `tape`→`nearline=1`.
2. local (`posix`/`pblock`): `out->path` canonicalised + confined via
   `xrootd_prepare_export_root` (own `rootfd` for openat2 confinement).
3. remote: parse `//host[:port][/path]` (IPv6-bracket aware); default ports (1094
   xroot, 443 https, 80 http, 7480 s3); `out->path` = the remainder.
4. `args`: `credential=<n>` → `xrootd_credential_lookup` (operator error if missing);
   `block_size=<n>` → `ngx_parse_size`.
5. `out->configured=1`; capability status checked after `build_tier`.

### 4.3 Defaults & errors

| Written | Means |
|---|---|
| no `xrootd_storage_backend` | `backend = posix:<xrootd_root>` |
| `xrootd_cache_store /ssd` (no scheme) | `posix:/ssd` |
| `xrootd_cache on` without `_store` | `[emerg]` "xrootd_cache requires xrootd_cache_store" (no legacy default, P2) |
| `xrootd_stage on` without `_store` | `[emerg]` "xrootd_stage requires xrootd_stage_store" |
| `tape://…` backend without `xrootd_cache` | `[emerg]` (G8, §9.4) |

### 4.4 Mirror directives

`xrootd_webdav_{storage_backend,cache,cache_store,stage,stage_store,…}` and
`xrootd_s3_{…}` call the **same** `xrootd_tier_parse_store` + the shared process-wide
credential registry; internal fields live in the `common.*` preamble
(`ngx_http_xrootd_shared_conf_t`) so one parser serves all three protocols.

---

## 5. The composition engine (`vfs_backend_registry.c`)

```c
static xrootd_sd_instance_t *
xrootd_tier_build_stack(xrootd_vfs_backend_entry_t *e, ngx_log_t *log)
{
    xrootd_sd_instance_t *top, *store;
    if (e->stack.composed) return e->stack.composed;             /* memoised per worker */

    top = xrootd_tier_build(&e->stack.backend, log);
    if (!top) return NULL;
    if (e->stack.backend.nearline && !e->stack.cache_store.configured)
        return NULL;          /* G8: tape requires cache — config-time [emerg], §9.4 */

    if (e->stack.stage_store.configured) {
        store = xrootd_tier_build(&e->stack.stage_store, log);
        if (!store) return NULL;
        top = xrootd_sd_stage_create(top, store, &e->stack.stage);   /* §12 */
    }
    if (e->stack.cache_store.configured) {
        store = xrootd_tier_build(&e->stack.cache_store, log);
        if (!store) return NULL;
        top = xrootd_sd_cache_create(top, store, &e->stack.cache);    /* §10 */
    }
    e->stack.composed = top;
    return top;
}
```

`xrootd_tier_build` is the **single** driver-name dispatch (Appendix C):

```c
xrootd_sd_instance_t *xrootd_tier_build(const xrootd_tier_cfg_t *t, ngx_log_t *log) {
    if (!strcmp(t->driver,"posix"))  return xrootd_sd_posix_root_create(t->path, log);
    if (!strcmp(t->driver,"pblock")) return xrootd_sd_pblock_create(t->path, t->block_size, log);
    if (!strcmp(t->driver,"xroot"))  return xrootd_sd_xroot_create_origin(t->host,t->port,t->tls,
                                              cred_bearer(t),cred_proxy(t),cred_cadir(t), log);
    if (!strcmp(t->driver,"http"))   return xrootd_sd_http_create(&http_cfg_from(t), log);
    if (!strcmp(t->driver,"s3"))     return xrootd_sd_remote_create(&s3_cfg_from(t), log);
    if (!strcmp(t->driver,"rados"))  return xrootd_sd_rados_create(&rados_cfg_from(t), log);  /* SP3 */
    if (!strcmp(t->driver,"tape"))   return xrootd_sd_tape_create(&tape_cfg_from(t), log);    /* SP4 */
    return NULL;   /* unknown scheme — operator error, not "needs dev" */
}
```

Ordering: cache outermost → stage → backend. The VFS (`vfs_open.c:59
vctx->sd = xrootd_vfs_backend_resolve(...)`) consumes the composed top **blind** (P3,
G4/G5).

---

## 6. Fully-tiered state via the generic `cstore` (G3, P3)

### 6.1 `cstore` — the cache's one storage adapter (`src/cache/cstore.{c,h}`)

The *only* code touching a cache store driver:

```c
typedef struct {
    xrootd_sd_instance_t *store;
    int                   meta_mode;   /* AUTO|LOCAL|XATTR|SIDECAR (§6.3)            */
    xrootd_cinfo_l1_t    *l1;          /* per-worker write-through cinfo cache       */
} xrootd_cstore_t;

xrootd_sd_staged_t *xrootd_cstore_fill_open (xrootd_cstore_t*, const char *key, mode_t);
ssize_t             xrootd_cstore_fill_write(xrootd_sd_staged_t*, const void*, size_t, off_t);
ngx_int_t           xrootd_cstore_fill_commit(xrootd_sd_staged_t*);
void                xrootd_cstore_fill_abort (xrootd_sd_staged_t*);
xrootd_sd_obj_t    *xrootd_cstore_serve_open (xrootd_cstore_t*, const char *key, int *err);
ssize_t             xrootd_cstore_serve_pread(xrootd_sd_obj_t*, void*, size_t, off_t);
ngx_int_t           xrootd_cstore_evict      (xrootd_cstore_t*, const char *key);
ngx_int_t  xrootd_cstore_cinfo_load (xrootd_cstore_t*, const char *key, xrootd_cinfo_t*);
ngx_int_t  xrootd_cstore_cinfo_store(xrootd_cstore_t*, const char *key, const xrootd_cinfo_t*);
ngx_int_t  xrootd_cstore_lock       (xrootd_cstore_t*, const char *key, const xrootd_lock_t*);
ngx_int_t  xrootd_cstore_scan       (xrootd_cstore_t*, xrootd_cstore_visit_fn, void *ctx);
ngx_int_t  xrootd_cstore_freespace  (xrootd_cstore_t*, uint64_t *total, uint64_t *avail);
```

Mapping (all generic; Appendix C is per-driver): `fill_*`/`serve_*` →
`store->driver->{staged_*,open,pread,unlink}`; `cinfo/lock` → §6.3; `scan` →
`store->driver->{opendir,readdir,stat}`; `freespace` → `store->driver->statf`
(phase-62 slot) or `statvfs` for posix.

### 6.2 The cinfo record is already portable

`.cinfo` (`cinfo.h`: magic `0x58434931` "XCI1", versioned LE header — magic, version,
flags `COMPLETE|PARTIAL`, block_size, size, mtime, nblocks, access_count,
bytes_served, last_access, **dirty_lo/dirty_hi/dirty_since/flush_gen/last_flush** —
plus the block bitmap) is a self-contained blob; `xrootd_cinfo_serialize`/`_parse`
exist. Moving it to an xattr is a transport change, not a format change.

### 6.3 cinfo/meta/lock encoding modes (`meta_mode=AUTO` resolves from store caps)

- **`LOCAL`** (posix store): the `.cinfo`/`.meta`/lock files next to the object —
  byte-identical to the pre-phase-64 tree; existing cinfo unit tests run unchanged.
- **`XATTR`** (any store with `CAP_XATTR`): cinfo blob → xattr `user.xrd.cinfo` via
  `store->driver->setxattr`; `.meta` → `user.xrd.meta`; lock → `user.xrd.lock` (the
  phase-57 xattr-lock). Key registry = Appendix B.
- **`SIDECAR`** (no practical xattr — a dev fallback, P1): a co-located
  `<key>.xrdcinfo` object via `staged_*`.

### 6.4 Remote-store performance policy (`batch_cinfo`, default auto)

For a non-local store: (1) **batch on commit** — the bitmap mutates in L1 during a
fill; one `cinfo_store` (remote `setxattr`) per object on `fill_commit`/evict/
flush-gen-bump (not per block); (2) **L1 write-through** — `xrootd_cinfo_l1_t` keys
cinfo by object per worker (bounded LRU, `xrootd_cache_index_cache`, default 4096),
reads hit L1, misses `getxattr`; (3) **verify = coherence** — `xrootd_cache_verify on`
(checksum-on-fill) is the freshness check, not per-read cinfo reads. A posix store
auto-selects `LOCAL`+`batch_cinfo=0` = the old per-op behaviour (G5).

### 6.5 The slice cache folds into `cstore` (§13)

A partial object is a cinfo with the `PARTIAL` flag + a present bitmap;
`cstore_serve_pread` consults the bitmap and range-fills misses through the fill spine
— there is no separate slice store or `slice_fill.c`.

---

## 7. Reuse vs. new (the honest ledger)

| Concern | Reused | New | SP |
|---|---|---|---|
| SD vtable + caps | phase-55+ `sd.h` | `NEARLINE` cap + `recall` slot; rados/tape; writable http/s3 | SP3/SP4 |
| Registry composition | C-2 | `tier_build`/`tier_build_stack` | SP1 |
| Fill spine | phase-63 `cache_fill_from_source` | `cstore_fill_*` | SP1/SP2 |
| Stage decorator | C-6 `sd_stage.c` | explicit `store`; absorbs upload/multipart/writethrough | SP1/SP2 |
| Read cache | XCache policy modules | `sd_cache` + generic `cstore`; absorbs slice/scratch | SP1/SP2 |
| Async-staging engine | FRM queue+waiter + `xfer` mover | one engine for recall/migrate/write-back/upload (§11) | SP1/SP4 |
| xattr over a driver | phase-62; `sd_xroot` getxattr/setxattr | cinfo/meta/lock as driver xattrs | SP2 |
| Credentials | §14 | per-tier `credential=` | SP1 |
| Tape recall | FRM `FRM_XFER_TAPE` + `waiter.h` | recall = the cache miss-fill (§9) | SP4 |
| Observability gauge | phase-63 C-7 | per-tier `xrootd_tier_info` + `xrootd_stage_*{kind}` | SP1 |

---

## 8. The config processor (SP1)

### 8.1 Single entry point

Each protocol finaliser (`runtime_server.c`, `webdav/config.c`, `s3/module.c`)
replaces its phase-63 backend/credential/staging block with
`xrootd_tier_configure(cf, &xcf->common, err, sizeof err)`
(`src/fs/tier/tier_config.c`): parse the three store URLs into `e->stack.{backend,
cache_store,stage_store}`; populate `e->stack.{cache,stage}` policy PODs from the new
directives; register the entry. Local tiers are status-checked now; remote tiers at
first `build_stack` per worker (a one-time notice, export held inactive — never a
crash).

### 8.2 Registry entry reduced to `{ char root_canon[PATH_MAX]; xrootd_tier_stack_t stack; }`

The flat phase-63 `backend[16]`/`origin_*`/`staging` fields are subsumed by `stack.*`
and **deleted** (§14).

### 8.3 Directives — Appendix D is the full table (new tier + cache-policy directives;
the deleted legacy directives).

### 8.4 "Needs development" reporting (P1)

```
[warn] xrootd_cache_store "rados://pool/ns": the rados driver as a cache store is not
       yet implemented (needs development: slot staged_open, cap XATTR — phase-64 SP3).
       This export is inactive until that driver gains the slot.
```

Always "**not yet implemented / needs development**," never "unsupported"/"cannot." A
*missing credential block* / *unknown scheme* / *tape-without-cache* **is** operator
error → `[emerg]` (Appendix F distinguishes the classes).

---

## 9. Nearline (tape) tier mechanics (P4)

### 9.1 Model

A `tape` backend is nearline: an object is *online* (recalled to the MSS disk buffer)
or *offline* (on tape, minutes-to-hours away). Serving offline data requires a recall
into a faster tier — **exactly a cache miss-fill**, but slow and async, so the open is
**parked** (FRM `waiter.h`) rather than blocked.

### 9.2 Read flow (recall = async cache-fill)

```
client open(read) → sd_cache.open:
    cstore_cinfo_load(key)
    HIT (online in the cache store)        → serve from the cache store
    MISS:
        st = backend->driver->stat(key)
        if st online:    fill spine: backend->pread → cstore_fill_*     (normal miss-fill)
        if st nearline:  rc = backend->driver->recall(key, reqid)
                         frm_waiter_add(reqid, open-options, conn)        # PARK
                         return XRD_ST_AIO / WebDAV 202 "staging"          # async
        # the stage scheduler drives the recall (xfer mover, §11) tape→cache store;
        # on completion frm_waiter_deliver(reqid) wakes parked opens → re-enter
        # sd_cache.open → now a HIT → serve.
```

The **recall target is the cache store tier** (P4): FRM stages tape→cache store (local
or even a remote `roots://` cache server), cinfo records the now-online object. The
node holds no recall state beyond the FRM durable queue.

### 9.3 The `recall` advisory slot

```c
/* Initiate or join an async recall of `key` into the cache store. Returns NGX_AGAIN
 * (queued/in-flight; park), NGX_OK (already online; do a normal fill), or NGX_ERROR.
 * NULL on non-nearline drivers. */
ngx_int_t (*recall)(xrootd_sd_instance_t *inst, const char *key, char reqid_out[40]);
```

The `frm` backend driver's `recall` (the migrated FRM, §13b) = `xrootd_stage_submit(RECALL,…)` (§11). A
future MSS-native driver (HPSS/CTA) implements `recall` against its API, plugged into
the **same** waiter/queue.

### 9.4 tape REQUIRES cache (+stage for writes) (G8)

A nearline backend with no `cache_store.configured`:
`[emerg] xrootd_storage_backend "tape://…" is nearline and requires xrootd_cache (the
recall target); add xrootd_cache on; xrootd_cache_store <fast FS>;`. A writable tape
export also requires a stage tier (writes buffer there, then migrate = flush, §9.5).

### 9.5 Write flow (migrate ≡ stage-flush, no separate path)

A write lands in the stage store (sd_stage); the stage **commit** flushes to the
backend. For a tape backend the flush is the migration (disk-stage → tape), enqueued
as `FRM_XFER_WT` on the same FRM queue, driven by the same `xfer` mover. There is no
migrate-specific code — it falls out of the generic stage flush whose `source` driver
is `tape`.

---

## 10. The generic VFS / cache layering (P3)

- **VFS** (`src/fs/vfs_*.c`): only change — `xrootd_vfs_backend_resolve` returns a
  **composed** instance. `xrootd_vfs_open`/`_read`/`_write`/`_stat`/the staged path
  call `ctx->sd->driver->*` exactly as today; no VFS branch knows about cache/stage/
  tiers (G4/G5). `xrootd_vfs_staged_*` (Mode-A passthrough after C-6) keeps delegating
  to `ctx->sd->driver->staged_*`.
- **Cache** (`src/cache/*`): the policy modules (`cache_admit.c`, `evict_*.c`,
  `verify.c`, `cache_reap.c`, `reap_watermark.c`, `cache_fs_sampler.c`) keep their
  logic, swap storage calls to `cstore`. They never branch on driver type.
- **The cache open path** (`open_or_fill.c`/`open.c`) becomes the `sd_cache` decorator
  `open` (§10); the legacy `fetch.c` scheme-dispatch is deleted (§14); there is one
  generic fill: `backend->open/pread → cstore_fill_*`.
- **Code-review gate (G5):** no file under `src/cache/` or `src/fs/vfs_*.c` may
  `strcmp` a driver name or branch on a protocol — only `cstore`/`tier_build`/the
  staging engine may.

---

## 11. The one async-staging engine (P4, P5)

### 11.1 The engine = FRM's generic substrate, EXTRACTED (P5 + P6)

The generic durable-transfer machinery is **extracted out of `src/frm/`** (P6, §13b)
into `src/fs/xfer/stage_engine.{c,h}` — it was never tape-specific: (a) the **durable
queue** (`queue.c`/`reqfile.c`/`reqid.c`/`index.c`/`reconcile.c`/`reaper.c`/`compact.c`,
keyed by `frm_xfer_kind_t` = `FRM_XFER_TAPE`/`FRM_XFER_WT`); (b) the **waiter**
(`waiter.c`/`.h` — `frm_waiter_add`/`_deliver`/`_poll_local`, parks/wakes stalled
opens); (c) the **generic byte mover** (`xrootd_xfer_mover_t`, `xfer/xfer_mover_*.c`) +
the audit ledger. After extraction this is **the one engine** every async-staging
caller uses — the `sd_stage`/`sd_cache` decorators *and* the `frm` backend driver (its
recall/migrate). `src/frm/`'s queue/waiter/reconcile become `stage_engine`; its
tape-residency becomes the `frm` driver (§13b). The API:

```c
typedef enum {
    XROOTD_STAGE_RECALL    = FRM_XFER_TAPE,   /* tape → cache store      (in)  */
    XROOTD_STAGE_FLUSH     = FRM_XFER_WT,     /* stage store → backend   (out) */
    XROOTD_STAGE_UPLOAD    = 2,               /* client body → stage store(in) */
    XROOTD_STAGE_MULTIPART = 3,               /* S3 part → stage store   (in)  */
} xrootd_stage_kind_t;

typedef struct { unsigned async:1; off_t size_hint; uint16_t open_options;
                 ngx_connection_t *conn; } xrootd_stage_opts_t;

/* Enqueue a durable transfer src(driver+key) → dst(driver+key) of `kind`; the xfer
 * mover drives it; the waiter wakes parked opens on completion. Returns the reqid
 * (to park on) or "" if it ran inline. */
const char *xrootd_stage_submit(xrootd_stage_kind_t kind,
    xrootd_sd_instance_t *src, const char *src_key,
    xrootd_sd_instance_t *dst, const char *dst_key,
    const xrootd_stage_opts_t *opts);
```

`xrootd_stage_submit` = `frm_request_add` + the `xfer` mover, generalised so `src`/
`dst` are **SD instances** (any driver) instead of the FRM-specific
local-path/`stagecmd`. The mover is the generic `staged_*`/`pread` loop (the phase-63
promote loop), driver-agnostic.

### 11.2 Callers (one engine for all four kinds)

- **recall** (§9.2): `sd_cache` miss on a nearline backend → `submit(RECALL, backend,
  key, cache_store, key)` + park.
- **flush/migrate** (§9.5): `sd_stage.staged_commit` → `submit(FLUSH, stage_store,
  key, backend, key)`.
- **upload** (§13): the POSC/WebDAV PUT path → `sd_stage` → `submit(UPLOAD,
  client-body, key, stage_store, key)` (or inline for small bodies).
- **multipart** (§13): each S3 part → an `sd_stage` part write; `CompleteMultipart` →
  assemble on the stage store, then a normal `FLUSH`.

One queue, one waiter, one mover, one ledger — for every async data movement.

### 11.3 State machine (Appendix H) — submit → durable enqueue → (park | inline) →
scheduler pops → mover copies → complete → waiter wakes; restart → reconcile replays
in-flight reqids (no loss).

---

## 12. The `sd_cache` + `sd_stage` decorators

### 12.1 `sd_cache` (`src/fs/backend/cache/sd_cache.{c,h}`)

```c
typedef struct { xrootd_sd_instance_t *source; xrootd_cstore_t cstore;
                 xrootd_cache_policy_t policy; } sd_cache_inst_state;
```

Slot behaviour (generic, no driver branch):
- `open(READ)`: `cstore_cinfo_load(key)`. **Fresh complete hit** → `cstore_serve_open`
  (store-backed read obj; `obj->driver`=store, so `pread` bypasses the decorator).
  **Miss/stale** → admit filter (policy) → if nearline-source: §9.2 recall+park; else
  fill spine `source->open/pread → cstore_fill_*` → `cstore_cinfo_store` (batched) →
  return the store-backed read obj. **Partial** → cinfo bitmap range-fill (§6.5).
- `open(WRITE/CREATE/TRUNC)`: pass through to `source->driver->open`; on a successful
  write invalidate the cached copy (`cstore_evict`/cinfo drop).
- namespace (`stat`/`unlink`/`rename`/`mkdir`/`opendir`/`readdir`/`getxattr`/…):
  forward to `source`; `unlink`/`rename` also `cstore_evict(key)`.
- `staged_*`: forward to `source`. `caps`: `source` caps (transport-transparent).
- **async boundary preserved**: a miss-fill runs only on the fill worker; the
  hit/miss + offload stay on the event loop (root://); WebDAV/S3 run inline on their
  worker. The decorator never blocks the event loop.

### 12.2 `sd_stage` (`src/fs/backend/stage/sd_stage.{c,h}`)

`sd_stage_create(source, store, policy)` (was `(source, stage_root, log)`):
`staged_open`→`store->driver->staged_open`; `staged_write`→`store->driver->staged_write`;
`staged_commit`→ `xrootd_stage_submit(FLUSH, store, key, source, key)` (async) or
inline (sync). A `posix:` stage store is byte-identical to phase-63. The
crash-mid-flush journal **is** the FRM durable queue (`FRM_XFER_WT`), living on the
stage store for a remote stage (SP2).

---

## 13. Consolidation manifest — one cache, one stage (P5: FOLD + DELETE)

| Duplicate system | Files | Folds into | Deleted / kept |
|---|---|---|---|
| POSC/WebDAV upload-stage dir | `compat/staged_file.c`, `webdav/put.c` staging | `sd_stage` + `submit(UPLOAD)` | the bespoke `xrootd_staged_open`/`commit_staged` upload path **deleted** |
| materialize-to-scratch | `fs/vfs_scratch.{c,h}` (callers `frm/stage.c`, `zip/zip_member.c`) | `cstore_fill_*` / `submit(RECALL)` for FRM | `vfs_scratch` **deleted**; FRM stage uses the engine; zip uses `cstore` |
| S3 multipart staging | `s3/multipart_*.c` | `sd_stage` (parts = staged writes) + `submit(MULTIPART)` | the S3-private on-disk part buffer **deleted**; the S3 protocol layer (part list, ETags) **kept**, its storage through `sd_stage` |
| slice cache | `cache/slice.c`, `slice_fill.c` | `cstore` partial-object (cinfo `PARTIAL` bitmap) | `slice*.c` **folded into `cstore`** |
| write-through flush | `cache/writethrough_flush.c` (+ `_decision`,`_replay`) | `sd_stage` commit + `submit(FLUSH)`; `_decision`→`stage.policy.fn`; `_replay`→FRM reconcile | `writethrough_flush.c` flush loop **deleted**; decide + replay **kept** (re-homed) |
| **the entire FRM subsystem** | `src/frm/*` | **migrated** (§13b): generic substrate → `stage_engine`; residency → the `frm` backend FS driver | `src/frm/` **dissolved**; the `stagecmd` subprocess + scratch **deleted**; no `src/frm/` path survives (P6) |

**Survivors everything routes through:** `sd_cache`+`cstore` (the one cache);
`sd_stage` (the one stage decorator); `xrootd_stage_submit` + `xfer` mover +
`stage_engine`'s durable queue/waiter/reconcile (the one async-staging engine, ex-FRM);
the `frm` backend FS driver (the one tape/nearline implementation); `cinfo`/`meta`/
`lock` (re-homed onto `cstore`); the SD drivers.

**Acceptance (G9):** after SP1+SP2+SP4, `grep -r` finds no caller of
`xrootd_staged_open` outside `sd_stage`, no `vfs_scratch`, no `slice_fill`, no
`writethrough_flush` flush loop, no S3-private disk part buffer, and **no `src/frm/`
directory** — every data-staging path resolves to `xrootd_stage_submit` + the two
decorators, and tape is the `frm` backend driver.

---

## 13b. FRM → backend-filesystem migration manifest (P6)

`src/frm/` (~3850 LOC) is dissolved into two homes; nothing keeps the `frm` *subsystem*
identity. The split is along the line that was always there — generic durable transfer
vs. tape-specific residency:

| `src/frm/` file | LOC | New home | Role after migration |
|---|---|---|---|
| `queue.c` | 630 | `fs/xfer/stage_engine.c` | the durable transfer queue (generic) |
| `reqfile.c` | 361 | `fs/xfer/stage_engine.c` | the on-disk request record |
| `reqid.c` | 63 | `fs/xfer/stage_engine.c` | request id minting |
| `index.c` | 359 | `fs/xfer/stage_engine.c` | the in-flight index (generic) |
| `reconcile.c` | 116 | `fs/xfer/stage_engine.c` | restart replay (generic durability) |
| `reaper.c` | 99 | `fs/xfer/stage_engine.c` | completed-request GC |
| `compact.c` | 38 | `fs/xfer/stage_engine.c` | queue compaction |
| `waiter.c` / `.h` | 338/57 | `fs/xfer/stage_engine.c` | park/wake stalled opens (generic) |
| `stage.c` | 578 | `fs/backend/frm/sd_frm.c` | the **recall** slot (delete the `stagecmd` subprocess; use the engine + the driver's own MSS call) |
| `migrate_purge.c` | 142 | `fs/backend/frm/sd_frm.c` | **migrate** (staged_* flush) + **purge** (unlink) |
| `residency.c` | 248 | `fs/backend/frm/sd_frm.c` | the online/nearline/offline **stat** model |
| `directives.c` | 142 | split: queue knobs → tier/engine config; MSS knobs → the `frm` tier's store-URL params |
| `metrics.c` | 120 | `fs/xfer/stage_engine.c` (the `xrootd_stage_*{kind}` family, §19) |
| `frm.h`/`frm_internal.h`/`frm_format.h` | 559 | split: the durable-record format → `stage_engine.h`; the residency model → `sd_frm.h` |

After migration: tape is configured as `xrootd_storage_backend tape://mss credential=…`
(no `xrootd_frm_*` directives — they're gone); the `frm` driver's `stat`/`recall`/
`staged_*` implement residency over `stage_engine`; the cache tier is the recall target
(P4). The MSS access method (the old `stagecmd`) becomes the `frm` driver's pluggable
MSS adapter (an exec adapter for legacy `stagecmd`, or an in-process HPSS/CTA adapter),
selected on the `tape://` store-URL — a driver detail, below the seam.

### 13c. Dissolution ORDER (the safe migration sequence — P6 execution)

§13/§13b give the end-state mapping; this is the dependency-ordered sequence to GET
there without breaking the tree. `src/frm/` is one live, interconnected subsystem (a
caller audit: the internal machinery — `reqfile`/`index`/`reaper`/`compact`/`reqid`/
`waiter` — all serves the durable queue; the only EXTERNAL entries are the residency
probe, the FRM queue ops, the write-through `xrootd_wt_*`, the `xrootd_frm_*`
directives, and the process.c init). Nothing is independently dead, so cuts proceed
per-consumer, each gated on a green build + the relevant tests:

1. **Residency seam** (precondition) — ✅ **DONE + verified**. Add
   `xrootd_vfs_residency(ctx, &out, &nearline_export)` backed by the composed
   instance (the `frm` backend's residency for a `tape://` export; ONLINE otherwise).
   **Boundary correction:** the "8 consumers" framing conflated two groups. The
   read-only residency **ADVERTISEMENTS** are the real consumers and are ALL migrated
   to the seam: `s3/object.c` (×2), `webdav/propfind_props.c`, `read/stat.c`,
   `read/statx.c` (and root:// open faults go through the recall-park, not a probe).
   But `read/open_request.c`'s STAGE gate (it *queues an FRM stage*) and
   `webdav/tape_rest.c` (the WLCG Tape REST API — `frm_request_*` on nearly every
   line; its `frm_file_locality` reads SHOULD reflect the OLD FRM's own residency
   because it IS the OLD FRM's HTTP API) are NOT residency "consumers" — they are the
   OLD FRM **machinery itself** and migrate WITH the queue removal (steps 2-3), not as
   seam swaps. So `residency.c` stays until the OLD FRM is re-architected.
   **STATUS (step 1a DONE + verified):** the seam exists and is proven — an SD
   `residency` vtable slot + `xrootd_sd_residency_t` (`fs/backend/sd.h`),
   `sd_frm_residency` over the MSS adapter (`fs/backend/frm/sd_frm.c`), and
   `xrootd_vfs_residency(ctx, &out, &nearline_export)` (`fs/vfs_stat.c`) which walks
   any cache/stage decorators down to the `CAP_NEARLINE` driver (ONLINE for a
   non-nearline export; the optional `nearline_export` flag lets a caller emit the
   WLCG `ONLINE_AND_NEARLINE` locality). **All THREE protocols' read-only residency
   ADVERTISEMENTS are migrated to the seam:** (a) **s3** (`s3/object.c`, decoupled
   from `frm/frm.h`; the GET check moved BEFORE open so a `tape://` GET → 403
   InvalidObjectState instead of faulting a recall — correct S3/Glacier), coverage
   `tests/run_s3_tape_residency.sh`; (b) **webdav PROPFIND `xrd:locality`**
   (`propfind_props.c`; the whole propfind subsystem's shared header swapped
   `frm/frm.h`→`fs/vfs.h`), coverage in `tests/run_tape_exec_adapter.sh`; (c)
   **root:// `kXR_stat`/`kXR_statx` offline flag** (`read/stat.c`, `read/statx.c`) —
   this also **fixed a real phase-64 gap**: the OLD check was gated on
   `conf->frm.enable`, so a `tape://` export's root:// stat did NOT report
   `kXR_offline` (no FRM config); now backend residency drives it, verified
   `tests/run_tape_recall_stream.sh` (`Flags: …Offline…`, no recall faulted). The
   three old xattr-on-posix tests were converted (`test_frm_phase1_http.py`,
   `test_frm_staging.py`). **REMAINING (folds into steps 2-3):** the root://
   `open_request` STAGE GATE (it *queues an FRM stage*, not just a residency read)
   and webdav `tape_rest` (the WLCG restore API) are queue-entangled — they migrate
   WITH the queue removal. Until `open_request` does, the OLD FRM open-staging still
   honors the xattr while stat does not — a documented transitional state (the
   `test_frm_staging` open-stage tests still pass on the OLD gate). `residency.c`
   stays until then (still used inside the OLD FRM stage path).
2. **Write-through → `stage_engine`.** Route `xrootd_wt_flush_on_close`/`_sync_handle`
   and the restart `_replay` through `sd_stage` commit + `submit(FLUSH)` + the
   stage_engine reconcile (already built); keep the SHM dirty-tracking (re-homed).
   Verify root:// write-back cache flush + crash replay. ⇒ the `xrootd_wt_*` ↔ FRM
   journal coupling gone.
3. **Orphan + delete the FRM queue.** With (1)+(2) done, `queue`/`reqfile`/`reqid`/
   `index`/`reconcile`/`reaper`/`compact`/`waiter`/`metrics`/`stage`/`migrate_purge`
   have no callers → delete; remove the process.c/postconfig `frm_queue_init` /
   `frm_stage_scheduler_register` / `frm_migrate_purge_register` /
   `xrootd_wt_replay_register` init.
4. **Directives.** Delete the `xrootd_frm_*` directives + the `xcf->frm` conf (P2: an
   old config fails `nginx -t` with a pointer to the `tape://` grammar).
5. **Build + tests.** Drop the `src/frm/*` sources from `./config`; delete
   `tests/test_frm_*.py` (superseded by the phase-64 tape tests —
   `run_tape_recall_{async,stream}.sh`, `run_tape_exec_adapter.sh`).
6. **`rm -rf src/frm/`** ⇒ G9 met (no `src/frm/` path survives).

The functional substrate each step migrates ONTO already exists and is verified on the
phase-64 side (the `stage_engine` durable queue + reconcile + off-loop mover; the
`sd_frm` residency/recall/migrate over the MSS adapter); P6 is the consumer migration,
not new capability. Step 1 (the residency seam) is the smallest self-contained start.

---

## 14. Legacy removal manifest (P2: DELETE)

**Directives + conf fields + setters deleted:** `xrootd_cache_origin`, `_origin_tls`,
`_origin_proxy`, `_origin_cadir`, `_origin_client`, `_origin_token_file`,
`_origin_forward_token`, `_origin_s3_*`, `xrootd_cache_root`,
`xrootd_cache_storage_backend`, `xrootd_storage_staging`; the conf fields
`cache_origin_*`/`cache_root`/`cache_storage_backend`; `module_cache_proxy_directives.c`.

**Code deleted:** `fetch.c`'s `cache_origin_scheme` switch +
`xrootd_cache_fetch_origin_xroot`/`_s3` (folded into the one `cstore` fill from the
backend tier); the `XROOTD_CACHE_SCHEME_*` enum; `origin/http_transport.c`,
`origin/pelican.c`, `origin/pelican_register.c` (http/pelican fetch become a **backend
tier** — `http://` driver / a future `pelican://` driver — so the cache-private
libcurl + the scheme dispatch are deleted, their behaviour reachable as a backend
tier); `xrootd_sd_xroot_create(conf)` (the conf-borrowing variant; only
`_create_origin(...)` survives, since there is no `cache_origin*` conf to borrow).

**Kept:** `origin_*.c` (the `sd_xroot` wire client); `cinfo.c`/`meta.c`/`lock.c`/the
eviction modules (re-homed onto `cstore`); the FRM queue model (re-used by the engine).

**Migration:** none. An old config fails `nginx -t` with a pointer to the tier
grammar (Appendix F). A pre-existing on-disk **local** cache tree is readable as a
`posix:` cache store (format unchanged), but no shim translates old directives.

---

## 15. Generic-layer expansion checklist (P3, P5)

- `cstore.{c,h}` — the one storage adapter; only code touching a cache store driver.
- `cinfo`/`meta`/`lock` — gain a `(xrootd_cstore_t *)` param; raw-POSIX bodies behind
  `meta_mode==LOCAL`; XATTR/SIDECAR call `cstore`.
- `evict_*`/`cache_reap`/`reap_watermark`/`cache_fs_sampler` — walk+reclaim via
  `cstore_scan`/`_evict`/`_freespace`.
- `io`/`slice*` → `cstore_fill_*`/`serve_*` (slice folds in, §6.5).
- `open_or_fill`/`open` → the `sd_cache.open` body (event-loop hit/miss + offload
  stays).
- `fetch.c` → the generic `cstore` fill from the backend tier; scheme dispatch deleted.
- `frm/stage.c` → `stage_engine.c` (`xrootd_stage_submit`); `s3/multipart_*` storage →
  `sd_stage`; `vfs_scratch` callers → `cstore`/`submit`; `writethrough_flush` →
  `sd_stage.staged_commit`.
- VFS: no change except the resolve returns a composed instance.

Review gates: G5 (no driver `strcmp` under `src/cache/`/`src/fs/vfs_*.c`) and G9 (the
only data-movement primitives are `xrootd_stage_submit` + the two decorators).

---

## 16. Failure modes (full table)

| Failure | Behaviour | Surfaced as |
|---|---|---|
| backend unreachable on a cache miss | existing redirect-to-origin / 5xx | protocol error / redirect |
| **cache store** unreachable | **bypass the cache**, serve from `source`; never fail the read | `[warn]` + `xrootd_tier_unreachable_total{tier="cache"}`; read succeeds |
| **stage store** unreachable | writes fail fast (cannot buffer durably) | protocol write error |
| driver missing a role slot | export inactive, **"needs development"** (P1) | `[warn]` (§8.4) |
| unknown scheme / missing credential / tape-without-cache | operator error | `[emerg]` (Appendix F) |
| nearline recall in flight | open **parked** (FRM waiter), not failed | XRD_ST_AIO / WebDAV 202; resumes on `frm_waiter_deliver` |
| recall exceeds `stage_ttl` | parked open times out; request stays durable for retry | kXR_wait / client retry; recall not lost |
| partial fill / crash mid-flush | stage journal (FRM queue) + reconcile; commit-then-verify for a torn fill | recovered on restart; no torn serve |
| stage flush (migrate) fails | dirty object stays on the stage store; FRM reconcile retries | `[warn]` + metric; durability preserved |
| cinfo write fails (remote store) | the fill is aborted (no half-cached object claimed fresh); re-fetched next time | `[warn]` + metric; correctness preserved |
| credential expiry (GSI/token) | per-fill instance build reads the current credential; rotation picked up next op | transparent |

Invariant: **a sick cache degrades to "no cache" (slower), never wrong bytes or a
failed read; a sick stage fails writes loudly; a recall is never lost** (the FRM
durable queue owns it).

---

## 17. Security & confinement

- Each local store tier gets its own `rootfd` (openat2 `RESOLVE_BENEATH`), exactly
  like `xrootd_root` — a cache/stage store dir is a confined managed root.
- Remote tiers authenticate via the §14 credential (ztn/GSI with MITM origin-cert
  verify, phase-63 C-3) — identity is a property of the tier, threaded once.
- The cinfo/meta/lock xattrs use the reserved `user.xrd.*` namespace; a client cannot
  set them (the VFS xattr handler already maps client attrs to `user.U.*`).
- The staging engine's `src`/`dst` are SD instances confined to their tier roots; no
  raw paths cross a tier boundary.

---

## 18. Performance notes

- Local store: zero overhead vs. today (`meta_mode=LOCAL`, `batch_cinfo=0`, the
  decorator's hit path returns the store obj directly so `pread` is one indirection).
- Remote cache store: cinfo batched on commit + L1 write-through (§6.4); a warm hit is
  one `cinfo_load` (L1) + a remote `pread` — the same round-trips as reading the
  origin, but from a *fast* cache server.
- Tape: the recall cost is the MSS latency (minutes-hours), fully async via the parked
  open; once online, reads are cache hits at cache-store speed.
- The L1 cinfo cache + the per-tier instance memoisation (per worker) bound the
  control-plane cost.

---

## 19. Observability

`xrootd_tier_info{export,tier="backend|cache|stage",driver,origin,auth,health,status,
nearline} 1` (`status ∈ {ready,needs_dev}`, `health ∈ {up,down}`). The FRM metrics are
re-labelled by `xrootd_stage_kind_t` into one family:
`xrootd_stage_submitted_total{kind}`, `xrootd_stage_completed_total{kind}`,
`xrootd_stage_inflight{kind}`, `xrootd_stage_parked_opens`, plus
`xrootd_cache_hit_total`/`_miss_total`/`_fill_bytes_total`, `xrootd_cache_evicted_total`,
`xrootd_tier_unreachable_total{tier}`. `/healthz` reports each tier's reachability
(cheap `stat("/")` with a short timeout, cached N seconds).

---

## 20. Testing strategy (overview; per-SP specifics in §22–§26)

- **SP1** — the compose matrix (local stores), the needs-dev/operator-error message
  split, the no-legacy + one-stage `grep` gates, phase-63 rewritten onto the grammar.
- **SP2** — a multi-server harness proving state lives remotely
  (restart-survives-warm-hit, remote eviction, cinfo-as-remote-xattr).
- **SP3** — the §3 matrix parametrised (each driver as backend/cache/stage; rados via
  `ceph_harness.sh`).
- **SP4** — the engine: UPLOAD/FLUSH/MULTIPART/RECALL through one queue; restart→
  reconcile (no loss); park+wake; no generic durable-queue code left in `src/frm/`.
- **SP5** — tape recall (park→stage→resume), tape migrate (write→stage→flush→tape),
  tape-requires-cache `[emerg]`, and `src/frm/` dissolved (G9/P6).

---

## 21. Open questions (resolved when SP2/SP4/SP5 are picked up)

cinfo-as-xattr vs sidecar under the batched policy (measure); the stage journal's
durability on a remote stage store beyond the object write; the RADOS credential
representation (keyring path vs §14 field); whether `recall` should expose progress
for a client `kXR_wait` hint.

---

## 22. SP1 — Tier abstraction + grammar + composition + staging-engine seam (manifest)

**New:** `src/fs/tier/{tier.h,tier_config.c,tier_build.c}`; `backend/cache/sd_cache.
{c,h}`; `cache/cstore.{c,h}` (interface + LOCAL mode); `cache/cinfo_l1.{c,h}`;
`fs/xfer/stage_engine.{c,h}`.
**Changed:** `vfs_backend_registry.{c,h}`; `backend/stage/sd_stage.{c,h}`; the three
module/config files (new directives, delete legacy); `cinfo`/`meta`/`lock`/`evict_*`/
`io`/`slice*` → `cstore` (LOCAL = old); `frm/stage.c` → `stage_engine`;
`metrics/writer.c`; top-level `config`.
**Deleted (§13/§14):** legacy directives + scheme dispatch + `http_transport`/
`pelican*`; the FRM `stagecmd` subprocess; the bespoke upload-stage open path.
**Tests:** `run_tier_compose_matrix.sh`; `run_tier_status_notices.sh` (needs-dev
`[warn]` not crash; operator errors `[emerg]`); `run_tier_no_legacy.sh` (G6);
`run_tier_one_stage.sh` (G9 — upload/multipart/writethrough route through
`stage_submit`; deleted symbols `grep` to 0); phase-63 suite rewritten.
**Exit:** matrix + notices + gates green; a local cache tree `diff`-identical to a
LOCAL-mode run (G5/G6/G9).

## 23. SP2 — Cache/stage state fully on the store driver

**New:** `cstore` XATTR/SIDECAR modes; `cache/cinfo_xattr.{c,h}` (cinfo ↔
`user.xrd.cinfo`); the L1 + batch policy. **Changed:** `cinfo`/`meta`/`lock`/`evict_*`/
`cache_reap`/`reap_watermark`/`io` flip LOCAL→driver-routed; `sd_cache` shell→full;
`sd_stage`+the FRM journal → the stage store. **Tests:** `run_tier_remote_store.sh`
(cache_store=`roots://`; warm hit survives a **restart of the cache node**; remote
eviction; cinfo is a remote `user.xrd.cinfo` xattr); `run_tier_remote_stage.sh`.

## 24. SP3 — Driver development for the §3 matrix

Writable http/WebDAV + s3 stores; pblock/xroot as cache/stage stores; the `rados`
driver (phase-60). Each increment flips its cells READY.
`tests/run_tier_matrix_drivers.sh` parametrises the grid.

## 25. SP4 — Extract `stage_engine` from FRM (P5 + P6, the generic substrate)

Migrate FRM's **generic durable-transfer substrate** out of `src/frm/` into
`src/fs/xfer/stage_engine.{c,h}` (§13b: `queue.c`/`reqfile.c`/`reqid.c`/`index.c`/
`reconcile.c`/`reaper.c`/`compact.c`/`waiter.c`), generalising the request `src`/`dst`
from FRM's local-path/`stagecmd` model to **SD instances** (`xrootd_stage_submit`,
§11). Route the SP1 thin seam, `sd_stage.staged_commit`, the upload/multipart paths,
and the (still-`src/frm/`) recall through the extracted engine. **Changed:** `frm/*`
generic files move + lose their FRM identity; `sd_stage`/`sd_cache` call
`stage_submit`; the metrics become `xrootd_stage_*{kind}`. **Tests:**
`run_stage_engine_kinds.sh` (UPLOAD/FLUSH/MULTIPART/RECALL all through one queue;
restart→reconcile replays in-flight, no loss); `run_stage_engine_park.sh` (a slow
transfer parks + wakes an open). **Exit:** no generic durable-queue code remains under
`src/frm/`; `sd_stage`/`sd_cache` use only `stage_submit`.

## 26. SP5 — The `frm` nearline backend FS driver (P4 + P6); dissolve `src/frm/`

Migrate FRM's **tape-residency** logic into the `frm` backend driver
`src/fs/backend/frm/sd_frm.{c,h}` (§13b: `stage.c`→`recall`, `migrate_purge.c`→migrate/
purge via `staged_*`/`unlink`, `residency.c`→the online/nearline/offline `stat`),
implementing the SD vtable over `stage_engine` (SP4). A pluggable **MSS adapter** (exec
for legacy `stagecmd`, or in-process HPSS/CTA) is selected on the `tape://` store-URL.
**New:** `sd_frm.{c,h}` + the MSS-adapter interface. **Changed:** `tier_build` gains
the `frm` arm; `read/open*` parks on `NGX_AGAIN` from `recall` (the `stage_engine`
waiter); `tier_build_stack` enforces tape-requires-cache (G8); the `xrootd_frm_*`
directives are **deleted** (replaced by `tape://` + the tier grammar); **`src/frm/` is
removed** (its files now live in `stage_engine` + `sd_frm`). **Tests:**
`run_tier_tape_recall.sh` (stub MSS = a slow `roots://` origin marked nearline; open
parks → recall stages into the cache store → the parked open resumes as a hit);
`run_tier_tape_migrate.sh` (write → stage → migrate flush → tape); `run_tier_tape_
requires_cache.sh` (`[emerg]`, G8); `run_frm_dissolved.sh` (`grep` proves no
`src/frm/` directory, G9/P6). **Exit:** tape is `xrootd_storage_backend tape://…`; the
§3 `frm` row flips READY; `src/frm/` is gone.

---

## Appendix A — SD vtable (+ the two new slots)

The 30 phase-55 slots: `init`,`cleanup` · `open`,`close` · `pread`,`pwrite`,`preadv`,
`preadv2`,`copy_range`,`read_sendfile_fd`,`ftruncate`,`fsync`,`fstat` · `stat`,
`unlink`,`mkdir`,`rename`,`server_copy`,`setattr` · `opendir`,`readdir`,`closedir` ·
`getxattr`,`listxattr`,`setxattr`,`removexattr` · `staged_open`,`staged_write`,
`staged_commit`,`staged_abort` — **plus** `recall` (§9.3). Caps: `FD`,`SENDFILE`,
`RANDOM_WRITE`,`RANGE_READ`,`TRUNCATE`,`SERVER_COPY`,`XATTR`,`HARD_RENAME`,`DIRS`,
`APPEND`,`IOURING`,`FSCS` — **plus** `NEARLINE`.

## Appendix B — tier-xattr key registry

| xattr | holds | format |
|---|---|---|
| `user.xrd.cinfo` | the cinfo record | `cinfo.h` versioned LE blob (magic `XCI1`) |
| `user.xrd.meta` | origin checksum + size | `.meta` blob (alg+hex+size+mtime) |
| `user.xrd.lock` | WebDAV/POSC lock | phase-57 xattr-lock blob |
| `user.xrd.wt` | in-flight write-back/recall journal | reqid + key + kind + state |

Per store: `pblock`=`user.*` rows; `s3`=`x-amz-meta-xrd-{cinfo,meta,lock,wt}` (b64);
`http`/WebDAV=`xrd:` DAV dead-properties; `rados`=omap `xrd.{cinfo,meta,lock,wt}`; for
`tape` the FRM index is the metadata of record.

## Appendix C — per-driver wire-op map

| Driver | data read | data write | list/scan | xattr get/set | delete | freespace |
|---|---|---|---|---|---|---|
| posix | `pread` | `pwrite`/staged | `readdir`+`stat` | `f{get,set}xattr` | `unlink` | `statvfs` |
| pblock | block pread | block staged | catalog scan | catalog `user.*` | catalog del | catalog sum |
| xroot | kXR_read | kXR_write/kXR_open(new) | kXR_dirlist | kXR_fattr | kXR_rm | kXR_query space |
| http/WebDAV | GET range | PUT/MKCOL | PROPFIND depth-1 | PROPPATCH/PROPFIND | DELETE | DAV quota-avail |
| s3 | GET range | PUT/MPU | ListObjectsV2 prefix | `x-amz-meta-*` (CopyObject REPLACE) | DeleteObject | n/a |
| rados | `rados_read` | `rados_write_full` | omap/nspace list | omap get/set | `rados_remove` | `rados_df` |
| `frm` (tape) | `pread` (online) / `recall`→`stage_engine` (offline) | `staged_*` (migrate via the engine) | residency index | residency index fields | MSS purge | MSS df |

## Appendix D — config directive table

| Directive | Args | Sets |
|---|---|---|
| `xrootd_storage_backend` | `<store-url> [credential=]` | `stack.backend` |
| `xrootd_cache` | `on\|off` | `stack.cache.enabled` |
| `xrootd_cache_store` | `<store-url> [credential=][block_size=]` | `stack.cache_store` |
| `xrootd_stage` | `on\|off` | `stack.stage.enabled` |
| `xrootd_stage_store` | `<store-url> [credential=][block_size=]` | `stack.stage_store` |
| `xrootd_stage_flush` | `sync\|async` | `stack.stage.flush_mode` (write-back AND tape migrate) |
| `xrootd_cache_max_object` | `<size>` | policy.max_file_size |
| `xrootd_cache_evict_at` / `_evict_to` | `<pct>` | policy thresholds |
| `xrootd_cache_verify` | `off\|on\|strict` | policy.verify |
| `xrootd_cache_include`/`_deny`/`_allow` | `<regex>`/`<prefix>` | policy filters |
| `xrootd_cache_slice` | `<size>` | policy.slice_size |
| `xrootd_cache_dirty_max_age` | `<time>` | policy.dirty_max_age |
| `xrootd_cache_meta` | `auto\|local\|xattr\|sidecar` | policy.meta_mode |
| `xrootd_cache_batch_cinfo` | `auto\|on\|off` | policy.batch_cinfo |
| `xrootd_cache_index_cache` | `<n>` | policy.l1_entries |
| `xrootd_webdav_*` / `xrootd_s3_*` mirrors | as above | `common.*` |
| **deleted (§14)** | `xrootd_cache_origin*`, `_cache_root`, `_cache_storage_backend`, `_storage_staging` | — |

## Appendix E — metrics

`xrootd_tier_info{export,tier,driver,origin,auth,health,status,nearline}`;
`xrootd_stage_{submitted,completed}_total{kind}`, `xrootd_stage_inflight{kind}`,
`xrootd_stage_parked_opens`; `xrootd_cache_{hit,miss,fill_bytes,evicted}_total`;
`xrootd_tier_unreachable_total{tier}`.

## Appendix F — config-message classes

| Class | Condition | Severity | Wording |
|---|---|---|---|
| **needs development** (P1) | driver lacks a role slot/cap | `[warn]`, export inactive | "…not yet implemented (needs development: slot X, cap Y — SP…)" |
| operator error | unknown scheme | `[emerg]` | "unknown driver scheme \"<s>\"" |
| operator error | `credential=` names no block | `[emerg]` | "no xrootd_credential \"<name>\"" |
| operator error | `xrootd_cache` without `_store` | `[emerg]` | "xrootd_cache requires xrootd_cache_store" |
| operator error | `tape://` backend without cache (P4) | `[emerg]` | "tape:// is nearline and requires xrootd_cache" |
| operator error | remote store, no port + no default | `[emerg]` | "missing port" |
| **removed** (P2) | a deleted legacy directive | `[emerg]` | "xrootd_cache_origin is removed — use xrootd_cache_store (phase-64)" |

## Appendix G — capability ↔ role quick reference

`RANGE_READ`: every read role · `RANDOM_WRITE`: writable backend + cache/stage stores
· `DIRS`: cache store (eviction scan) · `XATTR`: cache/stage stores (cinfo/meta/lock) ·
`NEARLINE`: tape backend · `SENDFILE`/`FD`: a zero-copy serve optimisation (optional) ·
`TRUNCATE`/`SERVER_COPY`/`HARD_RENAME`/`APPEND`/`IOURING`/`FSCS`: optional accelerators.

## Appendix H — the staging-engine state machine

```
submit(kind, src, dst, opts):
    reqid = frm_request_add(kind, src_key, dst_key)               # durable
    if opts.async || size_hint large:
        frm_waiter_add(reqid, opts.open_options, opts.conn)        # PARK the open
        return reqid
    else:
        xfer_mover(src→dst); frm_request_complete(reqid); return ""   # inline

scheduler (per worker timer / thread pool):
    for reqid in frm_ready():
        rc = xfer_mover(src→dst)         # src->open/pread loop → dst->staged_*→commit
        if rc==OK:  frm_request_complete(reqid); frm_waiter_deliver(reqid, OK)
        else:       frm_request_fail(reqid);     frm_waiter_deliver(reqid, ERR)   # stays durable

reconcile (restart):
    for reqid in frm_inflight(): re-submit to the scheduler          # no loss
```

---

## Appendix I — full data structures (every type, no ellipsis)

```c
/* ---- src/fs/xfer/stage_engine.h : the one async-staging engine (ex-FRM, P6) ---- */

typedef enum {
    XROOTD_STAGE_RECALL    = 0,   /* nearline backend → cache store   (data in)  */
    XROOTD_STAGE_FLUSH     = 1,   /* stage store → backend            (data out) */
    XROOTD_STAGE_UPLOAD    = 2,   /* client body → stage store        (data in)  */
    XROOTD_STAGE_MULTIPART = 3,   /* S3 part(s) → stage store         (data in)  */
} xrootd_stage_kind_t;            /* wire-compatible with the legacy frm_xfer_kind_t */

typedef enum {
    XROOTD_SREQ_QUEUED=0, XROOTD_SREQ_INFLIGHT=1, XROOTD_SREQ_DONE=2,
    XROOTD_SREQ_FAILED=3, XROOTD_SREQ_EXPIRED=4,
} xrootd_sreq_state_t;

/* The durable on-disk request record (migrated from frm/reqfile.c). One per transfer;
 * fsync'd before the mover starts so a crash leaves a recoverable row. */
typedef struct {
    char                 reqid[40];        /* minted by reqid (ex-frm/reqid.c)        */
    xrootd_stage_kind_t  kind;
    xrootd_sreq_state_t  state;
    char                 src_driver[16];   /* the instance is rebuilt from the tier   */
    char                 src_key[1024];
    char                 dst_driver[16];
    char                 dst_key[1024];
    uint16_t             open_options;     /* echoed to a parked open on wake          */
    uint64_t             size_hint;
    uint64_t             bytes_done;        /* resume cursor (mover writes it through)  */
    int64_t              enqueued_at, started_at, finished_at;
    uint32_t             attempts;
    int32_t              last_errno;
} xrootd_sreq_t;

/* The durable queue handle (migrated from frm/queue.c+index.c). Per export; its store
 * is itself a tier (default a local dir; may be a roots:// journal store, SP2). */
typedef struct xrootd_stage_queue_s xrootd_stage_queue_t;

typedef struct {
    unsigned          async:1;             /* park vs inline                           */
    off_t             size_hint;
    uint16_t          open_options;        /* for the parked open                      */
    ngx_connection_t *conn;                /* the client to wake (waiter)              */
    ngx_msec_t        ttl_ms;              /* 0 = engine default                       */
} xrootd_stage_opts_t;

const char *xrootd_stage_submit(xrootd_stage_kind_t,
    xrootd_sd_instance_t *src, const char *src_key,
    xrootd_sd_instance_t *dst, const char *dst_key, const xrootd_stage_opts_t*);
void        xrootd_stage_scheduler_tick(void);              /* per-worker timer        */
void        xrootd_stage_reconcile(xrootd_stage_queue_t*);  /* restart replay          */

/* ---- src/fs/backend/frm/sd_frm.h : the nearline backend driver (P6) ---- */

/* The pluggable MSS adapter — how the frm driver actually talks to the tape system.
 * One vtable; the tape:// store-URL selects the adapter (exec | hpss | cta | stub). */
typedef struct {
    const char *name;                                   /* "exec"|"hpss"|"cta"|"stub" */
    /* residency: is `key` online, nearline (recallable), or offline/absent? */
    int  (*residency)(void *mss, const char *key, off_t *size_out, time_t *mtime_out);
    /* begin a recall of `key` to the MSS online buffer; returns 0 (started)/-1. The
     * actual byte copy buffer→cache-store is the generic mover. */
    int  (*recall_begin)(void *mss, const char *key);
    /* poll a recall: 1 online (ready), 0 in-flight, -1 error. */
    int  (*recall_poll)(void *mss, const char *key);
    /* migrate `key` from the MSS online buffer to tape (after the mover wrote it). */
    int  (*migrate)(void *mss, const char *key);
    int  (*purge)(void *mss, const char *key);          /* drop the online copy       */
    void (*destroy)(void *mss);
} xrootd_mss_adapter_t;

#define XROOTD_RESIDENCY_ONLINE   0
#define XROOTD_RESIDENCY_NEARLINE 1
#define XROOTD_RESIDENCY_OFFLINE  2   /* recall will fault it in                       */
#define XROOTD_RESIDENCY_ABSENT  -1

typedef struct {
    const xrootd_mss_adapter_t *mss;     /* the selected adapter                       */
    void                       *mss_ctx; /* its per-instance state                     */
    xrootd_stage_queue_t       *queue;   /* the shared engine queue                    */
    char                        host[256];
} sd_frm_inst_state;

/* ---- src/cache/cstore.h : the cache's one storage adapter (full) ---- */

typedef ngx_int_t (*xrootd_cstore_visit_fn)(const char *key,
    const xrootd_cinfo_t *ci, void *ctx);   /* eviction/reaper callback               */

typedef struct {                            /* per-worker write-through cinfo cache    */
    /* bounded LRU keyed by object key → xrootd_cinfo_t; size = policy.l1_entries */
    void *opaque;
} xrootd_cinfo_l1_t;

typedef struct {
    xrootd_sd_instance_t *store;            /* the cache_store tier instance           */
    int                   meta_mode;        /* XROOTD_CMETA_{AUTO,LOCAL,XATTR,SIDECAR}  */
    xrootd_cinfo_l1_t    *l1;
    int                   batch_cinfo;      /* -1 auto | 0 per-op | 1 batch-on-commit   */
} xrootd_cstore_t;

/* ---- src/fs/backend/cache/sd_cache.h ---- */
typedef struct {
    xrootd_sd_instance_t  *source;          /* the tier below (stage | backend)        */
    xrootd_cstore_t        cstore;
    xrootd_cache_policy_t  policy;
} sd_cache_inst_state;
```

## Appendix J — sequence diagrams (every flow)

```
(J1) READ — cache HIT
 client → VFS.open(read) → sd_cache.open:
   cinfo = cstore_cinfo_load(key)         # L1 hit, no store round-trip
   COMPLETE → obj = cstore_serve_open(key)# obj.driver = store driver
 client → VFS.pread(obj) → store.pread    # bypasses sd_cache (obj is store-owned)

(J2) READ — cache MISS, online backend
 sd_cache.open:
   cinfo miss → admit(policy) ok
   st = backend.stat(key)  → online
   staged = cstore_fill_open(key)
   loop: backend.pread → cstore_fill_write(staged)
   cstore_fill_commit(staged) ; cstore_cinfo_store(key, cinfo)   # batched: one xattr
   if policy.verify: checksum-on-fill (backend kXR_Qcksum)       # commit-then-verify
   return cstore_serve_open(key)

(J3) READ — nearline (tape) MISS  → recall + PARK
 sd_cache.open:
   cinfo miss
   st = frm_backend.stat(key) → nearline
   reqid = frm_backend.recall(key)                  # = stage_submit(RECALL, frm, key, cache_store, key)
                                                     #   mss.recall_begin + enqueue
   stage_waiter_add(reqid, open_options, conn)       # PARK; return XRD_ST_AIO / 202
 ... (minutes) scheduler: mss.recall_poll → online ; mover: mss-buffer.pread → cache_store.staged_*
   stage_complete(reqid) ; waiter_deliver(reqid, OK)
 woken open re-enters sd_cache.open → cinfo now COMPLETE → serve (J1)

(J4) WRITE → stage → flush/migrate
 client → VFS.open(write) → sd_cache.open passes through → sd_stage.open
   staged = stage_store.staged_open(key)
 client → VFS.write → sd_stage.staged_write → stage_store.staged_write
 client → VFS.close/commit → sd_stage.staged_commit:
   reqid = stage_submit(FLUSH, stage_store, key, backend, key, {async})
   (if backend is frm: the mover writes backend.staged_* then mss.migrate → tape)
   return (async: the durable queue owns it; sync: run inline + verify)

(J5) S3 MULTIPART
 InitiateMPU            → sd_stage.staged_open(upload_key)            # one staged handle
 UploadPart n           → sd_stage.staged_write(part bytes at offset) # parts = staged writes
 CompleteMPU            → assemble order/ETags (S3 layer) ; staged_commit
                        → stage_submit(FLUSH, stage_store, key, backend, key)
 AbortMPU               → sd_stage.staged_abort → stage_store.unlink

(J6) RESTART RECONCILE
 worker init → stage_reconcile(queue):
   for reqid in INFLIGHT rows: re-submit to the scheduler            # no transfer lost
   waiters re-park on the next client open of the same key
```

## Appendix K — cstore function contracts (pre / post / errno)

| Function | Pre | Post / returns | errno on failure |
|---|---|---|---|
| `fill_open(key,mode)` | store has `RANDOM_WRITE` | a staged handle on the store; or NULL | ENOSPC, EACCES, EIO |
| `fill_write(st,buf,len,off)` | `st` open | bytes written (==len) or -1 | EIO, ENOSPC |
| `fill_commit(st)` | `st` open | NGX_OK (object published + cinfo stored, batched); consumes `st` | EIO |
| `fill_abort(st)` | `st` open | temp dropped; `st` freed | (best-effort) |
| `serve_open(key,&err)` | object present (cinfo COMPLETE/PARTIAL) | a store-backed read obj; or NULL+err | ENOENT, EIO |
| `serve_pread(obj,buf,len,off)` | obj from serve_open; range present (else range-fill, §6.5) | bytes or -1 | EIO, EAGAIN (partial-not-yet-filled) |
| `evict(key)` | — | object + cinfo removed; NGX_OK even if absent (idempotent) | EIO (store error) |
| `cinfo_load(key,&ci)` | — | NGX_OK + ci (L1 or getxattr); NGX_DECLINED if absent | EIO |
| `cinfo_store(key,ci)` | store has `XATTR` (or SIDECAR) | NGX_OK; L1 updated write-through | EIO, ENOTSUP |
| `scan(visit,ctx)` | store has `DIRS` | visits every cached key with its cinfo | EIO |
| `freespace(&tot,&avail)` | — | NGX_OK + bytes (statf/statvfs) | EIO |

Invariant: a `cstore` failure on the **read** path degrades to a backend read (P-failure
§16); on the **fill** path it aborts the fill (the object is simply re-fetched). It
never corrupts a served byte.

## Appendix L — the parser & validation algorithms (pseudocode)

```
xrootd_tier_parse_store(url, args, out, err):
  i = index_of(url, ':') ; if i<0: emerg("no scheme")            # operator error
  scheme = url[0:i] ; loc = url[i+1:]
  out.driver = { root,roots→xroot ; http,https→http ; else→scheme }
  out.tls    = scheme in {roots, https}
  out.nearline = scheme == tape
  if scheme in {posix, pblock}:
      out.path = canonicalize_confined(loc)                       # own rootfd
  else:                                                           # //host[:port]/path
      (out.host, out.port, rest) = parse_authority(loc)           # IPv6-bracket aware
      if out.port==0: out.port = default_port(scheme)             # 1094/443/80/7480
      out.path = rest
  for a in args:
      if a startswith "credential=":
          out.credential = credential_lookup(a.value) ; if NULL: emerg("no credential")
      elif a startswith "block_size=": out.block_size = parse_size(a.value)
      else: emerg("unknown store param")
  out.configured = 1

xrootd_tier_status(t, probe, gap):                                # P1: never a blocker
  need = role_contract[t.role]                                    # slots+caps (§2.2)
  for slot in need.slots: if probe.driver.<slot> == NULL:
      gap = {slot, "", sp_for(t.driver, t.role)} ; return NEEDS_DEV
  if (probe.driver.caps & need.caps) != need.caps:
      gap = {"", first_missing_cap(probe.driver.caps, need.caps), sp_for(...)} ; return NEEDS_DEV
  return READY
# caller (tier_configure): local tier → check now; remote → check at first build_stack.
# READY→active ; NEEDS_DEV→ [warn] "needs development …" + export inactive (NOT a crash).
```

## Appendix M — per-sub-project test specs (exact configs + assertions)

```
# SP1  run_tier_compose_matrix.sh — one combo shown; the script loops the curated 9.
#   backend=pblock:/b  cache=posix:/c  stage=posix:/s
#   PUT /f (2.6MB) → assert bytes appear under /s temp then promoted to /b ; /c empty
#   GET /f (cold)  → assert byte-exact ; assert /c/f exists (filled) ; cinfo present
#   GET /f (warm)  → assert served from /c (no backend read; check access log)
#   fill /c past evict_at → assert eviction reclaimed to evict_to ; dirty skipped
# SP1  run_tier_status_notices.sh
#   cache_store rados://p  → nginx -t exit 0, log [warn] "needs development … SP3", export inactive
#   cache_store gopher://x → nginx -t exit !=0, [emerg] "unknown driver scheme"
#   cache_store roots://o credential=nope → [emerg] "no xrootd_credential"
# SP1  run_tier_no_legacy.sh
#   config with xrootd_cache_origin → nginx -t [emerg] "removed — use xrootd_cache_store"
#   grep -rE 'cache_origin|cache_root|cache_storage_backend|storage_staging' src/ == 0   # G6
# SP1  run_tier_one_stage.sh
#   webdav PUT + s3 MPU + write-through all run ; then
#   grep -rl 'xrootd_staged_open' src/ outside sd_stage == 0 ; no vfs_scratch/slice_fill/writethrough_flush  # G9
# SP4  run_stage_engine_kinds.sh
#   drive UPLOAD,FLUSH,MULTIPART,RECALL ; kill -9 mid-transfer ; restart ;
#   assert reconcile replays the inflight reqids ; final bytes byte-exact ; no dup
#   grep -rl 'durable queue' src/frm/ == 0   # engine left FRM
# SP5  run_tier_tape_recall.sh
#   backend tape://stub (a slow roots:// origin marked nearline) ; cache=pblock:/c
#   GET /f → response is 202/AIO (parked) ; after recall, the SAME conn resumes → byte-exact ; /c/f present
# SP5  run_frm_dissolved.sh
#   [ ! -d src/frm ]  && grep -rl 'src/frm' config == 0     # P6/G9
```

## Appendix N — glossary

| Term | Meaning |
|---|---|
| **tier** | one storage filesystem in the stack: `backend`, `cache_store`, or `stage_store`; an `xrootd_sd_instance_t` built from `{driver,location,credential}` |
| **store** | the FS a cache/stage tier keeps its bytes on (any driver) |
| **`cstore`** | the cache's one driver-agnostic storage adapter (§6.2) — the only code that touches a cache store driver (P3) |
| **`sd_cache` / `sd_stage`** | the read-cache / write-stage SD-driver **decorators** the registry composes (P3) |
| **staging engine** | the one async durable-transfer mechanism (`xrootd_stage_submit` + the FRM-derived queue/waiter/reconcile + the `xfer` mover), shared by recall/migrate/write-back/upload (P4,P5) |
| **`frm` driver** | the migrated FRM subsystem as a nearline backend FS driver (P6) |
| **nearline / recall / migrate** | tape residency: offline→online recall (= async cache-fill), online→tape migrate (= stage-flush) |
| **cinfo** | the per-object block-present bitmap + validity/dirty record; stored LOCAL or as `user.xrd.cinfo` on the store (§6) |
| **needs development** | a driver lacking a role slot — a tracked dev task, never a blocker (P1) |
| **composed top** | `cache(stage(backend))` — what the registry returns and the VFS resolves to (G4) |

## Appendix O — symbol cross-reference (where each new thing is defined / used)

| Symbol | Defined | Used by |
|---|---|---|
| `xrootd_tier_cfg_t` / `_stack_t` | §2.1 `tier.h` | registry entry (§8.2), `tier_build` (§5.2) |
| `xrootd_tier_build` / `_build_stack` | §5 `tier_build.c` | `vfs_backend_resolve` (§5.1) |
| `xrootd_tier_parse_store` / `_status` | §4.2/§2.2 `tier_config.c` | `tier_configure` (§8.1), Appendix L |
| `xrootd_cstore_t` + API | §6.1 / App I `cstore.{c,h}` | `sd_cache` (§12.1), evict/reaper (§15) |
| `xrootd_sd_cache_create` | §12.1 `sd_cache.c` | `tier_build_stack` (§5.1) |
| `xrootd_sd_stage_create(source,store,policy)` | §12.2 `sd_stage.c` | `tier_build_stack` (§5.1) |
| `xrootd_stage_submit` + `xrootd_sreq_t` | §11 / App I `stage_engine.{c,h}` | sd_stage commit, sd_frm recall/migrate, upload, MPU |
| `xrootd_mss_adapter_t` | App I `sd_frm.h` | the `frm` driver (§26) |
| `recall` slot + `NEARLINE` cap | §2.2/§9.3/App A | `sd_frm` (§26), `sd_cache.open` (§12.1, J3) |
