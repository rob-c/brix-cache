# B2 — Real FRM / Tape MSS Staging: Historical Implementation Plan

**Status:** Historical plan / as-built reference. The `src/frm/` subsystem now
exists; use [`../../src/frm/README.md`](../../src/frm/README.md) and
[`../05-operations/operation-status.md`](../05-operations/operation-status.md)
for current behavior.

**Build governance:** current source registration lives in the top-level
`config` script (`ngx_module_srcs` and module deps lists). `src/core/config/config.h`
contains module config structs/directive declarations, but it is not the
authoritative `ngx_module_srcs` list.

---

## 1. Overview & Goals

### What B2 delivers

B2 turns the existing fire-and-forget staging hook (`src/protocols/root/query/prepare_cmd.c` — a double-fork `execv` that captures no state, reaps nothing, and hard-codes `reqid="0"` at `prepare.c:338`) into a **durable, async, de-duplicating tape-staging subsystem** that survives client disconnect and worker restart. Concretely:

- **A durable stage-request queue** (`src/frm/`) that is the source of truth, file-backed and crash-safe, with an SHM hot index for O(1) cross-worker lookup. State **outlives the connection and the worker** — the prerequisite for tape recalls that take minutes to hours.
- **Real `kXR_prepare` semantics**: stage / cancel / evict, plus `kXR_QPrep` polling that reports true queue state (`A`/`q`/`s`/`f`/`M`) across reconnects and workers.
- **`kXR_offline` residency awareness** across all three faces: stream `kXR_stat`/`kXR_statx`/`kXR_open`, WebDAV PROPFIND `<xrd:locality>`, and S3 HEAD `x-amz-storage-class: GLACIER` / `x-amz-restore` — one probe, no per-protocol drift.
- **A real transfer worker** that runs the operator copycmd on the thread-pool, **reaps and verifies** (copy-to-temp → stat → atomic rename), enforces a global `copymax` concurrency cap, de-dups concurrent opens of the same file to a single recall, and applies `.fail`/hold backoff.
- **The WLCG Tape REST API** on the `davs://` face (`/api/v1/stage`, `release`, `archiveinfo`/`fileinfo`, `cancel`) so FTS/gfal2 clients work unchanged.
- **Async completion delivery** (`kXR_waitresp` → `kXR_attn(asynresp)`) so a stalled `kXR_open` is satisfied in place when the recall lands — with full tolerance of a client that disconnected during the stall.

### Non-goals (delegated to the storage backend)

- **Category-2 migration & purge** (disk→tape copy-out, watermark GC). These belong to the real MSS backend (**CTA / dCache / HPSS**); B2 exposes the directives and metrics scaffolding (`xrootd_frm_migrate_copycmd`, `xrootd_frm_purge_watermark`) and a `migrate_purge.c` stub, but the *policy engine* is **out of scope** and shipped only as deferrable Phase 4 parity.
- **In-process tape drivers.** B2 always shells out to an operator `copycmd`/`residency_cmd`; we never link a tape library.
- **Cross-site bulk orchestration** (that is FTS's job).

### Headline effort

| Milestone | Effort | What you get |
|---|---|---|
| **Usable synchronous gateway** (Phases 0–1) | **~12 person-weeks** | Durable queue, residency/offline awareness, real transfer worker with reaping/dedup/backoff, pollable `kXR_QPrep`, `kXR_wait`-and-retry opens. No server push, but fully functional tape gateway. |
| **MVP** (Phases 0–3) | **~24 person-weeks** | Adds cancel/evict, the WLCG HTTP Tape REST API, and async `kXR_waitresp`→`asynresp` push delivery with disconnect tolerance. |
| **Phase 4 parity** (F1–F6) | deferrable | cmsd `Have` integration, migrate/purge, residency-cmd polish, multi-queue selectors. |

---

## 2. Architecture

### End-to-end flow

```
                        ┌──────────────────────── nginx master ─────────────────────────┐
                        │  postconfig: frm_queue_init() — reconcile file → SHM index     │
                        │  (validate header, CRC-scan records, rebuild chains, compact)  │
                        └───────────────────────────┬────────────────────────────────────┘
                                                    │ fork (index warm before workers)
   CLIENT            WORKER (event loop)            │            THREAD POOL          DURABLE STORE
     │ kXR_prepare/HTTP POST /stage  ──────────────►│                                 ┌──────────────┐
     │                                              │  frm_request_add ──────────────►│ <queue> file │ (truth)
     │ ◄── reqid (durable, host-qualified) ─────────│  (fcntl lkExcl, fsync, commit)  │ + <queue>.lock│
     │                                              │  index insert ◄── SHM hot index │ + SHM index  │ (cache)
     │ kXR_open (miss, stageable) ─────────────────►│                                 └──────────────┘
     │                                              │  frm_residency_probe (xattr+SHM)
     │                                              │  frm_stage_claim → LAUNCH/DEDUP/FULL
     │ ◄── kXR_wait (Phase 1) / kXR_waitresp (P3) ──│  scheduler posts stage_job ────►│ copycmd → .anew
     │   (client polls QPrep, or parks streamid)    │                                 │ stat+verify size
     │                                              │  done(main): finish ONLINE ◄────│ rename .anew→pfn
     │ ◄── kXR_attn(asynresp) [P3] / re-open hit ───│  deliver_waiters / kick sched   └──────────────┘
```

### Mapping onto the nginx worker + SHM + thread-pool model

- **Durable queue = file + SHM index.** The on-disk file (modeled on `XrdFrcReqFile`) is **crash-durable truth**; nginx SHM is *process-group-lifetime, not fsync'd*, so it is treated strictly as a **hot read cache** rebuilt by reconciliation at master start. This is the load-bearing invariant of the whole subsystem. Authority rule: **file = truth, SHM = cache**; any mutate takes `fcntl` whole-file lock → writes+fsyncs file → then patches SHM; any divergence (`generation` mismatch) collapses back to the file.
- **Cross-worker / cross-host coordination** uses an `fcntl(F_SETLKW)` lock on a `<queue>.lock` sidecar (serializes *processes and hosts* sharing the FS, including a real `frm_xfragent`), fronted by an in-process `ngx_shmtx_t` fast-path. **Lock order is always `ngx_shmtx → fcntl`** — deadlock-free.
- **Blocking work runs on the thread pool**, never the event loop (INVARIANT: async I/O is event-loop-only). The transfer worker (`xrootd_stage_worker_thread`) does blocking `waitpid`/`stat`/`rename` on a pool thread, then posts a main-thread done callback — exactly the `xrootd_cache_fill_t` pattern (`src/fs/cache/open_or_fill.c:78-80`, `src/core/aio/aio.h:32-40`), but **connectionless** (keyed by `reqid`, not a `c`/`ctx`).
- **Async delivery** reuses the deferred-response wire machinery: `kXR_waitresp` parks a streamid (`xrootd_send_waitresp`), and on completion `xrootd_send_attn_asynresp` pushes the real answer carrying the *saved* streamid. The routing key {`worker_pid`, `conn_number`, `streamid`} mirrors `XrdXrootdReqID{Sid,Lid,Linst}` so a stalled connection can be re-found in its owning worker — and rejected if it was recycled.
- **Residency** is one xattr (`user.frm.residency`) + one SHM dedup-set lookup, folded into a single `frm_residency_probe()` that every protocol face calls. Absent xattr ⇒ ONLINE (zero migration for existing exports).

---

## 3. The new `src/frm/` subsystem

> **Design tension to resolve in Phase 0.** Three component designs propose slightly different homes/names for the durable store: (M1) `src/frm/` with `frm_queue_t` + a fixed-record `XrdFrcReqFile`-style file; (M7/M5) `src/stage/` with an SHM-only `xrootd_stage_table_t`; (config-build-test) `src/frm/` with a `queue.c` append journal + `queue_shm.c` index folded into the **stream** module. **The plan of record is `src/frm/`** (M1's durable file = truth + SHM index = cache), folded into the **existing stream module** (config-build-test's build decision — FRM owns no listener). The M7/M5 `xrootd_stage_*` waiter/worker structs are retained but live in `src/frm/` and key off M1's durable `reqid`. Where a design said `src/stage/`, read `src/frm/`. This unification is the **first work item of Phase 0**.

### 3.1 File tree

| File | Responsibility |
|---|---|
| `src/frm/frm.h` | Public API: `frm_queue_t`, `frm_req_view_t`, `frm_request_*`, `frm_reqid_generate`, `frm_reap_expired`, and the `xrootd_frm_conf_t` directive struct. The only header `src/protocols/root/query/prepare.c`, the HTTP Tape REST, and residency code include. |
| `src/frm/frm_format.h` | On-disk format (pure layout, no code): `FRM_*` constants, `frm_file_hdr_t`, `frm_record_t`, `frm_status_t`, `frm_cstype_t`, `FRM_OPT_*`, `_Static_assert(sizeof(frm_record_t)==FRM_REC_SIZE)`. |
| `src/frm/frm_internal.h` | Internal shared decls (lock enum, header ops, chain ops) consumed by `reqfile/index/reconcile/compact/queue`. |
| `src/frm/reqfile.c` | **Durable file engine** (`XrdFrcReqFile` analog): `fcntl` lock helpers (`lkShare/lkExcl/lkNone/lkInit`), header read/refresh, `frm_rec_read`/`frm_rec_write` (pread/pwrite + CRC32c + fdatasync), free-list pop/push, active-chain link/unlink, WAL append/commit ordering. Owns the file fd + `<queue>.lock` fd. |
| `src/frm/index.c` | **SHM hot index**: zone configure/init (`ngx_shared_memory_add`, `(void*)1` sentinel, flexible-array `slots[]`, `ngx_shmtx` lock-first), `frm_index_insert/lookup/remove/scan`, generation check, LRU reap-on-full + `reconcile_full_total` metric (the `src/protocols/root/session/registry.c:249-289` pattern). |
| `src/frm/reconcile.c` | **Master-start reconciliation** (`Init` analog): validate header, CRC-scan all records, rebuild ordered chains, drive compaction, repopulate SHM index, sync `generation`. Called from `frm_queue_init`. |
| `src/frm/compact.c` | **Compaction** (`ReWrite` analog): stream active records → `<queue>.new`, dense relink, fsync header, atomic `rename`, bump `generation`, request index rebuild; threshold helper `frm_compact_needed()`. |
| `src/frm/reqid.c` | `frm_reqid_generate`: durable `seq` bump under file lock, format `"<seq>.<pid>@<host>"`, host cached once at init. |
| `src/frm/queue.c` | **Façade + lifecycle**: `frm_queue_t`, `frm_queue_get` (name→queue registry), `frm_queue_init`, and the public `frm_request_add/get/set_status/delete/list` + `frm_reap_expired`, each orchestrating index (fast) + reqfile (durable) in authority order. |
| `src/frm/reaper.c` | Worker-0-only `ngx_event` timer driving `frm_reap_expired` + compaction threshold check. |
| `src/frm/directives.c` | Directive setters + table fragment (custom setters for `queue_path` validation and `purge_watermark` ratio→ppm). |
| `src/frm/residency.h` | Residency model: `frm_residency_state_t`, `frm_residency_t`, `frm_residency_xattr_t`, stage-registry + stage-fail decls. |
| `src/frm/residency_xattr.c` | `user.frm.residency` xattr encode/decode/read/write (mirrors `src/protocols/webdav/prop_xattr.c:23-118`). |
| `src/frm/residency_probe.c` | `frm_residency_probe()` — the single source of truth for resident/backend-exists/staging. |
| `src/frm/stage_registry.c` | **SHM dedup-set** (`frm_stage_table_t`): `frm_stage_claim` (atomic test-and-claim → LAUNCH/DEDUP/FULL), `frm_stage_dedup_lookup`, `frm_stage_release` (clone of `src/tpc/key_registry.c:154-183`). |
| `src/frm/stage_fail.c` | `.fail`/hold sidecar backoff (port of `XrdOssStage.cc:134-139`): `frm_stage_fail_check/_mark/_clear`. |
| `src/frm/stage_launch.c` | Detached launcher on `FRM_STAGE_LAUNCH`: fail-check → xattr `staging` → post worker job → on done flip xattr + clear/mark. |
| `src/frm/stage_registry.h` | Waiter + worker structs: `xrootd_stage_waiter_t`, `xrootd_stage_entry_t` (waiters[]), `xrootd_stage_job_t`, CRUD signatures. |
| `src/frm/stage_exec.c` | **Reap-and-capture exec** (extends `prepare_cmd.c`): single-fork `execv` + `waitpid` on a pool thread; factors out shared `xrootd_close_inherited_fds()` from `prepare_cmd.c:103-152`. |
| `src/frm/stage_worker.c` | M7 transfer worker: `xrootd_stage_worker_thread` (copy→temp→verify→rename) + `xrootd_stage_worker_done`. |
| `src/frm/stage_scheduler.c` | Per-worker drain timer: `xrootd_stage_claim_queued` up to `copymax-running`, post jobs, skip `retry_not_before>now`. |
| `src/frm/stage_deliver.c` | M5 async delivery: `xrootd_stage_deliver_waiters` + `deliver_one` (causality guard, liveness check, `asynresp` push). |
| `src/frm/metrics.c` | FRM Prometheus exporter (`xrootd_export_frm_metrics`), reachable from the HTTP metrics module. |
| `src/frm/migrate_purge.c` | Phase 4 stub: migrate copycmd-out + watermark purge timer (Category-2, deferrable). |
| `src/protocols/webdav/tape_rest.c` / `.h` | WLCG Tape REST API router + body handlers (Phase 2). |
| `src/frm/README.md` | Subsystem doc (required by doc-tree standard): truth-vs-cache invariant, lock order, WAL/commit-point rule, `kXR_prepare`/`kXR_QPrep` integration. |

### 3.2 Durable queue record (actual C — `frm_format.h`)

```c
#define FRM_MAGIC          0x46524d31u   /* "FRM1" little-endian */
#define FRM_VERSION        1
#define FRM_REQID_LEN      40            /* matches XrdFrcRequest::ID[40]   */
#define FRM_LFN_LEN        3072          /* matches XrdFrcRequest::LFN[3072]*/
#define FRM_USER_LEN       256
#define FRM_DN_LEN         256
#define FRM_NOTIFY_LEN     512
#define FRM_CSVAL_LEN      64
#define FRM_SELECTOR_LEN   32

typedef enum {
    FRM_ST_FREE = 0, FRM_ST_QUEUED = 1, FRM_ST_STAGING = 2,
    FRM_ST_ONLINE = 3, FRM_ST_FAILED = 4, FRM_ST_CANCELLED = 5
} frm_status_t;

#define FRM_OPT_MSG_FAIL   0x00000001u   /* notify on failure  (XRootD)     */
#define FRM_OPT_MSG_SUCC   0x00000002u   /* notify on success  (XRootD)     */
#define FRM_OPT_MAKE_RW    0x00000004u   /* stage for write    (XRootD)     */
#define FRM_OPT_MIGRATE    0x00000010u
#define FRM_OPT_PURGE      0x00000020u
#define FRM_OPT_REGISTER   0x00000040u   /* FIFO-front registration request */
#define FRM_OPT_COLOC      0x00010000u   /* kXR_coloc hint (ours)           */
#define FRM_OPT_STAGE      0x00020000u   /* kXR_stage  (ours)               */

typedef enum {
    FRM_CS_NONE=0, FRM_CS_SHA1=1, FRM_CS_SHA2=2, FRM_CS_SHA3=3,
    FRM_CS_ADLER32=4, FRM_CS_MD5=5, FRM_CS_CRC32=6
} frm_cstype_t;

/* First FRM_REC_SIZE bytes of the queue file. All integers little-endian. */
typedef struct {
    uint32_t  magic;        /* FRM_MAGIC — reject foreign files            */
    uint32_t  version;      /* FRM_VERSION — refuse newer formats          */
    uint32_t  rec_size;     /* FRM_REC_SIZE this file was written with      */
    uint32_t  hdr_crc32c;   /* CRC32c of header with this field == 0       */
    int64_t   first;        /* byte offset of head record   (0 = empty)    */
    int64_t   last;         /* byte offset of tail record   (0 = empty)    */
    int64_t   free;         /* byte offset of free-list head (0 = grow EOF)*/
    uint64_t  seq;          /* monotonic reqid sequence (survives restart) */
    uint64_t  generation;   /* bumped on each compaction (.new swap)       */
    int64_t   created_tod;
    uint8_t   reserved[FRM_REC_SIZE_HDR_PAD];   /* zero-fill to FRM_REC_SIZE*/
} frm_file_hdr_t;

typedef struct {
    /* linkage + identity (first cache line hot) */
    int64_t   self;         /* byte offset of THIS record (self-check)     */
    int64_t   next;         /* next in active OR free chain (0 = end)      */
    uint64_t  rec_crc32c;   /* CRC32c of whole record with this field == 0 */
    /* request identity */
    char      reqid[FRM_REQID_LEN];    /* "<seq>.<pid>@<host>" NUL-term     */
    char      lfn[FRM_LFN_LEN];
    int16_t   opaque_off;              /* offset of '?' in lfn, -1 if none  */
    int16_t   lfn_url_off;
    /* requester */
    char      requester_dn[FRM_DN_LEN];/* GSI DN or token "sub"            */
    char      user[FRM_USER_LEN];
    /* delivery */
    char      notify[FRM_NOTIFY_LEN];  /* notify target, "-" = none         */
    char      selector[FRM_SELECTOR_LEN];
    /* integrity request */
    char      cs_value[FRM_CSVAL_LEN];
    uint8_t   cs_type;                 /* frm_cstype_t                      */
    /* control */
    uint8_t   status;                  /* frm_status_t                      */
    int8_t    priority;                /* -1..2, XRootD Prty range          */
    uint8_t   queue;                   /* stgQ/migQ/getQ/putQ (XRootD numQ) */
    uint32_t  options;                 /* FRM_OPT_* bitmask                 */
    int32_t   fail_code;               /* errno-style reason when FAILED    */
    uint32_t  attempts;
    /* timestamps (unix seconds) */
    int64_t   tod_added;
    int64_t   tod_status;
    int64_t   tod_expire;              /* hard expiry; 0 = never (reaper)   */
    uint8_t   reserved[FRM_REC_RESERVED]; /* pad so sizeof == FRM_REC_SIZE  */
} frm_record_t;
/* FRM_REC_SIZE fixed (e.g. 4608 = 1.5 pages) >= sizeof(frm_record_t);
 * _Static_assert(sizeof(frm_record_t)==FRM_REC_SIZE) guards it. */
```

**SHM index entry** (active records only; 3 KB `lfn` not stored — `lfn_hash` covers dedup):

```c
typedef struct {
    char       reqid[FRM_REQID_LEN];
    uint64_t   lfn_hash;     /* FNV-1a of lfn */
    int64_t    file_off;     /* byte offset of record in file */
    uint8_t    status; int8_t priority; uint8_t queue; uint8_t in_use;
    int64_t    tod_added; int64_t tod_expire;
    ngx_msec_t last_seen;    /* LRU reaper */
} frm_index_entry_t;

typedef struct {
    ngx_shmtx_sh_t    lock;        /* MUST be first */
    uint64_t          generation;  /* must equal file hdr.generation */
    uint32_t          capacity, count;
    uint64_t          reconcile_full_total;
    frm_index_entry_t slots[];
} frm_index_table_t;
```

### 3.3 Public API (`frm.h`)

```c
typedef struct frm_queue_s frm_queue_t;

typedef struct {
    const char *lfn;            /* required */
    const char *requester_dn;   /* may be NULL */
    const char *user, *notify, *selector, *cs_value;
    frm_cstype_t cs_type;
    uint32_t     options;       /* FRM_OPT_* */
    int8_t       priority;      /* -1..2 */
    uint8_t      queue;
    int64_t      tod_expire;    /* 0 = never */
} frm_req_view_t;

/* queue resolution / lifecycle (config + master init) */
frm_queue_t *frm_queue_get(const ngx_str_t *name);
ngx_int_t    frm_queue_init(frm_queue_t *q, ngx_log_t *log);   /* reconcile */

/* durable, globally-unique "<hdr.seq++>.<pid>@<host>" under file lock */
ngx_int_t    frm_reqid_generate(frm_queue_t *q, char *buf, size_t buf_sz);

/* mutating ops (fcntl lkExcl, fsync, then patch SHM). add returns NGX_DECLINED
 * on duplicate live request for same lfn+queue (dedup). */
ngx_int_t    frm_request_add(frm_queue_t *q, const frm_req_view_t *req,
                             char *reqid_out, size_t reqid_out_sz, ngx_log_t *log);
ngx_int_t    frm_request_get(frm_queue_t *q, const char *reqid,
                             frm_record_t *out, ngx_log_t *log);
ngx_int_t    frm_request_set_status(frm_queue_t *q, const char *reqid,
                             frm_status_t status, int32_t fail_code, ngx_log_t *log);
ngx_int_t    frm_request_delete(frm_queue_t *q, const char *reqid, ngx_log_t *log);

/* listing (fcntl lkShare; iterates SHM index). status<0=any; queue==0xff=any */
ngx_int_t    frm_request_list(frm_queue_t *q, ngx_uint_t *cursor,
                             int status, int queue, const char *dn_filter,
                             frm_record_t *out, ngx_log_t *log);

/* maintenance (worker-0 timer) */
ngx_int_t    frm_reap_expired(frm_queue_t *q, time_t now, ngx_log_t *log);
```

> **API reconciliation note.** M2/M4/M7 component designs call slightly leaner signatures (`frm_request_add(const frm_request_t*)`, `frm_request_get(reqid,path,out)`, `frm_file_locality(path)`). The plan-of-record signatures above (M1) are the **canonical façade**; Phase 0 ships thin `(reqid,path)`-keyed and `frm_request_find_by_path` adapter wrappers in `queue.c` so the M2/M4/M7 call sites compile against one stable header. The HTTP Tape REST `frm_request_list_files`/`frm_request_cancel`/`frm_pin_release`/`frm_file_locality`/`frm_request_list_active` are also added to `frm.h` as thin façade entry points over the same store.

### 3.4 Directive table (server-scope, `NGX_STREAM_SRV_CONF`)

All FRM directives are server-scope (matching `xrootd_prepare_command` at `src/protocols/root/stream/module.c:652`). Fields live in a `xrootd_frm_conf_t frm;` sub-struct embedded in `ngx_stream_xrootd_srv_conf_t` (`src/core/types/config.h`), right after `prepare_command`, mirroring `xrootd_mirror_conf_t mirror;`.

| Directive | Args | `conf->frm.*` | Default | Setter |
|---|---|---|---|---|
| `xrootd_frm` | on\|off | `ngx_flag_t enable` | off | flag |
| `xrootd_frm_queue_path` | path | `ngx_str_t queue_path` | "" (req. if enable) | str + postconfig validate absolute/writable |
| `xrootd_frm_max_inflight` | N | `ngx_uint_t max_inflight` | 64 | num |
| `xrootd_frm_stagecmd` | cmd | `ngx_str_t stagecmd` | inherits `prepare_command` | str (merge fallback) |
| `xrootd_frm_copycmd` | cmd | `ngx_str_t copycmd` | "" | str |
| `xrootd_frm_copymax` | N | `ngx_uint_t copymax` | 4 | num |
| `xrootd_frm_stage_ttl` | time | `ngx_msec_t stage_ttl` | 600000 | msec |
| `xrootd_frm_xfrhold` | time | `ngx_msec_t xfrhold_ms` | 30000 | msec |
| `xrootd_frm_stage_wait` | sec | `ngx_uint_t stage_wait` | 30 | num |
| `xrootd_frm_fail_backoff` | time | `ngx_msec_t fail_backoff_ms` | 60000 | msec |
| `xrootd_frm_fail_retries` | N | `ngx_uint_t fail_retries` | 3 | num |
| `xrootd_frm_residency_cmd` | cmd | `ngx_str_t residency_cmd` | "" | str |
| `xrootd_frm_copy_timeout` | time | `ngx_msec_t copy_timeout` | 0 (none) | msec |
| **Cat-2 (Phase 4)** | | | | |
| `xrootd_frm_migrate_copycmd` | cmd | `ngx_str_t migrate_copycmd` | "" | str |
| `xrootd_frm_purge_watermark` | high low | `ngx_uint_t purge_hi_ppm, purge_lo_ppm` | 0 0 (off) | custom TAKE2 ratio→ppm |
| `xrootd_frm_purge_interval` | time | `ngx_msec_t purge_interval_ms` | 300000 | msec |

Merge in `ngx_stream_xrootd_merge_srv_conf` (`src/core/config/server_conf.c`), inits in `ngx_stream_xrootd_create_srv_conf`. The stagecmd→prepare_command inheritance: `if (conf->frm.stagecmd.len == 0) conf->frm.stagecmd = conf->prepare_command;`.

**HTTP-side directive** (Phase 2): `xrootd_webdav_tape_rest on|off` in `src/protocols/webdav/module.c` (~L321), field `ngx_flag_t tape_rest;` in `webdav.h` loc_conf (~L139).

---

## 4. Phased implementation

### Phase 0 — Foundation (M1 durable queue + M2 prepare opcode rewrite)

**Goal:** a durable, crash-safe stage queue with real reqids, wired into `kXR_prepare`/`kXR_QPrep`. No transfers yet — the request is durable and pollable, the legacy fire-and-forget command still runs.

**CREATE:**
- `src/frm/frm_format.h`, `src/frm/frm.h`, `src/frm/frm_internal.h` — formats + API + internal decls (§3.2/§3.3). Reuse credit: `src/core/compat/crc32c.c` SSE4.2 CRC32c verbatim; struct discipline from `XrdFrcReqFile.hh:74-79`.
- `src/frm/reqfile.c` — file engine: `fcntl` lock (replicates `XrdFrcReqFile::FileLock`, `XrdFrcReqFile.cc:491-534`), header read/refresh (`:518-528`), `frm_rec_read/_write` (pread/pwrite + CRC + fdatasync), free-list pop/push (`:88-96,175-180`), WAL append/commit (`:116-118,553-564`). Reuse: pread/pwrite + fsync idioms from `src/fs/cache/open_or_fill.c`.
- `src/frm/index.c` — SHM zone (clone `src/net/manager/registry.h:45-48` lock-first flexible array; LRU reaper `src/protocols/root/session/registry.c:226-289`).
- `src/frm/reconcile.c` — `Init` analog (`XrdFrcReqFile.cc:216-302`): validate, CRC-scan, rebuild chains ordered `(priority desc, tod_added asc)` (`:266-283`), compact, repopulate index.
- `src/frm/compact.c` — `ReWrite` analog (`XrdFrcReqFile.cc:571-623`): stream → `.new`, fsync, atomic `rename`, bump `generation`.
- `src/frm/reqid.c` — durable `seq` bump (persisted analog of `xrootd_tpc_generate_key`, `src/tpc/key_registry.c:118-127`).
- `src/frm/queue.c` — façade + `frm_queue_get`/`frm_queue_init` + public ops + the `(reqid,path)` adapter wrappers (§3.3 note).
- `src/frm/reaper.c` — worker-0 timer.
- `src/frm/directives.c` — directive table fragment + custom setters.
- `src/frm/README.md`.

**MODIFY:**
- `src/core/types/config.h` — embed `xrootd_frm_conf_t frm;` after `prepare_command`.
- `src/protocols/root/stream/module.c` (~L652, after `xrootd_prepare_command`) — register the FRM directive block.
- `src/core/config/server_conf.c` — `create_srv_conf` UNSET inits + `merge_srv_conf` FRM block (stagecmd inheritance).
- `src/core/config/postconfiguration.c` — `ngx_shared_memory_add` for the index zone; wire `frm_queue_init` into the master post-config phase (before fork).
- `src/core/config/process.c` — register the reaper timer in `init_process`.
- `src/core/types/context.h:292` — widen `char prepare_reqid[32]` → `char prepare_reqid[XROOTD_FRM_REQID_LEN]` (host-qualified reqids exceed 32; truncation would break QPrep matching).
- `src/protocols/root/query/prepare.c`:
  - add `#include "../frm/frm.h"` (after line 5).
  - **`xrootd_handle_prepare`:** replace the cancel/evict noop (222–227) with cancel dispatch (`xrootd_prepare_handle_cancel`) + `is_evict` deferral (§2b of M2); generate reqid before parse loop (§2c) — replaces `ngx_memcpy(ctx->prepare_reqid,"0",2)` at **338**; widen `out_resolved` guard at **285** to `(collect_stage || do_enqueue || is_evict)` (§2d); enqueue one record per resolved path in loop tail **302–305** via `xrootd_prepare_enqueue_one` (§2d); store durable reqid at **338** via `ngx_cpystrn`; gate/remove inline `xrootd_prepare_invoke_command` **343–357** behind `!conf->frm.enable` (legacy path); rebuild notify body **368–399** with the real reqid (variable-length; recompute `ok_len = HDR + reqid_len`); return real reqid at **401**; evict return (§2f).
  - **`xrootd_query_prep_status`:** capture reqid replacing **441–447** (§5a); read queue state via `frm_request_get` replacing the bare stat **504–518** (§5b) — emit `A`/`q`/`s`/`f`/`M`, falling back to `xrootd_stat_beneath` on no-record. The auth chain at **506–511** stays verbatim.
  - new statics `xrootd_prepare_handle_cancel` (§4a), `xrootd_prepare_enqueue_one` (§4b), `xrootd_prepare_status_char` (§4c).
- **config script** — add all `src/frm/*.c` to `ngx_module_srcs` (after the `src/protocols/root/query/prepare_cmd.c` line at **L441**); add `src/frm/*.h` to `ngx_xrootd_stream_deps`.

**Reuse credit:** ~70% of `reqfile.c`/`reconcile.c`/`compact.c` logic is a direct port of `XrdFrcReqFile`; CRC32c, SHM zone, LRU reaper, fcntl-lock, and `(void*)1` sentinel are all existing patterns. Net new logic is the index↔file authority glue and the prepare.c surgery.

**BUILD:** new `.c` files ⇒ **one `./configure` run** then `make -j$(nproc)`; validate with `objs/nginx -t`.

**TEST PLAN** (`tests/test_frm_queue.py`, self-contained nginx fixture per `test_srr_endpoint.py`):
- *Durable-queue (queue.c/index.c):* **S** enqueue → `frm_request_get` returns it; restart nginx → reconciliation rebuilds index, request still gettable (`reconcile_full_total` / `generation` advanced). **E** truncate last record / corrupt `rec_crc32c` → reconcile skips it, does not crash, no double-link. **N** record with `lfn` containing `..`/NUL is re-validated through `resolve_path` on replay, not blindly trusted.
- *prepare opcode (prepare.c):* **S** `kXR_prepare(kXR_stage)` returns a non-`"0"` host-qualified reqid; `kXR_QPrep` with that reqid reports per-path state. **E** `kXR_QPrep` with unknown reqid → `M`/declined, no crash. **N** path traversal in the prepare payload rejected by `xrootd_prepare_check_path` (confine chain untouched, 85–181).
- *cancel:* **S** `kXR_prepare(kXR_cancel)` with reqid in payload line 0 → `frm_request_delete`, `kXR_ok`. **E** empty payload → `kXR_ArgMissing "Prepare requestid not specified"`. **N** unknown reqid → idempotent `kXR_ok` (no oracle).

**DEFINITION OF DONE:** `kXR_prepare` issues durable reqids that survive disconnect and a full nginx restart; `kXR_QPrep` reports real queue state across reconnects/workers; `reqid="0"` is gone; crash mid-append never corrupts the chain (CRC + `self`-check verified); legacy `prepare_command` still fires when `frm.enable` off. Ships independently as a "durable prepare" feature even with no transfer worker.

---

### Phase 1 — Discoverable, pollable, synchronous gateway (M3 status + M4 residency/offline + M7-thin worker + M8 dedup/backoff)

**Goal:** the **usable synchronous tape gateway (~12pw cumulative).** Files are residency-aware on every face; a `kXR_open` of a nearline file triggers a real, reaped, de-duplicated recall and stalls the client with `kXR_wait`-and-retry; `kXR_QPrep` reports live progress.

**CREATE:**
- `src/frm/residency.h`, `src/frm/residency_xattr.c` — `user.frm.residency` xattr (mirror `src/protocols/webdav/prop_xattr.c:23-118`; absent ⇒ ONLINE, `NGX_DECLINED` on `ENODATA`/`ENOATTR`).
- `src/frm/residency_probe.c` — `frm_residency_probe()` (§1 of M4): off→`{ONLINE}` (0 syscalls); dedup-set lookup first; then xattr; default ONLINE. Composes with existing `xrootd_cache_path_flag()` (independent bit).
- `src/frm/stage_registry.c` + decls in `residency.h` — `frm_stage_table_t` SHM dedup-set, `frm_stage_claim` (LAUNCH/DEDUP/FULL atomic under one `ngx_shmtx_lock`, clone `src/tpc/key_registry.c:154-183`), `frm_stage_dedup_lookup`, `frm_stage_release`. `frm_stage_configure_registry(cf)`.
- `src/frm/stage_fail.c` — `.fail`/hold sidecar (port `XrdOssStage.cc:134-139`): `frm_stage_fail_check/_mark/_clear`.
- `src/frm/stage_exec.c` — reap-and-capture exec helper `xrootd_stage_run_copycmd` (single-fork + `waitpid` on a pool thread; factor shared `xrootd_close_inherited_fds()` out of `prepare_cmd.c:103-152`, reuse the no-shell `execv` body and SECURITY block `prepare_cmd.c:32-37`).
- `src/frm/stage_registry.h` + `src/frm/stage_worker.c` — `xrootd_stage_job_t`; `xrootd_stage_worker_thread` (Fetch logic `XrdFrmTransfer.cc:146-328`: pre-stat → copy to `pfn.anew` → verify `stat`+size → atomic `rename` → on fail unlink+`.fail`) + `xrootd_stage_worker_done` (commit M1 status, `frm_stage_release`, fail-backoff `retry_not_before`, scheduler kick). **Phase-1 `worker_done` does NOT call `deliver_waiters`** — that's Phase 3.
- `src/frm/stage_scheduler.c` — per-worker drain timer: `xrootd_stage_claim_queued` (QUEUED→RUNNING atomic vs `copymax`, `ngx_atomic_fetch_add(&running)`), post `xrootd_task_bind(task, worker_thread, worker_done)` + `ngx_thread_task_post` (reuse `src/fs/cache/open_or_fill.c:78-80`, `src/core/aio/aio.h:32-40`), skip `retry_not_before>now`.
- `src/frm/stage_launch.c` — detached launcher on `FRM_STAGE_LAUNCH`: fail-check → xattr `staging` → enqueue/post → flip xattr on done.

**MODIFY:**
- `src/protocols/root/read/stat.c:123` — after `xrootd_cache_path_flag()`, probe residency; OR `kXR_offline`(=8) / `kXR_bkpexist`(=128, backend_exists) / `kXR_poscpend`(=64, staging) into `extra_flags` (channel `kXR_cachersp` already uses; `src/protocols/root/path/stat_body.c:18` already OR-merges, no change there).
- `src/protocols/root/read/statx.c:186` — same injection where `extra` is computed (batched must match single).
- `src/protocols/root/read/open_request.c:413` — after `S_ISDIR` check / before `xrootd_auth_gate` (**read opens only**), the stall/stage block (§4 of M4): not-resident + no-backend → `kXR_NotFound`; `.fail==ENOENT` → `kXR_NotFound`; `.fail==HOLD` → `xrootd_send_wait` (no relaunch); else `frm_stage_claim` → on LAUNCH `frm_stage_launch`, then `xrootd_send_wait(conf->frm.stage_wait)` (LAUNCH/DEDUP/FULL all stall). `kXR_nowait`/`?frm.stage=0` (nostage) → `kXR_FSError` offline error, never recall. Write/create branch (**421**) skipped. Auth gate at **416** still fires after the probe — **no residency oracle for unauthorized callers.**
- `src/protocols/webdav/propfind.c` — add `PF_LOCALITY (1u<<19)`, bump `PF_ALL` (44–63), register `{"locality",PF_LOCALITY}` (96), add `<xrd:locality/>` to PROPNAME (474), emit value in `propfind_entry` (609, files only) via `frm_residency_probe` → `ONLINE`/`NEARLINE`/`ONLINE_AND_NEARLINE`/`LOST`.
- `src/protocols/s3/object.c:189` (`s3_handle_head`) + `:89` (`s3_handle_get`) — probe; if `!resident && backend_exists` add `x-amz-storage-class: GLACIER` + `x-amz-restore`; GET of nearline → `403 InvalidObjectState` (never block).
- Top-level `config` script — register new `.c`/`.h` files in the relevant
  `ngx_module_srcs`/deps lists; update `src/core/config/config.h` only for config
  structs/directive declarations. Wire `frm_stage_configure_registry(cf)` into
  `src/core/config/postconfiguration.c` alongside `xrootd_tpc_key_configure_registry`.
- **config:** add `src/frm/metrics.c` to the **HTTP metrics module** srcs block; add the FRM `ngx_xrootd_frm_metrics_t frm;` block to `src/observability/metrics/metrics.h` (state enum `XROOTD_FRM_STATE_*`, `XROOTD_FRM_FAIL_*`, latency buckets), `XROOTD_FRM_METRIC_INC/ADD` macros in `metrics_macros.h`, exporter prototype in `metrics_internal.h`, fan-out from `xrootd_export_prometheus_metrics` in `src/observability/metrics/stream.c`. **Mixed-ABI rule applies** (`metrics.h` struct grows): clean rebuild or touch a `.c` in every module including `metrics.h`.

**Reuse credit:** residency xattr is a structural clone of the WebDAV lock xattr; the dedup set and the worker thread/done binder are clones of the TPC key registry and cache-fill job respectively; the stall is the existing `xrootd_send_wait`. The genuinely new code is the copy→temp→verify→rename worker body and the open-path stall policy.

**BUILD:** new `.c` ⇒ **`./configure` + full clean `make`** (also forced by the `metrics.h` ABI growth).

**TEST PLAN** (`tests/test_frm_staging.py` + `tests/frm_fake_mss.py` simulator):
- *Residency/offline emission (stat/statx/propfind/s3):* **S** resident file → no `kXR_offline`, serves normally; nearline → `kXR_offline|kXR_bkpexist` on `kXR_stat`, `NEARLINE` on PROPFIND, `GLACIER` on S3 HEAD — same instant, all three faces. **E** offline/lost → `kXR_NotFound` / S3 `InvalidObjectState`. **N** a nearline file the caller is **not** authorized for → `kXR_NotAuthorized` (probe runs post-`stat_beneath`, auth_gate still fires), never a residency oracle.
- *Async-completion ordering (worker/exec/scheduler):* **S** `FRM_LATENCY_MS=1500`; open offline → `kXR_wait`; poll `kXR_QPrep` until `A <path>`; re-open succeeds; `stage_latency_seconds` recorded. **E** permanent stagecmd fail → after `fail_retries` QPrep stays `M`, open returns kXR error (not infinite wait). **N** client cannot shorten/skip `xfrhold` or force completion by replaying a streamid.
- *Concurrent-open dedup (stage_registry.c):* **S** 8 simultaneous opens of one offline path → exactly **one** stagecmd (`FRM_AUDIT_LOG` line count == 1, `dedup_hits_total == 7`, exactly one `FRM_STAGE_LAUNCH`). **E** the single in-flight stage fails → all 8 waiters get the failure consistently. **N** flood of distinct nonexistent paths cannot exceed `max_inflight`/exhaust fds — excess queued or shed `kXR_Overloaded`.

**DEFINITION OF DONE:** a nearline file opened over `root://` triggers exactly one real recall, the client stalls and retries to a hit; offline residency is reported byte-consistently across stream/WebDAV/S3; copymax bounds concurrent transfers; `.fail`/hold prevents respin; Prometheus exposes `xrootd_frm_*`. **This is a shippable synchronous tape gateway** — no server push, but fully functional.

---

### Phase 2 — Cancel/evict polish + HTTP WLCG Tape REST API (M6 + M2-http)

**Goal:** the standard WLCG HTTP Tape REST surface so FTS/gfal2 drive staging over `davs://`, plus completed evict/release semantics.

**CREATE:**
- `src/protocols/webdav/tape_rest.h` / `src/protocols/webdav/tape_rest.c` — router `webdav_tape_handle(r)` (parses `/api/v1/{stage,release,unpin,archiveinfo,fileinfo}[/{id}[/cancel]]`), method gating, per-verb auth/scope, jansson parse/build, reqid minting (reuse `RAND_bytes` per `macaroon_endpoint.c:388`). Endpoint→M1 mapping:
  - `POST /api/v1/stage` → mint reqid, per file `frm_request_add(... FRM_OPT_STAGE, diskLifetime, activity)` → `201` `{requestId,id,accessURL,request}` + `Location:`.
  - `GET /api/v1/stage/{id}` → `frm_request_get` + `frm_request_list_files` + `frm_file_locality` → `StageBulkRequestStatusModel` (`status` ∈ STARTED/COMPLETED/CANCELLED; per-file QUEUED/COMPLETED/CANCELLED/ERROR/UNKNOWN, `pathsStaged`, `failures[]`).
  - `DELETE /api/v1/stage/{id}` → `frm_request_delete` → `204`.
  - `POST /api/v1/stage/{id}/cancel` → `frm_request_cancel(id, paths[])` → `204`.
  - `POST /api/v1/release/{id}` (alias `unpin`) → per-path `frm_pin_release` → `200` `{unpinnedFiles,nonUnpinnedFiles}`.
  - `POST /api/v1/archiveinfo` (alias `fileinfo`) → **synchronous** `frm_file_locality` per path (stat + residency, **no queue write**) → `[{path,exists,onDisk,onTape,checksums,locality}]`.
  - `GET /api/v1/stage` (+ `/release`/`/archiveinfo`) → `frm_request_list_active`.
  - Reuse `send_json` from `macaroon_endpoint.c:194` (or factor `webdav_send_json` into `io.c`); jansson build exactly like `dashboard/api.c` (`-ljansson` already in `CORE_LIBS`).

**MODIFY:**
- `src/frm/queue.c` / `frm.h` — implement the façade entry points `frm_request_list_files`, `frm_request_cancel`, `frm_pin_release`, `frm_file_locality`, `frm_request_list_active` over the existing store.
- `src/protocols/webdav/module.c` (~L321, next to `xrootd_webdav_tpc`) — register `xrootd_webdav_tape_rest` flag directive.
- `src/protocols/webdav/webdav.h` (~L139) — `ngx_flag_t tape_rest;` in loc_conf; init `NGX_CONF_UNSET` in `config.c:create_loc_conf`; `ngx_conf_merge_value(...,0)` (off by default).
- `src/protocols/webdav/dispatch.c` — at top of `ngx_http_xrootd_webdav_handler`, **before** proxy-mode delegation (L70) and method routing, insert the `/api/v1/` prefix check → `webdav_tape_handle(r)` (POST bodies via `xrootd_http_read_body` → `NGX_DONE`; GET/DELETE inline). Same structural slot as the macaroon block (42–67).
- Auth (M6/auth): mutating verbs require bearer `storage.stage` per path (`xrootd_identity_check_token_scope(...,write=1)`, `storage.modify` accepted as superset for cancel/release); `archiveinfo` requires `storage.read`; any failing path → `403` whole-request (no partial side effects); anonymous → `401`; GSI-cert auth gated behind `conf->common.allow_write` (INVARIANT 11). Every wire `path` → `ngx_http_xrootd_webdav_resolve_path` **before** any `frm_*` call (INVARIANT 4).
- **config** — add `src/protocols/webdav/tape_rest.c` to `ngx_module_srcs` (~L572 webdav block), `tape_rest.h` to `ngx_xrootd_webdav_deps` (~L208).

**Reuse credit:** `macaroon_endpoint.c` is the near-complete precedent (POST/JSON/body-read/reqid/scope); the M1 store already exists from Phase 0. New code is the endpoint router + the WLCG schema marshalling.

**BUILD:** new `.c`/`.h` ⇒ **one `./configure`** then `make`.

**TEST PLAN** (`tests/test_tape_rest.py`):
- **S** POST `/stage` with `storage.stage` token → `201` + `Location`; GET `{id}` → `files[].state`; `archiveinfo` → `onDisk`/`locality`.
- **E** GET unknown id → `404`; malformed JSON / empty `files` → `400`; DELETE → `204`.
- **N** read-only token (no `storage.stage`) → `403`; anonymous → `401`; `../../etc/passwd` in `files[].path` → rejected by `resolve_path` (`403/400`, never escapes root).
- *evict/cancel (stream side):* **S** `kXR_prepare(kXR_evict)` marks purge-eligible (`frm_request_set_status FRM_PURGE`), returns reqid. **E** evict of unknown path → ignored miss, ok. **N** cancel cannot delete another tenant's request (auth chain enforced upstream).

**DEFINITION OF DONE:** FTS/gfal2 can submit/poll/cancel/release/archiveinfo over `davs://` against the same durable queue that `root://` uses; both spec names and deployed aliases resolve; auth scopes enforced per-path with no partial side effects.

---

### Phase 3 — Async completion delivery (M5)

**Goal:** satisfy a stalled `kXR_open` **in place** via `kXR_waitresp`→`kXR_attn(asynresp)`, with full disconnect tolerance — eliminating the poll-and-retry latency/load of Phase 1.

**CREATE:**
- `src/frm/stage_deliver.c` — `xrootd_stage_deliver_waiters(reqid)` + `deliver_one(entry, waiter, c, ctx)`:
  - causality guard: emit `asynresp` only if `waitresp_sent` latched (re-check before push); on a race, send `xrootd_send_waitresp` first.
  - liveness check: resolve `conn_number → ngx_connection_t` in this worker's `ngx_cycle->connections`, validate `c->number == waiter.conn_number`, not closing, `ctx->destroyed == 0` (the `src/core/aio/resume.c:23` guard generalized); any failure → drop waiter silently, free slot.
  - `ONLINE` → build the real open-ok body (fhandle) for `entry->pfn` bound to `c` and push via `xrootd_send_attn_asynresp(ctx, c, waiter.streamid, kXR_ok, body, len)` (manager mode → `kXR_redirect` body); `FAILED` → `asynresp(entry->xrd_error, err_msg)`. Then `xrootd_aio_resume(c)`. **Pass the saved `waiter.streamid`** — never `ctx->cur_streamid`.
  - cross-worker fan-out (M5 mech B): elected scheduler signals owning `worker_pid`; each worker runs `deliver_waiters` only for its own PID's waiters (no cross-process pointer access).

**MODIFY:**
- `src/frm/stage_registry.h` — populate `waiters[]` + `waitresp_sent` (the schema already carries them from Phase 1; this turns them on).
- `src/protocols/root/read/open_request.c` — replace the Phase-1 `xrootd_send_wait` stall (for stageable misses) with: `xrootd_stage_admit`/look-up-by-lfn dedup → `xrootd_stage_add_waiter{ngx_pid, c->number, hash(sessid), cur_streamid, waitresp_sent=0}` → `xrootd_send_waitresp` now → latch `waitresp_sent=1` → return to `XRD_ST_REQ_HEADER`. (Keep a config/feature flag so Phase-1 `kXR_wait` behavior remains selectable.)
- `src/frm/stage_worker.c` `xrootd_stage_worker_done` — now calls `xrootd_stage_deliver_waiters(reqid)` after `xrootd_stage_finish` (the call site already reserved in §2.5).
- `src/protocols/root/query/prepare.c` notify block (393–399) — now able to send `asyncms` on real completion for `missing>0` (the deferred "completion pipe" future-work comment is resolved).
- `src/protocols/root/connection/disconnect.c` — **no required teardown**: waiters are identified by `conn_number`, so a stale waiter is harmless (reaped at delivery or by TTL). The transfer is **not** cancelled by disconnect. Optional best-effort clear of `(ngx_pid, c->number)` waiters for tidiness.
- **config** — add `src/frm/stage_deliver.c` to `ngx_module_srcs`.

**Reuse credit:** the entire wire layer (`xrootd_send_waitresp` `src/.../control.c`, `xrootd_send_attn_asynresp` `async.c:113`, `xrootd_aio_resume`) and the `ctx->destroyed` liveness guard already exist; the schema already carries `waiters[]`. New code is the fan-out + liveness re-find + the open-ok body rebuild for a parked streamid.

**BUILD:** new `.c` ⇒ **`./configure`** then `make` (no struct ABI change beyond Phase-1 reservations → if `metrics.h` unchanged, the ABI rule may not bite, but a clean rebuild is safest).

**TEST PLAN** (`tests/test_frm_async.py`):
- **S** open offline → `kXR_waitresp` (streamid parked); recall completes → `kXR_attn(asynresp, kXR_ok)` on the **same** streamid; client uses the fhandle without re-open. Assert `waitresp` strictly precedes `asynresp`.
- **E** recall fails → `asynresp(kXR_error)` on the parked streamid; client sees the real error, not a hang.
- **N (disconnect tolerance):** client disconnects during the stall → `deliver_one` finds `c->number` mismatch/`destroyed`, drops the waiter silently, transfer still completes, M1 state `ONLINE`; reconnecting client gets a hit / `QPrep` `A`. Assert no crash, no cross-process deref, waiter slot freed.
- **N (causality):** an `asynresp` is never emitted for a streamid that never parked a `waitresp` (guard verified by forcing the race).

**DEFINITION OF DONE:** a stalled open is satisfied in place within milliseconds of `rename`; multiple waiters on one reqid are woken from a single completion; a client may disconnect mid-stall without losing the recall or crashing the server; `kXR_prepare(kXR_notify)` for `missing>0` finally delivers `asyncms`.

---

### Phase 4 — Optional parity (F1–F6, deferrable)

Independent, low-priority items, each its own change + 3 tests:
- **F1 cmsd `Have`** — on stage completion in manager mode, `xrootd_srv_register` the now-resident path (`XrdFrmTransfer.cc:254`); the cache-fill done callback is the template.
- **F2 multi-queue selectors** — honor `selector`/`queue` (`stgQ/migQ/getQ/putQ`) so distinct activity classes map to distinct queues.
- **F3 residency-cmd** — wire `xrootd_frm_residency_cmd` as an authoritative out-of-band residency oracle (overrides the xattr) for sites with an external locality DB.
- **F4 per-source quota / TTL reaper polish** — bound queue growth per DN/VO; extend the reaper.
- **F5 checksum verification on stage-in** — honor `cs_type`/`cs_value`; fail recall on mismatch.
- **F6 Category-2 migrate/purge** (`src/frm/migrate_purge.c`) — **explicit non-goal of B2**; ship only the directive/metric scaffolding + the fake-MSS migrate mode. Real policy delegated to CTA/dCache/HPSS. Tests in `tests/test_frm_migrate_purge.py` exercise the scaffolding (migrate-out → purge-eligible; migrate-fail → disk intact; watermark math vs ppm parse) but the engine stays a stub.

**DEFINITION OF DONE:** each F-item lands independently behind its own directive/flag; none is required for the MVP.

---

## 5. Risks & mitigations

| Risk | Severity | Mitigation |
|---|---|---|
| **Durability across restart (the #1 risk).** nginx SHM is process-group-lifetime, not fsync'd — naively homing state in SHM loses every queued recall on restart, and the original bug homed it on the *connection* (`ctx->prepare_paths`, freed at `disconnect.c:32-36`). | Critical | **File = truth, SHM = cache.** File-backed fixed-record log modeled on `XrdFrcReqFile`; **header-write is the commit point**; WAL ordering = body+`fdatasync` then header+`fsync`; atomic `rename` compaction (a crash mid-compact leaves the *old* file intact). Per-record `rec_crc32c` + `self`-check make torn records *detectable* (XRootD's format has neither). Master-start `frm_queue_init` reconciles file→SHM before workers fork; any `generation` mismatch collapses SHM back to the file. Test 1S restart-durability + 1E truncated-tail are gating. |
| **Async delivery to a disconnected client.** A multi-hour stall guarantees some clients vanish; dereferencing a freed `ngx_connection_t*` cross-worker would crash nginx. | High | The waiter stores **`{worker_pid, conn_number, sessid_hash, streamid}`, never a pointer**. `deliver_one` re-finds the connection by `conn_number` and validates `c->number == waiter.conn_number` + `!destroyed` + not-closing; any mismatch → silent drop + slot free. Each worker only ever touches connections it owns. The transfer is **not** cancelled by disconnect, so a reconnecting client gets a hit. Phase-3 test 3N (disconnect mid-stall) is gating. |
| **Manager-mode redirect × `kXR_offline`.** A redirect loop or an offline DS that never resolves could wedge the client. | High | Manager `kXR_open` redirects to the DS; the DS does the residency probe + stall/stage; on permanent failure the DS surfaces `kXR_NotFound` and the manager exhausts `tried`/`triedrc` (the `conformance_topologies` redirect-loop fix path, `xrootd_manager_tried_exhausted`) → `kXR_NotFound`, never a loop. F1 `Have` registration makes the post-stage retry resolve to a real read. Phase-1/4 manager-redirect tests (5E redirect-loop, 5N injected-`tried` host) are gating. |
| **Concurrent-open thundering herd.** N opens of one tape file must not launch N recalls or exhaust fds. | Medium | `frm_stage_claim` does test-and-claim under a single `ngx_shmtx_lock` → exactly one `LAUNCH`, N-1 `DEDUP`; `copymax` caps global RUNNING via `ngx_atomic`; `FRM_STAGE_FULL` and `max_inflight` shed with `kXR_Overloaded`. Phase-1 dedup test (8 opens → 1 stagecmd, `dedup_hits_total==7`) is gating. |
| **Respin on permanent failure.** A backend that always fails a file would spin the queue forever. | Medium | `.fail`/hold sidecar (port of `XrdOssStage.cc:134-139`) checked **before** claim → `HOLD` stalls without relaunch, `ENOENT` → immediate `kXR_NotFound`; fail-backoff `retry_not_before = now + min(base<<attempts, cap)`; after `fail_retries` the entry stays `FAILED`. |
| **Fake-MSS test simulator fidelity.** Tests must deterministically exercise latency/partial/permanent failure without a real tape system. | Medium | `tests/frm_fake_mss.py` — env-driven (`FRM_LATENCY_MS`, `FRM_FAIL_MODE`, `FRM_FAIL_RATE` hash-stable, `FRM_FAIL_PATH`, `FRM_TAPE_DIR`, `FRM_AUDIT_LOG`, `FRM_RESIDENCY_PROBE`), `execv`'d with absolute argv (matching `prepare_cmd.c` layout). "online"=under `DATA_DIR`, "offline"=only under `FRM_TAPE_DIR`. Self-contained nginx fixture (`test_srr_endpoint.py` pattern) runs under `TEST_SKIP_SERVER_SETUP` without the fleet; new ports `FRM_STAGE_PORT=11206`/`FRM_MGR_PORT=11207`/`FRM_DATA_PORT=11208`. |
| **Mixed-ABI stale-object crash.** Growing `ngx_xrootd_metrics_t` (Phase 1) + incremental `make` → SIGSEGV from stale objects (memory `build_header_dep_mixed_abi`). | Medium | Any `metrics.h`/`config.h` struct-layout change ⇒ **clean full rebuild**, never incremental. Documented in each phase's BUILD step. |

---

## 6. Build governance & sequencing notes

**Source list authority.** The build is governed by the top-level **`config` script** (`ngx_module_srcs` ~L235–L520; deps lists `ngx_xrootd_stream_deps`, `ngx_xrootd_webdav_deps` ~L208) — **not** `src/core/config/config.h`. Every new `.c` must be appended there; every new `.h` to the right deps list. Editing generated Makefiles or nginx core is forbidden.

**FRM is folded into the existing stream module**, not a new `ngx_module_type=STREAM` block: it shares `ngx_stream_xrootd_srv_conf_t`, the metrics SHM, `xrootd_handle_prepare`, and the open/redirect handler, and **owns no listener** (the one standalone stream module, `ngx_stream_xrootd_cms_srv_module`, is separate only because it owns a listener). The reaper/scheduler timers hang off the stream module's `init_process`; the SHM zones off its `postconfiguration` — same pattern as CMS heartbeat, JWKS refresh, and CRL timers.

**`./configure` triggers** (per BUILD GOVERNANCE — new `.c`/new top-level directive/new SHM zone require `./configure`; incremental `make` otherwise):

| Phase | Adds new `.c`? | New directives? | New SHM zone? | Build |
|---|---|---|---|---|
| **0** | yes (`src/frm/{frm_format.h,frm.h,reqfile,index,reconcile,compact,reqid,queue,reaper,directives}`) | yes (`xrootd_frm*`) | yes (index zone) | `./configure` + `make` |
| **1** | yes (`residency_*`, `stage_{registry,fail,exec,worker,scheduler,launch}`, `metrics`) | a few (`stage_ttl`/`xfrhold`/`copymax`…) | yes (dedup-set zone) + `metrics.h` ABI grows | `./configure` + **clean** `make` |
| **2** | yes (`webdav/tape_rest.{c,h}`) | yes (`xrootd_webdav_tape_rest`) | no | `./configure` + `make` |
| **3** | yes (`stage_deliver.c`) | feature flag only | no (Phase-1 reserved `waiters[]`) | `./configure` + `make` |
| **4** | yes (`migrate_purge.c`) | yes (Cat-2) | no | `./configure` + `make` |

**Independent shipping.** Each phase is a standalone, deployable feature:
- **Phase 0** ships "durable prepare" — reqids survive disconnect and restart; pollable `kXR_QPrep`. Useful even with the legacy `prepare_command` doing the actual recall.
- **Phase 1** ships the **usable synchronous tape gateway (~12pw)** — residency-aware faces + real reaped/deduped transfers + `kXR_wait`-and-retry. A site can run production tape staging here.
- **Phase 2** ships the WLCG HTTP Tape REST API for FTS/gfal2; depends only on Phase 0's store (works alongside Phase 1's worker).
- **Phase 3** ships async push (`kXR_waitresp`/`asynresp`); strictly forward-compatible (Phase 1 reserved the schema), upgrades latency/load without touching M1/M7.
- **Phase 4** items each land independently behind their own directive; none gates the MVP.

**Cumulative effort checkpoints:** Phases 0–1 = ~12pw (synchronous gateway); Phases 0–3 = ~24pw (MVP). Phase 4 is opportunistic.
