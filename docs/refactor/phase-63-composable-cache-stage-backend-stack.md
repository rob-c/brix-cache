# Phase 63 — Composable storage stack: any backend, generic read cache + write stage, assembled by config

**Status: COMPLETE + XCache fill-path consolidated — design 2026-06-29; C-1..C-7 +
§14 done; cache fill unified onto ONE driver spine 2026-06-29.**

> **XCache fill consolidation (2026-06-29).** The duplicate origin-fill machinery is
> gone: `fetch.c` now has ONE spine, `xrootd_cache_fill_from_source(t, source)`, that
> every path uses — the registry backend (C-1), the per-fill root:// (`sd_xroot`), and
> S3 (`sd_remote`). `cache_origin` root:// fills (anonymous, bearer/ztn, AND X.509/GSI
> with MITM origin-cert verify) are now **fully in-process** through `sd_xroot`, so the
> two GSI **subprocess** paths — `fetch_origin_exec` (read fill, 132 LOC) and
> `wt_run_flush_exec` (write-back, 149 LOC) — plus the duplicate fill loops (~195 LOC)
> are **deleted (~476 LOC)**. All cache tests + `test_chaos_mixed_auth` (GSI) green.
> `origin_*.c` stays (the `sd_xroot` wire client). `http_transport.c`/`pelican*.c`
> remain — they implement the http/https/pelican `cache_origin` schemes (supported,
> if untested; sd_http lacks their GSI-mTLS/Digest/director features). Every step of §9 is landed: any
source backend, generic cache fill + driver write-back, token+GSI auth (read +
write-back) across stream/WebDAV/S3, the registry composes the stack, one generic
write-back stage decorator, and /metrics observability. Remaining = optional cleanup
only (the `xrootd_credential_*` deprecation shim §14.5, GSI origin-cert verification,
and the "fold upstream/proxy/frm" stretch goal in C-7). The composable stack's user-facing capabilities
are now substantially in place: any source backend (posix/pblock/xroot/http), a
generic read cache filling from it, driver write-back, and bearer-token
authentication to a token-auth origin for BOTH read fill and write-back, at stream
AND http (WebDAV) scope. Remaining: the **GSI/X.509 half of C-3** (in-process
signed-DH — the hard crypto piece; tokens are the modern WLCG path), and the
**C-2/C-6/C-7 refactors** (decorator uniformity + stager consolidation + observability
— architectural cleanup, NOT new capability: the cache already reaches WebDAV/S3 via
`xrootd_cache_open` in `vfs_open.c`). Land them incrementally, not as one change.

> **Implementation log.**
> - **C-1 ✅ (2026-06-29).** The read cache now fills from the export's *registered
>   source backend* when no separate `xrootd_cache_origin` is set:
>   `xrootd_cache_fill_t` gained `source_inst`; `open_or_fill.c` resolves the
>   backend race-free on the main thread (gated on a remote `xroot` source +
>   no `cache_origin`); `xrootd_cache_fetch_origin_backend()` (fetch.c) is the
>   generic `source->driver->open`→`pread`→staged-sink fill; the dispatcher routes
>   to it when `source_inst != NULL`; the cache config gate accepts a remote
>   `xrootd_storage_backend` in lieu of `cache_origin`. Additive —
>   `source_inst == NULL` keeps every legacy `cache_origin` path byte-identical.
>   E2E: `tests/run_cache_backend_source.sh` (miss fills from the backend, stored
>   locally, warm hit, multi-chunk). Regressions green: `run_cache_xroot_origin`,
>   `run_cache_s3_origin`, `run_cache_pblock_pblock`, `run_remote_backend_write`.
> - **C-4 ✅ (2026-06-29).** A read-only **`http` source driver** (`backend/http/`
>   `sd_http.c`) over the shared libcurl transport (`xrootd_s3_origin_curl_transport`,
>   the same vtable `sd_s3` uses): `open`/`stat` HEAD for the size, `pread` issues a
>   byte `Range` GET, no SigV4, no kernel fd (memory-served). A 206 response is the
>   exact range; a 200 (origin ignored `Range:` — e.g. stock python `http.server`)
>   is the whole object, sliced at `off` so the C-1 fill loop stays correct and
>   terminating against either origin. Wired through the registry:
>   `xrootd_storage_backend http://host[:port]/base` (and `https://`) →
>   `xrootd_vfs_backend_config_http` → `sd_http`; the C-1 fill trigger
>   (`open_or_fill.c`) and the cache config gate both accept an `http(s)` source, and
>   checksum-on-fill is suppressed for non-`xroot` sources (no in-band digest).
>   E2E: `tests/run_cache_http_source.sh` — a stock static-HTTP origin (plain nginx,
>   no XRootD) fills the cache via real 206 Range GETs: cold miss byte-exact + stored
>   locally, warm hit, multi-chunk (> 1 MiB) byte-exact. Regressions green:
>   `run_cache_backend_source`, `run_cache_xroot_origin`, `run_remote_backend_write`.
> - **C-5 ✅ (2026-06-29).** The cache **write-back flush** now reaches the origin
>   ONLY through the `sd_xroot` driver — the write-side mirror of C-1's driver fill.
>   `writethrough_flush.c`'s `xrootd_wt_run_flush` builds a per-flush remote instance
>   (`xrootd_sd_xroot_create_origin(host, port, tls)`) and streams the dirty bytes via
>   `dest->driver->{open(O_WRITE),pwrite,ftruncate,fsync}` (new
>   `xrootd_wt_copy_body_driver`), replacing the inline
>   `origin_connect_addr`/`bootstrap`/`open_write` + `xrootd_wt_copy_body` wire path
>   (deleted). Worker-thread-safe create/destroy, so it runs unchanged in both sync
>   and async (thread-pool) modes. The GSI/proxy origin keeps the `xrdcp` exec path
>   (unchanged). The bytes on the wire are identical (sd_xroot's write slots wrap the
>   same anonymous kXR ops) — the win is that the cache no longer speaks the origin
>   protocol directly, so any writable backend can become the write-back target.
>   E2E: `tests/run_cache_wt_driver.sh` (sync + async + multi-chunk flush byte-exact
>   to a remote root:// origin, plus read-back). Regressions green:
>   `run_remote_backend_write` (transparent write-through), `run_pblock_writethrough`.
>   **NB:** like C-1, this does not yet *delete* `cache/origin_*.c` (978 LOC) — sd_xroot
>   still calls those shared wire helpers; the literal deletion is their relocation
>   under `backend/xroot/` once the legacy `cache_origin` fill path is also migrated.
> - **§14 (token slice) ✅ (2026-06-29).** The reusable `xrootd_credential <name> { … }`
>   block (`src/core/config/credential_block.{c,h}`, the nginx `map`/`geo` block-handler
>   pattern) parses the §14.4 POD (`x509_proxy`/`x509_cert`/`x509_key`/`ca_dir`/`token`/
>   `token_file`/`token_forward`/`tls`/`vo`), interned by name (dedup = reload-safe).
>   A source backend names it via the sibling `xrootd_storage_credential <name>`
>   (stream); `runtime_server.c` resolves it at config time → bearer (inline `token`
>   or first line of `token_file`) → `xrootd_vfs_backend_set_credential()` → the
>   registry threads it into `sd_http` (new `cfg.bearer_token` ⇒ `Authorization:
>   Bearer` on every HEAD/GET). E2E `tests/run_credential_http_bearer.sh`: a
>   bearer-gated static-HTTP origin (401 otherwise) fills the cache only WITH the
>   credential (inline + token_file forms, multi-chunk), and a no-credential node is
>   correctly 401-rejected (negative control). **Deferred:** the X.509/GSI fields are
>   parsed + stored but consumed by **C-3** (sd_xroot in-process GSI); the
>   proxy/TPC/cache-origin consumers + the full `xrootd_credential_*` deprecation
>   shim (§14.5) and http/s3-scope parity are follow-ons. `sd_http` stays anonymous
>   when no credential is named (every existing config byte-identical).
> - **C-3 (token/ztn half) ✅ (2026-06-29).** `sd_xroot` now authenticates a
>   token-required root:// origin in-process via **XrdSecztn**. The origin client
>   bootstrap (`cache/origin_protocol.c`) learned that a `kXR_ok` login on an
>   authenticated origin still carries an auth advert (`body = sessid(16) +
>   "&P=ztn,..."`, vs the bare 16-byte sessid an anonymous origin sends) — so on a
>   `&P=`-bearing login (or `kXR_authmore`) it runs a single-round ztn `kXR_auth`
>   (credtype `"ztn\0"`, payload `"ztn\0"+JWT` — the exact format the native
>   `sec_token.c` sends and this server's `gsi/token.c` parses). The bearer reaches
>   the bootstrap through the §14 chain: `xrootd_storage_credential` → registry
>   `origin_token` → `xrootd_sd_xroot_create_origin(…, bearer, …)` → the synthetic
>   conf's `cache_origin_bearer`. E2E `tests/run_credential_xroot_ztn.sh`: a
>   token-auth origin (`xrootd_auth token` + JWKS) fills the cache only with the
>   credential (`make_token.py` JWT via `token_file`, multi-chunk), no-credential
>   node correctly rejected. Anonymous origins are byte-identical (the 16-byte-body
>   check skips the auth path). **Deferred:** the **GSI / X.509-proxy** half of C-3
>   (in-process signed-DH handshake — the hard piece) consumes the §14 `x509_*`
>   fields; TLS-to-origin trusted-CA wiring; and authenticated *write-back* (C-5 now
>   threads `cache_origin_bearer` into its dest, latent until a wt-origin credential
>   is configured).

This phase turns the storage plane into a **config-assembled middleware stack**:
any local *or* remote filesystem as the source, with a **generic read cache** and
a **generic write stage (write-back)** that compose in front of *any* backend. It
retires the bespoke **XCache** origin machinery — whose "fetch-from-a-remote-source"
and "write-back-to-a-remote-origin" functions are already (partly) reproduced by
the backend SD drivers — by re-pointing the cache's fill/flush at the *registered
source backend* and folding the duplicate stagers into one decorator.

> **This is not a green-field refactor.** Reading the code shows the migration is
> already **~60% done**: the cache's local store is an SD instance, two of the
> five fill paths already go driver→driver, the write-back already *reads* the
> dirty file through the driver, the registry already accepts `xroot` as a primary
> backend, and the write-back **replay shares the FRM journal-recovery scan**.
> This doc inventories exactly what remains, what each removal is *gated on*, the
> concrete decorator shape, the failure modes, the test matrix, and the order to
> land it.

**Builds on:** [`src/fs/README.md`](../../src/fs/README.md),
[`phase-55-storage-backend-abstraction.md`](phase-55-storage-backend-abstraction.md)
(the SD driver seam), [`phase-62-vfs-namespace-metadata-seam-closure.md`](phase-62-vfs-namespace-metadata-seam-closure.md)
(the VFS as the sole storage truth),
[`docs/09-developer-guide/pblock-metadata-performance.md`](../09-developer-guide/pblock-metadata-performance.md)
(the "measure the layering cost" caveat).

**Reading guide:** §0–§2 = the model + the exact current state (with file:line);
§3–§4 = the target + the change set; §5 = removals; §6 = data flows; §7–§13 =
enablers, risks, order, config-compat, tests, observability, failure modes; §14 =
config-name harmonization + the common upstream-credential block; appendices = the
vtable, the on-disk `.cinfo`, the file ledger.

---

## 0. The one-sentence model

> **The source filesystem, the read cache, and the write stage are all
> SD-driver-shaped middleware; an export resolves (in `vfs_backend_registry`) to a
> stack `source → [stage] → [cache] → VFS`, composed entirely from nginx config —
> so the cache and stage work in front of any backend (local or remote) and the
> XCache's private origin wire-client (`origin_connection`/`origin_protocol`/
> `origin_response`, 978 LOC) is deleted because the source backend *is* the
> generic way to reach a remote source.**

---

## 1. Vocabulary — the exact types everything below references

| Type (`src/fs/backend/sd.h`) | What it is |
|---|---|
| `xrootd_sd_driver_t` | the **30-slot** capability-typed vtable (full list in Appendix A) + a `caps` bitmap (Appendix A) |
| `xrootd_sd_instance_t` | a *bound* driver: `{driver, log, pool, state, root_canon}` — one per export per worker |
| `xrootd_sd_obj_t` | a per-open handle (`{inst, driver, fd, state, snap}`) from `driver->open`; `snap` carries size/mtime |
| `xrootd_sd_staged_t` | an in-progress atomic write from `driver->staged_open` (→ `staged_write` → `staged_commit`/`staged_abort`) |
| `xrootd_sd_stat_t` | protocol-neutral stat (`size`, `mtime`, `ctime`, `mode`, `ino`, `is_dir`, `is_reg`) |
| `xrootd_vfs_ctx_t` (`vfs.h`) | the per-op context: `{pool, log, proto, root_canon, cache_root_canon, sd, resolved, allow_write, cache_enabled, cache_writethrough, …}` |
| `xrootd_cache_fill_t` (`cache_internal.h`) | a heap-allocated **fill task** posted to the blocking pool: `clean_path`/`cache_path`/`part_path`/`lock_path`, `file_size`, `conf`, error fields |
| `xrootd_cache_sink_t` (`cache_internal.h`) | the **write target** of a fill/flush: a tagged union `{fd (POSIX pwrite) ‖ staged (driver `staged_write`) ‖ mem (buffer)}` |
| `xrootd_cache_cinfo_t` (`cinfo.h`) | the **on-disk cache-file state** — present-bitmap header + write-back state + validity (Appendix B) |

**Key fact #1 — the cache's *local store* is already an SD instance.**
`xrootd_cache_storage(conf)` (`cache_storage.c:210`) returns `conf->cache_storage_inst`,
an `xrootd_sd_instance_t`. Fills write into it via `driver->staged_open`/`staged_write`;
hits serve via `driver->pread`; eviction enumerates it via the driver
(`evict_policy.c:206`). The cache store is POSIX by default but already supports a
backend (`run_cache_pblock_pblock.sh` proves a pblock-backed cache store works). So
the *cache side* of the stack is already fully driver-abstracted.

---

## 2. Current state — what already routes through drivers, and what does not

### 2.1 The read hit/miss decision (`cache/open.c:139`)

`xrootd_cache_open(ctx, flags, &fh)` is the VFS hook called at `vfs_open.c:399`
**before** the bound driver. Its decision tree:

```
DECLINE (NGX_DECLINED) immediately if:
  • !ctx->cache_enabled  OR  cache_root_canon empty
  • flags & XROOTD_VFS_O_NOCACHE
  • flags & (WRITE | CREATE | TRUNC | APPEND)     ← cache is read-only serve
otherwise:
  inst = xrootd_cache_storage_by_root(cache_root_canon)     # the cache SD instance
  key  = cache_path - cache_root_canon                      # namespace key under cache_root
  if inst->driver->stat(inst, key, &sd_st) == ENOENT → DECLINE   # miss
  if !sd_st.is_reg → DECLINE
  validate against .meta sidecar (origin size/mtime freshness)
  serve: open via inst->driver->open(key, O_READ) → adopt as the VFS read handle
  return NGX_OK
```

`NGX_OK` = served from cache; `NGX_DECLINED` = miss → fall through to the bound
source driver / POSIX cascade; `NGX_ERROR` = hard error. **The hit-serve is already
100% driver-based** (`inst->driver->stat`/`open`/`pread`). The miss is where the
fill happens.

### 2.2 The miss fill (`fetch.c:600` dispatcher)

A miss schedules a fill task; `xrootd_cache_fetch_origin(t)` dispatches by
`conf->cache_origin_scheme`:

| Origin scheme | Fill mechanism | Driver-based? |
|---|---|---|
| `S3` | `fetch_origin_s3` → `sd_remote → sd_s3` driver→driver copy into the staged sink | **YES** |
| anonymous `root://` | `fetch_origin_xroot` → `sd_xroot_create` → `origin->driver->open/pread` → `cache_inst->driver->staged_open` | **YES** |
| `HTTP`/`HTTPS`/WebDAV | `xrootd_cache_http_download` (`http_transport.c`, libcurl) → `commit_part` | no — libcurl |
| `PELICAN` | `xrootd_cache_pelican_download` (`pelican.c` director 307 + libcurl) | no — libcurl |
| authenticated `root://` (`cache_origin_proxy`/`token_file` set) | `fetch_origin_exec` → **native-client subprocess** | no — exec, *because `sd_xroot` is anon-login-only* |

The driver-based exemplar already in the tree — `fetch_origin_xroot` (`fetch.c:475`),
abridged and annotated:

```c
origin = xrootd_sd_xroot_create(conf, log);                          /* remote source instance     */
src    = origin->driver->open(origin, t->clean_path,
                              XROOTD_SD_O_READ, 0, &e);               /* open over the wire          */
t->file_size = (uint64_t) src->snap.size;                            /* size from the open snapshot */
/* admission: xrootd_cache_admit(size/deny/allow/regex) — generic, unchanged     */
staged = cache_inst->driver->staged_open(cache_inst, key, 0644, &e); /* local atomic write          */
sink.staged = staged;                                                /* driver staged_write sink    */
for (off = 0; off < file_size; off += n) {                           /* driver→driver copy          */
    n = src->driver->pread(src, buf, want, off);
    xrootd_cache_sink_pwrite(&sink, buf, n, off);
}
/* commit_staged(t, cache_inst, ...) → staged_commit; verify (checksum-on-fill)  */
```

This is **exactly the generic shape** the whole cache should use for every source.
The only reasons it is not universal are **auth** (`sd_xroot` is anon-only,
`sd_xroot.c:6`) and **transport** (`http_transport`/`pelican` are libcurl, not a
driver). There are already tests for both driver-based origins:
`tests/run_cache_xroot_origin.sh` and `tests/run_cache_s3_origin.sh`.

### 2.3 The write-back (`writethrough_flush.c`, 1087 LOC)

Already **reads** the dirty local copy through the driver:

```c
o     = sd->driver->open(sd, key, XROOTD_SD_O_READ, 0, &derr);   /* :303 block-aware read   */
nread = obj->driver->pread(obj, buf, want, offset);             /* :353                    */
```

…but has **two** terminal sinks, only one driver-based:

- **origin wire client** — `xrootd_cache_origin_write_chunk` (`:365`) +
  `xrootd_cache_origin_truncate` (`:376`) → `origin_connection`/`origin_protocol`.
- **driver staged** — `si->driver->staged_open`/`staged_write` (`:615`/`:633`).

So write-back is *hybrid*: a driver-staged flush exists; a `root://` origin still
flushes through the bespoke wire client. **Replay** (`writethrough_replay.c`)
re-drives crashed flushes after startup **through the shared FRM journal-recovery
scan** (`#include "../fs/xfer/xfer_reconcile.h"`; master-side `frm_reconcile` resets
crashed `STAGING`→`QUEUED`). This already-shared journal is why FRM folds into the
generic stage (§5).

### 2.4 The `.cinfo` write-back state machine (the durability substrate)

`xrootd_cache_cinfo_t` (`cinfo.h`, full layout in Appendix B) is the per-cache-file
state. The write-back-relevant fields drive the state machine:

```
dirty_lo == dirty_hi              → CLEAN
dirty_lo <  dirty_hi              → DIRTY  (extent [lo,hi) needs write-back)
dirty_since                       → when this dirty episode began (reaper input)
flush_gen                         → bumped on each SUCCESSFUL write-back (monotonic)
last_flush / bytes_flushed        → stats / freshness
```

Plus validity (`size`/`mtime`/`etag`/`cks_*`) and a **present bitmap** (`nblocks`
bits at `block_size` granularity) for partial-file caching. This engine is already
**source-agnostic** — it records "what is dirty," not "where it flushes to." The
stale-dirty reaper (`cache_reap.c`, `cache_dirty_max_age`) bounds abandoned dirty
files. **Nothing here changes** when the flush target becomes a generic driver.

### 2.5 The fill concurrency model (thundering-herd safe, `lock.c`)

Concurrent misses for the same path are serialized by an **atomic O_EXCL filesystem
lock** (no `fcntl`):

```
two-phase poll (cache_lock_timeout, XROOTD_CACHE_LOCK_POLL_USEC intervals):
  phase 1: if cache file already present → serve it (someone else filled it)
  phase 2: try open(lock_path, O_CREAT|O_EXCL) → owner fills into part_path,
           renames part_path → cache_path atomically, unlinks lock_path
  neither within timeout → kXR_FileLocked
```

`part_path` = `cache_path + PART_SUFFIX` (in-progress), `lock_path` =
`cache_path + LOCK_SUFFIX`. This is **independent of the source** and survives the
migration unchanged — it guards the *local* fill, not the origin protocol.

### 2.6 The registry (`vfs_backend_registry.c`)

```c
typedef struct {
    char                  root_canon[PATH_MAX];
    char                  backend[16];   /* "pblock" | "xroot"  ← remote source already allowed */
    int64_t               block_size;
    void                 *srv_conf;       /* xroot: the srv conf the origin reads */
    xrootd_sd_instance_t *inst;           /* lazily built per worker, or NULL */
} xrootd_vfs_backend_entry_t;             /* xrootd_vfs_backends[64] */
```

Resolves **one** instance per `root_canon` (`xrootd_vfs_backend_resolve`). It does
**not** yet model a *stack* (source wrapped by cache/stage), and the cache's source
is configured **separately** via `xrootd_cache_origin*` rather than "wrap the
registered backend." That separation is the central structural gap.

### 2.7 The duplicate stagers

| File | LOC | Role |
|---|---|---|
| `cache/writethrough_{flush,decision,replay}.c` | 1087 + 124 + 126 | cache write-back (dirty `.cinfo` → flush, replay on restart via xfer_reconcile) |
| `fs/vfs_staged.c` | 244 | VFS wrapper over `driver->staged_*` for the upload paths |
| `fs/vfs_scratch.c` | 177 | materialize-to-scratch (stage object → local POSIX → VFS↔VFS move) |

…plus S3 multipart (`src/s3/multipart_*`) and the WebDAV/S3 PUT upload-stage dir.

---

## 3. Target architecture

```
source backend   posix | pblock | block | xroot | remote | s3 | rados | http
     ▲
  [ stage ]      write-back: writes land on stage_root, flush async via source->pwrite/staged_commit
     ▲
  [ read cache ] miss → source->open/pread; store slice on cache_root; cinfo/admit/evict/verify
     ▲
   VFS  (src/fs/)  →  every protocol (root:// / WebDAV / S3 / CMS) UNCHANGED
```

### 3.1 The decorator contract (concrete)

A `cache(source)` / `stage(source)` decorator is an `xrootd_sd_instance_t` whose
`driver` slots delegate to a wrapped `source` and interpose the cache/stage logic.
Sketch of the **read-cache** decorator instance state + the two hot slots:

```c
/* inst->state for the cache decorator */
typedef struct {
    xrootd_sd_instance_t *source;       /* the wrapped backend (posix/xroot/s3/...) */
    xrootd_sd_instance_t *store;        /* the local cache store (== conf->cache_storage_inst) */
    xrootd_cache_policy_t  policy;      /* admit/evict/verify/watermark config */
} sd_cache_state_t;

static xrootd_sd_obj_t *
sd_cache_open(xrootd_sd_instance_t *inst, const char *path, int fl, mode_t m, int *e)
{
    sd_cache_state_t *cs = inst->state;
    if (fl & XROOTD_SD_O_WRITE)          /* writes bypass the read cache */
        return cs->source->driver->open(cs->source, path, fl, m, e);
    if (store_has_fresh(cs, path))       /* hit: serve from the local store */
        return cs->store->driver->open(cs->store, key_of(path), XROOTD_SD_O_READ, 0, e);
    fill_from_source(cs, path);          /* miss: source->open/pread → store staged_* */
    return cs->store->driver->open(cs->store, key_of(path), XROOTD_SD_O_READ, 0, e);
}

static ssize_t
sd_cache_pread(xrootd_sd_obj_t *o, void *buf, size_t n, off_t off)
{   /* o is a store-backed read handle after open; present-bitmap gates range-fill */
    return o->driver->pread(o, buf, n, off);
}
```

`caps` of the decorator = the wrapped backend's caps **minus what the layer cannot
honor** (e.g. drop `SENDFILE` unless the store can serve block-0 from a local fd —
see Risk #6). The **stage** decorator is symmetric on the write side: `open(O_WRITE)`
returns a store-backed staged handle; `pwrite` lands locally + marks the `.cinfo`
dirty extent; a background flush drives `source->pwrite`/`staged_commit` per
`xrootd_wt_default_decide`.

Because the VFS dispatch (`xrootd_vfs_ctx_driver`) is already driver-shaped, a
decorator instance slots in with **zero handler changes**. (Interim option: keep the
cache as the `vfs_open` hook and only swap its *source* per C-1; converge to the
decorator for full uniformity in C-2.)

### 3.2 Registry composition (the algorithm)

`xrootd_vfs_backend_resolve(root_canon)` becomes a **stack builder**:

```
e = lookup(root_canon)
if e->inst != NULL: return e->inst                 # per-worker memoized top-of-stack
src = build_source(e)                              # posix|pblock|xroot|s3|http...
top = src
if e->stage_enabled: top = wrap_stage(top, e->stage_root, e->stage_policy)
if e->cache_enabled: top = wrap_cache(top, e->cache_root, e->cache_policy)
e->inst = top                                       # memoize
return top
```

Ordering rationale: **cache is outermost** (a read hit must short-circuit before the
stage/source); **stage sits between cache and source** (a write lands in the stage,
which later flushes to source; a subsequent read can be served from cache or the
still-dirty stage). The directive handlers populate `e->{cache,stage}_*`; the stack
is built **lazily per worker** (same copy-on-write-after-fork discipline the entry
already uses).

### 3.3 Config grammar (current → proposed)

Current cache directives (`cache/directives.c`): `xrootd_cache_origin addr:port`,
`xrootd_cache_eviction_threshold`, `xrootd_cache_max_file_size`,
`xrootd_cache_include_regex`, `xrootd_cache_verify`/`_verify_digest`,
`xrootd_cache_deny_prefix`/`_allow_prefix`, plus scheme/proxy/token fields and the
watermark knobs (`cache_high_watermark`, `cache_dirty_max_age`).

Proposed — the source moves to the backend selector; the cache stops naming its own
origin (full old→new map in §10):

```nginx
xrootd_storage_backend  xroot://origin:1094/data;   # any source; already accepts xroot
xrootd_cache  on;  xrootd_cache_root /ssd/cache;     # generic read cache over the source
  xrootd_cache_eviction_threshold 90;  xrootd_cache_max_file_size 50g;  xrootd_cache_verify on;
xrootd_stage  on;  xrootd_stage_root /nvme/stage;    # generic write-back over the source
  xrootd_stage_flush async;                           # xrootd_wt_default_decide policy
```

---

## 4. Changes required (file-by-file, with the blocker each removal waits on)

### C-1 — Cache fills from the *registered source backend*, not `cache_origin_*`
**Files:** `cache/{open,fetch,slice_fill,thread}.c`, `vfs_backend_registry.*`.
Generalize `xrootd_cache_fetch_origin` to the `fetch_origin_xroot` shape for **every**
backend (`open`→`pread`→staged sink), with the source = the export's registered
`sd_instance`. The per-scheme branch becomes "ask the bound source driver." Store,
admission, `.cinfo`, eviction, verify, the O_EXCL fill lock — all untouched. *The
spine.*

### C-2 — Registry composes a STACK  ✅ IMPLEMENTED (2026-06-29)
**Files:** `vfs_backend_registry.c`. `xrootd_vfs_backend_entry_build` is now the single
composition point: `build_source(e)` makes the raw source (xroot/http/pblock), then it
wraps it in the C-6 stage decorator when `e->staging` is set and the source can stage;
the composed top is memoized as `e->inst`. `resolve` returns it. (A read cache stays the
`vfs_open` hook per the interim option — the cache already reaches every protocol via
`xrootd_cache_open`, so no decorator is needed there for capability.) Verified by all
staging + remote-backend tests.

### C-3 — `sd_xroot` gains GSI/token auth  ✅ COMPLETE (2026-06-29)
**Token (ztn):** the origin client bootstrap presents the §14 bearer via XrdSecztn on
an authenticated login (`cache/origin_protocol.c`, `xrootd_cache_origin_auth_ztn`).
**GSI (X.509):** `xrootd_cache_origin_auth_gsi` runs the two-round XrdSecgsi handshake
IN-PROCESS — round-1 `kXGC_certreq` (`xrootd_gsi_build_certreq`) → server `kXGS_cert`
→ round-2 `kXGC_cert` (`xrootd_gsi_build_cert_response` with the proxy chain + key) →
`kXR_ok`. The DH/cipher/proof-of-possession math is the **shared `gsi_core` kernel**
(the same `client/lib/sec/sec_gsi.c` and `src/tpc/gsi_outbound_exchange.c` drive), so
no XrdCl/subprocess and no parallel crypto. The proxy PEM path threads through the §14
credential (`x509_proxy`) → registry `origin_x509_proxy` →
`xrootd_sd_xroot_create_origin(…, x509_proxy, …)` → the synthetic conf's
`cache_origin_x509_proxy`. The login-advert dispatch picks ztn (bearer set) or gsi
(proxy set) from the `&P=…` block. E2E `run_credential_xroot_ztn.sh` +
`run_credential_xroot_gsi.sh` (CA-signed PKI via `pki_helpers.blitz_test_pki`,
byte-exact + multi-chunk + negative control). **MITM hardening ✅ (2026-06-29):** the
credential's `ca_dir` threads through to the synthetic conf's `gsi_store`
(`xrootd_build_ca_store`), and `auth_gsi` now REQUIRES the origin's server cert
(kXRS_x509 bucket) to be present AND verify against it (`X509_verify_cert`, proxy
certs allowed) before agreeing a shared secret — absent/invalid cert ⇒
kXR_NotAuthorized. No `ca_dir` = the operator opted out (unverified origin). The MITM
negative (`ca_dir` = wrong/empty CA ⇒ fill refused) is covered in the GSI test.

**Original design note (now satisfied):**

**Files:** `backend/xroot/sd_xroot.c` (today *"Anonymous login only"*, line 6),
reusing `src/gsi` (X.509 proxy) and `src/token` (bearer) rather than reimplementing.
The credential source is the backend's referenced **`xrootd_credential` block (§14)**
— `build_source(e)` hands `sd_xroot` the resolved `xrootd_credential_t`, replacing
`cache_origin_proxy`/`token_file`. *Unlocks deleting `fetch_origin_exec` (the
subprocess) and — with C-5 — authenticated write-back; and (with §14) one credential
vocabulary shared with the proxy/TPC upstream paths.*

### C-4 — `http` source driver  ✅ IMPLEMENTED (2026-06-29)
**Files:** new `backend/http/sd_http.c` (read-only: `open`/`stat` HEAD for size,
`pread` Range GET over the shared `xrootd_s3_origin_curl_transport`; CAP_RANGE_READ
only; memory-served, no fd); registry wiring in `vfs_backend_registry.c`
(`config_http` + `http(s)://host[:port]/base` parse + the `entry_build` `http`
branch); C-1 trigger + cache config gate accept an `http` source. A 200 reply to a
ranged GET (origin ignored `Range:`) is sliced at `off` so the fill loop terminates.
E2E `tests/run_cache_http_source.sh`. **Still TODO** (deferred, not blocking): fold
`cache/http_transport.c` away, and relocate `cache/pelican.c` (director 307-discovery
as `open`-time resolution) + `pelican_register.c` (advertise hook) behind this driver.
*Unlocks deleting the cache-private libcurl.*

### C-5 — Write-back via `source->pwrite`/`staged_commit`  ✅ IMPLEMENTED (2026-06-29)
**Files:** `cache/writethrough_flush.c` — `xrootd_wt_run_flush` now builds a per-flush
`sd_xroot` instance (`xrootd_sd_xroot_create_origin`) and writes via
`dest->driver->{open(O_WRITE),pwrite,ftruncate,fsync}` (`xrootd_wt_copy_body_driver`),
replacing the inline `origin_connect_addr`/`bootstrap`/`open_write` + the deleted
`xrootd_wt_copy_body`. Sync + async, anonymous origin (the GSI/proxy origin keeps the
`xrdcp` exec path). The replay/journal (`writethrough_replay.c` + `xfer_reconcile`) is
source-agnostic and untouched. E2E `tests/run_cache_wt_driver.sh`. **Still TODO**
(deferred): authenticated write-back (needs C-3), a non-`xroot` writable `remote`
backend, and the literal removal of `origin_connection`/`protocol`/`response`
(978 LOC) — those wire helpers are still shared by `sd_xroot`; deletion is their
relocation under `backend/xroot/` once the legacy `cache_origin` fill is migrated too.

### C-6 — One generic `stage` decorator  ✅ IMPLEMENTED (2026-06-29)
**Files:** new `src/fs/backend/stage/sd_stage.{c,h}` — the write-back stage decorator.
It wraps a source: every namespace/xattr/dir/open op forwards to it (open returns the
source's own object, so read byte-I/O bypasses the decorator), and `staged_open/write/
commit/abort` implement local-temp → promote-to-source (the former `vfs_staged.c` Mode-B
`xrootd_vfs_staged_promote`, now living here). `vfs_staged.c` is reduced to a pure Mode-A
pass-through (delegates to the resolved instance's `staged_*`); Mode B + the inline
promote are deleted. The registry (C-2) composes it when staging is configured, so there
is now ONE write-back stager in front of any writable source. E2E: `run_remote_backend_staging`,
`run_remote_backend_webdav`, `run_pblock_writethrough` all green. **Note:** `vfs_scratch.c` +
`cache/writethrough_*` were NOT folded in — they serve distinct domains (FRM scratch / the
root:// write-through-cache flush) and consolidating them is a separate, lower-value pass.

**Original design note:**
**Files:** fold `fs/vfs_staged.c` + `fs/vfs_scratch.c` + `cache/writethrough_*` over
the `xrootd_cache_sink_t` + the `.cinfo` engine; keep `xrootd_wt_default_decide`
(`writethrough_decision.c:21`, already fail-closed) as the async/deny policy. S3
multipart stays backend-specific (it *is* the S3 commit protocol); the upload-stage
dir folds in. *Unlocks removal of two parallel stagers; one durability/replay story.*

### C-7 — Redirect the XCache API/admin/metrics  ✅ IMPLEMENTED (2026-06-29, core)
**Files:** `vfs_backend_registry.{c,h}` (read-only introspection:
`xrootd_vfs_backend_export_count` + `_export_info` → `xrootd_vfs_backend_info_t`),
`metrics/writer.c` (`xrootd_storage_backend_metrics_emit`), `metrics/handler.c`,
`metrics/metrics_internal.h`. `/metrics` now emits one `xrootd_storage_backend_info{
export,backend,origin,auth,staging} 1` gauge per export — the composed stack is
observable (source backend, origin host:port[+tls], the §14 auth method, and whether
the stage decorator is composed). E2E `run_storage_backend_metrics.sh`. **Deferred (low
value / risky):** removing the legacy `cache_origin_*` host/port/proxy/token directives
(a deprecation shim, not an additive change) and the "fold upstream/proxy/frm" stretch.

---

## 5. What can be almost completely removed or consolidated (LOC + gate)

| Component | LOC | Verdict | Gated on | Why redundant |
|---|---|---|---|---|
| `cache/origin_connection.c` + `origin_protocol.c` + `origin_response.c` | **978** | **Remove** | C-1, C-3, C-4, C-5 | The cache's private XRootD wire client — reproduced by `sd_xroot`/`sd_remote` once fills/flush go via the driver. **Headline deletion.** |
| `cache/http_transport.c` + `pelican.c` + `pelican_register.c` | — | **Relocate** | C-4 | Becomes `backend/http`; director discovery + register are remote-backend concerns. |
| `cache/fetch_origin_exec` (native-client subprocess fill) | — | **Remove** | C-3 | Exists only because `sd_xroot` is anon-only. |
| `fs/vfs_staged.c` + `fs/vfs_scratch.c` + cache `writethrough_*` | 244 + 177 + 1337 | **Consolidate → one** | C-6 | Three parallel stage-then-commit impls → one decorator over the shared sink + `.cinfo`. |
| `src/upstream/` | 1463 | **Mostly removable** | C-2, C-4 | The HTTP/WebDAV "proxy to an upstream" connection layer = an `http` remote backend + cache decorator; only a pure non-caching pass-through still wants it. |
| `src/proxy/` | 4501 | **Partially removable** | C-2, C-3 | The cache/forward-in-front-of-upstream role = `xroot` backend + cache decorator. **Residual stays:** see §5.1. |
| `src/frm/` | 3234 | **Folds into a backend + stage** | C-6 | FRM tape staging = a `tape`/`hsm` **source backend** (its durable queue is the commit); it **already shares `xfer_reconcile`** with the cache replay. The WLCG Tape REST *API surface* stays. |

### 5.1 Deep dive — what *stays* in the "removable" subsystems
- **`src/proxy/` (4501 LOC):** the **zero-copy splice pure-relay** (`events_splice.c`,
  the `socket→pipe→socket` no-store forward) is **not** storage and is **not**
  reproduced by the cache — keep it, or model it explicitly as a "no-store cache"
  mode of the cache decorator. The **redirect/forward request rewriting**
  (`forward_*`) for manager/redirector topologies is protocol routing, not storage —
  keep. Only the "fetch-from-upstream-and-serve" role overlaps the `xroot` backend.
- **`src/upstream/` (1463 LOC):** the WebDAV/HTTP upstream proxy connection +
  auth/tls (`auth.c`/`tls.c`/`request.c`/`response.c`) is reproduced by `sd_http` +
  cache for the *caching* case; a pure transparent reverse-proxy without caching
  would still want it. Verdict "mostly," not "fully."
- **`src/frm/` (3234 LOC):** the **durable queue + journal** (`queue.c`,
  `xfer_reconcile`) is the commit mechanism of a tape/HSM backend, and the cache
  replay **already depends on it** — so FRM becomes the `tape` source backend's
  internals + the generic stage. The **WLCG Tape REST API** handlers stay (an API
  surface, not storage).

---

## 6. Data-flow walkthroughs (before → after)

### 6.1 Cached read miss of `/data/f` against an authenticated `root://` origin
**Before:** `cache_open` DECLINE → fill task → O_EXCL lock → `fetch_origin_exec`
forks the native client (auth from env) → writes `part_path` → rename →
`commit_part` → serve. *(Subprocess + bespoke origin code.)*
**After (C-1/C-3):** `cache_open` DECLINE → fill task → O_EXCL lock → source =
registered credentialed `sd_xroot` → `source->open(O_READ)` → `source->pread` loop →
`store->staged_open`/`staged_write` → `staged_commit` → rename → serve. *(All
in-process, all vtable.)*

### 6.2 Write-back of a dirty cached file to the origin
**Before:** `writethrough_flush` reads local via `driver->pread`, writes origin via
`origin_write_chunk` + `_truncate` (wire client); `flush_gen++` on success.
**After (C-5):** same driver read; write via `source->pwrite`/`ftruncate`/`fsync`
(or `staged_open`→`staged_write`→`staged_commit` for atomic-publish backends like
S3); `flush_gen++` unchanged. `origin_*` gone.

### 6.3 Crash mid-flush, then restart (durability)
**Unchanged by this phase:** at worker startup `writethrough_replay` runs the shared
`xfer_reconcile` scan (master `frm_reconcile` resets `STAGING`→`QUEUED`), re-drives
the dirty `.cinfo` files; the stale-dirty reaper bounds anything abandoned past
`cache_dirty_max_age`. The flush *target* is now a driver, but the recovery path is
the same journal — which is exactly why FRM and the stage unify.

### 6.4 Local POSIX export, no cache (the default)
`cache_open` returns DECLINE (cache disabled) → POSIX confinement cascade. The stack
is `source(posix)` only; decorators absent; zero overhead.

---

## 7. Enablers already in place (why this is tractable, with evidence)

- VFS is the **sole storage seam** for every protocol (phase-62) — nothing above the
  registry changes when a decorator is inserted.
- The cache is **already a VFS-layer hook** (`vfs_open.c:399` → `xrootd_cache_open`).
- The cache **local store is already an SD instance** (`conf->cache_storage_inst`);
  a pblock-backed cache store is already tested (`run_cache_pblock_pblock.sh`).
- **Two fill paths already go driver→driver** (`fetch_origin_s3`,
  `fetch_origin_xroot`), each with a test (`run_cache_s3_origin.sh`,
  `run_cache_xroot_origin.sh`).
- The **write sink is already abstracted** (`xrootd_cache_sink_t`: `fd`/`staged`/`mem`).
- The **registry already accepts `xroot`** as a primary backend.
- The **`.cinfo` write-back engine** (present-bitmap + dirty extent + `flush_gen` +
  reaper) is generic and source-agnostic.
- The **replay path already shares the FRM journal** (`xfer_reconcile`).
- `sd_xroot` already has read **and** write data slots — only auth is missing.

---

## 8. Risks & caveats

1. **Layering is not free.** A remote-backend fill *through* the cache carries the
   driver-dispatch + slice-store overhead the hardwired origin client inlines. Per
   the pblock perf work, **A/B the composed stack** (`xroot+cache` vs old XCache) and
   keep that benchmark.
2. **Pure pass-through must survive.** The splice relay in `src/proxy/` is a no-store
   role the cache does not cover; keep it or model it as a "no-store cache."
3. **Durability of the generic stage.** The stage inherits the write-back
   crash-consistency contract (`flush_gen` replay + reaper). Any source used as a
   stage target must surface real commit failures so a lost flush is retried/bounded;
   `xrootd_wt_default_decide` is already fail-closed — keep that.
4. **Confinement boundaries differ per layer.** Export-confined VFS open
   (`RESOLVE_BENEATH`) applies to local roots; a remote source is confined by the
   *remote* server. `cache_root`/`stage_root` stay local; the source does not.
5. **Auth surface for `sd_xroot` (C-3).** Credentialed in-process login pulls GSI/
   token handling into the data path; reuse `src/gsi`/`src/token`, keep the anon path.
6. **Capability honesty.** A read cache over a remote source must **not** advertise
   `SENDFILE` unless the store can serve block-0 from a local fd, or the VFS sendfile
   gate mis-routes. The decorator's `caps` must reflect reality (Appendix A).
7. **Cache-key vs namespace collisions.** The cache stores by a namespace key under
   `cache_root` (`open.c`: `key = cache_path - cache_root_canon`). A driver-backed
   store (pblock cache) must key identically to the POSIX store, or hits miss.
8. **Validity across sources.** `.cinfo` validity is `size`/`mtime`/`etag`/`cks`.
   Different source backends expose different freshness signals (S3 etag vs POSIX
   mtime vs root:// checksum) — the decorator must pick the strongest the source
   offers and record it, or stale serves leak.

---

## 9. Migration order (dependency-ordered; each step independently shippable)

| Step | Change | Exit criteria | Unlocks |
|---|---|---|---|
| 1 | **C-1 ✅ DONE** — cache fills from the bound driver (gated on a remote `xroot` source + no `cache_origin`); `cache_origin_*` unchanged | `xroot+cache` serves a miss in-process (`run_cache_backend_source.sh`); legacy paths green | the spine |
| 2 | **C-3** — `sd_xroot` GSI/token auth | authenticated `root://` origin fills in-process | delete `fetch_origin_exec` |
| 3 | **C-4** — `http` source driver (relocate transport/pelican) | HTTP/Pelican fill via the driver | delete cache-private libcurl |
| 4 | **C-5** — write-back via `source->pwrite`/`staged_commit` | dirty flush uses the driver; replay still green | **delete `origin_connection`/`protocol`/`response` (978 LOC)** |
| 5 | **C-2** — registry composes `cache(source)`/`stage(source)`; flip defaults | `xrootd_cache on; xrootd_stage on;` compose over any `xrootd_storage_backend` | cache/stage in front of any backend |
| 6 | **C-6** — one generic stage decorator | `vfs_staged`/`vfs_scratch`/`writethrough` consolidated; replay green | delete two stagers |
| 7 | **C-7** — redirect XCache API/admin/metrics | dashboard/metrics read decorator state; origin config removed | XCache framing gone |
| 8 | **Fold `upstream`/`proxy` caching roles, then `frm`** | pure-relay isolated; FRM = `tape` backend + Tape REST shim | subsystem shrink |

---

## 10. Backward-compat / config migration

| Old directive | New | Note |
|---|---|---|
| `xrootd_cache_origin host:port` (root://) | `xrootd_storage_backend xroot://host:port/...` | source is the backend |
| `cache_origin_scheme http(s)` | `xrootd_storage_backend http(s)://...` | via `sd_http` |
| `cache_origin_scheme pelican` | `xrootd_storage_backend pelican://...` | `sd_http` + director discovery |
| `cache_origin_scheme s3` | `xrootd_storage_backend s3://...` | via `sd_s3` (already) |
| `cache_origin_proxy` / `cache_origin_token_file` / `_forward_token` / `_cadir` / `_tls` | a named `xrootd_credential` block referenced as `credential=<name>` on the backend | needs C-3; full scheme + the cross-subsystem unification in **§14** |
| `xrootd_proxy_upstream_*` / `xrootd_webdav_proxy_certs` / `xrootd_mirror_token` (upstream identity) | the same `xrootd_credential` block (an upstream is a non-caching source) | §14 — one credential vocabulary for every upstream |
| `xrootd_wt_*` (write-through knobs) | `xrootd_stage_*` | naming harmonized in §14.2 |
| `xrootd_cache_root / _eviction_threshold / _max_file_size / _verify / _include_regex / _deny_prefix / _allow_prefix / cache_high_watermark / cache_dirty_max_age` | **unchanged** | generic cache policy, source-independent |
| (write-through implied by cache) | `xrootd_stage on; xrootd_stage_root …` | explicit stage decorator |

A compatibility shim can keep `xrootd_cache_origin` parsing for one release,
translating it to the equivalent `xrootd_storage_backend` + `xrootd_cache on`.

---

## 11. Test matrix (existing → what each step adds)

Existing cache tests (reuse as regression oracles): `run_cache_xroot_origin.sh`,
`run_cache_s3_origin.sh`, `run_cache_pblock_{pblock,posix}.sh`,
`run_cache_watermark{,_config}.sh`, `run_cache_reaper.sh`,
`run_cache_stage_throttle.sh`, `test_cache_write_through.py`,
`test_cache_reap_metrics.py`, `test_http_cache_hit.py`, `test_slice_cache.py`,
`test_webdav_auth_cache.py`, `run_cinfo_tests` (81 checks), `run_cache_admit_tests`
(11).

| Step | New / extended test |
|---|---|
| C-1 | `run_cache_xroot_origin.sh` passes with fill-from-bound-driver flag on; byte-exact hit vs origin |
| C-3 | new `run_cache_xroot_origin_gsi.sh` (authenticated origin fills in-process; no subprocess) |
| C-4 | extend `test_http_cache_hit.py` to assert the `sd_http` driver path (no libcurl-in-cache) |
| C-5 | `test_cache_write_through.py` byte-exact flush via driver; crash-mid-flush replay still recovers |
| C-2 | new `run_cache_compose.sh` — `xrootd_storage_backend xroot + cache + stage` end-to-end |
| C-6 | upload paths (`run_pblock_root.sh`, S3 multipart, WebDAV PUT) green on the unified stage |
| C-7 | dashboard/metrics assertions read decorator state; `/healthz` cache fields intact |

Plus the perf oracle from §8.1: `xroot+cache` ops/throughput vs the retired XCache.

---

## 12. Observability surface (must be preserved across the move)

Existing metrics (`src/metrics`, `src/cache`) that the decorator must keep emitting:
`cache_fill` / `cache_fill_done`, `cache_evictions_total`, `cache_evicted_bytes_total`,
`cache_eviction_errors_total`, `cache_eviction_threshold_ratio`,
`cache_dirty_reaped_total`, plus the `.cinfo` stats (`access_count`, `bytes_served`,
`last_access`, `flush_gen`, `bytes_flushed`). The decorator emits these from the same
points (fill start/done, evict, flush) regardless of source — they describe the
*cache*, not the origin, so they survive the re-point unchanged.

---

## 13. Failure modes & edge cases (must hold post-refactor)

1. **Source down on miss** → fill fails → serve the client an origin-mapped error
   (`xrootd_cache_set_error(kXR_*)`); do **not** poison the cache with a partial file
   (the `part_path`→`cache_path` rename is the commit barrier; a failed fill leaves
   only `part_path`, GC'd by the reaper).
2. **Eviction races a fill** → the O_EXCL lock + `part_path` staging means eviction
   only ever removes *committed* `cache_path` files; an in-flight `part_path` is not
   an eviction candidate.
3. **Reload** → standard nginx drain; the per-worker `inst` (stack top) is rebuilt on
   the new config; in-flight fills finish on the old worker.
4. **Dirty flush fails repeatedly** → `flush_gen` does not advance; `dirty_since`
   ages; the stale-dirty reaper bounds the file at `cache_dirty_max_age` (WARN); the
   replay journal retries on restart. Never a silent loss.
5. **Capability mismatch** (e.g. stage over a read-only `remote`) → the registry
   **rejects** `xrootd_stage on` at config time (the source lacks `pwrite`/
   `staged_commit`), failing fast rather than at first write.
6. **Mixed validity signals** → if a source offers no strong freshness signal, the
   decorator must treat the cache as **revalidate-always** or **TTL-bounded**, never
   "trust forever" (Risk #8).

---

## 14. Config harmonization + a common upstream-credential block

> **Status: token slice ✅ IMPLEMENTED (2026-06-29).** The `xrootd_credential` block,
> the named registry, the `xrootd_storage_credential` reference, and the **bearer**
> threading into `sd_http` are done + tested (`tests/run_credential_http_bearer.sh`).
> The X.509/GSI fields parse + store but are consumed by C-3; the proxy/TPC/cache-origin
> migration and the `_*` deprecation shim (§14.5) remain. **http-scope parity ✅
> (2026-06-29):** `xrootd_credential` + `xrootd_webdav_storage_credential` registered
> at NGX_HTTP scope (`src/webdav/`), sharing the process-wide credential registry —
> a WebDAV export over a token-auth root:// origin authenticates via sd_xroot ztn
> (`tests/run_credential_webdav_xroot.sh`). **S3-scope parity ✅ (2026-06-29):**
> `xrootd_s3_storage_backend` + `xrootd_s3_storage_credential` (`src/s3/module.c`)
> give an **S3 export a composable source backend** — S3 GetObject (which already
> goes through `xrootd_vfs_open`) now serves from a remote root:///http source via
> the same VFS path, anonymous or ztn-authenticated
> (`tests/run_s3_storage_backend.sh`). The S3 export was POSIX-only before this.

Once *any* backend can be a source / cache / stage, two cross-cutting cleanups
become both possible and necessary: the config surface must read **uniformly**, and
the answer to **"how do I authenticate to an upstream?"** must be written **once**
and reused by every consumer that opens an upstream connection (source fill,
write-back flush, a direct serve, the stream/WebDAV proxy, TPC). Today the same
concepts are spelled five different ways.

### 14.1 The fragmentation today

Upstream-identity / credential config is spread across four unrelated families that
each reinvent the same X.509-proxy + CA + bearer-token vocabulary:

| Consumer | Directives today |
|---|---|
| Cache origin fill / write-back | `xrootd_cache_origin_proxy`, `_token_file`, `_forward_token`, `_cadir`, `_tls`, `_client` |
| Stream proxy upstream | `xrootd_proxy_upstream`, `_upstream_tls`, `_upstream_tls_ca`, `_upstream_tls_name`, `xrootd_proxy_login_user`, `xrootd_proxy_auth` |
| WebDAV proxy / TPC | `xrootd_webdav_proxy_upstream`, `_proxy_certs`, `_proxy_auth`, `xrootd_mirror_token`, `_mirror_strip_auth` |
| (future) `sd_xroot` auth (C-3) | — (currently *anonymous login only*) |

Same concepts, five spellings. A site that fronts an authenticated `root://` origin
with a cache **and** proxies a WebDAV upstream configures the *same* grid proxy
twice, in two different grammars.

### 14.2 Principle: prefix = subsystem, suffix = role

| Prefix | Owns | Examples |
|---|---|---|
| `xrootd_storage_*` | the backend / the composed stack | `xrootd_storage_backend`, `xrootd_storage_staging` |
| `xrootd_cache_*` | read-cache **policy** (source-independent) | `xrootd_cache_root`, `_eviction_threshold`, `_max_file_size`, `_verify` |
| `xrootd_stage_*` | write-back **policy** | `xrootd_stage`, `xrootd_stage_root`, `xrootd_stage_flush` |
| `xrootd_credential` | a **named, reusable** identity used to reach an upstream | (block, §14.3) |

Suffix conventions, applied everywhere: `_root` = a local (confined) directory; a
bare flag = on/off; `_<noun>` = a policy scalar. With this scheme the deprecated
families collapse cleanly:

- `xrootd_cache_origin_*` *(the origin **address**)* → `xrootd_storage_backend <url>` (§10).
- `xrootd_cache_origin_{proxy,token_file,forward_token,cadir,tls}` *(the origin
  **credential**)* → a `credential=<name>` reference (§14.3).
- `xrootd_wt_*` *(write-through knobs)* → `xrootd_stage_*`.
- `xrootd_proxy_upstream*` / `xrootd_webdav_proxy_*` credential bits → the same
  `credential=<name>` — an upstream is just a **non-caching source**.

### 14.3 The common upstream-credential block

A `xrootd_credential <name> { … }` block declares **once** how this server proves
its identity to (and verifies) an upstream, and is referenced by any consumer that
opens an upstream connection:

```nginx
# main/http/stream scope — declared once, referenced anywhere
xrootd_credential grid {
    x509_proxy     /etc/grid-security/x509up;          # a ready VOMS proxy, OR:
    # x509_cert    /etc/grid-security/hostcert.pem;
    # x509_key     /etc/grid-security/hostkey.pem;
    ca_dir         /etc/grid-security/certificates;     # verify the upstream
    # token        "eyJ…";   OR
    token_file     /run/secrets/origin.tok;             # bearer (WLCG / SciToken)
    token_forward  off;                                 # on = delegate the CLIENT's token
    tls            on;                                  # roots:// / https
    # vo           atlas:/atlas/Role=production;        # optional VOMS FQAN
}

xrootd_credential pub { }                               # anonymous (explicit; the default)

# the SOURCE backend names its credential — this is what drives sd_xroot C-3 auth:
xrootd_storage_backend  roots://origin:1094/data  credential=grid;
#   → the cache fill, the write-back flush, and a direct serve ALL inherit it.

# the SAME credential reaches a proxied / TPC upstream (the upstream is a source):
xrootd_proxy_upstream   roots://peer:1094  credential=grid;
```

**Resolution & precedence.** A consumer's credential is, in order: the explicit
`credential=<name>` on its own directive → the enclosing scope's
`xrootd_credential default { … }` → anonymous (`pub`). `token_forward on` makes the
upstream identity the **client's** delegated token (the gateway impersonates the
caller) instead of the server's own — the existing `cache_origin_forward_token`
semantic, generalized to every upstream.

**What it unifies (replaces):**

| Old | New |
|---|---|
| `xrootd_cache_origin_proxy /p` | `xrootd_credential c { x509_proxy /p; }` + `credential=c` |
| `xrootd_cache_origin_token_file /t` | `… { token_file /t; }` |
| `xrootd_cache_origin_forward_token on` | `… { token_forward on; }` |
| `xrootd_cache_origin_cadir /d` + `_tls on` | `… { ca_dir /d; tls on; }` |
| `xrootd_proxy_upstream_tls_ca /d` / `_tls_name n` | `… { ca_dir /d; }` (SNI from the URL) |
| `xrootd_webdav_proxy_certs on` / `xrootd_mirror_token …` | `credential=<name>` on the upstream |

### 14.4 How it threads the stack (implementation note)

The block parses into a small POD `xrootd_credential_t`
(`{x509_proxy, x509_cert, x509_key, ca_dir, token, token_file, forward, tls, vo}`)
**interned by name on the cycle pool**. The registry entry (§2.6) gains a
`credential` pointer; **`build_source(e)`** hands it to the source driver's create —
so **C-3** `sd_xroot` reads its GSI/token from there rather than from
`cache_origin_*`, and the `http`/`s3` sources read their bearer/SigV4 the same way.
Because the cache/stage decorators (§3.1) wrap that *same* source instance, the
fill, the write-back, and a direct serve all use one credential with **no extra
config** — the point being that **identity is a property of the source, not of each
subsystem that happens to reach it**. The proxy/TPC paths take the *same*
`xrootd_credential_t`, so `src/gsi` (X.509 proxy) and `src/token` (bearer) are the
**single** implementation — the §5 consolidation extends to credentials, deleting
the duplicated proxy/token plumbing across `cache` / `proxy` / `webdav`.

### 14.5 Migration

`xrootd_credential` is **purely additive**: the old `cache_origin_*` /
`proxy_upstream_*` / `webdav_proxy_*` credential directives keep working for one
release via the same compatibility shim as §10, which synthesizes an
anonymous-plus-overrides credential per subsystem. `nginx -t` WARNs on a deprecated
credential directive and prints the `xrootd_credential` equivalent. This change is
config-grammar only — it rides on the C-2/C-3 plumbing and adds no new data path.

---

## Appendix A — The SD vtable (all 30 slots) + caps

**Slots** (`src/fs/backend/sd.h`): `init`, `cleanup` · `open`, `close` · `pread`,
`pwrite`, `preadv`, `preadv2`, `copy_range`, `read_sendfile_fd`, `ftruncate`,
`fsync`, `fstat` · `stat`, `unlink`, `mkdir`, `rename`, `server_copy`, `setattr` ·
`opendir`, `readdir`, `closedir` · `getxattr`, `listxattr`, `setxattr`,
`removexattr` · `staged_open`, `staged_write`, `staged_commit`, `staged_abort`.

A **read-cache** decorator needs of its source: `open`, `pread`/`preadv`, `stat`,
`fstat` (+ `read_sendfile_fd` only if propagating zero-copy). A **stage** decorator
additionally needs: `pwrite`/`ftruncate`/`fsync` **or** `staged_open`/`staged_write`/
`staged_commit`. A backend lacking the write set cannot be a stage target (§13.5).

**Caps** (`xrootd_sd_cap_t`): `FD`, `SENDFILE`, `RANDOM_WRITE`, `RANGE_READ`,
`TRUNCATE`, `SERVER_COPY`, `XATTR`, `HARD_RENAME`, `DIRS`, `APPEND`, `IOURING`,
`FSCS`. The decorator's `caps` = wrapped caps minus those it cannot honor (notably
`SENDFILE`/`FD` over a remote source unless the local store serves block-0).

## Appendix B — `xrootd_cache_cinfo_t` on-disk (the cache-file state)

```
magic, version, flags, block_size, reserved          # header
size, mtime                                          # origin validity
nblocks, <present bitmap: nblocks bits>              # partial-file presence
access_count, bytes_served, last_access             # serve stats
dirty_lo, dirty_hi, dirty_since, flush_gen,         # WRITE-BACK STATE (v3)
  last_flush, bytes_flushed
etag[], cks_alg[], cks_hex[]                         # strong freshness / verify
```

The write-back state machine and validity are **source-independent**; the re-point
(C-1/C-5) changes *where* a dirty extent flushes, not *what* the state means.

## Appendix C — Files touched vs deleted (summary)

- **Touched (wiring):** `vfs_backend_registry.{c,h}`, `cache/{open,fetch,slice_fill,thread}.c`, `cache/writethrough_flush.c`, `cache/directives.c`, `backend/xroot/sd_xroot.c`, dashboard/metrics.
- **New:** `backend/http/sd_http.c`, the cache/stage decorator driver(s).
- **Deleted:** `cache/origin_connection.c`, `cache/origin_protocol.c`, `cache/origin_response.c`, the `fetch_origin_exec` path; **consolidated:** `fs/vfs_staged.c`, `fs/vfs_scratch.c`.
- **Relocated:** `cache/http_transport.c`, `cache/pelican.c`, `cache/pelican_register.c` → `backend/http/`.
- **Shrunk to a backend + shim:** `src/frm/`, the caching role of `src/upstream/` and `src/proxy/`.
