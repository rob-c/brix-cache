# Phase 63 — Composable storage stack: any backend, generic read cache + write stage, assembled by config

**Status: PROPOSED (design / analysis — no code yet, 2026-06-29).**

This phase turns the storage plane into a **config-assembled middleware stack**:
any local *or* remote filesystem as the source, with a **generic read cache** and
a **generic write stage (write-back)** that compose in front of *any* backend. It
retires the bespoke **XCache** origin machinery — whose "fetch-from-a-remote-source"
and "write-back-to-a-remote-origin" functions are already (partly) reproduced by
the backend SD drivers — by re-pointing the cache's fill/flush at the *registered
source backend* and folding the duplicate stagers into one decorator.

> **This is not a green-field refactor.** Reading the code shows the migration is
> already **~60% done**: the cache's local store is an SD instance, two of the
> five fill paths (S3, anonymous `root://`) already go driver→driver, the
> write-back already *reads* the dirty file through the driver, and the registry
> already accepts `xroot` as a primary backend. This doc inventories exactly
> what remains, what each removal is *gated on*, and the order to land it.

**Builds on:** [`src/fs/README.md`](../../src/fs/README.md),
[`phase-55-storage-backend-abstraction.md`](phase-55-storage-backend-abstraction.md)
(the SD driver seam), [`phase-62-vfs-namespace-metadata-seam-closure.md`](phase-62-vfs-namespace-metadata-seam-closure.md)
(the VFS as the sole storage truth),
[`docs/09-developer-guide/pblock-metadata-performance.md`](../09-developer-guide/pblock-metadata-performance.md)
(the "measure the layering cost" caveat).

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

## 1. Vocabulary (exact types, so the rest is unambiguous)

| Type (`src/fs/backend/sd.h`) | What it is |
|---|---|
| `xrootd_sd_driver_t` | the 30-slot capability-typed vtable (`open`/`pread`/`pwrite`/`stat`/`mkdir`/`staged_open`/`staged_write`/`staged_commit`/…) + a `caps` bitmap |
| `xrootd_sd_instance_t` | a *bound* driver: `{driver, log, pool, state, root_canon}` — one per export per worker |
| `xrootd_sd_obj_t` | a per-open handle (`{inst, driver, fd, state, snap}`) returned by `driver->open` |
| `xrootd_sd_staged_t` | an in-progress atomic write returned by `driver->staged_open` (→ `staged_write` → `staged_commit`/`staged_abort`) |
| `xrootd_vfs_ctx_t` (`vfs.h`) | the per-op context a handler fills: `{pool, log, proto, root_canon, cache_root_canon, sd, resolved, allow_write, cache_enabled, cache_writethrough, …}` |
| `xrootd_cache_fill_t` (`cache_internal.h`) | a heap-allocated **fill task** posted to the blocking thread pool: paths (`clean_path`/`cache_path`/`part_path`/`lock_path`), `file_size`, error fields, `conf` |
| `xrootd_cache_sink_t` (`cache_internal.h`) | the **write target** of a fill/flush: a tagged union `{fd (POSIX pwrite) ‖ staged (driver `staged_write`) ‖ mem (buffer)}` |

**Key fact #1 — the cache's *local store* is already an SD instance.**
`xrootd_cache_storage(conf)` (`cache_storage.c:210`) just returns
`conf->cache_storage_inst`, an `xrootd_sd_instance_t`. Fills write into it via
`driver->staged_open`/`staged_write`; hits serve via `driver->pread`; eviction
enumerates it via the driver (`evict_policy.c:206`). So the *cache side* of the
stack is already fully driver-abstracted.

---

## 2. Current state — what already routes through drivers, and what does not

### 2.1 The read path

`vfs_open.c:399` calls the VFS cache hook **before** the bound driver:

```
xrootd_vfs_open(ctx, flags)
  └─ xrootd_cache_open(ctx, flags, &fh)        # cache/open.c:139
       NGX_OK       → serve hit from conf->cache_storage_inst (driver->pread)
       NGX_ERROR    → fail
       NGX_DECLINED → miss/pass-through → fall to the bound driver / POSIX cascade
```

A **miss** schedules a fill task and `xrootd_cache_fetch_origin(t)`
(`fetch.c:600`) dispatches by `conf->cache_origin_scheme`:

| Origin scheme | Fill mechanism | Driver-based? |
|---|---|---|
| `S3` | `xrootd_cache_fetch_origin_s3` → `sd_remote → sd_s3` driver→driver copy into the staged sink | **YES** |
| anonymous `root://` | `xrootd_cache_fetch_origin_xroot` → `xrootd_sd_xroot_create` → `origin->driver->open/pread` → `cache_inst->driver->staged_open` | **YES** |
| `HTTP`/`HTTPS`/WebDAV | `xrootd_cache_http_download` (`http_transport.c`, libcurl) → `commit_part` | no — libcurl |
| `PELICAN` | `xrootd_cache_pelican_download` (`pelican.c` director 307 + libcurl) | no — libcurl |
| authenticated `root://` (`cache_origin_proxy`/`token_file` set) | `xrootd_cache_fetch_origin_exec` → **native-client subprocess** | no — exec, *because `sd_xroot` is anon-login-only* |

The driver-based exemplar already in the tree — `xrootd_cache_fetch_origin_xroot`
(`fetch.c:475`), abridged:

```c
origin = xrootd_sd_xroot_create(conf, log);                         /* remote source instance   */
src    = origin->driver->open(origin, t->clean_path,
                              XROOTD_SD_O_READ, 0, &e);              /* open over the wire        */
t->file_size = (uint64_t) src->snap.size;                           /* size from the snap        */
/* admission gate (size/prefix/regex) — generic, unchanged */
staged = cache_inst->driver->staged_open(cache_inst, key, 0644,&e); /* local atomic write        */
sink.staged = staged;                                               /* driver staged_write sink  */
/* loop: src->driver->pread(...) → xrootd_cache_sink_pwrite(&sink,...) */
```

This is **exactly the generic shape** the whole cache should use — a source
`sd_instance` opened, `pread` into a `staged` sink on the cache `sd_instance`. The
only reason it is not universal is auth (`sd_xroot` anon-only) and transport
(`http_transport`/`pelican` are libcurl, not a driver).

### 2.2 The write-back path

`writethrough_flush.c` (1087 LOC) already **reads** the dirty local copy through
the driver:

```c
o     = sd->driver->open(sd, key, XROOTD_SD_O_READ, 0, &derr);   /* :303 block-aware read   */
nread = obj->driver->pread(obj, buf, want, offset);             /* :353                    */
```

…but it has **two** terminal sinks, only one of which is driver-based:

- **origin wire client** — `xrootd_cache_origin_write_chunk` (`:365`) +
  `xrootd_cache_origin_truncate` (`:376`), i.e. `origin_connection`/`origin_protocol`.
- **driver staged** — `si->driver->staged_open`/`staged_write` (`:615`/`:633`).

So the write-back is *hybrid*: a driver-staged flush exists, but a `root://`
origin still flushes through the bespoke wire client.

### 2.3 The registry

`xrootd_vfs_backend_registry.c` already models a per-export backend:

```c
typedef struct {
    char                  root_canon[PATH_MAX];
    char                  backend[16];   /* "pblock" | "xroot"  ← remote source already allowed */
    int64_t               block_size;
    void                 *srv_conf;       /* xroot: the srv conf the origin reads */
    xrootd_sd_instance_t *inst;           /* lazily built per worker, or NULL */
} xrootd_vfs_backend_entry_t;             /* xrootd_vfs_backends[64] */
```

It resolves **one** instance per `root_canon` (`xrootd_vfs_backend_resolve`). It
does **not** yet model a *stack* (source wrapped by cache/stage), and the cache's
source is configured **separately** via `xrootd_cache_origin*` directives rather
than "wrap the registered backend." That separation is the central structural gap.

### 2.4 The duplicate stagers

Three parallel "buffer-write-locally-then-commit-to-backend" implementations:

| File | LOC | Role |
|---|---|---|
| `src/cache/writethrough_{flush,decision,replay}.c` | 1087 + 124 + 126 | the cache write-back (dirty `.cinfo` → flush to origin/driver, replay on restart) |
| `src/fs/vfs_staged.c` | 244 | VFS wrapper over `driver->staged_*` for the upload paths |
| `src/fs/vfs_scratch.c` | 177 | materialize-to-scratch (stage object → local POSIX → VFS↔VFS move) |

…plus S3 multipart (`src/s3/multipart_*`) and the WebDAV/S3 PUT upload-stage dir.

---

## 3. Target architecture

A config-assembled **decorator stack**, every layer SD-driver-shaped, built by the
registry:

```
source backend   posix | pblock | block | xroot | remote | s3 | rados | http
     ▲
  [ stage ]      write-back: writes land on stage_root, flush async via source->pwrite/staged_commit
     ▲
  [ read cache ] miss → source->open/pread; store slice on cache_root; cinfo/admit/evict/verify
     ▲
   VFS  (src/fs/)  →  every protocol (root:// / WebDAV / S3 / CMS) UNCHANGED
```

### 3.1 The decorator contract

A `cache(source)` / `stage(source)` decorator is an `xrootd_sd_instance_t` whose
`driver` slots delegate to the wrapped `source` and interpose the cache/stage
logic. Two viable shapes:

- **(a) A real SD driver decorator.** `xrootd_sd_cache_driver` /
  `xrootd_sd_stage_driver` implement the vtable; `inst->state` holds
  `{source_inst, local_store_inst, policy}`. `caps` = the wrapped backend's caps
  minus what the layer changes (a read cache over a remote source still advertises
  `RANGE_READ`; it cannot advertise `SENDFILE` unless it serves block-0 from a
  local fd). Cleanest for composition; the VFS dispatch (`xrootd_vfs_ctx_driver`)
  is already driver-shaped, so it slots in with **zero handler changes**.
- **(b) Keep the cache as a VFS-layer hook** (`xrootd_cache_open` at `vfs_open.c`)
  but feed it the registered source (§4 C-1). Smaller diff; less uniform (stage
  and cache would compose differently). **Recommended interim** for C-1; converge
  to (a) for full modularity.

### 3.2 Config grammar (current → proposed)

Current cache directives (`src/cache/directives.c`): `xrootd_cache_origin
addr:port`, `xrootd_cache_eviction_threshold`, `xrootd_cache_max_file_size`,
`xrootd_cache_include_regex`, `xrootd_cache_verify` / `_verify_digest`,
`xrootd_cache_deny_prefix` / `_allow_prefix`, plus the scheme/proxy/token fields.

Proposed — the source moves to the backend selector; the cache stops naming its
own origin:

```nginx
# the source is ANY backend (the existing knob — already accepts xroot)
xrootd_storage_backend  xroot://origin:1094/data;   # or s3://… http://… posix (default)

# generic read cache in front of the bound source
xrootd_cache  on;
xrootd_cache_root            /ssd/cache;
xrootd_cache_eviction_threshold 90;          # (kept)
xrootd_cache_max_file_size   50g;            # (kept)
xrootd_cache_verify          on;             # checksum-on-fill (kept)

# generic write-back stage in front of the bound source
xrootd_stage  on;
xrootd_stage_root            /nvme/stage;
xrootd_stage_flush           async;          # writethrough_decision policy
```

`xrootd_cache_origin*` (host/port/scheme/proxy/token) **collapse into the backend
selector** — a Pelican origin becomes `xrootd_storage_backend
http://director-discovered`, a GSI origin becomes the source driver's credential
config. This is the modularity payoff: the operator composes `source` + `cache` +
`stage` as independent parts.

---

## 4. Changes required (file-by-file, with the blocker each removal waits on)

### C-1 — Cache fills from the *registered source backend*, not `cache_origin_*`
**Files:** `cache/open.c`, `cache/fetch.c`, `cache/slice_fill.c`, `vfs_backend_registry.*`.
Make the fill source = the export's registered source `xrootd_sd_instance_t`
(reachable from `ctx`/`conf`) and generalize `xrootd_cache_fetch_origin` to the
`fetch_origin_xroot` shape for **every** backend (`open`→`pread`→staged sink). The
per-scheme branch (`cache_origin_scheme`) becomes "ask the bound source driver."
The cache store, admission, `.cinfo`, eviction, verify are untouched.
*Unlocks nothing yet by itself, but it is the spine everything else hangs on.*

### C-2 — Registry composes a STACK
**Files:** `vfs_backend_registry.{c,h}`, the directive handlers.
Extend the entry to `{source, cache?, stage?}` and have `resolve` return the
composed top of stack. `xrootd_storage_backend` sets the source; `xrootd_cache` /
`xrootd_stage` wrap it. (Decorator shape per §3.1.)
*Unlocks: cache/stage in front of any backend — the headline capability.*

### C-3 — `sd_xroot` gains GSI/token auth
**Files:** `backend/xroot/sd_xroot.c` (currently *"Anonymous login only"*, line 6).
Add credentialed login (X.509 proxy / bearer token) so authenticated `root://`
origins fetch in-process.
*Unlocks the deletion of `xrootd_cache_fetch_origin_exec` (the native-client
subprocess) — and, with C-5, the write-back to authenticated origins.*

### C-4 — `http` source driver
**Files:** new `backend/http/sd_http.c`; relocate `cache/http_transport.c` +
`cache/pelican.c` logic behind it.
`open`/`pread`/`stat` over libcurl as a driver; Pelican director discovery is its
`open`-time resolution. After this, HTTP/HTTPS/WebDAV/Pelican fills go through the
generic C-1 path.
*Unlocks the deletion of `http_transport`/`pelican` as cache-private code (they
survive as the driver).*

### C-5 — Write-back via `source->pwrite`/`staged_commit`
**Files:** `cache/writethrough_flush.c` (replace `:365`/`:376`
`origin_write_chunk`/`origin_truncate` with the source driver's write path).
Needs C-3 (auth) + the source driver's `pwrite`/`fsync`/`ftruncate` (`sd_xroot`
already has them; `remote` needs them).
*Unlocks the deletion of `origin_connection`/`origin_protocol`/`origin_response`
(978 LOC) — once the read fill (C-1/C-3/C-4) and the write-back both go via
drivers, the wire client has no callers.*

### C-6 — One generic `stage` decorator
**Files:** fold `fs/vfs_staged.c` + `fs/vfs_scratch.c` + `cache/writethrough_*`
into a single stage layer over the `xrootd_cache_sink_t` (`fd`/`staged`/`mem`) and
the existing `.cinfo` dirty/`flush_gen`/`dirty_since` engine; keep
`xrootd_wt_default_decide` (`writethrough_decision.c:21`) as the async/deny policy.
S3 multipart stays backend-specific (it *is* the S3 commit protocol) but its
local-spool shape aligns; the upload-stage dir folds in.
*Unlocks: removal of two parallel stagers; one durability/replay story.*

### C-7 — Redirect the XCache API/admin/metrics
**Files:** `src/dashboard/*`, `src/metrics/*`, `/healthz`, `cache/directives.c`.
Point the cache endpoints/metrics at the decorator state (`cinfo`/admission/
eviction); remove origin host/port/scheme/proxy/token config (now the source
backend).

---

## 5. What can be almost completely removed or consolidated (with LOC + gate)

| Component | LOC | Verdict | Gated on | Why redundant |
|---|---|---|---|---|
| `cache/origin_connection.c` + `origin_protocol.c` + `origin_response.c` | **978** | **Remove** | C-1, C-3, C-4, C-5 | The cache's private XRootD wire client — reproduced by `sd_xroot`/`sd_remote` once fills/flush go via the driver. **The headline deletion.** |
| `cache/http_transport.c` + `pelican.c` + `pelican_register.c` | — | **Relocate** | C-4 | Becomes `backend/http`; director discovery becomes a remote-backend concern. Bytes-moving code survives as a driver. |
| `cache/fetch_origin_exec` (native-client subprocess fill) | — | **Remove** | C-3 | Exists only because `sd_xroot` is anon-only; authenticated in-process fetch replaces it. |
| `fs/vfs_staged.c` + `fs/vfs_scratch.c` + cache `writethrough_*` | 244 + 177 + 1337 | **Consolidate → one** | C-6 | Three parallel stage-then-commit impls → one stage decorator over the shared sink + `.cinfo`. |
| `src/upstream/` | 1463 | **Mostly removable** | C-2, C-4 | The HTTP/WebDAV "proxy to an upstream" connection layer = an `http` remote backend + cache decorator; only a pure non-caching pass-through still wants it. |
| `src/proxy/` | 4501 | **Partially removable** | C-2, C-3 | The "cache/forward in front of an upstream data server" role = `xroot` backend + cache decorator. **Residual:** the zero-copy splice **pure-relay** (no-store) path — keep it or model it as a "no-store cache." |
| `src/frm/` | 3234 | **Folds into a backend + stage** | C-6 | FRM tape staging = a `tape`/`hsm` **source backend** (its durable queue is the commit mechanism) wrapped by the generic stage. The WLCG Tape REST *API surface* stays; the staging machinery merges. |

> Honest accounting: of the ~978 LOC origin trio, **all** is removable; of the
> ~4500 LOC `proxy` and ~1463 LOC `upstream`, only the *caching/forwarding* role
> is — the splice pure-relay and redirect logic are not storage and stay. `frm`
> shrinks to a backend + Tape REST shim, not zero.

---

## 6. Data-flow walkthroughs (before → after)

### 6.1 Cached read miss of `/data/f` against a remote `root://` origin
**Before (authenticated origin):** `xrootd_cache_open` DECLINE → fill task →
`fetch_origin_exec` forks `xrdcp`/native client (auth from env) → writes
`part_path` → `commit_part` → serve. *(Subprocess + bespoke origin code.)*
**After (C-1/C-3):** `xrootd_cache_open` DECLINE → fill task → source =
registered `sd_xroot` instance (credentialed) → `source->open(O_READ)` →
`source->pread` loop → `cache_inst->staged_open`/`staged_write` →
`staged_commit` → serve. *(All in-process, all driver vtable.)*

### 6.2 Write-back of a dirty cached file to the origin
**Before:** `writethrough_flush` reads local via `driver->pread`, writes origin via
`xrootd_cache_origin_write_chunk` + `_truncate` (wire client).
**After (C-5):** same driver read; write via `source->pwrite`/`ftruncate`/`fsync`
(or `staged_open`→`staged_write`→`staged_commit` for atomic-publish backends like
S3). `origin_*` gone.

### 6.3 Local POSIX export, no cache (the default)
Unchanged: `xrootd_cache_open` returns DECLINE (cache disabled) → POSIX confinement
cascade. The stack is `source(posix)` only; decorators absent.

---

## 7. Enablers already in place (why this is tractable, with evidence)

- The VFS is the **sole storage seam** for every protocol (phase-62) — nothing
  above the registry changes when a decorator is inserted.
- The cache is **already a VFS-layer hook** (`vfs_open.c:399` → `xrootd_cache_open`),
  not bolted onto one protocol.
- The cache **local store is already an SD instance** (`conf->cache_storage_inst`),
  with `staged_open`/`staged_write` fills, `pread` serves, driver-enumerated eviction.
- **Two fill paths already go driver→driver** (`fetch_origin_s3`,
  `fetch_origin_xroot`) — the generic shape exists and works.
- The **write sink is already abstracted** (`xrootd_cache_sink_t`: `fd`/`staged`/`mem`).
- The **registry already accepts `xroot`** as a primary backend
  (`backend[16] = "pblock"|"xroot"`).
- The **`.cinfo` write-back engine** (dirty/`flush_gen`/`dirty_since`, admission
  filter, stale-dirty reaper) is generic and source-agnostic.
- `sd_xroot` already has read **and** write data slots — only auth is missing.

---

## 8. Risks & caveats

1. **Layering is not free.** A remote-backend fill *through* the cache carries the
   driver-dispatch + slice-store overhead the hardwired origin client currently
   inlines. Per the pblock perf work, **A/B the composed stack** (`xroot+cache`
   vs the old XCache) and keep that benchmark — do not assume parity.
2. **Pure pass-through must survive.** The zero-copy splice relay in `src/proxy/`
   is a no-store forwarding role the cache does not cover; model it as a "no-store
   cache" or keep it explicitly — do not delete it with the origin client.
3. **Durability of the generic stage.** The stage inherits the write-back
   crash-consistency contract (`flush_gen` replay, the stale-dirty reaper). Any
   source used as a stage target must surface real commit failures so a lost flush
   is retried/bounded, never silently dropped (`xrootd_wt_default_decide` is
   already fail-closed — keep that).
4. **Confinement boundaries differ per layer.** Export-confined VFS open
   (`RESOLVE_BENEATH`) applies to local roots; a remote source is confined by the
   *remote* server. The decorator must not assume a local `root_canon` for a remote
   source — `cache_root`/`stage_root` stay local; the source does not.
5. **Auth surface for `sd_xroot` (C-3).** Credentialed in-process login pulls GSI/
   token handling into the server data path; reuse the existing `src/gsi` /
   `src/token` machinery rather than re-implementing, and keep the anon path for
   anon origins.
6. **Capability honesty.** A read cache over a remote source must *not* advertise
   `SENDFILE` unless it can serve block-0 from a local fd; the decorator's `caps`
   must reflect what it can actually do, or the VFS sendfile gate will mis-route.

---

## 9. Migration order (dependency-ordered; each step independently shippable)

| Step | Change | Exit criteria | Unlocks |
|---|---|---|---|
| 1 | **C-1 behind a flag** — cache fills from the bound driver; keep `cache_origin_*` as default | `xroot+cache` serves a miss in-process; A/B vs XCache recorded | the spine |
| 2 | **C-3** — `sd_xroot` GSI/token auth | authenticated `root://` origin fills in-process | delete `fetch_origin_exec` |
| 3 | **C-4** — `http` source driver (relocate transport/pelican) | HTTP/Pelican fill via the driver | delete cache-private libcurl |
| 4 | **C-5** — write-back via `source->pwrite`/`staged_commit` | dirty flush to origin uses the driver | **delete `origin_connection`/`protocol`/`response` (978 LOC)** |
| 5 | **C-2** — registry composes `cache(source)` / `stage(source)`; flip defaults | `xrootd_cache on; xrootd_stage on;` compose over any `xrootd_storage_backend` | cache/stage in front of any backend |
| 6 | **C-6** — one generic stage decorator | `vfs_staged`/`vfs_scratch`/`writethrough` consolidated | delete two stagers |
| 7 | **C-7** — redirect XCache API/admin/metrics | dashboard/metrics read decorator state; origin config removed | XCache framing gone |
| 8 | **Fold `upstream`/`proxy` caching roles, then `frm`** into the backend+stack model | pure-relay isolated; FRM is a `tape` backend + Tape REST shim | subsystem shrink |

The biggest clean deletion is the cache's private origin client (step 4);
everything after is shrinking standalone subsystems into "a backend + the generic
cache/stage stack."

---

## Appendix A — SD vtable slots this phase leans on

`open`, `close`, `pread`, `pwrite`, `fstat`, `ftruncate`, `fsync`, `stat`,
`staged_open`, `staged_write`, `staged_commit`, `staged_abort`, `opendir`/`readdir`
(eviction). A read-cache decorator needs only the read + staged-write set of its
wrapped source; a stage decorator additionally needs the source's `pwrite`/
`staged_commit`. A backend that lacks a slot (e.g. read-only `remote`) simply
cannot be a stage *target* — the registry rejects `xrootd_stage on` over it.

## Appendix B — Files touched vs deleted (summary)

- **Touched (wiring):** `vfs_backend_registry.{c,h}`, `cache/{open,fetch,slice_fill,thread}.c`, `cache/writethrough_flush.c`, `cache/directives.c`, `backend/xroot/sd_xroot.c`, dashboard/metrics.
- **New:** `backend/http/sd_http.c`, the cache/stage decorator driver(s).
- **Deleted:** `cache/origin_connection.c`, `cache/origin_protocol.c`, `cache/origin_response.c`, `cache/fetch_origin_exec` path; **consolidated:** `fs/vfs_staged.c`, `fs/vfs_scratch.c`.
- **Shrunk to a backend + shim:** `src/frm/`, the caching role of `src/upstream/` and `src/proxy/`.
