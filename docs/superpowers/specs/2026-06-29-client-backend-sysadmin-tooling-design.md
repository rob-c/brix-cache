# Backend-aware sysadmin tooling — folded into the scan engine + `xrdstorascan`

**Status:** design / spec — approved direction 2026-06-29
**Owner:** Rob Currie
**Date:** 2026-06-29
**Supersedes/extends:** [`2026-06-29-storage-scan-verify-design.md`](2026-06-29-storage-scan-verify-design.md)
— that spec defined the `src/scan/` engine (`dump`/`verify`/`fill`/`compare`) and
the `xrdstorascan` client. This spec **folds the new backend-sysadmin feature
menu into that same engine and tool** rather than spawning parallel tooling
(operator decision 2026-06-29: "fold entirely into scan").

**Scope:** make the new Ceph/RADOS (`sd_ceph`) and pblock backends *appealing to
sysadmins* by extending the one scan engine + one client with: single-file
verification, backend introspection, backend-catalog inventory with orphan
detection, namespace↔catalog drift reconciliation, gateway performance testing,
and backend/cluster health — all as new modes/subcommands. **No RADOS symbol
above `src/fs/backend/`** (CLAUDE.md #11): the one new below-seam capability
(backend-catalog enumeration) is an `xrootd_sd_driver_t` vtable verb; everything
above it stays backend-neutral.

---

## 0. Why this is one tool, not six

The base scan engine is already a *throttled, confined, streaming, resumable,
backend-neutral walk → per-object action → NDJSON* pipeline. Every feature in the
menu is a variation on (a) **what we enumerate** (namespace subtree vs. backend
object catalog vs. a single path vs. nothing), and (b) **what action we run per
item** (read stored cksum, recompute, stat the backend, time an I/O, reconcile).
So each menu feature is a new **enumeration source** and/or a new **mode**, reusing
the engine's throttle, confinement, ordering, cursor/resume, transport, and auth.

```
enumeration source        ×        per-item action            =  mode
─────────────────                  ─────────────                  ────
namespace walk (vfs_walk)          read stored cksum              dump      (base)
namespace walk                     recompute vs stored            verify    (base)
namespace walk                     fill missing cksum             fill      (base)
namespace walk                     stream stored (diff @client)   compare   (base)
single path                        backend introspection          inspect   (A2)  NEW
backend catalog (NEW driver verb)  emit object + opt stat         inventory (E1)  NEW
catalog ∪ namespace                reconcile                      drift     (D2)  NEW
sample of namespace / synthetic    timed read/write, percentiles  bench     (B*)  NEW
none (endpoint query)              backend + cluster health       health    (C1)  NEW
```

`verify` over a **single path** (the client just points the existing `verify`
mode at one file URL) *is* the "test an individual file" ask (A1); a client-only
`--wire` variant additionally pulls the bytes end-to-end and compares to
`kXR_Qcksum` for a true round-trip trust check.

---

## 1. New below-seam capability — backend-catalog enumeration

The only feature needing storage-layer work is **E1 inventory / D2 drift**: they
must list what the backend *physically holds*, independent of the namespace. That
is a new optional verb on the storage-driver vtable (`src/fs/backend/sd.h`):

```c
/* Enumerate the driver's own object catalog (NOT a namespace walk).
 * Fires cb once per stored object with its backend key, logical path if the
 * driver can recover it (else NULL ⇒ candidate orphan), and optional stat.
 * Capability-gated: drivers without a native catalog leave the fn ptr NULL. */
typedef int (*xrootd_sd_enumerate_fn)(xrootd_sd_instance_t *sd,
                                      int want_stat,
                                      xrootd_sd_catalog_cb cb, void *ctx);
```

- **`sd_ceph`** (`src/fs/backend/rados/`): `rados_nobjects_list_open` →
  `rados_nobjects_list_next` over the pool; key→LFN via the existing flat
  LFN↔object-key map (reverse lookup); `want_stat` ⇒ `rados_stat` per object.
- **`sd_pblock`** (`src/fs/backend/pblock/`): scan the block-metadata/index space
  it already maintains for its namespace; `want_stat` reads the per-object size
  from the same index (cheap, no extra I/O).
- **`sd_posix`**: capability **absent** (NULL fn). For POSIX the "catalog" *is* the
  namespace, so `inventory`/`drift` either fall back to a `vfs_walk` (catalog ≡
  namespace ⇒ no orphans possible) or report "not supported for this backend",
  per `--require-catalog`.

This is the sole RADOS-touching code; it lives in the driver, below the seam.
A driver-agnostic `xrootd_vfs_enumerate_catalog()` wrapper in `src/fs/` exposes
it to the engine, returning `ENOTSUP` when the bound driver lacks the verb.

---

## 2. New modes (engine — `scan_engine.c`)

### 2.1 `inspect` (A2) — single-path backend introspection
Enumeration source: the one `path`. Action: resolve to the bound driver, emit
backend type, backend object key(s), backend `stat` (size/mtime as the *backend*
sees them — `rados_stat`/pblock-index, **not** the namespace stat), stored-cksum
source (xattr/CSI/none), and a `namespace_consistent` flag (namespace stat ==
backend stat). One `inspect` record. Reads no object bytes.

### 2.2 `inventory` (E1) — backend-catalog dump
Enumeration source: `xrootd_vfs_enumerate_catalog()` (the new verb). Action: emit
one `object` record per stored object: backend key, recovered logical path (or
`null` ⇒ orphan candidate), and — when `--stats` — size/mtime. `--stats` is the
throttle lever: names-only is one catalog scan; with stats adds a per-object
`stat` (gated by the concurrency cap, not the byte-rate cap — no bytes read).
Records stream in catalog order with the same cursor/resume contract.

### 2.3 `drift` (D2) — namespace ↔ catalog reconciliation
Enumeration source: **both** — a `vfs_walk` of the namespace subtree *and* a
catalog enumeration — merged. Action: classify each logical path / object key:
`in_both` (optionally size-compared), `orphan_object` (catalog, no namespace),
`namespace_only` (namespace entry, no backing object). Emits `drift` records +
a `summary` with per-class counts. This is the object-store "fsck". Memory bound:
the catalog side is held in a compact open-addressing key set (key→size); the
namespace walk streams against it, so peak memory is O(catalog), not O(both).

### 2.4 `bench` (B1–B5) — gateway performance test
A different shape: it does **not** walk-then-checksum. Enumeration source is
either a **sample** of existing objects (drawn from a quick catalog/namespace
sample) or **synthetic** objects the bench creates under a scratch prefix and
removes after. Action per worker: timed read or write of a fixed block, looped.
Controls (query params / flags): `op=read|write`, `block=<size>` (sweepable list
`1M,4M,16M`), `parallel=<n>` (sweepable), `pattern=seq|random`, `duration=<s>` or
`count=<n>`, `warm=0|1` (B4: first-touch vs re-read), `durable=0|1` (B5: include
fsync/commit in the write timing). Emits a `bench` record per (block,parallel)
cell with throughput, IOPS, and latency p50/p95/p99 (HDR-style histogram), and a
`summary`. The byte-rate throttle is **off** for bench (the point is to find the
ceiling); the concurrency cap still bounds blast radius, and `bench` requires the
explicit `xrootd_scan_bench on` directive (it generates load by design).

### 2.5 `health` (C1) — backend + cluster health
Enumeration source: none. Action: query the bound driver for backend type and,
for Ceph, cluster health (`rados_cluster_stat` / mon health string), pool, repl/EC
scheme, OSD up/in, free/used. One `health` record. Surfaces Ceph health to an
admin with no shell on the gateway. Reuses SRR capacity where it already exists.

---

## 3. New record types (NDJSON — `scan_record.c`)

```json
{"t":"inspect","path":"/atlas/x.root","backend":"ceph","key":"atlas.x.root","size":12345,"mtime":1719600000,"stored_src":"xattr","namespace_consistent":true}
{"t":"object","key":"atlas.x.root","path":"/atlas/x.root","size":12345,"mtime":1719600000,"orphan":false}
{"t":"drift","key":"atlas.orphan.0","path":null,"class":"orphan_object","size":4096}
{"t":"bench","op":"read","block":4194304,"parallel":8,"pattern":"seq","throughput_mbps":920.4,"iops":230,"p50_ms":4.1,"p95_ms":9.7,"p99_ms":18.2}
{"t":"health","backend":"ceph","cluster":"HEALTH_OK","pool":"atlas","scheme":"EC4+2","osd_up":48,"osd_in":48,"free_bytes":1.2e15,"used_bytes":3.4e14}
```

`file`/`cursor`/`summary` from the base spec are unchanged. `drift`/`inventory`
extend `summary` with their class counters.

---

## 4. Transport, config, auth (reuse + small adds)

- **Endpoint:** same `GET /xrootd/api/v1/scan`, `mode=inspect|inventory|drift|
  bench|health` added to the existing param parser; same chunked NDJSON, admin
  auth, `openat2 RESOLVE_BENEATH` confinement.
- **New params:** `stats=0|1` (inventory), and the bench knobs (§2.4). All bench
  knobs clamp to operator ceilings.
- **New directives** (`src/config`):
  ```nginx
  xrootd_scan_bench        on | off;   # default off — bench generates load
  xrootd_scan_bench_root   <path>;     # scratch prefix for synthetic bench objects
  ```
  plus the existing `xrootd_scan*` set. Bench writes/synthetic objects live only
  under `xrootd_scan_bench_root`, confined like the rest.
- **Layering:** `scan_engine`/`scan_throttle`/`scan_record` stay ngx-free; `inspect`/
  `inventory`/`drift`/`health` actions call only `xrootd_vfs_*` (incl. the new
  `xrootd_vfs_enumerate_catalog`); `bench`'s I/O is `xrootd_vfs_open_fd_at`
  + `obj->driver->pread/pwrite` through the VFS core — no backend symbol leaks up.

---

## 5. Client — `xrdstorascan` new subcommands

```
xrdstorascan inspect    root://host//atlas/x.root              # A2 one-file backend facts
xrdstorascan verify     root://host//atlas/x.root              # A1 single-file (server recompute vs stored)
xrdstorascan verify     root://host//atlas/x.root --wire       # A1 true end-to-end (pull bytes, cmp kXR_Qcksum)
xrdstorascan inventory  davs://host//atlas/ [--stats] -o objs.tsv   # E1 backend catalog (+ orphans)
xrdstorascan drift      davs://host//atlas/                    # D2 namespace↔catalog fsck
xrdstorascan bench      root://host//atlas/ --op read --block 1M,4M,16M --parallel 1,4,16   # B1 sweep
xrdstorascan health     davs://host/                           # C1 backend/Ceph health
```

- Renders the new NDJSON record types → TSV (default) / `--json` / `--summary`,
  consistent with the base tool's output modes; `bench` also gets a `--table`
  human grid (rows = block size, cols = parallelism).
- `inventory`/`drift` honor `--resume` via the same `.scanstate` cursor sidecar.
- `verify --wire` is the one **client-side** action (reuses `xrdc_file_open_read`
  + `xrdc_cksum_fd` + `xrdc_query_cksum`); it needs **no** server engine, so it
  works against any backend today and is the first shippable slice (§7).
- `bench` client can also run **purely client-side** (`--wire`, the default when
  the server lacks the bench mode): it times reads/writes over the live `root://`
  connection — the black-box "how fast is this gateway from where I sit" test —
  and prints the same table. Server-side `bench` (next to the OSDs) is the
  `--server` variant.

---

## 6. Testing (3-per-change: success + error + security-neg)

**Engine unit** (extends `scan` standalone unit test):
- `inspect`/`inventory`/`drift` record formatting; drift reconciliation set math
  (orphan / namespace-only / in-both, size-mismatch) against a synthetic
  catalog+namespace pair; bench histogram percentile math (pure, seeded samples).
- catalog-enumeration fallback: POSIX driver (no verb) ⇒ `ENOTSUP` surfaced, not
  a crash; `--require-catalog` vs fallback-to-walk behavior.

**HTTP integration** (`tests/test_scan.py` additions):
- `inspect` on a known file returns correct backend/key/size and
  `namespace_consistent:true`; on a drift-injected file → `false`.
- `inventory --stats` over a fixture tree matches known objects+sizes; an
  injected orphan object appears with `orphan:true`, `path:null`.
- `drift` flags injected orphan + namespace-only + size-mismatch exactly once.
- `bench --op read` produces monotonic-sane throughput/latency for a sweep; honors
  `count`/`duration`; `xrootd_scan_bench off` ⇒ mode disabled (404).
- `health` returns backend type (POSIX harness: `backend:"posix"`).

**Security-neg:** non-admin → 403; `path=../escape` confined/403; bench knobs above
ceiling clamped; bench root traversal confined; `health` leaks no host paths
(low-cardinality, PII-free, per metric-label rules).

**CEPH / pblock:** against the phase-60 single-node Ceph harness and a pblock
export: `inventory`/`drift` exercise the real catalog verb; `inspect` shows the
RADOS object key; `bench` measures the real gateway. POSIX vs pblock `inventory`
of the same logical tree must agree on paths+sizes (orphans only where injected).

---

## 7. Implementation phasing

Built incrementally; each phase ships and is tested on its own.

1. **Phase 1 — client-only, zero server dependency (ships now):** `xrdstorascan`
   tool foundation + `verify --wire` (A1) + client-side `bench` (B1, `--wire`).
   These answer both original example asks, work against any backend over today's
   wire, and need no `src/scan` engine. *(TDD against the existing test fleet.)*
2. **Phase 2 — base scan engine** (`dump`/`verify`/`fill`/`compare`) per the
   superseded spec — the server-side foundation the rest of the modes ride on.
3. **Phase 3 — introspection modes:** `inspect` (A2) + `health` (C1) (point
   queries, no catalog verb).
4. **Phase 4 — catalog verb + inventory/drift:** the `xrootd_sd_enumerate_fn`
   driver verb (`sd_ceph`, `sd_pblock`) + `inventory` (E1) + `drift` (D2).
5. **Phase 5 — server-side bench** + Ceph-harness integration for all modes.

---

## 8. Scope boundaries (YAGNI — inherits base spec §9)

- **No remediation** — `drift`/`inventory` report orphans; they never delete or
  re-link. Cleanup is a separate, deliberate admin action.
- **No new `root://` opcode** — HTTP NDJSON is the only server transport;
  `verify --wire`/`bench --wire` use the existing `root://` data path client-side.
- **`bench` is opt-in** (`xrootd_scan_bench on`) and confined to a scratch root —
  it is the only mode that writes or generates load.
- **Catalog verb is optional** — backends without a native object catalog (POSIX)
  degrade gracefully; no scan-specific backend code beyond the one vtable verb.
