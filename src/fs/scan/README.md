# `src/fs/scan/` — bulk storage scan / verify / inventory engine

A throttled, confined, streaming, resumable, **backend-neutral** engine that
enumerates storage and runs a per-object action, streaming one NDJSON record per
object to an admin. Drives POSIX, pblock, S3 and **Ceph/RADOS** identically,
because every filesystem touch goes through the VFS seam (`brix_vfs_*`) — no
backend symbol appears here.

Design: [`../../docs/superpowers/specs/2026-06-29-storage-scan-verify-design.md`](../../docs/superpowers/specs/2026-06-29-storage-scan-verify-design.md)
and the folded sysadmin-tooling menu
[`../../docs/superpowers/specs/2026-06-29-client-backend-sysadmin-tooling-design.md`](../../docs/superpowers/specs/2026-06-29-client-backend-sysadmin-tooling-design.md).

## Layering

`scan_record`, `scan_throttle`, `scan_emit` (and the orchestration in
`scan_engine`) are **ngx-free and protocol-agnostic** — they take a `rootfd`, a
parsed options struct, and an emit callback. `scan_http.c` is the *only*
nginx-coupled file; it owns the `ngx_http_request_t`, admin auth, param parse,
and chunked NDJSON output. This boundary lets a future `root://` scan opcode
reuse the engine unchanged.

## Files

| File | Role | Tested by |
|---|---|---|
| `scan_record.{c,h}` | NDJSON line formatting (`file`/`cursor`/`summary`) + JSON string escaping | `scan_unittest.c` |
| `scan_throttle.{c,h}` | token-bucket byte-rate math, budget check, adaptive multiplier | `scan_unittest.c` |
| `scan_emit.{c,h}` | ordered reorder buffer — out-of-order worker completion emits in walk order (monotonic cursor) | `scan_unittest.c` |
| `scan_drift.{c,h}` | namespace↔catalog reconciliation set (D2): seed catalog keys, stream namespace to classify in-both/size-mismatch/namespace-only, then surface unmatched catalog keys (orphan objects). O(catalog) memory | `scan_unittest.c` |
| `scan_engine.{c,h}` | VFS-driven walk (`brix_vfs_walk`) + per-file action dispatch (`dump`/`verify`/`fill`/`compare` via `brix_integrity_get_fd`); appends NDJSON via `scan_record` | `tests/test_scan.py` (HTTP) |
| `scan_http.c` | admin HTTP endpoint `GET /xrootd/api/v1/scan`: auth, param parse, `openat2` confinement, buffered NDJSON body | `tests/test_scan.py` |

## Endpoint

`GET /xrootd/api/v1/scan?mode=dump|verify|fill|compare|inspect|health&path=<rel>&alg=<name>&max_files=<n>`
— admin-auth (same gate as the dashboard file browser), confined under
`brix_scan_root`. `dump`/`verify`/`fill`/`compare`/`inspect` emit one record per
object + a final `summary`; `health` emits a single capacity record. Config:

```nginx
location /xrootd {
    brix_dashboard on; brix_dashboard_password "...";
    brix_scan_root      /export;   # empty (default) ⇒ endpoint 404 (disabled)
    brix_scan_max_files 100000;    # operator cap per request
}
```

## Status

- **Phase 2a (done):** the three ngx-free cores, TDD'd, run standalone
  (`tests/test_scan.py::test_scan_core_suite` — no server):
  ```
  gcc -Wall -Wextra -Werror -I src/fs/scan -o /tmp/scan_ut \
      src/fs/scan/scan_unittest.c src/fs/scan/scan_record.c \
      src/fs/scan/scan_throttle.c src/fs/scan/scan_emit.c -lm && /tmp/scan_ut
  ```
- **Phase 2b (done):** `scan_engine.c` + `scan_http.c` + the `brix_scan_root`/
  `brix_scan_max_files` directives + `./config` registration. HTTP integration
  covered by `tests/test_scan.py` (dump/verify/fill, bit-rot mismatch detection,
  auth-401, disabled-404, bad-mode-400, traversal confinement). v1 runs the walk
  **synchronously** in the request (bounded by `brix_scan_max_files`, opt-in,
  admin-only — same risk class as the synchronous admin file browser).
- **Phase 2b follow-on:** off-load the walk to the thread pool + chunked
  streaming + the byte-rate throttle (the `scan_throttle`/`scan_emit` machinery is
  already in place).
- **Client (done):** `xrdstorascan dump|verify|fill|compare|inspect|health
  <dashboard-url>` (HTTP consumer of the endpoint; `verify`/`compare` exit 1 on a
  bit-rot mismatch). `verify` with a `root://` URL stays the client-side
  end-to-end check.
- **Phase 3 (done):** `inspect` (A2 — per-file backend/stat/checksum-source +
  `namespace_consistent`) and `health` (C1 — `statvfs` capacity). These report the
  **POSIX view** of `brix_scan_root`: the engine walks the export via `openat2`,
  not the SD-driver seam, so `backend` is `"posix"`. Driver-bound introspection
  (Ceph object key, cluster `HEALTH_OK`/OSDs) requires routing the scan through
  the VFS driver — a **Phase 4** prerequisite shared with the catalog verb
  (`inventory`/`drift`).
- **Phase 4a (done):** the `scan_drift` reconciliation core (the D2 set
  algorithm), TDD'd standalone (in `scan_unittest.c`).
- **Phase 4b (next, needs a backend + driver binding):** the SD-driver
  `enumerate`-catalog vtable verb (`rados_nobjects_list` for Ceph; blob-vs-catalog
  for pblock) + a driver-agnostic `brix_vfs_enumerate_catalog()` wrapper
  (`ENOTSUP` when absent), then `inventory` (E1) + `drift` (D2) modes that bind
  the scan endpoint to the export's driver and reconcile via `scan_drift`. The
  payoff (orphan detection) is cross-backend and is best verified on the phase-60
  single-node Ceph harness — so the verb + HTTP wiring land together with that
  harness rather than as untested scaffolding here.

New source files register in the top-level `./config`
(`$ngx_addon_dir/src/fs/scan/...`), then `rm -rf objs && ./configure && make`.
The standalone `scan_unittest.c` is **not** built into the module.
