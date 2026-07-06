# Read-Cache Partial-Fill Test Suite — Design

**Status:** DESIGN (approved 2026-07-01) — awaiting spec review before writing-plans
**Owner:** Rob Currie
**Scope:** a new pytest suite (~22–24 tests) + one small client tool that verify, per
modular backend and per cache config, exactly **what a partial (range) read writes into
the read cache** — sparse block fill vs. whole-file fill vs. nothing.

---

## 1. Goal

Answer, with executable + deterministic tests: *"Are partial reads written to the cache,
and which bytes, depending on the cache config and the backend FS type?"*

Concretely, for each `(backend, cache-config, read-pattern)` combination, assert the exact
cache residency after the read — the `.cinfo` **present-bitmap** (which blocks are cached)
and the `COMPLETE`/`PARTIAL` flag — plus a behavioral confirmation that the cached bytes
serve with the backend removed.

## 2. Background — the mechanism (verified in the tree)

- The cache records residency in a per-object `.cinfo` sidecar (`src/fs/cache/cinfo.h`,
  magic `XCI1`, version 3): a fixed LE header (`flags`, `block_size`, `size`, `nblocks`,
  …) followed immediately by a present-bitmap of `ceil(nblocks/8)` bytes.
  Flags: `F_COMPLETE 0x1` (every block present), `F_PARTIAL 0x2` (some, not all).
- **Sparse partial fill** is done by the generic `sd_cache` slice decorator
  (`xrootd_sd_cache_create(src, store, policy, …)` in `src/fs/backend/cache/sd_cache.c`),
  whose `policy.slice_size` drives fixed-block sparse fill → a range read marks only the
  touched blocks (`F_PARTIAL`).
- **The wiring gap (drives the Hybrid decision):** `src/fs/cache/cache_storage.c` only builds
  that decorator when `cache_slice_size > 0 && cache_origin_host.len > 0`, and hardwires the
  source to `xrootd_sd_xroot_create_origin(...)` — i.e. **partial fill is currently wired
  only for a `root://` (xroot) origin** configured via `xrootd_cache_origin HOST:PORT`.
  Every other backend (posix/pblock/http/s3/rados as `xrootd_storage_backend`) takes the
  default **whole-file fill** path ("SP1 whole-file caching", `src/fs/cache/open_or_fill.c` →
  `COMPLETE`); `cache_slice_size` is silently ignored for them.

So current behavior:

| Cache source                              | Partial read writes to cache |
|-------------------------------------------|------------------------------|
| `xrootd_cache_origin` (root:// origin) + `cache_slice_size` | **sparse** — only touched blocks (`PARTIAL`) |
| `xrootd_storage_backend {posix,pblock,http,s3,rados}`       | **whole file** (`COMPLETE`), slice ignored |
| any source, size over `cache_max_file_size`/`cache_max_object` | **nothing** cached |
| any source, path excluded by admission (`deny_prefix`/`include_regex`) | **nothing** cached |

## 3. Scope decisions (from brainstorming)

- **Backends:** all — posix, pblock, xroot-origin always-on; http/s3/rados gated
  (`pytest.skip` when the origin/env/Docker is absent).
- **Config axes:** slice-vs-whole-file (core), `cache_slice_size` values, `cache_max_file_size`
  / `cache_max_object` (size gate), admission (`cache_deny_prefix` / `cache_include_regex`).
- **Verification:** cinfo present-bitmap (exact blocks + `PARTIAL`/`COMPLETE`) **and** a
  behavioral confirm (hide backend, re-read).
- **Direction (Hybrid):** the suite documents *current* behavior now — xroot → real
  `PARTIAL` asserts; other backends → `COMPLETE` asserts marked `xfail(reason=…)` so they
  flip green automatically when the generic-slice wiring lands (§7). No production behavior
  change in this task except the additive read-only `xrdcinfo` tool.
- **Tooling:** pytest matrix (Approach A) **plus** a small faithful C dumper (Approach C).

## 4. Component 1 — `xrdcinfo` cache-residency dumper (client tool)

A single-purpose, read-only CLI: `client/apps/xrdcinfo.c` → `client/bin/xrdcinfo`,
registered by adding `xrdcinfo` to `BINS` in `client/Makefile:141` (built via the existing
generic `$(BINDIR)/%: apps/%.o $(CLIENT_LIB)` rule).

- **Usage:** `xrdcinfo <path-to.cinfo>` — dump a sidecar; `xrdcinfo --xattr <object>` — read
  the `user.xrd.cinfo` xattr of a cache object instead.
- **Faithfulness:** reuses the on-disk layout from `src/fs/cache/cinfo.h` (the `XCI1`/v3 struct
  + magic). If `cinfo.h` is not ngx-free-includable, the tool carries a minimal standalone
  mirror of the frozen versioned header (the format is version-stable). It validates
  `magic == XCI1` and `version == 3`, then locates the present-bitmap as the **trailing
  `ceil(nblocks/8)` bytes** of the file (padding-proof; no dependence on `sizeof` layout).
- **Output (JSON, one object, stdout):**
  ```json
  {"version":3,"flags":["PARTIAL"],"block_size":65536,"size":300000,
   "nblocks":5,"present_count":2,"present_blocks":[1,2],"complete":false}
  ```
  On a missing file/record: exit code 3 and `{"absent":true}`. On a bad magic/version:
  exit code 2 and `{"error":"bad_magic"|"bad_version"}`.
- **Unit test:** `tests/c/test_xrdcinfo.sh` (or a case in the python suite) feeds it a
  live-produced sidecar and a hand-crafted `COMPLETE` sidecar and checks the JSON — proves
  the dumper before the suite relies on it.

## 5. Component 2 — Test harness (`tests/_cache_partial_helpers.py`)

Shared fixtures/helpers, modeled on `tests/test_cache_write_through.py`
(`_establish_session`) and the `tests/run_cache_*.sh` config shapes.

- `make_cache_node(backend, *, slice_size=None, max_file_size=None, max_object=None,
  deny_prefix=None, include_regex=None, meta="local", tmp)` → renders a composable cache
  nginx config, starts it on a dedicated high port, yields
  `CacheNode(cache_port, cache_store_dir, backend_handle)`. Config skeleton:
  ```
  stream { server {
      listen 127.0.0.1:<CACHE_PORT>; brix_root on; xrootd_auth none;
      xrootd_cache on;
      xrootd_cache_store posix:<STORE>;   xrootd_cache_root /;
      xrootd_cache_meta  local;           # force the .cinfo sidecar (inspectable)
      <BACKEND-WIRING>                     # per-backend, see below
      [xrootd_cache_slice_size <N>;]
      [xrootd_cache_max_file_size <N>;] [xrootd_cache_max_object <N>;]
      [xrootd_cache_deny_prefix <P>;] [xrootd_cache_include_regex <RE>;]
  } }
  ```
  Per-backend `<BACKEND-WIRING>`:
  - **xroot (partial path):** start a `root://` origin (a plain posix or pblock nginx on
    its own port), then `xrootd_cache_origin 127.0.0.1:<ORIGIN_PORT>;` — this sets
    `cache_origin_host`, the only path that composes the slice decorator. The origin's own
    backend is parametrizable (posix-origin / pblock-origin) to show partial fill is
    independent of what sits behind the root:// origin.
  - **posix / pblock (whole-file path):** `xrootd_storage_backend posix:<DIR>;` /
    `xrootd_storage_backend pblock://<DIR>/;`.
  - **http / s3 / rados (gated):** `xrootd_storage_backend http://… | s3://… | rados://…;`
    behind an availability probe; `pytest.skip` when the origin/Docker/env is absent.
- `kxr_open(sock, path)` + `kxr_read(sock, fh, off, length)` → raw-wire `kXR_open`(3010) /
  `kXR_read`(3013) built on the file's existing `_establish_session`/`_recv_exact` helpers;
  returns the exact bytes so tests can also assert byte-correctness of the served range.
- `residency(cache_store_dir, key)` → find the object's `.cinfo` under the store, run
  `client/bin/xrdcinfo`, parse the JSON → dict `{flags, block_size, nblocks,
  present_blocks, present_count, complete}` or `{"absent": True}`.
- `hide_backend(node)` / `restore_backend(node)` → stop (or firewall) the origin/backend
  for the behavioral confirm, then restore.
- `seed(node, path, size)` → write a deterministic pattern file into the backend/origin so
  block contents are predictable and byte-checkable.

## 6. Component 3 — Test matrix (`tests/test_cache_partial_fill.py`, ~22–24 tests)

Parametrized from a compact table. Block indices below assume `slice_size = 64 KiB`.

**Group 1 — xroot origin sparse partial fill (real `PARTIAL` asserts, 8):**
1. `test_single_block_range_marks_one_block` — read `[0, 64K)` → `PARTIAL`, `present=[0]`.
2. `test_midfile_range_marks_correct_index` — read `[128K, 192K)` → `present=[2]` (not 0).
3. `test_cross_boundary_range_marks_two_blocks` — read `[32K, 96K)` → `present=[0,1]`.
4. `test_whole_file_read_marks_complete` — read `[0, size)` → `COMPLETE`, all bits set.
5. `test_two_disjoint_ranges_accumulate` — read `[0,64K)` then `[192K,256K)` →
   `present=[0,3]` (bitmap is a union across reads).
6. `test_eof_partial_last_block` — read the final partial block → its bit set, `PARTIAL`.
7. `test_slice_size_64k_vs_1m[64k]` / `[1m]` — same byte range `[100K,200K)` under two
   `slice_size` values → different `present_blocks` and `block_size` (2 params).
8. (param of #7) covers the second size — counts as its own test node.
   *Origin-backend param:* Group-1 runs with a `posix-origin` and a `pblock-origin` behind
   the root:// origin to show partial fill is backend-independent behind xroot.

**Group 2 — whole-file backends, current behavior (4, `xfail`-marked "generic slice pending"):**
9.  `test_posix_backend_partial_read_is_whole_file` — posix backend, read `[0,64K)` →
    `COMPLETE` (documents SP1).
10. `test_pblock_backend_partial_read_is_whole_file` — pblock backend → `COMPLETE`.
11. `test_posix_slice_size_is_ignored` — posix backend **with** `cache_slice_size` set,
    partial read → still `COMPLETE` (proves slice is ignored off the xroot path — the key
    "depends on config" gap). `xfail(strict=True)` flips to expect `PARTIAL` when wired.
12. `test_pblock_slice_size_is_ignored` — same for pblock.

**Group 3 — size + admission negatives, generic (5):**
13. `test_oversized_file_not_cached[max_file_size]` — file > `cache_max_file_size`, xroot
    partial read → residency `absent`.
14. `test_oversized_file_not_cached[max_object]` — file > `cache_max_object`, whole-file
    backend read → residency `absent`.
15. `test_within_cap_is_cached` — file ≤ cap → cached (`COMPLETE` or `PARTIAL` per path).
16. `test_deny_prefix_excludes_path` — path under `cache_deny_prefix`, read → `absent`.
17. `test_include_regex_excludes_path` — path not matching `cache_include_regex` → `absent`.

**Group 4 — behavioral confirm (3):**
18. `test_cached_block_serves_with_backend_hidden` — xroot: read `[128K,192K)`, hide origin,
    re-read the same range → byte-exact from cache.
19. `test_uncached_block_misses_with_backend_hidden` — same node, re-read an *unfilled*
    range with the origin hidden → miss (error / short / refetch failure), proving the
    bitmap gates what serves.
20. `test_whole_file_backend_serves_any_range_offline` — posix backend, read once
    (`COMPLETE`), hide backend, re-read an arbitrary range → served.

**Group 5 — gated heavier backends (3, skip if env absent):**
21. `test_http_backend_partial_read_is_whole_file` — http origin → current `COMPLETE`
    (`xfail` pending, `skip` if no http origin).
22. `test_s3_backend_partial_read_is_whole_file` — s3 origin → `COMPLETE` (skip if no S3 env).
23. `test_rados_backend_partial_read_is_whole_file` — rados origin → `COMPLETE`
    (skip if no Docker/librados).

**Total:** 23 test nodes (Group 1 expands via the `slice_size` and origin-backend params to
comfortably exceed 20 runnable nodes), plus the `xrdcinfo` unit check.

## 7. Component 4 — Tracked follow-up (documented, NOT built here)

`docs/refactor/phase-64-generic-slice-fill.md` (short): the single wiring change to compose
the `sd_cache` slice decorator over the **generic** `cache_storage_inst` source (not just
the xroot origin) when `cache_slice_size > 0`, per phase-64 P3 ("keep the cache generic —
no driver `strcmp`"). Notes the acceptance signal: the Group-2/5 `xfail(strict=True)`
assertions flip from `COMPLETE` to `PARTIAL` with no test rewrite. This file is the record
of the gap; implementing it is a separate spec→plan→build cycle.

## 8. File layout & build registration

| Path | Kind | Note |
|---|---|---|
| `client/apps/xrdcinfo.c` | new | the dumper |
| `client/Makefile` | edit | add `xrdcinfo` to `BINS` (line 141) |
| `tests/_cache_partial_helpers.py` | new | fixtures/helpers |
| `tests/test_cache_partial_fill.py` | new | the matrix |
| `tests/c/test_xrdcinfo.sh` | new | dumper unit check |
| `docs/refactor/phase-64-generic-slice-fill.md` | new | follow-up record |
| `tests/run_suite.sh` | edit (maybe) | `test_cache_partial_fill.py` is parallel-safe; the
  gated backends self-skip, so no lane change is expected. |

## 9. Error handling, gating, isolation

- **Gating:** http/s3/rados fixtures probe availability first and `pytest.skip("<backend>
  origin not available")` — never fail — when the env/Docker is absent.
- **Isolation:** each node uses a dedicated high port (allocated via `free_ports`, ≥ the
  suite's reserved band) and its own `tmp` cache-store + backend dirs, torn down per test.
  No reliance on the shared managed fleet, so runnable with `TEST_SKIP_SERVER_SETUP=1`.
- **cinfo absence:** `residency()` treats "no `.cinfo`" and `xrdcinfo`'s `{"absent":true}`
  identically → the negative tests assert `absent` without special-casing.
- **Determinism:** `seed()` writes a fixed byte pattern; reads assert both the bitmap and
  the returned bytes; `slice_size` and offsets are chosen so block indices are exact.

## 10. Out of scope

- Implementing generic-slice wiring (§7) or any production behavior change.
- Write-back / staging cache paths (covered by `test_cache_write_through.py` and the
  `run_cache_wt_*` suite).
- Eviction / watermark / reaper behavior (covered by `run_cache_watermark*.sh`,
  `test_cache_reap_metrics.py`).
- Checksum-on-fill verification (covered by the pelican/verify tests).

## 11. Success criteria

- `xrdcinfo` builds into `client/bin/` and its unit check passes.
- `PYTHONPATH=tests python -m pytest tests/test_cache_partial_fill.py -v` yields ≥ 20 run
  nodes green (xroot `PARTIAL` groups + generic negatives + behavioral), with the whole-file
  backend "slice ignored" nodes reported `xfail` (documented gap), and heavier backends
  `skip` when their env is absent.
- Every assertion is deterministic on a quiet box (no timing/flake dependence) and the
  gated backends never *fail* on an environment without them.
