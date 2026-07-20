# `pblock` metadata performance — characterization & optimizations

> **Audience:** developers tuning or extending the `pblock` storage backend.
> **Scope:** the metadata (namespace) path — `mkdir`/`stat`/`chmod`/`setattr`/
> `unlink`/`rename`/`open` — *not* the bulk byte path (which never touches SQLite).
> **Companion:** [`pblock-storage-backend.md`](pblock-storage-backend.md) (the
> backend itself), [`phase-62-vfs-namespace-metadata-seam-closure.md`](../refactor/phase-62-vfs-namespace-metadata-seam-closure.md)
> (the VFS namespace seam these ops flow through).

---

## 0. TL;DR

- A concurrent GSI metadata storm (~1000 `mkdir`/create/`chmod`/`stat`/`rm` ops,
  8 sessions) runs **correct and stable** on `pblock`, but at **~2.5–2.8× lower
  throughput than POSIX** (~6 k vs ~16 k ops/s on a WSL2 loopback box) with a
  **~3× wider tail** (p99 ~6 ms vs ~2 ms).
- Flame graphs pin the cost precisely: **~54% of `pblock`'s server-worker CPU is
  inside `libsqlite3.so`**; POSIX spends **0** there and runs at the kernel-VFS
  floor. The gap *is* the catalog — one SQLite operation per metadata op.
- It is **not** catalog size (flat to 1 M entries), **not** `synchronous`
  (already `NORMAL`; `FULL`→`OFF` moves it only ~13%), and **not** WAL-checkpoint
  cadence. It is the **per-write WAL-commit vs. a single kernel syscall** — an
  architectural floor.
- Three optimizations landed (below). They **halve the lookup CPU** and cut
  SQLite's share to ~44%, with the biggest real-world win on **read/stat-heavy**
  workloads. On the deliberately write-heavy storm the throughput needle moves
  little because writes are WAL-commit-bound.
- **POSIX has nothing to optimize here** — it is already at the kernel floor.

---

## 1. How it was measured

**Workload — `tests/tools/pblock_meta_bench.c`** (built on `libxrdc`): N pthread
workers, each holding **one persistent GSI connection**, run a deterministic
per-worker subtree program — `mkdir` a small tree, `chmod` it, create files
(open `kXR_new` + close), `chmod` + `stat` each, then `rm`/`rmdir`. Default
8 workers × 125 ops ≈ 912 counted create-phase ops. JSON out: ops/sec +
p50/p95/p99. This is **Layer (a)** of the `pblock-meta-gsi` scenario in
[`tests/cmdscripts/pblock_live.py`](../../tests/cmdscripts/pblock_live.py)
(the Python port of the retired `run_pblock_meta_gsi.sh`).

**Profiling.** WSL2 has no PMU, so `perf record -F 499 -e task-clock
--call-graph dwarf,16384 -p <worker>` + Brendan Gregg's FlameGraph. To isolate
the *storage* path, profiling uses **anonymous auth** (the GSI handshake is
identical for both backends and would only add a shared crypto blob) and a high
per-connection op count so handshakes amortise. Per-symbol self-time is dominated
by `brix_session_handle_publish` purely because `-O3` inlines the dispatch
hot-path into it — the signal lives in the **per-DSO** breakdown.

> Absolute ops/s is environment-specific (WSL2 + loopback + warm cache). The
> durable signal is the **ratio** and the **CPU-by-DSO** split, not the raw
> figures.

## 2. Baseline: where the CPU goes

`perf report --sort=dso` on the worker during the storm:

| CPU by shared object | pblock | POSIX |
|---|---|---|
| `libsqlite3.so` (self) | **53.7%** | **0%** |
| nginx module (self) | 29.9% | **86.2%** |
| libc (syscalls/strings) | 16.1% | 13.5% |

The module dispatch + handler work is roughly the **same absolute cost** for both
backends; `pblock` simply carries a ~54% SQLite layer on top. POSIX runs almost
entirely in its own dispatch code plus thin kernel syscalls (`mkdirat`,
`fstatat`, `openat`, `unlinkat`, `close`).

The catalog calls driving that SQLite mass (folded-stack sample counts):

```
341  pblock_catalog_lookup   ← #1: nearly every op looks a path up first
225  sd_pblock_stat
153  pblock_catalog_put
130  sd_pblock_unlink
116  sd_pblock_open
106  sd_pblock_setattr
```

`pblock_catalog_lookup` dominates because it is called **redundantly**: the
write/existing path-existence **gate** (`src/protocols/root/path/op_path.c`) probes a path, then
the handler does its **own** lookup; a `stat` looks the same path up twice; a
create looks up parent then target; every sibling create re-probes the shared
parent. Each lookup *also* re-`prepare`s + `finalize`s a fresh statement (no
statement reuse), so a hit avoids the SQL compile *and* the B-tree descent.

## 3. What does *not* move the gap

Measured with the same storm (best-of-N), `cmdscripts.pblock_live pblock-meta-gsi` plumbing:

| Lever | Result |
|---|---|
| **Catalog size** 0 → 1,000,000 rows | **~flat** (6.8 k → 6.2 k ops/s, ~10%). The `path` PRIMARY KEY B-tree scales logarithmically. |
| **`synchronous`** `FULL`→`NORMAL`→`OFF` | only **~13%** end-to-end (5.5 k → 5.8 k → 6.2 k). Already at `NORMAL`; fsync is *not* the dominant cost. |
| **WAL `wal_autocheckpoint`** (1000 / 0 / 10000) | marginal & noisy. |

Even the most reckless config (`synchronous=OFF`, autocheckpoint disabled, zero
durability) tops out ~6.2 k ops/s — still **~2.4× slower than POSIX**. The floor
is **one transaction commit per metadata write** vs. one kernel syscall.

These two pragmas are exposed as **env tunables** (default = prior behaviour, so
backward-compatible) for characterisation / ops experiments — see
`pblock_catalog_open` in [`sd_pblock_catalog.c`](../../src/fs/backend/pblock/sd_pblock_catalog.c):

| Env var | Default | Effect |
|---|---|---|
| `PBLOCK_SYNC` | `NORMAL` | `OFF` \| `NORMAL` \| `FULL` — the WAL fsync discipline. |
| `PBLOCK_WAL_AUTOCKPT` | (SQLite 1000) | WAL auto-checkpoint threshold in pages; `0` disables. |

## 4. The optimizations

### #1 — Namespace lookup cache (`sd_pblock_catalog.c`)

A **direct-mapped `path → pblock_meta` cache** (8192 buckets, FNV-1a) sits in
front of SQLite, inside the catalog layer so it is transparent to the driver and
its invalidation is co-located with every write.

- **Positive entries only.** An absent path always falls through to SQL, so a
  create immediately after a miss stays correct (no negative caching to get
  stale).
- **Coherency via a generation counter.** A fill-after-miss installs only if no
  invalidation landed during the SQL window (`nscache_gen` snapshot →
  `nscache_store` re-checks). So a row a concurrent writer just changed can never
  be cached stale. Worker-local + mutex-guarded (the catalog is `FULLMUTEX`).
- **Invalidation:** `put` installs the new meta (`nscache_put`, bumps gen);
  `touch`/`remove` drop the entry (`nscache_inval`); `rename` reparents whole
  subtrees so it **clears** the cache (`nscache_clear`). A `calloc` failure simply
  disables the cache — lookups still work, only slower.

**Effect:** `pblock_catalog_lookup` self-CPU **halved** (341 → 171 samples),
SQLite's DSO share fell **53.7% → 46.2%**, storm throughput **+~12%**. The cache
shines most on **read/stat-heavy** workloads (`ls`, `stat`, PROPFIND), where it
turns nearly every lookup into a memory hit.

### #2 — Single-statement metadata mutations (`sd_pblock_catalog.c` + `sd_pblock.c`)

The driver previously did **read-modify-write** for two ops. Collapsed to one
statement each — no preceding `SELECT`:

- **`sd_pblock_mkdir`** → `pblock_catalog_create`: a plain `INSERT`; the
  `path` PRIMARY KEY **constraint** is the existence check (`SQLITE_CONSTRAINT`
  → `EEXIST`). Was `lookup` + `INSERT OR REPLACE`.
- **`sd_pblock_setattr`** (kXR_chmod / kXR_setattr) → `pblock_catalog_setattr`:
  one `UPDATE … SET ctime=?, mode = CASE WHEN ? THEN (mode & 61440)|(perm & 511)
  …, mtime = CASE WHEN ? …` (61440 = `S_IFMT`, 511 = `0777`, so the type bits are
  preserved and the permission triad replaced — exactly the prior math).
  `changed == 0` → `ENOENT`. Was `lookup` + modify + `INSERT OR REPLACE`.

**Effect:** `pblock_catalog_put` samples **166 → 68** (those callers moved off
`put`), SQLite share **46.2% → 44.1%**, statement count down. Throughput on the
write-heavy storm is within run-to-run noise — the number of **WAL commits** is
unchanged (one write is still one commit); #2 removes the *reads* before those
writes and lowers CPU, which is the win on busier / multi-tenant workers.

> **POSIX impact: none.** #2 is entirely inside `src/fs/backend/pblock/`. The
> POSIX driver and confined-canon helpers are untouched.

### #3 — Skip the redundant existence gate for non-POSIX exports (`src/protocols/root/path/op_path.c`)

For an `EXISTING`-mode op (`stat`/`rm`/`chmod`/`setattr`/`truncate`), the gate's
probe is redundant with the operation's own driver call, which already returns
`ENOENT` → `NotFound`. `op_path_existence_gate` now **skips that probe when a
non-POSIX backend is bound** (`brix_vfs_backend_resolve(root_canon) != NULL`):

- **Gated to non-POSIX** — the default POSIX export keeps the probe verbatim, so
  POSIX behaviour (and its existence-before-auth ordering) is **byte-identical**.
- **`WRITE`-mode is untouched** — the parent-directory existence check stays,
  because `pblock`'s `mkdir`/`create` does **not** enforce parent existence
  itself (skipping it would let `mkdir /missing/child` create an orphan). Verified:
  `mkdir` into an absent parent still returns `NotFound` on `pblock`.
- **One caveat, by design:** for a non-POSIX export an *unauthorized* probe of an
  *absent* `EXISTING` path now returns `403` (auth runs first) instead of `404`
  (existence-first). This is a *reduction* in existence disclosure — a security
  improvement — and only affects non-POSIX exports. Authorized/anon callers still
  get `NotFound`.

Smallest of the three once #1 is in (the gate probe is now a cache hit anyway),
but it removes the gate's `vctx` setup + cached lookup per `EXISTING` op.

## 5. The residual gap — and the only levers left

After #1–#3, `pblock` is **~44% SQLite** and the metadata storm is
**write-bound**: each metadata *write* (`create`, `setattr`, `unlink`, `mkdir`)
is one SQLite **transaction commit** (WAL append + an fsync at `synchronous=
NORMAL`); POSIX does **one kernel syscall**. That difference is the ~2.5× floor
and no read-side caching, statement-collapsing, or durability pragma closes it.

The only changes that *would* move it are architectural and were **not** taken
(they trade correctness/durability or add machinery):

- **Coalesce many writes into one transaction** — a per-worker write-back batch
  that commits N namespace mutations together, amortising the WAL fsync. Needs a
  flush policy + crash-consistency story (a batch lost on crash must be
  recoverable or bounded).
- **Relax durability** (`PBLOCK_SYNC=OFF`) — ~13% for a real durability loss;
  not a default.
- **A non-SQLite namespace** (e.g. an LSM or a custom B-tree) — a different
  backend, not a tune.

For the common **read/stat-heavy** metadata pattern, #1 already brings `pblock`
much closer to POSIX; the write-heavy storm is the worst case and the one quoted
above.

## 6. Reproducing

```bash
# correctness + the 3-layer storm (GSI), incl. chmod-persist + nested-mkdir guards
# (run from tests/; also exercised by pytest tests/test_cmd_pblock_live.py)
python3 -m cmdscripts.pblock_live pblock-meta-gsi
python3 -m cmdscripts.pblock_live --selftest  # success / fault / GSI-negative

# A/B a durability knob (env read at catalog open)
PBLOCK_SYNC=OFF  python3 -m cmdscripts.pblock_live pblock-meta-gsi
PBLOCK_WAL_AUTOCKPT=0 python3 -m cmdscripts.pblock_live pblock-meta-gsi

# flame graph of the server worker (task-clock + dwarf; needs ~/FlameGraph)
#   start a pblock server, then:
perf record -F 499 -e task-clock --call-graph dwarf,16384 -p <worker_pid> -- sleep 25
perf script | ~/FlameGraph/stackcollapse-perf.pl | ~/FlameGraph/flamegraph.pl > pblock.svg
perf report --sort=dso        # the headline: libsqlite3.so self-%
```

## 7. Invariants for future changes

1. **The hot byte path must never touch SQLite** (unchanged here — these are all
   metadata ops). Block-0 fd + `sendfile` stay as in the main doc.
2. **Cache coherency is load-bearing.** Any new code that mutates the `objects`
   table MUST go through `pblock_catalog_{put,create,setattr,touch,remove,
   rename}` (each invalidates/installs) — never a raw `INSERT/UPDATE/DELETE` on
   `objects` that bypasses the cache. The `pblock-meta-gsi` chmod-persist guard
   and `pblock-root` byte-exact checks (both `cmdscripts/pblock_live.py`
   scenarios) catch a stale cache.
3. **#3's gate skip is non-POSIX-only and EXISTING-only.** Do not extend it to
   `WRITE` mode — `pblock` relies on the gate for parent-existence.
4. **Measure by DSO, not by symbol** — `-O3` inlining hides the real split behind
   `brix_session_handle_publish`.
