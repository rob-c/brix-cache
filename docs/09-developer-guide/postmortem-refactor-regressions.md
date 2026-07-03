# Postmortem: refactor-era regressions and how to prevent them

**Date:** 2026-06-27
**Scope:** bugs surfaced while bringing the full test suite green during the large
in-flight refactor (file splits across `copy.c`, `registry.c`, `propfind.c`,
`ssi.c`, the VFS/cache data plane, `session/`, and the client umbrella headers).

This is a *class*-level retrospective, not a single incident. Each section is a
distinct failure mode with its root cause and the concrete guardrail that stops it
recurring. The checklist at the end is the pre-merge gate for finishing the
refactor.

---

## 1. Data-plane offset conflation — HIGH (silent data corruption)

**What broke.** `brix_cache_origin_read_chunk()` used a single `offset`
parameter for *both* the origin **read** position and the local **write**
position, and wrote each reply at the per-call counter `*got` (which resets to 0
every `BRIX_CACHE_FETCH_CHUNK` = 1 MiB).

- Whole-file fetch (`fetch.c`): every chunk after the first re-wrote at file
  offset 0, so **any cached file larger than 1 MiB was corrupted and truncated**.
  Only the checksum-on-fill verify caught it (adler32 mismatch) — without that
  verify the cache would have silently served corrupt data.
- The first fix (make the write absolute, `offset + *got`) then **regressed the
  slice fill** (`slice_fill.c`), which reads at an *absolute* origin offset but
  writes into a *0-relative* per-slice `.part` file.

**Why it slipped.** The only test that exercises a >1 MiB cache fill
(`integrity_matrix[rt-cache-root]`) and the slice tests both live deep in the
suite; every `-x` run stopped at an earlier failure and never reached them.

**Prevention.**
- A routine that copies bytes from a remote source into a local file **must take
  the read offset and the write offset as separate parameters.** Never reuse one
  variable for both. (Final shape: `read_chunk(..., read_off, dst_off, ...)`.)
- Any chunked copy loop needs a test with input **larger than the chunk size**
  (multi-chunk), and partial/slice writers need a test where the destination base
  differs from the source base.
- Keep **checksum-on-fill verification ON** in the cache test topologies — it is
  the last line of defense against fill corruption.

## 2. A working tree that does not compile, masked by stale objects — HIGH

**What broke.** `session/lifecycle.c` had `req.` where a pointer required `req->`
(a formatter/linter mangled the `->`). The working tree **did not compile**, but
incremental `make` reused the stale `.o`, so nginx "built" and ran the *old*
object for many iterations — every behavioral test ran against code that was no
longer what the source said.

**Prevention.**
- Before trusting a build, confirm the changed translation units actually
  recompiled. When results look stale or shared headers changed, do a clean
  rebuild of the affected subtree (`make clean` / touch-all), not just incremental.
- The auto-formatter/linter must **not** run on `.c/.h` — it has repeatedly
  injected docblocks and flipped `->`/`.` (see the linter-corruption notes). If it
  must run, gate it behind a compile check.
- CI must build from a **clean object tree** so a non-compiling working tree fails
  fast instead of hiding behind cached `.o` files.

## 3. File-layout-coupled guardrail / marker tests — MEDIUM (false failures)

**What broke.** Dozens of "assert marker `M` is present in file `F`" guardrails
failed purely because the refactor moved code: `registry.c` → `registry_health.c`
/ `registry_select.c`; `propfind.c` → `propfind_props.c` / `propfind_walk.c` /
`propfind_internal.h`; webdav status-code test classes → the `_b` split;
`gsi_core.c` → `gsi_cipher/rsa/buf/dh.c`; multipart `#include` amalgamation →
separate `config` compilation units.

**Prevention.**
- When you split a file, `grep` the **test tree** for the old path/symbol and
  update the guardrails in the *same* commit.
- Prefer guardrails that assert a marker exists somewhere in a **module
  (directory glob)** over a specific file when the intent is "this helper is used,"
  not "it lives in this exact file."
- These guardrail files are pure file reads (≈instant) — run them as a fast
  pre-merge gate on any file-moving change.

## 4. Tests built against installed / standalone artifacts — MEDIUM

**What broke.**
- The `libxrdc` demo could not find `protocol/codec/wire_codec.h` nor the umbrella
  `xrdc_net.h` / `xrdc_auth.h` / `xrdc_ops.h` — the `install` target was not
  updated when `protocol.h` / `xrdc.h` gained those `#include`s.
- The slice standalone unit test failed to link `ngx_cached_time` (meta.o gained
  an `ngx_time()` call) and `brix_cache_cinfo_path` (slice.o gained the call).

**Prevention.**
- When a *public* header gains an `#include`, update the install target to ship
  the included header in the same change. A "compile a tiny consumer against the
  installed prefix" smoke test catches the whole class.
- When module code gains a new external symbol, update the standalone unit-test
  stubs / link list in the same change.

## 5. Zero-copy `splice()` over edge-triggered epoll — MEDIUM (latency stalls)

**What broke.** The `root://` proxy spliced *streamed* (not-fully-buffered) read
bodies. When the body had not all arrived, the pump handed the remainder to a
buffered relay, but the EPOLLET edge does not reliably re-fire after `splice()`
drains a socket → ~1–2% of reads stalled until the 30 s `proxy_read_timeout`.
Over two stacked proxy hops (the "mesh" topology) this turned into intermittent
conformance timeouts.

**Prevention.**
- Only `splice()` a body that is **already fully buffered** in the socket
  (`FIONREAD >= dlen`); use the buffered relay for streamed data. Do **not** rely
  on the ET edge re-firing after a `splice()` drains the socket.
- Topology/mesh conformance must be run **repeatedly (or under load)** — a single
  pass hides a 1–2 % tail-latency stall.

## 6. Server-vs-stock behavior parity — MEDIUM

**What broke.**
- `open(kXR_open_updt)` of a *missing* file **created** it via resume staging,
  diverging from stock (which returns `kXR_NotFound` — `updt` alone has no
  `O_CREAT`). The staging/resume path bypassed the open-flag→POSIX invariant.
- SSI multi-write dispatched on the **first** write instead of accumulating until
  the read, so a second write was rejected `kXR_FileLocked`.

**Prevention.**
- Keep the differential conformance tests pinned against stock for write-open flag
  semantics and SSI; any refactor that changes a *dispatch trigger* or a *staging*
  decision must re-run them.
- The invariant "`kXR_open_updt` alone ⇒ `O_RDWR`, no `O_CREAT`" must hold on the
  staging/resume path too, not just the direct-open mapping.

## 7. FUSE create over a staging server — MEDIUM

**What broke.** The server stages writes, so a just-created file's *final* path is
not visible to `stat` until close. The FUSE `getattr` issued right after `create`
returned `ENOENT`, failing **every** FUSE create/write.

**Prevention.** A client whose `getattr` can be invoked with an open write handle
must report the *open handle's* state when the staged final path is not yet
visible (track a write high-water on the handle).

## 8. Batch / concurrency temp-name collisions — LOW-MEDIUM

**What broke.** The VFS POSIX temp name used the pid only; `xrdcp -j` batch
workers are threads sharing one pid, so two same-basename destinations collided on
an identical temp and failed `O_EXCL` (`File exists`).

**Prevention.** Any process-shared temp name needs a **per-call atomic counter**
(or tid), not just the pid. Mirror the existing `copy_local.c::make_temp_path`
pattern (`<dst>.tmp.<pid>.<seq>`).

---

## Test-running hygiene (process, not code)

- **Run the suite without `-x` periodically.** `-x` masks every deterministic
  failure after the first; that hid the slice-cache and digest-range failures for
  many iterations.
- **After fixing a shared helper, run every test that touches that module**, not
  just the one that failed. The cache-fill fix regressed a *sibling* caller
  (slice fill) that a single-test re-run would not have caught.
- **Two-lane split.** Run destructive suites (`chaos*`, `evil*`, `*_resilience`,
  `resilience/`) and resource-heavy ones (`clientconf_*`, which forks many xrdcp
  subprocesses) **serially / `-n0`**; run the rest in parallel. Under the parallel
  pool, the conformance `dirlist` tests race on the shared export root (and cascade
  into the four `topology[*]` runs) — known flakes, green in isolation.
- **Seed generation:** use `random.randbytes()` / `rng.randbytes()`, not
  `bytes(rng.getrandbits(8) for _ in range(n))` — the latter cost ~11 s per
  (wiped) session generating `large200.bin`.

## Running the suite as a reliable source of truth (`tests/run_suite.sh`)

The full suite (~6900 tests) is a real-server integration suite, so a fraction of
tests are **load-correlated flaky**: under a saturated parallel pool, shared
single-worker daemons (the fleet nginx, the reference xrootd, the XrdHttp server)
respond slowly enough that ~0.3% of tests transiently `ConnectionReset`/time out —
a *different* set each run. These are environmental, not product bugs.

`tests/run_suite.sh` makes the suite a trustworthy pass/fail signal:

1. **Lane split.** A few dozen tests genuinely cannot share the pool — they assert
   timing/throughput ratios (`test_concurrent`, `test_throughput`,
   `*_performance_conformance`, `test_proxy_large_read`), drive a multi-node mesh
   (`test_cms_mesh_interop`), spawn nested conformance runs that hammer the shared
   reference (`test_conformance_topologies`), or drive a shared XrdHttp/VOMS daemon
   (`test_xrdhttp_wait_retry_digest_range`, `TestVomsExtraction`). These are
   `@pytest.mark.serial` and run in their own lane. Destructive suites (chaos/evil/
   `*_resilience`/netfault) self-start FIXED-port instances → serial lane.
   `clientconf` forks many subprocesses → its own `-n2` lane. `tests/userns/` needs
   privileges → excluded.
2. **Escalating `--lf` re-run.** After each lane's main pass, re-run ONLY the
   failures on a now-quiet box (`--lf -n2`, then serial). A load flake passes when
   run alone; a REAL bug fails even quiet and is reported red. Observed: this
   clears 5–15 transient flakes per run with zero human triage. Do NOT use inline
   `--reruns` for these — the flakes are load-correlated, so an immediate in-process
   retry stays inside the same saturated window and fails too.

Wall: ~14 min, overall PASS, reproducibly. The bulk parallel lane (the common-case
fast feedback) is ~3–4 min. The remaining wall is bounded by the inherently-slow
serial tests (a 65s dynamic-module build, throughput measurements, chaos/topology);
they cannot be parallelized or shortened without weakening what they verify.

If you ever need to speed the full run materially, the only lever left is reducing
shared-daemon contention at the source (e.g. the fleet's `worker_processes 1`) —
but that changes single-worker semantics several tests assume, so validate
carefully before touching it.

## Pre-merge checklist for finishing the refactor

- [ ] Clean build (no cached objects) of `src/` and `client/`.
- [ ] Full suite **without `-x`** at moderate parallelism; triage each failure in
      isolation (real vs xdist-contention flake).
- [ ] All guardrail / marker test files green (`test_phase*`, `test_plan*`,
      `test_cross_protocol_shared_helpers*`).
- [ ] `libxrdc` install + demo smoke build green; the `slice` and `gsi` standalone
      unit tests green.
- [ ] Cache integrity tests with files **>1 MiB** (whole-file *and* slice) green.
- [ ] `topology[mesh]` run several times to rule out tail-latency stalls.
