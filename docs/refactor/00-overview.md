# Intent-Centric Architecture Refactor — Master Overview

**Date:** 2026-06-11  
**Author:** architecture audit  
**Status:** IN PROGRESS — most phases have landed in `src/`. This file is the
master index for the refactor series; treat the code as authoritative where a
phase doc and `src/` disagree.

> **2026-06-13 archival note:** the implementation plans for fully-landed phases
> (1, 7, 9, 10, 12–17) and the resolved/superseded Phase-29 working notes were
> moved to [`../_archive/refactor/`](../_archive/refactor/) — the work is done, so
> those plans are now history. The phase docs that remain here are active design
> records (current code) or open/forward-looking plans (e.g. 19, 29-spec, 30–33).

---

## The Problem

nginx-xrootd is currently protocol-centric: the source tree is organised around the wire opcode that arrives on the socket.  Every opcode handler owns its own copy of the same four cross-cutting concerns:

1. **Path extraction + canonicalisation** — `xrootd_extract_path` → `xrootd_resolve_path*` (22 handlers do this inline)
2. **Three-tier auth triad** — `xrootd_check_authdb` + `xrootd_check_vo_acl_identity` + `xrootd_check_token_scope` (35+ call sites)
3. **Errno → kXR mapping** — duplicated `if (err == EACCES)` ladders (30+ sites)
4. **Structured access log** — `XROOTD_RETURN_OK` / `XROOTD_RETURN_ERR` with identical arg shape (60+ sites)

An intent-centric architecture reverses this: each operation is declared as a **descriptor** that says *what* it does; a single shared interpreter handles *how*: path resolution, auth gating, logging, error mapping, and metrics — called exactly once each, in exactly one place.

---

## Baseline Metrics (src/ as of 2026-06-11)

| Subdirectory | LoC    | Primary concern |
|---|---|---|
| `webdav/`    | 13,748 | HTTP WebDAV + TPC |
| `compat/`    | 8,061  | shared helpers, errno mapping |
| `s3/`        | 6,870  | S3 REST API |
| `cache/`     | 4,751  | read-through cache |
| `tpc/`       | 4,739  | native XRootD TPC |
| `proxy/`     | 4,467  | upstream proxy mode |
| `dashboard/` | 4,157  | monitoring dashboard |
| `read/`      | 3,612  | stat/open/read/close/locate |
| `path/`      | 3,586  | path resolution + ACL |
| `metrics/`   | 3,450  | Prometheus counters |
| `token/`     | 3,100  | JWT/WLCG validation |
| `query/`     | 3,067  | kXR_query / kXR_prepare |
| `write/`     | 2,966  | namespace mutation ops |
| `connection/`| 2,109  | nginx event wiring |
| `aio/`       | 2,099  | async pread/pwrite |
| `session/`   | 1,729  | login/auth/protocol/bind |
| `crypto/`    | 1,726  | GSI/x509 |
| `upstream/`  | 1,554  | redirector protocol |
| `stream/`    | 1,534  | module descriptor + lifecycle |
| `manager/`   | 1,354  | CMS cluster registry |
| `response/`  | 806    | wire response builders |
| `dirlist/`   | 692    | kXR_dirlist |
| **Total**    | **94,944** | |

**Protocol layers targeted by this refactor** (write + read + session + connection + response):  
~12,842 LoC — these contain the highest density of repeated patterns.

---

## Phase Summary

| Phase | Title | Primary Target | Projected ΔLoC | Risk |
|---|---|---|---|---|
| 1 | Boilerplate Infrastructure | New macros / helpers | −300 | Low |
| 2 | Auth Gate Unification | 35+ auth triads | −250 | Low-Medium |
| 3 | Path Resolution Middleware | 22 inline resolvers | −200 | Medium |
| 4 | Simple Op Descriptor Tables | write/ handlers | −450 | Medium |
| 5 | Config Merge Consolidation | ~14 config files | −300 | Low |
| 6 | WebDAV Helper Consolidation | webdav/ response code | −350 | Medium |
| **Total** | | | **−1,850** | |

After all six phases: projected **93,094 LoC** — a **~2% reduction in total** but a **~14% reduction in the protocol layers** (write + read + session).  The bigger gain is consistency: every handler becomes a thin wrapper over shared infrastructure, making each one auditable in isolation without understanding the full call graph.

---

## Governing Principles

1. **Each phase leaves the module in a fully working state.**  All 2,187 tests must pass (with `pytest tests/ -n 4 -v`) before the phase is considered complete.

2. **Phases are strictly ordered.**  Phase N may depend on the infrastructure introduced in Phase N-1.  Do not begin a later phase until the earlier one is merged and green.

3. **No behaviour changes.**  These phases are pure refactors: same wire responses, same auth semantics, same error codes, same log format.  If a test fails during a phase it is a regression, not an intentional change.

4. **New helpers go in `src/core/compat/`.**  Cross-cutting helpers that are not specific to any one subsystem live there, where they already are (`error_mapping.h`, `namespace_ops.h`).

5. **No new source files without `config.h` registration.**  Every new `.c` added to `NGX_ADDON_SRCS` requires a `./configure` run.  New `.h`-only infrastructure does not.

6. **Rollback is `git revert <phase-commit>`.**  Each phase is a single atomic commit with a clear boundary.

---

## Phase Dependency Graph

```
Phase 1 (macros)
    └── Phase 2 (auth gate)
            └── Phase 3 (path middleware)
                    └── Phase 4 (op descriptors)

Phase 5 (config macros)   — independent of 1-4
Phase 6 (WebDAV helpers)  — depends on Phase 1 macros only
```

Phases 5 and 6 can be executed in parallel with Phases 2–4 by separate engineers since they touch non-overlapping subdirectories.

---

## What is Explicitly Out of Scope

- **WHAT/WHY/HOW auto-injected comment blocks**: these account for ~25–35% of lines in small handler files and represent a separate policy question.  Removing or condensing them would reduce LoC by an estimated further 1,000–2,000 lines but requires an explicit documentation policy change.  This refactor does not touch comments.

- **webdav/tpc.c, s3/, cache/, token/, tpc/**: these contain substantial domain-specific logic that cannot be expressed as generic descriptors without significant risk.  Out of scope for now.

- **Wire protocol correctness**: pgread/pgwrite CRC32c, TLS buffer invariants, kXR_attn framing — all untouched.

---

## Verification Baseline

Before starting any phase, record the baseline:

```bash
# Full suite, 4 workers — must stay green throughout
PYTHONPATH=tests pytest tests/ -n 4 --tb=short -q

# Incremental build sanity
make -j$(nproc) 2>&1 | grep -E "^(error|warning):" | wc -l

# Smoke test: anonymous read
XRD_LOGLEVEL=Info xrdcp root://localhost:11094//test.txt /tmp/smoke-out
```

---

## Phase index (live design records)

Each phase below is a design record for work that has landed in `src/` (or an
open / forward-looking plan). Completed-and-superseded phase plans were moved to
[`../_archive/refactor/`](../_archive/refactor/) (see the archive note above).

| Phase | Document | Topic |
|---|---|---|
| 2 | [`phase-2-auth-gate-unification.md`](phase-2-auth-gate-unification.md) | auth gate unification |
| 3 | [`phase-3-path-resolution-middleware.md`](phase-3-path-resolution-middleware.md) | path resolution middleware |
| 4 | [`phase-4-op-descriptors.md`](phase-4-op-descriptors.md) | op descriptors |
| 5 | [`phase-5-config-consolidation.md`](phase-5-config-consolidation.md) | config consolidation |
| 6 | [`phase-6-webdav-helpers.md`](phase-6-webdav-helpers.md) | webdav helpers |
| 8 | [`phase-8-openat2-confinement.md`](phase-8-openat2-confinement.md) | openat2 confinement |
| 11 | [`phase-11-compat-rationalization.md`](phase-11-compat-rationalization.md) | compat rationalization |
| 18 | [`phase-18-auth-gate-completion.md`](phase-18-auth-gate-completion.md) | auth gate completion |
| 19 | [`phase-19-http3-quic.md`](phase-19-http3-quic.md) | http3 quic |
| 20 | [`phase-20-shm-kv-management.md`](phase-20-shm-kv-management.md) | shm kv management |
| 21 | [`phase-21-subrequests-upstream-filters.md`](phase-21-subrequests-upstream-filters.md) | subrequests upstream filters |
| 22 | [`phase-22-stream-health-checks.md`](phase-22-stream-health-checks.md) | stream health checks |
| 23 | [`phase-23-dynamic-upstreams.md`](phase-23-dynamic-upstreams.md) | dynamic upstreams |
| 24 | [`phase-24-traffic-mirroring.md`](phase-24-traffic-mirroring.md) | traffic mirroring |
| 25 | [`phase-25-rate-limiting.md`](phase-25-rate-limiting.md) | rate limiting |
| 26 | [`phase-26-slice-caching.md`](phase-26-slice-caching.md) | slice caching |
| 27 | [`phase-27-memory-safety-hardening.md`](phase-27-memory-safety-hardening.md) | memory safety hardening |
| 28 | [`phase-28-adversarial-hardening.md`](phase-28-adversarial-hardening.md) | adversarial hardening |
| 29 | [`phase-29-phase3-aio-pipelining-spec.md`](phase-29-phase3-aio-pipelining-spec.md) | phase3 aio pipelining spec |
| 30 | [`phase-30-hyper-optimization-throughput-latency.md`](phase-30-hyper-optimization-throughput-latency.md) | hyper optimization throughput latency |
| 31 | [`phase-31-memory-budget-streaming.md`](phase-31-memory-budget-streaming.md) | memory budget streaming |
| 32 | [`phase-32-data-plane-perf-parity.md`](phase-32-data-plane-perf-parity.md) | data plane perf parity |
| 33 | [`phase-33-perf-optimization-post-feature-complete.md`](phase-33-perf-optimization-post-feature-complete.md) | perf optimization post feature complete |
| 34 | [`phase-34-packet-marking-scitags.md`](phase-34-packet-marking-scitags.md) | packet marking / SciTags |
| 35 | [`phase-35-frm-tape-staging.md`](phase-35-frm-tape-staging.md) | FRM / tape MSS staging (B2) — durable stage queue, kXR_offline residency, WLCG Tape REST, async completion |
| 36 | [`phase-36-ipv6-completion.md`](phase-36-ipv6-completion.md) | full IPv6 across all protocols — bracket IPv6 literals in wire host:port (registry/redirect/CMS/proxy/TPC), shared host_format helper, buffer widening |
| 37 | [`phase-37-native-xrdcp-xrdfs-clients.md`](phase-37-native-xrdcp-xrdfs-clients.md) | clean-room pure-C native clients (xrdcp/xrdfs/xrddiag/…) + libxrdc + xrootdfs FUSE atop libxrdproto |
| 38 | [`phase-38-file-size-unix-modularity.md`](phase-38-file-size-unix-modularity.md) | file-size / Unix modularity — smaller single-purpose source files |
| 39 | [`phase-39-network-fault-resilience.md`](phase-39-network-fault-resilience.md) | network-fault resilience (plan) — per-PDU/drain/handshake deadlines, TPC stall bounding + reaper, proxy wbuf/splice fixes, CMS dead-peer detection, two-tier 20%-loss test; all off-by-default, hot-path-neutral |
| 42 | [`phase-42-compression.md`](phase-42-compression.md) | comprehensive compression ✅ DONE — full modern codec set (gzip/deflate, xz/lzma, zstd, brotli, bzip2, **lz4**) across root://+WebDAV+S3 + native client, in 4 directions (inbound PUT decode, outbound GET encode, ZIP member reads, root:// inline read+write). Keystone = one shared codec vtable in libxrdproto + bomb guard; W0 zcrc32, W1 inbound, W2 outbound, W3 ZIP, W4 root:// read, W5 root:// write (per-request frames; pgread/pgwrite/readv/writev stay plaintext). lz4 is a 6th codec proving the vtable is pluggable; a build matrix tests dynamic-module dlopen + no-codec graceful degrade. All off-by-default + invisible to stock peers. NB: upstream XRootD is DEFLATE/zlib-only — lzma/zstd/brotli/bzip2/lz4 are deliberate extensions |
| 43 | [`phase-43-s3-protocol-completion.md`](phase-43-s3-protocol-completion.md) | S3 protocol completion (plan) — `src/s3/` correctness + SDK compatibility (aws-cli/boto3/rclone/s5cmd); builds on phase-9 SigV4 + existing multipart/POST-object/DeleteObjects + crc64 reuse. No root:///WebDAV changes |
| 44 | [`phase-44-io-uring-backend.md`](phase-44-io-uring-backend.md) | optional Linux io_uring I/O backend (plan), server + client. Server (`src/`) = disk-I/O only (network is nginx-core-owned, off-limits): a 3rd tier behind `xrootd_aio_post_task` (io_uring → thread pool → inline), reusing the six `*_aio_t` structs + `*_aio_done` callbacks unchanged; per-worker ring, completions to nginx epoll via an `eventfd` wrapped in an `ngx_connection_t` (public APIs, no core patching); first cut maps read/write/readv/writev+fsync, pgread/dirlist/multi-fd stay on the pool. Client (`client/`) staged lowest-risk-first: (1) deep-queue local-disk ring for the xrdcp `copy.c` pump behind the unchanged adapter interface, (2) FUSE-local inherits it, (3) optional `aio.c` epoll→io_uring engine swap (`POLL_ADD` multishot drop-in first, TLS-safe; cleartext RECV/SEND later), default off. Gated on `pkg-config liburing` + runtime probe; auto-fallback; no wire-framing changes; phase-31 budget preserved. §7 duplication analysis: the server eventfd→epoll completion bridge is a forced re-derivation of nginx core's own libaio integration (`ngx_epoll_aio_init`/`ngx_epoll_eventfd_handler`) — core's is `static`, libaio-bound, read-only+O_DIRECT, and addon-unreachable; we reuse `ngx_posted_events`/thread-pool/sendfile unchanged. nginx ships no io_uring (only backlog #568; unmerged 2020/2021 nginx-devel patches + CarterLi fork). §8 security hardening: (a) 4-level runtime disable incl. a no-restart hot kill switch (cross-worker SHM atomic flipped via the phase-23 admin API or a watched panic-file) for CVE response; (b) privilege containment — io_uring runs in the unprivileged worker on broker-opened RESOLVE_BENEATH fds (Phase-40 impersonation), ring locked via `io_uring_register_restrictions` to fd-only data opcodes so it can never open/traverse a namespace; root broker never uses io_uring. EXHAUSTIVE implementation reference (§9–§19, ~38k words): §9 data structures/types, §10 per-opcode submission cookbook, §11 completion reaper, §12 client disk-ring, §13 client event-loop engine, §14 security threat model + kill-switch/containment code, §15 config/build/kernel-capability reference, §16 observability + CVE runbook, §17 test plan + parity matrix, §18 granular workstream/gate breakdown (SB-W1..8/CB-W1..6, milestones M1..M11), §19 risk register + decisions log + glossary. HYPER implementation appendices (§20–§31, ~57k words total): §20–§21 near-final annotated source skeletons (server `src/core/aio/uring.{h,c}`+`uring_submit.c`; client `uring.{h,c}`+`copy.c` adapters+`aio.c` engine vtable), §22 exact edit hunks for every existing file, §23 state machines + sequence diagrams, §24 concurrency/memory-ordering proofs (single-event-thread invariant, UAF guards A–D), §25 liburing API reference, §26 error/status mapping (no-new-error-paths proof), §27 capacity/sizing model, §28 30-row failure-injection matrix, §29 PR-by-PR rollout (PR-01..30) + review checklists, §30 CI/CD job/gating definitions, §31 15 ADRs + design FAQ, §32 **startup fail-fast** (`xrootd_io_uring on` makes xrootd refuse to start — `nginx -t` errors + master exits — when the backend was built without liburing (config-time, no probe) or is runtime-blocked by seccomp/old-kernel; `auto`/`off` always start; client `--io-uring=on` exits non-zero; ADR-16 + full `xrootd_uring_validate_conf` postconfiguration hook; deepened in §32.13–§32.18: three-layer availability model (compile/link/runtime), full worker-init backstop code, build introspection so operators can verify "compiled in" (nginx -V banner / config endpoint / gauge), compile-time static-assert guards, 5 worked startup scenarios, and REQ-IOURING-FAILFAST formalized as MUST). §33 formal requirements + traceability matrix (OPS/FR/NFR/SEC/BLD, fail-fast = OPS-1), §34 per-function interface/ABI contracts (pre/post/invariants/thread-context), §35 kernel/liburing/distro compatibility & support matrix |
| 53 | [`phase-53-reordering-loss-resilience.md`](phase-53-reordering-loss-resilience.md) | reordering & packet-loss resilience ✅ DONE + verified — fault_proxy `reorder`/`jitter`/ppm-`lossy` levers; **#3** runtime `xrootd_pipeline_depth` (default 8, was 4); **#1** userspace-TLS read pipelining (wired the dead `rd_pool`, 96 concurrent TLS reads under reorder ASAN-clean); `XRDC_BACKOFF_BASE_MS` tuning (repo `xrdcp` 6.3× at 1% `root://` loss); **HTTP `Range`-resume** in `xrdc_http_download`/`webfile` (repo `xrdcp` over HTTP 0/8 → 8/8 at ≥0.01% loss, ~1000× tolerance); `xrootd_tcp_congestion <algo>` per-socket setsockopt on stream+WebDAV+S3. Key findings: reorder = uniform latency tax (all clients/servers converge ~118 MB/s at 1%); loss = client resilience is everything (repo resilient, official `xrdcp` cliffs at 1% / can't do http at all). Caveat: the userspace-relay harness can't validate `tcp_congestion` (no true IP reordering) — verified it *applies* (`ss`), not that it improves loopback throughput |
| 55 | [`phase-55-storage-backend-abstraction.md`](phase-55-storage-backend-abstraction.md) | storage-backend abstraction (plan) — lift POSIX out of `src/fs/` into a capability-typed Storage Driver (SD) vtable below the VFS (`src/fs/backend/`: `sd_posix`/`sd_block`/`sd_object`), so a block/object (S3) backend can become a first-class then primary storage backend with zero change above the seam (protocol handlers/metrics/cache/access-log untouched). Keystone = the Phase-54 PREPARE/EXECUTE/COMPLETE split already isolates raw syscalls in `vfs_io_core.c`; the driver vtable cuts exactly there. Each export binds a **pair** of independently-selectable SD instances — a durable **backend store** (`xrootd_storage_backend`) and an in-progress **staging store** (`xrootd_storage_staging`), both defaulting to the same POSIX instance (zero change for existing deployments). Splitting them is the honest fix for the object random-write limitation: stage random/out-of-order/checkpointed uploads on fast POSIX scratch, then **promote** the finished object into the backend as one sequential multipart PUT (native rename fast-path when staging==backend). Capability bitmap (`CAP_FD/SENDFILE/RANDOM_WRITE/RANGE_READ/SERVER_COPY/XATTR/HARD_RENAME/DIRS/IOURING`) drives VFS adaptation (sendfile→memory-chain when `!CAP_SENDFILE`; server-copy→stream-through; in-place random-write on committed object→501+metric; rename→copy+delete). Five hard problems resolved: fd/sendfile leak (retire `xrootd_vfs_file_fd()`), confinement-as-FS-concept (per-driver primitive: `RESOLVE_BENEATH` vs key-prefix), random-write/atomic-rename (staged-write lifecycle = object multipart), `copy_file_range`/CopyObject, blocking network I/O (reuse the AIO thread-pool tier). 6 phases (55.A scaffolding → B raw-I/O → C namespace/dir/stat/xattr/staged → D block driver → E object/S3 driver → F promote+tiering-cache). POSIX driver is behaviour-preserving (existing ~5180-test suite = oracle); non-POSIX backends opt-in behind `xrootd_storage_backend posix\|block\|s3`. Open Qs: cache-as-tiering-driver, CMS space reporting, Phase-40 impersonation→store-credential identity, Phase-44 io_uring orthogonality (`CAP_IOURING`-gated) |
| 56 | [`phase-56-vfs-storage-driver-perf-audit.md`](phase-56-vfs-storage-driver-perf-audit.md) | VFS↔Storage-Driver↔POSIX data-plane optimization audit + roadmap (**first phases landed: F0 CI seam guard, A-1 byte-primitive de-indirection, D-1 monotonic latency clock** — all build-clean under `-Werror`, static-marker-baseline-preserved; rest sequenced. Codifies `CLAUDE.md` #11 `proto→VFS→POSIX`) — hyper-detailed perf+expansion catalogue for the Phase-54 io-core + Phase-55 SD seam, with the **4 live funnels traced** (HTTP-read=`vfs_open`+`sendfile_fd`+`file_serve.c`; stream-read/write=`vfs_io_execute` jobs; HTTP-write=`staged_open`+`staged_commit`), per-finding **measurement recipes** (§10), **SD-slot ABI contracts** (§13), **exact edit hunks** (§14), and a glossary (App B). **Top finding (§3):** the two marquee VFS entry points `xrootd_vfs_read`/`xrootd_vfs_write` have **zero callers** — the data plane bypasses them — so wire-or-delete (recommend delete + re-doc) before its sub-optimizations matter. Cross-cutting **impersonation axis (§0.3):** confined metadata stats are a broker **IPC round-trip** per child under Phase-40 impersonation (not a syscall), so stat-elision wins are far larger there. Genuinely-hot: **A-1** strip the dead SD-vtable indirection from the raw `pread_full`/`pwrite_full`/`write_counted` loops (they hard-code `xrootd_sd_posix_driver` → indirect call buys nothing for POSIX, blocks inlining per 64 KB chunk; the one layer common to all 4 funnels); **B-1** stack/direct borrow on the `root://` hot open (kills ~3 `pcalloc`/open); **D-1** VFS latency uses cached `ngx_current_msec` → inline metadata ops report **0 µs** (use `CLOCK_MONOTONIC`); **D-2** the bulk data plane (stream R/W, HTTP sendfile) emits **no** op-latency metric at all (only 10 `xrootd_metric_op_done` refs tree-wide, none on the data path) — histogram blind spot over the busiest ops; **B-2** push existing `POSIX_FADV_*` into a seam `read_advise` slot so root://+S3 inherit it, not just WebDAV; **B-5** `staged_commit`/`vfs_copy` re-stat by path for the metric byte-count instead of `fstat`-ing the open fd (a broker IPC under impersonation). Metadata trims: **C-1** `d_type` in `xrootd_sd_dirent_t` to drop per-child stat in the `fs_walk` tree walker + S3 LIST (DT_UNKNOWN falls back); **C-5** `xrootd_vfs_readdir` stats children by **full path** not dirfd-relative `fstatat` (O(depth)→O(1) off-impersonation); **C-2** per-worker bounded **negative-stat** cache (default off, identity-scoped, false-ENOENT-guarded); **C-3** `CAP_IOURING`-gated batched `statx` for `want_stat` dirlist (behind Phase 44); **C-4** dirlist `fstatat` error branch hides EIO/EACCES as ENOENT. Latent/dead-body items (E-1 `make_file_chain` path alloc, E-2 `write_file_buf` 64 KB bounce→`copy_file_range`, E-3 writethrough pre-scan) are wire-or-delete-first. **Pillar F (§9) — "VFS as the sole source of data-plane truth" (the complement of §3):** an audit for every handler that reaches **past** the VFS into the confined-POSIX-helper layer. Tier-1 (raw libc on export data) is ~clean (Phase 54 funneled the byte plane); **tier-2 is a 105-site backlog in 39 files** (comment-filtered; raw grep ~121 over-counts doc-block mentions, e.g. `mv.c`'s header names `ns_rename` 8×) — handlers across `read/`,`write/`,`webdav/`,`s3/`,`dirlist/`,`tpc/`,`query/`,`connection/` call `xrootd_*_confined_canon`/`_beneath`/`xrootd_ns_*`/`xrootd_staged_*` directly (28 open + 30 stat + 9 opendir + 8 ns-mutate + 30 staged, the last mostly abort-ladders) instead of `xrootd_vfs_*`, so the op is unmetered/uncached and POSIX-pinned (a non-POSIX backend can't serve it). Appendix C enumerates every site; a scorecard (§9.4.1) shows the partial-migration state (e.g. WebDAV DELETE✓/MKCOL✗ same file; S3 POST-object✓/simple-PUT✗). **F-2 priority:** the S3-multipart part-file **write** side uses raw `open`+a userspace `read`/`write` copy loop while its **read** side is `RESOLVE_BENEATH`-confined (with a documented planted-symlink fix) — an **asymmetry** (defence-in-depth + a `copy_range` perf win), corrected from an earlier "unconfined attacker path" overstatement since the part paths are server-constructed. **F6 is the hot/risky tail:** the stream `kXR_open` handle-table (`open_resolved_file.c`/`fd_table.c`) wants the raw fd — migrate last, pair with B-1. Ships a scope ruling (VFS owns client export data+namespace; gateway-private sidecars→VFS staging store per Phase 55.F), a CI seam guard (`tools/ci/check_vfs_seam.sh` + shrinking allowlist — none exists today) and a phased F0–F7 migration (byte-identical: each `xrootd_vfs_*` wrapper already calls the same confined helper underneath). Appendix A records 3 findings demoted by the reachability check so they're not re-promoted as hot-path wins |
| 54 | [`phase-54-vfs-thread-safe-io-core.md`](phase-54-vfs-thread-safe-io-core.md) | thread-safe VFS I/O core (plan) — route ALL disk ops, incl. worker-thread offloads, through the VFS layer. Split each op into a PREPARE (loop: confine + pool-alloc + snapshot into a POD `xrootd_vfs_job_t`) / EXECUTE (thread/loop/io_uring: pure `pread`/`pwrite`/`readdir`/CRC into pre-allocated buffers, no pool/metrics/log/cache) / COMPLETE (loop: meter + access-log + cache-record + handle counters) triad mapping onto the existing `xrootd_aio_post_task` lifecycle. New `src/fs/vfs_io_core.{c,h}` dispatcher reuses `xrootd_vfs_pread_full`/`pwrite_full`/`xrootd_pgread_read_encode_inplace`/`xrootd_readv_read_segments` as the EXECUTE phase; AIO workers (`reads/write/readv/dirlist`) rewired to call it instead of duplicating raw syscalls. io_uring untouched (job is a superset of the SQE inputs). dirlist gets a confinement upgrade (raw `open` → `xrootd_open_beneath` `RESOLVE_BENEATH`). `VFS-LOOP-ONLY`/`VFS-THREAD-SAFE` annotation contract enforced by CI grep + include rule. Full rewire, 8 incremental phases (0 scaffolding → read → write → readv → pgread → writev → dirlist → cleanup), each with the 3-tests rule + perf gate, validated across thread-pool / inline / io_uring backends |
| 58 | [`phase-58-xrootd-parity-batch.md`](phase-58-xrootd-parity-batch.md) | XRootD parity batch (plan + detailed spec) — 7 official features absent/partial in the module, plus checksum-at-rest and a `.cinfo` cache-metadata analysis (excludes plugin ABI + UDP monitoring). Tiered quick-wins → focused → gated. Detailed wire layouts + function signatures per item: **(1)** `?authz=` query bearer token (`webdav/auth_token.c` fallback + access-log redaction); **(2)** dCache `application/macaroon-request` content-type (reuse `xrootd_macaroon_issue` + ISO-8601 duration parse + dCache `uri{}` body); **(3)** XrdDig remote diagnostics over root://+HTTP (new `src/dig/`, reuses dashboard `openat2 RESOLVE_BENEATH` confinement + a principal→subtree allow-file); **(4)** OssArc archive aggregation (Phase A member-read finishes deferred `zip_member.c` over the built `zip_dir.c`; Phase B FRM-driven compose/stage via external archiver); **(5)** GSI proxy delegation `kXGC_sigpxy`/`kXGS_pxyreq` (constants exist; add `kXRS_x509`/`kXRS_x509_req` buckets, new `src/auth/gsi/delegation.c` CSR-gen→sign→store; Phase 2 TPC-consume gated on fixing outbound native-GSI); **(6)** Composite Cluster Name Space (minimal CMS-fed inventory subset, **product-decision-gated**); **(7)** XrdSsi (**likely non-goal**, minimal unary RRInfo subset if a consumer appears). **§8 checksum-at-rest:** builds on existing `compat/integrity_info.c` (`user.XrdCks.<alg>` text xattr, mtime+size-keyed) — adds binary `XrdCksData` interop codec, optional `.cks` sidecar for no-xattr fs, checksum-on-ingest (close/PUT/TPC), and a later per-page CSI+scrub phase. **§9 `.cinfo`:** extends the cache's existing `.meta` validity sidecar to a versioned `.cinfo` with a block-present bitmap (partial-fill survival across restart), access stats (LFU/age eviction), and origin-digest verify-on-fill. Decisions RESOLVED (ADR-1..4): CNS in scope (minimal subset), SSI in scope validated by official-cluster interop, GSI Phase-2 gated on fixing outbound native-GSI first, checksum xattr stored host-order (stock-compatible same-arch). Hyper-detailed (~16k words, §0–§NN): per-feature wire byte-layout tables, near-final annotated skeletons (§S) + **compile-ready corrected sources** (§EE: iso8601, macaroon-request handler + caveats walker, XrdCksData codec, checksum sidecar, cinfo load/store), exact before/after edit hunks (§T), state machines + sequence diagrams (§U) + explicit transition tables (§HH), concurrency/memory-ordering/reentrancy proofs (§V), capacity & perf model (§W), 30-row failure-injection matrix (§X), CI/CD + PR-by-PR rollout w/ review checklists (§Y), observability (§AA), full config reference (§BB), kernel/dep compat (§CC), official-cluster interop harness (§DD), **per-function ABI/contract tables (§FF)**, **wire test vectors / hex fixtures (§GG)**, pytest specs (§II), DoD + kill-switches (§JJ), migration/back-compat (§KK), design FAQ (§LL), formal requirements FR/NFR/SEC/BLD/OPS + traceability (§MM), open questions (§NN), ADR log, risk register, glossary |
| 59 | [`phase-59-scitokens-csi-throttle-bwm-parity.md`](phase-59-scitokens-csi-throttle-bwm-parity.md) | Three remaining functional-parity gaps vs official XRootD (capabilities the module partially covers, not at upstream's config/contract breadth; excludes plugin ABI + UDP). **W1 SciTokens breadth** (`XrdSciTokens`): multi-issuer registry parsed from the upstream `scitokens.cfg` INI (new `src/auth/token/issuer_registry.c` + `subject_map.c` + `monitor.c`), per-issuer `base_path`/`restricted_path` namespace scoping, subject→username + `groups_claim` mapping (`name_mapfile`), `authorization_strategy` modes (capability/group/mapping), and an HTTP-native IO monitor hook replacing `XrdSciTokensMon` (Prometheus, never UDP); single-issuer directives stay as a back-compat shortcut. **W2 CSI page-checksum tagstore** (`XrdOssCsi`) — the per-page phase Phase-58 §8 deferred: per-4096-byte-page CRC32C in a versioned sidecar (`src/fs/backend/csi_tagstore.c` + `csi_verify.c`, all tag-file I/O inside the backend per the data-POSIX-confinement invariant), read-verify/write-update, RMW+verify-before-write on partial pages, hole/`nofill`/`nomissing`/`prefix` options, optional paced scrub; pgWrite stores client CRC directly (no recompute fast path); own on-disk format, byte-level `.xrdt` interop a documented follow-on. **W3 Throttle/Bwm parity**: W3a maps the exact `throttle.*` contract onto `src/net/ratelimit/` (`throttle_compat.c`) — the IO-**load** concurrency metric (service-time/s, not request count, added as a new keying mode so existing `xrootd_concurrency_limit` is untouched), `max_open_files`/`max_active_connections` per-user SHM counters on open/close, `userconfig` INI precedence (exact>glob>`*`>global), delay-then-error via `kXR_wait`/`503` up to `max_wait`, loadshed, trace categories; W3b a default-off `XrdBwm` reservation manager (`reservation.c`: Schedule→handle→Done/Status, `bwm.src`/`dst` endpoint classes, TPC reserve/release) documented as legacy/niche. 4 ADRs (INI config-compat, own tag format, Bwm default-off, new concurrency mode additive), risk register (per-page verify perf, partial-write RMW correctness, SHM contention→spin+yield mutexes, W1 scope creep→document unsupported keys), 6-PR rollout, all features default-off (kill-switch = config revert). Builds on Phase-58 §8/§9; not started. **Hyper-detailed (~21.5k words, 37 sections, §0–§Z):** exact upstream `scitokens.cfg` grammar table + the `XrdOssCsiTagstoreFile.cc:72-113` 20-byte tag-header byte-layout + the full `throttle.*` directive contract; **compile-ready source listings (§EE)** for all 8 new files (`ini.{c,h}`, `issuer_registry.{c,h}`, `subject_map.c`, `monitor.c`, `csi_tagstore.{c,h}`, `csi_verify.c`, `throttle_compat.{c,h}`, `reservation.{c,h}`); explicit (state,event)→action **transition tables (§HH)** for all 5 FSMs; 11 exact edit hunks against real functions/lines (§T); 32-row failure-injection matrix (§X) each pinned to a test; per-function ABI/contract tables (§FF); format hex fixtures + golden CRC vectors (§GG); capacity/latency model with real CRC-throughput math (§W); CI job-gate definitions + runnable interop harness scripts (§Y/§DD); formal FR/NFR/SEC/BLD/OPS requirements + traceability (§MM/§R); 5 ADRs + 6-row risk register (§Z); pytest specs (§II); DoD + kill-switches (§JJ); migration/back-compat (§KK); design FAQ + open questions (§LL/§NN); glossary. Latest expansion adds full (non-elided) function bodies in §EE (the `validate_registry` strategy ladder, subject mapfile lookup w/ mtime cache, the `ngx_command_t` directive table + custom `xrootd_throttle` parser, the paced CSI scrub timer), a **per-handler integration cookbook (§QQ)** tracing the exact call-site edits in `auth_token.c`/`gsi/token.c`/`vfs_io_core.c`/`get.c`/`open.c`/`tpc.c` (incl. ADR-6: HTTP GET disables sendfile under CSI since sendfile bytes can't be verified in-band), a Prometheus metric catalog with `# HELP`/`# TYPE`/label-sets + a cardinality proof (§AA), real pytest test skeletons for all 4 suites (§II), a full directive grammar/default/scope/merge/validation table (§BB), and 7 ADRs in Context/Decision/Consequences/Alternatives form (§Z). Further deepened with a **STRIDE security threat model (§ST)** per workstream (incl. the honest CRC-is-integrity-not-authenticity limitation + keyed-MAC follow-on), a complete **errno→kXR→HTTP error-mapping table for every new path (§EM)**, a **kernel/distro support matrix + degradation behavior (§CC)**, golden CRC32C test vectors + a fully-expanded CSI header hex + a decoded SciToken JWT fixture + a short-last-page tag-array walkthrough (§GG), the full `merge_srv_conf()` body with cross-directive validation + one-time registry build (§EE.19), per-PR file manifests for all 6 PRs (§Y.1), and an expanded glossary + design FAQ. Final tranche adds **6 end-to-end ASCII sequence diagrams (§SEQ)** tracing every component boundary (client→handler→token/throttle→io-core→backend→tag file), a **normative on-disk tag-file format spec (§FMT)** with versioning/evolution rules + a corruption/crash-recovery procedure table + `tools/csi_rebuild`, the **authdb integration spec (§ADB)** wiring the `group`/`mapping` strategies into `src/auth/authz/authdb.c` `g`/`u` rules with a worked example, an **operational runbook (§RUN)** (enable/verify/rollback/incident-response per feature), and a **worked stock-xrootd→nginx config-migration (§MIG)** with the directive-by-directive mapping |
