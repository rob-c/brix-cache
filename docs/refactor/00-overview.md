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

4. **New helpers go in `src/compat/`.**  Cross-cutting helpers that are not specific to any one subsystem live there, where they already are (`error_mapping.h`, `namespace_ops.h`).

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
