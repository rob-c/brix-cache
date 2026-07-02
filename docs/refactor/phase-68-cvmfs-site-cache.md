# Phase-68: CVMFS Site Cache Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Spec:** [docs/superpowers/specs/2026-07-02-cvmfs-site-cache-design.md](../superpowers/specs/2026-07-02-cvmfs-site-cache-design.md)

> **EXECUTION RECORD (2026-07-02):** all 22 tasks implemented and committed
> (one commit per task, `git log --oneline --grep=cvmfs`). All eleven test
> suites green: `run_cvmfs_{classify,reverse,verify,failover,manifest,proxy,
> select,holdopen,keepalive}.sh`, `run_scvmfs.sh`, `run_cvmfs_stock.sh`.
> Deviations from the plan text, resolved against the live tree:
> `proxy_cache_valid` takes no variables (stock config uses per-class
> locations); `xrootd_cache_include_regex` is stream-only (T9 used the geo
> passthrough as the manifest stopgap until T12); verify/TTL/stale hook the
> phase-64 sd_cache tier fill (not the legacy fetch.c engine); nginx ≥1.11
> has no port_start/port_end (T14 parses the raw request line);
> backend-entry stand-ins map onto the root_canon-keyed registry (proxy mode
> uses synthetic per-upstream exports); VOMS scvmfs authz deferred (needs a
> conf-independent seam out of webdav/auth_cert.c). Honest test counting
> (grep -oF, the one-line-JSON ctl-log made every count vacuous) surfaced
> and fixed two real gaps: HTTP fill coalescing (stampede was N fills) and
> an EOF-probe GET per fill. PENDING (needs root on the box):
> `sudo tests/cvmfs/run_matrix.sh` netem sweep; both OP gate verdicts await
> ticks in deploy/cvmfs/baselines/RESULTS.md (execution continued through
> the gates per the OP's standing instruction).

**Goal:** Turn nginx-xrootd into a reliable CVMFS site cache (Squid/Varnish replacement) for a Tier-2 with a lossy, reordering network — adding **`cvmfs://` as a dedicated protocol plane** (own module, own content handler, own directive family, like `s3/`), plus an **experimental `scvmfs://` secure variant layered on top of it**, reusing the posix read-through cache tier and the `sd_http` origin driver, with CVMFS URL classification, CAS verify-on-fill, origin selection (static/geo/rtt), never-drop client semantics, and forward-proxy mode.

**Architecture:** `src/protocols/cvmfs/` is a first-class protocol directory: its own HTTP module (`ngx_http_xrootd_cvmfs_module`) installs a dedicated content handler on any location with `xrootd_cvmfs on` — CVMFS traffic never enters the WebDAV dispatch. The handler classifies CVMFS URLs, rejects everything else, and serves bytes through the **existing** phase-63/64 composition `xrootd_cvmfs_storage_backend http://stratum1/cvmfs/<repo>` + `xrootd_cvmfs_cache_store <dir>` (per-protocol directives over the shared `common.*` tier struct, exactly the s3/webdav idiom) using the shared `src/core/http/` file-response/Range/conditional helpers. `scvmfs://` (Task 22, EXPERIMENTAL) is the same handler core behind a TLS listener with an optional client-authz gate — a security preamble, not a second implementation. New C: the module + handler, a pure-C classifier, geo passthrough, a CVMFS-CAS mode in `verify.c`, multi-endpoint failover + selection in `sd_http`, manifest TTL in `.cinfo`, never-drop fill semantics, proxy-mode absolute-URI handling, and the scvmfs security gate.

**Tech Stack:** C (nginx module, existing patterns), bash `run_*.sh` self-contained tests (pattern: `tests/run_cache_http_source.sh`), Python 3 (mock Stratum-1 + harness, pytest), `tc netem` lab, stock nginx `proxy_cache` for the Phase-1 baseline.

## Global Constraints

- **NO `goto`** anywhere in `src/` (early-return + helper decomposition per `docs/09-developer-guide/coding-standards.md`).
- Functional/modular: one job per function, explicit `ctx`/conf parameters, no new globals (per-worker statics allowed where the codebase already uses them).
- Use HELPERS from CLAUDE.md — never reimplement path/auth/metrics/framing. All export-path FS access via `xrootd_vfs_*` (VFS seam is closed; keep it closed). Non-export raw FS calls need a same-line `/* vfs-seam-allow: <reason> */`.
- 3 tests per change: success + error + security-negative.
- Every new `.c` file must be added to the repo-root `./config` source list, then full rebuild: `rm -rf /tmp/nginx-1.28.3/objs && cd /tmp/nginx-1.28.3 && ./configure --with-stream --with-stream_ssl_module --with-http_ssl_module --with-http_dav_module --with-threads --add-module=/home/rcurrie/HEP-x/nginx-xrootd && make -j$(nproc)` (configure over stale objs ⇒ mixed-ABI garbage). Incremental edits: `make -j$(nproc)` only.
- Do NOT edit generated Makefiles or the nginx build tree's own sources.
- Metric labels low-cardinality only (URL *class*, never repo/path).
- Wire log strings through `xrootd_sanitize_log_string()`.
- Commit steps below assume the OP has authorized this plan's execution (repo policy: no git commands without OP instruction). One commit per task, message style `feat(cvmfs): …` / `test(cvmfs): …`.
- Suite gate before each phase boundary: `tests/run_suite.sh --pr` must stay green.

## The protocol plane: `cvmfs://` and `scvmfs://`

**`cvmfs://` is a dedicated protocol in this module's sense of the word** —
the same sense in which S3 is one: HTTP on the wire, but with its own
directory (`src/protocols/cvmfs/`), its own nginx HTTP module and content
handler, its own directive family (`xrootd_cvmfs_*` including per-protocol
tier directives), its own metrics family, its own access-log/guard
identity, and its own row in CLAUDE.md's ROUTING and OP→FILE tables. A
`cvmfs://` location is NOT a WebDAV location: `xrootd_cvmfs on` alone
activates it, no `xrootd_webdav` anywhere, and none of WebDAV's methods,
auth modes, or dispatch exist on it. What IS shared sits below the protocol
seam, where sharing is the architecture: the VFS/tier storage plane
(`src/fs/`), the `sd_http` origin driver, and the `src/core/http/` shared
HTTP semantics (file response, Range, conditionals) that exist precisely so
protocol handlers never reimplement them.

Wire honesty: CVMFS clients speak plain HTTP; `cvmfs://` names the
protocol plane (config, docs, metrics, logs), not a new wire syntax —
identical to how the S3 plane is REST-over-HTTP.

**`scvmfs://` (EXPERIMENTAL, Task 22) is a secondary protocol layered on
`cvmfs://`, not beside it.** One handler core; scvmfs adds a security
preamble in front of it: the listener is TLS (`listen … ssl`), plain-HTTP
requests are refused, an optional client-authz gate (bearer token or
VOMS/GSI proxy cert — existing HELPERS, never reimplemented) runs before
classification, and https upstreams are permitted (the `cvmfs://`
proxy-mode https refusal stays in force outside scvmfs contexts). It maps
onto real-world "secure CVMFS" (X.509/authz-protected repositories, where
Stratum-1s require credentials and content is not world-readable).
Experimental status is structural: its own directive family
(`xrootd_scvmfs_*`), its own test suite, its own metrics counter, marked
experimental in every doc, and **excluded from Gate 2 and the pilot** — it
can slip or be dropped without touching the `cvmfs://` deliverable.

## Execution Guide

### Task dependency graph

```
Phase 0:  T1 (mock) ──┬─→ T3 (harness) ──→ T4 (baselines)
          T2 (netem) ─┘        │
Phase 1:                       └─→ T5 (stock config) ══ GATE 1 (OP go/no-go)
Phase 2:  T6 (CAS spike, blocks T10 only)
          T7 (classifier) ─→ T8 (directives) ─→ T9 (gate+geo, e2e MVP)
Phase 3:  T9 ─→ T10 (verify, needs T6 verdict)
          T9 ─→ T11 (failover)          [independent of T10]
          T9 ─→ T12 (manifest TTL)      [independent of T10/T11]
          T9 ─→ T13 (negative cache)    [independent of T10/T11/T12]
          T8,T11 ─→ T14 (proxy mode)
Phase 3B: T11 ─→ T19 (origin selection: static/geoip/rtt)
          T9,T11 ─→ T20 (never-drop fill semantics)
          T20 ─→ T21 (TCP keepalive + connection durability)
          T21 ─→ T22 (EXPERIMENTAL scvmfs:// — NOT gating; can slip/be cut)
          T10..T14, T19..T21 ─→ T15 (matrix) ══ GATE 2 (OP go/no-go for pilot)
Phase 4:  T9 ─→ T16 (metrics)  T9 ─→ T17 (guard/fail2ban)  all ─→ T18 (runbook)
```

Parallelizable groups (independent files, safe for parallel subagents):
{T1, T2}, {T10, T11, T12, T13} after T9, {T19, T20} after T11, {T16, T17}
after T9. Everything else is sequential. T6 can run any time after T1 (it
only needs a network). **T15 (matrix) and Gate 2 run only after Phase 3B**
— the matrix acceptance criteria include the never-drop and keepalive
behaviors.

### Effort estimates (single engineer, cold on this repo)

| Task | Est. | Task | Est. | Task | Est. |
|---|---|---|---|---|---|
| T1 mock | 0.5 d | T8 directives | 0.5 d | T15 matrix | 1 d |
| T2 netem | 0.25 d | T9 gate+geo | 1.5 d | T16 visibility | 1.5 d |
| T3 harness | 0.5 d | T10 verify | 1 d | T17 guard | 0.5 d |
| T4 baselines | 0.5 d | T11 failover | 1.5 d | T18 runbook | 1 d |
| T5 stock | 1 d | T12 manifest TTL | 1.5 d | T19 origin select | 2 d |
| T6 spike | 0.25 d | T13 negative | 0.5 d | T20 never-drop | 2 d |
| T7 classifier | 0.5 d | T14 proxy mode | 2 d | T21 keepalive | 0.75 d |
|  |  |  |  | T22 scvmfs (exp.) | 1.5 d |

Total ≈ 22.5 engineer-days (21 without the experimental scvmfs task) plus
the two OP gates and the Phase-5 pilot (2–4 weeks calendar, near-zero
engineering effort). T8/T9 include the dedicated-module scaffolding; T16
includes the full traffic-visibility stack (proto identity, access log,
dashboard), not just counters.

### Test-port registry (every port this plan allocates — no collisions)

| Ports | Owner |
|---|---|
| 12811–12814 | T1 pytest mock / T4 baselines (squid 12813, varnish 12814) |
| 12821–12823 | T5 stock config (mock / reverse / proxy listener) |
| 12831–12832 | T8/T9 `run_cvmfs_reverse.sh` (mock / cache) |
| 12841–12842 | T10 `run_cvmfs_verify.sh` |
| 12851–12853 | T11 `run_cvmfs_failover.sh` (mock1 / mock2 / cache) |
| 12861–12862 | T12 `run_cvmfs_manifest.sh` |
| 12871–12873 | T14 `run_cvmfs_proxy.sh` (mock1 / mock2 / cache) |
| 12881–12883 | T15 `run_matrix.sh` (mock / reverse / proxy listener) |
| 12891–12893 | T19 `run_cvmfs_select.sh` (mock A / mock B / cache; 127.0.0.1:1 = refused endpoint) |
| 12894–12895 | T20 `run_cvmfs_holdopen.sh` (mock / cache) |
| 12896–12898 | T21 `run_cvmfs_keepalive.sh` (mock / cache / neg-control listener) |
| 12901–12902 | T22 `run_scvmfs.sh` (mock / TLS listener) |
| 9100 | metrics scrapes (T16), standard module metrics port |
| 10.199.0.0/24 | T2 netem lab (host .1, ns .2) |

### Cross-cutting plumbing conventions (referenced by several tasks)

1. **Fill-context threading (T10, T12).** The CVMFS knobs that the fill
   worker needs (`quarantine_dir`, `manifest_ttl`, effective verify mode)
   travel on `xrootd_cache_fill_t`. Add to that struct (in
   `src/fs/cache/cache_internal.h`, next to its existing policy fields):

   ```c
       /* phase-68 CVMFS personality knobs, copied from the loc-conf at fill
        * allocation time (the worker thread must not touch ngx conf trees). */
       const char *cvmfs_quarantine_dir;   /* NULL/"" = unlink on mismatch  */
       time_t      cvmfs_manifest_ttl;     /* 0 = no expiry stamping        */
       unsigned    cvmfs_cas_verify:1;     /* mode == cvmfs-cas             */
   ```

   The cvmfs handler's fill-allocation path (whole-file `open_or_fill.c`
   reached from `handler.c`'s serve step) copies these from `lcf->cvmfs` +
   the location's cache conf; for non-cvmfs protocols the fields stay zero
   and every phase-68 branch is inert.

2. **Request-ctx override for proxy mode (T14).** The cvmfs module's own
   request ctx (`ngx_http_xrootd_cvmfs_ctx_t` in `cvmfs.h`, set by the
   handler on entry) carries:

   ```c
   typedef struct {
       xrootd_vfs_backend_entry_t *backend_override;  /* proxy mode (T14) */
       cvmfs_url_info_t            url;               /* classify result  */
       ngx_uint_t                  cache_status;      /* HIT/FILL/STALE/NEG
                                                         — $cvmfs_cache (T16) */
       ngx_str_t                   origin_used;       /* host:port of fill
                                                         origin — $cvmfs_origin */
       unsigned                    secure:1;          /* scvmfs (T22)     */
   } ngx_http_xrootd_cvmfs_ctx_t;
   ```

   The single place the handler's serve path resolves "which backend entry
   serves this request" (`cvmfs_resolve_backend()` in `handler.c`) checks
   `ctx->backend_override` first, else the location's static entry. Every
   downstream layer (tier, cache, sd_http) is backend-entry-driven already
   and needs no change.

3. **Status mapping for fill failures.** Fills surface errno per the
   existing table (CLAUDE.md `errno → kXR → HTTP`): verify MISMATCH sets
   `EIO`-class failure with `kXR_ChkSumErr`, which the HTTP plane maps to
   **502** (bad gateway: the *origin transfer* was bad, not the client
   request). Both-origins-down (T11) is `EIO` → 502 as well. A REQUIRE-mode
   verify with no computable digest is 502. Client-side CVMFS handles 5xx
   by failing over per its own proxy/host lists — never send 500 for
   origin-side trouble, reserve it for genuine local faults.

4. **Log line shape for rejects (T9/T17).** Rejected requests log one
   WARN via `XROOTD_DIAG` with fixed prefix `cvmfs-reject`:

   ```
   ... [warn] ... cvmfs-reject: method=%V uri="%V" client=%V class=reject
       cause="path is not a CVMFS traffic shape"
       fix="only /cvmfs/<repo>/{data/…,.cvmfspublished,.cvmfswhitelist,.cvmfsreflog,api/v1.0/geo/…} are served"
   ```

   URI is passed through `xrootd_sanitize_log_string()` first. The
   fail2ban filter (T17) and the httpguard log-phase classifier both key
   on `cvmfs-reject:`; keep the prefix stable.

5. **Naming.** All new exported symbols are `xrootd_cvmfs_*`; file-static
   helpers are `cvmfs_*`. New directives are `xrootd_cvmfs_*`. Metric
   series are `xrootd_cvmfs_*_total`. Test scripts are
   `tests/run_cvmfs_*.sh`. No exceptions — greppability is a feature.

6. **Client-connection durability rules (T20/T21 — binding on every task
   that touches a response path).** The CVMFS client keeps per-proxy
   failure bookkeeping; a proxy that *breaks connections* gets skipped
   (client falls to the next proxy group or DIRECT) — which defeats the
   whole cache. Therefore:
   - **A TCP close/reset is NEVER used as an error signal.** Every
     client-visible failure is a well-formed HTTP response with a
     `Content-Length`, sent on a connection that stays open
     (`r->keepalive = 1`).
   - Origin trouble while a client waits → hold the request and keep
     retrying upstream until `xrootd_cvmfs_client_hold` expires; only then
     answer **504 + `Retry-After`** (still keep-alive). The client's own
     retry re-enters through the same warm TCP connection and coalesces
     onto the still-running fill.
   - **502** is reserved for *definitive* origin badness inside the hold
     window (CAS verify mismatch after all endpoints tried); **504** means
     "still trying, come back"; **404** is a definitive origin answer and
     is never retried.
   - Client aborting NEVER cancels a fill (detached fills, T20): the fill
     completes and populates the cache so the retry is a hit.

7. **Upstream-outcome classification (T20; single source of truth —
   `fill_retry.h`).**

   | Fill outcome | Action |
   |---|---|
   | connect refused / unreachable / timeout / TLS fail | backoff, next-ranked endpoint, retry until deadline |
   | mid-transfer stall (LOW_SPEED) / reset | same as above (partial `.part` discarded) |
   | HTTP 5xx from origin | same as above |
   | HTTP 404 / 403 from origin | definitive — stop, propagate (404 feeds the T13 negative cache) |
   | CAS verify MISMATCH (T10) | quarantine; retry ONCE per remaining endpoint (corruption is often path-local); all mismatch ⇒ 502 |
   | success | done |

   Deadline: `xrootd_cvmfs_client_hold` (default 25 s) while ≥ 1 waiter is
   attached; `xrootd_cvmfs_fill_max_life` (default 300 s) once detached.
   Backoff: 250 ms doubling to an 8 s cap, half-jitter.

## File Structure (locked in up front)

```
tests/cvmfs/
  mock_stratum1.py        synthetic CVMFS repo server + fault injection + request log
  netem_lab.sh            netns/veth + tc netem profiles (clean/loss/reorder/corrupt/jitter)
  harness.py              scenario runner (TTFB, error rate, stampede, corrupt-admission) → JSON
  spike_cas_hash.sh       one-shot spike: pin CVMFS hash convention vs a real Stratum-1
tests/
  test_cvmfs_mock.py      pytest for the mock server (fault modes, layout)
  test_cvmfs_harness.py   pytest for the harness metrics math
  run_cvmfs_classify.sh   standalone-gcc unit test for the pure-C classifier
  run_cvmfs_reverse.sh    e2e reverse-mode: cold fill / warm hit / stampede / gate rejects
  run_cvmfs_verify.sh     bit-flip netem → 0 corrupt admissions + quarantine
  run_cvmfs_failover.sh   two origins, one stalled → transparent failover
  run_cvmfs_manifest.sh   manifest TTL / revalidate / stale-if-error
  run_cvmfs_proxy.sh      absolute-URI proxy mode + allowlist security-neg
  run_cvmfs_select.sh     origin selection: static order / geo coords / rtt probe
  run_cvmfs_holdopen.sh   never-drop semantics: hold+retry, 504-keepalive, detached fill
  run_cvmfs_keepalive.sh  TCP keepalive on the wire + conn survives errors + reuse
  run_scvmfs.sh           EXPERIMENTAL scvmfs://: TLS-only + authz gate + parity
deploy/cvmfs/
  nginx-proxy-cache.conf  Phase-1 stock-nginx config (deployable, also the control group)
  baselines/squid.conf    comparison baseline
  baselines/varnish.vcl   comparison baseline
  README.md               runbook: sizing, topology, client config, Squid migration
src/protocols/cvmfs/     ← DEDICATED PROTOCOL DIRECTORY (peer of webdav/, s3/)
  module.c                nginx HTTP module: loc-conf create/merge, directive
                          table (all xrootd_cvmfs_* + xrootd_scvmfs_*),
                          postconfig content-handler installation
  cvmfs.h                 protocol surface: loc-conf + request-ctx structs,
                          gate/handler prototypes, metric macro
  handler.c               dedicated content handler: ctx setup, method filter,
                          gate, backend resolve, tier open-or-fill, file
                          response via core/http helpers
  classify.h classify.c   pure-C URL classifier (no ngx deps — standalone-testable)
  gate.c                  classify → route/reject policy + negative cache
  geo.c                   uncached Geo-API passthrough over the shared HTTP transport
  request.c               proxy-mode absolute-URI → (upstream, path) + allowlist
  upstreams.c             bounded lazy per-upstream backend registry (proxy mode)
  origin_geo.c/.h         pure-C haversine + rank-by-metric (standalone-testable)
  origin_probe.c          per-worker RTT probe timer (thread-pool connect timing)
  secure.c                scvmfs:// security preamble: TLS-required check +
                          optional bearer/VOMS authz gate (EXPERIMENTAL, T22)
src/fs/cache/
  fill_retry.c/.h         upstream-outcome classification + backoff retry loop
                          + detached-fill deadline logic (convention #7)
  verify.c                + XROOTD_CACHE_VERIFY_CVMFS_CAS mode + quarantine
  cinfo.{c,h}             + optional expires_at (manifest TTL), v3-compatible flag bit
src/fs/backend/http/
  sd_http.c               + multi-endpoint set with EWMA health + failover
src/observability/metrics/  + cvmfs counter family
```

---

# PHASE 0 — Lab + baselines (no module code)

### Task 1: Mock Stratum-1 server

**Files:**
- Create: `tests/cvmfs/mock_stratum1.py`
- Test: `tests/test_cvmfs_mock.py`

**Interfaces:**
- Produces: `python3 tests/cvmfs/mock_stratum1.py --port P --repo test.cern.ch --objects N [--seed S]` — serves `/cvmfs/<repo>/.cvmfspublished`, `/cvmfs/<repo>/.cvmfswhitelist`, `/cvmfs/<repo>/data/<2hex>/<38hex>[C]`, `/cvmfs/<repo>/api/v1.0/geo/<proxy>/<servers>`.
- Control API (consumed by every later e2e test): `GET /ctl/log` → JSON list of `{path, ts}`; `POST /ctl/fault {"mode": "none|stall|reset|corrupt", "count": N}` (fault applies to the next N data requests); `GET /ctl/manifest/bump` → rewrites `.cvmfspublished` with a new revision.
- `make_repo(root, repo, n_objects, seed)` — also importable so tests can compute expected hashes.

- [ ] **Step 1: Write the failing pytest**

```python
# tests/test_cvmfs_mock.py
import hashlib, json, subprocess, sys, time, urllib.request, urllib.error
import pytest

PORT = 12811
BASE = f"http://127.0.0.1:{PORT}"

@pytest.fixture(scope="module")
def mock():
    p = subprocess.Popen([sys.executable, "tests/cvmfs/mock_stratum1.py",
                          "--port", str(PORT), "--repo", "test.cern.ch",
                          "--objects", "8", "--seed", "42"])
    for _ in range(50):
        try:
            urllib.request.urlopen(BASE + "/ctl/log", timeout=0.2); break
        except Exception:
            time.sleep(0.1)
    yield BASE
    p.terminate(); p.wait()

def _objects(base):
    return json.load(urllib.request.urlopen(base + "/ctl/objects"))

def test_cas_object_name_is_sha1_of_body(mock):
    for url in _objects(mock)[:3]:
        body = urllib.request.urlopen(mock + url).read()
        hexd = url.rsplit("/", 2)[-2] + url.rsplit("/", 2)[-1]
        hexd = hexd.rstrip("C")                      # catalog suffix
        assert hashlib.sha1(body).hexdigest() == hexd

def test_manifest_present_and_bumpable(mock):
    m1 = urllib.request.urlopen(mock + "/cvmfs/test.cern.ch/.cvmfspublished").read()
    urllib.request.urlopen(mock + "/ctl/manifest/bump")
    m2 = urllib.request.urlopen(mock + "/cvmfs/test.cern.ch/.cvmfspublished").read()
    assert m1 != m2

def test_fault_corrupt_flips_bytes_once(mock):
    url = _objects(mock)[0]
    good = urllib.request.urlopen(mock + url).read()
    req = urllib.request.Request(mock + "/ctl/fault", method="POST",
        data=json.dumps({"mode": "corrupt", "count": 1}).encode())
    urllib.request.urlopen(req)
    bad = urllib.request.urlopen(mock + url).read()
    assert bad != good and len(bad) == len(good)
    assert urllib.request.urlopen(mock + url).read() == good   # fault consumed

def test_fault_reset_drops_connection(mock):
    url = _objects(mock)[0]
    req = urllib.request.Request(mock + "/ctl/fault", method="POST",
        data=json.dumps({"mode": "reset", "count": 1}).encode())
    urllib.request.urlopen(req)
    with pytest.raises(Exception):
        urllib.request.urlopen(mock + url, timeout=3).read()

def test_request_log_records_paths(mock):
    url = _objects(mock)[1]
    urllib.request.urlopen(mock + url).read()
    log = json.load(urllib.request.urlopen(mock + "/ctl/log"))
    assert any(e["path"] == url for e in log)

def test_geo_api_returns_server_order(mock):
    r = urllib.request.urlopen(
        mock + "/cvmfs/test.cern.ch/api/v1.0/geo/x/a.cern.ch,b.cern.ch").read()
    assert r.strip() in (b"1,2", b"2,1")
```

- [ ] **Step 2: Run to verify it fails**

Run: `PYTHONPATH=tests pytest tests/test_cvmfs_mock.py -v`
Expected: FAIL (`mock_stratum1.py` not found).

- [ ] **Step 3: Implement the mock**

```python
#!/usr/bin/env python3
# tests/cvmfs/mock_stratum1.py — synthetic CVMFS Stratum-1 with fault injection.
#
# Serves a real CVMFS URL layout (manifest, whitelist, SHA1-named CAS objects,
# geo API) plus a /ctl/ control plane for tests: request log, one-shot faults
# (stall / reset / corrupt), manifest bump. Single-threaded-safe state via a lock.
import argparse, hashlib, json, os, random, socket, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

STATE = {"log": [], "fault": {"mode": "none", "count": 0},
         "objects": {}, "repo": "", "revision": 1, "lock": threading.Lock()}

def make_repo(repo, n_objects, seed):
    rng = random.Random(seed)
    objs = {}
    for i in range(n_objects):
        body = bytes(rng.getrandbits(8) for _ in range(rng.randint(4096, 262144)))
        hexd = hashlib.sha1(body).hexdigest()
        suffix = "C" if i == 0 else ""          # object 0 poses as a catalog
        objs[f"/cvmfs/{repo}/data/{hexd[:2]}/{hexd[2:]}{suffix}"] = body
    return objs

def manifest(repo, revision):
    root = hashlib.sha1(f"{repo}:{revision}".encode()).hexdigest()
    return (f"C{root}\nB4096\nRd41d8cd98f00b204e9800998ecf8427e\n"
            f"D240\nS{revision}\nN{repo}\nX{root}\nT{int(time.time())}\n"
            f"--\n{root}\n").encode()

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):        # silence default stderr chatter
        pass

    def _send(self, code, body, ctype="application/octet-stream"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _take_fault(self):
        with STATE["lock"]:
            f = STATE["fault"]
            if f["count"] > 0:
                f["count"] -= 1
                return f["mode"]
        return "none"

    def do_POST(self):
        if self.path == "/ctl/fault":
            n = int(self.headers.get("Content-Length", 0))
            req = json.loads(self.rfile.read(n))
            with STATE["lock"]:
                STATE["fault"] = {"mode": req["mode"], "count": int(req["count"])}
            return self._send(200, b"ok")
        self._send(404, b"")

    def do_GET(self):
        repo = STATE["repo"]
        if self.path == "/ctl/log":
            with STATE["lock"]:
                body = json.dumps(STATE["log"]).encode()
            return self._send(200, body, "application/json")
        if self.path == "/ctl/objects":
            return self._send(200, json.dumps(sorted(STATE["objects"])).encode(),
                              "application/json")
        if self.path == "/ctl/manifest/bump":
            with STATE["lock"]:
                STATE["revision"] += 1
            return self._send(200, b"ok")

        with STATE["lock"]:
            STATE["log"].append({"path": self.path, "ts": time.time()})

        if self.path == f"/cvmfs/{repo}/.cvmfspublished":
            return self._send(200, manifest(repo, STATE["revision"]))
        if self.path == f"/cvmfs/{repo}/.cvmfswhitelist":
            return self._send(200, b"mock-whitelist\n")
        if self.path.startswith(f"/cvmfs/{repo}/api/v1.0/geo/"):
            servers = self.path.rsplit("/", 1)[-1].split(",")
            order = ",".join(str(i + 1) for i in range(len(servers)))
            return self._send(200, order.encode() + b"\n", "text/plain")

        body = STATE["objects"].get(self.path)
        if body is None:
            return self._send(404, b"not found")
        mode = self._take_fault()
        if mode == "reset":
            self.connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                                       b"\x01\x00\x00\x00\x00\x00\x00\x00")
            self.connection.close()
            return
        if mode == "stall":
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body[:64]); self.wfile.flush()
            time.sleep(30)                      # longer than any fill stall timeout
            return
        if mode == "corrupt":
            body = bytes(b ^ 0xFF if i == len(body) // 2 else b
                         for i, b in enumerate(body))
        self._send(200, body)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--repo", default="test.cern.ch")
    ap.add_argument("--objects", type=int, default=16)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--bind", default="127.0.0.1")
    args = ap.parse_args()
    STATE["repo"] = args.repo
    STATE["objects"] = make_repo(args.repo, args.objects, args.seed)
    ThreadingHTTPServer((args.bind, args.port), Handler).serve_forever()

if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run to verify it passes**

Run: `PYTHONPATH=tests pytest tests/test_cvmfs_mock.py -v`
Expected: 6 PASS.

- [ ] **Step 5: Commit**

```bash
git add tests/cvmfs/mock_stratum1.py tests/test_cvmfs_mock.py
git commit -m "test(cvmfs): mock Stratum-1 with CAS layout, fault injection, request log"
```

---

### Task 2: netem lab

**Files:**
- Create: `tests/cvmfs/netem_lab.sh`

**Interfaces:**
- Produces: `netem_lab.sh up|down|profile <name>|status`. `up` creates netns `cvmfslab` with veth pair `cvmfs-h` (host, `10.199.0.1/24`) ↔ `cvmfs-n` (ns, `10.199.0.2/24`). Origin processes run **inside** the ns bound to `10.199.0.2`; the cache under test runs on the host and reaches the origin through the impaired veth. Profiles: `clean`, `loss` (3 % loss), `reorder` (25 % reorder, 10 ms), `corrupt` (0.5 % corrupt), `jitter` (80 ms ± 40 ms), `site` (all of the above mildly — the Tier-2 pathology composite).
- Needs root (`sudo`); every consumer test must skip gracefully when `ip netns` is unavailable.

- [ ] **Step 1: Write the script**

```bash
#!/usr/bin/env bash
# tests/cvmfs/netem_lab.sh — impaired-network lab for CVMFS cache testing.
# Host side 10.199.0.1 (cache under test) <-> ns "cvmfslab" 10.199.0.2 (origin).
# Impairment is applied on BOTH veth ends so loss/reorder hits each direction.
set -eu
NS=cvmfslab; VH=cvmfs-h; VN=cvmfs-n; HIP=10.199.0.1; NIP=10.199.0.2

profile_args() {
    case "$1" in
        clean)   echo "" ;;
        loss)    echo "loss 3%" ;;
        reorder) echo "delay 10ms reorder 25% 50%" ;;
        corrupt) echo "corrupt 0.5%" ;;
        jitter)  echo "delay 80ms 40ms distribution normal" ;;
        site)    echo "delay 30ms 15ms loss 1% reorder 10% 50% corrupt 0.1%" ;;
        *) echo "unknown profile: $1" >&2; exit 2 ;;
    esac
}

cmd_up() {
    ip netns add "$NS"
    ip link add "$VH" type veth peer name "$VN"
    ip link set "$VN" netns "$NS"
    ip addr add "$HIP/24" dev "$VH"; ip link set "$VH" up
    ip netns exec "$NS" ip addr add "$NIP/24" dev "$VN"
    ip netns exec "$NS" ip link set "$VN" up
    ip netns exec "$NS" ip link set lo up
    echo "lab up: host $HIP <-> ns $NS $NIP"
}

cmd_profile() {
    local args; args="$(profile_args "$1")"
    tc qdisc del dev "$VH" root 2>/dev/null || true
    ip netns exec "$NS" tc qdisc del dev "$VN" root 2>/dev/null || true
    if [ -n "$args" ]; then
        # shellcheck disable=SC2086
        tc qdisc add dev "$VH" root netem $args
        # shellcheck disable=SC2086
        ip netns exec "$NS" tc qdisc add dev "$VN" root netem $args
    fi
    echo "profile: $1 ($args)"
}

cmd_down() {
    ip link del "$VH" 2>/dev/null || true
    ip netns del "$NS" 2>/dev/null || true
    echo "lab down"
}

case "${1:-}" in
    up) cmd_up ;;
    down) cmd_down ;;
    profile) cmd_profile "${2:?profile name}" ;;
    status) tc qdisc show dev "$VH" 2>/dev/null || echo "lab not up" ;;
    *) echo "usage: $0 up|down|profile <clean|loss|reorder|corrupt|jitter|site>|status" >&2
       exit 2 ;;
esac
```

- [ ] **Step 2: Verify by hand (requires sudo; skip on CI)**

Run: `sudo tests/cvmfs/netem_lab.sh up && sudo tests/cvmfs/netem_lab.sh profile loss && ping -c3 -I 10.199.0.1 10.199.0.2; sudo tests/cvmfs/netem_lab.sh down`
Expected: pings succeed (possibly with drops); `profile: loss (loss 3%)` printed; teardown clean.

- [ ] **Step 3: Commit**

```bash
chmod +x tests/cvmfs/netem_lab.sh
git add tests/cvmfs/netem_lab.sh
git commit -m "test(cvmfs): tc-netem lab with site-pathology profiles"
```

---

### Task 3: Scenario harness

**Files:**
- Create: `tests/cvmfs/harness.py`
- Test: `tests/test_cvmfs_harness.py`

**Interfaces:**
- Consumes: mock Stratum-1 control API (Task 1).
- Produces: `run_scenarios(cache_base_url, mock_ctl_url, object_urls) -> dict` and CLI `python3 tests/cvmfs/harness.py --cache URL --mock URL --out results.json`. Result keys (later tasks assert on these): `cold_ttfb_p50_ms`, `cold_ttfb_p99_ms`, `warm_ttfb_p50_ms`, `error_rate`, `stampede_origin_fetches` (int — MUST be 1 for a coalescing cache), `corrupt_served` (int — MUST be 0 for a verifying cache).

- [ ] **Step 1: Write the failing pytest** (pure-math checks; no servers needed)

```python
# tests/test_cvmfs_harness.py
import sys
sys.path.insert(0, "tests/cvmfs")
from harness import percentile, summarize

def test_percentile_interpolation():
    assert percentile([10, 20, 30, 40], 50) == 25.0
    assert percentile([5], 99) == 5.0

def test_summarize_counts_errors_and_corruption():
    samples = [
        {"ok": True,  "ttfb_ms": 10, "body_sha1": "aa", "expect_sha1": "aa"},
        {"ok": False, "ttfb_ms": None, "body_sha1": None, "expect_sha1": "aa"},
        {"ok": True,  "ttfb_ms": 30, "body_sha1": "XX", "expect_sha1": "aa"},
    ]
    s = summarize(samples)
    assert s["error_rate"] == 1 / 3
    assert s["corrupt_served"] == 1
    assert s["ttfb_p50_ms"] == 20.0
```

- [ ] **Step 2: Run to verify it fails**

Run: `PYTHONPATH=tests pytest tests/test_cvmfs_harness.py -v`
Expected: FAIL (no `harness` module).

- [ ] **Step 3: Implement**

```python
#!/usr/bin/env python3
# tests/cvmfs/harness.py — measures a CVMFS cache: TTFB, errors, coalescing,
# corruption admission. Output JSON is the comparison currency across
# squid/varnish/stock-nginx/module runs.
import argparse, concurrent.futures, hashlib, json, time, urllib.request

def percentile(vals, p):
    xs = sorted(vals)
    if not xs:
        return None
    if len(xs) == 1:
        return float(xs[0])
    k = (len(xs) - 1) * p / 100.0
    lo, hi = int(k), min(int(k) + 1, len(xs) - 1)
    return xs[lo] + (xs[hi] - xs[lo]) * (k - lo)

def fetch(url, expect_sha1, timeout=20):
    t0 = time.monotonic()
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            first = r.read(1)
            ttfb = (time.monotonic() - t0) * 1000.0
            body = first + r.read()
        return {"ok": True, "ttfb_ms": ttfb,
                "body_sha1": hashlib.sha1(body).hexdigest(),
                "expect_sha1": expect_sha1}
    except Exception:
        return {"ok": False, "ttfb_ms": None, "body_sha1": None,
                "expect_sha1": expect_sha1}

def summarize(samples):
    oks = [s for s in samples if s["ok"]]
    return {
        "error_rate": (len(samples) - len(oks)) / len(samples) if samples else 0,
        "corrupt_served": sum(1 for s in oks
                              if s["body_sha1"] != s["expect_sha1"]),
        "ttfb_p50_ms": percentile([s["ttfb_ms"] for s in oks], 50),
        "ttfb_p99_ms": percentile([s["ttfb_ms"] for s in oks], 99),
    }

def _expect(url):
    hexd = url.rsplit("/", 2)[-2] + url.rsplit("/", 2)[-1]
    return hexd.rstrip("C")

def _origin_fetches(mock, path):
    log = json.load(urllib.request.urlopen(mock + "/ctl/log"))
    return sum(1 for e in log if e["path"] == path)

def run_scenarios(cache, mock, objects, stampede_n=50):
    out = {}
    cold = [fetch(cache + u, _expect(u)) for u in objects]
    c = summarize(cold)
    out["cold_ttfb_p50_ms"], out["cold_ttfb_p99_ms"] = c["ttfb_p50_ms"], c["ttfb_p99_ms"]
    warm = [fetch(cache + u, _expect(u)) for u in objects]
    out["warm_ttfb_p50_ms"] = summarize(warm)["ttfb_p50_ms"]
    out["error_rate"] = summarize(cold + warm)["error_rate"]
    out["corrupt_served"] = summarize(cold + warm)["corrupt_served"]

    # stampede: N concurrent cold requests for ONE object → count origin hits
    victim = objects[-1]
    before = _origin_fetches(mock, victim)
    with concurrent.futures.ThreadPoolExecutor(max_workers=stampede_n) as ex:
        res = list(ex.map(lambda _: fetch(cache + victim, _expect(victim)),
                          range(stampede_n)))
    assert all(r["ok"] for r in res), "stampede requests failed"
    out["stampede_origin_fetches"] = _origin_fetches(mock, victim) - before
    return out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cache", required=True)
    ap.add_argument("--mock", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    objects = json.load(urllib.request.urlopen(args.mock + "/ctl/objects"))
    results = run_scenarios(args.cache, args.mock, objects)
    with open(args.out, "w") as f:
        json.dump(results, f, indent=2)
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run to verify it passes**

Run: `PYTHONPATH=tests pytest tests/test_cvmfs_harness.py -v`
Expected: 3 PASS.

- [ ] **Step 5: Commit**

```bash
git add tests/cvmfs/harness.py tests/test_cvmfs_harness.py
git commit -m "test(cvmfs): scenario harness — TTFB/error/coalescing/corruption metrics"
```

---

### Task 4: Squid + Varnish baseline configs and a baseline runner

**Files:**
- Create: `deploy/cvmfs/baselines/squid.conf`, `deploy/cvmfs/baselines/varnish.vcl`, `tests/cvmfs/run_baselines.sh`

**Interfaces:**
- Produces: `tests/cvmfs/run_baselines.sh <squid|varnish> <listen-port> <origin-host:port>` — starts the proxy with the baseline config against the mock, runs `harness.py`, writes `baseline_<name>.json`. Skips with exit 0 + message if the binary is absent (dev boxes won't all have squid/varnish).

- [ ] **Step 1: Write the configs**

```
# deploy/cvmfs/baselines/squid.conf — WLCG-style CVMFS frontier/squid baseline.
# Values follow the standard cvmfs squid guidance; ports/dirs templated by
# run_baselines.sh (@PORT@, @CACHEDIR@, @ORIGIN@).
http_port @PORT@
cache_mem 128 MB
maximum_object_size_in_memory 128 KB
cache_dir ufs @CACHEDIR@ 1024 16 256
maximum_object_size 1024 MB
collapsed_forwarding on
acl cvmfs_dst dstdomain @ORIGINHOST@
http_access allow cvmfs_dst
http_access deny all
refresh_pattern /.cvmfspublished$ 0 0% 2 refresh-ims
refresh_pattern /.cvmfswhitelist$ 0 0% 2 refresh-ims
refresh_pattern /data/ 1440 100% 43200 ignore-reload
refresh_pattern . 0 20% 4320
```

```vcl
# deploy/cvmfs/baselines/varnish.vcl — minimal CVMFS caching baseline.
vcl 4.1;
backend stratum1 { .host = "@ORIGINHOST@"; .port = "@ORIGINPORT@"; }

sub vcl_recv {
    if (req.url !~ "^/cvmfs/") { return (synth(403)); }
    if (req.url ~ "/api/v1\.0/geo/") { return (pass); }
    return (hash);
}
sub vcl_backend_response {
    if (bereq.url ~ "/data/") { set beresp.ttl = 30d; }
    elsif (bereq.url ~ "\.cvmfs(published|whitelist|reflog)$") {
        set beresp.ttl = 61s; set beresp.grace = 10m;
    }
}
```

- [ ] **Step 2: Write the runner**

```bash
#!/usr/bin/env bash
# tests/cvmfs/run_baselines.sh — run the harness against a squid or varnish
# baseline. Produces baseline_<name>.json for the comparison matrix. Skips
# cleanly when the proxy binary is not installed.
set -eu
NAME="${1:?squid|varnish}"; PORT="${2:?listen port}"; ORIGIN="${3:?host:port}"
HERE="$(cd "$(dirname "$0")" && pwd)"; REPO="$(cd "$HERE/../.." && pwd)"
OHOST="${ORIGIN%%:*}"; OPORT="${ORIGIN##*:}"
WORK="$(mktemp -d /tmp/cvmfs_baseline.XXXXXX)"; trap 'rm -rf "$WORK"' EXIT

case "$NAME" in
squid)
    command -v squid >/dev/null || { echo "SKIP: squid not installed"; exit 0; }
    sed -e "s/@PORT@/$PORT/" -e "s#@CACHEDIR@#$WORK/cache#" \
        -e "s/@ORIGINHOST@/$OHOST/" \
        "$REPO/deploy/cvmfs/baselines/squid.conf" > "$WORK/squid.conf"
    mkdir -p "$WORK/cache"
    squid -f "$WORK/squid.conf" -z 2>/dev/null; squid -f "$WORK/squid.conf"
    STOP="squid -f $WORK/squid.conf -k shutdown"
    # squid is a forward proxy: harness must use proxy-style URLs
    export http_proxy="http://127.0.0.1:$PORT"
    CACHEBASE="http://$ORIGIN"
    ;;
varnish)
    command -v varnishd >/dev/null || { echo "SKIP: varnishd not installed"; exit 0; }
    sed -e "s/@ORIGINHOST@/$OHOST/" -e "s/@ORIGINPORT@/$OPORT/" \
        "$REPO/deploy/cvmfs/baselines/varnish.vcl" > "$WORK/default.vcl"
    varnishd -a "127.0.0.1:$PORT" -f "$WORK/default.vcl" -n "$WORK/vn" -s malloc,256m
    STOP="pkill -f 'varnishd .*$WORK/vn'"
    CACHEBASE="http://127.0.0.1:$PORT"
    ;;
*) echo "unknown: $NAME" >&2; exit 2 ;;
esac

sleep 1
python3 "$HERE/harness.py" --cache "$CACHEBASE" \
    --mock "http://$ORIGIN" --out "baseline_${NAME}.json"
eval "$STOP" || true
echo "wrote baseline_${NAME}.json"
```

- [ ] **Step 3: Verify (with mock running; skips if proxies absent)**

Run:
```bash
python3 tests/cvmfs/mock_stratum1.py --port 12812 --objects 8 & MOCK=$!
tests/cvmfs/run_baselines.sh squid 12813 127.0.0.1:12812
tests/cvmfs/run_baselines.sh varnish 12814 127.0.0.1:12812
kill $MOCK
```
Expected: either `baseline_*.json` written with the six harness keys, or `SKIP: … not installed`.

- [ ] **Step 4: Commit**

```bash
chmod +x tests/cvmfs/run_baselines.sh
git add deploy/cvmfs/baselines/ tests/cvmfs/run_baselines.sh
git commit -m "test(cvmfs): squid/varnish baseline configs + harness runner"
```

**Phase-0 exit criterion:** with the netem `site` profile up and the mock in the ns, `run_baselines.sh` produces JSON for at least one of squid/varnish showing nonzero `error_rate` or `corrupt_served` under the `corrupt` profile — the yardstick numbers.

---

# PHASE 1 — Stock-nginx config prototype (Approach A, the control group)

### Task 5: `proxy_cache` prototype config + e2e run

**Files:**
- Create: `deploy/cvmfs/nginx-proxy-cache.conf`
- Test: `tests/run_cvmfs_stock.sh`

**Interfaces:**
- Produces: a deployable stock-nginx config (no module directives) implementing: per-class TTL, request coalescing (`proxy_cache_lock`), stale-on-error, Stratum-1 failover, reverse mode on `@PORT@` and proxy mode (absolute-URI via `$http_host` allowlist) on `@PPORT@`.
- The harness numbers from this task are the Phase-1 decision-gate input.

- [ ] **Step 1: Write the config**

```nginx
# deploy/cvmfs/nginx-proxy-cache.conf — CVMFS site cache on STOCK nginx.
# Templated by run_cvmfs_stock.sh: @PORT@ @PPORT@ @CACHEDIR@ @ORIGIN@ (host:port)
# Phase-1 prototype AND permanent control group for the module personality.
worker_processes 2;
error_log @CACHEDIR@/error.log info;
pid @CACHEDIR@/nginx.pid;
events { worker_connections 1024; }

http {
    access_log off;
    proxy_cache_path @CACHEDIR@/store levels=1:2 keys_zone=cvmfs:64m
                     max_size=10g inactive=30d use_temp_path=off;

    # URL class → TTL. CAS objects are content-addressed: cache ~forever.
    map $uri $cvmfs_ttl {
        ~/data/[0-9a-f]{2}/[0-9a-f]{36,}  720h;
        ~/\.cvmfs(published|whitelist|reflog)$  61s;
        default  0s;                       # geo api + everything else: uncached
    }

    upstream stratum1s {
        server @ORIGIN@ max_fails=3 fail_timeout=15s;
        # additional Stratum-1s appended here in production
    }

    # ---- reverse mode: CVMFS_SERVER_URL=http://cache:@PORT@/cvmfs/@fqrn@ ----
    server {
        listen @PORT@;
        location /cvmfs/ {
            proxy_pass http://stratum1s;
            proxy_cache cvmfs;
            proxy_cache_valid 200 $cvmfs_ttl;
            proxy_cache_key $uri;
            proxy_cache_lock on;                     # request coalescing
            proxy_cache_lock_timeout 60s;
            proxy_cache_use_stale error timeout updating http_502 http_504;
            proxy_connect_timeout 5s;
            proxy_read_timeout 20s;                  # stall guard
            proxy_next_upstream error timeout http_502 http_504;
            proxy_http_version 1.1;
            proxy_set_header Connection "";
        }
        location / { return 403; }
    }

    # ---- proxy mode: CVMFS_HTTP_PROXY=http://cache:@PPORT@ -------------------
    # CVMFS clients send absolute URIs; nginx resolves them and exposes $host.
    map $host $cvmfs_upstream_ok {
        hostnames;
        default 0;
        @ORIGINHOST@ 1;
        # every allowed Stratum-1 host listed here in production
    }
    server {
        listen @PPORT@;
        resolver 127.0.0.53 valid=300s ipv6=off;
        location / {
            if ($cvmfs_upstream_ok = 0) { return 403; }
            if ($uri !~ "^/cvmfs/") { return 403; }
            proxy_pass http://$host:$cvmfs_upstream_port$request_uri;
            proxy_cache cvmfs;
            proxy_cache_valid 200 $cvmfs_ttl;
            proxy_cache_key $host$uri;
            proxy_cache_lock on;
            proxy_cache_lock_timeout 60s;
            proxy_cache_use_stale error timeout updating http_502 http_504;
            proxy_connect_timeout 5s;
            proxy_read_timeout 20s;
        }
    }
    map $host $cvmfs_upstream_port { default 80; @ORIGINHOST@ @ORIGINPORT@; }
}
```

- [ ] **Step 2: Write the e2e test**

```bash
#!/usr/bin/env bash
# tests/run_cvmfs_stock.sh — Phase-1 stock-nginx CVMFS cache e2e:
#   1 cold+warm byte-exact through reverse mode
#   2 stampede → exactly 1 origin fetch (proxy_cache_lock)
#   3 security-neg: non-/cvmfs/ path → 403; disallowed upstream host → 403
set -u
NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
HERE="$(cd "$(dirname "$0")" && pwd)"; REPO="$(cd "$HERE/.." && pwd)"
MPORT=12821; RPORT=12822; PPORT=12823
PFX="$(mktemp -d /tmp/cvmfs_stock.XXXXXX)"; fail=0
ok(){ printf '  ok   %s\n' "$1"; }; bad(){ printf '  FAIL %s\n' "$1"; fail=1; }
cleanup(){ [ -f "$PFX/nginx.pid" ] && kill "$(cat "$PFX/nginx.pid")" 2>/dev/null
           kill "$MOCK" 2>/dev/null; rm -rf "$PFX"; }
trap cleanup EXIT

python3 "$HERE/cvmfs/mock_stratum1.py" --port $MPORT --objects 8 --seed 7 &
MOCK=$!; sleep 0.5

sed -e "s/@PORT@/$RPORT/" -e "s/@PPORT@/$PPORT/" -e "s#@CACHEDIR@#$PFX#" \
    -e "s/@ORIGIN@/127.0.0.1:$MPORT/" -e "s/@ORIGINHOST@/127.0.0.1/g" \
    -e "s/@ORIGINPORT@/$MPORT/" \
    "$REPO/deploy/cvmfs/nginx-proxy-cache.conf" > "$PFX/nginx.conf"
mkdir -p "$PFX/store"
"$NGINX" -c "$PFX/nginx.conf" -p "$PFX" || { bad "nginx start"; exit 1; }
sleep 0.5

OBJ="$(curl -s "http://127.0.0.1:$MPORT/ctl/objects" | python3 -c \
      'import json,sys; print(json.load(sys.stdin)[0])')"

# 1: cold + warm byte-exact
curl -s "http://127.0.0.1:$RPORT$OBJ" -o "$PFX/cold.bin"
curl -s "http://127.0.0.1:$RPORT$OBJ" -o "$PFX/warm.bin"
curl -s "http://127.0.0.1:$MPORT$OBJ" -o "$PFX/orig.bin"
cmp -s "$PFX/cold.bin" "$PFX/orig.bin" && cmp -s "$PFX/warm.bin" "$PFX/orig.bin" \
    && ok "cold+warm byte-exact" || bad "byte mismatch"

# 2: stampede coalescing on a fresh object
OBJ2="$(curl -s "http://127.0.0.1:$MPORT/ctl/objects" | python3 -c \
      'import json,sys; print(json.load(sys.stdin)[3])')"
N0="$(curl -s "http://127.0.0.1:$MPORT/ctl/log" | grep -c "$OBJ2" || true)"
for i in $(seq 1 40); do curl -s "http://127.0.0.1:$RPORT$OBJ2" -o /dev/null & done
wait
N1="$(curl -s "http://127.0.0.1:$MPORT/ctl/log" | grep -c "$OBJ2" || true)"
[ "$((N1 - N0))" -le 2 ] && ok "stampede coalesced ($((N1-N0)) origin fetches)" \
    || bad "stampede: $((N1-N0)) origin fetches"

# 3: security-neg
C1="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$RPORT/etc/passwd")"
C2="$(curl -s -o /dev/null -w '%{http_code}' -x "http://127.0.0.1:$PPORT" \
      "http://evil.example.org/cvmfs/x/data/aa/bb")"
[ "$C1" = 403 ] && ok "non-cvmfs path rejected" || bad "expected 403, got $C1"
[ "$C2" = 403 ] && ok "disallowed upstream rejected" || bad "expected 403, got $C2"

exit $fail
```

- [ ] **Step 3: Run it**

Run: `bash tests/run_cvmfs_stock.sh`
Expected: 4 × `ok`, exit 0. (`proxy_cache_lock` allows a small race — the `-le 2` tolerance is deliberate; the module personality in Task 9 is held to exactly 1.)

- [ ] **Step 4: Run the harness against it + record decision-gate numbers**

Run:
```bash
python3 tests/cvmfs/mock_stratum1.py --port 12821 --objects 16 &  # if not running
# start stock config as in the test, then:
python3 tests/cvmfs/harness.py --cache http://127.0.0.1:12822 \
    --mock http://127.0.0.1:12821 --out results_stock_clean.json
```
Then repeat under `netem_lab.sh profile site` and `profile corrupt` with the mock inside the ns. Record all three JSONs in `deploy/cvmfs/baselines/RESULTS.md` next to the Task-4 baselines.
Expected: stock nginx `corrupt_served > 0` under the corrupt profile — the number that justifies Phase 3's verify-on-fill.

`RESULTS.md` has a fixed shape (T15 appends module rows to the same table —
create it exactly like this so the renderer can extend it):

```markdown
# CVMFS cache comparison results

Rows are appended per (cache, netem profile) run; numbers come verbatim from
the harness JSON. Regenerate with tests/cvmfs/run_matrix.sh (T15) — manual
edits only in the Notes column.

| cache | profile | cold p50 ms | cold p99 ms | warm p50 ms | error rate | stampede fetches | corrupt served | date | notes |
|---|---|---|---|---|---|---|---|---|---|
| squid        | clean   | | | | | | | | |
| squid        | corrupt | | | | | | | | |
| varnish      | clean   | | | | | | | | |
| stock-nginx  | clean   | | | | | | | | |
| stock-nginx  | site    | | | | | | | | |
| stock-nginx  | corrupt | | | | | | | | |

## Gate-1 verdict (filled by the OP after Task 5)
- [ ] Stock config sufficient — stop after Task 18 runbook for stock config
- [ ] Continue to Phase 2 (module personality)
Reasoning:
```

- [ ] **Step 5: Commit**

```bash
chmod +x tests/run_cvmfs_stock.sh
git add deploy/cvmfs/nginx-proxy-cache.conf tests/run_cvmfs_stock.sh \
        deploy/cvmfs/baselines/RESULTS.md
git commit -m "feat(cvmfs): stock-nginx proxy_cache prototype + e2e + gate numbers"
```

**PHASE-1 DECISION GATE (STOP POINT):** present `RESULTS.md` to the OP. Continue to Phase 2 only on explicit go — if the stock config's numbers already satisfy the site (and the `corrupt_served` risk is accepted), the remaining phases are cancelled and Task 18's runbook is written for the stock config instead.

---

# PHASE 2 — Module MVP (Approach B core, reverse mode)

### Task 6: CAS hash-convention spike

**Files:**
- Create: `tests/cvmfs/spike_cas_hash.sh`
- Modify: `docs/superpowers/specs/2026-07-02-cvmfs-site-cache-design.md` (record the finding under §5.1)

**Interfaces:**
- Produces: a **documented, evidence-backed answer** to: is the CAS object name the SHA-1 of (a) the bytes as served by the Stratum-1, or (b) the zlib-inflated content? Task 10's verify implementation branches on this.

- [ ] **Step 1: Write the spike script**

```bash
#!/usr/bin/env bash
# tests/cvmfs/spike_cas_hash.sh — determine the CVMFS CAS hashing convention
# empirically against a real Stratum-1. Downloads the manifest, extracts the
# root catalog hash, fetches the object, and hashes it (raw and inflated).
set -eu
S1="${1:-http://cvmfs-stratum-one.cern.ch/cvmfs/cvmfs-config.cern.ch}"
M="$(curl -sf "$S1/.cvmfspublished")"
ROOT="$(printf '%s' "$M" | sed -n 's/^C//p' | head -1)"
echo "repo manifest root catalog: $ROOT"
URL="$S1/data/${ROOT:0:2}/${ROOT:2}C"
curl -sf "$URL" -o /tmp/spike_obj.raw
RAW="$(sha1sum /tmp/spike_obj.raw | cut -d' ' -f1)"
python3 - <<'EOF'
import zlib, hashlib
raw = open("/tmp/spike_obj.raw","rb").read()
try:
    print("inflated sha1:", hashlib.sha1(zlib.decompress(raw)).hexdigest())
except Exception as e:
    print("inflate failed:", e)
EOF
echo "raw sha1:      $RAW"
echo "expected:      $ROOT"
echo "VERDICT: whichever line matches 'expected' is the hashing convention."
```

- [ ] **Step 2: Run it (needs outbound network)**

Run: `bash tests/cvmfs/spike_cas_hash.sh`
Expected: one of the two hashes equals the expected value. Record the verdict, the exact command output, and the date in the spec §5.1 (replace the open-question paragraph with the finding). If neither matches (e.g., suffix-specific rules), extend the spike to a plain data chunk before proceeding — **Task 10 is blocked until this has a verdict.**

- [ ] **Step 3: Commit**

```bash
git add tests/cvmfs/spike_cas_hash.sh docs/superpowers/specs/2026-07-02-cvmfs-site-cache-design.md
git commit -m "test(cvmfs): CAS hash-convention spike + recorded verdict"
```

---

### Task 7: Pure-C URL classifier

**Files:**
- Create: `src/protocols/cvmfs/classify.h`, `src/protocols/cvmfs/classify.c`
- Test: `tests/run_cvmfs_classify.sh` (standalone gcc, pattern: guard core / zip_dir tests)
- Modify: `./config` (add `classify.c` to `ngx_module_srcs`), then full reconfigure+rebuild

**Interfaces:**
- Produces (consumed by Tasks 8, 9, 10, 14):

```c
/* classify.h */
typedef enum {
    CVMFS_URL_CAS = 0,      /* /cvmfs/<repo>/data/<2hex>/<hex36+>[suffix]     */
    CVMFS_URL_MANIFEST,     /* .cvmfspublished / .cvmfswhitelist / .cvmfsreflog */
    CVMFS_URL_GEO,          /* /cvmfs/<repo>/api/v1.0/geo/...                  */
    CVMFS_URL_REJECT        /* anything else                                   */
} cvmfs_url_class_e;

typedef struct {
    cvmfs_url_class_e  cls;
    const char        *repo;      size_t repo_len;   /* points into input     */
    const char        *rel;       size_t rel_len;    /* path under the repo   */
    char               cas_hex[129];                 /* CAS only, NUL-term    */
    size_t             cas_hex_len;
    char               cas_suffix;                   /* 0 or C/H/X/M/L/P      */
} cvmfs_url_info_t;

/* Classify `path` (len bytes, no query string). Returns 0 and fills *out;
 * never fails — unrecognized shapes come back CVMFS_URL_REJECT. Pure C,
 * no allocation, no ngx types (standalone-testable). */
int cvmfs_classify_url(const char *path, size_t len, cvmfs_url_info_t *out);
```

- [ ] **Step 1: Write the failing standalone test**

```bash
#!/usr/bin/env bash
# tests/run_cvmfs_classify.sh — standalone unit test for the pure-C classifier.
set -eu
HERE="$(cd "$(dirname "$0")/.." && pwd)"
T="$(mktemp -d /tmp/cvmfs_classify.XXXXXX)"; trap 'rm -rf "$T"' EXIT
cat > "$T/t.c" <<'EOF'
#include "protocols/cvmfs/classify.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static cvmfs_url_info_t C(const char *p) {
    cvmfs_url_info_t i; assert(cvmfs_classify_url(p, strlen(p), &i) == 0); return i;
}

int main(void) {
    cvmfs_url_info_t i;

    i = C("/cvmfs/atlas.cern.ch/data/ab/cdef0123456789abcdef0123456789abcdef01");
    assert(i.cls == CVMFS_URL_CAS);
    assert(i.repo_len == 13 && memcmp(i.repo, "atlas.cern.ch", 13) == 0);
    assert(i.cas_hex_len == 40 && i.cas_suffix == 0);
    assert(memcmp(i.cas_hex, "abcdef0123456789abcdef0123456789abcdef01", 40) == 0);

    i = C("/cvmfs/atlas.cern.ch/data/ab/cdef0123456789abcdef0123456789abcdef01C");
    assert(i.cls == CVMFS_URL_CAS && i.cas_suffix == 'C');

    i = C("/cvmfs/atlas.cern.ch/.cvmfspublished");
    assert(i.cls == CVMFS_URL_MANIFEST);
    i = C("/cvmfs/atlas.cern.ch/.cvmfswhitelist");
    assert(i.cls == CVMFS_URL_MANIFEST);

    i = C("/cvmfs/atlas.cern.ch/api/v1.0/geo/me/a,b,c");
    assert(i.cls == CVMFS_URL_GEO);

    /* rejects: wrong prefix, traversal, bad hex, short hash, bad suffix,
     * bad repo chars, empty repo */
    assert(C("/etc/passwd").cls == CVMFS_URL_REJECT);
    assert(C("/cvmfs/../etc/passwd").cls == CVMFS_URL_REJECT);
    assert(C("/cvmfs/a/data/zz/ff").cls == CVMFS_URL_REJECT);
    assert(C("/cvmfs/a.b/data/ab/cdef").cls == CVMFS_URL_REJECT);
    assert(C("/cvmfs/a.b/data/ab/cdef0123456789abcdef0123456789abcdef01Z").cls
           == CVMFS_URL_REJECT);
    assert(C("/cvmfs/bad repo/.cvmfspublished").cls == CVMFS_URL_REJECT);
    assert(C("/cvmfs//.cvmfspublished").cls == CVMFS_URL_REJECT);
    assert(C("/cvmfs/a.b/.cvmfspublished/extra").cls == CVMFS_URL_REJECT);

    printf("run_cvmfs_classify: 15 checks OK\n");
    return 0;
}
EOF
gcc -Wall -Werror -I"$HERE/src" -o "$T/t" "$T/t.c" "$HERE/src/protocols/cvmfs/classify.c"
"$T/t"
```

- [ ] **Step 2: Run to verify it fails**

Run: `bash tests/run_cvmfs_classify.sh`
Expected: gcc FAIL (`classify.h` missing).

- [ ] **Step 3: Implement**

```c
/* classify.c — CVMFS URL classifier.
 *
 * WHAT: maps a request path onto the four CVMFS traffic classes (immutable CAS
 *       object / mutable signed metadata / geo API / reject).
 * WHY:  the whole cache policy — TTL, verification, pass-through, guard — keys
 *       off the class; classifying in one pure function keeps policy testable
 *       without nginx and reusable from both dispatch and the fill verifier.
 * HOW:  hand-rolled prefix walk (no regex, no alloc): "/cvmfs/" + repo token
 *       ([a-z0-9.-]+, dots not leading) + one of the three known shapes.
 */
#include "classify.h"

#include <string.h>

static int hexlc(char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); }

static int repo_char(char c) {
    return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '-';
}

static int is_cas_suffix(char c) {
    return c == 'C' || c == 'H' || c == 'X' || c == 'M' || c == 'L' || c == 'P';
}

/* "<2hex>/<hex...>[suffix]" after ".../data/". Returns 0 on valid CAS. */
static int parse_cas(const char *p, size_t n, cvmfs_url_info_t *out) {
    size_t hexn;

    if (n < 3 || !hexlc(p[0]) || !hexlc(p[1]) || p[2] != '/')
        return -1;
    p += 3; n -= 3;
    for (hexn = 0; hexn < n && hexlc(p[hexn]); hexn++) { /* count hex run */ }
    if (hexn + 2 < 40 || hexn + 2 > 128)     /* sha1=40 .. shake128 etc.  */
        return -1;
    if (hexn == n) {
        out->cas_suffix = 0;
    } else if (hexn + 1 == n && is_cas_suffix(p[hexn])) {
        out->cas_suffix = p[hexn];
    } else {
        return -1;
    }
    out->cas_hex[0] = p[-3];                 /* re-join the 2-hex dir     */
    out->cas_hex[1] = p[-2];
    memcpy(out->cas_hex + 2, p, hexn);
    out->cas_hex_len = hexn + 2;
    out->cas_hex[out->cas_hex_len] = '\0';
    out->cls = CVMFS_URL_CAS;
    return 0;
}

int cvmfs_classify_url(const char *path, size_t len, cvmfs_url_info_t *out) {
    static const char pfx[] = "/cvmfs/";
    const char *p, *end, *repo;
    size_t      rn;

    memset(out, 0, sizeof(*out));
    out->cls = CVMFS_URL_REJECT;

    if (len <= sizeof(pfx) - 1 || memcmp(path, pfx, sizeof(pfx) - 1) != 0)
        return 0;
    p = path + sizeof(pfx) - 1;
    end = path + len;

    repo = p;
    while (p < end && repo_char(*p)) p++;
    rn = (size_t) (p - repo);
    if (rn == 0 || repo[0] == '.' || p >= end || *p != '/')
        return 0;
    out->repo = repo; out->repo_len = rn;
    p++;                                     /* skip '/' */
    out->rel = p; out->rel_len = (size_t) (end - p);

    if (out->rel_len >= 6 && memcmp(p, "data/", 5) == 0) {
        parse_cas(p + 5, out->rel_len - 5, out);   /* sets cls on success */
        return 0;
    }
    if ((out->rel_len == 15 && memcmp(p, ".cvmfspublished", 15) == 0)
        || (out->rel_len == 15 && memcmp(p, ".cvmfswhitelist", 15) == 0)
        || (out->rel_len == 12 && memcmp(p, ".cvmfsreflog", 12) == 0))
    {
        out->cls = CVMFS_URL_MANIFEST;
        return 0;
    }
    if (out->rel_len > 13 && memcmp(p, "api/v1.0/geo/", 13) == 0) {
        out->cls = CVMFS_URL_GEO;
        return 0;
    }
    return 0;
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `bash tests/run_cvmfs_classify.sh`
Expected: `run_cvmfs_classify: 15 checks OK`.

- [ ] **Step 5: Register in `./config` + full rebuild**

Add to the repo-root `./config`, in the module sources list (alongside the other `protocols/` entries):

```
                 $ngx_addon_dir/src/protocols/cvmfs/classify.c \
```

Run:
```bash
rm -rf /tmp/nginx-1.28.3/objs && cd /tmp/nginx-1.28.3 && \
./configure --with-stream --with-stream_ssl_module --with-http_ssl_module \
  --with-http_dav_module --with-threads \
  --add-module=/home/rcurrie/HEP-x/nginx-xrootd && make -j$(nproc)
```
Expected: exit 0.

- [ ] **Step 6: Commit**

```bash
git add src/protocols/cvmfs/classify.h src/protocols/cvmfs/classify.c \
        tests/run_cvmfs_classify.sh config
git commit -m "feat(cvmfs): pure-C URL classifier (CAS/manifest/geo/reject) + standalone test"
```

---

### Task 8: The `cvmfs://` protocol module (loc-conf + directives + handler registration)

**Files:**
- Create: `src/protocols/cvmfs/cvmfs.h`, `src/protocols/cvmfs/module.c`
- Modify: `./config` (add `module.c` to the source list AND `ngx_http_xrootd_cvmfs_module` to the HTTP modules list, alongside the existing webdav/s3 module registrations), full rebuild

**Interfaces:**
- Produces (consumed by every later cvmfs task):

```c
/* cvmfs.h — the cvmfs:// protocol surface.
 *
 * WHAT: loc-conf + request-ctx types, the handler entry, and the gate/geo
 *       prototypes for the dedicated CVMFS protocol plane.
 * WHY:  cvmfs:// is a first-class protocol (peer of webdav/, s3/): its own
 *       module owns configuration and its own content handler owns every
 *       request — WebDAV dispatch is never involved.
 * HOW:  the loc-conf embeds the SAME shared tier struct (`common`) the other
 *       HTTP protocols embed, so xrootd_cvmfs_storage_backend /
 *       xrootd_cvmfs_cache_store compose the identical phase-63/64 storage
 *       stack underneath a protocol-specific top.
 */
#include "classify.h"

typedef struct {
    ngx_flag_t   enable;           /* xrootd_cvmfs on|off (default off)       */
    time_t       manifest_ttl;     /* xrootd_cvmfs_manifest_ttl (default 61s) */
    time_t       negative_ttl;     /* xrootd_cvmfs_negative_ttl (default 10s) */
    ngx_str_t    quarantine_dir;   /* xrootd_cvmfs_quarantine_dir (optional)  */
    ngx_array_t *upstream_allow;   /* xrootd_cvmfs_upstream_allow host…       */
    ngx_uint_t   upstream_max;     /* xrootd_cvmfs_upstream_max (default 8)   */
} xrootd_cvmfs_conf_t;

typedef struct {
    /* shared per-protocol tier/storage config — SAME struct the webdav and
     * s3 loc-confs embed (see their module.c); populated by the
     * xrootd_cvmfs_storage_backend / xrootd_cvmfs_cache_store /
     * xrootd_cvmfs_stage* directive family below */
    xrootd_http_common_conf_t    common;

    xrootd_cvmfs_conf_t          cvmfs;      /* protocol-specific knobs      */
    /* scvmfs (T22, EXPERIMENTAL) fields land here later:                    */
    /* ngx_flag_t secure; ngx_uint_t secure_authz;                           */
} ngx_http_xrootd_cvmfs_loc_conf_t;

extern ngx_module_t  ngx_http_xrootd_cvmfs_module;

/* Content handler — installed at postconfig on xrootd_cvmfs-enabled
 * locations (Task 9 implements it). */
ngx_int_t ngx_http_xrootd_cvmfs_handler(ngx_http_request_t *r);

/* Gate — classify + route/reject policy, called BY the handler (Task 9). */
ngx_int_t xrootd_cvmfs_gate(ngx_http_request_t *r,
    ngx_http_xrootd_cvmfs_loc_conf_t *lcf);
```

Directive family (all `NGX_HTTP_LOC_CONF`, registered in the module's own
commands table): `xrootd_cvmfs`, `xrootd_cvmfs_manifest_ttl`,
`xrootd_cvmfs_negative_ttl`, `xrootd_cvmfs_quarantine_dir`,
`xrootd_cvmfs_upstream_allow` (multi), `xrootd_cvmfs_upstream_max` — plus
the per-protocol tier directives `xrootd_cvmfs_storage_backend` and
`xrootd_cvmfs_cache_store`, which are one-line entries pointing at the SAME
setters/offsets the webdav/s3 modules use for their `common.*` twins
(`webdav/module.c:101–144` is the template; this is the established
phase-64 idiom: each protocol registers its own names over the shared
struct). `xrootd_cache_*` cache-policy directives (include-regex, verify,
watermarks) are protocol-agnostic and already usable in any HTTP location —
no new registration needed.

**Handler installation (the "dedicated protocol" mechanics):** the module's
postconfiguration walks nothing — instead, exactly like the s3 module, the
`xrootd_cvmfs` directive's location gets the content handler at merge time:

```c
/* module.c, in merge_loc_conf, after the merges: */
    if (conf->cvmfs.enable) {
        ngx_http_core_loc_conf_t  *core;

        core = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
        core->handler = ngx_http_xrootd_cvmfs_handler;
    }
```

(Match the exact installation point the s3 module uses —
`src/protocols/s3/handler.c` registration via its `postconfig.c`/module —
whichever of merge-time vs postconfig-phase it uses, mirror it; the
invariant is: `xrootd_cvmfs on` alone makes the location a CVMFS protocol
endpoint, with no WebDAV directive present.)

- [ ] **Step 1: Write the failing config-validation test** (extend `run_cvmfs_reverse.sh`'s skeleton with only the `nginx -t` check for now)

```bash
#!/usr/bin/env bash
# tests/run_cvmfs_reverse.sh — module CVMFS personality e2e (built up over
# Tasks 8/9). Task-8 scope: the directives parse and merge.
set -u
NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
HERE="$(cd "$(dirname "$0")" && pwd)"
PFX="$(mktemp -d /tmp/cvmfs_rev.XXXXXX)"; fail=0
ok(){ printf '  ok   %s\n' "$1"; }; bad(){ printf '  FAIL %s\n' "$1"; fail=1; }
cleanup(){ [ -f "$PFX/nginx.pid" ] && kill "$(cat "$PFX/nginx.pid")" 2>/dev/null
           [ -n "${MOCK:-}" ] && kill "$MOCK" 2>/dev/null; rm -rf "$PFX"; }
trap cleanup EXIT
MPORT=12831; CPORT=12832
mkdir -p "$PFX/cache" "$PFX/logs"

cat > "$PFX/nginx.conf" <<EOF
daemon on; error_log $PFX/logs/e.log info; pid $PFX/nginx.pid;
thread_pool default threads=2;
events { worker_connections 128; }
http {
    access_log off;
    server {
        listen 127.0.0.1:$CPORT;
        location /cvmfs/ {
            xrootd_cvmfs_storage_backend http://127.0.0.1:$MPORT/cvmfs;
            xrootd_cvmfs_cache_store $PFX/cache;
            xrootd_cache_include_regex "/data/";
            xrootd_cvmfs on;
            xrootd_cvmfs_manifest_ttl 61;
        }
    }
}
EOF
"$NGINX" -t -c "$PFX/nginx.conf" -p "$PFX" 2>/dev/null \
    && ok "cvmfs directives parse" || bad "nginx -t rejected cvmfs config"
exit $fail
```

*(The `xrootd_cvmfs_storage_backend http://…/cvmfs` base maps request `/cvmfs/<repo>/…` → origin `/cvmfs/<repo>/…`; `xrootd_cache_include_regex "/data/"` makes the existing admission filter cache CAS objects only — manifests/geo go to the origin every time. That existing knob is the Phase-2 TTL stopgap from the spec.)*

- [ ] **Step 2: Run to verify it fails**

Run: `bash tests/run_cvmfs_reverse.sh`
Expected: `FAIL nginx -t rejected cvmfs config` (unknown directive `xrootd_cvmfs`).

- [ ] **Step 3: Implement `module.c`** — module boilerplate in the exact
shape of `src/protocols/s3/`'s module (ctx struct with
`create_loc_conf`/`merge_loc_conf`, commands table, `ngx_http_module_t` +
`ngx_module_t` definitions), owning `ngx_http_xrootd_cvmfs_loc_conf_t`
from `cvmfs.h`. The protocol-specific command entries:

```c
    { ngx_string("xrootd_cvmfs"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_cvmfs_loc_conf_t, cvmfs.enable),
      NULL },

    { ngx_string("xrootd_cvmfs_manifest_ttl"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_cvmfs_loc_conf_t, cvmfs.manifest_ttl),
      NULL },

    { ngx_string("xrootd_cvmfs_negative_ttl"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_cvmfs_loc_conf_t, cvmfs.negative_ttl),
      NULL },

    { ngx_string("xrootd_cvmfs_quarantine_dir"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_cvmfs_loc_conf_t, cvmfs.quarantine_dir),
      NULL },

    { ngx_string("xrootd_cvmfs_upstream_allow"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_conf_set_str_array_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_cvmfs_loc_conf_t, cvmfs.upstream_allow),
      NULL },

    { ngx_string("xrootd_cvmfs_upstream_max"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_cvmfs_loc_conf_t, cvmfs.upstream_max),
      NULL },
```

Add the two tier entries (`xrootd_cvmfs_storage_backend`,
`xrootd_cvmfs_cache_store`) with `offsetof(ngx_http_xrootd_cvmfs_loc_conf_t,
common.storage_backend)` / `common.cache_store`, reusing the identical
setter functions the webdav entries reference. In `create_loc_conf` set the
unset markers, in `merge_loc_conf` merge with defaults and install the
handler (matching the file's existing idiom):

```c
    /* create: */
    conf->cvmfs.enable = NGX_CONF_UNSET;
    conf->cvmfs.manifest_ttl = NGX_CONF_UNSET;
    conf->cvmfs.negative_ttl = NGX_CONF_UNSET;
    conf->cvmfs.upstream_allow = NGX_CONF_UNSET_PTR;
    conf->cvmfs.upstream_max = NGX_CONF_UNSET_UINT;
    /* common.*: initialise exactly as the s3 module's create does — each
     * protocol inits/merges common.* MANUALLY (established phase-64 gotcha:
     * there is deliberately no shared_init) */

    /* merge: */
    ngx_conf_merge_value(conf->cvmfs.enable, prev->cvmfs.enable, 0);
    ngx_conf_merge_sec_value(conf->cvmfs.manifest_ttl, prev->cvmfs.manifest_ttl, 61);
    ngx_conf_merge_sec_value(conf->cvmfs.negative_ttl, prev->cvmfs.negative_ttl, 10);
    ngx_conf_merge_str_value(conf->cvmfs.quarantine_dir, prev->cvmfs.quarantine_dir, "");
    ngx_conf_merge_ptr_value(conf->cvmfs.upstream_allow, prev->cvmfs.upstream_allow, NULL);
    ngx_conf_merge_uint_value(conf->cvmfs.upstream_max, prev->cvmfs.upstream_max, 8);
    /* common.* merges: mirror the s3 module's merge block */

    if (conf->cvmfs.enable) {
        /* dedicated protocol: this location's content handler is ours */
        ngx_http_core_loc_conf_t *core =
            ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
        core->handler = ngx_http_xrootd_cvmfs_handler;
    }
```

Until Task 9 lands the real handler, `ngx_http_xrootd_cvmfs_handler` is a
minimal stub in `module.c` returning `NGX_HTTP_NOT_IMPLEMENTED` — the
Task-8 test only asserts config validity; Task 9 moves the symbol into
`handler.c` and deletes the stub.

- [ ] **Step 4: Register in `./config` + full rebuild + run the test.**
Two `./config` changes: `module.c` in the source list AND the module name
appended to the HTTP-modules registration (find where
`ngx_http_xrootd_webdav_module` / the s3 module are added and add
`ngx_http_xrootd_cvmfs_module` beside them).

Run:
```bash
rm -rf /tmp/nginx-1.28.3/objs && cd /tmp/nginx-1.28.3 && \
./configure --with-stream --with-stream_ssl_module --with-http_ssl_module \
  --with-http_dav_module --with-threads \
  --add-module=/home/rcurrie/HEP-x/nginx-xrootd && make -j$(nproc) && \
bash /home/rcurrie/HEP-x/nginx-xrootd/tests/run_cvmfs_reverse.sh
```
Expected: build exit 0; `ok cvmfs directives parse`.

- [ ] **Step 5: Commit**

```bash
git add src/protocols/cvmfs/cvmfs.h src/protocols/cvmfs/module.c \
        config tests/run_cvmfs_reverse.sh
git commit -m "feat(cvmfs): dedicated cvmfs:// protocol module — loc-conf, directive family, handler slot"
```

---

### Task 9: Dedicated content handler + gate + geo passthrough + reverse-mode e2e

**Files:**
- Create: `src/protocols/cvmfs/handler.c`, `src/protocols/cvmfs/gate.c`, `src/protocols/cvmfs/geo.c`
- Modify: `src/protocols/cvmfs/module.c` (delete the Task-8 handler stub), `./config` (add all three files), full rebuild
- Test: extend `tests/run_cvmfs_reverse.sh`

**Interfaces:**
- Consumes: `cvmfs_classify_url` (Task 7), `ngx_http_xrootd_cvmfs_loc_conf_t` + the handler slot (Task 8), the shared HTTP transport vtable already used by `sd_http.c` (`xrootd_s3_transport_t` from `src/fs/cache/origin/transport.h` — `request()/resp_header()/resp_free()`), and the shared serve machinery: `xrootd_vfs_open()` / cache tier open-or-fill + the `src/core/http/` file-response helpers (the same ones the WebDAV/S3 GET paths use — security-load-bearing, never reimplemented).
- Produces: `ngx_int_t ngx_http_xrootd_cvmfs_handler(ngx_http_request_t *r)` — the protocol's content handler; `ngx_int_t xrootd_cvmfs_gate(ngx_http_request_t *r, ngx_http_xrootd_cvmfs_loc_conf_t *lcf)` — returns `NGX_DECLINED` (CAS/MANIFEST: handler proceeds to the tier serve path), a final status it already sent (geo passthrough, rejects), or an error status; `ngx_int_t xrootd_cvmfs_geo_passthrough(ngx_http_request_t *r, ngx_http_xrootd_cvmfs_loc_conf_t *lcf)` in `geo.c`.

- [ ] **Step 1: Extend the e2e test with the real behavior checks**

Append to `tests/run_cvmfs_reverse.sh` after the `nginx -t` check (and start the server + mock):

```bash
python3 "$HERE/cvmfs/mock_stratum1.py" --port $MPORT --objects 8 --seed 9 &
MOCK=$!; sleep 0.5
"$NGINX" -c "$PFX/nginx.conf" -p "$PFX"; sleep 0.5

OBJ="$(curl -s "http://127.0.0.1:$MPORT/ctl/objects" | python3 -c \
      'import json,sys; print(json.load(sys.stdin)[0])')"

# success: cold fill + warm hit, byte-exact, second read served without origin
curl -s "http://127.0.0.1:$CPORT$OBJ" -o "$PFX/cold.bin"
N_AFTER_COLD="$(curl -s "http://127.0.0.1:$MPORT/ctl/log" | grep -c "$OBJ")"
curl -s "http://127.0.0.1:$CPORT$OBJ" -o "$PFX/warm.bin"
N_AFTER_WARM="$(curl -s "http://127.0.0.1:$MPORT/ctl/log" | grep -c "$OBJ")"
curl -s "http://127.0.0.1:$MPORT$OBJ" -o "$PFX/orig.bin"
cmp -s "$PFX/cold.bin" "$PFX/orig.bin" && cmp -s "$PFX/warm.bin" "$PFX/orig.bin" \
    && ok "cold+warm byte-exact" || bad "byte mismatch"
[ "$N_AFTER_WARM" = "$N_AFTER_COLD" ] && ok "warm hit served from cache" \
    || bad "warm read went to origin"

# stampede: exactly 1 origin fetch (module fill-lock, stricter than stock's <=2)
OBJ2="$(curl -s "http://127.0.0.1:$MPORT/ctl/objects" | python3 -c \
      'import json,sys; print(json.load(sys.stdin)[4])')"
for i in $(seq 1 40); do curl -s "http://127.0.0.1:$CPORT$OBJ2" -o /dev/null & done
wait
N2="$(curl -s "http://127.0.0.1:$MPORT/ctl/log" | grep -c "$OBJ2")"
[ "$N2" = 1 ] && ok "stampede: exactly 1 origin fetch" || bad "stampede: $N2 fetches"

# manifest: served, NOT cached (goes to origin each time — include_regex stopgap)
curl -s "http://127.0.0.1:$CPORT/cvmfs/test.cern.ch/.cvmfspublished" -o "$PFX/m1"
curl -s "http://127.0.0.1:$MPORT/ctl/manifest/bump" >/dev/null
curl -s "http://127.0.0.1:$CPORT/cvmfs/test.cern.ch/.cvmfspublished" -o "$PFX/m2"
cmp -s "$PFX/m1" "$PFX/m2" && bad "manifest stale (cached!)" \
    || ok "manifest fetched fresh (uncached stopgap)"

# geo passthrough
G="$(curl -s "http://127.0.0.1:$CPORT/cvmfs/test.cern.ch/api/v1.0/geo/x/a,b")"
[ -n "$G" ] && ok "geo passthrough" || bad "geo empty"

# security-neg: rejects (403) for non-CVMFS shapes; 405 for writes
C1="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$CPORT/cvmfs/../etc/passwd")"
C2="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$CPORT/cvmfs/repo/random.txt")"
C3="$(curl -s -o /dev/null -w '%{http_code}' -X PUT --data x \
      "http://127.0.0.1:$CPORT/cvmfs/test.cern.ch/.cvmfspublished")"
[ "$C1" = 403 ] && ok "traversal rejected" || bad "traversal: $C1"
[ "$C2" = 403 ] && ok "non-class path rejected" || bad "non-class: $C2"
[ "$C3" = 405 ] && ok "write method rejected" || bad "PUT: $C3"
```

- [ ] **Step 2: Run to verify it fails**

Run: `bash tests/run_cvmfs_reverse.sh`
Expected: the reject checks FAIL (plain WebDAV GET serves/404s instead of 403; PUT isn't blocked by class).

- [ ] **Step 3: Implement `gate.c`**

```c
/* gate.c — CVMFS personality dispatch gate.
 *
 * WHAT: first hook in the WebDAV dispatch for locations with `xrootd_cvmfs on`:
 *       restricts methods to GET/HEAD, classifies the URI, rejects non-CVMFS
 *       shapes, routes the geo API to the uncached passthrough, and lets
 *       CAS/MANIFEST fall through (NGX_DECLINED) to the stock GET → VFS tier.
 * WHY:  a CVMFS cache must not be an open proxy or a generic WebDAV endpoint;
 *       class routing here keeps every downstream layer (tier, admission,
 *       verify) free of CVMFS-specific branching.
 * HOW:  pure classifier (classify.c) + early returns; rejects emit the guard
 *       signal via the existing httpguard hook and a low-cardinality metric.
 */
#include "cvmfs.h"

static ngx_int_t
cvmfs_reject(ngx_http_request_t *r, ngx_uint_t status)
{
    XROOTD_CVMFS_METRIC_INC(XROOTD_CVMFS_M_REJECT);       /* Task 16 wires this */
    return status;
}

ngx_int_t
xrootd_cvmfs_gate(ngx_http_request_t *r, ngx_http_xrootd_cvmfs_loc_conf_t *lcf)
{
    cvmfs_url_info_t  info;

    if (r->method != NGX_HTTP_GET && r->method != NGX_HTTP_HEAD) {
        return cvmfs_reject(r, NGX_HTTP_NOT_ALLOWED);
    }

    /* classify the unescaped, query-stripped path nginx already produced */
    if (cvmfs_classify_url((const char *) r->uri.data, r->uri.len, &info) != 0) {
        return cvmfs_reject(r, NGX_HTTP_FORBIDDEN);
    }

    switch (info.cls) {
    case CVMFS_URL_CAS:
    case CVMFS_URL_MANIFEST:
        XROOTD_CVMFS_METRIC_INC(info.cls == CVMFS_URL_CAS
                                ? XROOTD_CVMFS_M_CAS : XROOTD_CVMFS_M_MANIFEST);
        return NGX_DECLINED;              /* stock GET path serves via VFS tier */
    case CVMFS_URL_GEO:
        XROOTD_CVMFS_METRIC_INC(XROOTD_CVMFS_M_GEO);
        return xrootd_cvmfs_geo_passthrough(r, lcf);
    case CVMFS_URL_REJECT:
    default:
        return cvmfs_reject(r, NGX_HTTP_FORBIDDEN);
    }
}
```

(Until Task 16 lands the real metric slots, define `XROOTD_CVMFS_METRIC_INC(x)` as a no-op macro in `cvmfs.h`: `#define XROOTD_CVMFS_METRIC_INC(slot) /* wired in phase-4 */` — the call sites are placed now so Task 16 only swaps the macro body.)

- [ ] **Step 4: Implement `geo.c`**

```c
/* geo.c — uncached Geo-API passthrough.
 *
 * WHAT: forwards /cvmfs/<repo>/api/v1.0/geo/... (with query string) to the
 *       configured origin over the shared blocking HTTP transport and relays
 *       status + body. Never cached: the answer depends on the caller.
 * WHY:  CVMFS clients call the geo API through their site proxy at mount time
 *       to order CVMFS_SERVER_URL; failure is non-fatal for the client but a
 *       correct answer improves Stratum-1 ordering.
 * HOW:  geo responses are tiny (a comma-separated index list), so a bounded
 *       in-memory transport request on a thread-pool task is appropriate; the
 *       request is posted via the same aio task helper the tier fills use,
 *       and the completion builds a memory-backed ngx_chain_t response.
 */
#include "cvmfs.h"
#include "fs/cache/origin/transport.h"

#define CVMFS_GEO_RESP_MAX  8192
#define CVMFS_GEO_TIMEOUT_MS 5000

typedef struct {
    ngx_http_request_t *r;
    char                path[2048];      /* origin path incl. query          */
    char                host[256];
    int                 port;
    int                 tls;
    int                 status;          /* transport result                 */
    u_char             *body;            /* pool-allocated on completion     */
    size_t              body_len;
} cvmfs_geo_task_t;

/* thread-pool side: one blocking GET over the shared transport */
static void
cvmfs_geo_thread(void *data, ngx_log_t *log)
{
    cvmfs_geo_task_t            *t = data;
    const xrootd_s3_transport_t *tr = xrootd_cache_http_transport();
    xrootd_s3_resp_t             resp;
    char                         errbuf[256];

    t->status = NGX_HTTP_BAD_GATEWAY;
    if (tr->request(NULL, t->host, t->port, t->tls, "GET", t->path, NULL,
                    NULL, 0, CVMFS_GEO_TIMEOUT_MS, &resp,
                    errbuf, sizeof(errbuf)) != 0)
    {
        return;
    }
    t->status = (int) resp.status;
    if (resp.body_len > 0 && resp.body_len <= CVMFS_GEO_RESP_MAX) {
        t->body = ngx_palloc(t->r->pool, resp.body_len);
        if (t->body != NULL) {
            ngx_memcpy(t->body, resp.body, resp.body_len);
            t->body_len = resp.body_len;
        }
    }
    tr->resp_free(&resp);
}

/* event-loop side: emit the relayed response */
static void
cvmfs_geo_done(ngx_event_t *ev)
{
    cvmfs_geo_task_t    *t = ev->data;
    ngx_http_request_t  *r = t->r;
    ngx_buf_t           *b;
    ngx_chain_t          out;

    r->headers_out.status = (ngx_uint_t) t->status;
    r->headers_out.content_length_n = (off_t) t->body_len;
    if (ngx_http_send_header(r) != NGX_OK || t->body_len == 0) {
        ngx_http_finalize_request(r, NGX_HTTP_BAD_GATEWAY);
        return;
    }
    b = ngx_pcalloc(r->pool, sizeof(*b));
    if (b == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }
    b->pos = b->start = t->body;
    b->last = b->end = t->body + t->body_len;
    b->memory = 1; b->last_buf = 1;
    out.buf = b; out.next = NULL;
    ngx_http_finalize_request(r, ngx_http_output_filter(r, &out));
}
```

The entry point ties both halves together. It needs the origin endpoint the
location configured; the VFS backend entry already holds host/port/tls/base
for `http` backends — expose them with a small accessor added to
`src/fs/vfs/vfs_backend_config.c`:

```c
/* Return the HTTP endpoint of an http/https backend entry, or -1 for any
 * other backend kind. Pointers alias the entry's own storage (stable for
 * the config lifetime); callers must not free or modify them. */
int
xrootd_vfs_backend_http_endpoint(const xrootd_vfs_backend_entry_t *e,
    const char **host, int *port, int *tls, const char **base)
{
    if (e == NULL || ngx_strcmp(e->backend, "http") != 0) {
        return -1;
    }
    *host = e->http.host;
    *port = e->http.port;
    *tls  = e->http.tls;
    *base = e->http.base_path;
    return 0;
}
```

(Adjust the member names to the entry's actual http sub-struct — they are the
same fields `xrootd_vfs_backend_config_http()` fills; the accessor exists
precisely so `geo.c` does not reach into VFS internals.)

Then the passthrough entry in `geo.c`:

```c
/* Route a classified GEO request to the origin, uncached. Returns NGX_DONE
 * (async completion via cvmfs_geo_done) or an HTTP error status. */
ngx_int_t
xrootd_cvmfs_geo_passthrough(ngx_http_request_t *r,
    ngx_http_xrootd_cvmfs_loc_conf_t *lcf)
{
    cvmfs_geo_task_t   *t;
    const char         *host, *base;
    int                 port, tls, n;
    ngx_thread_task_t  *task;

    if (xrootd_vfs_backend_http_endpoint(lcf->common.backend_entry,
                                         &host, &port, &tls, &base) != 0)
    {
        /* geo passthrough requires an http(s) backend; proxy mode (T14)
         * installs its per-upstream entry in the ctx before we get here */
        return NGX_HTTP_NOT_IMPLEMENTED;
    }

    task = ngx_thread_task_alloc(r->pool, sizeof(cvmfs_geo_task_t));
    if (task == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    t = task->ctx;
    t->r = r;
    t->port = port;
    t->tls = tls;
    (void) ngx_cpystrn((u_char *) t->host, (u_char *) host, sizeof(t->host));

    /* origin path = <base> + <uri> [+ "?" + args]; reject over-long paths
     * instead of truncating (a truncated geo path returns a wrong answer). */
    if (r->args.len > 0) {
        n = snprintf(t->path, sizeof(t->path), "%s%.*s?%.*s", base,
                     (int) r->uri.len, r->uri.data,
                     (int) r->args.len, r->args.data);
    } else {
        n = snprintf(t->path, sizeof(t->path), "%s%.*s", base,
                     (int) r->uri.len, r->uri.data);
    }
    if (n < 0 || (size_t) n >= sizeof(t->path)) {
        return NGX_HTTP_URI_TOO_LARGE;
    }

    task->handler = cvmfs_geo_thread;
    task->event.handler = cvmfs_geo_done;
    task->event.data = t;

    if (xrootd_aio_post_task(r, task) != NGX_OK) {   /* src/core/aio helper */
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    r->main->count++;                 /* request survives until geo_done */
    return NGX_DONE;
}
```

Two integration notes the executor must resolve against the live code, not
guess: (a) `xrootd_aio_post_task` stands for whatever `src/core/aio/`'s
posting helper is actually called — use the exact helper the WebDAV GET
cache-fill path uses, including its thread-pool selection; (b) the transport
context passed as `tctx` in `cvmfs_geo_thread` must be obtained the same way
`sd_http` obtains it at instance init (`xrootd_cache_http_transport()` is the
shared-transport getter used in this plan — mirror the real name/init).
Both call patterns are visible in one grep:
`grep -rn "thread_task\|transport" src/fs/backend/http/ src/fs/cache/fetch.c`.

- [ ] **Step 5: Implement `handler.c` — the protocol's content handler**

```c
/* handler.c — the cvmfs:// content handler.
 *
 * WHAT: entry point for every request on an xrootd_cvmfs-enabled location:
 *       ctx setup → gate (method/class/reject/geo/negative-cache) → backend
 *       resolve (static entry, or T14 per-upstream override) → cache-tier
 *       open-or-fill → file response.
 * WHY:  cvmfs:// is a dedicated protocol — this handler owns the request
 *       end-to-end; nothing routes through the WebDAV dispatch.
 * HOW:  everything below the protocol seam is shared machinery: the tier
 *       serve step is the same open-or-fill + core/http file-response
 *       composition the other HTTP protocols use, with Range/HEAD/
 *       conditional semantics coming from src/core/http/ helpers.
 */
#include "cvmfs.h"

/* Resolve which backend entry serves this request (convention #2). */
static xrootd_vfs_backend_entry_t *
cvmfs_resolve_backend(ngx_http_request_t *r,
    ngx_http_xrootd_cvmfs_loc_conf_t *lcf)
{
    ngx_http_xrootd_cvmfs_ctx_t *ctx =
        ngx_http_get_module_ctx(r, ngx_http_xrootd_cvmfs_module);

    if (ctx != NULL && ctx->backend_override != NULL) {
        return ctx->backend_override;               /* proxy mode (T14) */
    }
    return lcf->common.backend_entry;
}

/* Serve a classified CAS/MANIFEST GET/HEAD from the tier. */
static ngx_int_t
cvmfs_serve(ngx_http_request_t *r, ngx_http_xrootd_cvmfs_loc_conf_t *lcf)
{
    xrootd_vfs_backend_entry_t *be = cvmfs_resolve_backend(r, lcf);

    if (be == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;      /* no backend configured */
    }
    /* Cache-tier open: hit → fd; miss → coalesced fill (async, NGX_DONE);
     * expired manifest → refill per T12. This is the same entry the
     * WebDAV/S3 GET paths drive; the request parks in the waiter machinery
     * on a miss and resumes in the fill-done callback. */
    return xrootd_cvmfs_tier_get(r, be, lcf);
}

ngx_int_t
ngx_http_xrootd_cvmfs_handler(ngx_http_request_t *r)
{
    ngx_http_xrootd_cvmfs_loc_conf_t *lcf =
        ngx_http_get_module_loc_conf(r, ngx_http_xrootd_cvmfs_module);
    ngx_http_xrootd_cvmfs_ctx_t      *ctx;
    ngx_int_t                         rc;

    ctx = ngx_pcalloc(r->pool, sizeof(*ctx));
    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_http_set_ctx(r, ctx, ngx_http_xrootd_cvmfs_module);

    rc = ngx_http_discard_request_body(r);          /* GET/HEAD only proto */
    if (rc != NGX_OK) {
        return rc;
    }

    rc = xrootd_cvmfs_gate(r, lcf);                 /* classify + police  */
    if (rc != NGX_DECLINED) {
        return rc;               /* reject status, geo NGX_DONE, neg-404 … */
    }
    return cvmfs_serve(r, lcf);
}
```

`xrootd_cvmfs_tier_get()` is a thin protocol-side wrapper (also in
`handler.c`, ~60 lines) around the existing serve composition: consult
cache readiness (`cache_http.h` helpers) → hit: `xrootd_vfs_open()` +
`core/http` file-response (which handles HEAD, Range, ETag/conditionals
from the fd + stat) → miss: allocate the fill (convention #1 fields from
`lcf`), post it, park the request (`r->main->count++`, waiter attach with
T20's hold timer once that lands). Build it by transcribing the WebDAV GET
path's calls into this file — same helper sequence, no webdav includes;
if a helper turns out to be `static` inside `webdav/get.c`, that is a
signal it belongs in `src/core/http/` — move it there (both protocols then
share it properly) rather than including webdav headers here.

`gate.c` from Step 3 is unchanged in substance but is now called by this
handler only; its `NGX_DECLINED` means "proceed to serve", and the
method filter rejects anything but GET/HEAD with 405 as before.

Add all three files to `./config`:

```
                 $ngx_addon_dir/src/protocols/cvmfs/handler.c \
                 $ngx_addon_dir/src/protocols/cvmfs/gate.c \
                 $ngx_addon_dir/src/protocols/cvmfs/geo.c \
```

- [ ] **Step 6: Full rebuild + run**

Run:
```bash
rm -rf /tmp/nginx-1.28.3/objs && cd /tmp/nginx-1.28.3 && \
./configure --with-stream --with-stream_ssl_module --with-http_ssl_module \
  --with-http_dav_module --with-threads \
  --add-module=/home/rcurrie/HEP-x/nginx-xrootd && make -j$(nproc) && \
bash /home/rcurrie/HEP-x/nginx-xrootd/tests/run_cvmfs_reverse.sh
```
Expected: all `ok` lines (parse, cold+warm byte-exact, warm-from-cache, stampede=1, manifest fresh, geo, 3 rejects), exit 0.

- [ ] **Step 7: Regression sweep + commit**

Run: `tests/run_suite.sh --pr` — must stay green (a brand-new protocol
module touches nothing unless `xrootd_cvmfs on` appears in a config; the
WebDAV plane is untouched by construction).

```bash
git add src/protocols/cvmfs/handler.c src/protocols/cvmfs/gate.c \
        src/protocols/cvmfs/geo.c src/protocols/cvmfs/module.c \
        src/fs/vfs/vfs_backend_config.c config tests/run_cvmfs_reverse.sh
git commit -m "feat(cvmfs): dedicated cvmfs:// content handler + gate + geo — reverse-mode MVP e2e green"
```

**Phase-2 exit criterion:** `run_cvmfs_reverse.sh` fully green; optionally a real `cvmfs2` container mount through the reverse endpoint (manual check, documented in `deploy/cvmfs/README.md` in Task 18).

---

# PHASE 3 — Reliability hardening

### Task 10: CVMFS-CAS verify-on-fill + quarantine

**Files:**
- Modify: `src/fs/cache/verify.h` (new mode enum value + entry point), `src/fs/cache/verify.c`, `src/fs/cache/fetch.c` (call site), `src/fs/cache/directives.c` (`xrootd_cache_verify` gains value `cvmfs-cas`)
- Test: `tests/run_cvmfs_verify.sh`

**Interfaces:**
- Consumes: Task-6 verdict (raw-vs-inflated hashing); `cvmfs_classify_url` (Task 7); existing `xrootd_checksum_hex_name_fd` shared checksum kernel; existing `xrootd_cache_verify_part` shape.
- Produces: enum value `XROOTD_CACHE_VERIFY_CVMFS_CAS` in `xrootd_cache_verify_mode_e`, and

```c
/* verify.h addition: self-verification against the CAS name in the fill's own
 * export-relative path. No origin digest needed. Returns VERIFIED, MISMATCH
 * (caller must discard/quarantine), or ERROR. Paths that do not classify as
 * CAS return UNVERIFIED (manifests, geo — not content-addressed). */
xrootd_cache_verify_result_e xrootd_cache_verify_cvmfs_cas(
    xrootd_cache_fill_t *t, const char *part_path, const char *export_path,
    char *out_alg, char *out_hex);

/* quarantine: rename the failed part into <quarantine_dir>/<basename>.<ts>
 * instead of unlinking, when a quarantine dir is configured. Best-effort. */
void xrootd_cache_quarantine_part(xrootd_cache_fill_t *t, const char *part_path,
    const char *quarantine_dir);
```

- [ ] **Step 1: Write the failing e2e test**

```bash
#!/usr/bin/env bash
# tests/run_cvmfs_verify.sh — CAS verify-on-fill:
#   1 corrupt origin response → NOT admitted, client gets 502, quarantine file
#   2 clean retry afterwards → fills and serves byte-exact (cache not poisoned)
#   3 security-neg: verify=off admits the corrupt object (documents the squid
#     failure mode this feature closes)
set -u
NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
HERE="$(cd "$(dirname "$0")" && pwd)"
MPORT=12841; CPORT=12842
PFX="$(mktemp -d /tmp/cvmfs_verify.XXXXXX)"; fail=0
ok(){ printf '  ok   %s\n' "$1"; }; bad(){ printf '  FAIL %s\n' "$1"; fail=1; }
cleanup(){ [ -f "$PFX/nginx.pid" ] && kill "$(cat "$PFX/nginx.pid")" 2>/dev/null
           kill "$MOCK" 2>/dev/null; rm -rf "$PFX"; }
trap cleanup EXIT
mkdir -p "$PFX/cache" "$PFX/quarantine" "$PFX/logs"

python3 "$HERE/cvmfs/mock_stratum1.py" --port $MPORT --objects 4 --seed 3 &
MOCK=$!; sleep 0.5

conf() {   # $1 = verify mode
cat > "$PFX/nginx.conf" <<EOF
daemon on; error_log $PFX/logs/e.log info; pid $PFX/nginx.pid;
thread_pool default threads=2;
events { worker_connections 128; }
http { access_log off; server {
    listen 127.0.0.1:$CPORT;
    location /cvmfs/ {
        xrootd_cvmfs_storage_backend http://127.0.0.1:$MPORT/cvmfs;
        xrootd_cvmfs_cache_store $PFX/cache;
        xrootd_cache_include_regex "/data/";
        xrootd_cache_verify $1;
        xrootd_cvmfs on;
        xrootd_cvmfs_quarantine_dir $PFX/quarantine;
    }
} } 
EOF
}

OBJ="$(curl -s "http://127.0.0.1:$MPORT/ctl/objects" | python3 -c \
      'import json,sys; print(json.load(sys.stdin)[1])')"

conf cvmfs-cas
"$NGINX" -c "$PFX/nginx.conf" -p "$PFX"; sleep 0.5

# 1: corrupt fill rejected
curl -s -X POST -d '{"mode":"corrupt","count":1}' "http://127.0.0.1:$MPORT/ctl/fault"
C="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$CPORT$OBJ")"
[ "$C" = 502 ] && ok "corrupt fill → 502, not admitted" || bad "corrupt fill: $C"
[ -n "$(ls -A "$PFX/quarantine")" ] && ok "corrupt part quarantined" \
    || bad "quarantine empty"

# 2: clean retry fills and matches
curl -s "http://127.0.0.1:$CPORT$OBJ" -o "$PFX/got.bin"
curl -s "http://127.0.0.1:$MPORT$OBJ" -o "$PFX/orig.bin"
cmp -s "$PFX/got.bin" "$PFX/orig.bin" && ok "clean retry byte-exact" \
    || bad "retry mismatch"

# 3: with verify off, the same corruption IS admitted (the squid failure mode)
kill "$(cat "$PFX/nginx.pid")"; rm -rf "$PFX/cache"; mkdir -p "$PFX/cache"
conf off
"$NGINX" -c "$PFX/nginx.conf" -p "$PFX"; sleep 0.5
curl -s -X POST -d '{"mode":"corrupt","count":1}' "http://127.0.0.1:$MPORT/ctl/fault"
curl -s "http://127.0.0.1:$CPORT$OBJ" -o "$PFX/poison1.bin"
curl -s "http://127.0.0.1:$CPORT$OBJ" -o "$PFX/poison2.bin"   # warm: from cache
cmp -s "$PFX/poison1.bin" "$PFX/orig.bin" && bad "verify=off unexpectedly clean" \
    || ok "verify=off admits corruption (documented gap)"
cmp -s "$PFX/poison1.bin" "$PFX/poison2.bin" && ok "poisoned cache re-serves it" \
    || bad "warm read differs from poisoned fill"
exit $fail
```

- [ ] **Step 2: Run to verify it fails**

Run: `bash tests/run_cvmfs_verify.sh`
Expected: `nginx -t`-level failure (`xrootd_cache_verify cvmfs-cas` invalid) or check 1 FAILs (corrupt object admitted).

- [ ] **Step 3: Implement**

In `verify.h`: add `XROOTD_CACHE_VERIFY_CVMFS_CAS` to `xrootd_cache_verify_mode_e` and the two prototypes from the Interfaces block. In `directives.c`, extend the `xrootd_cache_verify` enum table with `{ ngx_string("cvmfs-cas"), XROOTD_CACHE_VERIFY_CVMFS_CAS }`.

In `verify.c` (branch per Task-6 verdict — shown here for the **raw-bytes** convention; if the spike said *inflated*, insert a streaming `inflate` in front of the digest by hashing through a `z_stream` loop instead of `xrootd_checksum_hex_name_fd`):

```c
xrootd_cache_verify_result_e
xrootd_cache_verify_cvmfs_cas(xrootd_cache_fill_t *t, const char *part_path,
    const char *export_path, char *out_alg, char *out_hex)
{
    cvmfs_url_info_t  info;
    char              hex[129];
    int               fd;

    if (cvmfs_classify_url(export_path, strlen(export_path), &info) != 0
        || info.cls != CVMFS_URL_CAS)
    {
        return XROOTD_CACHE_VERIFY_UNVERIFIED;   /* not content-addressed */
    }

    fd = open(part_path, O_RDONLY | O_NOFOLLOW); /* vfs-seam-allow: cache-store staging file, svc-owned domain */
    if (fd < 0) {
        return XROOTD_CACHE_VERIFY_ERROR;
    }
    if (xrootd_checksum_hex_name_fd(fd, "sha1", hex, sizeof(hex)) != 0) {
        close(fd);
        return XROOTD_CACHE_VERIFY_ERROR;
    }
    close(fd);

    if (info.cas_hex_len != 40
        || ngx_strncasecmp((u_char *) hex, (u_char *) info.cas_hex, 40) != 0)
    {
        return XROOTD_CACHE_VERIFY_MISMATCH;
    }
    if (out_alg != NULL) { ngx_memcpy(out_alg, "sha1", sizeof("sha1")); }
    if (out_hex != NULL) { ngx_memcpy(out_hex, hex, 41); }
    return XROOTD_CACHE_VERIFY_VERIFIED;
}

void
xrootd_cache_quarantine_part(xrootd_cache_fill_t *t, const char *part_path,
    const char *quarantine_dir)
{
    char        dst[XROOTD_CACHE_PATH_MAX];
    const char *base;

    if (quarantine_dir == NULL || quarantine_dir[0] == '\0') {
        unlink(part_path); /* vfs-seam-allow: cache-store staging file */
        return;
    }
    base = strrchr(part_path, '/');
    base = (base != NULL) ? base + 1 : part_path;
    snprintf(dst, sizeof(dst), "%s/%s.%ld", quarantine_dir, base,
             (long) time(NULL));
    if (rename(part_path, dst) != 0) { /* vfs-seam-allow: cache-store staging file */
        unlink(part_path); /* vfs-seam-allow: cache-store staging file */
    }
}
```

In `fetch.c`, at the existing verify call site (where `xrootd_cache_verify_part()` runs before the atomic rename): when the effective mode is `XROOTD_CACHE_VERIFY_CVMFS_CAS`, call `xrootd_cache_verify_cvmfs_cas()` instead; on `MISMATCH`, call `xrootd_cache_quarantine_part()` with the loc-conf quarantine dir threaded through the fill ctx, set the fill error (`kXR_ChkSumErr` → HTTP 502 via the existing errno map), and log via `XROOTD_DIAG` with cause "origin transfer failed CAS verification — network corruption between cache and Stratum-1" and fix "check WAN path / middleboxes; object was quarantined, client will retry".

- [ ] **Step 4: Build + run**

Run: `cd /tmp/nginx-1.28.3 && make -j$(nproc) && bash /home/rcurrie/HEP-x/nginx-xrootd/tests/run_cvmfs_verify.sh`
Expected: 6 × `ok`, exit 0.

- [ ] **Step 5: Commit**

```bash
git add src/fs/cache/verify.h src/fs/cache/verify.c src/fs/cache/fetch.c \
        src/fs/cache/directives.c tests/run_cvmfs_verify.sh
git commit -m "feat(cvmfs): CAS verify-on-fill + quarantine — corrupt fills never admitted"
```

---

### Task 11: Multi-origin failover in `sd_http`

**Files:**
- Modify: `src/fs/backend/http/sd_http.c` (endpoint array + health + failover), `src/fs/vfs/vfs_backend_config.c` (parse `|`-separated URL list in `xrootd_storage_backend http://a/p|http://b/p`)
- Test: `tests/run_cvmfs_failover.sh`

**Interfaces:**
- Consumes: existing `sd_http_inst_state` / transport vtable.
- Produces: `xrootd_storage_backend` accepts a pipe-separated ordered list of http(s) URLs (mirrors `CVMFS_SERVER_URL` syntax). `sd_http_inst_state` gains `endpoints[SD_HTTP_EP_MAX=8]` each `{host, port, tls, base_path, fail_score}` and helpers:

```c
/* pick the healthiest endpoint (lowest EWMA fail score, order-stable ties). */
static sd_http_endpoint *sd_http_pick(sd_http_inst_state *is);
/* record outcome: score = score*7/8 + (ok ? 0 : 256). Cheap integer EWMA. */
static void sd_http_score(sd_http_endpoint *ep, int ok);
```

Every transport call site in `sd_http.c` (`head_size`, `pread`) becomes: pick → attempt → on transport error, score-fail and retry once on the next-best endpoint → score result.

- [ ] **Step 1: Write the failing e2e test**

```bash
#!/usr/bin/env bash
# tests/run_cvmfs_failover.sh — two mock origins; primary stalls/dies →
#   1 fills transparently from the secondary (client sees success)
#   2 primary recovers → traffic returns (health decay)
#   3 error-neg: BOTH origins down → clean 502, no worker stall
set -u
NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
HERE="$(cd "$(dirname "$0")" && pwd)"
M1=12851; M2=12852; CPORT=12853
PFX="$(mktemp -d /tmp/cvmfs_fo.XXXXXX)"; fail=0
ok(){ printf '  ok   %s\n' "$1"; }; bad(){ printf '  FAIL %s\n' "$1"; fail=1; }
cleanup(){ [ -f "$PFX/nginx.pid" ] && kill "$(cat "$PFX/nginx.pid")" 2>/dev/null
           kill "$MOCK1" "$MOCK2" 2>/dev/null; rm -rf "$PFX"; }
trap cleanup EXIT
mkdir -p "$PFX/cache" "$PFX/logs"

# identical repos (same seed) on both origins
python3 "$HERE/cvmfs/mock_stratum1.py" --port $M1 --objects 6 --seed 5 & MOCK1=$!
python3 "$HERE/cvmfs/mock_stratum1.py" --port $M2 --objects 6 --seed 5 & MOCK2=$!
sleep 0.5

cat > "$PFX/nginx.conf" <<EOF
daemon on; error_log $PFX/logs/e.log info; pid $PFX/nginx.pid;
thread_pool default threads=2;
events { worker_connections 128; }
http { access_log off; server {
    listen 127.0.0.1:$CPORT;
    location /cvmfs/ {
        xrootd_cvmfs_storage_backend "http://127.0.0.1:$M1/cvmfs|http://127.0.0.1:$M2/cvmfs";
        xrootd_cvmfs_cache_store $PFX/cache;
        xrootd_cache_include_regex "/data/";
        xrootd_cvmfs on;
    }
} }
EOF
"$NGINX" -c "$PFX/nginx.conf" -p "$PFX"; sleep 0.5

OBJS=($(curl -s "http://127.0.0.1:$M1/ctl/objects" | python3 -c \
       'import json,sys; print(" ".join(json.load(sys.stdin)))'))

# 1: kill primary → fill must come from secondary
kill "$MOCK1"; sleep 0.2
curl -s --max-time 25 "http://127.0.0.1:$CPORT${OBJS[0]}" -o "$PFX/a.bin"
curl -s "http://127.0.0.1:$M2${OBJS[0]}" -o "$PFX/ref.bin"
cmp -s "$PFX/a.bin" "$PFX/ref.bin" && ok "failover fill from secondary" \
    || bad "failover fill failed"
N2="$(curl -s "http://127.0.0.1:$M2/ctl/log" | grep -c "${OBJS[0]}")"
[ "$N2" -ge 1 ] && ok "secondary actually served it" || bad "secondary untouched"

# 2: primary back → eventually reused (health decay). Restart it on same port.
python3 "$HERE/cvmfs/mock_stratum1.py" --port $M1 --objects 6 --seed 5 & MOCK1=$!
sleep 0.5
for u in "${OBJS[@]:1:4}"; do curl -s "http://127.0.0.1:$CPORT$u" -o /dev/null; done
NP="$(curl -s "http://127.0.0.1:$M1/ctl/log" | grep -c '/data/' || true)"
[ "$NP" -ge 1 ] && ok "primary reused after recovery ($NP fills)" \
    || bad "primary never reused"

# 3: both down → clean fast 502
kill "$MOCK1" "$MOCK2"; sleep 0.2
C="$(curl -s --max-time 30 -o /dev/null -w '%{http_code}' \
     "http://127.0.0.1:$CPORT${OBJS[5]}")"
[ "$C" = 502 ] && ok "both-down → clean 502" || bad "both-down: $C"
exit $fail
```

- [ ] **Step 2: Run to verify it fails**

Run: `bash tests/run_cvmfs_failover.sh`
Expected: FAIL — `nginx -t` rejects the pipe-separated backend URL (or check 1 fails).

- [ ] **Step 3: Implement**

`vfs_backend_config.c`: in the existing `http://`/`https://` branch (around `vfs_backend_config.c:441`), split the value on `|` first; parse each segment with the existing host/port/base logic; store into a new endpoints array on the backend entry (extend `xrootd_vfs_backend_config_http` to `..._http_multi(root_canon, eps, n_eps)` keeping the single-URL wrapper delegating with `n_eps=1`).

`sd_http.c`:

```c
#define SD_HTTP_EP_MAX 8

typedef struct {
    char host[256];
    int  port, tls;
    char base_path[SD_HTTP_BASE_MAX];
    int  fail_score;                 /* integer EWMA; 0 = healthy            */
} sd_http_endpoint;

/* inst_state: replace the single host/port/tls/base with:
 *   sd_http_endpoint eps[SD_HTTP_EP_MAX]; int n_eps;                        */

static sd_http_endpoint *
sd_http_pick(sd_http_inst_state *is)
{
    sd_http_endpoint *best = &is->eps[0];
    int               i;

    for (i = 1; i < is->n_eps; i++) {
        if (is->eps[i].fail_score < best->fail_score) {
            best = &is->eps[i];
        }
    }
    return best;
}

static void
sd_http_score(sd_http_endpoint *ep, int ok)
{
    ep->fail_score = ep->fail_score * 7 / 8 + (ok ? 0 : 256);
}

/* request wrapper used by head_size/pread: try the best endpoint, then ONE
 * alternate on transport failure (HTTP 4xx is NOT a transport failure — the
 * object genuinely isn't there; do not mask it by failing over). */
static int
sd_http_request_fo(sd_http_inst_state *is, const char *method, const char *key,
    const char *range_hdr, xrootd_s3_resp_t *resp, sd_http_endpoint **used)
{
    sd_http_endpoint *ep = sd_http_pick(is);
    char              full[SD_HTTP_PATH_MAX], errbuf[256];
    int               attempt, rc;

    for (attempt = 0; attempt < 2; attempt++) {
        snprintf(full, sizeof(full), "%s%s", ep->base_path,
                 (key != NULL && key[0]) ? key : "/");
        rc = is->transport->request(is->tctx, ep->host, ep->port, ep->tls,
                                    method, full,
                                    is->auth_hdr[0] ? is->auth_hdr : range_hdr,
                                    NULL, 0, is->timeout_ms, resp,
                                    errbuf, sizeof(errbuf));
        sd_http_score(ep, rc == 0);
        if (rc == 0) {
            *used = ep;
            return 0;
        }
        if (is->n_eps < 2) {
            break;
        }
        ep = (ep == &is->eps[0]) ? &is->eps[1] : &is->eps[0];  /* next-best */
        if (attempt == 0) {
            ep = sd_http_pick(is);            /* re-pick excluding implicit  */
        }
    }
    errno = EIO;
    return -1;
}
```

Refactor `sd_http_head_size` and the `pread` path onto `sd_http_request_fo` (keeping their status-code → errno mapping unchanged). Note the existing `auth_hdr`/`range_hdr` slot sharing: today `request()` takes a single extra-header argument — pass the Range header when there is no auth header, and pre-join them when both exist (small helper `sd_http_extra_hdrs()` writing into a stack buffer).

- [ ] **Step 4: Build + run**

Run: `cd /tmp/nginx-1.28.3 && make -j$(nproc) && bash /home/rcurrie/HEP-x/nginx-xrootd/tests/run_cvmfs_failover.sh && bash /home/rcurrie/HEP-x/nginx-xrootd/tests/run_cache_http_source.sh`
Expected: failover test 5 × `ok`; the existing single-origin http-source test still green (regression).

- [ ] **Step 5: Commit**

```bash
git add src/fs/backend/http/sd_http.c src/fs/vfs/vfs_backend_config.c \
        tests/run_cvmfs_failover.sh
git commit -m "feat(cvmfs): pipe-separated multi-origin http backend with EWMA health failover"
```

---

### Task 12: Manifest TTL + revalidate + bounded stale-if-error

**Files:**
- Modify: `src/fs/cache/cinfo.h`/`cinfo.c` (optional `expires_at`, new flag bit `XROOTD_CINFO_F_EXPIRES`), `src/fs/cache/open.c` (hit path honors expiry), `src/protocols/cvmfs/gate.c` (MANIFEST routes through cache once TTL exists), `src/fs/cache/fetch.c` (stamp expiry on manifest fills)
- Test: `tests/run_cvmfs_manifest.sh`

**Interfaces:**
- Consumes: `cvmfs.manifest_ttl` (Task 8), cinfo v3 engine.
- Produces:

```c
/* cinfo.h additions. The header struct xrootd_cache_cinfo_t (cinfo.h:64,
 * uint16_t flags at offset 6, existing flag bits 0x0001–0x0008) gains ONE
 * trailing field and ONE flag bit:                                          */
#define XROOTD_CINFO_F_EXPIRES  0x0010u  /* expires_at field present+valid */
    /* ...appended as the LAST member of xrootd_cache_cinfo_t: */
    uint64_t expires_at;     /* unix secs; entry stale when now >= expires_at
                                and F_EXPIRES is set. 0 + no flag = no TTL. */

/* Stamp an expiry (sets F_EXPIRES). */
void xrootd_cache_cinfo_set_expires(xrootd_cache_cinfo_t *ci, time_t when);
/* 0 = fresh, 1 = expired, -1 = no expiry recorded (immutable entry). */
int  xrootd_cache_cinfo_expired(const xrootd_cache_cinfo_t *ci, time_t now);
```

**Compatibility rule (this is the load-bearing detail):** appending a field
changes `XROOTD_CACHE_CINFO_HDR_SIZE`, and cinfo files written before this
task are 8 bytes shorter. The reader must accept BOTH sizes: read
`HDR_SIZE`, and if only `HDR_SIZE - 8` bytes precede the bitmap, zero
`expires_at` and clear `F_EXPIRES` (mirroring the file's existing v2→v3
tolerant-read pattern). The writer always emits the full new header.
Version stays 3 — the flag bit is the presence signal, exactly like the
other optional v3 features.

Hit-path policy (in `xrootd_cache_open()`): `expired && origin reachable` → treat as miss (refill overwrites); `expired && refill fails` → serve stale if `age < 10 * ttl` (bounded stale-if-error), else 502. Config knob reuse: the bound is `10 * cvmfs.manifest_ttl`, not a new directive (YAGNI).

- [ ] **Step 1: Write the failing e2e test**

```bash
#!/usr/bin/env bash
# tests/run_cvmfs_manifest.sh — manifest caching semantics:
#   1 within TTL: second GET served from cache (0 extra origin hits)
#   2 after TTL + bump: refetch returns the NEW manifest
#   3 error-neg: after TTL with origin DOWN: bounded stale-serve (200, old body)
set -u
NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
HERE="$(cd "$(dirname "$0")" && pwd)"
MPORT=12861; CPORT=12862; TTL=2
PFX="$(mktemp -d /tmp/cvmfs_man.XXXXXX)"; fail=0
ok(){ printf '  ok   %s\n' "$1"; }; bad(){ printf '  FAIL %s\n' "$1"; fail=1; }
cleanup(){ [ -f "$PFX/nginx.pid" ] && kill "$(cat "$PFX/nginx.pid")" 2>/dev/null
           kill "$MOCK" 2>/dev/null; rm -rf "$PFX"; }
trap cleanup EXIT
mkdir -p "$PFX/cache" "$PFX/logs"
python3 "$HERE/cvmfs/mock_stratum1.py" --port $MPORT --objects 2 --seed 1 &
MOCK=$!; sleep 0.5

cat > "$PFX/nginx.conf" <<EOF
daemon on; error_log $PFX/logs/e.log info; pid $PFX/nginx.pid;
thread_pool default threads=2;
events { worker_connections 128; }
http { access_log off; server {
    listen 127.0.0.1:$CPORT;
    location /cvmfs/ {
        xrootd_cvmfs_storage_backend http://127.0.0.1:$MPORT/cvmfs;
        xrootd_cvmfs_cache_store $PFX/cache;
        xrootd_cvmfs on;
        xrootd_cvmfs_manifest_ttl $TTL;
    }
} }
EOF
# NOTE: no include_regex — Task 12 makes manifests cacheable-with-TTL, so the
# admission stopgap is dropped in this config; CAS still cached (no regex = all).
"$NGINX" -c "$PFX/nginx.conf" -p "$PFX"; sleep 0.5
M="/cvmfs/test.cern.ch/.cvmfspublished"

# 1: within TTL → cached
curl -s "http://127.0.0.1:$CPORT$M" -o "$PFX/m1"
N1="$(curl -s "http://127.0.0.1:$MPORT/ctl/log" | grep -c cvmfspublished)"
curl -s "http://127.0.0.1:$CPORT$M" -o "$PFX/m2"
N2="$(curl -s "http://127.0.0.1:$MPORT/ctl/log" | grep -c cvmfspublished)"
[ "$N1" = "$N2" ] && cmp -s "$PFX/m1" "$PFX/m2" && ok "fresh manifest from cache" \
    || bad "manifest not cached within TTL"

# 2: after TTL + bump → refetched, new content
curl -s "http://127.0.0.1:$MPORT/ctl/manifest/bump" >/dev/null
sleep $((TTL + 1))
curl -s "http://127.0.0.1:$CPORT$M" -o "$PFX/m3"
cmp -s "$PFX/m1" "$PFX/m3" && bad "manifest stale after TTL" \
    || ok "expired manifest revalidated"

# 3: after TTL with origin down → bounded stale-serve of m3
kill "$MOCK"; sleep $((TTL + 1))
C="$(curl -s -o "$PFX/m4" -w '%{http_code}' "http://127.0.0.1:$CPORT$M")"
[ "$C" = 200 ] && cmp -s "$PFX/m3" "$PFX/m4" && ok "stale-if-error serve" \
    || bad "stale-if-error: code=$C"
exit $fail
```

- [ ] **Step 2: Run to verify it fails**

Run: `bash tests/run_cvmfs_manifest.sh`
Expected: check 1 FAILs (manifest currently refetched every time — no TTL machinery).

- [ ] **Step 3: Implement**

**(a) `cinfo.c` — the two helpers + tolerant read:**

```c
void
xrootd_cache_cinfo_set_expires(xrootd_cache_cinfo_t *ci, time_t when)
{
    ci->expires_at = (uint64_t) when;
    ci->flags |= XROOTD_CINFO_F_EXPIRES;
}

int
xrootd_cache_cinfo_expired(const xrootd_cache_cinfo_t *ci, time_t now)
{
    if ((ci->flags & XROOTD_CINFO_F_EXPIRES) == 0) {
        return -1;                          /* immutable entry: never expires */
    }
    return ((uint64_t) now >= ci->expires_at) ? 1 : 0;
}
```

In the header-read function (the one validating magic/version before the
bitmap), where the fixed header is read:

```c
    /* v3 files written before phase-68 lack the trailing expires_at (8 B).
     * Accept both header sizes; short header ⇒ no expiry recorded. */
    n = read(fd, hdr, XROOTD_CACHE_CINFO_HDR_SIZE);
    if (n == (ssize_t) XROOTD_CACHE_CINFO_HDR_SIZE - 8) {
        hdr->expires_at = 0;
        hdr->flags &= (uint16_t) ~XROOTD_CINFO_F_EXPIRES;
    } else if (n != (ssize_t) XROOTD_CACHE_CINFO_HDR_SIZE) {
        return NGX_ERROR;                   /* unchanged short/garbage path */
    }
```

The pre-phase-68 file's bitmap begins 8 bytes earlier; the tolerant branch
must also rewind/track the bitmap offset accordingly — follow how the
existing v2-compat read already renegotiates offsets (same function).

**(b) `fetch.c` — stamp the expiry at publish time** (in the block that
writes the fresh cinfo just before the atomic rename; the fill ctx fields
come from cross-cutting convention #1):

```c
    if (t->cvmfs_manifest_ttl > 0) {
        cvmfs_url_info_t  uinfo;

        if (cvmfs_classify_url(t->export_path, strlen(t->export_path),
                               &uinfo) == 0
            && uinfo.cls == CVMFS_URL_MANIFEST)
        {
            xrootd_cache_cinfo_set_expires(&ci,
                ngx_time() + t->cvmfs_manifest_ttl);
        }
    }
```

**(c) `open.c` — expiry-aware hit path.** `xrootd_cache_open()` gains a
tri-state. Today it returns opened-fd/miss; add:

```c
/* open.h */
typedef enum {
    XROOTD_CACHE_OPEN_HIT = 0,
    XROOTD_CACHE_OPEN_MISS,
    XROOTD_CACHE_OPEN_EXPIRED   /* entry exists but TTL passed: refill, and
                                   keep the stale fd for bounded fallback   */
} xrootd_cache_open_status_e;
```

In the hit path, after the existing meta/cinfo validation succeeds:

```c
    if (xrootd_cache_cinfo_expired(&hdr, ngx_time()) == 1) {
        *stale_fd = fd;                 /* caller owns it for the fallback  */
        *stale_expired_at = (time_t) hdr.expires_at;
        return XROOTD_CACHE_OPEN_EXPIRED;
    }
```

**(d) `open_or_fill.c` — refill with bounded stale-if-error.** Where the
open status is consumed: `EXPIRED` behaves like `MISS` (allocate the fill,
post it), but the stale fd + its `expires_at` ride on the fill ctx. In the
completion path (`thread.c`/`open_or_fill.c` fill-done), on fill FAILURE:

```c
    if (fill->stale_fd >= 0) {
        time_t age_past_ttl = ngx_time() - fill->stale_expired_at;

        if (fill->cvmfs_manifest_ttl > 0
            && age_past_ttl < 9 * fill->cvmfs_manifest_ttl)
        {
            /* bounded stale-if-error: expiry was fill_time + ttl, so total
             * age <= 10*ttl. Serve the stale copy; log one WARN diag. */
            XROOTD_DIAG_WARN(log, "cvmfs manifest refill failed; serving "
                "stale copy (%.0fs past ttl)", (double) age_past_ttl,
                /* cause */ "origin unreachable or fill error",
                /* fix   */ "check Stratum-1 reachability; stale serving "
                            "stops at 10x manifest_ttl");
            return cvmfs_serve_stale(fill);   /* open path on stale_fd */
        }
        close(fill->stale_fd); /* vfs-seam-allow: cache-store fd, svc-owned */
        fill->stale_fd = -1;
    }
    /* fall through: existing error propagation (502 to the client) */
```

On fill SUCCESS the stale fd is simply closed and the fresh entry is served
as usual. `cvmfs_serve_stale` is a thin wrapper around the same
serve-from-cache-fd path a HIT uses — do not duplicate the sendfile logic,
call the existing helper with the stale fd. (`XROOTD_DIAG_WARN` stands for
the project's actual `XROOTD_DIAG` macro shape in `src/core/…/log_diag.h` —
match its real signature.)

`gate.c`: nothing to change — MANIFEST already falls through to the tier; just delete the `xrootd_cache_include_regex "/data/"` stopgap from the Task-9 test config so manifests are now admitted+TTL'd there too (update `run_cvmfs_reverse.sh`'s "manifest fetched fresh" check to instead bump-then-sleep past a 1 s TTL, mirroring this task's check 2).

- [ ] **Step 4: Build + run all three cvmfs e2e suites**

Run: `cd /tmp/nginx-1.28.3 && make -j$(nproc) && cd /home/rcurrie/HEP-x/nginx-xrootd && bash tests/run_cvmfs_manifest.sh && bash tests/run_cvmfs_reverse.sh && bash tests/run_cvmfs_verify.sh`
Expected: all green.

- [ ] **Step 5: Commit**

```bash
git add src/fs/cache/cinfo.h src/fs/cache/cinfo.c src/fs/cache/open.c \
        src/fs/cache/open_or_fill.c src/fs/cache/fetch.c \
        tests/run_cvmfs_manifest.sh tests/run_cvmfs_reverse.sh
git commit -m "feat(cvmfs): manifest TTL via cinfo expires_at + revalidate + bounded stale-if-error"
```

---

### Task 13: Negative caching

**Files:**
- Modify: `src/protocols/cvmfs/gate.c` (+ per-worker negative LRU), `src/protocols/cvmfs/cvmfs.h`
- Test: extend `tests/run_cvmfs_reverse.sh`

**Interfaces:**
- Consumes: `cvmfs.negative_ttl` (Task 8).
- Produces: a per-worker (no SHM — YAGNI) fixed-size open-addressing memo in `gate.c`:

```c
#define CVMFS_NEG_SLOTS 512
typedef struct { uint64_t path_hash; time_t until; } cvmfs_neg_slot;
/* returns 1 if `uri` 404'd within negative_ttl */
static int cvmfs_neg_check(const ngx_str_t *uri, time_t now);
/* records a 404 for negative_ttl seconds */
static void cvmfs_neg_store(const ngx_str_t *uri, time_t now, time_t ttl);
```

Gate flow addition: before declining a CAS/MANIFEST request, `cvmfs_neg_check` → immediate 404. The store hook is protocol-internal: the handler's serve path (`xrootd_cvmfs_tier_get()` in `handler.c`) calls `xrootd_cvmfs_notify_status()` at the point where the 404 status is finalized — no shared-path callback needed, since the dedicated protocol owns its whole request lifecycle (CVMFS-specific logic stays in `gate.c`).

- [ ] **Step 1: Write the failing checks** (append to `run_cvmfs_reverse.sh`)

```bash
# negative cache: 2 misses for the same bogus CAS name → 1 origin round-trip
BOGUS="/cvmfs/test.cern.ch/data/aa/$(python3 -c 'print("ab"*19)')"
curl -s -o /dev/null "http://127.0.0.1:$CPORT$BOGUS"
NB1="$(curl -s "http://127.0.0.1:$MPORT/ctl/log" | grep -c "$BOGUS")"
C="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$CPORT$BOGUS")"
NB2="$(curl -s "http://127.0.0.1:$MPORT/ctl/log" | grep -c "$BOGUS")"
[ "$C" = 404 ] && [ "$NB1" = "$NB2" ] && ok "negative cache absorbed repeat 404" \
    || bad "negative cache: code=$C origin=$NB1→$NB2"
```

- [ ] **Step 2: Run to verify it fails** — second request hits the origin again (`NB2 > NB1`).

- [ ] **Step 3: Implement.** In `gate.c` (per-worker statics are the
`negative cache — deliberately worker-local` exception to the no-globals
rule; each worker absorbing its own 404 storm is sufficient and avoids SHM):

```c
/* --- negative cache -------------------------------------------------------
 * Per-worker fixed-size direct-mapped memo of recent 404s. A slot collision
 * simply overwrites (false eviction = one extra origin round-trip; false
 * HITS are impossible because the full hash is compared, and even a true
 * 64-bit collision only mis-404s one object for negative_ttl seconds —
 * acceptable for a cache whose entries are retried by design).
 */
#define CVMFS_NEG_SLOTS 512u            /* power of two: mask, don't mod   */

typedef struct {
    uint64_t path_hash;                 /* FNV-1a of the full URI, 0=empty */
    time_t   until;
} cvmfs_neg_slot;

static cvmfs_neg_slot  cvmfs_neg[CVMFS_NEG_SLOTS];

static uint64_t
cvmfs_neg_hash(const ngx_str_t *uri)
{
    uint64_t h = 0xcbf29ce484222325ull;
    size_t   i;

    for (i = 0; i < uri->len; i++) {
        h = (h ^ uri->data[i]) * 0x100000001b3ull;
    }
    return (h != 0) ? h : 1;            /* 0 is the empty-slot marker      */
}

static int
cvmfs_neg_check(const ngx_str_t *uri, time_t now)
{
    uint64_t        h = cvmfs_neg_hash(uri);
    cvmfs_neg_slot *s = &cvmfs_neg[h & (CVMFS_NEG_SLOTS - 1)];

    return (s->path_hash == h && now < s->until);
}

static void
cvmfs_neg_store(const ngx_str_t *uri, time_t now, time_t ttl)
{
    uint64_t        h = cvmfs_neg_hash(uri);
    cvmfs_neg_slot *s = &cvmfs_neg[h & (CVMFS_NEG_SLOTS - 1)];

    s->path_hash = h;
    s->until = now + ttl;
}
```

Gate flow addition, in `xrootd_cvmfs_gate()` inside the CAS/MANIFEST case
before returning `NGX_DECLINED`:

```c
        if (lcf->cvmfs.negative_ttl > 0
            && cvmfs_neg_check(&r->uri, ngx_time()))
        {
            XROOTD_CVMFS_METRIC_INC(XROOTD_CVMFS_M_NEG_HIT);
            return NGX_HTTP_NOT_FOUND;
        }
```

The store hook: `xrootd_cvmfs_notify_status()` exported from `gate.c`
(declared in `cvmfs.h`):

```c
/* Called by the shared GET finalization when a cvmfs-enabled location has
 * produced its final status. Records 404s in the negative memo. */
void
xrootd_cvmfs_notify_status(ngx_http_request_t *r,
    ngx_http_xrootd_cvmfs_loc_conf_t *lcf, ngx_uint_t status)
{
    if (status == NGX_HTTP_NOT_FOUND && lcf->cvmfs.negative_ttl > 0) {
        cvmfs_neg_store(&r->uri, ngx_time(), lcf->cvmfs.negative_ttl);
    }
}
```

…invoked from the one place in the cvmfs handler's serve path where a 404
is finalized (the ENOENT branch of `xrootd_cvmfs_tier_get()` in
`handler.c` — the spot that runs the errno→HTTP mapping). Being inside the
dedicated protocol handler, no other protocol pays even a branch.

- [ ] **Step 4: Build + run**

Run: `cd /tmp/nginx-1.28.3 && make -j$(nproc) && bash /home/rcurrie/HEP-x/nginx-xrootd/tests/run_cvmfs_reverse.sh`
Expected: all previous `ok`s plus `ok negative cache absorbed repeat 404`.

- [ ] **Step 5: Commit**

```bash
git add src/protocols/cvmfs/gate.c src/protocols/cvmfs/cvmfs.h \
        src/protocols/cvmfs/handler.c tests/run_cvmfs_reverse.sh
git commit -m "feat(cvmfs): per-worker negative cache for 404 storms"
```

---

### Task 14: Proxy mode (absolute-URI) + upstream allowlist

**Files:**
- Create: `src/protocols/cvmfs/request.c`, `src/protocols/cvmfs/upstreams.c`
- Modify: `src/protocols/cvmfs/gate.c` (proxy-mode branch), `src/protocols/cvmfs/cvmfs.h`, `./config` (+2 files, full rebuild)
- Test: `tests/run_cvmfs_proxy.sh`

**Interfaces:**
- Consumes: `cvmfs.upstream_allow` / `cvmfs.upstream_max` (Task 8), multi-endpoint backend entries (Task 11), classifier (Task 7).
- Produces:

```c
/* request.c — proxy-mode target extraction.
 * A CVMFS client behind CVMFS_HTTP_PROXY sends "GET http://s1:8000/cvmfs/..."
 * — nginx parses absolute-form request-targets and exposes the authority via
 * r->host_start/r->host_end and r->port_start/r->port_end; r->uri holds the
 * path. Returns NGX_OK with host/port filled, NGX_DECLINED when the request
 * was origin-form (reverse mode), NGX_HTTP_FORBIDDEN when the authority is
 * not on the allowlist. */
ngx_int_t xrootd_cvmfs_proxy_target(ngx_http_request_t *r,
    const xrootd_cvmfs_conf_t *cc, ngx_str_t *host, in_port_t *port);

/* upstreams.c — bounded lazy registry: (host,port) → VFS backend entry built
 * with xrootd_vfs_backend_config_http(); at most cc->upstream_max entries per
 * worker, created on first use, reused thereafter. Cache keys (and therefore
 * cache_store paths) are prefixed "<host>_<port>/" so upstreams never collide.
 * Returns NULL + sets *status on capacity exhaustion (503). */
xrootd_vfs_backend_entry_t *xrootd_cvmfs_upstream_get(ngx_http_request_t *r,
    const xrootd_cvmfs_conf_t *cc, const ngx_str_t *host, in_port_t port,
    ngx_uint_t *status);
```

Gate integration: when `r->host_start != NULL` (absolute-form), run `proxy_target` → `upstream_get` → stash the entry in the request ctx so the downstream GET path resolves against it instead of the location's static backend (the VFS open path already takes the backend entry from a per-request lookup — extend that lookup to consult the ctx override first).

- [ ] **Step 1: Write the failing e2e test**

```bash
#!/usr/bin/env bash
# tests/run_cvmfs_proxy.sh — forward-proxy (CVMFS_HTTP_PROXY) mode:
#   1 absolute-URI GET through the cache → byte-exact, cached per-upstream
#   2 two distinct upstream hosts → distinct cache entries (no key collision)
#   3 security-neg: authority NOT on allowlist → 403, origin never contacted
set -u
NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
HERE="$(cd "$(dirname "$0")" && pwd)"
M1=12871; M2=12872; CPORT=12873
PFX="$(mktemp -d /tmp/cvmfs_proxy.XXXXXX)"; fail=0
ok(){ printf '  ok   %s\n' "$1"; }; bad(){ printf '  FAIL %s\n' "$1"; fail=1; }
cleanup(){ [ -f "$PFX/nginx.pid" ] && kill "$(cat "$PFX/nginx.pid")" 2>/dev/null
           kill "$MOCK1" "$MOCK2" 2>/dev/null; rm -rf "$PFX"; }
trap cleanup EXIT
mkdir -p "$PFX/cache" "$PFX/logs"
python3 "$HERE/cvmfs/mock_stratum1.py" --port $M1 --objects 4 --seed 11 & MOCK1=$!
python3 "$HERE/cvmfs/mock_stratum1.py" --port $M2 --objects 4 --seed 22 & MOCK2=$!
sleep 0.5

cat > "$PFX/nginx.conf" <<EOF
daemon on; error_log $PFX/logs/e.log info; pid $PFX/nginx.pid;
thread_pool default threads=2;
events { worker_connections 128; }
http { access_log off; server {
    listen 127.0.0.1:$CPORT;
    location / {
        xrootd_cvmfs_cache_store $PFX/cache;
        xrootd_cvmfs on;
        xrootd_cvmfs_upstream_allow 127.0.0.1;
        xrootd_cvmfs_upstream_max 4;
    }
} }
EOF
"$NGINX" -c "$PFX/nginx.conf" -p "$PFX"; sleep 0.5
PROXY="http://127.0.0.1:$CPORT"

O1="$(curl -s "http://127.0.0.1:$M1/ctl/objects" | python3 -c \
     'import json,sys; print(json.load(sys.stdin)[0])')"
O2="$(curl -s "http://127.0.0.1:$M2/ctl/objects" | python3 -c \
     'import json,sys; print(json.load(sys.stdin)[0])')"

# 1: proxy-style fetch, byte-exact, warm hit stays local
curl -s -x "$PROXY" "http://127.0.0.1:$M1$O1" -o "$PFX/p1.bin"
curl -s "http://127.0.0.1:$M1$O1" -o "$PFX/r1.bin"
cmp -s "$PFX/p1.bin" "$PFX/r1.bin" && ok "proxy-mode byte-exact" || bad "proxy bytes"
NA="$(curl -s "http://127.0.0.1:$M1/ctl/log" | grep -c "$O1")"
curl -s -x "$PROXY" "http://127.0.0.1:$M1$O1" -o /dev/null
NB="$(curl -s "http://127.0.0.1:$M1/ctl/log" | grep -c "$O1")"
[ "$NA" = "$NB" ] && ok "proxy-mode warm hit cached" || bad "warm went upstream"

# 2: second upstream is independent (different seed → different objects)
curl -s -x "$PROXY" "http://127.0.0.1:$M2$O2" -o "$PFX/p2.bin"
curl -s "http://127.0.0.1:$M2$O2" -o "$PFX/r2.bin"
cmp -s "$PFX/p2.bin" "$PFX/r2.bin" && ok "second upstream independent" \
    || bad "upstream cache-key collision"

# 3: disallowed authority → 403 (mock logs must NOT show the path)
C="$(curl -s -o /dev/null -w '%{http_code}' -x "$PROXY" \
     "http://evil.example.org/cvmfs/x/data/aa/$(python3 -c 'print("cd"*19)')")"
[ "$C" = 403 ] && ok "disallowed upstream rejected" || bad "allowlist: $C"
exit $fail
```

- [ ] **Step 2: Run to verify it fails**

Run: `bash tests/run_cvmfs_proxy.sh`
Expected: check 1 FAILs (absolute-URI request rejected or mis-served by reverse-only gate).

- [ ] **Step 3a: Implement `request.c`**

```c
/* request.c — proxy-mode target extraction + allowlist.
 *
 * WHAT: for absolute-form request lines ("GET http://s1:8000/cvmfs/..."),
 *       extract the authority nginx already parsed (r->host_start/end,
 *       r->port_start/end) and check it against xrootd_cvmfs_upstream_allow.
 * WHY:  a CVMFS site proxy is a proxy for the site's Stratum-1s ONLY —
 *       without the allowlist it is an open HTTP proxy.
 * HOW:  no parsing of our own: nginx validates absolute-form targets during
 *       request-line parsing and r->uri already holds just the path, so the
 *       classifier and every layer below see exactly the reverse-mode shape.
 */
#include "cvmfs.h"

ngx_int_t
xrootd_cvmfs_proxy_target(ngx_http_request_t *r, const xrootd_cvmfs_conf_t *cc,
    ngx_str_t *host, in_port_t *port)
{
    ngx_str_t   *allow;
    ngx_uint_t   i;
    ngx_int_t    p;

    if (r->host_start == NULL) {
        return NGX_DECLINED;                    /* origin-form: reverse mode */
    }

    /* cleartext only on cvmfs://: WLCG proxy traffic is plain HTTP; an
     * https target means a misconfigured client, not a feature request.
     * (scvmfs://, T22, lifts this on secure listeners: ctx->secure allows
     * https authorities and TLS upstream connects.) */
    if (r->schema_end - r->schema_start != 4
        || ngx_strncasecmp(r->schema_start, (u_char *) "http", 4) != 0)
    {
        return NGX_HTTP_FORBIDDEN;
    }

    host->data = r->host_start;
    host->len  = (size_t) (r->host_end - r->host_start);

    *port = 80;
    if (r->port_start != NULL) {
        p = ngx_atoi(r->port_start, (size_t) (r->port_end - r->port_start));
        if (p < 1 || p > 65535) {
            return NGX_HTTP_BAD_REQUEST;
        }
        *port = (in_port_t) p;
    }

    if (cc->upstream_allow == NULL || cc->upstream_allow->nelts == 0) {
        /* allowlist unset = proxy mode off: absolute-form always refused */
        return NGX_HTTP_FORBIDDEN;
    }
    allow = cc->upstream_allow->elts;
    for (i = 0; i < cc->upstream_allow->nelts; i++) {
        if (allow[i].len == host->len
            && ngx_strncasecmp(allow[i].data, host->data, host->len) == 0)
        {
            return NGX_OK;
        }
    }
    return NGX_HTTP_FORBIDDEN;
}
```

- [ ] **Step 3b: Implement `upstreams.c`**

```c
/* upstreams.c — bounded lazy per-upstream backend registry (proxy mode).
 *
 * WHAT: maps (host, port) → a VFS backend entry built once per worker and
 *       reused; the entry's cache paths are prefixed "<host>_<port>/" so
 *       objects from different Stratum-1s can never alias in the store.
 * WHY:  proxy mode serves "whatever allowed upstream the client asked for";
 *       the tier machinery is driven entirely by the backend entry, so a
 *       per-upstream entry is the whole integration.
 * HOW:  per-worker fixed array (upstream_max <= CVMFS_UP_MAX), linear scan —
 *       a site talks to a handful of Stratum-1s. No eviction: exhaustion is
 *       a config error (allowlist bigger than upstream_max) surfaced loudly.
 */
#include "cvmfs.h"

#define CVMFS_UP_MAX 16

typedef struct {
    ngx_str_t                    host;      /* worker-lifetime copy         */
    in_port_t                    port;
    xrootd_vfs_backend_entry_t  *entry;
} cvmfs_upstream_slot;

static cvmfs_upstream_slot  cvmfs_ups[CVMFS_UP_MAX];
static ngx_uint_t           cvmfs_ups_n;

xrootd_vfs_backend_entry_t *
xrootd_cvmfs_upstream_get(ngx_http_request_t *r, const xrootd_cvmfs_conf_t *cc,
    const ngx_str_t *host, in_port_t port, ngx_uint_t *status)
{
    ngx_uint_t                   i, cap;
    cvmfs_upstream_slot         *s;
    char                         hostz[256];
    xrootd_vfs_backend_entry_t  *e;

    for (i = 0; i < cvmfs_ups_n; i++) {
        s = &cvmfs_ups[i];
        if (s->port == port && s->host.len == host->len
            && ngx_strncasecmp(s->host.data, host->data, host->len) == 0)
        {
            return s->entry;
        }
    }

    cap = ngx_min(cc->upstream_max, CVMFS_UP_MAX);
    if (cvmfs_ups_n >= cap || host->len >= sizeof(hostz)) {
        XROOTD_DIAG_ERR(r->connection->log, "cvmfs upstream registry full",
            /* cause */ "more distinct Stratum-1 authorities than "
                        "xrootd_cvmfs_upstream_max",
            /* fix   */ "raise xrootd_cvmfs_upstream_max or trim "
                        "xrootd_cvmfs_upstream_allow");
        *status = NGX_HTTP_SERVICE_UNAVAILABLE;
        return NULL;
    }

    ngx_memcpy(hostz, host->data, host->len);
    hostz[host->len] = '\0';

    /* base "" — the request URI already carries /cvmfs/<repo>/…; cache-key
     * prefix isolates the store subtree per upstream. */
    e = xrootd_vfs_backend_entry_create_http(hostz, (int) port, /* tls */ 0,
            /* base */ "", /* key_prefix */ NULL /* built inside from host_port */);
    if (e == NULL) {
        *status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        return NULL;
    }

    s = &cvmfs_ups[cvmfs_ups_n];
    s->host.data = ngx_alloc(host->len, r->connection->log);
    if (s->host.data == NULL) {
        *status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        return NULL;
    }
    ngx_memcpy(s->host.data, host->data, host->len);
    s->host.len = host->len;
    s->port = port;
    s->entry = e;
    cvmfs_ups_n++;
    return e;
}
```

`xrootd_vfs_backend_entry_create_http()` is the runtime twin of the
config-time `xrootd_vfs_backend_config_http()`: same field population, but
allocating from the cycle pool instead of the conf pool and additionally
setting the entry's cache-key prefix to `"<host>_<port>"`. Add it beside
the config-time builder in `vfs_backend_config.c` so the two can never
drift; it must also run the same sd_http instance-init the config path
runs at postconfig (grep `sd_http` init in `vfs_backend_registry.c` and
call the same function). Worker-lifetime allocations here are deliberate
(`ngx_alloc`, no pool cleanup): the registry lives as long as the worker.

- [ ] **Step 3c: Gate integration** — at the top of `xrootd_cvmfs_gate()`,
before classification:

```c
    if (r->host_start != NULL) {                     /* absolute-form */
        ngx_str_t                    up_host;
        in_port_t                    up_port;
        ngx_uint_t                   status;
        xrootd_vfs_backend_entry_t  *e;
        ngx_http_xrootd_cvmfs_ctx_t *ctx;

        rc = xrootd_cvmfs_proxy_target(r, &lcf->cvmfs, &up_host, &up_port);
        if (rc == NGX_HTTP_FORBIDDEN || rc == NGX_HTTP_BAD_REQUEST) {
            return cvmfs_reject(r, (ngx_uint_t) rc);
        }
        if (rc == NGX_OK) {
            e = xrootd_cvmfs_upstream_get(r, &lcf->cvmfs, &up_host, up_port,
                                          &status);
            if (e == NULL) {
                return (ngx_int_t) status;
            }
            ctx = ngx_http_get_module_ctx(r, ngx_http_xrootd_cvmfs_module);
            ctx->backend_override = e;         /* convention #2 */
        }
        /* rc == NGX_DECLINED: origin-form on this listener — fall through */
    }
```

- [ ] **Step 4: Full rebuild (+2 files in `./config`) + run all cvmfs suites**

Run:
```bash
rm -rf /tmp/nginx-1.28.3/objs && cd /tmp/nginx-1.28.3 && \
./configure --with-stream --with-stream_ssl_module --with-http_ssl_module \
  --with-http_dav_module --with-threads \
  --add-module=/home/rcurrie/HEP-x/nginx-xrootd && make -j$(nproc) && \
cd /home/rcurrie/HEP-x/nginx-xrootd && \
for t in proxy reverse verify failover manifest; do bash tests/run_cvmfs_$t.sh || exit 1; done
```
Expected: all five suites green.

- [ ] **Step 5: Commit**

```bash
git add src/protocols/cvmfs/request.c src/protocols/cvmfs/upstreams.c \
        src/protocols/cvmfs/gate.c src/protocols/cvmfs/cvmfs.h config \
        tests/run_cvmfs_proxy.sh
git commit -m "feat(cvmfs): forward-proxy mode — absolute-URI + allowlist + per-upstream cache"
```

---

# PHASE 3B — Origin selection & never-drop client semantics

The Tier-2's problem is not just corruption — it is that flaky upstream
connectivity makes CVMFS clients *give up on the site cache* (skip to the
next proxy group or DIRECT), after which every WN hammers the WAN
individually. Phase 3B makes the cache (a) pick the best Stratum-1
deliberately (static order, geographic distance, or measured RTT), and
(b) absorb upstream failures *without ever surfacing them as broken client
connections* — conventions #6/#7 are the contract; these three tasks
implement it.

### Task 19: Origin selection engine (static / geo / rtt)

**Files:**
- Create: `src/protocols/cvmfs/origin_geo.c`, `src/protocols/cvmfs/origin_geo.h`, `src/protocols/cvmfs/origin_probe.c`
- Modify: `src/fs/backend/http/sd_http.c`/`sd_http.h` (rank field + rank API), `src/protocols/cvmfs/cvmfs.h` + `src/protocols/cvmfs/module.c` (4 new directives), `./config` (+2 files, full rebuild)
- Test: `tests/run_cvmfs_select.sh`

**Interfaces:**
- Consumes: T11's `sd_http_endpoint` array + EWMA `fail_score`.
- Produces:

```c
/* cvmfs.h conf additions */
typedef enum {
    XROOTD_CVMFS_SELECT_STATIC = 0,   /* configured order (default)        */
    XROOTD_CVMFS_SELECT_GEO,          /* haversine(here, origin coords)    */
    XROOTD_CVMFS_SELECT_RTT           /* measured TCP connect RTT (EWMA)   */
} xrootd_cvmfs_select_e;

    ngx_uint_t   origin_select;   /* xrootd_cvmfs_origin_select            */
    ngx_array_t *origin_coords;   /* xrootd_cvmfs_origin_coords host lat:lon */
    ngx_str_t    here;            /* xrootd_cvmfs_here lat:lon (geo mode)  */
    time_t       rtt_interval;    /* xrootd_cvmfs_rtt_interval (default 60)*/

/* origin_geo.h — pure C, no ngx types (standalone-testable) */
double xrootd_cvmfs_haversine_km(double lat1, double lon1,
                                 double lat2, double lon2);
/* stable argsort: ranks[i] = position of endpoint i in ascending metric
 * order (rank 0 = best); equal metrics keep configured order. */
void   xrootd_cvmfs_rank_by_metric(const double *metric, int n, int *ranks);

/* sd_http.h additions */
#define SD_HTTP_RANK_WEIGHT 4096
/* endpoint gains:  _Atomic int rank;  — written by the event loop (probe
 * done-handler / postconfig), read by fill threads; relaxed ordering is
 * sufficient (a momentarily stale rank costs one suboptimal fill, never
 * correctness). Effective pick score = rank*SD_HTTP_RANK_WEIGHT+fail_score,
 * so health (T11) breaks ties and can override a preferred-but-sick origin
 * only after ~16 consecutive failures — deliberate: preference is policy,
 * health is protection. */
void sd_http_set_ranks(xrootd_sd_instance_t *inst, const int *ranks, int n);
/* endpoint inventory for the prober (copies, no ngx types) */
int  sd_http_endpoint_list(xrootd_sd_instance_t *inst,
        char hosts[][256], int *ports, int max);
```

Directive semantics:

| Directive | Meaning |
|---|---|
| `xrootd_cvmfs_origin_select static\|geo\|rtt;` | selection policy (default `static`) |
| `xrootd_cvmfs_origin_coords <host[:port]> <lat>:<lon>;` | geographic position of one origin (multi; `geo` mode requires one per configured origin — `nginx -t` error otherwise). Matching: an entry with a port matches only that endpoint; without a port it matches every endpoint on that host (test rigs run several origins on 127.0.0.1; production Stratum-1s are one-per-host) |
| `xrootd_cvmfs_here <lat>:<lon>;` | this cache's own coordinates (`geo` mode requires it; e.g. Edinburgh `55.95:-3.19`) |
| `xrootd_cvmfs_rtt_interval <sec>;` | probe period, default 60; first probe fires within 500 ms of worker start so ranks exist before the first fill |

Coords-from-directive is the core mechanism because it is dependency-free
and deterministic to test. **Optional sub-step (only if the site wants
zero-config geo):** an mmdb lookup (`xrootd_cvmfs_geoip_db <path.mmdb>`,
build-gated on `--with-ld-opt=-lmaxminddb` + a `NGX_HAVE_MAXMINDDB` feature
test in `./config`) resolving each origin host at worker init (in the same
thread task as the first RTT probe — `getaddrinfo` blocks) and reading
`location.latitude/longitude` via `MMDB_lookup_sockaddr()`; explicit
`origin_coords` entries always override the database. Ship the core first;
the mmdb step is severable.

- [ ] **Step 1: Write the failing test**

```bash
#!/usr/bin/env bash
# tests/run_cvmfs_select.sh — origin selection policies:
#   0 standalone unit: haversine + stable argsort
#   1 static: first-listed origin serves the fill (failover untouched)
#   2 geo: nearer origin wins although listed second
#   3 rtt: refused first-listed endpoint is pre-ranked out by the probe
#   4 security/error-neg: geo without coords/here → nginx -t rejects
set -u
NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
HERE="$(cd "$(dirname "$0")" && pwd)"; REPO="$(cd "$HERE/.." && pwd)"
MA=12891; MB=12892; CPORT=12893
PFX="$(mktemp -d /tmp/cvmfs_sel.XXXXXX)"; fail=0
ok(){ printf '  ok   %s\n' "$1"; }; bad(){ printf '  FAIL %s\n' "$1"; fail=1; }
cleanup(){ [ -f "$PFX/nginx.pid" ] && kill "$(cat "$PFX/nginx.pid")" 2>/dev/null
           kill "$MOCKA" "$MOCKB" 2>/dev/null; rm -rf "$PFX"; }
trap cleanup EXIT
mkdir -p "$PFX/cache" "$PFX/logs"

# --- 0: pure-C unit (no nginx) ---------------------------------------------
cat > "$PFX/u.c" <<'EOF'
#include "protocols/cvmfs/origin_geo.h"
#include <assert.h>
#include <stdio.h>
int main(void) {
    /* Edinburgh <-> CERN is ~1180 km great-circle */
    double d = xrootd_cvmfs_haversine_km(55.95, -3.19, 46.23, 6.05);
    assert(d > 1000.0 && d < 1300.0);
    /* argsort with a tie: ties keep input order (stability) */
    double m[4] = { 9.0, 1.0, 9.0, 4.0 };
    int r[4];
    xrootd_cvmfs_rank_by_metric(m, 4, r);
    assert(r[1] == 0 && r[3] == 1 && r[0] == 2 && r[2] == 3);
    printf("origin_geo unit OK\n");
    return 0;
}
EOF
gcc -Wall -Werror -I"$REPO/src" -o "$PFX/u" "$PFX/u.c" \
    "$REPO/src/protocols/cvmfs/origin_geo.c" -lm && "$PFX/u" \
    && ok "unit: haversine+argsort" || bad "unit test"

python3 "$HERE/cvmfs/mock_stratum1.py" --port $MA --objects 4 --seed 31 & MOCKA=$!
python3 "$HERE/cvmfs/mock_stratum1.py" --port $MB --objects 4 --seed 31 & MOCKB=$!
sleep 0.5
OBJ="$(curl -s "http://127.0.0.1:$MA/ctl/objects" | python3 -c \
      'import json,sys; print(json.load(sys.stdin)[0])')"

mkconf() {  # $1 = select-specific directive lines, $2 = backend URL list
cat > "$PFX/nginx.conf" <<EOF
daemon on; error_log $PFX/logs/e.log info; pid $PFX/nginx.pid;
thread_pool default threads=2;
events { worker_connections 128; }
http { access_log off; server {
    listen 127.0.0.1:$CPORT;
    location /cvmfs/ {
        xrootd_cvmfs_storage_backend "$2";
        xrootd_cvmfs_cache_store $PFX/cache;
        xrootd_cache_include_regex "/data/";
        xrootd_cvmfs on;
$1
    }
} }
EOF
}
restart() { [ -f "$PFX/nginx.pid" ] && kill "$(cat "$PFX/nginx.pid")" && sleep 0.2
            rm -rf "$PFX/cache"; mkdir -p "$PFX/cache"
            "$NGINX" -c "$PFX/nginx.conf" -p "$PFX"; sleep 0.7; }

# --- 1: static — first-listed (A) serves ------------------------------------
mkconf "        xrootd_cvmfs_origin_select static;" \
       "http://127.0.0.1:$MA/cvmfs|http://127.0.0.1:$MB/cvmfs"
restart
curl -s "http://127.0.0.1:$CPORT$OBJ" -o /dev/null
NA="$(curl -s "http://127.0.0.1:$MA/ctl/log" | grep -c "$OBJ")"
NB="$(curl -s "http://127.0.0.1:$MB/ctl/log" | grep -c "$OBJ")"
[ "$NA" = 1 ] && [ "$NB" = 0 ] && ok "static: first-listed served" \
    || bad "static: A=$NA B=$NB"

# --- 2: geo — nearer origin (B=Edinburgh) wins although listed second -------
mkconf "        xrootd_cvmfs_origin_select geo;
        xrootd_cvmfs_here 55.95:-3.19;
        xrootd_cvmfs_origin_coords 127.0.0.1:$MA 46.23:6.05;
        xrootd_cvmfs_origin_coords 127.0.0.1:$MB 55.95:-3.19;" \
       "http://127.0.0.1:$MA/cvmfs|http://127.0.0.1:$MB/cvmfs"
restart
curl -s "http://127.0.0.1:$CPORT$OBJ" -o /dev/null
NB="$(curl -s "http://127.0.0.1:$MB/ctl/log" | grep -c "$OBJ")"
[ "$NB" = 1 ] && ok "geo: nearer origin served" || bad "geo: B=$NB"

# --- 3: rtt — refused endpoint pre-ranked out (not failed-over-from) --------
mkconf "        xrootd_cvmfs_origin_select rtt;
        xrootd_cvmfs_rtt_interval 1;" \
       "http://127.0.0.1:1/cvmfs|http://127.0.0.1:$MB/cvmfs"
restart
sleep 1.5                       # let the first probe run and rank
NB0="$(curl -s "http://127.0.0.1:$MB/ctl/log" | grep -c "$OBJ")"
curl -s "http://127.0.0.1:$CPORT$OBJ" -o /dev/null
NB1="$(curl -s "http://127.0.0.1:$MB/ctl/log" | grep -c "$OBJ")"
grep -q 'cvmfs rtt ranks:' "$PFX/logs/e.log" \
    && [ "$((NB1 - NB0))" = 1 ] && ok "rtt: probe pre-ranked live origin first" \
    || bad "rtt selection"

# --- 4: config-error negatives ----------------------------------------------
mkconf "        xrootd_cvmfs_origin_select geo;" \
       "http://127.0.0.1:$MA/cvmfs|http://127.0.0.1:$MB/cvmfs"
"$NGINX" -t -c "$PFX/nginx.conf" -p "$PFX" 2>/dev/null \
    && bad "geo without here/coords accepted" || ok "geo misconfig rejected"
exit $fail
```

- [ ] **Step 2: Run to verify it fails**

Run: `bash tests/run_cvmfs_select.sh`
Expected: unit-test gcc FAIL (`origin_geo.h` missing).

- [ ] **Step 3: Implement `origin_geo.c`**

```c
/* origin_geo.c — geographic distance + rank helpers (pure C).
 *
 * WHAT: haversine great-circle distance and a stable argsort used to turn
 *       any per-endpoint metric (km, RTT µs) into sd_http ranks.
 * WHY:  one rank producer shared by the geo and rtt policies keeps the
 *       driver's consumption contract (sd_http_set_ranks) single-shaped.
 * HOW:  no allocation, no ngx types; O(n²) insertion-style argsort is fine
 *       for n <= SD_HTTP_EP_MAX (8).
 */
#include "origin_geo.h"

#include <math.h>

#define CVMFS_EARTH_RADIUS_KM 6371.0

double
xrootd_cvmfs_haversine_km(double lat1, double lon1, double lat2, double lon2)
{
    double rl1 = lat1 * M_PI / 180.0, rl2 = lat2 * M_PI / 180.0;
    double dla = (lat2 - lat1) * M_PI / 180.0;
    double dlo = (lon2 - lon1) * M_PI / 180.0;
    double a = sin(dla / 2) * sin(dla / 2)
             + cos(rl1) * cos(rl2) * sin(dlo / 2) * sin(dlo / 2);

    return 2.0 * CVMFS_EARTH_RADIUS_KM * atan2(sqrt(a), sqrt(1.0 - a));
}

void
xrootd_cvmfs_rank_by_metric(const double *metric, int n, int *ranks)
{
    int i, j, better;

    for (i = 0; i < n; i++) {
        better = 0;
        for (j = 0; j < n; j++) {
            if (metric[j] < metric[i]
                || (metric[j] == metric[i] && j < i))
            {
                better++;
            }
        }
        ranks[i] = better;
    }
}
```

- [ ] **Step 4: Implement the sd_http rank API** — add `_Atomic int rank;`
to `sd_http_endpoint` (include `<stdatomic.h>`; the driver is pure C11),
change `sd_http_pick()`'s comparison to
`atomic_load_explicit(&ep->rank, memory_order_relaxed) * SD_HTTP_RANK_WEIGHT + ep->fail_score`,
and add:

```c
void
sd_http_set_ranks(xrootd_sd_instance_t *inst, const int *ranks, int n)
{
    sd_http_inst_state *is = inst->state;
    int                 i;

    for (i = 0; i < is->n_eps && i < n; i++) {
        atomic_store_explicit(&is->eps[i].rank, ranks[i],
                              memory_order_relaxed);
    }
}

int
sd_http_endpoint_list(xrootd_sd_instance_t *inst, char hosts[][256],
    int *ports, int max)
{
    sd_http_inst_state *is = inst->state;
    int                 i, n = (is->n_eps < max) ? is->n_eps : max;

    for (i = 0; i < n; i++) {
        memcpy(hosts[i], is->eps[i].host, sizeof(is->eps[i].host));
        ports[i] = is->eps[i].port;
    }
    return n;
}
```

- [ ] **Step 5: Implement `origin_probe.c`** (rtt mode) + the geo-mode
postconfig ranking:

```c
/* origin_probe.c — per-worker RTT probe for xrootd_cvmfs_origin_select rtt.
 *
 * WHAT: a repeating per-worker timer posts a thread-pool task that measures
 *       TCP connect RTT to every configured origin endpoint; the event-loop
 *       completion folds samples into an EWMA, ranks endpoints, and pushes
 *       ranks into the sd_http driver.
 * WHY:  on a Tier-2 with erratic routing, configured order and geography
 *       both lie; measured connect RTT is what the fills will actually feel.
 * HOW:  measurement is blocking (getaddrinfo + nonblocking connect + poll)
 *       and therefore lives on a thread-pool worker, mirroring the cache
 *       fill I/O pattern; the event loop only re-arms the timer and writes
 *       ranks (relaxed atomics — see sd_http.h).
 */
#include "cvmfs.h"
#include "origin_geo.h"
#include "fs/backend/http/sd_http.h"

#include <netdb.h>
#include <poll.h>
#include <time.h>

#define CVMFS_PROBE_TIMEOUT_MS 2000
#define CVMFS_PROBE_FAIL_US    (CVMFS_PROBE_TIMEOUT_MS * 1000L * 4)

typedef struct {
    ngx_event_t            timer;
    xrootd_sd_instance_t  *inst;
    ngx_log_t             *log;
    time_t                 interval;
    int                    n;
    char                   hosts[SD_HTTP_EP_MAX][256];
    int                    ports[SD_HTTP_EP_MAX];
    double                 ewma_us[SD_HTTP_EP_MAX];   /* 0 = no sample yet */
    long                   sample_us[SD_HTTP_EP_MAX]; /* thread → done     */
} cvmfs_probe_ctx_t;

/* One nonblocking connect, timed. Returns RTT µs, or -1 on any failure
 * (refused, unreachable, timeout, resolution failure). */
static long
cvmfs_connect_rtt_us(const char *host, int port, int timeout_ms)
{
    struct addrinfo  hints, *ai = NULL;
    struct pollfd    pfd;
    struct timespec  t0, t1;
    char             svc[8];
    int              fd, soerr = 0;
    socklen_t        slen = sizeof(soerr);
    long             us = -1;

    ngx_memzero(&hints, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_NUMERICSERV | AI_ADDRCONFIG;
    snprintf(svc, sizeof(svc), "%d", port);
    if (getaddrinfo(host, svc, &hints, &ai) != 0 || ai == NULL) {
        return -1;
    }
    fd = socket(ai->ai_family, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (fd < 0) {
        freeaddrinfo(ai);
        return -1;
    }
    clock_gettime(CLOCK_MONOTONIC, &t0);
    if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) {
        clock_gettime(CLOCK_MONOTONIC, &t1);
        us = (t1.tv_sec - t0.tv_sec) * 1000000L
           + (t1.tv_nsec - t0.tv_nsec) / 1000L;
    } else if (errno == EINPROGRESS) {
        pfd.fd = fd; pfd.events = POLLOUT;
        if (poll(&pfd, 1, timeout_ms) == 1
            && getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &slen) == 0
            && soerr == 0)
        {
            clock_gettime(CLOCK_MONOTONIC, &t1);
            us = (t1.tv_sec - t0.tv_sec) * 1000000L
               + (t1.tv_nsec - t0.tv_nsec) / 1000L;
        }
    }
    close(fd);
    freeaddrinfo(ai);
    return us;
}

/* thread-pool side: probe every endpoint sequentially */
static void
cvmfs_probe_thread(void *data, ngx_log_t *log)
{
    cvmfs_probe_ctx_t *pc = data;
    int                i;

    for (i = 0; i < pc->n; i++) {
        pc->sample_us[i] = cvmfs_connect_rtt_us(pc->hosts[i], pc->ports[i],
                                                CVMFS_PROBE_TIMEOUT_MS);
    }
}

/* event-loop side: fold EWMA, rank, push, re-arm */
static void
cvmfs_probe_done(ngx_event_t *ev)
{
    cvmfs_probe_ctx_t *pc = ev->data;
    double             metric[SD_HTTP_EP_MAX];
    int                ranks[SD_HTTP_EP_MAX], i;

    for (i = 0; i < pc->n; i++) {
        double s = (pc->sample_us[i] < 0) ? (double) CVMFS_PROBE_FAIL_US
                                          : (double) pc->sample_us[i];
        pc->ewma_us[i] = (pc->ewma_us[i] == 0.0)
                       ? s : pc->ewma_us[i] * 0.75 + s * 0.25;
        metric[i] = pc->ewma_us[i];
    }
    xrootd_cvmfs_rank_by_metric(metric, pc->n, ranks);
    sd_http_set_ranks(pc->inst, ranks, pc->n);

    ngx_log_error(NGX_LOG_INFO, pc->log, 0,
        "cvmfs rtt ranks: n=%d best=%s ewma0=%.0fus",
        pc->n, pc->hosts[/* index with rank 0 */
                cvmfs_rank_zero_index(ranks, pc->n)],
        metric[cvmfs_rank_zero_index(ranks, pc->n)]);

    ngx_add_timer(&pc->timer, (ngx_msec_t) pc->interval * 1000
                              + (ngx_msec_t) (ngx_random() % 1000));
}
```

Timer handler posts the thread task (same posting helper as T9's geo
passthrough); worker-init creates one `cvmfs_probe_ctx_t` per cvmfs
location whose `origin_select == RTT`, seeds host/port via
`sd_http_endpoint_list()`, and arms the first fire at `ngx_random() % 500`
ms. `cvmfs_rank_zero_index()` is a 4-line static helper returning `i` where
`ranks[i]==0`. **Geo mode needs no timer at all:** at postconfig, look up
each endpoint host in `origin_coords` (config error listing the missing
host if absent, and error if `here` unset), compute
`xrootd_cvmfs_haversine_km(here, coords[i])` into `metric[]`, rank once,
`sd_http_set_ranks()` once. Static mode: ranks = configured indices (also
set once, so the pick math is uniform across all three modes).

Directive registration (4 entries in `cvmfs/module.c`, same idiom as
Task 8; the enum directive):

```c
static ngx_conf_enum_t  xrootd_cvmfs_select_enum[] = {
    { ngx_string("static"), XROOTD_CVMFS_SELECT_STATIC },
    { ngx_string("geo"),    XROOTD_CVMFS_SELECT_GEO },
    { ngx_string("rtt"),    XROOTD_CVMFS_SELECT_RTT },
    { ngx_null_string, 0 }
};

    { ngx_string("xrootd_cvmfs_origin_select"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_cvmfs_loc_conf_t, cvmfs.origin_select),
      &xrootd_cvmfs_select_enum },
```

(`xrootd_cvmfs_origin_coords` takes 2 args → custom setter parsing
`host` + `lat:lon` into an array of `{ ngx_str_t host; double lat, lon; }`;
`xrootd_cvmfs_here` → `ngx_conf_set_str_slot` + postconfig parse;
`xrootd_cvmfs_rtt_interval` → `ngx_conf_set_sec_slot`, default 60.)

- [ ] **Step 6: Register `origin_geo.c` + `origin_probe.c` in `./config`, full
rebuild, run**

Run:
```bash
rm -rf /tmp/nginx-1.28.3/objs && cd /tmp/nginx-1.28.3 && \
./configure --with-stream --with-stream_ssl_module --with-http_ssl_module \
  --with-http_dav_module --with-threads \
  --add-module=/home/rcurrie/HEP-x/nginx-xrootd && make -j$(nproc) && \
bash /home/rcurrie/HEP-x/nginx-xrootd/tests/run_cvmfs_select.sh
```
Expected: 5 × `ok` (unit, static, geo, rtt, misconfig-rejected), exit 0.
Also rerun `tests/run_cvmfs_failover.sh` — T11 behavior must be unchanged
under default `static` selection.

- [ ] **Step 7: Commit**

```bash
git add src/protocols/cvmfs/origin_geo.c src/protocols/cvmfs/origin_geo.h \
        src/protocols/cvmfs/origin_probe.c src/protocols/cvmfs/cvmfs.h \
        src/fs/backend/http/sd_http.c src/fs/backend/http/sd_http.h \
        src/protocols/cvmfs/module.c config tests/run_cvmfs_select.sh
git commit -m "feat(cvmfs): origin selection engine — static order, geo distance, measured RTT"
```

---

### Task 20: Never-drop fill semantics (hold + retry-to-deadline + detached fills)

**Files:**
- Create: `src/fs/cache/fill_retry.c`, `src/fs/cache/fill_retry.h`
- Modify: `src/fs/cache/fetch.c` (retry loop around origin attempts), `src/fs/cache/open_or_fill.c` + `thread.c` (waiter hold-timer, detach, 504 sender, detached completion), `src/fs/cache/cache_internal.h` (fill struct: `_Atomic int waiters`, retry state), `src/protocols/cvmfs/cvmfs.h` + `cvmfs/module.c` (2 directives), `./config` (+1 file, full rebuild)
- Test: `tests/run_cvmfs_holdopen.sh`

**Interfaces:**
- Consumes: T11/T19 ranked endpoints; T13 negative cache (404s feed it); conventions #6/#7.
- Produces:

```c
/* fill_retry.h — upstream-outcome classification + deadline'd backoff.
 * Pure C except ngx_msec_t; runs on fill worker threads (sleeping there is
 * correct — blocking I/O already lives on these threads). */
typedef enum {
    XROOTD_FILL_OK = 0,
    XROOTD_FILL_RETRY,        /* transient: backoff, next endpoint          */
    XROOTD_FILL_DEFINITIVE    /* 404/403/other: propagate now, never retry  */
} xrootd_fill_class_e;

typedef struct {
    ngx_msec_t    backoff_ms;     /* next delay, starts 250, caps 8000      */
    time_t        start;          /* first-attempt wall clock               */
    time_t        client_hold;    /* conf: xrootd_cvmfs_client_hold         */
    time_t        max_life;       /* conf: xrootd_cvmfs_fill_max_life       */
    _Atomic int  *waiters;        /* the owning fill's waiter count         */
    unsigned      verify_budget;  /* MISMATCH retries left (= n_endpoints)  */
} xrootd_fill_retry_t;

void xrootd_fill_retry_init(xrootd_fill_retry_t *rs, time_t client_hold,
    time_t max_life, _Atomic int *waiters, unsigned n_endpoints);
xrootd_fill_class_e xrootd_fill_classify(int transport_err, int http_status,
    int verify_mismatch, xrootd_fill_retry_t *rs);
/* 1 = slept the backoff, try again; 0 = deadline passed, give up */
int  xrootd_fill_retry_wait(xrootd_fill_retry_t *rs);
```

New directives: `xrootd_cvmfs_client_hold <sec>` (default **25** — must be
below the WN's `CVMFS_TIMEOUT`, see runbook) and
`xrootd_cvmfs_fill_max_life <sec>` (default **300** — how long a *detached*
fill keeps retrying after every client has gone; bounds the resource leak
of retrying forever for an object nobody wants anymore).

**Semantics being implemented (restating convention #6 as behavior):**

1. While a client waits on a fill, upstream connect errors/stalls/5xx do
   NOT produce a client error — the fill worker walks the ranked endpoint
   list with jittered exponential backoff, over and over, until
   `client_hold` expires.
2. If `client_hold` expires: the waiter detaches and receives
   **504 + `Retry-After: 2` on a kept-alive connection**. The fill keeps
   running (now on the `max_life` deadline). The CVMFS client's automatic
   retry arrives on the same warm TCP connection, coalesces onto the
   still-running fill via the existing fill-lock, and gets the object the
   moment it lands.
3. A client that disconnects mid-wait detaches its waiter; the fill is
   never cancelled. Completion with zero waiters publishes to the cache
   silently.
4. 404/403 are definitive: answered immediately (no hold), 404 recorded in
   the T13 negative memo.

- [ ] **Step 1: Write the failing test**

```bash
#!/usr/bin/env bash
# tests/run_cvmfs_holdopen.sh — never-drop client semantics:
#   1 origin DOWN at request time, up 3s later → client (30s budget) gets 200
#   2 hold expiry → 504 + Retry-After on a KEPT-ALIVE conn; retry on the
#     SAME socket succeeds once the origin is back
#   3 client aborts mid-outage → detached fill still populates the cache
#   4 neg: 404 is definitive — immediate, exactly 1 origin hit, no hold
set -u
NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
HERE="$(cd "$(dirname "$0")" && pwd)"
MPORT=12894; CPORT=12895
PFX="$(mktemp -d /tmp/cvmfs_hold.XXXXXX)"; fail=0
ok(){ printf '  ok   %s\n' "$1"; }; bad(){ printf '  FAIL %s\n' "$1"; fail=1; }
cleanup(){ [ -f "$PFX/nginx.pid" ] && kill "$(cat "$PFX/nginx.pid")" 2>/dev/null
           [ -n "${MOCK:-}" ] && kill "$MOCK" 2>/dev/null; rm -rf "$PFX"; }
trap cleanup EXIT
mkdir -p "$PFX/cache" "$PFX/logs"

mkconf() {  # $1 = client_hold seconds
cat > "$PFX/nginx.conf" <<EOF
daemon on; error_log $PFX/logs/e.log info; pid $PFX/nginx.pid;
thread_pool default threads=4;
events { worker_connections 128; }
http { access_log off; server {
    listen 127.0.0.1:$CPORT;
    location /cvmfs/ {
        xrootd_cvmfs_storage_backend http://127.0.0.1:$MPORT/cvmfs;
        xrootd_cvmfs_cache_store $PFX/cache;
        xrootd_cache_include_regex "/data/";
        xrootd_cvmfs on;
        xrootd_cvmfs_client_hold $1;
        xrootd_cvmfs_fill_max_life 60;
        xrootd_cvmfs_negative_ttl 10;
    }
} }
EOF
}

# discover object names with a throwaway mock instance (same seed each start)
python3 "$HERE/cvmfs/mock_stratum1.py" --port $MPORT --objects 6 --seed 20 &
MOCK=$!; sleep 0.5
OBJS=($(curl -s "http://127.0.0.1:$MPORT/ctl/objects" | python3 -c \
       'import json,sys; print(" ".join(json.load(sys.stdin)))'))
kill "$MOCK"; MOCK=""; sleep 0.2

# --- 1: retry-until-origin-returns ------------------------------------------
mkconf 20; "$NGINX" -c "$PFX/nginx.conf" -p "$PFX"; sleep 0.3
( sleep 3; python3 "$HERE/cvmfs/mock_stratum1.py" --port $MPORT \
      --objects 6 --seed 20 & echo $! > "$PFX/mock.pid" ) &
C="$(curl -s --max-time 30 -o "$PFX/a.bin" -w '%{http_code}' \
     "http://127.0.0.1:$CPORT${OBJS[0]}")"
MOCK="$(cat "$PFX/mock.pid")"
curl -s "http://127.0.0.1:$MPORT${OBJS[0]}" -o "$PFX/ref.bin"
[ "$C" = 200 ] && cmp -s "$PFX/a.bin" "$PFX/ref.bin" \
    && ok "held through outage, served on recovery" || bad "outage hold: $C"

# --- 2: hold expiry → 504 keep-alive, retry on SAME socket -------------------
kill "$MOCK"; MOCK=""; sleep 0.2
kill "$(cat "$PFX/nginx.pid")"; sleep 0.2
mkconf 2; rm -rf "$PFX/cache"; mkdir -p "$PFX/cache"
"$NGINX" -c "$PFX/nginx.conf" -p "$PFX"; sleep 0.3
python3 - "$CPORT" "$MPORT" "${OBJS[1]}" "$HERE" <<'EOF' && ok "504-keepalive + same-socket retry" || fail=1
import http.client, subprocess, sys, time
cport, mport, obj, here = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3], sys.argv[4]
c = http.client.HTTPConnection("127.0.0.1", cport, timeout=30)
c.request("GET", obj)
r1 = c.getresponse()
body1 = r1.read()
assert r1.status == 504, f"want 504 got {r1.status}"
assert r1.getheader("Retry-After") is not None, "no Retry-After"
assert r1.getheader("Connection", "keep-alive").lower() != "close", "conn closed"
# origin comes back; retry over the SAME socket (raises if server closed it)
p = subprocess.Popen(["python3", f"{here}/cvmfs/mock_stratum1.py",
                      "--port", str(mport), "--objects", "6", "--seed", "20"])
time.sleep(1.0)
c.request("GET", obj)
r2 = c.getresponse()
b2 = r2.read()
p.terminate()
assert r2.status == 200 and len(b2) > 0, f"retry got {r2.status}"
print("holdopen python OK")
EOF
[ "$fail" = 1 ] && bad "504-keepalive scenario"

# --- 3: detached fill completes after client abort ---------------------------
kill "$(cat "$PFX/nginx.pid")"; sleep 0.2
mkconf 20; rm -rf "$PFX/cache"; mkdir -p "$PFX/cache"
"$NGINX" -c "$PFX/nginx.conf" -p "$PFX"; sleep 0.3
curl -s --max-time 1 "http://127.0.0.1:$CPORT${OBJS[2]}" -o /dev/null  # aborts
python3 "$HERE/cvmfs/mock_stratum1.py" --port $MPORT --objects 6 --seed 20 &
MOCK=$!; sleep 6            # detached fill (max_life 60) retries and lands
N1="$(curl -s "http://127.0.0.1:$MPORT/ctl/log" | grep -c "${OBJS[2]}")"
C="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$CPORT${OBJS[2]}")"
N2="$(curl -s "http://127.0.0.1:$MPORT/ctl/log" | grep -c "${OBJS[2]}")"
[ "$C" = 200 ] && [ "$N1" -ge 1 ] && [ "$N1" = "$N2" ] \
    && ok "detached fill populated cache (abort didn't cancel)" \
    || bad "detached fill: code=$C origin=$N1→$N2"

# --- 4: 404 definitive, immediate ---------------------------------------------
BOGUS="/cvmfs/test.cern.ch/data/aa/$(python3 -c 'print("ef"*19)')"
T0=$(date +%s)
C="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$CPORT$BOGUS")"
T1=$(date +%s)
[ "$C" = 404 ] && [ $((T1 - T0)) -le 2 ] && ok "404 immediate (no hold)" \
    || bad "404 path: code=$C took $((T1-T0))s"
exit $fail
```

- [ ] **Step 2: Run to verify it fails**

Run: `bash tests/run_cvmfs_holdopen.sh`
Expected: check 1 FAILs — today the very first connect error surfaces as a
fast 502 to the client.

- [ ] **Step 3: Implement `fill_retry.c`**

```c
/* fill_retry.c — see header. The classification table is convention #7 of
 * the phase-68 plan; keep the two in sync. */
#include "fill_retry.h"

#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#define FILL_BACKOFF_START_MS 250
#define FILL_BACKOFF_CAP_MS   8000

void
xrootd_fill_retry_init(xrootd_fill_retry_t *rs, time_t client_hold,
    time_t max_life, _Atomic int *waiters, unsigned n_endpoints)
{
    rs->backoff_ms = FILL_BACKOFF_START_MS;
    rs->start = time(NULL);
    rs->client_hold = client_hold;
    rs->max_life = max_life;
    rs->waiters = waiters;
    rs->verify_budget = n_endpoints;
}

xrootd_fill_class_e
xrootd_fill_classify(int transport_err, int http_status, int verify_mismatch,
    xrootd_fill_retry_t *rs)
{
    if (verify_mismatch) {
        /* corruption is often path-local: try each remaining endpoint once,
         * then give up definitively (502 — proven-bad data, not "later"). */
        if (rs->verify_budget > 0) {
            rs->verify_budget--;
            return XROOTD_FILL_RETRY;
        }
        return XROOTD_FILL_DEFINITIVE;
    }
    if (transport_err) {
        return XROOTD_FILL_RETRY;          /* refused/unreach/timeout/stall */
    }
    if (http_status >= 200 && http_status < 300) {
        return XROOTD_FILL_OK;
    }
    if (http_status >= 500) {
        return XROOTD_FILL_RETRY;
    }
    return XROOTD_FILL_DEFINITIVE;         /* 404, 403, 4xx: origin's answer */
}

int
xrootd_fill_retry_wait(xrootd_fill_retry_t *rs)
{
    time_t      now = time(NULL);
    time_t      window;
    ngx_msec_t  d;

    window = (atomic_load_explicit(rs->waiters, memory_order_relaxed) > 0)
           ? rs->client_hold : rs->max_life;
    if (now >= rs->start + window) {
        return 0;
    }
    /* half-jitter: [backoff/2, backoff) — decorrelates a farm of fills */
    d = rs->backoff_ms / 2
      + (ngx_msec_t) (random() % (rs->backoff_ms / 2 + 1));
    if (rs->backoff_ms < FILL_BACKOFF_CAP_MS) {
        rs->backoff_ms *= 2;
    }
    usleep((useconds_t) d * 1000);         /* fill worker thread: sleeping OK */
    return 1;
}
```

- [ ] **Step 4: Wire the loop into `fetch.c`.** Around the existing
per-attempt origin transfer (the code T11 already routes through the ranked
endpoint walk), the whole-file fetch becomes:

```c
    xrootd_fill_retry_t  rs;

    xrootd_fill_retry_init(&rs, t->cvmfs_client_hold, t->cvmfs_fill_max_life,
                           &t->waiters, (unsigned) sd_http_n_endpoints(inst));
    for ( ;; ) {
        rc = cvmfs_fetch_attempt(t, &transport_err, &http_status,
                                 &verify_mismatch);   /* one ranked-walk pass:
                                    existing download + T10 verify, per
                                    endpoint order from T19 */
        switch (xrootd_fill_classify(transport_err, http_status,
                                     verify_mismatch, &rs)) {
        case XROOTD_FILL_OK:
            return NGX_OK;
        case XROOTD_FILL_DEFINITIVE:
            return cvmfs_fill_fail(t, http_status);   /* existing error path */
        case XROOTD_FILL_RETRY:
            break;
        }
        if (!xrootd_fill_retry_wait(&rs)) {
            return cvmfs_fill_fail(t, 504);            /* deadline exhausted */
        }
    }
```

Non-CVMFS locations keep today's behavior: when `lcf->cvmfs.enable` is
off, `client_hold`/`max_life` are 0 and `xrootd_fill_retry_wait()` returns
0 on the first call — single-pass, exactly the pre-phase-68 semantics (add
that as an explicit early-return so the diff to existing callers is zero).

- [ ] **Step 5: Waiter hold-timer + detach + 504 sender** in
`open_or_fill.c` (all on the event loop — no locking against completion,
which also runs there):

```c
/* armed when a waiter attaches to a fill on a cvmfs location */
static void
cvmfs_hold_expire(ngx_event_t *ev)
{
    xrootd_cache_waiter_t *w = ev->data;

    cvmfs_waiter_detach(w);                 /* unlink from fill's list +
                                               atomic_fetch_sub(&waiters,1) */
    (void) cvmfs_send_retry_later(w->r);
}

static ngx_int_t
cvmfs_send_retry_later(ngx_http_request_t *r)
{
    static u_char     body[] = "origin temporarily unreachable; retrying — "
                               "please retry\n";
    ngx_table_elt_t  *h;
    ngx_buf_t        *b;
    ngx_chain_t       out;

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    h->hash = 1;
    ngx_str_set(&h->key, "Retry-After");
    ngx_str_set(&h->value, "2");

    r->headers_out.status = NGX_HTTP_GATEWAY_TIME_OUT;
    r->headers_out.content_length_n = sizeof(body) - 1;
    r->keepalive = 1;                       /* convention #6: NEVER close */
    if (ngx_http_send_header(r) != NGX_OK) {
        return NGX_ERROR;
    }
    b = ngx_pcalloc(r->pool, sizeof(*b));
    if (b == NULL) {
        return NGX_ERROR;
    }
    b->pos = b->start = body;
    b->last = b->end = body + sizeof(body) - 1;
    b->memory = 1;
    b->last_buf = 1;
    out.buf = b;
    out.next = NULL;
    ngx_http_finalize_request(r, ngx_http_output_filter(r, &out));
    return NGX_DONE;
}
```

Client-abort path: register the existing request-cleanup hook
(`ngx_http_cleanup_add`) on waiter attach to call `cvmfs_waiter_detach()`
— covers curl `--max-time`, TCP reset, worker-side timeout alike. The fill
struct's completion (`thread.c` fill-done) iterates whatever waiters remain
and must handle the zero-waiter case by publishing + releasing the fill
lock with no client interaction (verify against the current code — if a
request pointer is dereferenced unconditionally in fill-done today, THIS is
the bug this task fixes; the detached e2e check 3 will catch it).

- [ ] **Step 6: Directives** — `xrootd_cvmfs_client_hold`,
`xrootd_cvmfs_fill_max_life` (both `ngx_conf_set_sec_slot`, defaults 25 /
300, registration identical to Task 8's TTL entries), copied into the fill
ctx per cross-cutting convention #1.

- [ ] **Step 7: Register `fill_retry.c` in `./config`, full rebuild, run**

Run:
```bash
rm -rf /tmp/nginx-1.28.3/objs && cd /tmp/nginx-1.28.3 && \
./configure --with-stream --with-stream_ssl_module --with-http_ssl_module \
  --with-http_dav_module --with-threads \
  --add-module=/home/rcurrie/HEP-x/nginx-xrootd && make -j$(nproc) && \
cd /home/rcurrie/HEP-x/nginx-xrootd && bash tests/run_cvmfs_holdopen.sh && \
for t in reverse verify failover manifest proxy select; do
    bash tests/run_cvmfs_$t.sh || exit 1
done && tests/run_suite.sh --pr
```
Expected: holdopen 5 × `ok`; all prior suites unchanged; `--pr` green
(non-CVMFS fills take the zero-hold early-return).

- [ ] **Step 8: Commit**

```bash
git add src/fs/cache/fill_retry.c src/fs/cache/fill_retry.h \
        src/fs/cache/fetch.c src/fs/cache/open_or_fill.c src/fs/cache/thread.c \
        src/fs/cache/cache_internal.h src/protocols/cvmfs/cvmfs.h \
        src/protocols/cvmfs/module.c config tests/run_cvmfs_holdopen.sh
git commit -m "feat(cvmfs): never-drop semantics — hold+retry to deadline, 504-keepalive, detached fills"
```

---

### Task 21: TCP keepalive + client-connection durability (config + proof)

**Files:**
- Create: `tests/run_cvmfs_keepalive.sh`
- Modify: the reference configs inside `tests/run_cvmfs_reverse.sh` and Task 18's runbook (listen + keepalive block), `docs/04-protocols/cvmfs.md` (connection-durability section)

No module C code: nginx core already provides everything; this task pins
the exact configuration and **proves it on the wire**, because a missing
`so_keepalive` is invisible until a stateful site firewall silently drops
idle WN connections and the farm storms the cache with reconnects.

**The canonical listener block (used verbatim in the runbook and all
Phase-3B test configs):**

```nginx
    # so_keepalive=idle:intvl:cnt → SO_KEEPALIVE + TCP_KEEPIDLE/KEEPINTVL/KEEPCNT
    # 60s idle probe start beats typical stateful-firewall idle drops (300s+)
    # and keeps NAT/conntrack entries warm on the WN side.
    listen 3128 so_keepalive=60s:10s:6 backlog=2048;

    keepalive_timeout  3600s;      # hold WN connections for an hour idle
    keepalive_requests 1000000;    # never recycle a healthy connection early
    send_timeout          300s;    # slow WN ≠ dead WN
    client_header_timeout 300s;
    reset_timedout_connection off; # a FIN, never an RST, if we must close
```

Rationale, spelled out: the CVMFS client (libcurl under the hood) reuses
pooled connections to its proxy and tracks per-proxy failures. Every
avoidable close forces a reconnect (SYN through a possibly-lossy site
network); every *unclean* close risks being counted against the proxy's
health and triggering group failover or DIRECT. Kernel keepalive makes the
*cache* the side that detects dead peers, while middleboxes see steady
probes and keep state alive. The one-hour `keepalive_timeout` is
deliberately longer than any WN batch-job fetch cadence.

- [ ] **Step 1: Write the failing test**

```bash
#!/usr/bin/env bash
# tests/run_cvmfs_keepalive.sh — connection durability on the wire:
#   1 accepted socket has a kernel keepalive timer (ss shows timer:(keepalive))
#   2 neg-control listener WITHOUT so_keepalive shows no keepalive timer
#   3 200 sequential requests over ONE socket, zero reconnects
#   4 a 403 reject does NOT terminate the connection (error-then-success reuse)
set -u
NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
HERE="$(cd "$(dirname "$0")" && pwd)"
MPORT=12896; CPORT=12897; NPORT=12898
PFX="$(mktemp -d /tmp/cvmfs_ka.XXXXXX)"; fail=0
ok(){ printf '  ok   %s\n' "$1"; }; bad(){ printf '  FAIL %s\n' "$1"; fail=1; }
cleanup(){ [ -f "$PFX/nginx.pid" ] && kill "$(cat "$PFX/nginx.pid")" 2>/dev/null
           kill "$MOCK" 2>/dev/null; rm -rf "$PFX"; }
trap cleanup EXIT
mkdir -p "$PFX/cache" "$PFX/logs"
python3 "$HERE/cvmfs/mock_stratum1.py" --port $MPORT --objects 4 --seed 44 &
MOCK=$!; sleep 0.5

cat > "$PFX/nginx.conf" <<EOF
daemon on; error_log $PFX/logs/e.log info; pid $PFX/nginx.pid;
thread_pool default threads=2;
events { worker_connections 256; }
http {
    access_log off;
    keepalive_timeout 3600s; keepalive_requests 1000000;
    send_timeout 300s; client_header_timeout 300s;
    reset_timedout_connection off;
    server {
        listen 127.0.0.1:$CPORT so_keepalive=60s:10s:6 backlog=2048;
        location /cvmfs/ {
            xrootd_cvmfs_storage_backend http://127.0.0.1:$MPORT/cvmfs;
            xrootd_cvmfs_cache_store $PFX/cache;
            xrootd_cache_include_regex "/data/";
            xrootd_cvmfs on;
        }
        location / { return 403; }
    }
    server {   # negative control: same handler, NO so_keepalive
        listen 127.0.0.1:$NPORT;
        location /cvmfs/ {
            xrootd_cvmfs_storage_backend http://127.0.0.1:$MPORT/cvmfs;
            xrootd_cvmfs_cache_store $PFX/cache;
            xrootd_cache_include_regex "/data/";
            xrootd_cvmfs on;
        }
    }
}
EOF
"$NGINX" -c "$PFX/nginx.conf" -p "$PFX"; sleep 0.3
OBJ="$(curl -s "http://127.0.0.1:$MPORT/ctl/objects" | python3 -c \
      'import json,sys; print(json.load(sys.stdin)[0])')"

# 1+2: kernel keepalive timer present on CPORT, absent on NPORT
python3 - "$CPORT" "$NPORT" "$OBJ" <<'EOF' & HOLD=$!
import http.client, sys, time
for port in (int(sys.argv[1]), int(sys.argv[2])):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    c.request("GET", sys.argv[3]); c.getresponse().read()
    globals()[f"c{port}"] = c          # keep both sockets open
time.sleep(5)
EOF
sleep 1.5
ss -tno state established "( sport = :$CPORT )" | grep -q 'timer:(keepalive' \
    && ok "keepalive timer armed on cvmfs listener" || bad "no keepalive timer"
ss -tno state established "( sport = :$NPORT )" | grep -q 'timer:(keepalive' \
    && bad "neg-control unexpectedly has keepalive" \
    || ok "neg-control has no keepalive (assert is not vacuous)"
wait $HOLD 2>/dev/null

# 3+4: one socket, 200 requests + an error mid-stream, zero reconnects
python3 - "$CPORT" "$OBJ" <<'EOF' && ok "200 reqs + 403 on one socket" || bad "reuse broken"
import http.client, sys
c = http.client.HTTPConnection("127.0.0.1", int(sys.argv[1]), timeout=30)
for i in range(200):
    c.request("GET", sys.argv[2]); r = c.getresponse(); r.read()
    assert r.status == 200, f"req {i}: {r.status}"
c.request("GET", "/etc/passwd"); r = c.getresponse(); r.read()
assert r.status in (403, 405), f"reject: {r.status}"
c.request("GET", sys.argv[2]); r = c.getresponse(); r.read()   # raises if closed
assert r.status == 200, f"post-error: {r.status}"
print("keepalive python OK")
EOF
exit $fail
```

- [ ] **Step 2: Run to verify the delta** — with a plain `listen`, check 1
FAILs (no keepalive timer); after adding the canonical block, all 4 pass.

Run: `bash tests/run_cvmfs_keepalive.sh`
Expected final: 4 × `ok`, exit 0.

- [ ] **Step 3: Propagate the canonical block** — into
`run_cvmfs_reverse.sh`'s config (so every subsequent suite run exercises
it), the Task-18 runbook reference config (already shown there with the
`so_keepalive` listen line), and a "Connection durability" subsection in
`docs/04-protocols/cvmfs.md` reproducing the rationale paragraph above.

- [ ] **Step 4: Commit**

```bash
git add tests/run_cvmfs_keepalive.sh tests/run_cvmfs_reverse.sh \
        deploy/cvmfs/README.md docs/04-protocols/cvmfs.md
git commit -m "feat(cvmfs): TCP keepalive + connection-durability config, proven on the wire"
```

---

### Task 22: `scvmfs://` — EXPERIMENTAL secure protocol layered on `cvmfs://`

> **Status: EXPERIMENTAL.** Not part of Gate 2 or the pilot. Ships behind
> its own directives, its own test suite, and an "experimental" banner in
> every doc. It can slip or be cut without touching any `cvmfs://`
> deliverable. Build it only after the whole `cvmfs://` plane is green.

**What it is:** the same protocol core behind a TLS listener with a
client-authorization preamble — the site-cache face of "secure CVMFS"
(X.509/authz-protected repositories, where Stratum-1s require credentials
and repository content is not world-readable). Layering is literal: the
`cvmfs://` handler runs unchanged; `secure.c` runs *in front of* the gate
and only ever (a) refuses non-TLS transport, (b) authenticates the client,
(c) flips `ctx->secure` so proxy-mode https upstream targets and
`https://` storage backends become legal.

**Files:**
- Create: `src/protocols/cvmfs/secure.c`
- Modify: `src/protocols/cvmfs/cvmfs.h` + `src/protocols/cvmfs/module.c` (2 directives + loc-conf fields), `src/protocols/cvmfs/handler.c` (one call), `src/protocols/cvmfs/request.c` (https allowed when `ctx->secure`), Task-16 metrics (+1 counter), `./config` (+1 file, full rebuild)
- Test: `tests/run_scvmfs.sh`

**Interfaces:**
- Consumes: the whole `cvmfs://` plane (T8/T9), HELPERS `webdav_verify_bearer_token()` + `xrootd_token_check_scope()` (bearer mode) and the GSI/VOMS client-cert verification the WebDAV GSI+TLS listener already performs (`src/protocols/webdav/auth_cert.c` machinery — reused, never reimplemented), nginx core TLS (`listen … ssl`, `ssl_verify_client`).
- Produces:

```c
/* cvmfs.h additions */
typedef enum {
    XROOTD_SCVMFS_AUTHZ_NONE = 0,     /* TLS transport only, no client auth */
    XROOTD_SCVMFS_AUTHZ_BEARER,       /* Authorization: Bearer <JWT> + scope */
    XROOTD_SCVMFS_AUTHZ_VOMS          /* TLS client cert, GSI/VOMS verified  */
} xrootd_scvmfs_authz_e;

    /* in ngx_http_xrootd_cvmfs_loc_conf_t: */
    ngx_flag_t   secure;              /* xrootd_scvmfs on|off (default off)  */
    ngx_uint_t   secure_authz;        /* xrootd_scvmfs_authz (default none)  */

/* secure.c — the scvmfs preamble. NGX_DECLINED = authenticated (or authz
 * none), proceed; anything else is a final status (400/401/403). */
ngx_int_t xrootd_scvmfs_preamble(ngx_http_request_t *r,
    ngx_http_xrootd_cvmfs_loc_conf_t *lcf);
```

Directives: `xrootd_scvmfs on|off` (marks the location as the secure
variant; implies and requires `xrootd_cvmfs on` — config error otherwise)
and `xrootd_scvmfs_authz none|bearer|voms`. TLS itself is nginx-core
(`listen 8443 ssl; ssl_certificate …; ssl_certificate_key …;` and, for voms
mode, `ssl_verify_client optional_no_ca; ssl_client_certificate <CA>;` —
proxy-cert chains are validated by the module helper, not by nginx's own
chain check, exactly as the WebDAV GSI listener does it).

- [ ] **Step 1: Write the failing test**

```bash
#!/usr/bin/env bash
# tests/run_scvmfs.sh — EXPERIMENTAL scvmfs:// secure protocol:
#   1 TLS parity: GET over https serves byte-exact (same core as cvmfs://)
#   2 transport-neg: plain HTTP to the TLS listener → 400, never served
#   3 authz-neg (bearer): missing token → 401; garbage token → 401
#   4 layering: xrootd_scvmfs without xrootd_cvmfs → nginx -t error
set -u
NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
HERE="$(cd "$(dirname "$0")" && pwd)"
MPORT=12901; SPORT=12902
PFX="$(mktemp -d /tmp/scvmfs.XXXXXX)"; fail=0
ok(){ printf '  ok   %s\n' "$1"; }; bad(){ printf '  FAIL %s\n' "$1"; fail=1; }
cleanup(){ [ -f "$PFX/nginx.pid" ] && kill "$(cat "$PFX/nginx.pid")" 2>/dev/null
           kill "$MOCK" 2>/dev/null; rm -rf "$PFX"; }
trap cleanup EXIT
mkdir -p "$PFX/cache" "$PFX/logs"

# throwaway TLS identity for the listener
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=localhost" \
    -keyout "$PFX/key.pem" -out "$PFX/crt.pem" 2>/dev/null

python3 "$HERE/cvmfs/mock_stratum1.py" --port $MPORT --objects 4 --seed 55 &
MOCK=$!; sleep 0.5
OBJ="$(curl -s "http://127.0.0.1:$MPORT/ctl/objects" | python3 -c \
      'import json,sys; print(json.load(sys.stdin)[0])')"

mkconf() {  # $1 = authz mode, $2 = extra location lines
cat > "$PFX/nginx.conf" <<EOF
daemon on; error_log $PFX/logs/e.log info; pid $PFX/nginx.pid;
thread_pool default threads=2;
events { worker_connections 128; }
http { access_log off; server {
    listen 127.0.0.1:$SPORT ssl;
    ssl_certificate     $PFX/crt.pem;
    ssl_certificate_key $PFX/key.pem;
    location /cvmfs/ {
        xrootd_cvmfs_storage_backend http://127.0.0.1:$MPORT/cvmfs;
        xrootd_cvmfs_cache_store $PFX/cache;
        xrootd_cache_include_regex "/data/";
        xrootd_cvmfs on;
        xrootd_scvmfs on;
        xrootd_scvmfs_authz $1;
$2
    }
} }
EOF
}

# 1: TLS parity (authz none)
mkconf none ""
"$NGINX" -c "$PFX/nginx.conf" -p "$PFX"; sleep 0.3
curl -sk "https://127.0.0.1:$SPORT$OBJ" -o "$PFX/tls.bin"
curl -s  "http://127.0.0.1:$MPORT$OBJ" -o "$PFX/ref.bin"
cmp -s "$PFX/tls.bin" "$PFX/ref.bin" && ok "scvmfs TLS parity byte-exact" \
    || bad "TLS parity"

# 2: plain HTTP to the TLS port is refused, not served
C="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$SPORT$OBJ")"
[ "$C" = 400 ] && ok "plain HTTP on scvmfs listener refused" || bad "plain: $C"

# 3: bearer authz-negs
kill "$(cat "$PFX/nginx.pid")"; sleep 0.2
mkconf bearer ""
"$NGINX" -c "$PFX/nginx.conf" -p "$PFX"; sleep 0.3
C1="$(curl -sk -o /dev/null -w '%{http_code}' "https://127.0.0.1:$SPORT$OBJ")"
C2="$(curl -sk -o /dev/null -w '%{http_code}' \
      -H 'Authorization: Bearer not.a.token' "https://127.0.0.1:$SPORT$OBJ")"
[ "$C1" = 401 ] && [ "$C2" = 401 ] && ok "bearer: missing/garbage token → 401" \
    || bad "bearer negs: $C1/$C2"
# positive bearer/voms acceptance: exercised via the repo's existing token /
# GSI test fixtures (same infrastructure as the WebDAV auth tests, ports
# 11095/11097 fleet) — added as a pytest alongside, not in this self-
# contained script, and skipped when the fleet PKI is not up.

# 4: layering enforced at config time
cat > "$PFX/bad.conf" <<EOF
events { worker_connections 32; }
http { server { listen 127.0.0.1:$SPORT ssl;
    ssl_certificate $PFX/crt.pem; ssl_certificate_key $PFX/key.pem;
    location / { xrootd_scvmfs on; } } }
EOF
"$NGINX" -t -c "$PFX/bad.conf" -p "$PFX" 2>/dev/null \
    && bad "scvmfs without cvmfs accepted" || ok "scvmfs requires cvmfs (nginx -t)"
exit $fail
```

- [ ] **Step 2: Run to verify it fails**

Run: `bash tests/run_scvmfs.sh`
Expected: `nginx -t` FAIL (unknown directive `xrootd_scvmfs`).

- [ ] **Step 3: Implement `secure.c`**

```c
/* secure.c — scvmfs:// security preamble (EXPERIMENTAL).
 *
 * WHAT: transport + client-authz gate that runs before the cvmfs gate on
 *       locations with `xrootd_scvmfs on`.
 * WHY:  "secure CVMFS" repositories are credential-protected; the site
 *       cache must enforce the same boundary or it becomes a leak. Layering
 *       it as a preamble keeps ONE protocol core — scvmfs can never drift
 *       behaviorally from cvmfs because it IS cvmfs after this function.
 * HOW:  TLS presence comes from the connection (r->connection->ssl); bearer
 *       mode delegates to the existing token HELPERS; voms mode delegates
 *       to the same client-cert verification the WebDAV GSI+TLS listener
 *       uses. This file contains POLICY GLUE ONLY — zero crypto.
 */
#include "cvmfs.h"

static ngx_int_t
scvmfs_check_bearer(ngx_http_request_t *r)
{
    ngx_str_t  token;

    if (xrootd_http_bearer_from_headers(r, &token) != NGX_OK) {
        return NGX_HTTP_UNAUTHORIZED;              /* no Authorization hdr */
    }
    if (webdav_verify_bearer_token(&token) != NGX_OK) {
        return NGX_HTTP_UNAUTHORIZED;              /* invalid/expired JWT  */
    }
    /* read scope suffices for a read-only protocol */
    if (xrootd_token_check_scope_read(&token, &r->uri) != NGX_OK) {
        return NGX_HTTP_FORBIDDEN;                 /* valid, wrong scope   */
    }
    return NGX_DECLINED;
}

ngx_int_t
xrootd_scvmfs_preamble(ngx_http_request_t *r,
    ngx_http_xrootd_cvmfs_loc_conf_t *lcf)
{
    ngx_http_xrootd_cvmfs_ctx_t *ctx =
        ngx_http_get_module_ctx(r, ngx_http_xrootd_cvmfs_module);
    ngx_int_t                    rc;

    if (r->connection->ssl == NULL) {
        /* nginx core already 400s plain-HTTP-on-ssl-port before we run;
         * this guards mixed listeners and future non-TLS plumbing. */
        return NGX_HTTP_BAD_REQUEST;
    }

    switch (lcf->secure_authz) {
    case XROOTD_SCVMFS_AUTHZ_BEARER:
        rc = scvmfs_check_bearer(r);
        break;
    case XROOTD_SCVMFS_AUTHZ_VOMS:
        rc = xrootd_scvmfs_check_client_cert(r);   /* auth_cert.c reuse   */
        break;
    case XROOTD_SCVMFS_AUTHZ_NONE:
    default:
        rc = NGX_DECLINED;
        break;
    }
    if (rc != NGX_DECLINED) {
        XROOTD_CVMFS_METRIC_INC(XROOTD_CVMFS_M_REJECT);
        return rc;
    }
    ctx->secure = 1;                               /* unlocks https upstream */
    XROOTD_CVMFS_METRIC_INC(XROOTD_CVMFS_M_SECURE);
    return NGX_DECLINED;
}
```

Handler wiring — one call in `ngx_http_xrootd_cvmfs_handler()` after ctx
setup, before the gate:

```c
    if (lcf->secure) {
        rc = xrootd_scvmfs_preamble(r, lcf);
        if (rc != NGX_DECLINED) {
            return rc;
        }
    }
```

`request.c`: the https-refusal branch becomes
`if (!ctx->secure) return NGX_HTTP_FORBIDDEN;` for https authorities, and
`upstreams.c` passes `tls = ctx->secure && target_scheme_https` into the
backend builder. Config-time layering check: in `merge_loc_conf`, `secure
&& !cvmfs.enable` → `NGX_CONF_ERROR` with the message
`"xrootd_scvmfs requires xrootd_cvmfs on"`. Metrics: one new slot
`XROOTD_CVMFS_M_SECURE` in the T16 enum, exported as
`xrootd_scvmfs_requests_total`.

Stand-ins to resolve against live code (same rule as the main list):
`xrootd_http_bearer_from_headers` / `xrootd_token_check_scope_read` = the
actual header-extraction + read-scope helpers the WebDAV bearer path uses
(`auth_token.c`); `xrootd_scvmfs_check_client_cert` = a ~20-line wrapper
over the client-cert verification sequence in `auth_cert.c` (export the
needed function from there if it is currently static — do not copy it).

- [ ] **Step 4: Register `secure.c` in `./config`, full rebuild, run**

Run:
```bash
rm -rf /tmp/nginx-1.28.3/objs && cd /tmp/nginx-1.28.3 && \
./configure --with-stream --with-stream_ssl_module --with-http_ssl_module \
  --with-http_dav_module --with-threads \
  --add-module=/home/rcurrie/HEP-x/nginx-xrootd && make -j$(nproc) && \
cd /home/rcurrie/HEP-x/nginx-xrootd && bash tests/run_scvmfs.sh && \
for t in reverse verify failover manifest proxy select holdopen keepalive; do
    bash tests/run_cvmfs_$t.sh || exit 1
done
```
Expected: scvmfs 5 × `ok`; every cvmfs:// suite untouched (the preamble is
dead code when `xrootd_scvmfs` is absent).

- [ ] **Step 5: Docs + commit** — experimental banner blocks in
`docs/04-protocols/cvmfs.md` (scvmfs section) and a short
"Experimental: scvmfs://" appendix in `deploy/cvmfs/README.md` noting: the
client side needs `CVMFS_SERVER_URL=https://…` / an authz helper
(`CVMFS_AUTHZ_HELPER`) and that WLCG proxy-mode traffic stays cleartext
cvmfs:// for now.

```bash
git add src/protocols/cvmfs/secure.c src/protocols/cvmfs/cvmfs.h \
        src/protocols/cvmfs/module.c src/protocols/cvmfs/handler.c \
        src/protocols/cvmfs/request.c src/protocols/cvmfs/upstreams.c \
        src/observability/metrics/ config tests/run_scvmfs.sh \
        deploy/cvmfs/README.md docs/04-protocols/cvmfs.md
git commit -m "feat(scvmfs): EXPERIMENTAL secure protocol layered on cvmfs:// — TLS + authz preamble"
```

---

### Task 15: Full netem matrix + comparison report

**Files:**
- Create: `tests/cvmfs/run_matrix.sh`
- Modify: `deploy/cvmfs/baselines/RESULTS.md`

**Interfaces:**
- Consumes: everything above.
- Produces: `run_matrix.sh` — for each cache in {module-reverse, module-proxy, stock-nginx, squid?, varnish?} × each profile in {clean, loss, reorder, corrupt, jitter, site}: bring the lab up, start mock in-ns, start the cache, run `harness.py`, collect `results_<cache>_<profile>.json`; then render a markdown table into `RESULTS.md`. Requires sudo; skips proxies not installed.

- [ ] **Step 1: Write the runner**

```bash
#!/usr/bin/env bash
# tests/cvmfs/run_matrix.sh — the phase-68 comparison matrix. For each cache
# implementation x netem profile: fresh lab, mock inside the impaired ns,
# cache on the host, one harness run, one JSON. Renders RESULTS.md at the end.
# Requires root (netem). Skips squid/varnish when not installed.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"; REPO="$(cd "$HERE/../.." && pwd)"
NGINX="${NGINX:-/tmp/nginx-1.28.3/objs/nginx}"
LAB="$HERE/netem_lab.sh"; NIP=10.199.0.2
MPORT=12881; CPORT=12882; PPORT=12883
OUT="$REPO/deploy/cvmfs/baselines"
PROFILES="clean loss reorder corrupt jitter site"
CACHES="module-reverse module-proxy stock-nginx squid varnish"
[ "$(id -u)" = 0 ] || { echo "must run as root (netem)"; exit 2; }

start_mock() {
    ip netns exec cvmfslab python3 "$HERE/mock_stratum1.py" \
        --bind "$NIP" --port $MPORT --objects 16 --seed 68 & MOCK=$!
    sleep 0.5
}

start_cache() {   # $1 = cache name, $2 = workdir; sets CACHEBASE and STOP
    local w="$2"
    case "$1" in
    module-reverse)
        cat > "$w/nginx.conf" <<EOF
daemon on; error_log $w/e.log warn; pid $w/nginx.pid;
thread_pool default threads=4;
events { worker_connections 512; }
http { access_log off; server {
    listen 127.0.0.1:$CPORT;
    location /cvmfs/ {
        xrootd_cvmfs_storage_backend http://$NIP:$MPORT/cvmfs;
        xrootd_cvmfs_cache_store $w/cache;
        xrootd_cache_verify cvmfs-cas;
        xrootd_cvmfs on;
    }
} }
EOF
        mkdir -p "$w/cache"
        "$NGINX" -c "$w/nginx.conf" -p "$w"
        STOP="kill \$(cat $w/nginx.pid)"; CACHEBASE="http://127.0.0.1:$CPORT"
        unset http_proxy ;;
    module-proxy)
        cat > "$w/nginx.conf" <<EOF
daemon on; error_log $w/e.log warn; pid $w/nginx.pid;
thread_pool default threads=4;
events { worker_connections 512; }
http { access_log off; server {
    listen 127.0.0.1:$PPORT;
    location / {
        xrootd_cvmfs_cache_store $w/cache;
        xrootd_cache_verify cvmfs-cas;
        xrootd_cvmfs on;
        xrootd_cvmfs_upstream_allow $NIP;
    }
} }
EOF
        mkdir -p "$w/cache"
        "$NGINX" -c "$w/nginx.conf" -p "$w"
        STOP="kill \$(cat $w/nginx.pid)"
        export http_proxy="http://127.0.0.1:$PPORT"
        CACHEBASE="http://$NIP:$MPORT" ;;
    stock-nginx)
        sed -e "s/@PORT@/$CPORT/" -e "s/@PPORT@/$PPORT/" -e "s#@CACHEDIR@#$w#" \
            -e "s/@ORIGIN@/$NIP:$MPORT/" -e "s/@ORIGINHOST@/$NIP/g" \
            -e "s/@ORIGINPORT@/$MPORT/" \
            "$REPO/deploy/cvmfs/nginx-proxy-cache.conf" > "$w/nginx.conf"
        mkdir -p "$w/store"
        "$NGINX" -c "$w/nginx.conf" -p "$w"
        STOP="kill \$(cat $w/nginx.pid)"; CACHEBASE="http://127.0.0.1:$CPORT"
        unset http_proxy ;;
    squid|varnish)
        # delegate to the Task-4 runner; it sets its own proxy env/base
        SKIP_DELEGATE=1 ;;
    esac
}

: > "$OUT/matrix_rows.tsv"
for cache in $CACHES; do
    for prof in $PROFILES; do
        "$LAB" down >/dev/null 2>&1 || true
        "$LAB" up >/dev/null; "$LAB" profile "$prof" >/dev/null
        start_mock
        W="$(mktemp -d /tmp/cvmfs_matrix.XXXXXX)"
        SKIP_DELEGATE=0; start_cache "$cache" "$W"
        if [ "$SKIP_DELEGATE" = 1 ]; then
            "$HERE/run_baselines.sh" "$cache" $CPORT "$NIP:$MPORT" \
                && J="baseline_${cache}.json" || J=""
        else
            J="$OUT/results_${cache}_${prof}.json"
            python3 "$HERE/harness.py" --cache "$CACHEBASE" \
                --mock "http://$NIP:$MPORT" --out "$J" || J=""
            eval "$STOP" || true
        fi
        [ -n "$J" ] && printf '%s\t%s\t%s\n' "$cache" "$prof" "$J" \
            >> "$OUT/matrix_rows.tsv"
        kill "$MOCK" 2>/dev/null || true
        rm -rf "$W"
    done
done
"$LAB" down >/dev/null

python3 - "$OUT" <<'EOF'
import json, sys, os, datetime
out = sys.argv[1]
rows = [l.split("\t") for l in open(f"{out}/matrix_rows.tsv").read().splitlines()]
K = ["cold_ttfb_p50_ms","cold_ttfb_p99_ms","warm_ttfb_p50_ms",
     "error_rate","stampede_origin_fetches","corrupt_served"]
today = datetime.date.today().isoformat()
lines = []
for cache, prof, path in rows:
    try:
        d = json.load(open(path if os.path.isabs(path) else f"{out}/{path}"))
    except Exception:
        continue
    cells = [f"{d.get(k, ''):.1f}" if isinstance(d.get(k), float) else str(d.get(k, ""))
             for k in K]
    lines.append(f"| {cache} | {prof} | " + " | ".join(cells) + f" | {today} | |")
with open(f"{out}/RESULTS.md", "a") as f:
    f.write("\n".join(lines) + "\n")
print(f"appended {len(lines)} rows to RESULTS.md")
EOF
```

- [ ] **Step 2: Run the matrix**

Run: `sudo tests/cvmfs/run_matrix.sh`

The module configs inside `run_matrix.sh` use the Task-21 canonical
listener block plus `xrootd_cvmfs_client_hold 25;` so the matrix measures
the full Phase-3B behavior, not a bare MVP.

Expected acceptance numbers (the plan's hard exit criteria):
- module `corrupt_served == 0` on EVERY profile (stock/squid expected > 0 under `corrupt`);
- module `stampede_origin_fetches == 1` on every profile;
- module `error_rate` ≤ stock-nginx's on `site` profile;
- warm TTFB p50 < 5 ms on every profile (cache hits never touch the WAN);
- **zero client-visible connection failures on any profile** — extend
  `harness.py`'s `fetch()` to distinguish "HTTP error status" from
  "connection-level failure" (`ConnectionError`/`BrokenPipe`/reset) and
  emit `conn_failures`; the module must score `conn_failures == 0`
  everywhere (convention #6 — errors arrive as well-formed keep-alive HTTP,
  never as broken sockets);
- with the `site` profile and a mid-run 10 s origin blackout (add a
  `sleep`-kill-restart of the in-ns mock to the runner), module
  `error_rate` for requests issued during the blackout window is
  dominated by 504s, not 502s/conn failures — evidence the hold+retry path
  engaged.

- [ ] **Step 3: Commit**

```bash
git add tests/cvmfs/run_matrix.sh deploy/cvmfs/baselines/RESULTS.md
git commit -m "test(cvmfs): full netem comparison matrix — module vs stock vs squid/varnish"
```

**PHASE-3 EXIT / SECOND DECISION GATE:** RESULTS.md to the OP — the corrupt/stall numbers are the argument for the module path; pilot planning proceeds on OP go.

---

# PHASE 4 — Ops polish

### Task 16: Traffic visibility — metrics, protocol identity, access log, dashboard, healthz

**The requirement this task serves:** an operator must be able to SEE CVMFS
traffic at a glance, in every monitoring surface the module already has —
Prometheus, the built-in dashboard, and the access logs — without grepping
generic HTTP noise. Four sub-parts: (a) the cvmfs counter family, (b) a
first-class protocol identity so every EXISTING per-protocol metric and the
live dashboard light up for cvmfs automatically, (c) a dedicated access log
with cvmfs-specific variables, (d) healthz origin health.

**Files:**
- Modify: `src/observability/metrics/metrics.h` (enum slots + proto slot), `metrics_internal.h` (fields), `src/observability/metrics/writer.c` (export), `src/protocols/cvmfs/cvmfs.h` (real `XROOTD_CVMFS_METRIC_INC`), `src/protocols/cvmfs/handler.c` (proto tagging, tracking, variables), `src/protocols/cvmfs/module.c` (variable registration at preconfiguration), `src/fs/cache/fetch.c` (verify-failure + fill counters + fill-bytes), `sd_http.c` (failover counter), `src/observability/dashboard/` (proto label; see 16c), healthz JSON (+ per-endpoint `fail_score`)
- Test: extend `tests/run_cvmfs_reverse.sh` + `tests/run_cvmfs_verify.sh` with `/metrics` scrapes + access-log-format + dashboard-JSON checks

**Interfaces:**
- Produces Prometheus series (all counters unless noted):
  - cvmfs family: `xrootd_cvmfs_requests_total{class="cas|manifest|geo|reject"}`, `xrootd_cvmfs_fills_total`, `xrootd_cvmfs_fill_failures_total`, `xrootd_cvmfs_verify_failures_total`, `xrootd_cvmfs_origin_failovers_total`, `xrootd_cvmfs_negative_hits_total`, and the traffic-split pair `xrootd_cvmfs_bytes_served_total{source="hit|fill"}` (LAN out) + `xrootd_cvmfs_origin_bytes_total` (WAN in) — hit ratio and WAN-saved are one PromQL expression away;
  - protocol identity: `XROOTD_PROTO_CVMFS` in the existing per-protocol enum, so every existing `{proto=…}` family (`bytes_tx/rx`, `cache_hits[XROOTD_PROTO_COUNT]`, request counters emitted via the `webdav_metrics_return()`-style helper) grows a `cvmfs` label with zero new plumbing (T22 adds `scvmfs` the same way);
  - nginx variables (registered by the cvmfs module at preconfiguration, same mechanism as `webdav/module_init.c`): `$cvmfs_class` (`cas|manifest|geo|reject|-`), `$cvmfs_cache` (`hit|fill|stale|neg|-`), `$cvmfs_origin` (`host:port` that served a fill, `-` otherwise);
  - healthz gains `"cvmfs_origins": [{"host":…, "port":…, "fail_score":…}]`.
- Consumes: dashboard HTTP tracking helpers (`xrootd_dashboard_http_*` in `src/observability/dashboard/http_tracking.c` — the same side-effect calls the WebDAV/S3 handlers make).

- [ ] **Step 1: Add the failing metric checks** — after the corrupt-fill check in `run_cvmfs_verify.sh`:

```bash
V="$(curl -s "http://127.0.0.1:9100/metrics" | \
     sed -n 's/^xrootd_cvmfs_verify_failures_total //p')"
[ "${V:-0}" -ge 1 ] && ok "verify failure counted" || bad "metric missing/zero"
```
(and a `requests_total{class="cas"}` presence check in `run_cvmfs_reverse.sh`; wire the metrics port into both test configs).

- [ ] **Step 2: Implement** following the CLAUDE.md recipe (enum → field →
export → INC at callsite), in the SHM `ngx_atomic_t` counter-block idiom the
file already uses (`metrics.h:559` `cache_hits[XROOTD_PROTO_COUNT]` is the
nearest neighbour):

`metrics.h` — slot enum (keep COUNT last, same as the reap-reason enum):

```c
/* phase-68 CVMFS personality counters. Class-indexed; classes are a fixed
 * 4-value set so the label cardinality is bounded by construction. */
typedef enum {
    XROOTD_CVMFS_M_CAS = 0,
    XROOTD_CVMFS_M_MANIFEST,
    XROOTD_CVMFS_M_GEO,
    XROOTD_CVMFS_M_REJECT,
    XROOTD_CVMFS_M_CLASS_COUNT,
    /* scalar counters follow the class array in the stats block */
    XROOTD_CVMFS_M_NEG_HIT = XROOTD_CVMFS_M_CLASS_COUNT,
    XROOTD_CVMFS_M_FILL,
    XROOTD_CVMFS_M_FILL_FAIL,
    XROOTD_CVMFS_M_VERIFY_FAIL,
    XROOTD_CVMFS_M_ORIGIN_FAILOVER,
    XROOTD_CVMFS_M_COUNT
} xrootd_cvmfs_metric_e;
```

Per-server SHM stats struct (same struct that holds `cache_hits[]`) gains:

```c
    /* phase-68 CVMFS personality (indexed by xrootd_cvmfs_metric_e) */
    ngx_atomic_t  cvmfs[XROOTD_CVMFS_M_COUNT];
```

`cvmfs.h` — replace the Task-9 no-op macro:

```c
#define XROOTD_CVMFS_METRIC_INC(slot)                                        \
    do {                                                                     \
        xrootd_metrics_shm_t *m_ = xrootd_metrics_get();                     \
        if (m_ != NULL) {                                                    \
            (void) ngx_atomic_fetch_add(&m_->cvmfs[(slot)], 1);              \
        }                                                                    \
    } while (0)
```

(`xrootd_metrics_get()` stands for the accessor the existing HTTP-plane INC
macros use — copy the exact body of `XROOTD_PROXY_METRIC_INC` and swap the
field; the null-check-if-metrics-unconfigured behavior must match it.)

`writer.c` — export block, next to the cache metric family:

```c
    static const char *cvmfs_class[XROOTD_CVMFS_M_CLASS_COUNT] = {
        "cas", "manifest", "geo", "reject"
    };

    b = xrootd_metrics_buf_printf(b, last,
        "# HELP xrootd_cvmfs_requests_total CVMFS requests by traffic class\n"
        "# TYPE xrootd_cvmfs_requests_total counter\n");
    for (i = 0; i < XROOTD_CVMFS_M_CLASS_COUNT; i++) {
        b = xrootd_metrics_buf_printf(b, last,
            "xrootd_cvmfs_requests_total{class=\"%s\"} %uA\n",
            cvmfs_class[i], st->cvmfs[i]);
    }
    b = xrootd_metrics_buf_printf(b, last,
        "# TYPE xrootd_cvmfs_negative_hits_total counter\n"
        "xrootd_cvmfs_negative_hits_total %uA\n"
        "# TYPE xrootd_cvmfs_fills_total counter\n"
        "xrootd_cvmfs_fills_total %uA\n"
        "# TYPE xrootd_cvmfs_fill_failures_total counter\n"
        "xrootd_cvmfs_fill_failures_total %uA\n"
        "# TYPE xrootd_cvmfs_verify_failures_total counter\n"
        "xrootd_cvmfs_verify_failures_total %uA\n"
        "# TYPE xrootd_cvmfs_origin_failovers_total counter\n"
        "xrootd_cvmfs_origin_failovers_total %uA\n",
        st->cvmfs[XROOTD_CVMFS_M_NEG_HIT],
        st->cvmfs[XROOTD_CVMFS_M_FILL],
        st->cvmfs[XROOTD_CVMFS_M_FILL_FAIL],
        st->cvmfs[XROOTD_CVMFS_M_VERIFY_FAIL],
        st->cvmfs[XROOTD_CVMFS_M_ORIGIN_FAILOVER]);
```

(Mirror the file's real emit helper + format-spec conventions — `%uA` is
nginx's atomic-uint format; if the writer uses a different buffer helper,
follow it. The HELP/TYPE-then-loop shape must match neighbouring families.)

Callsites: `gate.c` already carries all four class INCs plus NEG_HIT from
Tasks 9/13 (the macro just became real). Add: `fetch.c` fill-done →
`M_FILL` on success / `M_FILL_FAIL` on failure / `M_VERIFY_FAIL` on CAS
mismatch (only when `t->cvmfs_cas_verify`); `sd_http.c`
`sd_http_request_fo()` → `M_ORIGIN_FAILOVER` when the second attempt is
entered. `sd_http.c` is ngx-free pure C — it cannot call the macro; give it
a counter hook instead: add `void (*failover_note)(void)` to
`sd_http_inst_state`, set from the ngx-side instance init to a one-line
function that INCs the metric. Healthz: in the existing healthz JSON
builder, when the location has cvmfs enabled, append
`"cvmfs_origins":[{"host":"…","port":N,"fail_score":N},…]` from the
endpoint array via a tiny accessor `sd_http_health_snapshot()` exported
from `sd_http.h` (copies host/port/score triplets into a caller buffer —
no ngx types in the driver).

Byte-split counters: `xrootd_cvmfs_bytes_served_total{source}` is
incremented at the two serve exits in `handler.c` (`hit`: after the
file-response completes from a cached fd; `fill`: in the fill-done resume
path) with the response byte count the serve helper already returns;
`xrootd_cvmfs_origin_bytes_total` is incremented in `fetch.c` with the
bytes actually pulled from the origin (count every attempt's received
bytes, including fills later discarded by verify — WAN cost is WAN cost).

- [ ] **Step 3: Protocol identity — make the EXISTING monitoring see cvmfs**

Add `XROOTD_PROTO_CVMFS` to the per-protocol enum in `metrics.h` (the one
sizing `cache_hits[XROOTD_PROTO_COUNT]` at `metrics.h:559` and the
per-proto byte counters; T22 later appends `XROOTD_PROTO_SCVMFS`
identically). Then tag every cvmfs request with it:

```c
/* handler.c, at the end of a served request (both hit and fill-resume
 * exits) — the same helper call the WebDAV methods make (HELPERS table): */
    webdav_metrics_return(r->headers_out.status, bytes_sent,
                          XROOTD_PROTO_CVMFS);
```

and bump `cache_hits[XROOTD_PROTO_CVMFS]` where the tier reports a hit
(the existing per-proto hit bump the other HTTP protocols use — same call,
new proto value). Every already-exported `{proto=…}` Prometheus family and
every existing dashboard/per-proto breakdown now shows `cvmfs` with no
further code. (If the proto enum is exported to the dashboard as a string
table, append `"cvmfs"` there — one array literal.)

- [ ] **Step 4: Dedicated access log — variables + format**

Register three variables at preconfiguration in `module.c` (mechanism:
`ngx_http_add_variable()`, exactly as `webdav/module_init.c` does), backed
by the request ctx the handler already fills:

```c
static ngx_http_variable_t  ngx_http_xrootd_cvmfs_vars[] = {
    { ngx_string("cvmfs_class"),  NULL, cvmfs_var_class,  0, 0, 0 },
    { ngx_string("cvmfs_cache"),  NULL, cvmfs_var_cache,  0, 0, 0 },
    { ngx_string("cvmfs_origin"), NULL, cvmfs_var_origin, 0, 0, 0 },
      ngx_http_null_variable
};

/* getters read ngx_http_xrootd_cvmfs_ctx_t: class from ctx->url.cls,
 * cache disposition from a new ctx->cache_status (set at the serve exits:
 * HIT / FILL / STALE / NEG), origin host:port from the fill result (dash
 * when served from cache). Unset ctx (non-cvmfs location) → "-". */
```

Canonical log format (documented in the runbook, used in the e2e configs):

```nginx
log_format cvmfs '$remote_addr [$time_local] "$request" $status '
                 '$body_bytes_sent $request_time '
                 'class=$cvmfs_class cache=$cvmfs_cache origin=$cvmfs_origin';
access_log /var/log/nginx-xrootd/cvmfs_access.log cvmfs;
```

One glance at the log now answers "what class, was it a hit, which
Stratum-1" per request — and `cache=fill` lines are exactly the WAN
traffic.

- [ ] **Step 5: Dashboard — live cvmfs transfers**

The dashboard already tracks HTTP requests as live transfers via the
`xrootd_dashboard_http_*` helpers (`src/observability/dashboard/
http_tracking.c`), with a pool-cleanup freeing the slot — tracking is a
side effect, display-only, never affects data movement (its README's core
rule). Wire the cvmfs handler the same way the WebDAV/S3 handlers are
wired: track-start after the gate passes (so rejects never occupy a slot),
with the protocol tag from Step 3 — the live-transfer table, events ring,
and history sparkline then show cvmfs traffic with its own proto label,
zero dashboard-side logic. Dashboard-side change is limited to whatever
proto-string table exists for rendering (append `"cvmfs"`, and `"scvmfs"`
in T22).

- [ ] **Step 6: Extend the failing checks, build, run, commit** — add to
`run_cvmfs_reverse.sh`: an access-log check (`grep -q 'class=cas cache=fill'`
after the cold read and `class=cas cache=hit` after the warm read, with the
`cvmfs` log_format wired into the test config), a per-proto family check
(`curl -s :9100/metrics | grep -q 'proto="cvmfs"'`), and a dashboard JSON
check (hit the dashboard snapshot endpoint during a slow fill — mock
`stall` fault — and `grep` the JSON for `"cvmfs"`; skip if the test config
has no dashboard location).

```bash
git add src/observability/metrics/ src/observability/dashboard/ \
        src/protocols/cvmfs/cvmfs.h src/protocols/cvmfs/handler.c \
        src/protocols/cvmfs/module.c src/fs/cache/fetch.c \
        src/fs/backend/http/sd_http.c \
        tests/run_cvmfs_reverse.sh tests/run_cvmfs_verify.sh
git commit -m "feat(cvmfs): traffic visibility — proto identity, byte-split metrics, cvmfs access log, dashboard tracking"
```

---

### Task 17: Guard + fail2ban + ratelimit defaults

**Files:**
- Modify: `src/protocols/cvmfs/gate.c` (emit the existing httpguard signal on REJECT), `deploy/fail2ban/` (add a `cvmfs-reject` filter + jail following the existing filter file pattern)
- Test: extend `tests/run_cvmfs_reverse.sh` (reject lines appear in the access log in the guard-parsable shape); fail2ban regex fixture test alongside the existing one in `deploy/fail2ban/`

- [ ] **Step 1: Failing check** — append to `run_cvmfs_reverse.sh` after the
security-neg block:

```bash
# guard-parsable reject line present in error log (convention #4 shape)
grep -q 'cvmfs-reject: .*class=reject' "$PFX/logs/e.log" \
    && ok "reject line guard-parsable" || bad "no cvmfs-reject log line"
```

and extend the existing fail2ban regex fixture test (the one landed with
phase-65 under `deploy/fail2ban/`) with three sample lines that MUST match
and one that must NOT:

```
2026/07/02 12:00:00 [warn] 1#0: *3 cvmfs-reject: method=GET uri="/cvmfs/../etc/passwd" client=192.0.2.7 class=reject cause="path is not a CVMFS traffic shape" fix="..."
2026/07/02 12:00:01 [warn] 1#0: *4 cvmfs-reject: method=PUT uri="/cvmfs/a.b/.cvmfspublished" client=192.0.2.7 class=reject cause="method not allowed" fix="..."
2026/07/02 12:00:02 [warn] 1#0: *5 cvmfs-reject: method=GET uri="/cvmfs/x/random" client=198.51.100.9 class=reject cause="path is not a CVMFS traffic shape" fix="..."
NOMATCH 2026/07/02 12:00:03 [warn] 1#0: *6 cvmfs manifest refill failed; serving stale copy client=192.0.2.7
```

- [ ] **Step 2: Implement.**

*Guard side.* The httpguard module classifies via its access/log-phase
handlers (`ngx_http_xrootd_guard_access_handler` /
`ngx_http_xrootd_guard_log_handler` in `src/net/httpguard/guard_http.h`) —
it sees the 403/405 statuses the gate produces without any new emit API.
Two changes only: (a) `cvmfs_reject()` in `gate.c` writes the convention-#4
`cvmfs-reject:` WARN line (URI through `xrootd_sanitize_log_string()`)
before returning the status, so the log-phase classifier and fail2ban have
one stable line to key on; (b) add a `cvmfs_reject` signal name to the
guard's classify table (`src/net/httpguard/classify_handler.c`) mapping
"cvmfs location + 403/405 final status" to that signal, following exactly
how the existing auth-reject signals are registered there.

*fail2ban side.* `deploy/fail2ban/filter.d/nginx-xrootd-cvmfs.conf`:

```ini
# Fail2Ban filter — nginx-xrootd CVMFS personality rejects (phase-68).
# Matches the stable "cvmfs-reject:" WARN line from src/protocols/cvmfs/gate.c.
# A worker node probing non-CVMFS paths through the site cache is either
# misconfigured or hostile; both deserve a timeout.
[Definition]
failregex = ^.*\[warn\].*cvmfs-reject: method=\S+ uri="[^"]*" client=<HOST> class=reject
ignoreregex =
```

Jail entry appended to the phase-65 jail file (same backend/log path
variables as its neighbours):

```ini
[nginx-xrootd-cvmfs]
enabled  = true
port     = 3128,8443
filter   = nginx-xrootd-cvmfs
logpath  = /tmp/xrd-test/logs/error.log
maxretry = 20
findtime = 60
bantime  = 600
```

`maxretry=20/findtime=60`: a healthy CVMFS client never sends a rejectable
URL, but a human with curl during debugging shouldn't get instabanned —
20/min is drastically above accidental and drastically below scanner rates.
- [ ] **Step 3: Build, test, commit**

```bash
git add src/protocols/cvmfs/gate.c deploy/fail2ban/
git commit -m "feat(cvmfs): guard signal + fail2ban jail for non-CVMFS probing"
```

---

### Task 18: Runbook + pilot checklist

**Files:**
- Create: `deploy/cvmfs/README.md`
- Modify: `CLAUDE.md` (OP→FILE row for cvmfs; one line), `docs/04-protocols/` (cvmfs page)

**`deploy/cvmfs/README.md` — full content to ship (verbatim start point;
the executor updates only facts that changed during implementation):**

````markdown
# CVMFS site cache on nginx-xrootd — deployment runbook

A drop-in replacement for the Squid layer between your worker nodes and the
CVMFS Stratum-1s, with two properties Squid does not have: **corrupt origin
transfers are never admitted to the cache** (CAS verify-on-fill) and
first-class Prometheus observability.

## Topology

Two **independent** cache nodes (no VIP, no keepalived — CVMFS clients do
their own load-balancing and failover):

```
WN farm ── CVMFS_HTTP_PROXY="http://cache1:3128|http://cache2:3128" ──┐
                                                                      │
   cache1: nginx-xrootd, N TB XFS cache_store  ── WAN ── Stratum-1s ──┤
   cache2: nginx-xrootd, N TB XFS cache_store  ── WAN ── Stratum-1s ──┘
```

`|` = load-balance between both; use `;` between groups for strict
failover ordering. Keep Squid installed but idle until the pilot completes.

## Sizing

| Farm size | cache_store | RAM | threads |
|---|---|---|---|
| ≤ 500 cores | 500 GB | 8 GB | thread_pool default threads=8 |
| ≤ 2000 cores | 1–2 TB | 16 GB | threads=16 |
| larger | 2–4 TB | 32 GB | threads=32 |

Store on XFS, dedicated filesystem (eviction watermarks assume the cache
owns the volume). Watermarks: evict at 85 %, hard-stop admission at 95 %
(`xrootd_cache_eviction_threshold` / watermark directives — see
docs/03-configuration/directives.md).

## Reference configuration (proxy mode)

```nginx
worker_processes auto;
error_log /var/log/nginx-xrootd/error.log warn;
thread_pool default threads=16;
events { worker_connections 4096; }
http {
    access_log /var/log/nginx-xrootd/cvmfs_access.log;

    # --- connection durability: keep every WN connection alive ------------
    # Kernel keepalive (60s idle, 10s probes, 6 tries) keeps NAT/firewall
    # state warm and lets the CACHE detect dead peers — the client never
    # experiences an unexplained close and never marks this proxy bad.
    keepalive_timeout  3600s;
    keepalive_requests 1000000;
    send_timeout          300s;
    client_header_timeout 300s;
    reset_timedout_connection off;   # FIN, never RST

    server {
        listen 3128 so_keepalive=60s:10s:6 backlog=2048;
        location / {
            xrootd_cvmfs_cache_store /srv/cvmfs-cache;
            xrootd_cache_verify cvmfs-cas;
            xrootd_cvmfs on;
            xrootd_cvmfs_manifest_ttl 61;
            xrootd_cvmfs_negative_ttl 10;
            xrootd_cvmfs_quarantine_dir /srv/cvmfs-quarantine;

            # --- never-drop semantics -----------------------------------
            # Hold a request up to 25s while retrying the Stratum-1s with
            # backoff; on expiry answer 504+Retry-After on the kept-alive
            # connection (the client's retry coalesces on the running fill).
            # MUST stay below the WN's CVMFS_TIMEOUT (see client tuning).
            xrootd_cvmfs_client_hold   25;
            xrootd_cvmfs_fill_max_life 300;

            # --- upstream selection: static | geo | rtt ------------------
            # rtt = probe connect latency every 60s, prefer the fastest;
            # geo = rank by great-circle distance from 'here';
            # static = the order of the allow/origin list.
            xrootd_cvmfs_origin_select rtt;
            xrootd_cvmfs_rtt_interval  60;
            # geo alternative:
            #   xrootd_cvmfs_origin_select geo;
            #   xrootd_cvmfs_here 55.95:-3.19;   # this cache (Edinburgh)
            #   xrootd_cvmfs_origin_coords cvmfs-stratum-one.cern.ch 46.23:6.05;
            #   xrootd_cvmfs_origin_coords cvmfs-s1fnal.opensciencegrid.org 41.85:-88.31;

            # every Stratum-1 host your experiments use — nothing else is proxied:
            xrootd_cvmfs_upstream_allow cvmfs-stratum-one.cern.ch;
            xrootd_cvmfs_upstream_allow cvmfs-s1fnal.opensciencegrid.org;
            xrootd_cvmfs_upstream_allow cvmfs-stratum-one.ihep.ac.cn;
            xrootd_cvmfs_upstream_max 8;
        }
    }
    server {   # metrics, firewalled to the monitoring host
        listen 9100;
        location /metrics { xrootd_metrics on; }
        location /healthz { xrootd_healthz on; }
    }
}
```

Reverse mode (optional second listener): same location shape plus
`xrootd_cvmfs_storage_backend "http://s1a/cvmfs|http://s1b/cvmfs";` and
clients use `CVMFS_SERVER_URL=http://cache:8000/cvmfs/@fqrn@` with
`CVMFS_HTTP_PROXY=DIRECT`.

## Client configuration

`/etc/cvmfs/default.local` on every WN:

```
CVMFS_HTTP_PROXY="http://cache1.site:3128|http://cache2.site:3128"

# --- timeout alignment with the cache's never-drop hold -------------------
# The cache holds a request up to xrootd_cvmfs_client_hold (25s) while it
# retries the Stratum-1s, then answers 504 on the kept-alive connection.
# The client's proxied timeout MUST exceed that hold, or the client gives
# up first and starts counting the cache as failed:
CVMFS_TIMEOUT=30              # default is 5 — far too low for a cold miss
CVMFS_TIMEOUT_DIRECT=10
CVMFS_MAX_RETRIES=3
# If the client ever does mark a proxy failed, come back to it quickly
# (default 300s leaves the cache benched for 5 minutes after one blip):
CVMFS_PROXY_RESET_AFTER=60
CVMFS_HOST_RESET_AFTER=120
```

**Why this alignment matters:** the whole never-drop design assumes the
cache answers *before* the client's patience runs out. `client_hold=25 <
CVMFS_TIMEOUT=30` guarantees the client always receives a well-formed HTTP
answer (data or 504-retry-later) on a healthy connection — so its proxy
bookkeeping stays clean and it never escalates to the failover group or
DIRECT. If you change one side, change the other.

Apply to running nodes without remount:

```
cvmfs_talk -i <repo> proxy set "http://cache1.site:3128|http://cache2.site:3128"
```

**Rollback is one variable:** point `CVMFS_HTTP_PROXY` back at the Squids.

## Monitoring

Scrape `:9100/metrics`. The series that matter:

| Series | Alert on | Meaning |
|---|---|---|
| `xrootd_cvmfs_verify_failures_total` | any increase | the WAN corrupted a transfer; the cache refused it. **This is your evidence for the network team** — each increment has a quarantined file in `/srv/cvmfs-quarantine` to prove it. |
| `xrootd_cvmfs_fill_failures_total` | rate spike | Stratum-1s unreachable/stalling |
| `xrootd_cvmfs_origin_failovers_total` | rate spike | primary Stratum-1 degraded |
| `xrootd_cvmfs_requests_total{class="reject"}` | sustained rate | something probing the cache (fail2ban jail `nginx-xrootd-cvmfs` bans it) |
| `xrootd_cvmfs_requests_total{class="cas"}` | — | traffic volume baseline |
| `xrootd_cvmfs_bytes_served_total{source="hit\|fill"}` | hit share dropping | LAN bytes to the farm, split by cache disposition — the hit-ratio source |
| `xrootd_cvmfs_origin_bytes_total` | sustained ≈ bytes_served | WAN bytes pulled from Stratum-1s; if this tracks bytes_served the cache isn't caching |
| `{proto="cvmfs"}` on the module-wide families | — | cvmfs as a slice of everything this node does (connections, tx/rx, cache hits) |
| `/healthz` `.cvmfs_origins[].fail_score` | > 0 sustained | per-origin health |

Quarantine hygiene: files there are evidence, not cache — prune with
`find /srv/cvmfs-quarantine -mtime +30 -delete` from cron.

### Ready-made PromQL (paste into Grafana)

```promql
# cache hit ratio (5m)
sum(rate(xrootd_cvmfs_bytes_served_total{source="hit"}[5m]))
  / sum(rate(xrootd_cvmfs_bytes_served_total[5m]))

# WAN bytes actually pulled from Stratum-1s vs LAN bytes served to the farm
sum(rate(xrootd_cvmfs_origin_bytes_total[5m]))          # WAN in
sum(rate(xrootd_cvmfs_bytes_served_total[5m]))          # LAN out
# their ratio = how much the cache is saving your broken WAN

# request mix by class
sum by (class) (rate(xrootd_cvmfs_requests_total[5m]))

# cvmfs share of ALL traffic this node serves (proto identity, T16)
sum(rate(xrootd_proxy_bytes_tx_total{proto="cvmfs"}[5m]))
  / sum(rate(xrootd_proxy_bytes_tx_total[5m]))
```

(Adjust the per-proto family name in the last query to the module's actual
exported name — see `/metrics` output; the `proto="cvmfs"` label is the
stable part.)

### Access log

Every request lands in `cvmfs_access.log` with the cvmfs format:

```
10.1.2.3 [02/Jul/2026:14:31:07 +0000] "GET /cvmfs/atlas.cern.ch/data/ab/cd…01 HTTP/1.1" 200 187342 0.004 class=cas cache=hit origin=-
10.1.2.4 [02/Jul/2026:14:31:09 +0000] "GET /cvmfs/atlas.cern.ch/.cvmfspublished HTTP/1.1" 200 421 0.812 class=manifest cache=fill origin=cvmfs-stratum-one.cern.ch:80
```

`cache=fill` lines ARE your WAN traffic; `awk '$0~/cache=fill/'` over a
time window is a poor man's WAN audit when Prometheus is down.

### Live dashboard

The built-in operator dashboard (`xrootd_dashboard on` location, see
docs/08-metrics-monitoring) shows in-flight CVMFS transfers with a `cvmfs`
protocol tag in the live transfer table, plus the events ring and history
sparkline. Firewall it — it exposes paths and client IPs.

## Pilot procedure (do not skip steps)

1. Deploy both cache nodes; run for 24 h with **no** clients; confirm clean
   logs and a green `/healthz`.
2. Pick ONE worker-node queue. Flip its `CVMFS_HTTP_PROXY`. Record date.
3. Soak **two weeks**. Watch: `error_rate` proxy for user pain =
   mount-failure tickets from that queue vs the Squid queues;
   `verify_failures_total` (expect > 0 if your network is as bad as
   believed — each one would have been a farm-poisoning event under Squid).
4. Expand queue-by-queue. Squid is decommissioned only after **two full
   clean soak periods** on the complete farm.
5. Any regression → rollback (step "one variable"), file the logs, stop.

## Squid → nginx-xrootd mapping

| squid.conf | here |
|---|---|
| `collapsed_forwarding on` | built-in (fill lock; exactly 1 origin fetch) |
| `refresh_pattern /data/ …` | built-in (CAS objects cached forever) |
| `refresh_pattern .cvmfspublished …` | `xrootd_cvmfs_manifest_ttl` |
| `acl cvmfs_dst dstdomain …` + `http_access` | `xrootd_cvmfs_upstream_allow` |
| `cache_dir ufs … ` | `xrootd_cvmfs_cache_store` + watermarks |
| `negative_ttl` | `xrootd_cvmfs_negative_ttl` |
| `cache_peer` parent ordering | `xrootd_cvmfs_origin_select static\|geo\|rtt` |
| `connect_retries` / `retry_on_error` | `xrootd_cvmfs_client_hold` (hold + endpoint-walking backoff, then 504-keepalive) |
| `client_persistent_connections on` | `so_keepalive=…` + `keepalive_timeout 3600s` (kernel-level, proven by `run_cvmfs_keepalive.sh`) |
| (no equivalent) | `xrootd_cache_verify cvmfs-cas` + quarantine |
| (no equivalent) | detached fills — a client abort never cancels an in-flight origin fetch |
````

- [ ] **CLAUDE.md OP→FILE row** (one line in the HTTP table):

```
| cvmfs:// site cache (+ experimental scvmfs://) | `src/protocols/cvmfs/module.c`, `handler.c`, `gate.c`, `classify.c`, `geo.c`, `request.c`, `upstreams.c`, `secure.c`, `src/fs/cache/verify.c` (cvmfs-cas), `fill_retry.c` |
```

…and a ROUTING-table row (same CLAUDE.md edit):

```
| `cvmfs://` (HTTP) / `scvmfs://` (TLS, experimental) | http | `src/protocols/cvmfs/handler.c` | site-config (e.g. 3128 / 8443) |
```

- [ ] **`docs/04-protocols/cvmfs.md`**: condensed protocol page — traffic
classes table (from spec §2.2), directive reference (the seven
`xrootd_cvmfs_*` directives with defaults), both deployment modes, metric
list, and links to the runbook + this plan + the spec.

- [ ] **Final step: full suite + docs commit**

Run: `tests/run_suite.sh --pr` and all six `run_cvmfs_*.sh` — everything green.

```bash
git add deploy/cvmfs/README.md CLAUDE.md docs/04-protocols/
git commit -m "docs(cvmfs): deployment runbook, pilot checklist, OP→FILE row"
```

---

## Self-review record

- **Spec coverage:** §2 client model → Tasks 5/14 (both modes); §2.2 classes → Task 7; coalescing → Tasks 5/9 asserts; verify/quarantine → Task 10; multi-origin → Task 11; manifest TTL/stale → Task 12; negative cache → Task 13; geo passthrough → Task 9; metrics/guard/ops → Tasks 16–18; netem evaluation + baselines → Tasks 1–4, 15; both decision gates present (after Task 5, after Task 15). CAS-dedup optimisation from spec §5 deliberately excluded (spec marks it optional-later — YAGNI). **Two OP-directed extensions beyond the original spec (2026-07-02):** (1) Phase 3B (Tasks 19–21): origin selection (static/geo/rtt), never-drop hold+retry semantics, TCP-keepalive client durability; (2) the protocol-plane restructure: `cvmfs://` is a dedicated protocol module/handler (the spec's §5 "thin personality on the WebDAV plane" is superseded — no WebDAV dispatch involvement) plus the EXPERIMENTAL `scvmfs://` secure layer (Task 22, non-gating). The spec's §5/§6 should be amended to match when next touched (a one-line note in the spec is sufficient — the plan is the source of truth for these areas).
- **Placeholder scan:** every task (1–21) carries full code, config, or verbatim document content — including the matrix runner (T15), the fail2ban filter/jail + guard wiring (T17), and the complete runbook text (T18). The only deliberately-unwritten code is behind the named stand-ins below, each of which specifies exactly how to resolve it. No TBDs.
- **Type consistency:** `cvmfs_url_info_t`/`cvmfs_classify_url` used identically in Tasks 7/9/10/12; `xrootd_cvmfs_conf_t` fields referenced in 9/10/12/13/14 all declared in Task 8; `sd_http_endpoint`/`fail_score` consistent between Tasks 11/16; harness JSON keys consistent between Tasks 3/5/15.
- **Named stand-ins the executor must resolve against the live code** (each
  is flagged at its use site; none changes the design): (a) T8/T9 —
  `xrootd_http_common_conf_t` and `common.backend_entry`/`common.cache_store`
  member names: use the ACTUAL shared per-protocol tier struct + field names
  the webdav/s3 loc-confs embed (grep `common\.` in `webdav/module.c` /
  `s3/`); the cvmfs loc-conf embeds the same struct, and
  `cvmfs_resolve_backend()` in `handler.c` reads the entry from it; also
  mirror the exact handler-installation point (merge-time vs postconfig)
  the s3 module uses.
  (b) T12 — `XROOTD_CACHE_OPEN_EXPIRED` tri-state: reuse an existing
  equivalent in `open.c`'s meta-validation returns if one exists.
  (c) T9 — `xrootd_aio_post_task` / `xrootd_cache_http_transport()`: use the
  exact thread-task posting helper and transport getter the WebDAV cache-fill
  path uses (`grep -rn "thread_task\|transport" src/fs/backend/http/
  src/fs/cache/fetch.c`). (d) T12/T14 — `XROOTD_DIAG_WARN`/`XROOTD_DIAG_ERR`:
  match the real `XROOTD_DIAG` macro signature in the log-diag header.
  (e) T14 — `xrootd_vfs_backend_entry_create_http`: new function, specified
  as the runtime twin of `xrootd_vfs_backend_config_http` (same fields,
  cycle-pool allocation, sd_http instance init as done in
  `vfs_backend_registry.c`). (f) T16 — `xrootd_metrics_get()` /
  `xrootd_metrics_buf_printf()`: copy the accessor and buffer-emit helpers
  from the existing `XROOTD_PROXY_METRIC_INC` macro and a neighbouring
  writer.c family. (g) T9 — `lcf->common.backend_entry` member name for the
  location's parsed backend entry: use the actual field
  `xrootd_cvmfs_storage_backend` populates. (h) T20 —
  `xrootd_cache_waiter_t` / `cvmfs_waiter_detach()`: use the actual waiter
  node type and unlink discipline of the existing fill-waiter list in
  `open_or_fill.c`; the request-cleanup hook must be idempotent with the
  hold-timer path (both may fire — detach must tolerate double calls).
  (i) T20 — `cvmfs_fetch_attempt()` / `cvmfs_fill_fail()` /
  `sd_http_n_endpoints()`: thin wrappers factored out of the existing
  `fetch.c` attempt/error code during the T20 refactor, plus a one-line
  endpoint-count accessor on the driver — name them to match the
  surrounding file. (j) T19 — the worker-init hook that creates RTT probe
  contexts: use the same per-worker timer-registration point the stale-dirty
  reaper uses (`cache_reap.c`'s hourly timer is the template). (k) T21 — if
  `ss` output formatting differs on the target kernel, loosen the assert to
  `grep -q 'keepalive'` on the established-socket line. (l) T16 — four
  copy-the-neighbour jobs, named so the executor greps them first: the
  per-protocol enum (`XROOTD_PROTO_*`, the one sizing
  `cache_hits[XROOTD_PROTO_COUNT]` at `metrics.h:559`), the per-proto
  request/byte helper (`webdav_metrics_return()` per the HELPERS table —
  confirm its real signature), the dashboard's proto string table (wherever
  the transfer table renders protocol names), and the variable-registration
  template (`webdav/module_init.c`'s `ngx_http_add_variable`
  preconfiguration hook).
- **Interfaces verified against the tree while writing this plan** (not
  guesses): `xrootd_cache_verify_part()` signature (`verify.h:70`),
  `xrootd_cache_cinfo_t` layout + flag bits `0x0001–0x0008` (`cinfo.h:42–92`),
  `sd_http_inst_state`/transport vtable (`sd_http.c:23–47`), the
  `http://`-scheme backend parse branch (`vfs_backend_config.c:441`),
  `xrootd_vfs_backend_config_http()` (`vfs_backend_config.c:80`), the WebDAV
  dispatch GET routing point (`dispatch.c:197`), tier directives
  `xrootd_webdav_{storage_backend,cache_store,stage*}` (`webdav/module.c:101–144`),
  guard handlers (`guard_http.h:62–69`), SHM atomic counter-block idiom +
  `cache_hits[]` (`metrics.h:559`), existing http-source cache e2e pattern
  (`tests/run_cache_http_source.sh`).

---

## Appendix A — Definition of done (whole phase-68)

- [ ] All nine `tests/run_cvmfs_*.sh` green (classify, reverse, verify,
      failover, manifest, proxy, select, holdopen, keepalive) +
      `tests/run_suite.sh --pr` green.
- [ ] `run_matrix.sh` acceptance numbers met: module `corrupt_served == 0`
      on every profile; `stampede_origin_fetches == 1`; `error_rate` on the
      `site` profile ≤ stock-nginx's; warm p50 < 5 ms; **`conn_failures ==
      0` on every profile**; blackout-window errors are 504s, not broken
      connections.
- [ ] Never-drop semantics proven: `run_cvmfs_holdopen.sh` demonstrates
      hold-through-outage (200 after recovery), 504-keepalive + same-socket
      retry, detached-fill population after client abort, and immediate
      definitive 404.
- [ ] Selection policies proven: `run_cvmfs_select.sh` demonstrates static
      order, geo distance, and RTT pre-ranking each choosing the intended
      origin, with misconfiguration rejected at `nginx -t`.
- [ ] Kernel keepalive proven on the wire: `run_cvmfs_keepalive.sh` shows
      the `timer:(keepalive)` on accepted sockets and 200-requests+error
      survival on a single connection.
- [ ] Traffic visibly monitorable in all three surfaces: `/metrics` exports
      the cvmfs family + byte-split pair + `proto="cvmfs"` labels on the
      module-wide families; the cvmfs access-log format emits
      `class=/cache=/origin=` per request (asserted in the reverse e2e);
      the live dashboard shows cvmfs transfers with their proto tag.
- [ ] `cvmfs://` is a genuinely dedicated protocol: every cvmfs e2e config
      contains no `xrootd_webdav` directive; `grep -rn 'webdav' src/protocols/cvmfs/`
      returns nothing (shared code was promoted to `src/core/http/`, not
      included across protocol directories).
- [ ] EXPERIMENTAL, non-gating: `run_scvmfs.sh` green when T22 is built —
      but Gate 2 and the pilot proceed regardless of T22's state; if T22 is
      cut, only its own files and doc sections are removed.
- [ ] `nginx -t` clean on: reverse config, proxy config, runbook reference
      config, and a config with `xrootd_cvmfs off` everywhere (personality
      fully inert when disabled).
- [ ] Config **reload** under load keeps serving (standard drain semantics —
      spot-check with the reverse e2e running in a loop across a `-s reload`).
- [ ] No `goto` introduced (`grep -rn "goto" src/protocols/cvmfs/ | wc -l` = 0);
      seam guard `tools/ci/check_vfs_seam.sh` green (the three
      `vfs-seam-allow` markers added by T10 are cache-store staging files —
      the same class the guard already allows for `fetch.c`).
- [ ] Both OP gates have recorded verdicts in `RESULTS.md`.
- [ ] Docs shipped: runbook, `docs/04-protocols/cvmfs.md`, CLAUDE.md row,
      spec §5.1 hash-convention verdict recorded.

## Appendix B — CVMFS vocabulary (for executors new to the domain)

| Term | Meaning |
|---|---|
| Stratum-0 / Stratum-1 | master repo server / its public HTTP replicas — our cache's upstreams |
| fqrn | fully-qualified repo name, e.g. `atlas.cern.ch` |
| CAS object | content-addressed blob at `/data/<2hex>/<hex…>`; name = hash of content ⇒ immutable, self-verifying |
| suffix letter | object kind tag on CAS names: C catalog, H history, X cert, M metainfo, L micro-catalog, P partial |
| `.cvmfspublished` | signed repo manifest; the ONLY frequently-refetched object; points at the current root catalog |
| catalog | SQLite directory listing, itself a CAS object (`…C`) |
| Geo API | `/api/v1.0/geo/…` — Stratum-1 orders itself relative to the caller; per-caller ⇒ uncacheable |
| proxy mode / reverse mode | client sends absolute URIs via `CVMFS_HTTP_PROXY` / client addresses the cache as the server via `CVMFS_SERVER_URL` |
| `cvmfs_talk` | client admin socket CLI — used for live proxy switching in the pilot |
| `CVMFS_TIMEOUT` | client's proxied-request timeout (default 5 s!) — must exceed `xrootd_cvmfs_client_hold` or the client aborts before the cache answers (runbook sets 30 s) |
| `CVMFS_PROXY_RESET_AFTER` | seconds before the client retries a proxy it marked failed (default 300) — runbook lowers it to 60 so a blip doesn't bench the cache for 5 min |
| proxy group failover | `CVMFS_HTTP_PROXY` groups: `\|` load-balances inside a group, `;` fails over between groups; a "failed" proxy triggers group escalation, then DIRECT — the exact behavior conventions #6/#7 exist to prevent |
| Stratum-1 selection | this plan's `xrootd_cvmfs_origin_select`: static (config order), geo (haversine from `xrootd_cvmfs_here`), rtt (probed connect latency EWMA) |
| `cvmfs://` | this module's dedicated CVMFS protocol plane (own module/handler/directives/metrics) — plain HTTP on the wire, like the S3 plane is REST-over-HTTP |
| `scvmfs://` | EXPERIMENTAL secure variant layered on `cvmfs://`: TLS listener + optional bearer/VOMS client authz + https upstreams; maps to authz-protected ("secure") CVMFS repositories |
| `CVMFS_AUTHZ_HELPER` | client-side plugin supplying credentials for secure repos — the WN counterpart of `scvmfs://` |
