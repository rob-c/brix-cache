# CVMFS Site Cache on nginx-xrootd — Draft Design & Plan

**Date:** 2026-07-02
**Status:** DRAFT — blue-sky exploration, not yet approved for implementation
**Author:** drafted for OP review

---

## 1. Problem Statement

A Tier-2 WLCG site serves CVMFS to its worker-node farm through site-local
HTTP caches (historically Squid; GPL Varnish currently under evaluation). The
site's network infrastructure is unreliable — sustained packet loss,
out-of-order delivery, flaky middleboxes — and the local admin team is
inexperienced, so infrastructure-level fixes are slow to land. The result is
recurring CVMFS client failures across the farm: slow catalog loads, stalled
object fetches, and (worst case) corrupted transfers that poison a shared
proxy cache.

**Goal:** explore replacing the Squid/Varnish layer with a site cache built on
this project — nginx's hardened HTTP(S) stack + event loop + thread pools,
plus the caching, integrity, and observability machinery already built here —
so that CVMFS at the site becomes reliable *despite* the network, not because
of it.

**Non-goals (explicit):**
- Not a CVMFS Stratum-1 replica (no snapshot/replication machinery).
- Not a general web forward proxy (only the CVMFS traffic shape).
- Not a fix for the underlying network — a mitigation layer.
- No writes: CVMFS client traffic is 100 % GET/HEAD.

---

## 2. Background: what a CVMFS site cache must do

### 2.1 Client fetch model

CVMFS clients (FUSE) fetch over plain HTTP(S) in one of two modes:

1. **Proxy mode** (`CVMFS_HTTP_PROXY="http://cache1:3128|http://cache2:3128"`):
   the client sends standard forward-proxy requests — an **absolute URI** in
   the request line — to the site proxy, which fetches from whichever
   Stratum-1 the client selected (`CVMFS_SERVER_URL` list, geo-sorted).
   Proxy groups (`|` = load-balance, `;` = failover) give client-side HA.
2. **Direct/reverse mode** (`CVMFS_SERVER_URL="http://cache.site/cvmfs/@fqrn@"`
   with `CVMFS_HTTP_PROXY=DIRECT`): the cache is addressed as if it were the
   server and proxies/caches upstream itself.

Proxy mode is the WLCG-standard deployment (drop-in for existing Squid
configs, zero per-repo config on the cache) — it is the primary target.
Reverse mode falls out almost for free and is kept as a secondary target.

### 2.2 Content classes (the whole caching policy)

| Class | URL shape | Mutability | Policy |
|---|---|---|---|
| CAS objects | `/cvmfs/<repo>/data/<2 hex>/<38 hex>[suffix]` | **Immutable** (content-addressed) | Cache effectively forever; safe to serve stale on origin outage; verifiable by hash |
| Repo manifest | `/cvmfs/<repo>/.cvmfspublished` | Mutable, signed | Short TTL (~60 s, matching Squid guidance); revalidate; stale-if-error bounded |
| Whitelist / reflog | `.cvmfswhitelist`, `.cvmfsreflog` | Mutable, signed | Short TTL, same as manifest |
| Geo API | `/cvmfs/<repo>/api/v1.0/geo/...` | Per-caller | Do **not** cache (or cache per-proxy-IP briefly); pass through |
| Anything else | — | — | Reject (guard) — a CVMFS cache should not be an open proxy |

Suffix letters on CAS objects (`C` catalog, `H` history, `X` cert, `M`
metainfo, `P` partial, `L` micro-catalogs) don't change cache policy — all
are immutable CAS.

### 2.3 What Squid/Varnish give (and what we must match or beat)

- **Request coalescing** (Squid collapsed_forwarding / Varnish waitinglist):
  one origin fetch per hot object regardless of how many WNs stampede. On a
  1000-core farm starting a pilot wave this is the single most important
  feature.
- **TTL policy per URL class**, refresh patterns.
- **Upstream failover** across Stratum-1s.
- **Large disk cache** with eviction.

What neither gives (our differentiators):
- **Integrity verification on fill.** A lossy/reordering network with broken
  middleboxes occasionally defeats TCP's weak checksum; Squid then caches a
  corrupt object and serves it to the whole farm until manually purged
  (CVMFS clients verify hashes and refuse it — the symptom is a repo-wide,
  persistent fetch failure). CVMFS objects are *content-addressed*: the cache
  can recompute the hash on fill and refuse to admit corruption. This
  directly attacks the site's actual failure mode.
- **First-class observability** (Prometheus metrics, dashboard, structured
  logs with cause/fix diagnostics) — already built here.
- **Bad-actor guard / fail2ban integration** — already built here.
- **One deployment stack** if the site also runs (or will run) this project
  for storage.

---

## 3. What already exists in this repo (requirement → subsystem map)

| CVMFS-cache requirement | Existing subsystem | State |
|---|---|---|
| Hardened HTTP(S) front end, worker pools | nginx core + module HTTP plane (`src/protocols/webdav/`, anonymous plain-HTTP GET path on 8443-style vhost) | Production |
| Read-through cache: miss → thread-pool fill from origin → serve from disk | `src/fs/cache/` (open_or_fill, fetch, thread, lock) | Production |
| HTTP(S) origin as the remote source | `src/fs/backend/http/sd_http.c` — read-only HTTP(S) source driver (HEAD size, Range GET) over the shared transport vtable | Landed (phase-63) |
| Composable cache tier over any backend | phase-64 tier layer: `xrootd_webdav_cache_store` etc. compose a posix cache store in front of a remote backend; runtime cold-fill→hit verified | Landed |
| Cache store on local POSIX disk | `src/fs/backend/posix/` + `sd_cache` decorator + `cstore.c` | Production |
| Per-file cache state (present bitmap, atime) | `.cinfo` v3 engine (`cinfo.c`) | Production |
| Admission policy (prefix/size/regex) | `cache_admit.c` (shared read/write filter) | Production |
| Eviction, watermarks, stale reaper | `evict_*.c`, `reap_watermark.c`, `cache_reap.c` | Production |
| Checksum verification on fill | `verify.c` (checksum-on-fill; currently digest-based vs origin) | Landed — needs CVMFS CAS mode |
| Origin stall/hang protection | libcurl `CURLOPT_LOW_SPEED_LIMIT/TIME` + connect timeouts (reboot-lockup audit) | Landed |
| Fill-lock with dead-owner reclaim (coalescing primitive) | `lock.c` (O_EXCL fill lock, `kill(pid,0)==ESRCH` reclaim) + stage waiter machinery (`src/fs/xfer/stage_waiter.c`) | Production |
| Metrics / dashboard / healthz | `src/observability/` | Production |
| Rate limiting, bad-actor guard, fail2ban | `src/net/ratelimit/`, `src/net/httpguard/`, `deploy/fail2ban/` | Production |
| Config reload without drop | standard nginx drain semantics (documented) | Production |

**Genuinely missing** (the actual work):

1. **Forward-proxy request handling** — accept absolute-URI request lines,
   derive (origin host, path) from the URL instead of a static export root.
2. **Multi-origin awareness** — today `cache_origin`/`storage_backend` is one
   configured remote; CVMFS needs "whatever Stratum-1 the client asked for"
   (proxy mode) or a failover list (reverse mode).
3. **URL-class policy engine** — immutable-forever vs short-TTL revalidate vs
   pass-through, plus TTL/revalidation semantics the current cache doesn't
   have (it assumes an immutable-ish grid-storage namespace).
4. **CVMFS CAS verify mode** — hash-the-object-you-fetched against the hash
   *in its own URL* (no origin round-trip needed, unlike current verify.c).
5. **Cache keying by (origin, repo, path)** — today keys derive from export
   paths (`cache_key.c`); need a namespace that can't collide across repos
   and (in proxy mode) across upstreams.

---

## 4. Candidate approaches

### Approach A — pure stock-nginx config (no module code)

Use nginx's built-in `proxy_cache` with `proxy_cache_lock` (coalescing),
`proxy_cache_use_stale error timeout updating`, `proxy_cache_valid` per
URL-class (via `map` on `$uri`), an `upstream {}` block of Stratum-1s with
passive health checks, and tuned `proxy_read_timeout`/`proxy_next_upstream`.
Proxy mode needs a small trick (nginx resolves absolute URIs; route on
`$host` with a `resolver` and an allowlist of Stratum-1 hosts).

- **Pros:** zero C code; deployable this week; already beats Varnish-GPL on
  HTTP robustness; a legitimate end-state if it proves sufficient.
- **Cons:** no CAS integrity verification (the site's key failure mode
  unaddressed); opaque hashed cache store (no per-object ops tooling);
  cache metrics limited to stub_status + logs; two config dialects if the
  site later runs the module for storage.

### Approach B — module-native CVMFS personality (RECOMMENDED)

A thin new protocol personality `src/protocols/cvmfs/` (GET/HEAD only,
~4–6 small files) that classifies CVMFS URLs, resolves the upstream, and
drives the **existing** VFS cache tier: posix `cache_store` in front of the
`sd_http` origin driver, `cache_admit` policy, `.cinfo` state, fill-lock
coalescing, eviction/reaper, metrics — plus the two real additions: a
**CVMFS CAS verify mode** in `verify.c` and **multi-origin resolution with
health scoring**.

- **Pros:** attacks the actual failure mode (verify-on-fill + quarantine);
  full metrics/dashboard/guard integration; transparent on-disk cache tree
  (object = file, inspectable, pre-heatable, rsync-able); one stack.
- **Cons:** real C work (est. 4–7 k LoC incl. tests) across several
  subsystems; cache tier gains its first TTL/revalidation semantics
  (bounded: only 3 metadata filenames need it).

### Approach C — hybrid split

Stock `proxy_cache` (Approach A) for the mutable metadata + Geo API;
module cache (Approach B) for immutable CAS objects only, front-routed by a
`location` split. CAS objects never need TTL logic, so the module cache
stays purely immutable.

- **Pros:** each layer does only what it's already good at; the module-side
  scope shrinks (no TTL engine at all).
- **Cons:** two cache stores to size/monitor/debug; still needs proxy-mode
  URL handling in both layers.

**Recommendation:** **B**, staged so that **A ships first as the Phase-1
baseline** (it is also the control group for evaluation), and C remains the
fallback if TTL semantics in the module cache turn out ugly. The phased plan
below encodes exactly that.

---

## 5. Architecture (Approach B)

```
 WN farm (CVMFS FUSE clients, CVMFS_HTTP_PROXY=this cache)
      │  HTTP GET (absolute URI, proxy mode)  /  GET /cvmfs/... (reverse mode)
      ▼
 nginx worker (event loop)
 ┌───────────────────────────────────────────────────────────────┐
 │ src/protocols/cvmfs/  (new, thin)                             │
 │   request.c   parse absolute/relative URI → (upstream, repo,  │
 │               path); reject non-CVMFS shapes (guard hook)     │
 │   classify.c  URL → {CAS | MANIFEST | GEO | REJECT}           │
 │   handler.c   GET/HEAD dispatch:                              │
 │     CAS      → VFS cache tier (below)                         │
 │     MANIFEST → cache tier with TTL/revalidate                 │
 │     GEO      → uncached pass-through (upstream subrequest)    │
 └───────────────┬───────────────────────────────────────────────┘
                 ▼
 src/fs/ VFS cache tier (existing)
   xrootd_vfs_open → cache hit? → sendfile from posix cache_store
                   → miss → fill-lock (coalesce) → thread-pool fill
                            via sd_http Range/whole GET from the
                            resolved origin → CAS verify → admit →
                            atomic rename into store → wake waiters
   ├── cache_admit.c   size/prefix/regex admission (per class)
   ├── verify.c        NEW mode: CVMFS CAS (hash vs URL), quarantine
   ├── cinfo.c         present bitmap / atime / (NEW: expiry for MANIFEST)
   ├── evict/reap      watermark eviction, never evicts an in-fill object
   └── origin/         NEW: origin_set.c — Stratum-1 health scoring,
                       stall timeouts (existing curl LOW_SPEED), retry
                       with next-origin failover (reverse mode)
```

Data-flow properties worth stating:

- **Coalescing:** N clients missing the same object → 1 fill (existing
  O_EXCL fill lock + waiter wakeup, dead-owner reclaim already fixed in the
  reboot-lockup audit). Clients wait in `XRD_ST_AIO`-style async park on the
  event loop, never blocking a worker.
- **Serve path:** cache hits are plain `sendfile()` from the posix store —
  nginx's best-case path; the flaky WAN is only ever touched by thread-pool
  fill workers with stall timeouts, never by the client-facing event loop.
- **Corruption firewall:** a fill whose bytes don't hash to the name in its
  URL is *not admitted* (deleted + counted + optionally quarantined to a
  side dir for postmortem), and the client gets a 502 so it retries/fails
  over per normal CVMFS semantics. The farm-poisoning failure mode is gone.
- **Proxy-mode cache key:** `<origin-host>/<repo>/<path>` under `cache_root`
  — CAS objects are origin-independent in content, but keying them per-origin
  keeps semantics trivially correct; an optional later optimisation
  (`cvmfs_cas_dedup`) can key CAS purely by hash across origins.

### 5.1 New components (all small, single-purpose — per coding standards)

| Component | Job | Est. size |
|---|---|---|
| `src/protocols/cvmfs/request.c/h` | absolute-URI + Host parsing → upstream/repo/path triple; allowlist check | ~300 LoC |
| `src/protocols/cvmfs/classify.c/h` | URL-class table (regex/prefix driven, table-dispatch) | ~150 LoC |
| `src/protocols/cvmfs/handler.c` | GET/HEAD entry, routes class → tier / passthrough; Range handling | ~400 LoC |
| `src/protocols/cvmfs/config.c` | directives: `xrootd_cvmfs on`, `xrootd_cvmfs_upstream_allow`, `xrootd_cvmfs_manifest_ttl`, `xrootd_cvmfs_verify`, `xrootd_cvmfs_quarantine_dir`, origin list (reverse mode) | ~250 LoC |
| `src/fs/cache/origin/origin_set.c` | ordered origin list + per-origin health score (EWMA of failures/stalls), pick/failover | ~350 LoC |
| `verify.c` extension | `XROOTD_CACHE_VERIFY_CVMFS_CAS` mode: stream-hash during fill, compare to URL hash, quarantine on mismatch | ~200 LoC |
| `cinfo` v3 extension | optional `expires_at` field for MANIFEST class (v3-compatible: new flag bit + field, old readers ignore) | ~100 LoC |
| Metrics | `cvmfs_{hits,misses,fills,fill_failures,verify_failures,coalesced_waiters,origin_failovers}` low-cardinality counters + fill-latency histogram | ~150 LoC |

**Hash-convention verdict (Phase-2 spike, RESOLVED 2026-07-02):** the CAS
object name is the SHA-1 of the bytes **as served by the Stratum-1** (the
compressed on-wire form) — verify is a straight digest of the fill, no
inflate. Established empirically by `tests/cvmfs/spike_cas_hash.sh` against
`http://cvmfs-stratum-one.cern.ch/cvmfs/cvmfs-config.cern.ch`:

```
repo manifest root catalog: 6dbdd7347740faea55832ca8545a113c974bef65
inflated sha1: cb3978f107828c19b696e869d121f65f3b7cbfa7
raw sha1:      6dbdd7347740faea55832ca8545a113c974bef65
expected:      6dbdd7347740faea55832ca8545a113c974bef65
```

`raw == expected` ⇒ **raw-bytes convention**; the root-catalog `C`-suffix
object follows the same rule as plain data chunks (name = hash of served
bytes). verify.c (Task 10) uses `xrootd_checksum_hex_name_fd(fd, "sha1", …)`
directly on the staged `.part` file.

---

## 6. Reliability features vs the site's actual network problems

| Site symptom | Mitigation | Source |
|---|---|---|
| Packet loss → stalled origin transfers | curl LOW_SPEED stall timeout on every fill; fill retried on next origin; client never waits past `cvmfs_fill_deadline` | exists + origin_set |
| Out-of-order / middlebox corruption | CAS verify-on-fill; corrupt bytes never enter the cache; `verify_failures` metric alerts the admins with *proof* the network mangled data (useful politically) | new verify mode |
| WAN flaps | Immutable CAS served from disk regardless of WAN state; MANIFEST served stale up to `stale_if_error` bound (CVMFS clients tolerate stale catalogs within repo TTL) | tier + small TTL logic |
| Farm-wide pilot-start stampede | fill-lock coalescing: one WAN fetch per object; waiters parked async | exists |
| Slow/lossy last-mile to WNs | nginx event loop + sendfile + keepalive tuning; LAN side is nginx's home turf | exists |
| Retry storms amplifying congestion | per-client rate limits (`src/net/ratelimit/`) + guard escalation for misbehaving WNs | exists |
| Silent degradation | Prometheus metrics + dashboard panel + healthz with per-origin health | exists + small additions |

---

## 7. Deployment topology

- **Two cache nodes** (VMs or repurposed boxes), each: nginx-xrootd with the
  cvmfs personality, N TB posix `cache_store` on local disk (XFS),
  watermark eviction at e.g. 85/95 %.
- Clients: `CVMFS_HTTP_PROXY="http://c1:3128|http://c2:3128"` — client-side
  load-balancing + failover, no keepalived/VIP needed (CVMFS handles it).
- Ports: dedicated plain-HTTP vhost (proxy traffic is cleartext per WLCG
  norm); optional HTTPS listener for direct/reverse mode later.
- Squid/Varnish stay running during pilot on different ports — flipping a
  farm between caches is one `CVMFS_HTTP_PROXY` change (or a
  `cvmfs_talk proxy switch` for live nodes).

---

## 8. Test & evaluation plan

The evaluation harness is as important as the cache: the claim is
"reliable on a bad network", so the lab must *have* a bad network.

1. **netem lab** (`tests/cvmfs/netem_lab.sh`): namespace/veth pair with
   `tc netem` profiles — `loss 1–5 %`, `reorder 25 % 50 %`, `delay
   50 ms 20 ms distribution normal`, `corrupt 0.1 %` — between cache and a
   local mock Stratum-1. Profiles named after the site's observed pathologies.
2. **Mock Stratum-1** (`tests/cvmfs/mock_stratum1.py`): serves a synthetic
   CVMFS repo tree (real layout: `.cvmfspublished`, CAS objects with correct
   hash-names) with fault injection (stall, mid-body reset, bit-flip —
   bit-flip is the verify-on-fill acceptance test).
3. **Real-client tests**: containerised `cvmfs2` client mounting a real repo
   (e.g. `cvmfs-config.cern.ch` or a locally published test repo) through the
   cache; assert mount, stat-walk, file reads, catalog refresh — under each
   netem profile.
4. **Stampede test**: 200 concurrent cold requests for one object → exactly
   1 origin fetch (assert via mock's request log), all clients byte-exact.
5. **Comparison matrix**: same suite against Squid and Varnish configs —
   produces the numbers that justify (or kill) the project. Metrics:
   time-to-first-byte p50/p99, fill failure rate, client-visible error rate,
   corrupt-object admission (should be 0 for us, >0 for Squid under
   `corrupt` netem).
6. Standard repo discipline: 3 tests per change (success + error +
   security-negative), `run_suite.sh --pr` gate, raw-wire style HTTP tests
   for the handler.

---

## 9. Phased roadmap

### Phase 0 — Lab + baseline (no repo code; ~2–3 days)
netem lab, mock Stratum-1, real-client harness, and the Squid/Varnish
baseline runs. **Exit:** reproducible failure numbers for
Squid/Varnish under each netem profile — the yardstick.

### Phase 1 — Stock-nginx config prototype (Approach A; ~2–3 days)
`deploy/cvmfs/nginx-proxy-cache.conf` + docs: proxy_cache + cache_lock +
use_stale + upstream failover + per-class TTL map, proxy-mode `$host`
routing with Stratum-1 allowlist. Run the full harness against it.
**Exit:** a deployable config the site could pilot immediately; harness
numbers vs Squid/Varnish. **Decision gate:** if Phase 1 alone fixes the
site's pain, pause here and pilot — Approach B continues only if the
integrity/observability gap is judged worth the C work.

### Phase 2 — CAS spike + module MVP (Approach B core; ~1–2 weeks)
- Half-day spike: pin down CVMFS hash convention against a real Stratum-1.
- `src/protocols/cvmfs/` handler (reverse mode first — single configured
  origin list, no absolute-URI parsing yet) driving the existing tier:
  posix cache_store ← sd_http origin, admission, coalescing, eviction.
- CAS classify + immutable policy; MANIFEST passthrough (uncached) as a
  stopgap so correctness never depends on TTL logic.
**Exit:** real cvmfs2 client mounts through the module cache under clean
network; stampede test passes; cold/warm parity with Phase 1.

### Phase 3 — Reliability hardening (~1–2 weeks)
- `verify.c` CVMFS-CAS mode + quarantine dir + `verify_failures` metric —
  bit-flip netem test must show 0 corrupt admissions.
- `origin_set.c` multi-origin health/failover; fill retry policy; negative
  caching (short-TTL 404 memo to absorb misconfigured-repo storms).
- MANIFEST TTL + revalidation + bounded stale-if-error (cinfo expiry field).
- Proxy mode: absolute-URI parsing + upstream allowlist (this is the
  drop-in-for-Squid milestone).
**Exit:** full netem matrix green; harness shows the corruption and stall
numbers beating Squid/Varnish baselines.

### Phase 4 — Ops polish (~1 week)
- Metrics + dashboard panel; healthz per-origin health; admin-friendly
  XROOTD_DIAG log lines for fill failures (cause/fix).
- Guard/fail2ban rules for non-CVMFS URL shapes; ratelimit defaults.
- Cache pre-heat tool (walk a catalog, warm CAS objects) — optional,
  reuses the client-side HTTP bits.
- `deploy/cvmfs/README.md`: sizing guidance, eviction watermarks,
  two-node topology, CVMFS client config snippets, Squid-migration notes.
**Exit:** deployable artifact + runbook.

### Phase 5 — Site pilot (~2–4 weeks calendar, low effort)
Two nodes at the site on alternate ports; move one WN queue's
`CVMFS_HTTP_PROXY`; watch dashboards for a fortnight; expand or roll back.
**Exit:** go/no-go on Squid/Varnish retirement, with site data.

---

## 10. Risks & open questions

| Risk / question | Impact | Handling |
|---|---|---|
| CVMFS hash convention (compressed vs uncompressed; suffix classes) | Shapes verify.c work | Phase-2 half-day spike, before any verify code |
| TTL/revalidation is genuinely new to the cache tier | Scope creep into a general HTTP cache | Confine to 3 literal filenames; MANIFEST-uncached stopgap keeps every phase shippable without it; Approach C split is the escape hatch |
| Absolute-URI proxy mode interacts oddly with nginx virtual-server routing | Proxy-mode milestone slips | Reverse mode ships first (Phase 2); proxy mode isolated in Phase 3; stock-nginx Phase 1 already proves nginx can route it |
| Site politics: admins may see this as blame-shifting | Adoption | `verify_failures` metric gives *evidence* of network corruption — frame as a diagnostic gift, not an indictment |
| Whole-object vs Range fills for large CAS objects | Memory/disk churn | CVMFS chunks large files (~MB-scale objects) — whole-object fill is right; keep slice machinery out of scope |
| Geo API pass-through correctness (per-proxy geo sorting) | Suboptimal Stratum-1 ordering, not correctness | Pass through uncached in all phases; revisit only if measured |
| Effort vs benefit if Phase 1 config already suffices | Wasted C work | Explicit decision gate after Phase 1 with harness numbers |

---

## 11. Summary

The repo already contains ~80 % of a CVMFS site cache: the HTTP front end,
the read-through posix cache tier with coalescing/admission/eviction, an
HTTP(S) origin driver, stall-timeout origin I/O, verification hooks,
metrics, and guard/ratelimit. The genuinely new work is a thin CVMFS URL
personality, CAS verify-on-fill, multi-origin failover, and a tightly-bounded
TTL feature for three metadata filenames. The phased plan ships a
deployable stock-nginx config in week one (also the evaluation control),
gates the C work on measured need, and lands the differentiating feature —
a cache that *cannot* be poisoned by the site's broken network — by Phase 3.
