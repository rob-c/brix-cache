# CVMFS deep-reference doc + CentOS9-Stream Docker demo — design

**Date:** 2026-07-02 · **Status:** approved by OP (scope: all three deliverables)
**Parent plan:** [docs/refactor/phase-68-cvmfs-site-cache.md](../../refactor/phase-68-cvmfs-site-cache.md)

## Problem

Phase-68 landed the `cvmfs://` protocol plane through T22, but three
operator-facing pieces are missing or thin:

1. **T16 traffic visibility is a stub** — `XROOTD_CVMFS_METRIC_INC` is a
   no-op, so Prometheus exports no cvmfs series and the dashboard has no
   cvmfs identity. A live demo would show nothing cvmfs-specific.
2. `docs/04-protocols/cvmfs.md` is a summary, not the hyper-detailed
   reference the OP wants (protocol diagrams, exact origin/replica
   selection behavior, evidence of correct operation).
3. There is no self-contained deployable artifact an operator can point a
   **real, official CVMFS client** at.

## Deliverables

### D1 — T16 implementation (prerequisite)

Exactly the committed plan's Task 16 (§4536 of the phase-68 plan): cvmfs
counter family + `XROOTD_PROTO_CVMFS` identity + `$cvmfs_class` /
`$cvmfs_cache` / `$cvmfs_origin` variables + healthz origin fail-scores +
dashboard proto label. Tests: `/metrics` scrape assertions added to
`run_cvmfs_reverse.sh` and `run_cvmfs_verify.sh` first (failing), then the
wiring. T17 is finished by committing the in-flight fail2ban sample log +
regex test.

### D2 — Hyper-detailed protocol doc

`docs/04-protocols/cvmfs.md` expanded in place (inbound links stay valid).
Structure:

1. Role of a CVMFS site cache; where this module sits (Squid replacement).
2. Architecture diagram: client → listener → gate → classifier → tier →
   `sd_http` → Stratum-1 set.
3. Wire protocol: reverse vs forward-proxy mode **sequence diagrams**
   (origin-form vs absolute-form request lines), method policy, geo
   passthrough.
4. Per-class cache semantics (CAS / MANIFEST / GEO / REJECT) incl. CAS
   verify-on-fill + quarantine and manifest TTL/revalidate/stale-if-error.
5. **Origin & replica selection (the deep chapter):** static order; the
   exact EWMA health/failover math in `sd_http.c`; geo mode (haversine
   ranking, `xrootd_cvmfs_origin_coords`/`_here`); rtt mode (probe timer
   cadence, scoring); the fill-outcome → action table (`fill_retry.h`);
   never-drop hold/retry/504/detach timeline with the real backoff
   constants. All numbers read from the code, not the plan.
6. Connection durability (keepalive listener block, why closes are poison).
7. `scvmfs://` (experimental).
8. Security: gate rejects, httpguard, fail2ban filter/jail.
9. Observability: metric families, variables, dashboard, healthz (post-D1).
10. Full directive reference.
11. **Evidence appendix:** dated output of the 10 shell suites + pytest
    suites + the committed matrix numbers (module `corrupt_served=0` /
    `conn_failures=0` vs stock's 32 silent poisonings).

### D3 — Docker demo (`deploy/cvmfs/docker/`)

A single container proving cache + dashboard + metrics + guard + fail2ban
coexist in ONE nginx config:

- **Dockerfile** — `quay.io/centos/centos:stream9`; dnf build deps +
  fail2ban; builds nginx 1.28.3 with `--add-module` of this repo (build
  context = repo root); non-root runtime user for nginx workers.
- **nginx.conf** — one file, three servers:
  - `:3128` cvmfs cache, **forward-proxy mode** (official clients set
    `CVMFS_HTTP_PROXY=http://host:3128`), upstream allowlist = real
    Stratum-1 hosts (CERN/EGI/OSG/FNAL/RAL), CAS verify on, never-drop
    defaults, durability listener block, `xrootd_guard` active, dedicated
    cvmfs access log.
  - `:3129` dashboard (`xrootd_dashboard on`, password via env template).
  - `:3130` Prometheus metrics.
- **fail2ban/** — jail using the committed
  `deploy/fail2ban/filter.d/nginx-xrootd-cvmfs.conf` against the container
  error log (+ guard audit jail). Real iptables bans when run with
  `--cap-add=NET_ADMIN`; documented log-only fallback otherwise.
- **entrypoint.sh** — starts fail2ban-server then nginx (foreground);
  fail-fast if either dies.
- **smoke.sh** — CI-style proof run by the agent: build image, start,
  fetch a real repo manifest through 3128 (absolute-form), assert cache
  hit on refetch, scrape 3130 for `xrootd_cvmfs_requests_total`, login
  page on 3129, fire non-CVMFS probes → assert `cvmfs-reject` logged and
  fail2ban ban registered.
- **README.md** — operator/client instructions: the exact
  `/etc/cvmfs/default.local` (`CVMFS_HTTP_PROXY`, `CVMFS_SERVER_URL`,
  `CVMFS_TIMEOUT` > `xrootd_cvmfs_client_hold` note), dashboards URLs,
  how to watch a ban happen.

**Client reality check:** an official client validates repository
signatures, so the demo proxies **real Stratum-1s** (container needs
outbound internet). The mock Stratum-1 stays a test-suite tool only.

## Non-goals

- No netem matrix rerun inside the container (root/sudo path already
  documented in `run_matrix.sh`).
- No scvmfs in the demo config (experimental, excluded from gates).
- No new cache-tier features; D1 touches observability surfaces only.

## Risks

- CentOS Stream 9 package drift (nginx build deps) — pinned in Dockerfile.
- Real-Stratum-1 dependence makes smoke.sh network-dependent; smoke has a
  `--mock` escape hatch using the test mock for offline runs (cache path
  only, not a real client mount).
- Dashboard is admin-only by design: demo binds 3129 with a password and
  the README says firewall it.
