# nginx-xrootd Kubernetes Test Lab — Master Design

**Date:** 2026-07-04
**Status:** Approved design (pre-implementation)
**Supersedes:** `k8s-tests/PLAN.md` (the earlier 10-week aspirational plan; this spec replaces it)

---

## 1. Purpose & Goal

Turn the project's local, single-host test topologies — above all the **chaos-mesh**
multi-tier fleet — into **reproducible, production-fidelity Kubernetes deployments** that
run **anywhere** on **minikube**, orchestrated with **Helm** following k8s best practices.

The audience includes an operator **new to Kubernetes**, so the deliverable must include
clear, teaching-oriented documentation and a single friendly driver script, not just raw
manifests.

### Success criteria

1. `minikube` + `helm` + one driver script brings up any named test **profile** from a clean
   machine with no external container registry required.
2. The **chaos-mesh** topology runs as **one pod per role** (true multi-node capable) with the
   existing `tests/test_chaos_mesh.py` scenarios passing against it.
3. x509 (CA/CRL/VOMS/proxy), WLCG **token/JWKS**, and **krb5** authorities run as **dedicated
   in-cluster site services** that the fleet consumes over the network (CRLs pulled over HTTP,
   JWKS fetched over HTTP) — not baked-in files.
4. The **existing** pytest suite (390 files, ~6,900 fast tests) runs **unmodified** against the
   cluster, driven purely by the `TEST_*` environment overrides already present in
   `tests/settings.py`.
5. Independent **Ceph / CephFS / RADOS** backends and the **xrootdfs FUSE** driver are testable
   in-cluster.
6. "One container per VM" is honored, with node-pinning selectable **per profile** (portable by
   default, strict one-role-per-node for high-fidelity/perf profiles).

### Non-goals

- Replacing the local `manage_test_servers.sh` workflow for day-to-day dev (it stays; the k8s
  lab is an additional, reproducible target).
- A hosted/multi-tenant CI cluster. CI wiring is a follow-on, not part of this spec.
- Rewriting any of the 390 test files. The suite is consumed as-is via env wiring.

---

## 2. Key Insight (why this is tractable)

`tests/settings.py` exposes **174 environment-overridable knobs**, including `TEST_SERVER_HOST`,
`TEST_HOST`, and every `TEST_*_PORT`. The auth authorities are already scripted
(`tests/lib/pki.sh`, `tests/utils/make_token.py`, `tests/kdc_helpers.py`,
`k8s-tests/pki-scripts/`).

**Therefore the k8s effort is packaging + orchestration + env-wiring, not test reimplementation.**
Every test-runner Job simply sets `TEST_*` variables to in-cluster Service DNS names and runs the
real suite.

This principle is load-bearing across every sub-project below. Any design choice that would
require forking or editing test logic is wrong by construction.

---

## 3. Current State (what we build on)

| Asset | Location | Reuse |
|---|---|---|
| Local topology definitions | `tests/lib/dedicated.sh` (89 dedicated fleets), `tests/lib/nginx.sh`, `tests/manage_test_servers.sh` | Source of truth for roles, ports, config files |
| Chaos-mesh configs | `tests/configs/nginx_chaos_tier{2,3}_*.conf`, `nginx_proxy.conf`, `nginx_cluster_{redir,ds}.conf` | Rendered into role ConfigMaps |
| Auth provisioning | `tests/lib/pki.sh`, `tests/utils/make_token.py`, `tests/kdc_helpers.py`, `k8s-tests/pki-scripts/` | Run inside authority images / bootstrap Jobs |
| Env-driven settings | `tests/settings.py` (174 `TEST_*` knobs) | Test-runner Job wiring |
| Container images | `k8s-tests/Dockerfiles/{rpm-builder,server,client,test-runner,xrootd-reference}` | Base for role/authority/runner images |
| Helm scaffolding | `k8s-tests/server-helm/`, `k8s-tests/test-infra-helm/` | Refactored into the chart layout in §4 |
| Raw manifests | `k8s-tests/k8s-manifests/` (netpol, quota, PSS, `lab-5-vms.yaml`) | Policies folded into `brix-common`; `lab-5-vms.yaml` (hardcoded `172.16.0.x`) **retired** |
| Bootstrap script | `k8s-tests/scripts/setup-minikube.sh` | Refactored into `xrd-lab` driver |

**Known anti-pattern to remove:** `lab-5-vms.yaml` pins Services to literal ClusterIPs
(`172.16.0.10` …). This is non-portable and is replaced by **stable Service DNS**.

---

## 4. Architecture

### 4.0 Chart & repository layout

```
k8s-tests/
├── xrd-lab                      # single driver script: up | deploy PROFILE | test SCENARIO | down | status
├── charts/
│   ├── brix-common/             # LIBRARY chart (helm type: library) — no deployable objects
│   │   └── templates/_*.tpl     # labels, selectors, nodePinning, netpol, quota, PSS, image ref
│   ├── brix-test-lab/           # UMBRELLA chart — depends on the subcharts below
│   │   ├── Chart.yaml           # dependencies + condition flags per subproject
│   │   └── values/
│   │       ├── values.dev.yaml      # single node, anon only
│   │       ├── values.gsi.yaml      # x509 authority plane + gsi fleet
│   │       ├── values.token.yaml    # token/JWKS + krb5
│   │       ├── values.chaos.yaml    # chaos-mesh topology
│   │       ├── values.cms.yaml      # CMS / hybrid meshes
│   │       ├── values.ceph.yaml     # Rook-Ceph backend + ceph tests
│   │       ├── values.fuse.yaml     # xrootdfs FUSE client
│   │       ├── values.perf.yaml     # pinned one-role-per-node
│   │       └── values.full.yaml     # everything on
│   ├── auth-authority/          # subchart: CA/CRL, VOMS, token/JWKS, krb5 KDC
│   ├── topology-role/           # subchart: generic role → Deployment+Service+ConfigMap
│   ├── main-fleet/              # subchart: multi-auth single-role servers + reference-xrootd
│   ├── backend-ceph/            # subchart: Rook-Ceph CephCluster + CephFS + pools (or thin wrapper)
│   └── test-runner/             # subchart: pytest Job(s) + results collection
├── images/                      # Dockerfiles (moved/renamed from Dockerfiles/)
│   ├── server/  authority/  client-fuse/  test-runner/  xrootd-reference/
├── scenarios/                   # scenario catalog (name → role set + values overlay)
│   └── catalog.yaml
└── docs/
    ├── README.md                # beginner quickstart
    ├── architecture.md          # this design, operator-facing
    └── walkthrough.md           # step-by-step first run
```

**`brix-common` (library chart)** is the single source of cross-cutting truth. Every subchart
`import`s it. It provides:

- `brix-common.labels` / `brix-common.selectorLabels` — standard `app.kubernetes.io/*` labels.
- `brix-common.nodePinning` — emits `affinity` from a `nodePinning: {mode: off|role, role: <name>}`
  values block. `off` → no constraint (portable default); `role` → `requiredDuringScheduling`
  anti-affinity that spreads distinct roles onto distinct nodes (the hybrid toggle from the
  design decision).
- `brix-common.image` — resolves `{repository, tag, pullPolicy}` with `pullPolicy: Never`
  default so in-cluster-loaded images are used (portability).
- `brix-common.netpol` / `brix-common.quota` / `brix-common.podSecurity` — folded-in versions of
  the existing `k8s-manifests/` policies, emitted once per namespace.

### 4.1 Cluster foundation (Sub-project #0)

- **minikube bootstrap** (`xrd-lab up [--profile P]`):
  - `minikube start` with a **pinned Kubernetes version** (single documented version, e.g.
    `--kubernetes-version=vX.Y.Z`), docker driver by default, `--nodes=N` where N derives from the
    profile (1 for `dev`, ≥ role-count for `perf`/pinned profiles).
  - Enable required addons (`metrics-server`; `ingress` only where a profile needs external
    reach). Ceph/FUSE profiles document extra driver requirements (see §4.6).
- **Image supply — no external registry:**
  - `xrd-lab` builds each image with `minikube image build -t <name>:<tag> images/<name>` and they
    become directly available to the cluster. `pullPolicy: Never`. This is what makes the lab
    "run anywhere" — no GHCR/registry dependency, no credentials.
  - A content tag derived from `git rev-parse --short HEAD` (or `dev`) keeps redeploys honest.
- **Profiles = values files** under `charts/brix-test-lab/values/`. A profile selects which
  subcharts are enabled (via umbrella `condition` flags) and supplies their parameters.
- **Namespacing:** one namespace per profile (`brix-<profile>`), created with PodSecurity labels
  by `brix-common`.

### 4.2 Auth-authority plane (Sub-project #1)

Modeled as **dedicated site services** the fleet reaches over the network — the production-grid
pattern, and the direct answer to "should the x509/token authorities be on their own node and
have tests pull CRLs from there": **yes**.

Components (each a Deployment + Service in the `auth-authority` subchart):

| Authority | Image basis | Serves | Consumed by |
|---|---|---|---|
| **grid-ca + CRL DP** | authority image running `pki-scripts/` + a static HTTP server | CA bundle, **CRL over HTTP** (`http://grid-ca/crl/...`) | Servers fetch/refresh CRLs; clients trust CA |
| **VOMS service** | authority image + VOMS attribute data (`lib/pki.sh` vomsdir) | VOMS `.lsc` / attribute issuance | GSI+VOMS auth tests |
| **token-issuer / JWKS** | authority image + `utils/make_token.py` | **JWKS over HTTP** (`/.well-known/...` / `/certs`), signed-token minting endpoint | Servers' `xrootd_token_jwks` points at the Service URL; clients mint tokens |
| **krb5 KDC** | MIT krb5 image + `kdc_helpers.py` | Kerberos realm, kadmin, keytabs | krb5 auth tests |

**Bootstrap flow:**

1. A **bootstrap Job** (Helm `pre-install`/`pre-upgrade` hook, or an init step in `xrd-lab deploy`)
   runs the existing provisioning scripts once and publishes:
   - **Secrets:** CA private key, host keys, host certs, KDC keytabs, token signing key.
   - **ConfigMaps:** CA bundle, VOMS `.lsc`/vomsdir, `jwks.json`, `krb5.conf`.
2. Authority Deployments mount their private material from Secrets and **serve** the public
   material (CRL, JWKS, VOMS) over HTTP.
3. Fleet servers mount the CA bundle (trust) and are configured with **URLs**, not files, for the
   dynamic material (CRL, JWKS) so refresh/rotation is exercised exactly as in production.

**x509 stance:** use the **repo's own grid CA** (from `pki-scripts/`), not cert-manager.
Rationale: cert-manager models ACME/short-lived TLS issuance and does not model grid CA + CRL
distribution + VOMS + proxy certificates. cert-manager remains an **optional** provider for
pure-TLS-only profiles that don't need the grid-security plane; it is not on the default path.

### 4.3 Topology-as-Helm; chaos-mesh reference (Sub-project #2; pattern reused by #5)

**Generic `topology-role` subchart.** A *role* is fully described by values:

```yaml
role:
  name: chaos-tier2
  image: { name: brix-server, tag: dev }
  configTemplate: chaos-tier2-cache      # selects a config template rendered to a ConfigMap
  ports: [ { name: xrootd, port: 1094 } ]
  upstreams: [ { name: UPSTREAM, service: chaos-tier3, port: 1094 } ]   # → env / config substitution
  nodePinning: { mode: off }             # or role
  readiness: { tcpPort: 1094 }
```

Each role renders to: a **ConfigMap** (nginx.conf from the matching `tests/configs/*.conf`,
with upstream host:port substituted from **Service DNS**), a **Deployment** (one pod = one
"VM"), and a **Service** (stable DNS). No hardcoded IPs — `chaos-tier1`'s upstream is the DNS
name `chaos-tier2`, etc.

**Chaos-mesh instantiation (5 roles):**

```
chaos-tier3 (storage)  ← chaos-tier2 (read-through cache)  ← chaos-tier1 (proxy)
chaos-discovery-redir (CMS manager/redirector)   chaos-discovery-ds (data server)
```

**Delayed-CMS scenario fidelity.** `test_chaos_mesh` asserts that a data server started *before*
its CMS manager fails to register, then reconnects once the manager appears. Model this with
**controlled start ordering**: the `chaos-discovery-ds` Deployment comes up while
`chaos-discovery-redir` is intentionally gated (init-container wait / delayed readiness), so the
real "failed → retried → registered" sequence occurs. The scenario driver (`xrd-lab test chaos`)
sequences the readiness gate to reproduce the exact timing the test observes.

**Test execution.** `xrd-lab test chaos` runs a `test-runner` Job with
`TEST_CHAOS_TIER1_PORT` etc. and `TEST_SERVER_HOST` pointed at the role Services, executing
`pytest tests/test_chaos_mesh.py`.

CMS meshes, hybrid mesh, and upstream/redirect chains (Sub-project #5) are **additional role
sets** in the same subchart — no new machinery.

### 4.4 Main fleet + test-runner (Sub-project #3)

- **`main-fleet` subchart:** the always-on multi-auth single-role servers — anon (`root://`),
  gsi, tls (`roots://`), token, webdav, s3, metrics — plus the **reference stock-XRootD** server
  for cross-backend parity. Each is a Deployment+Service; auth-enabled roles consume the §4.2
  authority plane.
- **`test-runner` subchart:** a pytest **Job** that sets `TEST_SERVER_HOST` + all relevant
  `TEST_*_PORT` to cluster DNS and runs the suite. Tiering mirrors `run_suite.sh`:
  - `test-runner` Job variants for `--fast`, `--pr`, `--nightly` (env-selected `-m` markers).
  - Serial/fixed-port families run in a dedicated single-lane Job (mirrors the `serial` marker
    constraint already encoded in `run_suite.sh`).
- **Results:** JUnit XML written to a results **PVC** (or `kubectl cp`/artifact out); an
  aggregation step summarizes pass/fail. Reuses the existing `test-runner/aggregate_results.py`
  shape.

### 4.5 Dedicated behavior fleets (Sub-project #4)

The 89 dedicated single-node scenarios (readonly, vo-acl, crl, tpc-ssrf, s3-presigned,
security-levels, ipv6, webdav-voms, …) are **data, not bespoke manifests**. A
`scenarios/catalog.yaml` maps each scenario name to: its config template, ports, auth mode, and
any upstream/backend refs. `xrd-lab test <scenario>` renders that entry through the generic
`topology-role` subchart, runs the matching test module(s), and tears down. This converts 89
hand-maintained fleets into one catalog + one chart.

### 4.6 External backends (Sub-project #6)

**Ceph / CephFS / RADOS** — independent, production-like:

- Deploy via the **Rook-Ceph operator** (`backend-ceph` subchart wraps/depends on Rook), creating
  a `CephCluster`, a CephFS filesystem, and RADOS pools. This replaces the docker
  `ceph_harness.sh` demo with a k8s-native, reproducible cluster.
- The `sd_ceph` storage backend and the CephFS↔RADOS interop tests target the in-cluster Ceph
  endpoints (env-wired like everything else).
- Documented resource floor: Ceph needs meaningfully more CPU/memory/disk than the other
  profiles; the `ceph` profile bumps the minikube sizing and is flagged as heavyweight.

**xrootdfs FUSE driver** — feasibility-gated:

- A **privileged client Pod** exposing `/dev/fuse` (via `securityContext` + device access) runs
  the xrootdfs mount and the FUSE-driver test set against the fleet.
- FUSE-on-minikube is the riskiest element (kernel/device access varies by driver). This section
  is explicitly **feasibility-gated**: the spec commits to the design and a documented fallback
  (run the FUSE tier against a node with `/dev/fuse`, or document the driver requirement) rather
  than promising it works on every driver. This is called out as a risk in §7.

### 4.7 Cross-cutting concerns

- **NetworkPolicy / ResourceQuota / PodSecurity:** the existing `k8s-manifests/` policies are
  folded into `brix-common` and emitted per namespace, so every profile is isolated and bounded.
- **Node pinning:** the hybrid toggle (§4.0 `brix-common.nodePinning`) is the *only* place
  pinning logic lives; profiles flip it on (`perf`, high-fidelity) or leave it off (portable).
- **Observability:** metrics Services are scrapeable; a lightweight Prometheus is an optional
  profile add-on, not required for correctness.

---

## 5. Sub-project boundaries (each becomes its own implementation plan)

Each row is an independently understandable, independently testable unit with a clear interface.
They are ordered so earlier units unblock later ones.

| # | Sub-project | Depends on | Delivers (interface) | Definition of done |
|---|---|---|---|---|
| 0 | Cluster & Helm foundation | — | `xrd-lab` script, `brix-common` library chart, umbrella chart skeleton, image build/load, `dev` profile, beginner docs | `xrd-lab up && xrd-lab deploy dev && xrd-lab test smoke` passes on a clean box; no external registry used |
| 1 | Auth-authority plane | 0 | `auth-authority` subchart; CA/CRL, VOMS, JWKS, krb5 Services + bootstrap Job publishing Secrets/ConfigMaps | A server pulls a CRL over HTTP and validates JWKS over HTTP from the authority Services; gsi + token + krb5 smoke tests pass |
| 2 | Chaos-mesh topology | 0, 1 | `topology-role` subchart + `chaos` profile; 5 roles wired by DNS; delayed-CMS ordering | `tests/test_chaos_mesh.py` passes against the cluster |
| 3 | Main fleet + test-runner | 0, 1 | `main-fleet` + `test-runner` subcharts; env-wired suite Jobs; results collection | `--fast` tier of the real suite runs green in-cluster; JUnit collected |
| 4 | Dedicated behavior fleets | 0, 1, 2 | `scenarios/catalog.yaml` + generic rendering; `xrd-lab test <scenario>` | A representative set (readonly, crl, tpc-ssrf, s3-presigned, security-level, ipv6, webdav-voms) passes |
| 5 | Remaining topologies | 2 | CMS-mesh, hybrid-mesh, upstream-chain role sets + `cms` profile | The corresponding mesh/upstream test modules pass |
| 6 | External backends (Ceph + FUSE) | 0 (Ceph), 3 (FUSE) | `backend-ceph` subchart (Rook), `ceph` + `fuse` profiles, privileged FUSE client | Ceph: `sd_ceph` + CephFS/RADOS interop tests pass; FUSE: xrootdfs test set passes **or** documented driver-gated fallback |

**Ordering recommendation:** 0 → 1 → 2 gives the first working, portable, production-fidelity
multi-node demo (the flagship chaos-mesh on real authorities). 3 broadens coverage; 4/5 reuse the
established patterns cheaply; 6 is independent and heavyweight, scheduled when the foundation is
stable.

---

## 6. Deployment profiles

| Profile | Nodes | Auth plane | Topology | Backends | Pinning | Use |
|---|---|---|---|---|---|---|
| `dev` | 1 | none/anon | main-fleet (anon) | POSIX | off | first run / iteration |
| `gsi` | 1–3 | CA/CRL/VOMS | main-fleet (gsi) | POSIX | off | x509 testing |
| `token` | 1–3 | JWKS + krb5 | main-fleet (token) | POSIX | off | token/krb5 testing |
| `chaos` | ≥5 (or 1) | token (identity-shift) | chaos-mesh 5 roles | POSIX | off / role | flagship multi-node |
| `cms` | ≥3 | none/gsi | CMS/hybrid meshes | POSIX | off / role | clustering |
| `ceph` | 1 (fat) | none | main-fleet | Rook-Ceph | off | Ceph/CephFS/RADOS |
| `fuse` | 1 | any | main-fleet | POSIX | off | xrootdfs FUSE |
| `perf` | ≥role-count | any | any | any | **role** | throughput / one-role-per-node |
| `full` | many (fat) | all | all | Rook-Ceph | role | full-fidelity soak |

---

## 7. Risks & mitigations

| Risk | Mitigation |
|---|---|
| Multi-node minikube on the docker driver has networking caveats (cross-node pod traffic, LoadBalancer) | Default profiles use free scheduling on a single node; document `--driver=kvm2`/`podman` for true multi-node pinned profiles; pinning is opt-in |
| FUSE (`/dev/fuse`) unavailable or restricted under some minikube drivers | §4.6 is feasibility-gated: privileged pod + device access first, documented driver requirement + node-local fallback if a driver blocks it |
| Rook-Ceph resource footprint too large for a laptop | `ceph`/`full` profiles document a raised minikube sizing floor and are flagged heavyweight; not part of `dev`/`chaos` |
| Delayed-CMS timing not reproducible via readiness gates | Model via init-container wait with a tunable delay; if flaky, drive the ordering explicitly from `xrd-lab test chaos` (start ds, wait, unblock redir) |
| Auth material drift between bootstrap Job and running authorities | Single bootstrap Job is the sole producer; authorities and fleet are pure consumers of its Secrets/ConfigMaps; redeploy re-runs bootstrap atomically |
| Test suite assumes localhost-only behavior somewhere despite env knobs | Validate in Sub-project 3 with the `--fast` tier first; any hardcoded host is fixed as a narrow, surfaced change (not a suite rewrite) |
| Beginner operator friction | `xrd-lab` wraps every multi-step flow; `docs/walkthrough.md` is a copy-paste first run; every profile has a one-line `deploy`/`test`/`down` |

---

## 8. What gets retired / refactored

- `k8s-tests/PLAN.md` → superseded by this spec (kept for history or removed at implementation
  time).
- `k8s-tests/k8s-manifests/lab-5-vms.yaml`, `fixed-ip-vms.yaml` → retired (hardcoded IPs);
  replaced by DNS-wired `topology-role`.
- `k8s-tests/server-helm/` → refactored into `charts/main-fleet` + `topology-role` + reuse of
  `brix-common` (no more duplicated `_helpers.tpl`).
- `k8s-tests/test-infra-helm/` → refactored into `charts/auth-authority`.
- `k8s-tests/scripts/*` → consolidated behind the `xrd-lab` driver.

---

## 9. Open questions deferred to implementation planning

- Exact pinned Kubernetes version and minikube resource defaults per profile (measured, not
  guessed).
- Whether Rook is vendored as a chart dependency or installed as a documented prerequisite in the
  `ceph` profile.
- Results artifact transport (PVC vs `kubectl cp` vs object store) — decided in Sub-project 3.
- Token-issuer service surface (static JWKS only vs a live minting endpoint) — decided in
  Sub-project 1 based on which token tests need dynamic minting.
```
