# K8s Test Lab — Sub-project #5: Remaining Topologies — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans (inline). Checkbox (`- [ ]`) steps. **No git commands** — "Checkpoint (no git)" is a verification gate.

**Goal:** Bring the remaining multi-node topologies onto the lab — CMS meshes (redirector + data-server variants, `test_manager_mode.py`/`test_cluster*.py`), upstream/redirect chains (`test_a_upstream_redirect.py`, `test_proxy_mode.py`), and the hybrid mesh (`tests/hybrid_mesh_lib.py`, `test_conformance_topologies.py`) — as additional role sets in the existing `topology-role` chart. No new machinery.

**Architecture:** Each topology is a small subchart that instantiates aliased `topology-role`s wired by Service DNS (exactly like `chaos-mesh` in #2). Configs are the repo's real `nginx_cluster_*.conf` / `nginx_upstream_*.conf` templates. Scenarios run via `test-runner` with `TEST_*` env pointed at the topology's Service DNS. Depends on #0, #1 (only where a topology needs auth), #2 (`topology-role`, `test-runner`, `brix-server`), #3 (auth plumbing if needed).

**Tech Stack:** Helm 3, helm-unittest, bats, kubeconform, pytest.

**Spec:** §4.3 (topologies #5). **Dependencies:** #0, #2. Auth-using variants also need #1/#3.

## Global Constraints

- Inherits all #0 constraints. No hardcoded IPs — Service DNS only. Real configs, unmodified tests, env-wired.

## Topologies (verified from `tests/lib/dedicated.sh`, `tests/cms_mesh_lib.py`, `tests/hybrid_mesh_lib.py`)

| Topology | Roles | Configs | Test module(s) |
|---|---|---|---|
| `cms-basic` | `manager` (redir+cms) + `ds` | `nginx_cluster_redir.conf`, `nginx_cluster_ds.conf` | `test_manager_mode.py`, `test_cluster*.py` |
| `upstream-chain` | `frontend` (proxy) + `backend` (origin) [+ stub variants] | `nginx_upstream_redirect.conf`, `nginx_upstream_waitresp.conf`, `nginx_upstream_error.conf`, `nginx_upstream_auth.conf` | `test_a_upstream_redirect.py`, `test_proxy_mode.py` |
| `hybrid-mesh` | 7 nodes (redirector `g`, nginx PSS `b`, xrootd PSS `c`, origins, S3/WebDAV front doors) per `hybrid_mesh_lib.py` PORTS band 11300–11321 | mix of cluster/proxy/webdav/s3 configs | `test_conformance_topologies.py` |

---

## File Structure

```
k8s-tests/
├── charts/cms-mesh/          { Chart.yaml, values.yaml, tests/ }         # Task 1
├── charts/upstream-chain/    { Chart.yaml, values.yaml, tests/ }         # Task 2
├── charts/hybrid-mesh/       { Chart.yaml, values.yaml, tests/ }         # Task 3
├── charts/topology-role/configs/   # + cluster/upstream/hybrid configs   # Tasks 1-3
├── charts/brix-test-lab/values/
│   ├── values.cms.yaml            # Task 4
│   └── values.hybrid.yaml         # Task 4
└── tests-bats/topologies_e2e.bats  # Task 4 (opt-in live)
```

---

## Task 1: `cms-mesh` subchart (manager + data-server)

**Files:**
- Create: `k8s-tests/charts/topology-role/configs/{cluster_redir,cluster_ds}.conf` (if not already present from #2's chaos variants — reuse `chaos-redir.conf`/`chaos-ds.conf` if identical, else add)
- Create: `k8s-tests/charts/cms-mesh/Chart.yaml`, `values.yaml`, `tests/cms_test.yaml`

**Interfaces:**
- Produces: `manager` role (listen 11101 mgr + CMS 11161) and `ds` role (listen 11162, `brix_cms_manager <manager-dns>:11161`). Service DNS `<rel>-manager`, `<rel>-ds`.

- [ ] **Step 1: Write the failing test** `charts/cms-mesh/tests/cms_test.yaml`:
```yaml
suite: cms mesh wiring
templates: [charts/ds/templates/configmap.yaml]
release: { name: brix-cms }
tests:
  - it: ds registers to the manager Service DNS
    asserts:
      - matchRegex: { path: data["nginx.conf"], pattern: "brix_cms_manager brix-cms-manager:11161" }
```

- [ ] **Step 2: Run** `helm dependency build k8s-tests/charts/cms-mesh 2>/dev/null||true; helm unittest k8s-tests/charts/cms-mesh` → FAIL.

- [ ] **Step 3: Write.** Reuse `chaos-redir.conf`/`chaos-ds.conf` as `cluster_redir.conf`/`cluster_ds.conf` (they are the same directives; if you kept chaos-specific names, add thin copies or point `configKey` at the chaos ones). `Chart.yaml`:
```yaml
apiVersion: v2
name: cms-mesh
type: application
version: 0.1.0
dependencies:
  - { name: topology-role, version: 0.1.0, repository: file://../topology-role, alias: manager }
  - { name: topology-role, version: 0.1.0, repository: file://../topology-role, alias: ds }
```
`values.yaml`:
```yaml
manager:
  role:
    name: manager
    configKey: cluster_redir
    ports: [ { name: xrootd, port: 11101 }, { name: cms, port: 11161 } ]
ds:
  role:
    name: ds
    configKey: cluster_ds
    ports: [ { name: xrootd, port: 11162 } ]
    upstreams: [ { name: CMS, service: manager, port: 11161 } ]
```

- [ ] **Step 4: Run** `helm dependency build k8s-tests/charts/cms-mesh && helm unittest k8s-tests/charts/cms-mesh` → PASS.
- [ ] **Step 5: Checkpoint (no git).**

---

## Task 2: `upstream-chain` subchart (proxy frontend + origin backend)

**Files:**
- Create: `k8s-tests/charts/topology-role/configs/{upstream_redirect,upstream_waitresp,upstream_error,upstream_auth}.conf`
- Create: `k8s-tests/charts/upstream-chain/Chart.yaml`, `values.yaml`, `tests/upstream_test.yaml`

**Interfaces:**
- Produces: `frontend` (proxy on 11120, upstream → `<rel>-backend:12120`) + `backend` (origin on 12120). The frontend's upstream directive resolves to the backend Service DNS. Variant selected by `frontend.role.configKey` (`upstream_redirect`/`upstream_waitresp`/…).

- [ ] **Step 1: Write the failing test** `tests/upstream_test.yaml`:
```yaml
suite: upstream chain wiring
templates: [charts/frontend/templates/configmap.yaml]
release: { name: brix-up }
tests:
  - it: frontend proxies to the backend Service DNS
    asserts:
      - matchRegex:
          path: data["nginx.conf"]
          pattern: "brix-up-backend:12120"
```

- [ ] **Step 2: Run** → FAIL.

- [ ] **Step 3: Write.** Import the upstream configs (mechanical transform from `tests/configs/nginx_upstream_*.conf`; the upstream host marker `{UPSTREAM_PORT}` and any host marker → `{{ .Release.Name }}-{{ (index .Values.role.upstreams 0).service }}:{{ ...port }}`). `Chart.yaml` aliases `frontend`+`backend`; `values.yaml`:
```yaml
frontend:
  role:
    name: frontend
    configKey: upstream_redirect
    ports: [ { name: xrootd, port: 11120 } ]
    upstreams: [ { name: UPSTREAM, service: backend, port: 12120 } ]
backend:
  role:
    name: backend
    configKey: anon         # a plain origin; reuse the fleet anon config
    ports: [ { name: xrootd, port: 12120 } ]
```

- [ ] **Step 4: Run** `helm dependency build k8s-tests/charts/upstream-chain && helm unittest k8s-tests/charts/upstream-chain` → PASS.
- [ ] **Step 5: Checkpoint (no git).**

---

## Task 3: `hybrid-mesh` subchart (7-node conformance topology)

**Files:**
- Create: `k8s-tests/charts/topology-role/configs/` (+ any hybrid-specific configs: dual-protocol redirector, PSS proxy, S3/WebDAV front doors — derive from `hybrid_mesh_lib.py` config builders)
- Create: `k8s-tests/charts/hybrid-mesh/Chart.yaml`, `values.yaml`, `tests/hybrid_test.yaml`

**Interfaces:**
- Produces: the 7 roles from `hybrid_mesh_lib.py` (redirector `g`, nginx PSS proxy `b`, xrootd PSS `c`, origins, S3 front door `a_s3`, WebDAV front door `a_dav`), each a `topology-role` (or a stock-xrootd Deployment for the `c` role), wired by Service DNS. Ports follow the lib's band (data 11300, cms 11301, s3 11320, dav 11321, proxy 11302 …).

- [ ] **Step 1: Write the failing test** `tests/hybrid_test.yaml`:
```yaml
suite: hybrid mesh
templates: [charts/proxy-b/templates/service.yaml]
release: { name: brix-hyb }
tests:
  - it: nginx PSS proxy role exposes its data port
    documentIndex: 0
    asserts:
      - equal: { path: spec.ports[0].port, value: 11302 }
```

- [ ] **Step 2: Run** → FAIL.

- [ ] **Step 3: Write.** Translate `hybrid_mesh_lib.py`'s config builders into `topology-role/configs/hybrid_*.conf` templates (redirector, PSS proxy, origins with S3/WebDAV listeners). Some roles are **stock xrootd** (`c` = xrootd PSS) — reuse the `brix-xrootd-ref:dev` image via a role whose image points at it and whose config is an xrootd `.cf` mounted instead of nginx.conf (add a `role.kind: xrootd` branch to `topology-role` deployment that sets the entrypoint/args accordingly, or a dedicated `stock-xrootd` mini-template). Keep it minimal: introduce `role.stockXrootd: { enabled, configFile }` handling in `topology-role/templates/deployment.yaml` that, when set, runs the reference image with the xrootd cf. `Chart.yaml` aliases the 7 roles; `values.yaml` sets ports per the lib band and `upstreams` per the topology diagram (b→g, c→g, front doors→origins).

- [ ] **Step 4: Run** `helm dependency build k8s-tests/charts/hybrid-mesh && helm unittest k8s-tests/charts/hybrid-mesh` → PASS.
- [ ] **Step 5: Checkpoint (no git).**

Note: the hybrid mesh is the heaviest topology (7 pods + a stock-xrootd redirector). It is a candidate for the `perf`/pinned profile; document that it needs `XRD_LAB_NODES>=3` for the `role` pinning mode.

---

## Task 4: Profiles + live e2e

**Files:**
- Modify: `k8s-tests/charts/brix-test-lab/Chart.yaml` (add `cms-mesh`, `upstream-chain`, `hybrid-mesh` deps, conditioned)
- Create: `k8s-tests/charts/brix-test-lab/values/values.cms.yaml`, `values.hybrid.yaml`
- Modify: `k8s-tests/xrd-lab` (scenarios `cms`, `upstream`, `hybrid` running the mapped tests)
- Create: `k8s-tests/tests-bats/topologies_e2e.bats`

**Interfaces:**
- Produces: `xrd-lab deploy cms|hybrid`; `xrd-lab test cms|upstream|hybrid` runs the mapped test modules via `test-runner`.

- [ ] **Step 1: Write the failing test** `tests-bats/topologies_e2e.bats`:
```bash
#!/usr/bin/env bats
LAB="${BATS_TEST_DIRNAME}/../xrd-lab"
setup_file() { [ "${XRD_LAB_E2E:-0}" = "1" ] || skip; "$LAB" up; }

@test "cms mesh manager_mode tests pass" {
  [ "${XRD_LAB_E2E:-0}" = "1" ] || skip
  "$LAB" deploy cms
  run "$LAB" test cms
  "$LAB" down cms || true
  [ "$status" -eq 0 ]
  [[ "$output" == *"passed"* ]]
}

@test "dry-run cms deploy wires ds to manager" {
  run env XRD_LAB_DRY_RUN=1 "$LAB" test cms
  [ "$status" -eq 0 ]
  [[ "$output" == *"test_manager_mode"* || "$output" == *"cms"* ]]
}
```

- [ ] **Step 2: Run** → FAIL.

- [ ] **Step 3: Implement.** Umbrella deps:
```yaml
  - { name: cms-mesh,       version: 0.1.0, repository: file://../cms-mesh,       condition: cms-mesh.enabled }
  - { name: upstream-chain, version: 0.1.0, repository: file://../upstream-chain, condition: upstream-chain.enabled }
  - { name: hybrid-mesh,    version: 0.1.0, repository: file://../hybrid-mesh,    condition: hybrid-mesh.enabled }
```
`values.cms.yaml`: `{ cms-mesh: { enabled: true }, smoke: { enabled: false } }`. `values.hybrid.yaml`: `{ hybrid-mesh: { enabled: true }, smoke: { enabled: false } }`. Add `xrd-lab` scenarios that helm-install `test-runner` with the mapped selection and per-role `TEST_*_HOST/PORT` env (manager→`<rel>-manager`, ds→`<rel>-ds`, etc.), wait, report. As with #2, verify/add per-role host env overrides in `settings.py` where the test module assumes a single host (surfaced narrow change per spec §7).

- [ ] **Step 4: Run tests.**
```bash
bats k8s-tests/tests-bats/topologies_e2e.bats   # dry-run passes, live skips
shellcheck k8s-tests/xrd-lab
helm dependency build k8s-tests/charts/brix-test-lab
helm template brix-cms k8s-tests/charts/brix-test-lab -f k8s-tests/charts/brix-test-lab/values/values.cms.yaml | kubeconform -strict -summary
```
Live:
```bash
XRD_LAB_E2E=1 bats k8s-tests/tests-bats/topologies_e2e.bats
XRD_LAB_E2E=1 XRD_LAB_NODES=3 bash -c 'k8s-tests/xrd-lab up && k8s-tests/xrd-lab deploy hybrid && k8s-tests/xrd-lab test hybrid'
```
Expected: cms + upstream pass; hybrid passes on a ≥3-node cluster (or single node without pinning).

- [ ] **Step 5: Checkpoint (no git).**

---

## Final verification (Sub-project #5)

- [ ] `helm unittest` green for `cms-mesh`, `upstream-chain`, `hybrid-mesh`.
- [ ] `helm template ... | kubeconform -strict -summary` → `Invalid: 0` for cms + hybrid profiles.
- [ ] `XRD_LAB_E2E=1`: `test_manager_mode.py`/`test_cluster*.py` (cms), `test_a_upstream_redirect.py`/`test_proxy_mode.py` (upstream), `test_conformance_topologies.py` (hybrid) pass.
- [ ] **DoD (spec §5 row 5):** the mesh/upstream/hybrid test modules pass. ✅

## Self-review notes

- **Spec coverage:** §4.3/#5 CMS meshes → Task 1; upstream chains → Task 2; hybrid mesh → Task 3; profiles + gates → Task 4. Reuses `topology-role` (#2) and `test-runner` (#2/#3) with zero new machinery beyond the `role.stockXrootd` branch for the hybrid `c` role.
- **Placeholder scan:** the hybrid config translation from `hybrid_mesh_lib.py` and the `settings.py` per-role host env addition are explicit, bounded implementation steps with stated resolutions, not TODOs.
- **Name consistency:** role Service DNS `<release>-<role>` and `configKey`→`configs/<key>.conf` identical to #2/#3/#4; CMS port 11161 and upstream port 12120 match `tests/lib/dedicated.sh` defaults; hybrid ports match `hybrid_mesh_lib.py` PORTS band.
```
