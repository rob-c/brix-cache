# K8s Test Lab — Sub-project #6: Ceph/CephFS/RADOS + FUSE Backends — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans (inline). Checkbox (`- [ ]`) steps. **No git commands** — "Checkpoint (no git)" is a verification gate.

**Goal:** Test the nginx-xrootd `sd_ceph` backend against a real in-cluster **Ceph/CephFS/RADOS** cluster, and exercise the **xrootdfs FUSE** driver against the deployed fleet — both reproducibly on minikube, replacing the Docker `ceph_harness.sh` and host-FUSE workflows.

**Architecture:** Ceph is deployed by the **Rook-Ceph operator** (`backend-ceph` subchart wrapping Rook), producing a `CephCluster` + a RADOS pool (`xrdtest`) + CephFS. A `ceph-connect` bootstrap Job extracts `ceph.conf` + admin keyring into a Secret the ceph-backed server role mounts; that role runs the `brix-server-ceph` image (librados-enabled) with `brix_storage_backend ceph:`. FUSE runs as a **privileged client Pod** (`/dev/fuse`, `fusermount3`) that builds `client/bin/xrootdfs` and runs `tests/test_xrootdfs*.py` against the fleet's anon Service. Depends on #0, #2 (`test-runner`, `brix-server`), #3 (fleet for the FUSE target).

**Tech Stack:** Helm 3, helm-unittest, bats, kubeconform, Rook-Ceph, librados, FUSE (libfuse3), pytest.

**Spec:** §4.6. **Dependencies:** #0, #2; FUSE target needs #3's fleet (or any anon role).

## Global Constraints

- Inherits all #0 constraints.
- **Ceph and FUSE profiles are heavyweight and documented as such.** The `ceph`/`full` profiles raise minikube sizing; FUSE requires a driver that exposes `/dev/fuse`.
- **FUSE is feasibility-gated** (spec §7): the privileged-pod approach is primary; if a minikube driver blocks `/dev/fuse`, the plan's tests **skip cleanly** (mirroring `test_xrootdfs.py`'s own `_FUSE_OK` gate) and the fallback (kvm2/bare-node with `/dev/fuse`) is documented — a skip is an acceptable DoD outcome with the reason recorded, not a failure.
- Real tests, unmodified, env-wired.

## Verified specifics

- Ceph backend scheme: `brix_storage_backend ceph:` / `rados://`; `sd_ceph` connects via librados using `CEPH_CONF` + `CEPH_KEYRING` + `CEPH_POOL` (`tests/ceph_harness.sh`, default pool `xrdtest`).
- FUSE: `xrootdfs root://host[:port]/ /mnt`; built via `make -C client bin/xrootdfs`; gated by `/dev/fuse` + `fusermount3`; `XROOTDFS_BIN` env selects the driver (`tests/test_xrootdfs.py`).

---

## File Structure

```
k8s-tests/
├── images/
│   ├── server-ceph/Dockerfile                   # brix-server + librados (Task 3)
│   └── client-fuse/Dockerfile                    # client build tree + libfuse3 + xrootd-client (Task 5)
├── charts/backend-ceph/
│   ├── Chart.yaml                                # dependency: rook-ceph (or documented prereq)
│   ├── values.yaml
│   ├── templates/
│   │   ├── cephcluster.yaml                       # CephCluster + CephBlockPool + CephFilesystem (Task 1)
│   │   ├── connect-job.yaml                        # extract ceph.conf+keyring -> Secret (Task 2)
│   │   └── ceph-server.yaml                         # ceph-backed nginx-xrootd role (Task 3)
│   └── tests/
│       ├── cephcluster_test.yaml
│       └── ceph_server_test.yaml
├── charts/fuse-client/
│   ├── Chart.yaml
│   ├── values.yaml
│   ├── templates/pod.yaml                          # privileged FUSE pod (Task 5)
│   └── tests/pod_test.yaml
├── charts/brix-test-lab/values/
│   ├── values.ceph.yaml                            # Task 4
│   └── values.fuse.yaml                            # Task 6
└── tests-bats/
    ├── ceph_e2e.bats                               # Task 4 (opt-in live, heavyweight)
    └── fuse_e2e.bats                                # Task 6 (opt-in live, driver-gated)
```

---

## Task 1: `backend-ceph` — Rook CephCluster + pool + CephFS

**Files:**
- Create: `k8s-tests/charts/backend-ceph/Chart.yaml`, `values.yaml`
- Create: `k8s-tests/charts/backend-ceph/templates/cephcluster.yaml`
- Create: `k8s-tests/charts/backend-ceph/tests/cephcluster_test.yaml`

**Interfaces:**
- Consumes: the Rook-Ceph operator (installed as a prerequisite — see Step 3 note).
- Produces: a `CephCluster` (single-node, directory/hostPath OSD for minikube), a `CephBlockPool` `xrdtest` (RADOS), and a `CephFilesystem` `xrdfs`. These CRs are what `sd_ceph` ultimately talks to.

- [ ] **Step 1: Write the failing test** `tests/cephcluster_test.yaml`:
```yaml
suite: ceph cluster CRs
templates: [templates/cephcluster.yaml]
release: { name: brix-ceph }
tests:
  - it: creates a single-mon CephCluster
    documentIndex: 0
    asserts:
      - equal: { path: kind, value: CephCluster }
      - equal: { path: spec.mon.count, value: 1 }
  - it: creates the xrdtest RADOS pool
    documentIndex: 1
    asserts:
      - equal: { path: kind, value: CephBlockPool }
      - equal: { path: metadata.name, value: xrdtest }
```

- [ ] **Step 2: Run** `helm unittest k8s-tests/charts/backend-ceph` → FAIL.

- [ ] **Step 3: Write.** `Chart.yaml` (Rook operator is a documented prerequisite installed by `xrd-lab`, not vendored, to keep this chart light):
```yaml
apiVersion: v2
name: backend-ceph
description: Rook-Ceph CephCluster + RADOS pool + CephFS for the sd_ceph backend
type: application
version: 0.1.0
```
`values.yaml`:
```yaml
ceph:
  image: quay.io/ceph/ceph:v18
  dataDirHostPath: /var/lib/rook
  pool: xrdtest
  filesystem: xrdfs
  monCount: 1
  osdCount: 1
```
`templates/cephcluster.yaml`:
```yaml
apiVersion: ceph.rook.io/v1
kind: CephCluster
metadata:
  name: {{ .Release.Name }}-ceph
  labels: {{- include "brix-common.labels" . | nindent 4 }}
spec:
  cephVersion: { image: {{ .Values.ceph.image }} }
  dataDirHostPath: {{ .Values.ceph.dataDirHostPath }}
  mon: { count: {{ .Values.ceph.monCount }}, allowMultiplePerNode: true }
  mgr: { count: 1 }
  dashboard: { enabled: false }
  storage:
    useAllNodes: true
    useAllDevices: false
    # minikube: OSD on a directory (no raw device) — set at deploy per node
    directories:
      - path: {{ .Values.ceph.dataDirHostPath }}/osd
---
apiVersion: ceph.rook.io/v1
kind: CephBlockPool
metadata:
  name: {{ .Values.ceph.pool }}
  labels: {{- include "brix-common.labels" . | nindent 4 }}
spec:
  failureDomain: osd
  replicated: { size: 1, requireSafeReplicaSize: false }
---
apiVersion: ceph.rook.io/v1
kind: CephFilesystem
metadata:
  name: {{ .Values.ceph.filesystem }}
  labels: {{- include "brix-common.labels" . | nindent 4 }}
spec:
  metadataPool: { replicated: { size: 1, requireSafeReplicaSize: false } }
  dataPools: [ { replicated: { size: 1, requireSafeReplicaSize: false } } ]
  metadataServer: { activeCount: 1, activeStandby: false }
```

Because Rook CRDs aren't in kubeconform's default schema, add `--ignore-missing-schemas` when validating this chart (record in Step 4). The Rook operator itself is installed by `xrd-lab` for the ceph profile:
```bash
helm repo add rook-release https://charts.rook.io/release
helm upgrade --install rook-ceph rook-release/rook-ceph --namespace rook-ceph --create-namespace
```
(This is the one profile that pulls a public chart; it is an operator, not one of *our* images, so it does not violate the no-external-registry rule for app images. Document the network requirement for the `ceph` profile.)

- [ ] **Step 4: Run** `helm dependency build k8s-tests/charts/backend-ceph 2>/dev/null||true; helm unittest k8s-tests/charts/backend-ceph` → PASS; `helm template brix-ceph k8s-tests/charts/backend-ceph | kubeconform -strict -ignore-missing-schemas -summary` → no hard errors.
- [ ] **Step 5: Checkpoint (no git).**

---

## Task 2: `ceph-connect` Job — extract ceph.conf + keyring into a Secret

**Files:**
- Create: `k8s-tests/charts/backend-ceph/templates/connect-job.yaml`
- Add suite `tests/connect_test.yaml`

**Interfaces:**
- Produces: Secret `<rel>-ceph-conn` with keys `ceph.conf`, `keyring`, and env-friendly `CEPH_POOL`. The ceph-backed server (Task 3) mounts it at `/etc/ceph`.
- Consumes: the running Rook cluster (uses Rook's `rook-ceph-tools` or `ceph` CLI to emit a minimal `ceph.conf` + client keyring).

- [ ] **Step 1: Write the failing test** `tests/connect_test.yaml`:
```yaml
suite: ceph connect job
templates: [templates/connect-job.yaml]
release: { name: brix-ceph }
tests:
  - it: is a post-install hook that writes the conn secret
    asserts:
      - isKind: { of: Job }
      - equal: { path: metadata.annotations["helm.sh/hook"], value: post-install,post-upgrade }
      - matchRegex: { path: spec.template.spec.containers[0].args[0], pattern: "kubectl create secret generic brix-ceph-ceph-conn" }
```

- [ ] **Step 2: Run** → FAIL.

- [ ] **Step 3: Write** `templates/connect-job.yaml` — a post-install hook Job (service account with secret-write RBAC, reuse the pattern from #1 Task 3) that runs inside the cluster, derives `ceph.conf` (mon endpoints from the Rook mon Service) + a client keyring (`ceph auth get-or-create client.xrd mon 'allow r' osd 'allow rwx pool=xrdtest'`), and `kubectl create secret generic <rel>-ceph-conn --from-file=ceph.conf=... --from-file=keyring=... --dry-run=client -o yaml | kubectl apply -f -`. Use the `rook/ceph` tools image (has the ceph CLI) plus kubectl; run in the `rook-ceph`-aware namespace with the mon endpoints discovered from the `rook-ceph-mon-endpoints` ConfigMap.

- [ ] **Step 4: Run** `helm unittest k8s-tests/charts/backend-ceph` → PASS.
- [ ] **Step 5: Checkpoint (no git).**

---

## Task 3: `brix-server-ceph` image + ceph-backed server role

**Files:**
- Create: `k8s-tests/images/server-ceph/Dockerfile`
- Create: `k8s-tests/charts/backend-ceph/templates/ceph-server.yaml`
- Create: `k8s-tests/charts/topology-role/configs/ceph.conf`
- Add suite `tests/ceph_server_test.yaml`

**Interfaces:**
- Produces image `brix-server-ceph:dev` (the server image + `librados`). Produces a `topology-role`-style Deployment+Service `<rel>-ceph-server` running `brix_storage_backend ceph:` and mounting the `<rel>-ceph-conn` Secret at `/etc/ceph`.

- [ ] **Step 1: Write the failing test** `tests/ceph_server_test.yaml`:
```yaml
suite: ceph server role
templates: [templates/ceph-server.yaml]
release: { name: brix-ceph }
tests:
  - it: mounts the ceph conn secret and uses the ceph backend
    documentIndex: 0
    asserts:
      - contains:
          path: spec.template.spec.volumes
          content: { name: ceph, secret: { secretName: brix-ceph-ceph-conn } }
```
And a topology-role config suite asserting `configs/ceph.conf` emits `brix_storage_backend ceph:`.

- [ ] **Step 2: Run** → FAIL.

- [ ] **Step 3: Write.**

`images/server-ceph/Dockerfile`:
```dockerfile
FROM brix-server:dev
USER root
RUN dnf install -y librados2 libradospp || microdnf install -y librados2 libradospp || true
```
(If the base `brix-server` was compiled without ceph support, the ceph backend must be enabled at module-configure time; in that case build `server-ceph` from the same multistage as #2 Task 1 with `--with` ceph and librados-devel present. Record this fork; verify the module's ceph backend build flag at implementation time.)

`configs/ceph.conf` (topology-role config):
```nginx
worker_processes auto;
events { worker_connections 1024; }
stream {
  server {
    listen {{ (index .Values.role.ports 0).port }};
    brix_root on;
    brix_storage_backend ceph:{{ .Values.role.data.pool | default "xrdtest" }};
    brix_auth none;
    brix_allow_write on;
  }
}
```
`templates/ceph-server.yaml` — a Deployment+Service (reuse `topology-role` by aliasing it in this chart, OR inline a minimal Deployment) that sets image `brix-server-ceph:dev`, mounts Secret `<rel>-ceph-conn` at `/etc/ceph`, env `CEPH_CONF=/etc/ceph/ceph.conf`, `CEPH_KEYRING=/etc/ceph/keyring`, `CEPH_POOL=xrdtest`. Preferred: add `backend-ceph` as an aliased `topology-role` dependency (`ceph-server`) fed `role.configKey: ceph` + `role.auth`-style secret mount via a small `role.cephSecret` addition to `topology-role` deployment (guarded, mounts the Secret at /etc/ceph). Add that `role.cephSecret` branch to `topology-role/templates/deployment.yaml`.

- [ ] **Step 4: Run** `helm unittest k8s-tests/charts/backend-ceph k8s-tests/charts/topology-role` → PASS.
- [ ] **Step 5: Checkpoint (no git).**

---

## Task 4: Ceph profile + live e2e (heavyweight)

**Files:**
- Modify: `k8s-tests/charts/brix-test-lab/Chart.yaml` (add `backend-ceph` dep, conditioned)
- Create: `k8s-tests/charts/brix-test-lab/values/values.ceph.yaml`
- Modify: `k8s-tests/xrd-lab` (ceph profile: bigger minikube, install Rook, build `brix-server-ceph`; `test ceph` scenario)
- Create: `k8s-tests/tests-bats/ceph_e2e.bats`

**Interfaces:**
- Produces: `xrd-lab deploy ceph` (installs Rook, CephCluster, ceph server); `xrd-lab test ceph` runs a `root://` put/get + the ceph/RADOS interop tests against `<rel>-ceph-server`.

- [ ] **Step 1: Write the failing test** `tests-bats/ceph_e2e.bats`:
```bash
#!/usr/bin/env bats
LAB="${BATS_TEST_DIRNAME}/../xrd-lab"
setup_file() { [ "${XRD_LAB_E2E_CEPH:-0}" = "1" ] || skip "set XRD_LAB_E2E_CEPH=1 (heavyweight)"; XRD_LAB_MEM=8192 "$LAB" up; "$LAB" deploy ceph; }
teardown_file() { [ "${XRD_LAB_E2E_CEPH:-0}" = "1" ] && "$LAB" down ceph || true; }

@test "root:// put/get round-trips through the ceph backend" {
  [ "${XRD_LAB_E2E_CEPH:-0}" = "1" ] || skip
  run "$LAB" test ceph
  [ "$status" -eq 0 ]
  [[ "$output" == *"ceph OK"* ]]
}

@test "dry-run ceph deploy installs rook and the ceph server" {
  run env XRD_LAB_DRY_RUN=1 "$LAB" deploy ceph
  [ "$status" -eq 0 ]
  [[ "$output" == *"rook-ceph"* ]]
}
```

- [ ] **Step 2: Run** → FAIL.

- [ ] **Step 3: Implement.** Umbrella dep `backend-ceph` (condition `backend-ceph.enabled`). `values.ceph.yaml`: `{ backend-ceph: { enabled: true }, smoke: { enabled: false } }`. In `xrd-lab`: a `ceph`-profile branch in `cmd_deploy` that (a) raises minikube memory (`XRD_LAB_MEM` default bumped for ceph), (b) `helm upgrade --install rook-ceph rook-release/rook-ceph -n rook-ceph --create-namespace` and waits for the operator, (c) builds `brix-server-ceph:dev`, (d) installs the umbrella with `values.ceph.yaml`. Add `scenario_ceph`: an ephemeral `xrdcp` put/get against `<rel>-ceph-server:1094` asserting byte-identical round-trip (`ceph OK`), plus optionally the `tests/ceph/*_smoke.sh` interop checks via a runner Job with `CEPH_CONF`/`CEPH_KEYRING` from the conn Secret.

- [ ] **Step 4: Run tests.**
```bash
bats k8s-tests/tests-bats/ceph_e2e.bats     # dry-run passes, live skips unless XRD_LAB_E2E_CEPH=1
shellcheck k8s-tests/xrd-lab
helm template brix-ceph k8s-tests/charts/brix-test-lab -f k8s-tests/charts/brix-test-lab/values/values.ceph.yaml | kubeconform -strict -ignore-missing-schemas -summary
```
Live (needs a beefy machine):
```bash
XRD_LAB_E2E_CEPH=1 bats k8s-tests/tests-bats/ceph_e2e.bats
```
Expected: Rook cluster reaches HEALTH_OK/WARN, ceph server serves a `root://` round-trip (`ceph OK`).

- [ ] **Step 5: Checkpoint (no git).**

---

## Task 5: `client-fuse` image + privileged FUSE pod

**Files:**
- Create: `k8s-tests/images/client-fuse/Dockerfile`
- Create: `k8s-tests/charts/fuse-client/Chart.yaml`, `values.yaml`, `templates/pod.yaml`, `tests/pod_test.yaml`

**Interfaces:**
- Produces image `brix-client-fuse:dev` (repo `client/` tree + build toolchain + libfuse3 + fusermount3 + xrootd-client + pytest + `tests/`). Produces a Pod with `securityContext.privileged: true` and `/dev/fuse` access that can build+run `xrootdfs`.

- [ ] **Step 1: Write the failing test** `tests/pod_test.yaml`:
```yaml
suite: fuse client pod
templates: [templates/pod.yaml]
release: { name: brix-fuse }
tests:
  - it: runs privileged with /dev/fuse
    asserts:
      - equal: { path: spec.containers[0].securityContext.privileged, value: true }
      - contains:
          path: spec.containers[0].volumeDevices
          content: { name: fuse, devicePath: /dev/fuse }
```
(If `volumeDevices` for `/dev/fuse` is awkward, assert a `hostPath` `/dev/fuse` volume + mount instead; adjust the test to match the chosen mechanism.)

- [ ] **Step 2: Run** → FAIL.

- [ ] **Step 3: Write.** `images/client-fuse/Dockerfile` (context = repo root):
```dockerfile
FROM almalinux:9
RUN dnf install -y gcc make fuse3 fuse3-devel xrootd-client openssl-devel python3 python3-pip krb5-devel && dnf clean all
RUN python3 -m pip install --no-cache-dir pytest
WORKDIR /opt/brix
COPY client/ /opt/brix/client/
COPY tests/  /opt/brix/tests/
COPY utils/  /opt/brix/utils/
ENV PYTHONPATH=/opt/brix/tests
CMD ["sleep","infinity"]
```
`templates/pod.yaml` — a Pod (not Deployment; it's a one-shot test host) with:
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: {{ .Release.Name }}-fuse-client
  labels: {{- include "brix-common.labels" . | nindent 4 }}
spec:
  restartPolicy: Never
  containers:
    - name: fuse
      image: "{{ .Values.image.repository }}:{{ .Values.image.tag }}"
      imagePullPolicy: {{ .Values.image.pullPolicy | default "Never" }}
      securityContext:
        privileged: true
      command: ["sleep","infinity"]
      volumeMounts:
        - { name: fuse, mountPath: /dev/fuse }
  volumes:
    - name: fuse
      hostPath: { path: /dev/fuse, type: CharDevice }
```
Note: the FUSE profile namespace must NOT enforce restricted PodSecurity (privileged pod); `xrd-lab` labels the `brix-fuse` namespace `pod-security.kubernetes.io/enforce=privileged`.

- [ ] **Step 4: Run** `helm dependency build k8s-tests/charts/fuse-client && helm unittest k8s-tests/charts/fuse-client` → PASS.
- [ ] **Step 5: Checkpoint (no git).**

---

## Task 6: FUSE profile + live e2e (driver-gated)

**Files:**
- Modify: `k8s-tests/charts/brix-test-lab/Chart.yaml` (add `fuse-client` dep, conditioned)
- Create: `k8s-tests/charts/brix-test-lab/values/values.fuse.yaml`
- Modify: `k8s-tests/xrd-lab` (fuse profile: privileged ns; `test fuse` scenario builds xrootdfs in-pod and runs test_xrootdfs)
- Create: `k8s-tests/tests-bats/fuse_e2e.bats`

**Interfaces:**
- Produces: `xrd-lab deploy fuse` (fleet anon + fuse client pod); `xrd-lab test fuse` execs into the pod, builds `client/bin/xrootdfs`, and runs `pytest tests/test_xrootdfs.py` with `TEST_SERVER_HOST=<fleet-anon-dns>`. Cleanly skips when `/dev/fuse` is unavailable.

- [ ] **Step 1: Write the failing test** `tests-bats/fuse_e2e.bats`:
```bash
#!/usr/bin/env bats
LAB="${BATS_TEST_DIRNAME}/../xrd-lab"
setup_file() { [ "${XRD_LAB_E2E:-0}" = "1" ] || skip; "$LAB" up; "$LAB" deploy fuse; }
teardown_file() { [ "${XRD_LAB_E2E:-0}" = "1" ] && "$LAB" down fuse || true; }

@test "xrootdfs FUSE tests pass or skip cleanly" {
  [ "${XRD_LAB_E2E:-0}" = "1" ] || skip
  run "$LAB" test fuse
  # pass OR clean skip are both acceptable (feasibility-gated)
  [[ "$output" == *"passed"* || "$output" == *"skipped"* ]]
}

@test "dry-run fuse test execs xrootdfs build + pytest in the pod" {
  run env XRD_LAB_DRY_RUN=1 "$LAB" test fuse
  [ "$status" -eq 0 ]
  [[ "$output" == *"make -C"* || "$output" == *"xrootdfs"* ]]
  [[ "$output" == *"test_xrootdfs"* ]]
}
```

- [ ] **Step 2: Run** → FAIL.

- [ ] **Step 3: Implement.** Umbrella dep `fuse-client` (condition). `values.fuse.yaml`: `{ main-fleet: { enabled: true, anon: { enabled: true } }, auth-authority: { enabled: false }, fuse-client: { enabled: true }, smoke: { enabled: false } }`. `xrd-lab` `fuse` profile labels the namespace `pod-security.kubernetes.io/enforce=privileged`. `scenario_fuse`:
```bash
scenario_fuse() {
    local ns="brix-fuse" pod="brix-fuse-fuse-client"
    if [ "$DRY_RUN" = "1" ]; then
        echo "kubectl -n $ns exec $pod -- make -C /opt/brix/client bin/xrootdfs"
        echo "kubectl -n $ns exec $pod -- env TEST_SERVER_HOST=brix-fuse-anon pytest tests/test_xrootdfs.py -p no:xdist -v"
        return 0
    fi
    kubectl -n "$ns" wait --for=condition=ready "pod/$pod" --timeout=180s
    kubectl -n "$ns" exec "$pod" -- make -C /opt/brix/client bin/xrootdfs
    kubectl -n "$ns" exec "$pod" -- env TEST_SERVER_HOST=brix-fuse-anon PYTHONPATH=/opt/brix/tests \
        pytest tests/test_xrootdfs.py -p no:xdist -v
}
```
Register `fuse)` in `cmd_test`.

- [ ] **Step 4: Run tests.**
```bash
bats k8s-tests/tests-bats/fuse_e2e.bats     # dry-run passes, live skips
shellcheck k8s-tests/xrd-lab
helm template brix-fuse k8s-tests/charts/brix-test-lab -f k8s-tests/charts/brix-test-lab/values/values.fuse.yaml | kubeconform -strict -summary
```
Live:
```bash
XRD_LAB_E2E=1 bats k8s-tests/tests-bats/fuse_e2e.bats
```
Expected: `test_xrootdfs.py` passes, or skips cleanly if the driver blocks `/dev/fuse` (record which — a clean skip is an acceptable feasibility-gated outcome; try `--driver=kvm2` to obtain `/dev/fuse` if a pass is required).

- [ ] **Step 5: Checkpoint (no git).**

---

## Final verification (Sub-project #6)

- [ ] `helm unittest` green for `backend-ceph`, `fuse-client`, and the `topology-role` ceph config suite.
- [ ] `helm template ... | kubeconform -strict -ignore-missing-schemas -summary` clean for ceph + fuse profiles.
- [ ] `XRD_LAB_E2E_CEPH=1 bats k8s-tests/tests-bats/ceph_e2e.bats` → `ceph OK` (Rook healthy, root:// round-trip through ceph backend).
- [ ] `XRD_LAB_E2E=1 bats k8s-tests/tests-bats/fuse_e2e.bats` → `test_xrootdfs.py` passes, or clean skip with the driver reason recorded.
- [ ] **DoD (spec §5 row 6):** Ceph — `sd_ceph` + CephFS/RADOS interop tests pass against Rook; FUSE — xrootdfs test set passes, or documented driver-gated fallback. ✅

## Self-review notes

- **Spec coverage:** §4.6 Ceph via Rook operator → Tasks 1,2,4; librados server + `ceph:` backend → Task 3; FUSE privileged pod + `/dev/fuse` → Tasks 5,6; feasibility-gating (clean skip acceptable) honored in Task 6 + Global Constraints, matching spec §7.
- **Placeholder scan:** implementation-time forks (base-image ceph build flag; `/dev/fuse` as `volumeDevices` vs `hostPath`) are explicit with stated resolutions and test adjustments, not TODOs. Rook is a documented public-chart prerequisite (operator, not an app image) — the no-registry rule for *our* images is preserved.
- **Name consistency:** conn Secret `<rel>-ceph-conn` defined in Task 2 used in Task 3; pool `xrdtest` matches `tests/ceph_harness.sh`; `configKey: ceph`→`configs/ceph.conf` matches the #2/#3/#4 convention; `role.cephSecret` branch added to `topology-role` (Task 3) mirrors the `role.auth` pattern from #3.
```
