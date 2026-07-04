# K8s Test Lab — Sub-project #0: Cluster & Helm Foundation — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the portable minikube + Helm foundation for the nginx-xrootd Kubernetes test lab — a `brix-common` library chart, an umbrella chart with profile values, a registry-free image build/load path, and a single `xrd-lab` driver — proven end-to-end by a minimal smoke deployment.

**Architecture:** A Helm *library* chart (`brix-common`) holds every cross-cutting helper (labels, image ref, node-pinning toggle, NetworkPolicy, ResourceQuota). Application subcharts consume it. An umbrella chart (`brix-test-lab`) composes subcharts and selects them per **profile** (a values file). A single bash driver (`xrd-lab`) wraps `minikube start` (pinned version), in-cluster `minikube image build` (no external registry), `helm upgrade --install`, and a smoke check. This sub-project ships only the foundation plus a throwaway-grade `smoke` app that exercises every mechanism; real server/authority images and charts arrive in later sub-projects.

**Tech Stack:** minikube, kubectl, docker, Helm 3, `helm-unittest` (chart unit tests), `bats-core` (bash tests), `kubeconform` (manifest schema validation), `yq`, `shellcheck`, bash.

**Spec:** `docs/superpowers/specs/2026-07-04-k8s-test-lab-design.md` — this plan implements §4.0 (chart/repo layout), §4.1 (cluster foundation), and the §4.7 cross-cutting policies. Sub-projects #1–#6 get their own plans and depend on the artifacts produced here.

## Global Constraints

- **Kubernetes version is pinned.** Default `XRD_LAB_K8S_VERSION=v1.31.4`; every `minikube start` passes `--kubernetes-version="$XRD_LAB_K8S_VERSION"`. Overridable by env, never hardcoded in more than one place.
- **No external image registry for our images.** App images are built with `minikube image build` and consumed with `imagePullPolicy: Never`. Base images pulled *during* `docker`/`minikube` build (e.g. `almalinux:9-minimal`) are permitted — the constraint forbids hosting/pulling *our* images through GHCR/DockerHub, not building from public bases.
- **Everything is namespaced per profile.** Namespace name is `brix-<profile>`. Namespaces carry PodSecurity Standard labels (`pod-security.kubernetes.io/enforce=baseline` for the lab; `restricted` where a profile can afford it).
- **All shell is `set -euo pipefail` and `shellcheck`-clean.** Small single-purpose functions, explicit args, early return — consistent with the repo coding ethos.
- **Chart repo root:** `k8s-tests/charts/`. Images: `k8s-tests/images/`. Driver: `k8s-tests/xrd-lab`. Docs: `k8s-tests/README.md`, `k8s-tests/docs/`.
- **Cross-cutting policy lives once**, in `brix-common`. No subchart re-implements labels/pinning/netpol/quota.

---

## File Structure

Created by this sub-project:

```
k8s-tests/
├── xrd-lab                                  # driver: up | deploy PROFILE | test SCENARIO | status | down  (Task 7,8)
├── tools/
│   └── require-tools.sh                      # verifies helm/bats/kubeconform/yq/shellcheck/minikube/kubectl/docker/jq (Task 0)
├── images/
│   └── smoke/
│       ├── Dockerfile                        # almalinux:9-minimal + nginx serving /healthz (Task 5)
│       └── nginx-smoke.conf                  # minimal nginx.conf with /healthz -> 200 (Task 5)
├── charts/
│   ├── brix-common/                          # LIBRARY chart — helpers only, no deployable objects
│   │   ├── Chart.yaml                         # type: library (Task 1)
│   │   └── templates/
│   │       ├── _names.tpl                     # name/fullname/chart (Task 1)
│   │       ├── _labels.tpl                    # labels/selectorLabels (Task 1)
│   │       ├── _image.tpl                     # image ref + pullPolicy (Task 2)
│   │       ├── _pinning.tpl                   # nodePinning affinity toggle (Task 3)
│   │       ├── _netpol.tpl                    # default NetworkPolicy (Task 4)
│   │       └── _quota.tpl                     # ResourceQuota (Task 4)
│   ├── smoke/                                # APP subchart consuming brix-common (Tasks 1-4)
│   │   ├── Chart.yaml                          # dependency: brix-common (file://../brix-common)
│   │   ├── values.yaml
│   │   ├── templates/
│   │   │   ├── deployment.yaml
│   │   │   ├── service.yaml
│   │   │   ├── networkpolicy.yaml
│   │   │   └── resourcequota.yaml
│   │   └── tests/                              # helm-unittest suites
│   │       ├── deployment_test.yaml
│   │       ├── image_test.yaml
│   │       ├── pinning_test.yaml
│   │       └── policy_test.yaml
│   └── brix-test-lab/                         # UMBRELLA chart (Task 6)
│       ├── Chart.yaml                          # dependency: smoke (condition smoke.enabled)
│       ├── values.yaml                         # safe defaults (all subcharts off)
│       ├── values/
│       │   └── values.dev.yaml                 # dev profile: smoke on
│       └── tests/
│           └── umbrella_test.yaml
├── tests-bats/
│   ├── require_tools.bats                     # Task 0
│   ├── smoke_image.bats                       # Task 5
│   ├── xrd_lab_unit.bats                      # Task 7 (dry-run, no cluster)
│   └── xrd_lab_e2e.bats                       # Task 8 (real minikube, opt-in)
├── README.md                                  # beginner quickstart (Task 9)
└── docs/
    └── walkthrough.md                         # copy-paste first run (Task 9)
```

Retired by this sub-project (Task 9): `k8s-tests/k8s-manifests/lab-5-vms.yaml`, `k8s-tests/k8s-manifests/fixed-ip-vms.yaml`, `k8s-tests/xrd-k8s` (superseded by `xrd-lab`).

---

## Task 0: Prerequisite tooling + repo scaffolding

**Files:**
- Create: `k8s-tests/tools/require-tools.sh`
- Create: `k8s-tests/tests-bats/require_tools.bats`
- Create dirs: `k8s-tests/charts/`, `k8s-tests/images/`, `k8s-tests/scenarios/`, `k8s-tests/docs/`, `k8s-tests/tests-bats/`

**Interfaces:**
- Produces: `tools/require-tools.sh` — exits `0` when all required tools are present, exits `1` and prints `MISSING: <tool>` lines otherwise. Honors `REQUIRE_TOOLS_LIST` env override (space-separated) for testing.

- [ ] **Step 1: Install the missing host tooling**

These are the TDD frameworks used by every later task. Run:

```bash
# Helm 3 (static binary)
curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
# helm-unittest plugin (chart unit tests)
helm plugin install https://github.com/helm-unittest/helm-unittest
# bats-core (bash test runner)
sudo apt-get update && sudo apt-get install -y bats shellcheck
# kubeconform (manifest schema validation) + yq (YAML query)
KV=v0.6.7; curl -fsSL "https://github.com/yannh/kubeconform/releases/download/${KV}/kubeconform-linux-amd64.tar.gz" | sudo tar -xz -C /usr/local/bin kubeconform
YQV=v4.44.3; sudo curl -fsSL -o /usr/local/bin/yq "https://github.com/mikefarah/yq/releases/download/${YQV}/yq_linux_amd64" && sudo chmod +x /usr/local/bin/yq
```

- [ ] **Step 2: Write the failing test**

Create `k8s-tests/tests-bats/require_tools.bats`:

```bash
#!/usr/bin/env bats

SCRIPT="${BATS_TEST_DIRNAME}/../tools/require-tools.sh"

@test "passes when every required tool is present" {
  run bash "$SCRIPT"
  [ "$status" -eq 0 ]
}

@test "fails and names a tool that is absent" {
  run env REQUIRE_TOOLS_LIST="definitely_not_a_real_binary_xyz" bash "$SCRIPT"
  [ "$status" -eq 1 ]
  [[ "$output" == *"MISSING: definitely_not_a_real_binary_xyz"* ]]
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `bats k8s-tests/tests-bats/require_tools.bats`
Expected: FAIL — `require-tools.sh` does not exist yet (`No such file or directory`).

- [ ] **Step 4: Write the minimal implementation**

Create `k8s-tests/tools/require-tools.sh`:

```bash
#!/usr/bin/env bash
# require-tools.sh — verify the host has every tool the k8s test lab needs.
set -euo pipefail

DEFAULT_TOOLS="minikube kubectl docker helm bats kubeconform yq jq shellcheck"
tools="${REQUIRE_TOOLS_LIST:-$DEFAULT_TOOLS}"

missing=0
for tool in $tools; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "MISSING: $tool" >&2
        missing=1
    fi
done

if [ "$missing" -ne 0 ]; then
    echo "One or more required tools are missing. See install notes in k8s-tests/README.md." >&2
    exit 1
fi
echo "All required tools present."
```

Then: `chmod +x k8s-tests/tools/require-tools.sh` and create the empty scaffolding dirs:

```bash
mkdir -p k8s-tests/charts k8s-tests/images k8s-tests/scenarios k8s-tests/docs k8s-tests/tests-bats
```

- [ ] **Step 5: Run test to verify it passes**

Run: `bats k8s-tests/tests-bats/require_tools.bats`
Expected: PASS (2 tests). If the first test fails with a `MISSING:` line, install that tool from Step 1 before proceeding.

Also run: `shellcheck k8s-tests/tools/require-tools.sh` → Expected: no output (clean).

- [ ] **Step 6: Commit**

```bash
git add k8s-tests/tools/require-tools.sh k8s-tests/tests-bats/require_tools.bats
git commit -m "build(k8s): tool prerequisite check + bats scaffolding for the test lab"
```

---

## Task 1: `brix-common` library chart + `smoke` consumer with standard labels

A Helm helper is not testable without a consumer, so this task creates the library chart **and** a minimal `smoke` application chart that renders a Deployment using the helpers. We assert on `smoke`'s rendered output with `helm-unittest`.

**Files:**
- Create: `k8s-tests/charts/brix-common/Chart.yaml`
- Create: `k8s-tests/charts/brix-common/templates/_names.tpl`
- Create: `k8s-tests/charts/brix-common/templates/_labels.tpl`
- Create: `k8s-tests/charts/smoke/Chart.yaml`
- Create: `k8s-tests/charts/smoke/values.yaml`
- Create: `k8s-tests/charts/smoke/templates/deployment.yaml`
- Create: `k8s-tests/charts/smoke/tests/deployment_test.yaml`

**Interfaces:**
- Produces (named templates, consumed by every later chart):
  - `brix-common.name` → chart/release base name (string)
  - `brix-common.fullname` → `<release>-<name>` truncated to 63 (string)
  - `brix-common.chart` → `<chart>-<version>` (string)
  - `brix-common.labels` → standard `app.kubernetes.io/*` label block (multi-line YAML; caller `nindent`s it)
  - `brix-common.selectorLabels` → `app.kubernetes.io/name` + `app.kubernetes.io/instance` (multi-line YAML)
  - All helpers take the **root context** (`.` / `$`) as their single argument.

- [ ] **Step 1: Write the failing test**

Create `k8s-tests/charts/smoke/tests/deployment_test.yaml`:

```yaml
suite: smoke deployment — identity and labels
templates:
  - templates/deployment.yaml
release:
  name: rel
tests:
  - it: names the Deployment <release>-smoke
    asserts:
      - isKind:
          of: Deployment
      - equal:
          path: metadata.name
          value: rel-smoke
  - it: applies the standard app.kubernetes.io labels
    asserts:
      - equal:
          path: metadata.labels["app.kubernetes.io/name"]
          value: smoke
      - equal:
          path: metadata.labels["app.kubernetes.io/instance"]
          value: rel
      - equal:
          path: metadata.labels["app.kubernetes.io/managed-by"]
          value: Helm
  - it: selector matches template labels
    asserts:
      - equal:
          path: spec.selector.matchLabels["app.kubernetes.io/name"]
          value: smoke
      - equal:
          path: spec.template.metadata.labels["app.kubernetes.io/name"]
          value: smoke
```

- [ ] **Step 2: Run test to verify it fails**

Run:
```bash
helm dependency build k8s-tests/charts/smoke 2>/dev/null || true
helm unittest k8s-tests/charts/smoke
```
Expected: FAIL — chart/templates do not exist yet (`Error: ... no such file`).

- [ ] **Step 3: Write the minimal implementation**

`k8s-tests/charts/brix-common/Chart.yaml`:
```yaml
apiVersion: v2
name: brix-common
description: Shared library chart (labels, image, node-pinning, policies) for the nginx-xrootd test lab
type: library
version: 0.1.0
```

`k8s-tests/charts/brix-common/templates/_names.tpl`:
```yaml
{{/*
brix-common.name — base name for all resources (the consuming chart's name).
*/}}
{{- define "brix-common.name" -}}
{{- .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
brix-common.fullname — <release>-<name>, truncated to the 63-char k8s limit.
*/}}
{{- define "brix-common.fullname" -}}
{{- printf "%s-%s" .Release.Name (include "brix-common.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
brix-common.chart — <chart>-<version>, sanitised for a label value.
*/}}
{{- define "brix-common.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}
```

`k8s-tests/charts/brix-common/templates/_labels.tpl`:
```yaml
{{/*
brix-common.labels — full standard label set. Caller nindents the result.
*/}}
{{- define "brix-common.labels" -}}
helm.sh/chart: {{ include "brix-common.chart" . }}
{{ include "brix-common.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | default .Chart.Version | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: brix-test-lab
{{- end -}}

{{/*
brix-common.selectorLabels — the stable identity used by selectors.
*/}}
{{- define "brix-common.selectorLabels" -}}
app.kubernetes.io/name: {{ include "brix-common.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
```

`k8s-tests/charts/smoke/Chart.yaml`:
```yaml
apiVersion: v2
name: smoke
description: Minimal deployable that exercises the brix-common foundation end-to-end
type: application
version: 0.1.0
appVersion: "0.1.0"
dependencies:
  - name: brix-common
    version: 0.1.0
    repository: file://../brix-common
```

`k8s-tests/charts/smoke/values.yaml`:
```yaml
image:
  repository: brix-smoke
  tag: dev
  pullPolicy: Never
service:
  port: 8080
nodePinning:
  mode: off        # off | role
resources:
  requests: { cpu: 25m, memory: 32Mi }
  limits:   { cpu: 100m, memory: 64Mi }
networkPolicy:
  enabled: true
resourceQuota:
  enabled: false
```

`k8s-tests/charts/smoke/templates/deployment.yaml`:
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ include "brix-common.fullname" . }}
  labels:
    {{- include "brix-common.labels" . | nindent 4 }}
spec:
  replicas: 1
  selector:
    matchLabels:
      {{- include "brix-common.selectorLabels" . | nindent 6 }}
  template:
    metadata:
      labels:
        {{- include "brix-common.labels" . | nindent 8 }}
    spec:
      containers:
        - name: smoke
          image: "{{ .Values.image.repository }}:{{ .Values.image.tag }}"
          ports:
            - name: http
              containerPort: {{ .Values.service.port }}
```

- [ ] **Step 4: Run test to verify it passes**

Run:
```bash
helm dependency build k8s-tests/charts/smoke
helm unittest k8s-tests/charts/smoke
```
Expected: PASS (3 tests in the suite).

- [ ] **Step 5: Commit**

```bash
git add k8s-tests/charts/brix-common k8s-tests/charts/smoke
git commit -m "feat(k8s): brix-common library chart (names+labels) + smoke consumer"
```

---

## Task 2: `brix-common.image` helper — image ref + `imagePullPolicy`

**Files:**
- Create: `k8s-tests/charts/brix-common/templates/_image.tpl`
- Modify: `k8s-tests/charts/smoke/templates/deployment.yaml` (use the helper)
- Create: `k8s-tests/charts/smoke/tests/image_test.yaml`

**Interfaces:**
- Consumes: `.Values.image.{repository,tag,pullPolicy}` on the calling chart.
- Produces:
  - `brix-common.image` → `"<repository>:<tag>"` string (given the root context; reads `.Values.image`).
  - `brix-common.imagePullPolicy` → `.Values.image.pullPolicy` defaulted to `Never`.

- [ ] **Step 1: Write the failing test**

Create `k8s-tests/charts/smoke/tests/image_test.yaml`:

```yaml
suite: smoke image reference
templates:
  - templates/deployment.yaml
release:
  name: rel
tests:
  - it: renders repository:tag from values
    set:
      image.repository: brix-smoke
      image.tag: abc123
    asserts:
      - equal:
          path: spec.template.spec.containers[0].image
          value: brix-smoke:abc123
  - it: defaults pull policy to Never (registry-free lab)
    asserts:
      - equal:
          path: spec.template.spec.containers[0].imagePullPolicy
          value: Never
  - it: honors an explicit pull policy override
    set:
      image.pullPolicy: IfNotPresent
    asserts:
      - equal:
          path: spec.template.spec.containers[0].imagePullPolicy
          value: IfNotPresent
```

- [ ] **Step 2: Run test to verify it fails**

Run: `helm unittest k8s-tests/charts/smoke -f tests/image_test.yaml`
Expected: FAIL — `imagePullPolicy` is absent from the rendered Deployment.

- [ ] **Step 3: Write the minimal implementation**

Create `k8s-tests/charts/brix-common/templates/_image.tpl`:
```yaml
{{/*
brix-common.image — "<repository>:<tag>" for the calling chart's .Values.image.
*/}}
{{- define "brix-common.image" -}}
{{- printf "%s:%s" .Values.image.repository .Values.image.tag -}}
{{- end -}}

{{/*
brix-common.imagePullPolicy — pull policy, defaulting to Never (images are
loaded straight into the node by `minikube image build`, never pulled).
*/}}
{{- define "brix-common.imagePullPolicy" -}}
{{- .Values.image.pullPolicy | default "Never" -}}
{{- end -}}
```

Modify the container block in `k8s-tests/charts/smoke/templates/deployment.yaml`:
```yaml
        - name: smoke
          image: {{ include "brix-common.image" . | quote }}
          imagePullPolicy: {{ include "brix-common.imagePullPolicy" . }}
          ports:
            - name: http
              containerPort: {{ .Values.service.port }}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `helm unittest k8s-tests/charts/smoke`
Expected: PASS (all suites, including the new 3 image tests).

- [ ] **Step 5: Commit**

```bash
git add k8s-tests/charts/brix-common/templates/_image.tpl k8s-tests/charts/smoke
git commit -m "feat(k8s): brix-common.image helper with Never-default pull policy"
```

---

## Task 3: `brix-common.nodePinning` — the per-profile one-role-per-node toggle

Implements the spec's hybrid node-pinning decision: `mode: off` (portable default, no constraint) or `mode: role` (each lab pod lands on its own node via pod anti-affinity on `topologyKey: kubernetes.io/hostname`, selecting all lab pods via `app.kubernetes.io/part-of: brix-test-lab`).

**Files:**
- Create: `k8s-tests/charts/brix-common/templates/_pinning.tpl`
- Modify: `k8s-tests/charts/smoke/templates/deployment.yaml` (inject affinity)
- Create: `k8s-tests/charts/smoke/tests/pinning_test.yaml`

**Interfaces:**
- Consumes: `.Values.nodePinning.mode` (`off`|`role`) on the calling chart.
- Produces: `brix-common.nodePinning` → emits an `affinity:` block when mode is `role`, and emits **nothing** when mode is `off`. Caller places it at `spec.template.spec` level.

- [ ] **Step 1: Write the failing test**

Create `k8s-tests/charts/smoke/tests/pinning_test.yaml`:

```yaml
suite: node pinning toggle
templates:
  - templates/deployment.yaml
release:
  name: rel
tests:
  - it: adds no affinity when pinning is off (portable default)
    set:
      nodePinning.mode: off
    asserts:
      - isNull:
          path: spec.template.spec.affinity
  - it: pins one lab pod per node when mode is role
    set:
      nodePinning.mode: role
    asserts:
      - equal:
          path: spec.template.spec.affinity.podAntiAffinity.requiredDuringSchedulingIgnoredDuringExecution[0].topologyKey
          value: kubernetes.io/hostname
      - equal:
          path: spec.template.spec.affinity.podAntiAffinity.requiredDuringSchedulingIgnoredDuringExecution[0].labelSelector.matchLabels["app.kubernetes.io/part-of"]
          value: brix-test-lab
```

- [ ] **Step 2: Run test to verify it fails**

Run: `helm unittest k8s-tests/charts/smoke -f tests/pinning_test.yaml`
Expected: FAIL — no `affinity` handling exists; the `role` case finds nothing at the affinity path.

- [ ] **Step 3: Write the minimal implementation**

Create `k8s-tests/charts/brix-common/templates/_pinning.tpl`:
```yaml
{{/*
brix-common.nodePinning — hybrid one-role-per-node toggle.
  mode: off  -> emit nothing (scheduler places pods freely; portable).
  mode: role -> pod anti-affinity so no two lab pods share a node, giving
                one-container-per-VM when the cluster has >= role-count nodes.
Caller inserts the result under spec.template.spec.
*/}}
{{- define "brix-common.nodePinning" -}}
{{- if eq (.Values.nodePinning.mode | default "off") "role" -}}
affinity:
  podAntiAffinity:
    requiredDuringSchedulingIgnoredDuringExecution:
      - topologyKey: kubernetes.io/hostname
        labelSelector:
          matchLabels:
            app.kubernetes.io/part-of: brix-test-lab
{{- end -}}
{{- end -}}
```

Modify `k8s-tests/charts/smoke/templates/deployment.yaml` — add the pinning include at the `spec.template.spec` level, immediately above `containers:`:
```yaml
    spec:
      {{- include "brix-common.nodePinning" . | nindent 6 }}
      containers:
```

- [ ] **Step 4: Run test to verify it passes**

Run: `helm unittest k8s-tests/charts/smoke`
Expected: PASS (all suites). The `off` case renders no `affinity:` key; the `role` case renders the anti-affinity block.

- [ ] **Step 5: Commit**

```bash
git add k8s-tests/charts/brix-common/templates/_pinning.tpl k8s-tests/charts/smoke
git commit -m "feat(k8s): brix-common.nodePinning per-profile one-role-per-node toggle"
```

---

## Task 4: `brix-common.networkPolicy` + `brix-common.resourceQuota` + smoke Service

Adds the cross-cutting isolation policies (spec §4.7) and the Service the smoke check reaches.

**Files:**
- Create: `k8s-tests/charts/brix-common/templates/_netpol.tpl`
- Create: `k8s-tests/charts/brix-common/templates/_quota.tpl`
- Create: `k8s-tests/charts/smoke/templates/service.yaml`
- Create: `k8s-tests/charts/smoke/templates/networkpolicy.yaml`
- Create: `k8s-tests/charts/smoke/templates/resourcequota.yaml`
- Create: `k8s-tests/charts/smoke/tests/policy_test.yaml`

**Interfaces:**
- Consumes: `.Values.networkPolicy.enabled`, `.Values.resourceQuota.enabled`, `.Values.service.port`.
- Produces:
  - `brix-common.networkPolicy` → a `NetworkPolicy` that default-denies ingress and allows traffic only from pods in the same namespace (label `app.kubernetes.io/part-of: brix-test-lab`).
  - `brix-common.resourceQuota` → a `ResourceQuota` with lab-sane hard limits.

- [ ] **Step 1: Write the failing test**

Create `k8s-tests/charts/smoke/tests/policy_test.yaml`:

```yaml
suite: service + isolation policies
release:
  name: rel
tests:
  - it: exposes the smoke port on a Service
    templates:
      - templates/service.yaml
    set:
      service.port: 8080
    asserts:
      - isKind:
          of: Service
      - equal:
          path: spec.ports[0].port
          value: 8080
      - equal:
          path: spec.selector["app.kubernetes.io/name"]
          value: smoke
  - it: allows only in-lab ingress via NetworkPolicy
    templates:
      - templates/networkpolicy.yaml
    set:
      networkPolicy.enabled: true
    asserts:
      - isKind:
          of: NetworkPolicy
      - equal:
          path: spec.ingress[0].from[0].podSelector.matchLabels["app.kubernetes.io/part-of"]
          value: brix-test-lab
  - it: renders no NetworkPolicy when disabled
    templates:
      - templates/networkpolicy.yaml
    set:
      networkPolicy.enabled: false
    asserts:
      - hasDocuments:
          count: 0
  - it: caps namespace resources when quota is enabled
    templates:
      - templates/resourcequota.yaml
    set:
      resourceQuota.enabled: true
    asserts:
      - isKind:
          of: ResourceQuota
      - isNotEmpty:
          path: spec.hard["limits.cpu"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `helm unittest k8s-tests/charts/smoke -f tests/policy_test.yaml`
Expected: FAIL — the service/networkpolicy/resourcequota templates do not exist.

- [ ] **Step 3: Write the minimal implementation**

`k8s-tests/charts/brix-common/templates/_netpol.tpl`:
```yaml
{{/*
brix-common.networkPolicy — default-deny ingress, allow only same-lab pods.
*/}}
{{- define "brix-common.networkPolicy" -}}
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: {{ include "brix-common.fullname" . }}-allow-lab
  labels:
    {{- include "brix-common.labels" . | nindent 4 }}
spec:
  podSelector:
    matchLabels:
      {{- include "brix-common.selectorLabels" . | nindent 6 }}
  policyTypes:
    - Ingress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app.kubernetes.io/part-of: brix-test-lab
{{- end -}}
```

`k8s-tests/charts/brix-common/templates/_quota.tpl`:
```yaml
{{/*
brix-common.resourceQuota — lab-sane hard caps for a profile namespace.
*/}}
{{- define "brix-common.resourceQuota" -}}
apiVersion: v1
kind: ResourceQuota
metadata:
  name: {{ include "brix-common.fullname" . }}-quota
  labels:
    {{- include "brix-common.labels" . | nindent 4 }}
spec:
  hard:
    requests.cpu: "8"
    requests.memory: 16Gi
    limits.cpu: "16"
    limits.memory: 32Gi
    pods: "50"
{{- end -}}
```

`k8s-tests/charts/smoke/templates/service.yaml`:
```yaml
apiVersion: v1
kind: Service
metadata:
  name: {{ include "brix-common.fullname" . }}
  labels:
    {{- include "brix-common.labels" . | nindent 4 }}
spec:
  type: ClusterIP
  selector:
    {{- include "brix-common.selectorLabels" . | nindent 4 }}
  ports:
    - name: http
      port: {{ .Values.service.port }}
      targetPort: http
      protocol: TCP
```

`k8s-tests/charts/smoke/templates/networkpolicy.yaml`:
```yaml
{{- if .Values.networkPolicy.enabled }}
{{ include "brix-common.networkPolicy" . }}
{{- end }}
```

`k8s-tests/charts/smoke/templates/resourcequota.yaml`:
```yaml
{{- if .Values.resourceQuota.enabled }}
{{ include "brix-common.resourceQuota" . }}
{{- end }}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `helm unittest k8s-tests/charts/smoke`
Expected: PASS (all four suites).

- [ ] **Step 5: Commit**

```bash
git add k8s-tests/charts/brix-common/templates/_netpol.tpl k8s-tests/charts/brix-common/templates/_quota.tpl k8s-tests/charts/smoke
git commit -m "feat(k8s): brix-common netpol+quota helpers, smoke Service"
```

---

## Task 5: `images/smoke` — the registry-free local image

**Files:**
- Create: `k8s-tests/images/smoke/Dockerfile`
- Create: `k8s-tests/images/smoke/nginx-smoke.conf`
- Create: `k8s-tests/tests-bats/smoke_image.bats`

**Interfaces:**
- Produces: a Docker image tag `brix-smoke:dev` serving HTTP `200` at `/healthz` on port `8080`. Consumed by the `smoke` chart (`image.repository: brix-smoke`) and by `xrd-lab test smoke`.

- [ ] **Step 1: Write the failing test**

Create `k8s-tests/tests-bats/smoke_image.bats`:

```bash
#!/usr/bin/env bats

IMG_DIR="${BATS_TEST_DIRNAME}/../images/smoke"
TAG="brix-smoke:batstest"

setup() {
  docker build -q -t "$TAG" "$IMG_DIR" >/dev/null
}

teardown() {
  cid="$(cat "${BATS_TEST_TMPDIR}/cid" 2>/dev/null || true)"
  [ -n "$cid" ] && docker rm -f "$cid" >/dev/null 2>&1 || true
  docker rmi -f "$TAG" >/dev/null 2>&1 || true
}

@test "smoke image serves 200 at /healthz" {
  cid="$(docker run -d -p 18080:8080 "$TAG")"
  echo "$cid" > "${BATS_TEST_TMPDIR}/cid"
  # wait for readiness (up to ~10s)
  for _ in $(seq 1 20); do
    code="$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:18080/healthz || true)"
    [ "$code" = "200" ] && break
    sleep 0.5
  done
  [ "$code" = "200" ]
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bats k8s-tests/tests-bats/smoke_image.bats`
Expected: FAIL — `docker build` fails because `images/smoke/Dockerfile` does not exist.

- [ ] **Step 3: Write the minimal implementation**

`k8s-tests/images/smoke/nginx-smoke.conf`:
```nginx
worker_processes 1;
events { worker_connections 64; }
http {
  server {
    listen 8080;
    location /healthz { return 200 "ok\n"; }
    location / { return 200 "brix smoke\n"; }
  }
}
```

`k8s-tests/images/smoke/Dockerfile`:
```dockerfile
# smoke — minimal, registry-free image proving the build/load/deploy path.
# Same base family as the real server image so it is not a foreign throwaway.
FROM almalinux:9-minimal
RUN microdnf install -y nginx && microdnf clean all
COPY nginx-smoke.conf /etc/nginx/nginx.conf
EXPOSE 8080
CMD ["nginx", "-g", "daemon off;"]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `bats k8s-tests/tests-bats/smoke_image.bats`
Expected: PASS (1 test). The container answers `/healthz` with HTTP 200.

- [ ] **Step 5: Commit**

```bash
git add k8s-tests/images/smoke k8s-tests/tests-bats/smoke_image.bats
git commit -m "build(k8s): registry-free smoke image serving /healthz"
```

---

## Task 6: `brix-test-lab` umbrella chart + `dev` profile

**Files:**
- Create: `k8s-tests/charts/brix-test-lab/Chart.yaml`
- Create: `k8s-tests/charts/brix-test-lab/values.yaml`
- Create: `k8s-tests/charts/brix-test-lab/values/values.dev.yaml`
- Create: `k8s-tests/charts/brix-test-lab/tests/umbrella_test.yaml`

**Interfaces:**
- Consumes: the `smoke` subchart (Task 1–4) and, transitively, `brix-common`.
- Produces: an installable umbrella whose subcharts are gated by `<subchart>.enabled`. `values/values.dev.yaml` is the `dev` **profile** consumed by `xrd-lab deploy dev` (Task 8). Convention locked here: `xrd-lab deploy <profile>` runs `helm upgrade --install brix-<profile> charts/brix-test-lab -f charts/brix-test-lab/values/values.<profile>.yaml`.

- [ ] **Step 1: Write the failing test**

Create `k8s-tests/charts/brix-test-lab/tests/umbrella_test.yaml`:

```yaml
suite: umbrella profile gating
templates:
  - charts/smoke/templates/deployment.yaml
release:
  name: brix-dev
tests:
  - it: renders the smoke subchart when enabled
    set:
      smoke.enabled: true
    asserts:
      - isKind:
          of: Deployment
      - equal:
          path: metadata.name
          value: brix-dev-smoke
  - it: renders nothing from smoke when disabled
    set:
      smoke.enabled: false
    asserts:
      - hasDocuments:
          count: 0
```

- [ ] **Step 2: Run test to verify it fails**

Run:
```bash
helm dependency build k8s-tests/charts/brix-test-lab 2>/dev/null || true
helm unittest k8s-tests/charts/brix-test-lab
```
Expected: FAIL — umbrella chart does not exist yet.

- [ ] **Step 3: Write the minimal implementation**

`k8s-tests/charts/brix-test-lab/Chart.yaml`:
```yaml
apiVersion: v2
name: brix-test-lab
description: Umbrella chart composing the nginx-xrootd Kubernetes test lab per profile
type: application
version: 0.1.0
appVersion: "0.1.0"
dependencies:
  - name: smoke
    version: 0.1.0
    repository: file://../smoke
    condition: smoke.enabled
```

`k8s-tests/charts/brix-test-lab/values.yaml` (safe defaults — everything off):
```yaml
# Default profile renders nothing; a profile values file turns subcharts on.
smoke:
  enabled: false
```

`k8s-tests/charts/brix-test-lab/values/values.dev.yaml`:
```yaml
# dev profile — single-node smoke deployment proving the foundation.
smoke:
  enabled: true
  image:
    repository: brix-smoke
    tag: dev
    pullPolicy: Never
  nodePinning:
    mode: off
  networkPolicy:
    enabled: true
  resourceQuota:
    enabled: false
```

- [ ] **Step 4: Run test to verify it passes, then validate rendering**

Run:
```bash
helm dependency build k8s-tests/charts/brix-test-lab
helm unittest k8s-tests/charts/brix-test-lab
helm lint k8s-tests/charts/brix-test-lab -f k8s-tests/charts/brix-test-lab/values/values.dev.yaml
helm template brix-dev k8s-tests/charts/brix-test-lab \
  -f k8s-tests/charts/brix-test-lab/values/values.dev.yaml \
  | kubeconform -strict -summary -kubernetes-version "$(echo "${XRD_LAB_K8S_VERSION:-v1.31.4}" | tr -d v)"
```
Expected: unittest PASS (2 tests); `helm lint` reports `0 chart(s) failed`; `kubeconform` prints `Valid: N` with `Invalid: 0, Errors: 0`.

- [ ] **Step 5: Commit**

```bash
git add k8s-tests/charts/brix-test-lab
git commit -m "feat(k8s): brix-test-lab umbrella chart + dev profile"
```

---

## Task 7: `xrd-lab` driver — command surface + dry-run core (no cluster needed)

The driver's command-building logic is unit-testable without a cluster: a `XRD_LAB_DRY_RUN=1` mode prints the exact `minikube`/`docker`/`helm`/`kubectl` command lines instead of running them.

**Files:**
- Create: `k8s-tests/xrd-lab`
- Create: `k8s-tests/tests-bats/xrd_lab_unit.bats`

**Interfaces:**
- Produces: `xrd-lab <command> [args]` with commands `up`, `deploy <profile>`, `test <scenario>`, `status`, `down`, `help`. Env knobs: `XRD_LAB_K8S_VERSION` (default `v1.31.4`), `XRD_LAB_NODES` (default `1`), `XRD_LAB_DRIVER` (default `docker`), `XRD_LAB_DRY_RUN` (when `1`, print commands, run nothing). Namespace convention: `brix-<profile>`.

- [ ] **Step 1: Write the failing test**

Create `k8s-tests/tests-bats/xrd_lab_unit.bats`:

```bash
#!/usr/bin/env bats

LAB="${BATS_TEST_DIRNAME}/../xrd-lab"

run_dry() { env XRD_LAB_DRY_RUN=1 "$LAB" "$@"; }

@test "up starts minikube with the pinned version and node count" {
  run run_dry up
  [ "$status" -eq 0 ]
  [[ "$output" == *"minikube start"* ]]
  [[ "$output" == *"--kubernetes-version=v1.31.4"* ]]
  [[ "$output" == *"--nodes=1"* ]]
}

@test "up honors XRD_LAB_NODES override" {
  run env XRD_LAB_DRY_RUN=1 XRD_LAB_NODES=5 "$LAB" up
  [[ "$output" == *"--nodes=5"* ]]
}

@test "deploy builds the smoke image into minikube and helm-installs the profile" {
  run run_dry deploy dev
  [ "$status" -eq 0 ]
  [[ "$output" == *"minikube image build"* ]]
  [[ "$output" == *"brix-smoke:dev"* ]]
  [[ "$output" == *"helm upgrade --install brix-dev"* ]]
  [[ "$output" == *"values/values.dev.yaml"* ]]
  [[ "$output" == *"--namespace brix-dev"* ]]
}

@test "deploy requires a profile argument" {
  run run_dry deploy
  [ "$status" -ne 0 ]
  [[ "$output" == *"profile"* ]]
}

@test "down deletes the profile release and namespace" {
  run run_dry down dev
  [[ "$output" == *"helm uninstall brix-dev"* ]]
  [[ "$output" == *"kubectl delete namespace brix-dev"* ]]
}

@test "unknown command exits non-zero with usage" {
  run run_dry frobnicate
  [ "$status" -ne 0 ]
  [[ "$output" == *"Usage:"* ]]
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bats k8s-tests/tests-bats/xrd_lab_unit.bats`
Expected: FAIL — `xrd-lab` does not exist.

- [ ] **Step 3: Write the minimal implementation**

Create `k8s-tests/xrd-lab`:
```bash
#!/usr/bin/env bash
# xrd-lab — driver for the nginx-xrootd Kubernetes test lab.
#   up               start the minikube cluster (pinned version)
#   deploy <profile> build images into the cluster + helm-install the profile
#   test <scenario>  run a scenario check against a deployed profile
#   status           show cluster + lab resources
#   down <profile>   uninstall a profile and delete its namespace
set -euo pipefail

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHART_DIR="$LAB_DIR/charts/brix-test-lab"

K8S_VERSION="${XRD_LAB_K8S_VERSION:-v1.31.4}"
NODES="${XRD_LAB_NODES:-1}"
DRIVER="${XRD_LAB_DRIVER:-docker}"
DRY_RUN="${XRD_LAB_DRY_RUN:-0}"

# run — execute a command, or print it verbatim under dry-run.
run() {
    if [ "$DRY_RUN" = "1" ]; then
        echo "$*"
    else
        "$@"
    fi
}

usage() {
    cat >&2 <<EOF
Usage: xrd-lab <command> [args]
  up                 Start the minikube cluster (k8s ${K8S_VERSION}, ${NODES} node(s))
  deploy <profile>   Build images into the cluster and helm-install the profile
  test <scenario>    Run a scenario check (e.g. smoke) against a deployed profile
  status             Show cluster nodes and lab resources
  down <profile>     Uninstall a profile release and delete its namespace
Env: XRD_LAB_K8S_VERSION XRD_LAB_NODES XRD_LAB_DRIVER XRD_LAB_DRY_RUN
EOF
}

cmd_up() {
    run minikube start --driver="$DRIVER" --nodes="$NODES" \
        --kubernetes-version="$K8S_VERSION"
    run minikube addons enable metrics-server
}

# build_images — build every image this profile needs straight into the node.
build_images() {
    run minikube image build -t brix-smoke:dev "$LAB_DIR/images/smoke"
}

cmd_deploy() {
    local profile="${1:-}"
    if [ -z "$profile" ]; then
        echo "error: deploy requires a <profile> argument" >&2
        usage
        return 2
    fi
    local ns="brix-${profile}"
    local values="$CHART_DIR/values/values.${profile}.yaml"
    build_images
    run kubectl create namespace "$ns" --dry-run=client -o yaml
    run kubectl label namespace "$ns" \
        pod-security.kubernetes.io/enforce=baseline --overwrite
    run helm dependency build "$CHART_DIR"
    run helm upgrade --install "brix-${profile}" "$CHART_DIR" \
        --namespace "$ns" --create-namespace \
        --values "$values" --wait --timeout 5m
}

cmd_down() {
    local profile="${1:-}"
    if [ -z "$profile" ]; then
        echo "error: down requires a <profile> argument" >&2
        usage
        return 2
    fi
    run helm uninstall "brix-${profile}" --namespace "brix-${profile}"
    run kubectl delete namespace "brix-${profile}" --ignore-not-found
}

cmd_status() {
    run kubectl get nodes -o wide
    run kubectl get pods -A -l app.kubernetes.io/part-of=brix-test-lab
}

main() {
    local command="${1:-help}"
    shift || true
    case "$command" in
        up)     cmd_up "$@" ;;
        deploy) cmd_deploy "$@" ;;
        test)   cmd_test "$@" ;;   # defined in Task 8
        status) cmd_status "$@" ;;
        down)   cmd_down "$@" ;;
        help|-h|--help) usage ;;
        *)      echo "error: unknown command '$command'" >&2; usage; return 2 ;;
    esac
}

main "$@"
```

Note: `cmd_test` is referenced but implemented in Task 8. To keep this task's `case` valid before Task 8, add a temporary stub directly above `main`:
```bash
cmd_test() { echo "error: 'test' is implemented in Task 8" >&2; return 2; }
```
(Task 8 Step 3 replaces this stub with the real function.)

Then: `chmod +x k8s-tests/xrd-lab`.

- [ ] **Step 4: Run test to verify it passes**

Run:
```bash
bats k8s-tests/tests-bats/xrd_lab_unit.bats
shellcheck k8s-tests/xrd-lab
```
Expected: bats PASS (6 tests); `shellcheck` clean (no output).

- [ ] **Step 5: Commit**

```bash
git add k8s-tests/xrd-lab k8s-tests/tests-bats/xrd_lab_unit.bats
git commit -m "feat(k8s): xrd-lab driver command surface with dry-run core"
```

---

## Task 8: `xrd-lab test smoke` + real end-to-end run

Implements the real `test` path and proves the whole foundation against a live minikube. The e2e bats test is **opt-in** (guarded by `XRD_LAB_E2E=1`) because it needs a running Docker/minikube and takes minutes.

**Files:**
- Modify: `k8s-tests/xrd-lab` (replace the `cmd_test` stub with the real implementation)
- Create: `k8s-tests/tests-bats/xrd_lab_e2e.bats`

**Interfaces:**
- Consumes: a deployed `dev` profile (Task 6/7) and the smoke image (Task 5).
- Produces: `xrd-lab test smoke` → exits `0` iff the smoke Service answers HTTP `200` at `/healthz`. Under `XRD_LAB_DRY_RUN=1` it prints the `kubectl`/curl commands it would run.

- [ ] **Step 1: Write the failing test**

Create `k8s-tests/tests-bats/xrd_lab_e2e.bats`:

```bash
#!/usr/bin/env bats
# Opt-in end-to-end test: requires Docker + minikube. Enable with XRD_LAB_E2E=1.

LAB="${BATS_TEST_DIRNAME}/../xrd-lab"

setup_file() {
  [ "${XRD_LAB_E2E:-0}" = "1" ] || skip "set XRD_LAB_E2E=1 to run the live e2e"
  "$LAB" up
  "$LAB" deploy dev
}

teardown_file() {
  [ "${XRD_LAB_E2E:-0}" = "1" ] || return 0
  "$LAB" down dev || true
}

@test "smoke deployment answers /healthz with 200 through the Service" {
  [ "${XRD_LAB_E2E:-0}" = "1" ] || skip "set XRD_LAB_E2E=1 to run the live e2e"
  run "$LAB" test smoke
  [ "$status" -eq 0 ]
  [[ "$output" == *"smoke OK"* ]]
}

@test "dry-run test prints a port-forward and a curl" {
  run env XRD_LAB_DRY_RUN=1 "$LAB" test smoke
  [ "$status" -eq 0 ]
  [[ "$output" == *"port-forward"* ]]
  [[ "$output" == *"/healthz"* ]]
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bats k8s-tests/tests-bats/xrd_lab_e2e.bats`
Expected: the live test **skips** (XRD_LAB_E2E unset), but the **dry-run test FAILS** — `cmd_test` is still the Task 7 stub, so it exits non-zero and prints no `port-forward`.

- [ ] **Step 3: Replace the `cmd_test` stub with the real implementation**

In `k8s-tests/xrd-lab`, replace the temporary `cmd_test` stub with:

```bash
# scenario_smoke — verify the smoke Service answers /healthz with 200.
scenario_smoke() {
    local ns="brix-dev"
    local svc="brix-dev-smoke"
    if [ "$DRY_RUN" = "1" ]; then
        echo "kubectl -n $ns port-forward svc/$svc 18080:8080"
        echo "curl -sf http://127.0.0.1:18080/healthz"
        return 0
    fi
    # Poll the Service via an ephemeral in-cluster curl pod (no host port-forward
    # race); assert HTTP 200 at /healthz.
    local code
    code="$(kubectl -n "$ns" run smoke-probe-$$ --rm -i --restart=Never \
        --image=brix-smoke:dev --image-pull-policy=Never --quiet \
        --command -- curl -s -o /dev/null -w '%{http_code}' \
        "http://${svc}.${ns}.svc.cluster.local:8080/healthz" 2>/dev/null || true)"
    if [ "$code" = "200" ]; then
        echo "smoke OK (200 /healthz)"
        return 0
    fi
    echo "smoke FAILED (got '${code:-no-response}')" >&2
    return 1
}

cmd_test() {
    local scenario="${1:-}"
    case "$scenario" in
        smoke) scenario_smoke ;;
        "")    echo "error: test requires a <scenario> argument" >&2; usage; return 2 ;;
        *)     echo "error: unknown scenario '$scenario'" >&2; return 2 ;;
    esac
}
```

- [ ] **Step 4: Run tests to verify they pass**

First the fast dry-run + lint:
```bash
bats k8s-tests/tests-bats/xrd_lab_e2e.bats     # live test skips, dry-run test PASSES
shellcheck k8s-tests/xrd-lab
bats k8s-tests/tests-bats/xrd_lab_unit.bats     # Task 7 tests still green
```
Expected: dry-run test PASS, live test SKIP; shellcheck clean; Task 7 suite still PASS.

Then the real end-to-end (this is the foundation's acceptance gate):
```bash
XRD_LAB_E2E=1 bats k8s-tests/tests-bats/xrd_lab_e2e.bats
```
Expected: both tests PASS — cluster starts, smoke image builds into the node, chart installs, the pod becomes Ready, and the Service returns `200` at `/healthz` (`smoke OK`). If minikube is slow, the first run may take several minutes; the `--wait --timeout 5m` on deploy covers pod readiness.

- [ ] **Step 5: Commit**

```bash
git add k8s-tests/xrd-lab k8s-tests/tests-bats/xrd_lab_e2e.bats
git commit -m "feat(k8s): xrd-lab test smoke + live end-to-end foundation gate"
```

---

## Task 9: Beginner docs + retire the superseded manifests

**Files:**
- Create: `k8s-tests/README.md`
- Create: `k8s-tests/docs/walkthrough.md`
- Delete: `k8s-tests/k8s-manifests/lab-5-vms.yaml`, `k8s-tests/k8s-manifests/fixed-ip-vms.yaml`, `k8s-tests/xrd-k8s`
- Create: `k8s-tests/tests-bats/docs.bats`

**Interfaces:**
- Produces: operator-facing docs whose commands match the real `xrd-lab` surface.

- [ ] **Step 1: Write the failing test**

Create `k8s-tests/tests-bats/docs.bats`:

```bash
#!/usr/bin/env bats

ROOT="${BATS_TEST_DIRNAME}/.."

@test "README documents the four core xrd-lab commands" {
  for cmd in "xrd-lab up" "xrd-lab deploy dev" "xrd-lab test smoke" "xrd-lab down dev"; do
    grep -qF "$cmd" "$ROOT/README.md"
  done
}

@test "retired manifests and the old driver are gone" {
  [ ! -f "$ROOT/k8s-manifests/lab-5-vms.yaml" ]
  [ ! -f "$ROOT/k8s-manifests/fixed-ip-vms.yaml" ]
  [ ! -f "$ROOT/xrd-k8s" ]
}

@test "walkthrough exists and references the pinned k8s version" {
  grep -qF "v1.31.4" "$ROOT/docs/walkthrough.md"
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bats k8s-tests/tests-bats/docs.bats`
Expected: FAIL — README/walkthrough absent; retired files still present.

- [ ] **Step 3: Write the docs and remove the superseded files**

Create `k8s-tests/README.md` (beginner quickstart). It MUST contain, verbatim, the four command strings the test greps and an install-prereqs pointer:

```markdown
# nginx-xrootd Kubernetes Test Lab

A portable, Helm-driven test lab that runs the project's server topologies on
**minikube** — no external container registry required, so it runs anywhere.

## Prerequisites

Run the checker; it names anything missing:

    ./tools/require-tools.sh

Install anything reported missing (helm, bats, kubeconform, yq, shellcheck;
minikube, kubectl, docker, jq). See `docs/walkthrough.md` for exact commands.

## Quickstart (dev profile)

    ./xrd-lab up            # start minikube (pinned Kubernetes version)
    ./xrd-lab deploy dev    # build images into the cluster + install the dev profile
    ./xrd-lab test smoke    # verify the smoke Service answers /healthz with 200
    ./xrd-lab down dev      # tear the profile down

## How it fits together

- `charts/brix-common` — a Helm *library* chart holding every shared helper
  (labels, image reference, the one-role-per-node pinning toggle, NetworkPolicy,
  ResourceQuota). Nothing else re-implements these.
- `charts/brix-test-lab` — the umbrella chart. A **profile** is a values file in
  `charts/brix-test-lab/values/`; it turns subcharts on and configures them.
- `xrd-lab` — the one script you run. Set `XRD_LAB_DRY_RUN=1` to see the exact
  commands it would execute without running them.

Later sub-projects add the auth-authority plane, the chaos-mesh topology, the
main test fleet, and the Ceph/FUSE backends as additional subcharts + profiles.
```

Create `k8s-tests/docs/walkthrough.md` — a copy-paste first run that includes the tool install commands from Task 0 Step 1 and the pinned version string `v1.31.4`, then the Quickstart block, plus a "what you should see" note for each step (pod Ready, `smoke OK`).

Remove the superseded files:
```bash
git rm k8s-tests/k8s-manifests/lab-5-vms.yaml k8s-tests/k8s-manifests/fixed-ip-vms.yaml k8s-tests/xrd-k8s
```

- [ ] **Step 4: Run test to verify it passes**

Run: `bats k8s-tests/tests-bats/docs.bats`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add k8s-tests/README.md k8s-tests/docs/walkthrough.md k8s-tests/tests-bats/docs.bats
git commit -m "docs(k8s): beginner README + walkthrough; retire lab-5-vms/xrd-k8s"
```

---

## Final verification (run after all tasks)

- [ ] **All chart unit tests green:**
  `helm unittest k8s-tests/charts/smoke && helm unittest k8s-tests/charts/brix-test-lab`
  Expected: all suites PASS.
- [ ] **All bash unit tests green:**
  `bats k8s-tests/tests-bats/require_tools.bats k8s-tests/tests-bats/xrd_lab_unit.bats k8s-tests/tests-bats/docs.bats`
  Expected: all PASS (the e2e file skips without `XRD_LAB_E2E=1`).
- [ ] **Rendered manifests schema-valid:**
  `helm template brix-dev k8s-tests/charts/brix-test-lab -f k8s-tests/charts/brix-test-lab/values/values.dev.yaml | kubeconform -strict -summary`
  Expected: `Invalid: 0, Errors: 0`.
- [ ] **Lint clean:** `helm lint k8s-tests/charts/brix-test-lab -f k8s-tests/charts/brix-test-lab/values/values.dev.yaml` → `0 chart(s) failed`; `shellcheck k8s-tests/xrd-lab k8s-tests/tools/require-tools.sh` → clean.
- [ ] **Live acceptance gate:** `XRD_LAB_E2E=1 bats k8s-tests/tests-bats/xrd_lab_e2e.bats` → both tests PASS (`smoke OK`).

**Definition of done (from spec §5, row 0):** `xrd-lab up && xrd-lab deploy dev && xrd-lab test smoke` passes on a clean box with no external registry used. ✅ when the live acceptance gate is green.

---

## Self-review notes (author check against spec)

- **Spec coverage:** §4.0 chart/repo layout → Tasks 1,4,6 (brix-common library chart, smoke app, umbrella); §4.1 cluster foundation (pinned version, in-cluster image build, no registry, profiles=values) → Tasks 5,6,7,8; §4.7 cross-cutting policies (netpol/quota/pinning/PSS) → Tasks 3,4,7 (PSS applied to the namespace in `cmd_deploy`). Auth plane, topology, main-fleet, Ceph/FUSE are explicitly **out of scope** for #0 and carried by their own plans (spec §5 rows 1–6).
- **Placeholder scan:** every code step contains complete, runnable content; the only forward reference (`cmd_test` in Task 7) is handled with an explicit stub + a Task-8 replacement, not a "TODO".
- **Type/name consistency:** helper names (`brix-common.name/fullname/chart/labels/selectorLabels/image/imagePullPolicy/nodePinning/networkPolicy/resourceQuota`) are defined once and referenced identically in the smoke chart and tests; release/namespace convention (`brix-<profile>`, release `brix-<profile>`, values `values.<profile>.yaml`) is consistent across Tasks 6–9; the pinned version `v1.31.4` appears as the single default in `xrd-lab` and is asserted in Tasks 6/7/9.
