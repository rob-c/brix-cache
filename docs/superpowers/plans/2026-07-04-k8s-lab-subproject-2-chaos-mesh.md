# K8s Test Lab — Sub-project #2: Chaos-Mesh Topology — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans (inline). Steps use checkbox (`- [ ]`) syntax. **No git commands** — every "Checkpoint (no git)" step is a verification gate, not a commit.

**Goal:** Run the chaos-mesh as one pod per role on minikube — `tier3 storage ← tier2 read-through cache ← tier1 proxy`, plus the CMS discovery pair (`redirector` + delayed `data-server`) — wired by stable Service DNS (no hardcoded IPs), with the existing `tests/test_chaos_mesh.py` scenarios passing against the cluster.

**Architecture:** A generic **`topology-role` subchart** turns a role definition (image, config template, upstream refs, ports, pinning) into a Deployment + Service + ConfigMap. Role nginx configs are the repo's real `tests/configs/nginx_*.conf` templates with `{BIND_HOST}`/`{UPSTREAM_PORT}`/`{CMS_PORT}` resolved to **Service DNS** at render time. A minimal **`test-runner`** image+subchart runs `pytest tests/test_chaos_mesh.py` with `TEST_CHAOS_*` env pointed at the role Services. The delayed-CMS scenario is reproduced by gating the redirector's readiness so the data-server starts first. Depends on #0 (`brix-common`, umbrella, `xrd-lab`); reuses #1's server image path only for the real nginx-xrootd build.

**Tech Stack:** Helm 3, helm-unittest, bats, kubeconform, the nginx-xrootd server image, pytest (existing suite).

**Spec:** `docs/superpowers/specs/2026-07-04-k8s-test-lab-design.md` §4.3. **Dependencies:** #0 complete. Needs a **real nginx-xrootd server image** (`brix-server:dev`); its Dockerfile is defined in Task 1 here and reused by #3.

## Global Constraints

- Inherits all #0 Global Constraints (pinned k8s version, no external registry, `brix-<profile>` namespaces + PSS, shellcheck-clean shell, cross-cutting policy only in `brix-common`).
- **No hardcoded pod IPs.** Every inter-role reference resolves to a Service DNS name `<release>-<role>` (e.g. `brix-chaos-chaos-tier3`). This is the whole point versus the retired `lab-5-vms.yaml`.
- **Role configs are the repo's real templates**, copied into the chart and rendered with Helm-substituted upstream host:port. Do not fork the nginx directive content.
- **The chaos test is consumed unmodified.** `tests/test_chaos_mesh.py` runs as-is; only `TEST_CHAOS_*` env vars are set to cluster DNS/ports.

## Chaos-mesh roles (verified from `tests/lib/dedicated.sh` + `tests/configs/`)

| Role (Service name suffix) | Config template | Listens | Upstream/CMS wiring |
|---|---|---|---|
| `chaos-tier3` | `nginx_chaos_tier3_storage.conf` | 1094 | posix storage (leaf) |
| `chaos-tier2` | `nginx_chaos_tier2_cache.conf` | 1094 | `brix_storage_backend root://<tier3-dns>:1094`; cache store posix |
| `chaos-tier1` | `nginx_proxy.conf` | 1094 | `brix_tap_proxy_upstream <tier2-dns>:1094` |
| `chaos-discovery-redir` | `nginx_cluster_redir.conf` | 1094 (mgr) + CMS 1096 | `brix_manager_mode` + `brix_cms_server` |
| `chaos-discovery-ds` | `nginx_cluster_ds.conf` | 1094 | `brix_cms_manager <redir-dns>:1096` (registers) |

`test_chaos_mesh.py` asserts (from its header + fixtures): (1) a data-server started *before* its CMS manager fails to register, then reconnects and registers once the manager appears; (2) tier1→tier2→tier3 read-through delivers a cache-filled file while tier2 is reloaded mid-read.

---

## File Structure

```
k8s-tests/
├── images/server/                              # real nginx-xrootd image (Task 1; reused by #3)
│   ├── Dockerfile
│   └── entrypoint.sh
├── images/test-runner/                         # pytest + tests tree (Task 6; extended by #3)
│   └── Dockerfile
├── charts/topology-role/                       # generic role → Deployment+Service+ConfigMap (Tasks 2-4)
│   ├── Chart.yaml
│   ├── values.yaml
│   ├── templates/
│   │   ├── _rolename.tpl
│   │   ├── configmap.yaml
│   │   ├── deployment.yaml
│   │   └── service.yaml
│   ├── configs/                                # copied real role configs, DNS-templated (Task 3)
│   │   ├── chaos-tier3.conf
│   │   ├── chaos-tier2.conf
│   │   ├── chaos-tier1.conf
│   │   ├── chaos-redir.conf
│   │   └── chaos-ds.conf
│   └── tests/
│       ├── role_render_test.yaml
│       └── wiring_test.yaml
├── charts/chaos-mesh/                          # instantiates the 5 roles (Task 5)
│   ├── Chart.yaml                               # dependency: topology-role (aliased x5) OR a loop
│   ├── values.yaml
│   └── tests/topology_test.yaml
├── charts/test-runner/                         # pytest Job subchart (Task 6)
│   ├── Chart.yaml
│   ├── values.yaml
│   ├── templates/job.yaml
│   └── tests/job_test.yaml
├── charts/brix-test-lab/values/values.chaos.yaml   # chaos profile (Task 7)
└── tests-bats/
    ├── server_image.bats                        # Task 1
    └── chaos_e2e.bats                           # Task 7 (opt-in live)
```

---

## Task 1: `images/server` — the real nginx-xrootd image

The chaos roles are all the nginx-xrootd module with different configs, so this builds the real server image once. Reused verbatim by Sub-project #3.

**Files:**
- Create: `k8s-tests/images/server/Dockerfile`
- Create: `k8s-tests/images/server/entrypoint.sh`
- Create: `k8s-tests/tests-bats/server_image.bats`

**Interfaces:**
- Produces image `brix-server:dev`: nginx with the compiled `ngx_brix` module, `xrdcp`/`xrdfs` clients, entrypoint that runs `nginx -c $NGINX_CONF -g 'daemon off;'` after validating config with `nginx -t`.

- [ ] **Step 1: Write the failing test** `k8s-tests/tests-bats/server_image.bats`:
```bash
#!/usr/bin/env bats
IMG_DIR="${BATS_TEST_DIRNAME}/../images/server"
REPO_ROOT="${BATS_TEST_DIRNAME}/../.."
TAG="brix-server:batstest"

setup() { docker build -q -t "$TAG" -f "$IMG_DIR/Dockerfile" "$REPO_ROOT" >/dev/null; }
teardown() { docker rmi -f "$TAG" >/dev/null 2>&1 || true; }

@test "server image has the brix module and validates a minimal config" {
  run docker run --rm "$TAG" bash -lc 'nginx -V 2>&1 | grep -q brix && command -v xrdcp'
  [ "$status" -eq 0 ]
}
```

- [ ] **Step 2: Run** `bats k8s-tests/tests-bats/server_image.bats` → FAIL (no Dockerfile).

- [ ] **Step 3: Write the implementation.** Two realistic build strategies — pick per repo state at implementation time:

**Strategy A (compile in-image, self-contained, preferred for portability):**
`k8s-tests/images/server/Dockerfile` (context = repo root):
```dockerfile
FROM almalinux:9 AS build
RUN dnf install -y gcc make pcre2-devel zlib-devel openssl-devel \
        krb5-devel libxml2-devel perl xrootd-client git curl tar && dnf clean all
ARG NGINX_VER=1.28.3
WORKDIR /src
RUN curl -fsSL https://nginx.org/download/nginx-${NGINX_VER}.tar.gz | tar xz
COPY . /src/brix
RUN cd nginx-${NGINX_VER} && \
    ./configure --with-stream --with-stream_ssl_module --with-http_ssl_module \
       --with-http_dav_module --with-threads --add-module=/src/brix && \
    make -j"$(nproc)" && make install

FROM almalinux:9
RUN dnf install -y pcre2 zlib openssl krb5-libs libxml2 xrootd-client && dnf clean all
COPY --from=build /usr/local/nginx /usr/local/nginx
COPY k8s-tests/images/server/entrypoint.sh /entrypoint.sh
RUN ln -s /usr/local/nginx/sbin/nginx /usr/local/bin/nginx && chmod +x /entrypoint.sh && mkdir -p /data/xrootd
EXPOSE 1094 1095 8443 8080 9100 1096
ENTRYPOINT ["/entrypoint.sh"]
```

**Strategy B (install the prebuilt RPM):** reuse the existing `k8s-tests/Dockerfiles/rpm-builder` to produce `k8s-tests/rpms/*.rpm`, then `rpm -ivh` it (the existing `Dockerfiles/server/Dockerfile` pattern). Choose B only if the RPM builder is known-good in this environment.

`k8s-tests/images/server/entrypoint.sh`:
```bash
#!/bin/bash
set -e
export NGINX_CONF="${NGINX_CONF:-/etc/brix/nginx.conf}"
mkdir -p /data/xrootd
nginx -t -c "$NGINX_CONF"
exec nginx -c "$NGINX_CONF" -g 'daemon off;'
```

- [ ] **Step 4: Run** `bats k8s-tests/tests-bats/server_image.bats` → PASS. (Strategy A build is slow the first time — allow several minutes.)

- [ ] **Step 5: Checkpoint (no git).**

---

## Task 2: `topology-role` subchart skeleton — Deployment+Service from a role

**Files:**
- Create: `k8s-tests/charts/topology-role/Chart.yaml`
- Create: `k8s-tests/charts/topology-role/values.yaml`
- Create: `k8s-tests/charts/topology-role/templates/_rolename.tpl`
- Create: `k8s-tests/charts/topology-role/templates/deployment.yaml`
- Create: `k8s-tests/charts/topology-role/templates/service.yaml`
- Create: `k8s-tests/charts/topology-role/tests/role_render_test.yaml`

**Interfaces:**
- Consumes: `brix-common`.
- Produces: a Deployment + Service named `<release>-<role.name>`, labelled `app.kubernetes.io/component: <role.name>`, with `brix-common.nodePinning` applied and `NGINX_CONF` set to the mounted config. Values shape:
```yaml
role:
  name: chaos-tier3
  image: { repository: brix-server, tag: dev, pullPolicy: Never }
  configKey: chaos-tier3          # selects configs/<configKey>.conf
  ports: [ { name: xrootd, port: 1094 } ]
  data: { root: /data/xrootd }
  nodePinning: { mode: off }
```

- [ ] **Step 1: Write the failing test** `tests/role_render_test.yaml`:
```yaml
suite: topology role render
templates: [templates/deployment.yaml, templates/service.yaml]
release: { name: brix-chaos }
tests:
  - it: names deployment+service <release>-<role>
    set:
      role: { name: chaos-tier3, image: { repository: brix-server, tag: dev }, ports: [ { name: xrootd, port: 1094 } ] }
    asserts:
      - equal: { path: metadata.name, value: brix-chaos-chaos-tier3, documentIndex: 0 }
      - equal: { path: metadata.name, value: brix-chaos-chaos-tier3, documentIndex: 1 }
      - equal:
          path: spec.selector["app.kubernetes.io/component"]
          value: chaos-tier3
          documentIndex: 1
  - it: exposes the role port on the Service
    set:
      role: { name: chaos-tier3, image: { repository: brix-server, tag: dev }, ports: [ { name: xrootd, port: 1094 } ] }
    documentIndex: 1
    asserts:
      - equal: { path: spec.ports[0].port, value: 1094 }
```

- [ ] **Step 2: Run** `helm dependency build k8s-tests/charts/topology-role 2>/dev/null||true; helm unittest k8s-tests/charts/topology-role` → FAIL.

- [ ] **Step 3: Write the implementation.**

`Chart.yaml`:
```yaml
apiVersion: v2
name: topology-role
description: Generic nginx-xrootd role (Deployment+Service+ConfigMap) for lab topologies
type: application
version: 0.1.0
appVersion: "0.1.0"
dependencies:
  - name: brix-common
    version: 0.1.0
    repository: file://../brix-common
```

`values.yaml`:
```yaml
role:
  name: role
  image: { repository: brix-server, tag: dev, pullPolicy: Never }
  configKey: ""
  ports: []
  data: { root: /data/xrootd }
  nodePinning: { mode: off }
  resources:
    requests: { cpu: 50m, memory: 96Mi }
    limits:   { cpu: "1", memory: 512Mi }
```

`templates/_rolename.tpl`:
```yaml
{{- define "topology-role.fullname" -}}
{{- printf "%s-%s" .Release.Name .Values.role.name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
```

`templates/service.yaml`:
```yaml
apiVersion: v1
kind: Service
metadata:
  name: {{ include "topology-role.fullname" . }}
  labels:
    {{- include "brix-common.labels" . | nindent 4 }}
    app.kubernetes.io/component: {{ .Values.role.name }}
spec:
  type: ClusterIP
  selector:
    {{- include "brix-common.selectorLabels" . | nindent 4 }}
    app.kubernetes.io/component: {{ .Values.role.name }}
  ports:
    {{- range .Values.role.ports }}
    - name: {{ .name }}
      port: {{ .port }}
      targetPort: {{ .port }}
      protocol: TCP
    {{- end }}
```

`templates/deployment.yaml`:
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ include "topology-role.fullname" . }}
  labels:
    {{- include "brix-common.labels" . | nindent 4 }}
    app.kubernetes.io/component: {{ .Values.role.name }}
spec:
  replicas: 1
  selector:
    matchLabels:
      {{- include "brix-common.selectorLabels" . | nindent 6 }}
      app.kubernetes.io/component: {{ .Values.role.name }}
  template:
    metadata:
      labels:
        {{- include "brix-common.labels" . | nindent 8 }}
        app.kubernetes.io/component: {{ .Values.role.name }}
    spec:
      {{- include "brix-common.nodePinning" . | nindent 6 }}
      containers:
        - name: {{ .Values.role.name }}
          image: "{{ .Values.role.image.repository }}:{{ .Values.role.image.tag }}"
          imagePullPolicy: {{ .Values.role.image.pullPolicy | default "Never" }}
          env:
            - { name: NGINX_CONF, value: /etc/brix/nginx.conf }
          ports:
            {{- range .Values.role.ports }}
            - { name: {{ .name }}, containerPort: {{ .port }} }
            {{- end }}
          volumeMounts:
            - { name: config, mountPath: /etc/brix }
            - { name: data,   mountPath: {{ .Values.role.data.root }} }
          resources: {{- toYaml .Values.role.resources | nindent 12 }}
      volumes:
        - name: config
          configMap:
            name: {{ include "topology-role.fullname" . }}-conf
        - name: data
          emptyDir: {}
```

Note: `nodePinning` reads `.Values.nodePinning` in `brix-common`; here it lives under `.Values.role.nodePinning`. Add a thin adapter in `brix-common._pinning.tpl`? No — instead pass a scoped dict. Simplest: in `brix-common.nodePinning`, read `.Values.nodePinning` OR fall back to `.Values.role.nodePinning`. Update `_pinning.tpl` (from #0) to:
```yaml
{{- $mode := "off" -}}
{{- if .Values.nodePinning -}}{{- $mode = (.Values.nodePinning.mode | default "off") -}}{{- end -}}
{{- if and .Values.role .Values.role.nodePinning -}}{{- $mode = (.Values.role.nodePinning.mode | default $mode) -}}{{- end -}}
{{- if eq $mode "role" -}}
... (unchanged affinity body) ...
```
(Record this as a #0-chart amendment applied here.)

The ConfigMap template is added in Task 3; to keep this task's render valid, add a placeholder ConfigMap now referencing the same name so the Deployment mounts resolve:
`templates/configmap.yaml`:
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: {{ include "topology-role.fullname" . }}-conf
  labels: {{- include "brix-common.labels" . | nindent 4 }}
data:
  nginx.conf: |
    events { worker_connections 64; }
    stream { server { listen {{ (index .Values.role.ports 0).port }}; } }
```

- [ ] **Step 4: Run** `helm dependency build k8s-tests/charts/topology-role && helm unittest k8s-tests/charts/topology-role` → PASS.

- [ ] **Step 5: Checkpoint (no git).**

---

## Task 3: Role config templates with Service-DNS upstream wiring

**Files:**
- Create: `k8s-tests/charts/topology-role/configs/chaos-{tier3,tier2,tier1,redir,ds}.conf` (copied from repo, `{...}` markers replaced by Helm expressions)
- Modify: `k8s-tests/charts/topology-role/templates/configmap.yaml` (render the selected config with `.Files.Get` + `tpl`)
- Create: `k8s-tests/charts/topology-role/tests/wiring_test.yaml`

**Interfaces:**
- Consumes: `.Values.role.configKey` and `.Values.role.upstreams` (list of `{ name, service, port }`).
- Produces: a ConfigMap whose `nginx.conf` is the real role config with `LOG_DIR`, `DATA_DIR`, and upstream host:port substituted. Upstream DNS name = `<release>-<upstreams[i].service>`.

- [ ] **Step 1: Write the failing test** `tests/wiring_test.yaml`:
```yaml
suite: role config DNS wiring
templates: [templates/configmap.yaml]
release: { name: brix-chaos }
tests:
  - it: tier2 points its storage backend at the tier3 Service DNS
    set:
      role:
        name: chaos-tier2
        configKey: chaos-tier2
        ports: [ { name: xrootd, port: 1094 } ]
        upstreams: [ { name: UPSTREAM, service: chaos-tier3, port: 1094 } ]
    asserts:
      - matchRegex:
          path: data["nginx.conf"]
          pattern: "brix_storage_backend root://brix-chaos-chaos-tier3:1094"
  - it: ds points its cms manager at the redirector Service DNS
    set:
      role:
        name: chaos-discovery-ds
        configKey: chaos-ds
        ports: [ { name: xrootd, port: 1094 } ]
        upstreams: [ { name: CMS, service: chaos-discovery-redir, port: 1096 } ]
    asserts:
      - matchRegex:
          path: data["nginx.conf"]
          pattern: "brix_cms_manager brix-chaos-chaos-discovery-redir:1096"
```

- [ ] **Step 2: Run** `helm unittest k8s-tests/charts/topology-role -f tests/wiring_test.yaml` → FAIL.

- [ ] **Step 3: Write the implementation.**

Copy each repo config into `configs/`, replacing the sed markers with Helm template expressions. Example `configs/chaos-tier2.conf` (from `tests/configs/nginx_chaos_tier2_cache.conf`):
```nginx
worker_processes 1;
error_log /var/log/brix/error.log info;
events { worker_connections 512; }
thread_pool default threads=4 max_queue=65536;
stream {
  server {
    listen {{ (index .Values.role.ports 0).port }};
    xrootd on;
    brix_auth none;
    brix_storage_backend root://{{ .Release.Name }}-{{ (index .Values.role.upstreams 0).service }}:{{ (index .Values.role.upstreams 0).port }};
    brix_cache_store     posix:{{ .Values.role.data.root }}/cache;
    brix_cache_root      /;
  }
}
```
`configs/chaos-tier1.conf` (from `nginx_proxy.conf`):
```nginx
worker_processes 1;
error_log /var/log/brix/error.log info;
events { worker_connections 256; }
stream {
  server {
    listen {{ (index .Values.role.ports 0).port }};
    xrootd on;
    brix_auth none;
    brix_tap_proxy on;
    brix_tap_proxy_upstream {{ .Release.Name }}-{{ (index .Values.role.upstreams 0).service }}:{{ (index .Values.role.upstreams 0).port }};
    brix_tap_proxy_auth anonymous;
  }
}
```
`configs/chaos-tier3.conf` (from `nginx_chaos_tier3_storage.conf`):
```nginx
worker_processes 1;
error_log /var/log/brix/error.log info;
events { worker_connections 512; }
stream {
  server {
    listen {{ (index .Values.role.ports 0).port }};
    xrootd on;
    brix_storage_backend posix:{{ .Values.role.data.root }};
    brix_auth none;
    brix_allow_write on;
  }
}
```
`configs/chaos-redir.conf` (from `nginx_cluster_redir.conf`; CMS port from a second listed port):
```nginx
worker_processes 1;
error_log /var/log/brix/error.log debug;
events { worker_connections 128; }
stream {
  server { listen {{ (index .Values.role.ports 0).port }}; xrootd on; brix_auth none; brix_manager_mode on; }
  server { listen {{ (index .Values.role.ports 1).port }}; brix_cms_server on; }
}
```
`configs/chaos-ds.conf` (from `nginx_cluster_ds.conf`):
```nginx
worker_processes 1;
error_log /var/log/brix/error.log debug;
events { worker_connections 128; }
stream {
  server {
    listen {{ (index .Values.role.ports 0).port }};
    xrootd on;
    brix_storage_backend posix:{{ .Values.role.data.root }};
    brix_auth none;
    brix_allow_write on;
    brix_cms_manager {{ .Release.Name }}-{{ (index .Values.role.upstreams 0).service }}:{{ (index .Values.role.upstreams 0).port }};
    brix_cms_paths /;
    brix_cms_interval 5;
    brix_listen_port {{ (index .Values.role.ports 0).port }};
  }
}
```

Rewrite `templates/configmap.yaml` to render the selected config through `tpl`:
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: {{ include "topology-role.fullname" . }}-conf
  labels: {{- include "brix-common.labels" . | nindent 4 }}
data:
  nginx.conf: |
    {{- $tmpl := printf "configs/%s.conf" .Values.role.configKey -}}
    {{- tpl (.Files.Get $tmpl) . | nindent 4 }}
```

- [ ] **Step 4: Run** `helm unittest k8s-tests/charts/topology-role` → PASS (render + wiring suites).

- [ ] **Step 5: Checkpoint (no git).** Also validate one render end-to-end:
`helm template t k8s-tests/charts/topology-role --set role.name=chaos-tier2,role.configKey=chaos-tier2,role.ports[0].name=xrootd,role.ports[0].port=1094,role.upstreams[0].service=chaos-tier3,role.upstreams[0].port=1094 | grep 'root://t-chaos-tier3:1094'` → matches.

---

## Task 4: Delayed-CMS readiness gate on the data-server role

**Files:**
- Modify: `k8s-tests/charts/topology-role/templates/deployment.yaml` (optional init-container gate)
- Modify: `k8s-tests/charts/topology-role/values.yaml` (add `role.startGate`)
- Add suite: `k8s-tests/charts/topology-role/tests/startgate_test.yaml`

**Interfaces:**
- Consumes: `.Values.role.startGate` = `{ enabled: bool, waitSeconds: int, waitFor: <service-dns> }`.
- Produces: when enabled, an initContainer that sleeps `waitSeconds` (and optionally TCP-waits `waitFor`) before the role container starts — used to force the data-server to attempt CMS registration before the redirector is up, then converge. Off by default (no init container).

- [ ] **Step 1: Write the failing test** `tests/startgate_test.yaml`:
```yaml
suite: role start gate
templates: [templates/deployment.yaml]
release: { name: brix-chaos }
tests:
  - it: no init container by default
    set:
      role: { name: chaos-tier3, ports: [ { name: xrootd, port: 1094 } ] }
    asserts:
      - isNull: { path: spec.template.spec.initContainers }
  - it: adds a delay init container when startGate enabled
    set:
      role:
        name: chaos-discovery-redir
        ports: [ { name: xrootd, port: 1094 } ]
        startGate: { enabled: true, waitSeconds: 8 }
    asserts:
      - matchRegex:
          path: spec.template.spec.initContainers[0].args[0]
          pattern: "sleep 8"
```

- [ ] **Step 2: Run** → FAIL.

- [ ] **Step 3: Write.** In `deployment.yaml`, insert above `containers:`:
```yaml
      {{- if and .Values.role.startGate .Values.role.startGate.enabled }}
      initContainers:
        - name: start-gate
          image: "{{ .Values.role.image.repository }}:{{ .Values.role.image.tag }}"
          imagePullPolicy: {{ .Values.role.image.pullPolicy | default "Never" }}
          command: ["/bin/sh","-c"]
          args:
            - |
              sleep {{ .Values.role.startGate.waitSeconds | default 5 }}
      {{- end }}
```
Add to `values.yaml` under `role:`: `startGate: { enabled: false, waitSeconds: 5 }`.

Note on modeling the scenario: the **redirector** carries the start gate (comes up late), so the **data-server** starts first and experiences the real "failed → retried → registered" CMS sequence `test_chaos_mesh` asserts. Set `waitSeconds` in the chaos values (Task 5) larger than `brix_cms_interval` (5s) so at least one failed registration attempt occurs.

- [ ] **Step 4: Run** `helm unittest k8s-tests/charts/topology-role` → PASS.
- [ ] **Step 5: Checkpoint (no git).**

---

## Task 5: `chaos-mesh` subchart — instantiate the 5 roles

**Files:**
- Create: `k8s-tests/charts/chaos-mesh/Chart.yaml`
- Create: `k8s-tests/charts/chaos-mesh/values.yaml`
- Create: `k8s-tests/charts/chaos-mesh/tests/topology_test.yaml`

**Interfaces:**
- Produces: the five roles via five aliased `topology-role` dependencies (`chaos-tier3`, `chaos-tier2`, `chaos-tier1`, `chaos-discovery-redir`, `chaos-discovery-ds`), each fed its role values. Service DNS names become `<release>-chaos-tier3`, etc.

- [ ] **Step 1: Write the failing test** `tests/topology_test.yaml`:
```yaml
suite: chaos mesh topology
templates:
  - charts/chaos-tier2/templates/configmap.yaml
release: { name: brix-chaos }
tests:
  - it: tier2 is wired to tier3 by DNS
    asserts:
      - matchRegex:
          path: data["nginx.conf"]
          pattern: "root://brix-chaos-chaos-tier3:1094"
```

- [ ] **Step 2: Run** `helm dependency build k8s-tests/charts/chaos-mesh 2>/dev/null||true; helm unittest k8s-tests/charts/chaos-mesh` → FAIL.

- [ ] **Step 3: Write.** `Chart.yaml` uses aliased dependencies:
```yaml
apiVersion: v2
name: chaos-mesh
description: Chaos-mesh 5-role topology (tier1/2/3 + CMS discovery pair)
type: application
version: 0.1.0
dependencies:
  - { name: topology-role, version: 0.1.0, repository: file://../topology-role, alias: chaos-tier3 }
  - { name: topology-role, version: 0.1.0, repository: file://../topology-role, alias: chaos-tier2 }
  - { name: topology-role, version: 0.1.0, repository: file://../topology-role, alias: chaos-tier1 }
  - { name: topology-role, version: 0.1.0, repository: file://../topology-role, alias: chaos-discovery-redir }
  - { name: topology-role, version: 0.1.0, repository: file://../topology-role, alias: chaos-discovery-ds }
```
`values.yaml` feeds each alias its `role`:
```yaml
chaos-tier3:
  role:
    name: chaos-tier3
    configKey: chaos-tier3
    ports: [ { name: xrootd, port: 1094 } ]
chaos-tier2:
  role:
    name: chaos-tier2
    configKey: chaos-tier2
    ports: [ { name: xrootd, port: 1094 } ]
    upstreams: [ { name: UPSTREAM, service: chaos-tier3, port: 1094 } ]
chaos-tier1:
  role:
    name: chaos-tier1
    configKey: chaos-tier1
    ports: [ { name: xrootd, port: 1094 } ]
    upstreams: [ { name: UPSTREAM, service: chaos-tier2, port: 1094 } ]
chaos-discovery-redir:
  role:
    name: chaos-discovery-redir
    configKey: chaos-redir
    ports: [ { name: xrootd, port: 1094 }, { name: cms, port: 1096 } ]
    startGate: { enabled: true, waitSeconds: 12 }   # > brix_cms_interval so DS fails once then converges
chaos-discovery-ds:
  role:
    name: chaos-discovery-ds
    configKey: chaos-ds
    ports: [ { name: xrootd, port: 1094 } ]
    upstreams: [ { name: CMS, service: chaos-discovery-redir, port: 1096 } ]
```

- [ ] **Step 4: Run** `helm dependency build k8s-tests/charts/chaos-mesh && helm unittest k8s-tests/charts/chaos-mesh` → PASS.
- [ ] **Step 5: Checkpoint (no git).**

---

## Task 6: `test-runner` image + subchart (runs the real pytest against cluster DNS)

**Files:**
- Create: `k8s-tests/images/test-runner/Dockerfile`
- Create: `k8s-tests/charts/test-runner/Chart.yaml`, `values.yaml`, `templates/job.yaml`, `tests/job_test.yaml`

**Interfaces:**
- Produces image `brix-test-runner:dev`: python3 + pytest + the repo `tests/` tree + `xrdcp`/`xrdfs` clients. Produces a Job that runs `pytest <selection>` with an env block mapping `TEST_*` to cluster Service DNS/ports. Consumed here for chaos; extended by #3 for the full suite.

- [ ] **Step 1: Write the failing test** `charts/test-runner/tests/job_test.yaml`:
```yaml
suite: test-runner job
templates: [templates/job.yaml]
release: { name: brix-chaos }
tests:
  - it: runs the configured pytest selection
    set:
      testRunner:
        selection: tests/test_chaos_mesh.py
        env:
          TEST_SERVER_HOST: brix-chaos-chaos-tier1
          TEST_CHAOS_TIER1_PORT: "1094"
    asserts:
      - isKind: { of: Job }
      - matchRegex:
          path: spec.template.spec.containers[0].args[0]
          pattern: "pytest tests/test_chaos_mesh.py"
      - contains:
          path: spec.template.spec.containers[0].env
          content: { name: TEST_CHAOS_TIER1_PORT, value: "1094" }
```

- [ ] **Step 2: Run** → FAIL.

- [ ] **Step 3: Write.** `images/test-runner/Dockerfile` (context = repo root):
```dockerfile
FROM almalinux:9
RUN dnf install -y python3 python3-pip xrootd-client openssl krb5-workstation && dnf clean all
RUN python3 -m pip install --no-cache-dir pytest pytest-timeout requests cryptography pyjwt
WORKDIR /opt/brix
COPY tests/ /opt/brix/tests/
COPY utils/ /opt/brix/utils/
ENV PYTHONPATH=/opt/brix/tests
CMD ["/bin/bash"]
```
`charts/test-runner/Chart.yaml`:
```yaml
apiVersion: v2
name: test-runner
description: Pytest Job that runs the real suite against the deployed lab
type: application
version: 0.1.0
dependencies:
  - { name: brix-common, version: 0.1.0, repository: file://../brix-common }
```
`values.yaml`:
```yaml
image: { repository: brix-test-runner, tag: dev, pullPolicy: Never }
testRunner:
  selection: tests/test_chaos_mesh.py
  extraArgs: "-p no:xdist -v"
  env: {}
```
`templates/job.yaml`:
```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: {{ .Release.Name }}-test-runner
  labels: {{- include "brix-common.labels" . | nindent 4 }}
spec:
  backoffLimit: 0
  template:
    metadata:
      labels: {{- include "brix-common.selectorLabels" . | nindent 8 }}
    spec:
      restartPolicy: Never
      containers:
        - name: pytest
          image: "{{ .Values.image.repository }}:{{ .Values.image.tag }}"
          imagePullPolicy: {{ .Values.image.pullPolicy | default "Never" }}
          workingDir: /opt/brix
          command: ["/bin/bash","-lc"]
          args:
            - |
              pytest {{ .Values.testRunner.selection }} {{ .Values.testRunner.extraArgs }}
          env:
            {{- range $k, $v := .Values.testRunner.env }}
            - { name: {{ $k }}, value: {{ $v | quote }} }
            {{- end }}
```

- [ ] **Step 4: Run** `helm dependency build k8s-tests/charts/test-runner && helm unittest k8s-tests/charts/test-runner` → PASS.
- [ ] **Step 5: Checkpoint (no git).**

Note: `test_chaos_mesh.py` reads `CHAOS_*` from `tests/settings.py`, which reads `TEST_CHAOS_*` env + `TEST_SERVER_HOST`. Confirm the exact env names by grepping `settings.py` at implementation time (verified present: `TEST_CHAOS_TIER1_PORT`, `TEST_CHAOS_TIER2_PORT`, `TEST_CHAOS_TIER3_PORT`, `TEST_CHAOS_DISCOVERY_REDIR_PORT`, `TEST_CHAOS_DISCOVERY_DS_PORT`, `TEST_SERVER_HOST`). Because the chaos roles live on distinct Services (distinct hostnames, all port 1094/1096), and `settings.py` uses a single `SERVER_HOST`, set per-tier host via the test's own overrides if it supports them; otherwise front the five roles behind one host is impossible — instead set `TEST_CHAOS_*_PORT` to the Service ports and `TEST_SERVER_HOST` to each Service by running the chaos test **from inside the tier1 pod's namespace** using distinct env host vars. **Implementation checkpoint:** verify whether `test_chaos_mesh.py` supports per-tier host env (`TEST_CHAOS_TIER*_HOST`); if not, add that override upstream in `settings.py` (a one-line, surfaced change) so each tier can carry its own DNS name. This is the one place the suite may need a tiny env-surface addition — allowed by spec §7's "narrow, surfaced change" clause.

---

## Task 7: chaos profile + live e2e

**Files:**
- Modify: `k8s-tests/charts/brix-test-lab/Chart.yaml` (add `chaos-mesh` + `test-runner` deps, conditioned)
- Create: `k8s-tests/charts/brix-test-lab/values/values.chaos.yaml`
- Modify: `k8s-tests/xrd-lab` (build server+test-runner images for chaos; add `test chaos` scenario running the Job and tailing results)
- Create: `k8s-tests/tests-bats/chaos_e2e.bats`

**Interfaces:**
- Produces: `xrd-lab deploy chaos` brings up the 5 roles; `xrd-lab test chaos` runs the test-runner Job and returns its exit status.

- [ ] **Step 1: Write the failing test** `tests-bats/chaos_e2e.bats`:
```bash
#!/usr/bin/env bats
LAB="${BATS_TEST_DIRNAME}/../xrd-lab"
setup_file() {
  [ "${XRD_LAB_E2E:-0}" = "1" ] || skip "set XRD_LAB_E2E=1"
  XRD_LAB_NODES="${XRD_LAB_NODES:-1}" "$LAB" up
  "$LAB" deploy chaos
}
teardown_file() { [ "${XRD_LAB_E2E:-0}" = "1" ] && "$LAB" down chaos || true; }

@test "chaos-mesh test_chaos_mesh.py passes in-cluster" {
  [ "${XRD_LAB_E2E:-0}" = "1" ] || skip
  run "$LAB" test chaos
  [ "$status" -eq 0 ]
  [[ "$output" == *"passed"* ]]
}

@test "dry-run chaos deploy wires DNS and runs the chaos test job" {
  run env XRD_LAB_DRY_RUN=1 "$LAB" test chaos
  [ "$status" -eq 0 ]
  [[ "$output" == *"test-runner"* ]]
}
```

- [ ] **Step 2: Run** → FAIL.

- [ ] **Step 3: Implement.** Add deps to umbrella `Chart.yaml`:
```yaml
  - { name: chaos-mesh, version: 0.1.0, repository: file://../chaos-mesh, condition: chaos-mesh.enabled }
  - { name: test-runner, version: 0.1.0, repository: file://../test-runner, condition: test-runner.enabled }
```
`values/values.chaos.yaml`:
```yaml
chaos-mesh: { enabled: true }
test-runner:
  enabled: false     # the Job is launched on demand by `xrd-lab test chaos`, not at deploy
smoke: { enabled: false }
```
Extend `xrd-lab build_images` to build `brix-server:dev` and `brix-test-runner:dev` for the chaos profile. Add `scenario_chaos`:
```bash
scenario_chaos() {
    local ns="brix-chaos"
    if [ "$DRY_RUN" = "1" ]; then
        echo "helm upgrade --install brix-chaos-run charts/test-runner --namespace $ns --set testRunner.selection=tests/test_chaos_mesh.py ..."
        echo "kubectl -n $ns wait --for=condition=complete job/brix-chaos-run-test-runner"
        return 0
    fi
    helm upgrade --install brix-chaos-run "$LAB_DIR/charts/test-runner" \
        --namespace "$ns" \
        --set image.repository=brix-test-runner,image.tag=dev \
        --set testRunner.selection=tests/test_chaos_mesh.py \
        --set testRunner.env.TEST_SERVER_HOST=brix-chaos-chaos-tier1 \
        --set testRunner.env.TEST_CHAOS_TIER1_PORT=1094 \
        --set testRunner.env.TEST_CHAOS_TIER2_PORT=1094 \
        --set testRunner.env.TEST_CHAOS_TIER3_PORT=1094 \
        --set testRunner.env.TEST_CHAOS_DISCOVERY_REDIR_PORT=1096 \
        --set testRunner.env.TEST_CHAOS_DISCOVERY_DS_PORT=1094 \
        --set testRunner.env.TEST_CHAOS_TIER1_HOST=brix-chaos-chaos-tier1 \
        --set testRunner.env.TEST_CHAOS_TIER2_HOST=brix-chaos-chaos-tier2 \
        --set testRunner.env.TEST_CHAOS_TIER3_HOST=brix-chaos-chaos-tier3 \
        --set testRunner.env.TEST_CHAOS_DISCOVERY_REDIR_HOST=brix-chaos-chaos-discovery-redir \
        --set testRunner.env.TEST_CHAOS_DISCOVERY_DS_HOST=brix-chaos-chaos-discovery-ds
    kubectl -n "$ns" wait --for=condition=complete --timeout=300s job/brix-chaos-run-test-runner || true
    kubectl -n "$ns" logs job/brix-chaos-run-test-runner
    kubectl -n "$ns" get job brix-chaos-run-test-runner -o jsonpath='{.status.succeeded}' | grep -q 1
}
```
Register `chaos)` in `cmd_test`.

- [ ] **Step 4: Run tests.**
```bash
bats k8s-tests/tests-bats/chaos_e2e.bats        # dry-run passes, live skips
shellcheck k8s-tests/xrd-lab
helm dependency build k8s-tests/charts/brix-test-lab
helm template brix-chaos k8s-tests/charts/brix-test-lab -f k8s-tests/charts/brix-test-lab/values/values.chaos.yaml | kubeconform -strict -summary
```
Then the live gate:
```bash
XRD_LAB_E2E=1 bats k8s-tests/tests-bats/chaos_e2e.bats
```
Expected: `passed` in the pytest output; Job status succeeded=1.

- [ ] **Step 5: Checkpoint (no git).**

---

## Final verification (Sub-project #2)

- [ ] `helm unittest` green for `topology-role`, `chaos-mesh`, `test-runner`.
- [ ] `helm template brix-chaos ... -f values.chaos.yaml | kubeconform -strict -summary` → `Invalid: 0`.
- [ ] `XRD_LAB_E2E=1 bats k8s-tests/tests-bats/chaos_e2e.bats` → `test_chaos_mesh.py` passes in-cluster.
- [ ] **DoD (spec §5 row 2):** `tests/test_chaos_mesh.py` passes against the cluster. ✅ when the live gate is green.

## Self-review notes

- **Spec coverage:** §4.3 generic role subchart → Tasks 2–4; chaos 5-role instantiation with DNS wiring → Tasks 3,5; delayed-CMS fidelity → Task 4 (+ Task 5 startGate 12s > 5s interval); test-runner env-wiring reuse of the real suite → Task 6; profile + live gate → Task 7.
- **Placeholder scan:** implementation-time checkpoints (server build strategy A/B; per-tier host env in `settings.py`) are explicit engineering forks with stated resolutions, not TODOs. The dry-run `echo` with `...` is print-only.
- **Name consistency:** role Service DNS `<release>-<role.name>` used identically across configs (Task 3), chaos values (Task 5), and the runner env (Task 7); `brix-common.nodePinning` amendment to also read `.Values.role.nodePinning` is recorded once (Task 2) and relied on thereafter; `configKey`→`configs/<key>.conf` mapping consistent between Tasks 2/3/5.
